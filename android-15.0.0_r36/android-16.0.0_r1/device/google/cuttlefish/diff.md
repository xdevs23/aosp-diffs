```diff
diff --git a/Android.bp b/Android.bp
index 64ad350ec..28043d5d2 100644
--- a/Android.bp
+++ b/Android.bp
@@ -184,3 +184,9 @@ java_test_host {
 
     test_suites: ["general-tests"],
 }
+
+prebuilt_etc_host {
+    name: "debian_substitution_marker",
+    filename: "debian_substitution_marker",
+    src: "debian_substitution_marker",
+}
diff --git a/AndroidProducts.mk b/AndroidProducts.mk
index 25f7873d1..ff5f2cc46 100644
--- a/AndroidProducts.mk
+++ b/AndroidProducts.mk
@@ -18,10 +18,12 @@ PRODUCT_MAKEFILES := \
 	aosp_cf_arm_minidroid:$(LOCAL_DIR)/vsoc_arm_minidroid/aosp_cf.mk \
 	aosp_cf_arm64_auto:$(LOCAL_DIR)/vsoc_arm64_only/auto/aosp_cf.mk \
 	aosp_cf_arm64_phone:$(LOCAL_DIR)/vsoc_arm64/phone/aosp_cf.mk \
+	aosp_cf_arm64_phone_vendor:$(LOCAL_DIR)/vsoc_arm64/phone/aosp_cf_vendor.mk \
 	aosp_cf_arm64_phone_pgagnostic:$(LOCAL_DIR)/vsoc_arm64_pgagnostic/phone/aosp_cf.mk \
 	aosp_cf_arm64_phone_fullmte:$(LOCAL_DIR)/vsoc_arm64_only/phone/aosp_cf_fullmte.mk \
 	aosp_cf_arm64_phone_hwasan:$(LOCAL_DIR)/vsoc_arm64/phone/aosp_cf_hwasan.mk \
 	aosp_cf_arm64_only_phone:$(LOCAL_DIR)/vsoc_arm64_only/phone/aosp_cf.mk \
+	aosp_cf_arm64_only_phone_vendor:$(LOCAL_DIR)/vsoc_arm64_only/phone/aosp_cf_vendor.mk \
 	aosp_cf_arm64_only_phone_hwasan:$(LOCAL_DIR)/vsoc_arm64_only/phone/aosp_cf_hwasan.mk \
 	aosp_cf_arm64_minidroid:$(LOCAL_DIR)/vsoc_arm64_minidroid/aosp_cf.mk \
 	aosp_cf_arm64_slim:$(LOCAL_DIR)/vsoc_arm64_only/slim/aosp_cf.mk \
@@ -31,6 +33,7 @@ PRODUCT_MAKEFILES := \
 	aosp_cf_riscv64_phone:$(LOCAL_DIR)/vsoc_riscv64/phone/aosp_cf.mk \
 	aosp_cf_x86_64_auto:$(LOCAL_DIR)/vsoc_x86_64_only/auto/aosp_cf.mk \
 	aosp_cf_x86_64_auto_dd:$(LOCAL_DIR)/vsoc_x86_64_only/auto_dd/aosp_cf.mk \
+	aosp_cf_x86_64_auto_dewd:$(LOCAL_DIR)/vsoc_x86_64_only/auto_dewd/aosp_cf.mk \
 	aosp_cf_x86_64_auto_md:$(LOCAL_DIR)/vsoc_x86_64_only/auto_md/aosp_cf.mk \
 	aosp_cf_x86_64_auto_mdnd:$(LOCAL_DIR)/vsoc_x86_64_only/auto_mdnd/aosp_cf.mk \
 	aosp_cf_x86_64_auto_portrait:$(LOCAL_DIR)/vsoc_x86_64_only/auto_portrait/aosp_cf.mk \
@@ -48,7 +51,6 @@ PRODUCT_MAKEFILES := \
 	aosp_cf_x86_64_only_phone_hsum:$(LOCAL_DIR)/vsoc_x86_64_only/phone/aosp_cf_hsum.mk \
 	aosp_cf_x86_64_slim:$(LOCAL_DIR)/vsoc_x86_64_only/slim/aosp_cf.mk \
 	aosp_cf_x86_64_wear:$(LOCAL_DIR)/vsoc_x86_64_only/wear/aosp_cf.mk \
-	aosp_cf_x86_only_phone:$(LOCAL_DIR)/vsoc_x86_only/phone/aosp_cf.mk \
 	aosp_cf_x86_go_phone:$(LOCAL_DIR)/vsoc_x86/go/aosp_cf.mk \
 	aosp_cf_x86_tv:$(LOCAL_DIR)/vsoc_x86/tv/aosp_cf.mk \
 	aosp_cf_x86_wear:$(LOCAL_DIR)/vsoc_x86/wear/aosp_cf.mk \
diff --git a/CleanSpec.mk b/CleanSpec.mk
index 6d10d1271..a21ed0a49 100644
--- a/CleanSpec.mk
+++ b/CleanSpec.mk
@@ -76,3 +76,5 @@ $(call add-clean-step, find $(PRODUCT_OUT)/system -type f -name "*charger*" -pri
 $(call add-clean-step, find $(PRODUCT_OUT)/vendor -type f -name "*health@*" -print0 | xargs -0 rm -f)
 $(call add-clean-step, find $(PRODUCT_OUT)/recovery/root -type f -name "*charger*" -print0 | xargs -0 rm -f)
 $(call add-clean-step, find $(PRODUCT_OUT)/recovery/root -type f -name "*health@*" -print0 | xargs -0 rm -f)
+
+$(call add-clean-step, rm -rf $(PRODUCT_OUT)/bootloader)
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca3..000000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/OWNERS_techleads b/OWNERS_techleads
index 5b98ee11c..5298fd054 100644
--- a/OWNERS_techleads
+++ b/OWNERS_techleads
@@ -5,3 +5,4 @@ jemoreira@google.com
 natsu@google.com
 rammuthiah@google.com
 schuffelen@google.com
+dimorinny@google.com
diff --git a/README.md b/README.md
index 8400fb999..40eddb3c4 100644
--- a/README.md
+++ b/README.md
@@ -27,13 +27,8 @@
    sudo apt install -y git devscripts config-package-dev debhelper-compat golang curl
    git clone https://github.com/google/android-cuttlefish
    cd android-cuttlefish
-   sudo apt install devscripts equivs
-   for dir in base frontend; do
-     pushd $dir
-     sudo mk-build-deps -i
-     dpkg-buildpackage -uc -us
-     popd
-   done
+   # Install build dependencies and build debian packages
+   ./tools/buildutils/build_packages.sh
    sudo dpkg -i ./cuttlefish-base_*_*64.deb || sudo apt-get install -f
    sudo dpkg -i ./cuttlefish-user_*_*64.deb || sudo apt-get install -f
    sudo usermod -aG kvm,cvdnetwork,render $USER
diff --git a/apex/com.google.cf.bt/Android.bp b/apex/com.google.cf.bt/Android.bp
index eff9ca6c9..529f41d44 100644
--- a/apex/com.google.cf.bt/Android.bp
+++ b/apex/com.google.cf.bt/Android.bp
@@ -22,13 +22,6 @@ prebuilt_etc {
     installable: false,
 }
 
-prebuilt_etc {
-    name: "android.hardware.bluetooth-service.default.xml",
-    src: ":manifest_android.hardware.bluetooth-service.default.xml",
-    sub_dir: "vintf",
-    installable: false,
-}
-
 prebuilt_etc {
     name: "android.hardware.bluetooth.finder-service.default.xml",
     src: ":manifest_android.hardware.bluetooth.finder-service.default.xml",
@@ -67,19 +60,18 @@ apex {
     soc_specific: true,
 
     binaries: [
-        "android.hardware.bluetooth-service.default",
+        "android.hardware.bluetooth-service.cuttlefish",
         "android.hardware.bluetooth.finder-service.default",
         "android.hardware.bluetooth.lmp_event-service.default",
         "android.hardware.bluetooth.ranging-service.default",
         "android.hardware.bluetooth.socket-service.default",
-        "bt_vhci_forwarder",
     ],
     prebuilts: [
         // permissions
         "android.hardware.bluetooth.prebuilt.xml",
         "android.hardware.bluetooth_le.prebuilt.xml",
         // vintf
-        "android.hardware.bluetooth-service.default.xml",
+        "android.hardware.bluetooth-service.cuttlefish.xml",
         "android.hardware.bluetooth.finder-service.default.xml",
         "android.hardware.bluetooth.lmp_event-service.default.xml",
         "android.hardware.bluetooth.ranging-service.default.xml",
diff --git a/apex/com.google.cf.bt/com.google.cf.bt.rc b/apex/com.google.cf.bt/com.google.cf.bt.rc
index ec7597ced..369134c7f 100644
--- a/apex/com.google.cf.bt/com.google.cf.bt.rc
+++ b/apex/com.google.cf.bt/com.google.cf.bt.rc
@@ -1,16 +1,7 @@
-# start bt_vhci_forwarder when apex is ready
-on property:apex.all.ready=true
-    start bt_vhci_forwarder
-
-service bt_vhci_forwarder /apex/com.google.cf.bt/bin/bt_vhci_forwarder -virtio_console_dev=${vendor.ser.bt-uart}
-    user bluetooth
-    group bluetooth
-
-service btlinux /apex/com.google.cf.bt/bin/hw/android.hardware.bluetooth-service.default
+service bt_hci /apex/com.google.cf.bt/bin/hw/android.hardware.bluetooth-service.cuttlefish --serial ${vendor.ser.bt-uart}
     class hal
     user bluetooth
-    group bluetooth net_admin net_bt_admin
-    capabilities NET_ADMIN
+    group bluetooth
 
 service bt_finder /apex/com.google.cf.bt/bin/hw/android.hardware.bluetooth.finder-service.default
     class hal
diff --git a/apex/com.google.cf.bt/file_contexts b/apex/com.google.cf.bt/file_contexts
index 8136019e3..66ed8a55b 100644
--- a/apex/com.google.cf.bt/file_contexts
+++ b/apex/com.google.cf.bt/file_contexts
@@ -1,8 +1,7 @@
 (/.*)?                                                        u:object_r:vendor_file:s0
-/bin/hw/android.hardware.bluetooth-service.default            u:object_r:hal_bluetooth_btlinux_exec:s0
+/bin/hw/android.hardware.bluetooth-service.cuttlefish         u:object_r:hal_bluetooth_default_exec:s0
 /bin/hw/android.hardware.bluetooth.finder-service.default     u:object_r:hal_bluetooth_btlinux_exec:s0
 /bin/hw/android.hardware.bluetooth.ranging-service.default    u:object_r:hal_bluetooth_btlinux_exec:s0
 /bin/hw/android.hardware.bluetooth.lmp_event-service.default  u:object_r:hal_bluetooth_btlinux_exec:s0
-/bin/hw/android.hardware.bluetooth.socket-service.default    u:object_r:hal_bluetooth_btlinux_exec:s0
-/bin/bt_vhci_forwarder                                        u:object_r:bt_vhci_forwarder_exec:s0
+/bin/hw/android.hardware.bluetooth.socket-service.default     u:object_r:hal_bluetooth_btlinux_exec:s0
 /etc(/.*)?                                                    u:object_r:vendor_configs_file:s0
diff --git a/apex/com.google.cf.rild/Android.bp b/apex/com.google.cf.rild/Android.bp
index 6e253cf82..23a7d87a3 100644
--- a/apex/com.google.cf.rild/Android.bp
+++ b/apex/com.google.cf.rild/Android.bp
@@ -49,6 +49,7 @@ apex {
         "android.hardware.telephony.gsm.prebuilt.xml",
         "android.hardware.telephony.ims.prebuilt.xml",
         "android.hardware.telephony.ims.singlereg.prebuilt.xml",
+        "android.hardware.telephony.satellite.prebuilt.xml",
         "com.google.cf.rild.rc",
         "com.google.cf.rild.xml",
     ],
diff --git a/build/Android.bp b/build/Android.bp
index 03beadd0a..c8847e58b 100644
--- a/build/Android.bp
+++ b/build/Android.bp
@@ -108,8 +108,8 @@ cvd_host_tools = [
     "build_super_image",
     "casimir",
     "casimir_control_server",
+    "cf_vhost_user_input",
     "common_crosvm",
-    "config_server",
     "console_forwarder",
     "control_env_proxy_server",
     "crosvm",
@@ -177,6 +177,7 @@ cvd_host_tools = [
     "screen_recording_server",
     "secure_env",
     "sefcontext_compile",
+    "sensors_simulator",
     "simg2img",
     "snapshot_util_cvd",
     "socket_vsock_proxy",
@@ -188,6 +189,7 @@ cvd_host_tools = [
     "unpack_bootimg",
     "vhal_proxy_server",
     "vhost_device_vsock",
+    "vulkan.lvp",
     "vulkan.pastel",
     "webRTC",
     "webrtc_operator",
@@ -217,6 +219,7 @@ cvd_host_webrtc_assets = [
     "webrtc_index.css",
     "webrtc_index.html",
     "webrtc_index.js",
+    "webrtc_keyboard.js",
     "webrtc_location.js",
     "webrtc_mouse.js",
     "webrtc_rootcanal.js",
@@ -277,6 +280,7 @@ cvd_host_aarch64_crosvm = [
     "aarch64_linux_gnu_libffi.so.7_for_crosvm",
     "aarch64_linux_gnu_libgbm.so.1_for_crosvm",
     "aarch64_linux_gnu_libgfxstream_backend.so_for_crosvm",
+    "aarch64_linux_gnu_libmem_overrides.so_for_crosvm",
     "aarch64_linux_gnu_libminijail.so_for_crosvm",
     "aarch64_linux_gnu_libvirglrenderer.so.1_for_crosvm",
     "aarch64_linux_gnu_libwayland_client.so.0_for_crosvm",
@@ -353,6 +357,16 @@ cvd_host_bootloader = [
     "bootloader_qemu_x86_64",
 ]
 
+cvd_host_ti50_emulator = [
+    "ti50_emulator_x86_64_bin",
+    "ti50_emulator_x86_64_lib",
+]
+
+cvd_host_keyboard_config = [
+    "desktop_keyboard.json",
+    "domkey_mapping.json",
+]
+
 prebuilt_etc_host {
     name: "cvd_avb_testkey_rsa2048",
     filename: "cvd_avb_testkey_rsa2048.pem",
@@ -405,6 +419,20 @@ cvd_host_netsim_gui_assets = [
     "netsim_ui_tslib",
 ]
 
+// From Vulkan Loader documentation:
+//
+//   If "library_path" specifies a relative pathname, it is relative
+//   to the path of the JSON manifest file.
+//
+// Our host package looks like:
+//
+//   <host package>/lib64/vulkan.pastel
+//   <host package>/usr/share/vulkan/icd.d/vk_swiftshader_icd.json
+//   <host package>/lib64/vulkan.lvp
+//   <host package>/usr/share/vulkan/icd.d/vk_lavapipe_icd.cf.json
+//
+// so need "../../../../lib64/vulkan.pastel" and "../../../../lib64/vulkan.lvp".
+
 genrule {
     name: "vk_swiftshader_icd.json",
     srcs: [
@@ -413,17 +441,6 @@ genrule {
     out: [
         "vk_swiftshader_icd.json",
     ],
-    // From Vulkan Loader documentation:
-    //
-    //   If "library_path" specifies a relative pathname, it is relative
-    //   to the path of the JSON manifest file.
-    //
-    // Our host package looks like:
-    //
-    //   <host package>/lib64/vulkan.pastel
-    //   <host package>/usr/share/vulkan/icd.d/vk_swiftshader_icd.json
-    //
-    // so need "../../../../lib64/vulkan.pastel".
     cmd: "sed -e 's|$${ICD_LIBRARY_PATH}|../../../../lib64/vulkan.pastel.so|g' $(in) > $(out)",
 }
 
@@ -438,20 +455,66 @@ cvd_host_swiftshader_files = [
     "vk_swiftshader_icd_json_prebuilt",
 ]
 
+genrule {
+    name: "vk_lavapipe_icd.cf.json",
+    srcs: [
+        ":mesa_vulkan_xml",
+    ],
+    out: [
+        "vk_lavapipe_icd.cf.json",
+    ],
+    tools: [
+        "vk_icd_gen",
+    ],
+    cmd: "python3 $(location vk_icd_gen) --api-version 1.4 --xml $(location :mesa_vulkan_xml) " +
+        "--lib-path ../../../../lib64/vulkan.lvp.so --out $(location vk_lavapipe_icd.cf.json)",
+}
+
+prebuilt_usr_share_host {
+    name: "vk_lavapipe_icd_json_prebuilt",
+    filename: "vk_lavapipe_icd.cf.json",
+    relative_install_path: "vulkan/icd.d",
+    src: ":vk_lavapipe_icd.cf.json",
+}
+
+cvd_host_lavapipe_files = [
+    "vk_lavapipe_icd_json_prebuilt",
+]
+
+cvd_default_input_device_specs = [
+    "default_keyboard_spec",
+    "default_mouse_spec",
+    "default_multi_touchpad_spec_template",
+    "default_multi_touchscreen_spec_template",
+    "default_rotary_wheel_spec",
+    "default_single_touchpad_spec_template",
+    "default_single_touchscreen_spec_template",
+    "default_switches_spec",
+]
+
+cvd_debian_marker = [
+    "debian_substitution_marker",
+]
+
 cvd_host_package_customization {
     name: "cvd-host_package",
     deps: cvd_host_tools +
         cvd_host_tests,
     multilib: {
         common: {
-            deps: cvd_host_webrtc_assets +
+            deps: cvd_default_input_device_specs +
+                cvd_host_webrtc_assets +
                 cvd_host_avb_testkey +
                 cvd_host_model_simulator_files +
                 cvd_host_acloud_data +
                 cvd_host_bootloader +
+                cvd_host_ti50_emulator +
+                cvd_host_keyboard_config +
                 cvd_host_swiftshader_files +
+                cvd_host_lavapipe_files +
                 cvd_openwrt_images +
                 cvd_host_netsim_gui_assets +
+                cvd_debian_marker +
                 automotive_proxy_config +
                 automotive_vhal_prop_configs,
         },
diff --git a/build/cvd-host-package.go b/build/cvd-host-package.go
index a5d81eb84..3208a6d56 100644
--- a/build/cvd-host-package.go
+++ b/build/cvd-host-package.go
@@ -136,20 +136,18 @@ func (c *cvdHostPackage) GenerateAndroidBuildActions(ctx android.ModuleContext)
 	tarballBuilder.Build("cvd_host_tarball", fmt.Sprintf("Creating tarball for %s", c.BaseModuleName()))
 	ctx.InstallFile(android.PathForModuleInstall(ctx), c.BaseModuleName()+".tar.gz", tarball)
 	c.tarballFile = android.PathForModuleInstall(ctx, c.BaseModuleName()+".tar.gz")
-}
-
-type cvdHostPackageMetadataProvider interface {
-	tarballMetadata() android.Path
-	stampMetadata() android.Path
-}
 
-func (p *cvdHostPackage) tarballMetadata() android.Path {
-	return p.tarballFile
+	android.SetProvider(ctx, CvdHostPackageMetadataInfoProvider, CvdHostPackageMetadataInfo{
+		TarballMetadata: c.tarballFile,
+		StampMetadata:   c.stampFile,
+	})
 }
 
-func (p *cvdHostPackage) stampMetadata() android.Path {
-	return p.stampFile
+type CvdHostPackageMetadataInfo struct {
+	TarballMetadata android.Path
+	StampMetadata   android.Path
 }
+var CvdHostPackageMetadataInfoProvider = blueprint.NewProvider[CvdHostPackageMetadataInfo]()
 
 // Create "hosttar" phony target with "cvd-host_package.tar.gz" path.
 // Add stamp files into "droidcore" dependency.
@@ -157,16 +155,16 @@ func (p *cvdHostPackageSingleton) GenerateBuildActions(ctx android.SingletonCont
 	var cvdHostPackageTarball android.Paths
 	var cvdHostPackageStamp android.Paths
 
-	ctx.VisitAllModules(func(module android.Module) {
-		if !module.Enabled(ctx) {
+	ctx.VisitAllModuleProxies(func(module android.ModuleProxy) {
+		if !android.OtherModulePointerProviderOrDefault(ctx, module, android.CommonModuleInfoProvider).Enabled {
 			return
 		}
-		if c, ok := module.(cvdHostPackageMetadataProvider); ok {
-			if !android.IsModulePreferred(module) {
+		if c, ok := android.OtherModuleProvider(ctx, module, CvdHostPackageMetadataInfoProvider); ok {
+			if !android.IsModulePreferredProxy(ctx, module) {
 				return
 			}
-			cvdHostPackageTarball = append(cvdHostPackageTarball, c.tarballMetadata())
-			cvdHostPackageStamp = append(cvdHostPackageStamp, c.stampMetadata())
+			cvdHostPackageTarball = append(cvdHostPackageTarball, c.TarballMetadata)
+			cvdHostPackageStamp = append(cvdHostPackageStamp, c.StampMetadata)
 		}
 	})
 
@@ -181,9 +179,7 @@ func (p *cvdHostPackageSingleton) GenerateBuildActions(ctx android.SingletonCont
 		ctx.Phony("hosttar", cvdHostPackageTarball...)
 		ctx.Phony("droidcore", cvdHostPackageStamp...)
 	}
-}
 
-func (p *cvdHostPackageSingleton) MakeVars(ctx android.MakeVarsContext) {
 	if p.tarballPaths != nil {
 		for _, path := range p.tarballPaths {
 			// The riscv64 cuttlefish builds can be run on qemu on an x86_64 or arm64 host. Dist both sets of host packages.
diff --git a/common/libs/fs/Android.bp b/common/libs/fs/Android.bp
index a5c23d9da..84024748c 100644
--- a/common/libs/fs/Android.bp
+++ b/common/libs/fs/Android.bp
@@ -26,6 +26,7 @@ cc_library {
     ],
     shared_libs: [
         "libbase",
+        "libcuttlefish_utils_environment",
         "libcuttlefish_utils_result",
         "liblog",
     ],
diff --git a/common/libs/fs/shared_fd.cpp b/common/libs/fs/shared_fd.cpp
index 0f5393975..b2c0a6609 100644
--- a/common/libs/fs/shared_fd.cpp
+++ b/common/libs/fs/shared_fd.cpp
@@ -38,6 +38,7 @@
 
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_select.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/result.h"
 
 // #define ENABLE_GCE_SHARED_FD_LOGGING 1
@@ -81,24 +82,6 @@ void CheckMarked(fd_set* in_out_mask, SharedFDSet* in_out_set) {
   }
 }
 
-/*
- * Android currently has host prebuilts of glibc 2.15 and 2.17, but
- * memfd_create was only added in glibc 2.27. It was defined in Linux 3.17,
- * so we consider it safe to use the low-level arbitrary syscall wrapper.
- */
-#ifndef __NR_memfd_create
-# if defined(__x86_64__)
-#  define __NR_memfd_create 319
-# elif defined(__i386__)
-#  define __NR_memfd_create 356
-# elif defined(__aarch64__)
-#  define __NR_memfd_create 279
-# else
-/* No interest in other architectures. */
-#  error "Unknown architecture."
-# endif
-#endif
-
 int memfd_create_wrapper(const char* name, unsigned int flags) {
 #ifdef __linux__
 #ifdef CUTTLEFISH_HOST
@@ -425,6 +408,16 @@ SharedFD SharedFD::Event(int initval, int flags) {
   int fd = eventfd(initval, flags);
   return std::shared_ptr<FileInstance>(new FileInstance(fd, errno));
 }
+
+#ifdef CUTTLEFISH_HOST
+SharedFD SharedFD::ShmOpen(const std::string& name, int oflag, int mode) {
+  errno = 0;
+  int fd = shm_open(name.c_str(), oflag, mode);
+  int error_num = errno;
+  return std::shared_ptr<FileInstance>(new FileInstance(fd, error_num));
+}
+#endif
+
 #endif
 
 SharedFD SharedFD::MemfdCreate(const std::string& name, unsigned int flags) {
@@ -759,8 +752,7 @@ std::string SharedFD::GetVhostUserVsockServerAddr(
 
 std::string SharedFD::GetVhostUserVsockClientAddr(int cid) {
   // TODO(b/277909042): better path than /tmp/vsock_{}/vm.vsock_{}
-  return fmt::format("/tmp/vsock_{}_{}/vm.vsock", cid,
-                     std::to_string(getuid()));
+  return fmt::format("{}/vsock_{}_{}/vm.vsock", TempDir(), cid, getuid());
 }
 
 SharedFD SharedFD::VsockClient(unsigned int cid, unsigned int port, int type,
@@ -903,7 +895,8 @@ int FileInstance::LinkAtCwd(const std::string& path) {
 
   std::string name = "/proc/self/fd/";
   name += std::to_string(fd_);
-  return linkat(-1, name.c_str(), AT_FDCWD, path.c_str(), AT_SYMLINK_FOLLOW);
+  return linkat(AT_FDCWD, name.c_str(), AT_FDCWD, path.c_str(),
+                AT_SYMLINK_FOLLOW);
 }
 
 int FileInstance::Listen(int backlog) {
diff --git a/common/libs/fs/shared_fd.h b/common/libs/fs/shared_fd.h
index 3f6730efd..4ae867b02 100644
--- a/common/libs/fs/shared_fd.h
+++ b/common/libs/fs/shared_fd.h
@@ -151,6 +151,9 @@ class SharedFD {
   static bool Pipe(SharedFD* fd0, SharedFD* fd1);
 #ifdef __linux__
   static SharedFD Event(int initval = 0, int flags = 0);
+#ifdef CUTTLEFISH_HOST
+  static SharedFD ShmOpen(const std::string& name, int oflag, int mode);
+#endif
 #endif
   static SharedFD MemfdCreate(const std::string& name, unsigned int flags = 0);
   static SharedFD MemfdCreateWithData(const std::string& name, const std::string& data, unsigned int flags = 0);
diff --git a/common/libs/sensors/sensors.h b/common/libs/sensors/sensors.h
new file mode 100644
index 000000000..15a87e333
--- /dev/null
+++ b/common/libs/sensors/sensors.h
@@ -0,0 +1,56 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+namespace cuttlefish {
+namespace sensors {
+/*
+  These must align with Goldfish sensor IDs as we reuse Goldfish sensor HAL
+  library for Cuttlefish sensor HAL. (See
+  `device/generic/goldfish/hals/sensors/sensor_list.h`.)
+*/
+inline constexpr int kAccelerationId = 0;
+inline constexpr int kGyroscopeId = 1;
+inline constexpr int kMagneticId = 2;
+inline constexpr int kUncalibMagneticId = 9;
+inline constexpr int kUncalibGyroscopeId = 10;
+inline constexpr int kUncalibAccelerationId = 17;
+/*
+  This is reserved specifically for Cuttlefish to identify the device
+  orientation relative to the East-North-Up coordinates frame. This is
+  not really a sensor but rather input from web UI for us to calculate
+  IMU readings.
+*/
+inline constexpr int kRotationVecId = 31;
+inline constexpr int kMaxSensorId = 31;
+
+/*
+  Each sensor ID also represent a bit offset for an app to specify sensors
+  via a bitmask.
+*/
+using SensorsMask = int;
+
+inline constexpr char INNER_DELIM = ':';
+inline constexpr char OUTER_DELIM = ' ';
+
+/* Sensors Commands */
+inline constexpr int kUpdateRotationVec = 0;
+inline constexpr int kGetSensorsData = 1;
+
+using SensorsCmd = int;
+
+}  // namespace sensors
+}  // namespace cuttlefish
diff --git a/common/libs/utils/Android.bp b/common/libs/utils/Android.bp
index 2bb9e3b02..e05bf70d0 100644
--- a/common/libs/utils/Android.bp
+++ b/common/libs/utils/Android.bp
@@ -20,9 +20,11 @@ package {
 cc_library {
     name: "libcuttlefish_utils",
     srcs: [
+        "architecture.cpp",
         "archive.cpp",
         "base64.cpp",
-        "environment.cpp",
+        "container.cpp",
+        "device_type.cpp",
         "files.cpp",
         "flag_parser.cpp",
         "flags_validator.cpp",
@@ -68,7 +70,10 @@ cc_library {
             ],
         },
     },
-    whole_static_libs: ["libcuttlefish_utils_result"],
+    whole_static_libs: [
+        "libcuttlefish_utils_environment",
+        "libcuttlefish_utils_result",
+    ],
     defaults: ["cuttlefish_host"],
     product_available: true,
 }
@@ -116,6 +121,21 @@ cc_library {
     export_include_dirs: ["."],
 }
 
+cc_library {
+    name: "libcuttlefish_utils_environment",
+    srcs: [
+        "environment.cpp",
+        "known_paths.cpp",
+    ],
+    defaults: ["cuttlefish_host"],
+    product_available: true,
+    target: {
+        darwin: {
+            enabled: true,
+        },
+    },
+}
+
 cc_library {
     name: "libcuttlefish_utils_result",
     product_available: true,
diff --git a/common/libs/utils/architecture.cpp b/common/libs/utils/architecture.cpp
new file mode 100644
index 000000000..605767f36
--- /dev/null
+++ b/common/libs/utils/architecture.cpp
@@ -0,0 +1,65 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+#include "common/libs/utils/architecture.h"
+
+#include <sys/utsname.h>
+
+#include <cstdlib>
+#include <string>
+
+#include <android-base/logging.h>
+#include <android-base/no_destructor.h>
+#include <android-base/strings.h>
+
+namespace cuttlefish {
+
+/** Returns e.g. aarch64, x86_64, etc */
+const std::string& HostArchStr() {
+  static android::base::NoDestructor<std::string> arch([] {
+    utsname buf;
+    CHECK_EQ(uname(&buf), 0) << strerror(errno);
+    return std::string(buf.machine);
+  }());
+  return *arch;
+}
+
+Arch HostArch() {
+  std::string arch_str = HostArchStr();
+  if (arch_str == "aarch64" || arch_str == "arm64") {
+    return Arch::Arm64;
+  } else if (arch_str == "arm") {
+    return Arch::Arm;
+  } else if (arch_str == "riscv64") {
+    return Arch::RiscV64;
+  } else if (arch_str == "x86_64") {
+    return Arch::X86_64;
+  } else if (arch_str.size() == 4 && arch_str[0] == 'i' && arch_str[2] == '8' &&
+             arch_str[3] == '6') {
+    return Arch::X86;
+  } else {
+    LOG(FATAL) << "Unknown host architecture: " << arch_str;
+    return Arch::X86;
+  }
+}
+
+bool IsHostCompatible(Arch arch) {
+  Arch host_arch = HostArch();
+  return arch == host_arch || (arch == Arch::Arm && host_arch == Arch::Arm64) ||
+         (arch == Arch::X86 && host_arch == Arch::X86_64);
+}
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/architecture.h b/common/libs/utils/architecture.h
new file mode 100644
index 000000000..01e9a4bae
--- /dev/null
+++ b/common/libs/utils/architecture.h
@@ -0,0 +1,34 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+
+namespace cuttlefish {
+
+enum class Arch {
+  Arm,
+  Arm64,
+  RiscV64,
+  X86,
+  X86_64,
+};
+
+const std::string& HostArchStr();
+Arch HostArch();
+bool IsHostCompatible(Arch arch);
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/base64.cpp b/common/libs/utils/base64.cpp
index 2f1441dce..5156d6907 100644
--- a/common/libs/utils/base64.cpp
+++ b/common/libs/utils/base64.cpp
@@ -18,56 +18,20 @@
 
 #include <cstddef>
 #include <cstdint>
-#include <optional>
 #include <string>
 #include <vector>
 
-#include <openssl/evp.h>
+#include <openssl/base64.h>
 
 namespace cuttlefish {
 
-namespace {
-
-// EVP_EncodedLength is boringssl specific so it can't be used outside of
-// android.
-std::optional<size_t> EncodedLength(size_t len) {
-  if (len + 2 < len) {
-    return std::nullopt;
-  }
-  len += 2;
-  len /= 3;
-
-  if (((len << 2) >> 2) != len) {
-    return std::nullopt;
-  }
-  len <<= 2;
-
-  if (len + 1 < len) {
-    return std::nullopt;
-  }
-  len++;
-
-  return {len};
-}
-
-// EVP_DecodedLength is boringssl specific so it can't be used outside of
-// android.
-std::optional<size_t> DecodedLength(size_t len) {
-  if (len % 4 != 0) {
-    return std::nullopt;
-  }
-
-  return {(len / 4) * 3};
-}
-
-}  // namespace
-
 bool EncodeBase64(const void *data, std::size_t size, std::string *out) {
-  auto len_res = EncodedLength(size);
-  if (!len_res) {
+  std::size_t max_length = 0;
+  if (EVP_EncodedLength(&max_length, size) == 0) {
     return false;
   }
-  out->resize(*len_res);
+
+  out->resize(max_length);
   auto enc_res =
       EVP_EncodeBlock(reinterpret_cast<std::uint8_t *>(out->data()),
                       reinterpret_cast<const std::uint8_t *>(data), size);
@@ -79,24 +43,15 @@ bool EncodeBase64(const void *data, std::size_t size, std::string *out) {
 }
 
 bool DecodeBase64(const std::string &data, std::vector<std::uint8_t> *buffer) {
-  auto len_res = DecodedLength(data.size());
-  if (!len_res) {
+  buffer->resize(data.size());
+  std::size_t actual_len = 0;
+  int success = EVP_DecodeBase64(buffer->data(), &actual_len, buffer->size(),
+                                 reinterpret_cast<const uint8_t *>(data.data()),
+                                 data.size());
+  if (success != 1) {
     return false;
   }
-  auto out_len = *len_res;
-  buffer->resize(out_len);
-  auto actual_len = EVP_DecodeBlock(buffer->data(),
-                                reinterpret_cast<const uint8_t *>(data.data()),
-                                data.size());
-  if (actual_len < 0) {
-    return false;
-  }
-
-  // DecodeBlock leaves null characters at the end of the buffer when the
-  // decoded message is not a multiple of 3.
-  while (!buffer->empty() && buffer->back() == '\0') {
-    buffer->pop_back();
-  }
+  buffer->resize(actual_len);
 
   return true;
 }
diff --git a/common/libs/utils/base64_test.cpp b/common/libs/utils/base64_test.cpp
index d3a7e886a..d582d1131 100644
--- a/common/libs/utils/base64_test.cpp
+++ b/common/libs/utils/base64_test.cpp
@@ -59,5 +59,39 @@ TEST(Base64Test, DecodeNonMult3) {
   ASSERT_EQ(out, expected);
 }
 
+TEST(Base64Test, EncodeOneZero) {
+  std::vector<uint8_t> in = {0};
+  std::string string_encoding;
 
+  ASSERT_TRUE(EncodeBase64(in.data(), in.size(), &string_encoding));
+
+  std::vector<uint8_t> out;
+  ASSERT_TRUE(DecodeBase64(string_encoding, &out));
+
+  ASSERT_EQ(in, out);
+}
+
+TEST(Base64Test, EncodeTwoZeroes) {
+  std::vector<uint8_t> in = {0, 0};
+  std::string string_encoding;
+
+  ASSERT_TRUE(EncodeBase64(in.data(), in.size(), &string_encoding));
+
+  std::vector<uint8_t> out;
+  ASSERT_TRUE(DecodeBase64(string_encoding, &out));
+
+  ASSERT_EQ(in, out);
+}
+
+TEST(Base64Test, EncodeThreeZeroes) {
+  std::vector<uint8_t> in = {0, 0, 0};
+  std::string string_encoding;
+
+  ASSERT_TRUE(EncodeBase64(in.data(), in.size(), &string_encoding));
+
+  std::vector<uint8_t> out;
+  ASSERT_TRUE(DecodeBase64(string_encoding, &out));
+
+  ASSERT_EQ(in, out);
+}
 }
diff --git a/common/libs/utils/container.cpp b/common/libs/utils/container.cpp
new file mode 100644
index 000000000..a1d2b937f
--- /dev/null
+++ b/common/libs/utils/container.cpp
@@ -0,0 +1,39 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+#include "common/libs/utils/container.h"
+
+#include <cstdlib>
+#include <string>
+
+#include "common/libs/utils/files.h"
+
+namespace cuttlefish {
+
+static bool IsRunningInDocker() {
+  // if /.dockerenv exists, it's inside a docker container
+  static std::string docker_env_path("/.dockerenv");
+  static bool ret =
+      FileExists(docker_env_path) || DirectoryExists(docker_env_path);
+  return ret;
+}
+
+bool IsRunningInContainer() {
+  // TODO: add more if we support other containers than docker
+  return IsRunningInDocker();
+}
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/container.h b/common/libs/utils/container.h
new file mode 100644
index 000000000..762538228
--- /dev/null
+++ b/common/libs/utils/container.h
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+namespace cuttlefish {
+
+bool IsRunningInContainer();
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/device_type.cpp b/common/libs/utils/device_type.cpp
new file mode 100644
index 000000000..6db9889f9
--- /dev/null
+++ b/common/libs/utils/device_type.cpp
@@ -0,0 +1,43 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "common/libs/utils/device_type.h"
+
+namespace cuttlefish {
+
+// Parse device type from android-info.txt config field.
+DeviceType ParseDeviceType(std::string_view type_name) {
+  if (type_name == "phone") {
+    return DeviceType::Phone;
+  } else if (type_name == "wear") {
+    return DeviceType::Wear;
+  } else if (type_name == "auto" || type_name == "auto_portrait" ||
+             type_name == "auto_dd" || type_name == "auto_md") {
+    return DeviceType::Auto;
+  } else if (type_name == "foldable") {
+    return DeviceType::Foldable;
+  } else if (type_name == "tv") {
+    return DeviceType::Tv;
+  } else if (type_name == "minidroid") {
+    return DeviceType::Minidroid;
+  } else if (type_name == "go") {
+    return DeviceType::Go;
+  } else {
+    return DeviceType::Unknown;
+  }
+}
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/device_type.h b/common/libs/utils/device_type.h
new file mode 100644
index 000000000..f0bb6e5da
--- /dev/null
+++ b/common/libs/utils/device_type.h
@@ -0,0 +1,36 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+
+namespace cuttlefish {
+
+enum class DeviceType {
+  Unknown = 0,
+  Phone,
+  Wear,
+  Auto,
+  Foldable,
+  Tv,
+  Minidroid,
+  Go,
+};
+
+// Parse device type android-info.txt config field.
+DeviceType ParseDeviceType(std::string_view type_name);
+
+}  // namespace cuttlefish
diff --git a/common/libs/utils/environment.cpp b/common/libs/utils/environment.cpp
index b8ff0d2d8..29dbe5e93 100644
--- a/common/libs/utils/environment.cpp
+++ b/common/libs/utils/environment.cpp
@@ -16,77 +16,18 @@
 
 #include "common/libs/utils/environment.h"
 
-#include <sys/utsname.h>
-
-#include <cstdio>
 #include <cstdlib>
-#include <memory>
-#include <ostream>
 #include <string>
 
-#include <android-base/logging.h>
-#include <android-base/no_destructor.h>
-#include <android-base/strings.h>
-
-#include "common/libs/utils/files.h"
-
 namespace cuttlefish {
 
 std::string StringFromEnv(const std::string& varname,
                           const std::string& defval) {
-  const char* const valstr = getenv(varname.c_str());
+  const char* const valstr = std::getenv(varname.c_str());
   if (!valstr) {
     return defval;
   }
   return valstr;
 }
 
-/** Returns e.g. aarch64, x86_64, etc */
-const std::string& HostArchStr() {
-  static android::base::NoDestructor<std::string> arch([] {
-    utsname buf;
-    CHECK_EQ(uname(&buf), 0) << strerror(errno);
-    return std::string(buf.machine);
-  }());
-  return *arch;
-}
-
-Arch HostArch() {
-  std::string arch_str = HostArchStr();
-  if (arch_str == "aarch64" || arch_str == "arm64") {
-    return Arch::Arm64;
-  } else if (arch_str == "arm") {
-    return Arch::Arm;
-  } else if (arch_str == "riscv64") {
-    return Arch::RiscV64;
-  } else if (arch_str == "x86_64") {
-    return Arch::X86_64;
-  } else if (arch_str.size() == 4 && arch_str[0] == 'i' && arch_str[2] == '8' &&
-             arch_str[3] == '6') {
-    return Arch::X86;
-  } else {
-    LOG(FATAL) << "Unknown host architecture: " << arch_str;
-    return Arch::X86;
-  }
-}
-
-bool IsHostCompatible(Arch arch) {
-  Arch host_arch = HostArch();
-  return arch == host_arch || (arch == Arch::Arm && host_arch == Arch::Arm64) ||
-         (arch == Arch::X86 && host_arch == Arch::X86_64);
-}
-
-static bool IsRunningInDocker() {
-  // if /.dockerenv exists, it's inside a docker container
-  static std::string docker_env_path("/.dockerenv");
-  static bool ret =
-      FileExists(docker_env_path) || DirectoryExists(docker_env_path);
-  return ret;
-}
-
-bool IsRunningInContainer() {
-  // TODO: add more if we support other containers than docker
-  return IsRunningInDocker();
-}
-
 }  // namespace cuttlefish
diff --git a/common/libs/utils/environment.h b/common/libs/utils/environment.h
index 7bea0a581..bf3fafc3d 100644
--- a/common/libs/utils/environment.h
+++ b/common/libs/utils/environment.h
@@ -19,21 +19,7 @@
 
 namespace cuttlefish {
 
-enum class Arch {
-  Arm,
-  Arm64,
-  RiscV64,
-  X86,
-  X86_64,
-};
-
 std::string StringFromEnv(const std::string& varname,
                           const std::string& defval);
 
-const std::string& HostArchStr();
-Arch HostArch();
-bool IsHostCompatible(Arch arch);
-
-bool IsRunningInContainer();
-
 }  // namespace cuttlefish
diff --git a/common/libs/utils/files.cpp b/common/libs/utils/files.cpp
index 51131c7df..e55ccd150 100644
--- a/common/libs/utils/files.cpp
+++ b/common/libs/utils/files.cpp
@@ -186,7 +186,7 @@ Result<void> EnsureDirectoryExists(const std::string& directory_path,
   }
   const auto parent_dir = android::base::Dirname(directory_path);
   if (parent_dir.size() > 1) {
-    EnsureDirectoryExists(parent_dir, mode, group_name);
+    CF_EXPECT(EnsureDirectoryExists(parent_dir, mode, group_name));
   }
   LOG(VERBOSE) << "Setting up " << directory_path;
   if (mkdir(directory_path.c_str(), mode) < 0 && errno != EEXIST) {
@@ -476,13 +476,17 @@ Result<std::string> ReadFileContents(const std::string& filepath) {
 }
 
 std::string CurrentDirectory() {
-  std::unique_ptr<char, void (*)(void*)> cwd(getcwd(nullptr, 0), &free);
-  std::string process_cwd(cwd.get());
-  if (!cwd) {
-    PLOG(ERROR) << "`getcwd(nullptr, 0)` failed";
-    return "";
+  std::vector<char> process_wd(1 << 12, ' ');
+  while (getcwd(process_wd.data(), process_wd.size()) == nullptr) {
+    if (errno == ERANGE) {
+      process_wd.resize(process_wd.size() * 2, ' ');
+    } else {
+      PLOG(ERROR) << "getcwd failed";
+      return "";
+    }
   }
-  return process_cwd;
+  // Will find the null terminator and size the string appropriately.
+  return std::string(process_wd.data());
 }
 
 FileSizes SparseFileSizes(const std::string& path) {
@@ -573,15 +577,19 @@ std::string FindImage(const std::string& search_path,
   return "";
 }
 
-std::string FindFile(const std::string& path, const std::string& target_name) {
+Result<std::string> FindFile(const std::string& path,
+                             const std::string& target_name) {
   std::string ret;
-  WalkDirectory(path,
-                [&ret, &target_name](const std::string& filename) mutable {
-                  if (android::base::Basename(filename) == target_name) {
-                    ret = filename;
-                  }
-                  return true;
-                });
+  auto res = WalkDirectory(
+      path, [&ret, &target_name](const std::string& filename) mutable {
+        if (android::base::Basename(filename) == target_name) {
+          ret = filename;
+        }
+        return true;
+      });
+  if (!res.ok()) {
+    return "";
+  }
   return ret;
 }
 
@@ -596,7 +604,10 @@ Result<void> WalkDirectory(
     file_path.append(filename);
     callback(file_path);
     if (DirectoryExists(file_path)) {
-      WalkDirectory(file_path, callback);
+      auto res = WalkDirectory(file_path, callback);
+      if (!res.ok()) {
+        return res;
+      }
     }
   }
   return {};
diff --git a/common/libs/utils/files.h b/common/libs/utils/files.h
index 64a05d3fa..43671cb43 100644
--- a/common/libs/utils/files.h
+++ b/common/libs/utils/files.h
@@ -83,7 +83,8 @@ FileSizes SparseFileSizes(const std::string& path);
 
 // Find file with name |target_name| under directory |path|, return path to
 // found file(if any)
-std::string FindFile(const std::string& path, const std::string& target_name);
+Result<std::string> FindFile(const std::string& path,
+                             const std::string& target_name);
 
 Result<void> WalkDirectory(
     const std::string& dir,
diff --git a/common/libs/utils/files_test.cpp b/common/libs/utils/files_test.cpp
index ea03cf6a4..6d4bacdf2 100644
--- a/common/libs/utils/files_test.cpp
+++ b/common/libs/utils/files_test.cpp
@@ -53,20 +53,20 @@ TEST_P(EmulateAbsolutePathWithPwd, NoHomeYesPwd) {
 
 INSTANTIATE_TEST_SUITE_P(
     CommonUtilsTest, EmulateAbsolutePathWithPwd,
-    testing::Values(InputOutput{.working_dir_ = "/x/y/z",
-                                .path_to_convert_ = "",
+    testing::Values(InputOutput{.path_to_convert_ = "",
+                                .working_dir_ = "/x/y/z",
                                 .expected_ = ""},
-                    InputOutput{.working_dir_ = "/x/y/z",
-                                .path_to_convert_ = "a",
+                    InputOutput{.path_to_convert_ = "a",
+                                .working_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/z/a"},
-                    InputOutput{.working_dir_ = "/x/y/z",
-                                .path_to_convert_ = ".",
+                    InputOutput{.path_to_convert_ = ".",
+                                .working_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/z"},
-                    InputOutput{.working_dir_ = "/x/y/z",
-                                .path_to_convert_ = "..",
+                    InputOutput{.path_to_convert_ = "..",
+                                .working_dir_ = "/x/y/z",
                                 .expected_ = "/x/y"},
-                    InputOutput{.working_dir_ = "/x/y/z",
-                                .path_to_convert_ = "./k/../../t/./q",
+                    InputOutput{.path_to_convert_ = "./k/../../t/./q",
+                                .working_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/t/q"}));
 
 TEST_P(EmulateAbsolutePathWithHome, YesHomeNoPwd) {
@@ -84,20 +84,20 @@ TEST_P(EmulateAbsolutePathWithHome, YesHomeNoPwd) {
 
 INSTANTIATE_TEST_SUITE_P(
     CommonUtilsTest, EmulateAbsolutePathWithHome,
-    testing::Values(InputOutput{.home_dir_ = "/x/y/z",
-                                .path_to_convert_ = "~",
+    testing::Values(InputOutput{.path_to_convert_ = "~",
+                                .home_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/z"},
-                    InputOutput{.home_dir_ = "/x/y/z",
-                                .path_to_convert_ = "~/a",
+                    InputOutput{.path_to_convert_ = "~/a",
+                                .home_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/z/a"},
-                    InputOutput{.home_dir_ = "/x/y/z",
-                                .path_to_convert_ = "~/.",
+                    InputOutput{.path_to_convert_ = "~/.",
+                                .home_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/z"},
-                    InputOutput{.home_dir_ = "/x/y/z",
-                                .path_to_convert_ = "~/..",
+                    InputOutput{.path_to_convert_ = "~/..",
+                                .home_dir_ = "/x/y/z",
                                 .expected_ = "/x/y"},
-                    InputOutput{.home_dir_ = "/x/y/z",
-                                .path_to_convert_ = "~/k/../../t/./q",
+                    InputOutput{.path_to_convert_ = "~/k/../../t/./q",
+                                .home_dir_ = "/x/y/z",
                                 .expected_ = "/x/y/t/q"}));
 
 }  // namespace cuttlefish
diff --git a/common/libs/utils/flag_parser.cpp b/common/libs/utils/flag_parser.cpp
index 9e1c975f5..6b6f51638 100644
--- a/common/libs/utils/flag_parser.cpp
+++ b/common/libs/utils/flag_parser.cpp
@@ -402,6 +402,49 @@ Result<void> ConsumeFlags(const std::vector<Flag>& flags,
   return {};
 }
 
+Result<void> ConsumeFlagsConstrained(const std::vector<Flag>& flags,
+                                     std::vector<std::string>& args) {
+  while (!args.empty()) {
+    const std::string& first_arg = args[0];
+    std::optional<std::string> next_arg;
+    if (args.size() > 1) {
+      next_arg = args[1];
+    }
+    Flag::FlagProcessResult outcome = Flag::FlagProcessResult::kFlagSkip;
+    for (const Flag& flag : flags) {
+      Flag::FlagProcessResult flag_outcome =
+          CF_EXPECT(flag.Process(first_arg, next_arg));
+      if (flag_outcome == Flag::FlagProcessResult::kFlagSkip) {
+        continue;
+      }
+      CF_EXPECTF(outcome == Flag::FlagProcessResult::kFlagSkip,
+                 "Multiple '{}' handlers", first_arg);
+      outcome = flag_outcome;
+    }
+    switch (outcome) {
+      case Flag::FlagProcessResult::kFlagSkip:
+        return {};
+      case Flag::FlagProcessResult::kFlagConsumed:
+        args.erase(args.begin());
+        break;
+      case Flag::FlagProcessResult::kFlagConsumedWithFollowing:
+        args.erase(args.begin(), args.begin() + 2);
+        break;
+      case Flag::FlagProcessResult::kFlagConsumedOnlyFollowing:
+        args.erase(args.begin() + 1, args.begin() + 2);
+        break;
+    }
+  }
+  return {};
+}
+
+Result<void> ConsumeFlagsConstrained(const std::vector<Flag>& flags,
+                                     std::vector<std::string>&& args) {
+  std::vector<std::string>& args_ref = args;
+  CF_EXPECT(ConsumeFlagsConstrained(flags, args_ref));
+  return {};
+}
+
 bool WriteGflagsCompatXml(const std::vector<Flag>& flags, std::ostream& out) {
   for (const auto& flag : flags) {
     if (!flag.WriteGflagsCompatXml(out)) {
diff --git a/common/libs/utils/flag_parser.h b/common/libs/utils/flag_parser.h
index b47b6f97c..0c527843e 100644
--- a/common/libs/utils/flag_parser.h
+++ b/common/libs/utils/flag_parser.h
@@ -120,6 +120,9 @@ class Flag {
   friend Flag InvalidFlagGuard();
   friend Flag UnexpectedArgumentGuard();
 
+  friend Result<void> ConsumeFlagsConstrained(const std::vector<Flag>& flags,
+                                              std::vector<std::string>&);
+
   std::vector<FlagAlias> aliases_;
   std::optional<std::string> help_;
   std::optional<std::function<std::string()>> getter_;
@@ -142,6 +145,14 @@ Result<void> ConsumeFlags(const std::vector<Flag>& flags,
                           std::vector<std::string>&&,
                           const bool recognize_end_of_option_mark = false);
 
+/* Handles a list of flags. Arguments are handled from the beginning. When an
+ * unrecognized argument is encountered, parsing stops. At most one flag matcher
+ * can handle a particular argument. */
+Result<void> ConsumeFlagsConstrained(const std::vector<Flag>& flags,
+                                     std::vector<std::string>&);
+Result<void> ConsumeFlagsConstrained(const std::vector<Flag>& flags,
+                                     std::vector<std::string>&&);
+
 bool WriteGflagsCompatXml(const std::vector<Flag>&, std::ostream&);
 
 /* If -verbosity or --verbosity flags have a value, translates it to an android
diff --git a/common/libs/utils/flag_parser_test.cpp b/common/libs/utils/flag_parser_test.cpp
index f4a83beaa..77d552240 100644
--- a/common/libs/utils/flag_parser_test.cpp
+++ b/common/libs/utils/flag_parser_test.cpp
@@ -400,6 +400,34 @@ TEST(FlagParser, EndOfOptionMark) {
   ASSERT_TRUE(flag);
 }
 
+TEST(FlagParser, ConsumesConstrainedEquals) {
+  std::vector<std::string> args{"--name=abc", "status", "--name=def"};
+
+  std::string name;
+  Flag name_flag = GflagsCompatFlag("name", name);
+
+  std::vector<Flag> flags = {name_flag};
+  EXPECT_THAT(ConsumeFlagsConstrained(flags, args), IsOk());
+
+  std::vector<std::string> expected_args = {"status", "--name=def"};
+  EXPECT_EQ(args, expected_args);
+  EXPECT_EQ(name, "abc");
+}
+
+TEST(FlagParser, ConsumesConstrainedSeparated) {
+  std::vector<std::string> args{"--name", "abc", "status", "--name", "def"};
+
+  std::string name;
+  Flag name_flag = GflagsCompatFlag("name", name);
+
+  std::vector<Flag> flags = {name_flag};
+  EXPECT_THAT(ConsumeFlagsConstrained(flags, args), IsOk());
+
+  std::vector<std::string> expected_args = {"status", "--name", "def"};
+  EXPECT_EQ(args, expected_args);
+  EXPECT_EQ(name, "abc");
+}
+
 class FlagConsumesArbitraryTest : public ::testing::Test {
  protected:
   void SetUp() override {
diff --git a/common/libs/utils/json.h b/common/libs/utils/json.h
index d2f62d89e..876d8471b 100644
--- a/common/libs/utils/json.h
+++ b/common/libs/utils/json.h
@@ -32,25 +32,28 @@ Result<Json::Value> LoadFromFile(SharedFD json_fd);
 Result<Json::Value> LoadFromFile(const std::string& path_to_file);
 
 template <typename T>
-T As(const Json::Value& v);
+Result<T> As(const Json::Value& v);
 
 template <>
-inline int As(const Json::Value& v) {
+inline Result<int> As(const Json::Value& v) {
+  CF_EXPECT(v.isInt());
   return v.asInt();
 }
 
 template <>
-inline std::string As(const Json::Value& v) {
+inline Result<std::string> As(const Json::Value& v) {
+  CF_EXPECT(v.isString());
   return v.asString();
 }
 
 template <>
-inline bool As(const Json::Value& v) {
+inline Result<bool> As(const Json::Value& v) {
+  CF_EXPECT(v.isBool());
   return v.asBool();
 }
 
 template <>
-inline Json::Value As(const Json::Value& v) {
+inline Result<Json::Value> As(const Json::Value& v) {
   return v;
 }
 
@@ -63,7 +66,7 @@ Result<T> GetValue(const Json::Value& root,
                "JSON selector \"{}\" does not exist", selector);
     traversal = &(*traversal)[selector];
   }
-  return As<T>(*traversal);
+  return CF_EXPECT(As<T>(*traversal));
 }
 
 template <typename T>
diff --git a/common/libs/utils/known_paths.cpp b/common/libs/utils/known_paths.cpp
new file mode 100644
index 000000000..795940de8
--- /dev/null
+++ b/common/libs/utils/known_paths.cpp
@@ -0,0 +1,27 @@
+/*
+ * Copyright (C) 2018 The Android Open Source Project
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
+#include "common/libs/utils/known_paths.h"
+
+#include "common/libs/utils/environment.h"
+
+#include <string>
+
+namespace cuttlefish {
+
+std::string TempDir() { return StringFromEnv("TMPDIR", "/tmp"); }
+
+}  // namespace cuttlefish
diff --git a/host/commands/process_sandboxer/unique_fd.h b/common/libs/utils/known_paths.h
similarity index 55%
rename from host/commands/process_sandboxer/unique_fd.h
rename to common/libs/utils/known_paths.h
index b923db452..38a6e0c95 100644
--- a/host/commands/process_sandboxer/unique_fd.h
+++ b/common/libs/utils/known_paths.h
@@ -13,32 +13,12 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-#ifndef ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_UNIQUE_FD_H
-#define ANDROID_DEVICE_GOOGLE_CUTTLEFISH_HOST_COMMANDS_PROCESS_SANDBOXER_UNIQUE_FD_H
+#pragma once
 
-namespace cuttlefish {
-namespace process_sandboxer {
-
-class UniqueFd {
- public:
-  UniqueFd() = default;
-  explicit UniqueFd(int fd);
-  UniqueFd(UniqueFd&&);
-  UniqueFd(UniqueFd&) = delete;
-  ~UniqueFd();
-  UniqueFd& operator=(UniqueFd&&);
-
-  int Get() const;
-  int Release();
-  void Reset(int fd);
+#include <string>
 
- private:
-  void Close();
+namespace cuttlefish {
 
-  int fd_ = -1;
-};
+std::string TempDir();
 
-}  // namespace process_sandboxer
 }  // namespace cuttlefish
-
-#endif
diff --git a/common/libs/utils/subprocess.cpp b/common/libs/utils/subprocess.cpp
index dd35a15c0..f0f1d4c0f 100644
--- a/common/libs/utils/subprocess.cpp
+++ b/common/libs/utils/subprocess.cpp
@@ -412,8 +412,21 @@ Subprocess Command::Start(SubprocessOptions options) const {
     return Subprocess(-1, {});
   }
 
+  for (auto& prerequisite : prerequisites_) {
+    auto prerequisiteResult = prerequisite();
+
+    if (!prerequisiteResult.ok()) {
+      LOG(ERROR) << "Failed to check prerequisites: "
+                 << prerequisiteResult.error().FormatForEnv();
+    }
+  }
+
+  // ToCharPointers allocates memory so it can't be called in the child process.
+  auto envp = ToCharPointers(env_);
   pid_t pid = fork();
   if (!pid) {
+    // LOG(...) can't be used in the child process because it may block waiting
+    // for other threads which don't exist in the child process.
 #ifdef __linux__
     if (options.ExitWithParent()) {
       prctl(PR_SET_PDEATHSIG, SIGHUP); // Die when parent dies
@@ -422,35 +435,23 @@ Subprocess Command::Start(SubprocessOptions options) const {
 
     do_redirects(redirects_);
 
-    for (auto& prerequisite : prerequisites_) {
-      auto prerequisiteResult = prerequisite();
-
-      if (!prerequisiteResult.ok()) {
-        LOG(ERROR) << "Failed to check prerequisites: "
-                   << prerequisiteResult.error().FormatForEnv();
-      }
-    }
-
     if (options.InGroup()) {
       // This call should never fail (see SETPGID(2))
       if (setpgid(0, 0) != 0) {
-        auto error = errno;
-        LOG(ERROR) << "setpgid failed (" << strerror(error) << ")";
+        exit(-errno);
       }
     }
     for (const auto& entry : inherited_fds_) {
       if (fcntl(entry.second, F_SETFD, 0)) {
-        int error_num = errno;
-        LOG(ERROR) << "fcntl failed: " << strerror(error_num);
+        exit(-errno);
       }
     }
     if (working_directory_->IsOpen()) {
       if (SharedFD::Fchdir(working_directory_) != 0) {
-        LOG(ERROR) << "Fchdir failed: " << working_directory_->StrError();
+        exit(-errno);
       }
     }
     int rval;
-    auto envp = ToCharPointers(env_);
     const char* executable = executable_ ? executable_->c_str() : cmd[0];
 #ifdef __linux__
     rval = execvpe(executable, const_cast<char* const*>(cmd.data()),
@@ -461,9 +462,7 @@ Subprocess Command::Start(SubprocessOptions options) const {
 #else
 #error "Unsupported architecture"
 #endif
-    // No need for an if: if exec worked it wouldn't have returned
-    LOG(ERROR) << "exec of " << cmd[0] << " with path \"" << executable
-               << "\" failed (" << strerror(errno) << ")";
+    // No need to check for error, execvpe/execve don't return on success.
     exit(rval);
   }
   if (pid == -1) {
@@ -483,6 +482,16 @@ Subprocess Command::Start(SubprocessOptions options) const {
   return Subprocess(pid, subprocess_stopper_);
 }
 
+std::string Command::ToString() const {
+  std::stringstream ss;
+  if (!env_.empty()) {
+    ss << android::base::Join(env_, " ");
+    ss << " ";
+  }
+  ss << android::base::Join(command_, " ");
+  return ss.str();
+}
+
 std::string Command::AsBashScript(
     const std::string& redirected_stdio_path) const {
   CHECK(inherited_fds_.empty())
diff --git a/common/libs/utils/subprocess.h b/common/libs/utils/subprocess.h
index 243b6e092..37521a126 100644
--- a/common/libs/utils/subprocess.h
+++ b/common/libs/utils/subprocess.h
@@ -304,6 +304,8 @@ class Command {
     return command_[0];
   }
 
+  std::string ToString() const;
+
   // Generates the contents for a bash script that can be used to run this
   // command. Note that this command must not require any file descriptors
   // or stdio redirects as those would not be available when the bash script
diff --git a/debian_substitution_marker b/debian_substitution_marker
new file mode 100644
index 000000000..e69de29bb
diff --git a/guest/commands/sensor_injection/main.cpp b/guest/commands/sensor_injection/main.cpp
index ccef05708..71764104f 100644
--- a/guest/commands/sensor_injection/main.cpp
+++ b/guest/commands/sensor_injection/main.cpp
@@ -32,8 +32,9 @@ using aidl::android::hardware::sensors::SensorStatus;
 using aidl::android::hardware::sensors::SensorType;
 
 std::shared_ptr<ISensors> startSensorInjection() {
-  auto sensors = ISensors::fromBinder(ndk::SpAIBinder(
-      AServiceManager_getService("android.hardware.sensors.ISensors/default")));
+  auto sensors =
+      ISensors::fromBinder(ndk::SpAIBinder(AServiceManager_checkService(
+          "android.hardware.sensors.ISensors/default")));
   CHECK(sensors != nullptr) << "Unable to get ISensors.";
 
   // Place the ISensors HAL into DATA_INJECTION mode so that we can
diff --git a/guest/hals/bluetooth/Android.bp b/guest/hals/bluetooth/Android.bp
new file mode 100644
index 000000000..4445a431b
--- /dev/null
+++ b/guest/hals/bluetooth/Android.bp
@@ -0,0 +1,53 @@
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
+rust_binary {
+    name: "android.hardware.bluetooth-service.cuttlefish",
+    relative_install_path: "hw",
+    vendor: true,
+    prefer_rlib: true,
+    rustlibs: [
+        "android.hardware.bluetooth-V1-rust",
+        "libandroid_logger",
+        "libanyhow",
+        "libargh",
+        "libbinder_rs",
+        "libbinder_tokio_rs",
+        "libbytes",
+        "liblibc",
+        "liblog_rust",
+        "libnix",
+        "libpdl_runtime",
+        "libthiserror",
+        "libtokio",
+    ],
+    proc_macros: [
+        "libasync_trait",
+    ],
+    features: ["rt"],
+    srcs: [
+        "src/main.rs",
+    ],
+}
+
+prebuilt_etc {
+    name: "android.hardware.bluetooth-service.cuttlefish.xml",
+    src: "bluetooth-service.cuttlefish.xml",
+    sub_dir: "vintf",
+    installable: false,
+}
diff --git a/guest/hals/bluetooth/OWNERS b/guest/hals/bluetooth/OWNERS
new file mode 100644
index 000000000..1c27c173c
--- /dev/null
+++ b/guest/hals/bluetooth/OWNERS
@@ -0,0 +1,3 @@
+include platform/packages/modules/Bluetooth:/OWNERS
+
+henrichataing@google.com
diff --git a/guest/hals/bluetooth/bluetooth-service.cuttlefish.xml b/guest/hals/bluetooth/bluetooth-service.cuttlefish.xml
new file mode 100644
index 000000000..4367c977f
--- /dev/null
+++ b/guest/hals/bluetooth/bluetooth-service.cuttlefish.xml
@@ -0,0 +1,7 @@
+<manifest version="1.0" type="device">
+  <hal format="aidl">
+    <name>android.hardware.bluetooth</name>
+    <version>1</version>
+    <fqname>IBluetoothHci/default</fqname>
+  </hal>
+</manifest>
diff --git a/guest/hals/bluetooth/src/hci.rs b/guest/hals/bluetooth/src/hci.rs
new file mode 100644
index 000000000..3a4275a27
--- /dev/null
+++ b/guest/hals/bluetooth/src/hci.rs
@@ -0,0 +1,285 @@
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
+//! Bluetooth HCI Service implementation.
+
+use android_hardware_bluetooth::aidl::android::hardware::bluetooth::{
+    IBluetoothHci::IBluetoothHci, IBluetoothHciCallbacks::IBluetoothHciCallbacks, Status::Status,
+};
+
+use binder::{DeathRecipient, IBinder, Interface, Strong};
+use log::{error, info, trace, warn};
+use std::fs;
+use std::io::{Read, Write};
+use std::os::fd::AsRawFd;
+use std::os::unix::fs::OpenOptionsExt;
+use std::sync::mpsc;
+use std::sync::{Arc, Mutex};
+
+#[derive(Clone, Copy, Debug)]
+enum Idc {
+    Command = 1,
+    AclData = 2,
+    ScoData = 3,
+    Event = 4,
+    IsoData = 5,
+}
+
+impl Idc {
+    const ACL_DATA: u8 = Idc::AclData as u8;
+    const SCO_DATA: u8 = Idc::ScoData as u8;
+    const EVENT: u8 = Idc::Event as u8;
+    const ISO_DATA: u8 = Idc::IsoData as u8;
+}
+
+enum ClientState {
+    Closed,
+    Opened {
+        initialized: bool,
+        callbacks: Strong<dyn IBluetoothHciCallbacks>,
+        _death_recipient: DeathRecipient,
+    },
+}
+
+struct ServiceState {
+    writer: fs::File,
+    client_state: ClientState,
+}
+
+pub struct BluetoothHci {
+    _handle: std::thread::JoinHandle<()>,
+    service_state: Arc<Mutex<ServiceState>>,
+}
+
+/// Configure a file descriptor as raw fd.
+fn make_raw(file: fs::File) -> std::io::Result<fs::File> {
+    use nix::sys::termios::*;
+    let mut attrs = tcgetattr(&file)?;
+    cfmakeraw(&mut attrs);
+    tcsetattr(&file, SetArg::TCSANOW, &attrs)?;
+    Ok(file)
+}
+
+/// Clear all data that might be left in the virtio-console
+/// device from a previous session.
+fn clear(mut file: fs::File) -> std::io::Result<fs::File> {
+    use nix::fcntl::*;
+    let mut flags = OFlag::from_bits_truncate(fcntl(file.as_raw_fd(), FcntlArg::F_GETFL)?);
+
+    // Make the input file nonblocking when checking if any data
+    // is available to read().
+    flags.insert(OFlag::O_NONBLOCK);
+    fcntl(file.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
+
+    // Drain bytes present in the file.
+    let mut data = [0; 4096];
+    loop {
+        match file.read(&mut data) {
+            // The return value 0 indicates that the file was
+            // closed remotely.
+            Ok(0) => panic!("failed to clear the serial device"),
+            Ok(size) if size == data.len() => (),
+            Ok(_) => break,
+            Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => break,
+            Err(err) => return Err(err),
+        }
+    }
+
+    // Restore the input file to blocking.
+    flags.remove(OFlag::O_NONBLOCK);
+    fcntl(file.as_raw_fd(), FcntlArg::F_SETFL(flags))?;
+
+    Ok(file)
+}
+
+impl BluetoothHci {
+    pub fn new(path: &str) -> Self {
+        // Open the serial file and configure it as raw file
+        // descriptor.
+        let mut reader = fs::OpenOptions::new()
+            .read(true)
+            .write(true)
+            .create(false)
+            .open(path)
+            .and_then(make_raw)
+            .and_then(clear)
+            .expect("failed to open the serial device");
+        let writer = reader.try_clone().expect("failed to clone serial for writing");
+
+        // Create the chip
+        let service_state =
+            Arc::new(Mutex::new(ServiceState { writer, client_state: ClientState::Closed }));
+
+        // Spawn the thread that will run the polling loop.
+        let handle = {
+            let service_state = service_state.clone();
+            std::thread::spawn(move || loop {
+                let mut data = [0; 4096];
+
+                // Read the packet idc.
+                reader.read_exact(&mut data[0..1]).unwrap();
+                let idc = data[0];
+
+                // Determine the header size.
+                let header_size = 1 + match idc {
+                    Idc::ACL_DATA => 4,
+                    Idc::SCO_DATA => 3,
+                    Idc::ISO_DATA => 4,
+                    Idc::EVENT => 2,
+                    _ => panic!("received invalid IDC bytes 0x{:02x}", idc),
+                };
+
+                // Read the packet header bytes.
+                reader.read_exact(&mut data[1..header_size]).unwrap();
+
+                // Determine the payload size.
+                let packet_size = header_size
+                    + match idc {
+                        Idc::ACL_DATA => u16::from_le_bytes([data[3], data[4]]) as usize,
+                        Idc::SCO_DATA => data[3] as usize,
+                        Idc::ISO_DATA => (u16::from_le_bytes([data[3], data[4]]) & 0x3fff) as usize,
+                        Idc::EVENT => data[2] as usize,
+                        _ => unreachable!(),
+                    };
+
+                // Read the packet payload bytes.
+                reader.read_exact(&mut data[header_size..packet_size]).unwrap();
+
+                trace!("read packet: {:?}", &data[..packet_size]);
+
+                // Forward the packet to the host stack.
+                {
+                    let mut service_state = service_state.lock().unwrap();
+                    match service_state.client_state {
+                        ClientState::Opened { ref callbacks, ref mut initialized, .. }
+                            if !*initialized =>
+                        {
+                            // While in initialization is pending, all packets are ignored except for the
+                            // HCI Reset Complete event.
+                            if matches!(
+                                &data[0..packet_size],
+                                [Idc::EVENT, 0x0e, 0x04, 0x01, 0x03, 0x0c, 0x00]
+                            ) {
+                                // The initialization of the controller is now complete,
+                                // report the status to the Host stack.
+                                callbacks.initializationComplete(Status::SUCCESS).unwrap();
+                                *initialized = true;
+                            }
+                        }
+                        ClientState::Opened { ref callbacks, .. } => match idc {
+                            Idc::ACL_DATA => callbacks.aclDataReceived(&data[1..packet_size]),
+                            Idc::SCO_DATA => callbacks.scoDataReceived(&data[1..packet_size]),
+                            Idc::ISO_DATA => callbacks.isoDataReceived(&data[1..packet_size]),
+                            Idc::EVENT => callbacks.hciEventReceived(&data[1..packet_size]),
+                            _ => unreachable!(),
+                        }
+                        .expect("failed to send HCI packet to host"),
+                        ClientState::Closed => (),
+                    }
+                }
+            })
+        };
+
+        BluetoothHci { _handle: handle, service_state }
+    }
+
+    fn send(&self, idc: Idc, data: &[u8]) -> binder::Result<()> {
+        let mut service_state = self.service_state.lock().unwrap();
+
+        if !matches!(service_state.client_state, ClientState::Opened { .. }) {
+            error!("IBluetoothHci::sendXX: not initialized");
+            return Err(binder::ExceptionCode::ILLEGAL_STATE.into());
+        }
+
+        service_state.writer.write_all(&[idc as u8]).unwrap();
+        service_state.writer.write_all(data).unwrap();
+
+        Ok(())
+    }
+}
+
+impl Interface for BluetoothHci {}
+
+impl IBluetoothHci for BluetoothHci {
+    fn initialize(&self, callbacks: &Strong<dyn IBluetoothHciCallbacks>) -> binder::Result<()> {
+        info!("IBluetoothHci::initialize");
+
+        let mut service_state = self.service_state.lock().unwrap();
+
+        if matches!(service_state.client_state, ClientState::Opened { .. }) {
+            error!("IBluetoothHci::initialize: already initialized");
+            callbacks.initializationComplete(Status::ALREADY_INITIALIZED)?;
+            return Ok(());
+        }
+
+        let mut death_recipient = {
+            let service_state = self.service_state.clone();
+            DeathRecipient::new(move || {
+                warn!("IBluetoothHci service has died");
+                let mut service_state = service_state.lock().unwrap();
+                service_state.client_state = ClientState::Closed;
+            })
+        };
+
+        callbacks.as_binder().link_to_death(&mut death_recipient)?;
+
+        service_state.client_state = ClientState::Opened {
+            initialized: false,
+            callbacks: callbacks.clone(),
+            _death_recipient: death_recipient,
+        };
+
+        // In order to emulate hardware reset of the controller,
+        // the HCI Reset command is sent from the HAL directly to clear
+        // all controller state.
+        // IBluetoothHciCallback.initializationComplete will be invoked
+        // the HCI Reset complete event is received.
+        service_state.writer.write_all(&[0x01, 0x03, 0x0c, 0x00]).unwrap();
+
+        Ok(())
+    }
+
+    fn close(&self) -> binder::Result<()> {
+        info!("IBluetoothHci::close");
+
+        let mut service_state = self.service_state.lock().unwrap();
+        service_state.client_state = ClientState::Closed;
+
+        Ok(())
+    }
+
+    fn sendAclData(&self, data: &[u8]) -> binder::Result<()> {
+        info!("IBluetoothHci::sendAclData");
+
+        self.send(Idc::AclData, data)
+    }
+
+    fn sendHciCommand(&self, data: &[u8]) -> binder::Result<()> {
+        info!("IBluetoothHci::sendHciCommand");
+
+        self.send(Idc::Command, data)
+    }
+
+    fn sendIsoData(&self, data: &[u8]) -> binder::Result<()> {
+        info!("IBluetoothHci::sendIsoData");
+
+        self.send(Idc::IsoData, data)
+    }
+
+    fn sendScoData(&self, data: &[u8]) -> binder::Result<()> {
+        info!("IBluetoothHci::sendScoData");
+
+        self.send(Idc::ScoData, data)
+    }
+}
diff --git a/guest/hals/bluetooth/src/main.rs b/guest/hals/bluetooth/src/main.rs
new file mode 100644
index 000000000..a2973a6c2
--- /dev/null
+++ b/guest/hals/bluetooth/src/main.rs
@@ -0,0 +1,63 @@
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
+//! Declared HAL services
+//!  - android.hardware.bluetooth.IBluetoothHci/default
+
+#![allow(unused_imports)]
+
+use android_hardware_bluetooth::aidl::android::hardware::bluetooth::IBluetoothHci::BnBluetoothHci;
+use binder::{self, BinderFeatures, ProcessState};
+use log::{error, info};
+
+mod hci;
+
+#[derive(argh::FromArgs, Debug)]
+/// Bluetooth HAL service.
+struct Opt {
+    #[argh(option, default = "String::from(\"/dev/hvc5\")")]
+    /// select the HCI serial device.
+    serial: String,
+}
+
+fn main() {
+    let opt: Opt = argh::from_env();
+
+    android_logger::init_once(
+        android_logger::Config::default()
+            .with_tag("bluetooth-cf")
+            .with_max_level(log::LevelFilter::Debug),
+    );
+
+    // Redirect panic messages to logcat.
+    std::panic::set_hook(Box::new(|message| {
+        error!("{}", message);
+        std::process::exit(-1);
+    }));
+
+    // Start binder thread pool with the minimum threads pool (= 1),
+    // because Bluetooth APEX is the only user of the Bluetooth Audio HAL.
+    ProcessState::set_thread_pool_max_thread_count(0);
+    ProcessState::start_thread_pool();
+
+    let hci_binder =
+        BnBluetoothHci::new_binder(hci::BluetoothHci::new(&opt.serial), BinderFeatures::default());
+
+    info!("Starting ..IBluetoothHci/default");
+    binder::add_service("android.hardware.bluetooth.IBluetoothHci/default", hci_binder.as_binder())
+        .expect("Failed to register IBluetoothHci/default service");
+
+    ProcessState::join_thread_pool();
+    info!("The Bluetooth HAL is shutting down");
+}
diff --git a/guest/hals/health/Android.bp b/guest/hals/health/Android.bp
index 704921fcd..7c6b86417 100644
--- a/guest/hals/health/Android.bp
+++ b/guest/hals/health/Android.bp
@@ -52,6 +52,7 @@ cc_binary {
     stl: "c++_static",
     proprietary: true,
     installable: false, // installed in APEX
+    vintf_fragment_modules: ["android.hardware.health-service.cuttlefish.xml"],
 }
 
 cc_binary {
@@ -59,7 +60,7 @@ cc_binary {
     defaults: ["android.hardware.health-service.cuttlefish-defaults"],
     recovery: true,
     init_rc: ["android.hardware.health-service.cuttlefish_recovery.rc"],
-    vintf_fragments: ["android.hardware.health-service.cuttlefish.xml"],
+    vintf_fragment_modules: ["android.hardware.health-service.cuttlefish.xml.recovery"],
     overrides: ["charger.recovery"],
 }
 
@@ -69,11 +70,16 @@ prebuilt_etc {
     installable: false,
 }
 
-prebuilt_etc {
+vintf_fragment {
+    name: "android.hardware.health-service.cuttlefish.xml.recovery",
+    src: "android.hardware.health-service.cuttlefish.xml",
+    recovery: true,
+}
+
+vintf_fragment {
     name: "android.hardware.health-service.cuttlefish.xml",
     src: "android.hardware.health-service.cuttlefish.xml",
-    sub_dir: "vintf",
-    installable: false,
+    vendor: true,
 }
 
 apex {
@@ -89,7 +95,6 @@ apex {
     overrides: ["charger"],
     prebuilts: [
         "android.hardware.health-service.cuttlefish.rc",
-        "android.hardware.health-service.cuttlefish.xml",
     ],
 }
 
diff --git a/guest/hals/keymint/rust/Android.bp b/guest/hals/keymint/rust/Android.bp
index 441e69f3a..dd2101271 100644
--- a/guest/hals/keymint/rust/Android.bp
+++ b/guest/hals/keymint/rust/Android.bp
@@ -64,35 +64,6 @@ prebuilt_etc {
     src: "android.hardware.security.secureclock-service.rust.xml",
 }
 
-prebuilt_etc {
-    name: "android.hardware.security.keymint-service.trusty.system.xml",
-    sub_dir: "vintf",
-    vendor: true,
-    src: "android.hardware.security.keymint-service.trusty.system.xml",
-}
-
-prebuilt_etc {
-    name: "android.hardware.security.sharedsecret-service.trusty.system.xml",
-    sub_dir: "vintf",
-    vendor: true,
-    src: "android.hardware.security.sharedsecret-service.trusty.system.xml",
-}
-
-prebuilt_etc {
-    name: "android.hardware.security.secureclock-service.trusty.system.xml",
-    sub_dir: "vintf",
-    vendor: true,
-    src: "android.hardware.security.secureclock-service.trusty.system.xml",
-}
-
-// permissions
-prebuilt_etc {
-    name: "android.hardware.hardware_keystore.rust-keymint.xml",
-    sub_dir: "permissions",
-    vendor: true,
-    src: "android.hardware.hardware_keystore.rust-keymint.xml",
-}
-
 apex_defaults {
     name: "com.android.hardware.keymint.rust_defaults",
     manifest: "manifest.json",
@@ -102,7 +73,7 @@ apex_defaults {
     updatable: false,
     prebuilts: [
         // permissions
-        "android.hardware.hardware_keystore.rust-keymint.xml",
+        "android.hardware.hardware_keystore.xml",
     ],
 }
 
@@ -129,8 +100,6 @@ apex {
     file_contexts: "file_contexts_trusty",
     prebuilts: [
         // vintf_fragments
-        "android.hardware.security.keymint-service.trusty.system.xml",
-        "android.hardware.security.secureclock-service.trusty.system.xml",
-        "android.hardware.security.sharedsecret-service.trusty.system.xml",
+        "android.hardware.security.keymint-service.trusty_system_vm.xml",
     ],
 }
diff --git a/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
deleted file mode 100644
index 3bef1d1ed..000000000
--- a/guest/hals/keymint/rust/android.hardware.security.keymint-service.trusty.system.xml
+++ /dev/null
@@ -1,12 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl" updatable-via-system="true">
-        <name>android.hardware.security.keymint</name>
-        <version>4</version>
-        <fqname>IKeyMintDevice/default</fqname>
-    </hal>
-    <hal format="aidl" updatable-via-system="true">
-        <name>android.hardware.security.keymint</name>
-        <version>3</version>
-        <fqname>IRemotelyProvisionedComponent/default</fqname>
-    </hal>
-</manifest>
diff --git a/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml
deleted file mode 100644
index 51e7ae5e6..000000000
--- a/guest/hals/keymint/rust/android.hardware.security.secureclock-service.trusty.system.xml
+++ /dev/null
@@ -1,6 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl" updatable-via-system="true">
-        <name>android.hardware.security.secureclock</name>
-        <fqname>ISecureClock/default</fqname>
-    </hal>
-</manifest>
diff --git a/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml b/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml
deleted file mode 100644
index 9d9185a4e..000000000
--- a/guest/hals/keymint/rust/android.hardware.security.sharedsecret-service.trusty.system.xml
+++ /dev/null
@@ -1,6 +0,0 @@
-<manifest version="1.0" type="device">
-    <hal format="aidl" updatable-via-system="true">
-        <name>android.hardware.security.sharedsecret</name>
-        <fqname>ISharedSecret/default</fqname>
-    </hal>
-</manifest>
diff --git a/guest/hals/ril/reference-libril/RefImsMedia.h b/guest/hals/ril/reference-libril/RefImsMedia.h
index 619b3211f..b8288579a 100644
--- a/guest/hals/ril/reference-libril/RefImsMedia.h
+++ b/guest/hals/ril/reference-libril/RefImsMedia.h
@@ -15,8 +15,11 @@
  */
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioImsMedia.h>
 #include <libradiocompat/RadioImsMediaSession.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/RefRadioConfig.h b/guest/hals/ril/reference-libril/RefRadioConfig.h
index fe2973d2c..1bab50557 100644
--- a/guest/hals/ril/reference-libril/RefRadioConfig.h
+++ b/guest/hals/ril/reference-libril/RefRadioConfig.h
@@ -16,7 +16,10 @@
 
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioConfig.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/RefRadioIms.h b/guest/hals/ril/reference-libril/RefRadioIms.h
index 32029716e..d3d4e72f4 100644
--- a/guest/hals/ril/reference-libril/RefRadioIms.h
+++ b/guest/hals/ril/reference-libril/RefRadioIms.h
@@ -15,7 +15,10 @@
  */
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioIms.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/RefRadioModem.h b/guest/hals/ril/reference-libril/RefRadioModem.h
index a0a20b1d0..b9362069b 100644
--- a/guest/hals/ril/reference-libril/RefRadioModem.h
+++ b/guest/hals/ril/reference-libril/RefRadioModem.h
@@ -16,7 +16,10 @@
 
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioModem.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/RefRadioNetwork.h b/guest/hals/ril/reference-libril/RefRadioNetwork.h
index caf4e5e95..e6fd2f010 100644
--- a/guest/hals/ril/reference-libril/RefRadioNetwork.h
+++ b/guest/hals/ril/reference-libril/RefRadioNetwork.h
@@ -15,7 +15,10 @@
  */
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioNetwork.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/RefRadioSim.h b/guest/hals/ril/reference-libril/RefRadioSim.h
index 560863972..d3be05aaa 100644
--- a/guest/hals/ril/reference-libril/RefRadioSim.h
+++ b/guest/hals/ril/reference-libril/RefRadioSim.h
@@ -16,7 +16,10 @@
 
 #pragma once
 
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <libradiocompat/RadioSim.h>
+#pragma clang diagnostic pop
 
 namespace cf::ril {
 
diff --git a/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml b/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
index 5409b9bf8..ed7339004 100644
--- a/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
+++ b/guest/hals/ril/reference-libril/android.hardware.radio@2.1.xml
@@ -1,42 +1,42 @@
 <manifest version="1.0" type="device">
     <hal format="aidl">
         <name>android.hardware.radio.config</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioConfig/default</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.data</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioData/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.ims</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IRadioIms/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.ims.media</name>
-        <version>3</version>
+        <version>4</version>
         <fqname>IImsMedia/default</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.messaging</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioMessaging/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.modem</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioModem/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.network</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioNetwork/slot1</fqname>
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.sim</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioSim/slot1</fqname>
     </hal>
     <hal format="aidl">
@@ -45,7 +45,7 @@
     </hal>
     <hal format="aidl">
         <name>android.hardware.radio.voice</name>
-        <version>4</version>
+        <version>5</version>
         <fqname>IRadioVoice/slot1</fqname>
     </hal>
 </manifest>
diff --git a/guest/hals/ril/reference-libril/rilSocketQueue.h b/guest/hals/ril/reference-libril/rilSocketQueue.h
index eaa515526..2f06bc687 100644
--- a/guest/hals/ril/reference-libril/rilSocketQueue.h
+++ b/guest/hals/ril/reference-libril/rilSocketQueue.h
@@ -19,8 +19,6 @@
 #include <hardware/ril/librilutils/proto/sap-api.pb.h>
 #include <utils/Log.h>
 
-using namespace std;
-
 /**
  * Template queue class to handling requests for a rild socket.
  * <p>
diff --git a/guest/hals/ril/reference-libril/ril_config.cpp b/guest/hals/ril/reference-libril/ril_config.cpp
index eef106868..a5c5f3513 100644
--- a/guest/hals/ril/reference-libril/ril_config.cpp
+++ b/guest/hals/ril/reference-libril/ril_config.cpp
@@ -22,12 +22,16 @@
 #include <android-base/logging.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <android/hardware/radio/config/1.1/IRadioConfig.h>
 #include <android/hardware/radio/config/1.2/IRadioConfigIndication.h>
 #include <android/hardware/radio/config/1.2/IRadioConfigResponse.h>
 #include <android/hardware/radio/config/1.3/IRadioConfig.h>
 #include <android/hardware/radio/config/1.3/IRadioConfigResponse.h>
 #include <libradiocompat/RadioConfig.h>
+#pragma clang diagnostic pop
 
 #include <ril.h>
 #include <guest/hals/ril/reference-libril/ril_service.h>
@@ -50,7 +54,7 @@ RIL_RadioFunctions *s_vendorFunctions_config = NULL;
 static CommandInfo *s_configCommands;
 struct RadioConfigImpl;
 sp<RadioConfigImpl> radioConfigService;
-volatile int32_t mCounterRadioConfig;
+std::atomic_int32_t mCounterRadioConfig;
 
 #if defined (ANDROID_MULTI_SIM)
 #define RIL_UNSOL_RESPONSE(a, b, c, d) RIL_onUnsolicitedResponse((a), (b), (c), (d))
@@ -308,7 +312,7 @@ void checkReturnStatus(Return<void>& ret) {
         // Caller should already hold rdlock, release that first
         // note the current counter to avoid overwriting updates made by another thread before
         // write lock is acquired.
-        int counter = mCounterRadioConfig;
+        int32_t counter = mCounterRadioConfig.load();
         pthread_rwlock_t *radioServiceRwlockPtr = radio_1_6::getRadioServiceRwlock(0);
         int ret = pthread_rwlock_unlock(radioServiceRwlockPtr);
         CHECK_EQ(ret, 0);
diff --git a/guest/hals/ril/reference-libril/ril_service.cpp b/guest/hals/ril/reference-libril/ril_service.cpp
index 5deb88c99..9b01b740b 100644
--- a/guest/hals/ril/reference-libril/ril_service.cpp
+++ b/guest/hals/ril/reference-libril/ril_service.cpp
@@ -25,10 +25,14 @@
 #include <android-base/logging.h>
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <android/hardware/radio/1.6/IRadio.h>
 #include <android/hardware/radio/1.6/IRadioIndication.h>
 #include <android/hardware/radio/1.6/IRadioResponse.h>
 #include <android/hardware/radio/1.6/types.h>
+#include <android/hardware/radio/deprecated/1.0/IOemHook.h>
 #include <libradiocompat/CallbackManager.h>
 #include <libradiocompat/RadioData.h>
 #include <libradiocompat/RadioIms.h>
@@ -37,8 +41,7 @@
 #include <libradiocompat/RadioModem.h>
 #include <libradiocompat/RadioSim.h>
 #include <libradiocompat/RadioVoice.h>
-
-#include <android/hardware/radio/deprecated/1.0/IOemHook.h>
+#pragma clang diagnostic pop
 
 #include <hwbinder/IPCThreadState.h>
 #include <hwbinder/ProcessState.h>
@@ -105,15 +108,15 @@ sp<RadioImpl_1_6> radioService[SIM_COUNT];
 sp<OemHookImpl> oemHookService[SIM_COUNT];
 int64_t nitzTimeReceived[SIM_COUNT];
 // counter used for synchronization. It is incremented every time response callbacks are updated.
-volatile int32_t mCounterRadio[SIM_COUNT];
-volatile int32_t mCounterOemHook[SIM_COUNT];
+std::atomic_int32_t mCounterRadio[SIM_COUNT];
+std::atomic_int32_t mCounterOemHook[SIM_COUNT];
 #else
 sp<RadioImpl_1_6> radioService[1];
 sp<OemHookImpl> oemHookService[1];
 int64_t nitzTimeReceived[1];
 // counter used for synchronization. It is incremented every time response callbacks are updated.
-volatile int32_t mCounterRadio[1];
-volatile int32_t mCounterOemHook[1];
+std::atomic_int32_t mCounterRadio[1];
+std::atomic_int32_t mCounterOemHook[1];
 hidl_vec<uint8_t> osAppIdVec;
 #endif
 
@@ -991,7 +994,8 @@ void checkReturnStatus(int32_t slotId, Return<void>& ret, bool isRadioService) {
         // Caller should already hold rdlock, release that first
         // note the current counter to avoid overwriting updates made by another thread before
         // write lock is acquired.
-        int counter = isRadioService ? mCounterRadio[slotId] : mCounterOemHook[slotId];
+        auto counter =
+                isRadioService ? mCounterRadio[slotId].load() : mCounterOemHook[slotId].load();
         pthread_rwlock_t *radioServiceRwlockPtr = radio_1_6::getRadioServiceRwlock(slotId);
         int ret = pthread_rwlock_unlock(radioServiceRwlockPtr);
         CHECK_EQ(ret, 0);
@@ -1035,6 +1039,64 @@ void checkReturnStatus(int32_t slotId, Return<void>& ret, bool isRadioService) {
     }
 }
 
+// Function to verify if the channels are valid for any of the given bands
+bool areEutranChannelsInsideBands(const RIL_EutranBands bands[], const uint32_t bands_length,
+                                  const uint32_t channels[], const uint32_t channels_length) {
+    // Map values:{band,{ndl_min, ndl_max}}
+    // Values from ETSI TS 136 101 V17.6.0 Table 5.7.3-1
+    std::unordered_map<int, std::pair<uint32_t, uint32_t>> band_info = {
+            {1, {0, 599}},        {2, {600, 1199}},     {3, {1200, 1949}},    {4, {1950, 2399}},
+            {5, {2400, 2649}},    {6, {2650, 2749}},    {7, {2750, 3449}},    {8, {3450, 3799}},
+            {9, {3800, 4149}},    {10, {4150, 4749}},   {11, {4750, 4949}},   {12, {5010, 5179}},
+            {13, {5180, 5279}},   {14, {5280, 5379}},   {17, {5730, 5849}},   {18, {5850, 5999}},
+            {19, {6000, 6149}},   {20, {6150, 6449}},   {21, {6450, 6599}},   {22, {6600, 7399}},
+            {23, {7500, 7699}},   {24, {7700, 8039}},   {25, {8040, 8689}},   {26, {8690, 9039}},
+            {27, {9040, 9209}},   {28, {9210, 9659}},   {29, {9660, 9769}},   {30, {9770, 9869}},
+            {31, {9870, 9919}},   {32, {9920, 10359}},  {33, {36000, 36199}}, {34, {36200, 36349}},
+            {35, {36350, 36949}}, {36, {36950, 37549}}, {37, {37550, 37749}}, {38, {37750, 38249}},
+            {39, {38250, 38649}}, {40, {38650, 39649}}, {41, {39650, 41589}}, {42, {41590, 43589}},
+            {43, {43590, 45589}}, {44, {45590, 46589}}, {45, {46590, 46789}}, {46, {46790, 54539}},
+            {47, {54540, 55239}}, {48, {55240, 56739}}, {49, {56740, 58239}}, {50, {58240, 59089}},
+            {51, {59090, 59139}}, {52, {59140, 60139}}, {53, {60140, 60254}}, {65, {65536, 66435}},
+            {66, {66436, 67335}}, {67, {67336, 67535}}, {68, {67536, 67835}}, {69, {67836, 68335}},
+            {70, {68336, 68585}}, {71, {68586, 68935}}, {72, {68936, 68985}}, {73, {68986, 69035}},
+            {74, {69036, 69465}}, {75, {69466, 70315}}, {76, {70316, 70365}}, {85, {70366, 70545}},
+            {87, {70546, 70595}}, {88, {70596, 70645}}, {103, {70646, 70655}}};
+
+    bool invalidValueFound = false;
+    // Check if every provided band is a valid band.
+    for (uint32_t j = 0; j < bands_length; ++j) {
+        if (band_info.find(static_cast<int>(bands[j])) == band_info.end()) {
+            RLOGE("areEutranChannelsInsideBands: band '%d' is not a valid band.", bands[j]);
+            invalidValueFound = true;
+        }
+    }
+
+    // Iterate through the channels and check if they belong to any bands.
+    for (uint32_t i = 0; i < channels_length; ++i) {
+        bool found = false;
+        for (uint32_t j = 0; j < bands_length; ++j) {
+            auto band_it = band_info.find(static_cast<int>(bands[j]));
+            if (band_info.find(static_cast<int>(bands[j])) != band_info.end() &&
+                channels[i] >= band_it->second.first && channels[i] <= band_it->second.second) {
+                found = true;
+                break;
+            }
+        }
+        if (!found) {
+            std::stringstream bands_str;
+            for (uint32_t k = 0; k < bands_length; ++k) {
+                bands_str << bands[k] << " ";
+            }
+            RLOGE("areEutranChannelsInsideBands: channel '%d' doesn't belong to any bands: '%s'",
+                  channels[i], bands_str.str().c_str());
+            invalidValueFound = true;
+        }
+    }
+
+    return !invalidValueFound;
+}
+
 void RadioImpl_1_6::checkReturnStatus(Return<void>& ret) {
     ::checkReturnStatus(mSlotId, ret, true);
 }
@@ -4324,6 +4386,7 @@ int prepareNetworkScanRequest_1_5(RIL_NetworkScanRequest_v1_5 &scan_request,
                     ras_to.bands.geran_bands[idx] =
                             static_cast<RIL_GeranBands>(geranBands[idx]);
                 }
+                // TODO(b/400453288): check that channels correspond to bands
                 break;
             }
             case V1_5::RadioAccessNetworks::UTRAN: {
@@ -4334,6 +4397,7 @@ int prepareNetworkScanRequest_1_5(RIL_NetworkScanRequest_v1_5 &scan_request,
                     ras_to.bands.utran_bands[idx] =
                             static_cast<RIL_UtranBands>(utranBands[idx]);
                 }
+                // TODO(b/400453288): check that channels correspond to bands
                 break;
             }
             case V1_5::RadioAccessNetworks::EUTRAN: {
@@ -4344,6 +4408,12 @@ int prepareNetworkScanRequest_1_5(RIL_NetworkScanRequest_v1_5 &scan_request,
                     ras_to.bands.eutran_bands[idx] =
                             static_cast<RIL_EutranBands>(eutranBands[idx]);
                 }
+                if (!areEutranChannelsInsideBands(ras_to.bands.eutran_bands, ras_to.bands_length,
+                                                  ras_to.channels, ras_to.channels_length)) {
+                    sendErrorResponse(pRI, RIL_E_INVALID_ARGUMENTS);
+                    return -1;
+                }
+
                 break;
             }
             case V1_5::RadioAccessNetworks::NGRAN: {
@@ -4354,6 +4424,7 @@ int prepareNetworkScanRequest_1_5(RIL_NetworkScanRequest_v1_5 &scan_request,
                     ras_to.bands.ngran_bands[idx] =
                             static_cast<RIL_NgranBands>(ngranBands[idx]);
                 }
+                // TODO(b/400453288): check that channels correspond to bands
                 break;
             }
             default:
@@ -4386,7 +4457,7 @@ int prepareNetworkScanRequest_1_5(RIL_NetworkScanRequest_v1_5 &scan_request,
 Return<void> RadioImpl_1_6::startNetworkScan_1_5(int32_t serial,
         const ::android::hardware::radio::V1_5::NetworkScanRequest& request) {
 #if VDBG
-    RLOGD("startNetworkScan_1_6: serial %d", serial);
+    RLOGD("startNetworkScan_1_5: serial %d", serial);
 #endif
 
     RequestInfo *pRI = android::addRequestToList(serial, mSlotId, RIL_REQUEST_START_NETWORK_SCAN);
diff --git a/guest/hals/ril/reference-libril/sap_service.cpp b/guest/hals/ril/reference-libril/sap_service.cpp
index 4689a1c1c..7caedab00 100644
--- a/guest/hals/ril/reference-libril/sap_service.cpp
+++ b/guest/hals/ril/reference-libril/sap_service.cpp
@@ -18,8 +18,12 @@
 
 #include <android/binder_manager.h>
 #include <android/binder_process.h>
+
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #include <android/hardware/radio/1.1/ISap.h>
 #include <libradiocompat/Sap.h>
+#pragma clang diagnostic pop
 
 #include <sap_service.h>
 #include "pb_decode.h"
@@ -973,7 +977,8 @@ void sap::registerService(const RIL_RadioFunctions *callbacks) {
         // use a compat shim to convert HIDL interface to AIDL and publish it
         // TODO(bug 220004469): replace with a full AIDL implementation
         static auto aidlHal = ndk::SharedRefBase::make<compat::Sap>(sapService[i]);
-        const auto instance = compat::Sap::descriptor + "/"s + std::string(serviceNames[i]);
+        const auto instance =
+                std::string(compat::Sap::descriptor) + "/" + std::string(serviceNames[i]);
         const auto status = AServiceManager_addService(aidlHal->asBinder().get(), instance.c_str());
         if (status == STATUS_OK) {
             RLOGD("registerService addService: instance %s, status %d", instance.c_str(), status);
diff --git a/guest/hals/ril/reference-ril/OWNERS b/guest/hals/ril/reference-ril/OWNERS
index 98dba3e41..0813bfb7c 100644
--- a/guest/hals/ril/reference-ril/OWNERS
+++ b/guest/hals/ril/reference-ril/OWNERS
@@ -1,9 +1,5 @@
-amitmahajan@google.com
 jackyu@google.com
 rgreenwalt@google.com
 fionaxu@google.com
-jminjie@google.com
-mpq@google.com
-shuoq@google.com
-refuhoo@google.com
+amruthr@google.com
 bohu@google.com
diff --git a/guest/hals/vehicle/VehicleService.cpp b/guest/hals/vehicle/VehicleService.cpp
index b70b421a3..c5b7a0abf 100644
--- a/guest/hals/vehicle/VehicleService.cpp
+++ b/guest/hals/vehicle/VehicleService.cpp
@@ -84,7 +84,7 @@ int main(int argc, char* argv[]) {
 
   constexpr auto maxConnectWaitTime = std::chrono::seconds(5);
   auto hardware = std::make_unique<GRPCVehicleHardware>(serverAddr);
-  if (const auto connected = hardware->waitForConnected(maxConnectWaitTime)) {
+  if (hardware->waitForConnected(maxConnectWaitTime)) {
     LOG(INFO) << "Connected to GRPC server at " << serverAddr;
   } else {
     LOG(INFO)
diff --git a/guest/hals/vehicle/apex/Android.bp b/guest/hals/vehicle/apex/Android.bp
index 4c38b9af4..434880105 100644
--- a/guest/hals/vehicle/apex/Android.bp
+++ b/guest/hals/vehicle/apex/Android.bp
@@ -41,5 +41,4 @@ apex {
     prebuilts: [
         "com.android.hardware.automotive.vehicle.cf.rc",
     ],
-    vintf_fragment_modules: ["android.hardware.automotive.vehicle@V3-cf-service.xml"],
 }
diff --git a/guest/hals/vehicle/apex/file_contexts b/guest/hals/vehicle/apex/file_contexts
index 46fb9f66a..2e35f534b 100644
--- a/guest/hals/vehicle/apex/file_contexts
+++ b/guest/hals/vehicle/apex/file_contexts
@@ -1,2 +1,3 @@
 (/.*)?	u:object_r:vendor_file:s0
+/etc(/.*)?	u:object_r:vendor_configs_file:s0
 /bin/hw/android.hardware.automotive.vehicle@V3-cf-service	u:object_r:hal_vehicle_default_exec:s0
diff --git a/guest/libs/wpa_supplicant_8_lib/Android.bp b/guest/libs/wpa_supplicant_8_lib/Android.bp
index 2187c6eb4..1f4982d9d 100644
--- a/guest/libs/wpa_supplicant_8_lib/Android.bp
+++ b/guest/libs/wpa_supplicant_8_lib/Android.bp
@@ -20,7 +20,10 @@ package {
 cc_library_static {
     name: "lib_driver_cmd_simulated_cf_bp",
     srcs: ["driver_cmd_nl80211.c"],
-    cflags: ["-DCONFIG_ANDROID_LOG"],
+    cflags: [
+        "-DCONFIG_ANDROID_LOG",
+        "-Wno-unused-parameter",
+    ],
     header_libs: [
         "wpa_supplicant_headers",
     ],
diff --git a/guest/monitoring/cuttlefish_service/proguard.flags b/guest/monitoring/cuttlefish_service/proguard.flags
index 4578c0d1b..088084609 100644
--- a/guest/monitoring/cuttlefish_service/proguard.flags
+++ b/guest/monitoring/cuttlefish_service/proguard.flags
@@ -17,13 +17,22 @@
 -keepattributes SourceFile,LineNumberTable,RuntimeVisible*Annotations,AnnotationDefault
 
 # Keep classes and methods that have the guava @VisibleForTesting annotation
--keep @com.google.common.annotations.VisibleForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.google.common.annotations.VisibleForTesting class * {
+  void <init>();
+}
 -keepclassmembers class * {
   @com.google.common.annotations.VisibleForTesting *;
 }
 
--keep public class * extends android.app.Service
--keep public class * extends android.content.BroadcastReceiver
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.app.Service {
+  void <init>();
+}
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep public class * extends android.content.BroadcastReceiver {
+  void <init>();
+}
 
 # -dontobfuscate
 -keep,allowshrinking class * { *; }
diff --git a/guest/services/trusty_security_vm_launcher/Android.bp b/guest/services/trusty_security_vm_launcher/Android.bp
index b88004fdf..812e37ae6 100644
--- a/guest/services/trusty_security_vm_launcher/Android.bp
+++ b/guest/services/trusty_security_vm_launcher/Android.bp
@@ -4,4 +4,5 @@ prebuilt_etc {
     filename: "trusty_security_vm_launcher.rc",
     relative_install_path: "init",
     system_ext_specific: true,
+    enabled: false,
 }
diff --git a/host/commands/assemble_cvd/Android.bp b/host/commands/assemble_cvd/Android.bp
index 85a52b778..0bdc366a7 100644
--- a/host/commands/assemble_cvd/Android.bp
+++ b/host/commands/assemble_cvd/Android.bp
@@ -54,7 +54,6 @@ cc_binary_host {
         "libcuttlefish_command_util",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libext2_blkid",
         "libfruit",
         "libjsoncpp",
         "libprotobuf-cpp-full",
@@ -69,7 +68,6 @@ cc_binary_host {
         "libcuttlefish_host_config_fastboot",
         "libcuttlefish_launch_cvd_proto",
         "libcuttlefish_vm_manager",
-        "libext2_uuid",
         "libgflags",
         "libgfxstream_graphics_detector_proto",
         "libimage_aggregator",
@@ -97,9 +95,6 @@ cc_binary_host {
             enabled: true,
         },
         linux: {
-            shared_libs: [
-                "libnl",
-            ],
             required: [
                 "mkuserimg_mke2fs",
             ],
@@ -107,3 +102,31 @@ cc_binary_host {
     },
     defaults: ["cuttlefish_host"],
 }
+
+cc_test_host {
+    name: "cf_assemble_tests",
+    shared_libs: [
+        "libbase",
+        "libcurl",
+        "libcuttlefish_fs",
+        "libcuttlefish_utils",
+        "libfruit",
+        "liblog",
+        "libprotobuf-cpp-full",
+    ],
+    srcs: [
+        "unittest/main_test.cc",
+        "unittest/utils_tests.cpp",
+    ],
+    static_libs: [
+        "libcuttlefish_host_config",
+        "libcuttlefish_launch_cvd_proto",
+        "libcuttlefish_msg_queue",
+        "libgflags",
+        "libgmock",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+    defaults: ["cuttlefish_host"],
+}
diff --git a/host/commands/assemble_cvd/assemble_cvd.cc b/host/commands/assemble_cvd/assemble_cvd.cc
index 0bfaea3a9..0a99ea01c 100644
--- a/host/commands/assemble_cvd/assemble_cvd.cc
+++ b/host/commands/assemble_cvd/assemble_cvd.cc
@@ -29,6 +29,7 @@
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
 #include "common/libs/utils/in_sandbox.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/tee_logging.h"
 #include "host/commands/assemble_cvd/clean.h"
 #include "host/commands/assemble_cvd/disk_flags.h"
@@ -454,9 +455,8 @@ Result<const CuttlefishConfig*> InitFilesystemAndCreateConfig(
                                       default_mode, default_group));
       CF_EXPECT(EnsureDirectoryExists(instance.PerInstanceGrpcSocketPath(""),
                                       default_mode, default_group));
-      auto vsock_dir =
-          fmt::format("/tmp/vsock_{0}_{1}", instance.vsock_guest_cid(),
-                      std::to_string(getuid()));
+      std::string vsock_dir = fmt::format("{}/vsock_{}_{}", TempDir(),
+                                          instance.vsock_guest_cid(), getuid());
       if (DirectoryExists(vsock_dir, /* follow_symlinks */ false) &&
           !IsDirectoryEmpty(vsock_dir)) {
         CF_EXPECT(RecursivelyRemoveDirectory(vsock_dir));
diff --git a/host/commands/assemble_cvd/boot_image_utils.cc b/host/commands/assemble_cvd/boot_image_utils.cc
index 27508ad3f..ff7a6518b 100644
--- a/host/commands/assemble_cvd/boot_image_utils.cc
+++ b/host/commands/assemble_cvd/boot_image_utils.cc
@@ -312,7 +312,11 @@ Result<void> RepackBootImage(const Avb& avb,
   int result = repack_cmd.Start().Wait();
   CF_EXPECT(result == 0, "Unable to run mkbootimg. Exited with status " << result);
 
-  CF_EXPECT(avb.AddHashFooter(tmp_boot_image_path, "boot", FileSize(boot_image_path)));
+  if (FileSize(tmp_boot_image_path) <= FileSize(boot_image_path)) {
+    CF_EXPECT(avb.AddHashFooter(tmp_boot_image_path, "boot", FileSize(boot_image_path)));
+  } else {
+    CF_EXPECT(avb.AddHashFooter(tmp_boot_image_path, "boot", 0));
+  }
   CF_EXPECT(DeleteTmpFileIfNotChanged(tmp_boot_image_path, new_boot_image_path));
 
   return {};
diff --git a/host/commands/assemble_cvd/disk_flags.cc b/host/commands/assemble_cvd/disk_flags.cc
index b8debb981..88b72ec55 100644
--- a/host/commands/assemble_cvd/disk_flags.cc
+++ b/host/commands/assemble_cvd/disk_flags.cc
@@ -87,8 +87,17 @@ DEFINE_string(
     "to "
     "be vbmeta_system_dlkm.img in the directory specified by "
     "-system_image_dir.");
+DEFINE_string(default_vvmtruststore_file_name,
+              CF_DEFAULTS_DEFAULT_VVMTRUSTSTORE_FILE_NAME,
+              "If the vvmtruststore_path parameter is empty then the default "
+              "file name of the vvmtruststore image in the directory specified"
+              " by -system_image_dir. If empty then there's no vvmtruststore "
+              "image assumed by default.");
 DEFINE_string(vvmtruststore_path, CF_DEFAULTS_VVMTRUSTSTORE_PATH,
-              "Location of the vvmtruststore image");
+              "Location of the vvmtruststore image. If empty and the "
+              "default_vvmtruststore_file_name parameter is not empty then the "
+              "image file is assumed to be the default_vvmtruststore_file_name "
+              "file in the directory specified by -system_image_dir.");
 
 DEFINE_string(
     default_target_zip, CF_DEFAULTS_DEFAULT_TARGET_ZIP,
@@ -188,11 +197,14 @@ Result<void> ResolveInstanceFiles() {
   std::string default_16k_kernel_image = "";
   std::string default_16k_ramdisk_image = "";
   std::string default_hibernation_image = "";
+  std::string vvmtruststore_path = "";
 
   std::string cur_system_image_dir;
   std::string comma_str = "";
   auto instance_nums =
       CF_EXPECT(InstanceNumsCalculator().FromGlobalGflags().Calculate());
+  auto default_vvmtruststore_file_name =
+      android::base::Split(FLAGS_default_vvmtruststore_file_name, ",");
   for (int instance_index = 0; instance_index < instance_nums.size(); instance_index++) {
     if (instance_index < system_image_dir.size()) {
       cur_system_image_dir = system_image_dir[instance_index];
@@ -231,6 +243,15 @@ Result<void> ResolveInstanceFiles() {
       CF_EXPECT(FileExists(ramdisk_16k),
                 ramdisk_16k + " missing for launching 16k cuttlefish");
     }
+
+    if (instance_index < default_vvmtruststore_file_name.size()) {
+      if (default_vvmtruststore_file_name[instance_index].empty()) {
+        vvmtruststore_path += comma_str;
+      } else {
+        vvmtruststore_path += comma_str + cur_system_image_dir + "/" +
+                              default_vvmtruststore_file_name[instance_index];
+      }
+    }
   }
   if (FLAGS_use_16k) {
     LOG(INFO) << "Using 16k kernel: " << default_16k_kernel_image;
@@ -271,7 +292,8 @@ Result<void> ResolveInstanceFiles() {
   SetCommandLineOptionWithMode("hibernation_image",
                                default_hibernation_image.c_str(),
                                google::FlagSettingMode::SET_FLAGS_DEFAULT);
-
+  SetCommandLineOptionWithMode("vvmtruststore_path", vvmtruststore_path.c_str(),
+                               google::FlagSettingMode::SET_FLAGS_DEFAULT);
   return {};
 }
 
diff --git a/host/commands/assemble_cvd/display.cpp b/host/commands/assemble_cvd/display.cpp
index dda983d33..5ef730849 100644
--- a/host/commands/assemble_cvd/display.cpp
+++ b/host/commands/assemble_cvd/display.cpp
@@ -104,6 +104,7 @@ class DisplaysConfigsFragmentImpl : public DisplaysConfigsFragment {
       display_config_json[kYRes] = display_configs.height;
       display_config_json[kDpi] = display_configs.dpi;
       display_config_json[kRefreshRateHz] = display_configs.refresh_rate_hz;
+      display_config_json[kOverlays] = display_configs.overlays;
       display_configs_json.append(display_config_json);
     }
     return display_configs_json;
@@ -125,6 +126,7 @@ class DisplaysConfigsFragmentImpl : public DisplaysConfigsFragment {
       display_config.dpi = display_config_json[kDpi].asInt();
       display_config.refresh_rate_hz =
           display_config_json[kRefreshRateHz].asInt();
+      display_config.overlays = display_config_json[kOverlays].asString();
       displays_configs.emplace_back(display_config);
     }
 
@@ -138,7 +140,7 @@ class DisplaysConfigsFragmentImpl : public DisplaysConfigsFragment {
   static constexpr char kYRes[] = "y_res";
   static constexpr char kDpi[] = "dpi";
   static constexpr char kRefreshRateHz[] = "refresh_rate_hz";
-
+  static constexpr char kOverlays[] = "overlays";
   DisplaysConfigs& displays_configs_;
 };
 
diff --git a/host/commands/assemble_cvd/flags.cc b/host/commands/assemble_cvd/flags.cc
index d0a81355d..74b5dc530 100644
--- a/host/commands/assemble_cvd/flags.cc
+++ b/host/commands/assemble_cvd/flags.cc
@@ -38,12 +38,16 @@
 #include <json/json.h>
 #include <json/writer.h>
 
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/base64.h"
+#include "common/libs/utils/container.h"
 #include "common/libs/utils/contains.h"
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
 #include "common/libs/utils/in_sandbox.h"
 #include "common/libs/utils/json.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/network.h"
 #include "host/commands/assemble_cvd/alloc.h"
 #include "host/commands/assemble_cvd/boot_config.h"
@@ -72,7 +76,7 @@
 
 using cuttlefish::DefaultHostArtifactsPath;
 using cuttlefish::HostBinaryPath;
-using cuttlefish::StringFromEnv;
+using cuttlefish::TempDir;
 using cuttlefish::vm_manager::CrosvmManager;
 using google::FlagSettingMode::SET_FLAGS_DEFAULT;
 using google::FlagSettingMode::SET_FLAGS_VALUE;
@@ -115,6 +119,9 @@ DEFINE_string(x_res, "0", "Width of the screen in pixels");
 DEFINE_string(y_res, "0", "Height of the screen in pixels");
 DEFINE_string(dpi, "0", "Pixels per inch for the screen");
 DEFINE_string(refresh_rate_hz, "60", "Screen refresh rate in Hertz");
+DEFINE_string(overlays, "",
+              "List of displays to overlay. Format is: 'vm_index:display_index "
+              "vm_index2:display_index2 [...]'");
 DEFINE_bool(use_16k, false, "Launch using 16k kernel");
 DEFINE_vec(kernel_path, CF_DEFAULTS_KERNEL_PATH,
               "Path to the kernel. Overrides the one from the boot image");
@@ -140,7 +147,8 @@ DEFINE_vec(vm_manager, CF_DEFAULTS_VM_MANAGER,
 DEFINE_vec(gpu_mode, CF_DEFAULTS_GPU_MODE,
            "What gpu configuration to use, one of {auto, custom, drm_virgl, "
            "gfxstream, gfxstream_guest_angle, "
-           "gfxstream_guest_angle_host_swiftshader, guest_swiftshader}");
+           "gfxstream_guest_angle_host_swiftshader, "
+           "gfxstream_guest_angle_host_lavapipe, guest_swiftshader}");
 DEFINE_vec(gpu_vhost_user_mode,
            fmt::format("{}", CF_DEFAULTS_GPU_VHOST_USER_MODE),
            "Whether or not to run the Virtio GPU worker in a separate"
@@ -164,6 +172,15 @@ DEFINE_vec(gpu_context_types, CF_DEFAULTS_GPU_CONTEXT_TYPES,
            "with --gpu_mode=custom."
            " For example \"--gpu_context_types=cross_domain:gfxstream\"");
 
+DEFINE_vec(
+    guest_hwui_renderer, CF_DEFAULTS_GUEST_HWUI_RENDERER,
+    "The default renderer that HWUI should use, one of {skiagl, skiavk}.");
+
+DEFINE_vec(guest_renderer_preload, CF_DEFAULTS_GUEST_RENDERER_PRELOAD,
+           "Whether or not Zygote renderer preload is disabled, one of {auto, "
+           "enabled, disabled}. Auto will choose whether or not to disable "
+           "based on the gpu mode and guest hwui renderer.");
+
 DEFINE_vec(
     guest_vulkan_driver, CF_DEFAULTS_GUEST_VULKAN_DRIVER,
     "Vulkan driver to use with Cuttlefish.  Android VMs require specifying "
@@ -494,6 +511,15 @@ DEFINE_vec(crosvm_use_rng, "true",
            "Controls the crosvm --no-rng flag"
            "The flag is given if crosvm_use_rng is false");
 
+DEFINE_vec(crosvm_simple_media_device, "false",
+           "Controls the crosvm --simple-media-device flag"
+           "The flag is given if crosvm_simple_media_device is true.");
+
+DEFINE_vec(crosvm_v4l2_proxy, CF_DEFAULTS_CROSVM_V4L2_PROXY,
+           "Controls the crosvm --v4l2-proxy flag"
+           "The flag is given if crosvm_v4l2_proxy is set with a valid string literal. "
+           "When this flag is set, crosvm_simple_media_device becomes ineffective.");
+
 DEFINE_vec(use_pmem, "true",
            "Make this flag false to disable pmem with crosvm");
 
@@ -521,9 +547,13 @@ DEFINE_vec(
 DEFINE_vec(vhost_user_block, CF_DEFAULTS_VHOST_USER_BLOCK ? "true" : "false",
            "(experimental) use crosvm vhost-user block device implementation ");
 
-DEFINE_string(early_tmp_dir, cuttlefish::StringFromEnv("TEMP", "/tmp"),
+DEFINE_string(early_tmp_dir, TempDir(),
               "Parent directory to use for temporary files in early startup");
 
+DEFINE_vec(enable_tap_devices, "true",
+           "TAP devices are used on linux for connecting to the network "
+           "outside the current machine.");
+
 DECLARE_string(assembly_dir);
 DECLARE_string(boot_image);
 DECLARE_string(system_image_dir);
@@ -532,6 +562,13 @@ DECLARE_string(snapshot_path);
 DEFINE_vec(vcpu_config_path, CF_DEFAULTS_VCPU_CONFIG_PATH,
            "configuration file for Virtual Cpufreq");
 
+DEFINE_string(kvm_path, "",
+              "Device node file used to create VMs. Uses a default if empty.");
+
+DEFINE_string(vhost_vsock_path, "",
+              "Device node file for the kernel vhost-vsock implementation. "
+              "Uses a default if empty. Ignored for QEMU.");
+
 namespace cuttlefish {
 using vm_manager::QemuManager;
 using vm_manager::Gem5Manager;
@@ -692,7 +729,14 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
           system_image_dir[instance_index] + "/android-info.txt";
     }
 
-    auto res = GetAndroidInfoConfig(instance_android_info_txt, "gfxstream");
+    auto res = GetAndroidInfoConfig(instance_android_info_txt, "device_type");
+    // If that "device_type" is not explicitly set, fall back to parse "config".
+    if (!res.ok()) {
+      res = GetAndroidInfoConfig(instance_android_info_txt, "config");
+    }
+    guest_config.device_type = ParseDeviceType(res.value_or(""));
+
+    res = GetAndroidInfoConfig(instance_android_info_txt, "gfxstream");
     guest_config.gfxstream_supported =
         res.ok() && res.value() == "supported";
 
@@ -706,6 +750,20 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
     guest_config.mouse_supported =
         res_mouse_support.ok() && res_mouse_support.value() == "supported";
 
+    auto res_custom_keyboard_config =
+        GetAndroidInfoConfig(instance_android_info_txt, "custom_keyboard");
+    if (res_custom_keyboard_config.ok()) {
+      guest_config.custom_keyboard_config =
+          DefaultHostArtifactsPath(res_custom_keyboard_config.value());
+    }
+
+    auto res_domkey_mapping_config =
+        GetAndroidInfoConfig(instance_android_info_txt, "domkey_mapping");
+    if (res_domkey_mapping_config.ok()) {
+      guest_config.domkey_mapping_config =
+          DefaultHostArtifactsPath(res_domkey_mapping_config.value());
+    }
+
     auto res_bgra_support = GetAndroidInfoConfig(instance_android_info_txt,
                                                  "supports_bgra_framebuffers");
     guest_config.supports_bgra_framebuffers =
@@ -720,6 +778,21 @@ Result<std::vector<GuestConfig>> ReadGuestConfig() {
     guest_config.prefer_drm_virgl_when_supported =
         res_prefer_drm_virgl_when_supported.value_or("") == "true";
 
+    auto res_ti50_emulator =
+        GetAndroidInfoConfig(instance_android_info_txt, "ti50_emulator");
+    guest_config.ti50_emulator = res_ti50_emulator.value_or("");
+    auto res_output_audio_streams_count = GetAndroidInfoConfig(
+        instance_android_info_txt, "output_audio_streams_count");
+    if (res_output_audio_streams_count.ok()) {
+      std::string output_audio_streams_count_str =
+          res_output_audio_streams_count.value();
+      CF_EXPECT(
+          android::base::ParseInt(output_audio_streams_count_str.c_str(),
+                                  &guest_config.output_audio_streams_count),
+          "Failed to parse value \"" << output_audio_streams_count_str
+                                     << "\" for output audio stream count");
+    }
+
     guest_configs.push_back(guest_config);
   }
   return guest_configs;
@@ -744,9 +817,10 @@ Result<ProtoType> ParseBinProtoFlagHelper(const std::string& flag_value,
   std::vector<uint8_t> output;
   CF_EXPECT(DecodeBase64(flag_value, &output));
   std::string serialized = std::string(output.begin(), output.end());
-
+  bool result = proto_result.ParseFromString(serialized);
   CF_EXPECT(proto_result.ParseFromString(serialized),
-            "Failed to parse binary proto, flag: "<< flag_name << ", value: " << flag_value);
+            "Failed to parse binary proto, flag: " << flag_name << ", value: "
+                                                   << flag_value);
   return proto_result;
 }
 
@@ -756,10 +830,12 @@ Result<std::vector<std::vector<CuttlefishConfig::DisplayConfig>>>
   ParseBinProtoFlagHelper<InstancesDisplays>(FLAGS_displays_binproto, "displays_binproto") : \
   ParseTextProtoFlagHelper<InstancesDisplays>(FLAGS_displays_textproto, "displays_textproto");
 
+  InstancesDisplays display_proto = CF_EXPECT(std::move(proto_result));
+
   std::vector<std::vector<CuttlefishConfig::DisplayConfig>> result;
-  for (int i=0; i<proto_result->instances_size(); i++) {
+  for (int i = 0; i < display_proto.instances_size(); i++) {
     std::vector<CuttlefishConfig::DisplayConfig> display_configs;
-    const InstanceDisplays& launch_cvd_instance = proto_result->instances(i);
+    const InstanceDisplays& launch_cvd_instance = display_proto.instances(i);
     for (int display_num=0; display_num<launch_cvd_instance.displays_size(); display_num++) {
       const InstanceDisplay& display = launch_cvd_instance.displays(display_num);
 
@@ -774,15 +850,26 @@ Result<std::vector<std::vector<CuttlefishConfig::DisplayConfig>>>
         display_refresh_rate_hz = display.refresh_rate_hertz();
       }
 
-      display_configs.push_back(CuttlefishConfig::DisplayConfig{
-        .width = display.width(),
-        .height = display.height(),
-        .dpi = display_dpi,
-        .refresh_rate_hz = display_refresh_rate_hz,
-        });
+      std::string overlays = "";
+
+      for (const auto& overlay : display.overlays()) {
+        overlays +=
+            fmt::format("{}:{} ", overlay.vm_index(), overlay.display_index());
+      }
+
+      auto dc = CuttlefishConfig::DisplayConfig{
+          .width = display.width(),
+          .height = display.height(),
+          .dpi = display_dpi,
+          .refresh_rate_hz = display_refresh_rate_hz,
+          .overlays = overlays,
+      };
+
+      display_configs.push_back(dc);
     }
     result.push_back(display_configs);
   }
+
   return result;
 }
 
@@ -973,7 +1060,8 @@ Result<void> CheckSnapshotCompatible(
 }
 
 std::optional<std::string> EnvironmentUdsDir() {
-  auto environments_uds_dir = "/tmp/cf_env_" + std::to_string(getuid());
+  std::string environments_uds_dir =
+      fmt::format("{}/cf_env_{}", TempDir(), getuid());
   if (DirectoryExists(environments_uds_dir) &&
       !CanAccess(environments_uds_dir, R_OK | W_OK | X_OK)) {
     return std::nullopt;
@@ -982,7 +1070,8 @@ std::optional<std::string> EnvironmentUdsDir() {
 }
 
 std::optional<std::string> InstancesUdsDir() {
-  auto instances_uds_dir = "/tmp/cf_avd_" + std::to_string(getuid());
+  std::string instances_uds_dir =
+      fmt::format("{}/cf_avd_{}", TempDir(), getuid());
   if (DirectoryExists(instances_uds_dir) &&
       !CanAccess(instances_uds_dir, R_OK | W_OK | X_OK)) {
     return std::nullopt;
@@ -990,6 +1079,20 @@ std::optional<std::string> InstancesUdsDir() {
   return instances_uds_dir;
 }
 
+std::string DefaultBootloaderArchDir(Arch arch) {
+  switch (arch) {
+    case Arch::Arm64:
+      return "aarch64";
+    case Arch::Arm:
+      return "arm";
+    case Arch::RiscV64:
+      return "riscv64";
+    case Arch::X86:
+    case Arch::X86_64:
+      return "x86_64";
+  }
+}
+
 } // namespace
 
 Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
@@ -1142,6 +1245,8 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   std::vector<int> dpi_vec = CF_EXPECT(GET_FLAG_INT_VALUE(dpi));
   std::vector<int> refresh_rate_hz_vec = CF_EXPECT(GET_FLAG_INT_VALUE(
       refresh_rate_hz));
+  std::vector<std::string> overlays_vec =
+      CF_EXPECT(GET_FLAG_STR_VALUE(overlays));
   std::vector<int> memory_mb_vec = CF_EXPECT(GET_FLAG_INT_VALUE(memory_mb));
   std::vector<int> camera_server_port_vec = CF_EXPECT(GET_FLAG_INT_VALUE(
       camera_server_port));
@@ -1227,6 +1332,10 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
       CF_EXPECT(GET_FLAG_STR_VALUE(gpu_renderer_features));
   std::vector<std::string> gpu_context_types_vec =
       CF_EXPECT(GET_FLAG_STR_VALUE(gpu_context_types));
+  std::vector<std::string> guest_hwui_renderer_vec =
+      CF_EXPECT(GET_FLAG_STR_VALUE(guest_hwui_renderer));
+  std::vector<std::string> guest_renderer_preload_vec =
+      CF_EXPECT(GET_FLAG_STR_VALUE(guest_renderer_preload));
   std::vector<std::string> guest_vulkan_driver_vec =
       CF_EXPECT(GET_FLAG_STR_VALUE(guest_vulkan_driver));
   std::vector<std::string> frames_socket_path_vec =
@@ -1266,6 +1375,10 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
       CF_EXPECT(GET_FLAG_BOOL_VALUE(crosvm_use_balloon));
   std::vector<bool> use_rng_vec =
       CF_EXPECT(GET_FLAG_BOOL_VALUE(crosvm_use_rng));
+  std::vector<bool> simple_media_device_vec =
+      CF_EXPECT(GET_FLAG_BOOL_VALUE(crosvm_simple_media_device));
+  std::vector<std::string> v4l2_proxy_vec =
+      CF_EXPECT(GET_FLAG_STR_VALUE(crosvm_v4l2_proxy));
   std::vector<bool> use_pmem_vec = CF_EXPECT(GET_FLAG_BOOL_VALUE(use_pmem));
   const bool restore_from_snapshot = !std::string(FLAGS_snapshot_path).empty();
   std::vector<std::string> device_external_network_vec =
@@ -1281,6 +1394,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   std::vector<std::string> vcpu_config_vec =
       CF_EXPECT(GET_FLAG_STR_VALUE(vcpu_config_path));
 
+  std::vector<bool> enable_tap_devices_vec =
+      CF_EXPECT(GET_FLAG_BOOL_VALUE(enable_tap_devices));
+
   std::string default_enable_sandbox = "";
   std::string default_enable_virtiofs = "";
   std::string comma_str = "";
@@ -1356,6 +1472,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
              << (FLAGS_enable_vhal_proxy_server &&
                  vhal_proxy_server_instance_num <= 0);
 
+  tmp_config_obj.set_kvm_path(FLAGS_kvm_path);
+  tmp_config_obj.set_vhost_vsock_path(FLAGS_vhost_vsock_path);
+
   // Environment specific configs
   // Currently just setting for the default environment
   auto environment_name =
@@ -1364,6 +1483,8 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
   auto env_config = const_cast<const CuttlefishConfig&>(tmp_config_obj)
                         .ForEnvironment(environment_name);
 
+  mutable_env_config.set_group_uuid(std::time(0));
+
   mutable_env_config.set_enable_wifi(FLAGS_enable_wifi);
 
   mutable_env_config.set_vhost_user_mac80211_hwsim(
@@ -1420,9 +1541,19 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 
     instance.set_crosvm_use_balloon(use_balloon_vec[instance_index]);
     instance.set_crosvm_use_rng(use_rng_vec[instance_index]);
+    instance.set_crosvm_simple_media_device(simple_media_device_vec[instance_index]);
+    instance.set_crosvm_v4l2_proxy(v4l2_proxy_vec[instance_index]);
     instance.set_use_pmem(use_pmem_vec[instance_index]);
     instance.set_bootconfig_supported(guest_configs[instance_index].bootconfig_supported);
     instance.set_enable_mouse(guest_configs[instance_index].mouse_supported);
+    if (guest_configs[instance_index].custom_keyboard_config.has_value()) {
+      instance.set_custom_keyboard_config(
+          guest_configs[instance_index].custom_keyboard_config.value());
+    }
+    if (guest_configs[instance_index].domkey_mapping_config.has_value()) {
+      instance.set_domkey_mapping_config(
+          guest_configs[instance_index].domkey_mapping_config.value());
+    }
     instance.set_filename_encryption_mode(
       guest_configs[instance_index].hctr2_supported ? "hctr2" : "cts");
     instance.set_use_allocd(use_allocd_vec[instance_index]);
@@ -1460,6 +1591,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 
     // end of wifi, bluetooth, Thread, connectivity setup
 
+    instance.set_audio_output_streams_count(
+        guest_configs[instance_index].output_audio_streams_count);
+
     if (vhost_user_vsock_vec[instance_index] == kVhostUserVsockModeAuto) {
       std::set<Arch> default_on_arch = {Arch::Arm64};
       if (guest_configs[instance_index].vhost_user_vsock) {
@@ -1520,6 +1654,7 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
               "instance_index " << instance_index << " out of boundary "
                                 << guest_configs.size());
     instance.set_target_arch(guest_configs[instance_index].target_arch);
+    instance.set_device_type(guest_configs[instance_index].device_type);
     instance.set_guest_android_version(
         guest_configs[instance_index].android_version_number);
     instance.set_console(console_vec[instance_index]);
@@ -1561,7 +1696,8 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
             .height = y_res_vec[instance_index],
             .dpi = dpi_vec[instance_index],
             .refresh_rate_hz = refresh_rate_hz_vec[instance_index],
-          });
+            .overlays = overlays_vec[instance_index],
+        });
       } else {
         LOG(WARNING)
             << "Ignoring --x_res and --y_res when --display specified.";
@@ -1649,7 +1785,9 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
         graphics_availability, gpu_mode_vec[instance_index],
         gpu_vhost_user_mode_vec[instance_index],
         gpu_renderer_features_vec[instance_index],
-        gpu_context_types_vec[instance_index], vmm_mode,
+        gpu_context_types_vec[instance_index],
+        guest_hwui_renderer_vec[instance_index],
+        guest_renderer_preload_vec[instance_index], vmm_mode,
         guest_configs[instance_index], instance));
     calculated_gpu_mode_vec[instance_index] = gpu_mode_vec[instance_index];
 
@@ -1890,6 +2028,16 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
       instance.set_vcpu_config_path(AbsolutePath(vcpu_cfg_path));
     }
 
+    if (!guest_configs[instance_index].ti50_emulator.empty()) {
+      auto ti50_emulator =
+          DefaultHostArtifactsPath(guest_configs[instance_index].ti50_emulator);
+      CF_EXPECT(FileExists(ti50_emulator),
+                "ti50 emulator binary does not exist");
+      instance.set_ti50_emulator(ti50_emulator);
+    }
+
+    instance.set_enable_tap_devices(enable_tap_devices_vec[instance_index]);
+
     instance_index++;
   }  // end of num_instances loop
 
@@ -1945,7 +2093,7 @@ Result<CuttlefishConfig> InitializeCuttlefishConfiguration(
 }
 
 Result<void> SetDefaultFlagsForQemu(
-    Arch target_arch,
+    const std::vector<GuestConfig>& guest_configs,
     std::map<std::string, std::string>& name_to_default_value) {
   auto instance_nums =
       CF_EXPECT(InstanceNumsCalculator().FromGlobalGflags().Calculate());
@@ -1956,25 +2104,47 @@ Result<void> SetDefaultFlagsForQemu(
       CF_EXPECT(GET_FLAG_BOOL_VALUE(start_webrtc));
   std::vector<std::string> system_image_dir =
       CF_EXPECT(GET_FLAG_STR_VALUE(system_image_dir));
+  std::string curr_bootloader = "";
   std::string curr_android_efi_loader = "";
+  std::string default_bootloader = "";
   std::string default_android_efi_loader = "";
   std::string default_start_webrtc = "";
 
   for (int instance_index = 0; instance_index < instance_nums.size();
        instance_index++) {
     if (instance_index >= system_image_dir.size()) {
+      curr_bootloader = system_image_dir[0];
       curr_android_efi_loader = system_image_dir[0];
     } else {
+      curr_bootloader = system_image_dir[instance_index];
       curr_android_efi_loader = system_image_dir[instance_index];
     }
+    curr_bootloader += "/bootloader";
     curr_android_efi_loader += "/android_efi_loader.efi";
 
+    // /bootloader isn't presented in the output folder by default and can be
+    // only fetched by --bootloader in fetch_cvd, so pick it only in case
+    // it's presented.
+    if (!FileExists(curr_bootloader)) {
+      // Fallback to default bootloader
+      curr_bootloader = DefaultHostArtifactsPath(std::format(
+          "etc/bootloader_{}/bootloader.qemu",
+          DefaultBootloaderArchDir(guest_configs[instance_index].target_arch)));
+    }
+
     if (instance_index > 0) {
+      default_bootloader += ",";
       default_android_efi_loader += ",";
       default_start_webrtc += ",";
     }
 
-    default_android_efi_loader += curr_android_efi_loader;
+    default_bootloader += curr_bootloader;
+    // EFI loader isn't presented in the output folder by default and can be
+    // only fetched by --uefi_app_build in fetch_cvd, so pick it only in case
+    // it's presented.
+    if (FileExists(curr_android_efi_loader)) {
+      default_android_efi_loader += curr_android_efi_loader;
+    }
     if (gpu_mode_vec[instance_index] == kGpuModeGuestSwiftshader &&
         !start_webrtc_vec[instance_index]) {
       // This makes WebRTC the default streamer unless the user requests
@@ -1991,29 +2161,11 @@ Result<void> SetDefaultFlagsForQemu(
   SetCommandLineOptionWithMode("start_webrtc", default_start_webrtc.c_str(),
                                SET_FLAGS_DEFAULT);
 
-  std::string default_bootloader = DefaultHostArtifactsPath("etc/bootloader_");
-  if (target_arch == Arch::Arm) {
-    // Bootloader is unstable >512MB RAM on 32-bit ARM
-    SetCommandLineOptionWithMode("memory_mb", "512", SET_FLAGS_VALUE);
-    default_bootloader += "arm";
-  } else if (target_arch == Arch::Arm64) {
-    default_bootloader += "aarch64";
-  } else if (target_arch == Arch::RiscV64) {
-    default_bootloader += "riscv64";
-  } else {
-    default_bootloader += "x86_64";
-  }
-  default_bootloader += "/bootloader.qemu";
   SetCommandLineOptionWithMode("bootloader", default_bootloader.c_str(),
                                SET_FLAGS_DEFAULT);
-  // EFI loader isn't presented in the output folder by default and can be only
-  // fetched by --uefi_app_build in fetch_cvd, so pick it only in case it's
-  // presented.
-  if (FileExists(default_android_efi_loader)) {
-    SetCommandLineOptionWithMode("android_efi_loader",
-                                 default_android_efi_loader.c_str(),
-                                 SET_FLAGS_DEFAULT);
-  }
+  SetCommandLineOptionWithMode("android_efi_loader",
+                               default_android_efi_loader.c_str(),
+                               SET_FLAGS_DEFAULT);
   return {};
 }
 
@@ -2036,43 +2188,46 @@ Result<void> SetDefaultFlagsForCrosvm(
   std::vector<std::string> system_image_dir =
       CF_EXPECT(GET_FLAG_STR_VALUE(system_image_dir));
   std::string curr_android_efi_loader = "";
-  std::string cur_bootloader = "";
+  std::string curr_bootloader = "";
   std::string default_android_efi_loader = "";
   std::string default_bootloader = "";
   std::string default_enable_sandbox_str = "";
   for (int instance_index = 0; instance_index < instance_nums.size();
        instance_index++) {
-    if (guest_configs[instance_index].android_version_number == "11.0.0") {
-      cur_bootloader = DefaultHostArtifactsPath("etc/bootloader_");
-      if (guest_configs[instance_index].target_arch == Arch::Arm64) {
-        cur_bootloader += "aarch64";
-      } else {
-        cur_bootloader += "x86_64";
-      }
-      cur_bootloader += "/bootloader.crosvm";
-    } else {
-      if (instance_index >= system_image_dir.size()) {
-        cur_bootloader = system_image_dir[0];
-      } else {
-        cur_bootloader = system_image_dir[instance_index];
-      }
-      cur_bootloader += "/bootloader";
-    }
     if (instance_index >= system_image_dir.size()) {
+      curr_bootloader = system_image_dir[0];
       curr_android_efi_loader = system_image_dir[0];
     } else {
+      curr_bootloader = system_image_dir[instance_index];
       curr_android_efi_loader = system_image_dir[instance_index];
     }
+    curr_bootloader += "/bootloader";
     curr_android_efi_loader += "/android_efi_loader.efi";
 
+    // /bootloader isn't presented in the output folder by default and can be
+    // only fetched by --bootloader in fetch_cvd, so pick it only in case
+    // it's presented.
+    if (!FileExists(curr_bootloader)) {
+      // Fallback to default bootloader
+      curr_bootloader = DefaultHostArtifactsPath(std::format(
+          "etc/bootloader_{}/bootloader.crosvm",
+          DefaultBootloaderArchDir(guest_configs[instance_index].target_arch)));
+    }
+
     if (instance_index > 0) {
       default_bootloader += ",";
       default_android_efi_loader += ",";
       default_enable_sandbox_str += ",";
       default_start_webrtc += ",";
     }
-    default_bootloader += cur_bootloader;
-    default_android_efi_loader += curr_android_efi_loader;
+
+    default_bootloader += curr_bootloader;
+    // EFI loader isn't presented in the output folder by default and can be
+    // only fetched by --uefi_app_build in fetch_cvd, so pick it only in case
+    // it's presented.
+    if (FileExists(curr_android_efi_loader)) {
+      default_android_efi_loader += curr_android_efi_loader;
+    }
     default_enable_sandbox_str += fmt::format("{}", default_enable_sandbox);
     if (!start_webrtc_vec[instance_index]) {
       // This makes WebRTC the default streamer unless the user requests
@@ -2086,14 +2241,9 @@ Result<void> SetDefaultFlagsForCrosvm(
   }
   SetCommandLineOptionWithMode("bootloader", default_bootloader.c_str(),
                                SET_FLAGS_DEFAULT);
-  // EFI loader isn't presented in the output folder by default and can be only
-  // fetched by --uefi_app_build in fetch_cvd, so pick it only in case it's
-  // presented.
-  if (FileExists(default_android_efi_loader)) {
-    SetCommandLineOptionWithMode("android_efi_loader",
-                                 default_android_efi_loader.c_str(),
-                                 SET_FLAGS_DEFAULT);
-  }
+  SetCommandLineOptionWithMode("android_efi_loader",
+                               default_android_efi_loader.c_str(),
+                               SET_FLAGS_DEFAULT);
   // This is the 1st place to set "start_webrtc" flag value
   SetCommandLineOptionWithMode("start_webrtc", default_start_webrtc.c_str(),
                                SET_FLAGS_DEFAULT);
@@ -2184,7 +2334,7 @@ Result<std::vector<GuestConfig>> GetGuestConfigAndSetDefaults() {
   auto name_to_default_value = CurrentFlagsToDefaultValue();
 
   if (vmm == VmmMode::kQemu) {
-    CF_EXPECT(SetDefaultFlagsForQemu(guest_configs[0].target_arch, name_to_default_value));
+    CF_EXPECT(SetDefaultFlagsForQemu(guest_configs, name_to_default_value));
   } else if (vmm == VmmMode::kCrosvm) {
     CF_EXPECT(SetDefaultFlagsForCrosvm(guest_configs, name_to_default_value));
   } else if (vmm == VmmMode::kGem5) {
@@ -2236,9 +2386,8 @@ std::string GetConfigFilePath(const CuttlefishConfig& config) {
 }
 
 std::string GetSeccompPolicyDir() {
-  static const std::string kSeccompDir = std::string("usr/share/crosvm/") +
-                                         cuttlefish::HostArchStr() +
-                                         "-linux-gnu/seccomp";
+  std::string kSeccompDir =
+      "usr/share/crosvm/" + HostArchStr() + "-linux-gnu/seccomp";
   return DefaultHostArtifactsPath(kSeccompDir);
 }
 
diff --git a/host/commands/assemble_cvd/flags.h b/host/commands/assemble_cvd/flags.h
index 8501311b8..42a01a106 100644
--- a/host/commands/assemble_cvd/flags.h
+++ b/host/commands/assemble_cvd/flags.h
@@ -30,6 +30,7 @@ namespace cuttlefish {
 
 struct GuestConfig {
   Arch target_arch;
+  DeviceType device_type;
   bool bootconfig_supported = false;
   bool hctr2_supported = false;
   std::string android_version_number;
@@ -39,6 +40,10 @@ struct GuestConfig {
   bool supports_bgra_framebuffers = false;
   bool prefer_drm_virgl_when_supported = false;
   bool mouse_supported = false;
+  std::string ti50_emulator;
+  std::optional<std::string> custom_keyboard_config;
+  std::optional<std::string> domkey_mapping_config;
+  int output_audio_streams_count = 1;
 };
 
 Result<std::vector<GuestConfig>> GetGuestConfigAndSetDefaults();
diff --git a/host/commands/assemble_cvd/flags_defaults.h b/host/commands/assemble_cvd/flags_defaults.h
index d1110bdcd..22ef2d963 100644
--- a/host/commands/assemble_cvd/flags_defaults.h
+++ b/host/commands/assemble_cvd/flags_defaults.h
@@ -65,6 +65,7 @@
 #define CF_DEFAULTS_SECCOMP_POLICY_DIR cuttlefish::GetSeccompPolicyDir()
 #define CF_DEFAULTS_ENABLE_SANDBOX false
 #define CF_DEFAULTS_ENABLE_VIRTIOFS false
+#define CF_DEFAULTS_CROSVM_V4L2_PROXY ""
 
 // Qemu default parameters
 #define CF_DEFAULTS_QEMU_BINARY_DIR cuttlefish::DefaultQemuBinaryDir()
@@ -125,6 +126,7 @@
 #define CF_DEFAULTS_VBMETA_VENDOR_DLKM_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VBMETA_SYSTEM_DLKM_IMAGE CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VENDOR_BOOT_IMAGE CF_DEFAULTS_DYNAMIC_STRING
+#define CF_DEFAULTS_DEFAULT_VVMTRUSTSTORE_FILE_NAME CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_VVMTRUSTSTORE_PATH CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_DEFAULT_TARGET_ZIP CF_DEFAULTS_DYNAMIC_STRING
 #define CF_DEFAULTS_SYSTEM_TARGET_ZIP CF_DEFAULTS_DYNAMIC_STRING
@@ -143,6 +145,8 @@
 #define CF_DEFAULTS_GPU_RENDERER_FEATURES ""
 #define CF_DEFAULTS_GPU_CONTEXT_TYPES \
   "gfxstream-vulkan:cross-domain:gfxstream-composer"
+#define CF_DEFAULTS_GUEST_HWUI_RENDERER ""
+#define CF_DEFAULTS_GUEST_RENDERER_PRELOAD "auto"
 #define CF_DEFAULTS_GUEST_VULKAN_DRIVER "ranchu"
 #define CF_DEFAULTS_FRAME_SOCKET_PATH ""
 #define CF_DEFAULTS_ENABLE_GPU_UDMABUF false
diff --git a/host/commands/assemble_cvd/graphics_flags.cc b/host/commands/assemble_cvd/graphics_flags.cc
index 995ac8484..afde3978c 100644
--- a/host/commands/assemble_cvd/graphics_flags.cc
+++ b/host/commands/assemble_cvd/graphics_flags.cc
@@ -45,6 +45,7 @@ enum class RenderingMode {
   kGfxstream,
   kGfxstreamGuestAngle,
   kGfxstreamGuestAngleHostSwiftshader,
+  kGfxstreamGuestAngleHostLavapipe,
   kVirglRenderer,
 };
 
@@ -62,6 +63,9 @@ Result<RenderingMode> GetRenderingMode(const std::string& mode) {
   if (mode == std::string(kGpuModeGfxstreamGuestAngleHostSwiftShader)) {
     return RenderingMode::kGfxstreamGuestAngleHostSwiftshader;
   }
+  if (mode == std::string(kGpuModeGfxstreamGuestAngleHostLavapipe)) {
+    return RenderingMode::kGfxstreamGuestAngleHostLavapipe;
+  }
   if (mode == std::string(kGpuModeGuestSwiftshader)) {
     return RenderingMode::kGuestSwiftShader;
   }
@@ -261,6 +265,7 @@ Result<std::string> SelectGpuMode(
       gpu_mode_arg != kGpuModeCustom && gpu_mode_arg != kGpuModeGfxstream &&
       gpu_mode_arg != kGpuModeGfxstreamGuestAngle &&
       gpu_mode_arg != kGpuModeGfxstreamGuestAngleHostSwiftShader &&
+      gpu_mode_arg != kGpuModeGfxstreamGuestAngleHostLavapipe &&
       gpu_mode_arg != kGpuModeGuestSwiftshader &&
       gpu_mode_arg != kGpuModeNone) {
     return CF_ERR("Invalid gpu_mode: " << gpu_mode_arg);
@@ -361,6 +366,30 @@ Result<bool> SelectGpuVhostUserMode(const std::string& gpu_mode,
   return gpu_vhost_user_mode_arg == kGpuVhostUserModeOn;
 }
 
+Result<GuestRendererPreload> SelectGuestRendererPreload(
+    const std::string& gpu_mode, const GuestHwuiRenderer guest_hwui_renderer,
+    const std::string& guest_renderer_preload_arg) {
+  GuestRendererPreload guest_renderer_preload =
+      GuestRendererPreload::kGuestDefault;
+
+  if (!guest_renderer_preload_arg.empty()) {
+    guest_renderer_preload =
+        CF_EXPECT(ParseGuestRendererPreload(guest_renderer_preload_arg));
+  }
+
+  if (guest_renderer_preload == GuestRendererPreload::kAuto) {
+    if (guest_hwui_renderer == GuestHwuiRenderer::kSkiaVk &&
+        (gpu_mode == kGpuModeGfxstreamGuestAngle ||
+         gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader)) {
+      LOG(INFO) << "Disabling guest renderer preload for Gfxstream based mode "
+                   "when running with SkiaVk.";
+      guest_renderer_preload = GuestRendererPreload::kDisabled;
+    }
+  }
+
+  return guest_renderer_preload;
+}
+
 #endif
 
 Result<std::string> GraphicsDetectorBinaryPath() {
@@ -559,7 +588,9 @@ Result<std::string> ConfigureGpuSettings(
     const gfxstream::proto::GraphicsAvailability& graphics_availability,
     const std::string& gpu_mode_arg, const std::string& gpu_vhost_user_mode_arg,
     const std::string& gpu_renderer_features_arg,
-    std::string& gpu_context_types_arg, VmmMode vmm,
+    std::string& gpu_context_types_arg,
+    const std::string& guest_hwui_renderer_arg,
+    const std::string& guest_renderer_preload_arg, VmmMode vmm,
     const GuestConfig& guest_config,
     CuttlefishConfig::MutableInstanceSpecific& instance) {
 #ifdef __APPLE__
@@ -584,7 +615,8 @@ Result<std::string> ConfigureGpuSettings(
 
   if (gpu_mode == kGpuModeGfxstream ||
       gpu_mode == kGpuModeGfxstreamGuestAngle ||
-      gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+      gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+      gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     CF_EXPECT(SetGfxstreamFlags(gpu_mode, gpu_renderer_features_arg,
                                 guest_config, graphics_availability, instance));
   }
@@ -616,8 +648,21 @@ Result<std::string> ConfigureGpuSettings(
     instance.set_enable_gpu_system_blob(false);
   }
 
+  GuestHwuiRenderer hwui_renderer = GuestHwuiRenderer::kUnknown;
+  if (!guest_hwui_renderer_arg.empty()) {
+    hwui_renderer = CF_EXPECT(
+        ParseGuestHwuiRenderer(guest_hwui_renderer_arg),
+        "Failed to parse HWUI renderer flag: " << guest_hwui_renderer_arg);
+  }
+  instance.set_guest_hwui_renderer(hwui_renderer);
+
+  const auto guest_renderer_preload = CF_EXPECT(SelectGuestRendererPreload(
+      gpu_mode, hwui_renderer, guest_renderer_preload_arg));
+  instance.set_guest_renderer_preload(guest_renderer_preload);
+
   instance.set_gpu_mode(gpu_mode);
   instance.set_enable_gpu_vhost_user(enable_gpu_vhost_user);
+
 #endif
 
   return gpu_mode;
diff --git a/host/commands/assemble_cvd/graphics_flags.h b/host/commands/assemble_cvd/graphics_flags.h
index f5d1ce884..f3b0d6652 100644
--- a/host/commands/assemble_cvd/graphics_flags.h
+++ b/host/commands/assemble_cvd/graphics_flags.h
@@ -33,7 +33,9 @@ Result<std::string> ConfigureGpuSettings(
     const gfxstream::proto::GraphicsAvailability& graphics_availability,
     const std::string& gpu_mode_arg, const std::string& gpu_vhost_user_mode_arg,
     const std::string& gpu_renderer_features_arg,
-    std::string& gpu_context_types_arg, VmmMode vmm,
+    std::string& gpu_context_types_arg,
+    const std::string& gpu_hwui_renderer_arg,
+    const std::string& guest_renderer_preload_arg, VmmMode vmm,
     const GuestConfig& guest_config,
     CuttlefishConfig::MutableInstanceSpecific& instance);
 
diff --git a/host/commands/assemble_cvd/proto/launch_cvd.proto b/host/commands/assemble_cvd/proto/launch_cvd.proto
index 87855e802..748d856a0 100644
--- a/host/commands/assemble_cvd/proto/launch_cvd.proto
+++ b/host/commands/assemble_cvd/proto/launch_cvd.proto
@@ -23,10 +23,15 @@ message InstanceDisplay {
   int32 height = 2;
   int32 dpi = 3;
   int32 refresh_rate_hertz = 4;
+  repeated DisplayOverlay overlays = 5;
 }
 message InstanceDisplays {
   repeated InstanceDisplay displays = 1;
 }
 message InstancesDisplays {
   repeated InstanceDisplays instances = 1;
+}
+message DisplayOverlay {
+  int32 vm_index = 1;
+  int32 display_index = 2;
 }
\ No newline at end of file
diff --git a/host/commands/assemble_cvd/unittest/main_test.cc b/host/commands/assemble_cvd/unittest/main_test.cc
new file mode 100644
index 000000000..99a6f4d74
--- /dev/null
+++ b/host/commands/assemble_cvd/unittest/main_test.cc
@@ -0,0 +1,22 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include <gtest/gtest.h>
+
+int main(int argc, char** argv) {
+  ::testing::InitGoogleTest(&argc, argv);
+  return RUN_ALL_TESTS();
+}
\ No newline at end of file
diff --git a/host/commands/assemble_cvd/unittest/utils_tests.cpp b/host/commands/assemble_cvd/unittest/utils_tests.cpp
new file mode 100644
index 000000000..2693e8d39
--- /dev/null
+++ b/host/commands/assemble_cvd/unittest/utils_tests.cpp
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include <string>
+
+#include <gtest/gtest.h>
+
+#include "common/libs/utils/base64.h"
+#include "launch_cvd.pb.h"
+
+namespace cuttlefish {
+
+TEST(DisplayConfigTest, ParseProto) {
+  std::string flag_value = "ChoKCgi4CBDYBBh4IDwKDAi4CBDYBBh4IDwqAA==";
+  // This is an encoded Display Config with zeros for integer values at end of
+  // buffer. (for overlays proto). This is implemented here to catch a corner
+  // case with truncated Base64 encodings resulting in error code when
+  // serializing.
+
+  std::vector<uint8_t> output;
+  DecodeBase64(flag_value, &output);
+  std::string serialized = std::string(output.begin(), output.end());
+
+  InstancesDisplays proto_result;
+  bool result = proto_result.ParseFromString(serialized);
+
+  EXPECT_EQ(proto_result.instances_size(), 1);
+
+  ASSERT_TRUE(result);
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/assemble_cvd/vendor_dlkm_utils.cc b/host/commands/assemble_cvd/vendor_dlkm_utils.cc
index 7f2fafec1..551f157fc 100644
--- a/host/commands/assemble_cvd/vendor_dlkm_utils.cc
+++ b/host/commands/assemble_cvd/vendor_dlkm_utils.cc
@@ -74,8 +74,8 @@ bool WriteLinesToFile(const Container& lines, const char* path) {
 }
 
 // Generate a filesystem_config.txt for all files in |fs_root|
-bool WriteFsConfig(const char* output_path, const std::string& fs_root,
-                   const std::string& mount_point) {
+Result<bool> WriteFsConfig(const char* output_path, const std::string& fs_root,
+                           const std::string& mount_point) {
   android::base::unique_fd fd(
       open(output_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
   if (!fd.ok()) {
@@ -87,8 +87,8 @@ bool WriteFsConfig(const char* output_path, const std::string& fs_root,
     PLOG(ERROR) << "Failed to write to " << output_path;
     return false;
   }
-  WalkDirectory(fs_root, [&fd, &output_path, &mount_point,
-                          &fs_root](const std::string& file_path) {
+  auto res = WalkDirectory(fs_root, [&fd, &output_path, &mount_point,
+                                     &fs_root](const std::string& file_path) {
     const auto filename = file_path.substr(
         fs_root.back() == '/' ? fs_root.size() : fs_root.size() + 1);
     std::string fs_context = " 0 0 644 capabilities=0x0\n";
@@ -102,6 +102,9 @@ bool WriteFsConfig(const char* output_path, const std::string& fs_root,
     }
     return true;
   });
+  if (!res.ok()) {
+    return false;
+  }
   return true;
 }
 
@@ -116,6 +119,7 @@ std::vector<std::string> GetRamdiskModules(
       "virtio_dma_buf.ko",
       "virtio-gpu.ko",
       "virtio_input.ko",
+      "virtio_mmio.ko",
       "virtio_net.ko",
       "virtio_pci.ko",
       "virtio_pci_legacy_dev.ko",
@@ -427,8 +431,13 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
   CHECK(ret.ok()) << ret.error().FormatForEnv();
   ret = EnsureDirectoryExists(system_modules_dir);
   UnpackRamdisk(ramdisk_path, ramdisk_stage_dir);
-  const auto module_load_file =
-      android::base::Trim(FindFile(ramdisk_stage_dir.c_str(), "modules.load"));
+  auto res = FindFile(ramdisk_stage_dir.c_str(), "modules.load");
+  if (!res) {
+    LOG(ERROR) << "Failed to find modules.dep file in input ramdisk "
+               << ramdisk_path;
+    return false;
+  }
+  const auto module_load_file = android::base::Trim(res.value());
   if (module_load_file.empty()) {
     LOG(ERROR) << "Failed to find modules.dep file in input ramdisk "
                << ramdisk_path;
@@ -458,16 +467,20 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
     if (IsKernelModuleSigned(module_location)) {
       const auto system_dlkm_module_location =
           fmt::format("{}/{}", system_modules_dir, module_path);
-      EnsureDirectoryExists(
+      auto res = EnsureDirectoryExists(
           android::base::Dirname(system_dlkm_module_location));
-      RenameFile(module_location, system_dlkm_module_location);
+      CHECK(res.ok()) << res.error().FormatForEnv();
+      auto ret = RenameFile(module_location, system_dlkm_module_location);
+      CHECK(ret.ok()) << ret.error().FormatForEnv();
       system_dlkm_modules.emplace(module_path);
     } else {
       const auto vendor_dlkm_module_location =
           fmt::format("{}/{}", vendor_modules_dir, module_path);
-      EnsureDirectoryExists(
+      auto res = EnsureDirectoryExists(
           android::base::Dirname(vendor_dlkm_module_location));
-      RenameFile(module_location, vendor_dlkm_module_location);
+      CHECK(res.ok()) << res.error().FormatForEnv();
+      auto ret = RenameFile(module_location, vendor_dlkm_module_location);
+      CHECK(ret.ok()) << ret.error().FormatForEnv();
       vendor_dlkm_modules.emplace(module_path);
     }
   }
@@ -492,7 +505,8 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
   if (FileExists(initramfs_blocklist_path)) {
     const auto vendor_dlkm_blocklist_path =
         fmt::format("{}/{}", vendor_modules_dir, "modules.blocklist");
-    RenameFile(initramfs_blocklist_path, vendor_dlkm_blocklist_path);
+    auto ret = RenameFile(initramfs_blocklist_path, vendor_dlkm_blocklist_path);
+    CHECK(ret.ok()) << ret.error().FormatForEnv();
   }
 
   // Write updated modules.dep and modules.load files
diff --git a/host/commands/assemble_cvd/vendor_dlkm_utils.h b/host/commands/assemble_cvd/vendor_dlkm_utils.h
index 77fcbbee8..a523e1a95 100644
--- a/host/commands/assemble_cvd/vendor_dlkm_utils.h
+++ b/host/commands/assemble_cvd/vendor_dlkm_utils.h
@@ -26,8 +26,8 @@ bool SplitRamdiskModules(const std::string& ramdisk_path,
                          const std::string& vendor_dlkm_build_dir,
                          const std::string& system_dlkm_build_dir);
 
-bool WriteFsConfig(const char* output_path, const std::string& fs_root,
-                   const std::string& mount_point);
+Result<bool> WriteFsConfig(const char* output_path, const std::string& fs_root,
+                           const std::string& mount_point);
 
 Result<void> RepackSuperWithPartition(const std::string& superimg_path,
                                       const std::string& image_path,
diff --git a/host/commands/casimir_control_server/Android.bp b/host/commands/casimir_control_server/Android.bp
index afaddb4de..2caed5c7d 100644
--- a/host/commands/casimir_control_server/Android.bp
+++ b/host/commands/casimir_control_server/Android.bp
@@ -68,6 +68,7 @@ cc_binary_host {
     srcs: [
         "casimir_controller.cpp",
         "hex.cpp",
+        "crc.cpp",
         "main.cpp",
     ],
     cflags: [
diff --git a/host/commands/casimir_control_server/casimir_control.proto b/host/commands/casimir_control_server/casimir_control.proto
index a5434e907..4cc3ea493 100644
--- a/host/commands/casimir_control_server/casimir_control.proto
+++ b/host/commands/casimir_control_server/casimir_control.proto
@@ -23,6 +23,7 @@ service CasimirControlService {
   rpc PollA (Void) returns (SenderId) {}
   rpc SetRadioState(RadioState) returns (Void) {}
   rpc SetPowerLevel(PowerLevel) returns (Void) {}
+  rpc SendBroadcast (SendBroadcastRequest) returns (SendBroadcastResponse) {}
   rpc Init(Void) returns (Void) {}
   rpc Close(Void) returns (Void) {}
 }
@@ -49,4 +50,26 @@ message RadioState {
 
 message PowerLevel {
   uint32 power_level = 1;
-}
\ No newline at end of file
+}
+
+message TransceiveConfiguration {
+    // A, B, F, V
+    optional string type = 1;
+    optional bool crc = 2;
+    // 0 to 8
+    optional uint32 bits = 3;
+    // 106, 212, 424, 848, 53, 26
+    optional uint32 bitrate = 4;
+    // value in microseconds
+    optional uint32 timeout = 5;
+    // 0 to 100
+    optional double power = 6;
+}
+
+message SendBroadcastRequest {
+    string data = 1;
+    optional TransceiveConfiguration configuration = 2;
+}
+
+message SendBroadcastResponse {
+}
diff --git a/host/commands/casimir_control_server/casimir_controller.cpp b/host/commands/casimir_control_server/casimir_controller.cpp
index fdf214f56..6c55754c1 100644
--- a/host/commands/casimir_control_server/casimir_controller.cpp
+++ b/host/commands/casimir_control_server/casimir_controller.cpp
@@ -18,6 +18,9 @@
 #include <chrono>
 #include <cstdint>
 
+#include "host/commands/casimir_control_server/crc.h"
+
+#include "casimir_control.grpc.pb.h"
 #include "casimir_controller.h"
 
 namespace cuttlefish {
@@ -87,7 +90,11 @@ Result<void> CasimirController::SetPowerLevel(uint32_t power_level) {
 Result<uint16_t> CasimirController::SelectNfcA() {
   PollCommandBuilder poll_command;
   poll_command.technology_ = Technology::NFC_A;
+  poll_command.format_ = PollingFrameFormat::SHORT;
+  poll_command.bitrate_ = BitRate::BIT_RATE_106_KBIT_S;
   poll_command.power_level_ = power_level;
+  // WUPA
+  poll_command.payload_ = std::vector<uint8_t>{0x52};
   CF_EXPECT(Write(poll_command), "Failed to send NFC-A poll command");
 
   auto res = CF_EXPECT(ReadRfPacket(10s), "Failed to get NFC-A poll response");
@@ -106,6 +113,7 @@ Result<void> CasimirController::SelectT4AT(uint16_t sender_id) {
   T4ATSelectCommandBuilder t4at_select_command;
   t4at_select_command.sender_ = sender_id;
   t4at_select_command.param_ = 0;
+  t4at_select_command.bitrate_ = BitRate::BIT_RATE_106_KBIT_S;
   CF_EXPECT(Write(t4at_select_command), "Failed to send T4AT select command");
 
   auto res = CF_EXPECT(ReadRfPacket(1s), "Failed to get T4AT response");
@@ -138,6 +146,7 @@ Result<std::vector<uint8_t>> CasimirController::SendApdu(
   data_builder.receiver_ = receiver_id;
   data_builder.technology_ = Technology::NFC_A;
   data_builder.protocol_ = Protocol::ISO_DEP;
+  data_builder.bitrate_ = BitRate::BIT_RATE_106_KBIT_S;
 
   CF_EXPECT(Write(data_builder), "Failed to send APDU bytes");
 
@@ -152,6 +161,83 @@ Result<std::vector<uint8_t>> CasimirController::SendApdu(
   return CF_ERR("Invalid APDU response");
 }
 
+Result<std::tuple<std::vector<uint8_t>, std::string, bool, uint32_t, uint32_t,
+                  uint32_t, double>>
+CasimirController::SendBroadcast(std::vector<uint8_t> data, std::string type,
+                                 bool crc, uint8_t bits, uint32_t bitrate,
+                                 uint32_t timeout, double power) {
+  PollCommandBuilder poll_command;
+
+  if (type == "A") {
+    poll_command.technology_ = Technology::NFC_A;
+    if (crc) {
+      data = CF_EXPECT(WithCrc16A(data), "Could not append CRC16A");
+    }
+  } else if (type == "B") {
+    poll_command.technology_ = Technology::NFC_B;
+    if (crc) {
+      data = CF_EXPECT(WithCrc16B(data), "Could not append CRC16B");
+    }
+    if (bits != 8) {
+      return CF_ERR(
+          "Sending NFC-B data with != 8 bits in the last byte is unsupported");
+    }
+  } else if (type == "F") {
+    poll_command.technology_ = Technology::NFC_F;
+    if (!crc) {
+      // For NFC-F, CRC also assumes preamble
+      return CF_ERR("Sending NFC-F data without CRC is unsupported");
+    }
+    if (bits != 8) {
+      return CF_ERR(
+          "Sending NFC-F data with != 8 bits in the last byte is unsupported");
+    }
+  } else if (type == "V") {
+    poll_command.technology_ = Technology::NFC_V;
+  } else {
+    poll_command.technology_ = Technology::RAW;
+  }
+
+  if (bitrate == 106) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_106_KBIT_S;
+  } else if (bitrate == 212) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_212_KBIT_S;
+  } else if (bitrate == 424) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_424_KBIT_S;
+  } else if (bitrate == 848) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_848_KBIT_S;
+  } else if (bitrate == 1695) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_1695_KBIT_S;
+  } else if (bitrate == 3390) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_3390_KBIT_S;
+  } else if (bitrate == 6780) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_6780_KBIT_S;
+  } else if (bitrate == 26) {
+    poll_command.bitrate_ = BitRate::BIT_RATE_26_KBIT_S;
+  } else {
+    return CF_ERR("Proper bitrate was not provided: " << bitrate);
+  }
+
+  poll_command.payload_ = std::move(data);
+
+  if (bits > 8) {
+    return CF_ERR("There can not be more than 8 bits in last byte: " << bits);
+  }
+  poll_command.format_ =
+      bits != 8 ? PollingFrameFormat::SHORT : PollingFrameFormat::LONG;
+
+  // Adjust range of values from 0-100 to 0-12
+  poll_command.power_level_ = static_cast<int>(std::round(power * 12 / 100));
+
+  CF_EXPECT(Write(poll_command), "Failed to send broadcast frame");
+
+  if (timeout != 0) {
+    CF_EXPECT(ReadRfPacket(std::chrono::microseconds(timeout)));
+  }
+
+  return std::make_tuple(data, type, crc, bits, bitrate, timeout, power);
+}
+
 Result<void> CasimirController::Write(const RfPacketBuilder& rf_packet) {
   std::vector<uint8_t> raw_bytes = rf_packet.SerializeToBytes();
   uint16_t header_bytes_le = htole16(raw_bytes.size());
@@ -171,17 +257,21 @@ Result<void> CasimirController::Write(const RfPacketBuilder& rf_packet) {
 }
 
 Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::ReadExact(
-    size_t size, std::chrono::milliseconds timeout) {
+    size_t size, std::chrono::microseconds timeout) {
   size_t total_read = 0;
   auto out = std::make_shared<std::vector<uint8_t>>(size);
   auto prev_time = std::chrono::steady_clock::now();
-  while (timeout.count() > 0) {
+  while (
+      std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count() >
+      0) {
     PollSharedFd poll_fd = {
         .fd = sock_,
         .events = EPOLLIN,
         .revents = 0,
     };
-    int res = sock_.Poll(&poll_fd, 1, timeout.count());
+    int res = sock_.Poll(
+        &poll_fd, 1,
+        std::chrono::duration_cast<std::chrono::milliseconds>(timeout).count());
     CF_EXPECT_GE(res, 0, "Failed to poll on the casimir socket");
     CF_EXPECT_EQ(poll_fd.revents, EPOLLIN,
                  "Unexpected poll result for reading");
@@ -199,7 +289,7 @@ Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::ReadExact(
     }
 
     auto current_time = std::chrono::steady_clock::now();
-    timeout -= std::chrono::duration_cast<std::chrono::milliseconds>(
+    timeout -= std::chrono::duration_cast<std::chrono::microseconds>(
         current_time - prev_time);
   }
 
@@ -209,7 +299,7 @@ Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::ReadExact(
 // Note: Although rf_packets.h doesn't document nor include packet header,
 // the header is necessary to know total packet size.
 Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::ReadRfPacket(
-    std::chrono::milliseconds timeout) {
+    std::chrono::microseconds timeout) {
   auto start_time = std::chrono::steady_clock::now();
 
   auto res = CF_EXPECT(ReadExact(sizeof(uint16_t), timeout),
@@ -218,7 +308,7 @@ Result<std::shared_ptr<std::vector<uint8_t>>> CasimirController::ReadRfPacket(
   int16_t packet_size = packet_size_slice.read_le<uint16_t>();
 
   auto current_time = std::chrono::steady_clock::now();
-  timeout -= std::chrono::duration_cast<std::chrono::milliseconds>(
+  timeout -= std::chrono::duration_cast<std::chrono::microseconds>(
       current_time - start_time);
   return CF_EXPECT(ReadExact(packet_size, timeout),
                    "Failed to read RF packet payload");
diff --git a/host/commands/casimir_control_server/casimir_controller.h b/host/commands/casimir_control_server/casimir_controller.h
index 3603cd7e9..6ca778144 100644
--- a/host/commands/casimir_control_server/casimir_controller.h
+++ b/host/commands/casimir_control_server/casimir_controller.h
@@ -38,6 +38,11 @@ class CasimirController {
 
   Result<void> SetPowerLevel(uint32_t power_level);
 
+  Result<std::tuple<std::vector<uint8_t>, std::string, bool, uint32_t, uint32_t,
+                    uint32_t, double>>
+  SendBroadcast(std::vector<uint8_t> data, std::string type, bool crc,
+                uint8_t bits, uint32_t bitrate, uint32_t timeout, double power);
+
   /*
    * Poll for NFC-A + ISO-DEP
    */
@@ -61,9 +66,9 @@ class CasimirController {
 
   Result<void> Write(const RfPacketBuilder& rf_packet);
   Result<std::shared_ptr<std::vector<uint8_t>>> ReadExact(
-      size_t size, std::chrono::milliseconds timeout);
+      size_t size, std::chrono::microseconds timeout);
   Result<std::shared_ptr<std::vector<uint8_t>>> ReadRfPacket(
-      std::chrono::milliseconds timeout);
+      std::chrono::microseconds timeout);
 
   SharedFD sock_;
   uint8_t power_level;
diff --git a/host/commands/casimir_control_server/crc.cpp b/host/commands/casimir_control_server/crc.cpp
new file mode 100644
index 000000000..09939af23
--- /dev/null
+++ b/host/commands/casimir_control_server/crc.cpp
@@ -0,0 +1,66 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include "host/commands/casimir_control_server/crc.h"
+
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+namespace {
+static std::vector<uint8_t> Crc16(const std::vector<uint8_t>& data,
+                                  uint16_t initial, bool invert) {
+  uint16_t w_crc = initial;
+
+  for (uint8_t byte : data) {
+    byte ^= (w_crc & 0x00FF);
+    byte ^= (byte << 4) & 0xFF;
+    w_crc = (w_crc >> 8) ^ ((byte << 8) & 0xFFFF) ^ ((byte << 3) & 0xFFFF) ^
+            ((byte >> 4) & 0xFFFF);
+  }
+
+  if (invert) {
+    w_crc = ~w_crc;
+  }
+
+  return {static_cast<uint8_t>(w_crc & 0xFF),
+          static_cast<uint8_t>((w_crc >> 8) & 0xFF)};
+}
+
+static std::vector<uint8_t> Crc16A(const std::vector<uint8_t>& data) {
+  return Crc16(data, 0x6363, false);
+}
+
+static std::vector<uint8_t> Crc16B(const std::vector<uint8_t>& data) {
+  return Crc16(data, 0xFFFF, true);
+}
+}  // namespace
+
+Result<std::vector<uint8_t>> WithCrc16A(const std::vector<uint8_t>& data) {
+  std::vector<uint8_t> newData = data;
+  std::vector<uint8_t> crc = Crc16A(newData);
+  newData.insert(newData.end(), crc.begin(), crc.end());
+  return newData;
+}
+
+Result<std::vector<uint8_t>> WithCrc16B(const std::vector<uint8_t>& data) {
+  std::vector<uint8_t> newData = data;
+  std::vector<uint8_t> crc = Crc16B(newData);
+  newData.insert(newData.end(), crc.begin(), crc.end());
+  return newData;
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/casimir_control_server/crc.h b/host/commands/casimir_control_server/crc.h
new file mode 100644
index 000000000..da1e8fb59
--- /dev/null
+++ b/host/commands/casimir_control_server/crc.h
@@ -0,0 +1,26 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+Result<std::vector<uint8_t>> WithCrc16A(const std::vector<uint8_t>& data);
+Result<std::vector<uint8_t>> WithCrc16B(const std::vector<uint8_t>& data);
+
+}  // namespace cuttlefish
diff --git a/host/commands/casimir_control_server/main.cpp b/host/commands/casimir_control_server/main.cpp
index b54692d9a..4adcd2e8d 100644
--- a/host/commands/casimir_control_server/main.cpp
+++ b/host/commands/casimir_control_server/main.cpp
@@ -35,7 +35,10 @@ using casimircontrolserver::PowerLevel;
 using casimircontrolserver::RadioState;
 using casimircontrolserver::SendApduReply;
 using casimircontrolserver::SendApduRequest;
+using casimircontrolserver::SendBroadcastRequest;
+using casimircontrolserver::SendBroadcastResponse;
 using casimircontrolserver::SenderId;
+using casimircontrolserver::TransceiveConfiguration;
 using casimircontrolserver::Void;
 
 using cuttlefish::CasimirController;
@@ -195,7 +198,7 @@ class CasimirControlServiceImpl final : public CasimirControlService::Service {
       // Step 2: Poll
       SenderId sender_id;
       CF_EXPECT(PollAResult(&sender_id));
-      id = sender_id.sender_id();
+      id = sender_id.sender_id() - 1;
     }
 
     // Step 3: Send APDU bytes
@@ -218,6 +221,69 @@ class CasimirControlServiceImpl final : public CasimirControlService::Service {
     return ResultToStatus(SendApduResult(request, response));
   }
 
+  Result<void> SendBroadcastResult(const SendBroadcastRequest* request,
+                                   SendBroadcastResponse* response) {
+    // Default configuration values
+    TransceiveConfiguration requestConfig;
+    // Type A
+    requestConfig.set_type("A");
+    // CRC present
+    requestConfig.set_crc(true);
+    // 8 bits in last byte
+    requestConfig.set_bits(8);
+    // 106kbps
+    requestConfig.set_bitrate(106);
+    // No timeout, timeout immediately
+    requestConfig.clear_timeout();
+    // 100% output power
+    requestConfig.set_power(100);
+
+    // Overwrite defaults with provided configuration, if present
+    if (request->has_configuration()) {
+      auto config = request->configuration();
+      if (config.has_type()) {
+        requestConfig.set_type(config.type());
+      }
+      if (config.has_crc()) {
+        requestConfig.set_crc(config.crc());
+      }
+      if (config.has_bits()) {
+        requestConfig.set_bits(config.bits());
+      }
+      if (config.has_bitrate()) {
+        requestConfig.set_bitrate(config.bitrate());
+      }
+      if (config.has_timeout()) {
+        requestConfig.set_timeout(config.timeout());
+      }
+      if (config.has_power()) {
+        requestConfig.set_power(config.power());
+      }
+    }
+
+    if (!device_.has_value()) {
+      device_ = CF_EXPECT(ConnectToCasimir(), "Failed to connect with casimir");
+      CF_EXPECT(Unmute(), "failed to unmute the device");
+    }
+
+    std::vector<uint8_t> requestData =
+        CF_EXPECT(HexToBytes(request->data()),
+                  "Failed to parse input. Must only contain [0-9a-fA-F]");
+
+    CF_EXPECT(device_->SendBroadcast(
+                  requestData, requestConfig.type(), requestConfig.crc(),
+                  requestConfig.bits(), requestConfig.bitrate(),
+                  requestConfig.timeout(), requestConfig.power()),
+              "Failed to send broadcast data");
+
+    return {};  // Success
+  }
+
+  Status SendBroadcast(ServerContext*, const SendBroadcastRequest* request,
+                       SendBroadcastResponse* response) override {
+    return ResultToStatus(SendBroadcastResult(request, response));
+  }
+
   std::optional<CasimirController> device_;
   bool is_radio_on_ = false;
 };
diff --git a/host/commands/display/Android.bp b/host/commands/display/Android.bp
index c64139c22..fdeaac581 100644
--- a/host/commands/display/Android.bp
+++ b/host/commands/display/Android.bp
@@ -30,6 +30,7 @@ cc_binary_host {
         "libcuttlefish_host_config",
         "libcuttlefish_run_cvd_proto",
         "libcuttlefish_utils",
+        "libcuttlefish_vm_manager",
         "libgflags",
         "libjsoncpp",
         "liblog",
diff --git a/host/commands/display/main.cpp b/host/commands/display/main.cpp
index 8320a78c6..e0d2f02dc 100644
--- a/host/commands/display/main.cpp
+++ b/host/commands/display/main.cpp
@@ -26,12 +26,12 @@
 #include <android-base/strings.h>
 
 #include "common/libs/utils/flag_parser.h"
-#include "common/libs/utils/subprocess.h"
+#include "common/libs/utils/result.h"
 #include "device/google/cuttlefish/host/libs/command_util/runner/run_cvd.pb.h"
-#include "host/commands/assemble_cvd/flags_defaults.h"
 #include "host/libs/command_util/util.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/display.h"
+#include "host/libs/vm_manager/crosvm_display_controller.h"
 
 namespace cuttlefish {
 namespace {
@@ -73,41 +73,6 @@ Currently supported output formats: jpg, png, webp.
 usage: cvd display screenshot <display id> <screenshot path>
 )";
 
-Result<int> RunCrosvmDisplayCommand(int instance_num,
-                                    const std::vector<std::string>& args) {
-  auto config = cuttlefish::CuttlefishConfig::Get();
-  if (!config) {
-    return CF_ERR("Failed to get Cuttlefish config.");
-  }
-  // TODO(b/260649774): Consistent executable API for selecting an instance
-  auto instance = config->ForInstance(instance_num);
-
-  const std::string crosvm_binary_path = instance.crosvm_binary();
-  const std::string crosvm_control_path = instance.CrosvmSocketPath();
-
-  cuttlefish::Command command(crosvm_binary_path);
-  command.AddParameter("gpu");
-  for (const std::string& arg : args) {
-    command.AddParameter(arg);
-  }
-  command.AddParameter(crosvm_control_path);
-
-  std::string out;
-  std::string err;
-  auto ret = RunWithManagedStdio(std::move(command), NULL, &out, &err);
-  if (ret != 0) {
-    std::cerr << "Failed to run crosvm display command: ret code: " << ret
-              << "\n"
-              << out << "\n"
-              << err;
-    return ret;
-  }
-
-  std::cerr << err << std::endl;
-  std::cout << out << std::endl;
-  return 0;
-}
-
 Result<int> GetInstanceNum(std::vector<std::string>& args) {
   int instance_num = 1;
   CF_EXPECT(
@@ -147,34 +112,18 @@ Result<int> DoAdd(std::vector<std::string>& args) {
     return 1;
   }
 
-  std::vector<std::string> add_displays_command_args;
-  add_displays_command_args.push_back("add-displays");
-
-  for (const auto& display_config : display_configs) {
-    const std::string w = std::to_string(display_config.width);
-    const std::string h = std::to_string(display_config.height);
-    const std::string dpi = std::to_string(display_config.dpi);
-    const std::string rr = std::to_string(display_config.refresh_rate_hz);
-
-    const std::string add_display_flag =
-        "--gpu-display=" + android::base::Join(
-                               std::vector<std::string>{
-                                   "mode=windowed[" + w + "," + h + "]",
-                                   "dpi=[" + dpi + "," + dpi + "]",
-                                   "refresh-rate=" + rr,
-                               },
-                               ",");
-
-    add_displays_command_args.push_back(add_display_flag);
-  }
-
-  return CF_EXPECT(
-      RunCrosvmDisplayCommand(instance_num, add_displays_command_args));
+  auto crosvm_display = CF_EXPECT(vm_manager::GetCrosvmDisplayController());
+  return CF_EXPECT(crosvm_display.Add(instance_num, display_configs));
 }
 
 Result<int> DoList(std::vector<std::string>& args) {
   const int instance_num = CF_EXPECT(GetInstanceNum(args));
-  return CF_EXPECT(RunCrosvmDisplayCommand(instance_num, {"list-displays"}));
+  auto crosvm_display = CF_EXPECT(vm_manager::GetCrosvmDisplayController());
+
+  auto out = CF_EXPECT(crosvm_display.List(instance_num));
+  std::cout << out << std::endl;
+
+  return 0;
 }
 
 Result<int> DoRemove(std::vector<std::string>& args) {
@@ -204,14 +153,8 @@ Result<int> DoRemove(std::vector<std::string>& args) {
     return 1;
   }
 
-  std::vector<std::string> remove_displays_command_args;
-  remove_displays_command_args.push_back("remove-displays");
-  for (const auto& display : displays) {
-    remove_displays_command_args.push_back("--display-id=" + display);
-  }
-
-  return CF_EXPECT(
-      RunCrosvmDisplayCommand(instance_num, remove_displays_command_args));
+  auto crosvm_display = CF_EXPECT(vm_manager::GetCrosvmDisplayController());
+  return CF_EXPECT(crosvm_display.Remove(instance_num, displays));
 }
 
 Result<int> DoScreenshot(std::vector<std::string>& args) {
diff --git a/host/commands/host_bugreport/main.cc b/host/commands/host_bugreport/main.cc
index 042c13411..b4dcb4dcc 100644
--- a/host/commands/host_bugreport/main.cc
+++ b/host/commands/host_bugreport/main.cc
@@ -25,13 +25,16 @@
 
 #include "common/libs/fs/shared_fd.h"
 #include "common/libs/fs/shared_select.h"
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/subprocess.h"
 #include "common/libs/utils/tee_logging.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "ziparchive/zip_writer.h"
 
 DEFINE_string(output, "host_bugreport.zip", "Where to write the output");
+DEFINE_bool(include_adb_bugreport, false, "Includes device's `adb bugreport`.");
 
 namespace cuttlefish {
 namespace {
@@ -56,8 +59,9 @@ void AddNetsimdLogs(ZipWriter& writer) {
   // is defined.
   // https://source.corp.google.com/h/googleplex-android/platform/superproject/main/+/main:tools/netsim/rust/common/src/system/mod.rs;l=37-57;drc=360ddb57df49472a40275b125bb56af2a65395c7
   std::string user = StringFromEnv("USER", "");
-  std::string dir = user.empty() ? "/tmp/android/netsimd"
-                                 : fmt::format("/tmp/android-{}/netsimd", user);
+  std::string dir = user.empty()
+                        ? TempDir() + "/android/netsimd"
+                        : fmt::format("{}/android-{}/netsimd", TempDir(), user);
   if (!DirectoryExists(dir)) {
     LOG(INFO) << "netsimd logs directory: `" << dir << "` does not exist.";
     return;
@@ -113,7 +117,7 @@ Result<void> CvdHostBugreportMain(int argc, char** argv) {
   ::android::base::InitLogging(argv, android::base::StderrLogger);
   google::ParseCommandLineFlags(&argc, &argv, true);
 
-  std::string log_filename = "/tmp/cvd_hbr.log.XXXXXX";
+  std::string log_filename = TempDir() + "/cvd_hbr.log.XXXXXX";
   {
     auto fd = SharedFD::Mkstemp(&log_filename);
     CF_EXPECT(fd->IsOpen(), "Unable to create log file: " << fd->StrError());
@@ -185,9 +189,9 @@ Result<void> CvdHostBugreportMain(int argc, char** argv) {
       }
     }
 
-    {
+    if (FLAGS_include_adb_bugreport) {
       // TODO(b/359657254) Create the `adb bugreport` asynchronously.
-      std::string device_br_dir = "/tmp/cvd_dbrXXXXXX";
+      std::string device_br_dir = TempDir() + "/cvd_dbrXXXXXX";
       CF_EXPECTF(mkdtemp(device_br_dir.data()) != nullptr,
                  "mkdtemp failed: '{}'", strerror(errno));
       auto result = CreateDeviceBugreport(instance, device_br_dir);
diff --git a/host/commands/metrics/Android.bp b/host/commands/metrics/Android.bp
index e17e53e24..65b0b1603 100644
--- a/host/commands/metrics/Android.bp
+++ b/host/commands/metrics/Android.bp
@@ -44,7 +44,6 @@ cc_binary {
     static_libs: [
         "libcuttlefish_host_config",
         "libcuttlefish_msg_queue",
-        "libext2_uuid",
         "libgflags",
     ],
     defaults: ["cuttlefish_host"],
diff --git a/host/commands/metrics/events.cc b/host/commands/metrics/events.cc
index 4cf9d1bec..37a7dea39 100644
--- a/host/commands/metrics/events.cc
+++ b/host/commands/metrics/events.cc
@@ -14,7 +14,6 @@
 // limitations under the License.
 
 #include <sys/utsname.h>
-#include <uuid.h>
 
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
diff --git a/host/commands/modem_simulator/Android.bp b/host/commands/modem_simulator/Android.bp
index 2ae447872..2987e8607 100644
--- a/host/commands/modem_simulator/Android.bp
+++ b/host/commands/modem_simulator/Android.bp
@@ -42,7 +42,6 @@ cc_defaults {
         "libcuttlefish_fs",
         "libcuttlefish_utils",
         "libjsoncpp",
-        "libnl",
     ],
     static_libs: [
         "libcuttlefish_host_config",
diff --git a/host/commands/modem_simulator/network_service.cpp b/host/commands/modem_simulator/network_service.cpp
index 3dc77b5b6..b254600f0 100644
--- a/host/commands/modem_simulator/network_service.cpp
+++ b/host/commands/modem_simulator/network_service.cpp
@@ -1167,27 +1167,30 @@ NetworkService::SignalStrength NetworkService::GetCurrentSignalStrength() {
   if (!IsHasNetwork()) {
     return result;
   }
+
   int percent = signal_strength_percent_;
   switch (current_network_mode_) {
     case M_MODEM_TECH_GSM:
       result.gsm_rssi = GetValueInRange(kRssiRange, percent);
+      result.gsm_ber = kBerUnknownValue;
       break;
     case M_MODEM_TECH_CDMA:
       result.cdma_dbm = GetValueInRange(kDbmRange, percent) * -1;
+      result.cdma_ecio = kEcioUnknownValue;
       break;
     case M_MODEM_TECH_EVDO:
       result.evdo_dbm = GetValueInRange(kDbmRange, percent) * -1;
+      result.evdo_ecio = kEcioUnknownValue;
+      result.evdo_snr = kSnrUnknownValue;
       break;
     case M_MODEM_TECH_LTE:
       result.lte_rsrp = GetValueInRange(kRsrpRange, percent) * -1;
+      result.lte_rssi = kRssiUnknownValue;
       break;
     case M_MODEM_TECH_WCDMA:
       result.wcdma_rssi = GetValueInRange(kRssiRange, percent);
       break;
     case M_MODEM_TECH_NR:
-      // special for NR: it uses LTE as primary, so LTE signal strength is
-      // needed as well
-      result.lte_rsrp = GetValueInRange(kRsrpRange, percent) * -1;
       result.nr_ss_rsrp = GetValueInRange(kRsrpRange, percent) * -1;
       break;
     default:
diff --git a/host/commands/modem_simulator/network_service.h b/host/commands/modem_simulator/network_service.h
index fd22fa729..ed9c1b0a2 100644
--- a/host/commands/modem_simulator/network_service.h
+++ b/host/commands/modem_simulator/network_service.h
@@ -61,6 +61,16 @@ class NetworkService : public ModemService, public std::enable_shared_from_this<
   void OnDataRegisterStateChanged();
   void OnSignalStrengthChanged();
 
+  enum ModemTechnology {
+    M_MODEM_TECH_GSM = 1 << 0,
+    M_MODEM_TECH_WCDMA = 1 << 1,
+    M_MODEM_TECH_CDMA = 1 << 2,
+    M_MODEM_TECH_EVDO = 1 << 3,
+    M_MODEM_TECH_TDSCDMA = 1 << 4,
+    M_MODEM_TECH_LTE = 1 << 5,
+    M_MODEM_TECH_NR = 1 << 6,
+  };
+
   enum RegistrationState {
     NET_REGISTRATION_UNREGISTERED = 0,
     NET_REGISTRATION_HOME         = 1,
@@ -201,22 +211,22 @@ class NetworkService : public ModemService, public std::enable_shared_from_this<
                            * Range [-23, 40], INT_MAX means invalid/unreported. */
 
     SignalStrength()
-        : gsm_rssi(kRssiUnknownValue),
-          gsm_ber(kBerUnknownValue),
-          cdma_dbm(kDbmUnknownValue),
-          cdma_ecio(kEcioUnknownValue),
-          evdo_dbm(kDbmUnknownValue),
-          evdo_ecio(kEcioUnknownValue),
-          evdo_snr(kSnrUnknownValue),
-          lte_rssi(kRssiUnknownValue),
+        : gsm_rssi(INT_MAX),
+          gsm_ber(INT_MAX),
+          cdma_dbm(INT_MAX),
+          cdma_ecio(INT_MAX),
+          evdo_dbm(INT_MAX),
+          evdo_ecio(INT_MAX),
+          evdo_snr(INT_MAX),
+          lte_rssi(INT_MAX),
           lte_rsrp(INT_MAX),
           lte_rsrq(INT_MAX),
           lte_rssnr(INT_MAX),
           lte_cqi(INT_MAX),
           lte_ta(INT_MAX),
           tdscdma_rscp(INT_MAX),
-          wcdma_rssi(kRssiUnknownValue),
-          wcdma_ber(kBerUnknownValue),
+          wcdma_rssi(INT_MAX),
+          wcdma_ber(INT_MAX),
           nr_ss_rsrp(INT_MAX),
           nr_ss_rsrq(INT_MAX),
           nr_ss_sinr(INT_MAX),
@@ -274,15 +284,6 @@ class NetworkService : public ModemService, public std::enable_shared_from_this<
   NetworkRegistrationStatus voice_registration_status_;
   NetworkRegistrationStatus data_registration_status_;
 
-  enum ModemTechnology {
-    M_MODEM_TECH_GSM    = 1 << 0,
-    M_MODEM_TECH_WCDMA  = 1 << 1,
-    M_MODEM_TECH_CDMA   = 1 << 2,
-    M_MODEM_TECH_EVDO   = 1 << 3,
-    M_MODEM_TECH_TDSCDMA= 1 << 4,
-    M_MODEM_TECH_LTE    = 1 << 5,
-    M_MODEM_TECH_NR     = 1 << 6,
-  };
   ModemTechnology current_network_mode_;
   int preferred_network_mode_;
   int modem_radio_capability_;
diff --git a/host/commands/modem_simulator/nvram_config.cpp b/host/commands/modem_simulator/nvram_config.cpp
index 021ba7391..2418d5a40 100644
--- a/host/commands/modem_simulator/nvram_config.cpp
+++ b/host/commands/modem_simulator/nvram_config.cpp
@@ -23,6 +23,7 @@
 
 #include "common/libs/utils/files.h"
 #include "host/commands/modem_simulator/device_config.h"
+#include "host/commands/modem_simulator/network_service.h"
 
 namespace cuttlefish {
 
@@ -34,8 +35,10 @@ static constexpr char kPreferredNetworkMode[] = "preferred_network_mode";
 static constexpr char kEmergencyMode[] = "emergency_mode";
 
 static constexpr int kDefaultNetworkSelectionMode = 0;     // AUTOMATIC
-static constexpr int kDefaultModemTechnoloy = 0x10;        // LTE
-static constexpr int kDefaultPreferredNetworkMode = 0x13;  // LTE | WCDMA | GSM
+static constexpr int kDefaultModemTechnoloy = NetworkService::M_MODEM_TECH_LTE;
+static constexpr int kDefaultPreferredNetworkMode =
+    NetworkService::M_MODEM_TECH_LTE | NetworkService::M_MODEM_TECH_WCDMA |
+    NetworkService::M_MODEM_TECH_GSM;
 static constexpr bool kDefaultEmergencyMode = false;
 
 /**
diff --git a/host/commands/process_sandboxer/Android.bp b/host/commands/process_sandboxer/Android.bp
index 2ae909c4b..e84e245b3 100644
--- a/host/commands/process_sandboxer/Android.bp
+++ b/host/commands/process_sandboxer/Android.bp
@@ -25,7 +25,6 @@ cc_binary_host {
     defaults: ["cuttlefish_buildhost_only"],
     srcs: [
         "credentialed_unix_server.cpp",
-        "filesystem.cpp",
         "logs.cpp",
         "main.cpp",
         "pidfd.cpp",
@@ -36,6 +35,7 @@ cc_binary_host {
         "policies/baseline.cpp",
         "policies/casimir.cpp",
         "policies/casimir_control_server.cpp",
+        "policies/cf_vhost_user_input.cpp",
         "policies/control_env_proxy_server.cpp",
         "policies/cvd_internal_start.cpp",
         "policies/echo_server.cpp",
@@ -67,7 +67,6 @@ cc_binary_host {
         "poll_callback.cpp",
         "sandbox_manager.cpp",
         "signal_fd.cpp",
-        "unique_fd.cpp",
     ],
     shared_libs: ["sandboxed_api_sandbox2"],
     static_libs: [
diff --git a/host/commands/process_sandboxer/credentialed_unix_server.cpp b/host/commands/process_sandboxer/credentialed_unix_server.cpp
index 3aac0ab73..a27c4cc55 100644
--- a/host/commands/process_sandboxer/credentialed_unix_server.cpp
+++ b/host/commands/process_sandboxer/credentialed_unix_server.cpp
@@ -18,23 +18,27 @@
 #include <sys/socket.h>
 #include <sys/un.h>
 
-#include <cstring>
+#include <cerrno>
+#include <cstdio>
 #include <string>
+#include <utility>
 
+#include <absl/status/status.h>
 #include <absl/status/statusor.h>
-
-#include "host/commands/process_sandboxer/unique_fd.h"
+#include <sandboxed_api/util/fileops.h>
 
 namespace cuttlefish::process_sandboxer {
 
-CredentialedUnixServer::CredentialedUnixServer(UniqueFd fd)
+using sapi::file_util::fileops::FDCloser;
+
+CredentialedUnixServer::CredentialedUnixServer(FDCloser fd)
     : fd_(std::move(fd)) {}
 
 absl::StatusOr<CredentialedUnixServer> CredentialedUnixServer::Open(
     const std::string& path) {
-  UniqueFd fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
+  FDCloser fd(socket(AF_UNIX, SOCK_SEQPACKET | SOCK_CLOEXEC, 0));
 
-  if (fd.Get() < 0) {
+  if (fd.get() < 0) {
     return absl::ErrnoToStatus(errno, "`socket` failed");
   }
   sockaddr_un socket_name = {
@@ -43,32 +47,32 @@ absl::StatusOr<CredentialedUnixServer> CredentialedUnixServer::Open(
   std::snprintf(socket_name.sun_path, sizeof(socket_name.sun_path), "%s",
                 path.c_str());
   sockaddr* sockname_ptr = reinterpret_cast<sockaddr*>(&socket_name);
-  if (bind(fd.Get(), sockname_ptr, sizeof(socket_name)) < 0) {
+  if (bind(fd.get(), sockname_ptr, sizeof(socket_name)) < 0) {
     return absl::ErrnoToStatus(errno, "`bind` failed");
   }
 
   int enable_passcred = 1;
-  if (setsockopt(fd.Get(), SOL_SOCKET, SO_PASSCRED, &enable_passcred,
+  if (setsockopt(fd.get(), SOL_SOCKET, SO_PASSCRED, &enable_passcred,
                  sizeof(enable_passcred)) < 0) {
     static constexpr char kErr[] = "`setsockopt(..., SO_PASSCRED, ...)` failed";
     return absl::ErrnoToStatus(errno, kErr);
   }
 
-  if (listen(fd.Get(), 10) < 0) {
+  if (listen(fd.get(), 10) < 0) {
     return absl::ErrnoToStatus(errno, "`listen` failed");
   }
 
   return CredentialedUnixServer(std::move(fd));
 }
 
-absl::StatusOr<UniqueFd> CredentialedUnixServer::AcceptClient() {
-  UniqueFd client(accept4(fd_.Get(), nullptr, nullptr, SOCK_CLOEXEC));
-  if (client.Get() < 0) {
+absl::StatusOr<FDCloser> CredentialedUnixServer::AcceptClient() {
+  FDCloser client(accept4(fd_.get(), nullptr, nullptr, SOCK_CLOEXEC));
+  if (client.get() < 0) {
     return absl::ErrnoToStatus(errno, "`accept` failed");
   }
   return client;
 }
 
-int CredentialedUnixServer::Fd() const { return fd_.Get(); }
+int CredentialedUnixServer::Fd() const { return fd_.get(); }
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/credentialed_unix_server.h b/host/commands/process_sandboxer/credentialed_unix_server.h
index aa149b837..b09ea5a47 100644
--- a/host/commands/process_sandboxer/credentialed_unix_server.h
+++ b/host/commands/process_sandboxer/credentialed_unix_server.h
@@ -19,8 +19,7 @@
 #include <string>
 
 #include <absl/status/statusor.h>
-
-#include "host/commands/process_sandboxer/unique_fd.h"
+#include <sandboxed_api/util/fileops.h>
 
 namespace cuttlefish::process_sandboxer {
 
@@ -28,14 +27,14 @@ class CredentialedUnixServer {
  public:
   static absl::StatusOr<CredentialedUnixServer> Open(const std::string& path);
 
-  absl::StatusOr<UniqueFd> AcceptClient();
+  absl::StatusOr<sapi::file_util::fileops::FDCloser> AcceptClient();
 
   int Fd() const;
 
  private:
-  CredentialedUnixServer(UniqueFd);
+  CredentialedUnixServer(sapi::file_util::fileops::FDCloser);
 
-  UniqueFd fd_;
+  sapi::file_util::fileops::FDCloser fd_;
 };
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/filesystem.cpp b/host/commands/process_sandboxer/filesystem.cpp
deleted file mode 100644
index 5de15cc25..000000000
--- a/host/commands/process_sandboxer/filesystem.cpp
+++ /dev/null
@@ -1,131 +0,0 @@
-// Copyright 2019 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include "host/commands/process_sandboxer/filesystem.h"
-
-#include <sys/stat.h>
-
-#include <deque>
-#include <initializer_list>
-#include <string>
-#include <string_view>
-
-#include <absl/strings/str_cat.h>
-#include <absl/strings/str_join.h>
-#include <absl/strings/str_split.h>
-#include <absl/strings/strip.h>
-
-namespace cuttlefish::process_sandboxer {
-
-// Copied from sandboxed_api/util/path.cc
-
-namespace internal {
-
-constexpr char kPathSeparator[] = "/";
-
-std::string JoinPathImpl(std::initializer_list<absl::string_view> paths) {
-  std::string result;
-  for (const auto& path : paths) {
-    if (path.empty()) {
-      continue;
-    }
-    if (result.empty()) {
-      absl::StrAppend(&result, path);
-      continue;
-    }
-    const auto comp = absl::StripPrefix(path, kPathSeparator);
-    if (absl::EndsWith(result, kPathSeparator)) {
-      absl::StrAppend(&result, comp);
-    } else {
-      absl::StrAppend(&result, kPathSeparator, comp);
-    }
-  }
-  return result;
-}
-
-}  // namespace internal
-
-// Copied from sandboxed_api/util/fileops.cc
-
-namespace {
-
-std::string StripBasename(std::string_view path) {
-  const auto last_slash = path.find_last_of('/');
-  if (last_slash == std::string::npos) {
-    return "";
-  }
-  if (last_slash == 0) {
-    return "/";
-  }
-  return std::string(path.substr(0, last_slash));
-}
-
-}  // namespace
-
-bool CreateDirectoryRecursively(const std::string& path, int mode) {
-  if (mkdir(path.c_str(), mode) == 0 || errno == EEXIST) {
-    return true;
-  }
-
-  // We couldn't create the dir for reasons we can't handle.
-  if (errno != ENOENT) {
-    return false;
-  }
-
-  // The ENOENT case, the parent directory doesn't exist yet.
-  // Let's create it.
-  const std::string dir = StripBasename(path);
-  if (dir == "/" || dir.empty()) {
-    return false;
-  }
-  if (!CreateDirectoryRecursively(dir, mode)) {
-    return false;
-  }
-
-  // Now the parent dir exists, retry creating the directory.
-  return mkdir(path.c_str(), mode) == 0;
-}
-
-std::string CleanPath(const std::string_view unclean_path) {
-  int dotdot_num = 0;
-  std::deque<absl::string_view> parts;
-  for (absl::string_view part :
-       absl::StrSplit(unclean_path, '/', absl::SkipEmpty())) {
-    if (part == "..") {
-      if (parts.empty()) {
-        ++dotdot_num;
-      } else {
-        parts.pop_back();
-      }
-    } else if (part != ".") {
-      parts.push_back(part);
-    }
-  }
-  if (absl::StartsWith(unclean_path, "/")) {
-    if (parts.empty()) {
-      return "/";
-    }
-    parts.push_front("");
-  } else {
-    for (; dotdot_num; --dotdot_num) {
-      parts.push_front("..");
-    }
-    if (parts.empty()) {
-      return ".";
-    }
-  }
-  return absl::StrJoin(parts, "/");
-}
-
-}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/filesystem.h b/host/commands/process_sandboxer/filesystem.h
deleted file mode 100644
index 26d9c4b8a..000000000
--- a/host/commands/process_sandboxer/filesystem.h
+++ /dev/null
@@ -1,49 +0,0 @@
-// Copyright 2019 Google LLC
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     https://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-#include <initializer_list>
-#include <string>
-#include <string_view>
-
-namespace cuttlefish::process_sandboxer {
-
-// Copied from sandboxed_api/util/fileops.h
-
-// Recursively creates a directory, skipping segments that already exist.
-bool CreateDirectoryRecursively(const std::string& path, int mode);
-
-// Copied from sandboxed_api/util/path.h
-
-namespace internal {
-// Not part of the public API.
-std::string JoinPathImpl(std::initializer_list<std::string_view> paths);
-}  // namespace internal
-
-// Joins multiple paths together using the platform-specific path separator.
-// Arguments must be convertible to absl::string_view.
-template <typename... T>
-inline std::string JoinPath(const T&... args) {
-  return internal::JoinPathImpl({args...});
-}
-
-// Collapses duplicate "/"s, resolve ".." and "." path elements, removes
-// trailing "/".
-//
-// NOTE: This respects relative vs. absolute paths, but does not
-// invoke any system calls in order to resolve relative paths to the actual
-// working directory. That is, this is purely a string manipulation, completely
-// independent of process state.
-std::string CleanPath(std::string_view path);
-
-}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/logs.cpp b/host/commands/process_sandboxer/logs.cpp
index adbb643eb..1190f1f49 100644
--- a/host/commands/process_sandboxer/logs.cpp
+++ b/host/commands/process_sandboxer/logs.cpp
@@ -18,17 +18,22 @@
 #include <fcntl.h>
 #include <unistd.h>
 
+#include <cerrno>
+#include <cstring>
+#include <iostream>
 #include <memory>
 #include <sstream>
 #include <string>
+#include <vector>
 
 #include <absl/log/log.h>
+#include <absl/log/log_entry.h>
 #include <absl/log/log_sink.h>
 #include <absl/log/log_sink_registry.h>
+#include <absl/status/status.h>
 #include <absl/status/statusor.h>
 
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 namespace {
 
 // Implementation based on absl::log_internal::StderrLogSink
@@ -86,5 +91,4 @@ absl::Status LogToFiles(const std::vector<std::string>& paths) {
   return absl::OkStatus();
 }
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/logs.h b/host/commands/process_sandboxer/logs.h
index 081dae56e..a762e5430 100644
--- a/host/commands/process_sandboxer/logs.h
+++ b/host/commands/process_sandboxer/logs.h
@@ -24,12 +24,10 @@
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
 
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 
 absl::Status LogToFiles(const std::vector<std::string>& paths);
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
 
 #endif
diff --git a/host/commands/process_sandboxer/main.cpp b/host/commands/process_sandboxer/main.cpp
index 824c29765..1d778b63a 100644
--- a/host/commands/process_sandboxer/main.cpp
+++ b/host/commands/process_sandboxer/main.cpp
@@ -17,7 +17,9 @@
 #include <fcntl.h>
 #include <stdlib.h>
 #include <sys/prctl.h>
+#include <unistd.h>
 
+#include <cerrno>
 #include <memory>
 #include <optional>
 #include <string>
@@ -25,6 +27,7 @@
 #include <utility>
 #include <vector>
 
+#include <absl/base/log_severity.h>
 #include <absl/flags/flag.h>
 #include <absl/flags/parse.h>
 #include <absl/log/check.h>
@@ -33,23 +36,20 @@
 #include <absl/log/log.h>
 #include <absl/status/status.h>
 #include <absl/strings/match.h>
-#include <absl/strings/numbers.h>
 #include <absl/strings/str_cat.h>
+#include <sandboxed_api/util/fileops.h>
+#include <sandboxed_api/util/path.h>
 
-#include "host/commands/process_sandboxer/filesystem.h"
 #include "host/commands/process_sandboxer/logs.h"
 #include "host/commands/process_sandboxer/pidfd.h"
 #include "host/commands/process_sandboxer/policies.h"
 #include "host/commands/process_sandboxer/sandbox_manager.h"
-#include "host/commands/process_sandboxer/unique_fd.h"
 
 inline constexpr char kCuttlefishConfigEnvVarName[] = "CUTTLEFISH_CONFIG_FILE";
 
 ABSL_FLAG(std::string, assembly_dir, "", "cuttlefish/assembly build dir");
 ABSL_FLAG(std::string, host_artifacts_path, "", "Host exes and libs");
 ABSL_FLAG(std::string, environments_dir, "", "Cross-instance environment dir");
-ABSL_FLAG(std::string, environments_uds_dir, "", "Environment unix sockets");
-ABSL_FLAG(std::string, instance_uds_dir, "", "Instance unix domain sockets");
 ABSL_FLAG(std::string, guest_image_path, "", "Directory with `system.img`");
 ABSL_FLAG(std::string, sandboxer_log_dir, "", "Where to write log files");
 ABSL_FLAG(std::vector<std::string>, log_files, std::vector<std::string>(),
@@ -57,12 +57,14 @@ ABSL_FLAG(std::vector<std::string>, log_files, std::vector<std::string>(),
 ABSL_FLAG(std::string, runtime_dir, "",
           "Working directory of host executables");
 ABSL_FLAG(bool, verbose_stderr, false, "Write debug messages to stderr");
-ABSL_FLAG(std::string, vsock_device_dir, "/tmp/vsock_3_1000",
-          "Directory path for unix sockets representing vsock connections");
 
 namespace cuttlefish::process_sandboxer {
 namespace {
 
+using sapi::file::CleanPath;
+using sapi::file::JoinPath;
+using sapi::file_util::fileops::FDCloser;
+
 std::optional<std::string_view> FromEnv(const std::string& name) {
   char* value = getenv(name.c_str());
   return value == NULL ? std::optional<std::string_view>() : value;
@@ -86,9 +88,9 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
     return absl::ErrnoToStatus(errno, "prctl(PR_SET_CHILD_SUBREAPER failed");
   }
 
-  std::string early_tmp_dir(FromEnv("TEMP").value_or("/tmp"));
-  early_tmp_dir += "/XXXXXX";
-  if (mkdtemp(early_tmp_dir.data()) == nullptr) {
+  std::string tmp_dir(FromEnv("TMPDIR").value_or("/tmp"));
+  tmp_dir += "/process_sandboxer.XXXXXX";
+  if (mkdtemp(tmp_dir.data()) == nullptr) {
     return absl::ErrnoToStatus(errno, "mkdtemp failed");
   }
 
@@ -96,17 +98,13 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
       .assembly_dir = CleanPath(absl::GetFlag(FLAGS_assembly_dir)),
       .cuttlefish_config_path =
           CleanPath(FromEnv(kCuttlefishConfigEnvVarName).value_or("")),
-      .early_tmp_dir = early_tmp_dir,
       .environments_dir = CleanPath(absl::GetFlag(FLAGS_environments_dir)),
-      .environments_uds_dir =
-          CleanPath(absl::GetFlag(FLAGS_environments_uds_dir)),
       .guest_image_path = CleanPath(absl::GetFlag(FLAGS_guest_image_path)),
       .host_artifacts_path =
           CleanPath(absl::GetFlag(FLAGS_host_artifacts_path)),
-      .instance_uds_dir = CleanPath(absl::GetFlag(FLAGS_instance_uds_dir)),
       .log_dir = CleanPath(absl::GetFlag(FLAGS_sandboxer_log_dir)),
       .runtime_dir = CleanPath(absl::GetFlag(FLAGS_runtime_dir)),
-      .vsock_device_dir = CleanPath(absl::GetFlag(FLAGS_vsock_device_dir)),
+      .tmp_dir = tmp_dir,
   };
 
   // TODO: schuffelen - try to guess these from the cvd_internal_start arguments
@@ -125,12 +123,6 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
     host.environments_dir =
         CleanPath(JoinPath(*home, "cuttlefish", "environments"));
   }
-  if (host.environments_uds_dir == ".") {
-    host.environments_uds_dir = "/tmp/cf_env_1000";
-  }
-  if (host.instance_uds_dir == ".") {
-    host.instance_uds_dir = "/tmp/cf_avd_1000/cvd-1";
-  }
   if (host.log_dir == "." && home.has_value()) {
     host.log_dir =
         CleanPath(JoinPath(*home, "cuttlefish", "instances", "cvd-1", "logs"));
@@ -193,7 +185,7 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
   std::vector<std::string> exe_argv(++args.begin(), args.end());
 
   if (absl::EndsWith(exe, "cvd_internal_start")) {
-    exe_argv.emplace_back("--early_tmp_dir=" + host.early_tmp_dir);
+    setenv("TMPDIR", host.tmp_dir.c_str(), 1);
   }
 
   auto sandbox_manager_res = SandboxManager::Create(std::move(host));
@@ -202,14 +194,14 @@ absl::Status ProcessSandboxerMain(int argc, char** argv) {
   }
   std::unique_ptr<SandboxManager> manager = std::move(*sandbox_manager_res);
 
-  std::vector<std::pair<UniqueFd, int>> fds;
+  std::vector<std::pair<FDCloser, int>> fds;
   for (int i = 0; i <= 2; i++) {
     auto duped = fcntl(i, F_DUPFD_CLOEXEC, 0);
     if (duped < 0) {
       static constexpr char kErr[] = "Failed to `dup` stdio file descriptor";
       return absl::ErrnoToStatus(errno, kErr);
     }
-    fds.emplace_back(UniqueFd(duped), i);
+    fds.emplace_back(FDCloser(duped), i);
   }
 
   std::vector<std::string> this_env;
diff --git a/host/commands/process_sandboxer/pidfd.cpp b/host/commands/process_sandboxer/pidfd.cpp
index 1a6f488ac..ef49d3b94 100644
--- a/host/commands/process_sandboxer/pidfd.cpp
+++ b/host/commands/process_sandboxer/pidfd.cpp
@@ -24,8 +24,15 @@
 #include <sys/types.h>
 #include <unistd.h>
 
+#include <cerrno>
+#include <cstdint>
 #include <fstream>
+#include <ios>
 #include <memory>
+#include <sstream>
+#include <string>
+#include <string_view>
+#include <unordered_map>
 #include <utility>
 #include <vector>
 
@@ -39,14 +46,15 @@
 #include <absl/strings/str_join.h>
 #include <absl/strings/str_split.h>
 #include <absl/types/span.h>
-
-#include "host/commands/process_sandboxer/unique_fd.h"
+#include <sandboxed_api/util/fileops.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file_util::fileops::FDCloser;
+
 absl::StatusOr<PidFd> PidFd::FromRunningProcess(pid_t pid) {
-  UniqueFd fd(syscall(__NR_pidfd_open, pid, 0));  // Always CLOEXEC
-  if (fd.Get() < 0) {
+  FDCloser fd(syscall(__NR_pidfd_open, pid, 0));  // Always CLOEXEC
+  if (fd.get() < 0) {
     return absl::ErrnoToStatus(errno, "`pidfd_open` failed");
   }
   return PidFd(std::move(fd), pid);
@@ -54,7 +62,7 @@ absl::StatusOr<PidFd> PidFd::FromRunningProcess(pid_t pid) {
 
 absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
     absl::Span<const std::string> argv,
-    std::vector<std::pair<UniqueFd, int>> fds,
+    std::vector<std::pair<FDCloser, int>> fds,
     absl::Span<const std::string> env) {
   int pidfd;
   clone_args args_for_clone = clone_args{
@@ -71,7 +79,7 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
     std::string argv_str = absl::StrJoin(argv, "','");
     VLOG(1) << res << ": Running w/o sandbox ['" << argv_str << "]";
 
-    UniqueFd fd(pidfd);
+    FDCloser fd(pidfd);
     return PidFd(std::move(fd), res);
   }
 
@@ -86,7 +94,7 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
 
   std::unordered_map<int, int> backup_mapping;
   for (const auto& [my_fd, target_fd] : fds) {
-    int backup = fcntl(my_fd.Get(), F_DUPFD, minimum_backup_fd);
+    int backup = fcntl(my_fd.get(), F_DUPFD, minimum_backup_fd);
     PCHECK(backup >= 0) << "fcntl(..., F_DUPFD) failed";
     int flags = fcntl(backup, F_GETFD);
     PCHECK(flags >= 0) << "fcntl(..., F_GETFD failed";
@@ -102,6 +110,7 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
 
   std::vector<std::string> argv_clone(argv.begin(), argv.end());
   std::vector<char*> argv_cstr;
+  argv_cstr.reserve(argv_clone.size());
   for (auto& arg : argv_clone) {
     argv_cstr.emplace_back(arg.data());
   }
@@ -109,6 +118,7 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
 
   std::vector<std::string> env_clone(env.begin(), env.end());
   std::vector<char*> env_cstr;
+  env_cstr.reserve(env_clone.size());
   for (std::string& env_member : env_clone) {
     env_cstr.emplace_back(env_member.data());
   }
@@ -123,16 +133,16 @@ absl::StatusOr<PidFd> PidFd::LaunchSubprocess(
   PLOG(FATAL) << "execv failed";
 }
 
-PidFd::PidFd(UniqueFd fd, pid_t pid) : fd_(std::move(fd)), pid_(pid) {}
+PidFd::PidFd(FDCloser fd, pid_t pid) : fd_(std::move(fd)), pid_(pid) {}
 
-int PidFd::Get() const { return fd_.Get(); }
+int PidFd::Get() const { return fd_.get(); }
 
-absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> PidFd::AllFds() {
-  std::vector<std::pair<UniqueFd, int>> fds;
+absl::StatusOr<std::vector<std::pair<FDCloser, int>>> PidFd::AllFds() {
+  std::vector<std::pair<FDCloser, int>> fds;
 
   std::string dir_name = absl::StrFormat("/proc/%d/fd", pid_);
   std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(dir_name.c_str()), closedir);
-  if (dir.get() == nullptr) {
+  if (!dir) {
     return absl::ErrnoToStatus(errno, "`opendir` failed");
   }
   for (dirent* ent = readdir(dir.get()); ent; ent = readdir(dir.get())) {
@@ -147,8 +157,8 @@ absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> PidFd::AllFds() {
       return absl::InternalError(error);
     }
     // Always CLOEXEC
-    UniqueFd our_fd(syscall(__NR_pidfd_getfd, fd_.Get(), other_fd, 0));
-    if (our_fd.Get() < 0) {
+    FDCloser our_fd(syscall(__NR_pidfd_getfd, fd_.get(), other_fd, 0));
+    if (our_fd.get() < 0) {
       return absl::ErrnoToStatus(errno, "`pidfd_getfd` failed");
     }
     fds.emplace_back(std::move(our_fd), other_fd);
@@ -174,7 +184,7 @@ static absl::StatusOr<std::vector<std::string>> ReadNullSepFile(
   std::vector<std::string> members = absl::StrSplit(buffer.str(), '\0');
   if (members.empty()) {
     return absl::InternalError(absl::StrFormat("'%v' is empty", path));
-  } else if (members.back() == "") {
+  } else if (members.back().empty()) {
     members.pop_back();  // may end in a null terminator
   }
   return members;
@@ -205,7 +215,7 @@ static absl::StatusOr<std::vector<pid_t>> FindChildPids(pid_t pid) {
 
   std::string task_dir = absl::StrFormat("/proc/%d/task", pid);
   std::unique_ptr<DIR, int (*)(DIR*)> dir(opendir(task_dir.c_str()), closedir);
-  if (dir.get() == nullptr) {
+  if (!dir) {
     return absl::ErrnoToStatus(errno, "`opendir` failed");
   }
 
@@ -225,7 +235,7 @@ static absl::StatusOr<std::vector<pid_t>> FindChildPids(pid_t pid) {
 
     std::string children_str;
     std::getline(children_stream, children_str);
-    for (std::string_view child_str : absl::StrSplit(children_str, " ")) {
+    for (std::string_view child_str : absl::StrSplit(children_str, ' ')) {
       if (child_str.empty()) {
         continue;
       }
@@ -262,7 +272,7 @@ absl::Status PidFd::HaltChildHierarchy() {
 }
 
 absl::Status PidFd::SendSignal(int signal) {
-  if (syscall(__NR_pidfd_send_signal, fd_.Get(), signal, nullptr, 0) < 0) {
+  if (syscall(__NR_pidfd_send_signal, fd_.get(), signal, nullptr, 0) < 0) {
     return absl::ErrnoToStatus(errno, "pidfd_send_signal failed");
   }
   return absl::OkStatus();
diff --git a/host/commands/process_sandboxer/pidfd.h b/host/commands/process_sandboxer/pidfd.h
index 23e53896f..492902df6 100644
--- a/host/commands/process_sandboxer/pidfd.h
+++ b/host/commands/process_sandboxer/pidfd.h
@@ -23,11 +23,9 @@
 
 #include <absl/status/statusor.h>
 #include <absl/types/span.h>
+#include <sandboxed_api/util/fileops.h>
 
-#include "host/commands/process_sandboxer/unique_fd.h"
-
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 
 class PidFd {
  public:
@@ -42,7 +40,7 @@ class PidFd {
    * process. */
   static absl::StatusOr<PidFd> LaunchSubprocess(
       absl::Span<const std::string> argv,
-      std::vector<std::pair<UniqueFd, int>> fds,
+      std::vector<std::pair<sapi::file_util::fileops::FDCloser, int>> fds,
       absl::Span<const std::string> env);
 
   int Get() const;
@@ -53,7 +51,9 @@ class PidFd {
    * Keys are file descriptor numbers in the target process, values are open
    * file descriptors in the current process.
    */
-  absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> AllFds();
+  absl::StatusOr<
+      std::vector<std::pair<sapi::file_util::fileops::FDCloser, int>>>
+  AllFds();
   absl::StatusOr<std::vector<std::string>> Argv();
   absl::StatusOr<std::vector<std::string>> Env();
 
@@ -64,13 +64,12 @@ class PidFd {
   absl::Status HaltChildHierarchy();
 
  private:
-  PidFd(UniqueFd, pid_t);
+  PidFd(sapi::file_util::fileops::FDCloser, pid_t);
   absl::Status SendSignal(int signal);
 
-  UniqueFd fd_;
+  sapi::file_util::fileops::FDCloser fd_;
   pid_t pid_;
 };
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
 #endif
diff --git a/host/commands/process_sandboxer/policies.cpp b/host/commands/process_sandboxer/policies.cpp
index 6e54e1c9d..ca48ad4a6 100644
--- a/host/commands/process_sandboxer/policies.cpp
+++ b/host/commands/process_sandboxer/policies.cpp
@@ -16,20 +16,31 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <stdlib.h>
+
+#include <cerrno>
 #include <memory>
 #include <ostream>
+#include <set>
+#include <string>
 #include <string_view>
+#include <utility>
 
 #include <absl/container/flat_hash_map.h>
 #include <absl/log/log.h>
 #include <absl/status/status.h>
+#include <sandboxed_api/sandbox2/policy.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
+#include <sandboxed_api/util/fileops.h>
+#include <sandboxed_api/util/path.h>
 
-#include "host/commands/process_sandboxer/filesystem.h"
 #include "host/commands/process_sandboxer/proxy_common.h"
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+using sapi::file_util::fileops::CreateDirectoryRecursively;
+
 absl::Status HostInfo::EnsureOutputDirectoriesExist() {
   if (!CreateDirectoryRecursively(assembly_dir, 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + assembly_dir);
@@ -37,12 +48,12 @@ absl::Status HostInfo::EnsureOutputDirectoriesExist() {
   if (!CreateDirectoryRecursively(environments_dir, 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + environments_dir);
   }
-  if (!CreateDirectoryRecursively(environments_uds_dir, 0700)) {
+  if (!CreateDirectoryRecursively(EnvironmentsUdsDir(), 0700)) {
     return absl::ErrnoToStatus(errno,
-                               "Failed to create " + environments_uds_dir);
+                               "Failed to create " + EnvironmentsUdsDir());
   }
-  if (!CreateDirectoryRecursively(instance_uds_dir, 0700)) {
-    return absl::ErrnoToStatus(errno, "Failed to create " + instance_uds_dir);
+  if (!CreateDirectoryRecursively(InstanceUdsDir(), 0700)) {
+    return absl::ErrnoToStatus(errno, "Failed to create " + InstanceUdsDir());
   }
   if (!CreateDirectoryRecursively(log_dir, 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + log_dir);
@@ -50,29 +61,42 @@ absl::Status HostInfo::EnsureOutputDirectoriesExist() {
   if (!CreateDirectoryRecursively(runtime_dir, 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + runtime_dir);
   }
-  if (!CreateDirectoryRecursively(vsock_device_dir, 0700)) {
+  if (!CreateDirectoryRecursively(VsockDeviceDir(), 0700)) {
     return absl::ErrnoToStatus(errno, "Failed to create " + runtime_dir);
   }
   return absl::OkStatus();
 }
 
+std::string HostInfo::EnvironmentsUdsDir() const {
+  return JoinPath(tmp_dir, "cf_env_1000");
+}
+
 std::string HostInfo::HostToolExe(std::string_view exe) const {
   return JoinPath(host_artifacts_path, "bin", exe);
 }
 
+std::string HostInfo::InstanceUdsDir() const {
+  return JoinPath(tmp_dir, "cf_avd_1000/cvd-1");
+}
+
+std::string HostInfo::VsockDeviceDir() const {
+  return JoinPath(tmp_dir, "vsock_3_1000");
+}
+
 std::ostream& operator<<(std::ostream& out, const HostInfo& host) {
   out << "HostInfo {\n";
   out << "\tassembly_dir: \"" << host.assembly_dir << "\"\n";
   out << "\tcuttlefish_config_path: \"" << host.cuttlefish_config_path
       << "\"\n";
-  out << "\tearly_tmp_dir: \"" << host.early_tmp_dir << "\"\n";
   out << "\tenvironments_dir: \"" << host.environments_dir << "\"\n";
-  out << "\tenvironments_uds_dir: " << host.environments_uds_dir << "\"\n";
+  out << "\tenvironments_uds_dir: " << host.EnvironmentsUdsDir() << "\"\n";
   out << "\tguest_image_path: " << host.guest_image_path << "\t\n";
   out << "\thost_artifacts_path: \"" << host.host_artifacts_path << "\"\n";
-  out << "\tinstance_uds_dir: " << host.instance_uds_dir << "\"\n";
+  out << "\tinstance_uds_dir: " << host.InstanceUdsDir() << "\"\n";
   out << "\tlog_dir: " << host.log_dir << "\"\n";
   out << "\truntime_dir: " << host.runtime_dir << "\"\n";
+  out << "\ttmp_dir: \"" << host.tmp_dir << "\"\n";
+  out << "\tvsock_device_dir: \"" << host.VsockDeviceDir() << "\"\n";
   return out << "}";
 }
 
@@ -86,6 +110,7 @@ std::unique_ptr<sandbox2::Policy> PolicyForExecutable(
   builders[host.HostToolExe("assemble_cvd")] = AssembleCvdPolicy;
   builders[host.HostToolExe("avbtool")] = AvbToolPolicy;
   builders[host.HostToolExe("casimir")] = CasimirPolicy;
+  builders[host.HostToolExe("cf_vhost_user_input")] = CfVhostUserInput;
   builders[host.HostToolExe("casimir_control_server")] =
       CasimirControlServerPolicy;
   builders[host.HostToolExe("control_env_proxy_server")] =
diff --git a/host/commands/process_sandboxer/policies.h b/host/commands/process_sandboxer/policies.h
index 94bcd754b..9500e45ba 100644
--- a/host/commands/process_sandboxer/policies.h
+++ b/host/commands/process_sandboxer/policies.h
@@ -31,18 +31,18 @@ namespace cuttlefish::process_sandboxer {
 struct HostInfo {
   absl::Status EnsureOutputDirectoriesExist();
   std::string HostToolExe(std::string_view exe) const;
+  std::string EnvironmentsUdsDir() const;
+  std::string InstanceUdsDir() const;
+  std::string VsockDeviceDir() const;
 
   std::string assembly_dir;
   std::string cuttlefish_config_path;
-  std::string early_tmp_dir;
   std::string environments_dir;
-  std::string environments_uds_dir;
   std::string guest_image_path;
   std::string host_artifacts_path;
-  std::string instance_uds_dir;
   std::string log_dir;
   std::string runtime_dir;
-  std::string vsock_device_dir;
+  std::string tmp_dir;
 };
 
 std::ostream& operator<<(std::ostream&, const HostInfo&);
@@ -53,6 +53,7 @@ sandbox2::PolicyBuilder AdbConnectorPolicy(const HostInfo&);
 sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo&);
 sandbox2::PolicyBuilder AvbToolPolicy(const HostInfo&);
 sandbox2::PolicyBuilder CasimirPolicy(const HostInfo&);
+sandbox2::PolicyBuilder CfVhostUserInput(const HostInfo&);
 sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo&);
 sandbox2::PolicyBuilder ControlEnvProxyServerPolicy(const HostInfo&);
 sandbox2::PolicyBuilder CvdInternalStartPolicy(const HostInfo&);
diff --git a/host/commands/process_sandboxer/policies/adb_connector.cpp b/host/commands/process_sandboxer/policies/adb_connector.cpp
index ad7979900..8cce76240 100644
--- a/host/commands/process_sandboxer/policies/adb_connector.cpp
+++ b/host/commands/process_sandboxer/policies/adb_connector.cpp
@@ -19,7 +19,7 @@
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
diff --git a/host/commands/process_sandboxer/policies/assemble_cvd.cpp b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
index 0e7d6cbb8..f4acbce8d 100644
--- a/host/commands/process_sandboxer/policies/assemble_cvd.cpp
+++ b/host/commands/process_sandboxer/policies/assemble_cvd.cpp
@@ -15,36 +15,41 @@
  */
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/prctl.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
+#include <sys/socket.h>
 #include <sys/syscall.h>
 
-#include <absl/strings/str_cat.h>
-#include <absl/strings/str_replace.h>
+#include <cerrno>
+#include <string>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder AssembleCvdPolicy(const HostInfo& host) {
   std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
   return BaselinePolicy(host, host.HostToolExe("assemble_cvd"))
       .AddDirectory(host.assembly_dir, /* is_ro= */ false)
       // TODO(schuffelen): Don't resize vbmeta in-place
       .AddDirectory(host.guest_image_path, /* is_ro= */ false)
+      .AddDirectory(
+          JoinPath(host.host_artifacts_path, "etc", "bootloader_x86_64"))
       .AddDirectory(JoinPath(host.host_artifacts_path, "etc", "cvd_config"))
       // TODO(schuffelen): Copy these files before modifying them
       .AddDirectory(JoinPath(host.host_artifacts_path, "etc", "openwrt"),
                     /* is_ro= */ false)
-      .AddDirectory(host.early_tmp_dir, /* is_ro= */ false)
       .AddDirectory(host.environments_dir, /* is_ro= */ false)
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory("/tmp/cf_avd_1000", /* is_ro= */ false)
       .AddDirectory(host.runtime_dir, /* is_ro= */ false)
-      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(host.tmp_dir, /* is_ro= */ false)
+      .AddDirectory(host.VsockDeviceDir(), /* is_ro= */ false)
       // `webRTC` actually uses this file, but `assemble_cvd` first checks
       // whether it exists in order to decide whether to connect to it.
       .AddFile("/run/cuttlefish/operator")
diff --git a/host/commands/process_sandboxer/policies/avbtool.cpp b/host/commands/process_sandboxer/policies/avbtool.cpp
index d5bedd6b8..3959ff203 100644
--- a/host/commands/process_sandboxer/policies/avbtool.cpp
+++ b/host/commands/process_sandboxer/policies/avbtool.cpp
@@ -16,17 +16,23 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <stdlib.h>
 #include <sys/ioctl.h>
+#include <sys/socket.h>
 #include <syscall.h>
+#include <unistd.h>
+
+#include <string>
 
 #include <absl/log/check.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 /*
  * This executable is built as a `python_binary_host`:
  * https://cs.android.com/android/platform/superproject/main/+/main:external/avb/Android.bp;l=136;drc=1bbcd661f0afe4ab56c7031f57d518a19015805e
@@ -84,6 +90,7 @@ sandbox2::PolicyBuilder AvbToolPolicy(const HostInfo& host) {
       .AllowPipe()
       .AllowSafeFcntl()
       .AllowSyscall(__NR_connect)
+      .AllowSyscall(__NR_mremap)
       .AllowSyscall(__NR_execve)
       .AllowSyscall(__NR_ftruncate)
       .AllowSyscall(__NR_recvmsg)
diff --git a/host/commands/process_sandboxer/policies/baseline.cpp b/host/commands/process_sandboxer/policies/baseline.cpp
index 2f8678914..b82cfbb4b 100644
--- a/host/commands/process_sandboxer/policies/baseline.cpp
+++ b/host/commands/process_sandboxer/policies/baseline.cpp
@@ -16,15 +16,20 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/mman.h>
 
+#include <string_view>
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder BaselinePolicy(const HostInfo& host,
                                        std::string_view exe) {
   return sandbox2::PolicyBuilder()
diff --git a/host/commands/process_sandboxer/policies/casimir.cpp b/host/commands/process_sandboxer/policies/casimir.cpp
index 4c33ff90e..4c1acf848 100644
--- a/host/commands/process_sandboxer/policies/casimir.cpp
+++ b/host/commands/process_sandboxer/policies/casimir.cpp
@@ -16,12 +16,15 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <netinet/ip_icmp.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
+#include <sys/socket.h>
 #include <sys/syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -32,7 +35,7 @@ sandbox2::PolicyBuilder CasimirPolicy(const HostInfo& host) {
       // `librustutils::inherited_fd` scans `/proc/self/fd` for open FDs.
       // Mounting a subset of `/proc/` is invalid.
       .AddDirectory("/proc", /* is_ro = */ false)
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
       .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
         return {
             ARG_32(2),  // prot
@@ -70,7 +73,8 @@ sandbox2::PolicyBuilder CasimirPolicy(const HostInfo& host) {
       .AllowSyscall(__NR_getrandom)
       .AllowSyscall(__NR_recvfrom)
       .AllowSyscall(__NR_sendto)
-      .AllowSyscall(__NR_shutdown);
+      .AllowSyscall(__NR_shutdown)
+      .AllowSyscall(__NR_statx);  // Not covered by AllowStat
 }
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/casimir_control_server.cpp b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
index bebfe7c33..2d6cb0097 100644
--- a/host/commands/process_sandboxer/policies/casimir_control_server.cpp
+++ b/host/commands/process_sandboxer/policies/casimir_control_server.cpp
@@ -16,10 +16,13 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -27,8 +30,8 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder CasimirControlServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("casimir_control_server"))
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscall(__NR_madvise,
                           {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
diff --git a/host/commands/process_sandboxer/policies/cf_vhost_user_input.cpp b/host/commands/process_sandboxer/policies/cf_vhost_user_input.cpp
new file mode 100644
index 000000000..2362c4c95
--- /dev/null
+++ b/host/commands/process_sandboxer/policies/cf_vhost_user_input.cpp
@@ -0,0 +1,61 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <sandboxed_api/util/path.h>
+
+namespace cuttlefish::process_sandboxer {
+
+using sapi::file::JoinPath;
+
+sandbox2::PolicyBuilder CfVhostUserInput(const HostInfo& host) {
+  return BaselinePolicy(host, host.HostToolExe("cf_vhost_user_input"))
+      .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddDirectory("/proc", /* is_ro= */ false)  // for inherited_fds
+      .AddDirectory(
+          JoinPath(host.host_artifacts_path, "etc", "default_input_devices"))
+      .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
+        return {
+            ARG_32(2),  // prot
+            JNE32(PROT_READ | PROT_WRITE,
+                  JUMP(&labels, cf_vhost_user_input_mmap_end)),
+            ARG_32(3),  // flags
+            JEQ32(MAP_STACK | MAP_ANONYMOUS | MAP_PRIVATE, ALLOW),
+            JEQ32(MAP_NORESERVE | MAP_SHARED, ALLOW),
+            LABEL(&labels, cf_vhost_user_input_mmap_end),
+        };
+      })
+      .AllowEpoll()
+      .AllowEventFd()
+      .AllowHandleSignals()
+      .AllowReaddir()
+      .AllowPrctlSetName()
+      .AllowSyscall(__NR_accept4)
+      .AllowSyscall(__NR_clone)
+      .AllowSyscall(__NR_getrandom)
+      .AllowSyscall(__NR_recvmsg)
+      .AllowSyscall(__NR_sendmsg)
+      .AllowSyscall(__NR_statx)
+      .AllowSafeFcntl();
+}
+
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp b/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp
index 9db224693..e784f7a87 100644
--- a/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp
+++ b/host/commands/process_sandboxer/policies/control_env_proxy_server.cpp
@@ -16,18 +16,21 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
+#include <cerrno>
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
 namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder ControlEnvProxyServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("control_env_proxy_server"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscall(__NR_madvise,
                           {ARG_32(2), JEQ32(MADV_DONTNEED, ALLOW)})
diff --git a/host/commands/process_sandboxer/policies/cvd_internal_start.cpp b/host/commands/process_sandboxer/policies/cvd_internal_start.cpp
index 165cab237..b8b3bfc2f 100644
--- a/host/commands/process_sandboxer/policies/cvd_internal_start.cpp
+++ b/host/commands/process_sandboxer/policies/cvd_internal_start.cpp
@@ -15,12 +15,12 @@
  */
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/prctl.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
+#include <sys/socket.h>
 #include <sys/syscall.h>
-#include <sys/un.h>
 
-#include <absl/log/log.h>
+#include <string>
 
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
diff --git a/host/commands/process_sandboxer/policies/echo_server.cpp b/host/commands/process_sandboxer/policies/echo_server.cpp
index 10e2d70cf..81080911c 100644
--- a/host/commands/process_sandboxer/policies/echo_server.cpp
+++ b/host/commands/process_sandboxer/policies/echo_server.cpp
@@ -20,6 +20,8 @@
 #include <sys/socket.h>
 #include <syscall.h>
 
+#include <cerrno>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -27,7 +29,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder EchoServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("echo_server"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddFile(host.cuttlefish_config_path)
diff --git a/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp b/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp
index 24ba97169..83d883e0a 100644
--- a/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp
+++ b/host/commands/process_sandboxer/policies/gnss_grpc_proxy.cpp
@@ -18,6 +18,7 @@
 
 #include <errno.h>
 #include <sys/mman.h>
+#include <sys/socket.h>
 #include <sys/syscall.h>
 
 #include <sandboxed_api/sandbox2/policybuilder.h>
@@ -27,7 +28,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder GnssGrpcProxyPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("gnss_grpc_proxy"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddFile(host.cuttlefish_config_path)
diff --git a/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp b/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
index d963c184e..9aac89800 100644
--- a/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
+++ b/host/commands/process_sandboxer/policies/kernel_log_monitor.cpp
@@ -16,8 +16,6 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
-#include <sys/prctl.h>
-
 #include <sandboxed_api/sandbox2/policybuilder.h>
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/process_sandboxer/policies/logcat_receiver.cpp b/host/commands/process_sandboxer/policies/logcat_receiver.cpp
index 62d187638..4ac08ec1e 100644
--- a/host/commands/process_sandboxer/policies/logcat_receiver.cpp
+++ b/host/commands/process_sandboxer/policies/logcat_receiver.cpp
@@ -16,8 +16,6 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
-#include <sys/prctl.h>
-
 #include <sandboxed_api/sandbox2/policybuilder.h>
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/process_sandboxer/policies/metrics.cpp b/host/commands/process_sandboxer/policies/metrics.cpp
index 2b6e0b1f6..f771b100b 100644
--- a/host/commands/process_sandboxer/policies/metrics.cpp
+++ b/host/commands/process_sandboxer/policies/metrics.cpp
@@ -18,7 +18,7 @@
 
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/process_sandboxer/policies/modem_simulator.cpp b/host/commands/process_sandboxer/policies/modem_simulator.cpp
index 9f6f8a8cc..2e5044849 100644
--- a/host/commands/process_sandboxer/policies/modem_simulator.cpp
+++ b/host/commands/process_sandboxer/policies/modem_simulator.cpp
@@ -16,15 +16,20 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
+#include <sys/socket.h>
 #include <syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder ModemSimulatorPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("modem_simulator"))
       .AddDirectory(JoinPath(host.host_artifacts_path, "/etc/modem_simulator"))
diff --git a/host/commands/process_sandboxer/policies/netsimd.cpp b/host/commands/process_sandboxer/policies/netsimd.cpp
index e9799f185..895d4f3be 100644
--- a/host/commands/process_sandboxer/policies/netsimd.cpp
+++ b/host/commands/process_sandboxer/policies/netsimd.cpp
@@ -16,25 +16,30 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
+#include <linux/prctl.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <vector>
+
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder NetsimdPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("netsimd"))
       .AddDirectory(JoinPath(host.host_artifacts_path, "bin", "netsim-ui"))
       .AddDirectory(JoinPath(host.runtime_dir, "internal"), /* is_ro= */ false)
+      .AddDirectory(host.tmp_dir, /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscalls(
           {__NR_getsockopt, __NR_setsockopt},
diff --git a/host/commands/process_sandboxer/policies/openwrt_control_server.cpp b/host/commands/process_sandboxer/policies/openwrt_control_server.cpp
index c6ac46dd4..fa8e6cc3b 100644
--- a/host/commands/process_sandboxer/policies/openwrt_control_server.cpp
+++ b/host/commands/process_sandboxer/policies/openwrt_control_server.cpp
@@ -16,12 +16,15 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <netinet/tcp.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <vector>
+
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -29,7 +32,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder OpenWrtControlServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("openwrt_control_server"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir)
       .AddFile("/dev/urandom")  // For gRPC
       .AddPolicyOnSyscall(__NR_madvise,
diff --git a/host/commands/process_sandboxer/policies/operator_proxy.cpp b/host/commands/process_sandboxer/policies/operator_proxy.cpp
index 3c7da6127..03cee0c34 100644
--- a/host/commands/process_sandboxer/policies/operator_proxy.cpp
+++ b/host/commands/process_sandboxer/policies/operator_proxy.cpp
@@ -18,7 +18,7 @@
 
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/process_sandboxer/policies/process_restarter.cpp b/host/commands/process_sandboxer/policies/process_restarter.cpp
index 14adad7fe..a879f55d2 100644
--- a/host/commands/process_sandboxer/policies/process_restarter.cpp
+++ b/host/commands/process_sandboxer/policies/process_restarter.cpp
@@ -15,13 +15,12 @@
  */
 #include "host/commands/process_sandboxer/policies.h"
 
-#include <sys/prctl.h>
+#include <linux/prctl.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <absl/log/log.h>
-#include <absl/strings/str_cat.h>
-#include <absl/strings/str_replace.h>
+#include <string>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
diff --git a/host/commands/process_sandboxer/policies/run_cvd.cpp b/host/commands/process_sandboxer/policies/run_cvd.cpp
index 0ec1fcc08..82d3213c6 100644
--- a/host/commands/process_sandboxer/policies/run_cvd.cpp
+++ b/host/commands/process_sandboxer/policies/run_cvd.cpp
@@ -15,26 +15,40 @@
  */
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/bpf_common.h>
+#include <linux/filter.h>
+#include <linux/prctl.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
 #include <sys/socket.h>
 #include <sys/stat.h>
 #include <syscall.h>
+#include <unistd.h>
+
+#include <cstdint>
+#include <string>
+#include <vector>
 
 #include <absl/strings/str_cat.h>
 #include <absl/strings/str_replace.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder RunCvdPolicy(const HostInfo& host) {
   std::string sandboxer_proxy = host.HostToolExe("sandboxer_proxy");
   return BaselinePolicy(host, host.HostToolExe("run_cvd"))
       .AddDirectory(host.runtime_dir, /* is_ro= */ false)
+      .AddDirectory(
+          JoinPath(host.host_artifacts_path, "etc", "default_input_devices"))
       .AddFile(host.cuttlefish_config_path)
+      .AddFile("/dev/null", /* is_ro= */ false)
       .AddFileAt(sandboxer_proxy, host.HostToolExe("adb_connector"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("casimir_control_server"))
+      .AddFileAt(sandboxer_proxy, host.HostToolExe("cf_vhost_user_input"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("control_env_proxy_server"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("crosvm"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("echo_server"))
@@ -58,18 +72,18 @@ sandbox2::PolicyBuilder RunCvdPolicy(const HostInfo& host) {
       .AddFileAt(sandboxer_proxy, host.HostToolExe("wmediumd"))
       .AddFileAt(sandboxer_proxy, host.HostToolExe("wmediumd_gen_config"))
       .AddDirectory(host.environments_dir)
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.VsockDeviceDir(), /* is_ro= */ false)
       // The UID inside the sandbox2 namespaces is always 1000.
-      .AddDirectoryAt(host.environments_uds_dir,
+      .AddDirectoryAt(host.EnvironmentsUdsDir(),
                       absl::StrReplaceAll(
-                          host.environments_uds_dir,
+                          host.EnvironmentsUdsDir(),
                           {{absl::StrCat("cf_env_", getuid()), "cf_env_1000"}}),
                       false)
-      .AddDirectoryAt(host.instance_uds_dir,
+      .AddDirectoryAt(host.InstanceUdsDir(),
                       absl::StrReplaceAll(
-                          host.instance_uds_dir,
+                          host.InstanceUdsDir(),
                           {{absl::StrCat("cf_avd_", getuid()), "cf_avd_1000"}}),
                       false)
       .AddPolicyOnSyscall(__NR_madvise,
@@ -129,6 +143,7 @@ sandbox2::PolicyBuilder RunCvdPolicy(const HostInfo& host) {
       .AllowSyscall(__NR_recvmsg)
       .AllowSyscall(__NR_sendmsg)
       .AllowSyscall(__NR_setpgid)
+      .AllowSyscall(__NR_shutdown)
       .AllowSyscall(__NR_socketpair)
       .AllowSyscall(__NR_waitid)  // Not covered by `AllowWait()`
       .AllowTCGETS()
diff --git a/host/commands/process_sandboxer/policies/screen_recording_server.cpp b/host/commands/process_sandboxer/policies/screen_recording_server.cpp
index b260da865..b229431f3 100644
--- a/host/commands/process_sandboxer/policies/screen_recording_server.cpp
+++ b/host/commands/process_sandboxer/policies/screen_recording_server.cpp
@@ -17,10 +17,13 @@
 #include "host/commands/process_sandboxer/policies.h"
 
 #include <errno.h>
+#include <linux/filter.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -28,7 +31,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder ScreenRecordingServerPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("screen_recording_server"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddFile(host.cuttlefish_config_path)
diff --git a/host/commands/process_sandboxer/policies/secure_env.cpp b/host/commands/process_sandboxer/policies/secure_env.cpp
index 1b5629729..09328da4b 100644
--- a/host/commands/process_sandboxer/policies/secure_env.cpp
+++ b/host/commands/process_sandboxer/policies/secure_env.cpp
@@ -18,6 +18,8 @@
 
 #include <syscall.h>
 
+#include <string>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 
 namespace cuttlefish::process_sandboxer {
diff --git a/host/commands/process_sandboxer/policies/simg2img.cpp b/host/commands/process_sandboxer/policies/simg2img.cpp
index a3266aa77..fbcefc070 100644
--- a/host/commands/process_sandboxer/policies/simg2img.cpp
+++ b/host/commands/process_sandboxer/policies/simg2img.cpp
@@ -16,9 +16,12 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/mman.h>
 #include <syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
diff --git a/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp b/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp
index 053536e68..ed0ee52a1 100644
--- a/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp
+++ b/host/commands/process_sandboxer/policies/socket_vsock_proxy.cpp
@@ -19,7 +19,7 @@
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -28,7 +28,7 @@ namespace cuttlefish::process_sandboxer {
 sandbox2::PolicyBuilder SocketVsockProxyPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("socket_vsock_proxy"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
-      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(host.VsockDeviceDir(), /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
       .AddPolicyOnSyscall(
           __NR_socket, {ARG_32(0), JEQ32(AF_UNIX, ALLOW), JEQ32(AF_INET, ALLOW),
diff --git a/host/commands/process_sandboxer/policies/tcp_connector.cpp b/host/commands/process_sandboxer/policies/tcp_connector.cpp
index 63eadb5da..c34b1a9d4 100644
--- a/host/commands/process_sandboxer/policies/tcp_connector.cpp
+++ b/host/commands/process_sandboxer/policies/tcp_connector.cpp
@@ -16,9 +16,10 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <sys/socket.h>
 #include <sys/syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -26,7 +27,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder TcpConnectorPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("tcp_connector"))
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
       .AddPolicyOnSyscall(__NR_socket, {ARG_32(0), JEQ32(AF_INET, ALLOW),
diff --git a/host/commands/process_sandboxer/policies/tombstone_receiver.cpp b/host/commands/process_sandboxer/policies/tombstone_receiver.cpp
index 446cee2f9..4e8a97df8 100644
--- a/host/commands/process_sandboxer/policies/tombstone_receiver.cpp
+++ b/host/commands/process_sandboxer/policies/tombstone_receiver.cpp
@@ -19,11 +19,12 @@
 #include <sys/syscall.h>
 
 #include <sandboxed_api/sandbox2/policybuilder.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder TombstoneReceiverPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("tombstone_receiver"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
diff --git a/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp b/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp
index d9f109200..419bf99b8 100644
--- a/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp
+++ b/host/commands/process_sandboxer/policies/vhost_device_vsock.cpp
@@ -16,10 +16,14 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
+#include <sys/socket.h>
 #include <syscall.h>
 
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
 
@@ -27,7 +31,7 @@ namespace cuttlefish::process_sandboxer {
 
 sandbox2::PolicyBuilder VhostDeviceVsockPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("vhost_device_vsock"))
-      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(host.VsockDeviceDir(), /* is_ro= */ false)
       .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
         return {
             ARG_32(2),  // prot
diff --git a/host/commands/process_sandboxer/policies/webrtc.cpp b/host/commands/process_sandboxer/policies/webrtc.cpp
index c9117e4aa..b58ac0121 100644
--- a/host/commands/process_sandboxer/policies/webrtc.cpp
+++ b/host/commands/process_sandboxer/policies/webrtc.cpp
@@ -16,30 +16,34 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
+#include <linux/prctl.h>
 #include <linux/sockios.h>
 #include <netinet/in.h>
 #include <netinet/tcp.h>
 #include <sys/ioctl.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <vector>
+
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder WebRtcPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("webRTC"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddDirectory(
           JoinPath(host.host_artifacts_path, "/usr/share/webrtc/assets"))
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.vsock_device_dir, /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.VsockDeviceDir(), /* is_ro= */ false)
       .AddDirectory(JoinPath(host.runtime_dir, "recording"), /* is_ro= */ false)
       .AddFile(host.cuttlefish_config_path)
       .AddFile("/dev/urandom")
diff --git a/host/commands/process_sandboxer/policies/webrtc_operator.cpp b/host/commands/process_sandboxer/policies/webrtc_operator.cpp
index 938779492..3947fe8bc 100644
--- a/host/commands/process_sandboxer/policies/webrtc_operator.cpp
+++ b/host/commands/process_sandboxer/policies/webrtc_operator.cpp
@@ -16,20 +16,25 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
+#include <linux/prctl.h>
 #include <netinet/ip_icmp.h>
 #include <netinet/tcp.h>
 #include <sys/mman.h>
-#include <sys/prctl.h>
+#include <sys/socket.h>
 #include <sys/syscall.h>
 
-#include <sandboxed_api/sandbox2/allow_unrestricted_networking.h>
+#include <vector>
+
+#include <sandboxed_api/sandbox2/allowlists/unrestricted_networking.h>
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder WebRtcOperatorPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("webrtc_operator"))
       .AddDirectory(host.log_dir, /* is_ro= */ false)
diff --git a/host/commands/process_sandboxer/policies/wmediumd.cpp b/host/commands/process_sandboxer/policies/wmediumd.cpp
index ac51ef5a2..d01023544 100644
--- a/host/commands/process_sandboxer/policies/wmediumd.cpp
+++ b/host/commands/process_sandboxer/policies/wmediumd.cpp
@@ -16,21 +16,26 @@
 
 #include "host/commands/process_sandboxer/policies.h"
 
+#include <linux/filter.h>
 #include <sys/mman.h>
 #include <sys/socket.h>
 #include <syscall.h>
 
+#include <cerrno>
+#include <vector>
+
 #include <sandboxed_api/sandbox2/policybuilder.h>
 #include <sandboxed_api/sandbox2/util/bpf_helper.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder WmediumdPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("wmediumd"))
-      .AddDirectory(host.environments_uds_dir, /* is_ro= */ false)
-      .AddDirectory(host.instance_uds_dir, /* is_ro= */ false)
+      .AddDirectory(host.EnvironmentsUdsDir(), /* is_ro= */ false)
+      .AddDirectory(host.InstanceUdsDir(), /* is_ro= */ false)
       .AddDirectory(host.log_dir, /* is_ro= */ false)
       .AddFile("/dev/urandom")  // For gRPC
       .AddFile(JoinPath(host.environments_dir, "env-1", "wmediumd.cfg"),
@@ -40,10 +45,10 @@ sandbox2::PolicyBuilder WmediumdPolicy(const HostInfo& host) {
       .AddPolicyOnMmap([](bpf_labels& labels) -> std::vector<sock_filter> {
         return {
             ARG_32(2),  // prot
-            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_webrtc_mmap_end)),
+            JNE32(PROT_READ | PROT_WRITE, JUMP(&labels, cf_wmediumd_mmap_end)),
             ARG_32(3),  // flags
             JEQ32(MAP_SHARED, ALLOW),
-            LABEL(&labels, cf_webrtc_mmap_end),
+            LABEL(&labels, cf_wmediumd_mmap_end),
         };
       })
       .AddPolicyOnSyscalls(
@@ -51,11 +56,10 @@ sandbox2::PolicyBuilder WmediumdPolicy(const HostInfo& host) {
           [](bpf_labels& labels) -> std::vector<sock_filter> {
             return {
                 ARG_32(1),  // level
-                JNE32(SOL_SOCKET,
-                      JUMP(&labels, cf_screen_recording_server_getsockopt_end)),
+                JNE32(SOL_SOCKET, JUMP(&labels, cf_wmediumd_getsockopt_end)),
                 ARG_32(2),  // optname
                 JEQ32(SO_REUSEPORT, ALLOW),
-                LABEL(&labels, cf_screen_recording_server_getsockopt_end),
+                LABEL(&labels, cf_wmediumd_getsockopt_end),
             };
           })
       .AddPolicyOnSyscall(__NR_madvise,
diff --git a/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp b/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp
index 5a6477a30..9a3d93a70 100644
--- a/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp
+++ b/host/commands/process_sandboxer/policies/wmediumd_gen_config.cpp
@@ -17,11 +17,12 @@
 #include "host/commands/process_sandboxer/policies.h"
 
 #include <sandboxed_api/sandbox2/policybuilder.h>
-
-#include "host/commands/process_sandboxer/filesystem.h"
+#include <sandboxed_api/util/path.h>
 
 namespace cuttlefish::process_sandboxer {
 
+using sapi::file::JoinPath;
+
 sandbox2::PolicyBuilder WmediumdGenConfigPolicy(const HostInfo& host) {
   return BaselinePolicy(host, host.HostToolExe("wmediumd_gen_config"))
       .AddDirectory(JoinPath(host.environments_dir, "env-1"),
diff --git a/host/commands/process_sandboxer/poll_callback.cpp b/host/commands/process_sandboxer/poll_callback.cpp
index 6b4d398be..d82478776 100644
--- a/host/commands/process_sandboxer/poll_callback.cpp
+++ b/host/commands/process_sandboxer/poll_callback.cpp
@@ -18,14 +18,16 @@
 
 #include <poll.h>
 
+#include <cerrno>
+#include <cstddef>
 #include <functional>
+#include <utility>
 #include <vector>
 
 #include <absl/log/log.h>
 #include <absl/status/status.h>
 
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 
 void PollCallback::Add(int fd, std::function<absl::Status(short)> cb) {
   pollfds_.emplace_back(pollfd{
@@ -56,5 +58,4 @@ absl::Status PollCallback::Poll() {
   return absl::OkStatus();
 }
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/poll_callback.h b/host/commands/process_sandboxer/poll_callback.h
index fdc77765a..25d38e63d 100644
--- a/host/commands/process_sandboxer/poll_callback.h
+++ b/host/commands/process_sandboxer/poll_callback.h
@@ -23,8 +23,7 @@
 
 #include <absl/status/status.h>
 
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 
 class PollCallback {
  public:
@@ -37,7 +36,6 @@ class PollCallback {
   std::vector<std::function<absl::Status(short)>> callbacks_;
 };
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
 
 #endif
diff --git a/host/commands/process_sandboxer/proxy_common.cpp b/host/commands/process_sandboxer/proxy_common.cpp
index 82212e728..0265adc15 100644
--- a/host/commands/process_sandboxer/proxy_common.cpp
+++ b/host/commands/process_sandboxer/proxy_common.cpp
@@ -16,13 +16,17 @@
 #include "host/commands/process_sandboxer/proxy_common.h"
 
 #include <sys/socket.h>
+#include <sys/uio.h>
 
+#include <cerrno>
 #include <cstdlib>
+#include <cstring>
+#include <optional>
 #include <string>
+#include <string_view>
 
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
-#include <absl/strings/numbers.h>
 
 namespace cuttlefish::process_sandboxer {
 
diff --git a/host/commands/process_sandboxer/proxy_common.h b/host/commands/process_sandboxer/proxy_common.h
index 9e2629a0f..bdcd10652 100644
--- a/host/commands/process_sandboxer/proxy_common.h
+++ b/host/commands/process_sandboxer/proxy_common.h
@@ -25,8 +25,7 @@
 
 #include <absl/status/statusor.h>
 
-namespace cuttlefish {
-namespace process_sandboxer {
+namespace cuttlefish::process_sandboxer {
 
 static const constexpr std::string_view kHandshakeBegin = "hello";
 static const constexpr std::string_view kManagerSocketPath = "/manager.sock";
@@ -51,6 +50,5 @@ class Message {
 
 absl::StatusOr<size_t> SendStringMsg(int sock, std::string_view msg);
 
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
+}  // namespace cuttlefish::process_sandboxer
 #endif
diff --git a/host/commands/process_sandboxer/sandbox_manager.cpp b/host/commands/process_sandboxer/sandbox_manager.cpp
index 929bc3a80..f66c60017 100644
--- a/host/commands/process_sandboxer/sandbox_manager.cpp
+++ b/host/commands/process_sandboxer/sandbox_manager.cpp
@@ -15,22 +15,30 @@
  */
 #include "host/commands/process_sandboxer/sandbox_manager.h"
 
-#include <fcntl.h>
-#include <linux/sched.h>
+#include <poll.h>
 #include <signal.h>
+#include <stdlib.h>
 #include <sys/eventfd.h>
-#include <sys/prctl.h>
+#include <sys/resource.h>
 #include <sys/signalfd.h>
 #include <sys/socket.h>
 #include <sys/syscall.h>
-#include <sys/un.h>
 #include <sys/wait.h>
 #include <unistd.h>
 
+#include <algorithm>
+#include <cerrno>
+#include <cstddef>
+#include <cstdint>
+#include <functional>
 #include <memory>
+#include <optional>
 #include <sstream>
+#include <string>
+#include <string_view>
 #include <thread>
 #include <utility>
+#include <vector>
 
 #include <absl/functional/bind_front.h>
 #include <absl/log/log.h>
@@ -43,30 +51,33 @@
 #include <absl/strings/numbers.h>
 #include <absl/strings/str_cat.h>
 #include <absl/strings/str_format.h>
-#include <absl/strings/str_join.h>
+#include <absl/time/time.h>
 #include <absl/types/span.h>
 #pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wdeprecated-declarations"
 #pragma clang diagnostic ignored "-Wunused-parameter"
 #include <sandboxed_api/sandbox2/executor.h>
 #include <sandboxed_api/sandbox2/policy.h>
 #include <sandboxed_api/sandbox2/sandbox2.h>
-#include <sandboxed_api/sandbox2/util.h>
+#include <sandboxed_api/util/fileops.h>
+#include <sandboxed_api/util/path.h>
 #pragma clang diagnostic pop
 
 #include "host/commands/process_sandboxer/credentialed_unix_server.h"
-#include "host/commands/process_sandboxer/filesystem.h"
 #include "host/commands/process_sandboxer/pidfd.h"
 #include "host/commands/process_sandboxer/policies.h"
 #include "host/commands/process_sandboxer/poll_callback.h"
 #include "host/commands/process_sandboxer/proxy_common.h"
+#include "host/commands/process_sandboxer/signal_fd.h"
 
 namespace cuttlefish::process_sandboxer {
 
 using sandbox2::Executor;
 using sandbox2::Policy;
 using sandbox2::Sandbox2;
-using sandbox2::Syscall;
-using sandbox2::util::GetProgName;
+using sapi::file::CleanPath;
+using sapi::file::JoinPath;
+using sapi::file_util::fileops::FDCloser;
 
 namespace {
 
@@ -116,7 +127,7 @@ class SandboxManager::ProcessNoSandbox : public SandboxManager::ManagedProcess {
 
 class SandboxManager::SandboxedProcess : public SandboxManager::ManagedProcess {
  public:
-  SandboxedProcess(std::optional<int> client_fd, UniqueFd event_fd,
+  SandboxedProcess(std::optional<int> client_fd, FDCloser event_fd,
                    std::unique_ptr<Sandbox2> sandbox)
       : client_fd_(client_fd),
         event_fd_(std::move(event_fd)),
@@ -133,7 +144,7 @@ class SandboxManager::SandboxedProcess : public SandboxManager::ManagedProcess {
   }
 
   std::optional<int> ClientFd() const override { return client_fd_; }
-  int PollFd() const override { return event_fd_.Get(); }
+  int PollFd() const override { return event_fd_.get(); }
 
   absl::StatusOr<uintptr_t> ExitCode() override {
     return sandbox_->AwaitResult().reason_code();
@@ -143,13 +154,13 @@ class SandboxManager::SandboxedProcess : public SandboxManager::ManagedProcess {
   void WaitForExit() {
     sandbox_->AwaitResult().IgnoreResult();
     uint64_t buf = 1;
-    if (write(event_fd_.Get(), &buf, sizeof(buf)) < 0) {
+    if (write(event_fd_.get(), &buf, sizeof(buf)) < 0) {
       PLOG(ERROR) << "Failed to write to eventfd";
     }
   }
 
   std::optional<int> client_fd_;
-  UniqueFd event_fd_;
+  FDCloser event_fd_;
   std::thread waiter_thread_;
   std::unique_ptr<Sandbox2> sandbox_;
 };
@@ -165,14 +176,14 @@ std::string RandomString(absl::BitGenRef gen, std::size_t size) {
 
 class SandboxManager::SocketClient {
  public:
-  SocketClient(SandboxManager& manager, UniqueFd client_fd)
+  SocketClient(SandboxManager& manager, FDCloser client_fd)
       : manager_(manager), client_fd_(std::move(client_fd)) {}
   SocketClient(SocketClient&) = delete;
 
-  int ClientFd() const { return client_fd_.Get(); }
+  int ClientFd() const { return client_fd_.get(); }
 
   absl::Status HandleMessage() {
-    auto message_status = Message::RecvFrom(client_fd_.Get());
+    auto message_status = Message::RecvFrom(client_fd_.get());
     if (!message_status.ok()) {
       return message_status.status();
     }
@@ -208,7 +219,7 @@ class SandboxManager::SocketClient {
         }
         pingback_ = RandomString(manager_.bit_gen_, 32);
         absl::StatusOr<std::size_t> stat =
-            SendStringMsg(client_fd_.Get(), pingback_);
+            SendStringMsg(client_fd_.get(), pingback_);
         if (stat.ok()) {
           client_state_ = ClientState::kIgnoredFd;
         }
@@ -237,12 +248,12 @@ class SandboxManager::SocketClient {
   }
 
   absl::Status SendExitCode(int code) {
-    auto send_exit_status = SendStringMsg(client_fd_.Get(), "exit");
+    auto send_exit_status = SendStringMsg(client_fd_.get(), "exit");
     if (!send_exit_status.ok()) {
       return send_exit_status.status();
     }
 
-    return SendStringMsg(client_fd_.Get(), std::to_string(code)).status();
+    return SendStringMsg(client_fd_.get(), std::to_string(code)).status();
   }
 
  private:
@@ -284,7 +295,7 @@ class SandboxManager::SocketClient {
     if ((*argv)[0] == "openssl") {
       (*argv)[0] = "/usr/bin/openssl";
     }
-    absl::StatusOr<std::vector<std::pair<UniqueFd, int>>> fds =
+    absl::StatusOr<std::vector<std::pair<FDCloser, int>>> fds =
         pid_fd_->AllFds();
     if (!fds.ok()) {
       return fds.status();
@@ -293,15 +304,16 @@ class SandboxManager::SocketClient {
     if (!env.ok()) {
       return env.status();
     }
-    fds->erase(std::remove_if(fds->begin(), fds->end(), [this](auto& arg) {
-      return arg.second == ignored_fd_;
-    }));
-    return manager_.RunProcess(client_fd_.Get(), std::move(*argv),
+    fds->erase(
+        std::remove_if(fds->begin(), fds->end(),
+                       [this](auto& arg) { return arg.second == ignored_fd_; }),
+        fds->end());
+    return manager_.RunProcess(client_fd_.get(), std::move(*argv),
                                std::move(*fds), *env);
   }
 
   SandboxManager& manager_;
-  UniqueFd client_fd_;
+  FDCloser client_fd_;
   std::optional<ucred> credentials_;
   std::optional<PidFd> pid_fd_;
 
@@ -356,7 +368,7 @@ SandboxManager::~SandboxManager() {
 
 absl::Status SandboxManager::RunProcess(
     std::optional<int> client_fd, absl::Span<const std::string> argv,
-    std::vector<std::pair<UniqueFd, int>> fds,
+    std::vector<std::pair<FDCloser, int>> fds,
     absl::Span<const std::string> env) {
   if (argv.empty()) {
     return absl::InvalidArgumentError("Not enough arguments");
@@ -374,7 +386,7 @@ absl::Status SandboxManager::RunProcess(
       continue;
     }
     auto& [stdio_dup, stdio] = fds.emplace_back(dup(i), i);
-    if (stdio_dup.Get() < 0) {
+    if (stdio_dup.get() < 0) {
       return absl::ErrnoToStatus(errno, "Failed to `dup` stdio descriptor");
     }
   }
@@ -391,7 +403,7 @@ absl::Status SandboxManager::RunProcess(
 
 absl::Status SandboxManager::RunSandboxedProcess(
     std::optional<int> client_fd, absl::Span<const std::string> argv,
-    std::vector<std::pair<UniqueFd, int>> fds,
+    std::vector<std::pair<FDCloser, int>> fds,
     absl::Span<const std::string> env, std::unique_ptr<Policy> policy) {
   if (VLOG_IS_ON(1)) {
     std::stringstream process_stream;
@@ -401,7 +413,7 @@ absl::Status SandboxManager::RunSandboxedProcess(
     }
     process_stream << "] with FD mapping: [\n";
     for (const auto& [fd_in, fd_out] : fds) {
-      process_stream << '\t' << fd_in.Get() << " -> " << fd_out << ",\n";
+      process_stream << '\t' << fd_in.get() << " -> " << fd_out << ",\n";
     }
     process_stream << "]\n";
     VLOG(1) << process_stream.str();
@@ -422,8 +434,8 @@ absl::Status SandboxManager::RunSandboxedProcess(
     executor->ipc()->MapFd(fd_outer.Release(), fd_inner);
   }
 
-  UniqueFd event_fd(eventfd(0, EFD_CLOEXEC));
-  if (event_fd.Get() < 0) {
+  FDCloser event_fd(eventfd(0, EFD_CLOEXEC));
+  if (event_fd.get() < 0) {
     return absl::ErrnoToStatus(errno, "`eventfd` failed");
   }
 
@@ -456,7 +468,7 @@ absl::Status SandboxManager::RunSandboxedProcess(
 
 absl::Status SandboxManager::RunProcessNoSandbox(
     std::optional<int> client_fd, absl::Span<const std::string> argv,
-    std::vector<std::pair<UniqueFd, int>> fds,
+    std::vector<std::pair<FDCloser, int>> fds,
     absl::Span<const std::string> env) {
   if (!client_fd) {
     return absl::InvalidArgumentError("no client for unsandboxed process");
@@ -476,16 +488,17 @@ bool SandboxManager::Running() const { return running_; }
 absl::Status SandboxManager::Iterate() {
   PollCallback poll_cb;
 
-  poll_cb.Add(signals_.Fd(), bind_front(&SandboxManager::Signalled, this));
-  poll_cb.Add(server_.Fd(), bind_front(&SandboxManager::NewClient, this));
+  poll_cb.Add(signals_.Fd(),
+              absl::bind_front(&SandboxManager::Signalled, this));
+  poll_cb.Add(server_.Fd(), absl::bind_front(&SandboxManager::NewClient, this));
 
   for (auto it = subprocesses_.begin(); it != subprocesses_.end(); it++) {
     int fd = (*it)->PollFd();
-    poll_cb.Add(fd, bind_front(&SandboxManager::ProcessExit, this, it));
+    poll_cb.Add(fd, absl::bind_front(&SandboxManager::ProcessExit, this, it));
   }
   for (auto it = clients_.begin(); it != clients_.end(); it++) {
     int fd = (*it)->ClientFd();
-    poll_cb.Add(fd, bind_front(&SandboxManager::ClientMessage, this, it));
+    poll_cb.Add(fd, absl::bind_front(&SandboxManager::ClientMessage, this, it));
   }
 
   return poll_cb.Poll();
@@ -521,7 +534,7 @@ absl::Status SandboxManager::NewClient(short revents) {
     running_ = false;
     return absl::InternalError("server socket exited");
   }
-  absl::StatusOr<UniqueFd> client = server_.AcceptClient();
+  absl::StatusOr<FDCloser> client = server_.AcceptClient();
   if (!client.ok()) {
     return client.status();
   }
diff --git a/host/commands/process_sandboxer/sandbox_manager.h b/host/commands/process_sandboxer/sandbox_manager.h
index 5711f68cc..e1cee37df 100644
--- a/host/commands/process_sandboxer/sandbox_manager.h
+++ b/host/commands/process_sandboxer/sandbox_manager.h
@@ -28,11 +28,11 @@
 #include <absl/status/statusor.h>
 #include <absl/types/span.h>
 #include <sandboxed_api/sandbox2/policy.h>
+#include <sandboxed_api/util/fileops.h>
 
 #include "host/commands/process_sandboxer/credentialed_unix_server.h"
 #include "host/commands/process_sandboxer/policies.h"
 #include "host/commands/process_sandboxer/signal_fd.h"
-#include "host/commands/process_sandboxer/unique_fd.h"
 
 namespace cuttlefish::process_sandboxer {
 
@@ -48,10 +48,10 @@ class SandboxManager {
    *
    * For (key, value) pairs in `fds`, `key` on the outside is mapped to `value`
    * in the sandbox, and `key` is `close`d on the outside. */
-  absl::Status RunProcess(std::optional<int> client_fd,
-                          absl::Span<const std::string> argv,
-                          std::vector<std::pair<UniqueFd, int>> fds,
-                          absl::Span<const std::string> env);
+  absl::Status RunProcess(
+      std::optional<int> client_fd, absl::Span<const std::string> argv,
+      std::vector<std::pair<sapi::file_util::fileops::FDCloser, int>> fds,
+      absl::Span<const std::string> env);
 
   /** Block until an event happens, and process all open events. */
   absl::Status Iterate();
@@ -75,15 +75,15 @@ class SandboxManager {
   SandboxManager(HostInfo, std::string runtime_dir, SignalFd,
                  CredentialedUnixServer);
 
-  absl::Status RunSandboxedProcess(std::optional<int> client_fd,
-                                   absl::Span<const std::string> argv,
-                                   std::vector<std::pair<UniqueFd, int>> fds,
-                                   absl::Span<const std::string> env,
-                                   std::unique_ptr<sandbox2::Policy> policy);
-  absl::Status RunProcessNoSandbox(std::optional<int> client_fd,
-                                   absl::Span<const std::string> argv,
-                                   std::vector<std::pair<UniqueFd, int>> fds,
-                                   absl::Span<const std::string> env);
+  absl::Status RunSandboxedProcess(
+      std::optional<int> client_fd, absl::Span<const std::string> argv,
+      std::vector<std::pair<sapi::file_util::fileops::FDCloser, int>> fds,
+      absl::Span<const std::string> env,
+      std::unique_ptr<sandbox2::Policy> policy);
+  absl::Status RunProcessNoSandbox(
+      std::optional<int> client_fd, absl::Span<const std::string> argv,
+      std::vector<std::pair<sapi::file_util::fileops::FDCloser, int>> fds,
+      absl::Span<const std::string> env);
 
   // Callbacks for the Iterate() `poll` loop.
   absl::Status ClientMessage(ClientIter it, short revents);
diff --git a/host/commands/process_sandboxer/sandboxer_proxy.cpp b/host/commands/process_sandboxer/sandboxer_proxy.cpp
index 48b82d99b..99eb364cc 100644
--- a/host/commands/process_sandboxer/sandboxer_proxy.cpp
+++ b/host/commands/process_sandboxer/sandboxer_proxy.cpp
@@ -14,16 +14,23 @@
  * limitations under the License.
  */
 
+#include <stdlib.h>
 #include <sys/socket.h>
 #include <sys/un.h>
 
+#include <algorithm>
+#include <cerrno>
+#include <cstddef>
+#include <cstring>
 #include <iostream>
+#include <string>
+#include <string_view>
 
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
 #include <absl/strings/numbers.h>
 
-#include "proxy_common.h"
+#include "host/commands/process_sandboxer/proxy_common.h"
 
 namespace cuttlefish::process_sandboxer {
 namespace {
diff --git a/host/commands/process_sandboxer/signal_fd.cpp b/host/commands/process_sandboxer/signal_fd.cpp
index d3a2ee7a7..a317b82b8 100644
--- a/host/commands/process_sandboxer/signal_fd.cpp
+++ b/host/commands/process_sandboxer/signal_fd.cpp
@@ -17,16 +17,24 @@
 
 #include <signal.h>
 #include <sys/signalfd.h>
+#include <sys/types.h>
+#include <unistd.h>
+
+#include <cerrno>
+#include <cstddef>
+#include <string>
+#include <utility>
 
 #include <absl/status/status.h>
 #include <absl/status/statusor.h>
 #include <absl/strings/str_cat.h>
-
-#include "host/commands/process_sandboxer/unique_fd.h"
+#include <sandboxed_api/util/fileops.h>
 
 namespace cuttlefish::process_sandboxer {
 
-SignalFd::SignalFd(UniqueFd fd) : fd_(std::move(fd)) {}
+using sapi::file_util::fileops::FDCloser;
+
+SignalFd::SignalFd(FDCloser fd) : fd_(std::move(fd)) {}
 
 absl::StatusOr<SignalFd> SignalFd::AllExceptSigChld() {
   sigset_t mask;
@@ -41,8 +49,8 @@ absl::StatusOr<SignalFd> SignalFd::AllExceptSigChld() {
     return absl::ErrnoToStatus(errno, "sigprocmask failed");
   }
 
-  UniqueFd fd(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
-  if (fd.Get() < 0) {
+  FDCloser fd(signalfd(-1, &mask, SFD_CLOEXEC | SFD_NONBLOCK));
+  if (fd.get() < 0) {
     return absl::ErrnoToStatus(errno, "signalfd failed");
   }
   return SignalFd(std::move(fd));
@@ -50,7 +58,7 @@ absl::StatusOr<SignalFd> SignalFd::AllExceptSigChld() {
 
 absl::StatusOr<signalfd_siginfo> SignalFd::ReadSignal() {
   signalfd_siginfo info;
-  auto read_res = read(fd_.Get(), &info, sizeof(info));
+  auto read_res = read(fd_.get(), &info, sizeof(info));
   if (read_res < 0) {
     return absl::ErrnoToStatus(errno, "`read(signal_fd_, ...)` failed");
   } else if (read_res == 0) {
@@ -62,6 +70,6 @@ absl::StatusOr<signalfd_siginfo> SignalFd::ReadSignal() {
   return info;
 }
 
-int SignalFd::Fd() const { return fd_.Get(); }
+int SignalFd::Fd() const { return fd_.get(); }
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/signal_fd.h b/host/commands/process_sandboxer/signal_fd.h
index e21672b72..777c30b94 100644
--- a/host/commands/process_sandboxer/signal_fd.h
+++ b/host/commands/process_sandboxer/signal_fd.h
@@ -19,8 +19,7 @@
 #include <sys/signalfd.h>
 
 #include <absl/status/statusor.h>
-
-#include "host/commands/process_sandboxer/unique_fd.h"
+#include <sandboxed_api/util/fileops.h>
 
 namespace cuttlefish::process_sandboxer {
 
@@ -33,9 +32,9 @@ class SignalFd {
   int Fd() const;
 
  private:
-  SignalFd(UniqueFd);
+  SignalFd(sapi::file_util::fileops::FDCloser);
 
-  UniqueFd fd_;
+  sapi::file_util::fileops::FDCloser fd_;
 };
 
 }  // namespace cuttlefish::process_sandboxer
diff --git a/host/commands/process_sandboxer/unique_fd.cpp b/host/commands/process_sandboxer/unique_fd.cpp
deleted file mode 100644
index 5208b9477..000000000
--- a/host/commands/process_sandboxer/unique_fd.cpp
+++ /dev/null
@@ -1,58 +0,0 @@
-/*
- * Copyright (C) 2024 The Android Open Source Project
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
-#include "host/commands/process_sandboxer/unique_fd.h"
-
-#include <unistd.h>
-
-#include <absl/log/log.h>
-
-namespace cuttlefish {
-namespace process_sandboxer {
-
-UniqueFd::UniqueFd(int fd) : fd_(fd) {}
-
-UniqueFd::UniqueFd(UniqueFd&& other) { std::swap(fd_, other.fd_); }
-
-UniqueFd::~UniqueFd() { Close(); }
-
-UniqueFd& UniqueFd::operator=(UniqueFd&& other) {
-  Close();
-  std::swap(fd_, other.fd_);
-  return *this;
-}
-
-int UniqueFd::Get() const { return fd_; }
-
-int UniqueFd::Release() {
-  int ret = -1;
-  std::swap(ret, fd_);
-  return ret;
-}
-
-void UniqueFd::Reset(int fd) {
-  Close();
-  fd_ = fd;
-}
-
-void UniqueFd::Close() {
-  if (fd_ > 0 && close(fd_) < 0) {
-    PLOG(ERROR) << "Failed to close fd " << fd_;
-  }
-  fd_ = -1;
-}
-
-}  // namespace process_sandboxer
-}  // namespace cuttlefish
diff --git a/host/commands/run_cvd/Android.bp b/host/commands/run_cvd/Android.bp
index d13798f5a..107a3009e 100644
--- a/host/commands/run_cvd/Android.bp
+++ b/host/commands/run_cvd/Android.bp
@@ -41,6 +41,8 @@ cc_binary_host {
         "launch/root_canal.cpp",
         "launch/screen_recording_server.cpp",
         "launch/secure_env.cpp",
+        "launch/sensors_simulator.cpp",
+        "launch/sensors_socket_pair.cpp",
         "launch/snapshot_control_files.cpp",
         "launch/streamer.cpp",
         "launch/uwb_connector.cpp",
@@ -62,7 +64,6 @@ cc_binary_host {
         "libcuttlefish_utils",
         "libcuttlefish_webrtc_command_channel",
         "libcuttlefish_webrtc_commands_proto",
-        "libext2_blkid",
         "libfruit",
         "libgoogleapis-status-proto",
         "libgrpc++_unsecure",
@@ -104,13 +105,12 @@ cc_binary_host {
                 "launch/mcu.cpp",
                 "launch/modem.cpp",
                 "launch/open_wrt.cpp",
+                "launch/ti50_emulator.cpp",
                 "launch/tombstone_receiver.cpp",
                 "launch/vhost_device_vsock.cpp",
+                "launch/vhost_input_devices.cpp",
                 "launch/wmediumd_server.cpp",
             ],
-            shared_libs: [
-                "libnl",
-            ],
         },
     },
     defaults: [
diff --git a/host/commands/run_cvd/boot_state_machine.cc b/host/commands/run_cvd/boot_state_machine.cc
index 03f05e0ba..d9fb1e511 100644
--- a/host/commands/run_cvd/boot_state_machine.cc
+++ b/host/commands/run_cvd/boot_state_machine.cc
@@ -459,6 +459,60 @@ class CvdBootStateMachine : public SetupFeature, public KernelLogPipeConsumer {
         }
       }
     }
+
+    // On a successful boot, keep draining events. If boot was unsuccessful,
+    // then run_cvd will get shut down anyway.
+    if (state_ &= kGuestBootCompleted) {
+      DrainBootEventPipe(boot_events_pipe);
+    }
+  }
+
+  // Continue consuming events from boot_events_pipe, until an interrupt is sent
+  // via interrupt_fd_read_.
+  //
+  // This is required as events are forwarded to run_cvd from
+  // kernel_log_monitor, which is listening to the FIFO from the virtual
+  // machine. If we don't keep consuming events from this pipe, then we can
+  // cause a full kernel lockup as all of the FIFOs between the VM and ourselves
+  // get filled up, eventually causing the virtio driver to fail to write to the
+  // VMM.
+  void DrainBootEventPipe(SharedFD boot_events_pipe) {
+    while (true) {
+      std::vector<PollSharedFd> poll_shared_fd = {
+          {
+              .fd = boot_events_pipe,
+              .events = POLLIN | POLLHUP,
+          },
+          {
+              .fd = interrupt_fd_read_,
+              .events = POLLIN | POLLHUP,
+          },
+      };
+      int result = SharedFD::Poll(poll_shared_fd, -1);
+
+      // interrupt_fd_read_
+      if (poll_shared_fd[1].revents & POLLIN) {
+        return;
+      }
+      if (result < 0) {
+        PLOG(FATAL) << "Failed to call Select";
+        return;
+      }
+
+      // boot_events_pipe
+      if (poll_shared_fd[0].revents & POLLHUP) {
+        LOG(ERROR) << "Failed to read a complete kernel event.";
+        return;
+      }
+      if (poll_shared_fd[0].revents & POLLIN) {
+        // Fully parse the message and throw it away.
+        Result<std::optional<monitor::ReadEventResult>> read_result =
+            monitor::ReadEvent(boot_events_pipe);
+        if (!read_result) {
+          return;
+        }
+      }
+    }
   }
 
   // Returns true if the machine is left in a final state
diff --git a/host/commands/run_cvd/launch/casimir.cpp b/host/commands/run_cvd/launch/casimir.cpp
index fffff1ff3..d148b1ca0 100644
--- a/host/commands/run_cvd/launch/casimir.cpp
+++ b/host/commands/run_cvd/launch/casimir.cpp
@@ -63,7 +63,8 @@ Result<std::vector<MonitorCommand>> Casimir(
   }
 
   std::vector<MonitorCommand> commands;
-  commands.emplace_back(CF_EXPECT(log_tee.CreateLogTee(casimir, "casimir")));
+  commands.emplace_back(
+      CF_EXPECT(log_tee.CreateFullLogTee(casimir, "casimir")));
   commands.emplace_back(std::move(casimir));
   return commands;
 }
diff --git a/host/commands/run_cvd/launch/input_connections_provider.h b/host/commands/run_cvd/launch/input_connections_provider.h
new file mode 100644
index 000000000..ecbcd00c6
--- /dev/null
+++ b/host/commands/run_cvd/launch/input_connections_provider.h
@@ -0,0 +1,40 @@
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
+#pragma once
+
+#include <vector>
+
+#include "common/libs/fs/shared_fd.h"
+#include "host/libs/config/feature.h"
+
+namespace cuttlefish {
+
+// Feature that provides access to the connections to the input devices.
+// Such connections are file descriptors over which (virtio_) input events can
+// be written to inject them to the VM and (virtio_) status updates can be read.
+class InputConnectionsProvider : public virtual SetupFeature {
+ public:
+  virtual ~InputConnectionsProvider() = default;
+
+  virtual SharedFD RotaryDeviceConnection() const = 0;
+  virtual SharedFD MouseConnection() const = 0;
+  virtual SharedFD KeyboardConnection() const = 0;
+  virtual SharedFD SwitchesConnection() const = 0;
+  virtual std::vector<SharedFD> TouchscreenConnections() const = 0;
+  virtual std::vector<SharedFD> TouchpadConnections() const = 0;
+};
+
+}  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/launch.h b/host/commands/run_cvd/launch/launch.h
index b68a03476..decc226cf 100644
--- a/host/commands/run_cvd/launch/launch.h
+++ b/host/commands/run_cvd/launch/launch.h
@@ -21,11 +21,10 @@
 
 #include <fruit/fruit.h>
 
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/subprocess.h"
-#include "host/commands/run_cvd/launch/auto_cmd.h"
 #include "host/commands/run_cvd/launch/grpc_socket_creator.h"
+#include "host/commands/run_cvd/launch/input_connections_provider.h"
 #include "host/commands/run_cvd/launch/log_tee_creator.h"
+#include "host/commands/run_cvd/launch/sensors_socket_pair.h"
 #include "host/commands/run_cvd/launch/snapshot_control_files.h"
 #include "host/commands/run_cvd/launch/webrtc_controller.h"
 #include "host/commands/run_cvd/launch/wmediumd_server.h"
@@ -34,7 +33,6 @@
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/feature.h"
 #include "host/libs/config/kernel_log_pipe_provider.h"
-#include "host/libs/vm_manager/vm_manager.h"
 
 namespace cuttlefish {
 
@@ -126,10 +124,10 @@ WmediumdServerComponent();
 Result<std::optional<MonitorCommand>> ModemSimulator(
     const CuttlefishConfig::InstanceSpecific&);
 
-fruit::Component<
-    fruit::Required<const CuttlefishConfig, KernelLogPipeProvider,
-                    const CuttlefishConfig::InstanceSpecific,
-                    const CustomActionConfigProvider, WebRtcController>>
+fruit::Component<fruit::Required<
+    const CuttlefishConfig, KernelLogPipeProvider, InputConnectionsProvider,
+    const CuttlefishConfig::InstanceSpecific, const CustomActionConfigProvider,
+    WebRtcController>>
 launchStreamerComponent();
 
 fruit::Component<WebRtcController> WebRtcControllerComponent();
@@ -139,6 +137,18 @@ fruit::Component<
                     const CuttlefishConfig::InstanceSpecific, LogTeeCreator>>
 McuComponent();
 
+fruit::Component<fruit::Required<const CuttlefishConfig::InstanceSpecific>,
+                 InputConnectionsProvider, LogTeeCreator>
+VhostInputDevicesComponent();
+
 std::optional<MonitorCommand> VhalProxyServer(
     const CuttlefishConfig&, const CuttlefishConfig::InstanceSpecific&);
+
+fruit::Component<fruit::Required<const CuttlefishConfig, LogTeeCreator,
+                                 const CuttlefishConfig::InstanceSpecific>>
+Ti50EmulatorComponent();
+
+Result<MonitorCommand> SensorsSimulator(
+    const CuttlefishConfig::InstanceSpecific&,
+    AutoSensorsSocketPair::Type& sensors_socket_pair);
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/log_tee_creator.cpp b/host/commands/run_cvd/launch/log_tee_creator.cpp
index e434eb1bf..b7a4e0d6d 100644
--- a/host/commands/run_cvd/launch/log_tee_creator.cpp
+++ b/host/commands/run_cvd/launch/log_tee_creator.cpp
@@ -15,23 +15,50 @@
 
 #include "host/commands/run_cvd/launch/log_tee_creator.h"
 
-namespace cuttlefish {
+#include <vector>
 
-LogTeeCreator::LogTeeCreator(const CuttlefishConfig::InstanceSpecific& instance)
-    : instance_(instance) {}
+#include "common/libs/utils/result.h"
+#include "common/libs/utils/subprocess.h"
+#include "host/libs/config/cuttlefish_config.h"
 
-Result<Command> LogTeeCreator::CreateLogTee(Command& cmd,
-                                            const std::string& process_name) {
+namespace cuttlefish {
+
+namespace {
+Result<Command> CreateLogTeeImpl(
+    Command& cmd, const CuttlefishConfig::InstanceSpecific& instance,
+    std::string process_name,
+    const std::vector<Subprocess::StdIOChannel>& log_channels) {
   auto name_with_ext = process_name + "_logs.fifo";
-  auto logs_path = instance_.PerInstanceInternalPath(name_with_ext.c_str());
+  auto logs_path = instance.PerInstanceInternalPath(name_with_ext.c_str());
   auto logs = CF_EXPECT(SharedFD::Fifo(logs_path, 0666));
 
-  cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut, logs);
-  cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdErr, logs);
+  for (const auto& channel : log_channels) {
+    cmd.RedirectStdIO(channel, logs);
+  }
 
   return Command(HostBinaryPath("log_tee"))
       .AddParameter("--process_name=", process_name)
       .AddParameter("--log_fd_in=", logs);
 }
+}  // namespace
+
+LogTeeCreator::LogTeeCreator(const CuttlefishConfig::InstanceSpecific& instance)
+    : instance_(instance) {}
+
+Result<Command> LogTeeCreator::CreateFullLogTee(Command& cmd,
+                                                std::string process_name) {
+  return CF_EXPECT(CreateLogTeeImpl(
+      cmd, instance_, std::move(process_name),
+      {Subprocess::StdIOChannel::kStdOut, Subprocess::StdIOChannel::kStdErr}));
+}
+
+Result<Command> LogTeeCreator::CreateLogTee(
+    Command& cmd, std::string process_name,
+    Subprocess::StdIOChannel log_channel) {
+  CF_EXPECT(log_channel != Subprocess::StdIOChannel::kStdIn,
+            "Invalid channel for log tee: stdin");
+  return CF_EXPECT(
+      CreateLogTeeImpl(cmd, instance_, std::move(process_name), {log_channel}));
+}
 
 }  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/log_tee_creator.h b/host/commands/run_cvd/launch/log_tee_creator.h
index 79a6d6006..4090eda9f 100644
--- a/host/commands/run_cvd/launch/log_tee_creator.h
+++ b/host/commands/run_cvd/launch/log_tee_creator.h
@@ -15,8 +15,11 @@
 
 #pragma once
 
+#include <string>
+
 #include <fruit/fruit.h>
 
+#include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/cuttlefish_config.h"
 
@@ -26,7 +29,13 @@ class LogTeeCreator {
  public:
   INJECT(LogTeeCreator(const CuttlefishConfig::InstanceSpecific& instance));
 
-  Result<Command> CreateLogTee(Command& cmd, const std::string& process_name);
+  // Creates a log tee command for the stdout and stderr channels of the given
+  // command.
+  Result<Command> CreateFullLogTee(Command& cmd, std::string process_name);
+
+  // Creates a log tee command for specified channel of the given command.
+  Result<Command> CreateLogTee(Command& cmd, std::string process_name,
+                               Subprocess::StdIOChannel log_channel);
 
  private:
   const CuttlefishConfig::InstanceSpecific& instance_;
diff --git a/host/commands/run_cvd/launch/mcu.cpp b/host/commands/run_cvd/launch/mcu.cpp
index 8076abebd..2851c5546 100644
--- a/host/commands/run_cvd/launch/mcu.cpp
+++ b/host/commands/run_cvd/launch/mcu.cpp
@@ -74,7 +74,7 @@ class Mcu : public vm_manager::VmmDependencyCommand {
     }
 
     std::vector<MonitorCommand> commands;
-    commands.emplace_back(CF_EXPECT(log_tee_.CreateLogTee(command, "mcu")));
+    commands.emplace_back(CF_EXPECT(log_tee_.CreateFullLogTee(command, "mcu")));
     commands.emplace_back(std::move(command));
     return commands;
   }
diff --git a/host/commands/run_cvd/launch/open_wrt.cpp b/host/commands/run_cvd/launch/open_wrt.cpp
index 734f65690..45162c264 100644
--- a/host/commands/run_cvd/launch/open_wrt.cpp
+++ b/host/commands/run_cvd/launch/open_wrt.cpp
@@ -91,6 +91,10 @@ class OpenWrt : public CommandSource {
         instance_.PerInstanceInternalUdsPath(crosvm_for_ap_socket),
         instance_.crosvm_binary());
 
+    if (!config_.kvm_path().empty()) {
+      ap_cmd.AddKvmPath(config_.kvm_path());
+    }
+
     ap_cmd.Cmd().AddParameter("--no-usb");
     ap_cmd.Cmd().AddParameter("--core-scheduling=false");
 
@@ -98,7 +102,7 @@ class OpenWrt : public CommandSource {
       ap_cmd.Cmd().AddParameter("--vhost-user=mac80211-hwsim,socket=",
                                 environment_.vhost_user_mac80211_hwsim());
     }
-    if (environment_.enable_wifi()) {
+    if (environment_.enable_wifi() && instance_.enable_tap_devices()) {
       ap_cmd.AddTap(instance_.wifi_tap_name());
     }
 
@@ -157,7 +161,7 @@ class OpenWrt : public CommandSource {
 
     std::vector<MonitorCommand> commands;
     commands.emplace_back(
-        CF_EXPECT(log_tee_.CreateLogTee(ap_cmd.Cmd(), "openwrt")));
+        CF_EXPECT(log_tee_.CreateFullLogTee(ap_cmd.Cmd(), "openwrt")));
     commands.emplace_back(std::move(ap_cmd.Cmd()));
     return commands;
   }
diff --git a/host/commands/run_cvd/launch/pica.cpp b/host/commands/run_cvd/launch/pica.cpp
index 13241f5f7..bc8fa7a20 100644
--- a/host/commands/run_cvd/launch/pica.cpp
+++ b/host/commands/run_cvd/launch/pica.cpp
@@ -42,7 +42,7 @@ Result<std::vector<MonitorCommand>> Pica(
                   .AddParameter("--pcapng-dir=", pcap_dir);
 
   std::vector<MonitorCommand> commands;
-  commands.emplace_back(CF_EXPECT(log_tee.CreateLogTee(pica, "pica")));
+  commands.emplace_back(CF_EXPECT(log_tee.CreateFullLogTee(pica, "pica")));
   commands.emplace_back(std::move(pica));
   return commands;
 }
diff --git a/host/commands/run_cvd/launch/root_canal.cpp b/host/commands/run_cvd/launch/root_canal.cpp
index e19133e56..4db21c275 100644
--- a/host/commands/run_cvd/launch/root_canal.cpp
+++ b/host/commands/run_cvd/launch/root_canal.cpp
@@ -87,7 +87,7 @@ class RootCanal : public CommandSource {
 
     std::vector<MonitorCommand> commands;
     commands.emplace_back(
-        CF_EXPECT(log_tee_.CreateLogTee(rootcanal, "rootcanal")));
+        CF_EXPECT(log_tee_.CreateFullLogTee(rootcanal, "rootcanal")));
     commands.emplace_back(std::move(rootcanal));
     commands.emplace_back(std::move(hci_vsock_proxy));
     commands.emplace_back(std::move(test_vsock_proxy));
diff --git a/host/commands/run_cvd/launch/sensors_simulator.cpp b/host/commands/run_cvd/launch/sensors_simulator.cpp
new file mode 100644
index 000000000..0792bf2af
--- /dev/null
+++ b/host/commands/run_cvd/launch/sensors_simulator.cpp
@@ -0,0 +1,39 @@
+//
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
+#include "host/commands/run_cvd/launch/launch.h"
+#include "host/libs/config/known_paths.h"
+
+namespace cuttlefish {
+
+Result<MonitorCommand> SensorsSimulator(
+    const CuttlefishConfig::InstanceSpecific& instance,
+    AutoSensorsSocketPair::Type& sensors_socket_pair) {
+  std::string to_guest_pipe_path =
+      instance.PerInstanceInternalPath("sensors_fifo_vm.in");
+  std::string from_guest_pipe_path =
+      instance.PerInstanceInternalPath("sensors_fifo_vm.out");
+  unlink(to_guest_pipe_path.c_str());
+  unlink(from_guest_pipe_path.c_str());
+  auto to_guest_fd = CF_EXPECT(SharedFD::Fifo(to_guest_pipe_path, 0660));
+  auto from_guest_fd = CF_EXPECT(SharedFD::Fifo(from_guest_pipe_path, 0660));
+  Command command(SensorsSimulatorBinary());
+  command.AddParameter("--sensors_in_fd=", from_guest_fd)
+      .AddParameter("--sensors_out_fd=", to_guest_fd)
+      .AddParameter("--webrtc_fd=", sensors_socket_pair->webrtc_socket);
+  return command;
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/run_cvd/launch/sensors_socket_pair.cpp b/host/commands/run_cvd/launch/sensors_socket_pair.cpp
new file mode 100644
index 000000000..b0ca5d0b5
--- /dev/null
+++ b/host/commands/run_cvd/launch/sensors_socket_pair.cpp
@@ -0,0 +1,31 @@
+//
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
+#include "host/commands/run_cvd/launch/sensors_socket_pair.h"
+
+namespace cuttlefish {
+
+Result<SensorsSocketPair> SensorsSocketPair::Create() {
+  SharedFD webrtc_socket;
+  SharedFD sensors_simulator_socket;
+  CF_EXPECT(SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0, &webrtc_socket,
+                                 &sensors_simulator_socket));
+  return SensorsSocketPair{
+      webrtc_socket,
+      sensors_simulator_socket,
+  };
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/run_cvd/launch/sensors_socket_pair.h b/host/commands/run_cvd/launch/sensors_socket_pair.h
new file mode 100644
index 000000000..423673e1c
--- /dev/null
+++ b/host/commands/run_cvd/launch/sensors_socket_pair.h
@@ -0,0 +1,35 @@
+//
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
+#pragma once
+
+#include <fruit/fruit.h>
+
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+#include "host/libs/config/feature.h"
+
+namespace cuttlefish {
+
+struct SensorsSocketPair {
+  SharedFD webrtc_socket;
+  SharedFD sensors_simulator_socket;
+
+  static Result<SensorsSocketPair> Create();
+};
+
+using AutoSensorsSocketPair = AutoSetup<SensorsSocketPair::Create>;
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/run_cvd/launch/streamer.cpp b/host/commands/run_cvd/launch/streamer.cpp
index 126bb86b6..2050f3ba9 100644
--- a/host/commands/run_cvd/launch/streamer.cpp
+++ b/host/commands/run_cvd/launch/streamer.cpp
@@ -22,18 +22,15 @@
 #include <vector>
 
 #include <android-base/logging.h>
+#include <fmt/ranges.h>
 #include <fruit/fruit.h>
 
-#include "common/libs/fs/shared_buf.h"
 #include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
 #include "host/commands/run_cvd/reporting.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
-#include "host/libs/vm_manager/crosvm_manager.h"
-#include "host/libs/vm_manager/qemu_manager.h"
 
 namespace cuttlefish {
 
@@ -59,9 +56,9 @@ std::vector<Command> LaunchCustomActionServers(
     // WebRTC and the action server.
     SharedFD webrtc_socket, action_server_socket;
     if (!SharedFD::SocketPair(AF_LOCAL, SOCK_STREAM, 0, &webrtc_socket,
-          &action_server_socket)) {
+                              &action_server_socket)) {
       LOG(ERROR) << "Unable to create custom action server socket pair: "
-        << strerror(errno);
+                 << strerror(errno);
       continue;
     }
 
@@ -76,10 +73,10 @@ std::vector<Command> LaunchCustomActionServers(
     if (first) {
       first = false;
       webrtc_cmd.AddParameter("-action_servers=", custom_action.server, ":",
-          webrtc_socket);
+                              webrtc_socket);
     } else {
       webrtc_cmd.AppendToLastParameter(",", custom_action.server, ":",
-          webrtc_socket);
+                                       webrtc_socket);
     }
   }
   return commands;
@@ -90,40 +87,47 @@ std::vector<Command> LaunchCustomActionServers(
 class StreamerSockets : public virtual SetupFeature {
  public:
   INJECT(StreamerSockets(const CuttlefishConfig& config,
+                         InputConnectionsProvider& input_connections_provider,
                          const CuttlefishConfig::InstanceSpecific& instance))
-      : config_(config), instance_(instance) {}
+      : config_(config),
+        instance_(instance),
+        input_connections_provider_(input_connections_provider) {}
 
   void AppendCommandArguments(Command& cmd) {
-    if (config_.vm_manager() == VmmMode::kQemu) {
-      cmd.AddParameter("-write_virtio_input");
-    }
-    if (!touch_servers_.empty()) {
-      bool is_chromeos =
-          instance_.boot_flow() ==
-              CuttlefishConfig::InstanceSpecific::BootFlow::ChromeOs ||
-          instance_.boot_flow() ==
-              CuttlefishConfig::InstanceSpecific::BootFlow::ChromeOsDisk;
-      if (is_chromeos) {
+    const int touch_count = instance_.display_configs().size() +
+                            instance_.touchpad_configs().size();
+    if (touch_count > 0) {
+      if (instance_.guest_os() ==
+          CuttlefishConfig::InstanceSpecific::GuestOs::ChromeOs) {
         cmd.AddParameter("--multitouch=false");
       }
-      cmd.AddParameter("-touch_fds=", touch_servers_[0]);
-      for (int i = 1; i < touch_servers_.size(); ++i) {
-        cmd.AppendToLastParameter(",", touch_servers_[i]);
+      std::vector<SharedFD> touch_connections =
+          input_connections_provider_.TouchscreenConnections();
+      for (const SharedFD& touchpad_connection :
+           input_connections_provider_.TouchpadConnections()) {
+        touch_connections.push_back(touchpad_connection);
+      }
+      cmd.AddParameter("-touch_fds=", touch_connections[0]);
+      for (int i = 1; i < touch_connections.size(); ++i) {
+        cmd.AppendToLastParameter(",", touch_connections[i]);
       }
     }
     if (instance_.enable_mouse()) {
-      cmd.AddParameter("-mouse_fd=", mouse_server_);
+      cmd.AddParameter("-mouse_fd=",
+                       input_connections_provider_.MouseConnection());
     }
-    cmd.AddParameter("-rotary_fd=", rotary_server_);
-    cmd.AddParameter("-keyboard_fd=", keyboard_server_);
+    cmd.AddParameter("-rotary_fd=",
+                     input_connections_provider_.RotaryDeviceConnection());
+    cmd.AddParameter("-keyboard_fd=",
+                     input_connections_provider_.KeyboardConnection());
     cmd.AddParameter("-frame_server_fd=", frames_server_);
     if (instance_.enable_audio()) {
       cmd.AddParameter("--audio_server_fd=", audio_server_);
     }
     cmd.AddParameter("--confui_in_fd=", confui_in_fd_);
     cmd.AddParameter("--confui_out_fd=", confui_out_fd_);
-    cmd.AddParameter("--sensors_in_fd=", sensors_host_to_guest_fd_);
-    cmd.AddParameter("--sensors_out_fd=", sensors_guest_to_host_fd_);
+    cmd.AddParameter("-switches_fd=",
+                     input_connections_provider_.SwitchesConnection());
   }
 
   // SetupFeature
@@ -135,28 +139,11 @@ class StreamerSockets : public virtual SetupFeature {
   }
 
  private:
-  std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
+  std::unordered_set<SetupFeature*> Dependencies() const override {
+    return {&input_connections_provider_};
+  }
 
   Result<void> ResultSetup() override {
-    int display_cnt = instance_.display_configs().size();
-    int touchpad_cnt = instance_.touchpad_configs().size();
-    for (int i = 0; i < display_cnt + touchpad_cnt; ++i) {
-      SharedFD touch_socket =
-          CreateUnixInputServer(instance_.touch_socket_path(i));
-      CF_EXPECT(touch_socket->IsOpen(), touch_socket->StrError());
-      touch_servers_.emplace_back(std::move(touch_socket));
-    }
-    if (instance_.enable_mouse()) {
-      mouse_server_ = CreateUnixInputServer(instance_.mouse_socket_path());
-      CF_EXPECT(mouse_server_->IsOpen(), mouse_server_->StrError());
-    }
-    rotary_server_ =
-        CreateUnixInputServer(instance_.rotary_socket_path());
-
-    CF_EXPECT(rotary_server_->IsOpen(), rotary_server_->StrError());
-    keyboard_server_ = CreateUnixInputServer(instance_.keyboard_socket_path());
-    CF_EXPECT(keyboard_server_->IsOpen(), keyboard_server_->StrError());
-
     frames_server_ = CreateUnixInputServer(instance_.frames_socket_path());
     CF_EXPECT(frames_server_->IsOpen(), frames_server_->StrError());
     // TODO(schuffelen): Make this a separate optional feature?
@@ -174,8 +161,6 @@ class StreamerSockets : public virtual SetupFeature {
     std::vector<std::string> fifo_files = {
         instance_.PerInstanceInternalPath("confui_fifo_vm.in"),
         instance_.PerInstanceInternalPath("confui_fifo_vm.out"),
-        instance_.PerInstanceInternalPath("sensors_fifo_vm.in"),
-        instance_.PerInstanceInternalPath("sensors_fifo_vm.out"),
     };
     for (const auto& path : fifo_files) {
       unlink(path.c_str());
@@ -186,23 +171,16 @@ class StreamerSockets : public virtual SetupFeature {
     }
     confui_in_fd_ = fds[0];
     confui_out_fd_ = fds[1];
-    sensors_host_to_guest_fd_ = fds[2];
-    sensors_guest_to_host_fd_ = fds[3];
     return {};
   }
 
   const CuttlefishConfig& config_;
   const CuttlefishConfig::InstanceSpecific& instance_;
-  std::vector<SharedFD> touch_servers_;
-  SharedFD mouse_server_;
-  SharedFD rotary_server_;
-  SharedFD keyboard_server_;
+  InputConnectionsProvider& input_connections_provider_;
   SharedFD frames_server_;
   SharedFD audio_server_;
   SharedFD confui_in_fd_;   // host -> guest
   SharedFD confui_out_fd_;  // guest -> host
-  SharedFD sensors_host_to_guest_fd_;
-  SharedFD sensors_guest_to_host_fd_;
 };
 
 class WebRtcServer : public virtual CommandSource,
@@ -214,13 +192,15 @@ class WebRtcServer : public virtual CommandSource,
                       StreamerSockets& sockets,
                       KernelLogPipeProvider& log_pipe_provider,
                       const CustomActionConfigProvider& custom_action_config,
-                      WebRtcController& webrtc_controller))
+                      WebRtcController& webrtc_controller,
+                      AutoSensorsSocketPair::Type& sensors_socket_pair))
       : config_(config),
         instance_(instance),
         sockets_(sockets),
         log_pipe_provider_(log_pipe_provider),
         custom_action_config_(custom_action_config),
-        webrtc_controller_(webrtc_controller) {}
+        webrtc_controller_(webrtc_controller),
+        sensors_socket_pair_(sensors_socket_pair) {}
   // DiagnosticInformation
   std::vector<std::string> Diagnostics() const override {
     if (!Enabled() ||
@@ -269,9 +249,6 @@ class WebRtcServer : public virtual CommandSource,
 
     webrtc.UnsetFromEnvironment("http_proxy");
     sockets_.AppendCommandArguments(webrtc);
-    if (config_.vm_manager() == VmmMode::kCrosvm) {
-      webrtc.AddParameter("-switches_fd=", switches_server_);
-    }
     // Currently there is no way to ensure the signaling server will already
     // have bound the socket to the port by the time the webrtc process runs
     // (the common technique of doing it from the launcher is not possible here
@@ -290,6 +267,10 @@ class WebRtcServer : public virtual CommandSource,
     for (auto& action : LaunchCustomActionServers(webrtc, actions)) {
       commands.emplace_back(std::move(action));
     }
+
+    webrtc.AddParameter("-sensors_fd=",
+                        sensors_socket_pair_->sensors_simulator_socket);
+
     commands.emplace_back(std::move(webrtc));
     return commands;
   }
@@ -304,15 +285,11 @@ class WebRtcServer : public virtual CommandSource,
   std::unordered_set<SetupFeature*> Dependencies() const override {
     return {static_cast<SetupFeature*>(&sockets_),
             static_cast<SetupFeature*>(&log_pipe_provider_),
-            static_cast<SetupFeature*>(&webrtc_controller_)};
+            static_cast<SetupFeature*>(&webrtc_controller_),
+            static_cast<SetupFeature*>(&sensors_socket_pair_)};
   }
 
   Result<void> ResultSetup() override {
-    if (config_.vm_manager() == VmmMode::kCrosvm) {
-      switches_server_ =
-          CreateUnixInputServer(instance_.switches_socket_path());
-      CF_EXPECT(switches_server_->IsOpen(), switches_server_->StrError());
-    }
     kernel_log_events_pipe_ = log_pipe_provider_.KernelLogPipe();
     CF_EXPECT(kernel_log_events_pipe_->IsOpen(),
               kernel_log_events_pipe_->StrError());
@@ -327,14 +304,15 @@ class WebRtcServer : public virtual CommandSource,
   WebRtcController& webrtc_controller_;
   SharedFD kernel_log_events_pipe_;
   SharedFD switches_server_;
+  AutoSensorsSocketPair::Type& sensors_socket_pair_;
 };
 
 }  // namespace
 
-fruit::Component<
-    fruit::Required<const CuttlefishConfig, KernelLogPipeProvider,
-                    const CuttlefishConfig::InstanceSpecific,
-                    const CustomActionConfigProvider, WebRtcController>>
+fruit::Component<fruit::Required<
+    const CuttlefishConfig, KernelLogPipeProvider, InputConnectionsProvider,
+    const CuttlefishConfig::InstanceSpecific, const CustomActionConfigProvider,
+    WebRtcController>>
 launchStreamerComponent() {
   return fruit::createComponent()
       .addMultibinding<CommandSource, WebRtcServer>()
diff --git a/host/commands/run_cvd/launch/ti50_emulator.cpp b/host/commands/run_cvd/launch/ti50_emulator.cpp
new file mode 100644
index 000000000..8e54d296d
--- /dev/null
+++ b/host/commands/run_cvd/launch/ti50_emulator.cpp
@@ -0,0 +1,213 @@
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
+#include <iterator>
+#include <memory>
+#include <unordered_set>
+#include <vector>
+
+#include <android-base/logging.h>
+#include <fruit/fruit.h>
+#include <json/json.h>
+#include <string.h>
+#include <sys/socket.h>
+
+#include "common/libs/fs/shared_buf.h"
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/files.h"
+#include "common/libs/utils/result.h"
+#include "common/libs/utils/socket2socket_proxy.h"
+#include "host/commands/run_cvd/launch/launch.h"
+#include "host/commands/run_cvd/launch/log_tee_creator.h"
+#include "host/libs/config/command_source.h"
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+namespace {
+
+const std::string kControlSocketName = "control_sock";
+class Ti50Emulator : public vm_manager::VmmDependencyCommand {
+ public:
+  INJECT(Ti50Emulator(const CuttlefishConfig::InstanceSpecific& instance,
+                      LogTeeCreator& log_tee))
+      : instance_(instance), log_tee_(log_tee) {}
+
+  // CommandSource
+  Result<std::vector<MonitorCommand>> Commands() override {
+    if (!Enabled()) {
+      LOG(ERROR) << "ti50 emulator is not enabled";
+      return {};
+    }
+
+    Command command(instance_.ti50_emulator());
+    command.AddParameter("-s");
+    command.AddParameter("--control_socket=",
+                         instance_.PerInstancePath(kControlSocketName));
+    command.AddParameter("-p=", instance_.instance_dir());
+
+    std::vector<MonitorCommand> commands;
+    commands.emplace_back(
+        CF_EXPECT(log_tee_.CreateFullLogTee(command, "ti50")));
+    commands.emplace_back(std::move(command));
+    return commands;
+  }
+
+  // SetupFeature
+  std::string Name() const override { return "Ti50Emulator"; }
+  bool Enabled() const override { return !instance_.ti50_emulator().empty(); }
+
+  // StatusCheckCommandSource
+  Result<void> WaitForAvailability() const {
+    if (!Enabled()) {
+      return {};
+    }
+
+    // Wait for control socket sending "READY".
+    SharedFD sock = SharedFD::Accept(*ctrl_sock_);
+    const char kExpectedReadyStr[] = "READY";
+    char buf[std::size(kExpectedReadyStr)];
+    CF_EXPECT_NE(sock->Read(buf, sizeof(buf)), 0);
+    CF_EXPECT(!strcmp(buf, "READY"), "Ti50 emulator should return 'READY'");
+
+    CF_EXPECT(ResetGPIO());
+
+    // Initialize TPM socket
+    CF_EXPECT(InitializeTpm());
+
+    return {};
+  }
+
+ private:
+  std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
+
+  Result<void> ResultSetup() override {
+    // Socket proxy
+    ctrl_sock_ = SharedFD::SocketLocalServer(
+        instance_.PerInstancePath(kControlSocketName), false, SOCK_STREAM,
+        0777);
+    if (!ctrl_sock_->IsOpen()) {
+      LOG(ERROR) << "Unable to create unix ctrl_sock server: "
+                 << ctrl_sock_->StrError();
+    }
+
+    return {};
+  }
+
+  Result<void> ResetGPIO() const {
+    // Write '1' to 'gpioPltRst' to initialize the emulator.
+    std::string gpio_sock = instance_.PerInstancePath("gpioPltRst");
+    CF_EXPECT(WaitForUnixSocket(gpio_sock, 30));
+
+    // Wait for the emulator's internal state to be initialized.
+    // Since the emulator polls the socket at 100 ms intervals before
+    // initializing , 1 second sleep after the socket being ready should be a
+    // sufficiently long.
+    // https://crrev.com/7447dbd20aee11809e89e04bb2fcb2a1476febe1/tpm2-simulator/tpm_executor_ti50_impl.cc#171
+    sleep(1);
+
+    SharedFD cl = SharedFD::SocketLocalClient(gpio_sock, false, SOCK_STREAM);
+    if (!cl->IsOpen()) {
+      return CF_ERR("Failed to connect to gpioPltRst");
+    }
+    CF_EXPECT_EQ(cl->Write("1", 1), 1);
+
+    LOG(INFO) << "ti50 emulator: reset GPIO!";
+    return {};
+  }
+
+  Result<void> InitializeTpm() const {
+    // Connects to direct_tpm_fifo socket, which is a bi-directional Unix domain
+    // socket.
+    std::string fifo_sock = instance_.PerInstancePath("direct_tpm_fifo");
+    CF_EXPECT(WaitForUnixSocket(fifo_sock, 30));
+
+    auto cl = SharedFD::SocketLocalClient(fifo_sock, false, SOCK_STREAM);
+    if (!cl->IsOpen()) {
+      return CF_ERR("Failed to connect to gpioPltRst");
+    }
+
+    const uint32_t kMaxRetryCount = 5;
+    // TPM2_Startup command with SU_CLEAR
+    const uint8_t kTpm2StartupCmd[] = {0x80, 0x01, 0x00, 0x00, 0x00, 0x0c,
+                                       0x00, 0x00, 0x01, 0x44, 0x00, 0x00};
+    ssize_t cmd_size = sizeof(kTpm2StartupCmd);
+    const uint8_t kExpectedResponse[] = {0x80, 0x01, 0x00, 0x00, 0x00,
+                                         0x0a, 0x00, 0x00, 0x00, 0x00};
+    ssize_t expected_response_size = sizeof(kExpectedResponse);
+    for (int i = 0; i < kMaxRetryCount; i++) {
+      CF_EXPECT_EQ(WriteAll(cl, (char*)kTpm2StartupCmd, cmd_size), cmd_size,
+                   "failed to write TPM2_startup command");
+
+      // Read a response.
+      // First, read a 2-byte tag and 4-byte size.
+      constexpr ssize_t kHeaderSize = 6;
+      uint8_t resp_header[kHeaderSize] = {0};
+      CF_EXPECT_EQ(ReadExact(cl, (char*)resp_header, kHeaderSize), kHeaderSize,
+                   "failed to read TPM2_startup response header");
+      uint8_t resp_size[4] = {resp_header[5], resp_header[4], resp_header[3],
+                              resp_header[2]};
+      uint32_t* response_size = reinterpret_cast<uint32_t*>(&resp_size);
+
+      // Then, read the response body.
+      uint32_t body_size = *response_size - kHeaderSize;
+      std::vector<char> resp_body(body_size);
+      CF_EXPECT_EQ(ReadExact(cl, &resp_body), body_size,
+                   "failed to read TPM2_startup response body");
+
+      // Check if the response is the expected one.
+      if (*response_size != expected_response_size) {
+        LOG(INFO) << "TPM response size mismatch. Try again: " << *response_size
+                  << " != " << expected_response_size;
+        sleep(1);
+        continue;
+      }
+
+      bool ok = true;
+      for (int i = 0; i < expected_response_size - kHeaderSize; i++) {
+        ok &= (resp_body.at(i) == kExpectedResponse[kHeaderSize + i]);
+      }
+      if (!ok) {
+        LOG(INFO) << "TPM response body mismatch. Try again.";
+        sleep(1);
+        continue;
+      }
+
+      LOG(INFO) << "TPM initialized successfully for Ti50";
+      return {};
+    }
+
+    return CF_ERR("Failed to initialize Ti50 emulator");
+  }
+
+  const CuttlefishConfig::InstanceSpecific& instance_;
+  LogTeeCreator& log_tee_;
+
+  std::unique_ptr<ProxyServer> socket_proxy_;
+
+  SharedFD ctrl_sock_;
+  SharedFD gpio_sock_;
+};
+}  // namespace
+
+fruit::Component<fruit::Required<const CuttlefishConfig, LogTeeCreator,
+                                 const CuttlefishConfig::InstanceSpecific>>
+Ti50EmulatorComponent() {
+  return fruit::createComponent()
+      .addMultibinding<vm_manager::VmmDependencyCommand, Ti50Emulator>()
+      .addMultibinding<CommandSource, Ti50Emulator>()
+      .addMultibinding<SetupFeature, Ti50Emulator>();
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/vhost_device_vsock.cpp b/host/commands/run_cvd/launch/vhost_device_vsock.cpp
index 5f9d2cd6a..1410dd567 100644
--- a/host/commands/run_cvd/launch/vhost_device_vsock.cpp
+++ b/host/commands/run_cvd/launch/vhost_device_vsock.cpp
@@ -25,6 +25,7 @@
 #include <fruit/fruit.h>
 
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/result.h"
 #include "host/commands/run_cvd/launch/log_tee_creator.h"
 #include "host/libs/config/command_source.h"
@@ -61,9 +62,9 @@ Result<std::vector<MonitorCommand>> VhostDeviceVsock::Commands() {
     }
 
     auto param = fmt::format(
-        "guest-cid={0},socket=/tmp/vsock_{0}_{1}/vhost.socket,uds-path=/tmp/"
-        "vsock_{0}_{1}/vm.vsock{2}",
-        i.vsock_guest_cid(), getuid(), isolation_groups);
+        "guest-cid={1},socket={0}/vsock_{1}_{2}/vhost.socket,uds-path={0}/"
+        "vsock_{1}_{2}/vm.vsock{3}",
+        TempDir(), i.vsock_guest_cid(), getuid(), isolation_groups);
     command.AddParameter("--vm");
     command.AddParameter(param);
     LOG(INFO) << "VhostDeviceVsock::vhost param is:" << param;
@@ -71,7 +72,7 @@ Result<std::vector<MonitorCommand>> VhostDeviceVsock::Commands() {
 
   std::vector<MonitorCommand> commands;
   commands.emplace_back(
-      CF_EXPECT(log_tee_.CreateLogTee(command, "vhost_device_vsock")));
+      CF_EXPECT(log_tee_.CreateFullLogTee(command, "vhost_device_vsock")));
   commands.emplace_back(std::move(command));
   return commands;
 }
@@ -83,8 +84,8 @@ bool VhostDeviceVsock::Enabled() const { return instance_.vhost_user_vsock(); }
 Result<void> VhostDeviceVsock::WaitForAvailability() const {
   if (Enabled()) {
     CF_EXPECT(WaitForUnixSocket(
-        fmt::format("/tmp/vsock_{0}_{1}/vm.vsock", instance_.vsock_guest_cid(),
-                    std::to_string(getuid())),
+        fmt::format("{}/vsock_{}_{}/vm.vsock", TempDir(),
+                    instance_.vsock_guest_cid(), std::to_string(getuid())),
         30));
   }
   return {};
diff --git a/host/commands/run_cvd/launch/vhost_input_devices.cpp b/host/commands/run_cvd/launch/vhost_input_devices.cpp
new file mode 100644
index 000000000..8493ca27b
--- /dev/null
+++ b/host/commands/run_cvd/launch/vhost_input_devices.cpp
@@ -0,0 +1,305 @@
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
+#include "host/commands/run_cvd/launch/launch.h"
+
+#include <sys/socket.h>
+
+#include <regex>
+#include <utility>
+#include <vector>
+
+#include <android-base/file.h>
+#include <fruit/fruit.h>
+
+#include "common/libs/utils/result.h"
+#include "common/libs/utils/subprocess.h"
+#include "host/commands/run_cvd/launch/input_connections_provider.h"
+#include "host/libs/config/command_source.h"
+#include "host/libs/config/known_paths.h"
+
+namespace cuttlefish {
+namespace {
+
+using Subprocess::StdIOChannel::kStdErr;
+
+// Holds all sockets related to a single vhost user input device process.
+struct DeviceSockets {
+  // Device end of the connection between device and streamer.
+  SharedFD device_end;
+  // Streamer end of the connection between device and streamer.
+  SharedFD streamer_end;
+  // Unix socket for the server to which the VMM connects to. It's created and
+  // held at the CommandSource level to ensure it already exists by the time the
+  // VMM runs and attempts to connect.
+  SharedFD vhu_server;
+};
+
+Result<DeviceSockets> NewDeviceSockets(const std::string& vhu_server_path) {
+  DeviceSockets ret;
+  CF_EXPECTF(
+      SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0, &ret.device_end,
+                           &ret.streamer_end),
+      "Failed to create connection sockets (socket pair) for input device: {}",
+      ret.device_end->StrError());
+
+  // The webRTC process currently doesn't read status updates from input
+  // devices, so the vhost processes will write that to /dev/null.
+  // These calls shouldn't return errors since we already know these are a newly
+  // created socket pair.
+  CF_EXPECTF(ret.device_end->Shutdown(SHUT_WR) == 0,
+             "Failed to close input connection's device for writes: {}",
+             ret.device_end->StrError());
+  CF_EXPECTF(ret.streamer_end->Shutdown(SHUT_RD) == 0,
+             "Failed to close input connection's streamer end for reads: {}",
+             ret.streamer_end->StrError());
+
+  ret.vhu_server =
+      SharedFD::SocketLocalServer(vhu_server_path, false, SOCK_STREAM, 0600);
+  CF_EXPECTF(ret.vhu_server->IsOpen(),
+             "Failed to create vhost user socket for device: {}",
+             ret.vhu_server->StrError());
+
+  return ret;
+}
+
+Command NewVhostUserInputCommand(const DeviceSockets& device_sockets,
+                                 const std::string& spec) {
+  Command cmd(VhostUserInputBinary());
+  cmd.AddParameter("--verbosity=DEBUG");
+  cmd.AddParameter("--socket-fd=", device_sockets.vhu_server);
+  cmd.AddParameter("--device-config=", spec);
+  cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdIn,
+                    device_sockets.device_end);
+  cmd.RedirectStdIO(Subprocess::StdIOChannel::kStdOut,
+                    SharedFD::Open("/dev/null", O_WRONLY));
+  return cmd;
+}
+
+struct TemplateVars {
+  int index;
+  int width;
+  int height;
+};
+
+std::string BuildTouchSpec(const std::string& spec_template,
+                           TemplateVars vars) {
+  std::pair<std::string, int> replacements[] = {{"%INDEX%", vars.index},
+                                                {"%WIDTH%", vars.width},
+                                                {"%HEIGHT%", vars.height}};
+  std::string spec = spec_template;
+  for (const auto& [key, value] : replacements) {
+    spec = std::regex_replace(spec, std::regex(key), std::to_string(value));
+  }
+  return spec;
+}
+
+// Creates the commands for the vhost user input devices.
+class VhostInputDevices : public CommandSource,
+                          public InputConnectionsProvider {
+ public:
+  INJECT(VhostInputDevices(const CuttlefishConfig::InstanceSpecific& instance,
+                           LogTeeCreator& log_tee))
+      : instance_(instance), log_tee_(log_tee) {}
+
+  // CommandSource
+  Result<std::vector<MonitorCommand>> Commands() override {
+    std::vector<MonitorCommand> commands;
+    Command rotary_cmd =
+        NewVhostUserInputCommand(rotary_sockets_, DefaultRotaryDeviceSpec());
+    Command rotary_log_tee = CF_EXPECT(
+        log_tee_.CreateLogTee(rotary_cmd, "vhost_user_rotary", kStdErr),
+        "Failed to create log tee command for rotary device");
+    commands.emplace_back(std::move(rotary_cmd));
+    commands.emplace_back(std::move(rotary_log_tee));
+
+    if (instance_.enable_mouse()) {
+      Command mouse_cmd =
+          NewVhostUserInputCommand(mouse_sockets_, DefaultMouseSpec());
+      Command mouse_log_tee = CF_EXPECT(
+          log_tee_.CreateLogTee(mouse_cmd, "vhost_user_mouse", kStdErr),
+          "Failed to create log tee command for mouse device");
+      commands.emplace_back(std::move(mouse_cmd));
+      commands.emplace_back(std::move(mouse_log_tee));
+    }
+
+    std::string keyboard_spec =
+        instance_.custom_keyboard_config().value_or(DefaultKeyboardSpec());
+    Command keyboard_cmd =
+        NewVhostUserInputCommand(keyboard_sockets_, keyboard_spec);
+    Command keyboard_log_tee = CF_EXPECT(
+        log_tee_.CreateLogTee(keyboard_cmd, "vhost_user_keyboard", kStdErr),
+        "Failed to create log tee command for keyboard device");
+    commands.emplace_back(std::move(keyboard_cmd));
+    commands.emplace_back(std::move(keyboard_log_tee));
+
+    Command switches_cmd =
+        NewVhostUserInputCommand(switches_sockets_, DefaultSwitchesSpec());
+    Command switches_log_tee = CF_EXPECT(
+        log_tee_.CreateLogTee(switches_cmd, "vhost_user_switches", kStdErr),
+        "Failed to create log tee command for switches device");
+    commands.emplace_back(std::move(switches_cmd));
+    commands.emplace_back(std::move(switches_log_tee));
+
+    const bool use_multi_touch =
+        instance_.guest_os() !=
+        CuttlefishConfig::InstanceSpecific::GuestOs::ChromeOs;
+
+    std::string touchscreen_template_path =
+        use_multi_touch ? DefaultMultiTouchscreenSpecTemplate()
+                        : DefaultSingleTouchscreenSpecTemplate();
+    const std::string touchscreen_template = CF_EXPECTF(
+        ReadFileContents(touchscreen_template_path),
+        "Failed to load touchscreen template: {}", touchscreen_template_path);
+    for (int i = 0; i < instance_.display_configs().size(); ++i) {
+      const int width = instance_.display_configs()[i].width;
+      const int height = instance_.display_configs()[i].height;
+      const std::string spec = BuildTouchSpec(
+          touchscreen_template, {.index = i, .width = width, .height = height});
+      const std::string spec_path = instance_.PerInstanceInternalPath(
+          fmt::format("touchscreen_spec_{}", i));
+      CF_EXPECTF(android::base::WriteStringToFile(spec, spec_path,
+                                                  true /*follow symlinks*/),
+                 "Failed to write touchscreen spec to file: {}", spec_path);
+      Command touchscreen_cmd =
+          NewVhostUserInputCommand(touchscreen_sockets_[i], spec_path);
+      Command touchscreen_log_tee =
+          CF_EXPECTF(log_tee_.CreateLogTee(
+                         touchscreen_cmd,
+                         fmt::format("vhost_user_touchscreen_{}", i), kStdErr),
+                     "Failed to create log tee for touchscreen device", i);
+      commands.emplace_back(std::move(touchscreen_cmd));
+      commands.emplace_back(std::move(touchscreen_log_tee));
+    }
+
+    std::string touchpad_template_path =
+        use_multi_touch ? DefaultMultiTouchpadSpecTemplate()
+                        : DefaultSingleTouchpadSpecTemplate();
+    const std::string touchpad_template = CF_EXPECTF(
+        ReadFileContents(touchpad_template_path),
+        "Failed to load touchpad template: {}", touchpad_template_path);
+    for (int i = 0; i < instance_.touchpad_configs().size(); ++i) {
+      const int width = instance_.touchpad_configs()[i].width;
+      const int height = instance_.touchpad_configs()[i].height;
+      const std::string spec = BuildTouchSpec(
+          touchpad_template, {.index = i, .width = width, .height = height});
+      const std::string spec_path =
+          instance_.PerInstanceInternalPath(fmt::format("touchpad_spec_{}", i));
+      CF_EXPECTF(android::base::WriteStringToFile(spec, spec_path,
+                                                  true /*follow symlinks*/),
+                 "Failed to write touchpad spec to file: {}", spec_path);
+      Command touchpad_cmd =
+          NewVhostUserInputCommand(touchpad_sockets_[i], spec_path);
+      Command touchpad_log_tee = CF_EXPECTF(
+          log_tee_.CreateLogTee(
+              touchpad_cmd, fmt::format("vhost_user_touchpad_{}", i), kStdErr),
+          "Failed to create log tee for touchpad {}", i);
+      commands.emplace_back(std::move(touchpad_cmd));
+      commands.emplace_back(std::move(touchpad_log_tee));
+    }
+    return commands;
+  }
+
+  // InputConnectionsProvider
+  SharedFD RotaryDeviceConnection() const override {
+    return rotary_sockets_.streamer_end;
+  }
+
+  SharedFD MouseConnection() const override {
+    return mouse_sockets_.streamer_end;
+  }
+
+  SharedFD KeyboardConnection() const override {
+    return keyboard_sockets_.streamer_end;
+  }
+
+  SharedFD SwitchesConnection() const override {
+    return switches_sockets_.streamer_end;
+  }
+
+  std::vector<SharedFD> TouchscreenConnections() const override {
+    std::vector<SharedFD> conns;
+    conns.reserve(touchscreen_sockets_.size());
+    for (const DeviceSockets& sockets : touchscreen_sockets_) {
+      conns.emplace_back(sockets.streamer_end);
+    }
+    return conns;
+  }
+
+  std::vector<SharedFD> TouchpadConnections() const override {
+    std::vector<SharedFD> conns;
+    conns.reserve(touchpad_sockets_.size());
+    for (const DeviceSockets& sockets : touchpad_sockets_) {
+      conns.emplace_back(sockets.streamer_end);
+    }
+    return conns;
+  }
+
+ private:
+  // SetupFeature
+  std::string Name() const override { return "VhostInputDevices"; }
+  std::unordered_set<SetupFeature*> Dependencies() const override { return {}; }
+  Result<void> ResultSetup() override {
+    rotary_sockets_ =
+        CF_EXPECT(NewDeviceSockets(instance_.rotary_socket_path()),
+                  "Failed to setup sockets for rotary device");
+    if (instance_.enable_mouse()) {
+      mouse_sockets_ =
+          CF_EXPECT(NewDeviceSockets(instance_.mouse_socket_path()),
+                    "Failed to setup sockets for mouse device");
+    }
+    keyboard_sockets_ =
+        CF_EXPECT(NewDeviceSockets(instance_.keyboard_socket_path()),
+                  "Failed to setup sockets for keyboard device");
+    switches_sockets_ =
+        CF_EXPECT(NewDeviceSockets(instance_.switches_socket_path()),
+                  "Failed to setup sockets for switches device");
+    touchscreen_sockets_.reserve(instance_.display_configs().size());
+    for (int i = 0; i < instance_.display_configs().size(); ++i) {
+      touchscreen_sockets_.emplace_back(
+          CF_EXPECTF(NewDeviceSockets(instance_.touch_socket_path(i)),
+                     "Failed to setup sockets for touchscreen {}", i));
+    }
+    touchpad_sockets_.reserve(instance_.touchpad_configs().size());
+    for (int i = 0; i < instance_.touchpad_configs().size(); ++i) {
+      int idx = touchscreen_sockets_.size() + i;
+      touchpad_sockets_.emplace_back(
+          CF_EXPECTF(NewDeviceSockets(instance_.touch_socket_path(idx)),
+                     "Failed to setup sockets for touchpad {}", i));
+    }
+    return {};
+  }
+
+  const CuttlefishConfig::InstanceSpecific& instance_;
+  LogTeeCreator& log_tee_;
+  DeviceSockets rotary_sockets_;
+  DeviceSockets mouse_sockets_;
+  DeviceSockets keyboard_sockets_;
+  DeviceSockets switches_sockets_;
+  std::vector<DeviceSockets> touchscreen_sockets_;
+  std::vector<DeviceSockets> touchpad_sockets_;
+};
+
+}  // namespace
+fruit::Component<fruit::Required<const CuttlefishConfig::InstanceSpecific>,
+                 InputConnectionsProvider, LogTeeCreator>
+VhostInputDevicesComponent() {
+  return fruit::createComponent()
+      .bind<InputConnectionsProvider, VhostInputDevices>()
+      .addMultibinding<CommandSource, VhostInputDevices>()
+      .addMultibinding<SetupFeature, VhostInputDevices>();
+}
+
+}  // namespace cuttlefish
diff --git a/host/commands/run_cvd/launch/wmediumd_server.cpp b/host/commands/run_cvd/launch/wmediumd_server.cpp
index 2e211a5b8..3007ab4e3 100644
--- a/host/commands/run_cvd/launch/wmediumd_server.cpp
+++ b/host/commands/run_cvd/launch/wmediumd_server.cpp
@@ -90,7 +90,7 @@ Result<std::vector<MonitorCommand>> WmediumdServer::Commands() {
   cmd.AddParameter("--grpc_uds_path=", grpc_socket_.CreateGrpcSocket(Name()));
 
   std::vector<MonitorCommand> commands;
-  commands.emplace_back(CF_EXPECT(log_tee_.CreateLogTee(cmd, "wmediumd")));
+  commands.emplace_back(CF_EXPECT(log_tee_.CreateFullLogTee(cmd, "wmediumd")));
   commands.emplace_back(std::move(cmd));
   return commands;
 }
diff --git a/host/commands/run_cvd/main.cc b/host/commands/run_cvd/main.cc
index 0b5860c0c..e0ffa86a0 100644
--- a/host/commands/run_cvd/main.cc
+++ b/host/commands/run_cvd/main.cc
@@ -35,6 +35,7 @@
 #include "common/libs/utils/subprocess.h"
 #include "common/libs/utils/tee_logging.h"
 #include "host/commands/run_cvd/boot_state_machine.h"
+#include "host/commands/run_cvd/launch/auto_cmd.h"
 #include "host/commands/run_cvd/launch/launch.h"
 #include "host/commands/run_cvd/reporting.h"
 #include "host/commands/run_cvd/server_loop.h"
@@ -68,8 +69,9 @@ class CuttlefishEnvironment : public DiagnosticInformation {
         "Launcher log: " + instance_.launcher_log_path(),
         "Instance configuration: " + config_path,
         // TODO(rammuthiah)  replace this with a more thorough cvd host package
-        // version scheme. Currently this only reports the Build NUmber of run_cvd
-        // and it is possible for other host binaries to be from different versions.
+        // version scheme. Currently this only reports the Build Number of
+        // run_cvd and it is possible for other host binaries to be from
+        // different versions.
         "Launcher Build ID: " + android::build::GetBuildNumber(),
     };
   }
@@ -136,9 +138,11 @@ fruit::Component<> runCvdComponent(
       .install(AutoCmd<TombstoneReceiver>::Component)
       .install(McuComponent)
       .install(VhostDeviceVsockComponent)
+      .install(VhostInputDevicesComponent)
       .install(WmediumdServerComponent)
       .install(launchStreamerComponent)
       .install(AutoCmd<VhalProxyServer>::Component)
+      .install(Ti50EmulatorComponent)
 #endif
       .install(AdbConfigComponent)
       .install(AdbConfigFragmentComponent)
@@ -170,6 +174,8 @@ fruit::Component<> runCvdComponent(
       .install(NetsimServerComponent)
       .install(AutoSnapshotControlFiles::Component)
       .install(AutoCmd<SecureEnv>::Component)
+      .install(AutoSensorsSocketPair::Component)
+      .install(AutoCmd<SensorsSimulator>::Component)
       .install(serverLoopComponent)
       .install(WebRtcControllerComponent)
       .install(AutoSetup<ValidateTapDevices>::Component)
@@ -243,7 +249,7 @@ Result<void> RunCvdMain(int argc, char** argv) {
   return CF_ERR("The server loop returned, it should never happen!!");
 }
 
-} // namespace cuttlefish
+}  // namespace cuttlefish
 
 int main(int argc, char** argv) {
   auto result = cuttlefish::RunCvdMain(argc, argv);
diff --git a/host/commands/run_cvd/server_loop_impl.cpp b/host/commands/run_cvd/server_loop_impl.cpp
index b411e5ef3..5d6d9a463 100644
--- a/host/commands/run_cvd/server_loop_impl.cpp
+++ b/host/commands/run_cvd/server_loop_impl.cpp
@@ -348,15 +348,15 @@ bool ServerLoopImpl::PowerwashFiles() {
 
   auto kregistry_path = instance_.access_kregistry_path();
   unlink(kregistry_path.c_str());
-  CreateBlankImage(kregistry_path, 2 /* mb */, "none");
+  std::ignore = CreateBlankImage(kregistry_path, 2 /* mb */, "none");
 
   auto hwcomposer_pmem_path = instance_.hwcomposer_pmem_path();
   unlink(hwcomposer_pmem_path.c_str());
-  CreateBlankImage(hwcomposer_pmem_path, 2 /* mb */, "none");
+  std::ignore = CreateBlankImage(hwcomposer_pmem_path, 2 /* mb */, "none");
 
   auto pstore_path = instance_.pstore_path();
   unlink(pstore_path.c_str());
-  CreateBlankImage(pstore_path, 2 /* mb */, "none");
+  std::ignore = CreateBlankImage(pstore_path, 2 /* mb */, "none");
 
   auto sdcard_path = instance_.sdcard_path();
   auto sdcard_size = FileSize(sdcard_path);
@@ -364,7 +364,7 @@ bool ServerLoopImpl::PowerwashFiles() {
   // round up
   auto sdcard_mb_size = (sdcard_size + (1 << 20) - 1) / (1 << 20);
   LOG(DEBUG) << "Size in mb is " << sdcard_mb_size;
-  CreateBlankImage(sdcard_path, sdcard_mb_size, "sdcard");
+  std::ignore = CreateBlankImage(sdcard_path, sdcard_mb_size, "sdcard");
 
   struct OverlayFile {
     std::string name;
diff --git a/host/commands/secure_env/in_process_tpm.cpp b/host/commands/secure_env/in_process_tpm.cpp
index 8c493571b..862af69cb 100644
--- a/host/commands/secure_env/in_process_tpm.cpp
+++ b/host/commands/secure_env/in_process_tpm.cpp
@@ -30,7 +30,10 @@ typedef int SOCKET;
 #endif
 #include "TpmBuildSwitches.h"
 #include "TpmTcpProtocol.h"
+#pragma clang diagnostic push
+#pragma clang diagnostic ignored "-Wmain"  // tolerate extern "C" int main()
 #include "Simulator_fp.h"
+#pragma clang diagnostic pop
 #include "Manufacture_fp.h"
 #define delete delete_
 #include "Platform_fp.h"
diff --git a/host/commands/secure_env/rust/Android.bp b/host/commands/secure_env/rust/Android.bp
index 57e8f7741..fba164675 100644
--- a/host/commands/secure_env/rust/Android.bp
+++ b/host/commands/secure_env/rust/Android.bp
@@ -57,6 +57,7 @@ rust_ffi_host {
         "liblibc",
         "liblog_rust",
     ],
+    prefer_rlib: true,
     defaults: ["cuttlefish_buildhost_only"],
 }
 
diff --git a/host/commands/secure_env/rust/tpm.rs b/host/commands/secure_env/rust/tpm.rs
index 5e1c2f987..113829b70 100644
--- a/host/commands/secure_env/rust/tpm.rs
+++ b/host/commands/secure_env/rust/tpm.rs
@@ -60,7 +60,7 @@ impl TpmHmac {
 
     fn hkdf_expand(&self, info: &[u8], out_len: usize) -> Result<Vec<u8>, Error> {
         // HKDF expand: feed the derivation info into HMAC (using the TPM key) repeatedly.
-        let n = (out_len + SHA256_DIGEST_LEN - 1) / SHA256_DIGEST_LEN;
+        let n = out_len.div_ceil(SHA256_DIGEST_LEN);
         if n > 256 {
             return Err(km_err!(UnknownError, "overflow in hkdf"));
         }
diff --git a/host/commands/sensors_simulator/Android.bp b/host/commands/sensors_simulator/Android.bp
new file mode 100644
index 000000000..17221f379
--- /dev/null
+++ b/host/commands/sensors_simulator/Android.bp
@@ -0,0 +1,47 @@
+//
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary_host {
+    name: "sensors_simulator",
+    srcs: [
+        "main.cpp",
+        "sensors_simulator.cpp",
+    ],
+    header_libs: [
+        "libeigen",
+    ],
+    shared_libs: [
+        "libbase",
+        "libcuttlefish_fs",
+        "libcuttlefish_transport",
+        "libcuttlefish_utils",
+        "libjsoncpp",
+        "liblog",
+    ],
+    static_libs: [
+        "libcuttlefish_host_config",
+        "libgflags",
+    ],
+    target: {
+        darwin: {
+            enabled: true,
+        },
+    },
+    defaults: ["cuttlefish_buildhost_only"],
+}
diff --git a/host/commands/sensors_simulator/main.cpp b/host/commands/sensors_simulator/main.cpp
new file mode 100644
index 000000000..b2a9ce29a
--- /dev/null
+++ b/host/commands/sensors_simulator/main.cpp
@@ -0,0 +1,105 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <string>
+#include <vector>
+
+#include <android-base/logging.h>
+#include <gflags/gflags.h>
+
+#include "common/libs/transport/channel_sharedfd.h"
+#include "host/commands/sensors_simulator/sensors_simulator.h"
+#include "host/libs/config/logging.h"
+
+DEFINE_int32(sensors_in_fd, -1, "Sensors virtio-console from host to guest");
+DEFINE_int32(sensors_out_fd, -1, "Sensors virtio-console from guest to host");
+DEFINE_int32(webrtc_fd, -1, "A file descriptor to communicate with webrtc");
+
+namespace cuttlefish {
+namespace sensors {
+
+namespace {
+
+static constexpr char kReqMisFormatted[] = "The request is mis-formatted.";
+
+Result<void> ProcessWebrtcRequest(transport::SharedFdChannel& channel,
+                                  SensorsSimulator& sensors_simulator) {
+  auto request =
+      CF_EXPECT(channel.ReceiveMessage(), "Couldn't receive message.");
+  std::stringstream ss(std::string(
+      reinterpret_cast<const char*>(request->payload), request->payload_size));
+  SensorsCmd cmd = request->command;
+  switch (cmd) {
+    case kUpdateRotationVec: {
+      double x, y, z;
+      char delimiter;
+      CF_EXPECT((ss >> x >> delimiter) && (delimiter == INNER_DELIM),
+                kReqMisFormatted);
+      CF_EXPECT((ss >> y >> delimiter) && (delimiter == INNER_DELIM),
+                kReqMisFormatted);
+      CF_EXPECT(static_cast<bool>(ss >> z), kReqMisFormatted);
+      sensors_simulator.RefreshSensors(x, y, z);
+      break;
+    }
+    case kGetSensorsData: {
+      int mask;
+      CF_EXPECT(static_cast<bool>(ss >> mask), kReqMisFormatted);
+      auto sensors_data = sensors_simulator.GetSensorsData(mask);
+      auto size = sensors_data.size();
+      cmd = kGetSensorsData;
+      auto response =
+          CF_EXPECT(transport::CreateMessage(cmd, true, size),
+                    "Failed to allocate message for cmd: "
+                        << cmd << " with size: " << size << " bytes.");
+      memcpy(response->payload, sensors_data.data(), size);
+      CF_EXPECT(channel.SendResponse(*response),
+                "Can't send request for cmd: " << cmd);
+      break;
+    }
+    default: {
+      return CF_ERR("Unsupported cmd: " << cmd);
+    }
+  }
+  return {};
+}
+
+int SensorsSimulatorMain(int argc, char** argv) {
+  DefaultSubprocessLogging(argv);
+  gflags::ParseCommandLineFlags(&argc, &argv, true);
+  auto webrtc_fd = SharedFD::Dup(FLAGS_webrtc_fd);
+  close(FLAGS_webrtc_fd);
+  if (!webrtc_fd->IsOpen()) {
+    LOG(FATAL) << "Unable to connect webrtc: " << webrtc_fd->StrError();
+  }
+  transport::SharedFdChannel channel(webrtc_fd, webrtc_fd);
+  SensorsSimulator sensors_simulator;
+  while (true) {
+    auto result = ProcessWebrtcRequest(channel, sensors_simulator);
+    if (!result.ok()) {
+      LOG(ERROR) << result.error().FormatForEnv();
+    }
+  }
+  return 0;
+}
+
+}  // namespace
+
+}  // namespace sensors
+}  // namespace cuttlefish
+
+int main(int argc, char* argv[]) {
+  return cuttlefish::sensors::SensorsSimulatorMain(argc, argv);
+}
\ No newline at end of file
diff --git a/host/commands/sensors_simulator/sensors_simulator.cpp b/host/commands/sensors_simulator/sensors_simulator.cpp
new file mode 100644
index 000000000..f8d5b6dab
--- /dev/null
+++ b/host/commands/sensors_simulator/sensors_simulator.cpp
@@ -0,0 +1,129 @@
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include "host/commands/sensors_simulator/sensors_simulator.h"
+
+#include <cmath>
+
+#include <android-base/logging.h>
+
+namespace cuttlefish {
+namespace sensors {
+
+namespace {
+
+constexpr double kG = 9.80665;  // meter per second^2
+const Eigen::Vector3d kGravityVec{0, kG, 0}, kMagneticField{0, 5.9, -48.4};
+
+inline double ToRadians(double x) { return x * M_PI / 180; }
+
+// Calculate the rotation matrix of the pitch, roll, and yaw angles.
+static Eigen::Matrix3d GetRotationMatrix(double x, double y, double z) {
+  x = ToRadians(-x);
+  y = ToRadians(-y);
+  z = ToRadians(-z);
+  // Create rotation matrices for each Euler angle
+  Eigen::Matrix3d rx =
+      Eigen::AngleAxisd(x, Eigen::Vector3d::UnitX()).toRotationMatrix();
+  Eigen::Matrix3d ry =
+      Eigen::AngleAxisd(y, Eigen::Vector3d::UnitY()).toRotationMatrix();
+  Eigen::Matrix3d rz =
+      Eigen::AngleAxisd(z, Eigen::Vector3d::UnitZ()).toRotationMatrix();
+
+  return rz * (ry * rx);
+}
+
+// Calculate new Accelerometer values of the new rotation degrees.
+static inline Eigen::Vector3d CalculateAcceleration(
+    Eigen::Matrix3d current_rotation_matrix) {
+  return current_rotation_matrix * kGravityVec;
+}
+
+// Calculate new Magnetometer values of the new rotation degrees.
+static inline Eigen::Vector3d CalculateMagnetometer(
+    Eigen::Matrix3d current_rotation_matrix) {
+  return current_rotation_matrix * kMagneticField;
+}
+
+// Calculate new Gyroscope values of the new rotation degrees.
+static Eigen::Vector3d CalculateGyroscope(
+    std::chrono::duration<double> duration,
+    Eigen::Matrix3d prior_rotation_matrix,
+    Eigen::Matrix3d current_rotation_matrix) {
+  double time_diff = duration.count();
+  if (time_diff == 0) {
+    return Eigen::Vector3d{0, 0, 0};
+  }
+  Eigen::Matrix3d transition_matrix =
+      prior_rotation_matrix * current_rotation_matrix.inverse();
+  // Convert rotation matrix to angular velocity numerator.
+  Eigen::AngleAxisd angle_axis(transition_matrix);
+  double angle = angle_axis.angle();
+  Eigen::Vector3d gyro = angle_axis.axis();
+  gyro *= angle;
+  gyro /= time_diff;
+  return gyro;
+}
+}  // namespace
+
+SensorsSimulator::SensorsSimulator()
+    : current_rotation_matrix_(GetRotationMatrix(0, 0, 0)),
+      last_event_timestamp_(std::chrono::high_resolution_clock::now()) {
+  // Initialize sensors_data_ based on rotation vector = (0, 0, 0)
+  RefreshSensors(0, 0, 0);
+}
+
+void SensorsSimulator::RefreshSensors(double x, double y, double z) {
+  auto rotation_matrix_update = GetRotationMatrix(x, y, z);
+  auto acc_update = CalculateAcceleration(rotation_matrix_update);
+  auto mgn_update = CalculateMagnetometer(rotation_matrix_update);
+
+  std::lock_guard<std::mutex> lock(sensors_data_mtx_);
+  auto current_time = std::chrono::high_resolution_clock::now();
+  auto duration = current_time - last_event_timestamp_;
+  last_event_timestamp_ = current_time;
+
+  auto gyro_update = CalculateGyroscope(duration, current_rotation_matrix_,
+                                        rotation_matrix_update);
+
+  current_rotation_matrix_ = rotation_matrix_update;
+
+  sensors_data_[kRotationVecId] << x, y, z;
+  sensors_data_[kAccelerationId] = acc_update;
+  sensors_data_[kGyroscopeId] = gyro_update;
+  sensors_data_[kMagneticId] = mgn_update;
+
+  // Copy the calibrated sensor data over for uncalibrated sensor support
+  sensors_data_[kUncalibAccelerationId] = acc_update;
+  sensors_data_[kUncalibGyroscopeId] = gyro_update;
+  sensors_data_[kUncalibMagneticId] = mgn_update;
+}
+
+std::string SensorsSimulator::GetSensorsData(const SensorsMask mask) {
+  std::stringstream sensors_msg;
+  std::lock_guard<std::mutex> lock(sensors_data_mtx_);
+  for (int id = 0; id <= kMaxSensorId; id++) {
+    if (mask & (1 << id)) {
+      auto v = sensors_data_[id];
+      sensors_msg << v(0) << INNER_DELIM << v(1) << INNER_DELIM << v(2)
+                  << OUTER_DELIM;
+    }
+  }
+  return sensors_msg.str();
+}
+
+}  // namespace sensors
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/frontend/webrtc/sensors_simulator.h b/host/commands/sensors_simulator/sensors_simulator.h
similarity index 55%
rename from host/frontend/webrtc/sensors_simulator.h
rename to host/commands/sensors_simulator/sensors_simulator.h
index 6c2e62eba..ff658e765 100644
--- a/host/frontend/webrtc/sensors_simulator.h
+++ b/host/commands/sensors_simulator/sensors_simulator.h
@@ -16,26 +16,37 @@
 
 #pragma once
 
-#include <Eigen/Dense>
-
 #include <chrono>
 #include <string>
 
+#include <Eigen/Dense>
+
+#include "common/libs/sensors/sensors.h"
+
 namespace cuttlefish {
-namespace webrtc_streaming {
+namespace sensors {
 
 class SensorsSimulator {
  public:
   SensorsSimulator();
   // Update sensor values based on new rotation status.
   void RefreshSensors(double x, double y, double z);
-  // Get sensors data in string format to be passed as a message.
-  std::string GetSensorsData();
+
+  // Return a string with serialized sensors data in ascending order of
+  // sensor id. A bitmask is used to specify which sensors to include.
+  // Each bit maps to a sensor type, and a set bit indicates that the
+  // corresponding sensor should be included in the returned data. Assuming
+  // accelerometer and gyroscope are specified, the returned string would be
+  // formatted as "<acc.x>:<acc.y>:<acc.z> <gyro.x>:<gyro.y>:<gyro.z>".
+  std::string GetSensorsData(const SensorsMask mask);
 
  private:
-  Eigen::Vector3d xyz_ {0, 0, 0}, acc_xyz_{0, 0, 0}, mgn_xyz_{0, 0, 0}, gyro_xyz_{0, 0, 0};
+  std::mutex sensors_data_mtx_;
+  Eigen::Vector3d sensors_data_[kMaxSensorId + 1];
   Eigen::Matrix3d prior_rotation_matrix_, current_rotation_matrix_;
-  std::chrono::time_point<std::chrono::high_resolution_clock> last_event_timestamp_;
+  std::chrono::time_point<std::chrono::high_resolution_clock>
+      last_event_timestamp_;
 };
-}  // namespace webrtc_streaming
-}  // namespace cuttlefish
+
+}  // namespace sensors
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/commands/stop/main.cc b/host/commands/stop/main.cc
index a738d849a..903c8e970 100644
--- a/host/commands/stop/main.cc
+++ b/host/commands/stop/main.cc
@@ -30,6 +30,7 @@
 #include <android-base/logging.h>
 
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/flag_parser.h"
 #include "common/libs/utils/result.h"
@@ -43,6 +44,11 @@
 namespace cuttlefish {
 namespace {
 
+// Historically, stop_cvd returned an error code everytime it had to fallback to
+// killing the instance process groups. If sending the kill signal failed the
+// returned exit code would have the third bit set.
+constexpr int kFallbackErrorBit = 1 << 2;
+
 std::set<std::string> FallbackDirs() {
   std::set<std::string> paths;
   std::string parent_path = StringFromEnv("HOME", ".");
@@ -99,7 +105,7 @@ std::set<pid_t> GetCandidateProcessGroups(const std::set<std::string>& dirs) {
 }
 
 int FallBackStop(const std::set<std::string>& dirs) {
-  auto exit_code = 1; // Having to fallback is an error
+  auto exit_code = 0;
 
   auto process_groups = GetCandidateProcessGroups(dirs);
   for (auto pgid: process_groups) {
@@ -108,7 +114,7 @@ int FallBackStop(const std::set<std::string>& dirs) {
     if (retval < 0) {
       LOG(ERROR) << "Failed to kill process group " << pgid << ": "
                  << strerror(errno);
-      exit_code |= 4;
+      exit_code |= kFallbackErrorBit;
     }
   }
 
diff --git a/host/commands/vhost_user_input/Android.bp b/host/commands/vhost_user_input/Android.bp
new file mode 100644
index 000000000..94bf6db2d
--- /dev/null
+++ b/host/commands/vhost_user_input/Android.bp
@@ -0,0 +1,104 @@
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
+rust_binary_host {
+    name: "cf_vhost_user_input",
+
+    srcs: ["main.rs"],
+
+    rustlibs: [
+        "libanyhow",
+        "libclap",
+        "libclap_builder",
+        "liblog_rust",
+        "libenv_logger",
+        "librustutils",
+        "libserde",
+        "libserde_json",
+        "libvhost_android",
+        "libvhost_user_backend",
+        "libvirtio_bindings",
+        "libvirtio_queue",
+        "libvm_memory_android",
+        "libvmm_sys_util",
+        "libzerocopy",
+    ],
+    proc_macros: [
+        "libclap_derive",
+    ],
+    defaults: [
+        "cuttlefish_buildhost_only",
+    ],
+}
+
+prebuilt_etc_host {
+    name: "default_rotary_wheel_spec",
+    src: "device_specs/rotary_wheel.json",
+    filename: "rotary_wheel.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_mouse_spec",
+    src: "device_specs/mouse.json",
+    filename: "mouse.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_keyboard_spec",
+    src: "device_specs/keyboard.json",
+    filename: "keyboard.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_switches_spec",
+    src: "device_specs/switches.json",
+    filename: "switches.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_single_touchscreen_spec_template",
+    src: "device_specs/single_touchscreen_template.json",
+    filename: "single_touchscreen_template.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_multi_touchscreen_spec_template",
+    src: "device_specs/multi_touchscreen_template.json",
+    filename: "multi_touchscreen_template.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_single_touchpad_spec_template",
+    src: "device_specs/single_touchpad_template.json",
+    filename: "single_touchpad_template.json",
+    sub_dir: "default_input_devices",
+}
+
+prebuilt_etc_host {
+    name: "default_multi_touchpad_spec_template",
+    src: "device_specs/multi_touchpad_template.json",
+    filename: "multi_touchpad_template.json",
+    sub_dir: "default_input_devices",
+}
diff --git a/host/commands/vhost_user_input/buf_reader.rs b/host/commands/vhost_user_input/buf_reader.rs
new file mode 100644
index 000000000..499a7a509
--- /dev/null
+++ b/host/commands/vhost_user_input/buf_reader.rs
@@ -0,0 +1,48 @@
+use std::io::Read;
+
+use anyhow::{bail, Context, Result};
+use log::trace;
+
+/// Object to read and temporarily store virtio input events.
+/// An std::io::BufReader can't be used because it doesn't provide a way to read more bytes when
+/// only a partial event has been read.
+#[derive(Clone)]
+pub struct BufReader<R: Read + Sync + Send> {
+    buf: [u8; 8192],
+    size: usize,
+    reader: R,
+}
+
+impl<R: Read + Sync + Send> BufReader<R> {
+    /// Create a new BufReader.
+    pub fn new(reader: R) -> BufReader<R> {
+        BufReader { buf: [0u8; 8192], size: 0, reader }
+    }
+
+    /// Reads available bytes from the underlying reader.
+    pub fn read_ahead(&mut self) -> Result<()> {
+        if self.size == self.buf.len() {
+            // The buffer may be full when the driver doesn't provide virtq buffers to receive the
+            // events.
+            bail!("Event buffer is full");
+        }
+        let read = self.reader.read(&mut self.buf[self.size..]).context("Failed to read events")?;
+        trace!("Read {} bytes", read);
+        if read == 0 {
+            bail!("Event source closed");
+        }
+        self.size += read;
+        Ok(())
+    }
+
+    /// Returns a slice with the available bytes.
+    pub fn buffer(&self) -> &[u8] {
+        &self.buf[..self.size]
+    }
+
+    /// Remove consumed bytes from the buffer, making more space for future reads.
+    pub fn consume(&mut self, count: usize) {
+        self.buf.copy_within(count..self.size, 0);
+        self.size -= count;
+    }
+}
diff --git a/host/commands/vhost_user_input/device_specs/keyboard.json b/host/commands/vhost_user_input/device_specs/keyboard.json
new file mode 100644
index 000000000..29b99d976
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/keyboard.json
@@ -0,0 +1,139 @@
+{
+  "name": "Cuttlefish Vhost User Keyboard 0",
+  "serial_name": "virtio-keyboard-0",
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "KEY_ESC": 1,
+        "KEY_1": 2,
+        "KEY_2": 3,
+        "KEY_3": 4,
+        "KEY_4": 5,
+        "KEY_5": 6,
+        "KEY_6": 7,
+        "KEY_7": 8,
+        "KEY_8": 9,
+        "KEY_9": 10,
+        "KEY_0": 11,
+        "KEY_MINUS": 12,
+        "KEY_EQUAL": 13,
+        "KEY_BACKSPACE": 14,
+        "KEY_TAB": 15,
+        "KEY_Q": 16,
+        "KEY_W": 17,
+        "KEY_E": 18,
+        "KEY_R": 19,
+        "KEY_T": 20,
+        "KEY_Y": 21,
+        "KEY_U": 22,
+        "KEY_I": 23,
+        "KEY_O": 24,
+        "KEY_P": 25,
+        "KEY_LEFTBRACE": 26,
+        "KEY_RIGHTBRACE": 27,
+        "KEY_ENTER": 28,
+        "KEY_LEFTCTRL": 29,
+        "KEY_A": 30,
+        "KEY_S": 31,
+        "KEY_D": 32,
+        "KEY_F": 33,
+        "KEY_G": 34,
+        "KEY_H": 35,
+        "KEY_J": 36,
+        "KEY_K": 37,
+        "KEY_L": 38,
+        "KEY_SEMICOLON": 39,
+        "KEY_APOSTROPHE": 40,
+        "KEY_GRAVE": 41,
+        "KEY_LEFTSHIFT": 42,
+        "KEY_BACKSLASH": 43,
+        "KEY_Z": 44,
+        "KEY_X": 45,
+        "KEY_C": 46,
+        "KEY_V": 47,
+        "KEY_B": 48,
+        "KEY_N": 49,
+        "KEY_M": 50,
+        "KEY_COMMA": 51,
+        "KEY_DOT": 52,
+        "KEY_SLASH": 53,
+        "KEY_RIGHTSHIFT": 54,
+        "KEY_KPASTERISK": 55,
+        "KEY_LEFTALT": 56,
+        "KEY_SPACE": 57,
+        "KEY_CAPSLOCK": 58,
+        "KEY_F1": 59,
+        "KEY_F2": 60,
+        "KEY_F3": 61,
+        "KEY_F4": 62,
+        "KEY_F5": 63,
+        "KEY_F6": 64,
+        "KEY_F7": 65,
+        "KEY_F8": 66,
+        "KEY_F9": 67,
+        "KEY_F10": 68,
+        "KEY_NUMLOCK": 69,
+        "KEY_SCROLLLOCK": 70,
+        "KEY_KP7": 71,
+        "KEY_KP8": 72,
+        "KEY_KP9": 73,
+        "KEY_KPMINUS": 74,
+        "KEY_KP4": 75,
+        "KEY_KP5": 76,
+        "KEY_KP6": 77,
+        "KEY_KPPLUS": 78,
+        "KEY_KP1": 79,
+        "KEY_KP2": 80,
+        "KEY_KP3": 81,
+        "KEY_KP0": 82,
+        "KEY_KPDOT": 83,
+        "KEY_F11": 87,
+        "KEY_F12": 88,
+        "KEY_KPENTER": 96,
+        "KEY_RIGHTCTRL": 97,
+        "KEY_KPSLASH": 98,
+        "KEY_SYSRQ": 99,
+        "KEY_RIGHTALT": 100,
+        "KEY_HOME": 102,
+        "KEY_UP": 103,
+        "KEY_PAGEUP": 104,
+        "KEY_LEFT": 105,
+        "KEY_RIGHT": 106,
+        "KEY_END": 107,
+        "KEY_DOWN": 108,
+        "KEY_PAGEDOWN": 109,
+        "KEY_INSERT": 110,
+        "KEY_DELETE": 111,
+        "KEY_PAUSE": 119,
+        "KEY_MENU": 139,
+        "KEY_PRINT": 210,
+        "KEY_POWER": 116,
+        "KEY_HOMEPAGE": 172,
+        "KEY_MUTE": 113,
+        "KEY_VOLUMEDOWN": 114,
+        "KEY_VOLUMEUP": 115,
+        "KEY_BACK": 158
+      }
+    },
+    {
+      "event_type": "EV_REP",
+      "event_type_code": 20,
+      "supported_events": {
+        "REP_DELAY": 0,
+        "REP_PERIOD": 1
+      }
+    },
+    {
+      "event_type": "EV_LED",
+      "event_type_code": 17,
+      "supported_events": {
+        "LED_CAPSL": 1,
+        "LED_NUML": 0,
+        "LED_SCROLLL": 2
+      }
+    }
+  ]
+}
+
diff --git a/host/commands/vhost_user_input/device_specs/mouse.json b/host/commands/vhost_user_input/device_specs/mouse.json
new file mode 100644
index 000000000..ac11178bf
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/mouse.json
@@ -0,0 +1,24 @@
+{
+  "name": "Cuttlefish Vhost User Mouse 0",
+  "serial_name": "virtio-mouse-0",
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "BTN_LEFT": 272,
+        "BTN_RIGHT": 273,
+        "BTN_MIDDLE": 274
+      }
+    },
+    {
+      "event_type": "EV_REL",
+      "event_type_code": 2,
+      "supported_events": {
+        "REL_X": 0,
+        "REL_Y": 1,
+        "REL_WHEEL": 8
+      }
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/multi_touchpad_template.json b/host/commands/vhost_user_input/device_specs/multi_touchpad_template.json
new file mode 100644
index 000000000..829f072eb
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/multi_touchpad_template.json
@@ -0,0 +1,107 @@
+{
+  "name": "Cuttlefish Vhost User Multitouch_Touchpad %INDEX%",
+  "serial_name": "virtio-multi-touch-touchpad-%INDEX%",
+  "properties": {
+    "INPUT_PROP_POINTER": 0,
+    "INPUT_PROP_BUTTONPAD": 2
+  },
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "BTN_TOUCH": 330,
+        "BTN_LEFT": 272,
+        "BTN_TOOL_FINGER": 325,
+        "BTN_TOOL_DOUBLETAP": 333,
+        "BTN_TOOL_TRIPLETAP": 334,
+        "BTN_TOOL_QUADTAP": 335
+      }
+    },
+    {
+      "event_type": "EV_ABS",
+      "event_type_code": 3,
+      "supported_events": {
+        "ABS_X": 0,
+        "ABS_Y": 1,
+        "ABS_MT_SLOT": 47,
+        "ABS_MT_POSITION_X": 53,
+        "ABS_MT_POSITION_Y": 54,
+        "ABS_MT_TRACKING_ID": 57,
+        "ABS_MT_TOOL_TYPE": 55,
+        "ABS_MT_PRESSURE": 58,
+        "ABS_MT_TOUCH_MAJOR": 48,
+        "ABS_MT_TOUCH_MINOR": 49,
+        "ABS_PRESSURE": 24
+      }
+    }
+  ],
+  "axis_info": [
+    {
+      "axis": "ABS_X",
+      "axis_code": 0,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_Y",
+      "axis_code": 1,
+      "min": 0,
+      "max": %HEIGHT%
+    },
+    {
+      "axis": "ABS_MT_POSITION_X",
+      "axis_code": 53,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_MT_POSITION_Y",
+      "axis_code": 54,
+      "min": 0,
+      "max": %HEIGHT%
+    },
+    {
+      "axis": "ABS_MT_SLOT",
+      "axis_code": 47,
+      "min": 0,
+      "max": 10
+    },
+    {
+      "axis": "ABS_MT_TRACKING_ID",
+      "axis_code": 57,
+      "min": 0,
+      "max": 65536
+    },
+    {
+      "axis": "ABS_MT_TOOL_TYPE",
+      "axis_code": 55,
+      "min": 0,
+      "max": 2
+    },
+    {
+      "axis": "ABS_MT_PRESSURE",
+      "axis_code": 58,
+      "min": 0,
+      "max": 255
+    },
+    {
+      "axis": "ABS_MT_TOUCH_MAJOR",
+      "axis_code": 48,
+      "min": 0,
+      "max": 4095
+    },
+    {
+      "axis": "ABS_MT_TOUCH_MINOR",
+      "axis_code": 49,
+      "min": 0,
+      "max": 4095
+    },
+    {
+      "axis": "ABS_PRESSURE",
+      "axis_code": 24,
+      "min": 0,
+      "max": 255
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/multi_touchscreen_template.json b/host/commands/vhost_user_input/device_specs/multi_touchscreen_template.json
new file mode 100644
index 000000000..bf72e02a2
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/multi_touchscreen_template.json
@@ -0,0 +1,66 @@
+{
+  "name": "Cuttlefish Vhost User Multitouch Touchscreen %INDEX%",
+  "serial_name": "virtio-touchscreen-%INDEX%",
+  "properties": {
+    "INPUT_PROP_DIRECT": 1
+  },
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "BTN_TOUCH": 330
+      }
+    },
+    {
+      "event_type": "EV_ABS",
+      "event_type_code": 3,
+      "supported_events": {
+        "ABS_X": 0,
+        "ABS_Y": 1,
+        "ABS_MT_SLOT": 47,
+        "ABS_MT_POSITION_X": 53,
+        "ABS_MT_POSITION_Y": 54,
+        "ABS_MT_TRACKING_ID": 57
+      }
+    }
+  ],
+  "axis_info": [
+    {
+      "axis": "ABS_X",
+      "axis_code": 0,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_Y",
+      "axis_code": 1,
+      "min": 0,
+      "max": %HEIGHT%
+    },
+    {
+      "axis": "ABS_MT_POSITION_X",
+      "axis_code": 53,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_MT_POSITION_Y",
+      "axis_code": 54,
+      "min": 0,
+      "max": %HEIGHT%
+    },
+    {
+      "axis": "ABS_MT_SLOT",
+      "axis_code": 47,
+      "min": 0,
+      "max": 10
+    },
+    {
+      "axis": "ABS_MT_TRACKING_ID",
+      "axis_code": 57,
+      "min": 0,
+      "max": 10
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/rotary_wheel.json b/host/commands/vhost_user_input/device_specs/rotary_wheel.json
new file mode 100644
index 000000000..a1a987758
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/rotary_wheel.json
@@ -0,0 +1,13 @@
+{
+  "name": "Cuttlefish Vhost User Rotary 0",
+  "serial_name": "virtio-rotary-0",
+  "events": [
+    {
+      "event_type": "EV_REL",
+      "event_type_code": 2,
+      "supported_events": {
+        "REL_WHEEL": 8
+      }
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/single_touchpad_template.json b/host/commands/vhost_user_input/device_specs/single_touchpad_template.json
new file mode 100644
index 000000000..373ab6d12
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/single_touchpad_template.json
@@ -0,0 +1,38 @@
+{
+  "name": "Cuttlefish Vhost User Touchpad %INDEX%",
+  "serial_name": "virtio-touchpad-%INDEX%",
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "BTN_TOUCH": 330,
+        "BTN_LEFT": 272,
+        "BTN_RIGHT": 273,
+        "BTN_TOOL_FINGER": 325
+      }
+    },
+    {
+      "event_type": "EV_ABS",
+      "event_type_code": 3,
+      "supported_events": {
+        "ABS_X": 0,
+        "ABS_Y": 1
+      }
+    }
+  ],
+  "axis_info": [
+    {
+      "axis": "ABS_X",
+      "axis_code": 0,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_Y",
+      "axis_code": 1,
+      "min": 0,
+      "max": %HEIGHT%
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/single_touchscreen_template.json b/host/commands/vhost_user_input/device_specs/single_touchscreen_template.json
new file mode 100644
index 000000000..d542563b8
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/single_touchscreen_template.json
@@ -0,0 +1,38 @@
+{
+  "name": "Cuttlefish Vhost User Touchscreen %INDEX%",
+  "serial_name": "virtio-touchscreen-%INDEX%",
+  "properties": {
+    "INPUT_PROP_DIRECT": 1
+  },
+  "events": [
+    {
+      "event_type": "EV_KEY",
+      "event_type_code": 1,
+      "supported_events": {
+        "BTN_TOUCH": 330
+      }
+    },
+    {
+      "event_type": "EV_ABS",
+      "event_type_code": 3,
+      "supported_events": {
+        "ABS_X": 0,
+        "ABS_Y": 1
+      }
+    }
+  ],
+  "axis_info": [
+    {
+      "axis": "ABS_X",
+      "axis_code": 0,
+      "min": 0,
+      "max": %WIDTH%
+    },
+    {
+      "axis": "ABS_Y",
+      "axis_code": 1,
+      "min": 0,
+      "max": %HEIGHT%
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/device_specs/switches.json b/host/commands/vhost_user_input/device_specs/switches.json
new file mode 100644
index 000000000..39697518e
--- /dev/null
+++ b/host/commands/vhost_user_input/device_specs/switches.json
@@ -0,0 +1,29 @@
+{
+  "name": "Cuttlefish Vhost User Switches 0",
+  "serial_name": "virtio-switches-0",
+  "events": [
+    {
+      "event_type": "EV_SW",
+      "event_type_code": 5,
+      "supported_events": {
+        "SW_LID": 0,
+        "SW_TABLET_MODE": 1,
+        "SW_HEADPHONE_INSERT": 2,
+        "SW_RFKILL_ALL": 3,
+        "SW_MICROPHONE_INSERT": 4,
+        "SW_DOCK": 5,
+        "SW_LINEOUT_INSERT": 6,
+        "SW_JACK_PHYSICAL_INS": 7,
+        "SW_VIDEOOUT_INSERT": 8,
+        "SW_CAMERA_LENS_COVER": 9,
+        "SW_KEYPAD_SLIDE": 10,
+        "SW_FRONT_PROXIMITY": 11,
+        "SW_ROTATE_LOCK": 12,
+        "SW_LINEIN_INSERT": 13,
+        "SW_MUTE_DEVICE": 14,
+        "SW_PEN_INSERTED": 15,
+        "SW_MACHINE_COVER": 16
+      }
+    }
+  ]
+}
diff --git a/host/commands/vhost_user_input/main.rs b/host/commands/vhost_user_input/main.rs
new file mode 100644
index 000000000..9228af963
--- /dev/null
+++ b/host/commands/vhost_user_input/main.rs
@@ -0,0 +1,108 @@
+//! vhost-user input device
+
+mod buf_reader;
+mod vhu_input;
+mod vio_input;
+
+use std::fs;
+use std::os::fd::{FromRawFd, IntoRawFd};
+use std::str::FromStr;
+use std::sync::{Arc, Mutex};
+
+use anyhow::{anyhow, bail, Context, Result};
+use clap::Parser;
+use log::{error, info, LevelFilter};
+use vhost::vhost_user::Listener;
+use vhost_user_backend::VhostUserDaemon;
+use vm_memory::{GuestMemoryAtomic, GuestMemoryMmap};
+
+use vhu_input::VhostUserInput;
+use vio_input::VirtioInputConfig;
+
+/// Vhost-user input server.
+#[derive(Parser, Debug)]
+#[command(about = None, long_about = None)]
+struct Args {
+    /// Log verbosity, one of Off, Error, Warning, Info, Debug, Trace.
+    #[arg(short, long, default_value_t = String::from("Debug") )]
+    verbosity: String,
+    /// File descriptor for the vhost user backend unix socket.
+    #[arg(short, long, required = true)]
+    socket_fd: i32,
+    /// Path to a file specifying the device's config in JSON format.
+    #[arg(short, long, required = true)]
+    device_config: String,
+}
+
+fn init_logging(verbosity: &str) -> Result<()> {
+    env_logger::builder()
+        .format_timestamp_secs()
+        .filter_level(
+            LevelFilter::from_str(verbosity)
+                .with_context(|| format!("Invalid log level: {}", verbosity))?,
+        )
+        .init();
+    Ok(())
+}
+
+fn main() -> Result<()> {
+    // SAFETY: First thing after main
+    unsafe {
+        rustutils::inherited_fd::init_once()
+            .context("Failed to take ownership of process' file descriptors")?
+    };
+    let args = Args::parse();
+    init_logging(&args.verbosity)?;
+
+    if args.socket_fd < 0 {
+        bail!("Invalid socket file descriptor: {}", args.socket_fd);
+    }
+
+    let device_config_str =
+        fs::read_to_string(args.device_config).context("Unable to read device config file")?;
+
+    let device_config = VirtioInputConfig::from_json(device_config_str.as_str())
+        .context("Unable to parse config file")?;
+
+    // SAFETY: No choice but to trust the caller passed a valid fd representing a unix socket.
+    let server_fd = rustutils::inherited_fd::take_fd_ownership(args.socket_fd)
+        .context("Failed to take ownership of socket fd")?;
+    loop {
+        let backend =
+            Arc::new(Mutex::new(VhostUserInput::new(device_config.clone(), std::io::stdin())));
+        let mut daemon = VhostUserDaemon::new(
+            "vhost-user-input".to_string(),
+            backend.clone(),
+            GuestMemoryAtomic::new(GuestMemoryMmap::new()),
+        )
+        .map_err(|e| anyhow!("Failed to create vhost user daemon: {:?}", e))?;
+
+        VhostUserInput::<std::io::Stdin>::register_handlers(
+            0i32, // stdin
+            daemon
+                .get_epoll_handlers()
+                .first()
+                .context("Daemon created without epoll handler threads")?,
+        )
+        .context("Failed to register epoll handler")?;
+
+        let listener = {
+            // vhost::vhost_user::Listener takes ownership of the underlying fd and closes it when
+            // wait returns, so a dup of the original fd is passed to the constructor.
+            let server_dup = server_fd.try_clone().context("Failed to clone socket fd")?;
+            // SAFETY: Safe because we just dupped this fd and don't use it anywhwere else.
+            // Listener takes ownership and ensures it's properly closed when finished with it.
+            unsafe { Listener::from_raw_fd(server_dup.into_raw_fd()) }
+        };
+        info!("Created vhost-user daemon");
+        daemon
+            .start(listener)
+            .map_err(|e| anyhow!("Failed to start vhost-user daemon: {:?}", e))?;
+        info!("Accepted connection in vhost-user daemon");
+        if let Err(e) = daemon.wait() {
+            // This will print an error even when the frontend disconnects to do a restart.
+            error!("Error: {:?}", e);
+        };
+        info!("Daemon exited");
+    }
+}
diff --git a/host/commands/vhost_user_input/vhu_input.rs b/host/commands/vhost_user_input/vhu_input.rs
new file mode 100644
index 000000000..90957beed
--- /dev/null
+++ b/host/commands/vhost_user_input/vhu_input.rs
@@ -0,0 +1,266 @@
+use std::fs::File;
+use std::io::{
+    stdout, Error as IoError, ErrorKind as IoErrorKind, Read, Result as IoResult, Write,
+};
+
+use anyhow::{bail, Context, Result};
+use log::{error, trace};
+use vhost::vhost_user::message::{
+    VhostTransferStateDirection, VhostTransferStatePhase, VhostUserProtocolFeatures,
+    VhostUserVirtioFeatures,
+};
+use vhost_user_backend::{
+    VhostUserBackend, VhostUserBackendMut, VringEpollHandler, VringRwLock, VringT,
+};
+use virtio_bindings::bindings::{
+    virtio_config::VIRTIO_F_NOTIFY_ON_EMPTY, virtio_config::VIRTIO_F_VERSION_1,
+    virtio_ring::VIRTIO_RING_F_EVENT_IDX,
+};
+use virtio_queue::QueueOwnedT;
+use vm_memory::{GuestAddressSpace, GuestMemoryAtomic, GuestMemoryMmap};
+use vmm_sys_util::epoll::EventSet;
+
+use crate::buf_reader::BufReader;
+use crate::vio_input::{trim_to_event_size_multiple, VirtioInputConfig};
+
+const VIRTIO_INPUT_NUM_QUEUES: usize = 2;
+const VIRTIO_INPUT_MAX_QUEUE_SIZE: usize = 256;
+const FEATURES: u64 = 1 << VIRTIO_F_VERSION_1
+    | 1 << VIRTIO_F_NOTIFY_ON_EMPTY
+    | 1 << VIRTIO_RING_F_EVENT_IDX
+    | VhostUserVirtioFeatures::PROTOCOL_FEATURES.bits();
+
+const EVENT_QUEUE: u16 = 0;
+const STATUS_QUEUE: u16 = 1;
+const EXIT_EVENT: u16 = 2;
+const STDIN_EVENT: u16 = 3;
+
+/// Vhost-user input backend implementation.
+#[derive(Clone)]
+pub struct VhostUserInput<R: Read + Sync + Send> {
+    config: VirtioInputConfig,
+    event_reader: BufReader<R>,
+    event_idx: bool,
+    mem: Option<GuestMemoryAtomic<GuestMemoryMmap>>,
+}
+
+impl<R: Read + Sync + Send> VhostUserBackendMut for VhostUserInput<R> {
+    type Bitmap = ();
+    type Vring = VringRwLock;
+    fn num_queues(&self) -> usize {
+        trace!("num_queues");
+        VIRTIO_INPUT_NUM_QUEUES
+    }
+
+    fn max_queue_size(&self) -> usize {
+        trace!("max_queue_size");
+        VIRTIO_INPUT_MAX_QUEUE_SIZE
+    }
+
+    fn features(&self) -> u64 {
+        trace!("features");
+        FEATURES
+    }
+
+    fn protocol_features(&self) -> VhostUserProtocolFeatures {
+        trace!("protocol_features");
+        VhostUserProtocolFeatures::CONFIG | VhostUserProtocolFeatures::DEVICE_STATE
+    }
+
+    fn set_event_idx(&mut self, enabled: bool) {
+        trace!("set_event_idx: {}", enabled);
+        self.event_idx = enabled;
+    }
+
+    fn update_memory(
+        &mut self,
+        mem: GuestMemoryAtomic<GuestMemoryMmap<Self::Bitmap>>,
+    ) -> IoResult<()> {
+        trace!("update_memory");
+        self.mem = Some(mem);
+        Ok(())
+    }
+
+    fn exit_event(&self, thread_index: usize) -> Option<vmm_sys_util::eventfd::EventFd> {
+        trace!("exit_event: thread_idx={}", thread_index);
+        vmm_sys_util::eventfd::EventFd::new(0).ok()
+    }
+
+    fn queues_per_thread(&self) -> Vec<u64> {
+        // Handle all queues in the same thread since only one queue has frequent activity.
+        vec![0xffff_ffff]
+    }
+
+    fn set_device_state_fd(
+        &mut self,
+        direction: VhostTransferStateDirection,
+        _phase: VhostTransferStatePhase,
+        _file: File,
+    ) -> IoResult<Option<File>> {
+        trace!("set_device_state_fd: direction={:?}", direction);
+        Ok(None)
+    }
+
+    fn check_device_state(&self) -> IoResult<()> {
+        trace!("check_device_state");
+        Ok(())
+    }
+
+    fn get_config(&self, offset: u32, size: u32) -> Vec<u8> {
+        trace!("get_config: offset={}, size={}", offset, size);
+        match self.config.get_raw() {
+            Ok(raw_config) => raw_config[offset as usize..(offset + size) as usize].to_vec(),
+            Err(e) => {
+                error!("Failed to get valid config: {:?}", e);
+                vec![0u8; size as usize]
+            }
+        }
+    }
+
+    fn set_config(&mut self, offset: u32, buf: &[u8]) -> IoResult<()> {
+        trace!("set_config: offset: {}, values: {:?}", offset, buf);
+        self.config.set_raw(offset, buf).map_err(|e| IoError::new(IoErrorKind::InvalidInput, e))
+    }
+
+    fn handle_event(
+        &mut self,
+        device_event: u16,
+        _evset: EventSet,
+        vrings: &[Self::Vring],
+        _thread_id: usize,
+    ) -> IoResult<()> {
+        match device_event {
+            EVENT_QUEUE => {
+                trace!("event queue event");
+                self.send_pending_events(&vrings[EVENT_QUEUE as usize]).map_err(IoError::other)?;
+            }
+            STATUS_QUEUE => {
+                trace!("status queue event");
+                self.write_status_updates(&vrings[STATUS_QUEUE as usize])
+                    .map_err(IoError::other)?;
+            }
+            EXIT_EVENT => {
+                trace!("Exit event");
+            }
+            STDIN_EVENT => {
+                trace!("Stdin event");
+                self.read_input_events().map_err(IoError::other)?;
+                self.send_pending_events(&vrings[EVENT_QUEUE as usize]).map_err(IoError::other)?;
+            }
+            _ => {
+                error!("Unknown device event: {}", device_event);
+            }
+        }
+        Ok(())
+    }
+}
+
+impl<R: Read + Sync + Send> VhostUserInput<R> {
+    /// Construct a new VhostUserInput backend.
+    pub fn new(device_config: VirtioInputConfig, reader: R) -> VhostUserInput<R> {
+        VhostUserInput {
+            config: device_config,
+            event_reader: BufReader::new(reader),
+            event_idx: false,
+            mem: None,
+        }
+    }
+
+    fn send_pending_events(&mut self, vring: &VringRwLock) -> Result<()> {
+        // Only if can send at least one full event
+        if trim_to_event_size_multiple(self.event_reader.buffer().len()) == 0 {
+            return Ok(());
+        }
+        let mut vring_state = vring.get_mut();
+        let Some(atomic_mem) = &self.mem else {
+            bail!("Guest memory not available");
+        };
+        while let Some(avail_desc) = vring_state
+            .get_queue_mut()
+            .iter(atomic_mem.memory())
+            .context("Failed to iterate over queue descriptors")?
+            .next()
+        {
+            let mem = atomic_mem.memory();
+            let head_index = avail_desc.head_index();
+            let mut writer = avail_desc.writer(&mem).context("Failed to get writable buffers")?;
+            let mut write_len =
+                std::cmp::min(self.event_reader.buffer().len(), writer.available_bytes());
+            // Send only full events
+            write_len = trim_to_event_size_multiple(write_len);
+            writer.write_all(&self.event_reader.buffer()[..write_len])?;
+            self.event_reader.consume(write_len);
+
+            vring_state
+                .add_used(head_index, write_len as u32)
+                .context("Couldn't return used descriptor to the ring")?;
+
+            if trim_to_event_size_multiple(self.event_reader.buffer().len()) == 0 {
+                // No more events available
+                break;
+            }
+        }
+        let needs_notification = !self.event_idx
+            || match vring_state.needs_notification() {
+                Ok(v) => v,
+                Err(e) => {
+                    error!("Couldn't check if vring needs notification: {:?}", e);
+                    true
+                }
+            };
+        if needs_notification {
+            vring_state.signal_used_queue().unwrap();
+        }
+        Ok(())
+    }
+
+    fn read_input_events(&mut self) -> Result<()> {
+        self.event_reader.read_ahead()?;
+        Ok(())
+    }
+
+    fn write_status_updates(&mut self, vring: &VringRwLock) -> Result<()> {
+        let mut vring_state = vring.get_mut();
+        let Some(atomic_mem) = &self.mem else {
+            bail!("Guest memory not available");
+        };
+        while let Some(avail_desc) = vring_state
+            .get_queue_mut()
+            .iter(atomic_mem.memory())
+            .context("Failed to iterate over queue descriptors")?
+            .next()
+        {
+            let mem = atomic_mem.memory();
+            let head_index = avail_desc.head_index();
+            let mut reader = avail_desc.reader(&mem).context("Failed to get readable buffers")?;
+            let bytes = reader.available_bytes();
+            let mut buf = vec![0u8; bytes];
+            reader.read_exact(&mut buf)?;
+            stdout().write_all(&buf)?;
+
+            vring_state
+                .add_used(head_index, bytes as u32)
+                .context("Couldn't return used descriptor to the ring")?;
+        }
+        let needs_notification = !self.event_idx
+            || match vring_state.needs_notification() {
+                Ok(v) => v,
+                Err(e) => {
+                    error!("Couldn't check if vring needs notification: {:?}", e);
+                    true
+                }
+            };
+        if needs_notification {
+            vring_state.signal_used_queue().unwrap();
+        }
+        Ok(())
+    }
+
+    pub fn register_handlers<T: VhostUserBackend>(
+        fd: i32,
+        handler: &VringEpollHandler<T>,
+    ) -> IoResult<()> {
+        trace!("register_handlers");
+        handler.register_listener(fd, vmm_sys_util::epoll::EventSet::IN, STDIN_EVENT as u64)
+    }
+}
diff --git a/host/commands/vhost_user_input/vio_input.rs b/host/commands/vhost_user_input/vio_input.rs
new file mode 100644
index 000000000..1e8096bf4
--- /dev/null
+++ b/host/commands/vhost_user_input/vio_input.rs
@@ -0,0 +1,241 @@
+use std::collections::BTreeMap;
+
+use anyhow::{bail, Context, Result};
+use log::debug;
+use serde::Deserialize;
+use zerocopy::byteorder::little_endian::U32 as Le32;
+use zerocopy::{FromBytes, FromZeros, Immutable, IntoBytes};
+
+#[allow(dead_code)]
+pub const VIRTIO_INPUT_CFG_UNSET: u8 = 0x00;
+pub const VIRTIO_INPUT_CFG_ID_NAME: u8 = 0x01;
+pub const VIRTIO_INPUT_CFG_ID_SERIAL: u8 = 0x02;
+pub const VIRTIO_INPUT_CFG_ID_DEVIDS: u8 = 0x03;
+pub const VIRTIO_INPUT_CFG_PROP_BITS: u8 = 0x10;
+pub const VIRTIO_INPUT_CFG_EV_BITS: u8 = 0x11;
+pub const VIRTIO_INPUT_CFG_ABS_INFO: u8 = 0x12;
+
+pub const VIRTIO_INPUT_EVENT_SIZE: usize = 8;
+
+/// Calculates the largest multiple of virtio input event size less than or equal to v.
+pub fn trim_to_event_size_multiple(v: usize) -> usize {
+    v & !(VIRTIO_INPUT_EVENT_SIZE - 1)
+}
+
+/// In memory representation of the virtio input configuration area.
+#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes)]
+#[repr(C)]
+struct virtio_input_config {
+    pub select: u8,
+    pub subsel: u8,
+    pub size: u8,
+    pub reserved: [u8; 5],
+    pub payload: [u8; 128],
+}
+
+#[derive(Copy, Clone, FromBytes, Immutable, IntoBytes)]
+#[repr(C)]
+struct virtio_input_absinfo {
+    min: Le32,
+    max: Le32,
+    fuzz: Le32,
+    flat: Le32,
+}
+
+impl From<&InputConfigFileAbsInfo> for virtio_input_absinfo {
+    fn from(absinfo: &InputConfigFileAbsInfo) -> virtio_input_absinfo {
+        virtio_input_absinfo {
+            min: Le32::from(absinfo.min),
+            max: Le32::from(absinfo.max),
+            fuzz: Le32::from(absinfo.fuzz),
+            flat: Le32::from(absinfo.flat),
+        }
+    }
+}
+
+/// Bitmap used in the virtio input configuration region.
+#[derive(Clone)]
+struct VirtioInputBitmap {
+    pub bitmap: [u8; 128],
+}
+
+impl VirtioInputBitmap {
+    pub fn new() -> VirtioInputBitmap {
+        VirtioInputBitmap { bitmap: [0u8; 128] }
+    }
+
+    /// Length of the minimum array that can hold all set bits in the map.
+    pub fn min_size(&self) -> u8 {
+        self.bitmap.iter().rposition(|v| *v != 0).map_or(0, |i| i + 1) as u8
+    }
+
+    fn set(&mut self, idx: u16) -> Result<()> {
+        let byte_pos = (idx / 8) as usize;
+        let bit_byte = 1u8 << (idx % 8);
+        if byte_pos >= self.bitmap.len() {
+            // This would only happen if new event codes (or types, or ABS_*, etc) are defined
+            // to be larger than or equal to 1024, in which case a new version
+            // of the virtio input protocol needs to be defined.
+            bail!("Bitmap index '{}' is out of bitmap bounds ({})", idx, 128);
+        }
+        self.bitmap[byte_pos] |= bit_byte;
+        Ok(())
+    }
+}
+
+/// Configuration of a virtio input device.
+#[derive(Clone)]
+pub struct VirtioInputConfig {
+    name: String,
+    serial_name: String,
+    properties: VirtioInputBitmap,
+    supported_events: BTreeMap<u16, VirtioInputBitmap>,
+    axis_info: BTreeMap<u16, virtio_input_absinfo>,
+    // [select, subsel]
+    select_bytes: [u8; 2],
+}
+
+impl VirtioInputConfig {
+    pub fn from_json(device_config_str: &str) -> Result<VirtioInputConfig> {
+        let config: InputConfigFile =
+            serde_json::from_str(device_config_str).context("Failed to parse JSON string")?;
+        debug!("Parsed device config: {:?}", config);
+
+        let mut supported_events = BTreeMap::<u16, VirtioInputBitmap>::new();
+        let mut supported_event_types = VirtioInputBitmap::new();
+        for event in config.events {
+            let mut bitmap = VirtioInputBitmap::new();
+            for &event_code in event.supported_events.values() {
+                bitmap.set(event_code)?;
+            }
+            supported_events.insert(event.event_type_code, bitmap);
+            debug!("supporting event: {}", event.event_type_code);
+            supported_event_types.set(event.event_type_code)?;
+        }
+        // zero is a special case: return all supported event types (just like EVIOCGBIT)
+        supported_events.insert(0, supported_event_types);
+
+        let mut properties = VirtioInputBitmap::new();
+        for &property in config.properties.values() {
+            properties.set(property)?;
+        }
+
+        let axis_info: BTreeMap<u16, virtio_input_absinfo> = config
+            .axis_info
+            .iter()
+            .map(|absinfo| (absinfo.axis_code, virtio_input_absinfo::from(absinfo)))
+            .collect();
+
+        Ok(VirtioInputConfig {
+            name: config.name,
+            serial_name: config.serial_name,
+            properties,
+            supported_events,
+            axis_info,
+            select_bytes: [0u8; 2],
+        })
+    }
+
+    pub fn set_raw(&mut self, offset: u32, buf: &[u8]) -> Result<()> {
+        let mut start = offset as usize;
+        let mut end = start + buf.len();
+
+        if end > std::mem::size_of::<virtio_input_config>() {
+            bail!("Config write out of bounds: start={}, end={}", start, end);
+        }
+
+        // The driver doesn't (and shouldn't) write past the first two bytes, but qemu always reads
+        // and writes the entire config space regardless of what the driver asks.
+        start = std::cmp::min(start, self.select_bytes.len());
+        end = std::cmp::min(end, self.select_bytes.len());
+
+        if start == end {
+            return Ok(());
+        }
+
+        self.select_bytes[start..end].copy_from_slice(&buf[0..end - start]);
+
+        Ok(())
+    }
+
+    pub fn get_raw(&self) -> Result<Vec<u8>> {
+        let mut config = virtio_input_config::new_zeroed();
+        config.select = self.select_bytes[0];
+        config.subsel = self.select_bytes[1];
+        match config.select {
+            VIRTIO_INPUT_CFG_ID_NAME => {
+                config.size = self.name.len() as u8;
+                config.payload[..self.name.len()].clone_from_slice(self.name.as_bytes());
+            }
+            VIRTIO_INPUT_CFG_ID_SERIAL => {
+                config.size = self.serial_name.len() as u8;
+                config.payload[..self.serial_name.len()]
+                    .clone_from_slice(self.serial_name.as_bytes());
+            }
+            VIRTIO_INPUT_CFG_ID_DEVIDS => {
+                // {0,0,0,0}
+                config.payload = [0u8; 128];
+            }
+            VIRTIO_INPUT_CFG_PROP_BITS => {
+                config.size = self.properties.min_size();
+                config.payload = self.properties.bitmap;
+            }
+            VIRTIO_INPUT_CFG_EV_BITS => {
+                if let Some(events) = self.supported_events.get(&u16::from(config.subsel)) {
+                    config.size = events.min_size();
+                    config.payload = events.bitmap;
+                } else {
+                    // This is not an error. Some drivers don't request the full list by
+                    // setting subsel to 0 and just ask for all types of events instead.
+                    config.size = 0;
+                }
+            }
+            VIRTIO_INPUT_CFG_ABS_INFO => {
+                let axis_code = config.subsel as u16;
+                if let Some(absinfo) = self.axis_info.get(&axis_code) {
+                    let size = std::mem::size_of::<virtio_input_absinfo>();
+                    config.size = size as u8;
+                    config.payload[0..size].copy_from_slice(absinfo.as_bytes());
+                } else {
+                    config.size = 0;
+                }
+            }
+            _ => {
+                bail!("Unsupported config selection: {}", config.select);
+            }
+        };
+        Ok(config.as_bytes().to_vec())
+    }
+}
+
+#[derive(Debug, Deserialize)]
+struct InputConfigFile {
+    name: String,
+    serial_name: String,
+    #[serde(default)]
+    properties: BTreeMap<String, u16>,
+    events: Vec<InputConfigFileEvent>,
+    #[serde(default)]
+    axis_info: Vec<InputConfigFileAbsInfo>,
+}
+
+#[derive(Debug, Deserialize)]
+struct InputConfigFileEvent {
+    #[allow(dead_code)]
+    event_type: String,
+    event_type_code: u16,
+    supported_events: BTreeMap<String, u16>,
+}
+
+#[derive(Debug, Deserialize)]
+struct InputConfigFileAbsInfo {
+    #[allow(dead_code)]
+    axis: String,
+    axis_code: u16,
+    min: u32,
+    max: u32,
+    #[serde(default)]
+    fuzz: u32,
+    #[serde(default)]
+    flat: u32,
+}
diff --git a/host/frontend/webrtc/Android.bp b/host/frontend/webrtc/Android.bp
index 72925ea62..6c411284b 100644
--- a/host/frontend/webrtc/Android.bp
+++ b/host/frontend/webrtc/Android.bp
@@ -91,7 +91,6 @@ cc_binary_host {
         "main.cpp",
         "screenshot_handler.cpp",
         "sensors_handler.cpp",
-        "sensors_simulator.cpp",
     ],
     cflags: [
         // libwebrtc headers need this
@@ -103,7 +102,6 @@ cc_binary_host {
     header_libs: [
         "libcuttlefish_confui_host_headers",
         "libdrm_headers",
-        "libeigen",
         "webrtc_signaling_headers",
     ],
     static_libs: [
@@ -120,13 +118,13 @@ cc_binary_host {
         "libcuttlefish_security",
         "libcuttlefish_transport",
         "libcuttlefish_utils",
+        "libcuttlefish_vm_manager",
         "libcuttlefish_wayland_server",
         "libcuttlefish_webrtc_command_channel",
         "libcuttlefish_webrtc_commands_proto",
         "libcuttlefish_webrtc_common",
         "libcuttlefish_webrtc_device",
         "libcvd_gnss_grpc_proxy",
-        "libdrm",
         "libevent",
         "libffi",
         "libft2.nodep",
@@ -146,7 +144,6 @@ cc_binary_host {
         "libyuv",
     ],
     shared_libs: [
-        "android.hardware.keymaster@4.0",
         "libbase",
         "libcrypto",
         "libcuttlefish_fs",
diff --git a/host/frontend/webrtc/audio_handler.cpp b/host/frontend/webrtc/audio_handler.cpp
index 114f377e9..744a45481 100644
--- a/host/frontend/webrtc/audio_handler.cpp
+++ b/host/frontend/webrtc/audio_handler.cpp
@@ -47,85 +47,61 @@ const virtio_snd_chmap_info CHMAPS[] = {{
 }};
 constexpr uint32_t NUM_CHMAPS = sizeof(CHMAPS) / sizeof(CHMAPS[0]);
 
-const virtio_snd_pcm_info STREAMS[] = {{
-    .hdr =
-        {
-            .hda_fn_nid = Le32(0),
-        },
-    .features = Le32(0),
-    // webrtc's api is quite primitive and doesn't allow for many different
-    // formats: It only takes the bits_per_sample as a parameter and assumes
-    // the underlying format to be one of the following:
-    .formats = Le64(
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S8) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S16) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S24) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S32)),
-    .rates = Le64(
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_5512) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_8000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_11025) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_16000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_22050) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_32000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_44100) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_48000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_64000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_88200) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_96000) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_176400) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_192000) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_384000)),
-    .direction = (uint8_t)AudioStreamDirection::VIRTIO_SND_D_OUTPUT,
-    .channels_min = 1,
-    .channels_max = 2,
-}, {
-    .hdr =
-        {
-            .hda_fn_nid = Le32(0),
-        },
-    .features = Le32(0),
-    // webrtc's api is quite primitive and doesn't allow for many different
-    // formats: It only takes the bits_per_sample as a parameter and assumes
-    // the underlying format to be one of the following:
-    .formats = Le64(
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S8) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S16) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S24) |
-        (((uint64_t)1) << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S32)),
-    .rates = Le64(
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_5512) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_8000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_11025) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_16000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_22050) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_32000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_44100) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_48000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_64000) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_88200) |
-        (((uint64_t)1) << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_96000) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_176400) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_192000) |
-        (((uint64_t)1) << (uint8_t)
-             AudioStreamRate::VIRTIO_SND_PCM_RATE_384000)),
-    .direction = (uint8_t)AudioStreamDirection::VIRTIO_SND_D_INPUT,
-    .channels_min = 1,
-    .channels_max = 2,
-}};
-constexpr uint32_t NUM_STREAMS = sizeof(STREAMS) / sizeof(STREAMS[0]);
-
-bool IsCapture(uint32_t stream_id) {
-  CHECK(stream_id < NUM_STREAMS) << "Invalid stream id: " << stream_id;
-  return STREAMS[stream_id].direction ==
-         (uint8_t)AudioStreamDirection::VIRTIO_SND_D_INPUT;
+virtio_snd_pcm_info GetVirtioSndPcmInfo(AudioStreamDirection direction,
+                                        int streamId) {
+  return {
+      .hdr =
+          {
+              .hda_fn_nid = Le32(streamId),
+          },
+      .features = Le32(0),
+      // webrtc's api is quite primitive and doesn't allow for many different
+      // formats: It only takes the bits_per_sample as a parameter and assumes
+      // the underlying format to be one of the following:
+      .formats = Le64((((uint64_t)1)
+                       << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S8) |
+                      (((uint64_t)1)
+                       << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S16) |
+                      (((uint64_t)1)
+                       << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S24) |
+                      (((uint64_t)1)
+                       << (uint8_t)AudioStreamFormat::VIRTIO_SND_PCM_FMT_S32)),
+      .rates = Le64((((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_5512) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_8000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_11025) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_16000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_22050) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_32000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_44100) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_48000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_64000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_88200) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_96000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_176400) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_192000) |
+                    (((uint64_t)1)
+                     << (uint8_t)AudioStreamRate::VIRTIO_SND_PCM_RATE_384000)),
+      .direction = (uint8_t)direction,
+      .channels_min = 1,
+      .channels_max = 2,
+  };
 }
 
+constexpr uint32_t NUM_INPUT_STREAMS = 1;
+
 class CvdAudioFrameBuffer : public webrtc_streaming::AudioFrameBuffer {
  public:
   CvdAudioFrameBuffer(const uint8_t* buffer, int bits_per_sample,
@@ -279,12 +255,21 @@ int SampleRate(uint8_t virtio_rate) {
 
 AudioHandler::AudioHandler(
     std::unique_ptr<AudioServer> audio_server,
-    std::shared_ptr<webrtc_streaming::AudioSink> audio_sink,
+    std::vector<std::shared_ptr<webrtc_streaming::AudioSink>> audio_sinks,
     std::shared_ptr<webrtc_streaming::AudioSource> audio_source)
-    : audio_sink_(audio_sink),
+    : audio_sinks_(std::move(audio_sinks)),
       audio_server_(std::move(audio_server)),
-      stream_descs_(NUM_STREAMS),
-      audio_source_(audio_source) {}
+      stream_descs_(audio_sinks_.size() + NUM_INPUT_STREAMS),
+      audio_source_(audio_source) {
+  streams_ = std::vector<virtio_snd_pcm_info>(stream_descs_.size());
+  streams_[0] =
+      GetVirtioSndPcmInfo(AudioStreamDirection::VIRTIO_SND_D_INPUT, 0);
+  for (int i = 0; i < audio_sinks_.size(); i++) {
+    int stream_id = NUM_INPUT_STREAMS + i;
+    streams_[stream_id] =
+        GetVirtioSndPcmInfo(AudioStreamDirection::VIRTIO_SND_D_OUTPUT, i);
+  }
+}
 
 void AudioHandler::Start() {
   server_thread_ = std::thread([this]() { Loop(); });
@@ -293,8 +278,8 @@ void AudioHandler::Start() {
 [[noreturn]] void AudioHandler::Loop() {
   for (;;) {
     auto audio_client = audio_server_->AcceptClient(
-        NUM_STREAMS, NUM_JACKS, NUM_CHMAPS,
-        262144 /* tx_shm_len */, 262144 /* rx_shm_len */);
+        streams_.size(), NUM_JACKS, NUM_CHMAPS, 262144 /* tx_shm_len */,
+        262144 /* rx_shm_len */);
     CHECK(audio_client) << "Failed to create audio client connection instance";
 
     std::thread playback_thread([this, &audio_client]() {
@@ -314,22 +299,22 @@ void AudioHandler::Start() {
 }
 
 void AudioHandler::StreamsInfo(StreamInfoCommand& cmd) {
-  if (cmd.start_id() >= NUM_STREAMS ||
-      cmd.start_id() + cmd.count() > NUM_STREAMS) {
+  if (cmd.start_id() >= streams_.size() ||
+      cmd.start_id() + cmd.count() > streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG, {});
     return;
   }
   std::vector<virtio_snd_pcm_info> stream_info(
-      &STREAMS[cmd.start_id()], &STREAMS[0] + cmd.start_id() + cmd.count());
+      &streams_[cmd.start_id()], &streams_[0] + cmd.start_id() + cmd.count());
   cmd.Reply(AudioStatus::VIRTIO_SND_S_OK, stream_info);
 }
 
 void AudioHandler::SetStreamParameters(StreamSetParamsCommand& cmd) {
-  if (cmd.stream_id() >= NUM_STREAMS) {
+  if (cmd.stream_id() >= streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG);
     return;
   }
-  const auto& stream_info = STREAMS[cmd.stream_id()];
+  const auto& stream_info = streams_[cmd.stream_id()];
   auto bits_per_sample = BitsPerSample(cmd.format());
   auto sample_rate = SampleRate(cmd.rate());
   auto channels = cmd.channels();
@@ -351,7 +336,7 @@ void AudioHandler::SetStreamParameters(StreamSetParamsCommand& cmd) {
 }
 
 void AudioHandler::PrepareStream(StreamControlCommand& cmd) {
-  if (cmd.stream_id() >= NUM_STREAMS) {
+  if (cmd.stream_id() >= streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG);
     return;
   }
@@ -359,7 +344,7 @@ void AudioHandler::PrepareStream(StreamControlCommand& cmd) {
 }
 
 void AudioHandler::ReleaseStream(StreamControlCommand& cmd) {
-  if (cmd.stream_id() >= NUM_STREAMS) {
+  if (cmd.stream_id() >= streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG);
     return;
   }
@@ -367,7 +352,7 @@ void AudioHandler::ReleaseStream(StreamControlCommand& cmd) {
 }
 
 void AudioHandler::StartStream(StreamControlCommand& cmd) {
-  if (cmd.stream_id() >= NUM_STREAMS) {
+  if (cmd.stream_id() >= streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG);
     return;
   }
@@ -376,7 +361,7 @@ void AudioHandler::StartStream(StreamControlCommand& cmd) {
 }
 
 void AudioHandler::StopStream(StreamControlCommand& cmd) {
-  if (cmd.stream_id() >= NUM_STREAMS) {
+  if (cmd.stream_id() >= streams_.size()) {
     cmd.Reply(AudioStatus::VIRTIO_SND_S_BAD_MSG);
     return;
   }
@@ -413,7 +398,7 @@ void AudioHandler::OnPlaybackBuffer(TxBuffer buffer) {
     std::lock_guard<std::mutex> lock(stream_desc.mtx);
     auto& holding_buffer = stream_descs_[stream_id].buffer;
     // Invalid or capture streams shouldn't send tx buffers
-    if (stream_id >= NUM_STREAMS || IsCapture(stream_id)) {
+    if (stream_id >= streams_.size() || IsCapture(stream_id)) {
       buffer.SendStatus(AudioStatus::VIRTIO_SND_S_BAD_MSG, 0, 0);
       return;
     }
@@ -424,6 +409,14 @@ void AudioHandler::OnPlaybackBuffer(TxBuffer buffer) {
       buffer.SendStatus(AudioStatus::VIRTIO_SND_S_OK, 0, buffer.len());
       return;
     }
+    auto sink_id = stream_id - NUM_INPUT_STREAMS;
+    if (sink_id >= audio_sinks_.size()) {
+      LOG(ERROR) << "Audio sink for stream id " << stream_id
+                 << " does not exist";
+      buffer.SendStatus(AudioStatus::VIRTIO_SND_S_BAD_MSG, 0, 0);
+      return;
+    }
+    auto audio_sink = audio_sinks_[sink_id];
     // Webrtc will silently ignore any buffer with a length different than 10ms,
     // so we must split any buffer bigger than that and temporarily store any
     // remaining frames that are less than that size.
@@ -447,7 +440,8 @@ void AudioHandler::OnPlaybackBuffer(TxBuffer buffer) {
             const_cast<const uint8_t*>(&buffer.get()[pos]),
             stream_desc.bits_per_sample, stream_desc.sample_rate,
             stream_desc.channels, frames);
-        audio_sink_->OnFrame(audio_frame_buffer, base_time);
+        // Multiple output streams are mixed on the client side.
+        audio_sink->OnFrame(audio_frame_buffer, base_time);
         pos += holding_buffer.buffer.size();
       } else {
         pos += holding_buffer.Add(buffer.get() + pos, buffer.len() - pos);
@@ -456,7 +450,7 @@ void AudioHandler::OnPlaybackBuffer(TxBuffer buffer) {
           CvdAudioFrameBuffer audio_frame_buffer(
               buffer_ptr, stream_desc.bits_per_sample, stream_desc.sample_rate,
               stream_desc.channels, frames);
-          audio_sink_->OnFrame(audio_frame_buffer, base_time);
+          audio_sink->OnFrame(audio_frame_buffer, base_time);
           holding_buffer.count = 0;
         }
       }
@@ -472,7 +466,7 @@ void AudioHandler::OnCaptureBuffer(RxBuffer buffer) {
   {
     std::lock_guard<std::mutex> lock(stream_desc.mtx);
     // Invalid or playback streams shouldn't send rx buffers
-    if (stream_id >= NUM_STREAMS || !IsCapture(stream_id)) {
+    if (stream_id >= streams_.size() || !IsCapture(stream_id)) {
       LOG(ERROR) << "Received capture buffers on playback stream " << stream_id;
       buffer.SendStatus(AudioStatus::VIRTIO_SND_S_BAD_MSG, 0, 0);
       return;
@@ -585,4 +579,10 @@ size_t AudioHandler::HoldingBuffer::freeCapacity() const {
 
 uint8_t* AudioHandler::HoldingBuffer::data() { return buffer.data(); }
 
+bool AudioHandler::IsCapture(uint32_t stream_id) const {
+  CHECK(stream_id < streams_.size()) << "Invalid stream id: " << stream_id;
+  return streams_[stream_id].direction ==
+         (uint8_t)AudioStreamDirection::VIRTIO_SND_D_INPUT;
+}
+
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/audio_handler.h b/host/frontend/webrtc/audio_handler.h
index a3ba71017..b40ad6205 100644
--- a/host/frontend/webrtc/audio_handler.h
+++ b/host/frontend/webrtc/audio_handler.h
@@ -52,9 +52,10 @@ class AudioHandler : public AudioServerExecutor {
   };
 
  public:
-  AudioHandler(std::unique_ptr<AudioServer> audio_server,
-               std::shared_ptr<webrtc_streaming::AudioSink> audio_sink,
-               std::shared_ptr<webrtc_streaming::AudioSource> audio_source);
+  AudioHandler(
+      std::unique_ptr<AudioServer> audio_server,
+      std::vector<std::shared_ptr<webrtc_streaming::AudioSink>> audio_sinks,
+      std::shared_ptr<webrtc_streaming::AudioSource> audio_source);
   ~AudioHandler() override = default;
 
   void Start();
@@ -74,11 +75,13 @@ class AudioHandler : public AudioServerExecutor {
 
  private:
   [[noreturn]] void Loop();
+  bool IsCapture(uint32_t stream_id) const;
 
-  std::shared_ptr<webrtc_streaming::AudioSink> audio_sink_;
+  std::vector<std::shared_ptr<webrtc_streaming::AudioSink>> audio_sinks_;
   std::unique_ptr<AudioServer> audio_server_;
   std::thread server_thread_;
   std::vector<StreamDesc> stream_descs_ = {};
   std::shared_ptr<webrtc_streaming::AudioSource> audio_source_;
+  std::vector<virtio_snd_pcm_info> streams_;
 };
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/connection_observer.cpp b/host/frontend/webrtc/connection_observer.cpp
index 52e2194d5..e019d0439 100644
--- a/host/frontend/webrtc/connection_observer.cpp
+++ b/host/frontend/webrtc/connection_observer.cpp
@@ -22,6 +22,7 @@
 
 #include <chrono>
 #include <map>
+#include <string>
 #include <thread>
 #include <vector>
 
@@ -31,8 +32,9 @@
 #include <android-base/parsedouble.h>
 #include <gflags/gflags.h>
 
-#include "common/libs/confui/confui.h"
 #include "common/libs/fs/shared_buf.h"
+#include "common/libs/utils/json.h"
+#include "common/libs/utils/result.h"
 #include "host/frontend/webrtc/adb_handler.h"
 #include "host/frontend/webrtc/bluetooth_handler.h"
 #include "host/frontend/webrtc/gpx_locations_handler.h"
@@ -40,8 +42,10 @@
 #include "host/frontend/webrtc/libdevice/camera_controller.h"
 #include "host/frontend/webrtc/libdevice/lights_observer.h"
 #include "host/frontend/webrtc/location_handler.h"
+#include "host/libs/config/config_utils.h"
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/input_connector/input_connector.h"
+#include "host/libs/vm_manager/crosvm_display_controller.h"
 
 namespace cuttlefish {
 
@@ -54,11 +58,11 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
  public:
   ConnectionObserverImpl(
       std::unique_ptr<InputConnector::EventSink> input_events_sink,
-      KernelLogEventsHandler *kernel_log_events_handler,
+      KernelLogEventsHandler &kernel_log_events_handler,
       std::map<std::string, SharedFD> commands_to_custom_action_servers,
       std::weak_ptr<DisplayHandler> display_handler,
       CameraController *camera_controller,
-      std::shared_ptr<webrtc_streaming::SensorsHandler> sensors_handler,
+      webrtc_streaming::SensorsHandler &sensors_handler,
       std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer)
       : input_events_sink_(std::move(input_events_sink)),
         kernel_log_events_handler_(kernel_log_events_handler),
@@ -73,7 +77,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
       display_handler->RemoveDisplayClient();
     }
     if (kernel_log_subscription_id_ != -1) {
-      kernel_log_events_handler_->Unsubscribe(kernel_log_subscription_id_);
+      kernel_log_events_handler_.Unsubscribe(kernel_log_subscription_id_);
     }
   }
 
@@ -107,9 +111,8 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
   }
 
   Result<void> OnMultiTouchEvent(const std::string &device_label,
-                                 Json::Value id, Json::Value slot,
-                                 Json::Value x, Json::Value y, bool down,
-                                 int size) {
+                                 Json::Value id, Json::Value x, Json::Value y,
+                                 bool down, int size) {
     std::vector<MultitouchSlot> slots(size);
     for (int i = 0; i < size; i++) {
       slots[i].id = id[i].asInt();
@@ -153,7 +156,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
       camera_controller_->SetMessageSender(control_message_sender);
     }
     kernel_log_subscription_id_ =
-        kernel_log_events_handler_->AddSubscriber(control_message_sender);
+        kernel_log_events_handler_.AddSubscriber(control_message_sender);
   }
 
   Result<void> OnLidStateChange(bool lid_open) override {
@@ -222,12 +225,13 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
 
   void OnSensorsChannelOpen(std::function<bool(const uint8_t *, size_t)>
                                 sensors_message_sender) override {
-    sensors_subscription_id = sensors_handler_->Subscribe(sensors_message_sender);
+    sensors_subscription_id =
+        sensors_handler_.Subscribe(sensors_message_sender);
     LOG(VERBOSE) << "Sensors channel open";
   }
 
   void OnSensorsChannelClosed() override {
-    sensors_handler_->UnSubscribe(sensors_subscription_id);
+    sensors_handler_.UnSubscribe(sensors_subscription_id);
   }
 
   void OnSensorsMessage(const uint8_t *msg, size_t size) override {
@@ -235,7 +239,8 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
     std::vector<std::string> xyz = android::base::Split(msgstr, " ");
 
     if (xyz.size() != 3) {
-      LOG(WARNING) << "Invalid rotation angles: Expected 3, received " << xyz.size();
+      LOG(WARNING) << "Invalid rotation angles: Expected 3, received "
+                   << xyz.size();
       return;
     }
 
@@ -246,7 +251,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
         << "Y rotation value must be a double";
     CHECK(android::base::ParseDouble(xyz.at(2), &z))
         << "Z rotation value must be a double";
-    sensors_handler_->HandleMessage(x, y, z);
+    sensors_handler_.HandleMessage(x, y, z);
   }
 
   void OnLightsChannelOpen(
@@ -335,6 +340,54 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
     SendLastFrameAsync(display_number);
   }
 
+  void OnDisplayAddMsg(const Json::Value &msg) override {
+    auto result = HandleDisplayAddMessage(msg);
+    if (!result.ok()) {
+      LOG(ERROR) << result.error().FormatForEnv();
+    }
+  }
+
+  Result<void> HandleDisplayAddMessage(const Json::Value &msg) {
+    auto width = CF_EXPECT(GetValue<int>(msg, {"width"}));
+    auto height = CF_EXPECT(GetValue<int>(msg, {"height"}));
+    auto dpi = CF_EXPECT(GetValue<int>(msg, {"dpi"}));
+    auto refresh_rate_hz = CF_EXPECT(GetValue<int>(msg, {"refresh_rate_hz"}));
+
+    auto display_config = CuttlefishConfig::DisplayConfig{
+        .width = width,
+        .height = height,
+        .dpi = dpi,
+        .refresh_rate_hz = refresh_rate_hz,
+    };
+
+    auto crosvm_display_conroller =
+        CF_EXPECT(vm_manager::GetCrosvmDisplayController());
+
+    int const instance_num = cuttlefish::GetInstance();
+    CF_EXPECT(crosvm_display_conroller.Add(instance_num, {display_config}));
+
+    return {};
+  }
+
+  void OnDisplayRemoveMsg(const Json::Value &msg) override {
+    auto result = HandleDisplayRemoveMessage(msg);
+    if (!result.ok()) {
+      LOG(ERROR) << result.error().FormatForEnv();
+    }
+  }
+
+  Result<void> HandleDisplayRemoveMessage(const Json::Value &msg) {
+    auto display_id = CF_EXPECT(GetValue<std::string>(msg, {"display_id"}));
+
+    auto crosvm_display_conroller =
+        CF_EXPECT(vm_manager::GetCrosvmDisplayController());
+
+    int const instance_num = cuttlefish::GetInstance();
+    CF_EXPECT(crosvm_display_conroller.Remove(instance_num, {display_id}));
+
+    return {};
+  }
+
   void OnCameraData(const std::vector<char> &data) override {
     if (camera_controller_) {
       camera_controller_->HandleMessage(data);
@@ -369,7 +422,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
   }
 
   std::unique_ptr<InputConnector::EventSink> input_events_sink_;
-  KernelLogEventsHandler *kernel_log_events_handler_;
+  KernelLogEventsHandler &kernel_log_events_handler_;
   int kernel_log_subscription_id_ = -1;
   std::shared_ptr<webrtc_streaming::AdbHandler> adb_handler_;
   std::shared_ptr<webrtc_streaming::BluetoothHandler> bluetooth_handler_;
@@ -379,7 +432,7 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
   std::map<std::string, SharedFD> commands_to_custom_action_servers_;
   std::weak_ptr<DisplayHandler> weak_display_handler_;
   CameraController *camera_controller_;
-  std::shared_ptr<webrtc_streaming::SensorsHandler> sensors_handler_;
+  webrtc_streaming::SensorsHandler& sensors_handler_;
   std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer_;
   int sensors_subscription_id = -1;
   int lights_subscription_id_ = -1;
@@ -387,10 +440,12 @@ class ConnectionObserverImpl : public webrtc_streaming::ConnectionObserver {
 
 CfConnectionObserverFactory::CfConnectionObserverFactory(
     InputConnector &input_connector,
-    KernelLogEventsHandler *kernel_log_events_handler,
+    KernelLogEventsHandler &kernel_log_events_handler,
+    webrtc_streaming::SensorsHandler &sensors_handler,
     std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer)
     : input_connector_(input_connector),
       kernel_log_events_handler_(kernel_log_events_handler),
+      sensors_handler_(sensors_handler),
       lights_observer_(lights_observer) {}
 
 std::shared_ptr<webrtc_streaming::ConnectionObserver>
@@ -399,7 +454,7 @@ CfConnectionObserverFactory::CreateObserver() {
       new ConnectionObserverImpl(
           input_connector_.CreateSink(), kernel_log_events_handler_,
           commands_to_custom_action_servers_, weak_display_handler_,
-          camera_controller_, shared_sensors_handler_, lights_observer_));
+          camera_controller_, sensors_handler_, lights_observer_));
 }
 
 void CfConnectionObserverFactory::AddCustomActionServer(
diff --git a/host/frontend/webrtc/connection_observer.h b/host/frontend/webrtc/connection_observer.h
index f71845c74..6eee399e8 100644
--- a/host/frontend/webrtc/connection_observer.h
+++ b/host/frontend/webrtc/connection_observer.h
@@ -36,7 +36,8 @@ class CfConnectionObserverFactory
  public:
   CfConnectionObserverFactory(
       InputConnector& input_connector,
-      KernelLogEventsHandler* kernel_log_events_handler,
+      KernelLogEventsHandler& kernel_log_events_handler,
+      webrtc_streaming::SensorsHandler& sensors_handler,
       std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer);
   ~CfConnectionObserverFactory() override = default;
 
@@ -52,13 +53,12 @@ class CfConnectionObserverFactory
 
  private:
   InputConnector& input_connector_;
-  KernelLogEventsHandler* kernel_log_events_handler_;
+  KernelLogEventsHandler& kernel_log_events_handler_;
   std::map<std::string, SharedFD>
       commands_to_custom_action_servers_;
   std::weak_ptr<DisplayHandler> weak_display_handler_;
   cuttlefish::CameraController* camera_controller_ = nullptr;
-  std::shared_ptr<webrtc_streaming::SensorsHandler> shared_sensors_handler_ =
-      std::make_shared<webrtc_streaming::SensorsHandler>();
+  webrtc_streaming::SensorsHandler& sensors_handler_;
   std::shared_ptr<webrtc_streaming::LightsObserver> lights_observer_;
 };
 
diff --git a/host/frontend/webrtc/display_handler.cpp b/host/frontend/webrtc/display_handler.cpp
index 4cbbd064f..ac010023a 100644
--- a/host/frontend/webrtc/display_handler.cpp
+++ b/host/frontend/webrtc/display_handler.cpp
@@ -23,13 +23,16 @@
 #include <libyuv.h>
 
 #include "host/frontend/webrtc/libdevice/streamer.h"
+#include "host/libs/screen_connector/composition_manager.h"
 
 namespace cuttlefish {
 
-DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
-                               ScreenshotHandler& screenshot_handler,
-                               ScreenConnector& screen_connector)
-    : streamer_(streamer),
+DisplayHandler::DisplayHandler(
+    webrtc_streaming::Streamer& streamer, ScreenshotHandler& screenshot_handler,
+    ScreenConnector& screen_connector,
+    std::optional<std::unique_ptr<CompositionManager>> composition_manager)
+    : composition_manager_(std::move(composition_manager)),
+      streamer_(streamer),
       screenshot_handler_(screenshot_handler),
       screen_connector_(screen_connector),
       frame_repeater_([this]() { RepeatFramesPeriodically(); }) {
@@ -55,6 +58,9 @@ DisplayHandler::DisplayHandler(webrtc_streaming::Streamer& streamer,
 
             std::lock_guard<std::mutex> lock(send_mutex_);
             display_sinks_[display_number] = display;
+            if (composition_manager_.has_value()) {
+              composition_manager_.value()->OnDisplayCreated(e);
+            }
           } else if constexpr (std::is_same_v<DisplayDestroyedEvent, T>) {
             LOG(VERBOSE) << "Display:" << e.display_number << " destroyed.";
 
@@ -85,14 +91,21 @@ DisplayHandler::GenerateProcessedFrameCallback
 DisplayHandler::GetScreenConnectorCallback() {
   // only to tell the producer how to create a ProcessedFrame to cache into the
   // queue
+  auto& composition_manager = composition_manager_;
   DisplayHandler::GenerateProcessedFrameCallback callback =
-      [](std::uint32_t display_number, std::uint32_t frame_width,
-         std::uint32_t frame_height, std::uint32_t frame_fourcc_format,
-         std::uint32_t frame_stride_bytes, std::uint8_t* frame_pixels,
-         WebRtcScProcessedFrame& processed_frame) {
+      [&composition_manager](
+          std::uint32_t display_number, std::uint32_t frame_width,
+          std::uint32_t frame_height, std::uint32_t frame_fourcc_format,
+          std::uint32_t frame_stride_bytes, std::uint8_t* frame_pixels,
+          WebRtcScProcessedFrame& processed_frame) {
         processed_frame.display_number_ = display_number;
         processed_frame.buf_ =
             std::make_unique<CvdVideoFrameBuffer>(frame_width, frame_height);
+        if (composition_manager.has_value()) {
+          composition_manager.value()->OnFrame(
+              display_number, frame_width, frame_height, frame_fourcc_format,
+              frame_stride_bytes, frame_pixels);
+        }
         if (frame_fourcc_format == DRM_FORMAT_ARGB8888 ||
             frame_fourcc_format == DRM_FORMAT_XRGB8888) {
           libyuv::ARGBToI420(
@@ -237,6 +250,11 @@ void DisplayHandler::RepeatFramesPeriodically() {
       for (auto& [display_number, buffer_info] : display_last_buffers_) {
         if (time_stamp >
             buffer_info->last_sent_time_stamp + kRepeatingInterval) {
+          if (composition_manager_.has_value()) {
+            composition_manager_.value()->ComposeFrame(
+                display_number, std::static_pointer_cast<CvdVideoFrameBuffer>(
+                                    buffer_info->buffer));
+          }
           buffers[display_number] = buffer_info;
         }
       }
diff --git a/host/frontend/webrtc/display_handler.h b/host/frontend/webrtc/display_handler.h
index c2739c82a..c3627d902 100644
--- a/host/frontend/webrtc/display_handler.h
+++ b/host/frontend/webrtc/display_handler.h
@@ -25,9 +25,11 @@
 #include "host/frontend/webrtc/cvd_video_frame_buffer.h"
 #include "host/frontend/webrtc/libdevice/video_sink.h"
 #include "host/frontend/webrtc/screenshot_handler.h"
+#include "host/libs/screen_connector/ring_buffer_manager.h"
 #include "host/libs/screen_connector/screen_connector.h"
 
 namespace cuttlefish {
+class CompositionManager;
 /**
  * ScreenConnectorImpl will generate this, and enqueue
  *
@@ -60,13 +62,13 @@ class DisplayHandler {
       ScreenConnector::GenerateProcessedFrameCallback;
   using WebRtcScProcessedFrame = cuttlefish::WebRtcScProcessedFrame;
 
-  DisplayHandler(webrtc_streaming::Streamer& streamer,
-                 ScreenshotHandler& screenshot_handler,
-                 ScreenConnector& screen_connector);
+  DisplayHandler(
+      webrtc_streaming::Streamer& streamer,
+      ScreenshotHandler& screenshot_handler, ScreenConnector& screen_connector,
+      std::optional<std::unique_ptr<CompositionManager>> composition_manager);
   ~DisplayHandler();
 
   [[noreturn]] void Loop();
-
   // If std::nullopt, send last frame for all displays.
   void SendLastFrame(std::optional<uint32_t> display_number);
 
@@ -82,11 +84,11 @@ class DisplayHandler {
     RUNNING,
     STOPPED,
   };
-
   GenerateProcessedFrameCallback GetScreenConnectorCallback();
   void SendBuffers(std::map<uint32_t, std::shared_ptr<BufferInfo>> buffers);
   void RepeatFramesPeriodically();
 
+  std::optional<std::unique_ptr<CompositionManager>> composition_manager_;
   std::map<uint32_t, std::shared_ptr<webrtc_streaming::VideoSink>>
       display_sinks_;
   webrtc_streaming::Streamer& streamer_;
diff --git a/host/frontend/webrtc/html_client/Android.bp b/host/frontend/webrtc/html_client/Android.bp
index 3b2220d8b..d1665ea92 100644
--- a/host/frontend/webrtc/html_client/Android.bp
+++ b/host/frontend/webrtc/html_client/Android.bp
@@ -100,3 +100,10 @@ prebuilt_usr_share_host {
     filename: "mouse.js",
     sub_dir: "webrtc/assets/js",
 }
+
+prebuilt_usr_share_host {
+    name: "webrtc_keyboard.js",
+    src: "js/keyboard.js",
+    filename: "keyboard.js",
+    sub_dir: "webrtc/assets/js",
+}
diff --git a/host/frontend/webrtc/html_client/client.html b/host/frontend/webrtc/html_client/client.html
index 13d36b095..52a5cccab 100644
--- a/host/frontend/webrtc/html_client/client.html
+++ b/host/frontend/webrtc/html_client/client.html
@@ -31,7 +31,6 @@
         </h3>
       </div>
       <section id="device-connection">
-        <audio id="device-audio"></audio>
         <div id='controls-and-displays'>
           <div id='control-panel-default-buttons' class='control-panel-column'>
             <button id='power_btn' title='Power' disabled='true' class='material-icons'>power_settings_new</button>
@@ -42,6 +41,7 @@
             <button id='home_btn' title='Home' disabled='true' class='material-icons'>home</button>
             <button id='menu_btn' title='Menu' disabled='true' class='material-icons'>menu</button>
             <button id='mouse_btn' title='Mouse' disabled='true' style="display:none" class='material-icons'>mouse</button>
+            <button id='keyboard-modal-button' title='keyboard console' class='material-icons'>keyboard</button>
             <button id='touchpad-modal-button' title='Touchpads' class='material-icons'>touch_app</button>
             <button id='rotate_left_btn' title='Rotate left' disabled='true' class='material-icons' data-adb="true">rotate_90_degrees_ccw</button>
             <button id='rotate_right_btn' title='Rotate right' disabled='true' class='material-icons' data-adb="true">rotate_90_degrees_cw</button>
@@ -61,7 +61,10 @@
             <div id='device-displays' tabindex="-1">
             </div>
           </div>
+          <button id='display-add-modal-button' title='Add display' class='material-icons'>add_to_queue</button>
         </div>
+        <!-- Audio tags of id with a prefix of "device-audio" will be inserted here dynamically
+        based on the number of audio streams.-->
       </section>
       <div id='device-details-modal' class='modal'>
         <div id='device-details-modal-header' class='modal-header'>
@@ -99,15 +102,6 @@
             <div class='bluetooth-drop-down'>
               <select id='bluetooth-wizard-type' validate-mac="true" required>
                 <option value="beacon">Beacon</option>
-                <option value="beacon_swarm">Beacon Swarm</option>
-                <!-- Disabled because they were "started but never finished" (according to mylesgw@)
-                <option value="car_kit">Car Kit</option>
-                <option value="classic">Classic</option> -->
-                <option value="keyboard">Keyboard</option>
-                <option value="remote_loopback">Remote Loopback</option>
-                <option value="scripted_beacon">Scripted Beacon</option>
-                <!-- Disabled because it will never show up in the UI
-                <option value="sniffer">Sniffer</option> -->
               </select>
             </div>
             <div class='bluetooth-text-field'><input type="text" id='bluetooth-wizard-mac' placeholder="Device MAC" validate-mac="true" required></input><span></span></div>
@@ -201,6 +195,30 @@
               </div>
 
       </div>
+      <div id='keyboard-modal' class='modal-wrapper'>
+
+        <!-- keyboard-prompt-modal modal -->
+        <div id='keyboard-prompt-modal' class='modal'>
+          <div id='keyboard-prompt-modal-header' class='modal-header'>
+            <h2>Keyboard</h2>
+            <button id='keyboard-prompt-modal-close' title='Close' class='material-icons modal-close'>close</button>
+          </div>
+          <div>
+            <div id='keyboard-prompt-text' class='keyboard-text'>
+              <div class='function-key-button'>
+                <button id='shift-button' title='Shift' class='modal-button'>Shift</button>
+                <button id='alt-button' title='Alt' class='modal-button'>Alt</button>
+                <button id='ctrl-button' title='Ctrl' class='modal-button'>Ctrl</button>
+                <button id='super-button' title='Super' class='modal-button'>Super</button>
+              </div>
+              <hr>
+              <div class='keyboard-button'>
+                <button id='tab-button' title='Tab' class='modal-button'>Tab</button>
+              </div>
+            </div>
+          </div>
+        </div>
+      </div>
       <div id='rotation-modal' class='modal'>
         <div id='rotation-modal-header' class='modal-header'>
             <h2>Rotation sensors</h2>
@@ -256,8 +274,27 @@
           <div class='touchpads'></div>
         </span>
       </div>
+      <div id='display-add-modal' class='modal'>
+        <div id='display-add-modal-header' class='modal-header'>
+          <h2>Add display</h2>
+          <button id='display-add-modal-close' title='Close' class='material-icons modal-close'>close</button>
+        </div>
+        <div>
+          <select id='display-spec-preset-select'>
+            <!-- setupDisplaySpecPresetSelector adds its options -->
+          </select>
+          <div class='display-spec-form'>
+            <label class='display-spec-label'>width<input type=number min=1 id='display-spec-width' required/></label>
+            <label class='display-spec-label'>height<input type=number min=1 id='display-spec-height' required/></label>
+            <label class='display-spec-label'>dpi<input type=number min=1 id='display-spec-dpi' required/></label>
+            <label class='display-spec-label'>refresh_rate_hz<input type=number min=1 id='display-spec-refresh-rate-hz' required/></label>
+          </div>
+          <button id='display-add-confirm' title='Add a new display' class='modal-button'>Add</button>
+        </div>
+      </div>
       <script src="js/adb.js"></script>
       <script src="js/location.js"></script>
+      <script src="js/keyboard.js"></script>
       <script src="js/rootcanal.js"></script>
       <script src="js/cf_webrtc.js" type="module"></script>
       <script src="js/controls.js"></script>
@@ -266,9 +303,12 @@
       <script src="js/app.js"></script>
       <template id="display-template">
         <div class="device-display">
-          <div class="device-display-info"></div>
+          <div class="device-display-info">
+            <div class="device-display-info-text"></div>
+            <button class="material-icons device-display-remove-button" title="Remove display">delete</button>
+          </div>
           <div class="device-video-container">
-            <video autoplay muted class="device-display-video"></video>
+            <video autoplay muted playsinline src="/" class="device-display-video"></video>
           </div>
         </div>
       </template>
diff --git a/host/frontend/webrtc/html_client/js/app.js b/host/frontend/webrtc/html_client/js/app.js
index d3a0e3ff1..1ddf9fd02 100644
--- a/host/frontend/webrtc/html_client/js/app.js
+++ b/host/frontend/webrtc/html_client/js/app.js
@@ -144,6 +144,24 @@ class DeviceControlApp {
   #micActive = false;
   #adbConnected = false;
 
+  #displaySpecPresets = {
+    'display-spec-preset-phone': {
+      name: 'Phone (720x1280)',
+      width: 720,
+      height: 1280,
+      dpi: 320,
+      'refresh-rate-hz': 60
+    },
+    'display-spec-preset-monitor': {
+      name: 'Monitor (1600x900)',
+      width: 1600,
+      height: 900,
+      dpi: 160,
+      'refresh-rate-hz': 60
+    }
+  };
+
+
   constructor(deviceConnection, parentController) {
     this.#deviceConnection = deviceConnection;
     this.#parentController = parentController;
@@ -164,15 +182,6 @@ class DeviceControlApp {
     createToggleControl(
         document.getElementById('record_video_btn'),
         enabled => this.#onVideoCaptureToggle(enabled));
-    const audioElm = document.getElementById('device-audio');
-
-    let audioPlaybackCtrl = createToggleControl(
-        document.getElementById('volume_off_btn'),
-        enabled => this.#onAudioPlaybackToggle(enabled), !audioElm.paused);
-    // The audio element may start or stop playing at any time, this ensures the
-    // audio control always show the right state.
-    audioElm.onplay = () => audioPlaybackCtrl.Set(true);
-    audioElm.onpause = () => audioPlaybackCtrl.Set(false);
 
     // Enable non-ADB buttons, these buttons use data channels to communicate
     // with the host, so they're ready to go as soon as the webrtc connection is
@@ -184,6 +193,25 @@ class DeviceControlApp {
     this.#showDeviceUI();
   }
 
+  #addAudioStream(stream_id, audioPlaybackCtrl) {
+    const audioId = `device-${stream_id}`;
+    if (document.getElementById(audioId)) {
+      console.warning(`Audio element with ID ${audioId} exists`);
+      return;
+    }
+    const deviceConnection = document.getElementById('device-connection');
+    const audioElm = document.createElement('audio');
+    audioElm.id = audioId;
+    audioElm.classList.add('device-audio');
+    deviceConnection.appendChild(audioElm);
+
+    // The audio element may start or stop playing at any time, this ensures the
+    // audio control always show the right state.
+    audioElm.onplay = () => audioPlaybackCtrl.Set(true);
+    audioElm.onpause = () => audioPlaybackCtrl.Set(false);
+    deviceConnection.appendChild(audioElm);
+  }
+
   #showDeviceUI() {
     // Set up control panel buttons
     addMouseListeners(
@@ -255,6 +283,9 @@ class DeviceControlApp {
     createModalButton(
         'location-set-cancel', 'location-prompt-modal', 'location-set-modal-close',
         'location-set-modal');
+    createModalButton('keyboard-modal-button', 'keyboard-prompt-modal',
+        'keyboard-prompt-modal-close');
+    createModalButton('display-add-modal-button', 'display-add-modal', 'display-add-modal-close');
     positionModal('rotation-modal-button', 'rotation-modal');
     positionModal('device-details-button', 'bluetooth-modal');
     positionModal('device-details-button', 'bluetooth-prompt');
@@ -268,6 +299,8 @@ class DeviceControlApp {
     positionModal('device-details-button', 'location-set-modal');
     positionModal('device-details-button', 'locations-import-modal');
 
+    positionModal('device-details-button', 'keyboard-prompt-modal');
+
     createButtonListener('bluetooth-prompt-list', null, this.#deviceConnection,
       evt => this.#onRootCanalCommand(this.#deviceConnection, "list", evt));
     createButtonListener('bluetooth-wizard-device', null, this.#deviceConnection,
@@ -298,6 +331,9 @@ class DeviceControlApp {
 
     createSliderListener('rotation-slider', () => this.#onMotionChanged(this.#deviceConnection));
 
+    createSelectListener('display-spec-preset-select', () => this.#updateDisplaySpecFrom());
+    createButtonListener('display-add-confirm', null, this.#deviceConnection, evt => this.#onDisplayAdditionConfirm(evt));
+
     if (this.#deviceConnection.description.custom_control_panel_buttons.length >
         0) {
       document.getElementById('control-panel-custom-buttons').style.display =
@@ -339,16 +375,25 @@ class DeviceControlApp {
       enableMouseButton(this.#deviceConnection);
     }
 
+    enableKeyboardRewriteButton(this.#deviceConnection);
+
     // Set up displays
     this.#updateDeviceDisplays();
     this.#deviceConnection.onStreamChange(stream => this.#onStreamChange(stream));
 
     // Set up audio
-    const deviceAudio = document.getElementById('device-audio');
+    let audioPlaybackCtrl = createToggleControl(
+        document.getElementById('volume_off_btn'),
+        enabled => this.#onAudioPlaybackToggle(enabled));
     for (const audio_desc of this.#deviceConnection.description.audio_streams) {
       let stream_id = audio_desc.stream_id;
+      this.#addAudioStream(stream_id, audioPlaybackCtrl);
       this.#deviceConnection.onStream(stream_id)
           .then(stream => {
+            const deviceAudio = document.getElementById(`device-${stream_id}`);
+            if (!deviceAudio) {
+              throw `Element with id device-${stream_id} not found`;
+            }
             deviceAudio.srcObject = stream;
             deviceAudio.play();
           })
@@ -401,6 +446,8 @@ class DeviceControlApp {
     this.#deviceConnection.onLocationMessage(msg => {
       console.debug("onLocationMessage = " +msg);
     });
+
+    this.#setupDisplaySpecPresetSelector();
   }
 
   #onStreamChange(stream) {
@@ -458,7 +505,10 @@ class DeviceControlApp {
 
     // Get sensor values from message.
     var sensor_vals = message.split(" ");
-    sensor_vals = sensor_vals.map((val) => parseFloat(val).toFixed(3));
+    var acc_update = sensor_vals[0].split(":").map((val) => parseFloat(val).toFixed(3));
+    var gyro_update = sensor_vals[1].split(":").map((val) => parseFloat(val).toFixed(3));
+    var mgn_update = sensor_vals[2].split(":").map((val) => parseFloat(val).toFixed(3));
+    var xyz_update = sensor_vals[3].split(":").map((val) => parseFloat(val).toFixed(3));
 
     const acc_val = document.getElementById('accelerometer-value');
     const mgn_val = document.getElementById('magnetometer-value');
@@ -468,19 +518,19 @@ class DeviceControlApp {
 
     // TODO: move to webrtc backend.
     // Inject sensors with new values.
-    adbShell(`/vendor/bin/cuttlefish_sensor_injection motion ${sensor_vals[3]} ${sensor_vals[4]} ${sensor_vals[5]} ${sensor_vals[6]} ${sensor_vals[7]} ${sensor_vals[8]} ${sensor_vals[9]} ${sensor_vals[10]} ${sensor_vals[11]}`);
+    adbShell(`/vendor/bin/cuttlefish_sensor_injection motion ${acc_update[0]} ${acc_update[1]} ${acc_update[2]} ${mgn_update[0]} ${mgn_update[1]} ${mgn_update[2]} ${gyro_update[0]} ${gyro_update[1]} ${gyro_update[2]}`);
 
     // Display new sensor values after injection.
-    acc_val.textContent = `${sensor_vals[3]} ${sensor_vals[4]} ${sensor_vals[5]}`;
-    mgn_val.textContent = `${sensor_vals[6]} ${sensor_vals[7]} ${sensor_vals[8]}`;
-    gyro_val.textContent = `${sensor_vals[9]} ${sensor_vals[10]} ${sensor_vals[11]}`;
+    acc_val.textContent = `${acc_update[0]} ${acc_update[1]} ${acc_update[2]}`;
+    mgn_val.textContent = `${mgn_update[0]} ${mgn_update[1]} ${mgn_update[2]}`;
+    gyro_val.textContent = `${gyro_update[0]} ${gyro_update[1]} ${gyro_update[2]}`;
 
     // Update xyz sliders with backend values.
     // This is needed for preserving device's state when display is turned on
     // and off, and for having the same state for multiple clients.
     for(let i = 0; i < 3; i++) {
-      xyz_val[i].textContent = sensor_vals[i];
-      xyz_range[i].value = sensor_vals[i];
+      xyz_val[i].textContent = xyz_update[i];
+      xyz_range[i].value = xyz_update[i];
     }
   }
 
@@ -489,7 +539,7 @@ class DeviceControlApp {
     let values = document.getElementsByClassName('rotation-slider-value');
     let xyz = [];
     for (var i = 0; i < values.length; i++) {
-      xyz[i] = values[i].innerHTML;
+      xyz[i] = values[i].textContent;
     }
     deviceConnection.sendSensorsMessage(`${xyz[0]} ${xyz[1]} ${xyz[2]}`);
   }
@@ -560,6 +610,80 @@ class DeviceControlApp {
 
   }
 
+  #setupDisplaySpecPresetSelector() {
+    const presetSelector = document.getElementById('display-spec-preset-select');
+    for (const id in this.#displaySpecPresets) {
+      const option = document.createElement('option');
+      option.value = id;
+      option.textContent = this.#displaySpecPresets[id].name;
+      presetSelector.appendChild(option);
+    }
+
+    const customOption = document.createElement('option');
+    customOption.value = 'display-spec-custom';
+    customOption.textContent = 'Custom';
+    presetSelector.appendChild(customOption);
+
+    this.#updateDisplaySpecFrom();
+  }
+
+  #updateDisplaySpecFrom() {
+    const presetSelector = document.getElementById('display-spec-preset-select');
+    const selectedPreset = presetSelector.value;
+
+    const parameters = ['width', 'height', 'dpi', 'refresh-rate-hz'];
+    const applyToParameterInputs = (fn) => {
+      for (const parameter of parameters) {
+        const inputElement = document.getElementById('display-spec-' + parameter);
+        fn(inputElement, parameter);
+      }
+    }
+
+    if (selectedPreset == 'display-spec-custom') {
+      applyToParameterInputs((inputElement, parameter) => inputElement.disabled = false);
+      return;
+    }
+
+    const preset = this.#displaySpecPresets[selectedPreset];
+    if (preset == undefined) {
+      console.error('Unknown preset is selected', selectedPreset);
+      return;
+    }
+
+    applyToParameterInputs((inputElement, parameter) => {
+      inputElement.value = preset[parameter];
+      inputElement.disabled = true;
+    });
+  }
+
+  #onDisplayAdditionConfirm(evt) {
+    if (evt.type != 'mousedown') {
+      return;
+    }
+
+    const getValue = (parameter) => {
+      const inputElement = document.getElementById('display-spec-' + parameter);
+      return inputElement.valueAsNumber;
+    }
+
+    const message = {
+      command: 'add-display',
+      width: getValue('width'),
+      height: getValue('height'),
+      dpi: getValue('dpi'),
+      refresh_rate_hz: getValue('refresh-rate-hz')
+    };
+    this.#deviceConnection.sendControlMessage(JSON.stringify(message));
+  }
+
+  #removeDisplay(displayId) {
+    const message = {
+      command: 'remove-display',
+      display_id: displayId
+    };
+    this.#deviceConnection.sendControlMessage(JSON.stringify(message));
+  }
+
   #showWebrtcError() {
     showError(
         'No connection to the guest device.  Please ensure the WebRTC' +
@@ -717,7 +841,8 @@ class DeviceControlApp {
         text += ` (Rotated ${this.#currentRotation}deg)`
       }
 
-      l.textContent = text;
+      const textElement = l.querySelector('.device-display-info-text');
+      textElement.textContent = text;
     });
 
     deviceDisplaysMessage.send();
@@ -792,7 +917,8 @@ class DeviceControlApp {
 
     const MAX_DISPLAYS = 16;
     for (let i = 0; i < MAX_DISPLAYS; i++) {
-      const stream_id = 'display_' + i.toString();
+      const display_id = i.toString();
+      const stream_id = 'display_' + display_id;
       const stream = this.#deviceConnection.getStream(stream_id);
 
       let deviceDisplayVideo = document.querySelector('#' + stream_id);
@@ -812,6 +938,13 @@ class DeviceControlApp {
             displayFragment.querySelector('.device-display-info');
         deviceDisplayInfo.id = stream_id + '_info';
 
+        let deviceDisplayRemoveButton =
+          displayFragment.querySelector('.device-display-remove-button');
+        deviceDisplayRemoveButton.id = stream_id + '_remove_button';
+        deviceDisplayRemoveButton.addEventListener('mousedown', () => {
+          this.#removeDisplay(display_id);
+        });
+
         deviceDisplayVideo = displayFragment.querySelector('video');
         deviceDisplayVideo.id = stream_id;
         deviceDisplayVideo.srcObject = stream;
@@ -1118,11 +1251,14 @@ class DeviceControlApp {
   }
 
   #onAudioPlaybackToggle(enabled) {
-    const audioElem = document.getElementById('device-audio');
-    if (enabled) {
-      audioElem.play();
-    } else {
-      audioElem.pause();
+    const audioElements = document.getElementsByClassName('device-audio');
+    for (let i = 0; i < audioElements.length; i++) {
+      const audioElem = audioElements[i];
+      if (enabled) {
+        audioElem.play();
+      } else {
+        audioElem.pause();
+      }
     }
   }
 
diff --git a/host/frontend/webrtc/html_client/js/controls.js b/host/frontend/webrtc/html_client/js/controls.js
index 09d7ad5d1..5e8ebeb0c 100644
--- a/host/frontend/webrtc/html_client/js/controls.js
+++ b/host/frontend/webrtc/html_client/js/controls.js
@@ -101,6 +101,11 @@ function createInputListener(input_id, func, listener) {
   input.addEventListener('input', listener);
 }
 
+function createSelectListener(select_id, listener) {
+  select = document.getElementById(select_id);
+  select.addEventListener('change', listener);
+}
+
 function validateMacAddress(val) {
   var regex = /^([0-9A-Fa-f]{2}[:-]){5}([0-9A-Fa-f]{2})$/;
   return (regex.test(val));
diff --git a/host/frontend/webrtc/html_client/js/keyboard.js b/host/frontend/webrtc/html_client/js/keyboard.js
new file mode 100644
index 000000000..bd6920baf
--- /dev/null
+++ b/host/frontend/webrtc/html_client/js/keyboard.js
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
+
+'use strict';
+
+function processButton(buttonName, keyCode, dc) {
+  function onMouseDown(evt) {
+    dc.sendKeyEvent(keyCode, "keydown");
+  }
+
+  function onMouseUp(evt) {
+    dc.sendKeyEvent(keyCode, "keyup");
+  }
+  let button = document.getElementById(buttonName);
+  button.addEventListener('mousedown', onMouseDown);
+  button.addEventListener('mouseup', onMouseUp);
+}
+
+function processToggleButton(buttonName, keyCode, dc) {
+  let toggle = false;
+  function onMouseDown(evt) {
+    const kPrimaryButton = 1;
+    if ((evt.buttons & kPrimaryButton) == 0) {
+      return;
+    }
+    toggle = !toggle;
+    if (toggle) {
+      dc.sendKeyEvent(keyCode, "keydown");
+    } else {
+      dc.sendKeyEvent(keyCode, "keyup");
+    }
+    this.classList.toggle('active');
+  }
+
+  let button = document.getElementById(buttonName);
+  button.addEventListener('mousedown', onMouseDown);
+}
+
+function enableKeyboardRewriteButton(dc) {
+  processToggleButton("shift-button", "ShiftLeft", dc);
+  processToggleButton("ctrl-button", "CtrlLeft", dc);
+  processToggleButton("alt-button", "AltLeft", dc);
+  processToggleButton("super-button", "MetaLeft", dc);
+  processButton("tab-button", "Tab", dc);
+}
diff --git a/host/frontend/webrtc/html_client/style.css b/host/frontend/webrtc/html_client/style.css
index 0516617a8..47be16904 100644
--- a/host/frontend/webrtc/html_client/style.css
+++ b/host/frontend/webrtc/html_client/style.css
@@ -22,12 +22,14 @@ body, body.dark-theme {
   --alert-bg: #927836; /* dark yellow */
   --info-bg: #007000; /* dark green */
   --modal-bg: #5f6368ea; /* Semi-transparent Google grey 500 */
-  --modal-button-bg: #e8eaed; /* Google grey 200 */
+  --modal-button-bg: #efefef; /* Google grey 200 */
   --modal-button-shadow: #444444;
-  --modal-button-fg: black;
+  --modal-button-fg: #434343;
   --modal-button-border: black;
   --modal-button-invalid-border: red;
   --modal-button-highlight-bg: #f4cccc; /* light red */
+  --modal-button-toggled-bg: #d9ead3ff; /* light green */
+  --modal-button-toggled-color: #274e13; /* dark green */
   --modal-padding: 20px;
   --bt-label-fg: green;
   --bt-label-invalid-fg: red;
@@ -50,12 +52,14 @@ body.light-theme {
   --alert-bg: #f3ef9e; /* light yellow */
   --info-bg: #a5d5a5; /* light green */
   --modal-bg: #d9d9d9ea; /* Semi-transparent Google grey 200 */
-  --modal-button-bg: #7b7b7b; /* Google grey 500 */
+  --modal-button-bg: #666666; /* Google grey 500 */
   --modal-button-shadow: #666666;
-  --modal-button-fg: #fafafa;
+  --modal-button-fg: #efefef;
   --modal-button-border: #c4c4c4; /* Google grey 300 */
   --modal-button-invalid-border: #c3413d; /*light red */
   --modal-button-highlight-bg: #a05555; /* dark red-ish */
+  --modal-button-toggled-bg: #d9ead3ff; /* light green */
+  --modal-button-toggled-color: #274e13; /* dark green */
   --bt-label-fg: green;
   --bt-label-invalid-fg: #c3413d; /* light red */
   --bt-action-bg: transparent;
@@ -182,7 +186,6 @@ body {
   background-color: transparent;
 }
 .modal-button, .modal-button-highlight {
-  background:    var(--modal-button-bg);
   border-radius: 10px;
   box-shadow:    1px 1px var(--modal-button-shadow);
   padding:       10px 20px;
@@ -190,6 +193,17 @@ body {
   display:       inline-block;
   font:          normal bold 14px/1 "Open Sans", sans-serif;
   text-align:    center;
+  cursor:        pointer;
+}
+.modal-button {
+  background: var(--modal-button-bg);
+}
+.modal-button-highlight {
+  background: var(--modal-button-highlight-bg);
+}
+.modal-button.active, .modal-button-highlight.active {
+  background-color: var(--modal-button-toggled-bg);
+  color:            var(--modal-button-toggled-color);
 }
 #bluetooth-wizard-mac:valid {
   border: 2px solid var(--modal-button-border);
@@ -207,12 +221,6 @@ body {
   content: 'OK';
   color: var(--bt-label-fg);
 }
-.modal-button {
-  background: var(--modal-button-bg);
-}
-.modal-button-highlight {
-  background: var(--modal-button-highlight-bg);
-}
 #device-details-modal span {
   white-space: pre;
 }
@@ -267,6 +275,32 @@ body {
 .location-button {
   text-align: center;
 }
+#display-add-modal-button {
+  margin-top: 10px;
+  margin-right: 10px;
+  height: 40px;
+  font-size: 32px;
+  color: var(--button-fg);
+  border: none;
+  border-radius: 10px;
+  outline: none;
+  background-color: var(--button-bg);
+}
+#display-add-modal-button.modal-button-opened {
+  background-color: var(--modal-bg);
+}
+.display-spec-form {
+  margin: 16px 0px;
+  display: flex;
+  gap: 8px;
+}
+.display-spec-label {
+  display: flex;
+  flex-direction: column;
+}
+.display-spec-label input {
+  width: 120px;
+}
 .sensors{
   position: sticky;
   right: 0;
@@ -371,6 +405,18 @@ body {
   margin-bottom: 10px;
   flex-grow: 0;
   flex-shrink: 0;
+  display: flex;
+  justify-content: space-between;
+  align-items: center;
+}
+
+.device-display-remove-button {
+  color: var(--main-fg);
+  background: none;
+  border: none;
+  outline: none;
+  padding: 0;
+  cursor: pointer;
 }
 
 /* The actual <video> element for each display. */
diff --git a/host/frontend/webrtc/libcommon/connection_controller.cpp b/host/frontend/webrtc/libcommon/connection_controller.cpp
index fff37ff5b..09a21877f 100644
--- a/host/frontend/webrtc/libcommon/connection_controller.cpp
+++ b/host/frontend/webrtc/libcommon/connection_controller.cpp
@@ -16,12 +16,11 @@
 
 #include "host/frontend/webrtc/libcommon/connection_controller.h"
 
-#include <algorithm>
 #include <vector>
 
 #include <android-base/logging.h>
 
-#include "host/frontend/webrtc/libcommon/audio_device.h"
+#include "common/libs/utils/json.h"
 #include "host/frontend/webrtc/libcommon/utils.h"
 
 namespace cuttlefish {
@@ -225,7 +224,8 @@ void ConnectionController::OnSetRemoteDescriptionComplete(
     const webrtc::RTCError& error) {
   if (!error.ok()) {
     // The remote description was rejected, can't connect to device.
-    FailConnection(ToString(error.type()) + std::string(": ") + error.message());
+    FailConnection(ToString(error.type()) + std::string(": ") +
+                   error.message());
     return;
   }
   AddPendingIceCandidates();
@@ -268,9 +268,8 @@ void ConnectionController::HandleSignalingMessage(const Json::Value& msg) {
 
 Result<void> ConnectionController::HandleSignalingMessageInner(
     const Json::Value& message) {
-  CF_EXPECT(ValidateJsonObject(message, "",
-                               {{"type", Json::ValueType::stringValue}}));
-  auto type = message["type"].asString();
+  auto type = CF_EXPECT(GetValue<std::string>(message, {"type"}),
+                        "Failed to get signaling message type");
 
   if (type == "request-offer") {
     auto ice_servers = CF_EXPECT(ParseIceServersMessage(message),
@@ -452,4 +451,3 @@ void ConnectionController::OnRemoveTrack(
 
 }  // namespace webrtc_streaming
 }  // namespace cuttlefish
-
diff --git a/host/frontend/webrtc/libcommon/utils.cpp b/host/frontend/webrtc/libcommon/utils.cpp
index 5122b3289..502f80594 100644
--- a/host/frontend/webrtc/libcommon/utils.cpp
+++ b/host/frontend/webrtc/libcommon/utils.cpp
@@ -17,37 +17,16 @@
 #include "host/frontend/webrtc/libcommon/utils.h"
 
 #include <functional>
-#include <map>
 
 #include <json/json.h>
 
+#include "common/libs/utils/json.h"
+
 namespace cuttlefish {
 namespace webrtc_streaming {
 
 namespace {
 
-Result<void> ValidateField(const Json::Value& obj, const std::string& type,
-                           const std::string& field_name,
-                           const Json::ValueType& field_type, bool required) {
-  CF_EXPECT(obj.isObject(), "Expected object with name-value pairs");
-  if (!obj.isMember(field_name) && !required) {
-    return {};
-  }
-  if (!(obj.isMember(field_name) &&
-        obj[field_name].isConvertibleTo(field_type))) {
-    std::string error_msg = "Expected a field named '";
-    error_msg += field_name + "' of type '";
-    error_msg += std::to_string(field_type);
-    error_msg += "'";
-    if (!type.empty()) {
-      error_msg += " in message of type '" + type + "'";
-    }
-    error_msg += ".";
-    return CF_ERR(error_msg);
-  }
-  return {};
-}
-
 template <typename T>
 Json::Value ToArray(const std::vector<T>& vec,
                     std::function<Json::Value(const T&)> to_json) {
@@ -60,27 +39,11 @@ Json::Value ToArray(const std::vector<T>& vec,
 
 }  // namespace
 
-Result<void> ValidateJsonObject(
-    const Json::Value& obj, const std::string& type,
-    const std::map<std::string, Json::ValueType>& required_fields,
-    const std::map<std::string, Json::ValueType>& optional_fields) {
-  for (const auto& field_spec : required_fields) {
-    CF_EXPECT(
-        ValidateField(obj, type, field_spec.first, field_spec.second, true));
-  }
-  for (const auto& field_spec : optional_fields) {
-    CF_EXPECT(
-        ValidateField(obj, type, field_spec.first, field_spec.second, false));
-  }
-  return {};
-}
-
 Result<std::unique_ptr<webrtc::SessionDescriptionInterface>>
 ParseSessionDescription(const std::string& type, const Json::Value& message,
                         webrtc::SdpType sdp_type) {
-  CF_EXPECT(ValidateJsonObject(message, type,
-                               {{"sdp", Json::ValueType::stringValue}}));
-  auto remote_desc_str = message["sdp"].asString();
+  auto remote_desc_str = CF_EXPECT(GetValue<std::string>(message, {"sdp"}),
+                                   "Failed to get 'sdp' property");
   auto remote_desc =
       webrtc::CreateSessionDescription(sdp_type, remote_desc_str);
   CF_EXPECT(remote_desc.get(), "Failed to parse sdp.");
@@ -89,18 +52,11 @@ ParseSessionDescription(const std::string& type, const Json::Value& message,
 
 Result<std::unique_ptr<webrtc::IceCandidateInterface>> ParseIceCandidate(
     const std::string& type, const Json::Value& message) {
-  CF_EXPECT(ValidateJsonObject(message, type,
-                               {{"candidate", Json::ValueType::objectValue}}));
-  auto candidate_json = message["candidate"];
-  CF_EXPECT(ValidateJsonObject(candidate_json, "ice-candidate/candidate",
-                               {
-                                   {"sdpMid", Json::ValueType::stringValue},
-                                   {"candidate", Json::ValueType::stringValue},
-                                   {"sdpMLineIndex", Json::ValueType::intValue},
-                               }));
-  auto mid = candidate_json["sdpMid"].asString();
-  auto candidate_sdp = candidate_json["candidate"].asString();
-  auto line_index = candidate_json["sdpMLineIndex"].asInt();
+  auto mid = CF_EXPECT(GetValue<std::string>(message, {"candidate", "sdpMid"}));
+  auto candidate_sdp =
+      CF_EXPECT(GetValue<std::string>(message, {"candidate", "candidate"}));
+  auto line_index =
+      CF_EXPECT(GetValue<int>(message, {"candidate", "sdpMLineIndex"}));
 
   auto candidate =
       std::unique_ptr<webrtc::IceCandidateInterface>(webrtc::CreateIceCandidate(
@@ -111,9 +67,7 @@ Result<std::unique_ptr<webrtc::IceCandidateInterface>> ParseIceCandidate(
 
 Result<std::string> ParseError(const std::string& type,
                                const Json::Value& message) {
-  CF_EXPECT(ValidateJsonObject(message, type,
-                               {{"error", Json::ValueType::stringValue}}));
-  return message["error"].asString();
+  return CF_EXPECT(GetValue<std::string>(message, {"error"}));
 }
 
 Result<std::vector<webrtc::PeerConnectionInterface::IceServer>>
diff --git a/host/frontend/webrtc/libcommon/utils.h b/host/frontend/webrtc/libcommon/utils.h
index c6f30db2f..185fe6070 100644
--- a/host/frontend/webrtc/libcommon/utils.h
+++ b/host/frontend/webrtc/libcommon/utils.h
@@ -16,7 +16,6 @@
 
 #pragma once
 
-#include <map>
 #include <memory>
 #include <vector>
 
@@ -29,13 +28,6 @@
 namespace cuttlefish {
 namespace webrtc_streaming {
 
-// Helper method to ensure a json object has the required fields convertible
-// to the appropriate types.
-Result<void> ValidateJsonObject(
-    const Json::Value& obj, const std::string& type,
-    const std::map<std::string, Json::ValueType>& required_fields,
-    const std::map<std::string, Json::ValueType>& optional_fields = {});
-
 // Parses a session description object from a JSON message.
 Result<std::unique_ptr<webrtc::SessionDescriptionInterface>>
 ParseSessionDescription(const std::string& type, const Json::Value& message,
diff --git a/host/frontend/webrtc/libdevice/Android.bp b/host/frontend/webrtc/libdevice/Android.bp
index f6ee9b679..e0420ceeb 100644
--- a/host/frontend/webrtc/libdevice/Android.bp
+++ b/host/frontend/webrtc/libdevice/Android.bp
@@ -51,7 +51,6 @@ cc_library {
         "libcuttlefish_wayland_server",
         "libcuttlefish_webrtc_common",
         "libcvd_gnss_grpc_proxy",
-        "libdrm",
         "libevent",
         "libffi",
         "libgflags",
diff --git a/host/frontend/webrtc/libdevice/connection_observer.h b/host/frontend/webrtc/libdevice/connection_observer.h
index d06fd4b70..15bf53ba3 100644
--- a/host/frontend/webrtc/libdevice/connection_observer.h
+++ b/host/frontend/webrtc/libdevice/connection_observer.h
@@ -50,9 +50,9 @@ class ConnectionObserver {
   virtual Result<void> OnTouchEvent(const std::string& device_label, int x,
                                     int y, bool down) = 0;
   virtual Result<void> OnMultiTouchEvent(const std::string& label,
-                                         Json::Value id, Json::Value slot,
-                                         Json::Value x, Json::Value y,
-                                         bool down, int size) = 0;
+                                         Json::Value id, Json::Value x,
+                                         Json::Value y, bool down,
+                                         int size) = 0;
 
   virtual Result<void> OnKeyboardEvent(uint16_t keycode, bool down) = 0;
 
@@ -77,6 +77,8 @@ class ConnectionObserver {
 
   virtual void OnCameraControlMsg(const Json::Value& msg) = 0;
   virtual void OnDisplayControlMsg(const Json::Value& msg) = 0;
+  virtual void OnDisplayAddMsg(const Json::Value& msg) = 0;
+  virtual void OnDisplayRemoveMsg(const Json::Value& msg) = 0;
 
   virtual void OnBluetoothChannelOpen(
       std::function<bool(const uint8_t*, size_t)> bluetooth_message_sender) = 0;
diff --git a/host/frontend/webrtc/libdevice/data_channels.cpp b/host/frontend/webrtc/libdevice/data_channels.cpp
index 85316ab70..b0caa263b 100644
--- a/host/frontend/webrtc/libdevice/data_channels.cpp
+++ b/host/frontend/webrtc/libdevice/data_channels.cpp
@@ -18,8 +18,10 @@
 
 #include <android-base/logging.h>
 
+#include "common/libs/utils/json.h"
 #include "host/frontend/webrtc/libcommon/utils.h"
 #include "host/frontend/webrtc/libdevice/keyboard.h"
+#include "host/libs/config/cuttlefish_config.h"
 
 namespace cuttlefish {
 namespace webrtc_streaming {
@@ -55,6 +57,7 @@ class DataChannelHandler : public webrtc::DataChannelObserver {
   std::function<bool(const Json::Value &)> GetJSONSender() {
     return [this](const Json::Value &msg) { return Send(msg); };
   }
+
  private:
   bool first_msg_received_ = false;
 };
@@ -92,63 +95,69 @@ class InputChannelHandler : public DataChannelHandler {
                "Received invalid JSON object over control channel: '{}'",
                error_message);
 
-    CF_EXPECTF(evt.isMember("type") && evt["type"].isString(),
-               "Input event doesn't have a valid 'type' field: ",
-               evt.toStyledString());
-    auto event_type = evt["type"].asString();
+    auto event_type = CF_EXPECT(GetValue<std::string>(evt, {"type"}),
+                                "Failed to get property 'type' from message");
+    auto get_or_err = [&event_type,
+                       &evt]<typename T>(const std::string &prop) -> Result<T> {
+      return CF_EXPECTF(GetValue<T>(evt, {prop}),
+                        "Failed to get property '{}' from '{}' message", prop,
+                        event_type);
+    };
+    auto get_int = [get_or_err](auto prop) -> Result<int> {
+      return get_or_err.operator()<int>(prop);
+    };
+    auto get_str = [get_or_err](auto prop) -> Result<std::string> {
+      return get_or_err.operator()<std::string>(prop);
+    };
+    auto get_arr = [get_or_err, &event_type](
+                              const std::string &prop) -> Result<Json::Value> {
+      Json::Value arr = CF_EXPECT(get_or_err.operator()<Json::Value>(prop));
+      CF_EXPECTF(arr.isArray(), "Property '{}' of '{}' message is not an array",
+                 prop, event_type);
+      return arr;
+    };
 
     if (event_type == "mouseMove") {
-      CF_EXPECT(ValidateJsonObject(evt, "mouseMove",
-                                   {{"x", Json::ValueType::intValue},
-                                    {"y", Json::ValueType::intValue}}));
-      int32_t x = evt["x"].asInt();
-      int32_t y = evt["y"].asInt();
+      int32_t x = CF_EXPECT(get_int("x"));
+      int32_t y = CF_EXPECT(get_int("y"));
 
       CF_EXPECT(observer()->OnMouseMoveEvent(x, y));
     } else if (event_type == "mouseButton") {
-      CF_EXPECT(ValidateJsonObject(evt, "mouseButton",
-                                   {{"button", Json::ValueType::intValue},
-                                    {"down", Json::ValueType::intValue}}));
-      int32_t button = evt["button"].asInt();
-      int32_t down = evt["down"].asInt();
+      int32_t button = CF_EXPECT(get_int("button"));
+      int32_t down = CF_EXPECT(get_int("down"));
 
       CF_EXPECT(observer()->OnMouseButtonEvent(button, down));
     } else if (event_type == "mouseWheel") {
-      CF_EXPECT(ValidateJsonObject(evt, "mouseWheel",
-                                   {{"pixels", Json::ValueType::intValue}}));
-      auto pixels = evt["pixels"].asInt();
+      int pixels = CF_EXPECT(get_int("pixels"));
+
       CF_EXPECT(observer()->OnMouseWheelEvent(pixels));
     } else if (event_type == "multi-touch") {
+      std::string label = CF_EXPECT(get_str("device_label"));
+      auto idArr = CF_EXPECT(get_arr("id"));
+      int32_t down = CF_EXPECT(get_int("down"));
+      auto xArr = CF_EXPECT(get_arr("x"));
+      auto yArr = CF_EXPECT(get_arr("y"));
+      int size = idArr.size();
+
       CF_EXPECT(
-          ValidateJsonObject(evt, "multi-touch",
-                             {{"id", Json::ValueType::arrayValue},
-                              {"down", Json::ValueType::intValue},
-                              {"x", Json::ValueType::arrayValue},
-                              {"y", Json::ValueType::arrayValue},
-                              {"device_label", Json::ValueType::stringValue}}));
-
-      auto label = evt["device_label"].asString();
-      auto idArr = evt["id"];
-      int32_t down = evt["down"].asInt();
-      auto xArr = evt["x"];
-      auto yArr = evt["y"];
-      auto slotArr = evt["slot"];
-      int size = evt["id"].size();
-
-      CF_EXPECT(observer()->OnMultiTouchEvent(label, idArr, slotArr, xArr, yArr,
-                                              down, size));
+          observer()->OnMultiTouchEvent(label, idArr, xArr, yArr, down, size));
     } else if (event_type == "keyboard") {
-      CF_EXPECT(
-          ValidateJsonObject(evt, "keyboard",
-                             {{"event_type", Json::ValueType::stringValue},
-                              {"keycode", Json::ValueType::stringValue}}));
-      auto down = evt["event_type"].asString() == std::string("keydown");
-      auto code = DomKeyCodeToLinux(evt["keycode"].asString());
+      auto cvd_config =
+          CF_EXPECT(CuttlefishConfig::Get(), "CuttlefishConfig is null!");
+      auto instance = cvd_config->ForDefaultInstance();
+      Json::Value domkey_mapping_config_json = instance.domkey_mapping_config();
+      bool down = CF_EXPECT(get_str("event_type")) == std::string("keydown");
+      std::string keycode = CF_EXPECT(get_str("keycode"));
+      uint16_t code = DomKeyCodeToLinux(keycode);
+      if (domkey_mapping_config_json.isMember("mappings") &&
+          domkey_mapping_config_json["mappings"].isMember(keycode)) {
+        code = domkey_mapping_config_json["mappings"][keycode].asUInt();
+      }
+
       CF_EXPECT(observer()->OnKeyboardEvent(code, down));
     } else if (event_type == "wheel") {
-      CF_EXPECT(ValidateJsonObject(evt, "wheel",
-                                   {{"pixels", Json::ValueType::intValue}}));
-      auto pixels = evt["pixels"].asInt();
+      int pixels = CF_EXPECT(get_int("pixels"));
+
       CF_EXPECT(observer()->OnRotaryWheelEvent(pixels));
     } else {
       return CF_ERRF("Unrecognized event type: '{}'", event_type);
@@ -177,24 +186,18 @@ class ControlChannelHandler : public DataChannelHandler {
         "Received invalid JSON object over control channel: '{}'",
         error_message);
 
-    CF_EXPECT(ValidateJsonObject(
-        evt, "command",
-        /*required_fields=*/{{"command", Json::ValueType::stringValue}},
-        /*optional_fields=*/
-        {
-            {"button_state", Json::ValueType::stringValue},
-            {"lid_switch_open", Json::ValueType::booleanValue},
-            {"hinge_angle_value", Json::ValueType::intValue},
-        }));
-    auto command = evt["command"].asString();
+    auto command =
+        CF_EXPECT(GetValue<std::string>(evt, {"command"}),
+                  "Failed to access 'command' property on control message");
 
     if (command == "device_state") {
       if (evt.isMember("lid_switch_open")) {
-        CF_EXPECT(
-            observer()->OnLidStateChange(evt["lid_switch_open"].asBool()));
+        CF_EXPECT(observer()->OnLidStateChange(
+            CF_EXPECT(GetValue<bool>(evt, {"lid_switch_open"}))));
       }
       if (evt.isMember("hinge_angle_value")) {
-        observer()->OnHingeAngleChange(evt["hinge_angle_value"].asInt());
+        observer()->OnHingeAngleChange(
+            CF_EXPECT(GetValue<int>(evt, {"hinge_angle_value"})));
       }
       return {};
     } else if (command.rfind("camera_", 0) == 0) {
@@ -203,11 +206,20 @@ class ControlChannelHandler : public DataChannelHandler {
     } else if (command == "display") {
       observer()->OnDisplayControlMsg(evt);
       return {};
+    } else if (command == "add-display") {
+      observer()->OnDisplayAddMsg(evt);
+      return {};
+    } else if (command == "remove-display") {
+      observer()->OnDisplayRemoveMsg(evt);
+      return {};
     }
 
-    auto button_state = evt["button_state"].asString();
+    auto button_state =
+        CF_EXPECT(GetValue<std::string>(evt, {"button_state"}),
+                  "Failed to get 'button_state' property of control message");
     LOG(VERBOSE) << "Control command: " << command << " (" << button_state
                  << ")";
+
     if (command == "power") {
       CF_EXPECT(observer()->OnPowerButton(button_state == "down"));
     } else if (command == "back") {
@@ -279,7 +291,9 @@ class CameraChannelHandler : public DataChannelHandler {
 // TODO(b/297361564)
 class SensorsChannelHandler : public DataChannelHandler {
  public:
-  void OnFirstMessage() override { observer()->OnSensorsChannelOpen(GetBinarySender()); }
+  void OnFirstMessage() override {
+    observer()->OnSensorsChannelOpen(GetBinarySender());
+  }
   Result<void> OnMessageInner(const webrtc::DataBuffer &msg) override {
     if (!first_msg_received_) {
       first_msg_received_ = true;
@@ -289,7 +303,8 @@ class SensorsChannelHandler : public DataChannelHandler {
     return {};
   }
 
-  void OnStateChangeInner(webrtc::DataChannelInterface::DataState state) override {
+  void OnStateChangeInner(
+      webrtc::DataChannelInterface::DataState state) override {
     if (state == webrtc::DataChannelInterface::kClosed) {
       observer()->OnSensorsChannelClosed();
     }
@@ -464,8 +479,8 @@ void DataChannelHandlers::OnDataChannelOpen(
     gpx_location_.reset(new DataChannelHandlerImpl<GpxLocationChannelHandler>(
         channel, observer_));
   } else if (label == kSensorsDataChannelLabel) {
-    sensors_.reset(new DataChannelHandlerImpl<SensorsChannelHandler>(
-        channel, observer_));
+    sensors_.reset(
+        new DataChannelHandlerImpl<SensorsChannelHandler>(channel, observer_));
   } else {
     unknown_channels_.emplace_back(
         new DataChannelHandlerImpl<UnknownChannelHandler>(channel, observer_));
diff --git a/host/frontend/webrtc/main.cpp b/host/frontend/webrtc/main.cpp
index 002ac16b7..680557a3c 100644
--- a/host/frontend/webrtc/main.cpp
+++ b/host/frontend/webrtc/main.cpp
@@ -45,6 +45,7 @@
 #include "host/libs/confui/host_mode_ctrl.h"
 #include "host/libs/confui/host_server.h"
 #include "host/libs/input_connector/input_connector.h"
+#include "host/libs/screen_connector/composition_manager.h"
 #include "host/libs/screen_connector/screen_connector.h"
 #include "webrtc_commands.pb.h"
 
@@ -64,15 +65,12 @@ DEFINE_int32(confui_in_fd, -1,
              "Confirmation UI virtio-console from host to guest");
 DEFINE_int32(confui_out_fd, -1,
              "Confirmation UI virtio-console from guest to host");
-DEFINE_int32(sensors_in_fd, -1, "Sensors virtio-console from host to guest");
-DEFINE_int32(sensors_out_fd, -1, "Sensors virtio-console from guest to host");
 DEFINE_string(action_servers, "",
               "A comma-separated list of server_name:fd pairs, "
               "where each entry corresponds to one custom action server.");
-DEFINE_bool(write_virtio_input, true,
-            "Whether to send input events in virtio format.");
 DEFINE_int32(audio_server_fd, -1, "An fd to listen on for audio frames");
 DEFINE_int32(camera_streamer_fd, -1, "An fd to send client camera frames");
+DEFINE_int32(sensors_fd, -1, "An fd to communicate with sensors_simulator.");
 DEFINE_string(client_dir, "webrtc", "Location of the client files");
 DEFINE_string(group_id, "", "The group id of device");
 
@@ -188,9 +186,7 @@ int CuttlefishMain() {
   auto cvd_config = CuttlefishConfig::Get();
   auto instance = cvd_config->ForDefaultInstance();
 
-  cuttlefish::InputConnectorBuilder inputs_builder(
-      FLAGS_write_virtio_input ? cuttlefish::InputEventType::Virtio
-                               : cuttlefish::InputEventType::Evdev);
+  cuttlefish::InputConnectorBuilder inputs_builder;
 
   const auto display_count = instance.display_configs().size();
   const auto touch_fds = android::base::Split(FLAGS_touch_fds, ",");
@@ -236,6 +232,9 @@ int CuttlefishMain() {
   auto kernel_log_events_client = SharedFD::Dup(FLAGS_kernel_log_events_fd);
   close(FLAGS_kernel_log_events_fd);
 
+  auto sensors_fd = cuttlefish::SharedFD::Dup(FLAGS_sensors_fd);
+  close(FLAGS_sensors_fd);
+
   confui::PipeConnectionPair conf_ui_comm_fd_pair{
       .from_guest_ = SharedFD::Dup(FLAGS_confui_out_fd),
       .to_guest_ = SharedFD::Dup(FLAGS_confui_in_fd)};
@@ -298,8 +297,11 @@ int CuttlefishMain() {
     lights_observer->Start();
   }
 
+  webrtc_streaming::SensorsHandler sensors_handler(sensors_fd);
+
   auto observer_factory = std::make_shared<CfConnectionObserverFactory>(
-      confui_virtual_input, &kernel_logs_event_handler, lights_observer);
+      confui_virtual_input, kernel_logs_event_handler, sensors_handler,
+      lights_observer);
 
   RecordingManager recording_manager;
 
@@ -309,8 +311,22 @@ int CuttlefishMain() {
       Streamer::Create(streamer_config, recording_manager, observer_factory);
   CHECK(streamer) << "Could not create streamer";
 
+  // Determine whether to enable Display Composition feature.
+  // It's enabled via the multi-vd config file entry 'overlays'
+  std::optional<std::unique_ptr<CompositionManager>> composition_manager;
+
+  if (cvd_config->OverlaysEnabled()) {
+    Result<std::unique_ptr<CompositionManager>> composition_manager_result =
+        CompositionManager::Create();
+    if (composition_manager_result.ok() && *composition_manager_result) {
+      composition_manager = std::optional<std::unique_ptr<CompositionManager>>(
+          std::move(*composition_manager_result));
+    }
+  }
+
   auto display_handler = std::make_shared<DisplayHandler>(
-      *streamer, screenshot_handler, screen_connector);
+      *streamer, screenshot_handler, screen_connector,
+      std::move(composition_manager));
 
   if (instance.camera_server_port()) {
     auto camera_controller = streamer->AddCamera(instance.camera_server_port(),
@@ -330,7 +346,8 @@ int CuttlefishMain() {
   }
 
   streamer->SetHardwareSpec("CPUs", instance.cpus());
-  streamer->SetHardwareSpec("RAM", std::to_string(instance.memory_mb()) + " mb");
+  streamer->SetHardwareSpec("RAM",
+                            std::to_string(instance.memory_mb()) + " mb");
 
   std::string user_friendly_gpu_mode;
   if (instance.gpu_mode() == kGpuModeGuestSwiftshader) {
@@ -351,11 +368,16 @@ int CuttlefishMain() {
 
   std::shared_ptr<AudioHandler> audio_handler;
   if (instance.enable_audio()) {
-    auto audio_stream = streamer->AddAudioStream("audio");
+    int output_streams_count = instance.audio_output_streams_count();
+    std::vector<std::shared_ptr<webrtc_streaming::AudioSink>> audio_streams(
+        output_streams_count);
+    for (int i = 0; i < audio_streams.size(); i++) {
+      audio_streams[i] = streamer->AddAudioStream("audio-" + std::to_string(i));
+    }
     auto audio_server = CreateAudioServer();
     auto audio_source = streamer->GetAudioSource();
-    audio_handler = std::make_shared<AudioHandler>(std::move(audio_server),
-                                                   audio_stream, audio_source);
+    audio_handler = std::make_shared<AudioHandler>(
+        std::move(audio_server), std::move(audio_streams), audio_source);
   }
 
   // Parse the -action_servers flag, storing a map of action server name -> fd
@@ -462,4 +484,4 @@ int main(int argc, char** argv) {
   cuttlefish::DefaultSubprocessLogging(argv);
   ::gflags::ParseCommandLineFlags(&argc, &argv, true);
   return cuttlefish::CuttlefishMain();
-}
\ No newline at end of file
+}
diff --git a/host/frontend/webrtc/screenshot_handler.h b/host/frontend/webrtc/screenshot_handler.h
index 6fe71f036..b84b7b787 100644
--- a/host/frontend/webrtc/screenshot_handler.h
+++ b/host/frontend/webrtc/screenshot_handler.h
@@ -21,7 +21,6 @@
 #include <unordered_set>
 
 #include <fmt/format.h>
-#include <rtc_base/time_utils.h>
 
 #include "common/libs/utils/result.h"
 #include "host/frontend/webrtc/libdevice/video_frame_buffer.h"
diff --git a/host/frontend/webrtc/sensors_handler.cpp b/host/frontend/webrtc/sensors_handler.cpp
index 74ffce954..142435305 100644
--- a/host/frontend/webrtc/sensors_handler.cpp
+++ b/host/frontend/webrtc/sensors_handler.cpp
@@ -24,14 +24,68 @@
 namespace cuttlefish {
 namespace webrtc_streaming {
 
-SensorsHandler::SensorsHandler() {}
+namespace {
+static constexpr sensors::SensorsMask kUiSupportedSensors =
+    (1 << sensors::kAccelerationId) | (1 << sensors::kGyroscopeId) |
+    (1 << sensors::kMagneticId) | (1 << sensors::kRotationVecId);
+}  // namespace
+
+SensorsHandler::SensorsHandler(SharedFD sensors_fd)
+    : channel_(transport::SharedFdChannel(sensors_fd, sensors_fd)) {
+  auto refresh_result = RefreshSensors(0, 0, 0);
+  if (!refresh_result.ok()) {
+    LOG(ERROR) << "Failed to refresh sensors: "
+               << refresh_result.error().FormatForEnv();
+  }
+}
 
 SensorsHandler::~SensorsHandler() {}
 
+Result<void> SensorsHandler::RefreshSensors(const double x, const double y,
+                                            const double z) {
+  std::stringstream ss;
+  ss << x << sensors::INNER_DELIM << y << sensors::INNER_DELIM << z;
+  auto msg = ss.str();
+  auto size = msg.size();
+  auto cmd = sensors::kUpdateRotationVec;
+  auto request = CF_EXPECT(transport::CreateMessage(cmd, size),
+                           "Failed to allocate message for cmd: "
+                               << cmd << " with size: " << size << " bytes. ");
+  std::memcpy(request->payload, msg.data(), size);
+  CF_EXPECT(channel_.SendRequest(*request),
+            "Can't send request for cmd: " << cmd);
+  return {};
+}
+
+Result<std::string> SensorsHandler::GetSensorsData() {
+  auto msg = std::to_string(kUiSupportedSensors);
+  auto size = msg.size();
+  auto cmd = sensors::kGetSensorsData;
+  auto request = CF_EXPECT(transport::CreateMessage(cmd, size),
+                           "Failed to allocate message for cmd: "
+                               << cmd << " with size: " << size << " bytes. ");
+  std::memcpy(request->payload, msg.data(), size);
+  CF_EXPECT(channel_.SendRequest(*request),
+            "Can't send request for cmd: " << cmd);
+  auto response =
+      CF_EXPECT(channel_.ReceiveMessage(), "Couldn't receive message.");
+  cmd = response->command;
+  auto is_response = response->is_response;
+  CF_EXPECT((cmd == sensors::kGetSensorsData) && is_response,
+            "Unexpected cmd: " << cmd << ", response: " << is_response);
+  return std::string(reinterpret_cast<const char*>(response->payload),
+                     response->payload_size);
+}
+
 // Get new sensor values and send them to client.
 void SensorsHandler::HandleMessage(const double x, const double y, const double z) {
-  sensors_simulator_->RefreshSensors(x, y, z);
-  UpdateSensors();
+  auto refresh_result = RefreshSensors(x, y, z);
+  if (!refresh_result.ok()) {
+    LOG(ERROR) << "Failed to refresh sensors: "
+               << refresh_result.error().FormatForEnv();
+    return;
+  }
+  UpdateSensorsUi();
 }
 
 int SensorsHandler::Subscribe(std::function<void(const uint8_t*, size_t)> send_to_client) {
@@ -42,7 +96,13 @@ int SensorsHandler::Subscribe(std::function<void(const uint8_t*, size_t)> send_t
   }
 
   // Send device's initial state to the new client.
-  std::string new_sensors_data = sensors_simulator_->GetSensorsData();
+  auto result = GetSensorsData();
+  if (!result.ok()) {
+    LOG(ERROR) << "Failed to get sensors data: "
+               << result.error().FormatForEnv();
+    return subscriber_id;
+  }
+  auto new_sensors_data = std::move(result.value());
   const uint8_t* message =
       reinterpret_cast<const uint8_t*>(new_sensors_data.c_str());
   send_to_client(message, new_sensors_data.size());
@@ -55,8 +115,14 @@ void SensorsHandler::UnSubscribe(int subscriber_id) {
   client_channels_.erase(subscriber_id);
 }
 
-void SensorsHandler::UpdateSensors() {
-  std::string new_sensors_data = sensors_simulator_->GetSensorsData();
+void SensorsHandler::UpdateSensorsUi() {
+  auto result = GetSensorsData();
+  if (!result.ok()) {
+    LOG(ERROR) << "Failed to get sensors data: "
+               << result.error().FormatForEnv();
+    return;
+  }
+  auto new_sensors_data = std::move(result.value());
   const uint8_t* message =
       reinterpret_cast<const uint8_t*>(new_sensors_data.c_str());
   std::lock_guard<std::mutex> lock(subscribers_mtx_);
diff --git a/host/frontend/webrtc/sensors_handler.h b/host/frontend/webrtc/sensors_handler.h
index 84de2946f..4e0236086 100644
--- a/host/frontend/webrtc/sensors_handler.h
+++ b/host/frontend/webrtc/sensors_handler.h
@@ -16,29 +16,33 @@
 
 #pragma once
 
-#include "host/frontend/webrtc/sensors_simulator.h"
-
 #include <chrono>
 #include <mutex>
 #include <thread>
 #include <unordered_map>
 
+#include "common/libs/sensors/sensors.h"
+#include "common/libs/transport/channel_sharedfd.h"
+
 namespace cuttlefish {
 namespace webrtc_streaming {
 
 struct SensorsHandler {
-  SensorsHandler();
+  SensorsHandler(SharedFD sensors_fd);
   ~SensorsHandler();
   void HandleMessage(const double x, const double y, const double z);
   int Subscribe(std::function<void(const uint8_t*, size_t)> send_to_client);
   void UnSubscribe(int subscriber_id);
 
  private:
-  void UpdateSensors();
-  SensorsSimulator* sensors_simulator_ = new SensorsSimulator();
+  Result<void> RefreshSensors(const double x, const double y, const double z);
+  Result<std::string> GetSensorsData();
+  void UpdateSensorsUi();
   std::unordered_map<int, std::function<void(const uint8_t*, size_t)>> client_channels_;
   int last_client_channel_id_ = -1;
   std::mutex subscribers_mtx_;
+  transport::SharedFdChannel channel_;
 };
+
 }  // namespace webrtc_streaming
 }  // namespace cuttlefish
diff --git a/host/frontend/webrtc/sensors_simulator.cpp b/host/frontend/webrtc/sensors_simulator.cpp
deleted file mode 100644
index 2fdcde3e1..000000000
--- a/host/frontend/webrtc/sensors_simulator.cpp
+++ /dev/null
@@ -1,108 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include "host/frontend/webrtc/sensors_simulator.h"
-
-#include <android-base/logging.h>
-
-#include <cmath>
-
-namespace cuttlefish {
-namespace webrtc_streaming {
-namespace {
-
-constexpr double kG = 9.80665;  // meter per second^2
-const Eigen::Vector3d kGravityVec{0, kG, 0}, kMagneticField{0, 5.9, -48.4};
-
-inline double toRadians(double x) { return x * M_PI / 180; }
-
-// Calculate the rotation matrix of the pitch, roll, and yaw angles.
-static Eigen::Matrix3d getRotationMatrix(double x, double y, double z) {
-  x = toRadians(-x);
-  y = toRadians(-y);
-  z = toRadians(-z);
-  // Create rotation matrices for each Euler angle
-  Eigen::Matrix3d rx = Eigen::AngleAxisd(x, Eigen::Vector3d::UnitX()).toRotationMatrix();
-  Eigen::Matrix3d ry = Eigen::AngleAxisd(y, Eigen::Vector3d::UnitY()).toRotationMatrix();
-  Eigen::Matrix3d rz = Eigen::AngleAxisd(z, Eigen::Vector3d::UnitZ()).toRotationMatrix();
-
-  return rz * (ry * rx);
-}
-
-// Calculate new Accelerometer values of the new rotation degrees.
-static inline Eigen::Vector3d calculateAcceleration(Eigen::Matrix3d current_rotation_matrix) {
-  return current_rotation_matrix * kGravityVec;
-}
-
-// Calculate new Magnetometer values of the new rotation degrees.
-static inline Eigen::Vector3d calculateMagnetometer(Eigen::Matrix3d current_rotation_matrix) {
-  return current_rotation_matrix * kMagneticField;
-}
-
-// Calculate new Gyroscope values of the new rotation degrees.
-static Eigen::Vector3d calculateGyroscope(std::chrono::duration<double> duration,
-                                          Eigen::Matrix3d prior_rotation_matrix,
-                                          Eigen::Matrix3d current_rotation_matrix) {
-  double time_diff = duration.count();
-  if (time_diff == 0) {
-    return Eigen::Vector3d{0, 0, 0};
-  }
-  Eigen::Matrix3d transition_matrix = prior_rotation_matrix * current_rotation_matrix.inverse();
-  // Convert rotation matrix to angular velocity numerator.
-  Eigen::AngleAxisd angle_axis(transition_matrix);
-  double angle = angle_axis.angle();
-  Eigen::Vector3d gyro = angle_axis.axis();
-  gyro *= angle;
-  gyro /= time_diff;
-  return gyro;
-}
-
-std::string SerializeVector(const Eigen::Vector3d& v) {
-  std::stringstream s;
-  s << v(0) << " " << v(1) << " " << v(2);
-  return s.str();
-}
-
-}  // namespace
-
-SensorsSimulator::SensorsSimulator()
-    : current_rotation_matrix_(getRotationMatrix(0, 0, 0)),
-      last_event_timestamp_(std::chrono::high_resolution_clock::now()) {}
-
-// Update sensor values based on new rotation status.
-void SensorsSimulator::RefreshSensors(double x, double y, double z) {
-  xyz_ << x, y, z;
-  prior_rotation_matrix_ = current_rotation_matrix_;
-  current_rotation_matrix_ = getRotationMatrix(x, y, z);
-  acc_xyz_ = calculateAcceleration(current_rotation_matrix_);
-  mgn_xyz_ = calculateMagnetometer(current_rotation_matrix_);
-  auto current_time = std::chrono::high_resolution_clock::now();
-  std::chrono::duration<double> duration = current_time - last_event_timestamp_;
-  gyro_xyz_ = calculateGyroscope(duration, prior_rotation_matrix_,
-                                 current_rotation_matrix_);
-  last_event_timestamp_ = current_time;
-}
-
-// Get sensors' data in string format to be passed as a message.
-std::string SensorsSimulator::GetSensorsData() {
-  std::stringstream sensors_data;
-  sensors_data << SerializeVector(xyz_) << " " << SerializeVector(acc_xyz_) << " "
-               << SerializeVector(mgn_xyz_) << " " << SerializeVector(gyro_xyz_);
-  return sensors_data.str();
-}
-
-}  // namespace webrtc_streaming
-}  // namespace cuttlefish
diff --git a/host/frontend/webrtc_operator/assets/style.css b/host/frontend/webrtc_operator/assets/style.css
index f53166b7b..3e5a6fd8c 100644
--- a/host/frontend/webrtc_operator/assets/style.css
+++ b/host/frontend/webrtc_operator/assets/style.css
@@ -59,9 +59,6 @@ body {
   position: relative;
   margin-right: 6px;
 }
-#device-audio {
-  height: 44px;
-}
 
 #status-div {
   flex-grow: 1;
diff --git a/host/libs/avb/avb.cpp b/host/libs/avb/avb.cpp
index 4a5f420f1..22012932f 100644
--- a/host/libs/avb/avb.cpp
+++ b/host/libs/avb/avb.cpp
@@ -68,8 +68,12 @@ Command Avb::GenerateAddHashFooter(const std::string& image_path,
   command.AddParameter(image_path);
   command.AddParameter("--partition_name");
   command.AddParameter(partition_name);
-  command.AddParameter("--partition_size");
-  command.AddParameter(partition_size_bytes);
+  if (partition_size_bytes > 0) {
+    command.AddParameter("--partition_size");
+    command.AddParameter(partition_size_bytes);
+  } else {
+    command.AddParameter("--dynamic_partition_size");
+  }
   return command;
 }
 
diff --git a/host/libs/command_util/snapshot_utils.cc b/host/libs/command_util/snapshot_utils.cc
index ccb427a29..ac4528fca 100644
--- a/host/libs/command_util/snapshot_utils.cc
+++ b/host/libs/command_util/snapshot_utils.cc
@@ -29,6 +29,7 @@
 #include <android-base/strings.h>
 
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/json.h"
 #include "common/libs/utils/result.h"
diff --git a/host/libs/config/Android.bp b/host/libs/config/Android.bp
index 4cb036feb..e357dd5c8 100644
--- a/host/libs/config/Android.bp
+++ b/host/libs/config/Android.bp
@@ -44,7 +44,6 @@ cc_library {
         "libbase",
         "libcuttlefish_fs",
         "libcuttlefish_utils",
-        "libext2_blkid",
         "libfruit",
         "libgflags",
         "libjsoncpp",
diff --git a/host/libs/config/adb/flags.cpp b/host/libs/config/adb/flags.cpp
index d17d1880e..fbab8a4b1 100644
--- a/host/libs/config/adb/flags.cpp
+++ b/host/libs/config/adb/flags.cpp
@@ -17,6 +17,7 @@
 
 #include <android-base/strings.h>
 
+#include "common/libs/utils/container.h"
 #include "common/libs/utils/flag_parser.h"
 #include "host/libs/config/config_flag.h"
 #include "host/libs/config/feature.h"
diff --git a/host/libs/config/config_flag.cpp b/host/libs/config/config_flag.cpp
index acb809ddf..42c7fd548 100644
--- a/host/libs/config/config_flag.cpp
+++ b/host/libs/config/config_flag.cpp
@@ -189,32 +189,31 @@ class ConfigFlagImpl : public ConfigFlag {
     if(!ReadFileToString(info_path, &android_info)) {
       return {};
     }
-    // grab the last value of config in android-info.txt,
+    // grab the config with name "config" in android-info.txt,
     // it's the setting that's respected.
     // TODO (rammuthiah) Replace this logic with ParseMiscInfo
     // from host/commands/assemble_cvd/misc_info.h
     // Currently blocked on linking error for misc_info which is part of
     // assemble_cvd and this bit of code which is in run_cvd.
-    size_t config_idx = android_info.rfind("config=");
-    if (config_idx == std::string::npos) {
-      return {};
-    }
-    std::string config_value = android_info.substr(config_idx);
-    std::string_view local_config_value(config_value);
-    if (!android::base::ConsumePrefix(&local_config_value, "config=")) {
-      return {};
-    }
-    auto split_config = Split(std::string{local_config_value},"\n");
+    auto split_config = Split(android_info, "\n");
     if (split_config.empty()) {
       return {};
     }
-    config_value = split_config[0];
-    if (!config_reader_.HasConfig(config_value)) {
-      LOG(WARNING) << info_path << " contains invalid config preset: '"
-                   << config_value << "'.";
-      return {};
+
+    for (std::string_view local_config_value : split_config) {
+      if (!android::base::ConsumePrefix(&local_config_value, "config=")) {
+        continue;
+      }
+
+      if (!config_reader_.HasConfig(std::string{local_config_value})) {
+        LOG(WARNING) << info_path << " contains invalid config preset: '"
+                     << local_config_value << "'.";
+        return {};
+      }
+      return std::string{local_config_value};
     }
-    return config_value;
+
+    return {};
   }
 
   ConfigReader& config_reader_;
diff --git a/host/libs/config/config_utils.cpp b/host/libs/config/config_utils.cpp
index ba22ed381..b9803a362 100644
--- a/host/libs/config/config_utils.cpp
+++ b/host/libs/config/config_utils.cpp
@@ -24,6 +24,7 @@
 #include <android-base/logging.h>
 #include <android-base/strings.h>
 
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/contains.h"
 #include "common/libs/utils/environment.h"
 #include "common/libs/utils/in_sandbox.h"
diff --git a/host/libs/config/cuttlefish_config.cpp b/host/libs/config/cuttlefish_config.cpp
index 9492ee819..9a9358daa 100644
--- a/host/libs/config/cuttlefish_config.cpp
+++ b/host/libs/config/cuttlefish_config.cpp
@@ -56,6 +56,8 @@ const char* const kGpuModeGfxstream = "gfxstream";
 const char* const kGpuModeGfxstreamGuestAngle = "gfxstream_guest_angle";
 const char* const kGpuModeGfxstreamGuestAngleHostSwiftShader =
     "gfxstream_guest_angle_host_swiftshader";
+const char* const kGpuModeGfxstreamGuestAngleHostLavapipe =
+    "gfxstream_guest_angle_host_lavapipe";
 const char* const kGpuModeGuestSwiftshader = "guest_swiftshader";
 const char* const kGpuModeNone = "none";
 
@@ -212,6 +214,19 @@ bool CuttlefishConfig::sig_server_strict() const {
   return (*dictionary_)[kSigServerStrict].asBool();
 }
 
+bool CuttlefishConfig::OverlaysEnabled() const {
+  for (const auto& curinstance : Instances()) {
+    if (curinstance.display_configs().size() > 0) {
+      for (const auto& curdisplay : curinstance.display_configs()) {
+        if (curdisplay.overlays.length() > 0) {
+          return true;
+        }
+      }
+    }
+  }
+  return false;
+}
+
 static constexpr char kHostToolsVersion[] = "host_tools_version";
 void CuttlefishConfig::set_host_tools_version(
     const std::map<std::string, uint32_t>& versions) {
@@ -541,6 +556,22 @@ void CuttlefishConfig::set_snapshot_path(const std::string& snapshot_path) {
   (*dictionary_)[kSnapshotPath] = snapshot_path;
 }
 
+static constexpr char kKvmPath[] = "kvm_path";
+std::string CuttlefishConfig::kvm_path() const {
+  return (*dictionary_)[kKvmPath].asString();
+}
+void CuttlefishConfig::set_kvm_path(const std::string& kvm_path) {
+  (*dictionary_)[kKvmPath] = kvm_path;
+}
+
+static constexpr char kVhostVsockPath[] = "vhost_vsock_path";
+std::string CuttlefishConfig::vhost_vsock_path() const {
+  return (*dictionary_)[kVhostVsockPath].asString();
+}
+void CuttlefishConfig::set_vhost_vsock_path(const std::string& path) {
+  (*dictionary_)[kVhostVsockPath] = path;
+}
+
 static constexpr char kStracedExecutables[] = "straced_host_executables";
 void CuttlefishConfig::set_straced_host_executables(
     const std::set<std::string>& straced_host_executables) {
diff --git a/host/libs/config/cuttlefish_config.h b/host/libs/config/cuttlefish_config.h
index ed8cde7c9..e2d9e8b43 100644
--- a/host/libs/config/cuttlefish_config.h
+++ b/host/libs/config/cuttlefish_config.h
@@ -28,7 +28,8 @@
 
 #include <fmt/ostream.h>
 
-#include "common/libs/utils/environment.h"
+#include "common/libs/utils/architecture.h"
+#include "common/libs/utils/device_type.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/config/config_constants.h"
 #include "host/libs/config/config_fragment.h"
@@ -61,6 +62,25 @@ enum class ExternalNetworkMode {
 std::ostream& operator<<(std::ostream&, ExternalNetworkMode);
 Result<ExternalNetworkMode> ParseExternalNetworkMode(std::string_view);
 
+enum class GuestHwuiRenderer {
+  kUnknown,
+  kSkiaGl,
+  kSkiaVk,
+};
+std::ostream& operator<<(std::ostream&, GuestHwuiRenderer);
+std::string ToString(GuestHwuiRenderer renderer);
+Result<GuestHwuiRenderer> ParseGuestHwuiRenderer(std::string_view);
+
+enum class GuestRendererPreload {
+  kAuto,
+  kGuestDefault,
+  kEnabled,
+  kDisabled,
+};
+std::ostream& operator<<(std::ostream&, GuestRendererPreload);
+std::string ToString(GuestRendererPreload);
+Result<GuestRendererPreload> ParseGuestRendererPreload(std::string_view);
+
 // Holds the configuration of the cuttlefish instances.
 class CuttlefishConfig {
  public:
@@ -114,6 +134,7 @@ class CuttlefishConfig {
     int height;
     int dpi;
     int refresh_rate_hz;
+    std::string overlays;
   };
 
   struct TouchpadConfig {
@@ -234,6 +255,9 @@ class CuttlefishConfig {
   void set_sig_server_strict(bool strict);
   bool sig_server_strict() const;
 
+  // Whether display composition is enabled for one or more displays
+  bool OverlaysEnabled() const;
+
   void set_host_tools_version(const std::map<std::string, uint32_t>&);
   std::map<std::string, uint32_t> host_tools_version() const;
 
@@ -275,6 +299,12 @@ class CuttlefishConfig {
   std::set<std::string> straced_host_executables() const;
   void set_straced_host_executables(const std::set<std::string>& executables);
 
+  std::string kvm_path() const;
+  void set_kvm_path(const std::string&);
+
+  std::string vhost_vsock_path() const;
+  void set_vhost_vsock_path(const std::string&);
+
   bool IsCrosvm() const;
 
   class InstanceSpecific;
@@ -303,8 +333,12 @@ class CuttlefishConfig {
 
     Json::Value* Dictionary();
     const Json::Value* Dictionary() const;
-  public:
+   public:
     std::string serial_number() const;
+
+    // Index of this instance within current configured group of VMs
+    int index() const;
+
     // If any of the following port numbers is 0, the relevant service is not
     // running on the guest.
 
@@ -450,6 +484,25 @@ class CuttlefishConfig {
 
     BootFlow boot_flow() const;
 
+    enum class GuestOs { Android, ChromeOs, Linux, Fuchsia };
+
+    GuestOs guest_os() const {
+      switch (boot_flow()) {
+        case BootFlow::Android:
+        case BootFlow::AndroidEfiLoader:
+          return GuestOs::Android;
+        case BootFlow::ChromeOs:
+        case BootFlow::ChromeOsDisk:
+          return GuestOs::ChromeOs;
+        case BootFlow::Linux:
+          return GuestOs::Linux;
+        case BootFlow::Fuchsia:
+          return GuestOs::Fuchsia;
+          // Don't include a default case, this needs to fail when not all cases
+          // are covered.
+      }
+    }
+
     // modem simulator related
     std::string modem_simulator_ports() const;
 
@@ -505,6 +558,8 @@ class CuttlefishConfig {
 
     bool crosvm_use_balloon() const;
     bool crosvm_use_rng() const;
+    bool crosvm_simple_media_device() const;
+    std::string crosvm_v4l2_proxy() const;
     bool use_pmem() const;
 
     // Wifi MAC address inside the guest
@@ -540,6 +595,8 @@ class CuttlefishConfig {
     // forces.
     bool use_bootloader() const;
 
+    DeviceType device_type() const;
+
     Arch target_arch() const;
 
     int cpus() const;
@@ -566,6 +623,8 @@ class CuttlefishConfig {
     bool run_as_daemon() const;
     bool enable_audio() const;
     bool enable_mouse() const;
+    std::optional<std::string> custom_keyboard_config() const;
+    const Json::Value& domkey_mapping_config() const;
     bool enable_gnss_grpc_proxy() const;
     bool enable_bootanimation() const;
     bool enable_usb() const;
@@ -577,6 +636,7 @@ class CuttlefishConfig {
     std::string boot_slot() const;
     bool fail_fast() const;
     bool vhost_user_block() const;
+    std::string ti50_emulator() const;
 
     // Kernel and bootloader logging
     bool enable_kernel_log() const;
@@ -618,6 +678,8 @@ class CuttlefishConfig {
     std::string gpu_gfxstream_transport() const;
     std::string gpu_renderer_features() const;
     std::string gpu_context_types() const;
+    GuestHwuiRenderer guest_hwui_renderer() const;
+    GuestRendererPreload guest_renderer_preload() const;
     std::string guest_vulkan_driver() const;
     bool guest_uses_bgra_framebuffers() const;
     std::string frames_socket_path() const;
@@ -692,6 +754,10 @@ class CuttlefishConfig {
     ExternalNetworkMode external_network_mode() const;
 
     bool start_vhal_proxy_server() const;
+
+    int audio_output_streams_count() const;
+
+    bool enable_tap_devices() const;
   };
 
   // A view into an existing CuttlefishConfig object for a particular instance.
@@ -703,7 +769,7 @@ class CuttlefishConfig {
     MutableInstanceSpecific(CuttlefishConfig* config, const std::string& id);
 
     Json::Value* Dictionary();
-  public:
+   public:
     void set_serial_number(const std::string& serial_number);
     void set_qemu_vnc_server_port(int qemu_vnc_server_port);
     void set_tombstone_receiver_port(int tombstone_receiver_port);
@@ -754,6 +820,8 @@ class CuttlefishConfig {
     void set_ap_boot_flow(InstanceSpecific::APBootFlow flow);
     void set_crosvm_use_balloon(const bool use_balloon);
     void set_crosvm_use_rng(const bool use_rng);
+    void set_crosvm_simple_media_device(const bool simple_media_device);
+    void set_crosvm_v4l2_proxy(const std::string v4l2_proxy);
     void set_use_pmem(const bool use_pmem);
     // Wifi MAC address inside the guest
     void set_wifi_mac_prefix(const int wifi_mac_prefix);
@@ -770,6 +838,7 @@ class CuttlefishConfig {
     void set_enable_sandbox(const bool enable_sandbox);
     void set_enable_virtiofs(const bool enable_virtiofs);
     void set_kgdb(bool kgdb);
+    void set_device_type(DeviceType type);
     void set_target_arch(Arch target_arch);
     void set_cpus(int cpus);
     void set_vcpu_config_path(const std::string& vcpu_config_path);
@@ -789,6 +858,10 @@ class CuttlefishConfig {
     void set_run_as_daemon(bool run_as_daemon);
     void set_enable_audio(bool enable);
     void set_enable_mouse(bool enable);
+    void set_custom_keyboard_config(
+        const std::string& custom_keyboard_config_json_path);
+    void set_domkey_mapping_config(
+        const std::string& domkey_mapping_config_json_path);
     void set_enable_usb(bool enable);
     void set_enable_gnss_grpc_proxy(const bool enable_gnss_grpc_proxy);
     void set_enable_bootanimation(const bool enable_bootanimation);
@@ -801,6 +874,7 @@ class CuttlefishConfig {
     void set_grpc_socket_path(const std::string& sockets);
     void set_fail_fast(bool fail_fast);
     void set_vhost_user_block(bool qemu_vhost_user_block);
+    void set_ti50_emulator(const std::string& ti50_emulator);
 
     // Kernel and bootloader logging
     void set_enable_kernel_log(bool enable_kernel_log);
@@ -844,6 +918,8 @@ class CuttlefishConfig {
     void set_gpu_gfxstream_transport(const std::string& transport);
     void set_gpu_renderer_features(const std::string& features);
     void set_gpu_context_types(const std::string& context_types);
+    void set_guest_hwui_renderer(GuestHwuiRenderer renderer);
+    void set_guest_renderer_preload(GuestRendererPreload preload);
     void set_guest_vulkan_driver(const std::string& driver);
     void set_guest_uses_bgra_framebuffers(bool uses_bgra);
     void set_frames_socket_path(const std::string& driver);
@@ -910,6 +986,10 @@ class CuttlefishConfig {
     // connect to.
     void set_start_vhal_proxy_server(bool enable_vhal_proxy_server);
 
+    void set_audio_output_streams_count(int count);
+
+    void set_enable_tap_devices(bool);
+
    private:
     void SetPath(const std::string& key, const std::string& path);
   };
@@ -967,6 +1047,7 @@ class CuttlefishConfig {
     std::string wmediumd_api_server_socket() const;
     std::string wmediumd_config() const;
     int wmediumd_mac_prefix() const;
+    int group_uuid() const;
   };
 
   class MutableEnvironmentSpecific {
@@ -991,6 +1072,8 @@ class CuttlefishConfig {
     void set_wmediumd_api_server_socket(const std::string& path);
     void set_wmediumd_config(const std::string& path);
     void set_wmediumd_mac_prefix(int mac_prefix);
+
+    void set_group_uuid(const int group_uuid);
   };
 
  private:
@@ -1026,6 +1109,7 @@ extern const char* const kGpuModeDrmVirgl;
 extern const char* const kGpuModeGfxstream;
 extern const char* const kGpuModeGfxstreamGuestAngle;
 extern const char* const kGpuModeGfxstreamGuestAngleHostSwiftShader;
+extern const char* const kGpuModeGfxstreamGuestAngleHostLavapipe;
 extern const char* const kGpuModeGuestSwiftshader;
 extern const char* const kGpuModeNone;
 
diff --git a/host/libs/config/cuttlefish_config_environment.cpp b/host/libs/config/cuttlefish_config_environment.cpp
index 94614a07a..50319d2db 100644
--- a/host/libs/config/cuttlefish_config_environment.cpp
+++ b/host/libs/config/cuttlefish_config_environment.cpp
@@ -150,4 +150,13 @@ int CuttlefishConfig::EnvironmentSpecific::wmediumd_mac_prefix() const {
   return (*Dictionary())[kWmediumdMacPrefix].asInt();
 }
 
+static constexpr char kGroupUuid[] = "group_uuid";
+void CuttlefishConfig::MutableEnvironmentSpecific::set_group_uuid(
+    int group_uuid) {
+  (*Dictionary())[kGroupUuid] = group_uuid;
+}
+int CuttlefishConfig::EnvironmentSpecific::group_uuid() const {
+  return (*Dictionary())[kGroupUuid].asInt();
+}
+
 }  // namespace cuttlefish
diff --git a/host/libs/config/cuttlefish_config_instance.cpp b/host/libs/config/cuttlefish_config_instance.cpp
index 1c6e35df5..af5ea28d5 100644
--- a/host/libs/config/cuttlefish_config_instance.cpp
+++ b/host/libs/config/cuttlefish_config_instance.cpp
@@ -17,6 +17,7 @@
 #include "cuttlefish_config.h"
 #include "host/libs/config/cuttlefish_config.h"
 
+#include <string>
 #include <string_view>
 
 #include <android-base/logging.h>
@@ -93,6 +94,68 @@ Result<VmmMode> ParseVmm(std::string_view str) {
   }
 }
 
+std::ostream& operator<<(std::ostream& out, GuestHwuiRenderer renderer) {
+  return out << ToString(renderer);
+}
+
+std::string ToString(GuestHwuiRenderer renderer) {
+  switch (renderer) {
+    case GuestHwuiRenderer::kUnknown:
+      return "unknown";
+    case GuestHwuiRenderer::kSkiaGl:
+      return "skiagl";
+    case GuestHwuiRenderer::kSkiaVk:
+      return "skiavk";
+  }
+}
+
+Result<GuestHwuiRenderer> ParseGuestHwuiRenderer(std::string_view str) {
+  if (android::base::EqualsIgnoreCase(str, "unknown")) {
+    return GuestHwuiRenderer::kUnknown;
+  } else if (android::base::EqualsIgnoreCase(str, "skiagl")) {
+    return GuestHwuiRenderer::kSkiaGl;
+  } else if (android::base::EqualsIgnoreCase(str, "skiavk")) {
+    return GuestHwuiRenderer::kSkiaVk;
+  } else {
+    return CF_ERRF("\"{}\" is not a valid HWUI renderer.", str);
+  }
+}
+
+std::ostream& operator<<(std::ostream& out, GuestRendererPreload preload) {
+  return out << ToString(preload);
+}
+
+std::string ToString(GuestRendererPreload preload) {
+  switch (preload) {
+    case GuestRendererPreload::kAuto:
+      return "auto";
+    case GuestRendererPreload::kGuestDefault:
+      return "default";
+    case GuestRendererPreload::kEnabled:
+      return "enabled";
+    case GuestRendererPreload::kDisabled:
+      return "disabled";
+  }
+}
+
+Result<GuestRendererPreload> ParseGuestRendererPreload(std::string_view str) {
+  if (android::base::EqualsIgnoreCase(str, "auto")) {
+    return GuestRendererPreload::kAuto;
+  } else if (android::base::EqualsIgnoreCase(str, "default")) {
+    return GuestRendererPreload::kGuestDefault;
+  } else if (android::base::EqualsIgnoreCase(str, "enabled")) {
+    return GuestRendererPreload::kEnabled;
+  } else if (android::base::EqualsIgnoreCase(str, "disabled")) {
+    return GuestRendererPreload::kDisabled;
+  } else {
+    return CF_ERRF("\"{}\" is not a valid renderer preload.", str);
+  }
+}
+
+std::ostream& operator<<(std::ostream&, GuestRendererPreload);
+std::string ToString(GuestRendererPreload);
+Result<GuestRendererPreload> ParseGuestRendererPreload(std::string_view);
+
 static constexpr char kInstanceDir[] = "instance_dir";
 CuttlefishConfig::MutableInstanceSpecific::MutableInstanceSpecific(
     CuttlefishConfig* config, const std::string& id)
@@ -459,6 +522,17 @@ void CuttlefishConfig::MutableInstanceSpecific::set_serial_number(
   (*Dictionary())[kSerialNumber] = serial_number;
 }
 
+int CuttlefishConfig::InstanceSpecific::index() const {
+  int instance_index = 0;
+  for (const auto& i : config_->Instances()) {
+    if (i.serial_number() == serial_number()) {
+      break;
+    }
+    instance_index++;
+  }
+  return instance_index;
+}
+
 static constexpr char kVirtualDiskPaths[] = "virtual_disk_paths";
 std::vector<std::string> CuttlefishConfig::InstanceSpecific::virtual_disk_paths() const {
   std::vector<std::string> virtual_disks;
@@ -815,6 +889,28 @@ void CuttlefishConfig::MutableInstanceSpecific::set_gpu_context_types(
   (*Dictionary())[kGpuContextTypes] = context_types;
 }
 
+static constexpr char kGuestHwuiRenderer[] = "guest_hwui_renderer";
+GuestHwuiRenderer CuttlefishConfig::InstanceSpecific::guest_hwui_renderer()
+    const {
+  auto str = (*Dictionary())[kGuestHwuiRenderer].asString();
+  return ParseGuestHwuiRenderer(str).value_or(GuestHwuiRenderer::kUnknown);
+}
+void CuttlefishConfig::MutableInstanceSpecific::set_guest_hwui_renderer(
+    GuestHwuiRenderer renderer) {
+  (*Dictionary())[kGuestHwuiRenderer] = ToString(renderer);
+}
+
+static constexpr char kGuestRendererPreload[] = "guest_renderer_preload";
+GuestRendererPreload
+CuttlefishConfig::InstanceSpecific::guest_renderer_preload() const {
+  auto str = (*Dictionary())[kGuestRendererPreload].asString();
+  return ParseGuestRendererPreload(str).value_or(GuestRendererPreload::kAuto);
+}
+void CuttlefishConfig::MutableInstanceSpecific::set_guest_renderer_preload(
+    GuestRendererPreload preload) {
+  (*Dictionary())[kGuestRendererPreload] = ToString(preload);
+}
+
 static constexpr char kVulkanDriver[] = "guest_vulkan_driver";
 std::string CuttlefishConfig::InstanceSpecific::guest_vulkan_driver() const {
   return (*Dictionary())[kVulkanDriver].asString();
@@ -901,6 +997,39 @@ bool CuttlefishConfig::InstanceSpecific::enable_mouse() const {
   return (*Dictionary())[kEnableMouse].asBool();
 }
 
+static constexpr char kCustomKeyboardConfig[] = "custom_keyboard_config";
+void CuttlefishConfig::MutableInstanceSpecific::set_custom_keyboard_config(
+    const std::string& custom_keyboard_config_json_path) {
+  (*Dictionary())[kCustomKeyboardConfig] = custom_keyboard_config_json_path;
+}
+std::optional<std::string>
+CuttlefishConfig::InstanceSpecific::custom_keyboard_config() const {
+  auto value = (*Dictionary())[kCustomKeyboardConfig];
+  if (value.isNull()) {
+    return std::nullopt;
+  }
+  return value.asString();
+}
+
+static constexpr char kDomkeyMappingConfig[] = "domkey_mapping_config";
+void CuttlefishConfig::MutableInstanceSpecific::set_domkey_mapping_config(
+    const std::string& domkey_mapping_config_json_path) {
+  Json::Value domkey_config_json;
+  Json::CharReaderBuilder builder;
+  std::ifstream ifs(domkey_mapping_config_json_path);
+  std::string error_message;
+  if (!Json::parseFromStream(builder, ifs, &domkey_config_json,
+                             &error_message)) {
+    LOG(ERROR) << "Could not read domkey config file "
+               << domkey_mapping_config_json_path << ": " << error_message;
+  }
+  (*Dictionary())[kDomkeyMappingConfig] = domkey_config_json;
+}
+const Json::Value& CuttlefishConfig::InstanceSpecific::domkey_mapping_config()
+    const {
+  return (*Dictionary())[kDomkeyMappingConfig];
+}
+
 static constexpr char kEnableGnssGrpcProxy[] = "enable_gnss_grpc_proxy";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_gnss_grpc_proxy(const bool enable_gnss_grpc_proxy) {
   (*Dictionary())[kEnableGnssGrpcProxy] = enable_gnss_grpc_proxy;
@@ -1012,6 +1141,15 @@ bool CuttlefishConfig::InstanceSpecific::vhost_user_block() const {
   return (*Dictionary())[kVhostUserBlock].asBool();
 }
 
+static constexpr char kTi50[] = "ti50";
+void CuttlefishConfig::MutableInstanceSpecific::set_ti50_emulator(
+    const std::string& ti50) {
+  (*Dictionary())[kTi50] = ti50;
+}
+std::string CuttlefishConfig::InstanceSpecific::ti50_emulator() const {
+  return (*Dictionary())[kTi50].asString();
+}
+
 static constexpr char kEnableWebRTC[] = "enable_webrtc";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_webrtc(bool enable_webrtc) {
   (*Dictionary())[kEnableWebRTC] = enable_webrtc;
@@ -1188,6 +1326,7 @@ static constexpr char kXRes[] = "x_res";
 static constexpr char kYRes[] = "y_res";
 static constexpr char kDpi[] = "dpi";
 static constexpr char kRefreshRateHz[] = "refresh_rate_hz";
+static constexpr char kOverlays[] = "overlays";
 std::vector<CuttlefishConfig::DisplayConfig>
 CuttlefishConfig::InstanceSpecific::display_configs() const {
   std::vector<DisplayConfig> display_configs;
@@ -1198,6 +1337,7 @@ CuttlefishConfig::InstanceSpecific::display_configs() const {
     display_config.dpi = display_config_json[kDpi].asInt();
     display_config.refresh_rate_hz =
         display_config_json[kRefreshRateHz].asInt();
+    display_config.overlays = display_config_json[kOverlays].asString();
     display_configs.emplace_back(display_config);
   }
   return display_configs;
@@ -1212,6 +1352,7 @@ void CuttlefishConfig::MutableInstanceSpecific::set_display_configs(
     display_config_json[kYRes] = display_configs.height;
     display_config_json[kDpi] = display_configs.dpi;
     display_config_json[kRefreshRateHz] = display_configs.refresh_rate_hz;
+    display_config_json[kOverlays] = display_configs.overlays;
     display_configs_json.append(display_config_json);
   }
 
@@ -1267,6 +1408,15 @@ Arch CuttlefishConfig::InstanceSpecific::target_arch() const {
   return static_cast<Arch>((*Dictionary())[kTargetArch].asInt());
 }
 
+static constexpr char kDeviceType[] = "device_type";
+void CuttlefishConfig::MutableInstanceSpecific::set_device_type(
+    DeviceType type) {
+  (*Dictionary())[kDeviceType] = static_cast<int>(type);
+}
+DeviceType CuttlefishConfig::InstanceSpecific::device_type() const {
+  return static_cast<DeviceType>((*Dictionary())[kDeviceType].asInt());
+}
+
 static constexpr char kEnableSandbox[] = "enable_sandbox";
 void CuttlefishConfig::MutableInstanceSpecific::set_enable_sandbox(const bool enable_sandbox) {
   (*Dictionary())[kEnableSandbox] = enable_sandbox;
@@ -1848,6 +1998,24 @@ bool CuttlefishConfig::InstanceSpecific::crosvm_use_rng() const {
   return (*Dictionary())[kCrosvmUseRng].asBool();
 }
 
+static constexpr char kCrosvmSimpleMediaDevice[] = "crosvm_simple_media_device";
+void CuttlefishConfig::MutableInstanceSpecific::set_crosvm_simple_media_device(
+    const bool use_media) {
+  (*Dictionary())[kCrosvmSimpleMediaDevice] = use_media;
+}
+bool CuttlefishConfig::InstanceSpecific::crosvm_simple_media_device() const {
+  return (*Dictionary())[kCrosvmSimpleMediaDevice].asBool();
+}
+
+static constexpr char kCrosvmV4l2Proxy[] = "crosvm_v4l2_proxy";
+void CuttlefishConfig::MutableInstanceSpecific::set_crosvm_v4l2_proxy(
+    const std::string v4l2_proxy) {
+  (*Dictionary())[kCrosvmV4l2Proxy] = v4l2_proxy;
+}
+std::string CuttlefishConfig::InstanceSpecific::crosvm_v4l2_proxy() const {
+  return (*Dictionary())[kCrosvmV4l2Proxy].asString();
+}
+
 static constexpr char kCrosvmUsePmem[] = "use_pmem";
 void CuttlefishConfig::MutableInstanceSpecific::set_use_pmem(
     const bool use_pmem) {
@@ -1857,6 +2025,15 @@ bool CuttlefishConfig::InstanceSpecific::use_pmem() const {
   return (*Dictionary())[kCrosvmUsePmem].asBool();
 }
 
+static constexpr char kEnableTapDevices[] = "enable_tap_devices";
+void CuttlefishConfig::MutableInstanceSpecific::set_enable_tap_devices(
+    const bool enable_tap_devices) {
+  (*Dictionary())[kEnableTapDevices] = enable_tap_devices;
+}
+bool CuttlefishConfig::InstanceSpecific::enable_tap_devices() const {
+  return (*Dictionary())[kEnableTapDevices].asBool();
+}
+
 std::string CuttlefishConfig::InstanceSpecific::touch_socket_path(
     int touch_dev_idx) const {
   return PerInstanceInternalUdsPath(
@@ -1864,11 +2041,11 @@ std::string CuttlefishConfig::InstanceSpecific::touch_socket_path(
 }
 
 std::string CuttlefishConfig::InstanceSpecific::mouse_socket_path() const {
-  return PerInstanceInternalPath("mouse.sock");
+  return PerInstanceInternalUdsPath("mouse.sock");
 }
 
 std::string CuttlefishConfig::InstanceSpecific::rotary_socket_path() const {
-  return PerInstanceInternalPath("rotary.sock");
+  return PerInstanceInternalUdsPath("rotary.sock");
 }
 
 std::string CuttlefishConfig::InstanceSpecific::keyboard_socket_path() const {
@@ -1907,6 +2084,15 @@ bool CuttlefishConfig::InstanceSpecific::start_vhal_proxy_server() const {
   return (*Dictionary())[kStartVhalProxyServer].asBool();
 }
 
+static constexpr char kAudioOutputStreamsCount[] = "audio_output_streams_count";
+void CuttlefishConfig::MutableInstanceSpecific::set_audio_output_streams_count(
+    int count) {
+  (*Dictionary())[kAudioOutputStreamsCount] = count;
+}
+int CuttlefishConfig::InstanceSpecific::audio_output_streams_count() const {
+  return (*Dictionary())[kAudioOutputStreamsCount].asInt();
+}
+
 std::string CuttlefishConfig::InstanceSpecific::factory_reset_protected_path() const {
   return PerInstanceInternalPath("factory_reset_protected.img");
 }
diff --git a/host/libs/config/data_image.cpp b/host/libs/config/data_image.cpp
index f2a2b680f..6109834af 100644
--- a/host/libs/config/data_image.cpp
+++ b/host/libs/config/data_image.cpp
@@ -18,8 +18,6 @@
 #include <android-base/logging.h>
 #include <android-base/result.h>
 
-#include "blkid.h"
-
 #include "common/libs/fs/shared_buf.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
@@ -92,29 +90,37 @@ Result<void> ResizeImage(const std::string& data_image, int data_image_mb,
 }
 
 std::string GetFsType(const std::string& path) {
-  std::string fs_type;
-  blkid_cache cache;
-  if (blkid_get_cache(&cache, NULL) < 0) {
-    LOG(INFO) << "blkid_get_cache failed";
-    return fs_type;
+  Command command("/usr/sbin/blkid");
+  command.AddParameter(path);
+
+  std::string blkid_out;
+  std::string blkid_err;
+  int code =
+      RunWithManagedStdio(std::move(command), nullptr, &blkid_out, &blkid_err);
+  if (code != 0) {
+    LOG(ERROR) << "blkid failed with code " << code << ". stdout='" << blkid_out
+               << "', stderr='" << blkid_err << "'";
+    return "";
   }
-  blkid_dev dev = blkid_get_dev(cache, path.c_str(), BLKID_DEV_NORMAL);
-  if (!dev) {
-    LOG(INFO) << "blkid_get_dev failed";
-    blkid_put_cache(cache);
-    return fs_type;
+
+  static constexpr std::string_view kTypePrefix = "TYPE=\"";
+
+  std::size_t type_begin = blkid_out.find(kTypePrefix);
+  if (type_begin == std::string::npos) {
+    LOG(ERROR) << "blkid did not report a TYPE. stdout='" << blkid_out
+               << "', stderr='" << blkid_err << "'";
+    return "";
   }
+  type_begin += kTypePrefix.size();
 
-  const char *type, *value;
-  blkid_tag_iterate iter = blkid_tag_iterate_begin(dev);
-  while (blkid_tag_next(iter, &type, &value) == 0) {
-    if (!strcmp(type, "TYPE")) {
-      fs_type = value;
-    }
+  std::size_t type_end = blkid_out.find('"', type_begin);
+  if (type_end == std::string::npos) {
+    LOG(ERROR) << "unable to find the end of the blkid TYPE. stdout='"
+               << blkid_out << "', stderr='" << blkid_err << "'";
+    return "";
   }
-  blkid_tag_iterate_end(iter);
-  blkid_put_cache(cache);
-  return fs_type;
+
+  return blkid_out.substr(type_begin, type_end - type_begin);
 }
 
 enum class DataImageAction { kNoAction, kCreateImage, kResizeImage };
diff --git a/host/libs/config/display.cpp b/host/libs/config/display.cpp
index 4e3622af4..04f9508f3 100644
--- a/host/libs/config/display.cpp
+++ b/host/libs/config/display.cpp
@@ -84,11 +84,18 @@ Result<std::optional<CuttlefishConfig::DisplayConfig>> ParseDisplayConfig(
                                                                       << "\"");
   }
 
+  std::string display_overlays = "";
+  auto overlays_it = props.find("overlays");
+  if (overlays_it != props.end()) {
+    display_overlays = overlays_it->second;
+  }
+
   return CuttlefishConfig::DisplayConfig{
       .width = display_width,
       .height = display_height,
       .dpi = display_dpi,
       .refresh_rate_hz = display_refresh_rate_hz,
+      .overlays = display_overlays,
   };
 }
 
diff --git a/host/libs/config/esp.cpp b/host/libs/config/esp.cpp
index bc1f5107c..c18a53002 100644
--- a/host/libs/config/esp.cpp
+++ b/host/libs/config/esp.cpp
@@ -20,11 +20,12 @@
 #include <utility>
 #include <vector>
 
-#include "host/libs/config/esp.h"
 #include "common/libs/fs/shared_buf.h"
-#include "common/libs/utils/subprocess.h"
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/files.h"
+#include "common/libs/utils/subprocess.h"
 #include "host/libs/config/cuttlefish_config.h"
+#include "host/libs/config/esp.h"
 
 namespace cuttlefish {
 
diff --git a/host/libs/config/esp.h b/host/libs/config/esp.h
index d376454a0..d7639f466 100644
--- a/host/libs/config/esp.h
+++ b/host/libs/config/esp.h
@@ -20,7 +20,7 @@
 #include <utility>
 #include <vector>
 
-#include "common/libs/utils/environment.h"
+#include "common/libs/utils/architecture.h"
 
 namespace cuttlefish {
 
diff --git a/host/libs/config/known_paths.cpp b/host/libs/config/known_paths.cpp
index 37e7b4ef5..ed6ff0053 100644
--- a/host/libs/config/known_paths.cpp
+++ b/host/libs/config/known_paths.cpp
@@ -20,12 +20,16 @@
 
 namespace cuttlefish {
 
-std::string AdbConnectorBinary() {
-  return HostBinaryPath("adb_connector");
+std::string AdbConnectorBinary() { return HostBinaryPath("adb_connector"); }
+
+std::string AutomotiveProxyBinary() {
+  return HostBinaryPath("automotive_vsock_proxy");
 }
 
 std::string AvbToolBinary() { return HostBinaryPath("avbtool"); }
 
+std::string CasimirBinary() { return HostBinaryPath("casimir"); }
+
 std::string CasimirControlServerBinary() {
   return HostBinaryPath("casimir_control_server");
 }
@@ -38,28 +42,57 @@ std::string ControlEnvProxyServerBinary() {
   return HostBinaryPath("control_env_proxy_server");
 }
 
-std::string EchoServerBinary() { return HostBinaryPath("echo_server"); }
+std::string DefaultKeyboardSpec() {
+  return DefaultHostArtifactsPath("etc/default_input_devices/keyboard.json");
+}
 
-std::string GnssGrpcProxyBinary() {
-  return HostBinaryPath("gnss_grpc_proxy");
+std::string DefaultMouseSpec() {
+  return DefaultHostArtifactsPath("etc/default_input_devices/mouse.json");
 }
 
-std::string KernelLogMonitorBinary() {
-  return HostBinaryPath("kernel_log_monitor");
+std::string DefaultMultiTouchpadSpecTemplate() {
+  return DefaultHostArtifactsPath(
+      "etc/default_input_devices/multi_touchpad_template.json");
 }
 
-std::string LogcatReceiverBinary() {
-  return HostBinaryPath("logcat_receiver");
+std::string DefaultMultiTouchscreenSpecTemplate() {
+  return DefaultHostArtifactsPath(
+      "etc/default_input_devices/multi_touchscreen_template.json");
 }
 
-std::string MetricsBinary() {
-  return HostBinaryPath("metrics");
+std::string DefaultRotaryDeviceSpec() {
+  return DefaultHostArtifactsPath(
+      "etc/default_input_devices/rotary_wheel.json");
 }
 
-std::string ModemSimulatorBinary() {
-  return HostBinaryPath("modem_simulator");
+std::string DefaultSingleTouchpadSpecTemplate() {
+  return DefaultHostArtifactsPath(
+      "etc/default_input_devices/single_touchpad_template.json");
 }
 
+std::string DefaultSingleTouchscreenSpecTemplate() {
+  return DefaultHostArtifactsPath(
+      "etc/default_input_devices/single_touchscreen_template.json");
+}
+
+std::string DefaultSwitchesSpec() {
+  return DefaultHostArtifactsPath("etc/default_input_devices/switches.json");
+}
+
+std::string EchoServerBinary() { return HostBinaryPath("echo_server"); }
+
+std::string GnssGrpcProxyBinary() { return HostBinaryPath("gnss_grpc_proxy"); }
+
+std::string KernelLogMonitorBinary() {
+  return HostBinaryPath("kernel_log_monitor");
+}
+
+std::string LogcatReceiverBinary() { return HostBinaryPath("logcat_receiver"); }
+
+std::string MetricsBinary() { return HostBinaryPath("metrics"); }
+
+std::string ModemSimulatorBinary() { return HostBinaryPath("modem_simulator"); }
+
 std::string NetsimdBinary() { return HostBinaryPath("netsimd"); }
 
 std::string OpenwrtControlServerBinary() {
@@ -74,6 +107,24 @@ std::string ProcessRestarterBinary() {
 
 std::string RootCanalBinary() { return HostBinaryPath("root-canal"); }
 
+std::string ScreenRecordingServerBinary() {
+  return HostBinaryPath("screen_recording_server");
+}
+
+std::string SecureEnvBinary() { return HostBinaryPath("secure_env"); }
+
+std::string SensorsSimulatorBinary() {
+  return HostBinaryPath("sensors_simulator");
+}
+
+std::string SocketVsockProxyBinary() {
+  return HostBinaryPath("socket_vsock_proxy");
+}
+
+std::string StopCvdBinary() { return HostBinaryPath("stop_cvd"); }
+
+std::string TcpConnectorBinary() { return HostBinaryPath("tcp_connector"); }
+
 std::string TestKeyRsa2048() {
   return DefaultHostArtifactsPath("etc/cvd_avb_testkey_rsa2048.pem");
 }
@@ -90,29 +141,19 @@ std::string TestPubKeyRsa4096() {
   return DefaultHostArtifactsPath("etc/cvd_rsa4096.avbpubkey");
 }
 
-std::string CasimirBinary() { return HostBinaryPath("casimir"); }
-
-std::string ScreenRecordingServerBinary() {
-  return HostBinaryPath("screen_recording_server");
+std::string TombstoneReceiverBinary() {
+  return HostBinaryPath("tombstone_receiver");
 }
 
-std::string SecureEnvBinary() { return HostBinaryPath("secure_env"); }
-
-std::string SocketVsockProxyBinary() {
-  return HostBinaryPath("socket_vsock_proxy");
+std::string VhalProxyServerBinary() {
+  return HostBinaryPath("vhal_proxy_server");
 }
 
-std::string StopCvdBinary() { return HostBinaryPath("stop_cvd"); }
-
-std::string TcpConnectorBinary() { return HostBinaryPath("tcp_connector"); }
-
-std::string TombstoneReceiverBinary() {
-  return HostBinaryPath("tombstone_receiver");
+std::string VhalProxyServerConfig() {
+  return DefaultHostArtifactsPath("etc/automotive/vhalconfig");
 }
 
-std::string WebRtcBinary() {
-  return HostBinaryPath("webRTC");
-}
+std::string WebRtcBinary() { return HostBinaryPath("webRTC"); }
 
 std::string WebRtcSigServerBinary() {
   return HostBinaryPath("webrtc_operator");
@@ -128,16 +169,8 @@ std::string WmediumdGenConfigBinary() {
   return HostBinaryPath("wmediumd_gen_config");
 }
 
-std::string AutomotiveProxyBinary() {
-  return HostBinaryPath("automotive_vsock_proxy");
-}
-
-std::string VhalProxyServerBinary() {
-  return HostBinaryPath("vhal_proxy_server");
-}
-
-std::string VhalProxyServerConfig() {
-  return DefaultHostArtifactsPath("etc/automotive/vhalconfig");
+std::string VhostUserInputBinary() {
+  return HostBinaryPath("cf_vhost_user_input");
 }
 
-} // namespace cuttlefish
+}  // namespace cuttlefish
diff --git a/host/libs/config/known_paths.h b/host/libs/config/known_paths.h
index 7895b20e9..2d6ee2006 100644
--- a/host/libs/config/known_paths.h
+++ b/host/libs/config/known_paths.h
@@ -20,10 +20,20 @@
 namespace cuttlefish {
 
 std::string AdbConnectorBinary();
+std::string AutomotiveProxyBinary();
 std::string AvbToolBinary();
+std::string CasimirBinary();
 std::string CasimirControlServerBinary();
 std::string ConsoleForwarderBinary();
 std::string ControlEnvProxyServerBinary();
+std::string DefaultKeyboardSpec();
+std::string DefaultMouseSpec();
+std::string DefaultMultiTouchpadSpecTemplate();
+std::string DefaultMultiTouchscreenSpecTemplate();
+std::string DefaultRotaryDeviceSpec();
+std::string DefaultSingleTouchpadSpecTemplate();
+std::string DefaultSingleTouchscreenSpecTemplate();
+std::string DefaultSwitchesSpec();
 std::string EchoServerBinary();
 std::string GnssGrpcProxyBinary();
 std::string KernelLogMonitorBinary();
@@ -35,24 +45,24 @@ std::string OpenwrtControlServerBinary();
 std::string PicaBinary();
 std::string ProcessRestarterBinary();
 std::string RootCanalBinary();
-std::string TestKeyRsa2048();
-std::string TestKeyRsa4096();
-std::string TestPubKeyRsa2048();
-std::string TestPubKeyRsa4096();
-std::string CasimirBinary();
 std::string ScreenRecordingServerBinary();
 std::string SecureEnvBinary();
+std::string SensorsSimulatorBinary();
 std::string SocketVsockProxyBinary();
 std::string StopCvdBinary();
 std::string TcpConnectorBinary();
+std::string TestKeyRsa2048();
+std::string TestKeyRsa4096();
+std::string TestPubKeyRsa2048();
+std::string TestPubKeyRsa4096();
 std::string TombstoneReceiverBinary();
+std::string VhalProxyServerBinary();
+std::string VhalProxyServerConfig();
+std::string VhostUserInputBinary();
 std::string WebRtcBinary();
 std::string WebRtcSigServerBinary();
 std::string WebRtcSigServerProxyBinary();
 std::string WmediumdBinary();
 std::string WmediumdGenConfigBinary();
-std::string AutomotiveProxyBinary();
-std::string VhalProxyServerBinary();
-std::string VhalProxyServerConfig();
 
-} // namespace cuttlefish
+}  // namespace cuttlefish
diff --git a/host/libs/confui/Android.bp b/host/libs/confui/Android.bp
index 30265d901..32cd6aac8 100644
--- a/host/libs/confui/Android.bp
+++ b/host/libs/confui/Android.bp
@@ -44,7 +44,6 @@ cc_library {
         "sign.cc",
     ],
     shared_libs: [
-        "android.hardware.keymaster@4.0",
         "libbase",
         "libcn-cbor",
         "libcrypto",
diff --git a/host/libs/confui/cbor.h b/host/libs/confui/cbor.h
index b77e0c7eb..931173532 100644
--- a/host/libs/confui/cbor.h
+++ b/host/libs/confui/cbor.h
@@ -21,8 +21,6 @@
 #include <string>
 #include <vector>
 
-#include <android/hardware/keymaster/4.0/types.h>
-
 #include <cn-cbor/cn-cbor.h>
 
 namespace cuttlefish {
diff --git a/host/libs/image_aggregator/Android.bp b/host/libs/image_aggregator/Android.bp
index 1a65f0947..f47ad0531 100644
--- a/host/libs/image_aggregator/Android.bp
+++ b/host/libs/image_aggregator/Android.bp
@@ -55,7 +55,6 @@ cc_library {
     static_libs: [
         "libcdisk_spec",
         "libcuttlefish_host_config",
-        "libext2_uuid",
         "libsparse",
     ],
     defaults: ["cuttlefish_host"],
diff --git a/host/libs/image_aggregator/image_aggregator.cc b/host/libs/image_aggregator/image_aggregator.cc
index 03b51fc95..f71207f65 100644
--- a/host/libs/image_aggregator/image_aggregator.cc
+++ b/host/libs/image_aggregator/image_aggregator.cc
@@ -26,6 +26,7 @@
 #include <stdio.h>
 
 #include <fstream>
+#include <random>
 #include <string>
 #include <vector>
 
@@ -35,7 +36,6 @@
 #include <cdisk_spec.pb.h>
 #include <google/protobuf/text_format.h>
 #include <sparse/sparse.h>
-#include <uuid.h>
 #include <zlib.h>
 
 #include "common/libs/fs/shared_buf.h"
@@ -242,6 +242,20 @@ MultipleImagePartition ToMultipleImagePartition(ImagePartition source) {
   };
 }
 
+void SetRandomUuid(std::uint8_t uuid[16]) {
+  // https://en.wikipedia.org/wiki/Universally_unique_identifier#Version_4_(random)
+  std::random_device dev;
+  std::mt19937 rng(dev());
+  std::uniform_int_distribution<std::mt19937::result_type> dist(0, 0xff);
+
+  for (int i = 0; i < 16; i++) {
+    uuid[i] = dist(rng);
+  }
+  // https://www.rfc-editor.org/rfc/rfc4122#section-4.4
+  uuid[7] = (uuid[7] & 0x0F) | 0x40;  // UUID v4
+  uuid[9] = (uuid[9] & 0x3F) | 0x80;
+}
+
 /**
  * Incremental builder class for producing partition tables. Add partitions
  * one-by-one, then produce specification files
@@ -251,16 +265,21 @@ private:
   std::vector<PartitionInfo> partitions_;
   std::uint64_t next_disk_offset_;
 
-  static const char* GetPartitionGUID(MultipleImagePartition source) {
+  static const std::uint8_t* GetPartitionGUID(MultipleImagePartition source) {
     // Due to some endianness mismatch in e2fsprogs GUID vs GPT, the GUIDs are
     // rearranged to make the right GUIDs appear in gdisk
     switch (source.type) {
-      case kLinuxFilesystem:
-        // Technically 0FC63DAF-8483-4772-8E79-3D69D8477DE4
-        return "AF3DC60F-8384-7247-8E79-3D69D8477DE4";
+      case kLinuxFilesystem: {
+        static constexpr std::uint8_t kLinuxFileSystemGuid[] = {
+            0xaf, 0x3d, 0xc6, 0xf,  0x83, 0x84, 0x72, 0x47,
+            0x8e, 0x79, 0x3d, 0x69, 0xd8, 0x47, 0x7d, 0xe4};
+        return kLinuxFileSystemGuid;
+      }
       case kEfiSystemPartition:
-        // Technically C12A7328-F81F-11D2-BA4B-00A0C93EC93B
-        return "28732AC1-1FF8-D211-BA4B-00A0C93EC93B";
+        static constexpr std::uint8_t kEfiSystemPartitionGuid[] = {
+            0x28, 0x73, 0x2a, 0xc1, 0x1f, 0xf8, 0xd2, 0x11,
+            0xba, 0x4b, 0x0,  0xa0, 0xc9, 0x3e, 0xc9, 0x3b};
+        return kEfiSystemPartitionGuid;
       default:
         LOG(FATAL) << "Unknown partition type: " << (int) source.type;
     }
@@ -370,7 +389,7 @@ public:
                 .partition_entry_size = sizeof(GptPartitionEntry),
             },
     };
-    uuid_generate(gpt.header.disk_guid);
+    SetRandomUuid(gpt.header.disk_guid);
     for (std::size_t i = 0; i < partitions_.size(); i++) {
       const auto& partition = partitions_[i];
       gpt.entries[i] = GptPartitionEntry{
@@ -378,11 +397,12 @@ public:
           .last_lba =
               (partition.offset + partition.AlignedSize()) / kSectorSize - 1,
       };
-      uuid_generate(gpt.entries[i].unique_partition_guid);
-      if (uuid_parse(GetPartitionGUID(partition.source),
-                     gpt.entries[i].partition_type_guid)) {
-        LOG(FATAL) << "Could not parse partition guid";
+      SetRandomUuid(gpt.entries[i].unique_partition_guid);
+      const std::uint8_t* const type_guid = GetPartitionGUID(partition.source);
+      if (type_guid == nullptr) {
+        LOG(FATAL) << "Could not recognize partition guid";
       }
+      memcpy(gpt.entries[i].partition_type_guid, type_guid, 16);
       std::u16string wide_name(partitions_[i].source.label.begin(),
                               partitions_[i].source.label.end());
       u16cpy((std::uint16_t*) gpt.entries[i].partition_name,
diff --git a/host/libs/input_connector/Android.bp b/host/libs/input_connector/Android.bp
index 62f341ac6..9d0223eb1 100644
--- a/host/libs/input_connector/Android.bp
+++ b/host/libs/input_connector/Android.bp
@@ -21,9 +21,9 @@ cc_library {
     name: "libcuttlefish_input_connector",
     srcs: [
         "event_buffer.cpp",
+        "input_connection.cpp",
         "input_connector.cpp",
         "input_devices.cpp",
-        "server_input_connection.cpp",
     ],
     shared_libs: [
         "libbase",
diff --git a/host/libs/input_connector/event_buffer.cpp b/host/libs/input_connector/event_buffer.cpp
index ccc845f1d..182cc5e33 100644
--- a/host/libs/input_connector/event_buffer.cpp
+++ b/host/libs/input_connector/event_buffer.cpp
@@ -24,39 +24,12 @@
 #include <linux/input.h>
 
 namespace cuttlefish {
-namespace {
 
-struct virtio_input_event {
-  uint16_t type;
-  uint16_t code;
-  int32_t value;
-};
+EventBuffer::EventBuffer(size_t num_events) { buffer_.reserve(num_events); }
 
-template <typename T>
-struct EventBufferImpl : public EventBuffer {
-  EventBufferImpl(size_t num_events) { buffer_.reserve(num_events); }
-  void AddEvent(uint16_t type, uint16_t code, int32_t value) override {
-    buffer_.push_back({.type = type, .code = code, .value = value});
-  }
-  const void* data() const override { return buffer_.data(); }
-  std::size_t size() const override { return buffer_.size() * sizeof(T); }
-
- private:
-  std::vector<T> buffer_;
-};
-
-}  // namespace
-
-std::unique_ptr<EventBuffer> CreateBuffer(InputEventType event_type,
-                                          size_t num_events) {
-  switch (event_type) {
-    case InputEventType::Virtio:
-      return std::unique_ptr<EventBuffer>(
-          new EventBufferImpl<virtio_input_event>(num_events));
-    case InputEventType::Evdev:
-      return std::unique_ptr<EventBuffer>(
-          new EventBufferImpl<input_event>(num_events));
-  }
+void EventBuffer::AddEvent(uint16_t type, uint16_t code, int32_t value) {
+  buffer_.push_back(
+      {.type = Le16(type), .code = Le16(code), .value = Le32(value)});
 }
 
 }  // namespace cuttlefish
diff --git a/host/libs/input_connector/event_buffer.h b/host/libs/input_connector/event_buffer.h
index e027dd6cf..eb7bffcff 100644
--- a/host/libs/input_connector/event_buffer.h
+++ b/host/libs/input_connector/event_buffer.h
@@ -19,23 +19,30 @@
 #include <cstdint>
 #include <cstdlib>
 
-#include <memory>
+#include <vector>
+
+#include "common/libs/utils/cf_endian.h"
 
 namespace cuttlefish {
-enum class InputEventType {
-  Virtio,
-  Evdev,
-};
 
 class EventBuffer {
  public:
-  virtual ~EventBuffer() = default;
-  virtual void AddEvent(uint16_t type, uint16_t code, int32_t value) = 0;
-  virtual size_t size() const = 0;
-  virtual const void* data() const = 0;
-};
+  EventBuffer(size_t num_events);
+
+  void AddEvent(uint16_t type, uint16_t code, int32_t value);
 
-std::unique_ptr<EventBuffer> CreateBuffer(InputEventType event_type,
-                                          size_t num_events);
+  size_t size() const { return buffer_.size() * sizeof(virtio_input_event); }
+
+  const void* data() const { return buffer_.data(); }
+
+ private:
+  struct virtio_input_event {
+    Le16 type;
+    Le16 code;
+    Le32 value;
+  };
+
+  std::vector<virtio_input_event> buffer_;
+};
 
 }  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connection.cpp b/host/libs/input_connector/input_connection.cpp
new file mode 100644
index 000000000..6e006d6c5
--- /dev/null
+++ b/host/libs/input_connector/input_connection.cpp
@@ -0,0 +1,35 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "host/libs/input_connector/input_connection.h"
+
+#include "common/libs/fs/shared_buf.h"
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+InputConnection::InputConnection(SharedFD conn) : conn_(conn) {}
+
+Result<void> InputConnection::WriteEvents(const void* data, size_t len) {
+  auto res = WriteAll(conn_, reinterpret_cast<const char*>(data), len);
+  CF_EXPECTF(res == len,
+             "Failed to write entire event buffer: wrote {} of {} bytes", res,
+             len);
+  return {};
+}
+
+}  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connection.h b/host/libs/input_connector/input_connection.h
index 2b573d1ee..7beee25c0 100644
--- a/host/libs/input_connector/input_connection.h
+++ b/host/libs/input_connector/input_connection.h
@@ -16,21 +16,22 @@
 
 #pragma once
 
-#include <memory>
-
 #include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
 
 namespace cuttlefish {
 
+// A connection to a vhost user input device, allowing to inject events to the
+// device.
 class InputConnection {
  public:
-  virtual ~InputConnection() = default;
+  InputConnection(SharedFD conn);
+  ~InputConnection() = default;
 
-  virtual Result<void> WriteEvents(const void* data, size_t len) = 0;
-};
+  Result<void> WriteEvents(const void* data, size_t len);
 
-// Create an input device that accepts connection on a socket (TCP or UNIX) and
-// writes input events to its client (typically crosvm).
-std::unique_ptr<InputConnection> NewServerInputConnection(SharedFD server_fd);
+ private:
+  SharedFD conn_;
+};
 
 }  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_connector.cpp b/host/libs/input_connector/input_connector.cpp
index fc8d82f9c..d61969f36 100644
--- a/host/libs/input_connector/input_connector.cpp
+++ b/host/libs/input_connector/input_connector.cpp
@@ -164,53 +164,49 @@ std::unique_ptr<InputConnector::EventSink> InputConnectorImpl::CreateSink() {
       new EventSinkImpl(devices_, sinks_count_));
 }
 
-InputConnectorBuilder::InputConnectorBuilder(InputEventType type)
-    : connector_(new InputConnectorImpl()), event_type_(type) {}
+InputConnectorBuilder::InputConnectorBuilder()
+    : connector_(new InputConnectorImpl()) {}
 
 InputConnectorBuilder::~InputConnectorBuilder() = default;
 
 void InputConnectorBuilder::WithMultitouchDevice(
-    const std::string& device_label, SharedFD server) {
+    const std::string& device_label, SharedFD conn) {
   CHECK(connector_->devices_.multitouch_devices.find(device_label) ==
         connector_->devices_.multitouch_devices.end())
       << "Multiple touch devices with same label: " << device_label;
   connector_->devices_.multitouch_devices.emplace(
       std::piecewise_construct, std::forward_as_tuple(device_label),
-      std::forward_as_tuple(NewServerInputConnection(server), event_type_));
+      std::forward_as_tuple(InputConnection(conn)));
 }
 
 void InputConnectorBuilder::WithTouchDevice(const std::string& device_label,
-                                            SharedFD server) {
+                                            SharedFD conn) {
   CHECK(connector_->devices_.touch_devices.find(device_label) ==
         connector_->devices_.touch_devices.end())
       << "Multiple touch devices with same label: " << device_label;
   connector_->devices_.touch_devices.emplace(
       std::piecewise_construct, std::forward_as_tuple(device_label),
-      std::forward_as_tuple(NewServerInputConnection(server), event_type_));
+      std::forward_as_tuple(InputConnection(conn)));
 }
 
-void InputConnectorBuilder::WithKeyboard(SharedFD server) {
+void InputConnectorBuilder::WithKeyboard(SharedFD conn) {
   CHECK(!connector_->devices_.keyboard) << "Keyboard already specified";
-  connector_->devices_.keyboard.emplace(NewServerInputConnection(server),
-                                        event_type_);
+  connector_->devices_.keyboard.emplace(InputConnection(conn));
 }
 
-void InputConnectorBuilder::WithSwitches(SharedFD server) {
+void InputConnectorBuilder::WithSwitches(SharedFD conn) {
   CHECK(!connector_->devices_.switches) << "Switches already specified";
-  connector_->devices_.switches.emplace(NewServerInputConnection(server),
-                                        event_type_);
+  connector_->devices_.switches.emplace(InputConnection(conn));
 }
 
-void InputConnectorBuilder::WithRotary(SharedFD server) {
+void InputConnectorBuilder::WithRotary(SharedFD conn) {
   CHECK(!connector_->devices_.rotary) << "Rotary already specified";
-  connector_->devices_.rotary.emplace(NewServerInputConnection(server),
-                                      event_type_);
+  connector_->devices_.rotary.emplace(InputConnection(conn));
 }
 
-void InputConnectorBuilder::WithMouse(SharedFD server) {
+void InputConnectorBuilder::WithMouse(SharedFD conn) {
   CHECK(!connector_->devices_.mouse) << "Mouse already specified";
-  connector_->devices_.mouse.emplace(NewServerInputConnection(server),
-                                     event_type_);
+  connector_->devices_.mouse.emplace(InputConnection(conn));
 }
 
 std::unique_ptr<InputConnector> InputConnectorBuilder::Build() && {
diff --git a/host/libs/input_connector/input_connector.h b/host/libs/input_connector/input_connector.h
index 02a37e04d..015f424a2 100644
--- a/host/libs/input_connector/input_connector.h
+++ b/host/libs/input_connector/input_connector.h
@@ -63,7 +63,7 @@ class InputConnectorImpl;
 
 class InputConnectorBuilder {
  public:
-  explicit InputConnectorBuilder(InputEventType type);
+  explicit InputConnectorBuilder();
   ~InputConnectorBuilder();
   InputConnectorBuilder(const InputConnectorBuilder&) = delete;
   InputConnectorBuilder(InputConnectorBuilder&&) = delete;
@@ -73,7 +73,7 @@ class InputConnectorBuilder {
   void WithTouchDevice(const std::string& device_label, SharedFD server);
   void WithKeyboard(SharedFD server);
   void WithSwitches(SharedFD server);
-  void WithRotary(SharedFD server);
+  void WithRotary(SharedFD conn);
   void WithMouse(SharedFD server);
   // This object becomes invalid after calling Build(), the rvalue reference
   // makes it explicit that it shouldn't be used after.
@@ -81,7 +81,6 @@ class InputConnectorBuilder {
 
  private:
   std::unique_ptr<InputConnectorImpl> connector_;
-  InputEventType event_type_;
 };
 
 }  // namespace cuttlefish
diff --git a/host/libs/input_connector/input_devices.cpp b/host/libs/input_connector/input_devices.cpp
index 4389b7d8a..0d82a3844 100644
--- a/host/libs/input_connector/input_devices.cpp
+++ b/host/libs/input_connector/input_devices.cpp
@@ -22,21 +22,24 @@
 
 namespace cuttlefish {
 
+Result<void> InputDevice::WriteEvents(const EventBuffer& buffer) {
+  CF_EXPECT(conn_.WriteEvents(buffer.data(), buffer.size()));
+  return {};
+}
+
 Result<void> TouchDevice::SendTouchEvent(int x, int y, bool down) {
-  auto buffer = CreateBuffer(event_type(), 4);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_ABS, ABS_X, x);
-  buffer->AddEvent(EV_ABS, ABS_Y, y);
-  buffer->AddEvent(EV_KEY, BTN_TOUCH, down);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(WriteEvents(*buffer));
+  EventBuffer buffer(4);
+  buffer.AddEvent(EV_ABS, ABS_X, x);
+  buffer.AddEvent(EV_ABS, ABS_Y, y);
+  buffer.AddEvent(EV_KEY, BTN_TOUCH, down);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> TouchDevice::SendMultiTouchEvent(
     const std::vector<MultitouchSlot>& slots, bool down) {
-  auto buffer = CreateBuffer(event_type(), 1 + 7 * slots.size());
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
+  EventBuffer buffer(1 + 7 * slots.size());
 
   for (auto& f : slots) {
     auto this_id = f.id;
@@ -50,28 +53,28 @@ Result<void> TouchDevice::SendMultiTouchEvent(
 
     // BTN_TOUCH DOWN must be the first event in a series
     if (down && is_new_contact) {
-      buffer->AddEvent(EV_KEY, BTN_TOUCH, 1);
+      buffer.AddEvent(EV_KEY, BTN_TOUCH, 1);
     }
 
-    buffer->AddEvent(EV_ABS, ABS_MT_SLOT, this_slot);
+    buffer.AddEvent(EV_ABS, ABS_MT_SLOT, this_slot);
     if (down) {
       if (is_new_contact) {
         // We already assigned this slot to this source and id combination, we
         // could use any tracking id for the slot as long as it's greater than 0
-        buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, NewTrackingId());
+        buffer.AddEvent(EV_ABS, ABS_MT_TRACKING_ID, NewTrackingId());
       }
-      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_X, this_x);
-      buffer->AddEvent(EV_ABS, ABS_MT_POSITION_Y, this_y);
+      buffer.AddEvent(EV_ABS, ABS_MT_POSITION_X, this_x);
+      buffer.AddEvent(EV_ABS, ABS_MT_POSITION_Y, this_y);
     } else {
       // released touch
-      buffer->AddEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
+      buffer.AddEvent(EV_ABS, ABS_MT_TRACKING_ID, -1);
       ReleaseSlot(this, this_id);
-      buffer->AddEvent(EV_KEY, BTN_TOUCH, 0);
+      buffer.AddEvent(EV_KEY, BTN_TOUCH, 0);
     }
   }
 
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(WriteEvents(*buffer));
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
@@ -129,62 +132,54 @@ int32_t TouchDevice::UseNewSlot() {
 }
 
 Result<void> MouseDevice::SendMoveEvent(int x, int y) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr,
-            "Failed to allocate input events buffer for mouse move event !");
-  buffer->AddEvent(EV_REL, REL_X, x);
-  buffer->AddEvent(EV_REL, REL_Y, y);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  EventBuffer buffer(2);
+  buffer.AddEvent(EV_REL, REL_X, x);
+  buffer.AddEvent(EV_REL, REL_Y, y);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> MouseDevice::SendButtonEvent(int button, bool down) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr,
-            "Failed to allocate input events buffer for mouse button event !");
+  EventBuffer buffer(2);
   std::vector<int> buttons = {BTN_LEFT, BTN_MIDDLE, BTN_RIGHT, BTN_BACK,
                               BTN_FORWARD};
   CF_EXPECT(button < (int)buttons.size(),
             "Unknown mouse event button: " << button);
-  buffer->AddEvent(EV_KEY, buttons[button], down);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  buffer.AddEvent(EV_KEY, buttons[button], down);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> MouseDevice::SendWheelEvent(int pixels) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_REL, REL_WHEEL, pixels);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  EventBuffer buffer(2);
+  buffer.AddEvent(EV_REL, REL_WHEEL, pixels);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> KeyboardDevice::SendEvent(uint16_t code, bool down) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_KEY, code, down);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  EventBuffer buffer(2);
+  buffer.AddEvent(EV_KEY, code, down);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> RotaryDevice::SendEvent(int pixels) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_REL, REL_WHEEL, pixels);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  EventBuffer buffer(2);
+  buffer.AddEvent(EV_REL, REL_WHEEL, pixels);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
 Result<void> SwitchesDevice::SendEvent(uint16_t code, bool state) {
-  auto buffer = CreateBuffer(event_type(), 2);
-  CF_EXPECT(buffer != nullptr, "Failed to allocate input events buffer");
-  buffer->AddEvent(EV_SW, code, state);
-  buffer->AddEvent(EV_SYN, SYN_REPORT, 0);
-  CF_EXPECT(conn().WriteEvents(buffer->data(), buffer->size()));
+  EventBuffer buffer(2);
+  buffer.AddEvent(EV_SW, code, state);
+  buffer.AddEvent(EV_SYN, SYN_REPORT, 0);
+  CF_EXPECT(WriteEvents(buffer));
   return {};
 }
 
diff --git a/host/libs/input_connector/input_devices.h b/host/libs/input_connector/input_devices.h
index c86bdde4e..1b9071fe4 100644
--- a/host/libs/input_connector/input_devices.h
+++ b/host/libs/input_connector/input_devices.h
@@ -20,7 +20,6 @@
 #include <cstdint>
 #include <cstdlib>
 #include <map>
-#include <memory>
 #include <mutex>
 #include <utility>
 #include <vector>
@@ -34,23 +33,20 @@ namespace cuttlefish {
 
 class InputDevice {
  public:
-  InputDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
-      : conn_(std::move(conn)), event_type_(event_type) {}
+  InputDevice(InputConnection conn) : conn_(conn) {}
   virtual ~InputDevice() = default;
 
  protected:
-  InputConnection& conn() { return *conn_; }
-  InputEventType event_type() const { return event_type_; }
+  Result<void> WriteEvents(const EventBuffer& buffer);
 
  private:
-  std::unique_ptr<InputConnection> conn_;
-  InputEventType event_type_;
+  InputConnection conn_;
 };
 
 class TouchDevice : public InputDevice {
  public:
-  TouchDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
-      : InputDevice(std::move(conn), event_type) {}
+  TouchDevice(InputConnection conn)
+      : InputDevice(conn) {}
 
   Result<void> SendTouchEvent(int x, int y, bool down);
 
@@ -66,11 +62,6 @@ class TouchDevice : public InputDevice {
   void OnDisconnectedSource(void* source);
 
  private:
-  Result<void> WriteEvents(const EventBuffer& buffer) {
-    CF_EXPECT(conn().WriteEvents(buffer.data(), buffer.size()));
-    return {};
-  }
-
   bool HasSlot(void* source, int32_t id);
 
   int32_t GetOrAcquireSlot(void* source, int32_t id);
@@ -94,8 +85,8 @@ class TouchDevice : public InputDevice {
 
 class MouseDevice : public InputDevice {
  public:
-  MouseDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
-      : InputDevice(std::move(conn), event_type) {}
+  MouseDevice(InputConnection conn)
+      : InputDevice(conn) {}
 
   Result<void> SendMoveEvent(int x, int y);
   Result<void> SendButtonEvent(int button, bool down);
@@ -104,26 +95,24 @@ class MouseDevice : public InputDevice {
 
 class KeyboardDevice : public InputDevice {
  public:
-  KeyboardDevice(std::unique_ptr<InputConnection> conn,
-                 InputEventType event_type)
-      : InputDevice(std::move(conn), event_type) {}
+  KeyboardDevice(InputConnection conn)
+      : InputDevice(conn) {}
 
   Result<void> SendEvent(uint16_t code, bool down);
 };
 
 class RotaryDevice : public InputDevice {
  public:
-  RotaryDevice(std::unique_ptr<InputConnection> conn, InputEventType event_type)
-      : InputDevice(std::move(conn), event_type) {}
+  RotaryDevice(InputConnection conn)
+      : InputDevice(conn) {}
 
   Result<void> SendEvent(int pixels);
 };
 
 class SwitchesDevice : public InputDevice {
  public:
-  SwitchesDevice(std::unique_ptr<InputConnection> conn,
-                 InputEventType event_type)
-      : InputDevice(std::move(conn), event_type) {}
+  SwitchesDevice(InputConnection conn)
+      : InputDevice(conn) {}
 
   Result<void> SendEvent(uint16_t code, bool state);
 };
diff --git a/host/libs/input_connector/server_input_connection.cpp b/host/libs/input_connector/server_input_connection.cpp
deleted file mode 100644
index c67ee3b2a..000000000
--- a/host/libs/input_connector/server_input_connection.cpp
+++ /dev/null
@@ -1,81 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include "host/libs/input_connector/input_connection.h"
-
-#include "common/libs/fs/shared_buf.h"
-#include "common/libs/fs/shared_fd.h"
-
-namespace cuttlefish {
-namespace {
-class ServerInputConnection : public InputConnection {
- public:
-  ServerInputConnection(SharedFD server);
-
-  Result<void> WriteEvents(const void* data, size_t len) override;
-
- private:
-  SharedFD server_;
-  SharedFD client_;
-  std::mutex client_mtx_;
-  std::thread monitor_;
-
-  void MonitorLoop();
-};
-
-ServerInputConnection::ServerInputConnection(SharedFD server)
-    : server_(server), monitor_(std::thread([this]() { MonitorLoop(); })) {}
-
-void ServerInputConnection::MonitorLoop() {
-  for (;;) {
-    client_ = SharedFD::Accept(*server_);
-    if (!client_->IsOpen()) {
-      LOG(ERROR) << "Failed to accept on input socket: " << client_->StrError();
-      continue;
-    }
-    do {
-      // Keep reading from the fd to detect when it closes.
-      char buf[128];
-      auto res = client_->Read(buf, sizeof(buf));
-      if (res < 0) {
-        LOG(ERROR) << "Failed to read from input client: "
-                   << client_->StrError();
-      } else if (res > 0) {
-        LOG(VERBOSE) << "Received " << res << " bytes on input socket";
-      } else {
-        std::lock_guard<std::mutex> lock(client_mtx_);
-        client_->Close();
-      }
-    } while (client_->IsOpen());
-  }
-}
-
-Result<void> ServerInputConnection::WriteEvents(const void* data, size_t len) {
-  std::lock_guard<std::mutex> lock(client_mtx_);
-  CF_EXPECT(client_->IsOpen(), "No input client connected");
-  auto res = WriteAll(client_, reinterpret_cast<const char*>(data), len);
-  CF_EXPECT(res == len, "Failed to write entire event buffer: wrote "
-                            << res << " of " << len << "bytes");
-  return {};
-}
-
-}  // namespace
-
-std::unique_ptr<InputConnection> NewServerInputConnection(SharedFD server_fd) {
-  return std::unique_ptr<InputConnection>(new ServerInputConnection(server_fd));
-}
-
-}  // namespace cuttlefish
diff --git a/host/libs/process_monitor/Android.bp b/host/libs/process_monitor/Android.bp
index 0c2534189..468da9262 100644
--- a/host/libs/process_monitor/Android.bp
+++ b/host/libs/process_monitor/Android.bp
@@ -21,7 +21,6 @@ cc_library {
     name: "libcuttlefish_process_monitor",
     srcs: [
         "process_monitor.cc",
-        "process_monitor_channel.cc",
     ],
     shared_libs: [
         "libbase",
@@ -35,6 +34,7 @@ cc_library {
     static_libs: [
         "libcuttlefish_command_util",
         "libcuttlefish_host_config",
+        "libcuttlefish_transport",
         "libgflags",
     ],
     target: {
diff --git a/host/libs/process_monitor/process_monitor.cc b/host/libs/process_monitor/process_monitor.cc
index b58ca8fac..fb5814542 100644
--- a/host/libs/process_monitor/process_monitor.cc
+++ b/host/libs/process_monitor/process_monitor.cc
@@ -23,39 +23,60 @@
 #include <sys/types.h>
 #include <sys/wait.h>
 
-#include <assert.h>
 #include <errno.h>
 #include <signal.h>
 #include <stdio.h>
 
 #include <algorithm>
 #include <atomic>
-#include <cstdint>
 #include <future>
 #include <memory>
 #include <string>
-#include <thread>
 #include <vector>
 
 #include <android-base/file.h>
 #include <android-base/logging.h>
+#include "android-base/strings.h"
 
-#include "common/libs/fs/shared_buf.h"
-#include "common/libs/fs/shared_select.h"
+#include "common/libs/transport/channel.h"
+#include "common/libs/transport/channel_sharedfd.h"
 #include "common/libs/utils/contains.h"
-#include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
-#include "host/libs/command_util/runner/defs.h"
 #include "host/libs/command_util/util.h"
-#include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/config/known_paths.h"
-#include "host/libs/process_monitor/process_monitor_channel.h"
 
 namespace cuttlefish {
-
 namespace {
 
+using transport::Channel;
+using transport::CreateMessage;
+using transport::ManagedMessage;
+
+enum ParentToChildMessageType : std::uint8_t {
+  kStop = 1,
+  kHostResume = 2,
+  kHostSuspend = 3,
+  kError = 4,
+};
+
+enum ChildToParentResponseType : std::uint8_t {
+  kSuccess = 0,
+  kFailure = 1,
+};
+
+Result<void> SendEmptyRequest(Channel& channel, uint32_t type) {
+  ManagedMessage message = CF_EXPECT(CreateMessage(type, false, 0));
+  CF_EXPECT(channel.SendRequest(*message));
+  return {};
+}
+
+Result<void> SendEmptyResponse(Channel& channel, uint32_t type) {
+  ManagedMessage message = CF_EXPECT(CreateMessage(type, true, 0));
+  CF_EXPECT(channel.SendResponse(*message));
+  return {};
+}
+
 void LogSubprocessExit(const std::string& name, pid_t pid, int wstatus) {
   LOG(INFO) << "Detected unexpected exit of monitored subprocess " << name;
   if (WIFEXITED(wstatus)) {
@@ -161,7 +182,7 @@ Result<void> SuspendResumeImpl(std::vector<MonitorEntry>& monitor_entries,
                                std::mutex& properties_mutex,
                                const SharedFD& channel_to_secure_env,
                                const bool is_suspend,
-                               SharedFD child_monitor_socket) {
+                               transport::SharedFdChannel& socket) {
   std::lock_guard lock(properties_mutex);
   auto secure_env_itr = std::find_if(
       monitor_entries.begin(), monitor_entries.end(), [](MonitorEntry& entry) {
@@ -207,6 +228,11 @@ Result<void> SuspendResumeImpl(std::vector<MonitorEntry>& monitor_entries,
       // secure_env was handled above in a customized way
       continue;
     }
+    if (android::base::StartsWith(prog_name, "cf_vhost_user_")) {
+      // vhost user backend processes need to continue handling requests from
+      // the VMM, which should send them the suspend signal.
+      continue;
+    }
 
     if (process_restart_bin == prog_name) {
       if (is_suspend) {
@@ -222,10 +248,7 @@ Result<void> SuspendResumeImpl(std::vector<MonitorEntry>& monitor_entries,
       CF_EXPECT(entry.proc->SendSignalToGroup(SIGCONT));
     }
   }
-  using process_monitor_impl::ChildToParentResponse;
-  using process_monitor_impl::ChildToParentResponseType;
-  ChildToParentResponse response(ChildToParentResponseType::kSuccess);
-  CF_EXPECT(response.Write(child_monitor_socket));
+  CF_EXPECT(SendEmptyResponse(socket, ChildToParentResponseType::kSuccess));
   return {};
 }
 
@@ -255,9 +278,8 @@ Result<void> ProcessMonitor::StartSubprocesses(
 Result<void> ProcessMonitor::ReadMonitorSocketLoop(std::atomic_bool& running) {
   LOG(DEBUG) << "Waiting for a `stop` message from the parent";
   while (running.load()) {
-    using process_monitor_impl::ParentToChildMessage;
-    auto message = CF_EXPECT(ParentToChildMessage::Read(child_monitor_socket_));
-    if (message.Stop()) {
+    ManagedMessage message = CF_EXPECT(child_channel_->ReceiveMessage());
+    if (message->command == ParentToChildMessageType::kStop) {
       running.store(false);
       // Wake up the wait() loop by giving it an exited child process
       if (fork() == 0) {
@@ -266,12 +288,11 @@ Result<void> ProcessMonitor::ReadMonitorSocketLoop(std::atomic_bool& running) {
       // will break the for-loop as running is now false
       continue;
     }
-    using process_monitor_impl::ParentToChildMessageType;
-    if (message.Type() == ParentToChildMessageType::kHostSuspend) {
+    if (message->command == ParentToChildMessageType::kHostSuspend) {
       CF_EXPECT(SuspendHostProcessesImpl());
       continue;
     }
-    if (message.Type() == ParentToChildMessageType::kHostResume) {
+    if (message->command == ParentToChildMessageType::kHostResume) {
       CF_EXPECT(ResumeHostProcessesImpl());
       continue;
     }
@@ -280,17 +301,19 @@ Result<void> ProcessMonitor::ReadMonitorSocketLoop(std::atomic_bool& running) {
 }
 
 Result<void> ProcessMonitor::SuspendHostProcessesImpl() {
+  CF_EXPECT(child_channel_.has_value());
   CF_EXPECT(SuspendResumeImpl(properties_.entries_, properties_mutex_,
                               channel_to_secure_env_, /* is_suspend */ true,
-                              child_monitor_socket_),
+                              *child_channel_),
             "Failed suspend");
   return {};
 }
 
 Result<void> ProcessMonitor::ResumeHostProcessesImpl() {
+  CF_EXPECT(child_channel_.has_value());
   CF_EXPECT(SuspendResumeImpl(properties_.entries_, properties_mutex_,
                               channel_to_secure_env_, /* is_suspend */ false,
-                              child_monitor_socket_),
+                              *child_channel_),
             "Failed resume");
   return {};
 }
@@ -327,16 +350,14 @@ ProcessMonitor::ProcessMonitor(ProcessMonitor::Properties&& properties,
 
 Result<void> ProcessMonitor::StopMonitoredProcesses() {
   CF_EXPECT(monitor_ != -1, "The monitor process has already exited.");
-  CF_EXPECT(parent_monitor_socket_->IsOpen(),
+  CF_EXPECT(parent_channel_.has_value(),
             "The monitor socket is already closed");
-  using process_monitor_impl::ParentToChildMessage;
-  using process_monitor_impl::ParentToChildMessageType;
-  ParentToChildMessage message(ParentToChildMessageType::kStop);
-  CF_EXPECT(message.Write(parent_monitor_socket_));
+  CF_EXPECT(
+      SendEmptyRequest(*parent_channel_, ParentToChildMessageType::kStop));
 
   pid_t last_monitor = monitor_;
   monitor_ = -1;
-  parent_monitor_socket_->Close();
+  parent_channel_.reset();
   int wstatus;
   CF_EXPECT(waitpid(last_monitor, &wstatus, 0) == last_monitor,
             "Failed to wait for monitor process");
@@ -349,56 +370,46 @@ Result<void> ProcessMonitor::StopMonitoredProcesses() {
 
 Result<void> ProcessMonitor::SuspendMonitoredProcesses() {
   CF_EXPECT(monitor_ != -1, "The monitor process has already exited.");
-  CF_EXPECT(parent_monitor_socket_->IsOpen(),
-            "The monitor socket is already closed");
-  using process_monitor_impl::ParentToChildMessage;
-  using process_monitor_impl::ParentToChildMessageType;
-  ParentToChildMessage message(ParentToChildMessageType::kHostSuspend);
-  CF_EXPECT(message.Write(parent_monitor_socket_));
-  using process_monitor_impl::ChildToParentResponse;
-  auto response =
-      CF_EXPECT(ChildToParentResponse::Read(parent_monitor_socket_));
-  CF_EXPECT(response.Success(),
+  CF_EXPECT(parent_channel_.has_value());
+  CF_EXPECT(SendEmptyRequest(*parent_channel_,
+                             ParentToChildMessageType::kHostSuspend));
+
+  ManagedMessage response = CF_EXPECT(parent_channel_->ReceiveMessage());
+  CF_EXPECT(response->command == ChildToParentResponseType::kSuccess,
             "On kHostSuspend, the child run_cvd returned kFailure.");
   return {};
 }
 
 Result<void> ProcessMonitor::ResumeMonitoredProcesses() {
   CF_EXPECT(monitor_ != -1, "The monitor process has already exited.");
-  CF_EXPECT(parent_monitor_socket_->IsOpen(),
-            "The monitor socket is already closed");
-  using process_monitor_impl::ParentToChildMessage;
-  using process_monitor_impl::ParentToChildMessageType;
-  ParentToChildMessage message(ParentToChildMessageType::kHostResume);
-  CF_EXPECT(message.Write(parent_monitor_socket_));
-  using process_monitor_impl::ChildToParentResponse;
-  auto response =
-      CF_EXPECT(ChildToParentResponse::Read(parent_monitor_socket_));
-  CF_EXPECT(response.Success(),
+  CF_EXPECT(parent_channel_.has_value());
+  CF_EXPECT(SendEmptyRequest(*parent_channel_,
+                             ParentToChildMessageType::kHostResume));
+
+  ManagedMessage response = CF_EXPECT(parent_channel_->ReceiveMessage());
+  CF_EXPECT(response->command == ChildToParentResponseType::kSuccess,
             "On kHostResume, the child run_cvd returned kFailure.");
   return {};
 }
 
 Result<void> ProcessMonitor::StartAndMonitorProcesses() {
   CF_EXPECT(monitor_ == -1, "The monitor process was already started");
-  CF_EXPECT(!parent_monitor_socket_->IsOpen(),
+  CF_EXPECT(!parent_channel_.has_value(),
             "Parent monitor socket was already opened");
   SharedFD parent_sock;
   SharedFD child_sock;
   SharedFD::SocketPair(AF_UNIX, SOCK_STREAM, 0, &parent_sock, &child_sock);
   monitor_ = fork();
   if (monitor_ == 0) {
-    child_monitor_socket_ = std::move(child_sock);
-    parent_sock->Close();
-    auto monitor_result = MonitorRoutine();
+    child_channel_ = transport::SharedFdChannel(child_sock, child_sock);
+    Result<void> monitor_result = MonitorRoutine();
     if (!monitor_result.ok()) {
       LOG(ERROR) << "Monitoring processes failed:\n"
                  << monitor_result.error().FormatForEnv();
     }
     std::exit(monitor_result.ok() ? 0 : 1);
   } else {
-    parent_monitor_socket_ = std::move(parent_sock);
-    child_sock->Close();
+    parent_channel_ = transport::SharedFdChannel(parent_sock, parent_sock);
     return {};
   }
 }
diff --git a/host/libs/process_monitor/process_monitor.h b/host/libs/process_monitor/process_monitor.h
index 0431ad377..0ef61c2f0 100644
--- a/host/libs/process_monitor/process_monitor.h
+++ b/host/libs/process_monitor/process_monitor.h
@@ -23,6 +23,7 @@
 #include <utility>
 #include <vector>
 
+#include "common/libs/transport/channel_sharedfd.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/command_source.h"
@@ -87,8 +88,8 @@ class ProcessMonitor {
   Properties properties_;
   const SharedFD channel_to_secure_env_;
   pid_t monitor_;
-  SharedFD parent_monitor_socket_;
-  SharedFD child_monitor_socket_;
+  std::optional<transport::SharedFdChannel> parent_channel_;
+  std::optional<transport::SharedFdChannel> child_channel_;
 
   /*
    * The lock that should be acquired when multiple threads
diff --git a/host/libs/process_monitor/process_monitor_channel.cc b/host/libs/process_monitor/process_monitor_channel.cc
deleted file mode 100644
index 3b802b242..000000000
--- a/host/libs/process_monitor/process_monitor_channel.cc
+++ /dev/null
@@ -1,82 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include "host/libs/process_monitor/process_monitor_channel.h"
-
-#include <string>
-
-#include "common/libs/fs/shared_buf.h"
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/result.h"
-
-namespace cuttlefish {
-namespace process_monitor_impl {
-
-ParentToChildMessage::ParentToChildMessage(const ParentToChildMessageType type)
-    : type_(type) {}
-
-Result<void> ParentToChildMessage::Write(const SharedFD& fd) {
-  CF_EXPECTF(fd->IsOpen(), "File descriptor to write ParentToChildMessage",
-             " is closed.");
-  const auto n_bytes = WriteAllBinary(fd, &type_);
-  std::string err_msg("Failed to communicate with monitor socket");
-  CF_EXPECTF(n_bytes == sizeof(type_),
-             "{} : {}. Expected to write {} bytes but wrote {} bytes.", err_msg,
-             fd->StrError(), sizeof(type_), n_bytes);
-  return {};
-}
-
-Result<ParentToChildMessage> ParentToChildMessage::Read(const SharedFD& fd) {
-  ParentToChildMessageType type = ParentToChildMessageType::kError;
-  CF_EXPECTF(fd->IsOpen(), "File descriptor to read ParentToChildMessage",
-             "from is closed.");
-  std::string err_msg("Could not read message from parent");
-  const auto n_bytes = ReadExactBinary(fd, &type);
-  CF_EXPECTF(n_bytes == sizeof(type),
-             "{} : {}. Expected To read {} bytes but actually read {} bytes",
-             err_msg, fd->StrError(), sizeof(type), n_bytes);
-  return ParentToChildMessage{type};
-}
-
-ChildToParentResponse::ChildToParentResponse(
-    const ChildToParentResponseType type)
-    : type_(type) {}
-
-Result<void> ChildToParentResponse::Write(const SharedFD& fd) {
-  CF_EXPECTF(fd->IsOpen(), "File descriptor to write ChildToParentResponse",
-             " is closed.");
-  const auto n_bytes = WriteAllBinary(fd, &type_);
-  std::string err_msg("Failed to communicate with monitor socket");
-  CF_EXPECTF(n_bytes == sizeof(type_),
-             "{} : {}. Expected to write {} bytes but wrote {} bytes.", err_msg,
-             fd->StrError(), sizeof(type_), n_bytes);
-  return {};
-}
-
-Result<ChildToParentResponse> ChildToParentResponse::Read(const SharedFD& fd) {
-  ChildToParentResponseType type = ChildToParentResponseType::kFailure;
-  CF_EXPECTF(fd->IsOpen(), "File descriptor to read ChildToParentResponse",
-             "from is closed.");
-  std::string err_msg("Could not read response from parent");
-  const auto n_bytes = ReadExactBinary(fd, &type);
-  CF_EXPECTF(n_bytes == sizeof(type),
-             "{} : {}. Expected To read {} bytes but actually read {} bytes",
-             err_msg, fd->StrError(), sizeof(type), n_bytes);
-  return ChildToParentResponse{type};
-}
-
-}  // namespace process_monitor_impl
-}  // namespace cuttlefish
diff --git a/host/libs/process_monitor/process_monitor_channel.h b/host/libs/process_monitor/process_monitor_channel.h
deleted file mode 100644
index 1d5e544d5..000000000
--- a/host/libs/process_monitor/process_monitor_channel.h
+++ /dev/null
@@ -1,63 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
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
-#include <cstdint>
-
-#include "common/libs/fs/shared_fd.h"
-#include "common/libs/utils/result.h"
-
-namespace cuttlefish {
-namespace process_monitor_impl {
-
-enum class ParentToChildMessageType : std::uint8_t {
-  kStop = 1,
-  kHostResume = 2,
-  kHostSuspend = 3,
-  kError = 4,
-};
-
-enum class ChildToParentResponseType : std::uint8_t {
-  kSuccess = 0,
-  kFailure = 1,
-};
-
-class ParentToChildMessage {
- public:
-  ParentToChildMessage(const ParentToChildMessageType type);
-  Result<void> Write(const SharedFD& fd);
-  static Result<ParentToChildMessage> Read(const SharedFD& fd);
-  bool Stop() const { return type_ == ParentToChildMessageType::kStop; }
-  auto Type() const { return type_; }
-
- private:
-  ParentToChildMessageType type_;
-};
-
-class ChildToParentResponse {
- public:
-  ChildToParentResponse(const ChildToParentResponseType type);
-  Result<void> Write(const SharedFD& fd);
-  static Result<ChildToParentResponse> Read(const SharedFD& fd);
-  bool Success() const { return type_ == ChildToParentResponseType::kSuccess; }
-
- private:
-  ChildToParentResponseType type_;
-};
-
-}  // namespace process_monitor_impl
-}  // namespace cuttlefish
diff --git a/host/libs/screen_connector/Android.bp b/host/libs/screen_connector/Android.bp
index 1496033d9..85b35bbfd 100644
--- a/host/libs/screen_connector/Android.bp
+++ b/host/libs/screen_connector/Android.bp
@@ -20,6 +20,8 @@ package {
 cc_library {
     name: "libcuttlefish_screen_connector",
     srcs: [
+        "composition_manager.cpp",
+        "ring_buffer_manager.cpp",
         "wayland_screen_connector.cpp",
     ],
     shared_libs: [
@@ -28,6 +30,7 @@ cc_library {
         "libfruit",
         "libjsoncpp",
         "liblog",
+        "libyuv",
     ],
     header_libs: [
         "libcuttlefish_confui_host_headers",
diff --git a/host/libs/screen_connector/composition_manager.cpp b/host/libs/screen_connector/composition_manager.cpp
new file mode 100644
index 000000000..dd0435c0a
--- /dev/null
+++ b/host/libs/screen_connector/composition_manager.cpp
@@ -0,0 +1,286 @@
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
+/*
+ * TODO(b/384939093): PLEASE NOTE: The implemented here is in a WIP status.
+ *
+ * Currently the Composition algorithm implemented in
+ * this module has a known limitation.  It uses IPC buffers in such a way where
+ * it is currently possible for frames to be simultaneously
+ * read and written from the same memory lcoation.  It's therefore possible to
+ * have some display artifacts as partial frames are read.  To remedy there is
+ * follow-up work (documented in b/384939093) planned.
+ */
+
+#include "host/libs/screen_connector/composition_manager.h"
+
+#include <android-base/parseint.h>
+#include <android-base/strings.h>
+#include <libyuv.h>
+
+#include <drm/drm_fourcc.h>
+#include "host/frontend/webrtc/display_handler.h"
+#include "host/libs/screen_connector/ring_buffer_manager.h"
+
+static const int kRedIdx = 0;
+static const int kGreenIdx = 1;
+static const int kBlueIdx = 2;
+static const int kAlphaIdx = 3;
+
+namespace cuttlefish {
+
+void alpha_blend_layer(std::uint8_t* frame_pixels, std::uint32_t h,
+                       std::uint32_t w, std::uint8_t* overlay) {
+  std::uint8_t* dst = frame_pixels;
+  std::uint8_t* src = overlay;
+  int max = w * h;
+  for (int idx = 0; idx < max; idx++) {
+    float a = ((float)src[kAlphaIdx]) / 255.0f;
+    float a_inv = 1.0f - a;
+    dst[kRedIdx] = (std::uint8_t)((src[kRedIdx] * a) + (dst[kRedIdx] * a_inv));
+    dst[kBlueIdx] =
+        (std::uint8_t)((src[kBlueIdx] * a) + (dst[kBlueIdx] * a_inv));
+    dst[kGreenIdx] =
+        (std::uint8_t)((src[kGreenIdx] * a) + (dst[kGreenIdx] * a_inv));
+    dst[kAlphaIdx] = 255;
+    dst += 4;
+    src += 4;
+  }
+}
+
+std::map<int, std::vector<CompositionManager::DisplayOverlay>>
+CompositionManager::ParseOverlays(std::vector<std::string> overlay_items) {
+  std::map<int, std::vector<DisplayOverlay>> overlays;
+  // This iterates the list of overlay tuples, entries are of the form x:y
+  // where x is a vm index in the cluster, and y is a display
+  // index within that vm.  Structured types are created as result.
+  for (int display_index = 0; display_index < overlay_items.size();
+       display_index++) {
+    auto overlay_item = android::base::Trim(overlay_items[display_index]);
+
+    if (overlay_item == "" || overlay_item == "_") {
+      continue;
+    }
+
+    std::vector<DisplayOverlay>& display_overlays = overlays[display_index];
+
+    std::vector<std::string> overlay_list =
+        android::base::Split(overlay_item, " ");
+
+    for (const auto& overlay_tuple_str : overlay_list) {
+      std::vector<std::string> overlay_tuple =
+          android::base::Split(overlay_tuple_str, ":");
+
+      DisplayOverlay docfg;
+
+      if (overlay_tuple.size() == 2) {
+        if (!(android::base::ParseInt(overlay_tuple[0], &docfg.src_vm_index) &&
+              android::base::ParseInt(overlay_tuple[1],
+                                      &docfg.src_display_index))) {
+          LOG(FATAL) << "Failed to parse display overlay directive: "
+                     << overlay_tuple_str;
+        } else {
+          display_overlays.push_back(docfg);
+        }
+      } else {
+        LOG(FATAL) << "Failed to parse display overlay directive, not a tuple "
+                      "of format x:y - "
+                   << overlay_tuple_str;
+      }
+    }
+  }
+  return overlays;
+}
+
+CompositionManager::CompositionManager(
+    int cluster_index, std::string& group_uuid,
+    std::map<int, std::vector<DisplayOverlay>>& overlays)
+    : display_ring_buffer_manager_(cluster_index - 1, group_uuid),
+      cluster_index_(cluster_index - 1),
+      group_uuid_(group_uuid),
+      cfg_overlays_(overlays) {}
+
+CompositionManager::~CompositionManager() {}
+
+Result<std::unique_ptr<CompositionManager>> CompositionManager::Create() {
+  auto cvd_config = CuttlefishConfig::Get();
+  auto instance = cvd_config->ForDefaultInstance();
+  // Aggregate all the display overlays into a single list per config
+  std::vector<std::string> overlays;
+  for (const auto& display : instance.display_configs()) {
+    overlays.push_back(display.overlays);
+  }
+
+  std::map<int, std::vector<CompositionManager::DisplayOverlay>> domap =
+      CompositionManager::ParseOverlays(overlays);
+  for (auto const& [display_index, display_overlays] : domap) {
+    for (auto const& display_overlay : display_overlays) {
+      CF_EXPECTF(display_overlay.src_vm_index < cvd_config->Instances().size(),
+                 "Invalid source overlay VM index: {}",
+                 display_overlay.src_vm_index);
+
+      const cuttlefish::CuttlefishConfig::InstanceSpecific src_instance =
+          cvd_config->Instances()[display_overlay.src_vm_index];
+
+      CF_EXPECTF(display_overlay.src_display_index <
+                     src_instance.display_configs().size(),
+                 "Invalid source overlay display index: {}",
+                 display_overlay.src_vm_index);
+
+      const cuttlefish::CuttlefishConfig::DisplayConfig src_display =
+          src_instance.display_configs()[display_overlay.src_display_index];
+
+      const cuttlefish::CuttlefishConfig::DisplayConfig dest_display =
+          instance.display_configs()[display_index];
+
+      CF_EXPECT(src_display.width == dest_display.width &&
+                    src_display.height == dest_display.height,
+                "Source and target overlay display must be of identical size.");
+    }
+  }
+
+  // Calculate the instance's position within cluster
+  // For display overlay config calculations
+  int instance_index = instance.index();
+
+  std::string group_uuid =
+      fmt::format("{}", cvd_config->ForDefaultEnvironment().group_uuid());
+
+  CF_EXPECT(group_uuid.length() > 0, "Invalid group UUID");
+
+  std::unique_ptr<CompositionManager> mgr(
+      new CompositionManager(instance_index + 1, group_uuid, domap));
+
+  return mgr;
+}
+
+// Whenever a display is created, a shared memory IPC ringbuffer
+// is initialized so that other frames can obtain this display's contents
+// for composition.
+void CompositionManager::OnDisplayCreated(const DisplayCreatedEvent& e) {
+  auto result = display_ring_buffer_manager_.CreateLocalDisplayBuffer(
+      cluster_index_, e.display_number, e.display_width, e.display_height);
+
+  if (!result.ok()) {
+    LOG(FATAL) << "OnDisplayCreated failed: " << result.error().FormatForEnv();
+  }
+}
+
+// Called every frame.
+void CompositionManager::OnFrame(std::uint32_t display_number,
+                                 std::uint32_t frame_width,
+                                 std::uint32_t frame_height,
+                                 std::uint32_t frame_fourcc_format,
+                                 std::uint32_t frame_stride_bytes,
+                                 std::uint8_t* frame_pixels) {
+  // First step is to push the local display pixels to the shared memory region
+  // ringbuffer
+  std::uint8_t* shmem_local_display = display_ring_buffer_manager_.WriteFrame(
+      cluster_index_, display_number, frame_pixels,
+      frame_width * frame_height * 4);
+
+  // Next some upkeep, the format of the frame is needed for blending
+  // computations.
+  LastFrameInfo last_frame_info = LastFrameInfo(
+      display_number, frame_width, frame_height, frame_fourcc_format,
+      frame_stride_bytes, (std::uint8_t*)shmem_local_display);
+
+  last_frame_info_map_[display_number] = last_frame_info;
+
+  // Lastly, the pixels of the current frame are modified by blending any
+  // configured layers over the top of the current 'base layer'
+  AlphaBlendLayers(frame_pixels, display_number, frame_width, frame_height);
+}
+
+// This is called to 'Force a Display Composition Refresh' on a display.  It is
+// triggered by a thread to force displays to constantly update so that when
+// layers are updated, the user will see the blended result.
+void CompositionManager::ComposeFrame(
+    int display_index, std::shared_ptr<CvdVideoFrameBuffer> buffer) {
+  if (!last_frame_info_map_.contains(display_index)) {
+    return;
+  }
+  LastFrameInfo& last_frame_info = last_frame_info_map_[display_index];
+
+  ComposeFrame(display_index, last_frame_info.frame_width_,
+               last_frame_info.frame_height_,
+               last_frame_info.frame_fourcc_format_,
+               last_frame_info.frame_stride_bytes_, buffer);
+}
+
+std::uint8_t* CompositionManager::AlphaBlendLayers(std::uint8_t* frame_pixels,
+                                                   int display_number,
+                                                   int frame_width,
+                                                   int frame_height) {
+  if (cfg_overlays_.count(display_number) == 0) {
+    return frame_pixels;
+  }
+
+  std::vector<DisplayOverlay>& cfg_overlays = cfg_overlays_[display_number];
+  int num_overlays = cfg_overlays.size();
+
+  std::vector<void*> overlays;
+  overlays.resize(num_overlays, nullptr);
+
+  for (int i = 0; i < num_overlays; i++) {
+    if (overlays[i] != nullptr) {
+      continue;
+    }
+
+    DisplayOverlay& layer = cfg_overlays[i];
+
+    overlays[i] = display_ring_buffer_manager_.ReadFrame(
+        layer.src_vm_index, layer.src_display_index, frame_width, frame_height);
+  }
+
+  for (auto i : overlays) {
+    if (i) {
+      alpha_blend_layer(frame_pixels, frame_height, frame_width,
+                        (std::uint8_t*)i);
+    }
+  }
+  return (std::uint8_t*)frame_pixels;
+}
+
+void CompositionManager::ComposeFrame(
+    int display, int width, int height, std::uint32_t frame_fourcc_format,
+    std::uint32_t frame_stride_bytes,
+    std::shared_ptr<CvdVideoFrameBuffer> buffer) {
+  std::uint8_t* shmem_local_display = display_ring_buffer_manager_.ReadFrame(
+      cluster_index_, display, width, height);
+
+  if (!frame_work_buffer_.contains(display)) {
+    frame_work_buffer_[display] = std::vector<std::uint8_t>(width * height * 4);
+  }
+  std::uint8_t* tmp_buffer = frame_work_buffer_[display].data();
+  memcpy(tmp_buffer, shmem_local_display, width * height * 4);
+
+  AlphaBlendLayers(tmp_buffer, display, width, height);
+
+  if (frame_fourcc_format == DRM_FORMAT_ARGB8888 ||
+      frame_fourcc_format == DRM_FORMAT_XRGB8888) {
+    libyuv::ARGBToI420(tmp_buffer, frame_stride_bytes, buffer->DataY(),
+                       buffer->StrideY(), buffer->DataU(), buffer->StrideU(),
+                       buffer->DataV(), buffer->StrideV(), width, height);
+  } else if (frame_fourcc_format == DRM_FORMAT_ABGR8888 ||
+             frame_fourcc_format == DRM_FORMAT_XBGR8888) {
+    libyuv::ABGRToI420(tmp_buffer, frame_stride_bytes, buffer->DataY(),
+                       buffer->StrideY(), buffer->DataU(), buffer->StrideU(),
+                       buffer->DataV(), buffer->StrideV(), width, height);
+  }
+}
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/libs/screen_connector/composition_manager.h b/host/libs/screen_connector/composition_manager.h
new file mode 100644
index 000000000..c63d2bfa2
--- /dev/null
+++ b/host/libs/screen_connector/composition_manager.h
@@ -0,0 +1,88 @@
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
+#include <android-base/logging.h>
+#include "common/libs/utils/result.h"
+#include "host/frontend/webrtc/cvd_video_frame_buffer.h"
+#include "host/frontend/webrtc/display_handler.h"
+#include "host/frontend/webrtc/libdevice/video_sink.h"
+#include "host/libs/screen_connector/screen_connector.h"
+
+namespace cuttlefish {
+class DisplayHandler;
+
+class CompositionManager {
+ public:
+  struct DisplayOverlay {
+    int src_vm_index;
+    int src_display_index;
+  };
+
+  ~CompositionManager();
+  static Result<std::unique_ptr<CompositionManager>> Create();
+
+  void OnDisplayCreated(const DisplayCreatedEvent& event);
+  void OnFrame(std::uint32_t display_number, std::uint32_t frame_width,
+               std::uint32_t frame_height, std::uint32_t frame_fourcc_format,
+               std::uint32_t frame_stride_bytes, std::uint8_t* frame_pixels);
+
+  void ComposeFrame(int display_index,
+                    std::shared_ptr<CvdVideoFrameBuffer> buffer);
+
+ private:
+  explicit CompositionManager(
+      int cluster_index, std::string& group_uuid,
+      std::map<int, std::vector<DisplayOverlay>>& overlays);
+
+  class LastFrameInfo {
+   public:
+    LastFrameInfo() {}
+    LastFrameInfo(std::uint32_t display_number, std::uint32_t frame_width,
+                  std::uint32_t frame_height, std::uint32_t frame_fourcc_format,
+                  std::uint32_t frame_stride_bytes,
+                  std::uint8_t* frame_pixels) {
+      display_number_ = display_number;
+      frame_width_ = frame_width;
+      frame_height_ = frame_height;
+      frame_fourcc_format_ = frame_fourcc_format;
+      frame_stride_bytes_ = frame_stride_bytes;
+      frame_pixels_ = frame_pixels;
+    }
+    std::uint32_t display_number_;
+    std::uint32_t frame_width_;
+    std::uint32_t frame_height_;
+    std::uint32_t frame_fourcc_format_;
+    std::uint32_t frame_stride_bytes_;
+    std::uint8_t* frame_pixels_;
+  };
+  static std::map<int, std::vector<CompositionManager::DisplayOverlay>>
+  ParseOverlays(std::vector<std::string> overlay_items);
+  std::uint8_t* AlphaBlendLayers(std::uint8_t* frame_pixels, int display,
+                                 int frame_width, int frame_height);
+  void ComposeFrame(int display, int width, int height,
+                    std::uint32_t frame_fourcc_format,
+                    std::uint32_t frame_stride_bytes,
+                    std::shared_ptr<CvdVideoFrameBuffer> buffer);
+  DisplayRingBufferManager display_ring_buffer_manager_;
+  int cluster_index_;
+  std::string group_uuid_;
+  std::map<int, std::vector<DisplayOverlay>> cfg_overlays_;
+  std::map<int, LastFrameInfo> last_frame_info_map_;
+  std::map<int, std::vector<std::uint8_t>> frame_work_buffer_;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/libs/screen_connector/ring_buffer_manager.cpp b/host/libs/screen_connector/ring_buffer_manager.cpp
new file mode 100644
index 000000000..9667f1b3a
--- /dev/null
+++ b/host/libs/screen_connector/ring_buffer_manager.cpp
@@ -0,0 +1,201 @@
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
+#include <string.h>
+
+#include <unistd.h>
+
+#include <android-base/logging.h>
+
+#include "ring_buffer_manager.h"
+
+namespace cuttlefish {
+
+namespace {
+constexpr int kNumberOfRingBufferFrames = 3;
+inline int RingBufferMemorySize(int w, int h) {
+  return sizeof(DisplayRingBufferHeader) +
+         ((w * h * 4) * kNumberOfRingBufferFrames);
+}
+}  // namespace
+
+void* DisplayRingBuffer::GetAddress() { return addr_; };
+
+Result<std::unique_ptr<DisplayRingBuffer>> DisplayRingBuffer::Create(
+    const std::string& name, int size) {
+  void* addr = nullptr;
+
+  SharedFD sfd =
+      SharedFD::ShmOpen(name, O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
+
+  CF_EXPECTF(sfd->IsOpen(), "Display buffer create failed {}", sfd->StrError());
+
+  sfd->Truncate(size);
+
+  ScopedMMap smm = sfd->MMap(NULL, size, PROT_WRITE, MAP_SHARED, 0);
+  addr = smm.get();
+
+  return std::unique_ptr<DisplayRingBuffer>(
+      new DisplayRingBuffer(addr, name, true, std::move(smm)));
+}
+
+DisplayRingBuffer::~DisplayRingBuffer() {
+  // Only unlink if we are the owner of the buffer.
+  if (owned_) {
+    shm_unlink(name_.c_str());
+  }
+}
+
+// Allowing optional in the case the buffer doesn't yet exist.
+std::optional<std::unique_ptr<DisplayRingBuffer>> DisplayRingBuffer::ShmemGet(
+    const std::string& name, int size) {
+  void* addr = nullptr;
+  SharedFD sfd = SharedFD::ShmOpen(name, O_RDWR, S_IRUSR | S_IWUSR);
+  if (!sfd->IsOpen()) {
+    return std::nullopt;
+  }
+  ScopedMMap smm = sfd->MMap(NULL, size, PROT_WRITE, MAP_SHARED, 0);
+  addr = smm.get();
+
+  if (!addr) {
+    return std::nullopt;
+  }
+
+  return std::unique_ptr<DisplayRingBuffer>(
+      new DisplayRingBuffer(addr, name, false, std::move(smm)));
+}
+
+DisplayRingBuffer::DisplayRingBuffer(void* addr, std::string name, bool owned,
+                                     ScopedMMap shm)
+    : addr_(addr), name_(std::move(name)), owned_(owned), shm_(std::move(shm)) {
+  header_ = (DisplayRingBufferHeader*)addr;
+}
+
+std::uint8_t* DisplayRingBuffer::WriteNextFrame(std::uint8_t* frame_data,
+                                                int size) {
+  int new_frame_index =
+      (header_->last_valid_frame_index_ + 1) % kNumberOfRingBufferFrames;
+
+  std::uint8_t* frame_memory_address =
+      ComputeFrameAddressForIndex(new_frame_index);
+  memcpy(frame_memory_address, frame_data, size);
+
+  header_->last_valid_frame_index_ = new_frame_index;
+  return frame_memory_address;
+}
+
+std::uint8_t* DisplayRingBuffer::CurrentFrame() {
+  return ComputeFrameAddressForIndex(header_->last_valid_frame_index_);
+}
+
+std::uint8_t* DisplayRingBuffer::ComputeFrameAddressForIndex(
+    std::uint32_t index) {
+  int frame_memory_index = (index * (header_->display_width_ *
+                                     header_->display_height_ * header_->bpp_));
+  return ((std::uint8_t*)addr_) + sizeof(DisplayRingBufferHeader) +
+         frame_memory_index;
+}
+
+void DisplayRingBufferHeader::set(std::uint32_t w, std::uint32_t h,
+                                  std::uint32_t bpp, std::uint32_t index) {
+  display_width_ = w;
+  display_height_ = h;
+  bpp_ = bpp;
+  last_valid_frame_index_.store(index);
+}
+
+DisplayRingBufferManager::DisplayRingBufferManager(int vm_index,
+                                                   std::string group_uuid)
+    : local_group_index_(vm_index), group_uuid_(group_uuid) {}
+
+Result<void> DisplayRingBufferManager::CreateLocalDisplayBuffer(
+    int vm_index, int display_index, int display_width, int display_height) {
+  auto buffer_key = std::make_pair(vm_index, display_index);
+
+  if (!display_buffer_cache_.contains(buffer_key)) {
+    std::string shmem_name = MakeLayerName(display_index);
+
+    auto shm_buffer = CF_EXPECT(DisplayRingBuffer::Create(
+        shmem_name, RingBufferMemorySize(display_width, display_height)));
+    std::uint8_t* shmem_local_display = (std::uint8_t*)shm_buffer->GetAddress();
+
+    // Here we coerce the IPC buffer into having a header with metadata
+    // containing DisplayRingBufferHeader struct.  Then copy the values over
+    // so that the metadata is initialized correctly. This allows any process
+    // to remotely understand the ringbuffer state properly, to obtain the size
+    // and compute valid frame addresses for reading / writing frame data.
+    DisplayRingBufferHeader* dbi =
+        (DisplayRingBufferHeader*)shmem_local_display;
+    dbi->set(display_width, display_height, 4, 0);
+
+    display_buffer_cache_[buffer_key] = std::move(shm_buffer);
+  }
+  return {};
+}
+
+std::uint8_t* DisplayRingBufferManager::WriteFrame(int vm_index,
+                                                   int display_index,
+                                                   std::uint8_t* frame_data,
+                                                   int size) {
+  auto buffer_key = std::make_pair(vm_index, display_index);
+  if (display_buffer_cache_.contains(buffer_key)) {
+    return display_buffer_cache_[buffer_key]->WriteNextFrame(frame_data, size);
+  }
+  // It's possible to request a write to buffer that doesn't yet exist.
+  return nullptr;
+}
+
+std::uint8_t* DisplayRingBufferManager::ReadFrame(int vm_index,
+                                                  int display_index,
+                                                  int frame_width,
+                                                  int frame_height) {
+  auto buffer_key = std::make_pair(vm_index, display_index);
+
+  // If this buffer was read successfully in the past, that valid pointer is
+  // returned from the cache
+  if (!display_buffer_cache_.contains(buffer_key)) {
+    // Since no cache found, next step is to request from OS to map a new IPC
+    // buffer. It may not yet exist so we want this method to only cache if it
+    // is a non-null pointer, to retrigger this logic continually every request.
+    // Once the buffer exists the pointer would become non-null
+
+    std::string shmem_name = MakeLayerName(display_index, vm_index);
+    std::optional<std::unique_ptr<DisplayRingBuffer>> shmem_buffer =
+        DisplayRingBuffer::ShmemGet(
+            shmem_name.c_str(),
+            RingBufferMemorySize(frame_width, frame_height));
+
+    if (shmem_buffer.has_value() && shmem_buffer.value()->GetAddress()) {
+      display_buffer_cache_[buffer_key] = std::move(shmem_buffer.value());
+    } else {
+      return nullptr;
+    }
+  }
+
+  return display_buffer_cache_[buffer_key]->CurrentFrame();
+}
+
+std::string DisplayRingBufferManager::MakeLayerName(int display_index,
+                                                    int vm_index) {
+  if (vm_index == -1) {
+    vm_index = local_group_index_;
+  }
+  return std::format("/cf_shmem_display_{}_{}_{}", vm_index, display_index,
+                     group_uuid_);
+}
+
+}  // end namespace cuttlefish
\ No newline at end of file
diff --git a/host/libs/screen_connector/ring_buffer_manager.h b/host/libs/screen_connector/ring_buffer_manager.h
new file mode 100644
index 000000000..9b605737a
--- /dev/null
+++ b/host/libs/screen_connector/ring_buffer_manager.h
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
+#pragma once
+
+#include <map>
+
+#include "common/libs/fs/shared_fd.h"
+#include "common/libs/utils/result.h"
+
+namespace cuttlefish {
+
+// This header is allocated / placed at start of IPC ringbuffer. Intention of
+// elements here is to allow to compute the valid read/write address for
+// current frame from an external process.
+struct DisplayRingBufferHeader {
+  volatile std::uint32_t display_width_;
+  volatile std::uint32_t display_height_;
+  volatile std::uint32_t bpp_;
+  std::atomic<std::uint32_t> last_valid_frame_index_;
+
+  void set(std::uint32_t w, std::uint32_t h, std::uint32_t bpp,
+           std::uint32_t index);
+};
+
+class DisplayRingBuffer {
+ public:
+  ~DisplayRingBuffer();
+  static Result<std::unique_ptr<DisplayRingBuffer>> Create(
+      const std::string& name, int size);
+  // Allowing optional in the case the buffer doesn't yet exist.
+  static std::optional<std::unique_ptr<DisplayRingBuffer>> ShmemGet(
+      const std::string& name, int size);
+
+  void* GetAddress();
+
+  std::uint8_t* WriteNextFrame(std::uint8_t* frame_data, int size);
+  std::uint8_t* CurrentFrame();
+  std::uint8_t* ComputeFrameAddressForIndex(std::uint32_t index);
+
+ private:
+  DisplayRingBuffer(void* addr, std::string name, bool owned, ScopedMMap shm);
+
+  DisplayRingBufferHeader* header_;
+  void* addr_;
+  std::string name_;
+  bool owned_;
+  ScopedMMap shm_;
+};
+
+class DisplayRingBufferManager {
+ public:
+  DisplayRingBufferManager(int vm_index, std::string group_uuid);
+  Result<void> CreateLocalDisplayBuffer(int vm_index, int display_index,
+                                        int display_width, int display_height);
+  std::uint8_t* WriteFrame(int vm_index, int display_index,
+                           std::uint8_t* frame_data, int size);
+  std::uint8_t* ReadFrame(int vm_index, int display_index, int frame_width,
+                          int frame_height);
+
+ private:
+  std::string MakeLayerName(int display_index, int vm_index = -1);
+  int local_group_index_;  // Index of the current process in the cluster of VMs
+  std::string group_uuid_;  // Unique identifier for entire VM cluster
+  // All IPC buffers are cached here for speed, to prevent OS from
+  // continually remapping RAM every read/write request.
+  std::map<std::pair<int, int>, std::unique_ptr<DisplayRingBuffer>>
+      display_buffer_cache_;
+};
+
+}  // namespace cuttlefish
\ No newline at end of file
diff --git a/host/libs/screen_connector/screen_connector.h b/host/libs/screen_connector/screen_connector.h
index f9e8be97a..2d9b3429f 100644
--- a/host/libs/screen_connector/screen_connector.h
+++ b/host/libs/screen_connector/screen_connector.h
@@ -74,6 +74,7 @@ class ScreenConnector : public ScreenConnectorInfo,
         cuttlefish::kGpuModeGfxstream,
         cuttlefish::kGpuModeGfxstreamGuestAngle,
         cuttlefish::kGpuModeGfxstreamGuestAngleHostSwiftShader,
+        cuttlefish::kGpuModeGfxstreamGuestAngleHostLavapipe,
         cuttlefish::kGpuModeGuestSwiftshader};
     if (!Contains(valid_gpu_modes, instance.gpu_mode())) {
       LOG(FATAL) << "Invalid gpu mode: " << instance.gpu_mode();
@@ -111,22 +112,30 @@ class ScreenConnector : public ScreenConnectorInfo,
         [this](std::uint32_t display_number, std::uint32_t frame_w,
                std::uint32_t frame_h, std::uint32_t frame_fourcc_format,
                std::uint32_t frame_stride_bytes, std::uint8_t* frame_bytes) {
-          const bool is_confui_mode = host_mode_ctrl_.IsConfirmatioUiMode();
-          if (is_confui_mode) {
-            return;
-          }
+          InjectFrame(display_number, frame_w, frame_h, frame_fourcc_format,
+                      frame_stride_bytes, frame_bytes);
+        });
+  }
 
-          ProcessedFrameType processed_frame;
+  void InjectFrame(std::uint32_t display_number, std::uint32_t frame_w,
+                   std::uint32_t frame_h, std::uint32_t frame_fourcc_format,
+                   std::uint32_t frame_stride_bytes,
+                   std::uint8_t* frame_bytes) {
+    const bool is_confui_mode = host_mode_ctrl_.IsConfirmatioUiMode();
+    if (is_confui_mode) {
+      return;
+    }
 
-          {
-            std::lock_guard<std::mutex> lock(streamer_callback_mutex_);
-            callback_from_streamer_(display_number, frame_w, frame_h,
-                                    frame_fourcc_format, frame_stride_bytes,
-                                    frame_bytes, processed_frame);
-          }
+    ProcessedFrameType processed_frame;
 
-          sc_frame_multiplexer_.PushToAndroidQueue(std::move(processed_frame));
-        });
+    {
+      std::lock_guard<std::mutex> lock(streamer_callback_mutex_);
+      callback_from_streamer_(display_number, frame_w, frame_h,
+                              frame_fourcc_format, frame_stride_bytes,
+                              frame_bytes, processed_frame);
+    }
+
+    sc_frame_multiplexer_.PushToAndroidQueue(std::move(processed_frame));
   }
 
   bool IsCallbackSet() const override {
diff --git a/host/libs/vm_manager/Android.bp b/host/libs/vm_manager/Android.bp
index ca6632979..23a399f24 100644
--- a/host/libs/vm_manager/Android.bp
+++ b/host/libs/vm_manager/Android.bp
@@ -22,6 +22,7 @@ cc_library {
     srcs: [
         "crosvm_builder.cpp",
         "crosvm_cpu.cpp",
+        "crosvm_display_controller.cpp",
         "crosvm_manager.cpp",
         "gem5_manager.cpp",
         "host_configuration.cpp",
diff --git a/host/libs/vm_manager/crosvm_builder.cpp b/host/libs/vm_manager/crosvm_builder.cpp
index efb51c682..72abd101f 100644
--- a/host/libs/vm_manager/crosvm_builder.cpp
+++ b/host/libs/vm_manager/crosvm_builder.cpp
@@ -36,10 +36,11 @@ std::string MacCrosvmArgument(std::optional<std::string_view> mac) {
 }
 
 std::string PciCrosvmArgument(std::optional<pci::Address> pci) {
-  return pci.has_value() ? fmt::format(",pci-address={}", pci.value().Id()) : "";
+  return pci.has_value() ? fmt::format(",pci-address={}", pci.value().Id())
+                         : "";
 }
 
-}
+}  // namespace
 
 CrosvmBuilder::CrosvmBuilder() : command_("crosvm") {}
 
@@ -97,21 +98,28 @@ void CrosvmBuilder::AddCpus(size_t cpus) {
   command_.AddParameter("--cpus=", cpus);
 }
 
-// TODO: b/243198718 - switch to virtio-console
 void CrosvmBuilder::AddHvcSink() {
-  command_.AddParameter(
-      "--serial=hardware=legacy-virtio-console,num=", ++hvc_num_, ",type=sink");
+  command_.AddParameter("--serial=hardware=virtio-console,num=", ++hvc_num_,
+                        ",type=sink");
 }
 void CrosvmBuilder::AddHvcReadOnly(const std::string& output, bool console) {
-  command_.AddParameter(
-      "--serial=hardware=legacy-virtio-console,num=", ++hvc_num_,
-      ",type=file,path=", output, console ? ",console=true" : "");
+  command_.AddParameter("--serial=hardware=virtio-console,num=", ++hvc_num_,
+                        ",type=file,path=", output,
+                        console ? ",console=true" : "");
 }
 void CrosvmBuilder::AddHvcReadWrite(const std::string& output,
                                     const std::string& input) {
+  command_.AddParameter("--serial=hardware=virtio-console,num=", ++hvc_num_,
+                        ",type=file,path=", output, ",input=", input);
+}
+void CrosvmBuilder::AddHvcSocket(const std::string& socket) {
   command_.AddParameter(
-      "--serial=hardware=legacy-virtio-console,num=", ++hvc_num_,
-      ",type=file,path=", output, ",input=", input);
+      "--serial=hardware=virtio-console,num=", ++hvc_num_,
+      ",type=unix-stream,input-unix-stream=true,path=", socket);
+}
+
+void CrosvmBuilder::AddKvmPath(const std::string& path) {
+  command_.AddParameter("--hypervisor=kvm[device=", path, "]");
 }
 
 void CrosvmBuilder::AddReadOnlyDisk(const std::string& path) {
@@ -150,9 +158,15 @@ void CrosvmBuilder::AddTap(const std::string& tap_name,
   command_.AddParameter("--net=tap-name=", tap_name, MacCrosvmArgument(mac),
                         PciCrosvmArgument(pci));
 }
-
 #endif
 
+void CrosvmBuilder::AddVhostUser(const std::string& type,
+                                 const std::string& socket_path,
+                                 int max_queue_size) {
+  command_.AddParameter("--vhost-user=type=", type, ",socket=", socket_path,
+                        ",max-queue-size=", max_queue_size);
+}
+
 int CrosvmBuilder::HvcNum() { return hvc_num_; }
 
 Command& CrosvmBuilder::Cmd() { return command_; }
diff --git a/host/libs/vm_manager/crosvm_builder.h b/host/libs/vm_manager/crosvm_builder.h
index 3e1aef9cf..9f03b20f3 100644
--- a/host/libs/vm_manager/crosvm_builder.h
+++ b/host/libs/vm_manager/crosvm_builder.h
@@ -42,6 +42,9 @@ class CrosvmBuilder {
   void AddHvcSink();
   void AddHvcReadOnly(const std::string& output, bool console = false);
   void AddHvcReadWrite(const std::string& output, const std::string& input);
+  void AddHvcSocket(const std::string& socket);
+
+  void AddKvmPath(const std::string& path);
 
   void AddReadOnlyDisk(const std::string& path);
   void AddReadWriteDisk(const std::string& path);
@@ -58,6 +61,15 @@ class CrosvmBuilder {
               std::optional<std::string_view> mac = std::nullopt,
               const std::optional<pci::Address>& pci = std::nullopt);
 #endif
+  // Adds a vhost-user device to the crosvm command.
+  // The max_queue_size parameter represents the maximum number of buffers the
+  // virtqueues can hold at a given time and must be a power of 2. It must be
+  // large enough to avoid dropping buffers during peak usage but not so large
+  // that it consumes excesive amounts of guest RAM. Most sources recommend a
+  // value between 256 and 1024, suggesting to start with 256 when in doubt and
+  // increase as needed for performance.
+  void AddVhostUser(const std::string& type, const std::string& socket_path,
+                    int max_queue_size = 256);
 
   int HvcNum();
 
diff --git a/host/libs/vm_manager/crosvm_cpu.cpp b/host/libs/vm_manager/crosvm_cpu.cpp
index 8facd5544..ebd67cdea 100644
--- a/host/libs/vm_manager/crosvm_cpu.cpp
+++ b/host/libs/vm_manager/crosvm_cpu.cpp
@@ -28,11 +28,11 @@ namespace cuttlefish {
 namespace {
 
 std::string SerializeFreqDomains(
-    const std::map<std::string, std::vector<int>>& freq_domains) {
+    const std::map<int, std::vector<int>>& freq_domains) {
   std::stringstream freq_domain_arg;
   bool first_vector = true;
 
-  for (const std::pair<std::string, std::vector<int>>& pair : freq_domains) {
+  for (const std::pair<int, std::vector<int>>& pair : freq_domains) {
     if (!first_vector) {
       freq_domain_arg << ",";
     }
@@ -50,9 +50,10 @@ Result<std::vector<std::string>> CrosvmCpuArguments(
     const Json::Value& vcpu_config_json) {
   std::vector<std::string> cpu_arguments;
 
-  std::map<std::string, std::vector<int>> freq_domains;
+  std::map<int, std::vector<int>> freq_domains;
   std::string affinity_arg = "--cpu-affinity=";
   std::string capacity_arg = "--cpu-capacity=";
+  std::string ipc_ratio_arg = "--cpu-ipc-ratio=";
   std::string frequencies_arg = "--cpu-frequencies-khz=";
   std::string cgroup_path_arg = "--vcpu-cgroup-path=";
   std::string freq_domain_arg;
@@ -71,6 +72,7 @@ Result<std::vector<std::string>> CrosvmCpuArguments(
   for (size_t i = 0; i < cpus; i++) {
     if (i != 0) {
       capacity_arg += ",";
+      ipc_ratio_arg += ",";
       affinity_arg += ":";
       frequencies_arg += ";";
     }
@@ -82,20 +84,20 @@ Result<std::vector<std::string>> CrosvmCpuArguments(
     const Json::Value cpu_json = CF_EXPECT(
         GetValue<Json::Value>(cpus_json, {cpu}), "Missing vCPU config!");
 
-    const std::string affinity =
-        CF_EXPECT(GetValue<std::string>(cpu_json, {"affinity"}));
+    const int affinity = CF_EXPECT(GetValue<int>(cpu_json, {"affinity"}));
     std::string affine_arg = fmt::format("{}={}", i, affinity);
 
     const std::string freqs =
         CF_EXPECT(GetValue<std::string>(cpu_json, {"frequencies"}));
     std::string freq_arg = fmt::format("{}={}", i, freqs);
 
-    const std::string capacity =
-        CF_EXPECT(GetValue<std::string>(cpu_json, {"capacity"}));
+    const int capacity = CF_EXPECT(GetValue<int>(cpu_json, {"capacity"}));
     std::string cap_arg = fmt::format("{}={}", i, capacity);
 
-    const std::string domain =
-        CF_EXPECT(GetValue<std::string>(cpu_json, {"freq_domain"}));
+    const int cpu_ipc_ratio = CF_EXPECT(GetValue<int>(cpu_json, {"ipc_ratio"}));
+    std::string ipc_arg = fmt::format("{}={}", i, cpu_ipc_ratio);
+
+    const int domain = CF_EXPECT(GetValue<int>(cpu_json, {"freq_domain"}));
 
     freq_domains[domain].push_back(i);
 
@@ -104,12 +106,14 @@ Result<std::vector<std::string>> CrosvmCpuArguments(
     capacity_arg += cap_arg;
     affinity_arg += affine_arg;
     frequencies_arg += freq_arg;
+    ipc_ratio_arg += ipc_arg;
 
     cpu_arguments.emplace_back(std::move(cpu_cluster));
   }
 
   cpu_arguments.emplace_back(std::move(affinity_arg));
   cpu_arguments.emplace_back(std::move(capacity_arg));
+  cpu_arguments.emplace_back(std::move(ipc_ratio_arg));
   cpu_arguments.emplace_back(std::move(frequencies_arg));
   cpu_arguments.emplace_back(std::move(cgroup_path_arg));
   cpu_arguments.emplace_back("--virt-cpufreq-upstream");
diff --git a/host/libs/vm_manager/crosvm_display_controller.cpp b/host/libs/vm_manager/crosvm_display_controller.cpp
new file mode 100644
index 000000000..91c419ff3
--- /dev/null
+++ b/host/libs/vm_manager/crosvm_display_controller.cpp
@@ -0,0 +1,120 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "host/libs/vm_manager/crosvm_display_controller.h"
+
+#include <android-base/logging.h>
+#include <cstddef>
+#include <iostream>
+#include <string>
+#include <vector>
+#include "common/libs/utils/result.h"
+#include "common/libs/utils/subprocess.h"
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+namespace vm_manager {
+
+Result<CrosvmDisplayController> GetCrosvmDisplayController() {
+  auto config = CuttlefishConfig::Get();
+  if (!config) {
+    return CF_ERR("Failed to get Cuttlefish config.");
+  }
+  auto vm_manager = config->vm_manager();
+  if (vm_manager != VmmMode::kCrosvm) {
+    LOG(ERROR) << "Expected vm_manager is kCrosvm but " << vm_manager;
+    return CF_ERR(
+        "CrosvmDisplayController is only available when VmmMode is kCrosvm");
+  }
+  return CrosvmDisplayController(config);
+}
+
+Result<int> CrosvmDisplayController::Add(
+    const int instance_num,
+    const std::vector<CuttlefishConfig::DisplayConfig>& display_configs) const {
+  std::vector<std::string> command_args;
+  command_args.push_back("add-displays");
+
+  for (const auto& display_config : display_configs) {
+    const std::string w = std::to_string(display_config.width);
+    const std::string h = std::to_string(display_config.height);
+    const std::string dpi = std::to_string(display_config.dpi);
+    const std::string rr = std::to_string(display_config.refresh_rate_hz);
+
+    const std::string add_display_flag =
+        "--gpu-display=" + android::base::Join(
+                               std::vector<std::string>{
+                                   "mode=windowed[" + w + "," + h + "]",
+                                   "dpi=[" + dpi + "," + dpi + "]",
+                                   "refresh-rate=" + rr,
+                               },
+                               ",");
+
+    command_args.push_back(add_display_flag);
+  }
+
+  return RunCrosvmDisplayCommand(instance_num, command_args, NULL);
+}
+
+Result<int> CrosvmDisplayController::Remove(
+    const int instance_num, const std::vector<std::string> display_ids) const {
+  std::vector<std::string> command_args;
+  command_args.push_back("remove-displays");
+
+  for (const auto& display_id : display_ids) {
+    command_args.push_back("--display-id=" + display_id);
+  }
+
+  return RunCrosvmDisplayCommand(instance_num, command_args, NULL);
+}
+
+Result<std::string> CrosvmDisplayController::List(const int instance_num) {
+  std::string out;
+  CF_EXPECT(RunCrosvmDisplayCommand(instance_num, {"list-displays"}, &out));
+  return out;
+}
+
+Result<int> CrosvmDisplayController::RunCrosvmDisplayCommand(
+    const int instance_num, const std::vector<std::string>& args,
+    std::string* stdout_str) const {
+  // TODO(b/260649774): Consistent executable API for selecting an instance
+  const CuttlefishConfig::InstanceSpecific instance =
+      config_->ForInstance(instance_num);
+
+  const std::string crosvm_binary_path = instance.crosvm_binary();
+  const std::string crosvm_control_path = instance.CrosvmSocketPath();
+
+  Command command(crosvm_binary_path);
+  command.AddParameter("gpu");
+  for (const std::string& arg : args) {
+    command.AddParameter(arg);
+  }
+  command.AddParameter(crosvm_control_path);
+
+  std::string err;
+  auto ret = RunWithManagedStdio(std::move(command), NULL, stdout_str, &err);
+  if (ret != 0) {
+    LOG(ERROR) << "Failed to run crosvm display command: ret code: " << ret
+               << "\n"
+               << err << std::endl;
+    return CF_ERRF("Failed to run crosvm display command: ret code: {}", ret);
+  }
+
+  return 0;
+}
+
+}  // namespace vm_manager
+}  // namespace cuttlefish
diff --git a/host/libs/vm_manager/crosvm_display_controller.h b/host/libs/vm_manager/crosvm_display_controller.h
new file mode 100644
index 000000000..b567d3d6e
--- /dev/null
+++ b/host/libs/vm_manager/crosvm_display_controller.h
@@ -0,0 +1,45 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include "common/libs/utils/result.h"
+#include "host/libs/config/cuttlefish_config.h"
+
+namespace cuttlefish {
+namespace vm_manager {
+
+class CrosvmDisplayController {
+ public:
+  CrosvmDisplayController(const CuttlefishConfig* config) : config_(config) {};
+  Result<int> Add(const int instance_num,
+                  const std::vector<CuttlefishConfig::DisplayConfig>&
+                      display_configs) const;
+  Result<int> Remove(const int instance_num,
+                     const std::vector<std::string> display_ids) const;
+  Result<std::string> List(const int instance_num);
+
+ private:
+  const CuttlefishConfig* config_;
+  Result<int> RunCrosvmDisplayCommand(const int instance_num,
+                                      const std::vector<std::string>& args,
+                                      std::string* stdout_str) const;
+};
+
+Result<CrosvmDisplayController> GetCrosvmDisplayController();
+
+}  // namespace vm_manager
+}  // namespace cuttlefish
diff --git a/host/libs/vm_manager/crosvm_manager.cpp b/host/libs/vm_manager/crosvm_manager.cpp
index 7932f16fc..9548c4560 100644
--- a/host/libs/vm_manager/crosvm_manager.cpp
+++ b/host/libs/vm_manager/crosvm_manager.cpp
@@ -34,9 +34,10 @@
 #include <json/json.h>
 #include <vulkan/vulkan.h>
 
-#include "common/libs/utils/environment.h"
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/json.h"
+#include "common/libs/utils/known_paths.h"
 #include "common/libs/utils/network.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
@@ -98,10 +99,12 @@ CrosvmManager::ConfigureGraphics(
   } else if (instance.gpu_mode() == kGpuModeGfxstream ||
              instance.gpu_mode() == kGpuModeGfxstreamGuestAngle ||
              instance.gpu_mode() ==
-                 kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+                 kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+             instance.gpu_mode() == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     const bool uses_angle =
         instance.gpu_mode() == kGpuModeGfxstreamGuestAngle ||
-        instance.gpu_mode() == kGpuModeGfxstreamGuestAngleHostSwiftShader;
+        instance.gpu_mode() == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+        instance.gpu_mode() == kGpuModeGfxstreamGuestAngleHostLavapipe;
 
     const std::string gles_impl = uses_angle ? "angle" : "emulation";
 
@@ -142,6 +145,20 @@ CrosvmManager::ConfigureGraphics(
     return CF_ERR("Unknown GPU mode " << instance.gpu_mode());
   }
 
+  if (auto r = instance.guest_hwui_renderer();
+      r != GuestHwuiRenderer::kUnknown) {
+    bootconfig_args["androidboot.hardware.guest_hwui_renderer"] = ToString(r);
+  }
+
+  const auto guest_renderer_preload = instance.guest_renderer_preload();
+  if (guest_renderer_preload == GuestRendererPreload::kEnabled) {
+    bootconfig_args["androidboot.hardware.guest_disable_renderer_preload"] =
+        "false";
+  } else if (guest_renderer_preload == GuestRendererPreload::kDisabled) {
+    bootconfig_args["androidboot.hardware.guest_disable_renderer_preload"] =
+        "true";
+  }
+
   if (!instance.gpu_angle_feature_overrides_enabled().empty()) {
     bootconfig_args["androidboot.hardware.angle_feature_overrides_enabled"] =
         instance.gpu_angle_feature_overrides_enabled();
@@ -198,6 +215,18 @@ Result<std::string> HostSwiftShaderIcdPathForArch() {
                                        << " for finding SwiftShader ICD.");
 }
 
+Result<std::string> HostLavapipeIcdPathForArch() {
+  switch (HostArch()) {
+    case Arch::X86:
+    case Arch::X86_64:
+      return HostUsrSharePath("vulkan/icd.d/vk_lavapipe_icd.cf.json");
+    default:
+      break;
+  }
+  return CF_ERR("Unhandled host arch " << HostArchStr()
+                                       << " for finding SwiftShader ICD.");
+}
+
 Result<void> MaybeConfigureVulkanIcd(const CuttlefishConfig& config,
                                      Command* command) {
   const auto& gpu_mode = config.ForDefaultInstance().gpu_mode();
@@ -210,6 +239,39 @@ Result<void> MaybeConfigureVulkanIcd(const CuttlefishConfig& config,
                                     swiftshader_icd_json_path);
     command->AddEnvironmentVariable("VK_ICD_FILENAMES",
                                     swiftshader_icd_json_path);
+  } else if (gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
+    const std::string lavapipe_icd_json_path =
+        CF_EXPECT(HostLavapipeIcdPathForArch());
+
+    // See https://github.com/KhronosGroup/Vulkan-Loader.
+    command->AddEnvironmentVariable("VK_DRIVER_FILES", lavapipe_icd_json_path);
+    command->AddEnvironmentVariable("VK_ICD_FILENAMES", lavapipe_icd_json_path);
+  }
+
+  return {};
+}
+
+// b/277618912: glibc's aarch64 memcpy uses unaligned accesses which seems to
+// cause SIGBUS errors on some Nvidia GPUs.
+Result<void> MaybeConfigureMemOverridesLibrary(const CuttlefishConfig& config,
+                                               Command* command) {
+  const auto& gpu_mode = config.ForDefaultInstance().gpu_mode();
+  const bool is_gpu_mode_accelerated =
+      (gpu_mode == kGpuModeDrmVirgl || gpu_mode == kGpuModeGfxstream ||
+       gpu_mode == kGpuModeGfxstreamGuestAngle);
+
+  const bool is_arm64 = HostArch() == Arch::Arm64;
+
+  if (is_gpu_mode_accelerated && is_arm64) {
+    LOG(INFO)
+        << "Enabling libmem_overrides.so preload to work around b/277618912.";
+
+    const std::string mem_override_lib_path =
+        HostBinaryPath("aarch64-linux-gnu/libmem_overrides.so");
+    CF_EXPECT(FileExists(mem_override_lib_path),
+              "Failed to find " << mem_override_lib_path);
+
+    command->AddEnvironmentVariable("LD_PRELOAD", mem_override_lib_path);
   }
 
   return {};
@@ -271,7 +333,8 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   CF_EXPECT(
       gpu_mode == kGpuModeGfxstream ||
           gpu_mode == kGpuModeGfxstreamGuestAngle ||
-          gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader,
+          gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+          gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe,
       "GPU mode " << gpu_mode << " not yet supported with vhost user gpu.");
 
   const std::string gpu_pci_address =
@@ -285,7 +348,8 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
     gpu_params_json["egl"] = true;
     gpu_params_json["gles"] = true;
   } else if (gpu_mode == kGpuModeGfxstreamGuestAngle ||
-             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     gpu_params_json["context-types"] = "gfxstream-vulkan";
     gpu_params_json["egl"] = false;
     gpu_params_json["gles"] = false;
@@ -350,6 +414,8 @@ Result<VhostUserDeviceCommands> BuildVhostUserGpu(
   gpu_device_cmd.Cmd().AddParameter("--params");
   gpu_device_cmd.Cmd().AddParameter(ToSingleLineString(gpu_params_json));
 
+  CF_EXPECT(MaybeConfigureMemOverridesLibrary(config, &gpu_device_cmd.Cmd()));
+
   CF_EXPECT(MaybeConfigureVulkanIcd(config, &gpu_device_cmd.Cmd()));
 
   gpu_device_cmd.Cmd().RedirectStdIO(Subprocess::StdIOChannel::kStdOut,
@@ -370,7 +436,8 @@ Result<void> ConfigureGpu(const CuttlefishConfig& config, Command* crosvm_cmd) {
 
   const std::string gles_string =
       gpu_mode == kGpuModeGfxstreamGuestAngle ||
-              gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader
+              gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+              gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe
           ? ",gles=false"
           : ",gles=true";
 
@@ -412,8 +479,9 @@ Result<void> ConfigureGpu(const CuttlefishConfig& config, Command* crosvm_cmd) {
           },
           ","));
     }
-    gpu_displays_string =
-        "displays=[[" + android::base::Join(gpu_displays_strings, "],[") + "]],";
+    gpu_displays_string = "displays=[[" +
+                          android::base::Join(gpu_displays_strings, "],[") +
+                          "]],";
 
     crosvm_cmd->AddParameter("--wayland-sock=", instance.frames_socket_path());
   }
@@ -431,7 +499,8 @@ Result<void> ConfigureGpu(const CuttlefishConfig& config, Command* crosvm_cmd) {
         "context-types=gfxstream-gles:gfxstream-vulkan:gfxstream-composer",
         gpu_common_3d_string);
   } else if (gpu_mode == kGpuModeGfxstreamGuestAngle ||
-             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     crosvm_cmd->AddParameter(
         "--gpu=", gpu_displays_string,
         "context-types=gfxstream-vulkan:gfxstream-composer",
@@ -492,6 +561,10 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   crosvm_cmd.AddControlSocket(instance.CrosvmSocketPath(),
                               instance.crosvm_binary());
 
+  if (!config.kvm_path().empty()) {
+    crosvm_cmd.AddKvmPath(config.kvm_path());
+  }
+
   if (!instance.smt()) {
     crosvm_cmd.Cmd().AddParameter("--no-smt");
   }
@@ -529,6 +602,14 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.Cmd().AddParameter("--no-rng");
   }
 
+  if (instance.crosvm_simple_media_device()) {
+    crosvm_cmd.Cmd().AddParameter("--simple-media-device");
+  }
+
+  if (!instance.crosvm_v4l2_proxy().empty()) {
+    crosvm_cmd.Cmd().AddParameter("--v4l2-proxy=", instance.crosvm_v4l2_proxy());
+  }
+
   if (instance.gdb_port() > 0) {
     CF_EXPECT(instance.cpus() == 1, "CPUs must be 1 for crosvm gdb mode");
     crosvm_cmd.Cmd().AddParameter("--gdb=", instance.gdb_port());
@@ -592,61 +673,41 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
   }
 
   if (instance.enable_webrtc()) {
-    bool is_chromeos =
-        instance.boot_flow() ==
-            CuttlefishConfig::InstanceSpecific::BootFlow::ChromeOs ||
-        instance.boot_flow() ==
-            CuttlefishConfig::InstanceSpecific::BootFlow::ChromeOsDisk;
-    auto touch_type_parameter =
-        is_chromeos ? "single-touch" : "multi-touch";
-
     auto display_configs = instance.display_configs();
     CF_EXPECT(display_configs.size() >= 1);
 
-    int touch_idx = 0;
-    for (auto& display_config : display_configs) {
-      crosvm_cmd.Cmd().AddParameter(
-          "--input=", touch_type_parameter, "[path=",
-          instance.touch_socket_path(touch_idx++),
-          ",width=", display_config.width,
-          ",height=", display_config.height, "]");
-    }
-    auto touchpad_configs = instance.touchpad_configs();
-    for (int i = 0; i < touchpad_configs.size(); ++i) {
-      auto touchpad_config = touchpad_configs[i];
-      crosvm_cmd.Cmd().AddParameter(
-          "--input=", touch_type_parameter, "[path=",
-          instance.touch_socket_path(touch_idx++),
-          ",width=", touchpad_config.width,
-          ",height=", touchpad_config.height,
-          ",name=", kTouchpadDefaultPrefix, i, "]");
+    const int display_cnt = instance.display_configs().size();
+    const int touchpad_cnt = instance.touchpad_configs().size();
+    const int total_touch_cnt = display_cnt + touchpad_cnt;
+    for (int touch_idx = 0; touch_idx < total_touch_cnt; ++touch_idx) {
+      crosvm_cmd.AddVhostUser("input", instance.touch_socket_path(touch_idx));
     }
     if (instance.enable_mouse()) {
-      crosvm_cmd.Cmd().AddParameter(
-          "--input=mouse[path=", instance.mouse_socket_path(), "]");
+      crosvm_cmd.AddVhostUser("input", instance.mouse_socket_path());
     }
-    crosvm_cmd.Cmd().AddParameter("--input=rotary[path=",
-                                  instance.rotary_socket_path(), "]");
-    crosvm_cmd.Cmd().AddParameter("--input=keyboard[path=",
-                                  instance.keyboard_socket_path(), "]");
-    crosvm_cmd.Cmd().AddParameter("--input=switches[path=",
-                                  instance.switches_socket_path(), "]");
+    crosvm_cmd.AddVhostUser("input", instance.rotary_socket_path());
+    crosvm_cmd.AddVhostUser("input", instance.keyboard_socket_path());
+    crosvm_cmd.AddVhostUser("input", instance.switches_socket_path());
   }
 
   // GPU capture can only support named files and not file descriptors due to
   // having to pass arguments to crosvm via a wrapper script.
 #ifdef __linux__
-  if (!gpu_capture_enabled) {
+  if (instance.enable_tap_devices() && !gpu_capture_enabled) {
     // The PCI ordering of tap devices is important. Make sure any change here
     // is reflected in ethprime u-boot variable.
-    // TODO(b/218364216, b/322862402): Crosvm occupies 32 PCI devices first and only then uses PCI
-    // functions which may break order. The final solution is going to be a PCI allocation strategy
-    // that will guarantee the ordering. For now, hardcode PCI network devices to unoccupied
-    // functions.
-    const pci::Address mobile_pci = pci::Address(0, VmManager::kNetPciDeviceNum, 1);
-    const pci::Address ethernet_pci = pci::Address(0, VmManager::kNetPciDeviceNum, 2);
-    crosvm_cmd.AddTap(instance.mobile_tap_name(), instance.mobile_mac(), mobile_pci);
-    crosvm_cmd.AddTap(instance.ethernet_tap_name(), instance.ethernet_mac(), ethernet_pci);
+    // TODO(b/218364216, b/322862402): Crosvm occupies 32 PCI devices first and
+    // only then uses PCI functions which may break order. The final solution is
+    // going to be a PCI allocation strategy that will guarantee the ordering.
+    // For now, hardcode PCI network devices to unoccupied functions.
+    const pci::Address mobile_pci =
+        pci::Address(0, VmManager::kNetPciDeviceNum, 1);
+    const pci::Address ethernet_pci =
+        pci::Address(0, VmManager::kNetPciDeviceNum, 2);
+    crosvm_cmd.AddTap(instance.mobile_tap_name(), instance.mobile_mac(),
+                      mobile_pci);
+    crosvm_cmd.AddTap(instance.ethernet_tap_name(), instance.ethernet_mac(),
+                      ethernet_pci);
 
     if (!config.virtio_mac80211_hwsim() && environment.enable_wifi()) {
       crosvm_cmd.AddTap(instance.wifi_tap_name());
@@ -682,12 +743,14 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
 
   if (instance.vsock_guest_cid() >= 2) {
     if (instance.vhost_user_vsock()) {
-      auto param =
-          fmt::format("/tmp/vsock_{}_{}/vhost.socket,max-queue-size=256",
-                      instance.vsock_guest_cid(), std::to_string(getuid()));
-      crosvm_cmd.Cmd().AddParameter("--vhost-user=vsock,socket=", param);
+      crosvm_cmd.AddVhostUser(
+          "vsock", fmt::format("{}/vsock_{}_{}/vhost.socket", TempDir(),
+                               instance.vsock_guest_cid(), getuid()));
+    } else if (config.vhost_vsock_path().empty()) {
+      crosvm_cmd.Cmd().AddParameter("--vsock=cid=", instance.vsock_guest_cid());
     } else {
-      crosvm_cmd.Cmd().AddParameter("--cid=", instance.vsock_guest_cid());
+      crosvm_cmd.Cmd().AddParameter("--vsock=cid=", instance.vsock_guest_cid(),
+                                    ",device=", config.vhost_vsock_path());
     }
   }
 
@@ -822,7 +885,6 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.AddHvcSink();
   }
 
-
   // /dev/hvc13 = sensors
   crosvm_cmd.AddHvcReadWrite(
       instance.PerInstanceInternalPath("sensors_fifo_vm.out"),
@@ -846,6 +908,13 @@ Result<std::vector<MonitorCommand>> CrosvmManager::StartCommands(
     crosvm_cmd.AddHvcSink();
   }
 
+  // /dev/hvc16 = Ti50 TPM FIFO
+  if (!instance.ti50_emulator().empty()) {
+    crosvm_cmd.AddHvcSocket(instance.PerInstancePath("direct_tpm_fifo"));
+  } else {
+    crosvm_cmd.AddHvcSink();
+  }
+
   for (auto i = 0; i < VmManager::kMaxDisks - disk_num; i++) {
     crosvm_cmd.AddHvcSink();
   }
diff --git a/host/libs/vm_manager/gem5_manager.cpp b/host/libs/vm_manager/gem5_manager.cpp
index 78f3e8044..080141624 100644
--- a/host/libs/vm_manager/gem5_manager.cpp
+++ b/host/libs/vm_manager/gem5_manager.cpp
@@ -33,13 +33,12 @@
 #include <android-base/logging.h>
 #include <vulkan/vulkan.h>
 
+#include "common/libs/utils/environment.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/cuttlefish_config.h"
 
-using cuttlefish::StringFromEnv;
-
 namespace cuttlefish {
 namespace vm_manager {
 namespace {
diff --git a/host/libs/vm_manager/qemu_manager.cpp b/host/libs/vm_manager/qemu_manager.cpp
index 4855cee6c..1908bd2b6 100644
--- a/host/libs/vm_manager/qemu_manager.cpp
+++ b/host/libs/vm_manager/qemu_manager.cpp
@@ -35,6 +35,7 @@
 #include <android-base/logging.h>
 #include <vulkan/vulkan.h>
 
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/files.h"
 #include "common/libs/utils/result.h"
 #include "common/libs/utils/subprocess.h"
@@ -42,6 +43,10 @@
 #include "host/libs/config/cuttlefish_config.h"
 #include "host/libs/vm_manager/vhost_user.h"
 
+// This is the QEMU default, but set it explicitly just in case it
+// changes upstream
+static const int kMaxSerialPorts = 31;
+
 namespace cuttlefish {
 namespace vm_manager {
 namespace {
@@ -154,10 +159,12 @@ QemuManager::ConfigureGraphics(
     };
   } else if (gpu_mode == kGpuModeGfxstream ||
              gpu_mode == kGpuModeGfxstreamGuestAngle ||
-             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     const bool uses_angle =
         gpu_mode == kGpuModeGfxstreamGuestAngle ||
-        gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader;
+        gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+        gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe;
     const std::string gles_impl = uses_angle ? "angle" : "emulation";
     const std::string gltransport =
         (instance.guest_android_version() == "11.0.0") ? "virtio-gpu-pipe"
@@ -350,28 +357,46 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   qemu_cmd.AddParameter("-name");
   qemu_cmd.AddParameter("guest=", instance.instance_name(), ",debug-threads=on");
 
-  qemu_cmd.AddParameter("-machine");
   std::string machine = is_x86 ? "pc,nvdimm=on" : "virt";
+  if (is_arm) {
+    if (IsHostCompatible(arch_)) {
+      machine += ",gic-version=3";
+    } else {
+      // QEMU doesn't support GICv3 with TCG yet
+      machine += ",gic-version=2";
+      CF_EXPECT(instance.cpus() <= 8, "CPUs must be no more than 8 with GICv2");
+    }
+  }
+  if (instance.mte()) {
+    machine += ",mte=on";
+  }
+  qemu_cmd.AddParameter("-machine");
+  qemu_cmd.AddParameter(machine, ",usb=off,dump-guest-core=off,memory-backend=vm_ram");
+
   if (IsHostCompatible(arch_)) {
+    qemu_cmd.AddParameter("-accel");
+    std::string accel;
 #ifdef __linux__
-    machine += ",accel=kvm";
+    accel = "kvm";
+    if (!config.kvm_path().empty()) {
+      accel += ",device=" + config.kvm_path();
+    }
 #elif defined(__APPLE__)
-    machine += ",accel=hvf";
+    accel = "hvf";
 #else
 #error "Unknown OS"
 #endif
-    if (is_arm) {
-      machine += ",gic-version=3";
-    }
-  } else if (is_arm) {
-    // QEMU doesn't support GICv3 with TCG yet
-    machine += ",gic-version=2";
-    CF_EXPECT(instance.cpus() <= 8, "CPUs must be no more than 8 with GICv2");
-  }
-  if (instance.mte()) {
-    machine += ",mte=on";
+    qemu_cmd.AddParameter(accel);
   }
-  qemu_cmd.AddParameter(machine, ",usb=off,dump-guest-core=off");
+
+  // Memory must be backed by a file for vhost-user to work correctly, otherwise
+  // qemu doesn't send the memory mappings necessary for the backend to access
+  // the virtqueues.
+  qemu_cmd.AddParameter("-object");
+  qemu_cmd.AddParameter("memory-backend-file,size=", instance.memory_mb(), "M",
+                        ",prealloc=on,share=on,mem-path=",
+                        instance.PerInstanceInternalPath("qemu.mem"),
+                        ",id=vm_ram");
 
   qemu_cmd.AddParameter("-m");
   auto maxmem = instance.memory_mb() +
@@ -428,7 +453,8 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   } else if (gpu_mode == kGpuModeGuestSwiftshader ||
              gpu_mode == kGpuModeGfxstream ||
              gpu_mode == kGpuModeGfxstreamGuestAngle ||
-             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+             gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
     qemu_cmd.AddParameter("-vnc");
     qemu_cmd.AddParameter("127.0.0.1:", instance.qemu_vnc_server_port());
   } else {
@@ -453,7 +479,8 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
           "virtio-gpu-rutabaga,x-gfxstream-gles=on,gfxstream-vulkan=on,"
           "x-gfxstream-composer=on,hostmem=256M";
     } else if (gpu_mode == kGpuModeGfxstreamGuestAngle ||
-               gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader) {
+               gpu_mode == kGpuModeGfxstreamGuestAngleHostSwiftShader ||
+               gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
       gpu_device =
           "virtio-gpu-rutabaga,gfxstream-vulkan=on,"
           "x-gfxstream-composer=on,hostmem=256M";
@@ -466,6 +493,12 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
                                         swiftshader_icd_json);
         qemu_cmd.AddEnvironmentVariable("VK_ICD_FILENAMES",
                                         swiftshader_icd_json);
+      } else if (gpu_mode == kGpuModeGfxstreamGuestAngleHostLavapipe) {
+        // See https://github.com/KhronosGroup/Vulkan-Loader.
+        const std::string lavapipe_icd_json =
+            HostUsrSharePath("vulkan/icd.d/vk_lavapipe_icd.cf.json");
+        qemu_cmd.AddEnvironmentVariable("VK_DRIVER_FILES", lavapipe_icd_json);
+        qemu_cmd.AddEnvironmentVariable("VK_ICD_FILENAMES", lavapipe_icd_json);
       }
     }
 
@@ -488,7 +521,8 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
 
   qemu_cmd.AddParameter("-device");
   qemu_cmd.AddParameter(
-      "virtio-serial-pci-non-transitional,max_ports=31,id=virtio-serial");
+      "virtio-serial-pci-non-transitional,max_ports=", kMaxSerialPorts,
+      ",id=virtio-serial");
 
   // /dev/hvc0 = kernel console
   // If kernel log is enabled, the virtio-console port will be specified as
@@ -590,10 +624,8 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
     add_hvc_sink();
   }
 
-  // sensors_fifo_vm.{in/out} are created along with the streamer process,
-  // which is not created w/ QEMU.
   // /dev/hvc13 = sensors
-  add_hvc_sink();
+  add_hvc(instance.PerInstanceInternalPath("sensors_fifo_vm"));
 
   // /dev/hvc14 = MCU CONTROL
   if (instance.mcu()["control"]["type"].asString() == "serial") {
@@ -613,6 +645,15 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
     add_hvc_sink();
   }
 
+  // /dev/hvc16 = Ti50 TPM FIFO
+  if (!instance.ti50_emulator().empty()) {
+    // TODO
+    // add_hvc_socket(instance.PerInstancePath("direct_tpm_fifo"));
+    add_hvc_sink();
+  } else {
+    add_hvc_sink();
+  }
+
   auto disk_num = instance.virtual_disk_paths().size();
 
   for (auto i = 0; i < VmManager::kMaxDisks - disk_num; i++) {
@@ -710,6 +751,8 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   qemu_cmd.AddParameter("virtio-rng-pci-non-transitional,rng=objrng0,id=rng0,",
                         "max-bytes=1024,period=2000");
 
+  // TODO: Use the vhost-user devices instead if/when qemu is accessed via
+  // webRTC instead of VNC.
   qemu_cmd.AddParameter("-device");
   qemu_cmd.AddParameter("virtio-mouse-pci,disable-legacy=on");
 
@@ -717,40 +760,53 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
   qemu_cmd.AddParameter("virtio-keyboard-pci,disable-legacy=on");
 
   // device padding for unsupported "switches" input
+  qemu_cmd.AddParameter("-chardev");
+  qemu_cmd.AddParameter("socket,path=", instance.switches_socket_path(), ",id=switches0");
   qemu_cmd.AddParameter("-device");
-  qemu_cmd.AddParameter("virtio-keyboard-pci,disable-legacy=on");
+  qemu_cmd.AddParameter("vhost-user-input-pci,chardev=switches0");
+
+  qemu_cmd.AddParameter("-chardev");
+  qemu_cmd.AddParameter("socket,path=", instance.rotary_socket_path(), ",id=rotary0");
+  qemu_cmd.AddParameter("-device");
+  qemu_cmd.AddParameter("vhost-user-input-pci,chardev=rotary0");
 
   auto vhost_net = instance.vhost_net() ? ",vhost=on" : "";
 
   qemu_cmd.AddParameter("-device");
   qemu_cmd.AddParameter("virtio-balloon-pci-non-transitional,id=balloon0");
 
+  bool has_network_devices = false;
   switch (instance.external_network_mode()) {
     case ExternalNetworkMode::kTap:
-      qemu_cmd.AddParameter("-netdev");
-      qemu_cmd.AddParameter(
-          "tap,id=hostnet0,ifname=", instance.mobile_tap_name(),
-          ",script=no,downscript=no", vhost_net);
-
-      qemu_cmd.AddParameter("-netdev");
-      qemu_cmd.AddParameter(
-          "tap,id=hostnet1,ifname=", instance.ethernet_tap_name(),
-          ",script=no,downscript=no", vhost_net);
+      if (instance.enable_tap_devices()) {
+        has_network_devices = true;
+        qemu_cmd.AddParameter("-netdev");
+        qemu_cmd.AddParameter(
+            "tap,id=hostnet0,ifname=", instance.mobile_tap_name(),
+            ",script=no,downscript=no", vhost_net);
 
-      if (!config.virtio_mac80211_hwsim()) {
         qemu_cmd.AddParameter("-netdev");
         qemu_cmd.AddParameter(
-            "tap,id=hostnet2,ifname=", instance.wifi_tap_name(),
+            "tap,id=hostnet1,ifname=", instance.ethernet_tap_name(),
             ",script=no,downscript=no", vhost_net);
+
+        if (!config.virtio_mac80211_hwsim()) {
+          qemu_cmd.AddParameter("-netdev");
+          qemu_cmd.AddParameter(
+              "tap,id=hostnet2,ifname=", instance.wifi_tap_name(),
+              ",script=no,downscript=no", vhost_net);
+        }
       }
       break;
     case cuttlefish::ExternalNetworkMode::kSlirp: {
+      has_network_devices = true;
       const std::string net =
           fmt::format("{}/{}", instance.ril_ipaddr(), instance.ril_prefixlen());
       const std::string& host = instance.ril_gateway();
       qemu_cmd.AddParameter("-netdev");
       // TODO(schuffelen): `dns` needs to match the first `nameserver` in
-      // `/etc/resolv.conf`. Implement something that generalizes beyond gLinux.
+      // `/etc/resolv.conf`. Implement something that generalizes beyond
+      // gLinux.
       qemu_cmd.AddParameter("user,id=hostnet0,net=", net, ",host=", host,
                             ",dns=127.0.0.1");
 
@@ -768,19 +824,23 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
                      instance.external_network_mode());
   }
 
-  // The ordering of virtio-net devices is important. Make sure any change here
-  // is reflected in ethprime u-boot variable
-  qemu_cmd.AddParameter("-device");
-  qemu_cmd.AddParameter(
-      "virtio-net-pci-non-transitional,netdev=hostnet0,id=net0,mac=",
-      instance.mobile_mac());
-  qemu_cmd.AddParameter("-device");
-  qemu_cmd.AddParameter("virtio-net-pci-non-transitional,netdev=hostnet1,id=net1,mac=",
-                        instance.ethernet_mac());
-  if (!config.virtio_mac80211_hwsim()) {
+  if (has_network_devices) {
+    // The ordering of virtio-net devices is important. Make sure any change
+    // here is reflected in ethprime u-boot variable
     qemu_cmd.AddParameter("-device");
-    qemu_cmd.AddParameter("virtio-net-pci-non-transitional,netdev=hostnet2,id=net2,mac=",
-                          instance.wifi_mac());
+    qemu_cmd.AddParameter(
+        "virtio-net-pci-non-transitional,netdev=hostnet0,id=net0,mac=",
+        instance.mobile_mac());
+    qemu_cmd.AddParameter("-device");
+    qemu_cmd.AddParameter(
+        "virtio-net-pci-non-transitional,netdev=hostnet1,id=net1,mac=",
+        instance.ethernet_mac());
+    if (!config.virtio_mac80211_hwsim()) {
+      qemu_cmd.AddParameter("-device");
+      qemu_cmd.AddParameter(
+          "virtio-net-pci-non-transitional,netdev=hostnet2,id=net2,mac=",
+          instance.wifi_mac());
+    }
   }
 
   if (is_x86 || is_arm) {
@@ -837,6 +897,14 @@ Result<std::vector<MonitorCommand>> QemuManager::StartCommands(
     qemu_cmd.AddParameter("tcp::", instance.gdb_port());
   }
 
+  // After all other devices are added, add some more console sinks
+  // so it doesn't upset any sepolicy, but works around a QEMU warning
+  // when U-Boot probes the ports between kDefaultNumHvcs and
+  // kMaxSerialPorts
+  while (hvc_num < kMaxSerialPorts) {
+    add_hvc_sink();
+  }
+
   commands.emplace_back(std::move(qemu_cmd), true);
   return commands;
 }
diff --git a/host/libs/vm_manager/vm_manager.h b/host/libs/vm_manager/vm_manager.h
index fe6682407..3fa286f31 100644
--- a/host/libs/vm_manager/vm_manager.h
+++ b/host/libs/vm_manager/vm_manager.h
@@ -22,6 +22,7 @@
 
 #include <fruit/fruit.h>
 
+#include "common/libs/utils/architecture.h"
 #include "common/libs/utils/result.h"
 #include "host/libs/config/command_source.h"
 #include "host/libs/config/cuttlefish_config.h"
@@ -62,7 +63,8 @@ class VmManager {
   // - /dev/hvc13 = sensors
   // - /dev/hvc14 = MCU control
   // - /dev/hvc15 = MCU UART
-  static const int kDefaultNumHvcs = 16;
+  // - /dev/hvc16 = Ti50 TPM FIFO
+  static const int kDefaultNumHvcs = 17;
 
   // This is the number of virtual disks (block devices) that should be
   // configured by the VmManager. Related to the description above regarding
diff --git a/host/libs/wayland/Android.bp b/host/libs/wayland/Android.bp
index 74bcb590d..1d12ff589 100644
--- a/host/libs/wayland/Android.bp
+++ b/host/libs/wayland/Android.bp
@@ -39,7 +39,6 @@ cc_library {
         "liblog",
     ],
     static_libs: [
-        "libdrm",
         "libffi",
         "libwayland_crosvm_gpu_display_extension_server_protocols",
         "libwayland_extension_server_protocols",
diff --git a/host/libs/websocket/websocket_server.cpp b/host/libs/websocket/websocket_server.cpp
index f48209b15..91c102b6b 100644
--- a/host/libs/websocket/websocket_server.cpp
+++ b/host/libs/websocket/websocket_server.cpp
@@ -148,7 +148,6 @@ void WebSocketServer::InitializeLwsObjects() {
     dyn_mounts_.push_back({
         .mount_next = nullptr,
         .mountpoint = path.c_str(),
-        .mountpoint_len = static_cast<uint8_t>(path.size()),
         .origin = "__http_polling__",
         .def = nullptr,
         .protocol = nullptr,
@@ -162,6 +161,7 @@ void WebSocketServer::InitializeLwsObjects() {
         .cache_revalidate = 0,
         .cache_intermediaries = 0,
         .origin_protocol = LWSMPRO_CALLBACK,  // dynamic
+        .mountpoint_len = static_cast<uint8_t>(path.size()),
         .basic_auth_login_file = nullptr,
     });
   }
@@ -176,7 +176,6 @@ void WebSocketServer::InitializeLwsObjects() {
   static_mount_ = {
       .mount_next = next_mount,
       .mountpoint = "/",
-      .mountpoint_len = 1,
       .origin = assets_dir_.c_str(),
       .def = "index.html",
       .protocol = nullptr,
@@ -190,6 +189,7 @@ void WebSocketServer::InitializeLwsObjects() {
       .cache_revalidate = 0,
       .cache_intermediaries = 0,
       .origin_protocol = LWSMPRO_FILE,  // files in a dir
+      .mountpoint_len = 1,
       .basic_auth_login_file = nullptr,
   };
 
diff --git a/recovery/Android.bp b/recovery/Android.bp
index ebc8e3fca..2d0f93ce5 100644
--- a/recovery/Android.bp
+++ b/recovery/Android.bp
@@ -25,7 +25,6 @@ cc_library {
         "-Wall",
         "-Werror",
         "-Wextra",
-        "-pedantic",
     ],
     srcs: [
         "recovery_ui.cpp",
diff --git a/shared/BoardConfig.mk b/shared/BoardConfig.mk
index 45d377a6b..056e9456f 100644
--- a/shared/BoardConfig.mk
+++ b/shared/BoardConfig.mk
@@ -19,21 +19,22 @@
 #
 
 # Some targets still require 32 bit, and 6.6 kernels don't support
-# 32 bit devices (Wear, Go, Auto)
+# 32 bit devices
 ifeq (true,$(CLOCKWORK_EMULATOR_PRODUCT))
 TARGET_KERNEL_USE ?= 6.1
 else ifneq (,$(findstring x86_tv,$(PRODUCT_NAME)))
 TARGET_KERNEL_USE ?= 6.1
-else
+else ifneq (,$(findstring _desktop,$(PRODUCT_NAME)))
 TARGET_KERNEL_USE ?= 6.6
+else
+TARGET_KERNEL_USE ?= 6.12
 endif
 
 TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
 
-ifneq (, $(filter $(PRODUCT_NAME),cf_x86_64_desktop))
-# TODO: b/357660371 - cf_arm64_desktop should use the desktop kernel, too
-SYSTEM_DLKM_SRC ?= device/google/cuttlefish_prebuilts/kernel/6.6-x86_64-desktop/system_dlkm
-KERNEL_MODULES_PATH ?= device/google/cuttlefish_prebuilts/kernel/6.6-x86_64-desktop/vendor_dlkm
+ifneq (,$(filter cf_x86_64_desktop cf_arm64_desktop,$(PRODUCT_NAME)))
+SYSTEM_DLKM_SRC ?= device/google/cuttlefish_prebuilts/kernel/6.6-$(TARGET_KERNEL_ARCH)-desktop/system_dlkm
+KERNEL_MODULES_PATH ?= device/google/cuttlefish_prebuilts/kernel/6.6-$(TARGET_KERNEL_ARCH)-desktop/vendor_dlkm
 else
 SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
 KERNEL_MODULES_PATH ?= \
@@ -95,6 +96,11 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_co
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_pci.ko
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(SYSTEM_VIRTIO_PREBUILTS_PATH)/vmw_vsock_virtio_transport.ko
 
+ifneq (,$(findstring auto, $(PRODUCT_NAME)))
+# Support arm64 Cuttlefish on-device deployment
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(KERNEL_MODULES_PATH)/virtio_mmio.ko)
+endif
+
 # GKI >5.15 will have and require virtio_pci_legacy_dev.ko
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(SYSTEM_VIRTIO_PREBUILTS_PATH)/virtio_pci_legacy_dev.ko)
 # GKI >5.10 will have and require virtio_pci_modern_dev.ko
@@ -117,10 +123,7 @@ BOARD_KERNEL_MODULES_16K += $(wildcard kernel/prebuilts/common-modules/virtual-d
 endif
 endif
 
-# TODO(b/170639028): Back up TARGET_NO_BOOTLOADER
-__TARGET_NO_BOOTLOADER := $(TARGET_NO_BOOTLOADER)
 include build/make/target/board/BoardConfigMainlineCommon.mk
-TARGET_NO_BOOTLOADER := $(__TARGET_NO_BOOTLOADER)
 
 # For now modules are only blocked in second stage init.
 # If a module ever needs to blocked in first stage init - add a new blocklist to
@@ -323,7 +326,7 @@ PRODUCT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/sepolicy/produc
 # PRODUCT_PUBLIC_SEPOLICY_DIRS += device/google/cuttlefish/shared/sepolicy/product/public
 # system_ext sepolicy
 SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/sepolicy/system_ext/private
-# SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += device/google/cuttlefish/shared/sepolicy/system_ext/public
+SYSTEM_EXT_PUBLIC_SEPOLICY_DIRS += device/google/cuttlefish/shared/sepolicy/system_ext/public
 
 STAGEFRIGHT_AVCENC_CFLAGS := -DANDROID_GCE
 
@@ -337,7 +340,6 @@ DHCPCD_USE_SCRIPT := yes
 
 TARGET_RECOVERY_PIXEL_FORMAT := ABGR_8888
 TARGET_RECOVERY_UI_LIB := librecovery_ui_cuttlefish
-TARGET_RECOVERY_FSTAB_GENRULE := gen_fstab_cf_f2fs_cts
 
 BOARD_SUPER_PARTITION_SIZE := 7516192768  # 7GiB
 BOARD_SUPER_PARTITION_GROUPS := google_system_dynamic_partitions google_vendor_dynamic_partitions
diff --git a/shared/auto/Android.bp b/shared/auto/Android.bp
index 2bc750507..8ef461566 100644
--- a/shared/auto/Android.bp
+++ b/shared/auto/Android.bp
@@ -1,5 +1,5 @@
 //
-// Copyright (C) 2024 The Android Open Source Project
+// Copyright (C) 2025 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
diff --git a/shared/auto/TEST_MAPPING b/shared/auto/TEST_MAPPING
index 6686d0ef9..a2a79d062 100644
--- a/shared/auto/TEST_MAPPING
+++ b/shared/auto/TEST_MAPPING
@@ -1,7 +1,10 @@
 {
   "auto-presubmit": [
     {
-      "name": "AndroidCarApiTest"
+      "name": "CarHiddenApiTest"
+    },
+    {
+      "name": "CarExtendedApiTest"
     },
     {
       "name": "CarSecurityPermissionTest"
diff --git a/shared/auto/android-info.txt b/shared/auto/android-info.txt
index 1b3dd601b..84393d871 100644
--- a/shared/auto/android-info.txt
+++ b/shared/auto/android-info.txt
@@ -2,3 +2,4 @@ config=auto
 gfxstream=supported
 gfxstream_gl_program_binary_link_status=supported
 vhost_user_vsock=true
+output_audio_streams_count=6
diff --git a/shared/auto/audio/Android.bp b/shared/auto/audio/Android.bp
new file mode 100644
index 000000000..ce3caa3c3
--- /dev/null
+++ b/shared/auto/audio/Android.bp
@@ -0,0 +1,21 @@
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
+soong_namespace {
+    imports: [
+        "frameworks/av/services/audiopolicy/config",
+        "frameworks/av/services/audiopolicy/engineconfigurable/parameter-framework/examples/Car",
+    ],
+}
diff --git a/shared/auto/audio/audio.mk b/shared/auto/audio/audio.mk
new file mode 100644
index 000000000..477902b55
--- /dev/null
+++ b/shared/auto/audio/audio.mk
@@ -0,0 +1,48 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+
+#
+# AudioService
+#
+PRODUCT_PRODUCT_PROPERTIES += \
+    ro.config.vc_call_vol_default=16 \
+    ro.config.media_vol_default=16 \
+    ro.config.alarm_vol_default=16 \
+    ro.config.system_vol_default=16 \
+
+#
+# AudioPolicy
+#
+BOARD_SEPOLICY_DIRS += frameworks/av/services/audiopolicy/engineconfigurable/sepolicy
+
+PRODUCT_PACKAGES += audio_policy_configuration.xml
+
+# Tool used for debug Parameter Framework (only for eng and userdebug builds)
+PRODUCT_PACKAGES_DEBUG += remote-process
+
+#
+# AudioPolicyEngine
+#
+PRODUCT_PACKAGES += audio_policy_engine_configuration.xml
+
+#
+# Audio HAL / AudioEffect HAL
+#
+PRODUCT_PACKAGES += audio_effects_config.xml
+
+#
+# CarService
+#
+PRODUCT_PACKAGES += car_audio_configuration.xml
diff --git a/shared/auto/audio/carservice/Android.bp b/shared/auto/audio/carservice/Android.bp
new file mode 100644
index 000000000..2bc05a16f
--- /dev/null
+++ b/shared/auto/audio/carservice/Android.bp
@@ -0,0 +1,20 @@
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
+prebuilt_etc {
+    name: "car_audio_configuration.xml",
+    vendor: true,
+    src: "car_audio_configuration.xml",
+}
diff --git a/shared/auto/audio/carservice/car_audio_configuration.xml b/shared/auto/audio/carservice/car_audio_configuration.xml
new file mode 100644
index 000000000..e5337d75d
--- /dev/null
+++ b/shared/auto/audio/carservice/car_audio_configuration.xml
@@ -0,0 +1,184 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<!--
+  Defines the audio configuration in a car, including
+    - Audio zones
+    - Zone configurations (in each audio zone)
+    - Volume groups (in each zone configuration)
+    - Context to audio bus mappings (in each volume group)
+  in the car environment.
+-->
+<carAudioConfiguration version="4">
+    <deviceConfigurations>
+        <deviceConfiguration name="useHalDuckingSignals" value="false" />
+        <deviceConfiguration name="useCoreAudioRouting" value="true" />
+        <deviceConfiguration name="useCoreAudioVolume" value="true" />
+        <deviceConfiguration name="useCarVolumeGroupMuting" value="true" />
+    </deviceConfigurations>
+    <activationVolumeConfigs>
+        <activationVolumeConfig name="activation_volume_on_boot_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="90" invocationType="onPlaybackChanged" />
+        </activationVolumeConfig>
+        <activationVolumeConfig name="activation_volume_on_source_changed_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="80" invocationType="onSourceChanged" />
+        </activationVolumeConfig>
+        <activationVolumeConfig name="activation_volume_on_playback_changed_config">
+            <activationVolumeConfigEntry minActivationVolumePercentage="20"
+                maxActivationVolumePercentage="80" />
+        </activationVolumeConfig>
+    </activationVolumeConfigs>
+    <oemContexts>
+        <oemContext name="oem_traffic_announcement">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_ANNOUNCEMENT" />
+                <audioAttribute usage="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"
+                    tags="VX_OEM_TA" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="oem_ipa">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_SAFETY" />
+                <usage value="AUDIO_USAGE_VEHICLE_STATUS" />
+                <audioAttribute usage="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"
+                    tags="VX_OEM_IPA" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="oem_xcall">
+            <audioAttributes>
+                <audioAttribute usage="AUDIO_USAGE_VOICE_COMMUNICATION"
+                    tags="VX_OEM_XCALL" />
+                <usage value="AUDIO_USAGE_EMERGENCY" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="third_party_alternate">
+            <audioAttributes>
+                <audioAttribute usage="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"
+                    tags="VX_OEM_ALTERNATE" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="third_party_auxiliary">
+            <audioAttributes>
+                <audioAttribute usage="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"
+                    tags="VX_OEM_AUXILIARY"/>
+                <audioAttribute usage="AUDIO_USAGE_ASSISTANT"
+                    tags="VX_OEM_AUXILIARY"/>
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="third_party_alert">
+            <audioAttributes>
+                <audioAttribute usage="AUDIO_USAGE_ALARM"
+                    tags="VX_OEM_ALERT" />
+                <audioAttribute usage="AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE"
+                    tags="VX_OEM_ALERT" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="voice_command">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_ASSISTANT"/>
+                <usage value="AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY"/>
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="music">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_MEDIA" />
+                <usage value="AUDIO_USAGE_GAME" />
+                <usage value="AUDIO_USAGE_UNKNOWN"/>
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="nav_guidance">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="ring">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE"/>
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="notification">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_NOTIFICATION" />
+                <usage value="AUDIO_USAGE_NOTIFICATION_EVENT" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="system">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_ASSISTANCE_SONIFICATION" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="alarm">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_ALARM" />
+            </audioAttributes>
+        </oemContext>
+        <oemContext name="voice_call">
+            <audioAttributes>
+                <usage value="AUDIO_USAGE_VOICE_COMMUNICATION" />
+                <usage value="AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING" />
+                <usage value="AUDIO_USAGE_CALL_ASSISTANT" />
+            </audioAttributes>
+        </oemContext>
+       </oemContexts>
+    <zones>
+        <zone isPrimary="true" name="primary zone" audioZoneId="0" occupantZoneId="0">
+            <zoneConfigs>
+                <zoneConfig  name="primary zone config 1" isDefault="true">
+                    <volumeGroups>
+                        <group name="entertainment" activationConfig="activation_volume_on_boot_config">
+                            <device address="BUS00_MEDIA_CARD_0_DEV_0">
+                                <context context="music"/>
+                            </device>
+                        </group>
+                        <group name="navvol" activationConfig="activation_volume_on_source_changed_config">
+                            <device address="BUS01_NAV_GUIDANCE_CARD_0_DEV_1">
+                                <context context="nav_guidance"/>
+                                <context context="oem_ipa"/>
+                                <context context="oem_traffic_announcement"/>
+                            </device>
+                            <device address="BUS02_NOTIFICATION_CARD_0_DEV_2">
+                                <context context="third_party_alternate"/>
+                            </device>
+                        </group>
+                        <group name="sdsvol" activationConfig="activation_volume_on_playback_changed_config">
+                            <device address="BUS04_ASSISTANT_CARD_0_DEV_4">
+                                <context context="voice_command"/>
+                                <context context="third_party_auxiliary"/>
+                            </device>
+                        </group>
+                        <group name="system" activationConfig="activation_volume_on_source_changed_config">
+                            <device address="BUS05_SYSTEM_CARD_0_DEV_5">
+                                <context context="system"/>
+                                <context context="notification"/>
+                            </device>
+                        </group>
+                        <group name="telringvol" activationConfig="activation_volume_on_playback_changed_config">
+                            <device address="BUS03_PHONE_CARD_0_DEV_3">
+                                <context context="voice_call"/>
+                                <context context="oem_xcall"/>
+                                <context context="ring"/>
+                                <context context="alarm"/>
+                                <context context="third_party_alert"/>
+                            </device>
+                        </group>
+                    </volumeGroups>
+                </zoneConfig>
+            </zoneConfigs>
+        </zone>
+    </zones>
+</carAudioConfiguration>
diff --git a/shared/auto/audio/effects/Android.bp b/shared/auto/audio/effects/Android.bp
new file mode 100644
index 000000000..3705a2423
--- /dev/null
+++ b/shared/auto/audio/effects/Android.bp
@@ -0,0 +1,20 @@
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
+prebuilt_etc {
+    name: "audio_effects_config.xml",
+    vendor: true,
+    src: "audio_effects_config.xml",
+}
diff --git a/shared/auto/audio_effects_config.xml b/shared/auto/audio/effects/audio_effects_config.xml
similarity index 97%
rename from shared/auto/audio_effects_config.xml
rename to shared/auto/audio/effects/audio_effects_config.xml
index cadde7d6d..e2c37bd43 100644
--- a/shared/auto/audio_effects_config.xml
+++ b/shared/auto/audio/effects/audio_effects_config.xml
@@ -46,7 +46,6 @@
         <library name="visualizer" path="libvisualizeraidl.so"/>
         <library name="volumesw" path="libvolumesw.so"/>
         <library name="extensioneffect" path="libextensioneffect.so"/>
-        <library name="spatializersw" path="libspatializersw.so"/>
     </libraries>
 
     <!-- list of effects to load.
@@ -87,7 +86,6 @@
         <effect name="volume" library="bundle" uuid="119341a0-8469-11df-81f9-0002a5d5c51b"/>
         <effect name="equalizer" library="bundle" uuid="ce772f20-847d-11df-bb17-0002a5d5c51b"/>
         <effect name="extension_effect" library="extensioneffect" uuid="fa81dd00-588b-11ed-9b6a-0242ac120002" type="fa81de0e-588b-11ed-9b6a-0242ac120002"/>
-        <effect name="spatializer" library="spatializersw" uuid="fa81a880-588b-11ed-9b6a-0242ac120002"/>
     </effects>
 
     <!-- Audio pre processor configurations.
diff --git a/vsoc_x86_only/kernel.mk b/shared/auto/audio/offending_gsi_system.mk
similarity index 74%
rename from vsoc_x86_only/kernel.mk
rename to shared/auto/audio/offending_gsi_system.mk
index 60bf204db..f2e461965 100644
--- a/vsoc_x86_only/kernel.mk
+++ b/shared/auto/audio/offending_gsi_system.mk
@@ -1,5 +1,5 @@
 #
-# Copyright (C) 2020 The Android Open Source Project
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,4 +13,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# This file is deprecated.
+#
+# Any changes vs GSI images should be done here
+#
+PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
+    system/bin/remote-process
diff --git a/shared/auto/audio/policy/Android.bp b/shared/auto/audio/policy/Android.bp
new file mode 100644
index 000000000..396583262
--- /dev/null
+++ b/shared/auto/audio/policy/Android.bp
@@ -0,0 +1,222 @@
+//
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
+/////////////////////////////////////////////////////////////
+//
+// Audio Policy Configuration files
+//
+//////////////////////////////////////////////////////////////
+
+prebuilt_etc {
+    name: "audio_policy_configuration.xml",
+    vendor: true,
+    src: ":audio_policy_configuration_top_file",
+    required: [
+        "audio_policy_volumes.xml",
+        "bluetooth_with_le_audio_policy_configuration_7_0.xml",
+        "default_volume_tables.xml",
+        "primary_audio_policy_configuration.xml",
+        "r_submix_audio_policy_configuration.xml",
+        "surround_sound_configuration_5_0.xml",
+    ],
+}
+
+filegroup {
+    name: "primary_audio_policy_configuration",
+    srcs: [
+        "primary_audio_policy_configuration.xml",
+    ],
+}
+
+prebuilt_etc {
+    name: "primary_audio_policy_configuration.xml",
+    src: ":primary_audio_policy_configuration",
+    vendor: true,
+}
+
+prebuilt_etc {
+    name: "r_submix_audio_policy_configuration.xml",
+    vendor: true,
+    src: ":r_submix_audio_policy_configuration",
+}
+
+prebuilt_etc {
+    name: "audio_policy_volumes.xml",
+    vendor: true,
+    src: ":audio_policy_volumes",
+}
+
+prebuilt_etc {
+    name: "default_volume_tables.xml",
+    vendor: true,
+    src: ":default_volume_tables",
+}
+
+prebuilt_etc {
+    name: "surround_sound_configuration_5_0.xml",
+    vendor: true,
+    src: ":surround_sound_configuration_5_0",
+}
+
+prebuilt_etc {
+    name: "bluetooth_with_le_audio_policy_configuration_7_0.xml",
+    vendor: true,
+    src: ":bluetooth_with_le_audio_policy_configuration_7_0",
+}
+
+//////////////////////////////////////////////////////////////
+//
+// Audio Policy Engine Configuration files
+//
+//////////////////////////////////////////////////////////////
+
+//
+// Generate audio_policy_engine criterion type file => provides device addresses criterion type
+//
+filegroup {
+    name: "audio_policy_configuration_files",
+    srcs: [
+        ":audio_policy_volumes",
+        ":bluetooth_with_le_audio_policy_configuration_7_0",
+        ":default_volume_tables",
+        ":primary_audio_policy_configuration",
+        ":r_submix_audio_policy_configuration",
+        ":surround_sound_configuration_5_0",
+    ],
+}
+
+filegroup {
+    name: "audio_policy_configuration_top_file",
+    srcs: ["audio_policy_configuration.xml"],
+}
+
+genrule {
+    name: "audio_policy_engine_criterion_types",
+    defaults: ["capbuildpolicycriteriontypesrule"],
+    srcs: [
+        ":audio_policy_configuration_files",
+        ":audio_policy_configuration_top_file",
+    ],
+}
+
+prebuilt_etc {
+    name: "audio_policy_engine_criterion_types.xml",
+    vendor: true,
+    src: ":audio_policy_engine_criterion_types",
+}
+
+filegroup {
+    name: "audio_policy_engine_configuration",
+    srcs: [
+        "engine/config/audio_policy_engine_configuration.xml",
+    ],
+}
+
+filegroup {
+    name: "audio_policy_engine_configuration_files",
+    srcs: [
+        ":audio_policy_engine_configuration",
+        ":audio_policy_engine_criteria",
+        ":audio_policy_engine_criterion_types",
+        "engine/config/audio_policy_engine_default_volumes.xml",
+        "engine/config/audio_policy_engine_product_strategies.xml",
+        "engine/config/audio_policy_engine_volumes.xml",
+    ],
+}
+
+prebuilt_etc {
+    name: "audio_policy_engine_configuration.xml",
+    vendor: true,
+    src: ":audio_policy_engine_configuration",
+    required: [
+        "audio_policy_engine_criteria.xml",
+        "audio_policy_engine_criterion_types.xml",
+        "audio_policy_engine_default_volumes.xml",
+        "audio_policy_engine_product_strategies.xml",
+        "audio_policy_engine_volumes.xml",
+        "parameter-framework.policy",
+    ],
+}
+
+prebuilt_etc {
+    name: "audio_policy_engine_product_strategies.xml",
+    vendor: true,
+    src: "engine/config/audio_policy_engine_product_strategies.xml",
+}
+
+prebuilt_etc {
+    name: "audio_policy_engine_volumes.xml",
+    vendor: true,
+    src: "engine/config/audio_policy_engine_volumes.xml",
+}
+
+prebuilt_etc {
+    name: "audio_policy_engine_default_volumes.xml",
+    vendor: true,
+    src: "engine/config/audio_policy_engine_default_volumes.xml",
+}
+
+//////////////////////////////////////////////////////////////
+//
+// Audio Policy Parameter Framework
+//
+//////////////////////////////////////////////////////////////
+
+//
+// Generate Audio Policy Parameter Framework Configurable Domains
+//
+filegroup {
+    name: "edd_files",
+    srcs: [
+        "engine/parameter-framework/Settings/device_for_input_source.pfw",
+        "engine/parameter-framework/Settings/device_for_product_strategies.pfw",
+        "engine/parameter-framework/Settings/volumes.pfw",
+    ],
+}
+
+// This is for Settings generation, must use socket port, so userdebug version is required
+filegroup {
+    name: "audio_policy_pfw_toplevel",
+    srcs: [":ParameterFrameworkConfigurationCapSrc"],
+}
+
+filegroup {
+    name: "audio_policy_pfw_structure_files",
+    srcs: [
+        ":CapClass",
+        ":CapSubsystem",
+        ":buildaidlcommontypesstructure_gen",
+        ":cap_product_strategies_structure",
+    ],
+}
+
+genrule {
+    name: "domaingeneratorpolicyrule_gen",
+    defaults: ["domaingeneratorpolicyrule"],
+    srcs: [
+        ":audio_policy_engine_criterion_types",
+        ":audio_policy_pfw_structure_files",
+        ":audio_policy_pfw_toplevel",
+        ":edd_files",
+    ],
+}
+
+prebuilt_etc {
+    name: "parameter-framework.policy",
+    filename_from_src: true,
+    vendor: true,
+    src: ":domaingeneratorpolicyrule_gen",
+    sub_dir: "parameter-framework/Settings/Policy",
+}
diff --git a/shared/auto/audio/policy/audio_policy_configuration.xml b/shared/auto/audio/policy/audio_policy_configuration.xml
new file mode 100644
index 000000000..8acf27e4d
--- /dev/null
+++ b/shared/auto/audio/policy/audio_policy_configuration.xml
@@ -0,0 +1,49 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<audioPolicyConfiguration version="1.0" xmlns:xi="http://www.w3.org/2001/XInclude">
+    <!-- version section contains a “version” tag in the form “major.minor” e.g. version=”1.0” -->
+
+    <modules>
+        <!-- Primary Audio HAL -->
+        <xi:include href="primary_audio_policy_configuration.xml"/>
+
+        <!-- Remote Submix Audio HAL -->
+        <xi:include href="r_submix_audio_policy_configuration.xml"/>
+
+        <!-- Bluetooth Audio HAL -->
+        <xi:include href="bluetooth_with_le_audio_policy_configuration_7_0.xml"/>
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
+    <!-- Surround Sound configuration -->
+
+    <xi:include href="surround_sound_configuration_5_0.xml"/>
+
+    <!-- End of Surround Sound configuration -->
+
+</audioPolicyConfiguration>
diff --git a/shared/auto/audio/policy/engine/config/audio_policy_engine_configuration.xml b/shared/auto/audio/policy/engine/config/audio_policy_engine_configuration.xml
new file mode 100644
index 000000000..c1e1f25d5
--- /dev/null
+++ b/shared/auto/audio/policy/engine/config/audio_policy_engine_configuration.xml
@@ -0,0 +1,43 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<!--
+     This is used to defined the configurable audio policy engine including;
+          audio_policy_engine_product_strategies.xml -
+               Defines the grouping of audio attributes and volume mapping
+          audio_policy_engine_criterion_types.xml -
+               Defines the different criteria types available to the engine
+          audio_policy_engine_criteria.xml -
+               Defines the actual criteria available to the engine
+          audio_policy_engine_volumes.xml -
+               Defines the volume groups which also includes the mapping to
+               different volume tables used for each device type
+          audio_policy_engine_default_volumes.xm -
+               Defines the volume curves mapping index to volume gains used
+               to manage the audio system
+-->
+
+
+<configuration version="1.0" xmlns:xi="http://www.w3.org/2001/XInclude">
+
+    <xi:include href="audio_policy_engine_product_strategies.xml"/>
+    <xi:include href="audio_policy_engine_criterion_types.xml"/>
+    <xi:include href="audio_policy_engine_criteria.xml"/>
+    <xi:include href="audio_policy_engine_volumes.xml"/>
+    <xi:include href="audio_policy_engine_default_volumes.xml"/>
+
+</configuration>
+
diff --git a/shared/auto/audio/policy/engine/config/audio_policy_engine_default_volumes.xml b/shared/auto/audio/policy/engine/config/audio_policy_engine_default_volumes.xml
new file mode 100644
index 000000000..743e09b6d
--- /dev/null
+++ b/shared/auto/audio/policy/engine/config/audio_policy_engine_default_volumes.xml
@@ -0,0 +1,103 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<!-- Default Volume Tables included by Audio Policy Configuration file -->
+<!-- Full Default Volume table for all device category -->
+<volumes>
+    <reference name="DEFAULT_VOLUME_STEPS_CURVE">
+    <!-- Default Volume Steps Curve -->
+        <point>0,-8400</point>
+        <point>1,-7827</point>
+        <point>2,-7225</point>
+        <point>3,-6429</point>
+        <point>4,-5827</point>
+        <point>5,-5366</point>
+        <point>6,-5103</point>
+        <point>7,-4844</point>
+        <point>8,-4645</point>
+        <point>9,-4446</point>
+        <point>10,-4242</point>
+        <point>11,-4088</point>
+        <point>12,-3871</point>
+        <point>13,-3683</point>
+        <point>14,-3592</point>
+        <point>15,-3397</point>
+        <point>16,-3297</point>
+        <point>17,-3195</point>
+        <point>18,-3100</point>
+        <point>19,-2902</point>
+        <point>20,-2800</point>
+        <point>21,-2707</point>
+        <point>22,-2505</point>
+        <point>23,-2405</point>
+        <point>24,-2307</point>
+        <point>25,-2106</point>
+        <point>26,-1991</point>
+        <point>27,-1892</point>
+        <point>28,-1704</point>
+        <point>29,-1598</point>
+        <point>30,-1505</point>
+        <point>31,-1396</point>
+        <point>32,-1203</point>
+        <point>33,-1096</point>
+        <point>34,-1010</point>
+        <point>35,-811</point>
+        <point>36,-702</point>
+        <point>37,-605</point>
+        <point>38,-405</point>
+        <point>39,-301</point>
+        <point>40,-211</point>
+    </reference>
+    <reference name="NOT_MUTABLE_VOLUME_STEPS_CURVE_5TO40">
+    <!-- Base on DEFAULT_VOLUME_STEPS_CURVE : Volume 36 Steps Curve -->
+        <point>0,-5366</point>
+        <point>1,-5103</point>
+        <point>2,-4844</point>
+        <point>3,-4645</point>
+        <point>4,-4446</point>
+        <point>5,-4242</point>
+        <point>6,-4088</point>
+        <point>7,-3871</point>
+        <point>8,-3683</point>
+        <point>9,-3592</point>
+        <point>10,-3397</point>
+        <point>11,-3297</point>
+        <point>12,-3195</point>
+        <point>13,-3100</point>
+        <point>14,-2902</point>
+        <point>15,-2800</point>
+        <point>16,-2707</point>
+        <point>17,-2505</point>
+        <point>18,-2405</point>
+        <point>19,-2307</point>
+        <point>20,-2106</point>
+        <point>21,-1991</point>
+        <point>22,-1892</point>
+        <point>23,-1704</point>
+        <point>24,-1598</point>
+        <point>25,-1505</point>
+        <point>26,-1396</point>
+        <point>27,-1203</point>
+        <point>28,-1096</point>
+        <point>29,-1010</point>
+        <point>30,-811</point>
+        <point>31,-702</point>
+        <point>32,-605</point>
+        <point>33,-405</point>
+        <point>34,-301</point>
+        <point>35,-211</point>
+    </reference>
+</volumes>
diff --git a/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml b/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml
new file mode 100644
index 000000000..824083cc8
--- /dev/null
+++ b/shared/auto/audio/policy/engine/config/audio_policy_engine_product_strategies.xml
@@ -0,0 +1,158 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<ProductStrategies>
+    <ProductStrategy name="oem_traffic_announcement" id="1000">
+        <AttributesGroup volumeGroup="navvol">
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"/>
+                <Bundle key="VX_OEM" value="TA"/>
+            </Attributes>
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ANNOUNCEMENT"/>
+            </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="oem_ipa" id="1001">
+        <AttributesGroup volumeGroup="navvol">
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"/>
+                <Bundle key="VX_OEM" value="IPA"/>
+            </Attributes>
+            <Attributes>
+                <Usage value="AUDIO_USAGE_SAFETY"/>
+            </Attributes>
+            <Attributes>
+                <Usage value="AUDIO_USAGE_VEHICLE_STATUS"/>
+            </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="oem_xcall" id="1002">
+        <AttributesGroup volumeGroup="telringvol">
+            <Attributes>
+                <Usage value="AUDIO_USAGE_VOICE_COMMUNICATION"/>
+                <Bundle key="VX_OEM" value="XCALL"/>
+            </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_EMERGENCY"/> </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="third_party_alternate" id="1003">
+        <AttributesGroup volumeGroup="navvol">
+            <Usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"/>
+            <Bundle key="VX_OEM" value="ALTERNATE"/>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="third_party_auxiliary" id="1004">
+        <AttributesGroup volumeGroup="sdsvol">
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"/>
+                <Bundle key="VX_OEM" value="AUXILIARY"/>
+            </Attributes>
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ASSISTANT"/>
+                <Bundle key="VX_OEM" value="AUXILIARY"/>
+            </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="third_party_alert" id="1005">
+        <AttributesGroup volumeGroup="telringvol">
+            <Attributes>
+                <Usage value="AUDIO_USAGE_ALARM"/>
+                <Bundle key="VX_OEM" value="ALERT"/>
+            </Attributes>
+            <Attributes>
+                <Usage value="AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE"/>
+                <Bundle key="VX_OEM" value="ALERT"/>
+            </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="voice_command" id="1006">
+        <AttributesGroup streamType="AUDIO_STREAM_ASSISTANT" volumeGroup="sdsvol">
+            <Attributes> <Usage value="AUDIO_USAGE_ASSISTANT"/> </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY"/> </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="voice_call" id="1007">
+        <AttributesGroup streamType="AUDIO_STREAM_VOICE_CALL" volumeGroup="telringvol">
+            <Attributes> <Usage value="AUDIO_USAGE_VOICE_COMMUNICATION"/> </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_VOICE_COMMUNICATION_SIGNALLING"/> </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_CALL_ASSISTANT"/> </Attributes>
+        </AttributesGroup>
+        <AttributesGroup streamType="AUDIO_STREAM_BLUETOOTH_SCO" volumeGroup="telringvol">
+            <Attributes> <Flags value="AUDIO_FLAG_SCO"/> </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="music" id="1008">
+        <AttributesGroup streamType="AUDIO_STREAM_MUSIC" volumeGroup="entertainment">
+            <Attributes> <Usage value="AUDIO_USAGE_MEDIA"/> </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_GAME"/> </Attributes>
+            <!-- Default product strategy has empty attributes -->
+            <Attributes></Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="nav_guidance" id="1009">
+        <AttributesGroup volumeGroup="navvol">
+            <Usage value="AUDIO_USAGE_ASSISTANCE_NAVIGATION_GUIDANCE"/>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="alarm" id="1010">
+        <AttributesGroup streamType="AUDIO_STREAM_ALARM" volumeGroup="telringvol">
+            <Usage value="AUDIO_USAGE_ALARM"/>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="ring" id="1011">
+        <AttributesGroup streamType="AUDIO_STREAM_RING" volumeGroup="telringvol">
+            <Usage value="AUDIO_USAGE_NOTIFICATION_TELEPHONY_RINGTONE"/>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="notification" id="1012">
+        <AttributesGroup streamType="AUDIO_STREAM_NOTIFICATION" volumeGroup="system">
+            <Attributes> <Usage value="AUDIO_USAGE_NOTIFICATION"/> </Attributes>
+            <Attributes> <Usage value="AUDIO_USAGE_NOTIFICATION_EVENT"/> </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="system" id="1013">
+        <AttributesGroup streamType="AUDIO_STREAM_SYSTEM" volumeGroup="system">
+            <Usage value="AUDIO_USAGE_ASSISTANCE_SONIFICATION"/>
+        </AttributesGroup>
+    </ProductStrategy>
+
+    <ProductStrategy name="tts" id="1014">
+        <!-- TTS stream MUST BE MANAGED OUTSIDE default product strategy if NO DEDICATED OUTPUT
+             for TTS, otherwise when beacon happens, default strategy is ... muted.
+             If it is media, it is annoying... -->
+        <AttributesGroup streamType="AUDIO_STREAM_TTS" volumeGroup="tts">
+            <Attributes> <Flags value="AUDIO_FLAG_BEACON"/> </Attributes>
+        </AttributesGroup>
+        <AttributesGroup streamType="AUDIO_STREAM_ACCESSIBILITY" volumeGroup="tts">
+            <Attributes> <Usage value="AUDIO_USAGE_ASSISTANCE_ACCESSIBILITY"/> </Attributes>
+        </AttributesGroup>
+    </ProductStrategy>
+
+</ProductStrategies>
diff --git a/shared/auto/audio/policy/engine/config/audio_policy_engine_volumes.xml b/shared/auto/audio/policy/engine/config/audio_policy_engine_volumes.xml
new file mode 100644
index 000000000..899ea7b35
--- /dev/null
+++ b/shared/auto/audio/policy/engine/config/audio_policy_engine_volumes.xml
@@ -0,0 +1,62 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<volumeGroups>
+    <volumeGroup>
+        <name>entertainment</name>
+        <indexMin>0</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="DEFAULT_VOLUME_STEPS_CURVE"/>
+        <volume deviceCategory="DEVICE_CATEGORY_HEADSET" ref="DEFAULT_VOLUME_STEPS_CURVE"/>
+    </volumeGroup>
+
+    <volumeGroup>
+        <name>navvol</name>
+        <indexMin>5</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="NOT_MUTABLE_VOLUME_STEPS_CURVE_5TO40"/>
+    </volumeGroup>
+
+    <volumeGroup>
+        <name>sdsvol</name>
+        <indexMin>5</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="NOT_MUTABLE_VOLUME_STEPS_CURVE_5TO40"/>
+    </volumeGroup>
+
+    <volumeGroup>
+        <name>system</name>
+        <indexMin>0</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="DEFAULT_VOLUME_STEPS_CURVE"/>
+    </volumeGroup>
+
+    <volumeGroup>
+        <name>telringvol</name>
+        <indexMin>5</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="NOT_MUTABLE_VOLUME_STEPS_CURVE_5TO40"/>
+    </volumeGroup>
+
+    <volumeGroup>
+        <name>tts</name>
+        <indexMin>0</indexMin>
+        <indexMax>40</indexMax>
+        <volume deviceCategory="DEVICE_CATEGORY_SPEAKER" ref="DEFAULT_VOLUME_STEPS_CURVE"/>
+    </volumeGroup>
+
+</volumeGroups>
+
diff --git a/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_input_source.pfw b/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_input_source.pfw
new file mode 100644
index 000000000..4607ed163
--- /dev/null
+++ b/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_input_source.pfw
@@ -0,0 +1,402 @@
+supDomain: DeviceForInputSource
+	domain: DefaultAndMic
+		conf: A2dp
+			AvailableInputDevices Includes BLUETOOTH_A2DP
+
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 1
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 1
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+		conf: WiredHeadset
+			AvailableInputDevices Includes WIRED_HEADSET
+
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 1
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 1
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+		conf: UsbDevice
+			AvailableInputDevices Includes USB_DEVICE
+
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 1
+					builtin_mic = 0
+					stub = 0
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 1
+					builtin_mic = 0
+					stub = 0
+
+		conf: BuiltinMic
+			AvailableInputDevices Includes BUILTIN_MIC
+
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources
+				component: default/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: mic/applicable_input_device/mask/
+					bluetooth_a2dp = 0
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+	domain: VoiceUplinkAndVoiceDownlinkAndVoiceCall
+		conf: VoiceCall
+			AvailableInputDevices Includes TELEPHONY_RX
+
+			component: /Policy/policy/input_sources
+				voice_downlink/applicable_input_device/mask/telephony_rx = 1
+				voice_call/applicable_input_device/mask/telephony_rx = 1
+				voice_uplink/applicable_input_device/mask/telephony_rx = 1
+				voice_downlink/applicable_input_device/mask/stub = 0
+				voice_call/applicable_input_device/mask/stub = 0
+				voice_uplink/applicable_input_device/mask/stub = 0
+
+		conf: Stub
+			AvailableInputDevices Includes BUILTIN_MIC
+
+			component: /Policy/policy/input_sources
+				voice_downlink/applicable_input_device/mask/telephony_rx = 0
+				voice_call/applicable_input_device/mask/telephony_rx = 0
+				voice_uplink/applicable_input_device/mask/telephony_rx = 0
+				voice_downlink/applicable_input_device/mask/stub = 1
+				voice_call/applicable_input_device/mask/stub = 1
+				voice_uplink/applicable_input_device/mask/stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources
+				voice_downlink/applicable_input_device/mask/telephony_rx = 0
+				voice_call/applicable_input_device/mask/telephony_rx = 0
+				voice_uplink/applicable_input_device/mask/telephony_rx = 0
+				voice_downlink/applicable_input_device/mask/stub = 0
+				voice_call/applicable_input_device/mask/stub = 0
+				voice_uplink/applicable_input_device/mask/stub = 0
+
+	domain: Camcorder
+		conf: BackMic
+			AvailableInputDevices Includes BACK_MIC
+
+			component: /Policy/policy/input_sources/camcorder/applicable_input_device/mask
+				back_mic = 1
+				builtin_mic = 0
+				stub = 0
+
+		conf: BuiltinMic
+			AvailableInputDevices Includes BUILTIN_MIC
+
+			component: /Policy/policy/input_sources/camcorder/applicable_input_device/mask
+				back_mic = 0
+				builtin_mic = 1
+				stub = 0
+
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			component: /Policy/policy/input_sources/camcorder/applicable_input_device/mask
+				back_mic = 0
+				builtin_mic = 0
+				stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources/camcorder/applicable_input_device/mask
+				back_mic = 0
+				builtin_mic = 0
+				stub = 0
+
+	domain: VoiceRecognitionAndUnprocessedAndHotword
+		conf: WiredHeadset
+			AvailableInputDevices Includes WIRED_HEADSET
+
+			component: /Policy/policy/input_sources
+				component: voice_recognition/applicable_input_device/mask
+					wired_headset = 1
+					usb_device = 0
+					stub = 0
+					builtin_mic = 0
+				component: unprocessed/applicable_input_device/mask
+					wired_headset = 1
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: hotword/applicable_input_device/mask
+					wired_headset = 1
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: voice_performance/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+		conf: UsbDevice
+			AvailableInputDevices Includes USB_DEVICE
+
+			component: /Policy/policy/input_sources
+				component: voice_recognition/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 1
+					builtin_mic = 0
+					stub = 0
+				component: unprocessed/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 1
+					builtin_mic = 0
+					stub = 0
+				component: hotword/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 1
+					builtin_mic = 0
+					stub = 0
+				component: voice_performance/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+
+		conf: BuiltinMic
+			AvailableInputDevices Includes BUILTIN_MIC
+
+			component: /Policy/policy/input_sources
+				component: voice_recognition/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+				component: unprocessed/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+				component: hotword/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+				component: voice_performance/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 1
+					stub = 0
+
+
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			component: /Policy/policy/input_sources
+				component: voice_recognition/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+				component: unprocessed/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+				component: hotword/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+				component: voice_performance/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources
+				component: voice_recognition/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: unprocessed/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: hotword/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+				component: voice_performance/applicable_input_device/mask
+					wired_headset = 0
+					usb_device = 0
+					builtin_mic = 0
+					stub = 0
+
+
+	domain: VoiceCommunication
+		conf: WiredHeadset
+			ForceUseForCommunication Is NONE
+			AvailableInputDevices Includes WIRED_HEADSET
+
+			component: /Policy/policy/input_sources/voice_communication/applicable_input_device/mask
+				wired_headset = 1
+				usb_device = 0
+				builtin_mic = 0
+				back_mic = 0
+				stub = 0
+
+		conf: UsbDevice
+			ForceUseForCommunication Is NONE
+			AvailableInputDevices Includes USB_DEVICE
+
+			component: /Policy/policy/input_sources/voice_communication/applicable_input_device/mask
+				wired_headset = 0
+				usb_device = 1
+				builtin_mic = 0
+				back_mic = 0
+				stub = 0
+
+		conf: BuiltinMic
+			AvailableInputDevices Includes BUILTIN_MIC
+			ANY
+				ForceUseForCommunication Is NONE
+				ALL
+					ForceUseForCommunication Is SPEAKER
+					AvailableInputDevices Excludes BACK_MIC
+
+			component: /Policy/policy/input_sources/voice_communication/applicable_input_device/mask
+				wired_headset = 0
+				usb_device = 0
+				builtin_mic = 1
+				back_mic = 0
+				stub = 0
+
+		conf: BackMic
+			ForceUseForCommunication Is SPEAKER
+			AvailableInputDevices Includes BACK_MIC
+
+			component: /Policy/policy/input_sources/voice_communication/applicable_input_device/mask
+				wired_headset = 0
+				usb_device = 0
+				builtin_mic = 0
+				back_mic = 1
+				stub = 0
+
+		conf: Default
+			#
+			# Fallback on the default input device which can be builtin mic for example
+			#
+			component: /Policy/policy/input_sources/voice_communication/applicable_input_device/mask
+				wired_headset = 0
+				usb_device = 0
+				builtin_mic = 1
+				back_mic = 0
+				stub = 0
+
+	domain: RemoteSubmix
+		conf: RemoteSubmix
+			AvailableInputDevices Includes REMOTE_SUBMIX
+
+			component: /Policy/policy/input_sources/remote_submix/applicable_input_device/mask
+				remote_submix = 1
+				stub = 0
+
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			component: /Policy/policy/input_sources/remote_submix/applicable_input_device/mask
+				remote_submix = 0
+				stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources/remote_submix/applicable_input_device/mask
+				remote_submix = 0
+				stub = 0
+
+	domain: FmTuner
+		conf: FmTuner
+			AvailableInputDevices Includes FM_TUNER
+
+			component: /Policy/policy/input_sources/fm_tuner/applicable_input_device/mask
+				fm_tuner = 1
+				stub = 0
+
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			component: /Policy/policy/input_sources/fm_tuner/applicable_input_device/mask
+				fm_tuner = 0
+				stub = 1
+
+		conf: Default
+			component: /Policy/policy/input_sources/fm_tuner/applicable_input_device/mask
+				fm_tuner = 0
+				stub = 0
+
+	domain: Voice
+		conf: Stub
+			AvailableInputDevices Includes DEFAULT
+
+			/Policy/policy/input_sources/echo_reference/applicable_input_device/mask/stub = 1
+
+		conf: Default
+			/Policy/policy/input_sources/echo_reference/applicable_input_device/mask/stub = 0
+
+
diff --git a/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_product_strategies.pfw b/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_product_strategies.pfw
new file mode 100644
index 000000000..603195140
--- /dev/null
+++ b/shared/auto/audio/policy/engine/parameter-framework/Settings/device_for_product_strategies.pfw
@@ -0,0 +1,276 @@
+supDomain: DeviceForProductStrategies
+	supDomain: OemTrafficAnnouncement
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+
+				/Policy/policy/product_strategies/vx_1000/device_address = BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+				component: /Policy/policy/product_strategies/vx_1000/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				/Policy/policy/product_strategies/vx_1000/device_address =
+				component: /Policy/policy/product_strategies/vx_1000/selected_output_devices/mask
+					bus = 0
+
+	supDomain: OemIpa
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1001/device_address = BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+
+				component: /Policy/policy/product_strategies/vx_1001/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1001/selected_output_devices/mask
+					bus = 0
+
+	supDomain: OemXCall
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1002/device_address = BUS03_PHONE_CARD_0_DEV_3
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS03_PHONE_CARD_0_DEV_3
+
+				component: /Policy/policy/product_strategies/vx_1002/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1002/selected_output_devices/mask
+					bus = 0
+
+	supDomain: 3rdPartyAlternate
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1003/device_address = BUS02_NOTIFICATION_CARD_0_DEV_2
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS02_NOTIFICATION_CARD_0_DEV_2
+
+				component: /Policy/policy/product_strategies/vx_1003/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1003/selected_output_devices/mask
+					bus = 0
+
+	supDomain: 3rdPartyAuxiliary
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1004/device_address = BUS04_ASSISTANT_CARD_0_DEV_4
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS04_ASSISTANT_CARD_0_DEV_4
+
+				component: /Policy/policy/product_strategies/vx_1004/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1004/selected_output_devices/mask
+					bus = 0
+
+	supDomain: 3rdPartyAlert
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1005/device_address = BUS03_PHONE_CARD_0_DEV_3
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS03_PHONE_CARD_0_DEV_3
+
+				component: /Policy/policy/product_strategies/vx_1005/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1005/selected_output_devices/mask
+					bus = 0
+
+	supDomain: VoiceCommand
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1006/device_address = BUS04_ASSISTANT_CARD_0_DEV_4
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS04_ASSISTANT_CARD_0_DEV_4
+
+				component: /Policy/policy/product_strategies/vx_1006/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1006/selected_output_devices/mask
+					bus = 0
+
+
+	supDomain: Music
+		domain: SelectedDevice
+			conf: RemoteSubmix
+				AvailableOutputDevices Includes REMOTE_SUBMIX
+				AvailableOutputDevicesAddresses Includes 0
+
+				component: /Policy/policy/product_strategies/vx_1008/selected_output_devices/mask
+					bus = 0
+					stub = 0
+					remote_submix = 1
+				/Policy/policy/product_strategies/vx_1008/device_address =
+
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS00_MEDIA_CARD_0_DEV_0
+
+				component: /Policy/policy/product_strategies/vx_1008/selected_output_devices/mask
+					bus = 1
+					stub = 0
+					remote_submix = 0
+				/Policy/policy/product_strategies/vx_1008/device_address = BUS00_MEDIA_CARD_0_DEV_0
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1008/selected_output_devices/mask
+					bus = 0
+					stub = 1
+					remote_submix = 0
+				/Policy/policy/product_strategies/vx_1008/device_address =
+
+	supDomain: NavGuidance
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1009/device_address = BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS01_NAV_GUIDANCE_CARD_0_DEV_1
+
+				component: /Policy/policy/product_strategies/vx_1009/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1009/selected_output_devices/mask
+					bus = 0
+
+
+	supDomain: VoiceCall
+		domain: SelectedDevice
+			conf: BtSco
+				AvailableOutputDevices Includes BLUETOOTH_SCO
+
+				/Policy/policy/product_strategies/vx_1007/device_address =
+				component: /Policy/policy/product_strategies/vx_1007/selected_output_devices/mask
+					bus = 0
+					bluetooth_sco = 1
+
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS03_PHONE_CARD_0_DEV_3
+
+				/Policy/policy/product_strategies/vx_1007/device_address = BUS03_PHONE_CARD_0_DEV_3
+				component: /Policy/policy/product_strategies/vx_1007/selected_output_devices/mask
+					bus = 1
+					bluetooth_sco = 0
+
+			conf: Default
+				/Policy/policy/product_strategies/vx_1007/device_address =
+				component: /Policy/policy/product_strategies/vx_1007/selected_output_devices/mask
+					bus = 0
+					bluetooth_sco = 0
+	supDomain: Alarm
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1010/device_address = BUS03_PHONE_CARD_0_DEV_3
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS03_PHONE_CARD_0_DEV_3
+
+				component: /Policy/policy/product_strategies/vx_1010/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1010/selected_output_devices/mask
+					bus = 0
+
+
+	supDomain: Ring
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1011/device_address = BUS03_PHONE_CARD_0_DEV_3
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS03_PHONE_CARD_0_DEV_3
+
+				component: /Policy/policy/product_strategies/vx_1011/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1011/selected_output_devices/mask
+					bus = 0
+
+
+	supDomain: Notification
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1012/device_address = BUS05_SYSTEM_CARD_0_DEV_5
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS05_SYSTEM_CARD_0_DEV_5
+
+				component: /Policy/policy/product_strategies/vx_1012/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1012/selected_output_devices/mask
+					bus = 0
+
+	supDomain: System
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1013/device_address = BUS05_SYSTEM_CARD_0_DEV_5
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS05_SYSTEM_CARD_0_DEV_5
+
+				component: /Policy/policy/product_strategies/vx_1013/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1013/selected_output_devices/mask
+					bus = 0
+
+	supDomain: Tts
+		domain: Calibration
+			conf: calibration
+				/Policy/policy/product_strategies/vx_1014/device_address = BUS00_MEDIA_CARD_0_DEV_0
+
+		domain: SelectedDevice
+			conf: Bus
+				AvailableOutputDevices Includes BUS
+				AvailableOutputDevicesAddresses Includes BUS00_MEDIA_CARD_0_DEV_0
+
+				component: /Policy/policy/product_strategies/vx_1014/selected_output_devices/mask
+					bus = 1
+
+			conf: Default
+				component: /Policy/policy/product_strategies/vx_1014/selected_output_devices/mask
+					bus = 0
diff --git a/shared/auto/audio/policy/engine/parameter-framework/Settings/volumes.pfw b/shared/auto/audio/policy/engine/parameter-framework/Settings/volumes.pfw
new file mode 100644
index 000000000..53c7540ab
--- /dev/null
+++ b/shared/auto/audio/policy/engine/parameter-framework/Settings/volumes.pfw
@@ -0,0 +1,29 @@
+supDomain: VolumeProfilesForStream
+	domain: Calibration
+		conf: Calibration
+			/Policy/policy/streams/voice_call/applicable_volume_profile/volume_profile = voice_call
+			/Policy/policy/streams/system/applicable_volume_profile/volume_profile = system
+			/Policy/policy/streams/ring/applicable_volume_profile/volume_profile = ring
+			/Policy/policy/streams/music/applicable_volume_profile/volume_profile = music
+			/Policy/policy/streams/alarm/applicable_volume_profile/volume_profile = alarm
+			/Policy/policy/streams/notification/applicable_volume_profile/volume_profile = notification
+			/Policy/policy/streams/bluetooth_sco/applicable_volume_profile/volume_profile = bluetooth_sco
+			/Policy/policy/streams/enforced_audible/applicable_volume_profile/volume_profile = enforced_audible
+			/Policy/policy/streams/tts/applicable_volume_profile/volume_profile = tts
+			/Policy/policy/streams/accessibility/applicable_volume_profile/volume_profile = accessibility
+			/Policy/policy/streams/assistant/applicable_volume_profile/volume_profile = assistant
+			/Policy/policy/streams/rerouting/applicable_volume_profile/volume_profile = rerouting
+			/Policy/policy/streams/patch/applicable_volume_profile/volume_profile = patch
+
+	domain: Dtmf
+		conf: InCall
+			ANY
+				TelephonyMode Is IN_CALL
+				TelephonyMode Is IN_COMMUNICATION
+
+			/Policy/policy/streams/dtmf/applicable_volume_profile/volume_profile = voice_call
+
+		conf: OutOfCall
+			/Policy/policy/streams/dtmf/applicable_volume_profile/volume_profile = dtmf
+
+
diff --git a/shared/auto/audio/policy/primary_audio_policy_configuration.xml b/shared/auto/audio/policy/primary_audio_policy_configuration.xml
new file mode 100644
index 000000000..d6f2ca5ab
--- /dev/null
+++ b/shared/auto/audio/policy/primary_audio_policy_configuration.xml
@@ -0,0 +1,143 @@
+<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<module name="primary" halVersion="7.0">
+  <attachedDevices>
+    <item>BUS00_MEDIA_CARD_0_DEV_0</item>
+    <item>BUS01_NAV_GUIDANCE_CARD_0_DEV_1</item>
+    <item>BUS02_NOTIFICATION_CARD_0_DEV_2</item>
+    <item>BUS03_PHONE_CARD_0_DEV_3</item>
+    <item>BUS04_ASSISTANT_CARD_0_DEV_4</item>
+    <item>BUS05_SYSTEM_CARD_0_DEV_5</item>
+    <item>builtin_mic</item>
+    <item>fm_tuner</item>
+    <item>telephony_tx</item>
+    <item>telephony_rx</item>
+  </attachedDevices>
+
+    <defaultOutputDevice>BUS00_MEDIA_CARD_0_DEV_0</defaultOutputDevice>
+    <mixPorts>
+        <mixPort name="primary_input" role="sink" maxActiveCount="1" maxOpenCount="1">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="8000 11025 16000 44100 48000"
+                channelMasks="AUDIO_CHANNEL_IN_STEREO AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_FRONT_BACK" />
+        </mixPort>
+        <mixPort name="radio_input" role="sink">
+           <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus0_usage_main_output" role="source" flags="AUDIO_OUTPUT_FLAG_PRIMARY">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus1_usage_nav_guidance_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus2_usage_notification_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus3_usage_voice_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus4_usage_assistant_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="mixport_bus5_usage_system_output" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="hfp_tx_mix" role="source">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+        </mixPort>
+        <mixPort name="hfp_rx_mix" role="sink" flags="AUDIO_INPUT_FLAG_PRIMARY">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+        </mixPort>
+    </mixPorts>
+
+    <devicePorts>
+        <devicePort tagName="builtin_mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" role="source" address="bottom_CARD_0_DEV_0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="16000 48000" channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO" />
+        </devicePort>
+        <devicePort tagName="fm_tuner" type="AUDIO_DEVICE_IN_FM_TUNER" role="source" address="tuner0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO" />
+            <gains>
+                <gain name="" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-3200" maxValueMB="600" defaultValueMB="0" stepValueMB="100" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS00_MEDIA_CARD_0_DEV_0" type="AUDIO_DEVICE_OUT_BUS" role="sink" address="BUS00_MEDIA_CARD_0_DEV_0">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus0_usage_main" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS01_NAV_GUIDANCE_CARD_0_DEV_1" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS01_NAV_GUIDANCE_CARD_0_DEV_1">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus1_usage_nav_guidance" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS02_NOTIFICATION_CARD_0_DEV_2" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS02_NOTIFICATION_CARD_0_DEV_2">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus2_usage_notification" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS03_PHONE_CARD_0_DEV_3" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS03_PHONE_CARD_0_DEV_3">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus3_usage_voice" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS04_ASSISTANT_CARD_0_DEV_4" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS04_ASSISTANT_CARD_0_DEV_4">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus4_usage_assistant" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="BUS05_SYSTEM_CARD_0_DEV_5" role="sink" type="AUDIO_DEVICE_OUT_BUS"
+            address="BUS05_SYSTEM_CARD_0_DEV_5">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain useForVolume="true" name="volume_bus5_usage_system" mode="AUDIO_GAIN_MODE_JOINT" minValueMB="-8800" maxValueMB="1200" defaultValueMB="-4550" stepValueMB="250" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="telephony_tx" type="AUDIO_DEVICE_OUT_TELEPHONY_TX" role="sink" address="hfp_client_out">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO" />
+            <gains>
+                <gain defaultValueMB="0" maxValueMB="4000" minValueMB="-8800" mode="AUDIO_GAIN_MODE_JOINT" name="" stepValueMB="100" useForVolume="false" />
+            </gains>
+        </devicePort>
+        <devicePort tagName="telephony_rx" type="AUDIO_DEVICE_IN_TELEPHONY_RX" role="source" address="hfp_client_in">
+            <profile name="" format="AUDIO_FORMAT_PCM_16_BIT" samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_MONO AUDIO_CHANNEL_IN_STEREO" />
+            <gains>
+                <gain defaultValueMB="0" maxValueMB="4000" minValueMB="-8400" mode="AUDIO_GAIN_MODE_JOINT" name="" stepValueMB="100" useForVolume="false" />
+            </gains>
+        </devicePort>
+    </devicePorts>
+
+    <routes>
+        <route type="mix" sink="primary_input" sources="builtin_mic" />
+        <route type="mix" sink="radio_input" sources="fm_tuner" />
+        <route type="mix" sink="BUS00_MEDIA_CARD_0_DEV_0" sources="mixport_bus0_usage_main_output"/>
+        <route type="mix" sink="BUS01_NAV_GUIDANCE_CARD_0_DEV_1" sources="mixport_bus1_usage_nav_guidance_output"/>
+        <route type="mix" sink="BUS02_NOTIFICATION_CARD_0_DEV_2" sources="mixport_bus2_usage_notification_output"/>
+        <route type="mix" sink="BUS03_PHONE_CARD_0_DEV_3" sources="mixport_bus3_usage_voice_output"/>
+        <route type="mix" sink="BUS04_ASSISTANT_CARD_0_DEV_4" sources="mixport_bus4_usage_assistant_output"/>
+        <route type="mix" sink="BUS05_SYSTEM_CARD_0_DEV_5" sources="mixport_bus5_usage_system_output"/>
+        <route type="mix" sink="telephony_tx" sources="builtin_mic,hfp_tx_mix" />
+        <route type="mix" sink="hfp_rx_mix" sources="telephony_rx" />
+    </routes>
+    </module>
diff --git a/shared/auto/audio_policy_configuration.xml b/shared/auto/audio_policy_configuration.xml
deleted file mode 100644
index 73582c6aa..000000000
--- a/shared/auto/audio_policy_configuration.xml
+++ /dev/null
@@ -1,96 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!--
-/*
-** Copyright 2021, The Android Open Source Project
-**
-** Licensed under the Apache License, Version 2.0 (the "License");
-** you may not use this file except in compliance with the License.
-** You may obtain a copy of the License at
-**
-**     http://www.apache.org/licenses/LICENSE-2.0
-**
-** Unless required by applicable law or agreed to in writing, software
-** distributed under the License is distributed on an "AS IS" BASIS,
-** WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-** See the License for the specific language governing permissions and
-** limitations under the License.
-*/
--->
-
-<!--
-  Overlay resources to configure car service based on each OEM's preference.
-  See also packages/services/Car/service/res/values/config.xml
--->
-<audioPolicyConfiguration version="7.0" xmlns:xi="http://www.w3.org/2001/XInclude">
-    <!-- Global configuration Declaration -->
-    <globalConfiguration speaker_drc_enabled="true"/>
-    <modules>
-      <module name="primary" halVersion="2.0">
-        <attachedDevices>
-            <item>Speaker</item>
-            <item>Built-In Mic</item>
-            <item>FM Tuner</item>
-        </attachedDevices>
-        <defaultOutputDevice>Speaker</defaultOutputDevice>
-        <mixPorts>
-            <mixPort name="primary output" role="source" flags="AUDIO_OUTPUT_FLAG_PRIMARY">
-                <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-                    samplingRates="44100" channelMasks="AUDIO_CHANNEL_OUT_STEREO"/>
-            </mixPort>
-            <mixPort name="primary input" role="sink" maxActiveCount="1" maxOpenCount="1">
-                <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-                    samplingRates="8000 16000" channelMasks="AUDIO_CHANNEL_IN_MONO"/>
-            </mixPort>
-            <mixPort name="mixport_tuner0" role="sink">
-                <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-                    samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO"/>
-            </mixPort>
-        </mixPorts>
-        <devicePorts>
-            <devicePort tagName="Speaker" role="sink" type="AUDIO_DEVICE_OUT_BUS"
-                address="Speaker">
-                <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-                    samplingRates="48000" channelMasks="AUDIO_CHANNEL_OUT_STEREO"/>
-                <gains>
-                    <gain name="" mode="AUDIO_GAIN_MODE_JOINT"
-                        minValueMB="-3200" maxValueMB="600" defaultValueMB="0" stepValueMB="100"/>
-                </gains>
-            </devicePort>
-
-            <devicePort tagName="Built-In Mic" type="AUDIO_DEVICE_IN_BUILTIN_MIC" role="source">
-            </devicePort>
-
-            <devicePort tagName="FM Tuner" type="AUDIO_DEVICE_IN_FM_TUNER" role="source"
-                address="tuner0">
-                <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
-                    samplingRates="48000" channelMasks="AUDIO_CHANNEL_IN_STEREO"/>
-                <gains>
-                    <gain name="" mode="AUDIO_GAIN_MODE_JOINT"
-                        minValueMB="-3200" maxValueMB="600" defaultValueMB="0" stepValueMB="100"/>
-                </gains>
-            </devicePort>
-        </devicePorts>
-        <routes>
-            <route type="mix" sink="Speaker"
-                sources="primary output"/>
-            <route type="mix" sink="primary input"
-                sources="Built-In Mic"/>
-            <route type="mix" sink="mixport_tuner0"
-                sources="FM Tuner"/>
-        </routes>
-      </module>
-
-      <!-- Remote Submix Audio HAL -->
-      <xi:include href="r_submix_audio_policy_configuration.xml"/>
-
-      <!-- Bluetooth Audio HAL -->
-      <xi:include href="bluetooth_audio_policy_configuration_7_0.xml"/>
-    </modules>
-
-    <xi:include href="audio_policy_volumes.xml"/>
-    <xi:include href="default_volume_tables.xml"/>
-
-    <!-- End of Volume section -->
-    <!-- End of Modules section -->
-
-</audioPolicyConfiguration>
diff --git a/shared/auto/audio_policy_engine.mk b/shared/auto/audio_policy_engine.mk
new file mode 100644
index 000000000..f58b02480
--- /dev/null
+++ b/shared/auto/audio_policy_engine.mk
@@ -0,0 +1,23 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+
+PRODUCT_SOONG_NAMESPACES += \
+    device/google/cuttlefish/shared/auto/audio
+
+# Car Audio Policy Configurable emulator
+$(call inherit-product, device/google/cuttlefish/shared/auto/audio/offending_gsi_system.mk)
+$(call inherit-product, device/google/cuttlefish/shared/auto/audio/audio.mk)
+
+
diff --git a/shared/auto/auto_ethernet/ethernet.rc b/shared/auto/auto_ethernet/ethernet.rc
index 8666405f3..ef4479027 100644
--- a/shared/auto/auto_ethernet/ethernet.rc
+++ b/shared/auto/auto_ethernet/ethernet.rc
@@ -15,6 +15,11 @@
 # Initialize network configuration before init so that routes are configured
 # before services are started
 
+# Hardcode the network interface for threadnetwork HAL to prevent it from trying
+# to use eth1, which is not available in the root network namespace in auto.
+on init
+    setprop persist.vendor.otsim.local_interface 127.0.0.1
+
 on post-fs
     exec_start auto-ethernet-setup
     exec_start auto-ethernet-namespace-setup
diff --git a/shared/auto/car_audio_configuration.xml b/shared/auto/car_audio_configuration.xml
deleted file mode 100644
index 5aebb215f..000000000
--- a/shared/auto/car_audio_configuration.xml
+++ /dev/null
@@ -1,58 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright (C) 2021 The Android Open Source Project
-
-     Licensed under the Apache License, Version 2.0 (the "License");
-     you may not use this file except in compliance with the License.
-     You may obtain a copy of the License at
-
-          http://www.apache.org/licenses/LICENSE-2.0
-
-     Unless required by applicable law or agreed to in writing, software
-     distributed under the License is distributed on an "AS IS" BASIS,
-     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-     See the License for the specific language governing permissions and
-     limitations under the License.
--->
-
-<!--
-  Defines the audio configuration in a car, including
-    - Audio zones
-    - Zone configurations (in each audio zone)
-    - Volume groups (in each zone configuration)
-    - Context to audio bus mappings (in each volume group)
-  in the car environment.
--->
-<carAudioConfiguration version="4">
-    <activationVolumeConfigs>
-        <activationVolumeConfig name="activation_volume_on_boot_config">
-            <activationVolumeConfigEntry minActivationVolumePercentage="20"
-                maxActivationVolumePercentage="90" invocationType="onPlaybackChanged" />
-        </activationVolumeConfig>
-    </activationVolumeConfigs>
-    <zones>
-        <zone name="Primary zone" isPrimary="true" occupantZoneId="0">
-            <zoneConfigs>
-                <zoneConfig name="Config 0" isDefault="true">
-                    <volumeGroups>
-                        <group activationConfig="activation_volume_on_boot_config">
-                            <device address="Speaker">
-                                <context context="music"/>
-                                <context context="navigation"/>
-                                <context context="voice_command"/>
-                                <context context="call_ring"/>
-                                <context context="call"/>
-                                <context context="alarm"/>
-                                <context context="notification"/>
-                                <context context="system_sound"/>
-                                <context context="emergency"/>
-                                <context context="safety"/>
-                                <context context="vehicle_status"/>
-                                <context context="announcement"/>
-                            </device>
-                        </group>
-                    </volumeGroups>
-                </zoneConfig>
-            </zoneConfigs>
-        </zone>
-    </zones>
-</carAudioConfiguration>
diff --git a/shared/auto/device_vendor.mk b/shared/auto/device_vendor.mk
index faff823a5..773b4dc2b 100644
--- a/shared/auto/device_vendor.mk
+++ b/shared/auto/device_vendor.mk
@@ -20,6 +20,8 @@ SYSTEM_EXT_MANIFEST_FILES += device/google/cuttlefish/shared/config/system_ext_m
 $(call inherit-product, packages/services/Car/car_product/build/car_vendor.mk)
 
 $(call inherit-product, frameworks/native/build/phone-xhdpi-2048-dalvik-heap.mk)
+$(call inherit-product, device/google/cuttlefish/shared/biometrics_face/device_vendor.mk)
+$(call inherit-product, device/google/cuttlefish/shared/biometrics_fingerprint/device_vendor.mk)
 $(call inherit-product, device/google/cuttlefish/shared/bluetooth/device_vendor.mk)
 $(call inherit-product, device/google/cuttlefish/shared/gnss/device_vendor.mk)
 $(call inherit-product, device/google/cuttlefish/shared/graphics/device_vendor.mk)
@@ -67,16 +69,6 @@ PRODUCT_COPY_FILES += \
 PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/auto/preinstalled-packages-product-car-cuttlefish.xml:$(TARGET_COPY_OUT_PRODUCT)/etc/sysconfig/preinstalled-packages-product-car-cuttlefish.xml
 
-ifndef LOCAL_AUDIO_PRODUCT_COPY_FILES
-LOCAL_AUDIO_PRODUCT_COPY_FILES := \
-    device/google/cuttlefish/shared/auto/car_audio_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/car_audio_configuration.xml \
-    device/google/cuttlefish/shared/auto/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/a2dp_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/a2dp_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/usb_audio_policy_configuration.xml
-LOCAL_AUDIO_PRODUCT_COPY_FILES += \
-    device/google/cuttlefish/shared/auto/audio_effects_config.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects_config.xml
-endif
-
 # Install automotive specific battery health HAL
 PRODUCT_PACKAGES += \
     android.hardware.health-service.automotive \
@@ -97,6 +89,9 @@ ifeq ($(LOCAL_VHAL_PRODUCT_PACKAGE),)
 endif
 PRODUCT_PACKAGES += $(LOCAL_VHAL_PRODUCT_PACKAGE)
 
+# Set car power policy daemon connect to VHAL timeout to 60s for emulator (default is 5s).
+PRODUCT_SYSTEM_PROPERTIES += cppd.connectvhal.Timeoutmillis=60000
+
 # Ethernet setup script for vehicle HAL
 ENABLE_AUTO_ETHERNET ?= true
 ifeq ($(ENABLE_AUTO_ETHERNET), true)
@@ -114,6 +109,7 @@ PRODUCT_PACKAGES += android.hardware.broadcastradio-service.default
 PRODUCT_PACKAGES += android.hardware.automotive.ivn@V1-default-service
 
 # AudioControl HAL
+# OEM may override the default service of the virtual device.
 ifeq ($(LOCAL_AUDIOCONTROL_HAL_PRODUCT_PACKAGE),)
     LOCAL_AUDIOCONTROL_HAL_PRODUCT_PACKAGE := android.hardware.automotive.audiocontrol-service.example
     BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/auto/sepolicy/audio
diff --git a/shared/auto/display_settings.xml b/shared/auto/display_settings.xml
index 50658383f..6a9a9dd9c 100644
--- a/shared/auto/display_settings.xml
+++ b/shared/auto/display_settings.xml
@@ -3,6 +3,12 @@
     <!-- Use physical port number instead of local id -->
     <config identifier="1" />
 
+    <!-- Display settings for the driver display -->
+    <display name="port:0"
+        ignoreOrientationRequest="true" />
+
     <!-- Display settings for cluster -->
-    <display name="port:1" dontMoveToTop="true" />
+    <display name="port:1"
+        ignoreOrientationRequest="true"
+        dontMoveToTop="true" />
 </display-settings>
diff --git a/shared/auto/overlay/frameworks/base/core/res/res/values/config.xml b/shared/auto/overlay/frameworks/base/core/res/res/values/config.xml
index 93e173442..f20efa8a4 100644
--- a/shared/auto/overlay/frameworks/base/core/res/res/values/config.xml
+++ b/shared/auto/overlay/frameworks/base/core/res/res/values/config.xml
@@ -28,8 +28,10 @@
     <bool name="config_guestUserEphemeral" translatable="false">true</bool>
     <!--  Maximum number of users allowed on the device. -->
     <integer name="config_multiuserMaximumUsers" translatable="false">4</integer>
-    <!-- Car uses hardware amplifier for volume. -->
-    <bool name="config_useFixedVolume">true</bool>
+    <!-- When car uses core volume, even if using hardware amplifier for volume, it relies on
+         AudioService / AudioPolicyManager to manage cache and volume application based
+         on activities on the outputs. -->
+    <bool name="config_useFixedVolume">false</bool>
     <!--
       Handle volume keys directly in CarAudioService without passing them to the foreground app
     -->
@@ -44,4 +46,23 @@
     <integer-array translatable="false" name="config_localPrivateDisplayPorts">
         <item>1</item> <!-- ClusterDisplay -->
     </integer-array>
+
+    <!-- Disable hard coded aliased stream table in AudioService.
+         When defining volume groups, we do expect group to be independent in term of volume
+         management, whatever regarding index in UI / Volume seekbars and volume curves. -->
+    <bool name="config_handleVolumeAliasesUsingVolumeGroups">true</bool>
+
+    <bool name="config_useAssistantVolume">true</bool>
+
+    <!-- The number of volume steps for the notification stream -->
+    <integer name="config_audio_notif_vol_steps">40</integer>
+
+    <!-- The default volume for the notification stream -->
+    <integer name="config_audio_notif_vol_default">5</integer>
+
+    <!-- The number of volume steps for the ring stream -->
+    <integer name="config_audio_ring_vol_steps">40</integer>
+
+    <!-- The default volume for the ring stream -->
+    <integer name="config_audio_ring_vol_default">5</integer>
 </resources>
diff --git a/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml b/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
index 95a4ed3f5..5e46aeb97 100644
--- a/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
+++ b/shared/auto/rro_overlay/CarServiceOverlay/res/values/config.xml
@@ -23,16 +23,7 @@
 -->
 <resources>
     <bool name="audioUseDynamicRouting">true</bool>
-    <!--  Configuration to enable muting of individual volume groups. If this is set to
-          false, muting of individual volume groups is disabled, instead muting will toggle master
-          mute. If this is set to true, car volume group muting is enabled and each individual
-          volume group can be muted separately. -->
-    <bool name="audioUseCarVolumeGroupMuting">true</bool>
-    <!--  Configuration to enable IAudioControl#onDevicesToDuckChange API to inform HAL when to
-      duck. If this is set to true, the API will receive signals indicating which output devices
-      to duck as well as what usages are currently holding focus. If set to false, the API will
-      not be called. -->
-    <bool name="audioUseHalDuckingSignals">false</bool>
+    <bool name="audioUseCarVolumeGroupEvent">true</bool>
      <!--  Configuration to enable min/max activation volume. If this is set to true, the volume of
           the volume group with min/max activation volume setting will be set to min activation
           volume or max activation volume if volume during activation is lower than min activation
diff --git a/shared/auto/rro_overlay/CarServiceOverlay/res/xml/overlays.xml b/shared/auto/rro_overlay/CarServiceOverlay/res/xml/overlays.xml
index 35e9f86d4..c82455966 100644
--- a/shared/auto/rro_overlay/CarServiceOverlay/res/xml/overlays.xml
+++ b/shared/auto/rro_overlay/CarServiceOverlay/res/xml/overlays.xml
@@ -16,10 +16,9 @@
   -->
 <overlay>
     <item target="bool/audioUseDynamicRouting" value="@bool/audioUseDynamicRouting" />
-    <item target="bool/audioUseCarVolumeGroupMuting" value="@bool/audioUseCarVolumeGroupMuting" />
-    <item target="bool/audioUseHalDuckingSignals" value="@bool/audioUseHalDuckingSignals" />
     <item target="array/config_occupant_zones" value="@array/config_occupant_zones" />
     <item target="array/config_occupant_display_mapping" value="@array/config_occupant_display_mapping" />
     <item target="array/config_carEvsService" value="@array/config_carEvsService" />
     <item target="bool/audioUseMinMaxActivationVolume" value="@bool/audioUseMinMaxActivationVolume" />
+    <item target="bool/audioUseCarVolumeGroupEvent" value="@bool/audioUseCarVolumeGroupEvent" />
 </overlay>
diff --git a/shared/auto/sepolicy/vendor/dumpstate.te b/shared/auto/sepolicy/vendor/dumpstate.te
index 2a98d49f9..1dd9c6a69 100644
--- a/shared/auto/sepolicy/vendor/dumpstate.te
+++ b/shared/auto/sepolicy/vendor/dumpstate.te
@@ -2,5 +2,16 @@
 binder_call(dumpstate, automotive_display_service_server)
 
 # Allow dumpstate to signal processes to dump.
-allow dumpstate hal_can_socketcan:process signal;
-allow dumpstate hal_occupant_awareness_default:process signal;
+allow dumpstate {
+  hal_vehicle_default
+  hal_audiocontrol_default
+  hal_ivn
+  hal_remoteaccess_default
+  hal_can_socketcan
+  hal_occupant_awareness_default
+}:process signal;
+
+dump_hal(hal_vehicle)
+dump_hal(hal_audiocontrol)
+dump_hal(hal_ivn)
+dump_hal(hal_remoteaccess)
diff --git a/shared/auto/sepolicy/vendor/vendor_init.te b/shared/auto/sepolicy/vendor/vendor_init.te
index 5911ecd15..a25d5b31a 100644
--- a/shared/auto/sepolicy/vendor/vendor_init.te
+++ b/shared/auto/sepolicy/vendor/vendor_init.te
@@ -1 +1,2 @@
 get_prop(vendor_init, auto_eth_namespace_setup_complete_prop)
+set_prop(vendor_init, vendor_otsim_local_interface_prop)
diff --git a/shared/auto/sepolicy/vhal/hal_vehicle_default.te b/shared/auto/sepolicy/vhal/hal_vehicle_default.te
index 545a76dab..6b5b3aa7c 100644
--- a/shared/auto/sepolicy/vhal/hal_vehicle_default.te
+++ b/shared/auto/sepolicy/vhal/hal_vehicle_default.te
@@ -2,4 +2,7 @@
 carwatchdog_client_domain(hal_vehicle_default)
 binder_use(hal_vehicle_default)
 
+starting_at_board_api(202504, `
+typeattribute hal_vehicle_default unconstrained_vsock_violators;
+')
 allow hal_vehicle_default self:vsock_socket { create connect getopt getattr read write shutdown };
diff --git a/shared/auto_dd/OWNERS b/shared/auto_dd/OWNERS
index 0fe6f2bdc..cccf76b63 100644
--- a/shared/auto_dd/OWNERS
+++ b/shared/auto_dd/OWNERS
@@ -1,5 +1,4 @@
 include device/google/cuttlefish:/shared/auto/OWNERS
-ycheo@google.com
 babakbo@google.com
 calhuang@google.com
 priyanksingh@google.com
\ No newline at end of file
diff --git a/shared/auto_dd/android-info.txt b/shared/auto_dd/android-info.txt
index d62f9accd..402665d3d 100644
--- a/shared/auto_dd/android-info.txt
+++ b/shared/auto_dd/android-info.txt
@@ -1,2 +1,3 @@
 config=auto_dd
 gfxstream=supported
+output_audio_streams_count=6
diff --git a/shared/auto_dd/display_settings.xml b/shared/auto_dd/display_settings.xml
index f07254bca..08375b4b5 100644
--- a/shared/auto_dd/display_settings.xml
+++ b/shared/auto_dd/display_settings.xml
@@ -22,11 +22,16 @@
   <!-- Use physical port number instead of local id -->
   <config identifier="1" />
 
+  <!-- Display settings for the driver display -->
+  <display name="port:0"
+        ignoreOrientationRequest="true" />
+
   <!-- Display settings for the distant display-->
   <display
         name="port:1"
         forcedWidth="4000"
         forcedHeight="800"
+        ignoreOrientationRequest="true"
         dontMoveToTop="true"/>
 
 </display-settings>
diff --git a/shared/auto_dewd/Android.bp b/shared/auto_dewd/Android.bp
new file mode 100644
index 000000000..f6d3bb1fe
--- /dev/null
+++ b/shared/auto_dewd/Android.bp
@@ -0,0 +1,24 @@
+//
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc_host {
+    name: "cvd_config_auto_dewd.json",
+    src: "config_auto_dewd.json",
+    sub_dir: "cvd_config",
+}
diff --git a/shared/auto_dewd/OWNERS b/shared/auto_dewd/OWNERS
new file mode 100644
index 000000000..87eb24ed2
--- /dev/null
+++ b/shared/auto_dewd/OWNERS
@@ -0,0 +1,5 @@
+include device/google/cuttlefish:/shared/auto/OWNERS
+alexstetson@google.com
+babakbo@google.com
+calhuang@google.com
+priyanksingh@google.com
diff --git a/shared/auto_dewd/android-info.txt b/shared/auto_dewd/android-info.txt
new file mode 100644
index 000000000..48f855046
--- /dev/null
+++ b/shared/auto_dewd/android-info.txt
@@ -0,0 +1,3 @@
+config=auto_dewd
+gfxstream=supported
+gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
diff --git a/shared/auto_dewd/config_auto_dewd.json b/shared/auto_dewd/config_auto_dewd.json
new file mode 100644
index 000000000..27835135a
--- /dev/null
+++ b/shared/auto_dewd/config_auto_dewd.json
@@ -0,0 +1,5 @@
+{
+	"display0": "width=1080,height=1920,dpi=140",
+	"memory_mb" : 4096,
+	"enable_vhal_proxy_server": true
+}
diff --git a/shared/auto_dewd/display_settings.xml b/shared/auto_dewd/display_settings.xml
new file mode 100644
index 000000000..b94b5f6e5
--- /dev/null
+++ b/shared/auto_dewd/display_settings.xml
@@ -0,0 +1,29 @@
+<?xml version='1.0' encoding='utf-8' standalone='yes' ?>
+<!--
+/*
+** Copyright 2025, The Android Open Source Project
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
+
+<display-settings>
+
+  <!-- Use physical port number instead of local id -->
+  <config identifier="1" />
+
+  <!-- Display settings for the driver display -->
+  <display name="port:0"
+      ignoreOrientationRequest="true" />
+
+</display-settings>
diff --git a/shared/auto_md/OWNERS b/shared/auto_md/OWNERS
index d3a1f8297..f311e6d98 100644
--- a/shared/auto_md/OWNERS
+++ b/shared/auto_md/OWNERS
@@ -1,2 +1 @@
 include device/google/cuttlefish:/shared/auto/OWNERS
-ycheo@google.com
diff --git a/shared/auto_md/android-info.txt b/shared/auto_md/android-info.txt
index 9021818c8..c4b6eefc2 100644
--- a/shared/auto_md/android-info.txt
+++ b/shared/auto_md/android-info.txt
@@ -1,3 +1,4 @@
 config=auto_md
 gfxstream=supported
-gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
+gfxstream_gl_program_binary_link_status=supported
+output_audio_streams_count=6
\ No newline at end of file
diff --git a/shared/auto_md/display_settings.xml b/shared/auto_md/display_settings.xml
index 1922d42c2..5ea78b372 100644
--- a/shared/auto_md/display_settings.xml
+++ b/shared/auto_md/display_settings.xml
@@ -22,21 +22,28 @@
   <!-- Use physical port number instead of local id -->
   <config identifier="1" />
 
+  <!-- Display settings for the driver display -->
+  <display name="port:0"
+      ignoreOrientationRequest="true" />
+
   <!-- Display settings for cluster -->
   <display name="port:1"
       forcedDensity="120"
+      ignoreOrientationRequest="true"
       dontMoveToTop="true"/>
 
   <!-- Display settings for 1st passenger display / 2nd Home -->
   <display name="port:2"
       shouldShowSystemDecors="true"
       shouldShowIme="true"
+      ignoreOrientationRequest="true"
       forcedDensity="120" />
 
   <!-- Display settings for 2nd passenger display / 3rd Home -->
   <display name="port:3"
       shouldShowSystemDecors="true"
       shouldShowIme="true"
+      ignoreOrientationRequest="true"
       forcedDensity="120" />
 
 </display-settings>
diff --git a/shared/auto_mdnd/android-info.txt b/shared/auto_mdnd/android-info.txt
new file mode 100644
index 000000000..345d7361b
--- /dev/null
+++ b/shared/auto_mdnd/android-info.txt
@@ -0,0 +1 @@
+output_audio_streams_count=6
diff --git a/shared/auto_portrait/android-info.txt b/shared/auto_portrait/android-info.txt
index 110c70aa6..01bbf4c1b 100644
--- a/shared/auto_portrait/android-info.txt
+++ b/shared/auto_portrait/android-info.txt
@@ -1,3 +1,4 @@
 config=auto_portrait
 gfxstream=supported
-gfxstream_gl_program_binary_link_status=supported
\ No newline at end of file
+gfxstream_gl_program_binary_link_status=supported
+output_audio_streams_count=6
\ No newline at end of file
diff --git a/shared/auto_portrait/display_settings.xml b/shared/auto_portrait/display_settings.xml
index 54a150860..b06ca86a3 100644
--- a/shared/auto_portrait/display_settings.xml
+++ b/shared/auto_portrait/display_settings.xml
@@ -22,4 +22,8 @@
   <!-- Use physical port number instead of local id -->
   <config identifier="1" />
 
+  <!-- Display settings for the driver display -->
+  <display name="port:0"
+      ignoreOrientationRequest="true" />
+
 </display-settings>
diff --git a/shared/bluetooth/device_vendor.mk b/shared/bluetooth/device_vendor.mk
index 60c090adb..f7c135440 100644
--- a/shared/bluetooth/device_vendor.mk
+++ b/shared/bluetooth/device_vendor.mk
@@ -27,8 +27,10 @@ LOCAL_BT_PROPERTIES ?= \
 PRODUCT_VENDOR_PROPERTIES += \
     ${LOCAL_BT_PROPERTIES} \
 
+ifneq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),true)
 PRODUCT_COPY_FILES += \
-    frameworks/av/services/audiopolicy/config/bluetooth_audio_policy_configuration_7_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_audio_policy_configuration_7_0.xml \
+    frameworks/av/services/audiopolicy/config/bluetooth_with_le_audio_policy_configuration_7_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/bluetooth_with_le_audio_policy_configuration_7_0.xml
+endif
 
 PRODUCT_PACKAGES += com.google.cf.bt
 
diff --git a/shared/bluetooth/sepolicy/bt_vhci_forwarder.te b/shared/bluetooth/sepolicy/bt_vhci_forwarder.te
deleted file mode 100644
index 21726968c..000000000
--- a/shared/bluetooth/sepolicy/bt_vhci_forwarder.te
+++ /dev/null
@@ -1,6 +0,0 @@
-type bt_vhci_forwarder, domain;
-type bt_vhci_forwarder_exec, exec_type, vendor_file_type, file_type;
-
-init_daemon_domain(bt_vhci_forwarder)
-
-allow bt_vhci_forwarder bt_device:chr_file { open read write ioctl};
diff --git a/shared/bluetooth/sepolicy/file_contexts b/shared/bluetooth/sepolicy/file_contexts
index 3dbc4ba43..7cb047fe2 100644
--- a/shared/bluetooth/sepolicy/file_contexts
+++ b/shared/bluetooth/sepolicy/file_contexts
@@ -1,4 +1,2 @@
 /dev/hvc5  u:object_r:bt_device:s0
 /dev/vhci  u:object_r:bt_device:s0
-
-/vendor/bin/bt_vhci_forwarder  u:object_r:bt_vhci_forwarder_exec:s0
diff --git a/shared/camera/sepolicy/hal_camera_default.te b/shared/camera/sepolicy/hal_camera_default.te
index 8783a4472..0bc9ebdc8 100644
--- a/shared/camera/sepolicy/hal_camera_default.te
+++ b/shared/camera/sepolicy/hal_camera_default.te
@@ -10,6 +10,9 @@ binder_call(sensor_service_server, hal_camera_default)
 hal_client_domain(hal_camera_default, hal_thermal)
 
 # Vsocket camera
+starting_at_board_api(202504, `
+typeattribute hal_camera_default unconstrained_vsock_violators;
+')
 allow hal_camera_default self:vsock_socket { accept bind create getopt listen read write };
 
 set_prop(hal_camera_default, vendor_camera_prop)
diff --git a/shared/config/Android.bp b/shared/config/Android.bp
index 6dd17b0c3..346e819db 100644
--- a/shared/config/Android.bp
+++ b/shared/config/Android.bp
@@ -124,6 +124,17 @@ prebuilt_etc {
     vendor_ramdisk: true,
 }
 
+prebuilt_etc {
+    name: "fstab.cf.f2fs.cts.recovery",
+    srcs: [
+        ":gen_fstab_cf_f2fs_cts",
+    ],
+    dsts: [
+        "recovery.fstab",
+    ],
+    recovery: true,
+}
+
 prebuilt_etc {
     name: "fstab.cf.ext4.hctr2",
     src: ":gen_fstab_cf_ext4_hctr2",
diff --git a/shared/config/audio/policy/audio_policy_configuration.xml b/shared/config/audio/policy/audio_policy_configuration.xml
index 6e57dd04b..3c07e675c 100644
--- a/shared/config/audio/policy/audio_policy_configuration.xml
+++ b/shared/config/audio/policy/audio_policy_configuration.xml
@@ -28,7 +28,7 @@
         <xi:include href="r_submix_audio_policy_configuration.xml"/>
 
         <!-- Bluetooth Audio HAL -->
-        <xi:include href="bluetooth_audio_policy_configuration_7_0.xml"/>
+        <xi:include href="bluetooth_with_le_audio_policy_configuration_7_0.xml"/>
     </modules>
     <!-- End of Modules section -->
 
diff --git a/shared/config/audio/policy/primary_audio_policy_configuration.xml b/shared/config/audio/policy/primary_audio_policy_configuration.xml
index 3d2a15108..8376decc3 100644
--- a/shared/config/audio/policy/primary_audio_policy_configuration.xml
+++ b/shared/config/audio/policy/primary_audio_policy_configuration.xml
@@ -30,6 +30,12 @@
                      samplingRates="8000 11025 16000 32000 44100 48000"
                      channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
         </mixPort>
+        <mixPort name="compressed_offload" role="source"
+                 flags="AUDIO_OUTPUT_FLAG_DIRECT AUDIO_OUTPUT_FLAG_COMPRESS_OFFLOAD AUDIO_OUTPUT_FLAG_NON_BLOCKING">
+            <profile name="" format="AUDIO_FORMAT_APE"
+                     samplingRates="44100 48000"
+                     channelMasks="AUDIO_CHANNEL_OUT_MONO AUDIO_CHANNEL_OUT_STEREO"/>
+        </mixPort>
         <mixPort name="primary input" role="sink">
             <profile name="" format="AUDIO_FORMAT_PCM_16_BIT"
                      samplingRates="8000 11025 16000 32000 44100 48000"
@@ -69,7 +75,7 @@
     </devicePorts>
     <routes>
         <route type="mix" sink="Speaker"
-               sources="primary output"/>
+               sources="primary output,compressed_offload"/>
         <route type="mix" sink="primary input"
                sources="Built-In Mic"/>
 
diff --git a/shared/config/fstab.in b/shared/config/fstab.in
index 2ee4f8c0c..a995e3280 100644
--- a/shared/config/fstab.in
+++ b/shared/config/fstab.in
@@ -6,7 +6,7 @@ system /system erofs ro wait,logical,first_stage_mount,slotselect,avb=vbmeta_sys
 system /system ext4 noatime,ro,errors=panic wait,logical,first_stage_mount,slotselect,avb=vbmeta_system,avb_keys=/avb
 # Add all non-dynamic partitions except system, after this comment
 /dev/block/by-name/userdata /data @userdata_fs_type@ nodev,noatime,nosuid,@userdata_mount_flags@ latemount,wait,check,quota,formattable,keydirectory=/metadata/vold/metadata_encryption,@userdata_fsmgr_flags@
-/dev/block/by-name/userdata /data ext4 nodev,noatime,nosuid,errors=panic latemount,wait,check,quota,keydirectory=/metadata/vold/metadata_encryption,@userdata_fsmgr_flags@
+/dev/block/by-name/userdata /data ext4 nodev,noatime,nosuid,errors=panic latemount,reservedsize=128M,wait,check,quota,keydirectory=/metadata/vold/metadata_encryption,@userdata_fsmgr_flags@
 /dev/block/by-name/metadata /metadata @metadata_fs_type@ nodev,noatime,nosuid wait,check,formattable,first_stage_mount
 /dev/block/by-name/metadata /metadata ext4 nodev,noatime,nosuid wait,check,first_stage_mount
 /dev/block/by-name/misc /misc emmc defaults defaults
diff --git a/shared/config/graphics/init_graphics.vendor.rc b/shared/config/graphics/init_graphics.vendor.rc
index 2dafd6dca..0c41e0665 100644
--- a/shared/config/graphics/init_graphics.vendor.rc
+++ b/shared/config/graphics/init_graphics.vendor.rc
@@ -13,4 +13,6 @@ on early-init
     setprop ro.cpuvulkan.version ${ro.boot.cpuvulkan.version}
     setprop ro.opengles.version ${ro.boot.opengles.version}
     setprop debug.angle.feature_overrides_enabled ${ro.boot.hardware.angle_feature_overrides_enabled}
-    setprop debug.angle.feature_overrides_disabled ${ro.boot.hardware.angle_feature_overrides_disabled}
\ No newline at end of file
+    setprop debug.angle.feature_overrides_disabled ${ro.boot.hardware.angle_feature_overrides_disabled}
+    setprop debug.hwui.renderer ${ro.boot.hardware.guest_hwui_renderer}
+    setprop ro.zygote.disable_gl_preload ${ro.boot.hardware.guest_disable_renderer_preload}
diff --git a/shared/config/init.vendor.rc b/shared/config/init.vendor.rc
index e0b09104d..676740244 100644
--- a/shared/config/init.vendor.rc
+++ b/shared/config/init.vendor.rc
@@ -9,6 +9,9 @@ on early-init
     start vendor.dlkm_loader
     # specially load zram as it is a "leaf" GKI module
     exec u:r:modprobe:s0 -- /system/bin/modprobe -a -d /system/lib/modules zram.ko
+    # only load vkms after virtio_gpu has been loaded
+    wait /dev/dri/card0
+    exec u:r:vendor_modprobe:s0 -- /vendor/bin/modprobe -d /vendor/lib/modules vkms.ko create_default_dev=0
 
 on early-init && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
 com.android.hardware.keymint.rust_cf_guest_trusty_nonsecure
@@ -86,6 +89,10 @@ on boot
     symlink /dev/hvc6 /dev/gnss0
     symlink /dev/hvc7 /dev/gnss1
 
+    # enable f2fs sanity check to dump more metadata info to kmsg
+    # once it detects inode corruption
+    write /dev/sys/fs/by-name/userdata/sanity_check 1
+
 on property:sys.boot_completed=1
     trigger sys-boot-completed-set
     mkdir /mnt/vendor/custom 0755 root root
diff --git a/shared/config/input/Android.bp b/shared/config/input/Android.bp
index 544e31c21..8076c5235 100644
--- a/shared/config/input/Android.bp
+++ b/shared/config/input/Android.bp
@@ -29,12 +29,12 @@ apex {
         // Set input_device.config_file.apex={apexname} sysprop
         "com.google.cf.input.config.rc",
         // Configs
-        "Crosvm_Virtio_Multitouch_Touchpad_0.idc",
-        "Crosvm_Virtio_Multitouch_Touchscreen_0.idc",
-        "Crosvm_Virtio_Multitouch_Touchscreen_1.idc",
-        "Crosvm_Virtio_Multitouch_Touchscreen_2.idc",
-        "Crosvm_Virtio_Multitouch_Touchscreen_3.idc",
-        "Crosvm_Virtio_Rotary_0.idc",
+        "Cuttlefish_Vhost_User_Multitouch_Touchpad_0.idc",
+        "Cuttlefish_Vhost_User_Multitouch_Touchscreen_0.idc",
+        "Cuttlefish_Vhost_User_Multitouch_Touchscreen_1.idc",
+        "Cuttlefish_Vhost_User_Multitouch_Touchscreen_2.idc",
+        "Cuttlefish_Vhost_User_Multitouch_Touchscreen_3.idc",
+        "Cuttlefish_Vhost_User_Rotary_0.idc",
     ],
 }
 
@@ -52,37 +52,37 @@ prebuilt_defaults {
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Multitouch_Touchpad_0.idc",
-    src: "Crosvm_Virtio_Multitouch_Touchpad_0.idc",
+    name: "Cuttlefish_Vhost_User_Multitouch_Touchpad_0.idc",
+    src: "Cuttlefish_Vhost_User_Multitouch_Touchpad_0.idc",
     defaults: ["crosvm_idc_defaults"],
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Multitouch_Touchscreen_0.idc",
-    src: "Crosvm_Virtio_Multitouch_Touchscreen_0.idc",
+    name: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_0.idc",
+    src: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_0.idc",
     defaults: ["crosvm_idc_defaults"],
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Multitouch_Touchscreen_1.idc",
-    src: "Crosvm_Virtio_Multitouch_Touchscreen_1.idc",
+    name: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_1.idc",
+    src: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_1.idc",
     defaults: ["crosvm_idc_defaults"],
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Multitouch_Touchscreen_2.idc",
-    src: "Crosvm_Virtio_Multitouch_Touchscreen_2.idc",
+    name: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_2.idc",
+    src: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_2.idc",
     defaults: ["crosvm_idc_defaults"],
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Multitouch_Touchscreen_3.idc",
-    src: "Crosvm_Virtio_Multitouch_Touchscreen_3.idc",
+    name: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_3.idc",
+    src: "Cuttlefish_Vhost_User_Multitouch_Touchscreen_3.idc",
     defaults: ["crosvm_idc_defaults"],
 }
 
 prebuilt_etc {
-    name: "Crosvm_Virtio_Rotary_0.idc",
-    src: "Crosvm_Virtio_Rotary_0.idc",
+    name: "Cuttlefish_Vhost_User_Rotary_0.idc",
+    src: "Cuttlefish_Vhost_User_Rotary_0.idc",
     defaults: ["crosvm_idc_defaults"],
 }
diff --git a/shared/config/input/Crosvm_Virtio_Multitouch_Touchpad_0.idc b/shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchpad_0.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Multitouch_Touchpad_0.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchpad_0.idc
diff --git a/shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_0.idc b/shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_0.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_0.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_0.idc
diff --git a/shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_1.idc b/shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_1.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_1.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_1.idc
diff --git a/shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_2.idc b/shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_2.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_2.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_2.idc
diff --git a/shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_3.idc b/shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_3.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Multitouch_Touchscreen_3.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Multitouch_Touchscreen_3.idc
diff --git a/shared/config/input/Crosvm_Virtio_Rotary_0.idc b/shared/config/input/Cuttlefish_Vhost_User_Rotary_0.idc
similarity index 100%
rename from shared/config/input/Crosvm_Virtio_Rotary_0.idc
rename to shared/config/input/Cuttlefish_Vhost_User_Rotary_0.idc
diff --git a/shared/config/manifest.xml b/shared/config/manifest.xml
index 5ac59208e..3bd976871 100644
--- a/shared/config/manifest.xml
+++ b/shared/config/manifest.xml
@@ -16,7 +16,7 @@
 ** limitations under the License.
 */
 -->
-<manifest version="1.0" type="device" target-level="202504">
+<manifest version="1.0" type="device" target-level="202604">
 
     <!-- DO NOT ADD MORE - use vintf_fragments -->
 
diff --git a/shared/config/previous_manifest.xml b/shared/config/previous_manifest.xml
index 18ae50ee5..3d37c1295 100644
--- a/shared/config/previous_manifest.xml
+++ b/shared/config/previous_manifest.xml
@@ -16,7 +16,7 @@
 ** limitations under the License.
 */
 -->
-<manifest version="1.0" type="device" target-level="202404">
+<manifest version="1.0" type="device" target-level="202504">
 
     <!-- DO NOT ADD MORE - use vintf_fragments -->
 
diff --git a/shared/config/ueventd.rc b/shared/config/ueventd.rc
index 5b01e3646..7d8f217a2 100644
--- a/shared/config/ueventd.rc
+++ b/shared/config/ueventd.rc
@@ -55,5 +55,11 @@
 # MCU UART
 /dev/hvc15 0666 system system
 
+# Ti50 emulator
+/dev/hvc16 0666 hsm hsm
+
 # Factory Reset Protection
 /dev/block/by-name/frp 0660 system system
+
+# v4l2loopback and virtio-media devices
+/dev/video*   0660 system    camera
diff --git a/shared/desktop/Android.bp b/shared/desktop/Android.bp
new file mode 100644
index 000000000..065fedce6
--- /dev/null
+++ b/shared/desktop/Android.bp
@@ -0,0 +1,25 @@
+//
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+prebuilt_etc {
+    name: "desktop_excluded_cellular_hardware_features.prebuilt.xml",
+    src: "desktop_excluded_cellular_hardware_features.xml",
+    relative_install_path: "permissions",
+    soc_specific: true,
+}
diff --git a/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml b/shared/desktop/desktop_excluded_cellular_hardware_features.xml
similarity index 51%
rename from guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml
rename to shared/desktop/desktop_excluded_cellular_hardware_features.xml
index 1ab21336d..d7b67886d 100644
--- a/guest/hals/keymint/rust/android.hardware.hardware_keystore.rust-keymint.xml
+++ b/shared/desktop/desktop_excluded_cellular_hardware_features.xml
@@ -1,5 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<!-- Copyright 2021 The Android Open Source Project
+<!-- Copyright 2025 The Android Open Source Project
 
      Licensed under the Apache License, Version 2.0 (the "License");
      you may not use this file except in compliance with the License.
@@ -13,6 +13,14 @@
      See the License for the specific language governing permissions and
      limitations under the License.
 -->
+
 <permissions>
-  <feature name="android.hardware.hardware_keystore" version="400" />
+    <!-- Desktop does not support the following features -->
+    <unavailable-feature name="android.hardware.telephony.calling" />
+    <unavailable-feature name="android.hardware.telephony.carrierlock" />
+    <unavailable-feature name="android.hardware.telephony.gsm" />
+    <unavailable-feature name="android.hardware.telephony.euicc.mep" />
+    <unavailable-feature name="android.hardware.telephony.ims" />
+    <unavailable-feature name="android.hardware.telephony.ims.singlereg" />
+    <unavailable-feature name="android.hardware.telephony.satellite" />
 </permissions>
diff --git a/shared/desktop/device_vendor.mk b/shared/desktop/device_vendor.mk
index 1674846f7..a1e51a4f1 100644
--- a/shared/desktop/device_vendor.mk
+++ b/shared/desktop/device_vendor.mk
@@ -17,6 +17,10 @@
 PRODUCT_MANIFEST_FILES += device/google/cuttlefish/shared/config/product_manifest.xml
 SYSTEM_EXT_MANIFEST_FILES += device/google/cuttlefish/shared/config/system_ext_manifest.xml
 
+# Extend cuttlefish common sepolicy with desktop-specific functionality.
+BOARD_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy
+SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/google/cuttlefish/shared/desktop/sepolicy/system_ext/private
+
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_vendor.mk)
 
 $(call inherit-product, frameworks/native/build/tablet-7in-xhdpi-2048-dalvik-heap.mk)
diff --git a/shared/desktop/sepolicy/system_ext/private/empty.te b/shared/desktop/sepolicy/system_ext/private/empty.te
new file mode 100644
index 000000000..fc679a4f3
--- /dev/null
+++ b/shared/desktop/sepolicy/system_ext/private/empty.te
@@ -0,0 +1 @@
+# This file is left intentionally blank so this directory exists on all branches.
diff --git a/shared/desktop/sepolicy/system_ext/private/gscd.te b/shared/desktop/sepolicy/system_ext/private/gscd.te
new file mode 100644
index 000000000..06630e9fd
--- /dev/null
+++ b/shared/desktop/sepolicy/system_ext/private/gscd.te
@@ -0,0 +1,4 @@
+# Cuttlefish-specific policy for the GSC daemon (gscd)
+
+# Allow gscd to communicate with the Ti50 host_emulation daemon via virtio-console
+allow gscd ti50_char_device:chr_file rw_file_perms;
diff --git a/shared/device.mk b/shared/device.mk
index 693a675ce..a86613508 100644
--- a/shared/device.mk
+++ b/shared/device.mk
@@ -20,9 +20,6 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/languages_full.mk)
 # Enable updating of APEXes
 $(call inherit-product, $(SRC_TARGET_DIR)/product/updatable_apex.mk)
 
-# Enable userspace reboot
-$(call inherit-product, $(SRC_TARGET_DIR)/product/userspace_reboot.mk)
-
 # Enforce generic ramdisk allow list
 $(call inherit-product, $(SRC_TARGET_DIR)/product/generic_ramdisk.mk)
 
@@ -32,6 +29,11 @@ VENDOR_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 # Set boot SPL
 BOOT_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 
+# Use EROFS APEX as default
+ifeq (true,$(RELEASE_APEX_USE_EROFS_PREINSTALLED))
+PRODUCT_DEFAULT_APEX_PAYLOAD_TYPE := erofs
+endif
+
 PRODUCT_VENDOR_PROPERTIES += \
     ro.vendor.boot_security_patch=$(BOOT_SECURITY_PATCH)
 
@@ -73,7 +75,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/emulated_storage.mk)
 # partition, instead of the vendor partition, and do not need vendor
 # sepolicy
 PRODUCT_PRODUCT_PROPERTIES += \
-    remote_provisioning.hostname=staging-remoteprovisioning.sandbox.googleapis.com \
+    remote_provisioning.hostname=preprod-remoteprovisioning.googleapis.com \
     persist.adb.tcp.port=5555 \
     ro.com.google.locationfeatures=1 \
     persist.sys.fuse.passthrough.enable=true \
@@ -202,6 +204,7 @@ PRODUCT_PACKAGES += \
     cuttlefish_overlay_nfc \
     cuttlefish_overlay_settings_provider \
     cuttlefish_overlay_uwb \
+    cuttlefish_overlay_uwb_gsi \
 
 #
 # Satellite vendor service for CF
@@ -216,10 +219,10 @@ PRODUCT_PACKAGES += CFSatelliteService
 #
 
 ifeq ($(RELEASE_AIDL_USE_UNFROZEN),true)
-PRODUCT_SHIPPING_API_LEVEL := 36
+PRODUCT_SHIPPING_API_LEVEL := 37
 LOCAL_DEVICE_FCM_MANIFEST_FILE ?= device/google/cuttlefish/shared/config/manifest.xml
 else
-PRODUCT_SHIPPING_API_LEVEL := 35
+PRODUCT_SHIPPING_API_LEVEL := 36
 LOCAL_DEVICE_FCM_MANIFEST_FILE ?= device/google/cuttlefish/shared/config/previous_manifest.xml
 endif
 DEVICE_MANIFEST_FILE += $(LOCAL_DEVICE_FCM_MANIFEST_FILE)
@@ -241,14 +244,8 @@ PRODUCT_COPY_FILES += \
     device/google/cuttlefish/shared/config/seriallogging.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/seriallogging.rc \
     device/google/cuttlefish/shared/config/ueventd.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
     device/google/cuttlefish/shared/permissions/privapp-permissions-cuttlefish.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/privapp-permissions-cuttlefish.xml \
-    frameworks/av/media/libeffects/data/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml \
     frameworks/av/media/libstagefright/data/media_codecs_google_audio.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_audio.xml \
     frameworks/av/media/libstagefright/data/media_codecs_google_telephony.xml:$(TARGET_COPY_OUT_VENDOR)/etc/media_codecs_google_telephony.xml \
-    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
-    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml \
-    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/surround_sound_configuration_5_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/surround_sound_configuration_5_0.xml \
-    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/usb_audio_policy_configuration.xml \
     frameworks/native/data/etc/android.hardware.ethernet.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.ethernet.xml \
     frameworks/native/data/etc/android.hardware.usb.accessory.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.accessory.xml \
     frameworks/native/data/etc/android.hardware.usb.host.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.usb.host.xml \
@@ -260,6 +257,16 @@ PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.software.ipsec_tunnels.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.ipsec_tunnels.xml \
     frameworks/native/data/etc/android.software.verified_boot.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.software.verified_boot.xml \
 
+ifneq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),true)
+PRODUCT_COPY_FILES += \
+    frameworks/av/media/libeffects/data/audio_effects.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects.xml \
+    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
+    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml \
+    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
+    frameworks/av/services/audiopolicy/config/surround_sound_configuration_5_0.xml:$(TARGET_COPY_OUT_VENDOR)/etc/surround_sound_configuration_5_0.xml \
+    frameworks/av/services/audiopolicy/config/usb_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/usb_audio_policy_configuration.xml
+endif
+
 #
 # Device input config
 # Install .kcm/.kl/.idc files via input.config apex
@@ -270,6 +277,7 @@ PRODUCT_PACKAGES += \
     fstab.cf.f2fs.hctr2 \
     fstab.cf.f2fs.hctr2.vendor_ramdisk \
     fstab.cf.f2fs.cts \
+    fstab.cf.f2fs.cts.recovery \
     fstab.cf.f2fs.cts.vendor_ramdisk \
     fstab.cf.ext4.hctr2 \
     fstab.cf.ext4.hctr2.vendor_ramdisk \
@@ -307,16 +315,15 @@ PRODUCT_SYSTEM_EXT_PROPERTIES += \
     ro.audio.ihaladaptervendorextension_enabled=true
 endif
 
+ifneq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),true)
 ifndef LOCAL_AUDIO_PRODUCT_COPY_FILES
 LOCAL_AUDIO_PRODUCT_COPY_FILES := \
     device/google/cuttlefish/shared/config/audio/policy/audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_configuration.xml \
-    device/google/cuttlefish/shared/config/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/r_submix_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/r_submix_audio_policy_configuration.xml \
-    frameworks/av/services/audiopolicy/config/audio_policy_volumes.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_policy_volumes.xml \
-    frameworks/av/services/audiopolicy/config/default_volume_tables.xml:$(TARGET_COPY_OUT_VENDOR)/etc/default_volume_tables.xml
+    device/google/cuttlefish/shared/config/audio/policy/primary_audio_policy_configuration.xml:$(TARGET_COPY_OUT_VENDOR)/etc/primary_audio_policy_configuration.xml
 LOCAL_AUDIO_PRODUCT_COPY_FILES += \
     hardware/interfaces/audio/aidl/default/audio_effects_config.xml:$(TARGET_COPY_OUT_VENDOR)/etc/audio_effects_config.xml
 endif
+endif
 
 PRODUCT_PACKAGES += $(LOCAL_AUDIO_PRODUCT_PACKAGE)
 PRODUCT_COPY_FILES += $(LOCAL_AUDIO_PRODUCT_COPY_FILES)
@@ -417,18 +424,15 @@ endif
 #
 ifeq ($(RELEASE_AVF_ENABLE_EARLY_VM),true)
   TRUSTY_KEYMINT_IMPL ?= rust
-  TRUSTY_SYSTEM_VM ?= nonsecure
+  TRUSTY_SYSTEM_VM ?= enabled_with_placeholder_trusted_hal
 endif
-ifeq ($(TRUSTY_SYSTEM_VM),nonsecure)
-    $(call inherit-product, system/core/trusty/keymint/trusty-keymint.mk)
+ifeq ($(TRUSTY_SYSTEM_VM), enabled_with_placeholder_trusted_hal)
+    $(call soong_config_set_bool, trusty_system_vm, enabled, true)
+    $(call soong_config_set_bool, trusty_system_vm, placeholder_trusted_hal, true)
+    $(call soong_config_set, trusty_system_vm, buildtype, $(TARGET_BUILD_VARIANT))
+    $(call inherit-product, system/core/trusty/keymint/trusty-keymint-apex.mk)
     $(call inherit-product, system/core/trusty/trusty-storage-cf.mk)
-    PRODUCT_PACKAGES += \
-        lk_trusty.elf \
-        trusty_security_vm_launcher \
-        early_vms.xml \
-        cf-trusty_security_vm_launcher.rc \
-        lk_trusty.elf \
-        trusty-ut-ctrl.system \
+    $(call inherit-product, packages/modules/Virtualization/guest/trusty/security_vm/security_vm.mk)
 
 endif
 
diff --git a/shared/foldable/device_state_configuration.xml b/shared/foldable/device_state_configuration.xml
index f6377c66a..be20981ab 100644
--- a/shared/foldable/device_state_configuration.xml
+++ b/shared/foldable/device_state_configuration.xml
@@ -65,6 +65,20 @@
     </properties>
   </device-state>
 
+  <device-state>
+    <identifier>4</identifier>
+    <name>CONCURRENT_INNER_DEFAULT</name>
+    <properties>
+        <property>com.android.server.policy.PROPERTY_EMULATED_ONLY</property>
+        <property>com.android.server.policy.PROPERTY_POLICY_CANCEL_WHEN_REQUESTER_NOT_ON_TOP</property>
+        <property>com.android.server.policy.PROPERTY_POLICY_UNSUPPORTED_WHEN_THERMAL_STATUS_CRITICAL</property>
+        <property>com.android.server.policy.PROPERTY_POLICY_UNSUPPORTED_WHEN_POWER_SAVE_MODE</property>
+        <property>com.android.server.policy.PROPERTY_POLICY_AVAILABLE_FOR_APP_REQUEST</property>
+        <property>com.android.server.policy.PROPERTY_FOLDABLE_DISPLAY_CONFIGURATION_INNER_PRIMARY</property>
+        <property>com.android.server.policy.PROPERTY_FEATURE_DUAL_DISPLAY_INTERNAL_DEFAULT</property>
+    </properties>
+  </device-state>
+
   <device-state>
     <identifier>5</identifier>
     <name>REAR_DISPLAY_OUTER_DEFAULT</name>
diff --git a/shared/foldable/display_layout_configuration.xml b/shared/foldable/display_layout_configuration.xml
index c5f57c853..c448a2c0a 100644
--- a/shared/foldable/display_layout_configuration.xml
+++ b/shared/foldable/display_layout_configuration.xml
@@ -51,4 +51,46 @@
       <address>4619827353912518657</address>
     </display>
   </layout>
+
+  <layout>
+  <!-- CONCURRENT_INNER_DEFAULT -->
+    <state>4</state>
+    <display enabled="true" defaultDisplay="true" refreshRateZoneId="concurrent">
+        <address>4619827353912518656</address>
+        <position>front</position>
+        <brightnessThrottlingMapId>concurrent</brightnessThrottlingMapId>
+        <refreshRateThermalThrottlingMapId>concurrent</refreshRateThermalThrottlingMapId>
+    </display>
+
+    <display enabled="true" refreshRateZoneId="concurrent">
+        <address>4619827353912518657</address>
+        <position>rear</position>
+        <brightnessThrottlingMapId>concurrent</brightnessThrottlingMapId>
+        <leadDisplayAddress>4619827353912518656</leadDisplayAddress>
+    </display>
+  </layout>
+
+  <layout>
+  <!-- REAR_DISPLAY_OUTER_DEFAULT -->
+    <state>5</state>
+    <display enabled="true" defaultDisplay="true" refreshRateZoneId="concurrent">
+      <address>4619827353912518657</address>
+      <!-- Although this is the outer "rear" display, in this mode it is front relative
+           to the user. The inner display which is facing away from the user is the
+           rear display. Configuring it this way also means that DisplayManagerService's
+           mirrororing logic can correctly prevent the outer display's content from
+           being mirrored onto the inner display. -->
+      <position>front</position>
+      <brightnessThrottlingMapId>concurrent</brightnessThrottlingMapId>
+    </display>
+
+    <display enabled="true" refreshRateZoneId="concurrent">
+        <address>4619827353912518656</address>
+        <position>rear</position>
+        <brightnessThrottlingMapId>concurrent</brightnessThrottlingMapId>
+        <refreshRateThermalThrottlingMapId>concurrent</refreshRateThermalThrottlingMapId>
+        <leadDisplayAddress>4619827353912518657</leadDisplayAddress>
+    </display>
+  </layout>
+
 </layouts>
diff --git a/shared/graphics/device_vendor.mk b/shared/graphics/device_vendor.mk
index 6f2052abd..a44886f99 100644
--- a/shared/graphics/device_vendor.mk
+++ b/shared/graphics/device_vendor.mk
@@ -62,6 +62,10 @@ PRODUCT_VENDOR_PROPERTIES += \
 # does not emulate "real display timing".
 PRODUCT_VENDOR_PROPERTIES += ro.vendor.hwc.drm.present_fence_not_reliable=true
 
+# drm_hwcomposer uses all display cards available by default.
+# Force using virtio_gpu (card0) exclusively.
+PRODUCT_VENDOR_PROPERTIES += vendor.hwc.drm.device=/dev/dri/card0
+
 PRODUCT_SYSTEM_PROPERTIES += \
     service.sf.prime_shader_cache=0
 
diff --git a/shared/graphics/sepolicy/file_contexts b/shared/graphics/sepolicy/file_contexts
index 5027637c7..ee2ff6381 100644
--- a/shared/graphics/sepolicy/file_contexts
+++ b/shared/graphics/sepolicy/file_contexts
@@ -2,6 +2,7 @@
 
 /dev/dri u:object_r:gpu_device:s0
 /dev/dri/card0  u:object_r:graphics_device:s0
+/dev/dri/card1  u:object_r:graphics_device:s0
 /dev/dri/renderD128  u:object_r:gpu_device:s0
 
 /vendor/bin/hw/android\.hardware\.graphics\.allocator-service\.minigbm   u:object_r:hal_graphics_allocator_default_exec:s0
diff --git a/shared/graphics/sepolicy/hal_graphics_composer_default.te b/shared/graphics/sepolicy/hal_graphics_composer_default.te
index 643c2d9a4..5626e72a1 100644
--- a/shared/graphics/sepolicy/hal_graphics_composer_default.te
+++ b/shared/graphics/sepolicy/hal_graphics_composer_default.te
@@ -7,6 +7,11 @@ allow hal_graphics_composer_default kmsg_device:chr_file w_file_perms;
 
 allow hal_graphics_composer_default hal_graphics_mapper_service:service_manager find;
 
+# inherited from attribute hal_graphics_composer_server
+starting_at_board_api(202504, `
+typeattribute hal_graphics_composer_default unconstrained_vsock_violators;
+')
+
 # Suppress warnings for drm_hwcomposer trying to read some vendor.hwc.*
 # properties as Cuttlefish never configures these properties.
-dontaudit hal_graphics_composer_default default_prop:file read;
\ No newline at end of file
+dontaudit hal_graphics_composer_default default_prop:file read;
diff --git a/shared/minidroid/BoardConfig.mk b/shared/minidroid/BoardConfig.mk
index 6af12fae4..2c2c637ee 100644
--- a/shared/minidroid/BoardConfig.mk
+++ b/shared/minidroid/BoardConfig.mk
@@ -16,7 +16,7 @@
 
 # FIXME: Split up and merge back in with shared/BoardConfig.mk
 
-TARGET_KERNEL_USE ?= 6.1
+TARGET_KERNEL_USE ?= 6.12
 TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
 TARGET_KERNEL_PATH ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)/kernel-$(TARGET_KERNEL_USE)
 KERNEL_MODULES_PATH ?= \
diff --git a/shared/minidroid/device.mk b/shared/minidroid/device.mk
index f7d0f2a9f..04a9cc17e 100644
--- a/shared/minidroid/device.mk
+++ b/shared/minidroid/device.mk
@@ -29,11 +29,6 @@ BOOT_SECURITY_PATCH := $(PLATFORM_SECURITY_PATCH)
 PRODUCT_VENDOR_PROPERTIES += \
     ro.vendor.boot_security_patch=$(BOOT_SECURITY_PATCH)
 
-# Disable Treble and the VNDK
-PRODUCT_FULL_TREBLE_OVERRIDE := false
-PRODUCT_USE_VNDK_OVERRIDE := false
-PRODUCT_USE_PRODUCT_VNDK_OVERRIDE := false
-
 PRODUCT_SHIPPING_API_LEVEL := 33
 
 PRODUCT_USE_DYNAMIC_PARTITIONS := true
diff --git a/shared/minidroid/sample/aidl/com/android/minidroid/testservice/ITestService.aidl b/shared/minidroid/sample/aidl/com/android/minidroid/testservice/ITestService.aidl
index 59b862044..ee7c6061b 100644
--- a/shared/minidroid/sample/aidl/com/android/minidroid/testservice/ITestService.aidl
+++ b/shared/minidroid/sample/aidl/com/android/minidroid/testservice/ITestService.aidl
@@ -1,7 +1,7 @@
 package com.android.minidroid.testservice;
 
 interface ITestService {
-    const int SERVICE_PORT = 5678;
+    const int PORT = 5678;
 
     /* make server process print 'Hello World' to stdout. */
     void sayHello();
diff --git a/shared/minidroid/sample/server.cpp b/shared/minidroid/sample/server.cpp
index 2656d9a1f..c0a461de7 100644
--- a/shared/minidroid/sample/server.cpp
+++ b/shared/minidroid/sample/server.cpp
@@ -45,7 +45,7 @@ void start_test_service() {
   };
   auto testService = ndk::SharedRefBase::make<TestService>();
 
-  bi::sd::setupRpcServer(testService->asBinder(), testService->SERVICE_PORT);
+  bi::sd::setupRpcServer(testService->asBinder(), testService->PORT);
 }
 }  // namespace
 
diff --git a/shared/overlays/foldable/core/res/values/config.xml b/shared/overlays/foldable/core/res/values/config.xml
index 36ba4cdd8..d978408f0 100644
--- a/shared/overlays/foldable/core/res/values/config.xml
+++ b/shared/overlays/foldable/core/res/values/config.xml
@@ -21,10 +21,12 @@
   <string name="config_display_features" translatable="false">fold-[884,0,884,2208]</string>
   <!-- Map of System DeviceState supplied by DeviceStateManager to WM Jetpack posture. -->
   <string-array name="config_device_state_postures" translatable="false">
-      <item>0:1</item> <!-- CLOSED : STATE_FLAT -->
-      <item>1:2</item> <!-- HALF_OPENED : STATE_HALF_OPENED -->
-      <item>2:3</item> <!-- OPENED : STATE_FLIPPED -->
-      <item>3:1</item> <!-- REAR_DISPLAY: STATE_FLAT -->
+      <item>0:1</item>    <!-- CLOSED                     : STATE_FLAT -->
+      <item>1:2</item>    <!-- HALF_OPENED                : STATE_HALF_OPENED -->
+      <item>2:3</item>    <!-- OPENED                     : STATE_FLIPPED -->
+      <item>3:1</item>    <!-- REAR_DISPLAY               : STATE_FLAT -->
+      <item>4:1000</item> <!-- CONCURRENT                 : COMMON_STATE_USE_BASE_STATE -->
+      <item>5:1</item>    <!-- REAR_DISPLAY_OUTER_DEFAULT : COMMON_STATE_NO_FOLDING_FEATURES -->
   </string-array>
 
   <!-- Map of DeviceState to rotation lock setting. Each entry must be in the format "key:value",
@@ -62,6 +64,7 @@
        state. Default is empty. -->
   <integer-array name="config_rearDisplayDeviceStates" translatable="false">
     <item>3</item> <!-- REAR_DISPLAY_STATE -->
+    <item>5</item> <!-- REAR_DISPLAY_OUTER_DEFAULT -->
   </integer-array>
 
   <!-- Indicates whether to enable an animation when unfolding a device or not -->
diff --git a/shared/overlays/nfc/res/values/config.xml b/shared/overlays/nfc/res/values/config.xml
index 4f822693b..8d669ba0a 100644
--- a/shared/overlays/nfc/res/values/config.xml
+++ b/shared/overlays/nfc/res/values/config.xml
@@ -15,4 +15,5 @@
 -->
 <resources>
   <bool name="nfc_observe_mode_supported">true</bool>
+  <bool name="nfc_proprietary_getcaps_supported">true</bool>
 </resources>
diff --git a/shared/overlays/uwb/Android.bp b/shared/overlays/uwb/Android.bp
index aa7847753..b71d38e67 100644
--- a/shared/overlays/uwb/Android.bp
+++ b/shared/overlays/uwb/Android.bp
@@ -7,3 +7,10 @@ runtime_resource_overlay {
     sdk_version: "current",
     product_specific: true,
 }
+
+// GSI replaces product_specific overlay, keep a separte config for GSI with vendor: true
+runtime_resource_overlay {
+    name: "cuttlefish_overlay_uwb_gsi",
+    sdk_version: "current",
+    vendor: true,
+}
diff --git a/shared/sensors/multihal/entry.cpp b/shared/sensors/multihal/entry.cpp
index 3d0f11e5a..88d764c6a 100644
--- a/shared/sensors/multihal/entry.cpp
+++ b/shared/sensors/multihal/entry.cpp
@@ -15,8 +15,8 @@
  */
 
 #include <log/log.h>
-#include <multihal_sensors_transport.h>
 #include <multihal_sensors.h>
+#include <multihal_sensors_transport.h>
 
 #include "common/libs/transport/channel_sharedfd.h"
 
@@ -26,8 +26,8 @@ namespace {
 
 class VconsoleSensorsTransport : public goldfish::SensorsTransport {
  public:
-  VconsoleSensorsTransport(const char* path)
-      : console_sensors_fd_(cuttlefish::SharedFD::Open(path, O_RDWR)),
+  VconsoleSensorsTransport(cuttlefish::SharedFD fd)
+      : console_sensors_fd_(std::move(fd)),
         pure_sensors_fd_(console_sensors_fd_->UNMANAGED_Dup()),
         sensors_channel_(console_sensors_fd_, console_sensors_fd_) {}
 
@@ -36,7 +36,8 @@ class VconsoleSensorsTransport : public goldfish::SensorsTransport {
   int Send(const void* msg, int size) override {
     auto message_result = cuttlefish::transport::CreateMessage(0, size);
     if (!message_result.ok()) {
-      LOG(ERROR) << "Failed to allocate sensors message with size: " << size << " bytes. "
+      LOG(ERROR) << "Failed to allocate sensors message with size: " << size
+                 << " bytes. "
                  << "Error message: " << message_result.error().Message();
       return -1;
     }
@@ -46,7 +47,8 @@ class VconsoleSensorsTransport : public goldfish::SensorsTransport {
 
     auto send_result = sensors_channel_.SendRequest(*message);
     if (!send_result.ok()) {
-      LOG(ERROR) << "Failed to send sensors message with size: " << size << " bytes. "
+      LOG(ERROR) << "Failed to send sensors message with size: " << size
+                 << " bytes. "
                  << "Error message: " << send_result.error().Message();
       return -1;
     }
@@ -91,13 +93,23 @@ class VconsoleSensorsTransport : public goldfish::SensorsTransport {
 
 }  // namespace
 
+inline constexpr const char kSensorsConsolePath[] = "/dev/hvc13";
+
 extern "C" ISensorsSubHal* sensorsHalGetSubHal_2_1(uint32_t* version) {
   // Leaking the memory intentionally to make sure this object is available
   // for other threads after main thread is terminated:
   // https://google.github.io/styleguide/cppguide.html#Static_and_Global_Variables
   // go/totw/110#destruction
   static goldfish::MultihalSensors* impl = new goldfish::MultihalSensors([]() {
-    return std::make_unique<VconsoleSensorsTransport>("/dev/hvc13");
+    const auto fd = cuttlefish::SharedFD::Open(kSensorsConsolePath, O_RDWR);
+    if (!fd->IsOpen()) {
+      LOG(FATAL) << "Could not connect to sensors: " << fd->StrError();
+    }
+    if (fd->SetTerminalRaw() < 0) {
+      LOG(FATAL) << "Could not make " << kSensorsConsolePath
+                 << " a raw terminal: " << fd->StrError();
+    }
+    return std::make_unique<VconsoleSensorsTransport>(fd);
   });
 
   *version = SUB_HAL_2_1_VERSION;
diff --git a/shared/sepolicy/product/private/tombstone_transmit.te b/shared/sepolicy/product/private/tombstone_transmit.te
index 289be52da..6b0d8cf17 100644
--- a/shared/sepolicy/product/private/tombstone_transmit.te
+++ b/shared/sepolicy/product/private/tombstone_transmit.te
@@ -9,4 +9,5 @@ get_prop(tombstone_transmit, vsock_tombstone_port_prop)
 allow tombstone_transmit self:capability net_admin;
 r_dir_file(tombstone_transmit, tombstone_data_file)
 
+typeattribute tombstone_transmit unconstrained_vsock_violators;
 allow tombstone_transmit self:{ vsock_socket } create_socket_perms_no_ioctl;
diff --git a/shared/sepolicy/system_ext/private/audio_vendor_parameter_parser_service.te b/shared/sepolicy/system_ext/private/audio_vendor_parameter_parser_service.te
index 155c8404a..6d0e84995 100644
--- a/shared/sepolicy/system_ext/private/audio_vendor_parameter_parser_service.te
+++ b/shared/sepolicy/system_ext/private/audio_vendor_parameter_parser_service.te
@@ -10,4 +10,8 @@ add_service(audio_vendor_parameter_parser, audio_vendor_parameter_parser_service
 binder_call(audioserver, audio_vendor_parameter_parser)
 binder_call(audio_vendor_parameter_parser, servicemanager)
 
+# Add permission to access/read and get system properties
+# ro.audio.ihaladaptervendorextension_libname
+get_prop(audio_vendor_parameter_parser, system_audio_config_prop)
+
 allow audioserver audio_vendor_parameter_parser_service:service_manager find;
diff --git a/shared/sepolicy/system_ext/private/file_contexts b/shared/sepolicy/system_ext/private/file_contexts
index 57b3a5aa9..9499114d5 100644
--- a/shared/sepolicy/system_ext/private/file_contexts
+++ b/shared/sepolicy/system_ext/private/file_contexts
@@ -1,6 +1,7 @@
 /data/vendor/radio(/.*)?               u:object_r:radio_vendor_data_file:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hardware\.audio\.parameter_parser\.example_service u:object_r:audio_vendor_parameter_parser_exec:s0
 /(system_ext|system/system_ext)/bin/hw/android\.hardware\.security\.keymint-service\.rust\.trusty\.system\.nonsecure  u:object_r:hal_keymint_system_exec:s0
+/(system_ext|system/system_ext)/bin/hw/android\.hardware\.security\.keymint-service\.trusty_system_vm  u:object_r:hal_keymint_system_exec:s0
 is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
     /(system_ext|system/system_ext)/bin/trusty_security_vm_launcher u:object_r:trusty_security_vm_launcher_exec:s0
 ')
diff --git a/shared/sepolicy/system_ext/private/secure_storage_system.te b/shared/sepolicy/system_ext/private/secure_storage_system.te
index 4d7e653ed..8b85e09fd 100644
--- a/shared/sepolicy/system_ext/private/secure_storage_system.te
+++ b/shared/sepolicy/system_ext/private/secure_storage_system.te
@@ -28,6 +28,7 @@ allow rpmb_dev_wv_system rpmb_dev_system_socket:sock_file rw_file_perms;
 
 #============= storageproxyd_system ==============
 type storageproxyd_system, domain, coredomain;
+typeattribute storageproxyd_system unconstrained_vsock_violators;
 type storageproxyd_system_exec, exec_type, system_file_type, file_type;
 type secure_storage_persist_system_file, file_type, data_file_type, core_data_file_type;
 type secure_storage_system_file, file_type, data_file_type, core_data_file_type;
diff --git a/shared/sepolicy/system_ext/public/file.te b/shared/sepolicy/system_ext/public/file.te
new file mode 100644
index 000000000..2fd615044
--- /dev/null
+++ b/shared/sepolicy/system_ext/public/file.te
@@ -0,0 +1 @@
+type ti50_char_device, dev_type;
diff --git a/shared/sepolicy/system_ext/public/uevent.te b/shared/sepolicy/system_ext/public/uevent.te
new file mode 100644
index 000000000..e5be47d4f
--- /dev/null
+++ b/shared/sepolicy/system_ext/public/uevent.te
@@ -0,0 +1 @@
+allow ueventd ti50_char_device:chr_file { rw_file_perms create setattr };
diff --git a/shared/sepolicy/vendor/file_contexts b/shared/sepolicy/vendor/file_contexts
index f5a5cbec0..b290a629b 100644
--- a/shared/sepolicy/vendor/file_contexts
+++ b/shared/sepolicy/vendor/file_contexts
@@ -43,9 +43,12 @@
 
 # hvc14 for MCU control
 /dev/hvc14  u:object_r:mcu_control_device:s0
-# hvc14 for MCU UART
+# hvc15 for MCU UART
 /dev/hvc15  u:object_r:mcu_uart_device:s0
 
+# hvc16 for Ti50 emulator
+/dev/hvc16  u:object_r:ti50_char_device:s0
+
 # ARM serial console device
 /dev/ttyAMA[0-9]*  u:object_r:serial_device:s0
 
diff --git a/shared/sepolicy/vendor/hal_light_cuttlefish.te b/shared/sepolicy/vendor/hal_light_cuttlefish.te
index e02f8e042..56ef539fa 100644
--- a/shared/sepolicy/vendor/hal_light_cuttlefish.te
+++ b/shared/sepolicy/vendor/hal_light_cuttlefish.te
@@ -4,4 +4,7 @@ hal_server_domain(hal_light_cuttlefish, hal_light)
 type hal_light_cuttlefish_exec, exec_type, vendor_file_type, file_type;
 init_daemon_domain(hal_light_cuttlefish)
 
+starting_at_board_api(202504, `
+typeattribute hal_light_cuttlefish unconstrained_vsock_violators;
+')
 allow hal_light_cuttlefish self:{ socket vsock_socket } { create_socket_perms_no_ioctl listen accept };
diff --git a/shared/sepolicy/vendor/socket_vsock_proxy.te b/shared/sepolicy/vendor/socket_vsock_proxy.te
index 6f729639d..65f540978 100644
--- a/shared/sepolicy/vendor/socket_vsock_proxy.te
+++ b/shared/sepolicy/vendor/socket_vsock_proxy.te
@@ -6,6 +6,9 @@ init_daemon_domain(socket_vsock_proxy)
 allow socket_vsock_proxy self:global_capability_class_set { net_admin net_raw };
 allow socket_vsock_proxy self:{ socket vsock_socket } { create getopt read write getattr listen accept bind shutdown };
 
+starting_at_board_api(202504, `
+typeattribute socket_vsock_proxy unconstrained_vsock_violators;
+')
 # TODO: socket returned by accept() has unlabeled context on it. Give it a
 # specific label.
 allow socket_vsock_proxy unlabeled:{ socket vsock_socket } { getopt read write shutdown };
diff --git a/shared/sepolicy/vendor/telephony/libcuttlefish_rild.te b/shared/sepolicy/vendor/telephony/libcuttlefish_rild.te
index 6e2958e7b..a1e52a3fb 100644
--- a/shared/sepolicy/vendor/telephony/libcuttlefish_rild.te
+++ b/shared/sepolicy/vendor/telephony/libcuttlefish_rild.te
@@ -10,5 +10,8 @@ net_domain(libcuttlefish_rild)
 
 get_prop(libcuttlefish_rild, vendor_modem_simulator_ports_prop)
 
+starting_at_board_api(202504, `
+typeattribute libcuttlefish_rild unconstrained_vsock_violators;
+')
 allow libcuttlefish_rild self:{ socket vsock_socket } { create_socket_perms_no_ioctl getattr };
-allow libcuttlefish_rild su:{ socket udp_socket } { create_socket_perms_no_ioctl getattr };
\ No newline at end of file
+allow libcuttlefish_rild su:{ socket udp_socket } { create_socket_perms_no_ioctl getattr };
diff --git a/shared/sepolicy/vendor/vendor_init.te b/shared/sepolicy/vendor/vendor_init.te
index b36ae6769..0122fab9a 100644
--- a/shared/sepolicy/vendor/vendor_init.te
+++ b/shared/sepolicy/vendor/vendor_init.te
@@ -2,6 +2,7 @@ vendor_internal_prop(vendor_graphics_config_prop)
 
 allow vendor_init {
   audio_device
+  graphics_device
 }:chr_file { getattr };
 
 set_prop(vendor_init, vendor_hwcomposer_prop)
diff --git a/shared/telephony/device_vendor.mk b/shared/telephony/device_vendor.mk
index 954076efa..2038ee4ad 100644
--- a/shared/telephony/device_vendor.mk
+++ b/shared/telephony/device_vendor.mk
@@ -20,13 +20,6 @@ ifneq ($(TARGET_NO_TELEPHONY), true)
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_vendor.mk)
 
-PRODUCT_VENDOR_PROPERTIES += \
-    keyguard.no_require_sim=true \
-    ro.cdma.home.operator.alpha=Android \
-    ro.cdma.home.operator.numeric=302780 \
-    ro.com.android.dataroaming=true \
-    ro.telephony.default_network=9 \
-
 # If downstream target provides its own RILD, set TARGET_USES_CF_RILD := false
 TARGET_USES_CF_RILD ?= true
 ifeq ($(TARGET_USES_CF_RILD),true)
diff --git a/shared/wear/aosp_system.mk b/shared/wear/aosp_system.mk
index 8e3e09626..ea1b93aa5 100644
--- a/shared/wear/aosp_system.mk
+++ b/shared/wear/aosp_system.mk
@@ -39,7 +39,6 @@ PRODUCT_PACKAGES += \
     $(RELEASE_PACKAGE_NFC_STACK) \
     netutils-wrapper-1.0 \
     screenrecord \
-    StatementService \
     TelephonyProvider \
     TeleService \
     UserDictionaryProvider \
diff --git a/shared/wear/aosp_system_ext.mk b/shared/wear/aosp_system_ext.mk
index 2fade9abd..6d9bd9735 100644
--- a/shared/wear/aosp_system_ext.mk
+++ b/shared/wear/aosp_system_ext.mk
@@ -16,4 +16,6 @@
 
 $(call inherit-product, $(SRC_TARGET_DIR)/product/base_system_ext.mk)
 
-PRODUCT_PACKAGES += CarrierConfig
+PRODUCT_PACKAGES += \
+    CarrierConfig \
+    StatementService \
diff --git a/shared/wear/aosp_vendor.mk b/shared/wear/aosp_vendor.mk
index c837fb119..831e7f01e 100644
--- a/shared/wear/aosp_vendor.mk
+++ b/shared/wear/aosp_vendor.mk
@@ -27,7 +27,6 @@ PRODUCT_PACKAGES += \
     CellBroadcastAppPlatform \
     CellBroadcastServiceModulePlatform \
     com.android.tethering \
-    InProcessNetworkStack \
 
 PRODUCT_MINIMIZE_JAVA_DEBUG_INFO := true
 
diff --git a/shared/wear/device_vendor.mk b/shared/wear/device_vendor.mk
index f7046b844..502dcaf97 100644
--- a/shared/wear/device_vendor.mk
+++ b/shared/wear/device_vendor.mk
@@ -44,7 +44,7 @@ $(call inherit-product, device/google/cuttlefish/shared/device.mk)
 PRODUCT_COPY_FILES += \
     frameworks/native/data/etc/android.hardware.audio.output.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.audio.output.xml \
     frameworks/native/data/etc/android.hardware.faketouch.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.faketouch.xml \
-    frameworks/native/data/etc/android.hardware.location.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.location.xml \
+    frameworks/native/data/etc/android.hardware.sensor.compass.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/android.hardware.sensor.compass.xml \
 
 # Runtime Resource Overlays
 PRODUCT_PACKAGES += \
diff --git a/tests/graphics/Android.bp b/tests/graphics/Android.bp
index e489161fd..3b851dda3 100644
--- a/tests/graphics/Android.bp
+++ b/tests/graphics/Android.bp
@@ -18,12 +18,12 @@ package {
 
 java_test_host {
     name: "CuttlefishDisplayHotplugTest",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
     srcs: [
         "src/com/android/cuttlefish/tests/CuttlefishDisplayHotplugTest.java",
     ],
-    data_native_bins: [
-        "cvd_internal_display",
-    ],
     test_options: {
         unit_test: false,
     },
@@ -35,9 +35,6 @@ java_test_host {
         "cts-tradefed",
         "tradefed",
     ],
-    static_libs: [
-        "cuttlefish_host_test_utils",
-    ],
     plugins: [
         "auto_annotation_plugin",
         "auto_value_plugin",
@@ -47,6 +44,34 @@ java_test_host {
     ],
 }
 
+java_test_host {
+    name: "CuttlefishDisplayTests",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
+    srcs: [
+        "src/com/android/cuttlefish/tests/CuttlefishDisplayTests.java",
+    ],
+    test_options: {
+        unit_test: false,
+    },
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "compatibility-host-util",
+        "cts-tradefed",
+        "tradefed",
+    ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
+    device_common_data: [
+        ":CuttlefishVulkanSamplesFullscreenColor",
+    ],
+}
+
 java_test_host {
     name: "CuttlefishGraphicsConfigurationTest",
     srcs: [
@@ -65,6 +90,9 @@ java_test_host {
 
 java_test_host {
     name: "CuttlefishVulkanSnapshotTests",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
     srcs: [
         "src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java",
     ],
diff --git a/tests/graphics/display/Android.bp b/tests/graphics/display/Android.bp
new file mode 100644
index 000000000..961ac38f1
--- /dev/null
+++ b/tests/graphics/display/Android.bp
@@ -0,0 +1,69 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_binary {
+    name: "simply_red",
+    defaults: ["hwc_deps"],
+    srcs: [
+        "./src/simply_red.cpp",
+    ],
+    static_libs: [
+        "hwc_tester",
+    ],
+    include_dirs: [
+        "platform_testing/tests/display/hcct/utils",
+    ],
+    compile_multilib: "both",
+    multilib: {
+        lib32: {
+            suffix: "32",
+        },
+        lib64: {
+            suffix: "",
+        },
+    },
+}
+
+java_test_host {
+    name: "CuttlefishHwcRedSmokeTest",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
+    srcs: [
+        "CuttlefishHwcRedSmokeTest.java",
+    ],
+    data_device_bins_both: [
+        "simply_red",
+    ],
+    test_options: {
+        unit_test: false,
+    },
+    test_suites: [
+        "device-tests",
+    ],
+    libs: [
+        "compatibility-host-util",
+        "cts-tradefed",
+        "tradefed",
+    ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
+    test_config_template: "display_config_template.xml",
+}
diff --git a/tests/graphics/display/CuttlefishHwcRedSmokeTest.java b/tests/graphics/display/CuttlefishHwcRedSmokeTest.java
new file mode 100644
index 000000000..a5105c4cf
--- /dev/null
+++ b/tests/graphics/display/CuttlefishHwcRedSmokeTest.java
@@ -0,0 +1,83 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+package com.android.cuttlefish.tests;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.cuttlefish.tests.utils.UnlockScreenRule;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import java.awt.Color;
+import java.util.Arrays;
+import java.util.List;
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+
+/**
+ * Tests that exercises HWC operations. By using `simply_red` binary, test that the HWC is showing a
+ * red color on the screen by taking a screenshot through Cuttlefish to verify the HWC output.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class CuttlefishHwcRedSmokeTest extends CuttlefishHostTest {
+    @Rule public TestLogData mLogs = new TestLogData();
+
+    private static final String HWC_TEST_BINARY = "simply_red";
+    private static final String DEVICE_TEST_DIR =
+        "/data/cf_display_tests/" + CuttlefishHwcRedSmokeTest.class.getSimpleName();
+    private Thread binaryRunThread;
+
+    @Before
+    public void setUp() throws Exception {
+        // The binary runs indefinitely to maintain the color on the screen.
+        // Host test doesn't allow commands to run in the background using `&`, so we start the
+        // binary in a separate thread here.
+        binaryRunThread = new Thread(() -> {
+            try {
+                getDevice().executeShellCommand(DEVICE_TEST_DIR + "/" + HWC_TEST_BINARY);
+            } catch (Exception e) {
+                CLog.e("Error running HWC_TEST_BINARY: " + e.toString());
+            }
+        });
+        binaryRunThread.start();
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        getDevice().executeShellCommand("pkill " + HWC_TEST_BINARY);
+        binaryRunThread.interrupt();
+    }
+
+    @Test
+    public void testHwcRedDisplay() throws Exception {
+        final WaitForColorsResult result =
+            waitForColors(Arrays.asList(ExpectedColor.create(0.5f, 0.5f, Color.RED)));
+
+        if (!result.succeeded()) {
+            saveScreenshotToTestResults("screenshot", result.failureImage(), mLogs);
+        }
+
+        assertThat(result.succeeded()).isTrue();
+    }
+}
diff --git a/tests/graphics/display/OWNERS b/tests/graphics/display/OWNERS
new file mode 100644
index 000000000..5a03129ec
--- /dev/null
+++ b/tests/graphics/display/OWNERS
@@ -0,0 +1,2 @@
+markyacoub@google.com
+ddavenport@google.com
diff --git a/tests/graphics/display/display_config_template.xml b/tests/graphics/display/display_config_template.xml
new file mode 100644
index 000000000..c28eed247
--- /dev/null
+++ b/tests/graphics/display/display_config_template.xml
@@ -0,0 +1,32 @@
+<?xml version="1.0" encoding="utf-8"?>
+<!-- Copyright (C) 2025 The Android Open Source Project
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
+<configuration description="Config for Cuttlefish HWC test cases">
+    <option name="test-suite-tag" value="CfHwcTests" />
+    <target_preparer class="com.android.tradefed.targetprep.RootTargetPreparer"/>
+
+    <target_preparer class="com.android.compatibility.common.tradefed.targetprep.FilePusher">
+        <option name="push" value="{MODULE}->/data/cf_display_tests/{MODULE}" />
+    </target_preparer>
+
+    <target_preparer class="com.android.tradefed.targetprep.RunCommandTargetPreparer">
+        <option name="run-command" value="stop" />
+        <option name="teardown-command" value="start" />
+    </target_preparer>
+
+    <test class="com.android.tradefed.testtype.HostTest">
+        <option name="class" value="com.android.cuttlefish.tests.{MODULE}" />
+    </test>
+</configuration>
diff --git a/tests/graphics/display/src/simply_red.cpp b/tests/graphics/display/src/simply_red.cpp
new file mode 100644
index 000000000..76fef7564
--- /dev/null
+++ b/tests/graphics/display/src/simply_red.cpp
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <log/log.h>
+#include "Readback.h"
+#include "hwc_tester.h"
+
+/*
+ * A simple binary that takes over the HWC through its AIDL Client Wrappers and
+ * display a simple red color on the screen.
+ */
+
+static volatile bool keep_running = true;
+void signal_handler(int) { keep_running = false; }
+
+int main() {
+  hcct::HwcTester tester;
+
+  // Get all available displays
+  auto display_ids = tester.GetAllDisplayIds();
+  if (display_ids.empty()) {
+    ALOGE("No displays available");
+    return 1;
+  }
+
+  tester.DrawSolidColorToScreen(display_ids[0], libhwc_aidl_test::RED);
+
+  // Stay on, allowing the host tests to take screenshots and process.
+  signal(SIGTERM, signal_handler);
+  while (keep_running) {
+    sleep(1);
+  }
+
+  return 0;
+}
diff --git a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayTests.java b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayTests.java
new file mode 100644
index 000000000..a5d97f915
--- /dev/null
+++ b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishDisplayTests.java
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
+package com.android.cuttlefish.tests;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.cuttlefish.tests.utils.UnlockScreenRule;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
+import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
+import java.awt.Color;
+import java.awt.image.BufferedImage;
+import java.util.Arrays;
+import java.util.List;
+import javax.imageio.ImageIO;
+import org.junit.After;
+import org.junit.Assert;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TestRule;
+import org.junit.runner.RunWith;
+
+/**
+ * Tests that a Cuttlefish device can interactively connect and disconnect displays.
+ */
+@RunWith(DeviceJUnit4ClassRunner.class)
+public class CuttlefishDisplayTests extends CuttlefishHostTest {
+
+    @Rule
+    public TestLogData mLogs = new TestLogData();
+
+    @Rule
+    public final UnlockScreenRule mUnlockScreenRule = new UnlockScreenRule(this);
+
+    private static final String FULLSCREEN_COLOR_APK =
+        "CuttlefishVulkanSamplesFullscreenColor.apk";
+    private static final String FULLSCREEN_COLOR_PKG =
+        "com.android.cuttlefish.vulkan_samples.fullscreen_color";
+    private static final String FULLSCREEN_COLOR_PKG_MAIN_ACTIVITY =
+        "android.app.NativeActivity";
+
+    @Before
+    public void setUp() throws Exception {
+        getDevice().uninstallPackage(FULLSCREEN_COLOR_PKG);
+        installPackage(FULLSCREEN_COLOR_APK);
+    }
+
+    @After
+    public void tearDown() throws Exception {
+        getDevice().uninstallPackage(FULLSCREEN_COLOR_PKG);
+    }
+
+    @Test
+    public void testBasicDisplayOutput() throws Exception {
+        getDevice().executeShellCommand(
+            String.format("am start -n %s/%s", FULLSCREEN_COLOR_PKG,
+                          FULLSCREEN_COLOR_PKG_MAIN_ACTIVITY));
+
+        final WaitForColorsResult result =
+            waitForColors(Arrays.asList(ExpectedColor.create(0.5f, 0.5f, Color.RED)));
+        if (!result.succeeded()) {
+            saveScreenshotToTestResults("screenshot", result.failureImage(), mLogs);
+        }
+        assertThat(result.succeeded()).isTrue();
+    }
+
+}
diff --git a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java
index f0f45e73c..e648b6e8a 100644
--- a/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java
+++ b/tests/graphics/src/com/android/cuttlefish/tests/CuttlefishVulkanSnapshotTests.java
@@ -17,20 +17,17 @@ package com.android.cuttlefish.tests;
 
 import static com.google.common.truth.Truth.assertThat;
 
+import com.android.cuttlefish.tests.utils.CuttlefishHostTest;
+import com.android.cuttlefish.tests.utils.UnlockScreenRule;
 import com.android.tradefed.config.Option;
 import com.android.tradefed.device.internal.DeviceResetHandler;
 import com.android.tradefed.device.internal.DeviceSnapshotHandler;
 import com.android.tradefed.log.LogUtil.CLog;
-import com.android.tradefed.result.ByteArrayInputStreamSource;
-import com.android.tradefed.result.InputStreamSource;
-import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
-import com.google.auto.value.AutoValue;
 import java.awt.Color;
 import java.awt.image.BufferedImage;
-import java.io.ByteArrayOutputStream;
 import java.io.File;
 import java.util.Arrays;
 import java.util.List;
@@ -43,9 +40,7 @@ import org.junit.Before;
 import org.junit.Rule;
 import org.junit.Test;
 import org.junit.rules.TestRule;
-import org.junit.runner.Description;
 import org.junit.runner.RunWith;
-import org.junit.runners.model.Statement;
 
 /**
  * Test snapshot/restore function.
@@ -57,7 +52,7 @@ import org.junit.runners.model.Statement;
  * setup.
  */
 @RunWith(DeviceJUnit4ClassRunner.class)
-public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
+public class CuttlefishVulkanSnapshotTests extends CuttlefishHostTest {
     private static final String VK_SAMPLES_MAIN_ACTIVITY = "android.app.NativeActivity";
 
     private static final String VK_SAMPLES_FULLSCREEN_COLOR_APK =
@@ -85,32 +80,11 @@ public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
             VK_SAMPLES_FULLSCREEN_TEXTURE_PKG, //
             VK_SAMPLES_SECONDARY_COMMAND_BUFFER_PKG);
 
-    private static final int SCREENSHOT_CHECK_ATTEMPTS = 5;
-
-    private static final int SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS = 1000;
-
     @Rule
     public TestLogData mLogs = new TestLogData();
 
-    private void unlockDevice() throws Exception {
-        getDevice().executeShellCommand("input keyevent KEYCODE_WAKEUP");
-        getDevice().executeShellCommand("input keyevent KEYCODE_MENU");
-    }
-
-    // TODO: Move this into `device/google/cuttlefish/tests/utils` if it works?
     @Rule
-    public final TestRule mUnlockScreenRule = new TestRule() {
-        @Override
-        public Statement apply(Statement base, Description description) {
-            return new Statement() {
-                @Override
-                public void evaluate() throws Throwable {
-                    unlockDevice();
-                    base.evaluate();
-                }
-            };
-        }
-    };
+    public final UnlockScreenRule mUnlockScreenRule = new UnlockScreenRule(this);
 
     @Before
     public void setUp() throws Exception {
@@ -129,108 +103,6 @@ public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
         }
     }
 
-    private void saveScreenshotToTestResults(String name, BufferedImage screenshot) throws Exception {
-        ByteArrayOutputStream bytesOutputStream = new ByteArrayOutputStream();
-        ImageIO.write(screenshot, "png", bytesOutputStream);
-        byte[] bytes = bytesOutputStream.toByteArray();
-        ByteArrayInputStreamSource bytesInputStream = new ByteArrayInputStreamSource(bytes);
-        mLogs.addTestLog(name, LogDataType.PNG, bytesInputStream);
-    }
-
-    private BufferedImage getScreenshot() throws Exception {
-        InputStreamSource screenshotStream = getDevice().getScreenshot();
-
-        assertThat(screenshotStream).isNotNull();
-
-        return ImageIO.read(screenshotStream.createInputStream());
-    }
-
-    // Vulkan implementations can support different levels of precision which can
-    // result in slight pixel differences. This threshold should be small but was
-    // otherwise chosen arbitrarily to allow for small differences.
-    private static final int PIXEL_DIFFERENCE_THRESHOLD = 16;
-
-    private boolean isApproximatelyEqual(Color actual, Color expected) {
-        int diff = Math.abs(actual.getRed() - expected.getRed())
-            + Math.abs(actual.getGreen() - expected.getGreen())
-            + Math.abs(actual.getBlue() - expected.getBlue());
-        return diff <= PIXEL_DIFFERENCE_THRESHOLD;
-    }
-
-    @AutoValue
-    public static abstract class ExpectedColor {
-        static ExpectedColor create(float u, float v, Color color) {
-            return new AutoValue_CuttlefishVulkanSnapshotTests_ExpectedColor(u, v, color);
-        }
-
-        abstract float u();
-        abstract float v();
-        abstract Color color();
-    }
-
-    @AutoValue
-    public static abstract class WaitForColorsResult {
-        static WaitForColorsResult create(@Nullable BufferedImage image) {
-            return new AutoValue_CuttlefishVulkanSnapshotTests_WaitForColorsResult(image);
-        }
-
-        @Nullable abstract BufferedImage failureImage();
-
-        boolean succeeded() { return failureImage() == null; }
-    }
-
-
-    private WaitForColorsResult waitForColors(List<ExpectedColor> expectedColors) throws Exception {
-        assertThat(expectedColors).isNotEmpty();
-
-        BufferedImage screenshot = null;
-
-        for (int attempt = 0; attempt < SCREENSHOT_CHECK_ATTEMPTS; attempt++) {
-            CLog.i("Grabbing screenshot (attempt %d of %d)", attempt, SCREENSHOT_CHECK_ATTEMPTS);
-
-            screenshot = getScreenshot();
-
-            final int screenshotW = screenshot.getWidth();
-            final int screenshotH = screenshot.getHeight();
-
-            boolean foundAllExpectedColors = true;
-            for (ExpectedColor expected : expectedColors) {
-                final float sampleU = expected.u();
-
-                // Images from `getDevice().getScreenshot()` seem to use the top left as the
-                // the origin. Flip-y here for what is (subjectively) the more natural origin.
-                final float sampleV = 1.0f - expected.v();
-
-                final int sampleX = (int) (sampleU * (float) screenshotW);
-                final int sampleY = (int) (sampleV * (float) screenshotH);
-
-                final Color sampledColor = new Color(screenshot.getRGB(sampleX, sampleY));
-                final Color expectedColor = expected.color();
-
-                if (!isApproximatelyEqual(sampledColor, expectedColor)) {
-                    CLog.i("Screenshot check %d failed at u:%f v:%f (x:%d y:%d with w:%d h:%d) "
-                            + "expected:%s actual:%s",
-                        attempt, sampleU, sampleV, sampleX, sampleY, screenshotW, screenshotH,
-                        expectedColor, sampledColor);
-                    foundAllExpectedColors = false;
-                }
-            }
-
-            if (foundAllExpectedColors) {
-                CLog.i("Screenshot attempt %d found all expected colors.", attempt);
-                return WaitForColorsResult.create(null);
-            }
-
-            CLog.i("Screenshot attempt %d did not find all expected colors. Sleeping for %d ms and "
-                    + "trying again.",
-                attempt, SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
-
-            Thread.sleep(SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
-        }
-
-        return WaitForColorsResult.create(screenshot);
-    }
-
     private void runOneSnapshotTest(String pkg, List<ExpectedColor> expectedColors)
         throws Exception {
         final String snapshotId = "snapshot_" + UUID.randomUUID().toString();
@@ -238,14 +110,15 @@ public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
         // Reboot to make sure device isn't dirty from previous tests.
         getDevice().reboot();
 
-        unlockDevice();
+        mUnlockScreenRule.unlockDevice();
 
         getDevice().executeShellCommand(
             String.format("am start -n %s/%s", pkg, VK_SAMPLES_MAIN_ACTIVITY));
 
         final WaitForColorsResult beforeSnapshotResult = waitForColors(expectedColors);
         if (!beforeSnapshotResult.succeeded()) {
-            saveScreenshotToTestResults("before_snapshot_restore_screenshot", beforeSnapshotResult.failureImage());
+            saveScreenshotToTestResults(
+                "before_snapshot_restore_screenshot", beforeSnapshotResult.failureImage(), mLogs);
         }
         assertThat(beforeSnapshotResult.succeeded()).isTrue();
 
@@ -260,7 +133,8 @@ public class CuttlefishVulkanSnapshotTests extends BaseHostJUnit4Test {
 
         final WaitForColorsResult afterSnapshotRestoreResult = waitForColors(expectedColors);
         if (!afterSnapshotRestoreResult.succeeded()) {
-            saveScreenshotToTestResults("after_snapshot_restore_screenshot", afterSnapshotRestoreResult.failureImage());
+            saveScreenshotToTestResults(
+                "after_snapshot_restore_screenshot", afterSnapshotRestoreResult.failureImage(), mLogs);
         }
         assertThat(afterSnapshotRestoreResult.succeeded()).isTrue();
     }
diff --git a/tests/hal/Android.bp b/tests/hal/Android.bp
index 6d1d771aa..057639729 100644
--- a/tests/hal/Android.bp
+++ b/tests/hal/Android.bp
@@ -25,6 +25,7 @@ cc_test {
         "libhidl-gen-utils",
         "libhidlmetadata",
     ],
+    require_root: true,
     shared_libs: [
         "libbase",
         "libbinder",
diff --git a/tests/hal/hal_implementation_test.cpp b/tests/hal/hal_implementation_test.cpp
index fd5721e87..09f0e0196 100644
--- a/tests/hal/hal_implementation_test.cpp
+++ b/tests/hal/hal_implementation_test.cpp
@@ -153,6 +153,7 @@ struct VersionedAidlPackage {
   std::string name;
   size_t version;
   int bugNum;
+  std::string instance;
   bool operator<(const VersionedAidlPackage& rhs) const {
     return (name < rhs.name || (name == rhs.name && version < rhs.version));
   }
@@ -169,6 +170,7 @@ static const std::set<std::string> kAutomotiveOnlyAidl = {
      */
     "android.automotive.watchdog",
     "android.frameworks.automotive.display",
+    "android.frameworks.automotive.power",
     "android.frameworks.automotive.powerpolicy",
     "android.frameworks.automotive.powerpolicy.internal",
     "android.frameworks.automotive.telemetry",
@@ -280,7 +282,6 @@ static const std::vector<VersionedAidlPackage> kKnownMissingAidl = {
     {"android.hardware.security.see.storage.", 1, 379940224},
     {"android.hardware.security.see.hwcrypto.", 1, 379940224},
     {"android.hardware.security.see.hdcp.", 1, 379940224},
-    {"android.system.vold.", 1, 362567323},
 };
 
 // android.hardware.foo.IFoo -> android.hardware.foo.
@@ -389,7 +390,8 @@ static std::vector<VersionedAidlPackage> allAidlManifestInterfaces() {
     if (i.format() != vintf::HalFormat::AIDL) {
       return true;  // continue
     }
-    ret.push_back({i.package() + "." + i.interface(), i.version().minorVer, 0});
+    ret.push_back({i.package() + "." + i.interface(), i.version().minorVer, 0,
+                   i.instance()});
     return true;  // continue
   };
   vintf::VintfObject::GetDeviceHalManifest()->forEachInstance(setInserter);
@@ -411,6 +413,34 @@ TEST(Hal, AllAidlInterfacesAreInAosp) {
   }
 }
 
+TEST(Hal, NoExtensionsOnAospInterfaces) {
+  if (!kAidlUseUnfrozen) {
+    GTEST_SKIP() << "Not valid in 'next' configuration";
+  }
+  if (getDeviceType() != DeviceType::PHONE) {
+    GTEST_SKIP() << "Test only supports phones right now";
+  }
+  for (const auto& package : allAidlManifestInterfaces()) {
+    if (isAospAidlInterface(package.name)) {
+      std::string instance = package.name + "/" + package.instance;
+      sp<IBinder> binder =
+          defaultServiceManager()->waitForService(String16(instance.c_str()));
+      EXPECT_NE(binder, nullptr)
+          << "Failed to find " << instance << " even though it is declared. "
+          << "Check for crashes or misconficuration of the service";
+      if (binder) {
+        sp<IBinder> extension = nullptr;
+        auto status = binder->getExtension(&extension);
+        EXPECT_EQ(status, OK) << "Failed to getExtension on " << instance
+                              << " status: " << statusToString(status);
+        EXPECT_EQ(extension, nullptr)
+            << "Found an extension interface on " << instance
+            << ". This is not allowed on Cuttlefish";
+      }
+    }
+  }
+}
+
 struct AidlPackageCheck {
   bool hasRegistration;
   bool knownMissing;
diff --git a/tests/ril/src/com/android/cuttlefish/ril/tests/RilE2eTests.java b/tests/ril/src/com/android/cuttlefish/ril/tests/RilE2eTests.java
index d35e85c6a..bdcc403ad 100644
--- a/tests/ril/src/com/android/cuttlefish/ril/tests/RilE2eTests.java
+++ b/tests/ril/src/com/android/cuttlefish/ril/tests/RilE2eTests.java
@@ -106,7 +106,8 @@ public class RilE2eTests {
         Assert.assertEquals("Android Virtual Operator", mTeleManager.getNetworkOperatorName());
         Assert.assertFalse(mTeleManager.isNetworkRoaming());
         Assert.assertTrue(mTeleManager.isSmsCapable());
-        Assert.assertSame(TelephonyManager.NETWORK_TYPE_LTE, mTeleManager.getVoiceNetworkType());
+        Assert.assertNotSame(TelephonyManager.NETWORK_TYPE_UNKNOWN,
+                mTeleManager.getVoiceNetworkType());
         Assert.assertSame(TelephonyManager.SIM_STATE_READY, mTeleManager.getSimState());
         Assert.assertSame(TelephonyManager.PHONE_TYPE_GSM, mTeleManager.getPhoneType());
         Assert.assertSame(mTeleManager.getActiveModemCount(), 1);
diff --git a/tests/utils/Android.bp b/tests/utils/Android.bp
index 92856522a..f5000fcdd 100644
--- a/tests/utils/Android.bp
+++ b/tests/utils/Android.bp
@@ -17,12 +17,26 @@ package {
 }
 
 java_library_host {
-    name: "cuttlefish_host_test_utils",
+    name: "cuttlefish_host_test_utils_impl",
     srcs: [
         "src/**/*.java",
     ],
+    plugins: [
+        "auto_annotation_plugin",
+        "auto_value_plugin",
+    ],
     libs: [
         "compatibility-host-util",
         "tradefed",
     ],
 }
+
+java_defaults {
+    name: "cuttlefish_host_test_utils_defaults",
+    data_native_bins: [
+        "cvd_internal_display",
+    ],
+    static_libs: [
+        "cuttlefish_host_test_utils_impl",
+    ],
+}
diff --git a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlLocalRunner.java b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlLocalRunner.java
index a334c6692..3dc472ac4 100644
--- a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlLocalRunner.java
+++ b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlLocalRunner.java
@@ -23,6 +23,7 @@ import com.android.tradefed.util.RunUtil;
 
 import java.io.File;
 import java.io.FileNotFoundException;
+import java.io.IOException;
 import java.nio.file.Path;
 import java.nio.file.Paths;
 import java.util.Arrays;
@@ -76,4 +77,9 @@ public class CuttlefishControlLocalRunner implements CuttlefishControlRunner {
     public String getHostRuntimePath(String basename) throws FileNotFoundException {
         return Paths.get(this.runtimeDirectoryPath, basename).toAbsolutePath().toString();
     }
+
+    @Override
+    public File getFile(String path) throws IOException {
+        return new File(path);
+    }
 }
\ No newline at end of file
diff --git a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRemoteRunner.java b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRemoteRunner.java
index a4e995aa0..c2c2556fc 100644
--- a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRemoteRunner.java
+++ b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRemoteRunner.java
@@ -29,7 +29,9 @@ import com.android.tradefed.util.RunUtil;
 
 import com.google.common.collect.Iterables;
 
+import java.io.File;
 import java.io.FileNotFoundException;
+import java.io.IOException;
 import java.nio.file.Paths;
 import java.util.ArrayList;
 import java.util.Arrays;
@@ -109,4 +111,10 @@ public class CuttlefishControlRemoteRunner implements CuttlefishControlRunner {
     public String getHostRuntimePath(String basename) throws FileNotFoundException {
         return Paths.get(this.basePath, "cuttlefish_runtime", basename).toAbsolutePath().toString();
     }
+
+    @Override
+    public File getFile(String path) throws IOException {
+        return RemoteFileUtil.fetchRemoteFile(
+            testDeviceAvdInfo, testDeviceOptions, runUtil, DEFAULT_TIMEOUT_MILLIS, path);
+    }
 }
diff --git a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRunner.java b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRunner.java
index 33e3cdcf5..2c5cd55b2 100644
--- a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRunner.java
+++ b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishControlRunner.java
@@ -18,7 +18,9 @@ package com.android.cuttlefish.tests.utils;
 
 import com.android.tradefed.util.CommandResult;
 
+import java.io.File;
 import java.io.FileNotFoundException;
+import java.io.IOException;
 
 public interface CuttlefishControlRunner {
 
@@ -28,4 +30,6 @@ public interface CuttlefishControlRunner {
 
     public String getHostRuntimePath(String basename) throws FileNotFoundException;
 
+    public File getFile(String path) throws IOException;
+
 }
\ No newline at end of file
diff --git a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishHostTest.java b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishHostTest.java
index d773f0b16..6417f6d7d 100644
--- a/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishHostTest.java
+++ b/tests/utils/src/com/android/cuttlefish/tests/utils/CuttlefishHostTest.java
@@ -16,15 +16,37 @@
 
 package com.android.cuttlefish.tests.utils;
 
+import static com.google.common.truth.Truth.assertThat;
+
 import com.android.tradefed.device.ITestDevice;
 import com.android.tradefed.device.cloud.RemoteAndroidVirtualDevice;
 import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.result.ByteArrayInputStreamSource;
+import com.android.tradefed.result.InputStreamSource;
+import com.android.tradefed.result.LogDataType;
 import com.android.tradefed.testtype.DeviceJUnit4ClassRunner;
+import com.android.tradefed.testtype.DeviceJUnit4ClassRunner.TestLogData;
 import com.android.tradefed.testtype.junit4.BaseHostJUnit4Test;
 import com.android.tradefed.util.CommandResult;
+import com.android.tradefed.util.CommandStatus;
+import com.google.auto.value.AutoValue;
+
+import java.awt.image.BufferedImage;
+import java.awt.Color;
+import java.io.ByteArrayOutputStream;
+import java.io.File;
+import java.util.ArrayList;
+import java.util.List;
+
+import javax.annotation.Nullable;
+import javax.imageio.ImageIO;
 
 import org.junit.Before;
 import org.junit.runner.RunWith;
+import org.junit.rules.TestRule;
+import org.junit.runner.Description;
+import org.junit.runner.RunWith;
+import org.junit.runners.model.Statement;
 
 /**
  * Base test class for interacting with a Cuttlefish device with host binaries.
@@ -44,4 +66,136 @@ public abstract class CuttlefishHostTest extends BaseHostJUnit4Test {
         }
     }
 
+    private static final long DEFAULT_COMMAND_TIMEOUT_MS = 5000;
+
+    private static final int SCREENSHOT_CHECK_ATTEMPTS = 5;
+
+    private static final int SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS = 1000;
+
+    private static final String CVD_DISPLAY_BINARY_BASENAME = "cvd_internal_display";
+
+    protected BufferedImage getDisplayScreenshot() throws Exception {
+        File screenshotTempFile =  File.createTempFile("screenshot", ".png");
+        screenshotTempFile.deleteOnExit();
+
+        // TODO: Switch back to using `cvd` after either:
+        //  * Commands under `cvd` can be used with instances launched through `launch_cvd`.
+        //  * ATP launches instances using `cvd start` instead of `launch_cvd`.
+        String cvdDisplayBinary = runner.getHostBinaryPath(CVD_DISPLAY_BINARY_BASENAME);
+
+        List<String> fullCommand = new ArrayList<String>();
+        fullCommand.add(cvdDisplayBinary);
+        fullCommand.add("screenshot");
+        fullCommand.add("--screenshot_path=" + screenshotTempFile.getAbsolutePath());
+
+        CommandResult result = runner.run(DEFAULT_COMMAND_TIMEOUT_MS, fullCommand.toArray(new String[0]));
+        if (!CommandStatus.SUCCESS.equals(result.getStatus())) {
+            throw new IllegalStateException(
+                    String.format("Failed to run display screenshot command:\nstdout: %s\nstderr: %s",
+                                  result.getStdout(),
+                                  result.getStderr()));
+        }
+
+        BufferedImage screenshot = ImageIO.read(runner.getFile(screenshotTempFile.getAbsolutePath()));
+        if (screenshot == null) {
+            throw new IllegalStateException(String.format("Failed to read screenshot from %s", screenshotTempFile));
+        }
+
+        return screenshot;
+    }
+
+    // Vulkan implementations can support different levels of precision which can
+    // result in slight pixel differences. This threshold should be small but was
+    // otherwise chosen arbitrarily to allow for small differences.
+    private static final int PIXEL_DIFFERENCE_THRESHOLD = 16;
+
+    private boolean isApproximatelyEqual(Color actual, Color expected) {
+        int diff = Math.abs(actual.getRed() - expected.getRed())
+            + Math.abs(actual.getGreen() - expected.getGreen())
+            + Math.abs(actual.getBlue() - expected.getBlue());
+        return diff <= PIXEL_DIFFERENCE_THRESHOLD;
+    }
+
+    @AutoValue
+    public static abstract class ExpectedColor {
+        public static ExpectedColor create(float u, float v, Color color) {
+            return new AutoValue_CuttlefishHostTest_ExpectedColor(u, v, color);
+        }
+
+        public abstract float u();
+        public abstract float v();
+        public abstract Color color();
+    }
+
+    @AutoValue
+    public static abstract class WaitForColorsResult {
+        public static WaitForColorsResult create(@Nullable BufferedImage image) {
+            return new AutoValue_CuttlefishHostTest_WaitForColorsResult(image);
+        }
+
+        public @Nullable abstract BufferedImage failureImage();
+
+        public boolean succeeded() { return failureImage() == null; }
+    }
+
+    protected WaitForColorsResult waitForColors(List<ExpectedColor> expectedColors) throws Exception {
+        assertThat(expectedColors).isNotEmpty();
+
+        BufferedImage screenshot = null;
+
+        for (int attempt = 0; attempt < SCREENSHOT_CHECK_ATTEMPTS; attempt++) {
+            CLog.i("Grabbing screenshot (attempt %d of %d)", attempt, SCREENSHOT_CHECK_ATTEMPTS);
+
+            screenshot = getDisplayScreenshot();
+
+            final int screenshotW = screenshot.getWidth();
+            final int screenshotH = screenshot.getHeight();
+
+            boolean foundAllExpectedColors = true;
+            for (ExpectedColor expected : expectedColors) {
+                final float sampleU = expected.u();
+
+                // Images from `getDevice().getScreenshot()` seem to use the top left as the
+                // the origin. Flip-y here for what is (subjectively) the more natural origin.
+                final float sampleV = 1.0f - expected.v();
+
+                final int sampleX = (int) (sampleU * (float) screenshotW);
+                final int sampleY = (int) (sampleV * (float) screenshotH);
+
+                final Color sampledColor = new Color(screenshot.getRGB(sampleX, sampleY));
+                final Color expectedColor = expected.color();
+
+                if (!isApproximatelyEqual(sampledColor, expectedColor)) {
+                    CLog.i("Screenshot check %d failed at u:%f v:%f (x:%d y:%d with w:%d h:%d) "
+                            + "expected:%s actual:%s",
+                        attempt, sampleU, sampleV, sampleX, sampleY, screenshotW, screenshotH,
+                        expectedColor, sampledColor);
+                    foundAllExpectedColors = false;
+                }
+            }
+
+            if (foundAllExpectedColors) {
+                CLog.i("Screenshot attempt %d found all expected colors.", attempt);
+                return WaitForColorsResult.create(null);
+            }
+
+            CLog.i("Screenshot attempt %d did not find all expected colors. Sleeping for %d ms and "
+                    + "trying again.",
+                attempt, SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
+
+            Thread.sleep(SCREENSHOT_CHECK_TIMEOUT_MILLISECONDS);
+        }
+
+        return WaitForColorsResult.create(screenshot);
+    }
+
+    protected void saveScreenshotToTestResults(String name, BufferedImage screenshot,
+            TestLogData testLogs) throws Exception {
+        ByteArrayOutputStream bytesOutputStream = new ByteArrayOutputStream();
+        ImageIO.write(screenshot, "png", bytesOutputStream);
+        byte[] bytes = bytesOutputStream.toByteArray();
+        ByteArrayInputStreamSource bytesInputStream = new ByteArrayInputStreamSource(bytes);
+        testLogs.addTestLog(name, LogDataType.PNG, bytesInputStream);
+    }
+
 }
diff --git a/tests/utils/src/com/android/cuttlefish/tests/utils/UnlockScreenRule.java b/tests/utils/src/com/android/cuttlefish/tests/utils/UnlockScreenRule.java
new file mode 100644
index 000000000..b131090e1
--- /dev/null
+++ b/tests/utils/src/com/android/cuttlefish/tests/utils/UnlockScreenRule.java
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
+package com.android.cuttlefish.tests.utils;
+
+import com.android.tradefed.device.ITestDevice;
+import com.android.tradefed.log.LogUtil.CLog;
+import com.android.tradefed.testtype.ITestInformationReceiver;
+
+import org.junit.rules.TestRule;
+import org.junit.runner.Description;
+import org.junit.runners.model.Statement;
+
+/**
+ * Test rule that attempts to unlock the device before each test.
+ */
+public class UnlockScreenRule implements TestRule {
+
+    private final ITestInformationReceiver mTestInformationReceiver;
+
+    public UnlockScreenRule(ITestInformationReceiver testInformationReceiver) {
+        mTestInformationReceiver = testInformationReceiver;
+    }
+
+    private ITestDevice getDevice() {
+        return mTestInformationReceiver.getTestInformation().getDevice();
+    }
+
+    public void unlockDevice() throws Exception {
+        getDevice().executeShellCommand("input keyevent KEYCODE_WAKEUP");
+        getDevice().executeShellCommand("input keyevent KEYCODE_MENU");
+    }
+
+    @Override
+    public Statement apply(Statement base, Description description) {
+        return new Statement() {
+            @Override
+            public void evaluate() throws Throwable {
+                unlockDevice();
+                base.evaluate();
+            }
+        };
+    }
+}
diff --git a/tests/wifi/Android.bp b/tests/wifi/Android.bp
index d7e36a8f9..2edd8a72d 100644
--- a/tests/wifi/Android.bp
+++ b/tests/wifi/Android.bp
@@ -27,4 +27,5 @@ android_test {
     ],
     sdk_version: "current",
     certificate: "platform",
+    test_suites: ["device-tests"],
 }
diff --git a/tests/wmediumd_control/Android.bp b/tests/wmediumd_control/Android.bp
index 57f67b743..8b7ed93f9 100644
--- a/tests/wmediumd_control/Android.bp
+++ b/tests/wmediumd_control/Android.bp
@@ -18,6 +18,9 @@ package {
 
 java_test_host {
     name: "CuttlefishWmediumdControlTest",
+    defaults: [
+        "cuttlefish_host_test_utils_defaults",
+    ],
     srcs: [
         "src/**/*.java",
     ],
@@ -33,7 +36,6 @@ java_test_host {
     ],
     static_libs: [
         "WmediumdServerProto_java",
-        "cuttlefish_host_test_utils",
         "libprotobuf-java-util-full",
         "platform-test-annotations",
     ],
diff --git a/tools/create_base_image_gce.sh b/tools/create_base_image_gce.sh
index 4e851fb50..4e1c6e6f1 100755
--- a/tools/create_base_image_gce.sh
+++ b/tools/create_base_image_gce.sh
@@ -130,7 +130,7 @@ sudo chroot /mnt/image /usr/bin/apt install -y aapt
 sudo chroot /mnt/image /usr/bin/apt install -y screen # needed by tradefed
 
 sudo chroot /mnt/image /usr/bin/find /home -ls
-sudo chroot /mnt/image /usr/bin/apt install -t bookworm-security -y linux-image-cloud-amd64
+sudo chroot /mnt/image /usr/bin/apt install -t bookworm -y linux-image-cloud-amd64
 
 # update QEMU version to most recent backport
 sudo chroot /mnt/image /usr/bin/apt install -y --only-upgrade qemu-system-x86 -t bookworm
diff --git a/tools/install_nvidia.sh b/tools/install_nvidia.sh
index 7c6e1e24c..49a726068 100755
--- a/tools/install_nvidia.sh
+++ b/tools/install_nvidia.sh
@@ -34,7 +34,7 @@ kmodver=$(dpkg -s linux-image-cloud-${arch} | grep ^Depends: | \
 
 apt-get install -y wget
 # Install headers from backports, to match the linux-image
-apt-get install -y -t bookworm-security $(echo linux-headers-${kmodver})
+apt-get install -y -t bookworm $(echo linux-headers-${kmodver})
 # Dependencies for nvidia-installer
 apt-get install -y dkms libglvnd-dev libc6-dev pkg-config
 
diff --git a/tools/launch_cvd_arm64_server.sh b/tools/launch_cvd_arm64_server.sh
index ad9ba6cb6..4dac8272d 100755
--- a/tools/launch_cvd_arm64_server.sh
+++ b/tools/launch_cvd_arm64_server.sh
@@ -62,7 +62,7 @@ rsync -avch $img_dir/android-info.txt $server:~/$cvd_home_dir --info=progress2
 if [ -f $img_dir/required_images ]; then
   rsync -aSvch --recursive $img_dir --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=progress2
 else
-  rsync -aSvch --recursive $img_dir/bootloader $img_dir/*.img $server:~/$cvd_home_dir --info=progress2
+  rsync -aSvch --recursive $img_dir/*.img $server:~/$cvd_home_dir --info=progress2
 fi
 if [ ! -z "$vendor_boot_debug_image" ]; then
   echo "use the debug ramdisk image: $vendor_boot_debug_image"
diff --git a/tools/launch_cvd_arm64_server_docker.sh b/tools/launch_cvd_arm64_server_docker.sh
index 11b4b891f..523017aef 100755
--- a/tools/launch_cvd_arm64_server_docker.sh
+++ b/tools/launch_cvd_arm64_server_docker.sh
@@ -83,8 +83,8 @@ if [ -f $img_dir/required_images ]; then
   rsync -aSvch --recursive $img_dir --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=progress2
   cvd_home_files=($(rsync -rzan --recursive $img_dir --out-format="%n" --files-from=$img_dir/required_images $server:~/$cvd_home_dir --info=name2 | awk '{print $1}'))
 else
-  rsync -aSvch --recursive $img_dir/bootloader $img_dir/*.img $server:~/$cvd_home_dir --info=progress2
-  cvd_home_files=($(rsync -rzan --recursive $img_dir/bootloader --out-format="%n" $img_dir/*.img $server:~/$cvd_home_dir --info=name2 | awk '{print $1}'))
+  rsync -aSvch --recursive $img_dir/*.img $server:~/$cvd_home_dir --info=progress2
+  cvd_home_files=($(rsync -rzan --recursive --out-format="%n" $img_dir/*.img $server:~/$cvd_home_dir --info=name2 | awk '{print $1}'))
 fi
 
 if [[ $vendor_boot_image != "" ]]; then
diff --git a/tools/update_gce_kernel.sh b/tools/update_gce_kernel.sh
index 2c9515916..7b9c924bc 100755
--- a/tools/update_gce_kernel.sh
+++ b/tools/update_gce_kernel.sh
@@ -18,5 +18,5 @@ set -x
 set -o errexit
 
 sudo apt update
-sudo apt install -t bookworm-security -y linux-image-cloud-amd64
+sudo apt install -t bookworm -y linux-image-cloud-amd64
 sudo reboot
diff --git a/vsoc_arm/BoardConfig.mk b/vsoc_arm/BoardConfig.mk
index 2991f8f5b..37edcf76e 100644
--- a/vsoc_arm/BoardConfig.mk
+++ b/vsoc_arm/BoardConfig.mk
@@ -18,13 +18,6 @@
 # arm target for Cuttlefish
 #
 
-TARGET_KERNEL_USE ?= 6.6
-TARGET_KERNEL_ARCH ?= arm64
-SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
-TARGET_KERNEL_PATH ?= $(SYSTEM_DLKM_SRC)/kernel-$(TARGET_KERNEL_USE)
-KERNEL_MODULES_PATH ?= \
-    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
-
 -include device/google/cuttlefish/vsoc_arm64/BoardConfig.mk
 
 TARGET_BOARD_PLATFORM := vsoc_arm
@@ -33,6 +26,7 @@ TARGET_ARCH_VARIANT := armv8-a
 TARGET_CPU_ABI := armeabi-v7a
 TARGET_CPU_ABI2 := armeabi
 TARGET_CPU_VARIANT := cortex-a53
+TARGET_KERNEL_ARCH := arm64
 TARGET_2ND_ARCH :=
 TARGET_2ND_ARCH_VARIANT :=
 TARGET_2ND_CPU_ABI :=
diff --git a/vsoc_arm/bootloader.mk b/vsoc_arm/bootloader.mk
index ce2944390..aa9f9a617 100644
--- a/vsoc_arm/bootloader.mk
+++ b/vsoc_arm/bootloader.mk
@@ -14,7 +14,5 @@
 # limitations under the License.
 #
 
-TARGET_NO_BOOTLOADER := false
-# FIXME: Copying the QEMU bootloader for now, but this should be updated..
-BOARD_PREBUILT_BOOTLOADER := \
-    device/google/cuttlefish_prebuilts/bootloader/crosvm_aarch64/u-boot.bin
+# May be booted using different bootloaders, so don't have the single one.
+TARGET_NO_BOOTLOADER := true
diff --git a/vsoc_arm64/bootloader.mk b/vsoc_arm64/bootloader.mk
index ce2944390..aa9f9a617 100644
--- a/vsoc_arm64/bootloader.mk
+++ b/vsoc_arm64/bootloader.mk
@@ -14,7 +14,5 @@
 # limitations under the License.
 #
 
-TARGET_NO_BOOTLOADER := false
-# FIXME: Copying the QEMU bootloader for now, but this should be updated..
-BOARD_PREBUILT_BOOTLOADER := \
-    device/google/cuttlefish_prebuilts/bootloader/crosvm_aarch64/u-boot.bin
+# May be booted using different bootloaders, so don't have the single one.
+TARGET_NO_BOOTLOADER := true
diff --git a/vsoc_arm64/phone/aosp_cf.mk b/vsoc_arm64/phone/aosp_cf.mk
index 74b03fcb7..fab33f785 100644
--- a/vsoc_arm64/phone/aosp_cf.mk
+++ b/vsoc_arm64/phone/aosp_cf.mk
@@ -57,3 +57,7 @@ PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.model=$(PRODUCT_DEVICE)
 
 PRODUCT_16K_DEVELOPER_OPTION := true
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_arm64/phone/aosp_cf_vendor.mk b/vsoc_arm64/phone/aosp_cf_vendor.mk
new file mode 100644
index 000000000..f1f908d8d
--- /dev/null
+++ b/vsoc_arm64/phone/aosp_cf_vendor.mk
@@ -0,0 +1,27 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+$(call inherit-product, device/google/cuttlefish/vsoc_arm64/phone/aosp_cf.mk)
+
+PRODUCT_NAME := aosp_cf_arm64_phone_vendor
+
+PRODUCT_BUILD_SYSTEM_IMAGE := false
+PRODUCT_BUILD_SYSTEM_OTHER_IMAGE := false
+PRODUCT_BUILD_PRODUCT_IMAGE := false
+PRODUCT_BUILD_SYSTEM_EXT_IMAGE := false
+PRODUCT_BUILD_SUPER_PARTITION := false
+TARGET_SKIP_OTA_PACKAGE := true
+
diff --git a/vsoc_arm64_only/phone/aosp_cf.mk b/vsoc_arm64_only/phone/aosp_cf.mk
index 64d6a6686..8c5f88504 100644
--- a/vsoc_arm64_only/phone/aosp_cf.mk
+++ b/vsoc_arm64_only/phone/aosp_cf.mk
@@ -59,3 +59,7 @@ PRODUCT_MAX_PAGE_SIZE_SUPPORTED := 16384
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_arm64_only/phone/aosp_cf_vendor.mk b/vsoc_arm64_only/phone/aosp_cf_vendor.mk
new file mode 100644
index 000000000..4f5e37d1d
--- /dev/null
+++ b/vsoc_arm64_only/phone/aosp_cf_vendor.mk
@@ -0,0 +1,27 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+$(call inherit-product, device/google/cuttlefish/vsoc_arm64_only/phone/aosp_cf.mk)
+
+PRODUCT_NAME := aosp_cf_arm64_only_phone_vendor
+
+PRODUCT_BUILD_SYSTEM_IMAGE := false
+PRODUCT_BUILD_SYSTEM_OTHER_IMAGE := false
+PRODUCT_BUILD_PRODUCT_IMAGE := false
+PRODUCT_BUILD_SYSTEM_EXT_IMAGE := false
+PRODUCT_BUILD_SUPER_PARTITION := false
+TARGET_SKIP_OTA_PACKAGE := true
+
diff --git a/vsoc_arm64_pgagnostic/phone/aosp_cf.mk b/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
index ff10dca22..28c946924 100644
--- a/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
+++ b/vsoc_arm64_pgagnostic/phone/aosp_cf.mk
@@ -68,3 +68,7 @@ PRODUCT_VENDOR_PROPERTIES += \
 PRODUCT_16K_DEVELOPER_OPTION := true
 
 TARGET_BOOTS_16K := true
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_arm_minidroid/bootloader.mk b/vsoc_arm_minidroid/bootloader.mk
index 959cd6160..aa9f9a617 100644
--- a/vsoc_arm_minidroid/bootloader.mk
+++ b/vsoc_arm_minidroid/bootloader.mk
@@ -14,7 +14,5 @@
 # limitations under the License.
 #
 
-TARGET_NO_BOOTLOADER := false
-# FIXME: Copying the QEMU bootloader for now, but this should be updated..
-BOARD_PREBUILT_BOOTLOADER := \
-    device/google/cuttlefish_prebuilts/bootloader/qemu_arm/u-boot.bin
+# May be booted using different bootloaders, so don't have the single one.
+TARGET_NO_BOOTLOADER := true
diff --git a/vsoc_riscv64/bootloader.mk b/vsoc_riscv64/bootloader.mk
index 427531bdf..4866ad375 100644
--- a/vsoc_riscv64/bootloader.mk
+++ b/vsoc_riscv64/bootloader.mk
@@ -14,7 +14,5 @@
 # limitations under the License.
 #
 
-TARGET_NO_BOOTLOADER := false
-# Only QEMU is supported for now
-BOARD_PREBUILT_BOOTLOADER := \
-    device/google/cuttlefish_prebuilts/bootloader/qemu_riscv64/u-boot.bin
+# May be booted using different bootloaders, so don't have the single one.
+TARGET_NO_BOOTLOADER := true
diff --git a/vsoc_riscv64/phone/aosp_cf.mk b/vsoc_riscv64/phone/aosp_cf.mk
index 668ea09bd..998f8810a 100644
--- a/vsoc_riscv64/phone/aosp_cf.mk
+++ b/vsoc_riscv64/phone/aosp_cf.mk
@@ -73,3 +73,7 @@ PRODUCT_PACKAGES += \
 PRODUCT_VENDOR_PROPERTIES += \
     ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
     ro.soc.model=$(PRODUCT_DEVICE)
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_x86/go/aosp_cf.mk b/vsoc_x86/go/aosp_cf.mk
index e1bd4297c..6dd038eb0 100644
--- a/vsoc_x86/go/aosp_cf.mk
+++ b/vsoc_x86/go/aosp_cf.mk
@@ -25,10 +25,8 @@ PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := relaxed
 # These packages come from go_defaults.mk
 PRODUCT_ARTIFACT_PATH_REQUIREMENT_ALLOWED_LIST += \
     system/apex/com.android.tethering.capex \
-    system/app/PlatformCaptivePortalLogin/PlatformCaptivePortalLogin.apk \
     system/etc/permissions/platform_privapp_allowlist_com.android.cellbroadcastservice.xml \
     system/priv-app/CellBroadcastServiceModulePlatform/CellBroadcastServiceModulePlatform.apk \
-    system/priv-app/InProcessNetworkStack/InProcessNetworkStack.apk \
 
 #
 # All components inherited here go to system_ext image (same as GSI system_ext)
diff --git a/vsoc_x86_64/bootloader.mk b/vsoc_x86_64/bootloader.mk
index 6294ca755..aa9f9a617 100644
--- a/vsoc_x86_64/bootloader.mk
+++ b/vsoc_x86_64/bootloader.mk
@@ -14,6 +14,5 @@
 # limitations under the License.
 #
 
-TARGET_NO_BOOTLOADER := false
-BOARD_PREBUILT_BOOTLOADER := \
-    device/google/cuttlefish_prebuilts/bootloader/crosvm_x86_64/u-boot.rom
+# May be booted using different bootloaders, so don't have the single one.
+TARGET_NO_BOOTLOADER := true
diff --git a/vsoc_x86_64/phone/aosp_cf.mk b/vsoc_x86_64/phone/aosp_cf.mk
index e7c7dc2bc..d1c8ab38f 100644
--- a/vsoc_x86_64/phone/aosp_cf.mk
+++ b/vsoc_x86_64/phone/aosp_cf.mk
@@ -64,9 +64,10 @@ PRODUCT_VENDOR_PROPERTIES += \
 
 # Ignore all Android.mk files
 PRODUCT_IGNORE_ALL_ANDROIDMK := true
-# Allow the following Android.mk files
-PRODUCT_ALLOWED_ANDROIDMK_FILES := bootable/recovery/Android.mk
-PRODUCT_ANDROIDMK_ALLOWLIST_FILE := vendor/google/build/androidmk/aosp_cf_allowlist.mk
+# TODO(b/342327756, b/342330305): Allow the following Android.mk files
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
+
+PRODUCT_USE_SOONG_NOTICE_XML := true
 
 # Compare target product name directly to avoid this from any product inherits aosp_cf.mk
 ifneq ($(filter aosp_cf_x86_64_phone aosp_cf_x86_64_phone_soong_system aosp_cf_x86_64_foldable,$(TARGET_PRODUCT)),)
@@ -75,6 +76,17 @@ ifneq ($(CLANG_COVERAGE),true)
 ifneq ($(NATIVE_COVERAGE),true)
 USE_SOONG_DEFINED_SYSTEM_IMAGE := true
 PRODUCT_SOONG_DEFINED_SYSTEM_IMAGE := aosp_shared_system_image
+
+# For a gradual rollout, we're starting with just enabling this for aosp_cf_x86_64_phone and
+# not any of the other products that inherit from it.
+ifeq ($(TARGET_PRODUCT),aosp_cf_x86_64_phone)
+ifeq (,$(TARGET_BUILD_APPS))
+ifeq (,$(UNBUNDLED_BUILD))
+PRODUCT_SOONG_ONLY := $(RELEASE_SOONG_ONLY_CUTTLEFISH)
+endif
+endif
+endif
+
 endif # NATIVE_COVERAGE
 endif # CLANG_COVERAGE
 endif # aosp_cf_x86_64_phone aosp_cf_x86_64_foldable
diff --git a/vsoc_x86_64_only/auto/aosp_cf.mk b/vsoc_x86_64_only/auto/aosp_cf.mk
index bf8ca68ff..625fcf398 100644
--- a/vsoc_x86_64_only/auto/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto/aosp_cf.mk
@@ -26,9 +26,9 @@ PRODUCT_ENFORCE_RRO_TARGETS := frameworks-res
 
 PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := true
 
-# HSUM is currently incompatible with telephony.
-# TODO(b/283853205): Properly disable telephony using per-partition makefile.
-TARGET_NO_TELEPHONY := true
+# Telephony: Use Minradio RIL instead of Cuttlefish RIL
+TARGET_USES_CF_RILD := false
+PRODUCT_PACKAGES += com.android.hardware.radio.minradio.virtual
 
 #
 # All components inherited here go to system_ext image
@@ -45,6 +45,16 @@ $(call inherit-product, packages/services/Car/car_product/build/car_product.mk)
 #
 $(call inherit-product, device/google/cuttlefish/shared/auto/device_vendor.mk)
 
+
+LOCAL_USE_VENDOR_AUDIO_CONFIGURATION?= false
+ifeq ($(LOCAL_USE_VENDOR_AUDIO_CONFIGURATION),false)
+# Auto CF target is configured to use Configurable Audio Policy Engine if vendor audio configuration
+# flag is not set.
+# However, to prevent fallback on common cuttlefish audio configuration files, make use
+# of the vendor flag even for default cuttlefish auto config.
+LOCAL_USE_VENDOR_AUDIO_CONFIGURATION := true
+$(call inherit-product, device/google/cuttlefish/shared/auto/audio_policy_engine.mk)
+endif
 #
 # Special settings for the target
 #
diff --git a/vsoc_x86_64_only/auto_dd/OWNERS b/vsoc_x86_64_only/auto_dd/OWNERS
index 6190af78e..5bc897b71 100644
--- a/vsoc_x86_64_only/auto_dd/OWNERS
+++ b/vsoc_x86_64_only/auto_dd/OWNERS
@@ -1,5 +1,4 @@
 include device/google/cuttlefish:/shared/auto/OWNERS
-ycheo@google.com
 babakbo@google.com
 calhuang@google.com
 priyanksingh@google.com
diff --git a/vsoc_x86_64_only/auto_dd/aosp_cf.mk b/vsoc_x86_64_only/auto_dd/aosp_cf.mk
index eb1618f95..932be0b79 100644
--- a/vsoc_x86_64_only/auto_dd/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_dd/aosp_cf.mk
@@ -24,7 +24,6 @@ PRODUCT_PACKAGE_OVERLAYS += \
 
 EMULATOR_DYNAMIC_MULTIDISPLAY_CONFIG := false
 BUILD_EMULATOR_CLUSTER_DISPLAY := true
-TARGET_NO_TELEPHONY := true
 
 PRODUCT_SYSTEM_PROPERTIES += \
     ro.emulator.car.distantdisplay=true
diff --git a/vsoc_x86_64_only/auto_dewd/OWNERS b/vsoc_x86_64_only/auto_dewd/OWNERS
new file mode 100644
index 000000000..b190ef768
--- /dev/null
+++ b/vsoc_x86_64_only/auto_dewd/OWNERS
@@ -0,0 +1 @@
+include device/google/cuttlefish:/shared/auto_dewd/OWNERS
diff --git a/vsoc_x86_64_only/auto_dewd/aosp_cf.mk b/vsoc_x86_64_only/auto_dewd/aosp_cf.mk
new file mode 100644
index 000000000..e518e3af9
--- /dev/null
+++ b/vsoc_x86_64_only/auto_dewd/aosp_cf.mk
@@ -0,0 +1,44 @@
+#
+# Copyright (C) 2025 The Android Open Source Project
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
+# AOSP Car Cuttlefish Target with Declarative windowing definition language
+
+TARGET_BOARD_INFO_FILE := device/google/cuttlefish/shared/auto_dewd/android-info.txt
+
+PRODUCT_COPY_FILES += \
+    device/google/cuttlefish/shared/auto_dewd/display_settings.xml:$(TARGET_COPY_OUT_VENDOR)/etc/display_settings.xml
+
+# Exclude GAS Car Launcher
+DO_NOT_INCLUDE_GAS_CAR_LAUNCHER := true
+
+# Exclude Car UI Reference Design
+DO_NOT_INCLUDE_CAR_UI_REFERENCE_DESIGN := true
+
+# Exclude Car Visual Overlay
+DISABLE_CAR_PRODUCT_VISUAL_OVERLAY := true
+
+# Disable shared system image checking
+PRODUCT_ENFORCE_ARTIFACT_PATH_REQUIREMENTS := false
+$(call inherit-product, packages/services/Car/car_product/dewd/car_dewd_common.mk)
+$(call inherit-product, device/google/cuttlefish/vsoc_x86_64_only/auto/aosp_cf.mk)
+
+PRODUCT_NAME := aosp_cf_x86_64_auto_dewd
+PRODUCT_DEVICE := vsoc_x86_64_only
+PRODUCT_MANUFACTURER := Google
+PRODUCT_MODEL := AOSP Cuttlefish x86_64 auto 64-bit only with Declarative windowing definition language
+
+# Include the`launch_cvd --config auto_dewd` option.
+$(call soong_config_append,cvd,launch_configs,cvd_config_auto_dewd.json)
\ No newline at end of file
diff --git a/vsoc_x86_64_only/auto_md/aosp_cf.mk b/vsoc_x86_64_only/auto_md/aosp_cf.mk
index 5adfbb014..cb13870a8 100644
--- a/vsoc_x86_64_only/auto_md/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_md/aosp_cf.mk
@@ -25,10 +25,6 @@ PRODUCT_COPY_FILES += \
 PRODUCT_PACKAGE_OVERLAYS += \
     device/google/cuttlefish/shared/auto_md/overlay
 
-# HSUM is currently incompatible with telephony.
-# TODO(b/283853205): Properly disable telephony using per-partition makefile.
-TARGET_NO_TELEPHONY := true
-
 ENABLE_CLUSTER_OS_DOUBLE:=true
 
 PRODUCT_PACKAGES += \
diff --git a/vsoc_x86_64_only/auto_mdnd/aosp_cf.mk b/vsoc_x86_64_only/auto_mdnd/aosp_cf.mk
index 361ae59a5..380e03d89 100644
--- a/vsoc_x86_64_only/auto_mdnd/aosp_cf.mk
+++ b/vsoc_x86_64_only/auto_mdnd/aosp_cf.mk
@@ -21,10 +21,6 @@
 
 $(call inherit-product, device/google/cuttlefish/vsoc_x86_64_only/auto_md/aosp_cf.mk)
 
-# HSUM is currently incompatible with telephony.
-# TODO(b/283853205): Properly disable telephony using per-partition makefile.
-TARGET_NO_TELEPHONY := true
-
 PRODUCT_NAME := aosp_cf_x86_64_auto_mdnd
 PRODUCT_MODEL := Cuttlefish x86_64 auto 64-bit only multi-displays, no-driver
 
diff --git a/vsoc_x86_64_only/pc/aosp_cf.mk b/vsoc_x86_64_only/pc/aosp_cf.mk
index e6b9fe64a..6a40c953d 100644
--- a/vsoc_x86_64_only/pc/aosp_cf.mk
+++ b/vsoc_x86_64_only/pc/aosp_cf.mk
@@ -21,7 +21,7 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit_only.mk)
 $(call inherit-product, $(SRC_TARGET_DIR)/product/generic_system.mk)
 
 #
-# All components inherited here go to system_ext image (same as GSI system_ext)a
+# All components inherited here go to system_ext image (same as GSI system_ext)
 #
 $(call inherit-product, $(SRC_TARGET_DIR)/product/handheld_system_ext.mk)
 # $(call inherit-product, $(SRC_TARGET_DIR)/product/telephony_system_ext.mk)
diff --git a/vsoc_x86_64_only/phone/aosp_cf.mk b/vsoc_x86_64_only/phone/aosp_cf.mk
index eb36473b0..4667f4382 100644
--- a/vsoc_x86_64_only/phone/aosp_cf.mk
+++ b/vsoc_x86_64_only/phone/aosp_cf.mk
@@ -64,6 +64,5 @@ PRODUCT_VENDOR_PROPERTIES += \
 
 # Ignore all Android.mk files
 PRODUCT_IGNORE_ALL_ANDROIDMK := true
-# Allow the following Android.mk files
-PRODUCT_ALLOWED_ANDROIDMK_FILES := bootable/recovery/Android.mk
-PRODUCT_ANDROIDMK_ALLOWLIST_FILE := vendor/google/build/androidmk/aosp_cf_allowlist.mk
+# TODO(b/342327756, b/342330305): Allow the following Android.mk files
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk b/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
index 8b7064546..b5c6ce523 100644
--- a/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
+++ b/vsoc_x86_64_pgagnostic/phone/aosp_cf.mk
@@ -71,3 +71,7 @@ PRODUCT_VENDOR_PROPERTIES += \
 PRODUCT_16K_DEVELOPER_OPTION := true
 
 TARGET_BOOTS_16K := true
+
+# Ignore all Android.mk files
+PRODUCT_IGNORE_ALL_ANDROIDMK := true
+PRODUCT_ALLOWED_ANDROIDMK_FILES := art/Android.mk
diff --git a/vsoc_x86_only/BoardConfig.mk b/vsoc_x86_only/BoardConfig.mk
deleted file mode 100644
index b164f1e8f..000000000
--- a/vsoc_x86_only/BoardConfig.mk
+++ /dev/null
@@ -1,43 +0,0 @@
-#
-# Copyright 2020 The Android Open-Source Project
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
-# x86 (32-bit kernel) target for Cuttlefish
-#
-
-TARGET_BOARD_PLATFORM := vsoc_x86
-TARGET_ARCH := x86
-TARGET_ARCH_VARIANT := x86
-TARGET_CPU_ABI := x86
-
-TARGET_KERNEL_ARCH ?= i686
-TARGET_KERNEL_USE ?= 6.1
-KERNEL_MODULES_PATH := device/google/cuttlefish_prebuilts/kernel/$(TARGET_KERNEL_USE)-$(TARGET_KERNEL_ARCH)
-TARGET_KERNEL_PATH := $(KERNEL_MODULES_PATH)/kernel-$(TARGET_KERNEL_USE)
-# FIXME: system_dlkm should be specified as well
-
--include device/google/cuttlefish/shared/BoardConfig.mk
--include device/google/cuttlefish/shared/bluetooth/BoardConfig.mk
--include device/google/cuttlefish/shared/camera/BoardConfig.mk
--include device/google/cuttlefish/shared/gnss/BoardConfig.mk
--include device/google/cuttlefish/shared/graphics/BoardConfig.mk
--include device/google/cuttlefish/shared/identity/BoardConfig.mk
--include device/google/cuttlefish/shared/reboot_escrow/BoardConfig.mk
--include device/google/cuttlefish/shared/sensors/BoardConfig.mk
--include device/google/cuttlefish/shared/swiftshader/BoardConfig.mk
--include device/google/cuttlefish/shared/telephony/BoardConfig.mk
--include device/google/cuttlefish/shared/vibrator/BoardConfig.mk
--include device/google/cuttlefish/shared/virgl/BoardConfig.mk
diff --git a/vsoc_x86_only/phone/aosp_cf.mk b/vsoc_x86_only/phone/aosp_cf.mk
deleted file mode 100644
index 72e05210c..000000000
--- a/vsoc_x86_only/phone/aosp_cf.mk
+++ /dev/null
@@ -1,59 +0,0 @@
-#
-# Copyright (C) 2020 The Android Open Source Project
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
-PRODUCT_OTA_ENFORCE_VINTF_KERNEL_REQUIREMENTS := false
-
-#
-# All components inherited here go to vendor image
-#
-$(call inherit-product, device/google/cuttlefish/shared/phone/device_vendor.mk)
-
-#
-# Special settings for the target
-#
-# FIXME: For now, this uses the "64-bit" bootloader (for why, take a look at
-#        http://u-boot.10912.n7.nabble.com/64-bit-x86-U-Boot-td244620.html)
-$(call inherit-product, device/google/cuttlefish/vsoc_x86_64/bootloader.mk)
-
-# Exclude features that are not available on AOSP devices.
-PRODUCT_COPY_FILES += \
-    frameworks/native/data/etc/aosp_excluded_hardware.xml:$(TARGET_COPY_OUT_VENDOR)/etc/permissions/aosp_excluded_hardware.xml
-
-PRODUCT_NAME := aosp_cf_x86_only_phone
-PRODUCT_DEVICE := vsoc_x86_only
-PRODUCT_MANUFACTURER := Google
-PRODUCT_MODEL := Cuttlefish x86 phone 32-bit kernel
-
-PRODUCT_VENDOR_PROPERTIES += \
-    ro.soc.manufacturer=$(PRODUCT_MANUFACTURER) \
-    ro.soc.model=$(PRODUCT_DEVICE)
```

