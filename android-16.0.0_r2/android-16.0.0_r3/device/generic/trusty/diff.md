```diff
diff --git a/BoardConfig.mk b/BoardConfig.mk
index 8a928f5..09097a0 100644
--- a/BoardConfig.mk
+++ b/BoardConfig.mk
@@ -39,8 +39,11 @@ QEMU_CUSTOMIZATIONS := true
 
 # Include the ramdisk image into the target files because
 # the prebuilts in the Trusty manifest need it there.
+#
+# TODO: Switch back to LZ4 once we have a prebuilt lz4 binary
+# for replace_ramdisk_modules.py to call.
 BOARD_IMG_USE_RAMDISK := true
-BOARD_RAMDISK_USE_LZ4 := true
+BOARD_RAMDISK_USE_LZ4 := false
 BOARD_USES_GENERIC_KERNEL_IMAGE := true
 
 TARGET_KERNEL_USE ?= 6.12
@@ -64,6 +67,7 @@ VIRTUAL_DEVICE_MODULES_PATH ?= \
 RAMDISK_VIRTUAL_DEVICE_MODULES := \
     failover.ko \
     net_failover.ko \
+    system_heap.ko \
     virtio_mmio.ko \
     virtio_net.ko \
 
@@ -79,7 +83,6 @@ RAMDISK_SYSTEM_MODULES := \
 TRUSTY_MODULES_PATH ?= \
     kernel/prebuilts/common-modules/trusty/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
 RAMDISK_TRUSTY_MODULES := \
-    system_heap.ko \
     ffa-core.ko \
     ffa-module.ko \
     trusty-ffa.ko \
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index f47c317..b1515ee 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -7,5 +7,3 @@ bpfmt = true
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
 rustfmt = --config-path=rustfmt.toml
 
-[Hook Scripts]
-aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/boot_status/Android.bp b/boot_status/Android.bp
new file mode 100644
index 0000000..a278e6f
--- /dev/null
+++ b/boot_status/Android.bp
@@ -0,0 +1,6 @@
+prebuilt_etc {
+    name: "init.boot_status.rc",
+    system_ext_specific: true,
+    src: "init.boot_status.rc",
+    sub_dir: "init",
+}
diff --git a/boot_status/init.boot_status.rc b/boot_status/init.boot_status.rc
new file mode 100644
index 0000000..506dd0a
--- /dev/null
+++ b/boot_status/init.boot_status.rc
@@ -0,0 +1,4 @@
+on boot
+    write /dev/kmsg "boot_kpi: K - init.boot_status.rc 'on boot'"
+    setprop dev.bootcomplete 1
+    setprop sys.boot_completed 1
diff --git a/qemu_trusty_base.mk b/qemu_trusty_base.mk
index 4c2a748..3189781 100644
--- a/qemu_trusty_base.mk
+++ b/qemu_trusty_base.mk
@@ -103,6 +103,13 @@ TARGET_COPY_OUT_SYSTEM_EXT := system/system_ext
 BOARD_SYSTEM_EXTIMAGE_FILE_SYSTEM_TYPE :=
 SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/generic/trusty/sepolicy/system_ext/private
 
+# We explicitly set this so that ro.product.first_api_level is set.
+# This is important because there are certain provisioning-related VTS
+# tests that expect to derive the vendor API level a device was provisioned
+# with. If we'd like to test the bleeding edge of new provisioning requirements
+# in the future, this should be bumped as new API levels become available.
+PRODUCT_SHIPPING_API_LEVEL := 36
+
 # Creates metadata partition mount point under root for
 # the devices with metadata partition
 BOARD_USES_METADATA_PARTITION := true
@@ -134,8 +141,9 @@ PRODUCT_HOST_PACKAGES += \
     mke2fs \
     sload_f2fs \
     toybox \
+    trusty_metrics_atoms_protoc_plugin \
 
-PRODUCT_PACKAGES += init.usb.rc init.usb.configfs.rc
+PRODUCT_PACKAGES += init.usb.rc init.usb.configfs.rc init.boot_status.rc
 
 PRODUCT_FULL_TREBLE_OVERRIDE := true
 
@@ -161,9 +169,7 @@ VENDOR_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
 # Trusty VM/TEE products #
 ##########################
 
-# TODO(b/393850980): enable TRUSTY_SYSTEM_VM_USE_PVMFW when
-# necessary dependencied are available on QEMU (e.g. ARM TRNG supported in TF-A)
-TRUSTY_SYSTEM_VM_USE_PVMFW := false
+TRUSTY_SYSTEM_VM_USE_PVMFW := true
 ifeq ($(TRUSTY_SYSTEM_VM_USE_PVMFW),true)
 PRODUCT_PACKAGES += \
       pvmfw_test_img.img \
```

