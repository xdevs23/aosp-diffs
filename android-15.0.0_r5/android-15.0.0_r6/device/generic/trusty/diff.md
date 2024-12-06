```diff
diff --git a/Android.bp b/Android.bp
index 0574832..3c7ba4d 100644
--- a/Android.bp
+++ b/Android.bp
@@ -33,3 +33,46 @@ prebuilt_etc {
     vendor: true,
     src: "keymaster_soft_wrapped_attestation_keys.xml",
 }
+
+// Using java_genrule_host as it is the only genrule variant that has an
+// explicit host version. This is rather hacky but there is no built-in module
+// in soong to package up host tools.
+java_genrule_host {
+    name: "trusty-host_package",
+    tools: [
+        "adb",
+        "assemble_cvd",
+        "dtc",
+        "e2fsdroid",
+        "make_f2fs",
+        "mke2fs",
+        "rpmb_dev",
+        "sload_f2fs",
+        "toybox",
+        "trusty_qemu_system_aarch64",
+    ],
+    srcs: [
+        ":trusty_qemu_shared_files",
+    ],
+    cmd: "mkdir -p $(genDir)/trusty-host_package/bin && " +
+        "cp -f -t $(genDir)/trusty-host_package/bin " +
+        "$(location adb) $(location assemble_cvd) $(location dtc) " +
+        "$(location e2fsdroid) $(location make_f2fs) $(location mke2fs) " +
+        "$(location rpmb_dev) $(location sload_f2fs) " +
+        "$(location toybox) $(location trusty_qemu_system_aarch64) && " +
+        "cp -f -r `dirname $(location dtc)`/../lib64 $(genDir)/trusty-host_package/ && " +
+        "mkdir -p $(genDir)/trusty-host_package/share/qemu &&" +
+        "cp -f $(in) $(genDir)/trusty-host_package/share/qemu/ && " +
+        "tar Scfz $(out) -C $(genDir)/trusty-host_package --mtime='2020-01-01' .",
+    out: ["trusty-host_package.tar.gz"],
+
+    dist: {
+        targets: ["trusty-host_package"],
+    },
+
+    target: {
+        darwin: {
+            enabled: false,
+        },
+    },
+}
diff --git a/BoardConfig.mk b/BoardConfig.mk
index 7d09bb3..8037f8e 100644
--- a/BoardConfig.mk
+++ b/BoardConfig.mk
@@ -37,6 +37,66 @@ BOARD_SEPOLICY_DIRS += device/generic/trusty/sepolicy
 # like BUILD_QEMU_IMAGES would imply.
 QEMU_CUSTOMIZATIONS := true
 
+# Include the ramdisk image into the target files because
+# the prebuilts in the Trusty manifest need it there.
+BOARD_IMG_USE_RAMDISK := true
+BOARD_RAMDISK_USE_LZ4 := true
+BOARD_USES_GENERIC_KERNEL_IMAGE := true
+
+TARGET_KERNEL_USE ?= 6.6
+TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
+TARGET_KERNEL_PATH ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)/kernel-$(TARGET_KERNEL_USE)
+
+# Copy kernel image for use by emulator
+PRODUCT_COPY_FILES += $(TARGET_KERNEL_PATH):kernel
+
+# Distribute kernel image. Normally the kernel would be in boot.img,
+# but because we do not use a boot.img we need to dist the kernel image itself.
+ifneq ($(filter $(TARGET_PRODUCT), qemu_trusty_arm64),)
+$(call dist-for-goals, dist_files, $(PRODUCT_OUT)/kernel)
+endif
+
+# The list of modules strictly/only required either to reach second stage
+# init, OR for recovery. Do not use this list to workaround second stage
+# issues.
+VIRTUAL_DEVICE_MODULES_PATH ?= \
+    kernel/prebuilts/common-modules/virtual-device/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
+RAMDISK_VIRTUAL_DEVICE_MODULES := \
+    failover.ko \
+    net_failover.ko \
+    virtio_blk.ko \
+    virtio_console.ko \
+    virtio_mmio.ko \
+    virtio_net.ko \
+    virtio_pci.ko \
+
+# TODO(b/301606895): use kernel/prebuilts/common-modules/trusty when we have it
+TRUSTY_MODULES_PATH ?= \
+    kernel/prebuilts/common-modules/trusty/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
+RAMDISK_TRUSTY_MODULES := \
+    system_heap.ko \
+    trusty-core.ko \
+    trusty-ipc.ko \
+    trusty-log.ko \
+    trusty-test.ko \
+    trusty-virtio.ko \
+
+# Trusty modules should come after virtual device modules to preserve virtio
+# device numbering and /dev devices names, which we rely on for the rpmb and
+# test-runner virtio console ports.
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
+    $(patsubst %,$(VIRTUAL_DEVICE_MODULES_PATH)/%,$(RAMDISK_VIRTUAL_DEVICE_MODULES)) \
+    $(patsubst %,$(TRUSTY_MODULES_PATH)/%,$(RAMDISK_TRUSTY_MODULES)) \
+
+# GKI >5.15 will have and require virtio_pci_legacy_dev.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/virtio_pci_legacy_dev.ko)
+# GKI >5.10 will have and require virtio_pci_modern_dev.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/virtio_pci_modern_dev.ko)
+# GKI >6.4 will have an required vmw_vsock_virtio_transport_common.ko and vsock.ko
+BOARD_VENDOR_RAMDISK_KERNEL_MODULES += \
+    $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/vmw_vsock_virtio_transport_common.ko) \
+    $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/vsock.ko)
+
 TARGET_USERIMAGES_USE_EXT4 := true
 BOARD_SYSTEMIMAGE_PARTITION_SIZE := 536870912 # 512M
 BOARD_USERDATAIMAGE_PARTITION_SIZE := 268435456 # 256M
diff --git a/fstab.ranchu b/fstab.ranchu
deleted file mode 100644
index 3eed0be..0000000
--- a/fstab.ranchu
+++ /dev/null
@@ -1,6 +0,0 @@
-# Android fstab file.
-#<src>                                                  <mnt_point>         <type>    <mnt_flags and options>                              <fs_mgr_flags>
-# The filesystem that contains the filesystem checker binary (typically /system) cannot
-# specify MF_CHECK, and must come before any filesystems that do specify MF_CHECK
-/dev/block/vdc                                          /data               ext4      noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check
-/devices/*/block/vde                                    auto                auto      defaults                                             voldmanaged=sdcard:auto,encryptable=userdata
diff --git a/fstab.trusty b/fstab.trusty
new file mode 100644
index 0000000..10b849f
--- /dev/null
+++ b/fstab.trusty
@@ -0,0 +1,8 @@
+# Android fstab file.
+#<src>                                                  <mnt_point>         <type>    <mnt_flags and options>                              <fs_mgr_flags>
+# The filesystem that contains the filesystem checker binary (typically /system) cannot
+# specify MF_CHECK, and must come before any filesystems that do specify MF_CHECK
+/dev/block/vda        /system     ext4    ro,barrier=1        wait,first_stage_mount
+/dev/block/vdb        /vendor     ext4    ro,barrier=1        wait,first_stage_mount
+/dev/block/vdc        /data       ext4    noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check
+/devices/*/block/vde  auto        auto    defaults            voldmanaged=sdcard:auto,encryptable=userdata
diff --git a/init.qemu_trusty.rc b/init.qemu_trusty.rc
index 3571deb..e22482c 100644
--- a/init.qemu_trusty.rc
+++ b/init.qemu_trusty.rc
@@ -1,5 +1,5 @@
 on fs
-    mount_all /fstab.qemu_trusty
+    mount_all /vendor/etc/fstab.qemu_trusty
 
 on early-init
     mount debugfs debugfs /sys/kernel/debug mode=755
@@ -104,6 +104,7 @@ service fingerprintd /system/bin/fingerprintd
 service bugreport /system/bin/dumpstate -d -p
     class main
     disabled
+    user root
     oneshot
     keycodes 114 115 116
 
diff --git a/qemu_trusty_base.mk b/qemu_trusty_base.mk
index 97601ce..52a0f5a 100644
--- a/qemu_trusty_base.mk
+++ b/qemu_trusty_base.mk
@@ -66,6 +66,7 @@ PRODUCT_PACKAGES += \
     servicemanager \
     sh \
     su \
+    system-build.prop \
     toolbox \
     toybox \
     vdc \
@@ -112,7 +113,8 @@ PRODUCT_PACKAGES += init.usb.rc init.usb.configfs.rc
 PRODUCT_FULL_TREBLE_OVERRIDE := true
 
 PRODUCT_COPY_FILES += \
-    device/generic/trusty/fstab.ranchu:root/fstab.qemu_trusty \
+    device/generic/trusty/fstab.trusty:$(TARGET_COPY_OUT_RAMDISK)/fstab.qemu_trusty \
+    device/generic/trusty/fstab.trusty:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.qemu_trusty \
     device/generic/trusty/init.qemu_trusty.rc:$(TARGET_COPY_OUT_VENDOR)/etc/init/hw/init.qemu_trusty.rc \
     device/generic/trusty/ueventd.qemu_trusty.rc:$(TARGET_COPY_OUT_VENDOR)/etc/ueventd.rc \
     system/core/libprocessgroup/profiles/task_profiles.json:$(TARGET_COPY_OUT_VENDOR)/etc/task_profiles.json \
```

