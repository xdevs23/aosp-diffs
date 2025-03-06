```diff
diff --git a/Android.bp b/Android.bp
index 3c7ba4d..abb419e 100644
--- a/Android.bp
+++ b/Android.bp
@@ -44,8 +44,11 @@ java_genrule_host {
         "assemble_cvd",
         "dtc",
         "e2fsdroid",
+        "lz4",
         "make_f2fs",
+        "mkbootfs",
         "mke2fs",
+        "replace_ramdisk_modules",
         "rpmb_dev",
         "sload_f2fs",
         "toybox",
@@ -57,7 +60,8 @@ java_genrule_host {
     cmd: "mkdir -p $(genDir)/trusty-host_package/bin && " +
         "cp -f -t $(genDir)/trusty-host_package/bin " +
         "$(location adb) $(location assemble_cvd) $(location dtc) " +
-        "$(location e2fsdroid) $(location make_f2fs) $(location mke2fs) " +
+        "$(location e2fsdroid) $(location lz4) $(location make_f2fs) $(location mkbootfs) " +
+        "$(location mke2fs) $(location replace_ramdisk_modules) " +
         "$(location rpmb_dev) $(location sload_f2fs) " +
         "$(location toybox) $(location trusty_qemu_system_aarch64) && " +
         "cp -f -r `dirname $(location dtc)`/../lib64 $(genDir)/trusty-host_package/ && " +
diff --git a/BoardConfig.mk b/BoardConfig.mk
index 8037f8e..f3d39b9 100644
--- a/BoardConfig.mk
+++ b/BoardConfig.mk
@@ -64,10 +64,13 @@ VIRTUAL_DEVICE_MODULES_PATH ?= \
 RAMDISK_VIRTUAL_DEVICE_MODULES := \
     failover.ko \
     net_failover.ko \
-    virtio_blk.ko \
-    virtio_console.ko \
     virtio_mmio.ko \
     virtio_net.ko \
+
+SYSTEM_DLKM_SRC ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)
+RAMDISK_SYSTEM_MODULES := \
+    virtio_blk.ko \
+    virtio_console.ko \
     virtio_pci.ko \
 
 # TODO(b/301606895): use kernel/prebuilts/common-modules/trusty when we have it
@@ -85,7 +88,8 @@ RAMDISK_TRUSTY_MODULES := \
 # device numbering and /dev devices names, which we rely on for the rpmb and
 # test-runner virtio console ports.
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
-    $(patsubst %,$(VIRTUAL_DEVICE_MODULES_PATH)/%,$(RAMDISK_VIRTUAL_DEVICE_MODULES)) \
+    $(wildcard $(patsubst %,$(VIRTUAL_DEVICE_MODULES_PATH)/%,$(RAMDISK_VIRTUAL_DEVICE_MODULES))) \
+    $(wildcard $(patsubst %,$(SYSTEM_DLKM_SRC)/%,$(RAMDISK_SYSTEM_MODULES))) \
     $(patsubst %,$(TRUSTY_MODULES_PATH)/%,$(RAMDISK_TRUSTY_MODULES)) \
 
 # GKI >5.15 will have and require virtio_pci_legacy_dev.ko
```

