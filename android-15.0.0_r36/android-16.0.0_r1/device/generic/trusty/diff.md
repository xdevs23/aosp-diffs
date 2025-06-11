```diff
diff --git a/Android.bp b/Android.bp
index abb419e..35ec87c 100644
--- a/Android.bp
+++ b/Android.bp
@@ -13,6 +13,8 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
+soong_namespace {}
+
 package {
     default_applicable_licenses: ["device_generic_trusty_license"],
 }
diff --git a/BoardConfig.mk b/BoardConfig.mk
index f3d39b9..8a928f5 100644
--- a/BoardConfig.mk
+++ b/BoardConfig.mk
@@ -43,7 +43,7 @@ BOARD_IMG_USE_RAMDISK := true
 BOARD_RAMDISK_USE_LZ4 := true
 BOARD_USES_GENERIC_KERNEL_IMAGE := true
 
-TARGET_KERNEL_USE ?= 6.6
+TARGET_KERNEL_USE ?= 6.12
 TARGET_KERNEL_ARCH ?= $(TARGET_ARCH)
 TARGET_KERNEL_PATH ?= kernel/prebuilts/$(TARGET_KERNEL_USE)/$(TARGET_KERNEL_ARCH)/kernel-$(TARGET_KERNEL_USE)
 
@@ -72,12 +72,18 @@ RAMDISK_SYSTEM_MODULES := \
     virtio_blk.ko \
     virtio_console.ko \
     virtio_pci.ko \
+    virtio_pci_legacy_dev.ko \
+    virtio_pci_modern_dev.ko \
 
 # TODO(b/301606895): use kernel/prebuilts/common-modules/trusty when we have it
 TRUSTY_MODULES_PATH ?= \
     kernel/prebuilts/common-modules/trusty/$(TARGET_KERNEL_USE)/$(subst _,-,$(TARGET_KERNEL_ARCH))
 RAMDISK_TRUSTY_MODULES := \
     system_heap.ko \
+    ffa-core.ko \
+    ffa-module.ko \
+    trusty-ffa.ko \
+    trusty-smc.ko \
     trusty-core.ko \
     trusty-ipc.ko \
     trusty-log.ko \
@@ -92,18 +98,19 @@ BOARD_VENDOR_RAMDISK_KERNEL_MODULES := \
     $(wildcard $(patsubst %,$(SYSTEM_DLKM_SRC)/%,$(RAMDISK_SYSTEM_MODULES))) \
     $(patsubst %,$(TRUSTY_MODULES_PATH)/%,$(RAMDISK_TRUSTY_MODULES)) \
 
-# GKI >5.15 will have and require virtio_pci_legacy_dev.ko
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/virtio_pci_legacy_dev.ko)
-# GKI >5.10 will have and require virtio_pci_modern_dev.ko
-BOARD_VENDOR_RAMDISK_KERNEL_MODULES += $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/virtio_pci_modern_dev.ko)
 # GKI >6.4 will have an required vmw_vsock_virtio_transport_common.ko and vsock.ko
 BOARD_VENDOR_RAMDISK_KERNEL_MODULES += \
     $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/vmw_vsock_virtio_transport_common.ko) \
     $(wildcard $(VIRTUAL_DEVICE_MODULES_PATH)/vsock.ko)
 
+# The modules above should go into the vendor ramdisk,
+# but for some reason Soong considers it "generic ramdisk"
+BOARD_DO_NOT_STRIP_GENERIC_RAMDISK_MODULES := true
+BOARD_DO_NOT_STRIP_VENDOR_RAMDISK_MODULES := true
+
 TARGET_USERIMAGES_USE_EXT4 := true
 BOARD_SYSTEMIMAGE_PARTITION_SIZE := 536870912 # 512M
-BOARD_USERDATAIMAGE_PARTITION_SIZE := 268435456 # 256M
+BOARD_USERDATAIMAGE_PARTITION_SIZE := 536870912 # 512M (allows to store the ~100MB trusty_test_vm.elf)
 TARGET_COPY_OUT_VENDOR := vendor
 # ~100 MB vendor image. Please adjust system image / vendor image sizes
 # when finalizing them.
@@ -114,6 +121,8 @@ TARGET_USERIMAGES_SPARSE_EXT_DISABLED := true
 
 BOARD_PROPERTY_OVERRIDES_SPLIT_ENABLED := true
 BOARD_SEPOLICY_DIRS += build/target/board/generic/sepolicy
+BOARD_VENDOR_SEPOLICY_DIRS += device/generic/goldfish/sepolicy/vendor
+SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/generic/goldfish/sepolicy/system_ext/private
 
 # Enable A/B update
 TARGET_NO_RECOVERY := true
diff --git a/OWNERS b/OWNERS
new file mode 100644
index 0000000..390f6ff
--- /dev/null
+++ b/OWNERS
@@ -0,0 +1,2 @@
+# include OWNERS from the top level trusty repo
+include trusty:main:/OWNERS
diff --git a/PREUPLOAD.cfg b/PREUPLOAD.cfg
index dcf92be..f47c317 100644
--- a/PREUPLOAD.cfg
+++ b/PREUPLOAD.cfg
@@ -1,8 +1,11 @@
 [Builtin Hooks]
 clang_format = true
+rustfmt = true
+bpfmt = true
 
 [Builtin Hooks Options]
 clang_format = --commit ${PREUPLOAD_COMMIT} --style file --extensions c,h,cc,cpp
+rustfmt = --config-path=rustfmt.toml
 
 [Hook Scripts]
 aosp_hook = ${REPO_ROOT}/frameworks/base/tools/aosp/aosp_sha.sh ${PREUPLOAD_COMMIT} "."
diff --git a/apex/com.android.hardware.keymint/Android.bp b/apex/com.android.hardware.keymint/Android.bp
new file mode 100644
index 0000000..8658dca
--- /dev/null
+++ b/apex/com.android.hardware.keymint/Android.bp
@@ -0,0 +1,59 @@
+//
+// Copyright (C) 2025 The Android Open-Source Project
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
+apex_defaults {
+    name: "com.android.hardware.keymint.trusty.apex_defaults",
+    manifest: "manifest.json",
+    key: "com.google.trusty-qemu.apex.key",
+    certificate: ":com.google.trusty-qemu.apex.certificate",
+    soc_specific: true,
+    updatable: false,
+    file_contexts: "file_contexts",
+    prebuilts: [
+        // permissions
+        "android.hardware.hardware_keystore.xml",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.keymint.trusty_tee.cpp",
+    defaults: ["com.android.hardware.keymint.trusty.apex_defaults"],
+    prebuilts: [
+        // vintf fragments
+        "android.hardware.security.keymint-service.trusty.xml",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.keymint.trusty_tee",
+    defaults: ["com.android.hardware.keymint.trusty.apex_defaults"],
+    prebuilts: [
+        // vintf fragments
+        "android.hardware.security.keymint-service.rust.trusty.xml",
+    ],
+}
+
+apex {
+    name: "com.android.hardware.keymint.trusty_system_vm",
+    defaults: ["com.android.hardware.keymint.trusty.apex_defaults"],
+    prebuilts: [
+        // vintf fragments
+        "android.hardware.security.keymint-service.trusty_system_vm.xml",
+    ],
+}
diff --git a/apex/com.android.hardware.keymint/file_contexts b/apex/com.android.hardware.keymint/file_contexts
new file mode 100644
index 0000000..fafd0ea
--- /dev/null
+++ b/apex/com.android.hardware.keymint/file_contexts
@@ -0,0 +1,2 @@
+(/.*)?                                                      u:object_r:vendor_file:s0
+/etc(/.*)?                                                  u:object_r:vendor_configs_file:s0
diff --git a/apex/com.android.hardware.keymint/manifest.json b/apex/com.android.hardware.keymint/manifest.json
new file mode 100644
index 0000000..c52876c
--- /dev/null
+++ b/apex/com.android.hardware.keymint/manifest.json
@@ -0,0 +1,5 @@
+{
+  "name": "com.android.hardware.keymint",
+  "version": 1,
+  "bootstrap": true
+}
diff --git a/vendor.mk b/apex/com.android.hardware.keymint/trusty-apex.mk
similarity index 60%
rename from vendor.mk
rename to apex/com.android.hardware.keymint/trusty-apex.mk
index 4cc62d2..64c710a 100644
--- a/vendor.mk
+++ b/apex/com.android.hardware.keymint/trusty-apex.mk
@@ -1,5 +1,4 @@
-#
-# Copyright (C) 2019 The Android Open Source Project
+# Copyright (C) 2025 The Android Open Source Project
 #
 # Licensed under the Apache License, Version 2.0 (the "License");
 # you may not use this file except in compliance with the License.
@@ -13,11 +12,10 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
-# This file contains the definitions needed for a _really_ minimal system
-# image to be run under emulation under upstream QEMU (www.qemu.org), once
-# it supports a few Android virtual devices. Note that this is _not_ the
-# same as running under the Android emulator.
-
-PRODUCT_PACKAGES +=
-    dhcpclient \
+ifeq ($(KEYMINT_HAL_VENDOR_APEX_SELECT),true)
+PRODUCT_PACKAGES += \
+    com.android.hardware.keymint.trusty_tee.cpp \
+    com.android.hardware.keymint.trusty_tee \
+    com.android.hardware.keymint.trusty_system_vm \
 
+endif
diff --git a/apex/keys/Android.bp b/apex/keys/Android.bp
new file mode 100644
index 0000000..e0dbea0
--- /dev/null
+++ b/apex/keys/Android.bp
@@ -0,0 +1,29 @@
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
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+apex_key {
+    name: "com.google.trusty-qemu.apex.key",
+    public_key: "com.google.trusty-qemu.apex.avbpubkey",
+    private_key: "com.google.trusty-qemu.apex.pem",
+}
+
+// Created via: development/tools/make_key trusty-qemu.apex '/CN=trusty-qemu.apex'
+android_app_certificate {
+    name: "com.google.trusty-qemu.apex.certificate",
+    certificate: "com.google.trusty-qemu.apex",
+}
diff --git a/apex/keys/com.google.trusty-qemu.apex.avbpubkey b/apex/keys/com.google.trusty-qemu.apex.avbpubkey
new file mode 100644
index 0000000..90121bc
Binary files /dev/null and b/apex/keys/com.google.trusty-qemu.apex.avbpubkey differ
diff --git a/apex/keys/com.google.trusty-qemu.apex.pem b/apex/keys/com.google.trusty-qemu.apex.pem
new file mode 100644
index 0000000..1247aa6
--- /dev/null
+++ b/apex/keys/com.google.trusty-qemu.apex.pem
@@ -0,0 +1,52 @@
+-----BEGIN PRIVATE KEY-----
+MIIJQgIBADANBgkqhkiG9w0BAQEFAASCCSwwggkoAgEAAoICAQCjujWPNI/rxJHE
++vEdC2WGe6ayI7vyUex15xq56wiLLAP9vAiwor3PhMUFUsak3EI4fiKDWvFJrUPS
+4Cvw+P6EmYwds5oJTDSEWB5p4rLFGiBkZbVek69lSi9QCtzZ0oYW74zTvANrbb8o
+MTvG84cCiuiOtxuWYzTkVa92sbBmLLqx96k2N3TvjmRu7+MP1oeMjYyT5BjbbV/2
+JqQtl8FoWl5LynWCYvzchZ77dltpDrGMLqBnOk7AJtaj+zCsfj480R3yALtNK1Eb
+8vPEyl1dz4veCMBR3t53jgm2ntMbxZuwwHihPyAETBGv5Nb+ml1A89+6Qp/9OWk9
+vL+1hLMONb5IUqJ+IGNQ0pmADNOiGuOM4b0edQqU+50p1HNZZ2o7l2r2ZKSYf/Cf
+sfC1twsBoxVatavtZNWnB9C5XhB5y16VionSsNF+UjdGlMXb9wN9aOZa9tY0SKFU
+JtL2GnRW4TC90mYLKuaEmnMCn0RArNMIvRLamLjkmMAKChqPPRAMeDBqxyQY4x67
+XvE4sV6bajPnwAT7oOK975Tt5sDDjviYumFRN4o2oX87X1n9VCUXv80T2klWJ8hJ
+BhS6nG3nlAVPcbiTxR52A8+fHAbj2QN9rZzCY8FMP20rp0/xuWbmBsxBOZIQqnxW
+QXGAybGkwYvmqfwr588D/xCpIQSkewIDAQABAoICAB9nJcKz2C7mYvcfEoP5nZ1v
+tgdQ50mRAQOUMgIa3GalKJbQK/KFJFbbJlbhC4yvWlwvhTsghEsXWnzl1ke/2kFg
+mglQW2kRHrmLlTnF63f2jOP0xha/yNJqqix2COoWgPWBOMebtiQyxolU+BwutWR9
+dCF7aWUs3gY1kRP4/NZ8Gcrsr53ggSM5cnX8uNZe1VzWAXKUO1hK4C78Nl0wUD5N
+puxuhp9dkRZS4q1khB/gW5mBj+58toIQcPa+xRUwmYtcqJu0HDiu6D2uGadTERlf
+J3qMvyZ00sKnkaFfUSpwem4qXHjA/MkWNgZApCPtQ5mjrPOyt7EAA/l9bF/KdfUj
+C/CZAxLPFYpAdJGhAL3045nMzwS1m78ThRwiQUzda7PhbdZSsRTVRWSKvsYtr1h7
+D85QppWwS/JildibFK+rfdU5hRRgKXUHJY1sHdGZP6BHL0dmPAqy1gAvXSBwntVm
+KxA226RFBn9IIY6lbTxQcM7uCNJutV1NJrKwbbFMrDXRU6ya47yxqyyxZLvmsWxY
+Ngh04wv6sfZ/8R9ATYMAe//mFt0lQMwkmDoPcY34hibITE22LH4DnAtKz3QCPTD5
+zDViBgMkygIe/JfXwminzwBPmY6fakw68MaEjt3a4B8HM+9N/gSQ6srp+g9u2ag1
+2aeGovf3R0gZZtTKHhUxAoIBAQDbfIdVSvQ7r9VBUEUFtfFHEAhboQeamcx5LKJy
+NDc+RofC4rTQGuApwxgM6lCsfMt8oRn1tbLa61DsF+vR460PSYs2kyBl6GwcCnRT
+FEqUYjyDZzzjfVLhGpQQ1dSGihnOBFVJ1n9SRkks1tKOqZ0MuoeGzp3biN75eTuU
+e/6oPuYhpPDXRMLPYVOgT+XpK8p3F8mWlHPwanpXX2MDzZCeaAT5nRvi3ydAU9Dv
+dIUR1cEi9azZanjt7qunqvU3Fb5n4ERbv0gRL+tCG1jlcXMFeEnxPA0sv5OoL75l
+W3TWsTP9CCtwHXjZTBENPH4lef2rGFGuo86yMxIjyduRgsSFAoIBAQC+9wSgPErr
+K51VmNwXKCOofxttXmkedBv78GSxcOKQQtX7MUxx4yLiVOviDifaQdX5UTx2tSHW
+VfoVhqM/vFLceWOgIEkt1M2bV1/jX75Kc3CTt0ZejLaTyabtMH+Cva1vDiMBdLjC
+iJn0QLAliuwDNtzh4Ab7gvOwjANjUq/Qs+9cA2R1teEwS6ymxd/Ourepny3ydiyT
+y7MJ+yY/7OZStU89eNRDpLfb7ZJHlGJs1N8jB+nyXaijlsFbwBskjmQXY1bNPSwJ
+sJH8loXpJbRlaWRl8oYHC+lH6hmweSSqYMV7JNqQcc/YXtSQhsVxkMCi+rPPWDrJ
+MjeoOHYhbpT/AoIBAQDNuoLLos8cpyq35rpbqPe4SUHcSSrscZ6kMf8uFt11JP0Z
+4g/jRF27J2ACsxrdIrhFYGgJ1L8JzinyslVbThIn0yKHDA8BFoNHIVF5kfp57T6V
+WI5NGWo3DwecZCGp3gZkAdHDvSdogfMS8WU5Taikhq6D4GU8oqWFp2n+Ot8u6o4h
+GQ6aaJxFcA/Hozx4e5ByYryUxR+LSPLVtNYFeYhFwnBvXCEIXWzYMfgUit40Imy/
+DRJwVAl31A/XwDnK4Tmw+hh4+uldGtJkC2ge4GEUznRYhpY+zG9l5SKMtNXmawC0
++xRkKWveGhudkYcYL6li1w+xJ1+VzqMBIrMJSE5VAoIBABsQVw9+e/+oRrwC1e5S
+Oft/SBvP7YXrXqvt/ddH8FQRpNHcwsDBOAhrkKKQ7wT3n6Od57vLH+iIdtDmK+y0
+e+nTKlNfP//G0Pza/TP0NbvHcIT+zHJJ7vYy9f1Xijq1NwcuMbfbGvQ299qt8Ejh
+z2EFPXilj1fFz1OOBEznQxOI7LtVn78u76Mwll9sW7Oosq7PaGucY+TuUYlwlpMo
+t9uw5nIH1c1gYs5AdSK/3NMfuB/21ykKLQRCMVUXfMFJjNXjtkGQEdWtuILbsk7A
+kThuH1Rzcps9DOqsOsfP42piHJq/NlqSRqqbhfSVpRXbNfHjJeiU0IADJfApUFSc
+n3ECggEAfrGd2q9vNpWU7vzmjk2U1QIkB5zHze9uSbVjYi3Rd2IUv9YBuX9mdhY0
+vP3/kSp3g2elHpCc/CRz33Z/2R/3uNLhkhlVBDBTXbHDoBtkkRGDYoBF5t2qn2Rj
+sPLYGPTSApsn9Xvg6RLrrYRXaoz8x9BdDlctPSDavhocWAe4bbujcA8DZ3iDeDH0
+zAoGudcfmuh/9m9utDNrFW5uxcXBGXuBe4QzhknVA2BCaJrjZMXK2Zw6Bu6iLd6I
+TvnC9pbOd88zZNUbPP6MnDk4tm4oZgXhJQIoXDYyo+kxlrsEV4L3ZO2QZchEkxov
+EOngkQsUwvMl3nJNgj03a+dTN9O0Zg==
+-----END PRIVATE KEY-----
diff --git a/apex/keys/com.google.trusty-qemu.apex.pk8 b/apex/keys/com.google.trusty-qemu.apex.pk8
new file mode 100644
index 0000000..339d079
Binary files /dev/null and b/apex/keys/com.google.trusty-qemu.apex.pk8 differ
diff --git a/apex/keys/com.google.trusty-qemu.apex.x509.pem b/apex/keys/com.google.trusty-qemu.apex.x509.pem
new file mode 100644
index 0000000..53e2a5d
--- /dev/null
+++ b/apex/keys/com.google.trusty-qemu.apex.x509.pem
@@ -0,0 +1,20 @@
+-----BEGIN CERTIFICATE-----
+MIIDLzCCAhegAwIBAgIUZhf7qgKmidTmO85F2oW1j4kfCZwwDQYJKoZIhvcNAQEL
+BQAwJjEkMCIGA1UEAwwbY29tLmdvb2dsZS50cnVzdHktcWVtdS5hcGV4MCAXDTI1
+MDEyNzA2NDI1MFoYDzIwNTIwNjE0MDY0MjUwWjAmMSQwIgYDVQQDDBtjb20uZ29v
+Z2xlLnRydXN0eS1xZW11LmFwZXgwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEK
+AoIBAQDEEumHiLt6QdBZbJv7vmdoW9hS10+tHq/cI8d298egqI3g8EV9FBJ4L6Ch
+LEK8ZL+4hGu3BS5jLh3XoMkK3H+XA1xOlMfKwG5tfwOyL4fbIxnJjK4nDbkel4FP
+Df5EV9ERLclMKFXF+oG1MU2/GOuBD2H6qClnC6OVUK1ZHcZRz+HhVR3ub+P6k3tM
+p+4QLgc+qMFS1Yh1skP7BvNvvmGPQOe1fTO+z4mV9zsHZ59ykuV7VC7C15Jj3JWU
+kYzjgyrSUSbgVyQNiCISjCSc+KljjyWeUZsfv1fbUxt97LdFo6EDyY+4UhyGt0ri
+GZGAzMnyUB6J65HGjb27bd7meNdJAgMBAAGjUzBRMB0GA1UdDgQWBBST4Z4un7hW
+nZorApeZz5EGvJzQcTAfBgNVHSMEGDAWgBST4Z4un7hWnZorApeZz5EGvJzQcTAP
+BgNVHRMBAf8EBTADAQH/MA0GCSqGSIb3DQEBCwUAA4IBAQDCJZP1saJx6wQKXhgU
+Li7bAOZRXjAYc6uKE7+6PuJ1V/7RXukUh1QMCtie6escQ5ILUs+naRDHEWtoeM4L
+z1ccNIlj98w4G6oYgEGqdhFvHL4C+EI+Imn+XVuc5fxWnj3/wk7zQBjCm9SILShr
+GLnvCBtyNAa31qerOOpPOuButcmNTyYvk0uoxArC/vYcTNlKzr+MSOgLPByaJIFY
+OPaBSGSJBeAjniMDsZlBbge5/uN4/fZOIAjiSZ6QrTSuai26ATe4XpYhhauwGQjb
+z9XW6M0fOvqj5FHZEh2onmmVHieDxzf/TYd0+IKP6LGh/0FddMQCP6/97JUbXOIZ
+jSAM
+-----END CERTIFICATE-----
diff --git a/dhcp/client/Android.bp b/dhcp/client/Android.bp
new file mode 100644
index 0000000..ea53129
--- /dev/null
+++ b/dhcp/client/Android.bp
@@ -0,0 +1,36 @@
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
+cc_binary {
+    name: "dhcpclient",
+    srcs: [
+        "dhcpclient.cpp",
+        "interface.cpp",
+        "main.cpp",
+        "router.cpp",
+        "timer.cpp",
+    ],
+    shared_libs: [
+        "libcutils",
+        "liblog",
+    ],
+    static_libs: [
+        "libdhcpclient",
+    ],
+    proprietary: true,
+}
diff --git a/dhcp/client/dhcpclient.cpp b/dhcp/client/dhcpclient.cpp
new file mode 100644
index 0000000..037b9a6
--- /dev/null
+++ b/dhcp/client/dhcpclient.cpp
@@ -0,0 +1,518 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "dhcpclient.h"
+#include "dhcp.h"
+#include "interface.h"
+#include "log.h"
+
+#include <arpa/inet.h>
+#include <errno.h>
+#include <linux/if_ether.h>
+#include <poll.h>
+#include <unistd.h>
+
+#include <cutils/properties.h>
+
+#include <inttypes.h>
+
+// The initial retry timeout for DHCP is 4000 milliseconds
+static const uint32_t kInitialTimeout = 4000;
+// The maximum retry timeout for DHCP is 64000 milliseconds
+static const uint32_t kMaxTimeout = 64000;
+// A specific value that indicates that no timeout should happen and that
+// the state machine should immediately transition to the next state
+static const uint32_t kNoTimeout = 0;
+
+// Enable debug messages
+static const bool kDebug = false;
+
+// The number of milliseconds that the timeout should vary (up or down) from the
+// base timeout. DHCP requires a -1 to +1 second variation in timeouts.
+static const int kTimeoutSpan = 1000;
+
+static std::string addrToStr(in_addr_t address) {
+    struct in_addr addr = {address};
+    char buffer[64];
+    return inet_ntop(AF_INET, &addr, buffer, sizeof(buffer));
+}
+
+DhcpClient::DhcpClient(uint32_t options)
+    : mOptions(options), mRandomEngine(std::random_device()()),
+      mRandomDistribution(-kTimeoutSpan, kTimeoutSpan), mState(State::Init),
+      mNextTimeout(kInitialTimeout), mFuzzNextTimeout(true) {}
+
+Result DhcpClient::init(const char* interfaceName) {
+    Result res = mInterface.init(interfaceName);
+    if (!res) {
+        return res;
+    }
+
+    res = mRouter.init();
+    if (!res) {
+        return res;
+    }
+
+    res = mSocket.open(PF_PACKET, SOCK_DGRAM, htons(ETH_P_IP));
+    if (!res) {
+        return res;
+    }
+
+    res = mSocket.bindRaw(mInterface.getIndex());
+    if (!res) {
+        return res;
+    }
+    return Result::success();
+}
+
+Result DhcpClient::run() {
+    // Block all signals while we're running. This way we don't have to deal
+    // with things like EINTR. waitAndReceive then uses ppoll to set the
+    // original mask while polling. This way polling can be interrupted but
+    // socket writing, reading and ioctl remain interrupt free. If a signal
+    // arrives while we're blocking it will be placed in the signal queue
+    // and handled once ppoll sets the original mask. This way no signals are
+    // lost.
+    sigset_t blockMask, originalMask;
+    int status = ::sigfillset(&blockMask);
+    if (status != 0) {
+        return Result::error("Unable to fill signal set: %s", strerror(errno));
+    }
+    status = ::sigprocmask(SIG_SETMASK, &blockMask, &originalMask);
+    if (status != 0) {
+        return Result::error("Unable to set signal mask: %s", strerror(errno));
+    }
+
+    for (;;) {
+        // Before waiting, polling or receiving we check the current state and
+        // see what we should do next. This may result in polling but could
+        // also lead to instant state changes without any polling. The new state
+        // will then be evaluated instead, most likely leading to polling.
+        switch (mState) {
+        case State::Init:
+            // The starting state. This is the state the client is in when
+            // it first starts. It's also the state that the client returns
+            // to when things go wrong in other states.
+            setNextState(State::Selecting);
+            break;
+        case State::Selecting:
+            // In the selecting state the client attempts to find DHCP
+            // servers on the network. The client remains in this state
+            // until a suitable server responds.
+            sendDhcpDiscover();
+            increaseTimeout();
+            break;
+        case State::Requesting:
+            // In the requesting state the client has found a suitable
+            // server. The next step is to send a request directly to that
+            // server.
+            if (mNextTimeout >= kMaxTimeout) {
+                // We've tried to request a bunch of times, start over
+                setNextState(State::Init);
+            } else {
+                sendDhcpRequest(mServerAddress);
+                increaseTimeout();
+            }
+            break;
+        case State::Bound:
+            // The client enters the bound state when the server has
+            // accepted and acknowledged a request and given us a lease. At
+            // this point the client will wait until the lease is close to
+            // expiring and then it will try to renew the lease.
+            if (mT1.expired()) {
+                // Lease expired, renew lease
+                setNextState(State::Renewing);
+            } else {
+                // Spurious wake-up, continue waiting. Do not fuzz the
+                // timeout with a random offset. Doing so can cause wakeups
+                // before the timer has expired causing unnecessary
+                // processing. Even worse it can cause the timer to expire
+                // after the lease has ended.
+                mNextTimeout = mT1.remainingMillis();
+                mFuzzNextTimeout = false;
+            }
+            break;
+        case State::Renewing:
+            // In the renewing state the client is sending a request for the
+            // same address it had was previously bound to. If the second
+            // timer expires when in this state the client will attempt to
+            // do a full rebind.
+            if (mT2.expired()) {
+                // Timeout while renewing, move to rebinding
+                setNextState(State::Rebinding);
+            } else {
+                sendDhcpRequest(mServerAddress);
+                increaseTimeout();
+            }
+            break;
+        case State::Rebinding:
+            // The client was unable to renew the lease and moved to the
+            // rebinding state. In this state the client sends a request for
+            // the same address it had before to the broadcast address. This
+            // means that any DHCP server on the network is free to respond.
+            // After attempting this a few times the client will give up and
+            // move to the Init state to try to find a new DHCP server.
+            if (mNextTimeout >= kMaxTimeout) {
+                // We've tried to rebind a bunch of times, start over
+                setNextState(State::Init);
+            } else {
+                // Broadcast a request
+                sendDhcpRequest(INADDR_BROADCAST);
+                increaseTimeout();
+            }
+            break;
+        default:
+            break;
+        }
+        // The proper action for the current state has been taken, perform any
+        // polling and/or waiting needed.
+        waitAndReceive(originalMask);
+    }
+
+    return Result::error("Client terminated unexpectedly");
+}
+
+const char* DhcpClient::stateToStr(State state) {
+    switch (state) {
+    case State::Init:
+        return "Init";
+    case State::Selecting:
+        return "Selecting";
+    case State::Requesting:
+        return "Requesting";
+    case State::Bound:
+        return "Bound";
+    case State::Renewing:
+        return "Renewing";
+    case State::Rebinding:
+        return "Rebinding";
+    }
+    return "<unknown>";
+}
+
+void DhcpClient::waitAndReceive(const sigset_t& pollSignalMask) {
+    if (mNextTimeout == kNoTimeout) {
+        // If there is no timeout the state machine has indicated that it wants
+        // an immediate transition to another state. Do nothing.
+        return;
+    }
+
+    struct pollfd fds;
+    fds.fd = mSocket.get();
+    fds.events = POLLIN;
+
+    uint32_t timeout = calculateTimeoutMillis();
+    for (;;) {
+        uint64_t startedAt = now();
+
+        struct timespec ts;
+        ts.tv_sec = timeout / 1000;
+        ts.tv_nsec = (timeout - ts.tv_sec * 1000) * 1000000;
+
+        // Poll for any incoming traffic with the calculated timeout. While
+        // polling the original signal mask is set so that the polling can be
+        // interrupted.
+        int res = ::ppoll(&fds, 1, &ts, &pollSignalMask);
+        if (res == 0) {
+            // Timeout, return to let the caller evaluate
+            return;
+        } else if (res > 0) {
+            // Something to read
+            Message msg;
+            if (receiveDhcpMessage(&msg)) {
+                // We received a DHCP message, check if it's of interest
+                uint8_t msgType = msg.type();
+                switch (mState) {
+                case State::Selecting:
+                    if (msgType == DHCPOFFER) {
+                        // Received an offer, move to the Requesting state
+                        // to request it.
+                        mServerAddress = msg.serverId();
+                        mRequestAddress = msg.dhcpData.yiaddr;
+                        setNextState(State::Requesting);
+                        return;
+                    }
+                    break;
+                case State::Requesting:
+                case State::Renewing:
+                case State::Rebinding:
+                    // All of these states have sent a DHCP request and are
+                    // now waiting for an ACK so the behavior is the same.
+                    if (msgType == DHCPACK) {
+                        // Request approved
+                        if (configureDhcp(msg)) {
+                            // Successfully configured DHCP, move to Bound
+                            setNextState(State::Bound);
+                            return;
+                        }
+                        // Unable to configure DHCP, keep sending requests.
+                        // This may not fix the issue but eventually it will
+                        // allow for a full timeout which will lead to a
+                        // move to the Init state. This might still not fix
+                        // the issue but at least the client keeps trying.
+                    } else if (msgType == DHCPNAK) {
+                        // Request denied, halt network and start over
+                        haltNetwork();
+                        setNextState(State::Init);
+                        return;
+                    }
+                    break;
+                default:
+                    // For the other states the client is not expecting any
+                    // network messages so we ignore those messages.
+                    break;
+                }
+            }
+        } else {
+            // An error occurred in polling, don't do anything here. The client
+            // should keep going anyway to try to acquire a lease in the future
+            // if things start working again.
+        }
+        // If we reach this point we received something that's not a DHCP,
+        // message, we timed out, or an error occurred. Go again with whatever
+        // time remains.
+        uint64_t currentTime = now();
+        uint64_t end = startedAt + timeout;
+        if (currentTime >= end) {
+            // We're done anyway, return and let caller evaluate
+            return;
+        }
+        // Wait whatever the remaining time is
+        timeout = end - currentTime;
+    }
+}
+
+bool DhcpClient::configureDhcp(const Message& msg) {
+    size_t optsSize = msg.optionsSize();
+    if (optsSize < 4) {
+        // Message is too small
+        if (kDebug) ALOGD("Opts size too small %d", static_cast<int>(optsSize));
+        return false;
+    }
+
+    const uint8_t* options = msg.dhcpData.options;
+
+    memset(&mDhcpInfo, 0, sizeof(mDhcpInfo));
+
+    // Inspect all options in the message to try to find the ones we want
+    for (size_t i = 4; i + 1 < optsSize;) {
+        uint8_t optCode = options[i];
+        uint8_t optLength = options[i + 1];
+        if (optCode == OPT_END) {
+            break;
+        }
+
+        if (options + optLength + i >= msg.end()) {
+            // Invalid option length, drop it
+            if (kDebug)
+                ALOGD("Invalid opt length %d for opt %d", static_cast<int>(optLength),
+                      static_cast<int>(optCode));
+            return false;
+        }
+        const uint8_t* opt = options + i + 2;
+        switch (optCode) {
+        case OPT_LEASE_TIME:
+            if (optLength == 4) {
+                mDhcpInfo.leaseTime = ntohl(*reinterpret_cast<const uint32_t*>(opt));
+            }
+            break;
+        case OPT_T1:
+            if (optLength == 4) {
+                mDhcpInfo.t1 = ntohl(*reinterpret_cast<const uint32_t*>(opt));
+            }
+            break;
+        case OPT_T2:
+            if (optLength == 4) {
+                mDhcpInfo.t2 = ntohl(*reinterpret_cast<const uint32_t*>(opt));
+            }
+            break;
+        case OPT_SUBNET_MASK:
+            if (optLength == 4) {
+                mDhcpInfo.subnetMask = *reinterpret_cast<const in_addr_t*>(opt);
+            }
+            break;
+        case OPT_GATEWAY:
+            if (optLength >= 4) {
+                mDhcpInfo.gateway = *reinterpret_cast<const in_addr_t*>(opt);
+            }
+            break;
+        case OPT_MTU:
+            if (optLength == 2) {
+                mDhcpInfo.mtu = ntohs(*reinterpret_cast<const uint16_t*>(opt));
+            }
+            break;
+        case OPT_DNS:
+            if (optLength >= 4) {
+                mDhcpInfo.dns[0] = *reinterpret_cast<const in_addr_t*>(opt);
+            }
+            if (optLength >= 8) {
+                mDhcpInfo.dns[1] = *reinterpret_cast<const in_addr_t*>(opt + 4);
+            }
+            if (optLength >= 12) {
+                mDhcpInfo.dns[2] = *reinterpret_cast<const in_addr_t*>(opt + 8);
+            }
+            if (optLength >= 16) {
+                mDhcpInfo.dns[3] = *reinterpret_cast<const in_addr_t*>(opt + 12);
+            }
+            break;
+        case OPT_SERVER_ID:
+            if (optLength == 4) {
+                mDhcpInfo.serverId = *reinterpret_cast<const in_addr_t*>(opt);
+            }
+            break;
+        default:
+            break;
+        }
+        i += 2 + optLength;
+    }
+    mDhcpInfo.offeredAddress = msg.dhcpData.yiaddr;
+
+    if (mDhcpInfo.leaseTime == 0) {
+        // We didn't get a lease time, ignore this offer
+        return false;
+    }
+    // If there is no T1 or T2 timer given then we create an estimate as
+    // suggested for servers in RFC 2131.
+    uint32_t t1 = mDhcpInfo.t1, t2 = mDhcpInfo.t2;
+    mT1.expireSeconds(t1 > 0 ? t1 : (mDhcpInfo.leaseTime / 2));
+    mT2.expireSeconds(t2 > 0 ? t2 : ((mDhcpInfo.leaseTime * 7) / 8));
+
+    Result res = mInterface.bringUp();
+    if (!res) {
+        ALOGE("Could not configure DHCP: %s", res.c_str());
+        return false;
+    }
+
+    if (mDhcpInfo.mtu != 0) {
+        res = mInterface.setMtu(mDhcpInfo.mtu);
+        if (!res) {
+            // Consider this non-fatal, the system will not perform at its best
+            // but should still work.
+            ALOGE("Could not configure DHCP: %s", res.c_str());
+        }
+    }
+
+    char propName[64];
+    snprintf(propName, sizeof(propName), "vendor.net.%s.gw", mInterface.getName().c_str());
+    if (property_set(propName, addrToStr(mDhcpInfo.gateway).c_str()) != 0) {
+        ALOGE("Failed to set %s: %s", propName, strerror(errno));
+    }
+
+    int numDnsEntries = sizeof(mDhcpInfo.dns) / sizeof(mDhcpInfo.dns[0]);
+    for (int i = 0; i < numDnsEntries; ++i) {
+        snprintf(propName, sizeof(propName), "vendor.net.%s.dns%d", mInterface.getName().c_str(),
+                 i + 1);
+        if (mDhcpInfo.dns[i] != 0) {
+            if (property_set(propName, addrToStr(mDhcpInfo.dns[i]).c_str()) != 0) {
+                ALOGE("Failed to set %s: %s", propName, strerror(errno));
+            }
+        } else {
+            // Clear out any previous value here in case it was set
+            if (property_set(propName, "") != 0) {
+                ALOGE("Failed to clear %s: %s", propName, strerror(errno));
+            }
+        }
+    }
+
+    res = mInterface.setAddress(mDhcpInfo.offeredAddress, mDhcpInfo.subnetMask);
+    if (!res) {
+        ALOGE("Could not configure DHCP: %s", res.c_str());
+        return false;
+    }
+
+    if ((mOptions & static_cast<uint32_t>(ClientOption::NoGateway)) == 0) {
+        res = mRouter.setDefaultGateway(mDhcpInfo.gateway, mInterface.getIndex());
+        if (!res) {
+            ALOGE("Could not configure DHCP: %s", res.c_str());
+            return false;
+        }
+    }
+    return true;
+}
+
+void DhcpClient::haltNetwork() {
+    Result res = mInterface.setAddress(0, 0);
+    if (!res) {
+        ALOGE("Could not halt network: %s", res.c_str());
+    }
+    res = mInterface.bringDown();
+    if (!res) {
+        ALOGE("Could not halt network: %s", res.c_str());
+    }
+}
+
+bool DhcpClient::receiveDhcpMessage(Message* msg) {
+    bool isValid = false;
+    Result res = mSocket.receiveRawUdp(PORT_BOOTP_CLIENT, msg, &isValid);
+    if (!res) {
+        if (kDebug) ALOGD("Discarding message: %s", res.c_str());
+        return false;
+    }
+
+    return isValid && msg->isValidDhcpMessage(OP_BOOTREPLY, mLastMsg.dhcpData.xid);
+}
+
+uint32_t DhcpClient::calculateTimeoutMillis() {
+    if (!mFuzzNextTimeout) {
+        return mNextTimeout;
+    }
+    int adjustment = mRandomDistribution(mRandomEngine);
+    if (adjustment < 0 && static_cast<uint32_t>(-adjustment) > mNextTimeout) {
+        // Underflow, return a timeout of zero milliseconds
+        return 0;
+    }
+    return mNextTimeout + adjustment;
+}
+
+void DhcpClient::increaseTimeout() {
+    if (mNextTimeout == kNoTimeout) {
+        mNextTimeout = kInitialTimeout;
+    } else {
+        if (mNextTimeout < kMaxTimeout) {
+            mNextTimeout *= 2;
+        }
+        if (mNextTimeout > kMaxTimeout) {
+            mNextTimeout = kMaxTimeout;
+        }
+    }
+}
+
+void DhcpClient::setNextState(State state) {
+    if (kDebug) ALOGD("Moving from state %s to %s", stateToStr(mState), stateToStr(state));
+    mState = state;
+    mNextTimeout = kNoTimeout;
+    mFuzzNextTimeout = true;
+}
+
+void DhcpClient::sendDhcpRequest(in_addr_t destination) {
+    if (kDebug) ALOGD("Sending DHCPREQUEST");
+    mLastMsg = Message::request(mInterface.getMacAddress(), mRequestAddress, destination);
+    sendMessage(mLastMsg);
+}
+
+void DhcpClient::sendDhcpDiscover() {
+    if (kDebug) ALOGD("Sending DHCPDISCOVER");
+    mLastMsg = Message::discover(mInterface.getMacAddress());
+    sendMessage(mLastMsg);
+}
+
+void DhcpClient::sendMessage(const Message& message) {
+    Result res = mSocket.sendRawUdp(INADDR_ANY, PORT_BOOTP_CLIENT, INADDR_BROADCAST,
+                                    PORT_BOOTP_SERVER, mInterface.getIndex(), message);
+    if (!res) {
+        ALOGE("Unable to send message: %s", res.c_str());
+    }
+}
diff --git a/dhcp/client/dhcpclient.h b/dhcp/client/dhcpclient.h
new file mode 100644
index 0000000..2f6dce8
--- /dev/null
+++ b/dhcp/client/dhcpclient.h
@@ -0,0 +1,101 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#pragma once
+
+#include "interface.h"
+#include "message.h"
+#include "result.h"
+#include "router.h"
+#include "socket.h"
+#include "timer.h"
+
+#include <netinet/in.h>
+#include <stdint.h>
+
+#include <random>
+
+// Options to configure the behavior of the DHCP client.
+enum class ClientOption : uint32_t {
+    NoGateway = (1 << 0),  // Do not configure the system's default gateway
+};
+
+class DhcpClient {
+  public:
+    // Create a DHCP client with the given |options|. These options are values
+    // from the ClientOption enum.
+    explicit DhcpClient(uint32_t options);
+
+    // Initialize the DHCP client to listen on |interfaceName|.
+    Result init(const char* interfaceName);
+    Result run();
+
+  private:
+    enum class State { Init, Selecting, Requesting, Bound, Renewing, Rebinding };
+    const char* stateToStr(State state);
+
+    // Wait for any pending timeouts
+    void waitAndReceive(const sigset_t& pollSignalMask);
+    // Create a varying timeout (+- 1 second) based on the next timeout.
+    uint32_t calculateTimeoutMillis();
+    // Increase the next timeout in a manner that's compliant with the DHCP RFC.
+    void increaseTimeout();
+    // Move to |state|, the next poll timeout will be zero and the new
+    // state will be immediately evaluated.
+    void setNextState(State state);
+    // Configure network interface based on the DHCP configuration in |msg|.
+    bool configureDhcp(const Message& msg);
+    // Halt network operations on the network interface for when configuration
+    // is not possible and the protocol demands it.
+    void haltNetwork();
+    // Receive a message on the socket and populate |msg| with the received
+    // data. If the message is a valid DHCP message the method returns true. If
+    // it's not valid false is returned.
+    bool receiveDhcpMessage(Message* msg);
+
+    void sendDhcpDiscover();
+    void sendDhcpRequest(in_addr_t destination);
+    void sendMessage(const Message& message);
+    Result send(in_addr_t source, in_addr_t destination, uint16_t sourcePort,
+                uint16_t destinationPort, const uint8_t* data, size_t size);
+
+    uint32_t mOptions;
+    std::mt19937 mRandomEngine;  // Mersenne Twister RNG
+    std::uniform_int_distribution<int> mRandomDistribution;
+
+    struct DhcpInfo {
+        uint32_t t1;
+        uint32_t t2;
+        uint32_t leaseTime;
+        uint16_t mtu;
+        in_addr_t dns[4];
+        in_addr_t gateway;
+        in_addr_t subnetMask;
+        in_addr_t serverId;
+        in_addr_t offeredAddress;
+    } mDhcpInfo;
+
+    Router mRouter;
+    Interface mInterface;
+    Message mLastMsg;
+    Timer mT1, mT2;
+    Socket mSocket;
+    State mState;
+    uint32_t mNextTimeout;
+    bool mFuzzNextTimeout;
+
+    in_addr_t mRequestAddress;  // Address we'd like to use in requests
+    in_addr_t mServerAddress;   // Server to send request to
+};
diff --git a/dhcp/client/interface.cpp b/dhcp/client/interface.cpp
new file mode 100644
index 0000000..4a98333
--- /dev/null
+++ b/dhcp/client/interface.cpp
@@ -0,0 +1,220 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "interface.h"
+
+#include "netlink.h"
+
+#include <errno.h>
+#include <linux/if.h>
+#include <linux/if_ether.h>
+#include <linux/route.h>
+#include <linux/rtnetlink.h>
+#include <string.h>
+#include <unistd.h>
+
+in_addr_t broadcastFromNetmask(in_addr_t address, in_addr_t netmask) {
+    // The broadcast address is the address with the bits excluded in the
+    // netmask set to 1. For example if address = 10.0.2.15 and netmask is
+    // 255.255.255.0 then the broadcast is 10.0.2.255. If instead netmask was
+    // 255.0.0.0.0 then the broadcast would be 10.255.255.255
+    //
+    // Simply set all the lower bits to 1 and that should do it.
+    return address | (~netmask);
+}
+
+Interface::Interface() : mSocketFd(-1) {}
+
+Interface::~Interface() {
+    if (mSocketFd != -1) {
+        close(mSocketFd);
+        mSocketFd = -1;
+    }
+}
+
+Result Interface::init(const char* interfaceName) {
+    mInterfaceName = interfaceName;
+
+    if (mSocketFd != -1) {
+        return Result::error("Interface initialized more than once");
+    }
+
+    mSocketFd = ::socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
+    if (mSocketFd == -1) {
+        return Result::error("Failed to create interface socket for '%s': %s", interfaceName,
+                             strerror(errno));
+    }
+
+    Result res = populateIndex();
+    if (!res) {
+        return res;
+    }
+
+    res = populateMacAddress();
+    if (!res) {
+        return res;
+    }
+
+    res = bringUp();
+    if (!res) {
+        return res;
+    }
+
+    res = setAddress(0, 0);
+    if (!res) {
+        return res;
+    }
+
+    return Result::success();
+}
+
+Result Interface::bringUp() {
+    return setInterfaceUp(true);
+}
+
+Result Interface::bringDown() {
+    return setInterfaceUp(false);
+}
+
+Result Interface::setMtu(uint16_t mtu) {
+    struct ifreq request = createRequest();
+
+    strncpy(request.ifr_name, mInterfaceName.c_str(), sizeof(request.ifr_name));
+    request.ifr_mtu = mtu;
+    int status = ::ioctl(mSocketFd, SIOCSIFMTU, &request);
+    if (status != 0) {
+        return Result::error("Failed to set interface MTU %u for '%s': %s",
+                             static_cast<unsigned int>(mtu), mInterfaceName.c_str(),
+                             strerror(errno));
+    }
+
+    return Result::success();
+}
+
+Result Interface::setAddress(in_addr_t address, in_addr_t subnetMask) {
+    struct Request {
+        struct nlmsghdr hdr;
+        struct ifaddrmsg msg;
+        char buf[256];
+    } request;
+
+    memset(&request, 0, sizeof(request));
+
+    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
+    request.hdr.nlmsg_type = RTM_NEWADDR;
+    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_REPLACE;
+
+    request.msg.ifa_family = AF_INET;
+    // Count the number of bits in the subnet mask, this is the length.
+    request.msg.ifa_prefixlen = __builtin_popcount(subnetMask);
+    request.msg.ifa_index = mIndex;
+
+    addRouterAttribute(request, IFA_ADDRESS, &address, sizeof(address));
+    addRouterAttribute(request, IFA_LOCAL, &address, sizeof(address));
+    in_addr_t broadcast = broadcastFromNetmask(address, subnetMask);
+    addRouterAttribute(request, IFA_BROADCAST, &broadcast, sizeof(broadcast));
+
+    struct sockaddr_nl nlAddr;
+    memset(&nlAddr, 0, sizeof(nlAddr));
+    nlAddr.nl_family = AF_NETLINK;
+
+    int status = ::sendto(mSocketFd, &request, request.hdr.nlmsg_len, 0,
+                          reinterpret_cast<sockaddr*>(&nlAddr), sizeof(nlAddr));
+    if (status == -1) {
+        return Result::error("Unable to set interface address: %s", strerror(errno));
+    }
+    char buffer[8192];
+    status = ::recv(mSocketFd, buffer, sizeof(buffer), 0);
+    if (status < 0) {
+        return Result::error("Unable to read netlink response: %s", strerror(errno));
+    }
+    size_t responseSize = static_cast<size_t>(status);
+    if (responseSize < sizeof(nlmsghdr)) {
+        return Result::error("Received incomplete response from netlink");
+    }
+    auto response = reinterpret_cast<const nlmsghdr*>(buffer);
+    if (response->nlmsg_type == NLMSG_ERROR) {
+        if (responseSize < NLMSG_HDRLEN + sizeof(nlmsgerr)) {
+            return Result::error("Received an error from netlink but the "
+                                 "response was incomplete");
+        }
+        auto err = reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(response));
+        if (err->error) {
+            return Result::error("Could not set interface address: %s", strerror(-err->error));
+        }
+    }
+    return Result::success();
+}
+
+struct ifreq Interface::createRequest() const {
+    struct ifreq request;
+    memset(&request, 0, sizeof(request));
+    strncpy(request.ifr_name, mInterfaceName.c_str(), sizeof(request.ifr_name));
+    request.ifr_name[sizeof(request.ifr_name) - 1] = '\0';
+
+    return request;
+}
+
+Result Interface::populateIndex() {
+    struct ifreq request = createRequest();
+
+    int status = ::ioctl(mSocketFd, SIOCGIFINDEX, &request);
+    if (status != 0) {
+        return Result::error("Failed to get interface index for '%s': %s", mInterfaceName.c_str(),
+                             strerror(errno));
+    }
+    mIndex = request.ifr_ifindex;
+    return Result::success();
+}
+
+Result Interface::populateMacAddress() {
+    struct ifreq request = createRequest();
+
+    int status = ::ioctl(mSocketFd, SIOCGIFHWADDR, &request);
+    if (status != 0) {
+        return Result::error("Failed to get MAC address for '%s': %s", mInterfaceName.c_str(),
+                             strerror(errno));
+    }
+    memcpy(mMacAddress, &request.ifr_hwaddr.sa_data, ETH_ALEN);
+    return Result::success();
+}
+
+Result Interface::setInterfaceUp(bool shouldBeUp) {
+    struct ifreq request = createRequest();
+
+    int status = ::ioctl(mSocketFd, SIOCGIFFLAGS, &request);
+    if (status != 0) {
+        return Result::error("Failed to get interface flags for '%s': %s", mInterfaceName.c_str(),
+                             strerror(errno));
+    }
+
+    bool isUp = (request.ifr_flags & IFF_UP) != 0;
+    if (isUp != shouldBeUp) {
+        // Toggle the up flag
+        request.ifr_flags ^= IFF_UP;
+    } else {
+        // Interface is already in desired state, do nothing
+        return Result::success();
+    }
+
+    status = ::ioctl(mSocketFd, SIOCSIFFLAGS, &request);
+    if (status != 0) {
+        return Result::error("Failed to set interface flags for '%s': %s", mInterfaceName.c_str(),
+                             strerror(errno));
+    }
+
+    return Result::success();
+}
diff --git a/dhcp/client/interface.h b/dhcp/client/interface.h
new file mode 100644
index 0000000..1d9eb36
--- /dev/null
+++ b/dhcp/client/interface.h
@@ -0,0 +1,55 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#pragma once
+
+#include "result.h"
+
+#include <linux/if_ether.h>
+#include <netinet/in.h>
+
+#include <string>
+
+// A class representing a network interface. The class provides useful
+// functionality to configure and query the network interface.
+class Interface {
+  public:
+    Interface();
+    ~Interface();
+    Result init(const char* interfaceName);
+
+    // Returns the interface index indicated by the system
+    unsigned int getIndex() const { return mIndex; }
+    // Get the MAC address of the interface
+    const uint8_t (&getMacAddress() const)[ETH_ALEN] { return mMacAddress; }
+    // Get the name of the interface
+    const std::string& getName() const { return mInterfaceName; }
+
+    Result bringUp();
+    Result bringDown();
+    Result setMtu(uint16_t mtu);
+    Result setAddress(in_addr_t address, in_addr_t subnetMask);
+
+  private:
+    struct ifreq createRequest() const;
+    Result populateIndex();
+    Result populateMacAddress();
+    Result setInterfaceUp(bool shouldBeUp);
+
+    std::string mInterfaceName;
+    int mSocketFd;
+    unsigned int mIndex;
+    uint8_t mMacAddress[ETH_ALEN];
+};
diff --git a/dhcp/client/log.h b/dhcp/client/log.h
new file mode 100644
index 0000000..d541dd6
--- /dev/null
+++ b/dhcp/client/log.h
@@ -0,0 +1,19 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#define LOG_TAG "dhcpclient"
+#include <log/log.h>
diff --git a/dhcp/client/main.cpp b/dhcp/client/main.cpp
new file mode 100644
index 0000000..45e0b34
--- /dev/null
+++ b/dhcp/client/main.cpp
@@ -0,0 +1,71 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "dhcpclient.h"
+#include "log.h"
+
+static void usage(const char* program) {
+    ALOGE("Usage: %s [--no-gateway] -i <interface>", program);
+    ALOGE("  If the optional parameter --no-gateway is specified the client");
+    ALOGE("  will not configure the default gateway of the system.");
+}
+
+int main(int argc, char* argv[]) {
+    if (argc < 3) {
+        usage(argv[0]);
+        return 1;
+    }
+    const char* interfaceName = nullptr;
+    uint32_t options = 0;
+
+    for (int i = 1; i < argc; ++i) {
+        if (strcmp(argv[i], "-i") == 0) {
+            if (i + 1 < argc) {
+                interfaceName = argv[++i];
+            } else {
+                ALOGE("ERROR: -i parameter needs an argument");
+                usage(argv[0]);
+                return 1;
+            }
+        } else if (strcmp(argv[i], "--no-gateway") == 0) {
+            options |= static_cast<uint32_t>(ClientOption::NoGateway);
+        } else {
+            ALOGE("ERROR: unknown parameters %s", argv[i]);
+            usage(argv[0]);
+            return 1;
+        }
+    }
+    if (interfaceName == nullptr) {
+        ALOGE("ERROR: No interface specified");
+        usage(argv[0]);
+        return 1;
+    }
+
+    DhcpClient client(options);
+    Result res = client.init(interfaceName);
+    if (!res) {
+        ALOGE("Failed to initialize DHCP client: %s\n", res.c_str());
+        return 1;
+    }
+
+    res = client.run();
+    if (!res) {
+        ALOGE("DHCP client failed: %s\n", res.c_str());
+        return 1;
+    }
+    // This is weird and shouldn't happen, the client should run forever.
+    return 0;
+}
diff --git a/dhcp/client/netlink.h b/dhcp/client/netlink.h
new file mode 100644
index 0000000..d1c737a
--- /dev/null
+++ b/dhcp/client/netlink.h
@@ -0,0 +1,19 @@
+#pragma once
+
+#include <linux/rtnetlink.h>
+
+template <class Request>
+inline void addRouterAttribute(Request& r, int type, const void* data, size_t size) {
+    // Calculate the offset into the character buffer where the RTA data lives
+    // We use offsetof on the buffer to get it. This avoids undefined behavior
+    // by casting the buffer (which is safe because it's char) instead of the
+    // Request struct.(which is undefined because of aliasing)
+    size_t offset = NLMSG_ALIGN(r.hdr.nlmsg_len) - offsetof(Request, buf);
+    auto attr = reinterpret_cast<struct rtattr*>(r.buf + offset);
+    attr->rta_type = type;
+    attr->rta_len = RTA_LENGTH(size);
+    memcpy(RTA_DATA(attr), data, size);
+
+    // Update the message length to include the router attribute.
+    r.hdr.nlmsg_len = NLMSG_ALIGN(r.hdr.nlmsg_len) + RTA_ALIGN(attr->rta_len);
+}
diff --git a/dhcp/client/router.cpp b/dhcp/client/router.cpp
new file mode 100644
index 0000000..a26c3fc
--- /dev/null
+++ b/dhcp/client/router.cpp
@@ -0,0 +1,83 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#include "router.h"
+
+#include "netlink.h"
+
+#include <linux/rtnetlink.h>
+
+#include <errno.h>
+#include <string.h>
+#include <unistd.h>
+
+Router::Router() : mSocketFd(-1) {}
+
+Router::~Router() {
+    if (mSocketFd != -1) {
+        ::close(mSocketFd);
+        mSocketFd = -1;
+    }
+}
+
+Result Router::init() {
+    // Create a netlink socket to the router
+    mSocketFd = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
+    if (mSocketFd == -1) {
+        return Result::error(strerror(errno));
+    }
+    return Result::success();
+}
+
+Result Router::setDefaultGateway(in_addr_t gateway, unsigned int ifaceIndex) {
+    struct Request {
+        struct nlmsghdr hdr;
+        struct rtmsg msg;
+        char buf[256];
+    } request;
+
+    memset(&request, 0, sizeof(request));
+
+    // Set up a request to create a new route
+    request.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(request.msg));
+    request.hdr.nlmsg_type = RTM_NEWROUTE;
+    request.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE;
+
+    request.msg.rtm_family = AF_INET;
+    request.msg.rtm_dst_len = 0;
+    request.msg.rtm_table = RT_TABLE_MAIN;
+    request.msg.rtm_protocol = RTPROT_BOOT;
+    request.msg.rtm_scope = RT_SCOPE_UNIVERSE;
+    request.msg.rtm_type = RTN_UNICAST;
+
+    addRouterAttribute(request, RTA_GATEWAY, &gateway, sizeof(gateway));
+    addRouterAttribute(request, RTA_OIF, &ifaceIndex, sizeof(ifaceIndex));
+
+    return sendNetlinkMessage(&request, request.hdr.nlmsg_len);
+}
+
+Result Router::sendNetlinkMessage(const void* data, size_t size) {
+    struct sockaddr_nl nlAddress;
+    memset(&nlAddress, 0, sizeof(nlAddress));
+    nlAddress.nl_family = AF_NETLINK;
+
+    int res = ::sendto(mSocketFd, data, size, 0, reinterpret_cast<sockaddr*>(&nlAddress),
+                       sizeof(nlAddress));
+    if (res == -1) {
+        return Result::error("Unable to send on netlink socket: %s", strerror(errno));
+    }
+    return Result::success();
+}
diff --git a/dhcp/client/router.h b/dhcp/client/router.h
new file mode 100644
index 0000000..7de2272
--- /dev/null
+++ b/dhcp/client/router.h
@@ -0,0 +1,44 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#include <stdint.h>
+
+#include <netinet/in.h>
+
+#include "result.h"
+
+class Router {
+  public:
+    Router();
+    ~Router();
+    // Initialize the router, this has to be called before any other methods can
+    // be called. It only needs to be called once.
+    Result init();
+
+    // Set the default route to |gateway| on the interface specified by
+    // |interfaceIndex|. If the default route is already set up with the same
+    // configuration then nothing is done. If another default route exists it
+    // will be removed and replaced by the new one. If no default route exists
+    // a route will be created with the given parameters.
+    Result setDefaultGateway(in_addr_t gateway, unsigned int interfaceIndex);
+
+  private:
+    Result sendNetlinkMessage(const void* data, size_t size);
+
+    // Netlink socket for setting up neighbors and routes
+    int mSocketFd;
+};
diff --git a/dhcp/client/timer.cpp b/dhcp/client/timer.cpp
new file mode 100644
index 0000000..298c62b
--- /dev/null
+++ b/dhcp/client/timer.cpp
@@ -0,0 +1,44 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "timer.h"
+
+#include <time.h>
+
+uint64_t now() {
+    struct timespec time = {0, 0};
+    clock_gettime(CLOCK_MONOTONIC, &time);
+    return static_cast<uint64_t>(time.tv_sec) * 1000u +
+           static_cast<uint64_t>(time.tv_nsec / 1000000u);
+}
+
+Timer::Timer() : mExpires(0) {}
+
+void Timer::expireSeconds(uint64_t seconds) {
+    mExpires = now() + seconds * 1000u;
+}
+
+bool Timer::expired() const {
+    return now() >= mExpires;
+}
+
+uint64_t Timer::remainingMillis() const {
+    uint64_t current = now();
+    if (current > mExpires) {
+        return 0;
+    }
+    return mExpires - current;
+}
diff --git a/dhcp/client/timer.h b/dhcp/client/timer.h
new file mode 100644
index 0000000..22d58de
--- /dev/null
+++ b/dhcp/client/timer.h
@@ -0,0 +1,39 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include <stdint.h>
+
+// Return the current timestamp from a monotonic clock in milliseconds.
+uint64_t now();
+
+class Timer {
+  public:
+    // Create a timer, initially the timer is already expired.
+    Timer();
+
+    // Set the timer to expire in |seconds| seconds.
+    void expireSeconds(uint64_t seconds);
+
+    // Return true if the timer has expired.
+    bool expired() const;
+    // Get the remaining time on the timer in milliseconds.
+    uint64_t remainingMillis() const;
+
+  private:
+    uint64_t mExpires;
+};
diff --git a/dhcp/common/Android.bp b/dhcp/common/Android.bp
new file mode 100644
index 0000000..20d0c12
--- /dev/null
+++ b/dhcp/common/Android.bp
@@ -0,0 +1,33 @@
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
+cc_library_static {
+    name: "libdhcpclient",
+    srcs: [
+        "message.cpp",
+        "socket.cpp",
+        "utils.cpp",
+    ],
+    export_include_dirs: ["include"],
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+    ],
+    proprietary: true,
+}
diff --git a/dhcp/common/include/dhcp.h b/dhcp/common/include/dhcp.h
new file mode 100644
index 0000000..cc64b94
--- /dev/null
+++ b/dhcp/common/include/dhcp.h
@@ -0,0 +1,70 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#pragma once
+
+// Ports
+#define PORT_BOOTP_SERVER 67
+#define PORT_BOOTP_CLIENT 68
+
+// Operations
+#define OP_BOOTREQUEST 1
+#define OP_BOOTREPLY 2
+
+// Flags
+#define FLAGS_BROADCAST 0x8000
+
+// Hardware address types
+#define HTYPE_ETHER 1
+
+// The first four bytes of options are a cookie to indicate that the payload are
+// DHCP options as opposed to some other BOOTP extension.
+#define OPT_COOKIE1 0x63
+#define OPT_COOKIE2 0x82
+#define OPT_COOKIE3 0x53
+#define OPT_COOKIE4 0x63
+
+// BOOTP/DHCP options - see RFC 2132
+#define OPT_PAD 0
+
+#define OPT_SUBNET_MASK 1      // 4 <ipaddr>
+#define OPT_TIME_OFFSET 2      // 4 <seconds>
+#define OPT_GATEWAY 3          // 4*n <ipaddr> * n
+#define OPT_DNS 6              // 4*n <ipaddr> * n
+#define OPT_DOMAIN_NAME 15     // n <domainnamestring>
+#define OPT_MTU 26             // 2 <mtu>
+#define OPT_BROADCAST_ADDR 28  // 4 <ipaddr>
+
+#define OPT_REQUESTED_IP 50    // 4 <ipaddr>
+#define OPT_LEASE_TIME 51      // 4 <seconds>
+#define OPT_MESSAGE_TYPE 53    // 1 <msgtype>
+#define OPT_SERVER_ID 54       // 4 <ipaddr>
+#define OPT_PARAMETER_LIST 55  // n <optcode> * n
+#define OPT_MESSAGE 56         // n <errorstring>
+#define OPT_T1 58              // 4 <renewal time value>
+#define OPT_T2 59              // 4 <rebinding time value>
+#define OPT_CLASS_ID 60        // n <opaque>
+#define OPT_CLIENT_ID 61       // n <opaque>
+#define OPT_END 255
+
+// DHCP message types
+#define DHCPDISCOVER 1
+#define DHCPOFFER 2
+#define DHCPREQUEST 3
+#define DHCPDECLINE 4
+#define DHCPACK 5
+#define DHCPNAK 6
+#define DHCPRELEASE 7
+#define DHCPINFORM 8
diff --git a/dhcp/common/include/message.h b/dhcp/common/include/message.h
new file mode 100644
index 0000000..86b63c5
--- /dev/null
+++ b/dhcp/common/include/message.h
@@ -0,0 +1,115 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#pragma once
+
+#include <linux/if_ether.h>
+#include <netinet/in.h>
+#include <stddef.h>
+#include <string.h>
+
+#include <initializer_list>
+
+class Message {
+  public:
+    Message();
+    Message(const uint8_t* data, size_t size);
+    static Message discover(const uint8_t (&sourceMac)[ETH_ALEN]);
+    static Message request(const uint8_t (&sourceMac)[ETH_ALEN], in_addr_t requestAddress,
+                           in_addr_t serverAddress);
+    static Message offer(const Message& sourceMessage, in_addr_t serverAddress,
+                         in_addr_t offeredAddress, in_addr_t offeredNetmask,
+                         in_addr_t offeredGateway, const in_addr_t* offeredDnsServers,
+                         size_t numOfferedDnsServers);
+    static Message ack(const Message& sourceMessage, in_addr_t serverAddress,
+                       in_addr_t offeredAddress, in_addr_t offeredNetmask, in_addr_t offeredGateway,
+                       const in_addr_t* offeredDnsServers, size_t numOfferedDnsServers);
+    static Message nack(const Message& sourceMessage, in_addr_t serverAddress);
+
+    // Ensure that the data in the message represent a valid DHCP message
+    bool isValidDhcpMessage(uint8_t expectedOp) const;
+    // Ensure that the data in the message represent a valid DHCP message and
+    // has a xid (transaction ID) that matches |expectedXid|.
+    bool isValidDhcpMessage(uint8_t expectedOp, uint32_t expectedXid) const;
+
+    const uint8_t* data() const { return reinterpret_cast<const uint8_t*>(&dhcpData); }
+    uint8_t* data() { return reinterpret_cast<uint8_t*>(&dhcpData); }
+    const uint8_t* end() const { return data() + mSize; }
+
+    size_t optionsSize() const;
+    size_t size() const { return mSize; }
+    void setSize(size_t size) { mSize = size; }
+    size_t capacity() const { return sizeof(dhcpData); }
+
+    // Get the DHCP message type
+    uint8_t type() const;
+    // Get the DHCP server ID
+    in_addr_t serverId() const;
+    // Get the requested IP
+    in_addr_t requestedIp() const;
+
+    struct Dhcp {
+        uint8_t op;    /* BOOTREQUEST / BOOTREPLY    */
+        uint8_t htype; /* hw addr type               */
+        uint8_t hlen;  /* hw addr len                */
+        uint8_t hops;  /* client set to 0            */
+
+        uint32_t xid; /* transaction id             */
+
+        uint16_t secs; /* seconds since start of acq */
+        uint16_t flags;
+
+        uint32_t ciaddr; /* client IP addr             */
+        uint32_t yiaddr; /* your (client) IP addr      */
+        uint32_t siaddr; /* ip addr of next server     */
+                         /* (DHCPOFFER and DHCPACK)    */
+        uint32_t giaddr; /* relay agent IP addr        */
+
+        uint8_t chaddr[16]; /* client hw addr             */
+        char sname[64];     /* asciiz server hostname     */
+        char file[128];     /* asciiz boot file name      */
+
+        uint8_t options[1024]; /* optional parameters        */
+    } dhcpData;
+
+  private:
+    Message(uint8_t operation, const uint8_t (&macAddress)[ETH_ALEN], uint8_t type);
+
+    void addOption(uint8_t type, const void* data, uint8_t size);
+    template <typename T> void addOption(uint8_t type, T data) {
+        static_assert(sizeof(T) <= 255, "The size of data is too large");
+        addOption(type, &data, sizeof(data));
+    }
+    template <typename T, size_t N> void addOption(uint8_t type, T (&items)[N]) {
+        static_assert(sizeof(T) * N <= 255, "The size of data is too large");
+        uint8_t* opts = nextOption();
+        *opts++ = type;
+        *opts++ = sizeof(T) * N;
+        for (const T& item : items) {
+            memcpy(opts, &item, sizeof(item));
+            opts += sizeof(item);
+        }
+        updateSize(opts);
+    }
+    void endOptions();
+
+    const uint8_t* getOption(uint8_t optCode, uint8_t* length) const;
+    uint8_t* nextOption();
+    void updateSize(uint8_t* optionsEnd);
+    size_t mSize;
+};
+
+static_assert(offsetof(Message::Dhcp, htype) == sizeof(Message::Dhcp::op),
+              "Invalid packing for DHCP message struct");
diff --git a/dhcp/common/include/result.h b/dhcp/common/include/result.h
new file mode 100644
index 0000000..57d5174
--- /dev/null
+++ b/dhcp/common/include/result.h
@@ -0,0 +1,48 @@
+/*
+ * Copyright (C) 2017 The Android Open Source Project
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
+#include <stdarg.h>
+#include <stdio.h>
+
+#include <string>
+
+class Result {
+  public:
+    static Result success() { return Result(true); }
+    // Construct a result indicating an error.
+    static Result error(std::string message) { return Result(message); }
+    static Result error(const char* format, ...) {
+        char buffer[1024];
+        va_list args;
+        va_start(args, format);
+        vsnprintf(buffer, sizeof(buffer), format, args);
+        va_end(args);
+        buffer[sizeof(buffer) - 1] = '\0';
+        return Result(std::string(buffer));
+    }
+
+    bool isSuccess() const { return mSuccess; }
+    bool operator!() const { return !mSuccess; }
+
+    const char* c_str() const { return mMessage.c_str(); }
+
+  private:
+    explicit Result(bool success) : mSuccess(success) {}
+    explicit Result(std::string message) : mMessage(message), mSuccess(false) {}
+    std::string mMessage;
+    bool mSuccess;
+};
diff --git a/dhcp/common/include/socket.h b/dhcp/common/include/socket.h
new file mode 100644
index 0000000..4bdd223
--- /dev/null
+++ b/dhcp/common/include/socket.h
@@ -0,0 +1,71 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "result.h"
+
+#include <arpa/inet.h>
+
+class Message;
+
+class Socket {
+  public:
+    Socket();
+    Socket(const Socket&) = delete;
+    ~Socket();
+
+    Socket& operator=(const Socket&) = delete;
+
+    int get() const { return mSocketFd; }
+    // Open a socket, |domain|, |type| and |protocol| are as described in the
+    // man pages for socket.
+    Result open(int domain, int type, int protocol);
+    // Bind to a generic |sockaddr| of size |sockaddrLength|
+    Result bind(const void* sockaddr, size_t sockaddrLength);
+    // Bind to an IP |address| and |port|
+    Result bindIp(in_addr_t address, uint16_t port);
+    // Bind a raw socket to the interface with index |interfaceIndex|.
+    Result bindRaw(unsigned int interfaceIndex);
+    // Send data in |message| on an IP socket to
+    // |destinationAddress|:|destinationPort|, the message will egress on the
+    // interface specified by |interfaceIndex|
+    Result sendOnInterface(unsigned int interfaceIndex, in_addr_t destinationAddress,
+                           uint16_t destinationPort, const Message& message);
+    // Send |message| as a UDP datagram on a raw socket. The source address of
+    // the message will be |source|:|sourcePort| and the destination will be
+    // |destination|:|destinationPort|. The message will be sent on the
+    // interface indicated by |interfaceIndex|.
+    Result sendRawUdp(in_addr_t source, uint16_t sourcePort, in_addr_t destination,
+                      uint16_t destinationPort, unsigned int interfaceIndex,
+                      const Message& message);
+    // Receive data on the socket and indicate which interface the data was
+    // received on in |interfaceIndex|. The received data is placed in |message|
+    Result receiveFromInterface(Message* message, unsigned int* interfaceIndex);
+    // Receive UDP data on a raw socket. Expect that the protocol in the IP
+    // header is UDP and that the port in the UDP header is |expectedPort|. If
+    // the received data is valid then |isValid| will be set to true, otherwise
+    // false. The validity check includes the expected values as well as basic
+    // size requirements to fit the expected protocol headers.  The method will
+    // only return an error result if the actual receiving fails.
+    Result receiveRawUdp(uint16_t expectedPort, Message* message, bool* isValid);
+    // Enable |optionName| on option |level|. These values are the same as used
+    // in setsockopt calls.
+    Result enableOption(int level, int optionName);
+
+  private:
+    int mSocketFd;
+};
diff --git a/dhcp/common/include/utils.h b/dhcp/common/include/utils.h
new file mode 100644
index 0000000..69591e6
--- /dev/null
+++ b/dhcp/common/include/utils.h
@@ -0,0 +1,23 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include <arpa/inet.h>
+
+#include <string>
+
+std::string addrToStr(in_addr_t address);
diff --git a/dhcp/common/message.cpp b/dhcp/common/message.cpp
new file mode 100644
index 0000000..70a7100
--- /dev/null
+++ b/dhcp/common/message.cpp
@@ -0,0 +1,285 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "message.h"
+#include "dhcp.h"
+
+#include <string.h>
+
+#include <vector>
+
+static uint32_t sNextTransactionId = 1;
+
+// The default lease time in seconds
+static const uint32_t kDefaultLeaseTime = 10 * 60;
+
+// The parameters that the client would like to receive from the server
+static const uint8_t kRequestParameters[] = {
+    OPT_SUBNET_MASK, OPT_GATEWAY, OPT_DNS, OPT_BROADCAST_ADDR,
+    OPT_LEASE_TIME,  OPT_T1,      OPT_T2,  OPT_MTU};
+
+Message::Message() {
+    memset(&dhcpData, 0, sizeof(dhcpData));
+    mSize = 0;
+}
+
+Message::Message(const uint8_t* data, size_t size) {
+    if (size <= sizeof(dhcpData)) {
+        memcpy(&dhcpData, data, size);
+        mSize = size;
+    } else {
+        memset(&dhcpData, 0, sizeof(dhcpData));
+        mSize = 0;
+    }
+}
+
+Message Message::discover(const uint8_t (&sourceMac)[ETH_ALEN]) {
+    Message message(OP_BOOTREQUEST, sourceMac, static_cast<uint8_t>(DHCPDISCOVER));
+
+    message.addOption(OPT_PARAMETER_LIST, kRequestParameters);
+    message.endOptions();
+
+    return message;
+}
+
+Message Message::request(const uint8_t (&sourceMac)[ETH_ALEN], in_addr_t requestAddress,
+                         in_addr_t serverAddress) {
+
+    Message message(OP_BOOTREQUEST, sourceMac, static_cast<uint8_t>(DHCPREQUEST));
+
+    message.addOption(OPT_PARAMETER_LIST, kRequestParameters);
+    message.addOption(OPT_REQUESTED_IP, requestAddress);
+    message.addOption(OPT_SERVER_ID, serverAddress);
+    message.endOptions();
+
+    return message;
+}
+
+Message Message::offer(const Message& sourceMessage, in_addr_t serverAddress,
+                       in_addr_t offeredAddress, in_addr_t offeredNetmask, in_addr_t offeredGateway,
+                       const in_addr_t* offeredDnsServers, size_t numOfferedDnsServers) {
+
+    uint8_t macAddress[ETH_ALEN];
+    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
+    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPOFFER));
+
+    message.dhcpData.xid = sourceMessage.dhcpData.xid;
+    message.dhcpData.flags = sourceMessage.dhcpData.flags;
+    message.dhcpData.yiaddr = offeredAddress;
+    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
+
+    message.addOption(OPT_SERVER_ID, serverAddress);
+    message.addOption(OPT_LEASE_TIME, kDefaultLeaseTime);
+    message.addOption(OPT_SUBNET_MASK, offeredNetmask);
+    message.addOption(OPT_GATEWAY, offeredGateway);
+    message.addOption(OPT_DNS, offeredDnsServers, numOfferedDnsServers * sizeof(in_addr_t));
+
+    message.endOptions();
+
+    return message;
+}
+
+Message Message::ack(const Message& sourceMessage, in_addr_t serverAddress,
+                     in_addr_t offeredAddress, in_addr_t offeredNetmask, in_addr_t offeredGateway,
+                     const in_addr_t* offeredDnsServers, size_t numOfferedDnsServers) {
+    uint8_t macAddress[ETH_ALEN];
+    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
+    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPACK));
+
+    message.dhcpData.xid = sourceMessage.dhcpData.xid;
+    message.dhcpData.flags = sourceMessage.dhcpData.flags;
+    message.dhcpData.yiaddr = offeredAddress;
+    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
+
+    message.addOption(OPT_SERVER_ID, serverAddress);
+    message.addOption(OPT_LEASE_TIME, kDefaultLeaseTime);
+    message.addOption(OPT_SUBNET_MASK, offeredNetmask);
+    message.addOption(OPT_GATEWAY, offeredGateway);
+    message.addOption(OPT_DNS, offeredDnsServers, numOfferedDnsServers * sizeof(in_addr_t));
+
+    message.endOptions();
+
+    return message;
+}
+
+Message Message::nack(const Message& sourceMessage, in_addr_t serverAddress) {
+    uint8_t macAddress[ETH_ALEN];
+    memcpy(macAddress, sourceMessage.dhcpData.chaddr, sizeof(macAddress));
+    Message message(OP_BOOTREPLY, macAddress, static_cast<uint8_t>(DHCPNAK));
+
+    message.dhcpData.xid = sourceMessage.dhcpData.xid;
+    message.dhcpData.flags = sourceMessage.dhcpData.flags;
+    message.dhcpData.giaddr = sourceMessage.dhcpData.giaddr;
+
+    message.addOption(OPT_SERVER_ID, serverAddress);
+    message.endOptions();
+
+    return message;
+}
+
+bool Message::isValidDhcpMessage(uint8_t expectedOp, uint32_t expectedXid) const {
+    if (!isValidDhcpMessage(expectedOp)) {
+        return false;
+    }
+    // Only look for message with a matching transaction ID
+    if (dhcpData.xid != expectedXid) {
+        return false;
+    }
+    return true;
+}
+
+bool Message::isValidDhcpMessage(uint8_t expectedOp) const {
+    // Require that there is at least enough options for the DHCP cookie
+    if (dhcpData.options + 4 > end()) {
+        return false;
+    }
+
+    if (dhcpData.op != expectedOp) {
+        return false;
+    }
+    if (dhcpData.htype != HTYPE_ETHER) {
+        return false;
+    }
+    if (dhcpData.hlen != ETH_ALEN) {
+        return false;
+    }
+
+    // Need to have the correct cookie in the options
+    if (dhcpData.options[0] != OPT_COOKIE1) {
+        return false;
+    }
+    if (dhcpData.options[1] != OPT_COOKIE2) {
+        return false;
+    }
+    if (dhcpData.options[2] != OPT_COOKIE3) {
+        return false;
+    }
+    if (dhcpData.options[3] != OPT_COOKIE4) {
+        return false;
+    }
+
+    return true;
+}
+
+size_t Message::optionsSize() const {
+    auto options = reinterpret_cast<const uint8_t*>(&dhcpData.options);
+    const uint8_t* msgEnd = end();
+    if (msgEnd <= options) {
+        return 0;
+    }
+    return msgEnd - options;
+}
+
+uint8_t Message::type() const {
+    uint8_t length = 0;
+    const uint8_t* opt = getOption(OPT_MESSAGE_TYPE, &length);
+    if (opt && length == 1) {
+        return *opt;
+    }
+    return 0;
+}
+
+in_addr_t Message::serverId() const {
+    uint8_t length = 0;
+    const uint8_t* opt = getOption(OPT_SERVER_ID, &length);
+    if (opt && length == 4) {
+        return *reinterpret_cast<const in_addr_t*>(opt);
+    }
+    return 0;
+}
+
+in_addr_t Message::requestedIp() const {
+    uint8_t length = 0;
+    const uint8_t* opt = getOption(OPT_REQUESTED_IP, &length);
+    if (opt && length == 4) {
+        return *reinterpret_cast<const in_addr_t*>(opt);
+    }
+    return 0;
+}
+
+Message::Message(uint8_t operation, const uint8_t (&macAddress)[ETH_ALEN], uint8_t type) {
+    memset(&dhcpData, 0, sizeof(dhcpData));
+
+    dhcpData.op = operation;
+    dhcpData.htype = HTYPE_ETHER;
+    dhcpData.hlen = ETH_ALEN;
+    dhcpData.hops = 0;
+
+    dhcpData.flags = htons(FLAGS_BROADCAST);
+
+    dhcpData.xid = htonl(sNextTransactionId++);
+
+    memcpy(dhcpData.chaddr, macAddress, ETH_ALEN);
+
+    uint8_t* opts = dhcpData.options;
+
+    *opts++ = OPT_COOKIE1;
+    *opts++ = OPT_COOKIE2;
+    *opts++ = OPT_COOKIE3;
+    *opts++ = OPT_COOKIE4;
+
+    *opts++ = OPT_MESSAGE_TYPE;
+    *opts++ = 1;
+    *opts++ = type;
+
+    updateSize(opts);
+}
+
+void Message::addOption(uint8_t type, const void* data, uint8_t size) {
+    uint8_t* opts = nextOption();
+
+    *opts++ = type;
+    *opts++ = size;
+    memcpy(opts, data, size);
+    opts += size;
+
+    updateSize(opts);
+}
+
+void Message::endOptions() {
+    uint8_t* opts = nextOption();
+
+    *opts++ = OPT_END;
+
+    updateSize(opts);
+}
+
+const uint8_t* Message::getOption(uint8_t expectedOptCode, uint8_t* length) const {
+    size_t optsSize = optionsSize();
+    for (size_t i = 4; i + 2 < optsSize;) {
+        uint8_t optCode = dhcpData.options[i];
+        uint8_t optLen = dhcpData.options[i + 1];
+        const uint8_t* opt = dhcpData.options + i + 2;
+
+        if (optCode == OPT_END) {
+            return nullptr;
+        }
+        if (optCode == expectedOptCode) {
+            *length = optLen;
+            return opt;
+        }
+        i += 2 + optLen;
+    }
+    return nullptr;
+}
+
+uint8_t* Message::nextOption() {
+    return reinterpret_cast<uint8_t*>(&dhcpData) + size();
+}
+
+void Message::updateSize(uint8_t* optionsEnd) {
+    mSize = optionsEnd - reinterpret_cast<uint8_t*>(&dhcpData);
+}
diff --git a/dhcp/common/socket.cpp b/dhcp/common/socket.cpp
new file mode 100644
index 0000000..289118b
--- /dev/null
+++ b/dhcp/common/socket.cpp
@@ -0,0 +1,290 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "socket.h"
+
+#include "message.h"
+#include "utils.h"
+
+#include <errno.h>
+#include <linux/if_packet.h>
+#include <netinet/ip.h>
+#include <netinet/udp.h>
+#include <string.h>
+#include <sys/socket.h>
+#include <sys/types.h>
+#include <sys/uio.h>
+#include <unistd.h>
+
+// Combine the checksum of |buffer| with |size| bytes with |checksum|. This is
+// used for checksum calculations for IP and UDP.
+static uint32_t addChecksum(const uint8_t* buffer, size_t size, uint32_t checksum) {
+    const uint16_t* data = reinterpret_cast<const uint16_t*>(buffer);
+    while (size > 1) {
+        checksum += *data++;
+        size -= 2;
+    }
+    if (size > 0) {
+        // Odd size, add the last byte
+        checksum += *reinterpret_cast<const uint8_t*>(data);
+    }
+    // msw is the most significant word, the upper 16 bits of the checksum
+    for (uint32_t msw = checksum >> 16; msw != 0; msw = checksum >> 16) {
+        checksum = (checksum & 0xFFFF) + msw;
+    }
+    return checksum;
+}
+
+// Convenienct template function for checksum calculation
+template <typename T> static uint32_t addChecksum(const T& data, uint32_t checksum) {
+    return addChecksum(reinterpret_cast<const uint8_t*>(&data), sizeof(T), checksum);
+}
+
+// Finalize the IP or UDP |checksum| by inverting and truncating it.
+static uint32_t finishChecksum(uint32_t checksum) {
+    return ~checksum & 0xFFFF;
+}
+
+Socket::Socket() : mSocketFd(-1) {}
+
+Socket::~Socket() {
+    if (mSocketFd != -1) {
+        ::close(mSocketFd);
+        mSocketFd = -1;
+    }
+}
+
+Result Socket::open(int domain, int type, int protocol) {
+    if (mSocketFd != -1) {
+        return Result::error("Socket already open");
+    }
+    mSocketFd = ::socket(domain, type, protocol);
+    if (mSocketFd == -1) {
+        return Result::error("Failed to open socket: %s", strerror(errno));
+    }
+    return Result::success();
+}
+
+Result Socket::bind(const void* sockaddr, size_t sockaddrLength) {
+    if (mSocketFd == -1) {
+        return Result::error("Socket not open");
+    }
+
+    int status =
+        ::bind(mSocketFd, reinterpret_cast<const struct sockaddr*>(sockaddr), sockaddrLength);
+    if (status != 0) {
+        return Result::error("Unable to bind raw socket: %s", strerror(errno));
+    }
+
+    return Result::success();
+}
+
+Result Socket::bindIp(in_addr_t address, uint16_t port) {
+    struct sockaddr_in sockaddr;
+    memset(&sockaddr, 0, sizeof(sockaddr));
+    sockaddr.sin_family = AF_INET;
+    sockaddr.sin_port = htons(port);
+    sockaddr.sin_addr.s_addr = address;
+
+    return bind(&sockaddr, sizeof(sockaddr));
+}
+
+Result Socket::bindRaw(unsigned int interfaceIndex) {
+    struct sockaddr_ll sockaddr;
+    memset(&sockaddr, 0, sizeof(sockaddr));
+    sockaddr.sll_family = AF_PACKET;
+    sockaddr.sll_protocol = htons(ETH_P_IP);
+    sockaddr.sll_ifindex = interfaceIndex;
+
+    return bind(&sockaddr, sizeof(sockaddr));
+}
+
+Result Socket::sendOnInterface(unsigned int interfaceIndex, in_addr_t destinationAddress,
+                               uint16_t destinationPort, const Message& message) {
+    if (mSocketFd == -1) {
+        return Result::error("Socket not open");
+    }
+
+    char controlData[CMSG_SPACE(sizeof(struct in_pktinfo))] = {0};
+    struct sockaddr_in addr;
+    memset(&addr, 0, sizeof(addr));
+    addr.sin_family = AF_INET;
+    addr.sin_port = htons(destinationPort);
+    addr.sin_addr.s_addr = destinationAddress;
+
+    struct msghdr header;
+    memset(&header, 0, sizeof(header));
+    struct iovec iov;
+    // The struct member is non-const since it's used for receiving but it's
+    // safe to cast away const for sending.
+    iov.iov_base = const_cast<uint8_t*>(message.data());
+    iov.iov_len = message.size();
+    header.msg_name = &addr;
+    header.msg_namelen = sizeof(addr);
+    header.msg_iov = &iov;
+    header.msg_iovlen = 1;
+    header.msg_control = &controlData;
+    header.msg_controllen = sizeof(controlData);
+
+    struct cmsghdr* controlHeader = CMSG_FIRSTHDR(&header);
+    controlHeader->cmsg_level = IPPROTO_IP;
+    controlHeader->cmsg_type = IP_PKTINFO;
+    controlHeader->cmsg_len = CMSG_LEN(sizeof(struct in_pktinfo));
+    auto packetInfo = reinterpret_cast<struct in_pktinfo*>(CMSG_DATA(controlHeader));
+    memset(packetInfo, 0, sizeof(*packetInfo));
+    packetInfo->ipi_ifindex = interfaceIndex;
+
+    ssize_t status = ::sendmsg(mSocketFd, &header, 0);
+    if (status <= 0) {
+        return Result::error("Failed to send packet: %s", strerror(errno));
+    }
+    return Result::success();
+}
+
+Result Socket::sendRawUdp(in_addr_t source, uint16_t sourcePort, in_addr_t destination,
+                          uint16_t destinationPort, unsigned int interfaceIndex,
+                          const Message& message) {
+    struct iphdr ip;
+    struct udphdr udp;
+
+    ip.version = IPVERSION;
+    ip.ihl = sizeof(ip) >> 2;
+    ip.tos = 0;
+    ip.tot_len = htons(sizeof(ip) + sizeof(udp) + message.size());
+    ip.id = 0;
+    ip.frag_off = 0;
+    ip.ttl = IPDEFTTL;
+    ip.protocol = IPPROTO_UDP;
+    ip.check = 0;
+    ip.saddr = source;
+    ip.daddr = destination;
+    ip.check = finishChecksum(addChecksum(ip, 0));
+
+    udp.source = htons(sourcePort);
+    udp.dest = htons(destinationPort);
+    udp.len = htons(sizeof(udp) + message.size());
+    udp.check = 0;
+
+    uint32_t udpChecksum = 0;
+    udpChecksum = addChecksum(ip.saddr, udpChecksum);
+    udpChecksum = addChecksum(ip.daddr, udpChecksum);
+    udpChecksum = addChecksum(htons(IPPROTO_UDP), udpChecksum);
+    udpChecksum = addChecksum(udp.len, udpChecksum);
+    udpChecksum = addChecksum(udp, udpChecksum);
+    udpChecksum = addChecksum(message.data(), message.size(), udpChecksum);
+    udp.check = finishChecksum(udpChecksum);
+
+    struct iovec iov[3];
+
+    iov[0].iov_base = static_cast<void*>(&ip);
+    iov[0].iov_len = sizeof(ip);
+    iov[1].iov_base = static_cast<void*>(&udp);
+    iov[1].iov_len = sizeof(udp);
+    // sendmsg requires these to be non-const but for sending won't modify them
+    iov[2].iov_base = static_cast<void*>(const_cast<uint8_t*>(message.data()));
+    iov[2].iov_len = message.size();
+
+    struct sockaddr_ll dest;
+    memset(&dest, 0, sizeof(dest));
+    dest.sll_family = AF_PACKET;
+    dest.sll_protocol = htons(ETH_P_IP);
+    dest.sll_ifindex = interfaceIndex;
+    dest.sll_halen = ETH_ALEN;
+    memset(dest.sll_addr, 0xFF, ETH_ALEN);
+
+    struct msghdr header;
+    memset(&header, 0, sizeof(header));
+    header.msg_name = &dest;
+    header.msg_namelen = sizeof(dest);
+    header.msg_iov = iov;
+    header.msg_iovlen = sizeof(iov) / sizeof(iov[0]);
+
+    ssize_t res = ::sendmsg(mSocketFd, &header, 0);
+    if (res == -1) {
+        return Result::error("Failed to send message: %s", strerror(errno));
+    }
+    return Result::success();
+}
+
+Result Socket::receiveFromInterface(Message* message, unsigned int* interfaceIndex) {
+    char controlData[CMSG_SPACE(sizeof(struct in_pktinfo))];
+    struct msghdr header;
+    memset(&header, 0, sizeof(header));
+    struct iovec iov;
+    iov.iov_base = message->data();
+    iov.iov_len = message->capacity();
+    header.msg_iov = &iov;
+    header.msg_iovlen = 1;
+    header.msg_control = &controlData;
+    header.msg_controllen = sizeof(controlData);
+
+    ssize_t bytesRead = ::recvmsg(mSocketFd, &header, 0);
+    if (bytesRead < 0) {
+        return Result::error("Error receiving on socket: %s", strerror(errno));
+    }
+    message->setSize(static_cast<size_t>(bytesRead));
+    if (header.msg_controllen >= sizeof(struct cmsghdr)) {
+        for (struct cmsghdr* ctrl = CMSG_FIRSTHDR(&header); ctrl;
+             ctrl = CMSG_NXTHDR(&header, ctrl)) {
+            if (ctrl->cmsg_level == SOL_IP && ctrl->cmsg_type == IP_PKTINFO) {
+                auto packetInfo = reinterpret_cast<struct in_pktinfo*>(CMSG_DATA(ctrl));
+                *interfaceIndex = packetInfo->ipi_ifindex;
+            }
+        }
+    }
+    return Result::success();
+}
+
+Result Socket::receiveRawUdp(uint16_t expectedPort, Message* message, bool* isValid) {
+    struct iphdr ip;
+    struct udphdr udp;
+
+    struct iovec iov[3];
+    iov[0].iov_base = &ip;
+    iov[0].iov_len = sizeof(ip);
+    iov[1].iov_base = &udp;
+    iov[1].iov_len = sizeof(udp);
+    iov[2].iov_base = message->data();
+    iov[2].iov_len = message->capacity();
+
+    ssize_t bytesRead = ::readv(mSocketFd, iov, 3);
+    if (bytesRead < 0) {
+        return Result::error("Unable to read from socket: %s", strerror(errno));
+    }
+    if (static_cast<size_t>(bytesRead) < sizeof(ip) + sizeof(udp)) {
+        // Not enough bytes to even cover IP and UDP headers
+        *isValid = false;
+        return Result::success();
+    }
+    *isValid = ip.version == IPVERSION && ip.ihl == (sizeof(ip) >> 2) &&
+               ip.protocol == IPPROTO_UDP && udp.dest == htons(expectedPort);
+
+    message->setSize(bytesRead - sizeof(ip) - sizeof(udp));
+    return Result::success();
+}
+
+Result Socket::enableOption(int level, int optionName) {
+    if (mSocketFd == -1) {
+        return Result::error("Socket not open");
+    }
+
+    int enabled = 1;
+    int status = ::setsockopt(mSocketFd, level, optionName, &enabled, sizeof(enabled));
+    if (status == -1) {
+        return Result::error("Failed to set socket option: %s", strerror(errno));
+    }
+    return Result::success();
+}
diff --git a/dhcp/common/utils.cpp b/dhcp/common/utils.cpp
new file mode 100644
index 0000000..e94e423
--- /dev/null
+++ b/dhcp/common/utils.cpp
@@ -0,0 +1,25 @@
+/*
+ * Copyright 2017, The Android Open Source Project
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
+#include "utils.h"
+
+std::string addrToStr(in_addr_t address) {
+    char buffer[INET_ADDRSTRLEN];
+    if (::inet_ntop(AF_INET, &address, buffer, sizeof(buffer)) == nullptr) {
+        return "[unknown]";
+    }
+    return buffer;
+}
diff --git a/fstab.trusty b/fstab.trusty
index 10b849f..f04388b 100644
--- a/fstab.trusty
+++ b/fstab.trusty
@@ -1,8 +1,9 @@
 # Android fstab file.
-#<src>                                                  <mnt_point>         <type>    <mnt_flags and options>                              <fs_mgr_flags>
 # The filesystem that contains the filesystem checker binary (typically /system) cannot
 # specify MF_CHECK, and must come before any filesystems that do specify MF_CHECK
-/dev/block/vda        /system     ext4    ro,barrier=1        wait,first_stage_mount
-/dev/block/vdb        /vendor     ext4    ro,barrier=1        wait,first_stage_mount
-/dev/block/vdc        /data       ext4    noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check
-/devices/*/block/vde  auto        auto    defaults            voldmanaged=sdcard:auto,encryptable=userdata
+#<src>                 <mnt_point>   <type>  <mnt_flags and options>       <fs_mgr_flags>
+/dev/block/vda        /system        ext4    ro,barrier=1                  wait,first_stage_mount
+/dev/block/vdb        /vendor        ext4    ro,barrier=1                  wait,first_stage_mount
+/dev/block/vdc        /data          ext4    noatime,nosuid,nodev,nomblk_io_submit,errors=panic   wait,check
+/dev/block/vdd        /metadata      ext4    noatime,nosuid,nodev,sync     wait,check,formattable,first_stage_mount
+/devices/*/block/vde  auto           auto    defaults                      voldmanaged=sdcard:auto,encryptable=userdata
diff --git a/init.qemu_trusty.rc b/init.qemu_trusty.rc
index e22482c..c071db0 100644
--- a/init.qemu_trusty.rc
+++ b/init.qemu_trusty.rc
@@ -4,16 +4,45 @@ on fs
 on early-init
     mount debugfs debugfs /sys/kernel/debug mode=755
 
+# legacy cpp implementation - to be deprecated
+on post-fs && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
+com.android.hardware.keymint.trusty_tee.cpp
+    enable vendor.keymint-service.trusty_tee.cpp
+
+# rust implementation
+on post-fs && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
+com.android.hardware.keymint.trusty_tee
+    enable vendor.keymint-service.trusty_tee
+
+on early-init && property:ro.boot.vendor.apex.com.android.hardware.keymint=\
+com.android.hardware.keymint.trusty_system_vm
+    # Enable the Trusty Security VM
+    setprop trusty.security_vm.enabled 1
+    # Enable KeyMint that connects to the Trusty Security VM
+    setprop trusty.security_vm.keymint.enabled 1
+
+on post-fs
+    # Ensure rpmb_virt_device is ready and start storageproxyd
+    # (on-post-fs at the latest because vold
+    # needs secure storage for rollback protection
+    # of the data partition encryption key
+    wait /dev/vport4p1
+
 on post-fs-data
-# The storage proxy is a vendor binary, and so cannot access /data/ss
-    mkdir /data/vendor/ss 700 system system
-    mkdir /data/vendor/ss/persist 0770 system system
-    enable storageproxyd
+    mkdir /data/vendor/ss 0770 root system
+    mkdir /mnt/vendor/persist/ss 0770 root system
+    restorecon_recursive /mnt/vendor/persist/ss
+    symlink /mnt/vendor/persist/ss /data/vendor/ss/persist
+    chown root system /data/vendor/ss/persist
+    chmod 0770 /data/vendor/ss/persist
+    write /dev/kmsg "boot_kpi: K - restart storageproxyd"
+    restart storageproxyd
 
 on boot
+    write /dev/kmsg "boot_kpi: K - init.rc 'on boot'"
     chown root system /sys/power/wake_lock
     chown root system /sys/power/wake_unlock
-    setprop ro.radio.use-ppp no
+setprop ro.radio.use-ppp no
     setprop ro.build.product generic
     setprop ro.product.device generic
     setprop ro.hardware.audio.primary goldfish
@@ -108,8 +137,10 @@ service bugreport /system/bin/dumpstate -d -p
     oneshot
     keycodes 114 115 116
 
+# start storageproxyd when rpmb virtual port is ready
 service storageproxyd /vendor/bin/storageproxyd -d /dev/trusty-ipc-dev0 \
-        -r /dev/vport3p1 -p /data/vendor/ss -t virt
-    class main
-    disabled
+        -r /dev/vport4p1 -p /data/vendor/ss -t virt
+    class early_hal
     user system
+    group system
+    task_profiles MaxPerformance
diff --git a/manifest.xml b/manifest.xml
index d5e9f78..f3ba945 100644
--- a/manifest.xml
+++ b/manifest.xml
@@ -1,3 +1,3 @@
-<manifest version="1.0" type="device" target-level="5">
+<manifest version="1.0" type="device" target-level="202504">
   <!-- DO NOT ADD HALS HERE - use vintf_fragments -->
 </manifest>
diff --git a/microdroid/Android.bp b/microdroid/Android.bp
new file mode 100644
index 0000000..4162070
--- /dev/null
+++ b/microdroid/Android.bp
@@ -0,0 +1,50 @@
+package {
+    default_applicable_licenses: ["device_generic_trusty_license"],
+}
+
+prebuilt_etc {
+    name: "microdroid_vendor_trusty_init_rc",
+    filename: "init.trusty_modules.rc",
+    src: "init.trusty_modules.rc",
+    relative_install_path: "init",
+    no_full_install: true, // avoid collision with system partition's init.rc
+}
+
+prebuilt_etc {
+    name: "microdroid_vendor_trusty_ueventd_rc",
+    filename: "ueventd.rc",
+    src: "ueventd.rc",
+    no_full_install: true, // avoid collision with system partition's ueventd.rc
+}
+
+android_filesystem {
+    name: "microdroid_vendor_trusty_image",
+    partition_name: "microdroid-vendor",
+    type: "ext4",
+    file_contexts: "file_contexts",
+    use_avb: true,
+    avb_private_key: ":avb_testkey_rsa4096",
+    mount_point: "vendor",
+    deps: [
+        "microdroid_vendor_trusty_init_rc",
+        "microdroid_vendor_trusty_modules-android16-6.12-arm64",
+        "microdroid_vendor_trusty_ueventd_rc",
+        "trusty-ut-ctrl",
+    ],
+
+    product_variables: {
+        debuggable: {
+            deps: [
+                "tipc-test",
+            ],
+        },
+    },
+}
+
+prebuilt_etc {
+    name: "microdroid_vendor_trusty",
+    src: ":microdroid_vendor_trusty_image",
+    relative_install_path: "avf/microdroid",
+    filename: "microdroid_vendor.img",
+    vendor: true,
+}
diff --git a/microdroid/file_contexts b/microdroid/file_contexts
new file mode 100644
index 0000000..42504b8
--- /dev/null
+++ b/microdroid/file_contexts
@@ -0,0 +1,3 @@
+/vendor(/.*)?                 u:object_r:vendor_file:s0
+/vendor/etc(/.*)?             u:object_r:vendor_configs_file:s0
+/vendor/lib/modules(/.*)?     u:object_r:vendor_kernel_modules:s0
diff --git a/microdroid/init.trusty_modules.rc b/microdroid/init.trusty_modules.rc
new file mode 100644
index 0000000..1697b31
--- /dev/null
+++ b/microdroid/init.trusty_modules.rc
@@ -0,0 +1,35 @@
+# Copyright (C) 2025 The Android Open-Source Project
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
+on post-fs
+    insmod /vendor/lib/modules/6.12/ffa-core.ko
+    insmod /vendor/lib/modules/6.12/ffa-module.ko
+    insmod /vendor/lib/modules/6.12/trusty-core.ko
+    insmod /vendor/lib/modules/6.12/trusty-ffa.ko
+    insmod /vendor/lib/modules/6.12/trusty-ipc.ko
+    insmod /vendor/lib/modules/6.12/trusty-virtio-polling.ko default_vq_check_period_ms=500
+    insmod /vendor/lib/modules/6.12/trusty-populate.ko
+    insmod /vendor/lib/modules/6.12/system_heap.ko
+
+on post-fs-data
+    # /data is mounted noexec on microdroid
+    mkdir /data/nativetest64 0771 shell shell
+    mount tmpfs tmpfs /data/nativetest64 noatime nosuid nodev rw size=1M
+    restorecon /data/nativetest64
+
+    # tipc-test is not executable on the vendor image
+    mkdir /data/nativetest64/vendor 0771 shell shell
+    mkdir /data/nativetest64/vendor/tipc-test 0771 shell shell
+    copy /vendor/nativetest64/vendor/tipc-test/tipc-test /data/nativetest64/vendor/tipc-test/tipc-test
+    chmod 755 /data/nativetest64/vendor/tipc-test/tipc-test
diff --git a/microdroid/ueventd.rc b/microdroid/ueventd.rc
new file mode 100644
index 0000000..757c116
--- /dev/null
+++ b/microdroid/ueventd.rc
@@ -0,0 +1 @@
+/dev/trusty-ipc-dev0      0660   system     drmrpc
diff --git a/pvmfw/Android.bp b/pvmfw/Android.bp
new file mode 100644
index 0000000..ddcbbdb
--- /dev/null
+++ b/pvmfw/Android.bp
@@ -0,0 +1,37 @@
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+// Common defaults for pvmfw image generation.
+cc_genrule {
+    name: "pvmfw_test_img.gen",
+    tools: ["pvmfw-tool"],
+    enabled: false,
+    arch: {
+        arm64: {
+            srcs: [
+                ":pvmfw_bin",
+                ":test_avf_bcc_dat",
+            ],
+            enabled: true,
+        },
+    },
+    out: [
+        "pvmfw_test_img.img",
+    ],
+    cmd: "FILES=($(in)) && $(location pvmfw-tool) $(out) $${FILES[0]} $${FILES[1]}",
+}
+
+prebuilt_etc {
+    name: "pvmfw_test_img.img",
+    filename: "pvmfw_test_img.img",
+    relative_install_path: "pvmfw",
+    vendor: true,
+    target: {
+        android_arm64: {
+            src: ":pvmfw_test_img.gen",
+        },
+    },
+    src: ":empty_file",
+    installable: true,
+}
diff --git a/qemu_trusty_arm64.mk b/qemu_trusty_arm64.mk
index a643328..958311c 100644
--- a/qemu_trusty_arm64.mk
+++ b/qemu_trusty_arm64.mk
@@ -15,6 +15,12 @@
 $(call inherit-product, $(SRC_TARGET_DIR)/product/core_64_bit.mk)
 $(call inherit-product, $(LOCAL_PATH)/qemu_trusty_base.mk)
 
+# AVF
+$(call inherit-product, packages/modules/Virtualization/apex/product_packages.mk)
+
+# PVMFW support
+PRODUCT_BUILD_PVMFW_IMAGE := true
+
 PRODUCT_NAME := qemu_trusty_arm64
 PRODUCT_DEVICE := trusty
 PRODUCT_BRAND := Android
diff --git a/qemu_trusty_base.mk b/qemu_trusty_base.mk
index 52a0f5a..4c2a748 100644
--- a/qemu_trusty_base.mk
+++ b/qemu_trusty_base.mk
@@ -23,16 +23,25 @@ $(call inherit-product, $(SRC_TARGET_DIR)/product/updatable_apex.mk)
 
 $(call inherit-product, packages/modules/Virtualization/apex/product_packages.mk)
 
-PRODUCT_SOONG_NAMESPACES += device/generic/goldfish
+PRODUCT_SOONG_NAMESPACES += \
+	device/generic/goldfish \
+	device/generic/trusty \
 
+# select minimal set of services from build/make/target/product/base_system.mk
 PRODUCT_PACKAGES += \
+    aconfigd-system \
+    adbd_system_api \
+    aflags \
     com.android.adbd \
     com.android.virt \
     adbd_system_api \
     android.hardware.confirmationui@1.0-service.trusty \
+    android.hardware.trusty.hwcryptohal-service \
     android.hidl.allocator@1.0-service \
     android.system.suspend-service \
     apexd \
+    atrace \
+    awk \
     cgroups.json \
     com.android.art \
     com.android.i18n \
@@ -60,18 +69,25 @@ PRODUCT_PACKAGES += \
     logwrapper \
     mediaserver \
     mdnsd \
+    microdroid_vendor_trusty \
     odsign \
+    perfetto \
+    perfetto-extras \
     reboot \
     securedpud \
     servicemanager \
     sh \
     su \
+    strace \
     system-build.prop \
     toolbox \
     toybox \
+    traced \
+    traced_probes \
     vdc \
     vndservicemanager \
     vold \
+    sanitizer.libraries.txt \
 
 # VINTF stuff for system and vendor (no product / odm / system_ext / etc.)
 PRODUCT_PACKAGES += \
@@ -79,6 +95,17 @@ PRODUCT_PACKAGES += \
     system_manifest.xml \
     vendor_compatibility_matrix.xml \
     vendor_manifest.xml \
+    android.hardware.security.see.storage-service.trusty.xml \
+    android.hardware.security.see.authmgr.xml \
+
+PRODUCT_USE_DYNAMIC_PARTITIONS := true
+TARGET_COPY_OUT_SYSTEM_EXT := system/system_ext
+BOARD_SYSTEM_EXTIMAGE_FILE_SYSTEM_TYPE :=
+SYSTEM_EXT_PRIVATE_SEPOLICY_DIRS += device/generic/trusty/sepolicy/system_ext/private
+
+# Creates metadata partition mount point under root for
+# the devices with metadata partition
+BOARD_USES_METADATA_PARTITION := true
 
 # Devices that inherit from build/make/target/product/base.mk always have
 # /system/system_ext/etc/vintf/manifest.xml generated. And build-time VINTF
@@ -112,6 +139,9 @@ PRODUCT_PACKAGES += init.usb.rc init.usb.configfs.rc
 
 PRODUCT_FULL_TREBLE_OVERRIDE := true
 
+PRODUCT_AVF_MICRODROID_GUEST_GKI_VERSION := android16_612
+MICRODROID_VENDOR_IMAGE_MODULE := microdroid_vendor_trusty
+
 PRODUCT_COPY_FILES += \
     device/generic/trusty/fstab.trusty:$(TARGET_COPY_OUT_RAMDISK)/fstab.qemu_trusty \
     device/generic/trusty/fstab.trusty:$(TARGET_COPY_OUT_VENDOR)/etc/fstab.qemu_trusty \
@@ -123,10 +153,48 @@ PRODUCT_COPY_FILES += \
     device/generic/goldfish/data/etc/config.ini:config.ini \
     device/generic/trusty/advancedFeatures.ini:advancedFeatures.ini \
 
-# for Trusty
+# Set Vendor SPL to match platform
+# needed for properly provisioning keymint (HAL info)
+VENDOR_SECURITY_PATCH = $(PLATFORM_SECURITY_PATCH)
+
+##########################
+# Trusty VM/TEE products #
+##########################
+
+# TODO(b/393850980): enable TRUSTY_SYSTEM_VM_USE_PVMFW when
+# necessary dependencied are available on QEMU (e.g. ARM TRNG supported in TF-A)
+TRUSTY_SYSTEM_VM_USE_PVMFW := false
+ifeq ($(TRUSTY_SYSTEM_VM_USE_PVMFW),true)
+PRODUCT_PACKAGES += \
+      pvmfw_test_img.img \
+
+PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
+    hypervisor.pvmfw.path=/vendor/etc/pvmfw/pvmfw_test_img.img \
+
+else
+PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
+    hypervisor.pvmfw.path=none \
+
+endif
+
+KEYMINT_HAL_VENDOR_APEX_SELECT ?= true
+TRUSTY_KEYMINT_IMPL ?= rust
+# TODO(b/390206831): remove placeholder_trusted_hal when VM2TZ is supported
+TRUSTY_SYSTEM_VM ?= enabled_with_placeholder_trusted_hal
+ifeq ($(TRUSTY_SYSTEM_VM), enabled_with_placeholder_trusted_hal)
+    $(call soong_config_set_bool, trusty_system_vm, placeholder_trusted_hal, true)
+endif
+$(call soong_config_set_bool, trusty_system_vm, enabled, true)
+$(call soong_config_set, trusty_system_vm, buildtype, $(TARGET_BUILD_VARIANT))
+$(call soong_config_set_bool, trusty_tee, enabled, true)
+
+$(call inherit-product, packages/modules/Virtualization/guest/trusty/security_vm/security_vm.mk)
+
+$(call inherit-product, device/generic/trusty/apex/com.android.hardware.keymint/trusty-apex.mk)
 $(call inherit-product, system/core/trusty/trusty-base.mk)
 $(call inherit-product, system/core/trusty/trusty-storage.mk)
 $(call inherit-product, system/core/trusty/trusty-test.mk)
+$(call inherit-product-if-exists, trusty/vendor/google/proprietary/device/device.mk)
 
 # Test Utilities
 PRODUCT_PACKAGES += \
@@ -144,4 +212,5 @@ PRODUCT_PACKAGES += \
     VtsHalRemotelyProvisionedComponentTargetTest \
 
 PRODUCT_SYSTEM_DEFAULT_PROPERTIES += \
-    ro.adb.secure=0
\ No newline at end of file
+    ro.adb.secure=0 \
+    ro.boot.vendor.apex.com.android.hardware.keymint=com.android.hardware.keymint.trusty_tee \
diff --git a/sepolicy/attributes.te b/sepolicy/attributes.te
new file mode 100644
index 0000000..7e6def7
--- /dev/null
+++ b/sepolicy/attributes.te
@@ -0,0 +1 @@
+attribute vendor_persist_type;
diff --git a/sepolicy/dhcpclient.te b/sepolicy/dhcpclient.te
index f843bee..b28bb51 100644
--- a/sepolicy/dhcpclient.te
+++ b/sepolicy/dhcpclient.te
@@ -5,8 +5,9 @@ type dhcpclient_exec, exec_type, vendor_file_type, file_type;
 init_daemon_domain(dhcpclient)
 net_domain(dhcpclient)
 
-dontaudit dhcpclient kernel:system module_request;
-allow dhcpclient self:capability { net_admin net_raw };
+set_prop(dhcpclient, vendor_net_wlan0_prop);
+set_prop(dhcpclient, vendor_net_eth0_prop);
+allow dhcpclient self:capability { net_admin net_raw sys_module };
 allow dhcpclient self:netlink_route_socket { ioctl write nlmsg_write };
 allow dhcpclient varrun_file:dir search;
 allow dhcpclient self:packet_socket { create bind write read };
diff --git a/sepolicy/file.te b/sepolicy/file.te
index b3bd582..56cd574 100644
--- a/sepolicy/file.te
+++ b/sepolicy/file.te
@@ -1 +1,2 @@
-type varrun_file, file_type, data_file_type, mlstrustedobject;
+typeattribute mnt_vendor_file vendor_persist_type;
+type persist_file, file_type, vendor_persist_type;
diff --git a/sepolicy/file_contexts b/sepolicy/file_contexts
index 09b10d0..a81cf25 100644
--- a/sepolicy/file_contexts
+++ b/sepolicy/file_contexts
@@ -1,16 +1,20 @@
+/dev/block/vdd[0-9]*                 u:object_r:metadata_block_device:s0
 /dev/trusty-ipc-dev0                 u:object_r:tee_device:s0
 /dev/trusty-log0                     u:object_r:logbuffer_device:s0
-/dev/vport3p1                        u:object_r:rpmb_virt_device:s0
-/dev/vport3p2                        u:object_r:spi_virt_device:s0
-/vendor/bin/dhcpclient               u:object_r:dhcpclient_exec:s0
+/dev/vport4p1                        u:object_r:rpmb_virt_device:s0
+/dev/vport4p2                        u:object_r:spi_virt_device:s0
 /vendor/bin/securedpud               u:object_r:securedpud_exec:s0
 /vendor/bin/spiproxyd                u:object_r:tee_exec:s0
 /vendor/bin/storageproxyd            u:object_r:tee_exec:s0
-/data/vendor/var/run(/.*)?           u:object_r:varrun_file:s0
 /data/vendor/ss(/.*)?                u:object_r:tee_data_file:s0
-/vendor/bin/hw/android.hardware.confirmationui-service.trusty       u:object_r:hal_confirmationui_default_exec:s0
+/mnt/vendor/persist/ss(/.*)?         u:object_r:persist_ss_file:s0
+
+/vendor/bin/dhcpclient                                                  u:object_r:dhcpclient_exec:s0
+/vendor/bin/hw/android.hardware.confirmationui-service.trusty           u:object_r:hal_confirmationui_default_exec:s0
 /vendor/bin/hw/android.hardware.gatekeeper@1.0-service.trusty           u:object_r:hal_gatekeeper_default_exec:s0
 /vendor/bin/hw/android.hardware.gatekeeper-service.trusty               u:object_r:hal_gatekeeper_default_exec:s0
 /vendor/bin/hw/android.hardware.keymaster@4.0-service.trusty            u:object_r:hal_keymaster_default_exec:s0
 /vendor/bin/hw/android.hardware.security.keymint-service.trusty         u:object_r:hal_keymint_default_exec:s0
 /vendor/bin/hw/android.hardware.security.keymint-service.rust.trusty    u:object_r:hal_keymint_default_exec:s0
+/vendor/bin/hw/android.hardware.security.keymint-service.trusty_tee.cpp u:object_r:hal_keymint_default_exec:s0
+/vendor/bin/hw/android.hardware.security.keymint-service.trusty_tee     u:object_r:hal_keymint_default_exec:s0
diff --git a/sepolicy/property.te b/sepolicy/property.te
new file mode 100644
index 0000000..2a979fb
--- /dev/null
+++ b/sepolicy/property.te
@@ -0,0 +1,5 @@
+# Trusty storage FS ready
+vendor_internal_prop(vendor_trusty_storage_prop)
+
+# This prop will be set to "mounted" after /mnt/vendor/persist mounts
+vendor_internal_prop(vendor_persist_prop)
diff --git a/sepolicy/property_contexts b/sepolicy/property_contexts
new file mode 100644
index 0000000..de218cc
--- /dev/null
+++ b/sepolicy/property_contexts
@@ -0,0 +1,5 @@
+# Trusty
+ro.vendor.trusty.storage.fs_ready          u:object_r:vendor_trusty_storage_prop:s0
+
+# For checking if persist partition is mounted
+ro.vendor.persist.status u:object_r:vendor_persist_prop:s0 exact string
diff --git a/sepolicy/storageproxyd.te b/sepolicy/storageproxyd.te
index 63a1d6b..0d5acd5 100644
--- a/sepolicy/storageproxyd.te
+++ b/sepolicy/storageproxyd.te
@@ -1,8 +1,31 @@
+# virtual port device (qemu)
 type rpmb_virt_device, dev_type;
 
 allow tee rpmb_virt_device:chr_file { open read write };
 
-allow tee tee_data_file:dir rw_dir_perms;
+type persist_ss_file, file_type, vendor_persist_type;
+
+allow tee persist_ss_file:file create_file_perms;
+allow tee persist_ss_file:dir create_dir_perms;
+allow tee persist_file:dir r_dir_perms;
+allow tee mnt_vendor_file:dir r_dir_perms;
+allow tee tee_data_file:dir create_dir_perms;
+allow tee tee_data_file:lnk_file r_file_perms;
+
+# Handle wake locks
+wakelock_use(tee)
+
+binder_use(tee)
+allow tee fwk_vold_service:service_manager find;
+binder_call(tee, vold)
+binder_call(vold, tee)
 
 # Allow storageproxyd access to gsi_public_metadata_file
 read_fstab(tee)
+
+# storageproxyd starts before /data is mounted. It handles /data not being there
+# gracefully. However, attempts to access /data trigger a denial.
+dontaudit tee unlabeled:dir { search };
+
+set_prop(tee, vendor_trusty_storage_prop)
+
diff --git a/sepolicy/system_ext/private/file_contexts b/sepolicy/system_ext/private/file_contexts
new file mode 100644
index 0000000..1c022a8
--- /dev/null
+++ b/sepolicy/system_ext/private/file_contexts
@@ -0,0 +1,32 @@
+
+#############################
+# services
+/(system_ext|system/system_ext)/bin/hw/android\.hardware\.security\.keymint-service\.trusty_system_vm  u:object_r:hal_keymint_system_exec:s0
+/(system_ext|system/system_ext)/bin/trusty_security_vm_launcher u:object_r:trusty_security_vm_launcher_exec:s0
+/(system_ext|system/system_ext)/bin/trusty_security_vm_launcher_protected u:object_r:trusty_security_vm_launcher_exec:s0
+/(system_ext|system/system_ext)/bin/rpmb_dev\.system   u:object_r:rpmb_dev_system_exec:s0
+/(system_ext|system/system_ext)/bin/rpmb_dev\.test\.system   u:object_r:rpmb_dev_system_exec:s0
+/(system_ext|system/system_ext)/bin/rpmb_dev\.wv\.system   u:object_r:rpmb_dev_system_exec:s0
+/(system_ext|system/system_ext)/bin/storageproxyd\.system     u:object_r:storageproxyd_system_exec:s0
+
+#############################
+# sockets
+/dev/socket/rpmb_mock_system  u:object_r:rpmb_dev_system_socket:s0
+/dev/socket/rpmb_mock_test_system  u:object_r:rpmb_dev_system_socket:s0
+/dev/socket/rpmb_mock_wv_system  u:object_r:rpmb_dev_system_socket:s0
+
+#############################
+# persist files
+/mnt/secure_storage_rpmb_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+
+/mnt/secure_storage_rpmb_test_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_test_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+/mnt/secure_storage_rpmb_wv_system(/.*)?  u:object_r:secure_storage_rpmb_system_file:s0
+/mnt/secure_storage_persist_wv_system(/.*)?  u:object_r:secure_storage_persist_system_file:s0
+
+#############################
+# data files
+/data/secure_storage_system(/.*)?        u:object_r:secure_storage_system_file:s0
+/data/secure_storage_test_system(/.*)?        u:object_r:secure_storage_system_file:s0
+/data/secure_storage_wv_system(/.*)?        u:object_r:secure_storage_system_file:s0
diff --git a/sepolicy/system_ext/private/hal_keymint_system.te b/sepolicy/system_ext/private/hal_keymint_system.te
new file mode 100644
index 0000000..42bf85f
--- /dev/null
+++ b/sepolicy/system_ext/private/hal_keymint_system.te
@@ -0,0 +1,5 @@
+# Read device's serial number from system properties
+get_prop(hal_keymint_system, serialno_prop)
+
+# Read the OS patch level from system properties
+get_prop(hal_keymint_system, vendor_security_patch_level_prop)
diff --git a/sepolicy/system_ext/private/secure_storage_system.te b/sepolicy/system_ext/private/secure_storage_system.te
new file mode 100644
index 0000000..3c45d56
--- /dev/null
+++ b/sepolicy/system_ext/private/secure_storage_system.te
@@ -0,0 +1,33 @@
+#============= rpmb_dev_system ==============
+type rpmb_dev_system, domain, coredomain;
+type rpmb_dev_system_exec, exec_type, system_file_type, file_type;
+type secure_storage_rpmb_system_file, file_type, data_file_type, core_data_file_type;
+type rpmb_dev_system_socket, file_type, data_file_type, core_data_file_type;
+init_daemon_domain(rpmb_dev_system)
+allow rpmb_dev_system metadata_file:dir { search add_name write };
+allow rpmb_dev_system metadata_file:file { create open read write };
+allow rpmb_dev_system tmpfs:lnk_file read;
+allow rpmb_dev_system secure_storage_rpmb_system_file:dir rw_dir_perms;
+allow rpmb_dev_system secure_storage_rpmb_system_file:{file sock_file} create_file_perms;
+allow rpmb_dev_system secure_storage_rpmb_system_file:lnk_file read;
+allow rpmb_dev_system rpmb_dev_system_socket:sock_file rw_file_perms;
+
+#============= storageproxyd_system ==============
+type storageproxyd_system, domain, coredomain;
+typeattribute storageproxyd_system unconstrained_vsock_violators;
+type storageproxyd_system_exec, exec_type, system_file_type, file_type;
+type secure_storage_persist_system_file, file_type, data_file_type, core_data_file_type;
+type secure_storage_system_file, file_type, data_file_type, core_data_file_type;
+
+init_daemon_domain(storageproxyd_system)
+allow storageproxyd_system metadata_file:dir search;
+allow storageproxyd_system secure_storage_persist_system_file:dir rw_dir_perms;
+allow storageproxyd_system secure_storage_persist_system_file:file { create open read write };
+allow storageproxyd_system secure_storage_system_file:dir rw_dir_perms;
+allow storageproxyd_system secure_storage_system_file:file { create open read write getattr };
+allow storageproxyd_system self:vsock_socket { create_socket_perms_no_ioctl };
+
+unix_socket_connect(storageproxyd_system, rpmb_dev_system, rpmb_dev_system)
+
+# Allow storageproxyd_system access to gsi_public_metadata_file
+read_fstab(storageproxyd_system)
diff --git a/sepolicy/system_ext/private/trusty_security_vm_launcher.te b/sepolicy/system_ext/private/trusty_security_vm_launcher.te
new file mode 100644
index 0000000..aded084
--- /dev/null
+++ b/sepolicy/system_ext/private/trusty_security_vm_launcher.te
@@ -0,0 +1,18 @@
+is_flag_enabled(RELEASE_AVF_ENABLE_EARLY_VM, `
+    type trusty_security_vm_launcher, domain, coredomain;
+    type trusty_security_vm_launcher_exec, system_file_type, exec_type, file_type;
+    type trusty_security_vm_launcher_tmpfs, file_type;
+
+    init_daemon_domain(trusty_security_vm_launcher)
+    domain_auto_trans(init, trusty_security_vm_launcher_exec, trusty_security_vm_launcher)
+
+    early_virtmgr_use(trusty_security_vm_launcher)
+    binder_use(trusty_security_vm_launcher)
+
+    allow trusty_security_vm_launcher kmsg_debug_device:chr_file rw_file_perms;
+    use_bootstrap_libs(trusty_security_vm_launcher)
+
+    allow trusty_security_vm_launcher self:global_capability_class_set { net_bind_service ipc_lock sys_resource };
+
+    tmpfs_domain(trusty_security_vm_launcher)
+')
diff --git a/sepolicy/ueventd.te b/sepolicy/ueventd.te
new file mode 100644
index 0000000..985c8ec
--- /dev/null
+++ b/sepolicy/ueventd.te
@@ -0,0 +1 @@
+allow ueventd metadata_file:dir search;
diff --git a/sepolicy/vendor_init.te b/sepolicy/vendor_init.te
new file mode 100644
index 0000000..bf805d9
--- /dev/null
+++ b/sepolicy/vendor_init.te
@@ -0,0 +1,4 @@
+# Allow vendor_init to read ro.vendor.persist.status
+# to process init.rc actions
+set_prop(vendor_init, vendor_persist_prop)
+allow vendor_init rpmb_virt_device:chr_file { open getattr };
diff --git a/ueventd.qemu_trusty.rc b/ueventd.qemu_trusty.rc
index 7e46bba..9f113e7 100644
--- a/ueventd.qemu_trusty.rc
+++ b/ueventd.qemu_trusty.rc
@@ -1,5 +1,5 @@
 /dev/ion                  0660   system     system
-/dev/vport3p1             0660   system     system
-/dev/vport3p2             0660   system     system
+/dev/vport4p1             0660   system     system
+/dev/vport4p2             0660   system     system
 /dev/trusty-ipc-dev0      0660   system     drmrpc
 /dev/trusty-log0          0660   system     system
```

