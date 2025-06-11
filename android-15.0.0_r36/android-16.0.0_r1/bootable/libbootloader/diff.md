```diff
diff --git a/gbl/BUILD b/gbl/BUILD
index 0848b74..283421a 100644
--- a/gbl/BUILD
+++ b/gbl/BUILD
@@ -14,6 +14,10 @@
 
 load(":readme.bzl", "readme_test")
 
+package(
+    default_visibility = ["//visibility:public"],
+)
+
 readme_test(
     name = "readme_test",
     readme = "docs/efi_protocols.md",
diff --git a/gbl/README.md b/gbl/README.md
index e0fe1d0..eaf0f6e 100644
--- a/gbl/README.md
+++ b/gbl/README.md
@@ -147,6 +147,8 @@ configurations:
 
    Set path to GBL binary here: [fuchsia/src/firmware/gigaboot/cpp/backends.gni : gigaboot_gbl_efi_app](https://cs.opensource.google/fuchsia/fuchsia/+/main:src/firmware/gigaboot/cpp/backends.gni;l=25?q=gigaboot_gbl_efi_app)
 
+   Temporarily  need to enable GBL usage in gigaboot: [fuchsia/src/firmware/gigaboot/cpp/backends.gni : gigaboot_use_gbl](https://cs.opensource.google/fuchsia/fuchsia/+/main:src/firmware/gigaboot/cpp/backends.gni;l=25?q=gigaboot_gbl_efi_app#:~:text=to%20use%20GBL.-,gigaboot_use_gbl)
+
    E.g. in `fuchsia/src/firmware/gigaboot/cpp/backends.gni`:
    ```
    $ cat ./fuchsia/src/firmware/gigaboot/cpp/backends.gni
@@ -154,12 +156,13 @@ configurations:
    declare_args() {
       ...
       gigaboot_gbl_efi_app = "<path to EFI image>/gbl_x86_64.efi"
+      gigaboot_use_gbl = true
    }
    ```
 
    Or in `fx set`:
    ```
-   fx set core.x64 --args=gigaboot_gbl_efi_app='"<path to EFI image>/gbl_x86_64.efi"'
+   fx set core.x64 --args=gigaboot_gbl_efi_app='"<path to EFI image>/gbl_x86_64.efi"' --args=gigaboot_use_gbl=true
    ```
 
 2. Build: (this has to be done every time if EFI app changes)
diff --git a/gbl/bazel.MODULE.bazel b/gbl/bazel.MODULE.bazel
index 114ddbc..c55a05b 100644
--- a/gbl/bazel.MODULE.bazel
+++ b/gbl/bazel.MODULE.bazel
@@ -24,6 +24,7 @@ module(
 )
 
 register_toolchains(
+    "//prebuilts/build-tools:py_exec_tools_toolchain",
     "//prebuilts/build-tools:py_toolchain",
 )
 
@@ -39,10 +40,8 @@ bazel_dep(
 bazel_dep(
     name = "rules_pkg",
 )
-
-local_path_override(
-    module_name = "apple_support",
-    path = "external/bazelbuild-apple_support",
+bazel_dep(
+    name = "rules_python",
 )
 
 local_path_override(
@@ -67,7 +66,12 @@ local_path_override(
 
 local_path_override(
     module_name = "rules_java",
-    path = "external/bazelbuild-rules_java",
+    path = "bootable/libbootloader/gbl/fake_modules/rules_java",
+)
+
+local_path_override(
+    module_name = "rules_kotlin",
+    path = "bootable/libbootloader/gbl/fake_modules/rules_kotlin",
 )
 
 local_path_override(
@@ -84,3 +88,13 @@ local_path_override(
     module_name = "rules_python",
     path = "external/bazelbuild-rules_python",
 )
+
+local_path_override(
+    module_name = "rules_shell",
+    path = "external/bazelbuild-rules_shell",
+)
+
+local_path_override(
+    module_name = "protobuf",
+    path = "bootable/libbootloader/gbl/fake_modules/protobuf",
+)
diff --git a/gbl/bazel.bazelrc b/gbl/bazel.bazelrc
index 39f898f..2fb3f2f 100644
--- a/gbl/bazel.bazelrc
+++ b/gbl/bazel.bazelrc
@@ -63,3 +63,7 @@ test:ants --build_metadata=generate_test_uri=fusion
 
 common:android_ci --noshow_progress
 test:android_ci --config=ants
+
+common --enable_workspace
+common --incompatible_autoload_externally=+@rules_python,-ProguardSpecProvider,-java_binary,-java_import,-java_library,-java_plugin,-java_test,-java_runtime,-java_toolchain,-java_package_configuration,-@com_google_protobuf,-@protobuf,+@rules_shell,-@rules_android
+common --noincompatible_disallow_empty_glob
diff --git a/gbl/bazel.py b/gbl/bazel.py
index a27f4be..ce63130 100644
--- a/gbl/bazel.py
+++ b/gbl/bazel.py
@@ -16,6 +16,7 @@ import argparse
 import os
 import pathlib
 import sys
+from datetime import date
 from typing import Tuple, Optional
 
 _BAZEL_REL_PATH = "prebuilts/kernel-build-tools/bazel/linux-x86_64/bazel"
@@ -78,6 +79,7 @@ class BazelWrapper(object):
         self._parse_startup_options()
         self._parse_command_args()
         self._add_extra_startup_options()
+        self._add_build_number_command_args()
 
     def add_startup_option_to_parser(self, parser):
         parser.add_argument(
@@ -144,6 +146,15 @@ class BazelWrapper(object):
         _, self.transformed_command_args = parser.parse_known_args(
             self.command_args)
 
+    def _add_build_number_command_args(self):
+        """Adds options for BUILD_NUMBER."""
+        build_number = os.environ.get("BUILD_NUMBER")
+        if build_number is None:
+            # Changing the commandline causes rebuild. In order to *not* cause
+            # superfluous rebuilds, append a low-precision timestamp.
+            build_number = f"eng.{os.environ.get('USER')}.{date.today()}"
+        self.transformed_command_args += ["--action_env", f"BUILD_NUMBER={build_number}"]
+
     def _add_extra_startup_options(self):
         """Adds extra startup options after command args are parsed."""
 
diff --git a/gbl/docs/GBL_EFI_IMAGE_LOADING_PROTOCOL.md b/gbl/docs/GBL_EFI_IMAGE_LOADING_PROTOCOL.md
new file mode 100644
index 0000000..cc3e42b
--- /dev/null
+++ b/gbl/docs/GBL_EFI_IMAGE_LOADING_PROTOCOL.md
@@ -0,0 +1,248 @@
+# GBL EFI Image Loading Protocol
+
+This document describes the GBL Image Loading protocol. This optional protocol
+defines interfaces that can be used by EFI applications to specify implement
+customised buffer location in memory. And additional images for verification.
+
+|||
+| :--- | :--- |
+| **Status** | Work in progress |
+| **Created** | 2024-12-11 |
+
+
+## GBL_EFI_IMAGE_LOADING_PROTOCOL
+
+### Summary
+
+This protocol allows firmware to provide platform reserved memory spaces to
+applications for a specific usage or feature, or alternatively, specify the
+amount of memory the application should allocate dynamically for it.
+
+It also provides interface to communicate additional images to be verified by
+GBL.
+
+### GUID
+
+```c
+// {db84b4fa-53bd-4436-98a7-4e0271428ba8}
+#define GBL_EFI_IMAGE_LOADING_PROTOCOL_GUID          \
+  {                                                  \
+    0xdb84b4fa, 0x53bd, 0x4436, {                    \
+      0x98, 0xa7, 0x4e, 0x02, 0x71, 0x42, 0x8b, 0xa8 \
+    }                                                \
+  }
+```
+
+### Revision Number
+
+```c
+#define GBL_EFI_IMAGE_PROTOCOL_PROTOCOL_REVISION 0x00010000
+```
+
+### Protocol Interface Structure
+
+```c
+typedef struct _GBL_EFI_IMAGE_LOADING_PROTOCOL {
+  UINT64                        Revision;
+  GBL_EFI_GET_IMAGE_BUFFER      GetBuffer;
+  GBL_EFI_GET_VERIFY_PARTITIONS GetVerifyPartitions;
+} GBL_EFI_IMAGE_LOADING_PROTOCOL;
+```
+
+### Parameters
+
+**Revision** \
+The revision to which the GBL_EFI_IMAGE_BUFFER_PROTOCOL adheres. All future
+revisions must be backwards compatible. If a future version is not backwards
+compatible, a different GUID must be used.
+
+**GetBuffer** \
+Query custom buffer for the image. See
+[`GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()`](#gbl_efi_image_loading_protocolgetbuffer).
+
+**GetVerifyPartitions** \
+Query for list of partitions to be verified by GBL. See
+[`GBL_EFI_IMAGE_LOADING_PROTOCOL.GetVerifyPartitions()`](#gbl_efi_image_loading_protocolgetverifypartitions).
+
+
+## GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()
+
+### Summary
+
+`GetBuffer()` is used by GBL to get buffers for loading different images into
+RAM.
+
+### Prototype
+
+```c
+typedef
+EFI_STATUS
+(EFIAPI *GBL_EFI_GET_IMAGE_BUFFER) (
+  IN GBL_EFI_IMAGE_LOADING_PROTOCOL *This,
+  IN GBL_EFI_IMAGE_INFO             *ImageInfo,
+  OUT GBL_EFI_IMAGE_BUFFER          *Buffer,
+)
+```
+
+### Parameters
+
+**This** \
+A pointer to the
+[`GBL_EFI_IMAGE_LOADING_PROTOCOL`](#gbl_efi_image_loading_protocol) instance.
+
+**ImageInfo** \
+Information for the requested buffer. See
+[`GBL_EFI_IMAGE_INFO`](#gbl_efi_image_info) for details.
+
+**Buffer** \
+Output pointer for `GBL_EFI_IMAGE_BUFFER`. See
+[`GBL_EFI_IMAGE_BUFFER`](#gbl_efi_image_buffer) for details.
+
+### Description
+
+The interface is for the firmware to provide platform reserved memory spaces
+to, or instruct caller to allocate specific amount of memory for the usage
+context described in `GBL_EFI_IMAGE_INFO.StrUtf16`. The usage context is
+application specific and may represent usages such as buffers for loading
+specific partitions, sharing data with secure world, and downloading in
+fastboot etc.
+
+If platform has a reserved memory space for the usage context,
+`GBL_EFI_IMAGE_BUFFER.Memory` and `GBL_EFI_IMAGE_BUFFER.SizeBytes` should be
+set to the address and size of the memory. Ownership of the provided memory
+must be passed exclusively to GBL, and must not be retained for any other
+purpose by firmware.
+
+If the caller should allocate memory dynamically by itself for the usage
+context, `GBL_EFI_IMAGE_BUFFER.Memory` should be set to NULL and
+`GBL_EFI_IMAGE_BUFFER.SizeBytes` should be set to the amount of memory caller
+should allocate.
+
+Caller may pass a suggested size via `GBL_EFI_IMAGE_INFO.SizeBytes` based on
+its run time knowledge. Implementation should eventually determine the size.
+
+### Status Codes Returned
+
+|||
+| --- | --- |
+| EFI_SUCCESS | Buffer provided successfully |
+| EFI_OUT_OF_RESOURCES | Failed to allocate buffers due to lack of free memory |
+
+### Related Definitions
+
+#### GBL_EFI_IMAGE_BUFFER
+
+```c
+typedef
+struct GBL_EFI_IMAGE_BUFFER {
+  VOID  *Memory;
+  UINTN SizeBytes;
+} GBL_EFI_IMAGE_BUFFER;
+```
+
+**Memory** \
+Start address of the reserved buffer or NULL if caller should allocate.
+
+**SizeBytes** \
+Size of the reserved buffer or amount of memory caller should allocate.
+
+## GBL_EFI_IMAGE_LOADING_PROTOCOL.GetVerifyPartitions()
+
+### Summary
+
+Query for list of partitions to be verified by GBL.
+
+### Prototype
+
+```c
+typedef
+EFI_STATUS
+(EFIAPI *GBL_EFI_GET_VERIFY_PARTITIONS) (
+  IN GBL_EFI_IMAGE_LOADING_PROTOCOL *This,
+  IN OUT UINTN                      *NumberOfPartitions,
+  IN OUT GBL_EFI_PARTITION_NAME     *Partitions,
+);
+```
+
+### Parameters
+
+**This** \
+A pointer to the
+[`GBL_EFI_IMAGE_LOADING_PROTOCOL`](#gbl_efi_image_loading_protocol) instance.
+
+**NumberOfPartitions** \
+Number of elements in `Partitions[]`. Should be updated to
+number of partitions returned. If there are no partitions to be verified,
+`NumberOfPartitions` should be set to 0.
+
+**Partitions** \
+Array of partitions' names that should be verified. Should be update on return.
+And contain `NumberOfPartitions` valid elements.
+
+### Description
+
+This function is used to override list of partitions to be verified by GBL.
+
+If this function is not implemented or returns `EFI_UNSUPPORTED` GBL will verify
+default list of partitions.
+
+[`GBL_EFI_PARTITION_NAME`](#gbl_efi_partition_name) is struct representing
+partition name. Partition name is UCS-2 string of at most
+`PARTITION_NAME_LEN_U16` elements with terminating `NULL` element.
+
+### Status Codes Returned
+
+|||
+| --- | --- |
+| EFI_SUCCESS | Successfully provided additional partitions to verify |
+| EFI_INVALID_PARAMETER | If `Partitions[]` is `NULL`, where `NumberOfPartitions != 0` |
+
+### Related Definitions
+
+#### GBL_EFI_PARTITION_NAME
+
+```c
+const size_t PARTITION_NAME_LEN_U16 = 36;
+
+typedef
+struct GBL_EFI_PARTITION_NAME {
+  CHAR16 StrUtf16[PARTITION_NAME_LEN_U16];
+} GBL_EFI_PARTITION_NAME;
+```
+
+**StrUtf16** \
+UCS-2 C-String. This string contains partition name, that identifies what
+partition to use for additional validation. The string is at most
+`PARTITION_NAME_LEN_U16` of char16_t elements. E.g. `u"boot"`, `u"fdt"`
+
+#### GBL_EFI_IMAGE_INFO
+
+```c
+const size_t PARTITION_NAME_LEN_U16 = 36;
+
+typedef
+struct GBL_EFI_IMAGE_INFO {
+  CHAR16 ImageType[PARTITION_NAME_LEN_U16];
+  UINTN  SizeBytes;
+} GBL_EFI_IMAGE_INFO;
+```
+
+**ImageType** \
+UCS-2 C-String. This string describes the usage context for the buffer being
+queried. It should be at most `PARTITION_NAME_LEN_U16` of char16_t elements
+including terminating `u'\0'`. E.g. `u"dtb"`
+
+Below are usage strings reserved by GBL.
+
+```c
+//******************************************************
+// GBL reserved image types
+//******************************************************
+// Buffer for loading, verifying and fixing up OS images.
+#define GBL_IMAGE_TYPE_OS_LOAD L"os_load"
+// Buffer for use as fastboot download buffer.
+#define GBL_IMAGE_TYPE_FASTBOOT L"fastboot"
+```
+
+**SizeBytes** \
+Size of the buffer or allocation suggested by the caller.
diff --git a/gbl/docs/gbl_buffer_usage.md b/gbl/docs/gbl_buffer_usage.md
new file mode 100644
index 0000000..b50f718
--- /dev/null
+++ b/gbl/docs/gbl_buffer_usage.md
@@ -0,0 +1,64 @@
+# Buffer Usage in GBL
+
+This doc discusses how GBL (EFI bootloader) gets and uses buffers for various
+functionalities.
+
+## OS Load Buffer
+
+GBL needs a sufficiently large and contiguous buffer for loading, fixing up and
+assembling various OS images such as boot, init_boot, vendor_boot, dtb, dtbo,
+misc etc. This buffer can either be from EFI memory allocation or memory space
+reserved by the platform. At run time, GBL performs the following for
+requesting an OS load buffer.
+
+1. Via
+[GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md#gbl_efi_image_loading_protocolgetbuffer)
+
+   If [GBL_EFI_IMAGE_LOADING_PROTOCOL](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md) is
+   implemented, GBL will make a call to
+   `GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()` with input image type set to
+   [GBL_IMAGE_TYPE_OS_LOAD](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md#related-definitions-1)
+   and input size set to 0 (size determined by vendor). Vendor returns the size
+   and address of the reserved memory if available or instructs GBL to
+   allocates a specific amount of memory via EFI memory allocation.
+
+2. Via EFI Memory Allocation
+
+   If [GBL_EFI_IMAGE_LOADING_PROTOCOL](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md) is
+   not implemented GBL allocates a 256MB size buffer via EFI memory allocation.
+
+## Fastboot Download Buffer
+
+When booting to fastboot mode, GBL requires a buffer for download. The buffer
+is requested following the same process as the case of
+[OS Load Buffer](#os-load-buffer):
+
+1. Via
+[GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md#gbl_efi_image_loading_protocolgetbuffer)
+
+   If [GBL_EFI_IMAGE_LOADING_PROTOCOL](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md) is
+   implemented, GBL will make a call to
+   `GBL_EFI_IMAGE_LOADING_PROTOCOL.GetBuffer()` with input image type set to
+   [GBL_IMAGE_TYPE_FASTBOOT](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md#related-definitions-1)
+   and input size set to 0 (size determined by vendor). Vendor returns the size
+   and address of the reserved memory if available or instructs GBL to
+   allocates a specific amount of memory via EFI memory allocation.
+
+2. Via EFI Memory Allocation
+
+   If [GBL_EFI_IMAGE_LOADING_PROTOCOL](./GBL_EFI_IMAGE_LOADING_PROTOCOL.md) is
+   not implemented GBL allocates a 512MB size buffer via EFI memory allocation.
+
+## AARCH64 Kernel Decopmression
+
+GBL can detect and handle compressed kernel for aarch64. However, current
+implementation requires allocating a separate piece of memory for storing
+decompressed kernel temporarily. This buffer is allocated via EFI memory
+allocation.
+
+## AVB
+
+The AVB (Android Verified Boot) implementation in GBL requires allocating
+additional memory for constructing commandline argument strings and loading
+vbmeta images from disk and any other vendor required partitions for
+verification. The memory is allocated via EFI memory allocation.
diff --git a/gbl/docs/gbl_efi_ab_slot_protocol.md b/gbl/docs/gbl_efi_ab_slot_protocol.md
index 8e4b8b3..72bdb1f 100644
--- a/gbl/docs/gbl_efi_ab_slot_protocol.md
+++ b/gbl/docs/gbl_efi_ab_slot_protocol.md
@@ -634,6 +634,11 @@ system and the bootloader. For example, if the boot reason is 'recovery', the
 bootloader should load the recovery RAM disk and command line. This information
 is stored in a device specific location and format.
 
+**Note:** The boot reason should ONLY be determined by checking persistent storage.
+In particular, if a device supports [`GBL_EFI_FASTBOOT_PROTOCOL`](./gbl_efi_fastboot_protocol.md),
+the return value of `GBL_EFI_FASTBOOT_PROTOCOL.ShouldStopInFastboot()` should NOT
+affect whether the boot reason returned by `GetBootReason()` is `BOOTLOADER`.
+
 ### Status Codes Returned
 
 | Return Code             | Semantics                                                                                                                                                   |
diff --git a/gbl/docs/gbl_efi_avb_protocol.md b/gbl/docs/gbl_efi_avb_protocol.md
index 9d73de9..9dd6946 100644
--- a/gbl/docs/gbl_efi_avb_protocol.md
+++ b/gbl/docs/gbl_efi_avb_protocol.md
@@ -1,12 +1,17 @@
 # GBL AVB EFI Protocol
 
-This protocol delegates some of AVB-related logic to the firmware, including
-tasks such as verifying public keys, handling verification results, and
-managing the device’s secure state (e.g., ROT, lock state, rollback indexes,
-etc.).
-
 ## GBL_EFI_AVB_PROTOCOL
 
+### Summary
+
+This protocol allows to delegate device-specific Android verified booot (AVB)
+logic to the firmware.
+
+`GBL_EFI_AVB_PROTOCOL` protocol isn't required for dev GBL flavour with
+intention to support basic Android boot functionality on dev boards. On the
+production devices this protocol must be provided by the FW to ensure HLOS
+integrity.
+
 ### GUID
 ```c
 // {6bc66b9a-d5c9-4c02-9da9-50af198d912c}
@@ -78,10 +83,117 @@ Handle AVB verification result (i.e update ROT, set device state, display UI
 warnings/errors, handle anti-tampering, etc).
 [`HandleVerificationResult()`](#HandleVerificationResult).
 
-TODO(b/337846185): Cover more AVB functionality such as rollback indexes, open dice, etc.
-TODO(b/337846185): Detailed (per-method) doc once protocol is finalized.
+## GBL_EFI_AVB_PROTOCOL.ValidateVbmetaPublicKey() {#ValidateVbmetaPublicKey}
+
+### Summary
+
+Allows the firmware to check whether the public key used to sign the `vbmeta`
+partition is trusted by verifying it against the hardware-trusted key shipped
+with the device.
+
+### Prototype
+
+```c
+typedef
+EFI_STATUS
+(EFIAPI *GBL_EFI_AVB_VALIDATE_VBMETA_PUBLIC_KEY) (
+  IN GBL_EFI_AVB_PROTOCOL *This,
+  IN CONST UINT8 *PublicKeyData,
+  IN UINTN PublicKeyLength,
+  IN CONST UINT8 *PublicKeyMetadata,
+  IN UINTN PublicKeyMetadataLength,
+  /* GBL_EFI_AVB_KEY_VALIDATION_STATUS */ OUT UINT32 *ValidationStatus);
+```
+
+### Parameters
+
+#### This
+A pointer to the `GBL_EFI_AVB_PROTOCOL` instance.
+
+#### PublicKeyData
+A pointer to the public key extracted from `vbmeta`. Guaranteed to contain valid
+data of length `PublicKeyLength`.
+
+#### PublicKeyLength
+Specifies the length of the public key provided by `PublicKeyData`.
+
+#### PublicKeyMetadata
+A pointer to public key metadata generated using the `avbtool` `--public_key_metadata`
+flag. May be `NULL` if no public key metadata is provided.
+
+#### PublicKeyMetadataLength
+Specifies the length of the public key metadata provided by `PublicKeyMetadata`.
+Guaranteed to be 0 in case of `NULL` `PublicKeyMetadata`.
+
+#### ValidationStatus
+An output parameter that communicates the verification status to the GBL. `VALID`
+and `VALID_CUSTOM_KEY` are interpreted as successful validation statuses.
+
+### Related Definition
+
+```c
+// Vbmeta key validation status.
+//
+// https://source.android.com/docs/security/features/verifiedboot/boot-flow#locked-devices-with-custom-root-of-trust
+typedef enum {
+  VALID,
+  VALID_CUSTOM_KEY,
+  INVALID,
+} GBL_EFI_AVB_KEY_VALIDATION_STATUS;
+```
 
-### Status Codes Returned
+### Description
+
+`ValidateVbmetaPublicKey` must set `ValidationStatus` and return `EFI_SUCCESS`.
+Any non `EFI_SUCCESS` return value from this method is treated as a fatal verification
+error, so `red` state is reported and GBL fails to boot even if device is unlocked.
+
+**`ValidationStatus` and GBL boot flow**:
+
+* `VALID`: The public key is valid and trusted, so the device can continue the boot
+  process for both locked and unlocked states.
+
+* `VALID_CUSTOM_KEY`: The public key is valid but not fully trusted. GBL continues
+  booting a locked device with a `yellow` state and an unlocked device with an `orange` state.
+
+* `INVALID`: The public key is not valid. The device cannot continue the boot process
+  for locked devices; GBL reports a `red` status and resets. Unlocked devices can still
+  boot with an `orange` state.
+
+GBL calls this function once per AVB verification session.
+
+## GBL_EFI_AVB_PROTOCOL.ReadIsDeviceUnlocked() {#ReadIsDeviceUnlocked}
+
+### Summary
+
+Allows the firmware to provide the device's locking state to the GBL in a
+firmware-specific way.
+
+### Prototype
+
+```c
+typedef
+EFI_STATUS
+(EFIAPI *GBL_EFI_AVB_READ_IS_DEVICE_UNLOCKED) (
+  IN GBL_EFI_AVB_PROTOCOL *This,
+  OUT BOOLEAN *IsUnlocked);
+```
+
+### Parameters
+
+#### This
+A pointer to the `GBL_EFI_AVB_PROTOCOL` instance.
+
+#### IsUnlocked
+An output parameter that communicates the device locking state to the GBL.
+
+### Description
+
+An unlocked device state allows GBL not to force AVB and to boot the device with
+an `orange` boot state. GBL rejects continuing the boot process if this method
+returns any error. GBL may call this method multiple times per boot session.
+
+## Status Codes Returned
 
 The following EFI error types are used to communicate result to GBL and libavb in particular:
 
@@ -95,3 +207,5 @@ The following EFI error types are used to communicate result to GBL and libavb i
 | `EFI_STATUS_INVALID_PARAMETER` | Named persistent value size is not supported or does not match the expected size `libavb::AvbIOResult::AVB_IO_RESULT_ERROR_INVALID_VALUE_SIZE`          |
 | `EFI_STATUS_BUFFER_TOO_SMALL`  | Buffer is too small for the requested operation `libavb::AvbIOResult::AVB_IO_RESULT_ERROR_INSUFFICIENT_SPACE`                                           |
 | `EFI_STATUS_UNSUPPORTED`       | Operation isn't implemented / supported                                                                                                                 |
+
+TODO(b/337846185): Provide docs for all methods.
\ No newline at end of file
diff --git a/gbl/docs/gbl_efi_fastboot_protocol.md b/gbl/docs/gbl_efi_fastboot_protocol.md
index c0c94a5..02af175 100644
--- a/gbl/docs/gbl_efi_fastboot_protocol.md
+++ b/gbl/docs/gbl_efi_fastboot_protocol.md
@@ -50,6 +50,7 @@ typedef struct _GBL_EFI_FASTBOOT_PROTOCOL {
   GBL_EFI_FASTBOOT_CLEAR_LOCK                   ClearLock;
   GBL_EFI_FASTBOOT_GET_PARTITION_PERMISSIONS    GetPartitionPermissions;
   GBL_EFI_FASTBOOT_WIPE_USER_DATA               WipeUserData;
+  GBL_EFI_FASTBOOT_SHOULD_STOP_IN_FASTBOOT      ShouldStopInFastboot;
 } GBL_EFI_FASTBOOT_PROTOCOL;
 ```
 
@@ -610,3 +611,41 @@ as part of a refurbishment process, or for testing purposes.
 | `EFI_ACCESS_DENIED`     | The operation is not permitted in the current lock state. |
 | `EFI_DEVICE_ERROR`      | There was a block device or storage error.                |
 
+## `GBL_EFI_FASTBOOT_PROTOCOL.ShouldStopInFastboot()`
+
+### Summary
+
+Checks custom inputs to determine whether the device should stop in fastboot on boot.
+
+### Prototype
+
+```c
+typedef
+BOOL
+(EFIAPI * GBL_EFI_FASTBOOT_SHOULD_STOP_IN_FASTBOOT)(
+    IN GBL_EFI_FASTBOOT_PROTOCOL* This,
+);
+```
+
+### Parameters
+
+*This*
+
+A pointer to the [`GBL_EFI_FASTBOOT_PROTOCOL`](#protocol-interface-structure) instance.
+
+### Description
+
+Devices often define custom mechanisms for determining whether to enter fastboot mode
+on boot. A specific button press combination is common,
+e.g. pressing 'volume down' for three seconds while booting.
+
+`ShouldStopInFastboot()` returns whether the device should stop in fastboot mode
+due to device input.
+
+**Note:** `ShouldStopInFastboot()` should ONLY return `true` if the device specific
+button press is active. In particular, if the device supports
+[`GBL_EFI_AB_SLOT_PROTOCOL`](./gbl_efi_ab_slot_protocol.md),
+`ShouldStopInFastboot()` should NOT check the information provided by
+`GBL_EFI_AB_SLOT_PROTOCOL.GetBootReason()` or the underlying persistent boot reason.
+
+Any errors should cause a return value of `false`.
diff --git a/gbl/docs/gbl_os_configuration_protocol.md b/gbl/docs/gbl_os_configuration_protocol.md
index 2cd4935..1eafde4 100644
--- a/gbl/docs/gbl_os_configuration_protocol.md
+++ b/gbl/docs/gbl_os_configuration_protocol.md
@@ -211,7 +211,7 @@ If the buffer is not large enough to fit the fixups, the function should update
 GBL will then allocate a larger buffer, discard all modifications and repeat
 the `FixupBootConfig` call.
 
-`FixupBufferSize` must be updated on success to let GBL determine the fixup command line data size.
+`FixupBufferSize` must be updated on success to let GBL determine the bootconfig fixup size.
 
 ### Description
 
diff --git a/gbl/efi/BUILD b/gbl/efi/BUILD
index 2607b4e..64f9a04 100644
--- a/gbl/efi/BUILD
+++ b/gbl/efi/BUILD
@@ -51,6 +51,9 @@ rust_library(
 rust_test(
     name = "test",
     crate = ":libgbl_efi",
+    data = [
+        "@gbl//libfdt/test/data:all",
+    ],
     # TODO(b/355436086): mock out the rest of the libefi APIs and
     # remove dead-code; for now it would require a lot of invasive
     # code changes to selectively disable things on tests so this
diff --git a/gbl/efi/src/android_boot.rs b/gbl/efi/src/android_boot.rs
index 5a02b95..1f94325 100644
--- a/gbl/efi/src/android_boot.rs
+++ b/gbl/efi/src/android_boot.rs
@@ -12,62 +12,91 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::{efi_blocks::find_block_devices, fastboot::fastboot, ops::Ops, ops::RambootOps};
-use efi::{exit_boot_services, EfiEntry};
-use libgbl::{android_boot::load_android_simple, gbl_print, gbl_println, GblOps, Os, Result};
+use crate::{
+    fastboot::{with_fastboot_channels, VecPinFut},
+    ops::Ops,
+    utils::{get_platform_buffer_info, BufferInfo},
+};
+use alloc::{boxed::Box, vec::Vec};
+use core::{fmt::Write, str::from_utf8};
+use efi::{efi_print, efi_println, exit_boot_services, EfiEntry};
+use efi_types::{GBL_IMAGE_TYPE_FASTBOOT, GBL_IMAGE_TYPE_OS_LOAD};
+use gbl_async::poll;
+use libgbl::{android_boot::android_main, gbl_print, gbl_println, GblOps, Result};
 
-// The following implements a demo for booting Android from disk. It can be run from
-// Cuttlefish by adding `--android_efi_loader=<path of this EFI binary>` to the command line.
-//
-// A number of simplifications are made (see `android_load::load_android_simple()`):
-//
-//   * No A/B slot switching is performed. It always boot from *_a slot.
-//   * No AVB is performed.
-//   * No dynamic partitions.
-//   * Only support V3/V4 image and Android 13+ (generic ramdisk from the "init_boot" partition)
-//
-// The missing pieces above are currently under development as part of the full end-to-end boot
-// flow in libgbl, which will eventually replace this demo. The demo is currently used as an
-// end-to-end test for libraries developed so far.
-pub fn android_boot_demo(entry: EfiEntry) -> Result<()> {
-    let blks = find_block_devices(&entry)?;
-    let mut ops = Ops::new(&entry, &blks[..], Some(Os::Android));
-    let mut bootimg_buffer = &mut vec![0u8; 128 * 1024 * 1024][..]; // 128 MB
+const SZ_MB: usize = 1024 * 1024;
 
-    match ops.should_stop_in_fastboot() {
-        Ok(true) => fastboot(&mut ops, &mut bootimg_buffer)?,
-        Err(e) => {
-            gbl_println!(ops, "Warning: error while checking fastboot trigger ({:?})", e);
-            gbl_println!(ops, "Ignoring error and continuing with normal boot");
+/// Android bootloader main entry (before booting).
+///
+/// On success, returns a tuple of slices (ramdisk, fdt, kernel, remains).
+pub fn efi_android_load(
+    ops: &mut Ops,
+) -> Result<(&'static mut [u8], &'static mut [u8], &'static mut [u8], &'static mut [u8])> {
+    let entry = ops.efi_entry;
+    // Prepares the OS load buffer.
+    let img_type_os_load = from_utf8(GBL_IMAGE_TYPE_OS_LOAD).unwrap();
+    let load_buffer = match get_platform_buffer_info(&entry, img_type_os_load, 256 * SZ_MB) {
+        BufferInfo::Static(v) => v,
+        BufferInfo::Alloc(sz) => {
+            let alloc = vec![0u8; sz];
+            gbl_println!(ops, "Allocated {:#x} bytes for OS load buffer.", alloc.len());
+            alloc.leak()
         }
-        _ => {}
-    }
+    };
 
-    gbl_println!(ops, "Try booting as Android");
+    // Checks if we have a reserved buffer for fastboot
+    let img_type_fastboot = from_utf8(GBL_IMAGE_TYPE_FASTBOOT).unwrap();
+    let mut fastboot_buffer_info = None;
 
-    // Allocate buffer for load.
-    let mut load_buffer = vec![0u8; 128 * 1024 * 1024]; // 128MB
+    gbl_println!(ops, "Try booting as Android");
 
-    let (ramdisk, fdt, kernel, remains) = if bootimg_buffer.starts_with(b"ANDROID!") {
-        let mut ramboot_ops = RambootOps { ops: &mut ops, bootimg_buffer };
-        load_android_simple(&mut ramboot_ops, &mut load_buffer[..])?
-    } else {
-        load_android_simple(&mut ops, &mut load_buffer[..])?
-    };
+    Ok(android_main(ops, load_buffer.as_mut(), |fb| {
+        // Note: `get_or_insert_with` lazily evaluates closure (only when insert is necessary).
+        let buffer = fastboot_buffer_info.get_or_insert_with(|| {
+            get_platform_buffer_info(&entry, img_type_fastboot, 512 * SZ_MB)
+        });
+        let mut alloc;
+        let buffer = match buffer {
+            BufferInfo::Static(v) => &mut v[..],
+            BufferInfo::Alloc(sz) => {
+                alloc = vec![0u8; *sz];
+                efi_println!(entry, "Allocated {:#x} bytes for fastboot buffer.", alloc.len());
+                &mut alloc
+            }
+        };
+        // TODO(b/383620444): Investigate letting GblOps return fastboot channels.
+        with_fastboot_channels(&entry, |local, usb, tcp| {
+            // We currently only consider 1 parallell flash + 1 parallel download.
+            // This can be made configurable if necessary.
+            const GBL_FB_N: usize = 2;
+            let mut bufs = Vec::from_iter(buffer.chunks_exact_mut(buffer.len() / GBL_FB_N));
+            let bufs = &(&mut bufs[..]).into();
+            let mut fut = Box::pin(fb.run(bufs, VecPinFut::default(), local, usb, tcp));
+            while poll(&mut fut).is_none() {}
+        })
+    })?)
+}
 
-    gbl_println!(ops, "");
-    gbl_println!(
-        ops,
+/// Exits boot services and boots loaded android images.
+pub fn efi_android_boot(
+    entry: EfiEntry,
+    kernel: &[u8],
+    ramdisk: &[u8],
+    fdt: &[u8],
+    remains: &mut [u8],
+) -> Result<()> {
+    efi_println!(entry, "");
+    efi_println!(
+        entry,
         "Booting kernel @ {:#x}, ramdisk @ {:#x}, fdt @ {:#x}",
         kernel.as_ptr() as usize,
         ramdisk.as_ptr() as usize,
         fdt.as_ptr() as usize
     );
-    gbl_println!(ops, "");
+    efi_println!(entry, "");
 
     #[cfg(target_arch = "aarch64")]
     {
-        drop(blks); // Drop `blks` to release the borrow on `entry`.
         let _ = exit_boot_services(entry, remains)?;
         // SAFETY: We currently targets at Cuttlefish emulator where images are provided valid.
         unsafe { boot::aarch64::jump_linux_el2_or_lower(kernel, ramdisk, fdt) };
@@ -80,7 +109,6 @@ pub fn android_boot_demo(entry: EfiEntry) -> Result<()> {
         use libgbl::android_boot::BOOTARGS_PROP;
 
         let fdt = Fdt::new(&fdt[..])?;
-        drop(blks); // Drop `blks` to release the borrow on `entry`.
         let efi_mmap = exit_boot_services(entry, remains)?;
         // SAFETY: We currently target at Cuttlefish emulator where images are provided valid.
         unsafe {
@@ -115,8 +143,7 @@ pub fn android_boot_demo(entry: EfiEntry) -> Result<()> {
             .boot_services()
             .find_first_and_open::<efi::protocol::riscv::RiscvBootProtocol>()?
             .get_boot_hartid()?;
-        gbl_println!(ops, "riscv boot_hart_id: {}", boot_hart_id);
-        drop(blks); // Drop `blks` to release the borrow on `entry`.
+        efi_println!(entry, "riscv boot_hart_id: {}", boot_hart_id);
         let _ = exit_boot_services(entry, remains)?;
         // SAFETY: We currently target at Cuttlefish emulator where images are provided valid.
         unsafe { boot::riscv64::jump_linux(kernel, boot_hart_id, fdt) };
diff --git a/gbl/efi/src/fastboot.rs b/gbl/efi/src/fastboot.rs
index 485e3ab..a777c7f 100644
--- a/gbl/efi/src/fastboot.rs
+++ b/gbl/efi/src/fastboot.rs
@@ -22,21 +22,27 @@ use crate::{
     ops::Ops,
 };
 use alloc::{boxed::Box, vec::Vec};
-use core::{cmp::min, fmt::Write, future::Future, mem::take, pin::Pin, sync::atomic::AtomicU64};
+use core::{
+    cmp::min, fmt::Write, future::Future, mem::take, pin::Pin, sync::atomic::AtomicU64,
+    time::Duration,
+};
 use efi::{
     efi_print, efi_println,
+    local_session::LocalFastbootSession,
     protocol::{gbl_efi_fastboot_usb::GblFastbootUsbProtocol, Protocol},
     EfiEntry,
 };
 use fastboot::{TcpStream, Transport};
 use gbl_async::{block_on, YieldCounter};
 use liberror::{Error, Result};
-use libgbl::fastboot::{run_gbl_fastboot, GblTcpStream, GblUsbTransport, PinFutContainer};
+use libgbl::fastboot::{
+    run_gbl_fastboot, GblFastbootResult, GblTcpStream, GblUsbTransport, PinFutContainer,
+};
 
-const DEFAULT_TIMEOUT_MS: u64 = 5_000;
+const DEFAULT_TIMEOUT: Duration = Duration::from_secs(5);
 const FASTBOOT_TCP_PORT: u16 = 5554;
 
-struct EfiFastbootTcpTransport<'a, 'b, 'c> {
+pub(crate) struct EfiFastbootTcpTransport<'a, 'b, 'c> {
     socket: &'c mut EfiTcpSocket<'a, 'b>,
 }
 
@@ -49,12 +55,12 @@ impl<'a, 'b, 'c> EfiFastbootTcpTransport<'a, 'b, 'c> {
 impl TcpStream for EfiFastbootTcpTransport<'_, '_, '_> {
     /// Reads to `out` for exactly `out.len()` number bytes from the TCP connection.
     async fn read_exact(&mut self, out: &mut [u8]) -> Result<()> {
-        self.socket.receive_exact(out, DEFAULT_TIMEOUT_MS).await
+        self.socket.receive_exact(out, DEFAULT_TIMEOUT).await
     }
 
     /// Sends exactly `data.len()` number bytes from `data` to the TCP connection.
     async fn write_exact(&mut self, data: &[u8]) -> Result<()> {
-        self.socket.send_exact(data, DEFAULT_TIMEOUT_MS).await
+        self.socket.send_exact(data, DEFAULT_TIMEOUT).await
     }
 }
 
@@ -63,12 +69,12 @@ impl GblTcpStream for EfiFastbootTcpTransport<'_, '_, '_> {
         let efi_entry = self.socket.efi_entry;
         self.socket.poll();
         // If not listenining, start listening.
-        // If not connected but it's been `DEFAULT_TIMEOUT_MS`, restart listening in case the remote
+        // If not connected but it's been `DEFAULT_TIMEOUT`, restart listening in case the remote
         // client disconnects in the middle of TCP handshake and leaves the socket in a half open
         // state.
         if !self.socket.is_listening_or_handshaking()
             || (!self.socket.check_active()
-                && self.socket.time_since_last_listen() > DEFAULT_TIMEOUT_MS)
+                && self.socket.time_since_last_listen() > DEFAULT_TIMEOUT)
         {
             let _ = self
                 .socket
@@ -150,7 +156,7 @@ impl Transport for UsbTransport<'_> {
         let mut curr = &packet[..];
         while !curr.is_empty() {
             let to_send = min(curr.len(), self.max_packet_size);
-            self.protocol.send_packet(&curr[..to_send], DEFAULT_TIMEOUT_MS).await?;
+            self.protocol.send_packet(&curr[..to_send], DEFAULT_TIMEOUT).await?;
             // Forces a yield to the executor if the data received/sent reaches a certain
             // threshold. This is to prevent the async code from holding up the CPU for too long
             // in case IO speed is high and the executor uses cooperative scheduling.
@@ -182,7 +188,7 @@ fn init_usb(efi_entry: &EfiEntry) -> Result<UsbTransport> {
 
 // Wrapper of vector of pinned futures.
 #[derive(Default)]
-struct VecPinFut<'a>(Vec<Pin<Box<dyn Future<Output = ()> + 'a>>>);
+pub(crate) struct VecPinFut<'a>(Vec<Pin<Box<dyn Future<Output = ()> + 'a>>>);
 
 impl<'a> PinFutContainer<'a> for VecPinFut<'a> {
     fn add_with<F: Future<Output = ()> + 'a>(&mut self, f: impl FnOnce() -> F) {
@@ -199,9 +205,15 @@ impl<'a> PinFutContainer<'a> for VecPinFut<'a> {
     }
 }
 
-pub fn fastboot(efi_gbl_ops: &mut Ops, bootimg_buf: &mut [u8]) -> Result<()> {
-    let efi_entry = efi_gbl_ops.efi_entry;
-    efi_println!(efi_entry, "Entering fastboot mode...");
+/// Initializes GBL EFI fastboot channels and runs a caller provided closure with them.
+pub(crate) fn with_fastboot_channels(
+    efi_entry: &EfiEntry,
+    f: impl FnOnce(Option<LocalFastbootSession>, Option<UsbTransport>, Option<EfiFastbootTcpTransport>),
+) {
+    let local_session = LocalFastbootSession::start(efi_entry, Duration::from_millis(1))
+        .inspect(|_| efi_println!(efi_entry, "Starting local bootmenu."))
+        .inspect_err(|e| efi_println!(efi_entry, "Failed to start local bootmenu: {:?}", e))
+        .ok();
 
     let usb = init_usb(efi_entry)
         .inspect(|_| efi_println!(efi_entry, "Started Fastboot over USB."))
@@ -223,17 +235,28 @@ pub fn fastboot(efi_gbl_ops: &mut Ops, bootimg_buf: &mut [u8]) -> Result<()> {
         .ok();
     let tcp = tcp.as_mut().map(|v| EfiFastbootTcpTransport::new(v));
 
-    let download_buffers = vec![vec![0u8; 512 * 1024 * 1024]; 2].into();
-    block_on(run_gbl_fastboot(
-        efi_gbl_ops,
-        &download_buffers,
-        VecPinFut::default(),
-        usb,
-        tcp,
-        bootimg_buf,
-    ));
+    f(local_session, usb, tcp)
+}
+
+pub fn fastboot(efi_gbl_ops: &mut Ops, bootimg_buf: &mut [u8]) -> Result<GblFastbootResult> {
+    let efi_entry = efi_gbl_ops.efi_entry;
+    efi_println!(efi_entry, "Entering fastboot mode...");
+
+    let mut res = Default::default();
+    with_fastboot_channels(efi_entry, |local, usb, tcp| {
+        let download_buffers = vec![vec![0u8; 512 * 1024 * 1024]; 2].into();
+        res = block_on(run_gbl_fastboot(
+            efi_gbl_ops,
+            &download_buffers,
+            VecPinFut::default(),
+            local,
+            usb,
+            tcp,
+            bootimg_buf,
+        ));
+    });
 
     efi_println!(efi_entry, "Leaving fastboot mode...");
 
-    Ok(())
+    Ok(res)
 }
diff --git a/gbl/efi/src/fuchsia_boot.rs b/gbl/efi/src/fuchsia_boot.rs
index 44254e1..bf201b2 100644
--- a/gbl/efi/src/fuchsia_boot.rs
+++ b/gbl/efi/src/fuchsia_boot.rs
@@ -15,30 +15,35 @@
 use crate::utils::efi_to_zbi_mem_range_type;
 #[allow(unused_imports)]
 use crate::{
-    efi_blocks::find_block_devices, fastboot::fastboot, ops::Ops, utils::get_efi_mem_attr,
+    efi_blocks::{find_block_devices, EfiGblDisk},
+    fastboot::fastboot,
+    ops::Ops,
+    utils::get_efi_mem_attr,
 };
-use core::fmt::Write;
-use efi::{efi_print, efi_println, EfiEntry, EfiMemoryAttributesTable, EfiMemoryMap};
+use efi::{EfiEntry, EfiMemoryAttributesTable, EfiMemoryMap};
 use efi_types::{
     EfiMemoryAttributesTableHeader, EfiMemoryDescriptor, EFI_MEMORY_ATTRIBUTE_EMA_RUNTIME,
 };
 use liberror::Error;
 use liberror::Error::BufferTooSmall;
 use libgbl::{
+    constants::PAGE_SIZE as PAGE_SIZE_USIZE,
     fuchsia_boot::{zircon_check_enter_fastboot, zircon_load_verify_abr, zircon_part_name},
+    gbl_print, gbl_println,
+    ops::ImageBuffer,
     partition::check_part_unique,
+    GblOps,
     IntegrationError::UnificationError,
-    Os, Result,
+    Result,
 };
 use safemath::SafeNum;
 use zbi::{zbi_format::zbi_mem_range_t, ZbiContainer, ZbiFlags, ZbiType};
-use zerocopy::{ByteSliceMut, Ref};
+use zerocopy::{Ref, SplitByteSliceMut};
 
-const PAGE_SIZE: u64 = 4096;
+const PAGE_SIZE: u64 = PAGE_SIZE_USIZE as u64;
 
 /// Check if the disk GPT layout is a Fuchsia device layout.
-pub fn is_fuchsia_gpt(efi_entry: &EfiEntry) -> Result<()> {
-    let gpt_devices = find_block_devices(&efi_entry)?;
+pub fn is_fuchsia_gpt(disks: &[EfiGblDisk]) -> Result<()> {
     let partitions: &[&[&str]] = &[
         &["zircon_a", "zircon-a"],
         &["zircon_b", "zircon-b"],
@@ -50,7 +55,7 @@ pub fn is_fuchsia_gpt(efi_entry: &EfiEntry) -> Result<()> {
     ];
     if !partitions
         .iter()
-        .all(|&partition| partition.iter().any(|v| check_part_unique(&gpt_devices[..], *v).is_ok()))
+        .all(|&partition| partition.iter().any(|v| check_part_unique(&disks[..], *v).is_ok()))
     {
         return Err(Error::NotFound.into());
     }
@@ -58,23 +63,27 @@ pub fn is_fuchsia_gpt(efi_entry: &EfiEntry) -> Result<()> {
     Ok(())
 }
 
-/// Loads, verifies and boots Fuchsia according to A/B/R.
-pub fn fuchsia_boot_demo(efi_entry: EfiEntry) -> Result<()> {
-    efi_println!(efi_entry, "Try booting as Fuchsia/Zircon");
-
-    let (mut zbi_items_buffer, mut _kernel_buffer, slot) = {
-        let blks = find_block_devices(&efi_entry)?;
-        let mut ops = Ops::new(&efi_entry, &blks[..], Some(Os::Fuchsia));
-        // Checks whether to enter fastboot mode.
-        if zircon_check_enter_fastboot(&mut ops) {
-            fastboot(&mut ops, &mut [])?;
-        }
-        zircon_load_verify_abr(&mut ops)?
-    };
-    efi_println!(efi_entry, "Booting from slot: {}", zircon_part_name(Some(slot)));
-
-    let _zbi_items = zbi_items_buffer.used_mut();
+/// Loads and verifies Fuchsia according to A/B/R.
+///
+/// On success, returns the kernel and zbi_item buffer.
+pub fn efi_fuchsia_load(ops: &mut Ops) -> Result<(ImageBuffer<'static>, ImageBuffer<'static>)> {
+    gbl_println!(ops, "Try booting as Fuchsia/Zircon");
+    // Checks whether to enter fastboot mode.
+    if zircon_check_enter_fastboot(ops) {
+        fastboot(ops, &mut [])?;
+    }
+    let (zbi_items_buffer, kernel_buffer, slot) = zircon_load_verify_abr(ops)?;
+    gbl_println!(ops, "Booting from slot: {}", zircon_part_name(Some(slot)));
+    Ok((kernel_buffer, zbi_items_buffer))
+}
 
+/// Exits boot services and boots loaded fuchsia images.
+pub fn efi_fuchsia_boot(
+    _efi_entry: EfiEntry,
+    mut _kernel_buffer: ImageBuffer,
+    mut _zbi_items: ImageBuffer,
+) -> Result<()> {
+    let _zbi_items = _zbi_items.used_mut();
     #[cfg(target_arch = "aarch64")]
     {
         // Uses the unused buffer for `exit_boot_services` to store output memory map.
@@ -83,7 +92,7 @@ pub fn fuchsia_boot_demo(efi_entry: EfiEntry) -> Result<()> {
         // if none is provided.
         let item_size = zbi::ZbiContainer::parse(&mut _zbi_items[..])?.container_size()?;
         let (_, remains) = _zbi_items.split_at_mut(item_size);
-        let _ = efi::exit_boot_services(efi_entry, remains).unwrap();
+        let _ = efi::exit_boot_services(_efi_entry, remains).unwrap();
         // SAFETY: The kernel has passed libavb verification or device is unlocked, in which case we
         // assume the caller has addressed all safety and security concerns.
         unsafe { boot::aarch64::jump_zircon_el2_or_lower(_kernel_buffer.used_mut(), _zbi_items) };
@@ -94,11 +103,12 @@ pub fn fuchsia_boot_demo(efi_entry: EfiEntry) -> Result<()> {
         const BUFFER_SIZE: usize = 32 * 1024 / 2;
         let mut mem_map_buf = [0u8; BUFFER_SIZE];
         let mut zbi_items = zbi::ZbiContainer::parse(&mut _zbi_items[..])?;
-        let efi_memory_attribute_table = get_efi_mem_attr(&efi_entry).ok_or(Error::InvalidInput)?;
+        let efi_memory_attribute_table =
+            get_efi_mem_attr(&_efi_entry).ok_or(Error::InvalidInput)?;
 
         // `exit_boot_service` returnes EFI memory map that is used to derive and append MEM_CONFIG
         // items.
-        let efi_memory_map = efi::exit_boot_services(efi_entry, &mut mem_map_buf).unwrap();
+        let efi_memory_map = efi::exit_boot_services(_efi_entry, &mut mem_map_buf).unwrap();
 
         add_memory_items(&efi_memory_map, &efi_memory_attribute_table, &mut zbi_items)?;
 
@@ -121,7 +131,7 @@ fn add_memory_items<B>(
     zbi_items: &mut ZbiContainer<B>,
 ) -> Result<()>
 where
-    B: ByteSliceMut + PartialEq,
+    B: SplitByteSliceMut + PartialEq,
 {
     generate_efi_memory_attributes_table_item(
         efi_memory_map,
@@ -140,7 +150,7 @@ fn generate_efi_memory_attributes_table_item<'b, B>(
     zbi_items: &mut ZbiContainer<B>,
 ) -> Result<()>
 where
-    B: ByteSliceMut + PartialEq,
+    B: SplitByteSliceMut + PartialEq,
 {
     let payload = zbi_items.get_next_payload()?;
     let provided_payload_size = payload.len();
@@ -242,7 +252,7 @@ fn generate_mem_config_item<'b, B>(
     zbi_items: &mut ZbiContainer<B>,
 ) -> Result<()>
 where
-    B: ByteSliceMut + PartialEq,
+    B: SplitByteSliceMut + PartialEq,
 {
     let mut tail = zbi_items.get_next_payload()?;
     let provided_payload_size = tail.len();
diff --git a/gbl/efi/src/lib.rs b/gbl/efi/src/lib.rs
index d4313ba..1ed4d22 100644
--- a/gbl/efi/src/lib.rs
+++ b/gbl/efi/src/lib.rs
@@ -51,9 +51,13 @@ pub(crate) use efi_mocks as efi;
 
 #[cfg(not(test))]
 use {
+    crate::{
+        efi_blocks::{find_block_devices, EfiGblDisk},
+        ops::Ops,
+    },
     core::fmt::Write,
     efi::{efi_print, efi_println, EfiEntry},
-    libgbl::Result,
+    libgbl::{Os, Result},
     utils::loaded_image_path,
 };
 
@@ -64,7 +68,7 @@ enum TargetOs {
 }
 
 #[cfg(not(test))]
-fn get_target_os(entry: &EfiEntry) -> TargetOs {
+fn get_target_os(entry: &EfiEntry, disks: &[EfiGblDisk]) -> TargetOs {
     let mut buf = [0u8; 1];
     if entry
         .system_table()
@@ -78,7 +82,7 @@ fn get_target_os(entry: &EfiEntry) -> TargetOs {
             efi::GBL_EFI_OS_BOOT_TARGET_VARNAME
         );
         TargetOs::Fuchsia
-    } else if fuchsia_boot::is_fuchsia_gpt(&entry).is_ok() {
+    } else if fuchsia_boot::is_fuchsia_gpt(disks).is_ok() {
         efi_println!(entry, "Partition layout looks like Fuchsia. Proceeding as Fuchsia");
         TargetOs::Fuchsia
     } else {
@@ -95,9 +99,20 @@ pub fn app_main(entry: EfiEntry) -> Result<()> {
         efi_println!(entry, "Image path: {}", v);
     }
 
-    match get_target_os(&entry) {
-        TargetOs::Fuchsia => fuchsia_boot::fuchsia_boot_demo(entry)?,
-        TargetOs::Android => android_boot::android_boot_demo(entry)?,
+    let disks = find_block_devices(&entry)?;
+    match get_target_os(&entry, &disks) {
+        TargetOs::Fuchsia => {
+            let mut ops = Ops::new(&entry, &disks[..], Some(Os::Fuchsia));
+            let (kernel, zbi_items) = fuchsia_boot::efi_fuchsia_load(&mut ops)?;
+            drop(disks);
+            fuchsia_boot::efi_fuchsia_boot(entry, kernel, zbi_items)?;
+        }
+        TargetOs::Android => {
+            let mut ops = Ops::new(&entry, &disks[..], Some(Os::Android));
+            let (ramdisk, fdt, kernel, remains) = android_boot::efi_android_load(&mut ops)?;
+            drop(disks);
+            android_boot::efi_android_boot(entry, kernel, ramdisk, fdt, remains)?;
+        }
     }
 
     Ok(())
diff --git a/gbl/efi/src/net.rs b/gbl/efi/src/net.rs
index ef668b7..2a3de28 100644
--- a/gbl/efi/src/net.rs
+++ b/gbl/efi/src/net.rs
@@ -20,11 +20,12 @@ use alloc::{boxed::Box, vec::Vec};
 use core::{
     fmt::Write,
     sync::atomic::{AtomicU64, Ordering},
+    time::Duration,
 };
 use efi::{
     efi_print, efi_println,
     protocol::{simple_network::SimpleNetworkProtocol, Protocol},
-    utils::{ms_to_100ns, Timeout},
+    utils::Timeout,
     DeviceHandle, EfiEntry, Event, EventNotify, EventType, Tpl,
 };
 use efi_types::{EfiEvent, EfiMacAddress, EFI_TIMER_DELAY_TIMER_PERIODIC};
@@ -46,8 +47,8 @@ use smoltcp::{
 
 /// Ethernet frame size for frame pool.
 const ETHERNET_FRAME_SIZE: usize = 1536;
-// Update period in milliseconds for `NETWORK_TIMESTAMP`.
-const NETWORK_TIMESTAMP_UPDATE_PERIOD: u64 = 50;
+// Update period for `NETWORK_TIMESTAMP`.
+const NETWORK_TIMESTAMP_UPDATE_PERIOD: Duration = Duration::from_millis(50);
 // Size of the socket tx/rx application data buffer.
 const SOCKET_TX_RX_BUFFER: usize = 256 * 1024;
 
@@ -118,8 +119,14 @@ impl Drop for EfiNetworkDevice<'_> {
 
 // Implements network device trait backend for the `smoltcp` crate.
 impl<'a> Device for EfiNetworkDevice<'a> {
-    type RxToken<'b> = RxToken<'b> where Self: 'b;
-    type TxToken<'b> = TxToken<'a, 'b> where Self: 'b;
+    type RxToken<'b>
+        = RxToken<'b>
+    where
+        Self: 'b;
+    type TxToken<'b>
+        = TxToken<'a, 'b>
+    where
+        Self: 'b;
 
     fn capabilities(&self) -> DeviceCapabilities {
         // Taken from upstream example.
@@ -204,7 +211,9 @@ impl phy::TxToken for TxToken<'_, '_> {
         F: FnOnce(&mut [u8]) -> R,
     {
         loop {
-            match loop_with_timeout(self.efi_entry, 5000, || self.try_get_buffer().ok_or(false)) {
+            match loop_with_timeout(self.efi_entry, Duration::from_secs(5), || {
+                self.try_get_buffer().ok_or(false)
+            }) {
                 Ok(Some(send_buffer)) => {
                     // SAFETY:
                     // * The pointer is confirmed to come from one of `self.tx_frames`. It's
@@ -320,7 +329,7 @@ impl<'a, 'b> EfiTcpSocket<'a, 'b> {
     pub fn listen(&mut self, port: u16) -> Result<()> {
         self.get_socket().abort();
         self.get_socket().listen(port).map_err(listen_to_unified)?;
-        self.last_listen_timestamp = Some(self.timestamp(0));
+        self.last_listen_timestamp = Some(self.timestamp(0).as_millis() as u64);
         Ok(())
     }
 
@@ -330,9 +339,9 @@ impl<'a, 'b> EfiTcpSocket<'a, 'b> {
     }
 
     /// Returns the amount of time elapsed since last call to `Self::listen()`. If `listen()` has
-    /// never been called, `u64::MAX` is returned.
-    pub fn time_since_last_listen(&mut self) -> u64 {
-        self.last_listen_timestamp.map(|v| self.timestamp(v)).unwrap_or(u64::MAX)
+    /// never been called, `Duration::MAX` is returned.
+    pub fn time_since_last_listen(&mut self) -> Duration {
+        self.last_listen_timestamp.map(|v| self.timestamp(v)).unwrap_or(Duration::MAX)
     }
 
     /// Polls network device.
@@ -364,7 +373,7 @@ impl<'a, 'b> EfiTcpSocket<'a, 'b> {
     }
 
     /// Receives exactly `out.len()` number of bytes to `out`.
-    pub async fn receive_exact(&mut self, out: &mut [u8], timeout: u64) -> Result<()> {
+    pub async fn receive_exact(&mut self, out: &mut [u8], timeout: Duration) -> Result<()> {
         let timer = Timeout::new(self.efi_entry, timeout)?;
         let mut curr = &mut out[..];
         while !curr.is_empty() {
@@ -394,7 +403,7 @@ impl<'a, 'b> EfiTcpSocket<'a, 'b> {
     }
 
     /// Sends exactly `data.len()` number of bytes from `data`.
-    pub async fn send_exact(&mut self, data: &[u8], timeout: u64) -> Result<()> {
+    pub async fn send_exact(&mut self, data: &[u8], timeout: Duration) -> Result<()> {
         let timer = Timeout::new(self.efi_entry, timeout)?;
         let mut curr = &data[..];
         let mut last_send_queue = self.get_socket().send_queue();
@@ -437,19 +446,19 @@ impl<'a, 'b> EfiTcpSocket<'a, 'b> {
         &self.interface
     }
 
-    /// Returns the number of milliseconds elapsed since the `base` timestamp.
-    pub fn timestamp(&self, base: u64) -> u64 {
+    /// Returns the duration elapsed since the `base` timestamp.
+    pub fn timestamp(&self, base_in_millis: u64) -> Duration {
         let curr = self.timestamp.load(Ordering::Relaxed);
         // Assume there can be at most one overflow.
-        match curr < base {
-            true => u64::MAX - (base - curr),
-            false => curr - base,
-        }
+        Duration::from_millis(match curr < base_in_millis {
+            true => u64::MAX - (base_in_millis - curr),
+            false => curr - base_in_millis,
+        })
     }
 
     /// Returns a smoltcp time `Instant` value.
     fn instant(&self) -> Instant {
-        to_smoltcp_instant(self.timestamp(0))
+        to_smoltcp_instant(self.timestamp(0).as_millis() as u64)
     }
 
     /// Broadcasts Fuchsia Fastboot MDNS service once.
@@ -551,7 +560,10 @@ impl<'a, 'b, 'c> EfiGblNetworkInternal<'a, 'b, 'c> {
         // Initializes notification functions.
         if self.notify_fn.is_none() {
             self.notify_fn = Some(Box::new(|_: EfiEvent| {
-                self.timestamp.fetch_add(NETWORK_TIMESTAMP_UPDATE_PERIOD, Ordering::Relaxed);
+                self.timestamp.fetch_add(
+                    NETWORK_TIMESTAMP_UPDATE_PERIOD.as_millis() as u64,
+                    Ordering::Relaxed,
+                );
             }));
             self.notify = Some(EventNotify::new(Tpl::Callback, self.notify_fn.as_mut().unwrap()));
         }
@@ -569,7 +581,7 @@ impl<'a, 'b, 'c> EfiGblNetworkInternal<'a, 'b, 'c> {
         bs.set_timer(
             &_time_update_event,
             EFI_TIMER_DELAY_TIMER_PERIODIC,
-            ms_to_100ns(NETWORK_TIMESTAMP_UPDATE_PERIOD)?,
+            NETWORK_TIMESTAMP_UPDATE_PERIOD,
         )?;
 
         // Gets our MAC address and IPv6 address.
diff --git a/gbl/efi/src/ops.rs b/gbl/efi/src/ops.rs
index f3ab74c..636bbf2 100644
--- a/gbl/efi/src/ops.rs
+++ b/gbl/efi/src/ops.rs
@@ -25,14 +25,17 @@ use alloc::{
 };
 use arrayvec::ArrayVec;
 use core::{
-    cmp::min, ffi::CStr, fmt::Write, mem::MaybeUninit, num::NonZeroUsize, ops::DerefMut, ptr::null,
-    slice::from_raw_parts_mut,
+    ffi::CStr, fmt::Write, mem::MaybeUninit, num::NonZeroUsize, ops::DerefMut, ptr::null,
+    slice::from_raw_parts_mut, time::Duration,
 };
 use efi::{
     efi_print, efi_println,
     protocol::{
-        dt_fixup::DtFixupProtocol, gbl_efi_ab_slot::GblSlotProtocol, gbl_efi_avb::GblAvbProtocol,
-        gbl_efi_fastboot::GblFastbootProtocol, gbl_efi_image_loading::GblImageLoadingProtocol,
+        dt_fixup::DtFixupProtocol,
+        gbl_efi_ab_slot::GblSlotProtocol,
+        gbl_efi_avb::GblAvbProtocol,
+        gbl_efi_fastboot::GblFastbootProtocol,
+        gbl_efi_image_loading::{EfiImageBufferInfo, GblImageLoadingProtocol},
         gbl_efi_os_configuration::GblOsConfigurationProtocol,
     },
     EfiEntry,
@@ -44,7 +47,7 @@ use efi_types::{
     GBL_EFI_BOOT_REASON_RECOVERY, PARTITION_NAME_LEN_U16,
 };
 use fdt::Fdt;
-use gbl_storage::{BlockIo, Disk, Gpt, SliceMaybeUninit};
+use gbl_storage::{BlockIo, Disk, Gpt};
 use liberror::{Error, Result};
 use libgbl::{
     constants::{ImageName, BOOTCMD_SIZE},
@@ -63,7 +66,7 @@ use libgbl::{
 };
 use safemath::SafeNum;
 use zbi::ZbiContainer;
-use zerocopy::AsBytes;
+use zerocopy::IntoBytes;
 
 fn to_avb_validation_status_or_panic(status: GblEfiAvbKeyValidationStatus) -> KeyValidationStatus {
     match status {
@@ -87,10 +90,7 @@ fn avb_color_to_efi_color(color: BootStateColor) -> u32 {
 }
 
 fn dt_component_to_efi_dt(component: &DeviceTreeComponent) -> GblEfiVerifiedDeviceTree {
-    let metadata = match component.source {
-        DeviceTreeComponentSource::Dtb(m) | DeviceTreeComponentSource::Dtbo(m) => m,
-        _ => Default::default(),
-    };
+    let metadata = component.metadata.unwrap_or_default();
 
     GblEfiVerifiedDeviceTree {
         metadata: GblEfiDeviceTreeMetadata {
@@ -99,8 +99,8 @@ fn dt_component_to_efi_dt(component: &DeviceTreeComponent) -> GblEfiVerifiedDevi
                 DeviceTreeComponentSource::VendorBoot => {
                     efi_types::GBL_EFI_DEVICE_TREE_SOURCE_VENDOR_BOOT
                 }
-                DeviceTreeComponentSource::Dtb(_) => efi_types::GBL_EFI_DEVICE_TREE_SOURCE_DTB,
-                DeviceTreeComponentSource::Dtbo(_) => efi_types::GBL_EFI_DEVICE_TREE_SOURCE_DTBO,
+                DeviceTreeComponentSource::Dtb => efi_types::GBL_EFI_DEVICE_TREE_SOURCE_DTB,
+                DeviceTreeComponentSource::Dtbo => efi_types::GBL_EFI_DEVICE_TREE_SOURCE_DTBO,
             },
             id: metadata.id,
             rev: metadata.rev,
@@ -134,6 +134,23 @@ fn efi_error_to_avb_error(error: Error) -> AvbIoError {
     }
 }
 
+/// Helper for getting platform reserved buffer from EFI image loading prototol.
+pub(crate) fn get_buffer_from_protocol(
+    efi_entry: &EfiEntry,
+    image_name: &str,
+    size: usize,
+) -> Result<EfiImageBufferInfo> {
+    let mut image_type = [0u16; PARTITION_NAME_LEN_U16];
+    image_type.iter_mut().zip(image_name.encode_utf16()).for_each(|(dst, src)| {
+        *dst = src;
+    });
+    Ok(efi_entry
+        .system_table()
+        .boot_services()
+        .find_first_and_open::<GblImageLoadingProtocol>()?
+        .get_buffer(&GblEfiImageInfo { ImageType: image_type, SizeBytes: size })?)
+}
+
 pub struct Ops<'a, 'b> {
     pub efi_entry: &'a EfiEntry,
     pub disks: &'b [EfiGblDisk<'a>],
@@ -167,27 +184,18 @@ impl<'a, 'b> Ops<'a, 'b> {
     /// # Return
     /// * Ok(ImageBuffer) - Return buffer for partition loading and verification.
     /// * Err(_) - on error
-    fn get_buffer_image_loading(
+    pub(crate) fn get_buffer_image_loading(
         &mut self,
         image_name: &str,
         size: NonZeroUsize,
     ) -> GblResult<ImageBuffer<'static>> {
-        let mut image_type = [0u16; PARTITION_NAME_LEN_U16];
-        image_type.iter_mut().zip(image_name.encode_utf16()).for_each(|(dst, src)| {
-            *dst = src;
-        });
-        let image_info = GblEfiImageInfo { ImageType: image_type, SizeBytes: size.get() };
-        let efi_image_buffer = self
-            .efi_entry
-            .system_table()
-            .boot_services()
-            .find_first_and_open::<GblImageLoadingProtocol>()?
-            .get_buffer(&image_info)?;
-
         // EfiImageBuffer -> ImageBuffer
         // Make sure not to drop efi_image_buffer since we transferred ownership to ImageBuffer
-        let buffer = efi_image_buffer.take();
-        Ok(ImageBuffer::new(buffer))
+        Ok(ImageBuffer::new(
+            get_buffer_from_protocol(self.efi_entry, image_name, size.get())?
+                .take()
+                .ok_or(Error::InvalidState)?,
+        ))
     }
 
     /// Get buffer for partition loading and verification.
@@ -271,7 +279,7 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
         let found = wait_key_stroke(
             self.efi_entry,
             |key| key.unicode_char == 0x08 || (key.unicode_char == 0x0 && key.scan_code == 0x08),
-            2000,
+            Duration::from_secs(2),
         );
         if matches!(found, Ok(true)) {
             efi_println!(self.efi_entry, "Backspace pressed, entering fastboot");
@@ -475,20 +483,20 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
         commandline: &CStr,
         fixup_buffer: &'c mut [u8],
     ) -> Result<Option<&'c str>> {
-        Ok(
-            match self
-                .efi_entry
-                .system_table()
-                .boot_services()
-                .find_first_and_open::<GblOsConfigurationProtocol>()
-            {
-                Ok(protocol) => {
-                    protocol.fixup_kernel_commandline(commandline, fixup_buffer)?;
-                    Some(CStr::from_bytes_until_nul(&fixup_buffer[..])?.to_str()?)
-                }
-                _ => None,
-            },
-        )
+        match self
+            .efi_entry
+            .system_table()
+            .boot_services()
+            .find_first_and_open::<GblOsConfigurationProtocol>()
+        {
+            Ok(protocol) => {
+                protocol.fixup_kernel_commandline(commandline, fixup_buffer)?;
+                Ok(Some(CStr::from_bytes_until_nul(&fixup_buffer[..])?.to_str()?))
+            }
+            // Protocol is optional.
+            Err(Error::NotFound) => Ok(None),
+            Err(e) => Err(e),
+        }
     }
 
     fn fixup_bootconfig<'c>(
@@ -496,30 +504,30 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
         bootconfig: &[u8],
         fixup_buffer: &'c mut [u8],
     ) -> Result<Option<&'c [u8]>> {
-        Ok(
-            match self
-                .efi_entry
-                .system_table()
-                .boot_services()
-                .find_first_and_open::<GblOsConfigurationProtocol>()
-            {
-                Ok(protocol) => {
-                    let fixup_size = protocol.fixup_bootconfig(bootconfig, fixup_buffer)?;
-                    Some(&fixup_buffer[..fixup_size])
-                }
-                _ => None,
-            },
-        )
+        match self
+            .efi_entry
+            .system_table()
+            .boot_services()
+            .find_first_and_open::<GblOsConfigurationProtocol>()
+        {
+            Ok(protocol) => {
+                let fixup_size = protocol.fixup_bootconfig(bootconfig, fixup_buffer)?;
+                Ok(Some(&fixup_buffer[..fixup_size]))
+            }
+            // Protocol is optional.
+            Err(Error::NotFound) => Ok(None),
+            Err(e) => Err(e),
+        }
     }
 
     fn fixup_device_tree(&mut self, device_tree: &mut [u8]) -> Result<()> {
-        if let Ok(protocol) =
-            self.efi_entry.system_table().boot_services().find_first_and_open::<DtFixupProtocol>()
+        match self.efi_entry.system_table().boot_services().find_first_and_open::<DtFixupProtocol>()
         {
-            protocol.fixup(device_tree)?;
+            Ok(protocol) => protocol.fixup(device_tree),
+            // Protocol is optional.
+            Err(Error::NotFound) => Ok(()),
+            Err(e) => Err(e),
         }
-
-        Ok(())
     }
 
     fn select_device_trees(
@@ -562,7 +570,9 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
 
                 Ok(())
             }
-            _ => components_registry.autoselect(),
+            // Protocol is optional.
+            Err(Error::NotFound) => components_registry.autoselect(),
+            Err(e) => Err(e),
         }
     }
 
@@ -580,11 +590,16 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
     }
 
     fn fastboot_visit_all_variables(&mut self, cb: impl FnMut(&[&CStr], &CStr)) -> Result<()> {
-        self.efi_entry
+        match self
+            .efi_entry
             .system_table()
             .boot_services()
-            .find_first_and_open::<GblFastbootProtocol>()?
-            .get_var_all(cb)
+            .find_first_and_open::<GblFastbootProtocol>()
+        {
+            Ok(v) => v.get_var_all(cb),
+            Err(Error::NotFound) => Ok(()),
+            Err(e) => Err(e),
+        }
     }
 
     fn slots_metadata(&mut self) -> Result<SlotsMetadata> {
@@ -601,6 +616,39 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
         })
     }
 
+    #[cfg(not(test))]
+    fn get_current_slot(&mut self) -> Result<Slot> {
+        // TODO(b/383620444): GBL EFI slot protocol is currently implemented on a few platforms such
+        // as Cuttlefish but is out of sync. Wait until protocol is more stable and all platforms
+        // pick up the latest before enabling.
+        Err(Error::Unsupported)
+    }
+
+    #[cfg(not(test))]
+    fn get_next_slot(&mut self, _: bool) -> Result<Slot> {
+        // TODO(b/383620444): See `get_current_slot()`.
+        Err(Error::Unsupported)
+    }
+
+    #[cfg(not(test))]
+    fn set_active_slot(&mut self, _: u8) -> Result<()> {
+        // TODO(b/383620444): See `get_current_slot()`.
+        Err(Error::Unsupported)
+    }
+
+    #[cfg(not(test))]
+    fn set_reboot_reason(&mut self, _: RebootReason) -> Result<()> {
+        // TODO(b/383620444): See `get_current_slot()`.
+        Err(Error::Unsupported)
+    }
+
+    #[cfg(not(test))]
+    fn get_reboot_reason(&mut self) -> Result<RebootReason> {
+        // TODO(b/383620444): See `get_current_slot()`.
+        Err(Error::Unsupported)
+    }
+
+    #[cfg(test)]
     fn get_current_slot(&mut self) -> Result<Slot> {
         // TODO(b/363075013): Refactors the opening of slot protocol into a common helper once
         // `MockBootServices::find_first_and_open` is updated to return Protocol<'_, T>.
@@ -612,6 +660,7 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
             .try_into()
     }
 
+    #[cfg(test)]
     fn get_next_slot(&mut self, mark_boot_attempt: bool) -> Result<Slot> {
         self.efi_entry
             .system_table()
@@ -621,6 +670,7 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
             .try_into()
     }
 
+    #[cfg(test)]
     fn set_active_slot(&mut self, slot: u8) -> Result<()> {
         self.efi_entry
             .system_table()
@@ -629,6 +679,7 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
             .set_active_slot(slot)
     }
 
+    #[cfg(test)]
     fn set_reboot_reason(&mut self, reason: RebootReason) -> Result<()> {
         self.efi_entry
             .system_table()
@@ -637,6 +688,7 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
             .set_boot_reason(gbl_to_efi_boot_reason(reason), b"")
     }
 
+    #[cfg(test)]
     fn get_reboot_reason(&mut self) -> Result<RebootReason> {
         let mut subreason = [0u8; 128];
         self.efi_entry
@@ -649,6 +701,8 @@ impl<'a, 'b, 'd> GblOps<'b, 'd> for Ops<'a, 'b> {
 }
 
 /// Converts a [GblEfiBootReason] to [RebootReason].
+// TODO(b/383620444): Remove the attribute once all boards picks up the stable Slot protocol.
+#[allow(dead_code)]
 fn efi_to_gbl_boot_reason(reason: GblEfiBootReason) -> RebootReason {
     match reason {
         GBL_EFI_BOOT_REASON_RECOVERY => RebootReason::Recovery,
@@ -659,6 +713,8 @@ fn efi_to_gbl_boot_reason(reason: GblEfiBootReason) -> RebootReason {
 }
 
 /// Converts a [RebootReason] to [GblEfiBootReason].
+// TODO(b/383620444): Remove the attribute once all boards picks up the stable Slot protocol.
+#[allow(dead_code)]
 fn gbl_to_efi_boot_reason(reason: RebootReason) -> GblEfiBootReason {
     match reason {
         RebootReason::Recovery => GBL_EFI_BOOT_REASON_RECOVERY,
@@ -668,228 +724,6 @@ fn gbl_to_efi_boot_reason(reason: RebootReason) -> GblEfiBootReason {
     }
 }
 
-/// Inherits everything from `ops` but override a few such as read boot_a from
-/// bootimg_buffer, avb_write_rollback_index(), slot operation etc
-pub struct RambootOps<'b, T> {
-    pub ops: &'b mut T,
-    pub bootimg_buffer: &'b mut [u8],
-}
-
-impl<'a, 'd, T: GblOps<'a, 'd>> GblOps<'a, 'd> for RambootOps<'_, T> {
-    fn console_out(&mut self) -> Option<&mut dyn Write> {
-        self.ops.console_out()
-    }
-
-    fn should_stop_in_fastboot(&mut self) -> Result<bool> {
-        self.ops.should_stop_in_fastboot()
-    }
-
-    fn reboot(&mut self) {
-        self.ops.reboot()
-    }
-
-    fn disks(
-        &self,
-    ) -> &'a [GblDisk<
-        Disk<impl BlockIo + 'a, impl DerefMut<Target = [u8]> + 'a>,
-        Gpt<impl DerefMut<Target = [u8]> + 'a>,
-    >] {
-        self.ops.disks()
-    }
-
-    fn expected_os(&mut self) -> Result<Option<Os>> {
-        self.ops.expected_os()
-    }
-
-    fn zircon_add_device_zbi_items(
-        &mut self,
-        container: &mut ZbiContainer<&mut [u8]>,
-    ) -> Result<()> {
-        self.ops.zircon_add_device_zbi_items(container)
-    }
-
-    fn get_zbi_bootloader_files_buffer(&mut self) -> Option<&mut [u8]> {
-        self.ops.get_zbi_bootloader_files_buffer()
-    }
-
-    fn load_slot_interface<'c>(
-        &'c mut self,
-        _fnmut: &'c mut dyn FnMut(&mut [u8]) -> Result<()>,
-        _boot_token: BootToken,
-    ) -> GblResult<Cursor<'c>> {
-        self.ops.load_slot_interface(_fnmut, _boot_token)
-    }
-
-    fn avb_read_is_device_unlocked(&mut self) -> AvbIoResult<bool> {
-        self.ops.avb_read_is_device_unlocked()
-    }
-
-    fn avb_read_rollback_index(&mut self, _rollback_index_location: usize) -> AvbIoResult<u64> {
-        self.ops.avb_read_rollback_index(_rollback_index_location)
-    }
-
-    fn avb_write_rollback_index(&mut self, _: usize, _: u64) -> AvbIoResult<()> {
-        // We don't want to persist AVB related data such as updating antirollback indices.
-        Ok(())
-    }
-
-    fn avb_read_persistent_value(&mut self, name: &CStr, value: &mut [u8]) -> AvbIoResult<usize> {
-        self.ops.avb_read_persistent_value(name, value)
-    }
-
-    fn avb_write_persistent_value(&mut self, _: &CStr, _: &[u8]) -> AvbIoResult<()> {
-        // We don't want to persist AVB related data such as updating current VBH.
-        Ok(())
-    }
-
-    fn avb_erase_persistent_value(&mut self, _: &CStr) -> AvbIoResult<()> {
-        // We don't want to persist AVB related data such as updating current VBH.
-        Ok(())
-    }
-
-    fn avb_cert_read_permanent_attributes(
-        &mut self,
-        attributes: &mut CertPermanentAttributes,
-    ) -> AvbIoResult<()> {
-        self.ops.avb_cert_read_permanent_attributes(attributes)
-    }
-
-    fn avb_cert_read_permanent_attributes_hash(&mut self) -> AvbIoResult<[u8; SHA256_DIGEST_SIZE]> {
-        self.ops.avb_cert_read_permanent_attributes_hash()
-    }
-
-    fn get_image_buffer(
-        &mut self,
-        image_name: &str,
-        size: NonZeroUsize,
-    ) -> GblResult<ImageBuffer<'d>> {
-        self.ops.get_image_buffer(image_name, size)
-    }
-
-    fn get_custom_device_tree(&mut self) -> Option<&'a [u8]> {
-        self.ops.get_custom_device_tree()
-    }
-
-    fn fixup_os_commandline<'c>(
-        &mut self,
-        commandline: &CStr,
-        fixup_buffer: &'c mut [u8],
-    ) -> Result<Option<&'c str>> {
-        self.ops.fixup_os_commandline(commandline, fixup_buffer)
-    }
-
-    fn fixup_bootconfig<'c>(
-        &mut self,
-        bootconfig: &[u8],
-        fixup_buffer: &'c mut [u8],
-    ) -> Result<Option<&'c [u8]>> {
-        self.ops.fixup_bootconfig(bootconfig, fixup_buffer)
-    }
-
-    fn fixup_device_tree(&mut self, device_tree: &mut [u8]) -> Result<()> {
-        self.ops.fixup_device_tree(device_tree)
-    }
-
-    fn select_device_trees(
-        &mut self,
-        components_registry: &mut DeviceTreeComponentsRegistry,
-    ) -> Result<()> {
-        self.ops.select_device_trees(components_registry)
-    }
-
-    fn read_from_partition_sync(
-        &mut self,
-        part: &str,
-        off: u64,
-        out: &mut (impl SliceMaybeUninit + ?Sized),
-    ) -> Result<()> {
-        if part == "boot_a" {
-            let len = min(self.bootimg_buffer.len() - off as usize, out.len());
-            out.clone_from_slice(&self.bootimg_buffer[off as usize..off as usize + len]);
-            Ok(())
-        } else {
-            self.ops.read_from_partition_sync(part, off, out)
-        }
-    }
-
-    fn avb_handle_verification_result(
-        &mut self,
-        color: BootStateColor,
-        digest: Option<&CStr>,
-        boot_os_version: Option<&[u8]>,
-        boot_security_patch: Option<&[u8]>,
-        system_os_version: Option<&[u8]>,
-        system_security_patch: Option<&[u8]>,
-        vendor_os_version: Option<&[u8]>,
-        vendor_security_patch: Option<&[u8]>,
-    ) -> AvbIoResult<()> {
-        self.ops.avb_handle_verification_result(
-            color,
-            digest,
-            boot_os_version,
-            boot_security_patch,
-            system_os_version,
-            system_security_patch,
-            vendor_os_version,
-            vendor_security_patch,
-        )
-    }
-
-    fn avb_validate_vbmeta_public_key(
-        &self,
-        public_key: &[u8],
-        public_key_metadata: Option<&[u8]>,
-    ) -> AvbIoResult<KeyValidationStatus> {
-        self.ops.avb_validate_vbmeta_public_key(public_key, public_key_metadata)
-    }
-
-    fn slots_metadata(&mut self) -> Result<SlotsMetadata> {
-        // Ramboot is not suppose to call this interface.
-        unreachable!()
-    }
-
-    fn get_current_slot(&mut self) -> Result<Slot> {
-        // Ramboot is slotless
-        Err(Error::Unsupported)
-    }
-
-    fn get_next_slot(&mut self, _: bool) -> Result<Slot> {
-        // Ramboot is not suppose to call this interface.
-        unreachable!()
-    }
-
-    fn set_active_slot(&mut self, _: u8) -> Result<()> {
-        // Ramboot is not suppose to call this interface.
-        unreachable!()
-    }
-
-    fn set_reboot_reason(&mut self, _: RebootReason) -> Result<()> {
-        // Ramboot is not suppose to call this interface.
-        unreachable!()
-    }
-
-    fn get_reboot_reason(&mut self) -> Result<RebootReason> {
-        // Assumes that ramboot use normal boot mode. But we might consider supporting recovery
-        // if there is a usecase.
-        Ok(RebootReason::Normal)
-    }
-
-    fn fastboot_variable<'arg>(
-        &mut self,
-        _: &CStr,
-        _: impl Iterator<Item = &'arg CStr> + Clone,
-        _: &mut [u8],
-    ) -> Result<usize> {
-        // Ramboot should not need this.
-        unreachable!();
-    }
-
-    fn fastboot_visit_all_variables(&mut self, _: impl FnMut(&[&CStr], &CStr)) -> Result<()> {
-        // Ramboot should not need this.
-        unreachable!();
-    }
-}
-
 #[cfg(test)]
 mod test {
     use super::*;
@@ -899,6 +733,7 @@ mod test {
     };
     use efi_types::GBL_EFI_BOOT_REASON;
     use mockall::predicate::eq;
+    use std::slice;
 
     #[test]
     fn ops_write_trait() {
@@ -976,7 +811,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let ops = Ops::new(installed.entry(), &[], None);
@@ -1016,7 +851,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1056,7 +891,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1096,7 +931,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1140,7 +975,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1184,7 +1019,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1224,7 +1059,7 @@ mod test {
         mock_efi
             .boot_services
             .expect_find_first_and_open::<GblAvbProtocol>()
-            .returning(|| Err(Error::NotFound));
+            .return_const(Err(Error::NotFound));
 
         let installed = mock_efi.install();
         let mut ops = Ops::new(installed.entry(), &[], None);
@@ -1235,10 +1070,10 @@ mod test {
     /// Helper for testing `set_boot_reason`
     fn test_set_reboot_reason(input: RebootReason, expect: GBL_EFI_BOOT_REASON) {
         let mut mock_efi = MockEfi::new();
-        mock_efi.boot_services.expect_find_first_and_open::<GblSlotProtocol>().times(1).returning(
+        mock_efi.boot_services.expect_find_first_and_open::<GblSlotProtocol>().return_once(
             move || {
                 let mut slot = GblSlotProtocol::default();
-                slot.expect_set_boot_reason().times(1).returning(move |reason, _| {
+                slot.expect_set_boot_reason().return_once(move |reason, _| {
                     assert_eq!(reason, expect);
                     Ok(())
                 });
@@ -1273,10 +1108,10 @@ mod test {
     /// Helper for testing `get_boot_reason`
     fn test_get_reboot_reason(input: GBL_EFI_BOOT_REASON, expect: RebootReason) {
         let mut mock_efi = MockEfi::new();
-        mock_efi.boot_services.expect_find_first_and_open::<GblSlotProtocol>().times(1).returning(
+        mock_efi.boot_services.expect_find_first_and_open::<GblSlotProtocol>().return_once(
             move || {
                 let mut slot = GblSlotProtocol::default();
-                slot.expect_get_boot_reason().times(1).returning(move |_| Ok((input, 0)));
+                slot.expect_get_boot_reason().return_once(move |_| Ok((input, 0)));
                 Ok(slot)
             },
         );
@@ -1304,4 +1139,534 @@ mod test {
     fn test_get_reboot_reason_fastbootd() {
         test_get_reboot_reason(GBL_EFI_BOOT_REASON_FASTBOOTD, RebootReason::FastbootD);
     }
+
+    #[test]
+    fn test_get_var_all_not_found() {
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblFastbootProtocol>()
+            .return_once(|| Err(Error::NotFound));
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+        ops.fastboot_visit_all_variables(|_, _| {}).unwrap();
+    }
+
+    #[test]
+    fn test_get_var_all_other_errors() {
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblFastbootProtocol>()
+            .return_once(|| Err(Error::InvalidInput));
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+        assert!(ops.fastboot_visit_all_variables(|_, _| {}).is_err());
+    }
+
+    /// Helper for testing `GblOsConfigurationProtocol.fixup_os_commandline`
+    fn test_fixup_os_commandline<'a>(
+        expected_base: &'static CStr,
+        fixup_buffer: &'a mut [u8],
+        fixup_to_apply: &'static [u8],
+        protocol_lookup_error: Option<Error>,
+        protocol_result: Result<()>,
+    ) -> Result<Option<&'a str>> {
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblOsConfigurationProtocol>()
+            .return_once(move || {
+                if let Some(error) = protocol_lookup_error {
+                    return Err(error);
+                }
+
+                let mut os_configuration = GblOsConfigurationProtocol::default();
+
+                os_configuration.expect_fixup_kernel_commandline().return_once(
+                    move |base, buffer| {
+                        assert_eq!(base, expected_base);
+                        buffer[..fixup_to_apply.len()].copy_from_slice(fixup_to_apply);
+                        protocol_result
+                    },
+                );
+
+                Ok(os_configuration)
+            });
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        ops.fixup_os_commandline(expected_base, fixup_buffer)
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_success() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+        const FIXUP: &CStr = c"fixup1=value1 fixup2=value2";
+
+        let mut fixup_buffer = [0x0; FIXUP.to_bytes_with_nul().len()];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                FIXUP.to_bytes_with_nul(),
+                // No protocol lookup error.
+                None,
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Expects fixup applied.
+            Ok(Some(FIXUP.to_str().unwrap()))
+        );
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_success_empty_result() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+
+        let mut fixup_buffer = [0x0; 1];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                // Passes empty fixup to apply.
+                &[],
+                // No protocol lookup error.
+                None,
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Expected empty fixup.
+            Ok(Some("")),
+        );
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_wrong_fixup() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+
+        // Have no space for null terminator.
+        let mut fixup_buffer = [0x0; BASE.to_bytes().len()];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                BASE.to_bytes(),
+                // No protocol lookup error.
+                None,
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Expected error, cannot build c string.
+            Err(Error::InvalidInput),
+        );
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_protocol_error() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+
+        let mut fixup_buffer = [0x0; 0];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                &[],
+                // No protocol lookup error.
+                None,
+                // Protocol returns error.
+                Err(Error::BufferTooSmall(Some(100))),
+            ),
+            // Expected to be catched.
+            Err(Error::BufferTooSmall(Some(100))),
+        );
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_protocol_not_found() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+
+        let mut fixup_buffer = [0x0; 0];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                &[],
+                // Protocol not found.
+                Some(Error::NotFound),
+                // No protocol call error.
+                Ok(()),
+            ),
+            // No fixup in case protocol not found.
+            Ok(None),
+        );
+    }
+
+    #[test]
+    fn test_fixup_os_commandline_protocol_lookup_failed() {
+        const BASE: &CStr = c"key1=value1 key2=value2";
+
+        let mut fixup_buffer = [0x0; 0];
+        assert_eq!(
+            test_fixup_os_commandline(
+                BASE,
+                &mut fixup_buffer,
+                &[],
+                // Protocol lookup failed.
+                Some(Error::AccessDenied),
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Error catched.
+            Err(Error::AccessDenied),
+        );
+    }
+
+    /// Helper for testing `GblOsConfigurationProtocol.fixup_bootconfig`
+    fn test_fixup_bootconfig<'a>(
+        expected_base: &'static [u8],
+        fixup_buffer: &'a mut [u8],
+        fixup_to_apply: &'static [u8],
+        protocol_lookup_error: Option<Error>,
+        protocol_result_error: Option<Error>,
+    ) -> Result<Option<&'a [u8]>> {
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblOsConfigurationProtocol>()
+            .return_once(move || {
+                if let Some(error) = protocol_lookup_error {
+                    return Err(error);
+                }
+
+                let mut os_configuration = GblOsConfigurationProtocol::default();
+
+                os_configuration.expect_fixup_bootconfig().return_once(move |base, buffer| {
+                    assert_eq!(base, expected_base);
+                    buffer[..fixup_to_apply.len()].copy_from_slice(fixup_to_apply);
+
+                    if let Some(protocol_result_error) = protocol_result_error {
+                        return Err(protocol_result_error);
+                    }
+
+                    Ok(fixup_to_apply.len())
+                });
+
+                Ok(os_configuration)
+            });
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        ops.fixup_bootconfig(expected_base, fixup_buffer)
+    }
+
+    #[test]
+    fn test_fixup_bootconfig_success() {
+        const BASE: &[u8] = b"key1=value1\nkey2=value2";
+        const FIXUP: &[u8] = b"fixup1=value1\nfixup2=value2";
+
+        let mut fixup_buffer = [0x0; FIXUP.len()];
+        assert_eq!(
+            test_fixup_bootconfig(
+                BASE,
+                &mut fixup_buffer,
+                FIXUP,
+                // No protocol lookup error.
+                None,
+                // No protocol call error.
+                None,
+            ),
+            // Expects fixup applied.
+            Ok(Some(FIXUP)),
+        );
+    }
+
+    #[test]
+    fn test_fixup_bootconfig_protocol_error() {
+        const BASE: &[u8] = b"key1=value1\nkey2=value2";
+        const FIXUP: &[u8] = b"fixup1=value1\nfixup2=value2";
+
+        let mut fixup_buffer = [0x0; FIXUP.len()];
+        assert_eq!(
+            test_fixup_bootconfig(
+                BASE,
+                &mut fixup_buffer,
+                FIXUP,
+                // No protocol lookup error.
+                None,
+                // Protocol returns error.
+                Some(Error::BufferTooSmall(Some(100))),
+            ),
+            // Expected to be catched.
+            Err(Error::BufferTooSmall(Some(100))),
+        );
+    }
+
+    #[test]
+    fn test_fixup_bootconfig_protocol_not_found() {
+        const BASE: &[u8] = b"key1=value1\nkey2=value2";
+        const FIXUP: &[u8] = b"fixup1=value1\nfixup2=value2";
+
+        let mut fixup_buffer = [0x0; FIXUP.len()];
+        assert_eq!(
+            test_fixup_bootconfig(
+                BASE,
+                &mut fixup_buffer,
+                FIXUP,
+                // Protocol not found.
+                Some(Error::NotFound),
+                // No protocol call error.
+                None,
+            ),
+            // No fixup in case protocol not found.
+            Ok(None),
+        );
+    }
+
+    #[test]
+    fn test_fixup_bootconfig_protocol_lookup_failed() {
+        const BASE: &[u8] = b"key1=value1\nkey2=value2";
+        const FIXUP: &[u8] = b"fixup1=value1\nfixup2=value2";
+
+        let mut fixup_buffer = [0x0; FIXUP.len()];
+        assert_eq!(
+            test_fixup_bootconfig(
+                BASE,
+                &mut fixup_buffer,
+                FIXUP,
+                // Protocol lookup failed.
+                Some(Error::AccessDenied),
+                // No protocol call error.
+                None,
+            ),
+            // Error catched.
+            Err(Error::AccessDenied),
+        );
+    }
+
+    #[test]
+    fn test_select_device_tree_components_select_base_and_overlay() {
+        let base = include_bytes!("../../libfdt/test/data/base.dtb").to_vec();
+        let overlay = include_bytes!("../../libfdt/test/data/overlay_by_path.dtbo").to_vec();
+        let overlay2 = include_bytes!("../../libfdt/test/data/overlay_by_reference.dtbo").to_vec();
+        let mut buffer = vec![0u8; 2 * 1024 * 1024]; // 2 MB
+
+        let base_scoped = base.clone();
+        let overlay_scoped = overlay.clone();
+        let overlay2_scoped = overlay2.clone();
+        let mut mock_efi = MockEfi::new();
+        mock_efi.con_out.expect_write_str().return_const(Ok(()));
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblOsConfigurationProtocol>()
+            .return_once(|| {
+                let mut os_configuration = GblOsConfigurationProtocol::default();
+
+                os_configuration.expect_select_device_trees().return_once(move |components| {
+                    assert_eq!(components.len(), 3);
+
+                    // SAFETY:
+                    // `components[*].device_trees` are pointing to corresponding base device
+                    // tree and overlays buffers.
+                    let (base_passed, overlay_passed, overlay2_passed) = unsafe {
+                        (
+                            slice::from_raw_parts(
+                                components[0].device_tree as *const u8,
+                                base_scoped.len(),
+                            ),
+                            slice::from_raw_parts(
+                                components[1].device_tree as *const u8,
+                                overlay_scoped.len(),
+                            ),
+                            slice::from_raw_parts(
+                                components[2].device_tree as *const u8,
+                                overlay2_scoped.len(),
+                            ),
+                        )
+                    };
+
+                    assert_eq!(base_passed, &base_scoped);
+                    assert_eq!(overlay_passed, &overlay_scoped[..]);
+                    assert_eq!(overlay2_passed, &overlay2_scoped[..]);
+
+                    // Select the base device and the second overlay. The first overlay is not
+                    // being selected.
+                    components[0].selected = true;
+                    components[2].selected = true;
+                    Ok(())
+                });
+
+                Ok(os_configuration)
+            });
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        let mut registry = DeviceTreeComponentsRegistry::new();
+        let mut current_buffer = &mut buffer[..];
+        current_buffer = registry
+            .append(&mut ops, DeviceTreeComponentSource::VendorBoot, &base, current_buffer)
+            .unwrap();
+        current_buffer = registry
+            .append(&mut ops, DeviceTreeComponentSource::Dtbo, &overlay, current_buffer)
+            .unwrap();
+        registry
+            .append(&mut ops, DeviceTreeComponentSource::Dtbo, &overlay2, current_buffer)
+            .unwrap();
+
+        assert_eq!(ops.select_device_trees(&mut registry), Ok(()));
+        assert_eq!(registry.selected(), Ok((&base[..], &[&overlay2[..]][..])));
+    }
+
+    #[test]
+    fn test_select_device_tree_protocol_error() {
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblOsConfigurationProtocol>()
+            .return_once(move || {
+                let mut os_configuration = GblOsConfigurationProtocol::default();
+
+                os_configuration
+                    .expect_select_device_trees()
+                    .return_once(move |_components| Err(Error::InvalidInput));
+
+                Ok(os_configuration)
+            });
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        let mut registry = DeviceTreeComponentsRegistry::new();
+
+        assert_eq!(ops.select_device_trees(&mut registry), Err(Error::InvalidInput));
+    }
+
+    #[test]
+    fn test_select_device_tree_protocol_not_found() {
+        let base = include_bytes!("../../libfdt/test/data/base.dtb").to_vec();
+        let mut buffer = vec![0u8; 2 * 1024 * 1024]; // 2 MB
+
+        let mut mock_efi = MockEfi::new();
+        mock_efi
+            .boot_services
+            .expect_find_first_and_open::<GblOsConfigurationProtocol>()
+            .return_once(move || Err(Error::NotFound));
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        // Appends some data to ensure autoselect is passed.
+        let mut registry = DeviceTreeComponentsRegistry::new();
+        let current_buffer = &mut buffer[..];
+        registry
+            .append(&mut ops, DeviceTreeComponentSource::VendorBoot, &base, current_buffer)
+            .unwrap();
+
+        assert_eq!(ops.select_device_trees(&mut registry), Ok(()));
+    }
+
+    /// Helper for testing `DtFixupProtocol.fixup`
+    fn test_fixup_device_tree(
+        base: &mut [u8],
+        base_after_fixup: &'static [u8],
+        protocol_lookup_error: Option<Error>,
+        protocol_result: Result<()>,
+    ) -> Result<()> {
+        let mut mock_efi = MockEfi::new();
+        mock_efi.boot_services.expect_find_first_and_open::<DtFixupProtocol>().return_once(
+            move || {
+                if let Some(error) = protocol_lookup_error {
+                    return Err(error);
+                }
+
+                let mut dt_fixup = DtFixupProtocol::default();
+
+                dt_fixup.expect_fixup().return_once(move |buffer| {
+                    buffer.copy_from_slice(base_after_fixup);
+                    protocol_result
+                });
+
+                Ok(dt_fixup)
+            },
+        );
+
+        let installed = mock_efi.install();
+        let mut ops = Ops::new(installed.entry(), &[], None);
+
+        let r = ops.fixup_device_tree(base);
+        assert_eq!(base, base_after_fixup);
+        r
+    }
+
+    #[test]
+    fn test_fixup_device_tree_success() {
+        const WITH_FIXUP: &[u8] = b"device tree after overlay applied";
+
+        let mut device_tree_buffer = [0x0; WITH_FIXUP.len()];
+        assert_eq!(
+            test_fixup_device_tree(
+                &mut device_tree_buffer,
+                WITH_FIXUP,
+                // No protocol lookup error.
+                None,
+                // No protocol call error.
+                Ok(()),
+            ),
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_fixup_device_tree_protocol_error() {
+        const WITH_FIXUP: &[u8] = b"device tree after overlay applied";
+
+        let mut device_tree_buffer = [0x0; WITH_FIXUP.len()];
+        assert_eq!(
+            test_fixup_device_tree(
+                &mut device_tree_buffer,
+                WITH_FIXUP,
+                // No protocol lookup error.
+                None,
+                // Protocol returns error.
+                Err(Error::BufferTooSmall(Some(100))),
+            ),
+            // Expected to be catched.
+            Err(Error::BufferTooSmall(Some(100))),
+        );
+    }
+
+    #[test]
+    fn test_fixup_device_tree_protocol_not_found() {
+        assert_eq!(
+            test_fixup_device_tree(
+                &mut [],
+                &[],
+                // Protocol not found.
+                Some(Error::NotFound),
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Protocol is optional, so passed.
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_fixup_device_tree_protocol_lookup_failed() {
+        assert_eq!(
+            test_fixup_device_tree(
+                &mut [],
+                &[],
+                // Protocol lookup failed.
+                Some(Error::AccessDenied),
+                // No protocol call error.
+                Ok(()),
+            ),
+            // Error catched.
+            Err(Error::AccessDenied),
+        );
+    }
 }
diff --git a/gbl/efi/src/utils.rs b/gbl/efi/src/utils.rs
index b1c5390..1595014 100644
--- a/gbl/efi/src/utils.rs
+++ b/gbl/efi/src/utils.rs
@@ -12,11 +12,13 @@
 // See the License for the specific language governing permissions and
 // limitations under the License.
 
-use crate::efi;
-use ::efi::EfiMemoryAttributesTable;
+use crate::{efi, ops::get_buffer_from_protocol};
+use ::efi::{efi_print, efi_println, EfiMemoryAttributesTable};
+use core::{fmt::Write, slice::from_raw_parts_mut, time::Duration};
 use efi::{
     protocol::{
         device_path::{DevicePathProtocol, DevicePathText, DevicePathToTextProtocol},
+        gbl_efi_image_loading::EfiImageBufferInfo,
         loaded_image::LoadedImageProtocol,
         simple_text_input::SimpleTextInputProtocol,
     },
@@ -55,7 +57,7 @@ pub fn loaded_image_path(entry: &EfiEntry) -> Result<DevicePathText> {
 }
 
 /// Find FDT from EFI configuration table.
-pub fn get_efi_fdt<'a>(entry: &'a EfiEntry) -> Option<(&FdtHeader, &[u8])> {
+pub fn get_efi_fdt(entry: &EfiEntry) -> Option<(&FdtHeader, &[u8])> {
     if let Some(config_tables) = entry.system_table().configuration_table() {
         for table in config_tables {
             if table.vendor_guid == EFI_DTB_TABLE_GUID {
@@ -92,18 +94,22 @@ pub fn efi_to_e820_mem_type(efi_mem_type: u32) -> u32 {
 /// Repetitively runs a closure until it signals completion or timeout.
 ///
 /// * If `f` returns `Ok(R)`, an `Ok(Some(R))` is returned immediately.
-/// * If `f` has been repetitively called and returning `Err(false)` for `timeout_ms`,  an
+/// * If `f` has been repetitively called and returning `Err(false)` for `timeout_duration`,  an
 ///   `Ok(None)` is returned. This is the time out case.
 /// * If `f` returns `Err(true)` the timeout is reset.
-pub fn loop_with_timeout<F, R>(efi_entry: &EfiEntry, timeout_ms: u64, mut f: F) -> Result<Option<R>>
+pub fn loop_with_timeout<F, R>(
+    efi_entry: &EfiEntry,
+    timeout_duration: Duration,
+    mut f: F,
+) -> Result<Option<R>>
 where
     F: FnMut() -> core::result::Result<R, bool>,
 {
-    let timeout = Timeout::new(efi_entry, timeout_ms)?;
+    let timeout = Timeout::new(efi_entry, timeout_duration)?;
     while !timeout.check()? {
         match f() {
             Ok(v) => return Ok(Some(v)),
-            Err(true) => timeout.reset(timeout_ms)?,
+            Err(true) => timeout.reset(timeout_duration)?,
             _ => {}
         }
     }
@@ -116,13 +122,13 @@ where
 pub fn wait_key_stroke(
     efi_entry: &EfiEntry,
     pred: impl Fn(EfiInputKey) -> bool,
-    timeout_ms: u64,
+    timeout: Duration,
 ) -> Result<bool> {
     let input = efi_entry
         .system_table()
         .boot_services()
         .find_first_and_open::<SimpleTextInputProtocol>()?;
-    loop_with_timeout(efi_entry, timeout_ms, || -> core::result::Result<Result<bool>, bool> {
+    loop_with_timeout(efi_entry, timeout, || -> core::result::Result<Result<bool>, bool> {
         match input.read_key_stroke() {
             Ok(Some(key)) if pred(key) => Ok(Ok(true)),
             Err(e) => Ok(Err(e.into())),
@@ -161,3 +167,40 @@ pub fn get_efi_mem_attr<'a>(entry: &'a EfiEntry) -> Option<EfiMemoryAttributesTa
             .flatten()
     })
 }
+
+/// Represents either an initialized static memory space or memory to be allocated by the given
+/// size.
+pub(crate) enum BufferInfo {
+    // A static memory space, i.e. memory space reserved by platform
+    Static(&'static mut [u8]),
+    Alloc(usize),
+}
+
+/// A helper for getting platform buffer info from EFI image loading protocol.
+pub(crate) fn get_platform_buffer_info(
+    efi_entry: &EfiEntry,
+    image_type: &str,
+    default_aloc_size: usize,
+) -> BufferInfo {
+    match get_buffer_from_protocol(efi_entry, image_type, 0) {
+        Ok(EfiImageBufferInfo::Buffer(mut buffer)) => {
+            let buffer = buffer.take();
+            buffer.fill(core::mem::MaybeUninit::zeroed());
+            efi_println!(
+                efi_entry,
+                "Found \"{image_type}\" buffer from EFI protocol: addr {:#x}, sz: {:#x}.",
+                buffer.as_mut_ptr() as usize,
+                buffer.len()
+            );
+            // SAFETY:
+            // * `buffer` is a &'static [MaybeUninit<u8>] and fully initialized by the previous
+            //   line.
+            // * MaybeUninit::zeroed() is a valid initialized value for u8.
+            BufferInfo::Static(unsafe {
+                from_raw_parts_mut(buffer.as_mut_ptr() as _, buffer.len())
+            })
+        }
+        Ok(EfiImageBufferInfo::AllocSize(sz)) if sz != 0 => BufferInfo::Alloc(sz),
+        _ => BufferInfo::Alloc(default_aloc_size),
+    }
+}
diff --git a/gbl/fake_modules/protobuf/MODULE.bazel b/gbl/fake_modules/protobuf/MODULE.bazel
new file mode 100644
index 0000000..cc8f9cf
--- /dev/null
+++ b/gbl/fake_modules/protobuf/MODULE.bazel
@@ -0,0 +1 @@
+module(name = "protobuf")
diff --git a/gbl/fake_modules/protobuf/bazel/BUILD.bazel b/gbl/fake_modules/protobuf/bazel/BUILD.bazel
new file mode 100644
index 0000000..65c9c6c
--- /dev/null
+++ b/gbl/fake_modules/protobuf/bazel/BUILD.bazel
@@ -0,0 +1,5 @@
+bzl_library(
+    name = "cc_proto_library_bzl",
+    srcs = ["cc_proto_library.bzl"],
+    visibility = ["//visibility:public"],
+)
diff --git a/gbl/fake_modules/protobuf/bazel/cc_proto_library.bzl b/gbl/fake_modules/protobuf/bazel/cc_proto_library.bzl
new file mode 100644
index 0000000..7723d12
--- /dev/null
+++ b/gbl/fake_modules/protobuf/bazel/cc_proto_library.bzl
@@ -0,0 +1,2 @@
+"""Fake cc_proto_library."""
+cc_proto_library = None
diff --git a/gbl/fake_modules/rules_java/MODULE.bazel b/gbl/fake_modules/rules_java/MODULE.bazel
new file mode 100644
index 0000000..622763c
--- /dev/null
+++ b/gbl/fake_modules/rules_java/MODULE.bazel
@@ -0,0 +1 @@
+module(name = "rules_java")
diff --git a/gbl/fake_modules/rules_kotlin/MODULE.bazel b/gbl/fake_modules/rules_kotlin/MODULE.bazel
new file mode 100644
index 0000000..9c55bb6
--- /dev/null
+++ b/gbl/fake_modules/rules_kotlin/MODULE.bazel
@@ -0,0 +1 @@
+module(name = "rules_kotlin")
diff --git a/gbl/integration/aosp_uefi-gbl-mainline/workspace.bzl b/gbl/integration/aosp_uefi-gbl-mainline/workspace.bzl
index ed62b44..3229325 100644
--- a/gbl/integration/aosp_uefi-gbl-mainline/workspace.bzl
+++ b/gbl/integration/aosp_uefi-gbl-mainline/workspace.bzl
@@ -20,7 +20,7 @@ u-boot-mainline branch.
 load("@bazel_tools//tools/build_defs/repo:utils.bzl", "maybe")
 load("@gbl//toolchain:gbl_workspace_util.bzl", "android_rust_prebuilts", "gbl_llvm_prebuilts")
 
-_CLANG_VERSION = "r530567"
+_CLANG_VERSION = "r547379"
 
 def rust_crate_build_file(
         name,
@@ -29,6 +29,7 @@ def rust_crate_build_file(
         deps = [],
         proc_macro_deps = [],
         features = [],
+        edition = "2021",
         rustc_flags = []):
     """Generate BUILD file content for a rust crate
 
@@ -43,6 +44,7 @@ def rust_crate_build_file(
         deps (List of strings): The `deps` field.
         proc_macro_deps (List of strings): The `proc_macro_deps` field.
         features (List of strings): The `features` field.
+        edition (String): Rust edition.
         rustc_flags (List of strings): The `rustc_flags` field.
 
     Returns:
@@ -61,13 +63,13 @@ load("@rules_rust//rust:defs.bzl", \"{rule}\")
     crate_name = \"{}\",
     srcs = glob(["**/*.rs"]),
     crate_features = {},
-    edition = "2021",
-    rustc_flags ={},
+    edition = \"{edition}\",
+    rustc_flags = {},
     visibility = ["//visibility:public"],
     deps = {},
     proc_macro_deps = {}
 )
-""".format(name, crate_name, features, rustc_flags, deps, proc_macro_deps, rule = rule)
+""".format(name, crate_name, features, rustc_flags, deps, proc_macro_deps, edition = edition, rule = rule)
 
 def define_gbl_workspace(name = None):
     """Set up worksapce dependencies for GBL
@@ -84,15 +86,26 @@ def define_gbl_workspace(name = None):
         path = "external/bazelbuild-rules_rust",
     )
 
+    maybe(
+        repo_rule = native.local_repository,
+        name = "rules_shell",
+        path = "external/bazelbuild-rules_shell",
+    )
+
     maybe(
         repo_rule = native.local_repository,
         name = "rules_license",
         path = "external/bazelbuild-rules_license",
     )
 
+    native.local_repository(
+        name = "googletest",
+        path = "external/googletest",
+    )
+
     native.new_local_repository(
         name = "rules_rust_tinyjson",
-        path = "external/rust/crates/tinyjson",
+        path = "external/rust/android-crates-io/crates/tinyjson",
         build_file = "@rules_rust//util/process_wrapper:BUILD.tinyjson.bazel",
     )
 
@@ -177,19 +190,13 @@ cc_library(
 
     native.new_local_repository(
         name = "uuid",
-        path = "external/rust/crates/uuid",
+        path = "external/rust/android-crates-io/crates/uuid",
         build_file_content = rust_crate_build_file("uuid"),
     )
 
-    native.new_local_repository(
-        name = "cstr",
-        path = "packages/modules/Virtualization/libs/cstr",
-        build_file_content = rust_crate_build_file("cstr"),
-    )
-
     native.new_local_repository(
         name = "spin",
-        path = "external/rust/crates/spin",
+        path = "external/rust/android-crates-io/crates/spin",
         build_file_content = rust_crate_build_file(
             "spin",
             features = [
@@ -205,13 +212,13 @@ cc_library(
 
     native.new_local_repository(
         name = "static_assertions",
-        path = "external/rust/crates/static_assertions",
+        path = "external/rust/android-crates-io/crates/static_assertions",
         build_file_content = rust_crate_build_file("static_assertions"),
     )
 
     native.new_local_repository(
         name = "managed",
-        path = "external/rust/crates/managed",
+        path = "external/rust/android-crates-io/crates/managed",
         build_file_content = rust_crate_build_file(
             "managed",
             features = ["map"],
@@ -226,7 +233,7 @@ cc_library(
 
     native.new_local_repository(
         name = "itertools",
-        path = "external/rust/crates/itertools",
+        path = "external/rust/android-crates-io/crates/itertools",
         build_file_content = rust_crate_build_file(
             "itertools",
             deps = ["@either"],
@@ -237,7 +244,7 @@ cc_library(
 
     native.new_local_repository(
         name = "itertools_noalloc",
-        path = "external/rust/crates/itertools",
+        path = "external/rust/android-crates-io/crates/itertools",
         build_file_content = rust_crate_build_file(
             "itertools_noalloc",
             crate_name = "itertools",
@@ -249,7 +256,7 @@ cc_library(
 
     native.new_local_repository(
         name = "either",
-        path = "external/rust/crates/either",
+        path = "external/rust/android-crates-io/crates/either",
         build_file_content = rust_crate_build_file(
             "either",
             features = ["default", "use_std"],
@@ -258,7 +265,7 @@ cc_library(
 
     native.new_local_repository(
         name = "either_noalloc",
-        path = "external/rust/crates/either",
+        path = "external/rust/android-crates-io/crates/either",
         build_file_content = rust_crate_build_file(
             "either_noalloc",
             crate_name = "either",
@@ -266,6 +273,7 @@ cc_library(
         ),
     )
 
+    # TODO(b/383783832): migrate to android-crates-io
     native.new_local_repository(
         name = "smoltcp",
         path = "external/rust/crates/smoltcp",
@@ -274,7 +282,7 @@ cc_library(
 
     native.new_local_repository(
         name = "arrayvec",
-        path = "external/rust/crates/arrayvec",
+        path = "external/rust/android-crates-io/crates/arrayvec",
         build_file_content = rust_crate_build_file(
             "arrayvec",
             rustc_flags = ["-A", "dead_code"],
@@ -283,7 +291,7 @@ cc_library(
 
     native.new_local_repository(
         name = "downcast",
-        path = "external/rust/crates/downcast",
+        path = "external/rust/android-crates-io/crates/downcast",
         build_file_content = rust_crate_build_file(
             "downcast",
             features = ["default", "std"],
@@ -292,23 +300,23 @@ cc_library(
 
     native.new_local_repository(
         name = "fragile",
-        path = "external/rust/crates/fragile",
+        path = "external/rust/android-crates-io/crates/fragile",
         build_file_content = rust_crate_build_file("fragile"),
     )
 
     native.new_local_repository(
         name = "lazy_static",
-        path = "external/rust/crates/lazy_static",
+        path = "external/rust/android-crates-io/crates/lazy_static",
         build_file_content = rust_crate_build_file("lazy_static"),
     )
 
     native.new_local_repository(
         name = "mockall",
-        path = "external/rust/crates/mockall",
+        path = "external/rust/android-crates-io/crates/mockall",
         build_file_content = rust_crate_build_file(
             "mockall",
             deps = [
-                "@cfg-if",
+                "@cfg_if",
                 "@downcast",
                 "@fragile",
                 "@lazy_static",
@@ -321,17 +329,17 @@ cc_library(
 
     native.new_local_repository(
         name = "mockall_derive",
-        path = "external/rust/crates/mockall_derive",
+        path = "external/rust/android-crates-io/crates/mockall_derive",
         build_file_content = rust_crate_build_file(
             "mockall_derive",
             rule = "rust_proc_macro",
-            deps = ["@cfg-if", "@proc-macro2", "@quote", "@syn"],
+            deps = ["@cfg_if", "@proc_macro2", "@quote", "@syn"],
         ),
     )
 
     native.new_local_repository(
         name = "predicates",
-        path = "external/rust/crates/predicates",
+        path = "external/rust/android-crates-io/crates/predicates",
         build_file_content = rust_crate_build_file(
             "predicates",
             deps = ["@itertools", "@predicates_core", "@termcolor"],
@@ -340,13 +348,13 @@ cc_library(
 
     native.new_local_repository(
         name = "predicates_core",
-        path = "external/rust/crates/predicates-core",
+        path = "external/rust/android-crates-io/crates/predicates-core",
         build_file_content = rust_crate_build_file("predicates_core"),
     )
 
     native.new_local_repository(
         name = "predicates_tree",
-        path = "external/rust/crates/predicates-tree",
+        path = "external/rust/android-crates-io/crates/predicates-tree",
         build_file_content = rust_crate_build_file(
             "predicates_tree",
             deps = ["@predicates_core", "@termtree"],
@@ -355,16 +363,17 @@ cc_library(
 
     native.new_local_repository(
         name = "termcolor",
-        path = "external/rust/crates/termcolor",
+        path = "external/rust/android-crates-io/crates/termcolor",
         build_file_content = rust_crate_build_file("termcolor"),
     )
 
     native.new_local_repository(
         name = "termtree",
-        path = "external/rust/crates/termtree",
+        path = "external/rust/android-crates-io/crates/termtree",
         build_file_content = rust_crate_build_file("termtree"),
     )
 
+    # TODO(b/383783832): migrate to android-crates-io
     native.new_local_repository(
         name = "zune_inflate",
         path = "external/rust/crates/zune-inflate",
@@ -376,7 +385,7 @@ cc_library(
 
     native.new_local_repository(
         name = "lz4_flex",
-        path = "external/rust/crates/lz4_flex",
+        path = "external/rust/android-crates-io/crates/lz4_flex",
         build_file_content = rust_crate_build_file(
             "lz4_flex",
             features = ["safe-decode"],
@@ -390,29 +399,111 @@ cc_library(
         build_file = "//prebuilts/fuchsia_sdk:BUILD.zbi.bazel",
     )
 
-    # Following are third party rust crates dependencies which already contain a
-    # BUILD file that we can use as-is without any modification.
-
-    THIRD_PARTY_CRATES = [
-        "bitflags",
-        "byteorder",
-        "cfg-if",
-        "crc32fast",
-        "hex",
-        "proc-macro2",
-        "quote",
-        "syn",
-        "unicode-ident",
-        "zerocopy",
-        "zerocopy-derive",
-    ]
-
-    for crate in THIRD_PARTY_CRATES:
-        native.new_local_repository(
-            name = crate,
-            path = "external/rust/crates/{}".format(crate),
-            build_file = "//external/rust/crates/{}:BUILD".format(crate),
-        )
+    native.new_local_repository(
+        name = "zerocopy",
+        path = "external/rust/android-crates-io/crates/zerocopy",
+        build_file_content = rust_crate_build_file(
+            "zerocopy",
+            features = ["derive", "simd", "zerocopy-derive"],
+            proc_macro_deps = ["@zerocopy_derive"],
+        ),
+    )
+
+    native.new_local_repository(
+        name = "zerocopy_derive",
+        path = "external/rust/android-crates-io/crates/zerocopy-derive",
+        build_file_content = rust_crate_build_file(
+            "zerocopy_derive",
+            rule = "rust_proc_macro",
+            deps = ["@proc_macro2", "@quote", "@syn"],
+        ),
+    )
+
+    native.new_local_repository(
+        name = "bitflags",
+        path = "external/rust/android-crates-io/crates/bitflags",
+        build_file_content = rust_crate_build_file("bitflags"),
+    )
+
+    native.new_local_repository(
+        name = "byteorder",
+        path = "external/rust/android-crates-io/crates/byteorder",
+        build_file_content = rust_crate_build_file("byteorder"),
+    )
+
+    native.new_local_repository(
+        name = "cfg_if",
+        path = "external/rust/android-crates-io/crates/cfg-if",
+        build_file_content = rust_crate_build_file("cfg_if"),
+    )
+
+    native.new_local_repository(
+        name = "crc32fast",
+        path = "external/rust/android-crates-io/crates/crc32fast",
+        build_file_content = rust_crate_build_file(
+            "crc32fast",
+            deps = ["@cfg_if"],
+            # Current version of the crate doesn't compile with newer editions.
+            edition = "2015",
+        ),
+    )
+
+    native.new_local_repository(
+        name = "hex",
+        path = "external/rust/android-crates-io/crates/hex",
+        build_file_content = rust_crate_build_file(
+            "hex",
+            features = ["alloc", "default", "std"],
+        ),
+    )
+
+    native.new_local_repository(
+        name = "quote",
+        path = "external/rust/android-crates-io/crates/quote",
+        build_file_content = rust_crate_build_file(
+            "quote",
+            features = ["default", "proc-macro"],
+            deps = ["@proc_macro2"],
+        ),
+    )
+
+    native.new_local_repository(
+        name = "unicode_ident",
+        path = "external/rust/android-crates-io/crates/unicode-ident",
+        build_file_content = rust_crate_build_file("unicode_ident"),
+    )
+
+    native.new_local_repository(
+        name = "syn",
+        path = "external/rust/android-crates-io/crates/syn",
+        build_file_content = rust_crate_build_file(
+            "syn",
+            features = [
+                "clone-impls",
+                "default",
+                "derive",
+                "extra-traits",
+                "full",
+                "parsing",
+                "printing",
+                "proc-macro",
+                "quote",
+                "visit",
+                "visit-mut",
+            ],
+            deps = ["@proc_macro2", "@quote", "@unicode_ident"],
+        ),
+    )
+
+    native.new_local_repository(
+        name = "proc_macro2",
+        path = "external/rust/android-crates-io/crates/proc-macro2",
+        build_file_content = rust_crate_build_file(
+            "proc_macro2",
+            deps = ["@unicode_ident"],
+            features = ["default", "proc-macro", "span-locations"],
+        ),
+    )
 
     # Set up a repo to export LLVM tool/library/header/sysroot paths
     gbl_llvm_prebuilts(name = "gbl_llvm_prebuilts")
diff --git a/gbl/libabr/BUILD b/gbl/libabr/BUILD
index 5f65a3d..ef1c491 100644
--- a/gbl/libabr/BUILD
+++ b/gbl/libabr/BUILD
@@ -34,6 +34,7 @@ rust_test(
     name = "libabr_test",
     crate = ":libabr",
     rustc_flags = ANDROID_RUST_LINTS,
+    visibility = ["//visibility:public"],
 )
 
 rust_static_library(
diff --git a/gbl/libabr/src/lib.rs b/gbl/libabr/src/lib.rs
index 94c9309..d836ad9 100644
--- a/gbl/libabr/src/lib.rs
+++ b/gbl/libabr/src/lib.rs
@@ -16,8 +16,7 @@
 
 #![cfg_attr(not(test), no_std)]
 
-use core::{cmp::min, ffi::c_uint, fmt::Write, mem::size_of};
-
+use core::{cmp::min, ffi::c_uint, ffi::CStr, fmt::Write, mem::size_of};
 use liberror::{Error, Result};
 
 const ABR_MAGIC: &[u8; 4] = b"\0AB0";
@@ -103,8 +102,8 @@ impl SlotIndex {
 
 // Implement conversion to c_uint for C interfaces
 impl From<SlotIndex> for c_uint {
-    fn from(_val: SlotIndex) -> Self {
-        match _val {
+    fn from(val: SlotIndex) -> Self {
+        match val {
             SlotIndex::A => 0,
             SlotIndex::B => 1,
             SlotIndex::R => 2,
@@ -114,8 +113,8 @@ impl From<SlotIndex> for c_uint {
 
 // Implement conversion to char
 impl From<SlotIndex> for char {
-    fn from(_val: SlotIndex) -> Self {
-        match _val {
+    fn from(val: SlotIndex) -> Self {
+        match val {
             SlotIndex::A => 'a',
             SlotIndex::B => 'b',
             SlotIndex::R => 'r',
@@ -123,6 +122,31 @@ impl From<SlotIndex> for char {
     }
 }
 
+// Implement conversion to c string suffix.
+impl From<SlotIndex> for &CStr {
+    fn from(s: SlotIndex) -> Self {
+        match s {
+            SlotIndex::A => c"_a",
+            SlotIndex::B => c"_b",
+            SlotIndex::R => c"_r",
+        }
+    }
+}
+
+// Implement conversion from char.
+impl TryFrom<char> for SlotIndex {
+    type Error = Error;
+
+    fn try_from(val: char) -> Result<Self> {
+        match val {
+            'a' => Ok(SlotIndex::A),
+            'b' => Ok(SlotIndex::B),
+            'r' => Ok(SlotIndex::R),
+            _ => Err(Error::InvalidInput),
+        }
+    }
+}
+
 // Implement conversion from c_uint for C interfaces.
 impl TryFrom<c_uint> for SlotIndex {
     type Error = Error;
diff --git a/gbl/libavb/BUILD.avb.bazel b/gbl/libavb/BUILD.avb.bazel
index 701468c..4c9d134 100644
--- a/gbl/libavb/BUILD.avb.bazel
+++ b/gbl/libavb/BUILD.avb.bazel
@@ -14,6 +14,7 @@
 
 load("@gbl//toolchain:gbl_toolchain.bzl", "link_static_cc_library")
 load("@gbl_llvm_prebuilts//:info.bzl", "LLVM_PREBUILTS_C_INCLUDE")
+load("@rules_cc//cc:defs.bzl", "cc_library")
 load("@rules_rust//bindgen:defs.bzl", "rust_bindgen")
 load("@rules_rust//rust:defs.bzl", "rust_library")
 
@@ -86,9 +87,8 @@ cc_library(
         "libavb/avb_vbmeta_image.c",
         "libavb/avb_version.c",
         "libavb_cert/avb_cert_validate.c",
-
-        # Contains noop placeholder for avb_printv/avb_printf
-        "@gbl//libavb:print.c",
+        # C implementations for sysdeps which cannot be implemented using Rust
+        "@gbl//libavb:deps.c",
     ],
     copts = [
         "-D_FILE_OFFSET_BITS=64",
@@ -102,7 +102,7 @@ cc_library(
         "-Wno-unused-parameter",
         "-ffunction-sections",
         "-g",
-        "-DAVB_ENABLE_DEBUG",
+        "-DAVB_USE_PRINTF_LOGS",
         "-DAVB_COMPILATION",
         # libavb uses more than 4K of stack space. This prevents the compiler from inserting
         # _chkstk().
@@ -143,17 +143,17 @@ rust_bindgen(
         "--bitfield-enum=Avb.*Flags",
         "--default-enum-style=rust",
         "--with-derive-default",
-        "--with-derive-custom=Avb.*Descriptor=FromZeroes,FromBytes",
-        "--with-derive-custom=AvbCertPermanentAttributes=FromZeroes,FromBytes,AsBytes",
-        "--with-derive-custom=AvbCertCertificate.*=FromZeroes,FromBytes,AsBytes",
-        "--with-derive-custom=AvbCertUnlock.*=FromZeroes,FromBytes,AsBytes",
+        "--with-derive-custom=Avb.*Descriptor=FromBytes,Immutable,KnownLayout",
+        "--with-derive-custom=AvbCertPermanentAttributes=FromBytes,IntoBytes",
+        "--with-derive-custom=AvbCertCertificate.*=FromBytes,IntoBytes",
+        "--with-derive-custom=AvbCertUnlock.*=FromBytes,IntoBytes",
         "--allowlist-type=AvbDescriptorTag",
         "--allowlist-type=Avb.*Flags",
         "--allowlist-function=.*",
         "--allowlist-var=AVB.*",
         "--use-core",
         "--raw-line=#![no_std]",
-        "--raw-line=use zerocopy::{AsBytes, FromBytes, FromZeroes};",
+        "--raw-line=use zerocopy::{Immutable, IntoBytes, FromBytes, KnownLayout};",
         "--ctypes-prefix=core::ffi",
     ],
     cc_lib = "headers",
diff --git a/gbl/libavb/print.c b/gbl/libavb/deps.c
similarity index 80%
rename from gbl/libavb/print.c
rename to gbl/libavb/deps.c
index 3f1e7d5..2bf4c7b 100644
--- a/gbl/libavb/print.c
+++ b/gbl/libavb/deps.c
@@ -12,13 +12,17 @@
  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  * See the License for the specific language governing permissions and
  * limitations under the License.
- *
  */
 
+#include <gbl/print.h>
 #include <libavb/avb_sysdeps.h>
+#include <stdarg.h>
 
-// Noop placeholder for avb_printf/avb_printv
-
-void avb_printf(const char* fmt, ...) {}
+void avb_printf(const char* fmt, ...) {
+  va_list args;
+  va_start(args, fmt);
+  gbl_printf(fmt, args);
+  va_end(args);
+}
 
 void avb_printv(const char* message, ...) {}
diff --git a/gbl/libboot/BUILD b/gbl/libboot/BUILD
index 4982222..47634d4 100644
--- a/gbl/libboot/BUILD
+++ b/gbl/libboot/BUILD
@@ -35,7 +35,7 @@ cc_library(
     deps = ["@linux_x86_64_sysroot//:linux_x86_64_sysroot_include"],
 )
 
-CUSTOM_DERIVES = "AsBytes,FromBytes,FromZeroes"
+CUSTOM_DERIVES = "Immutable,IntoBytes,FromBytes"
 
 rust_bindgen(
     name = "x86_bootparam_bindgen",
@@ -53,7 +53,7 @@ rust_bindgen(
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
 #![cfg_attr(not(test), no_std)]
-use zerocopy::{AsBytes, FromBytes, FromZeroes};""",
+use zerocopy::{Immutable, IntoBytes, FromBytes};""",
     ],
     cc_lib = ":bindgen_cc_lib",
     header = "@linux_x86_64_sysroot//:sysroot/usr/include/x86_64-linux-gnu/asm/bootparam.h",
@@ -64,6 +64,7 @@ rust_library(
     srcs = [":x86_bootparam_bindgen"],
     crate_root = ":x86_bootparam_bindgen",
     data = [":x86_bootparam_bindgen"],
+    rustc_flags = ["--cfg=zerocopy_derive_union_into_bytes"],
     deps = ["@zerocopy"],
 )
 
diff --git a/gbl/libboot/src/x86.rs b/gbl/libboot/src/x86.rs
index fcc3fab..e2fb128 100644
--- a/gbl/libboot/src/x86.rs
+++ b/gbl/libboot/src/x86.rs
@@ -51,7 +51,7 @@ use liberror::{Error, Result};
 use zbi::ZbiContainer;
 
 pub use x86_bootparam_defs::{boot_params, e820entry, setup_header};
-use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};
 
 // Sector size is fixed to 512
 const SECTOR_SIZE: usize = 512;
@@ -62,6 +62,12 @@ const LOAD_ADDR_HIGH: usize = 0x10_0000;
 // Flag value to use high address for protected mode kernel.
 const LOAD_FLAG_LOADED_HIGH: u8 = 0x1;
 
+/// In 64-bit boot protocol, the kernel is started by jumping to the
+/// 64-bit kernel entry point, which is the start address of loaded
+/// 64-bit kernel plus 0x200.
+#[cfg(target_arch = "x86_64")]
+const ENTRY_POINT_OFFSET: usize = 0x200;
+
 /// E820 RAM address range type.
 pub const E820_ADDRESS_TYPE_RAM: u32 = 1;
 /// E820 reserved address range type.
@@ -77,24 +83,26 @@ pub const E820_ADDRESS_TYPE_PMEM: u32 = 7;
 
 /// Wrapper for `struct boot_params {}` C structure
 #[repr(transparent)]
-#[derive(Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Immutable, IntoBytes, FromBytes, KnownLayout)]
 pub struct BootParams(boot_params);
 
 impl BootParams {
     /// Cast a bytes into a reference of BootParams header
     pub fn from_bytes_ref(buffer: &[u8]) -> Result<&BootParams> {
-        Ok(Ref::<_, BootParams>::new_from_prefix(buffer)
-            .ok_or(Error::BufferTooSmall(Some(size_of::<BootParams>())))?
-            .0
-            .into_ref())
+        Ok(Ref::into_ref(
+            Ref::<_, BootParams>::new_from_prefix(buffer)
+                .ok_or(Error::BufferTooSmall(Some(size_of::<BootParams>())))?
+                .0,
+        ))
     }
 
     /// Cast a bytes into a mutable reference of BootParams header.
     pub fn from_bytes_mut(buffer: &mut [u8]) -> Result<&mut BootParams> {
-        Ok(Ref::<_, BootParams>::new_from_prefix(buffer)
-            .ok_or(Error::BufferTooSmall(Some(size_of::<BootParams>())))?
-            .0
-            .into_mut())
+        Ok(Ref::into_mut(
+            Ref::<_, BootParams>::new_from_prefix(buffer)
+                .ok_or(Error::BufferTooSmall(Some(size_of::<BootParams>())))?
+                .0,
+        ))
     }
 
     /// Return a mutable reference of the `setup_header` struct field in `boot_params`
@@ -247,7 +255,7 @@ where
             "cld",
             "cli",
             "jmp {ep}",
-            ep = in(reg) LOAD_ADDR_HIGH,
+            ep = in(reg) LOAD_ADDR_HIGH + ENTRY_POINT_OFFSET,
             in("rsi") low_mem_addr,
         );
     }
diff --git a/gbl/libbootimg/BUILD b/gbl/libbootimg/BUILD
index 6d0f55a..72e9f38 100644
--- a/gbl/libbootimg/BUILD
+++ b/gbl/libbootimg/BUILD
@@ -45,7 +45,7 @@ BLOCKED_ITEMS_RE = "_.+|.?INT.+|PTR.+|ATOMIC.+|.+SOURCE|.+_H|SIG_.+|SIZE_.+|.?CH
 
 CUSTOM_STRUCT_RE = "(vendor_)?(boot_img_hdr|ramdisk_table_entry)_v\\d+"
 
-CUSTOM_STRUCT_DERIVES = "AsBytes,FromBytes,FromZeroes,PartialEq,Copy,Clone,Debug"
+CUSTOM_STRUCT_DERIVES = "Immutable,IntoBytes,FromBytes,KnownLayout,PartialEq,Copy,Clone,Debug"
 
 rust_bindgen(
     name = "bootimg_defs_bindgen",
@@ -65,7 +65,7 @@ rust_bindgen(
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
 #![cfg_attr(not(test), no_std)]
-use zerocopy::{AsBytes, FromBytes, FromZeroes};""",
+use zerocopy::{Immutable, IntoBytes, FromBytes, KnownLayout};""",
     ],
     cc_lib = ":bootimg_cc_header",
     clang_flags = select(
diff --git a/gbl/libbootparams/src/bootconfig.rs b/gbl/libbootparams/src/bootconfig.rs
index b9d7a0b..335b357 100644
--- a/gbl/libbootparams/src/bootconfig.rs
+++ b/gbl/libbootparams/src/bootconfig.rs
@@ -31,7 +31,8 @@ const BOOTCONFIG_MAGIC: &str = "#BOOTCONFIG\n";
 //     checksum: u32,
 //     bootconfig_magic: [u8]
 // }
-const BOOTCONFIG_TRAILER_SIZE: usize = 4 + 4 + BOOTCONFIG_MAGIC.len();
+/// Size of the bootconfig trailer.
+pub const BOOTCONFIG_TRAILER_SIZE: usize = 4 + 4 + BOOTCONFIG_MAGIC.len();
 
 impl<'a> BootConfigBuilder<'a> {
     /// Initialize with a given buffer.
diff --git a/gbl/libbootparams/src/commandline.rs b/gbl/libbootparams/src/commandline.rs
index f035795..02034bb 100644
--- a/gbl/libbootparams/src/commandline.rs
+++ b/gbl/libbootparams/src/commandline.rs
@@ -16,6 +16,7 @@
 //!
 //! https://www.kernel.org/doc/html/v4.14/admin-guide/kernel-parameters.html
 
+use crate::entry::{CommandlineParser, Entry};
 use core::ffi::CStr;
 use liberror::{Error, Error::BufferTooSmall, Error::InvalidInput, Result};
 
@@ -138,6 +139,11 @@ impl<'a> CommandlineBuilder<'a> {
         })
     }
 
+    /// Get the parsed kernel command line entries.
+    pub fn entries(&'a self) -> impl Iterator<Item = Result<Entry<'a>>> {
+        CommandlineParser::new(self.as_str())
+    }
+
     /// Update the command line null terminator at the end of the current buffer.
     fn update_null_terminator(&mut self) {
         self.buffer[self.current_size] = 0;
@@ -283,6 +289,23 @@ mod test {
         assert_eq!(builder.remaining_capacity(), 0);
     }
 
+    #[test]
+    fn test_get_entries() {
+        let mut test_commandline = TEST_COMMANDLINE.to_vec();
+        let builder = CommandlineBuilder::new_from_prefix(&mut test_commandline[..]).unwrap();
+
+        let data_from_builder = builder
+            .entries()
+            .map(|entry| entry.unwrap().to_string())
+            .collect::<Vec<String>>()
+            .join(" ");
+
+        assert_eq!(
+            data_from_builder,
+            CStr::from_bytes_until_nul(TEST_COMMANDLINE).unwrap().to_str().unwrap()
+        );
+    }
+
     #[test]
     fn test_add_to_empty_not_enough_space() {
         let mut buffer = [0u8; COMMANDLINE_TRAILING_SIZE];
diff --git a/gbl/libbootparams/src/entry.rs b/gbl/libbootparams/src/entry.rs
new file mode 100644
index 0000000..557abe4
--- /dev/null
+++ b/gbl/libbootparams/src/entry.rs
@@ -0,0 +1,242 @@
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
+//! Entities to parse and iterate over both kernel command line and bootconfig.
+
+use core::fmt::{Display, Formatter};
+use liberror::{Error, Result};
+
+/// A struct representing a key-value entry inside kernel command line or bootconfig.
+#[derive(Debug, PartialEq, Eq)]
+pub struct Entry<'a> {
+    /// Boot parameters entry key.
+    pub key: &'a str,
+    /// Boot parameters entry value (may be not presented).
+    pub value: Option<&'a str>,
+}
+
+/// Convert Entry into kernel command line / bootconfig compatible string.
+impl<'a> Display for Entry<'a> {
+    fn fmt(&self, f: &mut Formatter<'_>) -> core::fmt::Result {
+        match self.value {
+            Some(value) => write!(f, "{}={}", self.key, value),
+            None => write!(f, "{}", self.key),
+        }
+    }
+}
+
+/// To iterate over kernel command line entries.
+pub struct CommandlineParser<'a> {
+    data: &'a str,
+    pos: usize,
+}
+
+impl<'a> CommandlineParser<'a> {
+    /// Creates a new iterator from raw command line.
+    pub fn new(data: &'a str) -> Self {
+        CommandlineParser { data, pos: 0 }
+    }
+
+    fn remains(&self) -> &'a str {
+        &self.data.get(self.pos..).unwrap_or("")
+    }
+
+    fn peek(&self) -> Option<char> {
+        self.remains().chars().next()
+    }
+
+    fn skip(&mut self, n: usize) {
+        self.pos += n;
+    }
+
+    fn take_while<F>(&mut self, predicate: F) -> &'a str
+    where
+        F: Fn(char) -> bool,
+    {
+        let remains = self.remains();
+        let n = match remains.find(|c: char| !predicate(c)) {
+            Some(end) => end,
+            // Take everything if we cannot find.
+            None => remains.len(),
+        };
+
+        self.pos += n;
+        &remains[..n]
+    }
+
+    fn skip_whitespaces(&mut self) {
+        self.pos += self.remains().len() - self.remains().trim_start().len();
+    }
+
+    fn parse_key(&mut self) -> Option<&'a str> {
+        self.skip_whitespaces();
+
+        let key = self.take_while(|c| !c.is_whitespace() && c != '=');
+
+        match key.is_empty() {
+            true => None,
+            false => Some(key),
+        }
+    }
+
+    fn parse_value(&mut self) -> Result<Option<&'a str>> {
+        match self.peek() {
+            // Skip the '=' character.
+            Some('=') => self.skip(1),
+            // No value.
+            Some(c) if c.is_whitespace() => return Ok(None),
+            // End of input.
+            None => return Ok(None),
+            // Invalid input
+            _ => {
+                self.skip(self.remains().len());
+                return Err(Error::InvalidInput);
+            }
+        }
+
+        let value = match self.peek() {
+            // Check for the open quote.
+            Some('"') => {
+                // Skip it.
+                self.skip(1);
+                let value = self.take_while(|c| c != '"');
+
+                // Check for the close quote.
+                match self.peek() {
+                    Some('"') => {
+                        // Skip it.
+                        self.skip(1);
+                        value
+                    }
+                    _ => {
+                        self.skip(self.remains().len());
+                        return Err(Error::InvalidInput);
+                    }
+                }
+            }
+            _ => self.take_while(|c| !c.is_whitespace()),
+        };
+
+        Ok(Some(value))
+    }
+}
+
+/// Parse kernel command line format, so we can iterate over key-value entries.
+/// https://www.kernel.org/doc/html/v4.14/admin-guide/kernel-parameters.html
+impl<'a> Iterator for CommandlineParser<'a> {
+    type Item = Result<Entry<'a>>;
+
+    fn next(&mut self) -> Option<Self::Item> {
+        match self.parse_key() {
+            Some(key) => match self.parse_value() {
+                Ok(value) => Some(Ok(Entry { key, value })),
+                Err(e) => Some(Err(e)),
+            },
+            None => None,
+        }
+    }
+}
+
+#[cfg(test)]
+mod tests {
+    use super::*;
+
+    #[test]
+    fn test_kernel_command_line_valid_key_value() {
+        let mut iterator = CommandlineParser::new(
+            "video=vfb:640x400,bpp=32,memsize=3072000 console=ttyMSM0,115200n8 earlycon bootconfig",
+        );
+
+        assert_eq!(
+            iterator.next(),
+            Some(Ok(Entry { key: "video", value: Some("vfb:640x400,bpp=32,memsize=3072000") }))
+        );
+        assert_eq!(
+            iterator.next(),
+            Some(Ok(Entry { key: "console", value: Some("ttyMSM0,115200n8") }))
+        );
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "earlycon", value: None })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "bootconfig", value: None })));
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_multiple_spaces_between_entries() {
+        let mut iterator = CommandlineParser::new("key1=val1   key2    key3=val3   key4=val4   ");
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key1", value: Some("val1") })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key2", value: None })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key3", value: Some("val3") })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key4", value: Some("val4") })));
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_no_values() {
+        let mut iterator = CommandlineParser::new("key1 key2 key3");
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key1", value: None })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key2", value: None })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key3", value: None })));
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_empty_values() {
+        let mut iterator = CommandlineParser::new(r#"key1="" key2="" key3="""#);
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key1", value: Some("") })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key2", value: Some("") })));
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key3", value: Some("") })));
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_quoted_values() {
+        let mut iterator = CommandlineParser::new(r#"key1="value with spaces" key2="value""#);
+        assert_eq!(
+            iterator.next(),
+            Some(Ok(Entry { key: "key1", value: Some("value with spaces") }))
+        );
+        assert_eq!(iterator.next(), Some(Ok(Entry { key: "key2", value: Some("value") })));
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_value_with_new_line() {
+        let mut iterator = CommandlineParser::new("key1=\"value with \n new line\"");
+        assert_eq!(
+            iterator.next(),
+            Some(Ok(Entry { key: "key1", value: Some("value with \n new line") }))
+        );
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_invalid_missing_closing_quote() {
+        let mut iterator = CommandlineParser::new(r#"key="value without closing quote key2=val2"#);
+        assert_eq!(iterator.next(), Some(Err(Error::InvalidInput)));
+        // After encountering invalid input, the iterator may not produce more entries.
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_empty() {
+        let mut iterator = CommandlineParser::new("");
+        assert_eq!(iterator.next(), None);
+    }
+
+    #[test]
+    fn test_kernel_command_line_whitespace_only() {
+        let mut iterator = CommandlineParser::new("    \t   \n    ");
+        assert_eq!(iterator.next(), None);
+    }
+}
diff --git a/gbl/libbootparams/src/lib.rs b/gbl/libbootparams/src/lib.rs
index d9c5b94..54beea1 100644
--- a/gbl/libbootparams/src/lib.rs
+++ b/gbl/libbootparams/src/lib.rs
@@ -19,3 +19,6 @@
 
 pub mod bootconfig;
 pub mod commandline;
+pub mod entry;
+
+pub use self::entry::Entry;
diff --git a/gbl/libc/BUILD b/gbl/libc/BUILD
index fb92e50..32b305a 100644
--- a/gbl/libc/BUILD
+++ b/gbl/libc/BUILD
@@ -12,7 +12,9 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@gbl//toolchain:gbl_toolchain.bzl", "link_static_cc_library")
 load("@gbl//toolchain:gbl_workspace_util.bzl", "ANDROID_RUST_LINTS")
+load("@rules_cc//cc:defs.bzl", "cc_library", "cc_test")
 load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
 
 package(
@@ -25,6 +27,7 @@ rust_library(
     edition = "2021",
     rustc_flags = ANDROID_RUST_LINTS,
     deps = [
+        ":libc_c_staticlib",
         "@gbl//libsafemath",
     ],
 )
@@ -35,11 +38,20 @@ rust_test(
     rustc_flags = ANDROID_RUST_LINTS,
 )
 
+rust_library(
+    name = "libc_deps_posix",
+    srcs = ["deps/posix.rs"],
+    edition = "2021",
+    rustc_flags = ANDROID_RUST_LINTS,
+)
+
 cc_library(
     name = "headers",
     hdrs = [
         "include/debug.h",
+        "include/gbl/print.h",
         "include/inttypes.h",
+        "include/limits.h",
         "include/stdio.h",
         "include/stdlib.h",
         "include/string.h",
@@ -47,3 +59,30 @@ cc_library(
     ],
     includes = ["include"],
 )
+
+cc_library(
+    name = "libc_c",
+    srcs = [
+        "src/format.c",
+    ],
+    deps = [
+        ":headers",
+    ],
+)
+
+cc_test(
+    name = "libc_c_test",
+    srcs = ["src/format_test.cpp"],
+    target_compatible_with = [
+        "@platforms//os:linux",
+    ],
+    deps = [
+        ":libc_c",
+        "@googletest//:gtest_main",
+    ],
+)
+
+link_static_cc_library(
+    name = "libc_c_staticlib",
+    cc_library = ":libc_c",
+)
diff --git a/gbl/libc/deps/posix.rs b/gbl/libc/deps/posix.rs
new file mode 100644
index 0000000..1424b07
--- /dev/null
+++ b/gbl/libc/deps/posix.rs
@@ -0,0 +1,25 @@
+// Copyright 2025, The Android Open Source Project
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
+//! This library provides platform-specific implementations required by GBL libc.
+//! See `libc/src/lib.rs` for more details.
+//!
+//! This implementation relies on the Rust standard library and can only be used
+//! where it is available (mainly tests in case of GBL).
+
+/// Rust standard library-based print implementation required by GBL `libc`.
+#[no_mangle]
+pub extern "Rust" fn gbl_print(s: &dyn core::fmt::Display) {
+    print!("{}", s);
+}
diff --git a/gbl/libc/include/gbl/print.h b/gbl/libc/include/gbl/print.h
new file mode 100644
index 0000000..749dad7
--- /dev/null
+++ b/gbl/libc/include/gbl/print.h
@@ -0,0 +1,38 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef __GBL_PRINT_H__
+#define __GBL_PRINT_H__
+
+#include <stdarg.h>
+
+#ifdef __cplusplus
+extern "C" {
+#endif
+
+// GBL-speicifc function to expose print implementation to 3d party C code.
+// Implementation: libc/src/print.c
+void gbl_printf(const char* fmt, va_list args);
+
+// Printing back-end functions to be used by `gbl_printf`.
+// Implementation: libc/src/print.rs
+void gbl_print_string(const char* s);
+
+#ifdef __cplusplus
+}
+#endif
+
+#endif
diff --git a/gbl/libc/include/limits.h b/gbl/libc/include/limits.h
new file mode 100644
index 0000000..fda0a0f
--- /dev/null
+++ b/gbl/libc/include/limits.h
@@ -0,0 +1,24 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#ifndef __STDLIB_LIMITS_H__
+#define __STDLIB_LIMITS_H__
+
+#define LLONG_MAX ((long long)(~0ULL >> 1))
+#define LLONG_MIN (-LLONG_MAX - 1)
+#define ULLONG_MAX (~0ULL)
+
+#endif
diff --git a/gbl/libc/src/format.c b/gbl/libc/src/format.c
new file mode 100644
index 0000000..c62e351
--- /dev/null
+++ b/gbl/libc/src/format.c
@@ -0,0 +1,344 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+// Minimal format string implementation used by GBL to provide printing
+// functionality to third-party C code. Currently used by:
+//
+//   1. `external/libufdt` via `dto_print()`
+//   2. `external/avb/libavb` via `avb_printf()`
+//
+// Because this implementation is used by a limited set of consumers, it
+// provides a simplified format parser that meets the current requirements. The
+// integrator must ensure it remains sufficient for any new use cases.
+//
+// Current functionality is based on the format string specification:
+// (https://cplusplus.com/reference/cstdio/printf/)
+//
+//   %[flags][width][precision][length modifier][conversion specifier]
+//
+//   - flags: not supported (skipped by `skip_flags`)
+//   - width: not supported (skipped by `skip_width`)
+//   - precision: not supported (skipped by `skip_precision`)
+//   - length modifier: all are supported (l, ll, h, hh, z, etc.)
+//   - conversion specifier:
+//       * signed numeric values (i, d)
+//       * unsigned numeric values (u, o, x)
+//       * characters (c)
+//       * nul-terminated strings (s)
+//     Others are not supported (undefined behaviour).
+//
+// TODO(b/394149272): Support floating pointers formatting.
+//
+// The maximum supported output length is 2048 bytes (see `PRINT_BUFFER_SIZE`).
+// Any additional content is silently truncated.
+
+#include <limits.h>
+#include <stddef.h>
+#include <stdint.h>
+#include <stdlib.h>
+#include <string.h>
+
+#include "gbl/print.h"
+
+// Maximum amount of characters can be printed at once. The rest of symbols
+// are getting silently cut.
+#define PRINT_BUFFER_SIZE 2048
+
+#define NUMBER_ALPHABET "0123456789abcdef"
+
+#define BASE_DEC 10U
+#define BASE_OCT 8U
+#define BASE_HEX 16U
+
+#define FLAGS_LONG (1U << 0U)
+#define FLAGS_LONG_LONG (1U << 1U)
+#define FLAGS_CHAR (1U << 2U)
+#define FLAGS_SHORT (1U << 3U)
+
+#define ULL_MAX_DIGITS 20
+
+// Formats unsigned `value` in base `base` into `buffer`.
+//
+// Returns number of characters written to the result buffer.
+static size_t format_number_unsigned(unsigned long long value, char *buffer,
+                                     size_t buffer_len, unsigned int base) {
+  if (buffer_len == 0) return 0;
+
+  if (value == 0) {
+    buffer[0] = '0';
+    return 1;
+  }
+
+  char tmp[ULL_MAX_DIGITS];
+  int tmp_pos = 0;
+
+  // Convert number to reversed string
+  while (value > 0) {
+    tmp[tmp_pos++] = NUMBER_ALPHABET[value % base];
+    value /= base;
+  }
+
+  // Copy reversed number to buffer
+  size_t used = 0;
+  for (int i = tmp_pos - 1; i >= 0 && used < buffer_len; i--) {
+    buffer[used++] = tmp[i];
+  }
+
+  return used;
+}
+
+// Formats signed `value` in base `base` into `buffer`.
+//
+// Returns number of characters written to the result buffer.
+static size_t format_number_signed(long long value, char *buffer,
+                                   size_t buffer_len, unsigned int base) {
+  size_t used = 0;
+  unsigned long long abs = 0;
+
+  if (value < 0) {
+    if (used < buffer_len) {
+      buffer[used++] = '-';
+    }
+    abs = value == LLONG_MIN ? (unsigned long long)(-(value + 1)) + 1 : -value;
+  } else {
+    abs = value;
+  }
+
+  return used +
+         format_number_unsigned(abs, buffer + used, buffer_len - used, base);
+}
+
+// Formats nul-terminated string `s` into `buffer`.
+//
+// Returns number of characters written to the result buffer.
+static size_t format_string(const char *s, char *buffer, size_t buffer_len) {
+  size_t used = 0;
+  while (*s && used < buffer_len) {
+    buffer[used++] = *s++;
+  }
+  return used;
+}
+
+// Formats a single character `c` into `buffer`.
+//
+// Returns number of characters written to the result buffer.
+static size_t format_character(char c, char *buffer, size_t buffer_len) {
+  size_t used = 0;
+  if (buffer_len) {
+    buffer[used++] = c;
+  }
+  return used;
+}
+
+// Noop implementation of the number format used in both width and precision
+// segments to represent the number. Can be asterisk symbol or dec number.
+//
+// Returns number of processed symbols in the format string.
+static size_t skip_format_number(const char *fmt) {
+  if (*fmt == '*') return 1;
+
+  size_t used = 0;
+  while (*fmt >= '0' && *fmt <= '9') {
+    fmt++;
+    used++;
+  }
+  return used;
+}
+
+// Width segment isn't supported by this implementation. It's getting parsed,
+// but ignored.
+//
+// Returns number of processed symbols in the format string.
+static size_t skip_width(const char *fmt) { return skip_format_number(fmt); }
+
+// Precision segment isn't supported by this implementation. It's getting
+// parsed, but ignored.
+//
+// Returns number of processed symbols in the format string.
+static size_t skip_precision(const char *fmt) {
+  if (*fmt == '.') {
+    return 1 + skip_format_number(fmt + 1);
+  }
+  return 0;
+}
+
+// Format flags aren't supported by this implementation. They are getting
+// parsed, but ignored. Skipped symbols: '-', '+', ' ', '#', '0'.
+//
+// Returns number of processed symbols in the format string.
+static size_t skip_flags(const char *fmt) {
+  size_t used = 0;
+  while (strchr("-+ #0", *fmt) != NULL) {
+    fmt++;
+    used++;
+  }
+  return used;
+}
+
+// Parse length modifiers flags.
+//
+// Returns number of processed symbols in the format string.
+static size_t parse_length_modifiers(const char *fmt, unsigned int *out_flags) {
+  size_t used = 0;
+  switch (*fmt) {
+    case 'l':
+      *out_flags = FLAGS_LONG;
+      used++;
+      fmt++;
+      if (*fmt == 'l') {
+        *out_flags = FLAGS_LONG_LONG;
+        used++;
+      }
+      break;
+    case 'h':
+      *out_flags = FLAGS_SHORT;
+      used++;
+      fmt++;
+      if (*fmt == 'h') {
+        *out_flags = FLAGS_CHAR;
+        used++;
+      }
+      break;
+    case 'z':
+      *out_flags =
+          sizeof(size_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG;
+      used++;
+      break;
+    case 'j':
+      *out_flags |=
+          sizeof(intmax_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG;
+      used++;
+      break;
+    case 't':
+      *out_flags |=
+          sizeof(ptrdiff_t) == sizeof(long) ? FLAGS_LONG : FLAGS_LONG_LONG;
+      used++;
+      break;
+  }
+  return used;
+}
+
+// Appends an error message into `buffer` to handle unsupported format string
+// symbol error.
+//
+// Returns number of processed symbols in the error message.
+static size_t append_cannot_handle_error(char *buffer, size_t buffer_len,
+                                         char current) {
+  size_t used = 0;
+  used += format_string(
+      "GBL print implementation cannot handle format string at symbol: ",
+      buffer, buffer_len);
+  used += format_character(current, buffer + used, buffer_len - used);
+  return used;
+}
+
+// Format `fmt` into `buffer` using provided `args`.
+//
+// Only `buffer_len` bytes will be formatted. The rest of `fmt` string and
+// provided `args` will be ignored.
+static void gbl_printf_buffer(const char *fmt, va_list args, char *buffer,
+                              size_t buffer_len) {
+  // Ensure can nul terminate.
+  const size_t buffer_available = buffer_len - 1;
+
+  size_t i = 0;
+  while (*fmt && i < buffer_available) {
+    if (*fmt == '%') {
+      // %% case
+      if (*(fmt + 1) == '%') {
+        // Skip one % to print another.
+        fmt++;
+      } else {
+        unsigned int base = BASE_DEC;
+        unsigned int flags = 0;
+        fmt++;
+
+        fmt += skip_flags(fmt);
+        fmt += skip_width(fmt);
+        fmt += skip_precision(fmt);
+        fmt += parse_length_modifiers(fmt, &flags);
+
+        switch (*fmt) {
+          case 's':
+            i += format_string(va_arg(args, char *), buffer + i,
+                               buffer_available - i);
+            fmt++;
+            continue;
+          case 'o':
+          case 'x':
+          case 'u':
+            switch (*fmt) {
+              case 'o':
+                base = BASE_OCT;
+                break;
+              case 'x':
+                base = BASE_HEX;
+                break;
+            }
+            if (flags & FLAGS_LONG_LONG) {
+              i += format_number_unsigned(va_arg(args, unsigned long long),
+                                          buffer + i, buffer_available - i,
+                                          base);
+            } else if (flags & FLAGS_LONG) {
+              i += format_number_unsigned(va_arg(args, unsigned long),
+                                          buffer + i, buffer_available - i,
+                                          base);
+            } else {
+              i +=
+                  format_number_unsigned(va_arg(args, unsigned int), buffer + i,
+                                         buffer_available - i, base);
+            }
+            fmt++;
+            continue;
+          case 'd':
+          case 'i':
+            if (flags & FLAGS_LONG_LONG) {
+              i += format_number_signed(va_arg(args, long long), buffer + i,
+                                        buffer_available - i, base);
+            } else if (flags & FLAGS_LONG) {
+              i += format_number_signed(va_arg(args, long), buffer + i,
+                                        buffer_available - i, base);
+            } else {
+              i += format_number_signed(va_arg(args, int), buffer + i,
+                                        buffer_available - i, base);
+            }
+            fmt++;
+            continue;
+          case 'c':
+            i += format_character(va_arg(args, int), buffer + i,
+                                  buffer_available - i);
+            fmt++;
+            break;
+          default:
+            i += append_cannot_handle_error(buffer + i, buffer_available - i,
+                                            *fmt);
+            goto out;
+        }
+      }
+    }
+    buffer[i++] = *fmt++;
+  }
+
+out:
+  buffer[i] = 0;
+}
+
+// Generic output format implementation to be exposed to 3d party C code.
+void gbl_printf(const char *fmt, va_list args) {
+  char output_buffer[PRINT_BUFFER_SIZE];
+  gbl_printf_buffer(fmt, args, output_buffer, sizeof(output_buffer));
+  gbl_print_string(output_buffer);
+}
diff --git a/gbl/libc/src/format_test.cpp b/gbl/libc/src/format_test.cpp
new file mode 100644
index 0000000..4d0119b
--- /dev/null
+++ b/gbl/libc/src/format_test.cpp
@@ -0,0 +1,196 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+/*
+ * Copyright (C) 2023 The Android Open Source Project
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
+#include <gtest/gtest.h>
+
+#include "gbl/print.h"
+
+// Must be the same value as `PRINT_BUFFER_SIZE` from format.c
+#define MOCK_PRINT_BUFFER_SIZE 2048
+static char print_buffer[MOCK_PRINT_BUFFER_SIZE];
+
+void gbl_print_string(const char* s) {
+  strncpy(print_buffer, s, MOCK_PRINT_BUFFER_SIZE);
+}
+
+void test_gbl_printf(const char* fmt, ...) {
+  va_list args;
+  va_start(args, fmt);
+  gbl_printf(fmt, args);
+  va_end(args);
+}
+
+TEST(PrintfTest, FormatString) {
+  test_gbl_printf("before %s after", "text");
+  ASSERT_STREQ("before text after", print_buffer);
+}
+
+TEST(PrintfTest, FormatInt) {
+  test_gbl_printf("before %d after", 100);
+  ASSERT_STREQ("before 100 after", print_buffer);
+}
+
+TEST(PrintfTest, FormatChar) {
+  test_gbl_printf("char value: %c", 'a');
+  ASSERT_STREQ("char value: a", print_buffer);
+}
+
+TEST(PrintfTest, FormatCharAsciiCode) {
+  test_gbl_printf("char value: %hhd", 'a');
+  ASSERT_STREQ("char value: 97", print_buffer);
+}
+
+TEST(PrintfTest, FormatUnsigned) {
+  test_gbl_printf("Unsigned value: %u", 123456789U);
+  ASSERT_STREQ("Unsigned value: 123456789", print_buffer);
+}
+
+TEST(PrintfTest, FormatOctal) {
+  test_gbl_printf("Octal value: %o", 0777);
+  ASSERT_STREQ("Octal value: 777", print_buffer);
+}
+
+TEST(PrintfTest, FormatHex) {
+  test_gbl_printf("Hex value: %x", 0xabcdef);
+  ASSERT_STREQ("Hex value: abcdef", print_buffer);
+}
+
+TEST(PrintfTest, FormatEmptyString) {
+  test_gbl_printf("String: '%s'", "");
+  ASSERT_STREQ("String: ''", print_buffer);
+}
+
+TEST(PrintfTest, FormatMultiple) {
+  test_gbl_printf("Values: %d %u %x %s", -42, 42U, 0x42, "forty-two");
+  ASSERT_STREQ("Values: -42 42 42 forty-two", print_buffer);
+}
+
+TEST(PrintfTest, FormatLongLong) {
+  long long val = 1234567890123LL;
+  test_gbl_printf("Long long: %lld", val);
+  ASSERT_STREQ("Long long: 1234567890123", print_buffer);
+}
+
+TEST(PrintfTest, FormatLLongMin) {
+  long long val = LLONG_MIN;
+  char expected[64];
+  snprintf(expected, sizeof(expected), "LLONG_MIN: %lld", val);
+  test_gbl_printf("LLONG_MIN: %lld", val);
+  ASSERT_STREQ(expected, print_buffer);
+}
+
+TEST(PrintfTest, FormatULLongMax) {
+  unsigned long long val = ULLONG_MAX;
+  char expected[64];
+  snprintf(expected, sizeof(expected), "ULLONG_MAX: %llu", val);
+  test_gbl_printf("ULLONG_MAX: %llu", val);
+  ASSERT_STREQ(expected, print_buffer);
+}
+
+TEST(PrintfTest, FormatUnknownSpecifierErrorAppended) {
+  test_gbl_printf("Unknown specifier: %q");
+  ASSERT_STREQ(
+      "Unknown specifier: GBL print implementation cannot handle format string "
+      "at symbol: q",
+      print_buffer);
+}
+
+TEST(PrintfTest, FormatPercent) {
+  test_gbl_printf("percent: %%");
+  ASSERT_STREQ("percent: %", print_buffer);
+}
+
+TEST(PrintfTest, FormatIntNegative) {
+  test_gbl_printf("before %d after", -100);
+  ASSERT_STREQ("before -100 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipWidthZeroFlag) {
+  test_gbl_printf("before %08d after", 42);
+  ASSERT_STREQ("before 42 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipPrecisionInt) {
+  test_gbl_printf("before %.5d after", 2025);
+  ASSERT_STREQ("before 2025 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipComplexFlagsInt) {
+  test_gbl_printf("before %-015.6d after", -999);
+  ASSERT_STREQ("before -999 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipDynamicWidth) {
+  test_gbl_printf("before %*d after", 77);
+  ASSERT_STREQ("before 77 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipDynamicPrecision) {
+  test_gbl_printf("before %.*d after", 123);
+  ASSERT_STREQ("before 123 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipFlagsString) {
+  test_gbl_printf("before %-+#5.8s after", "TestMe!");
+  ASSERT_STREQ("before TestMe! after", print_buffer);
+}
+
+TEST(PrintfTest, SkipPlusFlag) {
+  test_gbl_printf("before %+d after", 100);
+  ASSERT_STREQ("before 100 after", print_buffer);
+}
+
+TEST(PrintfTest, SkipSpaceFlag) {
+  test_gbl_printf("before % d after", 500);
+  ASSERT_STREQ("before 500 after", print_buffer);
+}
+
+TEST(PrintfTest, LongStringIsTruncated) {
+  char long_string[MOCK_PRINT_BUFFER_SIZE + 100];
+  memset(long_string, 'A', sizeof(long_string) - 1);
+  long_string[sizeof(long_string) - 1] = '\0';
+
+  test_gbl_printf("%s", long_string);
+
+  ASSERT_EQ(strlen(print_buffer), MOCK_PRINT_BUFFER_SIZE - 1);
+  for (int i = 0; i < MOCK_PRINT_BUFFER_SIZE - 1; ++i) {
+    ASSERT_EQ(print_buffer[i], 'A') << "Expected character 'A' at index " << i
+                                    << ", but got '" << print_buffer[i] << "'";
+  }
+}
+
+TEST(PrintfTest, MultipleMessages) {
+  test_gbl_printf("First message: %s", "first");
+  ASSERT_STREQ("First message: first", print_buffer);
+  test_gbl_printf("Second message: %s", "second");
+  ASSERT_STREQ("Second message: second", print_buffer);
+}
diff --git a/gbl/libc/src/lib.rs b/gbl/libc/src/lib.rs
index 68301a4..ad039cd 100644
--- a/gbl/libc/src/lib.rs
+++ b/gbl/libc/src/lib.rs
@@ -1,4 +1,4 @@
-// Copyright 2023-2024, The Android Open Source Project
+// Copyright 2023-2025, The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -30,6 +30,7 @@ use safemath::SafeNum;
 
 pub use strcmp::{strcmp, strncmp};
 
+pub mod print;
 pub mod strchr;
 pub mod strcmp;
 pub mod strtoul;
@@ -47,6 +48,17 @@ extern "C" {
     pub fn strlen(s: *const c_char) -> usize;
 }
 
+// Linking the platform-specific functionality expected to be provided by the
+// library/app, which includes the GBL `libc`.
+extern "Rust" {
+    /// GBL `libc` expects user to provide platform-specific text output implementation
+    /// to allow libc to expose it for external C libraries.
+    ///
+    /// A default POSIX-based implementation is available at `libc/deps/posix.rs`.
+    /// An EFI-specific implementation is provided by `libefi/src/libc.rs`.
+    fn gbl_print(d: &dyn core::fmt::Display);
+}
+
 /// Extended version of void *malloc(size_t size) with ptr alignment configuration support.
 /// Libraries may have a different alignment requirements.
 ///
diff --git a/gbl/libc/src/print.rs b/gbl/libc/src/print.rs
new file mode 100644
index 0000000..32c5850
--- /dev/null
+++ b/gbl/libc/src/print.rs
@@ -0,0 +1,40 @@
+// Copyright 2025, The Android Open Source Project
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
+//! This module provides printing back-end functions to be used by GBL format
+//! printing implementation: libc/src/print.c
+
+use crate::gbl_print;
+use core::ffi::{c_char, CStr};
+
+/// Back-end function to print a nul-terminated string.
+///
+/// # Safety:
+///
+/// * `s` must be a valid null-terminated C string.
+#[no_mangle]
+pub unsafe extern "C" fn gbl_print_string(s: *const c_char) {
+    if s.is_null() {
+        return;
+    }
+    // SAFETY: `s` must be a valid nul-terminated C string.
+    let cstr = unsafe { CStr::from_ptr(s) };
+
+    // Safety:
+    // * `gbl_print` is expected to be statically linked and expected
+    // core::fmt::Display compatible types.
+    unsafe {
+        gbl_print(&cstr.to_string_lossy());
+    }
+}
diff --git a/gbl/libdttable/BUILD b/gbl/libdttable/BUILD
index 9313201..6330bb2 100644
--- a/gbl/libdttable/BUILD
+++ b/gbl/libdttable/BUILD
@@ -31,7 +31,7 @@ rust_bindgen(
     name = "libdttable_c_bindgen",
     bindgen_flags = [
         "--use-core",
-        "--with-derive-custom-struct=dt_table.*=AsBytes,FromBytes,FromZeroes,PartialEq",
+        "--with-derive-custom-struct=dt_table.*=IntoBytes,FromBytes,Immutable,KnownLayout,PartialEq",
         "--allowlist-type",
         "(dt_table.*)",
         "--allowlist-var",
@@ -40,7 +40,7 @@ rust_bindgen(
         """
 # ![cfg_attr(not(test), no_std)]
 
-use zerocopy::{AsBytes, FromBytes, FromZeroes};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout};
 """,
     ],
     cc_lib = "@libdttable_c",
diff --git a/gbl/libdttable/src/lib.rs b/gbl/libdttable/src/lib.rs
index 225afa7..3cd32a4 100644
--- a/gbl/libdttable/src/lib.rs
+++ b/gbl/libdttable/src/lib.rs
@@ -21,11 +21,11 @@ use core::mem::size_of;
 use libdttable_bindgen::{dt_table_entry, dt_table_header, DT_TABLE_MAGIC};
 use liberror::{Error, Result};
 use safemath::SafeNum;
-use zerocopy::{AsBytes, FromBytes, FromZeroes, LayoutVerified};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};
 
 /// Rust wrapper for the dt table header
 #[repr(transparent)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
+#[derive(Debug, Copy, Clone, IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq)]
 struct DtTableHeader(dt_table_header);
 
 impl DtTableHeader {
@@ -52,7 +52,7 @@ impl DtTableHeader {
 
 /// Rust wrapper for the dt table entry
 #[repr(transparent)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
+#[derive(Debug, Copy, Clone, Immutable, IntoBytes, KnownLayout, FromBytes, PartialEq)]
 struct DtTableHeaderEntry(dt_table_entry);
 
 impl DtTableHeaderEntry {
@@ -100,8 +100,8 @@ pub struct DtTableEntry<'a> {
 /// Represents entier multidt table image
 pub struct DtTableImage<'a> {
     buffer: &'a [u8],
-    header: LayoutVerified<&'a [u8], DtTableHeader>,
-    entries: LayoutVerified<&'a [u8], [DtTableHeaderEntry]>,
+    header: Ref<&'a [u8], DtTableHeader>,
+    entries: Ref<&'a [u8], [DtTableHeaderEntry]>,
 }
 
 /// To iterate over entries.
@@ -127,7 +127,7 @@ impl<'a> Iterator for DtTableImageIterator<'a> {
 impl<'a> DtTableImage<'a> {
     /// Verify and parse passed buffer following multidt table structure
     pub fn from_bytes(buffer: &'a [u8]) -> Result<DtTableImage<'a>> {
-        let (header_layout, _) = LayoutVerified::new_from_prefix(buffer)
+        let (header_layout, _) = Ref::new_from_prefix(buffer)
             .ok_or(Error::BufferTooSmall(Some(size_of::<DtTableHeader>())))?;
 
         let header: &DtTableHeader = &header_layout;
@@ -145,8 +145,7 @@ impl<'a> DtTableImage<'a> {
         let entries_buffer = buffer
             .get(entries_start..entries_end)
             .ok_or(Error::BufferTooSmall(Some(entries_end)))?;
-        let entries_layout =
-            LayoutVerified::new_slice(entries_buffer).ok_or(Error::InvalidInput)?;
+        let entries_layout = Ref::new_slice(entries_buffer).ok_or(Error::InvalidInput)?;
 
         Ok(DtTableImage { buffer: buffer, header: header_layout, entries: entries_layout })
     }
diff --git a/gbl/libefi/BUILD b/gbl/libefi/BUILD
index 56feebf..21d33c9 100644
--- a/gbl/libefi/BUILD
+++ b/gbl/libefi/BUILD
@@ -29,6 +29,7 @@ rust_library(
         "@gbl//libasync",
         "@gbl//libefi_types",
         "@gbl//liberror",
+        "@gbl//libfastboot",
         "@gbl//libgbl",
         "@gbl//libsafemath",
         "@gbl//libstorage",
diff --git a/gbl/libefi/mocks/lib.rs b/gbl/libefi/mocks/lib.rs
index 222bd7b..7c83859 100644
--- a/gbl/libefi/mocks/lib.rs
+++ b/gbl/libefi/mocks/lib.rs
@@ -22,12 +22,15 @@
 pub mod protocol;
 pub mod utils;
 
-use efi_types::{EfiConfigurationTable, EfiTimerDelay};
+use efi_types::{EfiConfigurationTable, EfiGuid, EfiTimerDelay};
 use liberror::Result;
 use mockall::mock;
 use protocol::{
+    dt_fixup::DtFixupProtocol,
     gbl_efi_ab_slot::GblSlotProtocol,
     gbl_efi_avb::GblAvbProtocol,
+    gbl_efi_fastboot::GblFastbootProtocol,
+    gbl_efi_os_configuration::GblOsConfigurationProtocol,
     simple_text_output::{passthrough_con_out, MockSimpleTextOutputProtocol},
 };
 use std::cell::RefCell;
@@ -246,6 +249,21 @@ fn passthrough_boot_services() -> MockBootServices {
             efi.as_mut().unwrap().boot_services.find_first_and_open::<GblSlotProtocol>()
         })
     });
+    services.expect_find_first_and_open::<GblFastbootProtocol>().returning(|| {
+        MOCK_EFI.with_borrow_mut(|efi| {
+            efi.as_mut().unwrap().boot_services.find_first_and_open::<GblFastbootProtocol>()
+        })
+    });
+    services.expect_find_first_and_open::<GblOsConfigurationProtocol>().returning(|| {
+        MOCK_EFI.with_borrow_mut(|efi| {
+            efi.as_mut().unwrap().boot_services.find_first_and_open::<GblOsConfigurationProtocol>()
+        })
+    });
+    services.expect_find_first_and_open::<DtFixupProtocol>().returning(|| {
+        MOCK_EFI.with_borrow_mut(|efi| {
+            efi.as_mut().unwrap().boot_services.find_first_and_open::<DtFixupProtocol>()
+        })
+    });
 
     services
 }
@@ -269,6 +287,9 @@ mock! {
     pub RuntimeServices {
         /// Performs a cold reset.
         pub fn cold_reset(&self);
+
+        /// Gets EFI variable.
+        pub fn get_variable(&self, guid: &EfiGuid, name: &str, out: &mut [u8]) -> Result<usize>;
     }
 }
 
@@ -276,7 +297,7 @@ mock! {
 pub type RuntimeServices = MockRuntimeServices;
 
 #[cfg(test)]
-pub mod test {
+mod test {
     use super::*;
     use mockall::predicate::eq;
     use std::fmt::Write;
diff --git a/gbl/libefi/mocks/protocol.rs b/gbl/libefi/mocks/protocol.rs
index 07206ba..e32231a 100644
--- a/gbl/libefi/mocks/protocol.rs
+++ b/gbl/libefi/mocks/protocol.rs
@@ -20,7 +20,7 @@
 use crate::{DeviceHandle, MOCK_EFI};
 use core::ffi::CStr;
 use core::fmt::Write;
-use efi::protocol::gbl_efi_image_loading::EfiImageBuffer;
+pub use efi::protocol::gbl_efi_image_loading::EfiImageBufferInfo;
 use efi_types::{
     EfiInputKey, GblEfiAvbKeyValidationStatus, GblEfiAvbVerificationResult, GblEfiImageInfo,
     GblEfiPartitionName, GblEfiVerifiedDeviceTree,
@@ -131,11 +131,13 @@ pub mod simple_text_output {
 pub mod gbl_efi_image_loading {
     use super::*;
 
+    pub use efi::protocol::gbl_efi_image_loading::EfiImageBufferInfo;
+
     mock! {
         /// Mock [efi::ImageLoadingProtocol].
         pub GblImageLoadingProtocol {
             /// Returns [EfiImageBuffer] matching `gbl_image_info`
-            pub fn get_buffer(&self, gbl_image_info: &GblEfiImageInfo) -> Result<EfiImageBuffer>;
+            pub fn get_buffer(&self, gbl_image_info: &GblEfiImageInfo) -> Result<EfiImageBufferInfo>;
 
             /// Returns number of partitions to be provided via `get_verify_partitions()`, and thus
             /// expected size of `partition_name` slice.
@@ -164,7 +166,7 @@ pub mod gbl_efi_os_configuration {
             pub fn fixup_kernel_commandline(
                 &self,
                 commandline: &CStr,
-                fixup: &[u8],
+                fixup: &mut [u8],
             ) -> Result<()>;
 
             /// Wraps `GBL_EFI_OS_CONFIGURATION_PROTOCOL.fixup_bootconfig()`
diff --git a/gbl/libefi/mocks/utils.rs b/gbl/libefi/mocks/utils.rs
index b3d9a75..96049cd 100644
--- a/gbl/libefi/mocks/utils.rs
+++ b/gbl/libefi/mocks/utils.rs
@@ -15,6 +15,7 @@
 //! Mock utils.
 
 use crate::MockEfiEntry;
+use core::time::Duration;
 use liberror::Result;
 use mockall::mock;
 
@@ -22,11 +23,11 @@ mock! {
     /// Mock [efi::utils::Timeout].
     pub Timeout {
         /// Creates a new [MockTimeout].
-        pub fn new(efi_entry: &MockEfiEntry, timeout_ms: u64) -> Result<Self>;
+        pub fn new(efi_entry: &MockEfiEntry, timeout: Duration) -> Result<Self>;
         /// Checks the timeout.
         pub fn check(&self) -> Result<bool>;
         /// Resets the timeout.
-        pub fn reset(&self, timeout_ms: u64) -> Result<()>;
+        pub fn reset(&self, timeout: Duration) -> Result<()>;
     }
 }
 /// Map to the libefi name so code under test can just use one name.
diff --git a/gbl/libefi/src/allocation.rs b/gbl/libefi/src/allocation.rs
index 03a27b0..80324ca 100644
--- a/gbl/libefi/src/allocation.rs
+++ b/gbl/libefi/src/allocation.rs
@@ -64,6 +64,8 @@ impl EfiState {
 // This is a bit ugly, but we only expect this library to be used by our EFI application so it
 // doesn't need to be super clean or scalable. The user has to declare the global variable
 // exactly as written in the [EfiAllocator] docs for this to link properly.
+//
+// TODO(b/396460116): Investigate using Mutex for the variable.
 extern "Rust" {
     static mut EFI_GLOBAL_ALLOCATOR: EfiAllocator;
 }
@@ -78,7 +80,10 @@ pub(crate) fn internal_efi_entry_and_rt(
     // event/notification/interrupt that can be triggered when they are called. This suggests that
     // there cannot be concurrent read and modification on `EFI_GLOBAL_ALLOCATOR` possible. Thus its
     // access is safe from race condition.
-    unsafe { EFI_GLOBAL_ALLOCATOR.get_efi_entry_and_rt() }
+    #[allow(static_mut_refs)]
+    unsafe {
+        EFI_GLOBAL_ALLOCATOR.get_efi_entry_and_rt()
+    }
 }
 
 /// Try to print via `EFI_SIMPLE_TEXT_OUTPUT_PROTOCOL` in `EFI_SYSTEM_TABLE.ConOut`.
@@ -245,16 +250,3 @@ unsafe impl GlobalAlloc for EfiAllocator {
         self.deallocate(real_start_ptr);
     }
 }
-
-/// API for allocating raw memory via EFI_BOOT_SERVICES
-pub fn efi_malloc(size: usize) -> *mut u8 {
-    // SAFETY: See SAFETY of `internal_efi_entry()`.
-    unsafe { EFI_GLOBAL_ALLOCATOR.allocate(size) }
-}
-
-/// API for deallocating raw memory previously allocated by `efi_malloc()`. Passing invalid
-/// pointer will cause the function to panic.
-pub fn efi_free(ptr: *mut u8) {
-    // SAFETY: See SAFETY of `internal_efi_entry()`.
-    unsafe { EFI_GLOBAL_ALLOCATOR.deallocate(ptr) }
-}
diff --git a/gbl/libefi/src/lib.rs b/gbl/libefi/src/lib.rs
index ca862a9..5438913 100644
--- a/gbl/libefi/src/lib.rs
+++ b/gbl/libefi/src/lib.rs
@@ -57,17 +57,23 @@ use alloc::vec::Vec;
 mod allocation;
 
 #[cfg(not(test))]
-pub use allocation::{efi_free, efi_malloc, EfiAllocator};
+pub mod libc;
+
+#[cfg(not(test))]
+pub use allocation::EfiAllocator;
 
 /// The Android EFI protocol implementation of an A/B slot manager.
 pub mod ab_slots;
+/// Local fastboot/bootmenu support.
+pub mod local_session;
+/// Idiomatic wrappers around EFI protocols.
 pub mod protocol;
 pub mod utils;
 
 #[cfg(not(test))]
 use core::{fmt::Write, panic::PanicInfo};
 
-use core::{marker::PhantomData, ptr::null_mut, slice::from_raw_parts};
+use core::{marker::PhantomData, ptr::null_mut, slice::from_raw_parts, time::Duration};
 use efi_types::{
     EfiBootService, EfiConfigurationTable, EfiEvent, EfiGuid, EfiHandle,
     EfiMemoryAttributesTableHeader, EfiMemoryDescriptor, EfiMemoryType, EfiRuntimeService,
@@ -496,11 +502,16 @@ impl<'a> BootServices<'a> {
         &self,
         event: &Event,
         delay_type: EfiTimerDelay,
-        trigger_time: u64,
+        trigger_time: Duration,
     ) -> Result<()> {
         // SAFETY: EFI_BOOT_SERVICES method call.
         unsafe {
-            efi_call!(self.boot_services.set_timer, event.efi_event, delay_type, trigger_time)
+            efi_call!(
+                self.boot_services.set_timer,
+                event.efi_event,
+                delay_type,
+                (trigger_time.as_nanos() / 100).try_into()?
+            )
         }
     }
 }
@@ -722,7 +733,7 @@ impl<'a, 'b> Iterator for EfiMemoryMapIter<'a, 'b> {
         }
         let bytes = &self.memory_map.buffer[self.offset..][..self.memory_map.descriptor_size];
         self.offset += self.memory_map.descriptor_size;
-        Some(Ref::<_, EfiMemoryDescriptor>::new_from_prefix(bytes).unwrap().0.into_ref())
+        Some(Ref::into_ref(Ref::<_, EfiMemoryDescriptor>::new_from_prefix(bytes).unwrap().0))
     }
 }
 
@@ -788,8 +799,9 @@ impl<'a> Iterator for EfiMemoryAttributesTableIter<'a> {
         // pieces greater than struct size. Thus can't just convert buffer to slice of
         // corresponding type.
         if let Some((desc_bytes, tail_new)) = self.tail.split_at_checked(self.descriptor_size) {
-            let desc =
-                Ref::<_, EfiMemoryDescriptor>::new_from_prefix(desc_bytes).unwrap().0.into_ref();
+            let desc = Ref::into_ref(
+                Ref::<_, EfiMemoryDescriptor>::new_from_prefix(desc_bytes).unwrap().0,
+            );
             self.tail = tail_new;
             Some(desc)
         } else {
@@ -944,9 +956,11 @@ mod test {
         EfiBlockIoProtocol, EfiEventNotify, EfiLocateHandleSearchType, EfiStatus, EfiTpl,
         EFI_MEMORY_TYPE_LOADER_CODE, EFI_MEMORY_TYPE_LOADER_DATA, EFI_STATUS_NOT_FOUND,
         EFI_STATUS_NOT_READY, EFI_STATUS_SUCCESS, EFI_STATUS_UNSUPPORTED,
+        EFI_TIMER_DELAY_TIMER_PERIODIC,
     };
     use std::{cell::RefCell, collections::VecDeque, mem::size_of, slice::from_raw_parts_mut};
-    use zerocopy::AsBytes;
+    use utils::RecurringTimer;
+    use zerocopy::IntoBytes;
 
     /// Helper function to generate a Protocol from an interface type.
     pub fn generate_protocol<'a, P: ProtocolInfo>(
@@ -969,6 +983,7 @@ mod test {
         pub create_event_trace: CreateEventTrace,
         pub close_event_trace: CloseEventTrace,
         pub check_event_trace: CheckEventTrace,
+        pub set_timer_trace: SetTimerTrace,
     }
 
     // Declares a global instance of EfiCallTraces.
@@ -1214,6 +1229,28 @@ mod test {
         })
     }
 
+    /// EFI_BOOT_SERVICE.SetTimer.
+    #[derive(Default)]
+    pub struct SetTimerTrace {
+        // Capture call params
+        pub inputs: VecDeque<(EfiEvent, EfiTimerDelay, u64)>,
+        // EfiStatus for return
+        pub outputs: VecDeque<EfiStatus>,
+    }
+
+    /// Mock of the `EFI_BOOT_SERVICE.SetTimer` C API in test environment.
+    extern "C" fn set_timer(
+        event: EfiEvent,
+        delay_type: EfiTimerDelay,
+        duration: u64,
+    ) -> EfiStatus {
+        EFI_CALL_TRACES.with(|trace| {
+            let trace = &mut trace.borrow_mut().set_timer_trace;
+            trace.inputs.push_back((event, delay_type, duration));
+            trace.outputs.pop_front().unwrap()
+        })
+    }
+
     /// A test wrapper that sets up a system table, image handle and runs a test function like it
     /// is an EFI application.
     /// TODO(300168989): Investigate using procedural macro to generate test that auto calls this.
@@ -1235,6 +1272,7 @@ mod test {
         boot_services.create_event = Some(create_event);
         boot_services.close_event = Some(close_event);
         boot_services.check_event = Some(check_event);
+        boot_services.set_timer = Some(set_timer);
         systab.boot_services = &mut boot_services as *mut _;
         let image_handle: usize = 1234; // Don't care.
 
@@ -1638,4 +1676,38 @@ mod test {
             assert!(efi_entry.system_table().boot_services().check_event(&res).is_err());
         });
     }
+
+    #[test]
+    fn test_check_recurring_timer() {
+        run_test(|image_handle, systab_ptr| {
+            let efi_entry = EfiEntry { image_handle, systab_ptr };
+            let event: EfiEvent = 666usize as _;
+
+            EFI_CALL_TRACES.with(|traces| {
+                let mut t = traces.borrow_mut();
+                t.create_event_trace.outputs.push_back(event);
+                t.set_timer_trace.outputs.push_back(EFI_STATUS_SUCCESS);
+                t.check_event_trace.outputs.push_back(EFI_STATUS_SUCCESS);
+            });
+
+            let recurring_timer =
+                RecurringTimer::new(&efi_entry, Duration::from_nanos(2112)).unwrap();
+
+            EFI_CALL_TRACES.with(|traces| {
+                let traces = traces.borrow();
+                assert_eq!(
+                    traces.create_event_trace.inputs,
+                    [(EventType::Timer as _, 0, None, null_mut())]
+                );
+                assert_eq!(
+                    traces.set_timer_trace.inputs,
+                    [(event, EFI_TIMER_DELAY_TIMER_PERIODIC, 21u64)]
+                );
+                // Make sure timer doesn't check itself automatically during construction.
+                assert_eq!(traces.check_event_trace.outputs, [EFI_STATUS_SUCCESS]);
+            });
+
+            assert_eq!(recurring_timer.check(), Ok(true));
+        });
+    }
 }
diff --git a/gbl/libefi/src/libc.rs b/gbl/libefi/src/libc.rs
new file mode 100644
index 0000000..a75f64b
--- /dev/null
+++ b/gbl/libefi/src/libc.rs
@@ -0,0 +1,29 @@
+// Copyright 2025, The Android Open Source Project
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
+//! This module provides platform-specific implementations required by GBL libc.
+//! See `libc/src/lib.rs` for more details.
+//!
+//! This implementation relies on the EFI framework, so can be only used where
+//! it's available.
+
+use crate::efi_try_print;
+use core::fmt::Write;
+use liberror::Result;
+
+/// EFI framework-based print implementation required by GBL `libc`.
+#[no_mangle]
+pub extern "Rust" fn gbl_print(s: &dyn core::fmt::Display) {
+    efi_try_print!("{}", s);
+}
diff --git a/gbl/libefi/src/local_session.rs b/gbl/libefi/src/local_session.rs
new file mode 100644
index 0000000..b2d6638
--- /dev/null
+++ b/gbl/libefi/src/local_session.rs
@@ -0,0 +1,59 @@
+// Copyright 2025, The Android Open Source Project
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
+use crate::{
+    protocol::{
+        gbl_efi_fastboot::{GblFastbootProtocol, LocalSessionContext},
+        Protocol,
+    },
+    utils::RecurringTimer,
+    EfiEntry,
+};
+use core::time::Duration;
+use fastboot::local_session::LocalSession;
+use liberror::Result;
+
+/// Represents a local, usually graphically driven fastboot/bootmenu session.
+pub struct LocalFastbootSession<'a> {
+    timer: RecurringTimer<'a>,
+    protocol: Protocol<'a, GblFastbootProtocol>,
+    context: LocalSessionContext,
+}
+
+impl<'a> LocalFastbootSession<'a> {
+    /// Starts a local fastboot session.
+    pub fn start(efi_entry: &'a EfiEntry, timeout: Duration) -> Result<Self> {
+        let timer = RecurringTimer::new(efi_entry, timeout)?;
+        let protocol = efi_entry
+            .system_table()
+            .boot_services()
+            .find_first_and_open::<GblFastbootProtocol>()?;
+        let context = protocol.start_local_session()?;
+        Ok(Self { timer, protocol, context })
+    }
+}
+
+impl LocalSession for LocalFastbootSession<'_> {
+    async fn update(&mut self, buf: &mut [u8]) -> Result<usize> {
+        self.timer.wait().await?;
+        let bufsize = self.protocol.update_local_session(&self.context, buf)?;
+        Ok(bufsize)
+    }
+}
+
+impl Drop for LocalFastbootSession<'_> {
+    fn drop(&mut self) {
+        let _ = self.protocol.close_local_session(&self.context);
+    }
+}
diff --git a/gbl/libefi/src/protocol/gbl_efi_fastboot.rs b/gbl/libefi/src/protocol/gbl_efi_fastboot.rs
index e50c74d..47c4e18 100644
--- a/gbl/libefi/src/protocol/gbl_efi_fastboot.rs
+++ b/gbl/libefi/src/protocol/gbl_efi_fastboot.rs
@@ -20,7 +20,7 @@ use crate::{
 };
 use core::{
     ffi::{c_char, c_void, CStr},
-    ptr::null,
+    ptr::{null, null_mut},
     slice::from_raw_parts,
     str::from_utf8,
 };
@@ -42,6 +42,9 @@ impl ProtocolInfo for GblFastbootProtocol {
         EfiGuid::new(0xc67e48a0, 0x5eb8, 0x4127, [0xbe, 0x89, 0xdf, 0x2e, 0xd9, 0x3d, 0x8a, 0x9a]);
 }
 
+/// Wrapper type for context parameter used in a fastboot local session.
+pub struct LocalSessionContext(*mut c_void);
+
 impl Protocol<'_, GblFastbootProtocol> {
     /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.get_var`
     pub fn get_var<'a>(
@@ -209,6 +212,45 @@ impl Protocol<'_, GblFastbootProtocol> {
         Ok(permissions)
     }
 
+    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.start_local_session()`
+    pub fn start_local_session(&self) -> Result<LocalSessionContext> {
+        let mut ctx = null_mut();
+        // SAFETY:
+        // `self.interface()?` guarantees self.interface is non-null and points to a valid object
+        // established by `Protocol::new()`.
+        // No parameters are retained, all parameters outlive the call, and no pointers are Null.
+        unsafe { efi_call!(self.interface()?.start_local_session, self.interface, &mut ctx)? };
+        Ok(LocalSessionContext(ctx))
+    }
+
+    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.update_local_session()`
+    pub fn update_local_session(&self, ctx: &LocalSessionContext, out: &mut [u8]) -> Result<usize> {
+        let mut bufsize = out.len();
+
+        // SAFETY:
+        // `self.interface()?` guarantees self.interface is non-null and points to a valid object
+        // established by `Protocol::new()`.
+        // No parameters are retained, all parameters outlive the call, and no pointers are Null.
+        unsafe {
+            efi_call!(
+                @bufsize bufsize,
+                self.interface()?.update_local_session,
+                self.interface,
+                ctx.0, out.as_mut_ptr(),
+                &mut bufsize)?
+        };
+        Ok(bufsize)
+    }
+
+    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.close_local_session()`
+    pub fn close_local_session(&self, ctx: &LocalSessionContext) -> Result<()> {
+        // SAFETY:
+        // `self.interface()?` guarantees self.interface is non-null and points to a valid object
+        // established by `Protocol::new()`.
+        // No parameters are retained, all parameters outlive the call, and no pointers are Null.
+        unsafe { efi_call!(self.interface()?.close_local_session, self.interface, ctx.0) }
+    }
+
     /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.wipe_user_data()`
     pub fn wipe_user_data(&self) -> Result<()> {
         // SAFETY:
@@ -218,6 +260,19 @@ impl Protocol<'_, GblFastbootProtocol> {
         unsafe { efi_call!(self.interface()?.wipe_user_data, self.interface) }
     }
 
+    /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.should_stop_in_fastboot()`
+    pub fn should_stop_in_fastboot(&self) -> bool {
+        let Ok(interface) = self.interface() else { return false };
+
+        let Some(should_stop_in_fastboot) = interface.should_stop_in_fastboot else { return false };
+        // SAFETY:
+        // `self.interface` is non-null due to check above.
+        // `self.interface` is an input parameter and will not be retained. It outlives the call.
+        // `should_stop_in_fastboot` is non-null due to check above.
+        // `should_stop_in_fastboot` is responsible for validating its input.
+        unsafe { should_stop_in_fastboot(self.interface) }
+    }
+
     /// Wrapper of `GBL_EFI_FASTBOOT_PROTOCOL.serial_number`
     pub fn serial_number(&self) -> Result<&str> {
         let serial_number = &self.interface()?.serial_number;
@@ -237,10 +292,11 @@ mod test {
     use crate::{
         protocol::GetVarAllCallback,
         test::{generate_protocol, run_test},
-        EfiEntry,
+        DeviceHandle, EfiEntry,
     };
     use core::{
         ffi::{c_void, CStr},
+        ptr::null_mut,
         slice::from_raw_parts_mut,
     };
     use efi_types::{EfiStatus, EFI_STATUS_SUCCESS};
@@ -411,4 +467,46 @@ mod test {
             assert_eq!(out, ["<Number of arguments exceeds limit>: "])
         });
     }
+
+    #[test]
+    fn test_should_stop_in_fastboot() {
+        unsafe extern "C" fn test_should_stop_in_fastboot(_: *mut GblEfiFastbootProtocol) -> bool {
+            true
+        }
+        run_test(|image_handle, systab_ptr| {
+            let mut fb = GblEfiFastbootProtocol {
+                should_stop_in_fastboot: Some(test_should_stop_in_fastboot),
+                ..Default::default()
+            };
+            let efi_entry = EfiEntry { image_handle, systab_ptr };
+            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);
+            assert!(protocol.should_stop_in_fastboot());
+        });
+    }
+
+    #[test]
+    fn test_should_stop_in_fastboot_no_interface() {
+        run_test(|image_handle, systab_ptr| {
+            let efi_entry = EfiEntry { image_handle, systab_ptr };
+            // SAFETY: `protocol.interface` is explicitly null for testing.
+            let protocol = unsafe {
+                Protocol::<GblFastbootProtocol>::new(
+                    DeviceHandle::new(null_mut()),
+                    null_mut(),
+                    &efi_entry,
+                )
+            };
+            assert!(!protocol.should_stop_in_fastboot());
+        });
+    }
+
+    #[test]
+    fn test_should_stop_in_fastboot_no_method() {
+        run_test(|image_handle, systab_ptr| {
+            let mut fb: GblEfiFastbootProtocol = Default::default();
+            let efi_entry = EfiEntry { image_handle, systab_ptr };
+            let protocol = generate_protocol::<GblFastbootProtocol>(&efi_entry, &mut fb);
+            assert!(!protocol.should_stop_in_fastboot());
+        });
+    }
 }
diff --git a/gbl/libefi/src/protocol/gbl_efi_fastboot_usb.rs b/gbl/libefi/src/protocol/gbl_efi_fastboot_usb.rs
index 7b37ef7..7c3e385 100644
--- a/gbl/libefi/src/protocol/gbl_efi_fastboot_usb.rs
+++ b/gbl/libefi/src/protocol/gbl_efi_fastboot_usb.rs
@@ -19,6 +19,7 @@ use crate::{
     utils::with_timeout,
     {efi_call, Event},
 };
+use core::time::Duration;
 use efi_types::{EfiGuid, GblEfiFastbootUsbProtocol};
 use gbl_async::yield_now;
 use liberror::{Error, Result};
@@ -130,8 +131,8 @@ impl Protocol<'_, GblFastbootUsbProtocol> {
     }
 
     /// Sends a packet over the USB.
-    pub async fn send_packet(&self, data: &[u8], timeout_ms: u64) -> Result<()> {
+    pub async fn send_packet(&self, data: &[u8], timeout: Duration) -> Result<()> {
         self.fastboot_usb_send(data)?;
-        with_timeout(self.efi_entry(), self.wait_send(), timeout_ms).await?.ok_or(Error::Timeout)?
+        with_timeout(self.efi_entry(), self.wait_send(), timeout).await?.ok_or(Error::Timeout)?
     }
 }
diff --git a/gbl/libefi/src/protocol/gbl_efi_image_loading.rs b/gbl/libefi/src/protocol/gbl_efi_image_loading.rs
index f832322..15c5e93 100644
--- a/gbl/libefi/src/protocol/gbl_efi_image_loading.rs
+++ b/gbl/libefi/src/protocol/gbl_efi_image_loading.rs
@@ -49,6 +49,33 @@ pub struct EfiImageBuffer {
     buffer: Option<&'static mut [MaybeUninit<u8>]>,
 }
 
+/// Represents either static reserved memory space or memory to be allocated dynamically.
+#[derive(Debug)]
+pub enum EfiImageBufferInfo {
+    /// Static memory space returned from UEFI firmware.
+    Buffer(EfiImageBuffer),
+    /// Target buffer should be dynamically allocated by the given size.
+    AllocSize(usize),
+}
+
+impl EfiImageBufferInfo {
+    /// Gets as EfiImageBuffer::Buffer;
+    pub fn buffer(&mut self) -> Option<&mut [MaybeUninit<u8>]> {
+        match self {
+            Self::Buffer(EfiImageBuffer { buffer: Some(v) }) => Some(v),
+            _ => None,
+        }
+    }
+
+    /// Move buffer ownership out of EfiImageBuffer, and consume it.
+    pub fn take(self) -> Option<&'static mut [MaybeUninit<u8>]> {
+        match self {
+            Self::Buffer(mut v) => Some(v.take()),
+            _ => None,
+        }
+    }
+}
+
 impl EfiImageBuffer {
     // # Safety
     //
@@ -73,7 +100,7 @@ impl EfiImageBuffer {
         returned_buffers.push(addr);
 
         // SAFETY:
-        // `gbl_buffer.Memory` is guarantied to be not null
+        // `gbl_buffer.Memory` is guaranteed to be not null
         // This code is relying on EFI protocol implementation to provide valid buffer pointer
         // to memory region of size `gbl_buffer.SizeBytes`.
         Ok(EfiImageBuffer {
@@ -87,7 +114,7 @@ impl EfiImageBuffer {
     }
 
     /// Move buffer ownership out of EfiImageBuffer, and consume it.
-    pub fn take(mut self) -> &'static mut [MaybeUninit<u8>] {
+    pub fn take(&mut self) -> &'static mut [MaybeUninit<u8>] {
         self.buffer.take().unwrap()
     }
 
@@ -133,7 +160,7 @@ impl Protocol<'_, GblImageLoadingProtocol> {
     /// Err(Error::EFI_STATUS_INVALID_PARAMETER) if received buffer is NULL
     /// Err(Error::EFI_STATUS_ALREADY_STARTED) buffer was already returned and is still in use.
     /// Err(err) if `err` occurred
-    pub fn get_buffer(&self, gbl_image_info: &GblEfiImageInfo) -> Result<EfiImageBuffer> {
+    pub fn get_buffer(&self, gbl_image_info: &GblEfiImageInfo) -> Result<EfiImageBufferInfo> {
         let mut gbl_buffer: GblEfiImageBuffer = Default::default();
         // SAFETY:
         // `self.interface()?` guarantees self.interface is non-null and points to a valid object
@@ -154,6 +181,8 @@ impl Protocol<'_, GblImageLoadingProtocol> {
 
         if gbl_buffer.SizeBytes < gbl_image_info.SizeBytes {
             return Err(Error::BufferTooSmall(Some(gbl_image_info.SizeBytes)));
+        } else if gbl_buffer.Memory.is_null() {
+            return Ok(EfiImageBufferInfo::AllocSize(gbl_buffer.SizeBytes));
         }
 
         // SAFETY:
@@ -161,7 +190,7 @@ impl Protocol<'_, GblImageLoadingProtocol> {
         // `gbl_buffer.Size` must be valid size of the buffer.
         // This protocol is relying on EFI protocol implementation to provide valid buffer pointer
         // to memory region of size `gbl_buffer.SizeBytes`.
-        let image_buffer = unsafe { EfiImageBuffer::new(gbl_buffer)? };
+        let image_buffer = EfiImageBufferInfo::Buffer(unsafe { EfiImageBuffer::new(gbl_buffer)? });
 
         Ok(image_buffer)
     }
@@ -785,35 +814,36 @@ mod test {
     }
 
     #[test]
-    fn test_proto_get_buffer_not_provided() {
+    fn test_proto_get_buffer_return_alloc_size() {
+        // SAFETY:
+        // * Caler must guarantee that `buffer` points to a valid instance of `GblEfiImageBuffer`.
         unsafe extern "C" fn get_buffer(
             _: *mut GblEfiImageLoadingProtocol,
-            image_info: *const GblEfiImageInfo,
+            _: *const GblEfiImageInfo,
             buffer: *mut GblEfiImageBuffer,
         ) -> EfiStatus {
-            assert!(!image_info.is_null());
-            assert!(!buffer.is_null());
             // SAFETY
-            // `buffer` must be valid pointer to `GblEfiImageBuffer`
+            // By safety requirement of this function, `buffer` points to a valid instance of
+            // `GblEfiImageBuffer`.
             let buffer = unsafe { buffer.as_mut() }.unwrap();
-
             buffer.Memory = null_mut();
-            buffer.SizeBytes = 10;
-
+            buffer.SizeBytes = MEMORY_TEST_BUF_SIZE;
             EFI_STATUS_SUCCESS
         }
 
         run_test(|image_handle, systab_ptr| {
-            let gbl_image_info: GblEfiImageInfo = Default::default();
+            let gbl_image_info: GblEfiImageInfo =
+                GblEfiImageInfo { ImageType: [0; PARTITION_NAME_LEN_U16], SizeBytes: 100 };
             let mut image_loading =
                 GblEfiImageLoadingProtocol { get_buffer: Some(get_buffer), ..Default::default() };
             let efi_entry = EfiEntry { image_handle, systab_ptr };
             let protocol =
                 generate_protocol::<GblImageLoadingProtocol>(&efi_entry, &mut image_loading);
-
             let _memory_guard = MEMORY_TEST.with_borrow_mut(|v| v.start());
-            let res = protocol.get_buffer(&gbl_image_info);
-            assert_eq!(res.unwrap_err(), Error::InvalidInput);
+            assert!(matches!(
+                protocol.get_buffer(&gbl_image_info),
+                Ok(EfiImageBufferInfo::AllocSize(MEMORY_TEST_BUF_SIZE))
+            ));
         });
     }
 
@@ -851,8 +881,8 @@ mod test {
                 generate_protocol::<GblImageLoadingProtocol>(&efi_entry, &mut image_loading);
 
             let _memory_guard = MEMORY_TEST.with_borrow_mut(|v| v.start());
-            let res = protocol.get_buffer(&gbl_image_info).unwrap();
-            assert!(res.buffer.as_ref().unwrap().is_empty());
+            let mut res = protocol.get_buffer(&gbl_image_info).unwrap();
+            assert!(res.buffer().as_ref().unwrap().is_empty());
         });
     }
 
@@ -934,9 +964,9 @@ mod test {
                 generate_protocol::<GblImageLoadingProtocol>(&efi_entry, &mut image_loading);
 
             let _memory_guard = MEMORY_TEST.with_borrow_mut(|v| v.start());
-            let buf = protocol.get_buffer(&gbl_image_info).unwrap();
-            assert_ne!(buf.buffer.as_ref().unwrap().as_ptr(), null_mut());
-            assert_eq!(buf.buffer.as_ref().unwrap().len(), 100);
+            let mut buf = protocol.get_buffer(&gbl_image_info).unwrap();
+            assert_ne!(buf.buffer().as_ref().unwrap().as_ptr(), null_mut());
+            assert_eq!(buf.buffer().as_ref().unwrap().len(), 100);
         });
     }
 
@@ -1107,7 +1137,7 @@ mod test {
                 generate_protocol::<GblImageLoadingProtocol>(&efi_entry, &mut image_loading);
 
             let _memory_guard = MEMORY_TEST.with_borrow_mut(|v| v.start());
-            let mut keep_alive: Vec<EfiImageBuffer> = vec![];
+            let mut keep_alive: Vec<EfiImageBufferInfo> = vec![];
             for _ in 1..=MAX_ARRAY_SIZE + 1 {
                 keep_alive.push(protocol.get_buffer(&gbl_image_info).unwrap());
             }
@@ -1186,7 +1216,7 @@ mod test {
         let _memory_guard = MEMORY_TEST.with_borrow_mut(|v| v.start());
         // SAFETY:
         // 'gbl_buffer` represents valid buffer created by vector.
-        let res1 = unsafe { EfiImageBuffer::new(gbl_buffer) }.unwrap();
+        let mut res1 = unsafe { EfiImageBuffer::new(gbl_buffer) }.unwrap();
         let buf_no_owner = res1.take();
 
         // Since `res1` was taken, we can't reuse same buffer.
diff --git a/gbl/libefi/src/utils.rs b/gbl/libefi/src/utils.rs
index f226687..30aa717 100644
--- a/gbl/libefi/src/utils.rs
+++ b/gbl/libefi/src/utils.rs
@@ -15,16 +15,10 @@
 //! This file provides some utilities built on EFI APIs.
 
 use crate::{EfiEntry, Event, EventType};
-use core::future::Future;
-use efi_types::EFI_TIMER_DELAY_TIMER_RELATIVE;
+use core::{future::Future, time::Duration};
+use efi_types::{EFI_TIMER_DELAY_TIMER_PERIODIC, EFI_TIMER_DELAY_TIMER_RELATIVE};
 use gbl_async::{select, yield_now};
 use liberror::Result;
-use safemath::SafeNum;
-
-/// Converts 1 ms to number of 100 nano seconds
-pub fn ms_to_100ns(ms: u64) -> Result<u64> {
-    Ok((SafeNum::from(ms) * 10 * 1000).try_into()?)
-}
 
 /// `Timeout` provide APIs for checking timeout.
 pub struct Timeout<'a> {
@@ -34,10 +28,10 @@ pub struct Timeout<'a> {
 
 impl<'a> Timeout<'a> {
     /// Creates a new instance and starts the timeout timer.
-    pub fn new(efi_entry: &'a EfiEntry, timeout_ms: u64) -> Result<Self> {
+    pub fn new(efi_entry: &'a EfiEntry, timeout: Duration) -> Result<Self> {
         let bs = efi_entry.system_table().boot_services();
         let timer = bs.create_event(EventType::Timer)?;
-        bs.set_timer(&timer, EFI_TIMER_DELAY_TIMER_RELATIVE, ms_to_100ns(timeout_ms)?)?;
+        bs.set_timer(&timer, EFI_TIMER_DELAY_TIMER_RELATIVE, timeout)?;
         Ok(Self { efi_entry, timer })
     }
 
@@ -47,17 +41,17 @@ impl<'a> Timeout<'a> {
     }
 
     /// Resets the timeout.
-    pub fn reset(&self, timeout_ms: u64) -> Result<()> {
+    pub fn reset(&self, timeout: Duration) -> Result<()> {
         let bs = self.efi_entry.system_table().boot_services();
-        bs.set_timer(&self.timer, EFI_TIMER_DELAY_TIMER_RELATIVE, ms_to_100ns(timeout_ms)?)?;
+        bs.set_timer(&self.timer, EFI_TIMER_DELAY_TIMER_RELATIVE, timeout)?;
         Ok(())
     }
 }
 
 /// Waits for a given amount of time.
-pub async fn wait(efi_entry: &EfiEntry, duration_ms: u64) -> Result<()> {
+pub async fn wait(efi_entry: &EfiEntry, duration: Duration) -> Result<()> {
     // EFI boot service has a `stall` API. But it's not async.
-    let timeout = Timeout::new(efi_entry, duration_ms)?;
+    let timeout = Timeout::new(efi_entry, duration)?;
     while !timeout.check()? {
         yield_now().await;
     }
@@ -74,11 +68,40 @@ pub async fn wait(efi_entry: &EfiEntry, duration_ms: u64) -> Result<()> {
 pub async fn with_timeout<F: Future<Output = R>, R>(
     efi_entry: &EfiEntry,
     fut: F,
-    timeout_ms: u64,
+    timeout: Duration,
 ) -> Result<Option<R>> {
-    let (timeout_res, res) = select(wait(efi_entry, timeout_ms), fut).await;
+    let (timeout_res, res) = select(wait(efi_entry, timeout), fut).await;
     match timeout_res {
         Some(Err(e)) => return Err(e),
         _ => Ok(res),
     }
 }
+
+/// Wrapper helping for a periodic timer.
+pub struct RecurringTimer<'a> {
+    efi_entry: &'a EfiEntry,
+    timer: Event<'a, 'static>,
+}
+
+impl<'a> RecurringTimer<'a> {
+    /// Constructs and starts a new periodic timer.
+    pub fn new(efi_entry: &'a EfiEntry, timeout: Duration) -> Result<Self> {
+        let bs = efi_entry.system_table().boot_services();
+        let timer = bs.create_event(EventType::Timer)?;
+        bs.set_timer(&timer, EFI_TIMER_DELAY_TIMER_PERIODIC, timeout)?;
+        Ok(Self { efi_entry, timer })
+    }
+
+    /// Checks whether the timer has expried.
+    pub fn check(&self) -> Result<bool> {
+        Ok(self.efi_entry.system_table().boot_services().check_event(&self.timer)?)
+    }
+
+    /// Waits asynchronously until the next tick.
+    pub async fn wait(&self) -> Result<()> {
+        while !self.check()? {
+            yield_now().await;
+        }
+        Ok(())
+    }
+}
diff --git a/gbl/libefi_types/BUILD b/gbl/libefi_types/BUILD
index e84d273..b5d7005 100644
--- a/gbl/libefi_types/BUILD
+++ b/gbl/libefi_types/BUILD
@@ -14,6 +14,7 @@
 
 load("@gbl//toolchain:gbl_workspace_util.bzl", "ANDROID_RUST_LINTS")
 load("@gbl_llvm_prebuilts//:info.bzl", "LLVM_PREBUILTS_C_INCLUDE")
+load("@rules_cc//cc:cc_library.bzl", "cc_library")
 load("@rules_rust//bindgen:defs.bzl", "rust_bindgen")
 load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
 
@@ -52,18 +53,18 @@ rust_bindgen(
         "--use-core",
         "--with-derive-partialeq",
         "--with-derive-default",
-        "--with-derive-custom-struct=EfiMemoryDescriptor=AsBytes,FromBytes,FromZeroes",
-        "--with-derive-custom-struct=EfiMemoryAttributesTableHeader=AsBytes,FromBytes,FromZeroes",
+        "--with-derive-custom-struct=EfiMemoryDescriptor=Immutable,IntoBytes,FromBytes,KnownLayout",
+        "--with-derive-custom-struct=EfiMemoryAttributesTableHeader=Immutable,IntoBytes,FromBytes,KnownLayout",
         "--allowlist-type",
         "(Efi.*)|(GblEfi.*)|(GBL_EFI_.*)",
         "--allowlist-var",
-        "PARTITION_NAME_LEN_U16|EFI_.*",
+        "PARTITION_NAME_LEN_U16|EFI_.*|GBL_.*",
         "--raw-line",
         """
 #![allow(non_camel_case_types)]
 #![allow(non_snake_case)]
 #![allow(missing_docs)]
-use zerocopy::{AsBytes, FromBytes, FromZeroes};""",
+use zerocopy::{Immutable, IntoBytes, FromBytes, KnownLayout};""",
     ],
     cc_lib = ":efi_c_headers",
     # For x86_32, we need to explicitly specify 32bit architecture.
diff --git a/gbl/libefi_types/defs/protocols/gbl_efi_fastboot_protocol.h b/gbl/libefi_types/defs/protocols/gbl_efi_fastboot_protocol.h
index 280059e..c0f0f57 100644
--- a/gbl/libefi_types/defs/protocols/gbl_efi_fastboot_protocol.h
+++ b/gbl/libefi_types/defs/protocols/gbl_efi_fastboot_protocol.h
@@ -86,12 +86,21 @@ typedef struct GblEfiFastbootProtocol {
   EfiStatus (*clear_lock)(struct GblEfiFastbootProtocol* this,
                           uint64_t lock_state);
 
+  // Local session methods
+  EfiStatus (*start_local_session)(struct GblEfiFastbootProtocol* this,
+                                   void** ctx);
+  EfiStatus (*update_local_session)(struct GblEfiFastbootProtocol* this,
+                                    void* ctx, uint8_t* buf, size_t* buf_size);
+  EfiStatus (*close_local_session)(struct GblEfiFastbootProtocol* this,
+                                   void* ctx);
+
   // Misc methods
   EfiStatus (*get_partition_permissions)(struct GblEfiFastbootProtocol* this,
                                          const char8_t* part_name,
                                          size_t part_name_len,
                                          uint64_t* permissions);
   EfiStatus (*wipe_user_data)(struct GblEfiFastbootProtocol* this);
+  bool (*should_stop_in_fastboot)(struct GblEfiFastbootProtocol* this);
 } GblEfiFastbootProtocol;
 
 #endif  // __GBL_EFI_FASTBOOT_PROTOCOL_H__
diff --git a/gbl/libefi_types/defs/protocols/gbl_efi_image_loading_protocol.h b/gbl/libefi_types/defs/protocols/gbl_efi_image_loading_protocol.h
index 5a6557a..6ab592d 100644
--- a/gbl/libefi_types/defs/protocols/gbl_efi_image_loading_protocol.h
+++ b/gbl/libefi_types/defs/protocols/gbl_efi_image_loading_protocol.h
@@ -26,6 +26,14 @@ const uint64_t GBL_EFI_IMAGE_LOADING_PROTOCOL_REVISION = 0x00010000;
 
 const size_t PARTITION_NAME_LEN_U16 = 36;
 
+//******************************************************
+// GBL reserved image types
+//******************************************************
+// Buffer for loading, verifying and fixing up OS images.
+#define GBL_IMAGE_TYPE_OS_LOAD L"os_load"
+// Buffer for use as fastboot download buffer.
+#define GBL_IMAGE_TYPE_FASTBOOT L"fastboot"
+
 typedef struct GblEfiImageInfo {
   char16_t ImageType[PARTITION_NAME_LEN_U16];
   size_t SizeBytes;
diff --git a/gbl/liberror/BUILD b/gbl/liberror/BUILD
index 1fdb664..754ea76 100644
--- a/gbl/liberror/BUILD
+++ b/gbl/liberror/BUILD
@@ -33,4 +33,5 @@ rust_test(
     name = "liberror_test",
     crate = ":liberror",
     rustc_flags = ANDROID_RUST_LINTS,
+    visibility = ["//visibility:public"],
 )
diff --git a/gbl/liberror/src/lib.rs b/gbl/liberror/src/lib.rs
index 542d3a8..269d2ce 100644
--- a/gbl/liberror/src/lib.rs
+++ b/gbl/liberror/src/lib.rs
@@ -222,6 +222,8 @@ pub enum Error {
     OperationProhibited,
     /// Catch-all error with optional debugging string.
     Other(Option<&'static str>),
+    /// Out of range.
+    OutOfRange,
     /// A resource has run out.
     OutOfResources,
     /// A protocol error occurred during the network operation.
@@ -232,10 +234,15 @@ pub enum Error {
     TftpError,
     /// Operation has timed out.
     Timeout,
+    /// Exceeds maximum number of partition for verification. The contained value represents the
+    /// maximum allowed number of partitions.
+    TooManyPartitions(usize),
     /// The remote network endpoint is not addressable.
     Unaddressable,
     /// An unknown, unexpected EFI_STATUS error code was returned,
     UnexpectedEfiError(efi::EfiStatus),
+    /// Return from function that is not expected to return.
+    UnexpectedReturn,
     /// Operation is unsupported
     Unsupported,
     /// Data verification has encountered a version number that is not supported.
diff --git a/gbl/libfastboot/BUILD b/gbl/libfastboot/BUILD
index 8804e0f..334842d 100644
--- a/gbl/libfastboot/BUILD
+++ b/gbl/libfastboot/BUILD
@@ -21,13 +21,14 @@ package(
 
 rust_library(
     name = "libfastboot",
-    srcs = ["src/lib.rs"],
+    srcs = glob(["**/*.rs"]),
     crate_name = "fastboot",
     edition = "2021",
     rustc_flags = ANDROID_RUST_LINTS,
     deps = [
         "@gbl//libasync",
         "@gbl//liberror",
+        "@gbl//libutils",
     ],
 )
 
diff --git a/gbl/libfastboot/src/lib.rs b/gbl/libfastboot/src/lib.rs
index b1e94c8..d589f2d 100644
--- a/gbl/libfastboot/src/lib.rs
+++ b/gbl/libfastboot/src/lib.rs
@@ -68,13 +68,16 @@
 #![allow(async_fn_in_trait)]
 
 use core::{
-    cmp::min,
     ffi::CStr,
     fmt::{Debug, Display, Formatter, Write},
     str::{from_utf8, Split},
 };
 use gbl_async::{block_on, yield_now};
 use liberror::{Error, Result};
+use libutils::{snprintf, FormattedBytes};
+
+/// Local session module
+pub mod local_session;
 
 /// Maximum packet size that can be accepted from the host.
 ///
@@ -176,7 +179,7 @@ pub struct CommandError(FormattedBytes<[u8; COMMAND_ERROR_LENGTH]>);
 impl CommandError {
     /// Converts to string.
     pub fn to_str(&self) -> &str {
-        from_utf8(&self.0 .0[..self.0 .1]).unwrap_or("")
+        self.0.to_str()
     }
 
     /// Clones the error.
@@ -193,7 +196,7 @@ impl Debug for CommandError {
 
 impl<T: Display> From<T> for CommandError {
     fn from(val: T) -> Self {
-        let mut res = CommandError(FormattedBytes([0u8; COMMAND_ERROR_LENGTH], 0));
+        let mut res = CommandError(FormattedBytes::new([0u8; COMMAND_ERROR_LENGTH]));
         write!(res.0, "{}", val).unwrap();
         res
     }
@@ -1015,57 +1018,6 @@ pub async fn run_tcp_session(
     run(&mut TcpTransport::new_and_handshake(tcp_stream)?, fb_impl).await
 }
 
-/// A helper data structure for writing formatted string to fixed size bytes array.
-#[derive(Debug)]
-pub struct FormattedBytes<T: AsMut<[u8]>>(T, usize);
-
-impl<T: AsMut<[u8]>> FormattedBytes<T> {
-    /// Create an instance.
-    pub fn new(buf: T) -> Self {
-        Self(buf, 0)
-    }
-
-    /// Get the size of content.
-    pub fn size(&self) -> usize {
-        self.1
-    }
-
-    /// Appends the given `bytes` to the contents.
-    ///
-    /// If `bytes` exceeds the remaining buffer space, any excess bytes are discarded.
-    ///
-    /// Returns the resulting contents.
-    pub fn append(&mut self, bytes: &[u8]) -> &mut [u8] {
-        let buf = &mut self.0.as_mut()[self.1..];
-        // Only write as much as the size of the bytes buffer. Additional write is silently
-        // ignored.
-        let to_write = min(buf.len(), bytes.len());
-        buf[..to_write].clone_from_slice(&bytes[..to_write]);
-        self.1 += to_write;
-        &mut self.0.as_mut()[..self.1]
-    }
-}
-
-impl<T: AsMut<[u8]>> core::fmt::Write for FormattedBytes<T> {
-    fn write_str(&mut self, s: &str) -> core::fmt::Result {
-        self.append(s.as_bytes());
-        Ok(())
-    }
-}
-
-/// A convenient macro that behaves similar to snprintf in C.
-#[macro_export]
-macro_rules! snprintf {
-    ( $arr:expr, $( $x:expr ),* ) => {
-        {
-            let mut formatted_bytes = FormattedBytes::new(&mut $arr[..]);
-            write!(formatted_bytes, $($x,)*).unwrap();
-            let size = formatted_bytes.size();
-            from_utf8(&$arr[..size]).unwrap()
-        }
-    };
-}
-
 /// A helper to convert a hex string into u64.
 pub(crate) fn hex_to_u64(s: &str) -> CommandResult<u64> {
     Ok(u64::from_str_radix(s.strip_prefix("0x").unwrap_or(s), 16)?)
@@ -1102,6 +1054,7 @@ pub fn next_arg_u64<'a, T: Iterator<Item = &'a str>>(args: &mut T) -> CommandRes
 #[cfg(test)]
 mod test {
     use super::*;
+    use core::cmp::min;
     use std::collections::{BTreeMap, VecDeque};
 
     #[derive(Default)]
diff --git a/gbl/libfastboot/src/local_session.rs b/gbl/libfastboot/src/local_session.rs
new file mode 100644
index 0000000..63303fa
--- /dev/null
+++ b/gbl/libfastboot/src/local_session.rs
@@ -0,0 +1,37 @@
+// Copyright 2025, The Android Open Source Project
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
+use crate::Transport;
+use liberror::Result;
+
+/// Trait for a device-local fastboot-like session.
+pub trait LocalSession {
+    /// Updates the context of the local session.
+    /// Polls inputs, updates graphics, and so forth.
+    async fn update(&mut self, buf: &mut [u8]) -> Result<usize>;
+
+    /// This is a hack to allow test structures to capture outgoing packets.
+    async fn process_outgoing_packet(&mut self, _: &[u8]) {}
+}
+
+impl<T: LocalSession> Transport for T {
+    async fn receive_packet(&mut self, out: &mut [u8]) -> Result<usize> {
+        self.update(out).await
+    }
+
+    async fn send_packet(&mut self, buf: &[u8]) -> Result<()> {
+        self.process_outgoing_packet(buf).await;
+        Ok(())
+    }
+}
diff --git a/gbl/libfdt/BUILD b/gbl/libfdt/BUILD
index fa416a0..a73779f 100644
--- a/gbl/libfdt/BUILD
+++ b/gbl/libfdt/BUILD
@@ -30,7 +30,7 @@ rust_bindgen(
         "--ctypes-prefix",
         "core::ffi",
         "--use-core",
-        "--with-derive-custom-struct=fdt_header=AsBytes,FromBytes,FromZeroes,PartialEq",
+        "--with-derive-custom-struct=fdt_header=Immutable,IntoBytes,KnownLayout,FromBytes,PartialEq",
         "--allowlist-function",
         "(fdt_.*)",
         "--allowlist-type",
@@ -43,7 +43,7 @@ rust_bindgen(
 #![allow(unsafe_op_in_unsafe_fn)]
 #![cfg_attr(not(test), no_std)]
 
-use zerocopy::{AsBytes, FromBytes, FromZeroes};
+use zerocopy::{Immutable, IntoBytes, KnownLayout, FromBytes};
 """,
     ],
     cc_lib = "@libfdt_c",
@@ -137,6 +137,9 @@ rust_test(
     ],
     crate = ":libfdt",
     rustc_flags = ANDROID_RUST_LINTS,
+    deps = [
+        "@gbl//libc:libc_deps_posix",
+    ],
 )
 
 link_static_cc_library(
diff --git a/gbl/libfdt/BUILD.libufdt_c.bazel b/gbl/libfdt/BUILD.libufdt_c.bazel
index 492ed2d..8d16281 100644
--- a/gbl/libfdt/BUILD.libufdt_c.bazel
+++ b/gbl/libfdt/BUILD.libufdt_c.bazel
@@ -12,6 +12,8 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@rules_cc//cc:defs.bzl", "cc_library")
+
 package(
     default_visibility = ["//visibility:public"],
 )
@@ -24,12 +26,11 @@ cc_library(
         "ufdt_node_pool.c",
         "ufdt_overlay.c",
         "ufdt_prop_dict.c",
+        "@gbl//libfdt:deps/print.c",
     ] + select({
         "@gbl//toolchain:gbl_rust_host_x86_64": ["sysdeps/libufdt_sysdeps_posix.c"],
         "//conditions:default": [
             "sysdeps/libufdt_sysdeps_vendor.c",
-            # Contains noop placeholder for dto_print from libufdt_sysdeps_vendor.c
-            "@gbl//libfdt:deps/print.c",
         ],
     }),
     hdrs = [
@@ -46,6 +47,8 @@ cc_library(
         "-DDTO_DISABLE_DEFAULT_VENDOR_LIBC_PRINT",
         # Disable default dto_malloc, dto_free implementations to include libufdt_sysdeps_vendor.c
         "-DDTO_DISABLE_DEFAULT_VENDOR_LIBC_ALLOCATION",
+        # Disable default dto_print implementation to include libufdt_sysdeps_posix.c
+        "-DDTO_DISABLE_DEFAULT_POSIX_LIBC_PRINT",
         # Disable default dto_malloc, dto_free implementations to include libufdt_sysdeps_posix.c
         "-DDTO_DISABLE_DEFAULT_POSIX_LIBC_ALLOCATION",
     ],
diff --git a/gbl/libfdt/deps/print.c b/gbl/libfdt/deps/print.c
index 0cd2a72..9c856c5 100644
--- a/gbl/libfdt/deps/print.c
+++ b/gbl/libfdt/deps/print.c
@@ -15,6 +15,11 @@
  *
  */
 
-// Noop placeholder for dto_print from libufdt
+#include <gbl/print.h>
 
-void dto_print(const char *fmt, ...) {}
\ No newline at end of file
+void dto_print(const char* fmt, ...) {
+  va_list args;
+  va_start(args, fmt);
+  gbl_printf(fmt, args);
+  va_end(args);
+}
\ No newline at end of file
diff --git a/gbl/libfdt/src/lib.rs b/gbl/libfdt/src/lib.rs
index 71ef623..406ce73 100644
--- a/gbl/libfdt/src/lib.rs
+++ b/gbl/libfdt/src/lib.rs
@@ -29,7 +29,7 @@ use libfdt_bindgen::{
     fdt_setprop_placeholder, fdt_strerror, fdt_subnode_offset_namelen,
 };
 use libufdt_bindgen::ufdt_apply_multioverlay;
-use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};
 
 /// Fdt header structure size.
 pub const FDT_HEADER_SIZE: usize = size_of::<FdtHeader>();
@@ -100,7 +100,7 @@ fn fdt_subnode_offset(fdt: &[u8], parent: c_int, name: &str) -> Result<c_int> {
 
 /// Rust wrapper for the FDT header data.
 #[repr(transparent)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
+#[derive(Debug, Copy, Clone, Immutable, IntoBytes, KnownLayout, FromBytes, PartialEq)]
 pub struct FdtHeader(fdt_header);
 
 impl FdtHeader {
@@ -125,20 +125,22 @@ impl FdtHeader {
     pub fn from_bytes_ref(buffer: &[u8]) -> Result<&FdtHeader> {
         fdt_check_header(buffer)?;
 
-        Ok(Ref::<_, FdtHeader>::new_from_prefix(buffer)
-            .ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?
-            .0
-            .into_ref())
+        Ok(Ref::into_ref(
+            Ref::<_, FdtHeader>::new_from_prefix(buffer)
+                .ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?
+                .0,
+        ))
     }
 
     /// Cast a bytes into a mutable reference of FDT header.
     pub fn from_bytes_mut(buffer: &mut [u8]) -> Result<&mut FdtHeader> {
         fdt_check_header(buffer)?;
 
-        Ok(Ref::<_, FdtHeader>::new_from_prefix(buffer)
-            .ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?
-            .0
-            .into_mut())
+        Ok(Ref::into_mut(
+            Ref::<_, FdtHeader>::new_from_prefix(buffer)
+                .ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?
+                .0,
+        ))
     }
 
     /// Get FDT header and raw bytes from a raw pointer.
@@ -222,8 +224,7 @@ impl<T: AsMut<[u8]> + AsRef<[u8]>> Fdt<T> {
     /// Creates a new mut [Fdt] wrapping the contents of `init`.
     pub fn new_mut(init: T) -> Result<Self> {
         let mut fdt = Fdt::new(init)?;
-        let new_size: u32 = fdt.as_mut().len().try_into().or(Err(Error::Other(None)))?;
-        fdt.header_mut()?.set_totalsize(new_size);
+        fdt.expand_to_buffer()?;
         Ok(fdt)
     }
 
@@ -238,9 +239,8 @@ impl<T: AsMut<[u8]> + AsRef<[u8]>> Fdt<T> {
                 fdt.as_mut().len().try_into().or(Err(Error::Other(None)))?,
             )
         })?;
-        let new_size: u32 = fdt.as_mut().len().try_into().or(Err(Error::Other(None)))?;
         let mut ret = Fdt::new(fdt)?;
-        ret.header_mut()?.set_totalsize(new_size);
+        ret.expand_to_buffer()?;
         Ok(ret)
     }
 
@@ -259,6 +259,17 @@ impl<T: AsMut<[u8]> + AsRef<[u8]>> Fdt<T> {
         Ok(())
     }
 
+    /// Expand the total size field in the header to match the full buffer size.
+    /// This allows the FDT to be modified further by ensuring sufficient space is available.
+    /// Typically used before making modifications to an existing FDT, especially if it was
+    /// previously shrunk. After modifications are complete, consider calling `shrink_to_fit`
+    /// to reduce the size before passing to the kernel.
+    pub fn expand_to_buffer(&mut self) -> Result<()> {
+        let buffer_size = self.0.as_ref().len().try_into().unwrap();
+        self.header_mut()?.set_totalsize(buffer_size);
+        Ok(())
+    }
+
     /// Delete node by `path``. Fail if node doesn't exist.
     pub fn delete_node(&mut self, path: &str) -> Result<()> {
         let node = self.find_node(path)?;
@@ -340,6 +351,8 @@ impl<T: AsMut<[u8]> + AsRef<[u8]>> Fdt<T> {
             )
         })?;
 
+        self.expand_to_buffer()?;
+
         Ok(())
     }
 
@@ -373,6 +386,8 @@ impl<T: AsRef<[u8]>> AsRef<[u8]> for Fdt<T> {
 
 #[cfg(test)]
 mod test {
+    extern crate libc_deps_posix;
+
     use super::*;
 
     // Fdt is required to be 8 bytes aligned. Buffer to test alignment-related logic.
@@ -383,6 +398,7 @@ mod test {
     fn check_overlays_are_applied(fdt: &[u8]) {
         let fdt = Fdt::new(fdt).unwrap();
 
+        assert_eq!(fdt.header_ref().unwrap().totalsize(), fdt.as_ref().len());
         assert_eq!(
             CStr::from_bytes_with_nul(
                 fdt.get_property("/dev-2/dev-2.2/dev-2.2.1", c"property-1").unwrap()
@@ -591,7 +607,6 @@ mod test {
         let mut fdt = Fdt::new_from_init(&mut fdt_buf[..], &base[..]).unwrap();
 
         fdt.multioverlay_apply(&[&overlay_modify[..] as _, &overlay_modify2[..] as _]).unwrap();
-        fdt.shrink_to_fit().unwrap();
 
         check_overlays_are_applied(fdt.0);
     }
@@ -607,7 +622,6 @@ mod test {
 
         fdt.multioverlay_apply(&[&overlay_modify[..] as _]).unwrap();
         fdt.multioverlay_apply(&[&overlay_modify2[..] as _]).unwrap();
-        fdt.shrink_to_fit().unwrap();
 
         check_overlays_are_applied(fdt.0);
     }
@@ -625,7 +639,6 @@ mod test {
         let mut fdt = Fdt::new_from_init(&mut fdt_buf[..], &base[..]).unwrap();
 
         fdt.multioverlay_apply(&[&overlay_modify[..] as _, &overlay_modify2[..] as _]).unwrap();
-        fdt.shrink_to_fit().unwrap();
 
         check_overlays_are_applied(fdt.0);
     }
@@ -644,7 +657,6 @@ mod test {
 
         fdt.multioverlay_apply(&[&overlay_modify[..] as _]).unwrap();
         fdt.multioverlay_apply(&[&overlay_modify2[..] as _]).unwrap();
-        fdt.shrink_to_fit().unwrap();
 
         check_overlays_are_applied(fdt.0);
     }
diff --git a/gbl/libgbl/BUILD b/gbl/libgbl/BUILD
index 044bdc9..8d68061 100644
--- a/gbl/libgbl/BUILD
+++ b/gbl/libgbl/BUILD
@@ -15,6 +15,10 @@
 load("@gbl//toolchain:gbl_workspace_util.bzl", "ANDROID_RUST_LINTS")
 load("@rules_rust//rust:defs.bzl", "rust_library", "rust_test")
 
+package(
+    default_visibility = ["//visibility:public"],
+)
+
 rust_library(
     name = "libgbl",
     srcs = glob(
@@ -31,7 +35,6 @@ rust_library(
         "@avb//:avb_bindgen",
         "@bitflags",
         "@crc32fast",
-        "@cstr",
         "@gbl//libabr",
         "@gbl//libasync",
         "@gbl//libboot",
@@ -61,39 +64,19 @@ rust_test(
     aliases = {"@itertools_noalloc": "itertools_noalloc"},
     compile_data = [
         "@gbl//libstorage/test:test_data",
-    ],
-    crate = ":libgbl",
-    crate_features = ["uuid"],
-    data = [
         "@gbl//libdttable/test/data:all",
         "@gbl//libfdt/test/data:all",
-        "@gbl//libgbl/testdata:cert_metadata.bin",
-        "@gbl//libgbl/testdata:cert_permanent_attributes.bad.bin",
-        "@gbl//libgbl/testdata:cert_permanent_attributes.bad.hash",
-        "@gbl//libgbl/testdata:cert_permanent_attributes.bin",
-        "@gbl//libgbl/testdata:cert_permanent_attributes.hash",
-        "@gbl//libgbl/testdata:sparse_test.bin",
-        "@gbl//libgbl/testdata:sparse_test_blk1024.bin",
-        "@gbl//libgbl/testdata:sparse_test_raw.bin",
-        "@gbl//libgbl/testdata:testkey_rsa4096_pub.bin",
-        "@gbl//libgbl/testdata:vbmeta_a.bin",
-        "@gbl//libgbl/testdata:vbmeta_b.bin",
-        "@gbl//libgbl/testdata:vbmeta_r.bin",
-        "@gbl//libgbl/testdata:vbmeta_slotless.bin",
-        "@gbl//libgbl/testdata:writeback_test_disk.bin",
-        "@gbl//libgbl/testdata:zircon_a.vbmeta",
-        "@gbl//libgbl/testdata:zircon_a.vbmeta.cert",
-        "@gbl//libgbl/testdata:zircon_a.zbi",
-        "@gbl//libgbl/testdata:zircon_b.zbi",
-        "@gbl//libgbl/testdata:zircon_r.zbi",
-        "@gbl//libgbl/testdata:zircon_slotless.zbi",
     ],
+    crate = ":libgbl",
+    crate_features = ["uuid"],
+    data = ["@gbl//libgbl/testdata"],
     rustc_flags = ANDROID_RUST_LINTS,
     deps = [
         "@avb//:avb_crypto_ops_sha_impl_staticlib",
         "@avb//:avb_test",
         "@gbl//libasync:cyclic_executor",
         "@gbl//libavb:sysdeps",
+        "@gbl//libc:libc_deps_posix",
         "@itertools",
         "@itertools_noalloc",
         "@static_assertions",
diff --git a/gbl/libgbl/Cargo.toml b/gbl/libgbl/Cargo.toml
index 3d330d8..12c938b 100644
--- a/gbl/libgbl/Cargo.toml
+++ b/gbl/libgbl/Cargo.toml
@@ -29,7 +29,7 @@ gbl_storage = {version = "0.1", path = "../libstorage"}
 spin = "0.9"
 static_assertions = "0"
 lazy_static = "1"
-zerocopy = {version = "=0.7.32"}
+zerocopy = {version = "=0.8"}
 crc32fast = "1.3"
 
 [dev-dependencies]
diff --git a/gbl/libgbl/src/android_boot/load.rs b/gbl/libgbl/src/android_boot/load.rs
new file mode 100644
index 0000000..e4ddb21
--- /dev/null
+++ b/gbl/libgbl/src/android_boot/load.rs
@@ -0,0 +1,1623 @@
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
+use super::{avb_verify_slot, cstr_bytes_to_str};
+use crate::{
+    android_boot::PartitionsToVerify,
+    constants::{FDT_ALIGNMENT, KERNEL_ALIGNMENT, PAGE_SIZE},
+    decompress::decompress_kernel,
+    gbl_print, gbl_println,
+    ops::GblOps,
+    partition::RAW_PARTITION_NAME_LEN,
+    IntegrationError,
+};
+use arrayvec::ArrayString;
+use bootimg::{defs::*, BootImage, VendorImageHeader};
+use bootparams::bootconfig::BootConfigBuilder;
+use core::{
+    array,
+    ffi::CStr,
+    fmt::Write,
+    ops::{Deref, Range},
+};
+use liberror::Error;
+use libutils::aligned_subslice;
+use safemath::SafeNum;
+use zerocopy::{IntoBytes, Ref};
+
+const DEFAULT_BUILD_ID: &str = "eng.build";
+
+// Represents a slot suffix.
+struct SlotSuffix([u8; 3]);
+
+impl SlotSuffix {
+    // Creates a new instance.
+    fn new(slot: u8) -> Result<Self, Error> {
+        let suffix = u32::from(slot) + u32::from(b'a');
+        match char::from_u32(suffix).map(|v| v.is_ascii_lowercase()) {
+            Some(true) => Ok(Self([b'_', suffix.try_into().unwrap(), 0])),
+            _ => Err(Error::Other(Some("Invalid slot index"))),
+        }
+    }
+
+    // Casts as CStr.
+    fn as_cstr(&self) -> &CStr {
+        CStr::from_bytes_with_nul(&self.0[..]).unwrap()
+    }
+}
+
+impl Deref for SlotSuffix {
+    type Target = str;
+
+    fn deref(&self) -> &Self::Target {
+        self.as_cstr().to_str().unwrap()
+    }
+}
+
+/// Returns a slotted partition name.
+fn slotted_part(part: &str, slot: u8) -> Result<ArrayString<RAW_PARTITION_NAME_LEN>, Error> {
+    let mut res = ArrayString::new_const();
+    write!(res, "{}{}", part, &SlotSuffix::new(slot)? as &str).unwrap();
+    Ok(res)
+}
+
+// Helper for constructing a range that ends at a page aligned boundary. Specifically, it returns
+// `start..round_up(start + sz, page_size)`
+fn page_aligned_range(
+    start: impl Into<SafeNum>,
+    sz: impl Into<SafeNum>,
+    page_size: impl Into<SafeNum>,
+) -> Result<Range<usize>, Error> {
+    let start = start.into();
+    Ok(start.try_into()?..(start + sz.into()).round_up(page_size.into()).try_into()?)
+}
+
+/// Represents a loaded boot image of version 2 and lower.
+///
+/// TODO(b/384964561): Investigate if the APIs are better suited for bootimg.rs. The issue
+/// is that it uses `Error` and `SafeNum` from GBL.
+struct BootImageV2Info<'a> {
+    cmdline: &'a str,
+    page_size: usize,
+    kernel_range: Range<usize>,
+    ramdisk_range: Range<usize>,
+    dtb_range: Range<usize>,
+    // Actual dtb size without padding.
+    //
+    // We need to know the exact size because the fdt buffer will be passed to
+    // `DeviceTreeComponentsRegistry::append` which assumes that the buffer contains concatenated
+    // device trees and will try to parse for additional device trees if the preivous one doesn't
+    // consume all buffer.
+    dtb_sz: usize,
+    image_size: usize,
+}
+
+impl<'a> BootImageV2Info<'a> {
+    /// Creates a new instance.
+    fn new(buffer: &'a [u8]) -> Result<Self, Error> {
+        let header = BootImage::parse(buffer)?;
+        if matches!(header, BootImage::V3(_) | BootImage::V4(_)) {
+            return Err(Error::InvalidInput);
+        }
+        // This is valid since v1/v2 are superset of v0.
+        let v0 = Ref::into_ref(Ref::<_, boot_img_hdr_v0>::from_prefix(&buffer[..]).unwrap().0);
+        let page_size: usize = v0.page_size.try_into()?;
+        let cmdline = cstr_bytes_to_str(&v0.cmdline[..])?;
+        let kernel_range = page_aligned_range(page_size, v0.kernel_size, page_size)?;
+        let ramdisk_range = page_aligned_range(kernel_range.end, v0.ramdisk_size, page_size)?;
+        let second_range = page_aligned_range(ramdisk_range.end, v0.second_size, page_size)?;
+
+        let start = u64::try_from(second_range.end)?;
+        let (off, sz) = match header {
+            BootImage::V1(v) => (v.recovery_dtbo_offset, v.recovery_dtbo_size),
+            BootImage::V2(v) => (v._base.recovery_dtbo_offset, v._base.recovery_dtbo_size),
+            _ => (start, 0),
+        };
+        let recovery_dtb_range = match off >= start {
+            true => page_aligned_range(off, sz, page_size)?,
+            _ if off == 0 => page_aligned_range(start, 0, page_size)?,
+            _ => return Err(Error::Other(Some("Unexpected recovery_dtbo_offset"))),
+        };
+        let dtb_sz: usize = match header {
+            BootImage::V2(v) => v.dtb_size.try_into().unwrap(),
+            _ => 0,
+        };
+        let dtb_range = page_aligned_range(recovery_dtb_range.end, dtb_sz, page_size)?;
+        let image_size = dtb_range.end;
+        Ok(Self { cmdline, page_size, kernel_range, ramdisk_range, dtb_range, dtb_sz, image_size })
+    }
+}
+
+// Contains information of a V3/V4 boot image.
+struct BootImageV3Info {
+    kernel_range: Range<usize>,
+    ramdisk_range: Range<usize>,
+    image_size: usize,
+}
+
+impl BootImageV3Info {
+    /// Creates a new instance.
+    fn new(buffer: &[u8]) -> Result<Self, Error> {
+        let header = BootImage::parse(buffer)?;
+        if !matches!(header, BootImage::V3(_) | BootImage::V4(_)) {
+            return Err(Error::InvalidInput);
+        }
+        let v3 = Self::v3(buffer);
+        let kernel_range = page_aligned_range(PAGE_SIZE, v3.kernel_size, PAGE_SIZE)?;
+        let ramdisk_range = page_aligned_range(kernel_range.end, v3.ramdisk_size, PAGE_SIZE)?;
+        let sz = match header {
+            BootImage::V4(v) => v.signature_size,
+            _ => 0,
+        };
+        let signature_range = page_aligned_range(ramdisk_range.end, sz, PAGE_SIZE)?;
+        let image_size = signature_range.end;
+
+        Ok(Self { kernel_range, ramdisk_range, image_size })
+    }
+
+    /// Gets the v3 base header.
+    fn v3(buffer: &[u8]) -> &boot_img_hdr_v3 {
+        // This is valid since v4 is superset of v3.
+        Ref::into_ref(Ref::from_prefix(&buffer[..]).unwrap().0)
+    }
+
+    // Decodes the kernel cmdline
+    fn cmdline(buffer: &[u8]) -> Result<&str, Error> {
+        cstr_bytes_to_str(&Self::v3(buffer).cmdline[..])
+    }
+}
+
+/// Contains vendor boot image information.
+struct VendorBootImageInfo {
+    header_size: usize,
+    ramdisk_range: Range<usize>,
+    dtb_range: Range<usize>,
+    // Actual dtb size without padding.
+    //
+    // We need to know the exact size because the fdt buffer will be passed to
+    // `DeviceTreeComponentsRegistry::append` which assumes that the buffer contains concatenated
+    // device trees and will try to parse for additional device trees if the preivous one doesn't
+    // consume all buffer.
+    dtb_sz: usize,
+    bootconfig_range: Range<usize>,
+    image_size: usize,
+}
+
+impl VendorBootImageInfo {
+    /// Creates a new instance.
+    fn new(buffer: &[u8]) -> Result<Self, Error> {
+        let header = VendorImageHeader::parse(buffer)?;
+        let v3 = Self::v3(buffer);
+        let page_size = v3.page_size;
+        let header_size = match header {
+            VendorImageHeader::V3(hdr) => SafeNum::from(hdr.as_bytes().len()),
+            VendorImageHeader::V4(hdr) => SafeNum::from(hdr.as_bytes().len()),
+        }
+        .round_up(page_size)
+        .try_into()?;
+        let ramdisk_range = page_aligned_range(header_size, v3.vendor_ramdisk_size, page_size)?;
+        let dtb_sz: usize = v3.dtb_size.try_into().unwrap();
+        let dtb_range = page_aligned_range(ramdisk_range.end, dtb_sz, page_size)?;
+
+        let (table_sz, bootconfig_sz) = match header {
+            VendorImageHeader::V4(hdr) => (hdr.vendor_ramdisk_table_size, hdr.bootconfig_size),
+            _ => (0, 0),
+        };
+        let table = page_aligned_range(dtb_range.end, table_sz, page_size)?;
+        let bootconfig_range = table.end..(table.end + usize::try_from(bootconfig_sz)?);
+        let image_size = SafeNum::from(bootconfig_range.end).round_up(page_size).try_into()?;
+        Ok(Self { header_size, ramdisk_range, dtb_range, dtb_sz, bootconfig_range, image_size })
+    }
+
+    /// Gets the v3 base header.
+    fn v3(buffer: &[u8]) -> &vendor_boot_img_hdr_v3 {
+        Ref::into_ref(Ref::<_, _>::from_prefix(&buffer[..]).unwrap().0)
+    }
+
+    // Decodes the vendor cmdline
+    fn cmdline(buffer: &[u8]) -> Result<&str, Error> {
+        cstr_bytes_to_str(&Self::v3(buffer).cmdline[..])
+    }
+}
+
+/// Contains various loaded image components by `android_load_verify`
+pub struct LoadedImages<'a> {
+    /// dtbo image.
+    pub dtbo: &'a mut [u8],
+    /// Kernel commandline.
+    pub boot_cmdline: &'a str,
+    /// Vendor commandline,
+    pub vendor_cmdline: &'a str,
+    /// DTB.
+    pub dtb: &'a mut [u8],
+    /// DTB from partition.
+    pub dtb_part: &'a mut [u8],
+    /// Kernel image.
+    pub kernel: &'a mut [u8],
+    /// Ramdisk image.
+    pub ramdisk: &'a mut [u8],
+    /// Unused portion. Can be used by the caller to construct FDT.
+    pub unused: &'a mut [u8],
+}
+
+impl<'a> Default for LoadedImages<'a> {
+    fn default() -> LoadedImages<'a> {
+        LoadedImages {
+            dtbo: &mut [][..],
+            boot_cmdline: "",
+            vendor_cmdline: "",
+            dtb: &mut [][..],
+            dtb_part: &mut [][..],
+            kernel: &mut [][..],
+            ramdisk: &mut [][..],
+            unused: &mut [][..],
+        }
+    }
+}
+
+/// Loads and verifies Android images of the given slot.
+pub fn android_load_verify<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    slot: u8,
+    is_recovery: bool,
+    load: &'c mut [u8],
+) -> Result<LoadedImages<'c>, IntegrationError> {
+    let mut res = LoadedImages::default();
+
+    let slot_suffix = SlotSuffix::new(slot)?;
+    // Additional partitions loaded before loading standard boot images.
+    let mut partitions = PartitionsToVerify::default();
+
+    // Loads dtbo.
+    let dtbo_part = slotted_part("dtbo", slot)?;
+    let (dtbo, remains) = load_entire_part(ops, &dtbo_part, &mut load[..])?;
+    if dtbo.len() > 0 {
+        partitions.try_push_preloaded(c"dtbo", &dtbo[..])?;
+    }
+
+    // Loads dtb.
+    let remains = aligned_subslice(remains, FDT_ALIGNMENT)?;
+    let dtb_part = slotted_part("dtb", slot)?;
+    let (dtb, remains) = load_entire_part(ops, &dtb_part, &mut remains[..])?;
+    if dtb.len() > 0 {
+        partitions.try_push_preloaded(c"dtb", &dtb[..])?;
+    }
+
+    let add = |v: &mut BootConfigBuilder| {
+        if !is_recovery {
+            v.add("androidboot.force_normal_boot=1\n")?;
+        }
+        write!(v, "androidboot.slot_suffix={}\n", &slot_suffix as &str)?;
+
+        // Placeholder value for now. Userspace can use this value to tell if device is booted with GBL.
+        // TODO(yochiang): Generate useful value like version, build_incremental in the bootconfig.
+        v.add("androidboot.gbl.version=0\n")?;
+
+        let build_number = match option_env!("BUILD_NUMBER") {
+            None | Some("") => DEFAULT_BUILD_ID,
+            Some(build_number) => build_number,
+        };
+        write!(v, "androidboot.gbl.build_number={}\n", build_number)?;
+        Ok(())
+    };
+
+    // Loads boot image header and inspect version
+    ops.read_from_partition_sync(&slotted_part("boot", slot)?, 0, &mut remains[..PAGE_SIZE])?;
+    match BootImage::parse(&remains[..]).map_err(Error::from)? {
+        BootImage::V3(_) | BootImage::V4(_) => {
+            load_verify_v3_and_v4(ops, slot, &partitions, add, &mut res, remains)?
+        }
+        _ => load_verify_v2_and_lower(ops, slot, &partitions, add, &mut res, remains)?,
+    };
+
+    drop(partitions);
+    res.dtbo = dtbo;
+    res.dtb_part = dtb;
+    Ok(res)
+}
+
+/// Loads and verifies android boot images of version 0, 1 and 2.
+///
+/// * Both kernel and ramdisk come from the boot image.
+/// * vendor_boot, init_boot are irrelevant.
+///
+/// # Args
+///
+/// * `ops`: An implementation of [GblOps].
+/// * `slot`: slot index.
+/// * `additional_partitions`: Additional partitions for verification.
+/// * `out`: A `&mut LoadedImages` for output.
+/// * `load`: The load buffer. The boot header must be preloaded into this buffer.
+fn load_verify_v2_and_lower<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    slot: u8,
+    additional_partitions: &PartitionsToVerify,
+    add_additional_bootconfig: impl FnOnce(&mut BootConfigBuilder) -> Result<(), Error>,
+    out: &mut LoadedImages<'c>,
+    load: &'c mut [u8],
+) -> Result<(), IntegrationError> {
+    gbl_println!(ops, "Android loading v2 or lower");
+    // Loads boot image.
+    let boot_size = BootImageV2Info::new(load).unwrap().image_size;
+    let boot_part = slotted_part("boot", slot)?;
+    let (boot, remains) = split(load, boot_size)?;
+    ops.read_from_partition_sync(&boot_part, 0, boot)?;
+
+    // Performs libavb verification.
+
+    // Prepares a BootConfigBuilder to add avb generated bootconfig.
+    let mut bootconfig_builder = BootConfigBuilder::new(remains)?;
+    // Puts in a subscope for auto dropping `to_verify`, so that the slices it
+    // borrows can be released.
+    {
+        let mut to_verify = PartitionsToVerify::default();
+        to_verify.try_push_preloaded(c"boot", &boot[..])?;
+        to_verify.try_extend_preloaded(additional_partitions)?;
+        avb_verify_slot(ops, slot, &to_verify, &mut bootconfig_builder)?;
+    }
+
+    add_additional_bootconfig(&mut bootconfig_builder)?;
+    // Adds platform-specific bootconfig.
+    bootconfig_builder.add_with(|bytes, out| {
+        Ok(ops.fixup_bootconfig(&bytes, out)?.map(|slice| slice.len()).unwrap_or(0))
+    })?;
+    let bootconfig_size = bootconfig_builder.config_bytes().len();
+
+    // We now have the following layout:
+    //
+    // | boot_hdr | kernel | ramdisk | second | recovery_dtb | dtb | bootconfig | remains |
+    // |------------------------------`boot_ex`---------------------------------|
+    //
+    // We need to:
+    // 1. move bootconfig to after ramdisk.
+    // 2. relocate the kernel to the tail so that all memory after it can be used as scratch memory.
+    //    It is observed that riscv kernel reaches into those memory and overwrites data.
+    //
+    // TODO(b/384964561): Investigate if `second`, `recovery_dtb` needs to be kept.
+    let (boot_ex, remains) = load.split_at_mut(boot_size + bootconfig_size);
+    let boot_img = BootImageV2Info::new(boot_ex).unwrap();
+    let page_size = boot_img.page_size;
+    let dtb_sz = boot_img.dtb_sz;
+    // Relocates kernel to tail.
+    let kernel_range = boot_img.kernel_range;
+    let kernel = boot_ex.get(kernel_range.clone()).unwrap();
+    let (remains, _, kernel_sz) = relocate_kernel(ops, kernel, remains)?;
+    // Relocates dtb to tail.
+    let dtb_range = boot_img.dtb_range;
+    let (_, dtb) = split_aligned_tail(remains, dtb_range.len(), FDT_ALIGNMENT)?;
+    dtb[..dtb_range.len()].clone_from_slice(boot_ex.get(dtb_range).unwrap());
+    // Move ramdisk forward and bootconfig following it.
+    let ramdisk_range = boot_img.ramdisk_range;
+    boot_ex.copy_within(ramdisk_range.start..ramdisk_range.end, kernel_range.start);
+    boot_ex.copy_within(boot_size.., kernel_range.start + ramdisk_range.len());
+
+    // We now have the following layout:
+    // | boot_hdr | ramdisk + bootconfig | unused | dtb | kernel |
+    let ramdisk_sz = ramdisk_range.len() + bootconfig_size;
+    let unused_sz = slice_offset(dtb, boot_ex) - page_size - ramdisk_sz;
+    let dtb_padding = dtb.len() - dtb_sz;
+    let hdr;
+    ([hdr, out.ramdisk, out.unused, out.dtb, _, out.kernel], _) =
+        split_chunks(load, &[page_size, ramdisk_sz, unused_sz, dtb_sz, dtb_padding, kernel_sz]);
+    out.boot_cmdline = BootImageV2Info::new(hdr).unwrap().cmdline;
+    Ok(())
+}
+
+/// Loads and verifies android boot images of version 3 and 4.
+///
+/// V3, V4 images have the following characteristics:
+///
+/// * Kernel comes from "boot_a/b" partition.
+/// * Generic ramdisk may come from either "boot_a/b" or "init_boot_a/b" partitions.
+/// * Vendor ramdisk comes from "vendor_boot_a/b" partition.
+/// * V4 vendor_boot contains additional bootconfig.
+///
+/// From the perspective of Android versions:
+///
+/// Android 11:
+///
+/// * Can use v3 header.
+/// * Generic ramdisk is in the "boot_a/b" partitions.
+///
+/// Android 12:
+///
+/// * Can use v3 or v4 header.
+/// * Generic ramdisk is in the "boot_a/b" partitions.
+///
+/// Android 13:
+///
+/// * Can use v3 or v4 header.
+/// * Generic ramdisk is in the "init_boot_a/b" partitions.
+///
+/// # References
+///
+/// https://source.android.com/docs/core/architecture/bootloader/boot-image-header
+/// https://source.android.com/docs/core/architecture/partitions/vendor-boot-partitions
+/// https://source.android.com/docs/core/architecture/partitions/generic-boot
+///
+/// # Args
+///
+/// * `ops`: An implementation of [GblOps].
+/// * `slot`: slot index.
+/// * `additional_partitions`: Additional partitions for verification.
+/// * `out`: A `&mut LoadedImages` for output.
+/// * `load`: The load buffer. The boot header must be preloaded into this buffer.
+fn load_verify_v3_and_v4<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    slot: u8,
+    additional_partitions: &PartitionsToVerify,
+    add_additional_bootconfig: impl FnOnce(&mut BootConfigBuilder) -> Result<(), Error>,
+    out: &mut LoadedImages<'c>,
+    load: &'c mut [u8],
+) -> Result<(), IntegrationError> {
+    gbl_println!(ops, "Android loading v3 or higher");
+    // Creates a `start` marker for `slice_offset()` to compute absolute slice offset later.
+    let (start, load) = load.split_at_mut(0);
+
+    let boot_part = slotted_part("boot", slot)?;
+    let vendor_boot_part = slotted_part("vendor_boot", slot)?;
+    let init_boot_part = slotted_part("init_boot", slot)?;
+
+    let boot_img_info = BootImageV3Info::new(load).unwrap();
+
+    // Loads vendor boot image.
+    ops.read_from_partition_sync(&vendor_boot_part, 0, &mut load[..PAGE_SIZE])?;
+    let vendor_boot_info = VendorBootImageInfo::new(&load[..PAGE_SIZE])?;
+    let (vendor_boot, remains) = split(&mut load[..], vendor_boot_info.image_size)?;
+    ops.read_from_partition_sync(&vendor_boot_part, 0, vendor_boot)?;
+
+    // Loads boot image.
+    let (boot, remains) = split(remains, boot_img_info.image_size)?;
+    ops.read_from_partition_sync(&boot_part, 0, boot)?;
+
+    // Loads init_boot image if boot doesn't contain a ramdisk.
+    let (init_boot, remains, init_boot_info) = match boot_img_info.ramdisk_range.len() > 0 {
+        false => {
+            ops.read_from_partition_sync(&init_boot_part, 0, &mut remains[..PAGE_SIZE])?;
+            let init_boot_info = BootImageV3Info::new(&remains[..])?;
+            let (out, remains) = split(remains, init_boot_info.image_size)?;
+            ops.read_from_partition_sync(&init_boot_part, 0, out)?;
+            (out, remains, Some(init_boot_info))
+        }
+        _ => (&mut [][..], remains, None),
+    };
+
+    // Performs libavb verification.
+
+    // Prepares a BootConfigBuilder to add avb generated bootconfig.
+    let mut bootconfig_builder = BootConfigBuilder::new(remains)?;
+    // Puts in a subscope for auto dropping `to_verify`, so that the slices it
+    // borrows can be released.
+    {
+        let mut to_verify = PartitionsToVerify::default();
+        to_verify.try_push_preloaded(c"boot", &boot)?;
+        to_verify.try_push_preloaded(c"vendor_boot", &vendor_boot)?;
+        if init_boot.len() > 0 {
+            to_verify.try_push_preloaded(c"init_boot", &init_boot)?;
+        }
+        to_verify.try_extend_preloaded(additional_partitions)?;
+        avb_verify_slot(ops, slot, &to_verify, &mut bootconfig_builder)?;
+    }
+
+    add_additional_bootconfig(&mut bootconfig_builder)?;
+    // Adds platform-specific bootconfig.
+    bootconfig_builder.add_with(|bytes, out| {
+        Ok(ops.fixup_bootconfig(&bytes, out)?.map(|slice| slice.len()).unwrap_or(0))
+    })?;
+
+    // We now have the following layout:
+    //
+    // +------------------------+
+    // | vendor boot header     |
+    // +------------------------+
+    // | vendor ramdisk         |
+    // +------------------------+
+    // | dtb                    |
+    // +------------------------+
+    // | vendor ramdisk table   |
+    // +------------------------+
+    // | vendor bootconfig      |
+    // +------------------------+    +------------------------+
+    // | boot hdr               |    | boot hdr               |
+    // +------------------------+    +------------------------+
+    // | kernel                 |    | kernel                 |
+    // +------------------------+    +------------------------+
+    // |                        |    | boot signature         |
+    // |                        | or +------------------------+
+    // | generic ramdisk        |    | init_boot hdr          |
+    // |                        |    +------------------------+
+    // |                        |    | generic ramdisk        |
+    // +------------------------+    +------------------------+
+    // | boot signature         |    | boot signature         |
+    // +------------------------+    +------------------------+
+    // | avb + board bootconfig |
+    // +------------------------+
+    // | unused                 |
+    // +------------------------+
+    //
+    // We need to:
+    // * Relocate kernel to the tail of the load buffer to reserve all memory after it for scratch.
+    // * Relocates dtb, boot hdr to elsewhere.
+    // * Move generic ramdisk to follow vendor ramdisk.
+    // * Move vendor bootconfig, avb + board bootconfig to follow generic ramdisk.
+
+    // Appends vendor bootconfig so that the section can be discarded.
+    let vendor_bootconfig = vendor_boot.get(vendor_boot_info.bootconfig_range).unwrap();
+    bootconfig_builder.add_with(|_, out| {
+        out.get_mut(..vendor_bootconfig.len())
+            .ok_or(Error::BufferTooSmall(Some(vendor_bootconfig.len())))?
+            .clone_from_slice(vendor_bootconfig);
+        Ok(vendor_bootconfig.len())
+    })?;
+    let bootconfig_size = bootconfig_builder.config_bytes().len();
+    let (bootconfig, remains) = remains.split_at_mut(bootconfig_size);
+
+    // Relocates kernel to tail.
+    let kernel = boot.get(boot_img_info.kernel_range.clone()).unwrap();
+    let (remains, kernel, kernel_sz) = relocate_kernel(ops, kernel, remains)?;
+    let kernel_buf_len = kernel.len();
+
+    // Relocates boot header to tail.
+    let (remains, boot_hdr) = split_aligned_tail(remains, PAGE_SIZE, 1)?;
+    boot_hdr.clone_from_slice(&boot[..PAGE_SIZE]);
+    let boot_hdr_sz = boot_hdr.len();
+
+    // Relocates dtb to tail.
+    let dtb = vendor_boot.get(vendor_boot_info.dtb_range).unwrap();
+    let (_, dtb_reloc) = split_aligned_tail(remains, dtb.len(), FDT_ALIGNMENT)?;
+    dtb_reloc[..dtb.len()].clone_from_slice(dtb);
+    let dtb_sz = vendor_boot_info.dtb_sz;
+    let dtb_pad = dtb_reloc.len() - dtb_sz;
+
+    // Moves generic ramdisk and bootconfig forward
+    let generic_ramdisk_range = match init_boot_info {
+        Some(v) => offset_range(v.ramdisk_range, slice_offset(init_boot, start)),
+        _ => offset_range(boot_img_info.ramdisk_range, slice_offset(boot, start)),
+    };
+    let vendor_ramdisk_range = vendor_boot_info.ramdisk_range;
+    let bootconfig_range = offset_range(0..bootconfig_size, slice_offset(bootconfig, start));
+    load.copy_within(generic_ramdisk_range.clone(), vendor_ramdisk_range.end);
+    load.copy_within(bootconfig_range, vendor_ramdisk_range.end + generic_ramdisk_range.len());
+    let ramdisk_sz = vendor_ramdisk_range.len() + generic_ramdisk_range.len() + bootconfig_size;
+
+    // We now have the following layout:
+    //
+    // +------------------------+
+    // | vendor boot header     |
+    // +------------------------+
+    // | vendor ramdisk         |
+    // +------------------------+
+    // | generic ramdisk        |
+    // +------------------------+
+    // | vendor bootconfig      |
+    // +------------------------+
+    // | avb + board bootconfig |
+    // +------------------------+
+    // | unused                 |
+    // +------------------------+
+    // | dtb                    |
+    // +------------------------+
+    // | boot hdr               |
+    // +------------------------+
+    // | kernel                 |
+    // +------------------------+
+    //
+    // Splits out the images and returns.
+    let vendor_hdr_sz = vendor_boot_info.header_size;
+    let unused_sz =
+        load.len() - vendor_hdr_sz - ramdisk_sz - boot_hdr_sz - dtb_sz - dtb_pad - kernel_buf_len;
+    let (vendor_hdr, boot_hdr);
+    ([vendor_hdr, out.ramdisk, out.unused, out.dtb, _, boot_hdr, out.kernel], _) = split_chunks(
+        load,
+        &[vendor_hdr_sz, ramdisk_sz, unused_sz, dtb_sz, dtb_pad, boot_hdr_sz, kernel_sz],
+    );
+    out.boot_cmdline = BootImageV3Info::cmdline(boot_hdr)?;
+    out.vendor_cmdline = VendorBootImageInfo::cmdline(vendor_hdr)?;
+    Ok(())
+}
+
+// A helper for calculating the relative offset of `buf` to `src`.
+fn slice_offset(buf: &[u8], src: &[u8]) -> usize {
+    (buf.as_ptr() as usize).checked_sub(src.as_ptr() as usize).unwrap()
+}
+
+/// Wrapper of `split_at_mut_checked` with error conversion.
+fn split(buffer: &mut [u8], size: usize) -> Result<(&mut [u8], &mut [u8]), Error> {
+    buffer.split_at_mut_checked(size).ok_or(Error::BufferTooSmall(Some(size)))
+}
+
+/// Calculates the offset from the start of the buffer to obtain an aligned tail
+/// that can fit at least `size` bytes with the given alignment.
+///
+/// Returns the starting offset of the aligned tail slice.
+fn aligned_tail_offset(buffer: &[u8], size: usize, align: usize) -> Result<usize, Error> {
+    let off = SafeNum::from(buffer.len()) - size;
+    let rem = buffer[off.try_into()?..].as_ptr() as usize % align;
+    Ok(usize::try_from(off - rem)?)
+}
+
+/// Split buffer from the tail with the given alignment such that the buffer is at least `size`
+/// bytes.
+fn split_aligned_tail(
+    buffer: &mut [u8],
+    size: usize,
+    align: usize,
+) -> Result<(&mut [u8], &mut [u8]), Error> {
+    split(buffer, aligned_tail_offset(buffer, size, align)?)
+}
+
+/// Splits a buffer into multiple chunks of the given sizes.
+///
+/// Returns an array of slices corresponding to the given sizes and the remaining slice.
+pub(super) fn split_chunks<'a, const N: usize>(
+    buf: &'a mut [u8],
+    sizes: &[usize; N],
+) -> ([&'a mut [u8]; N], &'a mut [u8]) {
+    let mut chunks: [_; N] = array::from_fn(|_| &mut [][..]);
+    let mut remains = buf;
+    for (i, ele) in sizes.iter().enumerate() {
+        (chunks[i], remains) = remains.split_at_mut(*ele);
+    }
+    (chunks, remains)
+}
+
+/// Helper for loading entire partition.
+///
+/// * Returns the loaded slice and the remaining slice.
+/// * If the partition doesn't exist, an empty loaded slice is returned.
+fn load_entire_part<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    part: &str,
+    load: &'c mut [u8],
+) -> Result<(&'c mut [u8], &'c mut [u8]), Error> {
+    match ops.partition_size(&part)? {
+        Some(sz) => {
+            let sz = sz.try_into()?;
+            gbl_println!(ops, "Found {} partition.", &part);
+            let (out, remains) = split(load, sz)?;
+            ops.read_from_partition_sync(&part, 0, out)?;
+            Ok((out, remains))
+        }
+        _ => {
+            gbl_println!(ops, "Partition {} doesn't exist. Skip loading.", &part);
+            Ok((&mut [][..], &mut load[..]))
+        }
+    }
+}
+
+/// A helper function for relocating and decompressing kernel to a different buffer.
+///
+/// The relocated kernel will be place at the tail.
+///
+/// Returns the leading unused slice, the relocated slice and the actual kernel size without
+/// alignment padding.
+fn relocate_kernel<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    kernel: &[u8],
+    dst: &'c mut [u8],
+) -> Result<(&'c mut [u8], &'c mut [u8], usize), Error> {
+    let decompressed_size = decompress_kernel(ops, kernel, dst)?;
+    let aligned_tail_off = aligned_tail_offset(dst, decompressed_size, KERNEL_ALIGNMENT)?;
+    dst.copy_within(0..decompressed_size, aligned_tail_off);
+    let (prefix, tail) = split(dst, aligned_tail_off)?;
+    Ok((prefix, tail, decompressed_size))
+}
+
+// Adds offset to a given range i.e. [start+off, end+off)
+fn offset_range(lhs: Range<usize>, off: usize) -> Range<usize> {
+    lhs.start.checked_add(off).unwrap()..lhs.end.checked_add(off).unwrap()
+}
+
+#[cfg(test)]
+pub(crate) mod tests {
+    use super::*;
+    use crate::{
+        gbl_avb::state::{BootStateColor, KeyValidationStatus},
+        ops::test::{FakeGblOps, FakeGblOpsStorage},
+        tests::AlignedBuffer,
+    };
+    use bootparams::bootconfig::BOOTCONFIG_TRAILER_SIZE;
+    use std::{
+        ascii::escape_default, collections::HashMap, ffi::CString, fmt, fs, path::Path,
+        string::String,
+    };
+
+    /// Export DEFAULT_BUILD_ID for other test modules.
+    pub const TEST_DEFAULT_BUILD_ID: &str = DEFAULT_BUILD_ID;
+
+    // See libgbl/testdata/gen_test_data.py for test data generation.
+    const TEST_ROLLBACK_INDEX_LOCATION: usize = 1;
+
+    // The commandline in the generated vendor boot image.
+    // See libgbl/testdata/gen_test_data.py for test data generation.
+    const TEST_VENDOR_CMDLINE: &str =
+        "cmd_vendor_key_1=cmd_vendor_val_1,cmd_vendor_key_2=cmd_vendor_val_2";
+    // The vendor bootconfig in the generated vendor boot image.
+    // See libgbl/testdata/gen_test_data.py for test data generation.
+    pub(crate) const TEST_VENDOR_BOOTCONFIG: &str =
+        "androidboot.config_1=val_1\x0aandroidboot.config_2=val_2\x0a";
+
+    /// Digest of public key used to execute AVB.
+    pub(crate) const TEST_PUBLIC_KEY_DIGEST: &str =
+        "7ec02ee1be696366f3fa91240a8ec68125c4145d698f597aa2b3464b59ca7fc3";
+
+    // Test data path
+    const TEST_DATA_PATH: &str = "external/gbl/libgbl/testdata/android";
+
+    /// Reads a data file under libgbl/testdata/
+    pub(crate) fn read_test_data(file: impl AsRef<str>) -> Vec<u8> {
+        println!("reading file: {}", file.as_ref());
+        fs::read(Path::new(format!("{TEST_DATA_PATH}/{}", file.as_ref()).as_str())).unwrap()
+    }
+
+    /// Reads a data file as string under libgbl/testdata/
+    pub(crate) fn read_test_data_as_str(file: impl AsRef<str>) -> String {
+        fs::read_to_string(Path::new(format!("{TEST_DATA_PATH}/{}", file.as_ref()).as_str()))
+            .unwrap()
+    }
+
+    // Returns the test dtb
+    fn test_dtb() -> Vec<u8> {
+        read_test_data("device_tree.dtb")
+    }
+
+    /// Generates a readable string for a bootconfig bytes.
+    pub(crate) fn dump_bootconfig(data: &[u8]) -> String {
+        let s = data.iter().map(|v| escape_default(*v).to_string()).collect::<Vec<_>>().concat();
+        let s = s.split("\\\\").collect::<Vec<_>>().join("\\");
+        s.split("\\n").collect::<Vec<_>>().join("\n")
+    }
+
+    /// A helper for assert checking ramdisk binary and bootconfig separately.
+    pub(crate) fn check_ramdisk(ramdisk: &[u8], expected_bin: &[u8], expected_bootconfig: &[u8]) {
+        let (ramdisk, bootconfig) = ramdisk.split_at(expected_bin.len());
+        assert_eq!(ramdisk, expected_bin);
+        assert_eq!(
+            bootconfig,
+            expected_bootconfig,
+            "\nexpect: \n{}\nactual: \n{}\n",
+            dump_bootconfig(expected_bootconfig),
+            dump_bootconfig(bootconfig),
+        );
+    }
+
+    /// Helper for testing load/verify and assert verfiication success.
+    fn test_android_load_verify_success(
+        slot: u8,
+        partitions: &[(CString, String)],
+        expected_kernel: &[u8],
+        expected_ramdisk: &[u8],
+        expected_bootconfig: &[u8],
+        expected_dtb: &[u8],
+        expected_dtbo: &[u8],
+        expected_vendor_cmdline: &str,
+    ) {
+        let mut storage = FakeGblOpsStorage::default();
+        for (part, file) in partitions {
+            storage.add_raw_device(part, read_test_data(file));
+        }
+        let mut ops = FakeGblOps::new(&storage);
+        ops.avb_ops.unlock_state = Ok(false);
+        ops.avb_ops.rollbacks = HashMap::from([(TEST_ROLLBACK_INDEX_LOCATION, Ok(0))]);
+        let mut load_buffer = AlignedBuffer::new(64 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let mut out_color = None;
+        let mut handler = |color,
+                           _: Option<&CStr>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>| {
+            out_color = Some(color);
+            Ok(())
+        };
+        ops.avb_handle_verification_result = Some(&mut handler);
+        ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));
+        let loaded = android_load_verify(&mut ops, slot, false, &mut load_buffer).unwrap();
+
+        assert_eq!(loaded.dtb, expected_dtb);
+        assert_eq!(out_color, Some(BootStateColor::Green));
+        assert_eq!(loaded.boot_cmdline, "cmd_key_1=cmd_val_1,cmd_key_2=cmd_val_2");
+        assert_eq!(loaded.vendor_cmdline, expected_vendor_cmdline);
+        assert_eq!(loaded.kernel, expected_kernel);
+        assert_eq!(loaded.kernel.as_ptr() as usize % KERNEL_ALIGNMENT, 0);
+        assert_eq!(loaded.dtbo, expected_dtbo);
+        check_ramdisk(loaded.ramdisk, expected_ramdisk, expected_bootconfig);
+    }
+
+    /// A helper for generating avb bootconfig with the given parameters.
+    pub(crate) struct AvbResultBootconfigBuilder {
+        vbmeta_size: usize,
+        digest: String,
+        boot_digest: Option<String>,
+        init_boot_digest: Option<String>,
+        dtb_digest: Option<String>,
+        dtbo_digest: Option<String>,
+        vendor_boot_digest: Option<String>,
+        public_key_digest: String,
+        color: BootStateColor,
+        unlocked: bool,
+        extra: String,
+    }
+
+    impl AvbResultBootconfigBuilder {
+        pub(crate) fn new() -> Self {
+            Self {
+                vbmeta_size: 0,
+                digest: String::new(),
+                boot_digest: None,
+                init_boot_digest: None,
+                dtb_digest: None,
+                dtbo_digest: None,
+                vendor_boot_digest: None,
+                public_key_digest: String::new(),
+                color: BootStateColor::Green,
+                unlocked: false,
+                extra: String::new(),
+            }
+        }
+
+        pub(crate) fn vbmeta_size(mut self, size: usize) -> Self {
+            self.vbmeta_size = size;
+            self
+        }
+
+        pub(crate) fn digest(mut self, digest: impl Into<String>) -> Self {
+            self.digest = digest.into();
+            self
+        }
+
+        pub(crate) fn partition_digest(mut self, name: &str, digest: impl Into<String>) -> Self {
+            let digest = Some(digest.into());
+            match name {
+                "boot" => self.boot_digest = digest,
+                "init_boot" => self.init_boot_digest = digest,
+                "vendor_boot" => self.vendor_boot_digest = digest,
+                "dtb" => self.dtb_digest = digest,
+                "dtbo" => self.dtbo_digest = digest,
+                _ => panic!("unknown digest name requested"),
+            };
+            self
+        }
+
+        pub(crate) fn public_key_digest(mut self, pk_digest: impl Into<String>) -> Self {
+            self.public_key_digest = pk_digest.into();
+            self
+        }
+
+        pub(crate) fn color(mut self, color: BootStateColor) -> Self {
+            self.color = color;
+            self
+        }
+
+        pub(crate) fn unlocked(mut self, unlocked: bool) -> Self {
+            self.unlocked = unlocked;
+            self
+        }
+
+        pub(crate) fn extra(mut self, extra: impl Into<String>) -> Self {
+            self.extra += &extra.into();
+            self
+        }
+
+        pub(crate) fn build_string(self) -> String {
+            let device_state = match self.unlocked {
+                true => "unlocked",
+                false => "locked",
+            };
+
+            let mut boot_digests = String::new();
+            for (name, maybe_digest) in [
+                ("boot", &self.boot_digest),
+                ("dtb", &self.dtb_digest),
+                ("dtbo", &self.dtbo_digest),
+                ("init_boot", &self.init_boot_digest),
+                ("vendor_boot", &self.vendor_boot_digest),
+            ] {
+                if let Some(digest) = maybe_digest {
+                    boot_digests += format!(
+                        "androidboot.vbmeta.{name}.hash_alg=sha256
+androidboot.vbmeta.{name}.digest={digest}\n"
+                    )
+                    .as_str()
+                }
+            }
+
+            format!(
+                "androidboot.vbmeta.device=PARTUUID=00000000-0000-0000-0000-000000000000
+androidboot.vbmeta.public_key_digest={}
+androidboot.vbmeta.avb_version=1.3
+androidboot.vbmeta.device_state={}
+androidboot.vbmeta.hash_alg=sha512
+androidboot.vbmeta.size={}
+androidboot.vbmeta.digest={}
+androidboot.vbmeta.invalidate_on_error=yes
+androidboot.veritymode=enforcing
+{}androidboot.verifiedbootstate={}
+{}",
+                self.public_key_digest,
+                device_state,
+                self.vbmeta_size,
+                self.digest,
+                boot_digests.as_str(),
+                self.color,
+                self.extra
+            )
+        }
+
+        pub(crate) fn build(self) -> Vec<u8> {
+            make_bootconfig(self.build_string())
+        }
+    }
+
+    // A helper for generating expected bootconfig.
+    pub(crate) fn make_bootconfig(bootconfig: impl AsRef<str>) -> Vec<u8> {
+        let bootconfig = bootconfig.as_ref();
+        let mut buffer = vec![0u8; bootconfig.len() + BOOTCONFIG_TRAILER_SIZE];
+        let mut res = BootConfigBuilder::new(&mut buffer).unwrap();
+        res.add_with(|_, out| {
+            out[..bootconfig.len()].clone_from_slice(bootconfig.as_bytes());
+            Ok(bootconfig.as_bytes().len())
+        })
+        .unwrap();
+        res.config_bytes().to_vec()
+    }
+
+    pub(crate) struct MakeExpectedBootconfigInclude {
+        pub boot: bool,
+        pub init_boot: bool,
+        pub vendor_boot: bool,
+        pub dtb: bool,
+        pub dtbo: bool,
+    }
+
+    impl MakeExpectedBootconfigInclude {
+        fn is_include_str(&self, name: &str) -> bool {
+            match name {
+                "boot" => self.boot,
+                "init_boot" => self.init_boot,
+                "vendor_boot" => self.vendor_boot,
+                "dtb" => self.dtb,
+                "dtbo" => self.dtbo,
+                _ => false,
+            }
+        }
+    }
+
+    impl Default for MakeExpectedBootconfigInclude {
+        fn default() -> MakeExpectedBootconfigInclude {
+            MakeExpectedBootconfigInclude {
+                boot: true,
+                init_boot: true,
+                vendor_boot: true,
+                dtb: true,
+                dtbo: true,
+            }
+        }
+    }
+
+    /// Helper for generating expected bootconfig after load and verification.
+    pub(crate) fn make_expected_bootconfig(
+        vbmeta_file: &str,
+        slot: char,
+        vendor_config: &str,
+        include: MakeExpectedBootconfigInclude,
+    ) -> Vec<u8> {
+        let vbmeta_file = Path::new(vbmeta_file);
+        let vbmeta_digest = vbmeta_file.with_extension("digest.txt");
+        let vbmeta_digest = vbmeta_digest.to_str().unwrap();
+        let mut builder = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data(vbmeta_file.to_str().unwrap()).len())
+            .digest(read_test_data_as_str(vbmeta_digest).strip_suffix("\n").unwrap())
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .extra("androidboot.force_normal_boot=1\n")
+            .extra(format!("androidboot.slot_suffix=_{slot}\n"))
+            .extra("androidboot.gbl.version=0\n")
+            .extra(format!("androidboot.gbl.build_number={TEST_DEFAULT_BUILD_ID}\n"))
+            .extra(FakeGblOps::GBL_TEST_BOOTCONFIG)
+            .extra(vendor_config);
+
+        for name in ["boot", "vendor_boot", "init_boot", "dtbo", "dtb"].iter() {
+            let file = vbmeta_file.with_extension(format!("{name}.digest.txt"));
+            println!("{file:?}");
+            if include.is_include_str(name)
+                && Path::new(format!("{TEST_DATA_PATH}/{}", file.to_str().unwrap()).as_str())
+                    .exists()
+            {
+                builder = builder.partition_digest(
+                    name,
+                    read_test_data_as_str(file.to_str().unwrap()).strip_suffix("\n").unwrap(),
+                );
+            }
+        }
+
+        builder.build()
+    }
+
+    /// Helper for testing load/verify for a/b slot v0,1,2 image with dtbo partition.
+    ///
+    /// # Args
+    ///
+    /// * `ver`: Boot image version.
+    /// * `slot`: Target slot to boot.
+    /// * `additional_part`: A list of pair `(partition name, file name)` representing additional
+    ///   partitions for creating boot storage.
+    /// * `expected_dtb`: The expected DTB.
+    /// * `expected_dtbo`: The expected DTBO.
+    fn test_android_load_verify_v2_and_lower_slot(
+        ver: u8,
+        slot: char,
+        additional_part: &[(CString, String)],
+        expected_dtb: &[u8],
+        expected_dtbo: &[u8],
+    ) {
+        let dtbo =
+            additional_part.iter().any(|(name, _)| name.to_str().unwrap().starts_with("dtbo_"));
+        let vbmeta = format!("vbmeta_v{ver}_{slot}.img");
+        let boot = format!("boot_v{ver}_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (CString::new(format!("boot_{slot}")).unwrap(), boot.clone()),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_part);
+
+        test_android_load_verify_success(
+            (u64::from(slot) - ('a' as u64)).try_into().unwrap(),
+            &parts,
+            &read_test_data(format!("kernel_{slot}.img")),
+            &read_test_data(format!("generic_ramdisk_{slot}.img")),
+            &make_expected_bootconfig(
+                &vbmeta,
+                slot,
+                "",
+                MakeExpectedBootconfigInclude { dtbo, dtb: false, ..Default::default() },
+            ),
+            expected_dtb,
+            expected_dtbo,
+            "",
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_v0_slot_a() {
+        test_android_load_verify_v2_and_lower_slot(0, 'a', &[], &[], &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_v0_slot_b() {
+        test_android_load_verify_v2_and_lower_slot(0, 'b', &[], &[], &[]);
+    }
+
+    #[test]
+    fn test_android_load_verify_v1_slot_a() {
+        test_android_load_verify_v2_and_lower_slot(1, 'a', &[], &[], &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_v1_slot_b() {
+        test_android_load_verify_v2_and_lower_slot(1, 'b', &[], &[], &[]);
+    }
+
+    #[test]
+    fn test_android_load_verify_v2_slot_a() {
+        test_android_load_verify_v2_and_lower_slot(2, 'a', &[], &test_dtb(), &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_v2_slot_b() {
+        test_android_load_verify_v2_and_lower_slot(2, 'b', &[], &test_dtb(), &[]);
+    }
+
+    fn test_android_load_verify_v2_and_lower_slot_with_dtbo(
+        ver: u8,
+        slot: char,
+        expected_dtb: &[u8],
+    ) {
+        let dtbo = read_test_data(format!("dtbo_{slot}.img"));
+        let parts: Vec<(CString, String)> =
+            vec![(CString::new(format!("dtbo_{slot}")).unwrap(), format!("dtbo_{slot}.img"))];
+        test_android_load_verify_v2_and_lower_slot(ver, slot, &parts, expected_dtb, &dtbo);
+    }
+
+    #[test]
+    fn test_android_load_verify_v0_slot_a_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(0, 'a', &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_v0_slot_b_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(0, 'b', &[]);
+    }
+
+    #[test]
+    fn test_android_load_verify_v1_slot_a_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(1, 'a', &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_v1_slot_b_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(1, 'b', &[]);
+    }
+
+    #[test]
+    fn test_android_load_verify_v2_slot_a_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(2, 'a', &test_dtb())
+    }
+
+    #[test]
+    fn test_android_load_verify_v2_slot_b_with_dtbo() {
+        test_android_load_verify_v2_and_lower_slot_with_dtbo(2, 'b', &test_dtb());
+    }
+
+    /// Helper for testing load/verify for v3/v4 boot/vendor_boot images.
+    ///
+    /// # Args
+    ///
+    /// * `partitions`: A list of pair `(partition name, file name)` for creating boot storage.
+    /// * `vbmeta_file`: The vbmeta file for the storage. Used for constructing expected bootconfig.
+    /// * `expected_kernel`: The expected kernel.
+    /// * `expected_digest`: The expected digest outputed by vbmeta.
+    /// * `expected_vendor_bootconfig`: The expected vendor_boot_config.
+    fn test_android_load_verify_v3_and_v4(
+        slot: char,
+        partitions: &[(CString, String)],
+        vbmeta: &str,
+        expected_kernel: &[u8],
+        expected_vendor_bootconfig: &str,
+        expected_dtbo: &[u8],
+    ) {
+        let dtbo = partitions.iter().any(|(name, _)| name.to_str().unwrap().starts_with("dtbo_"));
+        test_android_load_verify_success(
+            (u64::from(slot) - ('a' as u64)).try_into().unwrap(),
+            partitions,
+            expected_kernel,
+            &[
+                read_test_data(format!("vendor_ramdisk_{slot}.img")),
+                read_test_data(format!("generic_ramdisk_{slot}.img")),
+            ]
+            .concat(),
+            &make_expected_bootconfig(
+                &vbmeta,
+                slot,
+                expected_vendor_bootconfig,
+                MakeExpectedBootconfigInclude { dtbo, dtb: false, ..Default::default() },
+            ),
+            &test_dtb(),
+            expected_dtbo,
+            TEST_VENDOR_CMDLINE,
+        );
+    }
+
+    /// Helper for testing v3/v4 boot image without init_boot partition.
+    fn test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+        slot: char,
+        boot_ver: u32,
+        vendor_ver: u32,
+        additional_part: &[(CString, String)],
+        expected_vendor_bootconfig: &str,
+        expected_dtbo: &[u8],
+    ) {
+        let vbmeta = format!("vbmeta_v{boot_ver}_v{vendor_ver}_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (CString::new(format!("boot_{slot}")).unwrap(), format!("boot_v{boot_ver}_{slot}.img")),
+            (
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v{vendor_ver}_{slot}.img"),
+            ),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_part);
+        test_android_load_verify_v3_and_v4(
+            slot,
+            &parts[..],
+            &vbmeta,
+            &read_test_data(format!("kernel_{slot}.img")),
+            expected_vendor_bootconfig,
+            expected_dtbo,
+        );
+    }
+
+    /// Helper for testing v3/v4 boot image with init_boot partition.
+    fn test_android_load_verify_boot_v3_v4_slot_init_boot(
+        slot: char,
+        boot_ver: u32,
+        vendor_ver: u32,
+        additional_part: &[(CString, String)],
+        expected_vendor_bootconfig: &str,
+        expected_dtbo: &[u8],
+    ) {
+        let vbmeta = format!("vbmeta_v{boot_ver}_v{vendor_ver}_init_boot_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (
+                CString::new(format!("boot_{slot}")).unwrap(),
+                format!("boot_no_ramdisk_v{boot_ver}_{slot}.img"),
+            ),
+            (
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v{vendor_ver}_{slot}.img"),
+            ),
+            (CString::new(format!("init_boot_{slot}")).unwrap(), format!("init_boot_{slot}.img")),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_part);
+        test_android_load_verify_v3_and_v4(
+            slot,
+            &parts[..],
+            &vbmeta,
+            &read_test_data(format!("kernel_{slot}.img")),
+            expected_vendor_bootconfig,
+            expected_dtbo,
+        );
+    }
+
+    enum KernelCompression {
+        LZ4,
+        GZIP,
+    }
+
+    impl fmt::Display for KernelCompression {
+        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
+            match self {
+                KernelCompression::LZ4 => write!(f, "lz4"),
+                KernelCompression::GZIP => write!(f, "gz"),
+            }
+        }
+    }
+
+    /// Helper for testing v4 boot image with different kernel compression.
+    fn test_android_load_verify_boot_v4_compression_slot(
+        compression: KernelCompression,
+        slot: char,
+        expected_vendor_bootconfig: &str,
+        expected_dtbo: &[u8],
+    ) {
+        let vbmeta = format!("vbmeta_v4_{compression}_{slot}.img");
+        let parts: Vec<(CString, String)> = vec![
+            (
+                CString::new(format!("boot_{slot}")).unwrap(),
+                format!("boot_v4_{compression}_{slot}.img"),
+            ),
+            (
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v4_{slot}.img"),
+            ),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        test_android_load_verify_v3_and_v4(
+            slot,
+            &parts[..],
+            &vbmeta,
+            &read_test_data(format!("gki_boot_{compression}_kernel_uncompressed")),
+            expected_vendor_bootconfig,
+            expected_dtbo,
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_no_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot('a', 3, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_no_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot('b', 3, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot('a', 3, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot('b', 3, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_no_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+            'a',
+            3,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_no_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+            'b',
+            3,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot(
+            'a',
+            3,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot(
+            'b',
+            3,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_no_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot('a', 4, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_no_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot('b', 4, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot('a', 4, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot('b', 4, 3, &[], "", &[])
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_no_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+            'a',
+            4,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_no_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+            'b',
+            4,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_init_boot_slot_a() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot(
+            'a',
+            4,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_init_boot_slot_b() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot(
+            'b',
+            4,
+            4,
+            &[],
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    /// Same as `test_android_load_verify_boot_v3_v4_slot_no_init_boot` but with dtbo partition.
+    fn test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo(
+        slot: char,
+        boot_ver: u32,
+        vendor_ver: u32,
+        expected_vendor_bootconfig: &str,
+    ) {
+        let dtbo = read_test_data(format!("dtbo_{slot}.img"));
+        let parts: Vec<(CString, String)> =
+            vec![(CString::new(format!("dtbo_{slot}")).unwrap(), format!("dtbo_{slot}.img"))];
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot(
+            slot,
+            boot_ver,
+            vendor_ver,
+            &parts,
+            expected_vendor_bootconfig,
+            &dtbo,
+        );
+    }
+
+    /// Same as `test_android_load_verify_boot_v3_v4_slot_init_boot` but with dtbo partition.
+    fn test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo(
+        slot: char,
+        boot_ver: u32,
+        vendor_ver: u32,
+        expected_vendor_bootconfig: &str,
+    ) {
+        let dtbo = read_test_data(format!("dtbo_{slot}.img"));
+        let parts: Vec<(CString, String)> =
+            vec![(CString::new(format!("dtbo_{slot}")).unwrap(), format!("dtbo_{slot}.img"))];
+        test_android_load_verify_boot_v3_v4_slot_init_boot(
+            slot,
+            boot_ver,
+            vendor_ver,
+            &parts,
+            expected_vendor_bootconfig,
+            &dtbo,
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_no_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo('a', 3, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_no_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo('b', 3, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo('a', 3, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v3_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo('b', 3, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_no_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo(
+            'a',
+            3,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_no_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo(
+            'b',
+            3,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo(
+            'a',
+            3,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v3_vendor_v4_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo(
+            'b',
+            3,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_no_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo('a', 4, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_no_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo('b', 4, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo('a', 4, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v3_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo('b', 4, 3, "")
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_no_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo(
+            'a',
+            4,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_no_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_no_init_boot_with_dtbo(
+            'b',
+            4,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_init_boot_slot_a_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo(
+            'a',
+            4,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_boot_v4_vendor_v4_init_boot_slot_b_with_dtbo() {
+        test_android_load_verify_boot_v3_v4_slot_init_boot_with_dtbo(
+            'b',
+            4,
+            4,
+            TEST_VENDOR_BOOTCONFIG,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_gzip_boot_v4_vendor_v4_slot_a() {
+        test_android_load_verify_boot_v4_compression_slot(
+            KernelCompression::GZIP,
+            'a',
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_lz4_boot_v4_vendor_v4_slot_a() {
+        test_android_load_verify_boot_v4_compression_slot(
+            KernelCompression::LZ4,
+            'a',
+            TEST_VENDOR_BOOTCONFIG,
+            &[],
+        )
+    }
+}
diff --git a/gbl/libgbl/src/android_boot/mod.rs b/gbl/libgbl/src/android_boot/mod.rs
index 9c5815e..f5b9932 100644
--- a/gbl/libgbl/src/android_boot/mod.rs
+++ b/gbl/libgbl/src/android_boot/mod.rs
@@ -15,539 +15,1363 @@
 //! Android boot support.
 
 use crate::{
-    device_tree::{DeviceTreeComponentSource, DeviceTreeComponentsRegistry, FDT_ALIGNMENT},
-    gbl_avb::{
-        ops::GblAvbOps,
-        state::{BootStateColor, KeyValidationStatus},
+    constants::{FDT_ALIGNMENT, KERNEL_ALIGNMENT},
+    device_tree::{DeviceTreeComponentSource, DeviceTreeComponentsRegistry},
+    fastboot::{
+        run_gbl_fastboot, run_gbl_fastboot_stack, BufferPool, GblFastbootResult, GblTcpStream,
+        GblUsbTransport, LoadedImageInfo, PinFutContainer, Shared,
     },
-    gbl_print, gbl_println, GblOps, IntegrationError, Result,
+    gbl_print, gbl_println,
+    ops::RebootReason,
+    GblOps, Result,
 };
-use arrayvec::ArrayVec;
-use avb::{slot_verify, HashtreeErrorMode, Ops as _, SlotVerifyFlags};
-use bootimg::{BootImage, VendorImageHeader};
-use bootparams::{bootconfig::BootConfigBuilder, commandline::CommandlineBuilder};
-use core::{ffi::CStr, fmt::Write};
+use bootparams::commandline::CommandlineBuilder;
+use core::{array::from_fn, ffi::CStr};
 use dttable::DtTableImage;
-use fdt::Fdt;
+use fastboot::local_session::LocalSession;
+use fdt::{Fdt, FdtHeader};
+use gbl_async::block_on;
 use liberror::Error;
-use libutils::aligned_subslice;
+use libutils::{aligned_offset, aligned_subslice};
 use misc::{AndroidBootMode, BootloaderMessage};
 use safemath::SafeNum;
-use zerocopy::{AsBytes, ByteSlice};
 
-#[cfg(target_arch = "aarch64")]
-use crate::decompress::decompress_kernel;
+mod vboot;
+use vboot::{avb_verify_slot, PartitionsToVerify};
+
+pub(crate) mod load;
+use load::split_chunks;
+pub use load::{android_load_verify, LoadedImages};
 
 /// Device tree bootargs property to store kernel command line.
 pub const BOOTARGS_PROP: &CStr = c"bootargs";
-/// Linux kernel requires 2MB alignment.
-const KERNEL_ALIGNMENT: usize = 2 * 1024 * 1024;
 
 /// A helper to convert a bytes slice containing a null-terminated string to `str`
 fn cstr_bytes_to_str(data: &[u8]) -> core::result::Result<&str, Error> {
     Ok(CStr::from_bytes_until_nul(data)?.to_str()?)
 }
 
-/// Helper function for performing libavb verification.
-///
-/// Currently this requires the caller to preload all relevant images from disk; in its final
-/// state `ops` will provide the necessary callbacks for where the images should go in RAM and
-/// which ones are preloaded.
-///
-/// # Arguments
-/// * `ops`: [GblOps] providing device-specific backend.
-/// * `kernel`: buffer containing the `boot` image loaded from disk.
-/// * `vendor_boot`: buffer containing the `vendor_boot` image loaded from disk.
-/// * `init_boot`: buffer containing the `init_boot` image loaded from disk.
-/// * `dtbo`: buffer containing the `dtbo` image loaded from disk, if it exists.
-/// * `bootconfig_builder`: object to write the bootconfig data into.
+/// Loads Android images from the given slot on disk and fixes up bootconfig, commandline, and FDT.
 ///
-/// # Returns
-/// `()` on success, error if the images fail to verify or we fail to update the bootconfig.
-fn avb_verify_slot<'a, 'b>(
-    ops: &mut impl GblOps<'a, 'b>,
-    kernel: &[u8],
-    vendor_boot: &[u8],
-    init_boot: &[u8],
-    dtbo: Option<&[u8]>,
-    bootconfig_builder: &mut BootConfigBuilder,
-) -> Result<()> {
-    // We need the list of partition names to verify with libavb, and a corresponding list of
-    // (name, image) tuples to register as [GblAvbOps] preloaded data.
-    let mut partitions = ArrayVec::<_, 4>::new();
-    let mut preloaded = ArrayVec::<_, 4>::new();
-    for (c_name, image) in [
-        (c"boot", Some(kernel)),
-        (c"vendor_boot", Some(vendor_boot)),
-        (c"init_boot", Some(init_boot)),
-        (c"dtbo", dtbo),
-    ] {
-        if let Some(image) = image {
-            partitions.push(c_name);
-            preloaded.push((c_name.to_str().unwrap(), image));
-        }
-    }
+/// On success, returns a tuple of (ramdisk, fdt, kernel, unused buffer).
+pub fn android_load_verify_fixup<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'b, 'c>,
+    slot: u8,
+    is_recovery: bool,
+    load: &'a mut [u8],
+) -> Result<(&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8])> {
+    let load_addr = load.as_ptr() as usize;
+    let images = android_load_verify(ops, slot, is_recovery, load)?;
 
-    // TODO(b/337846185): Pass AVB_SLOT_VERIFY_FLAGS_RESTART_CAUSED_BY_HASHTREE_CORRUPTION in
-    // case verity corruption is detected by HLOS.
-    let mut avb_ops = GblAvbOps::new(ops, &preloaded[..], false);
-    let res = slot_verify(
-        &mut avb_ops,
-        &partitions,
-        Some(c"_a"),
-        SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NONE,
-        // TODO(b/337846185): For demo, we use the same setting as Cuttlefish u-boot.
-        // Pass AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO and handle EIO.
-        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
-    )
-    .map_err(|e| IntegrationError::from(e.without_verify_data()))?;
-
-    // TODO(b/337846185): Handle RED and RED_EIO (AVB_HASHTREE_ERROR_MODE_EIO).
-    let color = match avb_ops.read_is_device_unlocked()? {
-        false if avb_ops.key_validation_status()? == KeyValidationStatus::ValidCustomKey => {
-            BootStateColor::Yellow
+    let mut components = DeviceTreeComponentsRegistry::new();
+    let fdt_load = &mut images.unused[..];
+    // TODO(b/353272981): Remove get_custom_device_tree
+    let (fdt_load, base, overlays) = match ops.get_custom_device_tree() {
+        Some(v) => (fdt_load, v, &[][..]),
+        _ => {
+            let mut remains = match images.dtbo.len() > 0 {
+                // TODO(b/384964561, b/374336105): Investigate if we can avoid additional copy.
+                true => {
+                    gbl_println!(ops, "Handling overlays from dtbo");
+                    components.append_from_dttable(
+                        DeviceTreeComponentSource::Dtbo,
+                        &DtTableImage::from_bytes(images.dtbo)?,
+                        fdt_load,
+                    )?
+                }
+                _ => fdt_load,
+            };
+
+            if images.dtb.len() > 0 {
+                gbl_println!(ops, "Handling device tree from boot/vendor_boot");
+                remains = if FdtHeader::from_bytes_ref(images.dtb).is_ok() {
+                    gbl_println!(ops, "Device tree found in boot/vendor_boot");
+                    components.append(ops, DeviceTreeComponentSource::Boot, images.dtb, remains)?
+                } else if let Ok(table) = DtTableImage::from_bytes(images.dtb) {
+                    gbl_println!(
+                        ops,
+                        "Dttable with {} entries found in boot/vendor_boot",
+                        table.entries_count()
+                    );
+                    components.append_from_dttable(
+                        DeviceTreeComponentSource::Boot,
+                        &table,
+                        remains,
+                    )?
+                } else {
+                    return Err(Error::Other(Some(
+                        "Invalid or unrecognized device tree format in boot/vendor_boot",
+                    ))
+                    .into());
+                }
+            }
+
+            if images.dtb_part.len() > 0 {
+                gbl_println!(ops, "Handling device trees from dtb");
+                let dttable = DtTableImage::from_bytes(images.dtb_part)?;
+                remains = components.append_from_dttable(
+                    DeviceTreeComponentSource::Dtb,
+                    &dttable,
+                    remains,
+                )?;
+            }
+
+            gbl_println!(ops, "Selecting device tree components");
+            ops.select_device_trees(&mut components)?;
+            let (base, overlays) = components.selected()?;
+            (remains, base, overlays)
         }
-        false => BootStateColor::Green,
-        true => BootStateColor::Orange,
     };
-    avb_ops.handle_verification_result(&res, color)?;
+    let fdt_load = aligned_subslice(fdt_load, FDT_ALIGNMENT)?;
+    let mut fdt = Fdt::new_from_init(&mut fdt_load[..], base)?;
 
-    // Append avb generated bootconfig.
-    for cmdline_arg in res.cmdline().to_str().unwrap().split(' ') {
-        write!(bootconfig_builder, "{}\n", cmdline_arg).or(Err(Error::BufferTooSmall(None)))?;
-    }
+    // Adds ramdisk range to FDT
+    let ramdisk_addr: u64 = (images.ramdisk.as_ptr() as usize).try_into().map_err(Error::from)?;
+    let ramdisk_end: u64 = ramdisk_addr + u64::try_from(images.ramdisk.len()).unwrap();
+    fdt.set_property("chosen", c"linux,initrd-start", &ramdisk_addr.to_be_bytes())?;
+    fdt.set_property("chosen", c"linux,initrd-end", &ramdisk_end.to_be_bytes())?;
+    gbl_println!(ops, "linux,initrd-start: {:#x}", ramdisk_addr);
+    gbl_println!(ops, "linux,initrd-end: {:#x}", ramdisk_end);
+
+    // Updates the FDT commandline.
+    let device_tree_commandline_length = match fdt.get_property("chosen", BOOTARGS_PROP) {
+        Ok(val) => CStr::from_bytes_until_nul(val).map_err(Error::from)?.to_bytes().len(),
+        Err(_) => 0,
+    };
+
+    // Reserves 1024 bytes for separators and fixup.
+    let final_commandline_len = device_tree_commandline_length
+        + images.boot_cmdline.len()
+        + images.vendor_cmdline.len()
+        + 1024;
+    let final_commandline_buffer =
+        fdt.set_property_placeholder("chosen", BOOTARGS_PROP, final_commandline_len)?;
+    let mut commandline_builder =
+        CommandlineBuilder::new_from_prefix(&mut final_commandline_buffer[..])?;
+    commandline_builder.add(images.boot_cmdline)?;
+    commandline_builder.add(images.vendor_cmdline)?;
 
-    // Append "androidboot.verifiedbootstate="
-    write!(bootconfig_builder, "androidboot.verifiedbootstate={}\n", color)
-        .or(Err(Error::BufferTooSmall(None)))?;
-    Ok(())
+    // TODO(b/353272981): Handle buffer too small
+    commandline_builder.add_with(|current, out| {
+        // TODO(b/353272981): Verify provided command line and fail here.
+        Ok(ops.fixup_os_commandline(current, out)?.map(|fixup| fixup.len()).unwrap_or(0))
+    })?;
+    gbl_println!(ops, "final cmdline: \"{}\"", commandline_builder.as_str());
+
+    gbl_println!(ops, "Applying {} overlays", overlays.len());
+    fdt.multioverlay_apply(overlays)?;
+    gbl_println!(ops, "Overlays applied");
+    // `DeviceTreeComponentsRegistry` internally uses ArrayVec which causes it to have a default
+    // life time equal to the scope it lives in. This is unnecessarily strict and prevents us from
+    // accessing `load` buffer.
+    drop(components);
+
+    // Make sure we provide an actual device tree size, so FW can calculate amount of space
+    // available for fixup.
+    fdt.shrink_to_fit()?;
+    // TODO(b/353272981): Make a copy of current device tree and verify provided fixup.
+    // TODO(b/353272981): Handle buffer too small
+    ops.fixup_device_tree(fdt.as_mut())?;
+    fdt.shrink_to_fit()?;
+
+    // Moves the kernel forward to reserve as much space as possible. This is in case there is not
+    // enough memory after `load`, i.e. the memory after it is not mapped or is reserved.
+    let ramdisk_off = usize::try_from(ramdisk_addr).unwrap() - load_addr;
+    let fdt_len = fdt.header_ref()?.actual_size();
+    let fdt_off = fdt_load.as_ptr() as usize - load_addr;
+    let kernel_off = images.kernel.as_ptr() as usize - load_addr;
+    let kernel_len = images.kernel.len();
+    let mut kernel_new = (SafeNum::from(fdt_off) + fdt_len).try_into().map_err(Error::from)?;
+    kernel_new += aligned_offset(&mut load[kernel_new..], KERNEL_ALIGNMENT)?;
+    load.copy_within(kernel_off..kernel_off + kernel_len, kernel_new);
+    let ([_, ramdisk, fdt, kernel], unused) =
+        split_chunks(load, &[ramdisk_off, fdt_off - ramdisk_off, kernel_new - fdt_off, kernel_len]);
+    let ramdisk = &mut ramdisk[..usize::try_from(ramdisk_end - ramdisk_addr).unwrap()];
+    Ok((ramdisk, fdt, kernel, unused))
 }
 
-/// Helper function to parse common fields from boot image headers.
-///
-/// # Returns
+/// Gets the target slot to boot.
 ///
-/// Returns a tuple of 6 slices corresponding to:
-/// (kernel_size, cmdline, page_size, ramdisk_size, second_size, dtb_size)
-fn boot_header_elements<B: ByteSlice + PartialEq>(
-    hdr: &BootImage<B>,
-) -> Result<(usize, &str, usize, usize, usize, usize)> {
-    const PAGE_SIZE: usize = 4096; // V3/V4 image has fixed page size 4096;
-    Ok(match hdr {
-        BootImage::V2(ref hdr) => (
-            hdr._base._base.kernel_size as usize,
-            cstr_bytes_to_str(&hdr._base._base.cmdline[..])?,
-            hdr._base._base.page_size as usize,
-            hdr._base._base.ramdisk_size as usize,
-            hdr._base._base.second_size as usize,
-            hdr.dtb_size as usize,
-        ),
-        BootImage::V3(ref hdr) => (
-            hdr.kernel_size as usize,
-            cstr_bytes_to_str(&hdr.cmdline[..])?,
-            PAGE_SIZE,
-            hdr.ramdisk_size as usize,
-            0,
-            0,
-        ),
-        BootImage::V4(ref hdr) => (
-            hdr._base.kernel_size as usize,
-            cstr_bytes_to_str(&hdr._base.cmdline[..])?,
-            PAGE_SIZE,
-            hdr._base.ramdisk_size as usize,
-            0,
-            0,
-        ),
-        _ => {
-            return Err(Error::UnsupportedVersion.into());
+/// * If GBL is slotless (`GblOps::get_current_slot()` returns `Error::Unsupported`), the API
+///   behaves the same as `GblOps::get_next_slot()`.
+/// * If GBL is slotted, the API behaves the same as `GblOps::get_current_slot()` and
+///   `mark_boot_attempt` is ignored.
+/// * Default to A slot if slotting backend is not implemented on the platform.
+pub(crate) fn get_boot_slot<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    mark_boot_attempt: bool,
+) -> Result<char> {
+    let slot = match ops.get_current_slot() {
+        // Slotless bootloader
+        Err(Error::Unsupported) => {
+            gbl_println!(ops, "GBL is Slotless.");
+            ops.get_next_slot(mark_boot_attempt)
         }
-    })
+        v => v,
+    };
+    match slot {
+        Ok(slot) => Ok(slot.suffix.0),
+        Err(Error::Unsupported) => {
+            // Default to slot A if slotting is not supported.
+            // Slotless partition name is currently not supported. Revisit if this causes problems.
+            gbl_println!(ops, "Slotting is not supported. Choose A slot by default");
+            Ok('a')
+        }
+        Err(e) => {
+            gbl_println!(ops, "Failed to get boot slot: {e}");
+            Err(e.into())
+        }
+    }
 }
 
-/// Helper function to parse common fields from vendor image headers.
-///
-/// # Returns
-///
-/// Returns a tuple of 5 slices corresponding to:
-/// (vendor_ramdisk_size, hdr_size, cmdline, page_size, dtb_size, vendor_bootconfig_size, vendor_ramdisk_table_size)
-fn vendor_header_elements<B: ByteSlice + PartialEq>(
-    hdr: &VendorImageHeader<B>,
-) -> Result<(usize, usize, &str, usize, usize, usize, usize)> {
-    Ok(match hdr {
-        VendorImageHeader::V3(ref hdr) => (
-            hdr.vendor_ramdisk_size as usize,
-            SafeNum::from(hdr.bytes().len())
-                .round_up(hdr.page_size)
-                .try_into()
-                .map_err(Error::from)?,
-            cstr_bytes_to_str(&hdr.cmdline.as_bytes())?,
-            hdr.page_size as usize,
-            hdr.dtb_size as usize,
-            0,
-            0,
-        ),
-        VendorImageHeader::V4(ref hdr) => (
-            hdr._base.vendor_ramdisk_size as usize,
-            SafeNum::from(hdr.bytes().len())
-                .round_up(hdr._base.page_size)
-                .try_into()
-                .map_err(Error::from)?,
-            cstr_bytes_to_str(&hdr._base.cmdline.as_bytes())?,
-            hdr._base.page_size as usize,
-            hdr._base.dtb_size as usize,
-            hdr.bootconfig_size as usize,
-            hdr.vendor_ramdisk_table_size as usize,
-        ),
-    })
+/// Provides methods to run GBL fastboot.
+pub struct GblFastbootEntry<'d, G> {
+    ops: &'d mut G,
+    load: &'d mut [u8],
+    result: &'d mut GblFastbootResult,
+}
+
+impl<'a, 'd, 'e, G> GblFastbootEntry<'d, G>
+where
+    G: GblOps<'a, 'e>,
+{
+    /// Runs GBL fastboot with the given buffer pool, tasks container, and usb/tcp/local transport
+    /// channels.
+    ///
+    /// # Args
+    ///
+    /// * `buffer_pool`: An implementation of `BufferPool` wrapped in `Shared` for allocating
+    ///    download buffers.
+    /// * `tasks`: An implementation of `PinFutContainer` used as task container for GBL fastboot to
+    // /   schedule dynamically spawned async tasks.
+    /// * `local`: An implementation of `LocalSession` which exchanges fastboot packet from platform
+    ///   specific channels i.e. UX.
+    /// * `usb`: An implementation of `GblUsbTransport` that represents USB channel.
+    /// * `tcp`: An implementation of `GblTcpStream` that represents TCP channel.
+    pub async fn run<'b: 'c, 'c>(
+        self,
+        buffer_pool: &'b Shared<impl BufferPool>,
+        tasks: impl PinFutContainer<'c> + 'c,
+        local: Option<impl LocalSession>,
+        usb: Option<impl GblUsbTransport>,
+        tcp: Option<impl GblTcpStream>,
+    ) where
+        'a: 'c,
+        'd: 'c,
+    {
+        *self.result =
+            run_gbl_fastboot(self.ops, buffer_pool, tasks, local, usb, tcp, self.load).await;
+    }
+
+    /// Runs fastboot with N pre-allocated async worker tasks.
+    ///
+    /// Comparing  to `Self::run()`, this API   simplifies the input by handling the implementation of
+    /// `BufferPool` and `PinFutContainer` internally . However it only supports up to N parallel
+    /// tasks where N is determined at build time. The download buffer will be split into N chunks
+    /// evenly.
+    ///
+    /// The choice of N depends on the level of parallelism the platform can support. For platform
+    /// with `n` storage devices that can independently perform non-blocking IO, it will required
+    /// `N = n + 1` in order to achieve parallel flashing to all storages plus a parallel download.
+    /// However, it is common for partitions that need to be flashed to be on the same block device
+    /// so flashing of them becomes sequential, in which case N can be smaller. Caller should take
+    /// into consideration usage pattern for determining N. If platform only has one physical disk
+    /// or does not expect disks to be parallelizable, a common choice is N=2 which allows
+    /// downloading and flashing to be performed in parallel.
+    pub fn run_n<const N: usize>(
+        self,
+        download: &mut [u8],
+        local: Option<impl LocalSession>,
+        usb: Option<impl GblUsbTransport>,
+        tcp: Option<impl GblTcpStream>,
+    ) {
+        if N < 1 {
+            return self.run_n::<1>(download, local, usb, tcp);
+        }
+        // Splits into N download buffers.
+        let mut arr: [_; N] = from_fn(|_| Default::default());
+        for (i, v) in download.chunks_exact_mut(download.len() / N).enumerate() {
+            arr[i] = v;
+        }
+        let bufs = &mut arr[..];
+        *self.result =
+            block_on(run_gbl_fastboot_stack::<N>(self.ops, bufs, local, usb, tcp, self.load));
+    }
 }
 
-/// Loads Android images from disk and fixes up bootconfig, commandline, and FDT.
+/// Runs full Android bootloader bootflow before kernel handoff.
 ///
-/// A number of simplifications are made:
+/// The API performs slot selection, handles boot mode, fastboot and loads and verifies Android from
+/// disk.
 ///
-///   * No A/B slot switching is performed. It always boot from *_a slot.
-///   * No dynamic partitions.
-///   * Only support V3/V4 image and Android 13+ (generic ramdisk from the "init_boot" partition)
-///   * Only support booting recovery from boot image
+/// # Args:
 ///
-/// # Arguments
-/// * `ops`: the [GblOps] object providing platform-specific backends.
-/// * `load`: the combined buffer to load all images into.
+/// * `ops`: An implementation of `GblOps`.
+/// * `load`: Buffer for loading various Android images.
+/// * `run_fastboot`: A closure for running GBL fastboot. The closure is passed a
+///   `GblFastbootEntry` type which provides methods for running GBL fastboot. The caller is
+///   responsible for preparing the required inputs and calling the method in the closure. See
+///   `GblFastbootEntry` for more details.
 ///
-/// # Returns
-/// Returns a tuple of 4 slices corresponding to:
-///   (ramdisk load buffer, FDT load buffer, kernel load buffer, unused buffer).
-pub fn load_android_simple<'a, 'b, 'c>(
-    ops: &mut impl GblOps<'b, 'c>,
-    load: &'a mut [u8],
-) -> Result<(&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8])> {
-    const PAGE_SIZE: usize = 4096; // V3/V4 image has fixed page size 4096;
-
-    let (bcb_buffer, load) = load.split_at_mut(BootloaderMessage::SIZE_BYTES);
-    ops.read_from_partition_sync("misc", 0, bcb_buffer)?;
-    let bcb = BootloaderMessage::from_bytes_ref(bcb_buffer)?;
-    let boot_mode = bcb.boot_mode()?;
-    gbl_println!(ops, "boot mode from BCB: {}", boot_mode);
-
-    // TODO(b/370317273): use high level abstraction over boot to avoid working
-    // with offsets on application level.
-    // Parse boot header.
-    let (boot_header_buffer, load) = load.split_at_mut(PAGE_SIZE);
-    ops.read_from_partition_sync("boot_a", 0, boot_header_buffer)?;
-    let boot_header = BootImage::parse(boot_header_buffer).map_err(Error::from)?;
-    let (
-        kernel_size,
-        boot_cmdline,
-        kernel_hdr_size,
-        boot_ramdisk_size,
-        boot_second_size,
-        boot_dtb_size,
-    ) = boot_header_elements(&boot_header)?;
-    gbl_println!(ops, "boot image size: {}", kernel_size);
-    gbl_println!(ops, "boot image cmdline: \"{}\"", boot_cmdline);
-    gbl_println!(ops, "boot ramdisk size: {}", boot_ramdisk_size);
-    gbl_println!(ops, "boot dtb size: {}", boot_dtb_size);
-
-    // TODO(b/370317273): use high level abstraction over vendor_boot to avoid working
-    // with offsets on application level.
-    // Parse vendor boot header.
-    let (vendor_boot_header_buffer, load) = load.split_at_mut(PAGE_SIZE);
-    let vendor_boot_header;
-    let (
-        vendor_ramdisk_size,
-        vendor_hdr_size,
-        vendor_cmdline,
-        vendor_page_size,
-        vendor_dtb_size,
-        vendor_bootconfig_size,
-        vendor_ramdisk_table_size,
-    ) = match ops.partition_size("vendor_boot_a") {
-        Ok(Some(_sz)) => {
-            ops.read_from_partition_sync("vendor_boot_a", 0, vendor_boot_header_buffer)?;
-            vendor_boot_header =
-                VendorImageHeader::parse(vendor_boot_header_buffer).map_err(Error::from)?;
-            vendor_header_elements(&vendor_boot_header)?
+/// On success, returns a tuple of slices corresponding to `(ramdisk, FDT, kernel, unused)`
+pub fn android_main<'a, 'b, 'c, G: GblOps<'a, 'b>>(
+    ops: &mut G,
+    load: &'c mut [u8],
+    run_fastboot: impl FnOnce(GblFastbootEntry<'_, G>),
+) -> Result<(&'c mut [u8], &'c mut [u8], &'c mut [u8], &'c mut [u8])> {
+    let (bcb_buffer, _) = load
+        .split_at_mut_checked(BootloaderMessage::SIZE_BYTES)
+        .ok_or(Error::BufferTooSmall(Some(BootloaderMessage::SIZE_BYTES)))
+        .inspect_err(|e| gbl_println!(ops, "Buffer too small for reading misc. {e}"))?;
+    ops.read_from_partition_sync("misc", 0, bcb_buffer)
+        .inspect_err(|e| gbl_println!(ops, "Failed to read misc partition {e}"))?;
+    let bcb = BootloaderMessage::from_bytes_ref(bcb_buffer)
+        .inspect_err(|e| gbl_println!(ops, "Failed to parse bootloader messgae {e}"))?;
+    let boot_mode = bcb
+        .boot_mode()
+        .inspect_err(|e| gbl_println!(ops, "Failed to parse BCB boot mode {e}. Ignored"))
+        .unwrap_or(AndroidBootMode::Normal);
+    gbl_println!(ops, "Boot mode from BCB: {}", boot_mode);
+
+    if matches!(boot_mode, AndroidBootMode::BootloaderBootOnce) {
+        let mut zeroed_command = [0u8; misc::COMMAND_FIELD_SIZE];
+        ops.write_to_partition_sync(
+            "misc",
+            misc::COMMAND_FIELD_OFFSET.try_into().unwrap(),
+            &mut zeroed_command,
+        )?;
+    }
+
+    // Checks platform reboot reason.
+    let reboot_reason = ops
+        .get_reboot_reason()
+        .inspect_err(|e| {
+            gbl_println!(ops, "Failed to get reboot reason from platform: {e}. Ignored.")
+        })
+        .unwrap_or(RebootReason::Normal);
+    gbl_println!(ops, "Reboot reason from platform: {reboot_reason:?}");
+
+    // Checks and enters fastboot.
+    let result = &mut Default::default();
+    if matches!(reboot_reason, RebootReason::Bootloader)
+        || matches!(boot_mode, AndroidBootMode::BootloaderBootOnce)
+        || ops
+            .should_stop_in_fastboot()
+            .inspect_err(|e| {
+                gbl_println!(ops, "Warning: error while checking fastboot trigger ({:?})", e);
+                gbl_println!(ops, "Ignoring error and continuing with normal boot");
+            })
+            .unwrap_or(false)
+    {
+        gbl_println!(ops, "Entering fastboot mode...");
+        run_fastboot(GblFastbootEntry { ops, load: &mut load[..], result });
+        gbl_println!(ops, "Leaving fastboot mode...");
+    }
+
+    // Checks if "fastboot boot" has loaded an android image.
+    match &result.loaded_image_info {
+        Some(LoadedImageInfo::Android { .. }) => {
+            gbl_println!(ops, "Booting from \"fastboot boot\"");
+            return Ok(result.split_loaded_android(load).unwrap());
         }
-        _ => (0 as usize, 0 as usize, "", 0 as usize, 0 as usize, 0 as usize, 0),
+        _ => {}
+    }
+
+    // Checks whether fastboot has set a different active slot. Reboot if it does.
+    let slot_suffix = get_boot_slot(ops, true)?;
+    if result.last_set_active_slot.unwrap_or(slot_suffix) != slot_suffix {
+        gbl_println!(ops, "Active slot changed by \"fastboot set_active\". Reset..");
+        ops.reboot();
+        return Err(Error::UnexpectedReturn.into());
+    }
+
+    // Currently we assume slot suffix only takes value within 'a' to 'z'. Revisit if this
+    // is not the case.
+    //
+    // It's a little awkward to convert suffix char to integer which will then be converted
+    // back to char by the API. Consider passing in the char bytes directly.
+    let slot_idx = (u64::from(slot_suffix) - u64::from('a')).try_into().unwrap();
+
+    let is_recovery = matches!(reboot_reason, RebootReason::Recovery)
+        || matches!(boot_mode, AndroidBootMode::Recovery);
+    android_load_verify_fixup(ops, slot_idx, is_recovery, load)
+}
+
+#[cfg(test)]
+pub(crate) mod tests {
+    use super::*;
+    use crate::{
+        fastboot::test::{make_expected_usb_out, SharedTestListener, TestLocalSession},
+        gbl_avb::state::KeyValidationStatus,
+        ops::test::{slot, FakeGblOps, FakeGblOpsStorage},
+        tests::AlignedBuffer,
+    };
+    use load::tests::{
+        check_ramdisk, make_expected_bootconfig, read_test_data, read_test_data_as_str,
+        AvbResultBootconfigBuilder, MakeExpectedBootconfigInclude, TEST_DEFAULT_BUILD_ID,
+        TEST_PUBLIC_KEY_DIGEST, TEST_VENDOR_BOOTCONFIG,
     };
+    use std::{collections::HashMap, ffi::CString};
 
-    gbl_println!(ops, "vendor ramdisk size: {}", vendor_ramdisk_size);
-    gbl_println!(ops, "vendor cmdline: \"{}\"", vendor_cmdline);
-    gbl_println!(ops, "vendor dtb size: {}", vendor_dtb_size);
+    const TEST_ROLLBACK_INDEX_LOCATION: usize = 1;
 
-    let (dtbo_buffer, load) = match ops.partition_size("dtbo_a") {
-        Ok(Some(sz)) => {
-            let (dtbo_buffer, load) = load.split_at_mut(sz.try_into().unwrap());
-            ops.read_from_partition_sync("dtbo_a", 0, dtbo_buffer)?;
-            (Some(dtbo_buffer), load)
+    /// Helper for testing `android_load_verify_fixup` given a partition layout, target slot and
+    /// custom device tree.
+    fn test_android_load_verify_fixup(
+        slot: u8,
+        partitions: &[(CString, String)],
+        expected_kernel: &[u8],
+        expected_ramdisk: &[u8],
+        expected_bootconfig: &[u8],
+        expected_bootargs: &str,
+        expected_fdt_property: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let mut storage = FakeGblOpsStorage::default();
+        for (part, file) in partitions {
+            storage.add_raw_device(part, read_test_data(file));
         }
-        _ => (None, load),
-    };
+        let mut ops = FakeGblOps::new(&storage);
+        ops.avb_ops.unlock_state = Ok(false);
+        ops.avb_ops.rollbacks = HashMap::from([(TEST_ROLLBACK_INDEX_LOCATION, Ok(0))]);
+        let mut out_color = None;
+        let mut handler = |color,
+                           _: Option<&CStr>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>| {
+            out_color = Some(color);
+            Ok(())
+        };
+        ops.avb_handle_verification_result = Some(&mut handler);
+        ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));
+
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, fdt, kernel, _) =
+            android_load_verify_fixup(&mut ops, slot, false, &mut load_buffer).unwrap();
+        assert_eq!(kernel, expected_kernel);
+        check_ramdisk(ramdisk, expected_ramdisk, expected_bootconfig);
+
+        let fdt = Fdt::new(fdt).unwrap();
+        // "linux,initrd-start/end" are updated.
+        assert_eq!(
+            fdt.get_property("/chosen", c"linux,initrd-start").unwrap(),
+            (ramdisk.as_ptr() as usize).to_be_bytes(),
+        );
+        assert_eq!(
+            fdt.get_property("/chosen", c"linux,initrd-end").unwrap(),
+            (ramdisk.as_ptr() as usize + ramdisk.len()).to_be_bytes(),
+        );
 
-    let mut components: DeviceTreeComponentsRegistry<'a> = DeviceTreeComponentsRegistry::new();
-    let load = match dtbo_buffer {
-        Some(ref dtbo_buffer) => {
-            let dtbo_table = DtTableImage::from_bytes(dtbo_buffer)?;
-            components.append_from_dtbo(&dtbo_table, load)?
+        // Commandlines are updated.
+        assert_eq!(
+            CStr::from_bytes_until_nul(fdt.get_property("/chosen", c"bootargs").unwrap()).unwrap(),
+            CString::new(expected_bootargs).unwrap().as_c_str(),
+        );
+
+        // Fixup is applied.
+        assert_eq!(fdt.get_property("/chosen", c"fixup").unwrap(), &[1]);
+
+        // Other FDT properties are as expected.
+        for (path, property, res) in expected_fdt_property {
+            assert_eq!(
+                fdt.get_property(&path, &property).ok(),
+                res.clone(),
+                "{path}:{property:?} value doesn't match"
+            );
         }
-        _ => load,
-    };
+    }
 
-    // First: check for custom FDT (Cuttlefish).
-    let load = if ops.get_custom_device_tree().is_none() {
-        // Second: "vendor_boot" FDT.
-        let (source, part, offset, size) = if vendor_dtb_size > 0 {
-            // DTB is located after the header and ramdisk (aligned).
-            let offset = (SafeNum::from(vendor_hdr_size) + SafeNum::from(vendor_ramdisk_size))
-                .round_up(vendor_page_size)
-                .try_into()
-                .map_err(Error::from)?;
-            (DeviceTreeComponentSource::VendorBoot, "vendor_boot_a", offset, vendor_dtb_size)
-        // Third: "boot" FDT.
-        } else if boot_dtb_size > 0 {
-            // DTB is located after the header, kernel, ramdisk, and second images (aligned).
-            let mut offset = SafeNum::from(kernel_hdr_size);
-            for image_size in [kernel_size, boot_ramdisk_size, boot_second_size] {
-                offset += SafeNum::from(image_size).round_up(kernel_hdr_size);
-            }
+    /// Helper for testing `android_load_verify_fixup` for v2 boot image or lower.
+    fn test_android_load_verify_fixup_v2_or_lower(
+        ver: u8,
+        slot: char,
+        additional_parts: &[(&CStr, &str)],
+        additional_expected_fdt_properties: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let dtb =
+            additional_parts.iter().any(|(name, _)| name.to_str().unwrap().starts_with("dtb_"));
+        let dtbo =
+            additional_parts.iter().any(|(name, _)| name.to_str().unwrap().starts_with("dtbo_"));
+        let vbmeta = format!("vbmeta_v{ver}_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (CString::new(format!("boot_{slot}")).unwrap(), format!("boot_v{ver}_{slot}.img")),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        for (part, file) in additional_parts.iter().cloned() {
+            parts.push((part.into(), file.into()));
+        }
+
+        test_android_load_verify_fixup(
+            (u64::from(slot) - ('a' as u64)).try_into().unwrap(),
+            &parts,
+            &read_test_data(format!("kernel_{slot}.img")),
+            &read_test_data(format!("generic_ramdisk_{slot}.img")),
+            &make_expected_bootconfig(&vbmeta, slot, "",
+                MakeExpectedBootconfigInclude {dtb, dtbo, ..Default::default() }
+            ),
+            "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2 cmd_key_1=cmd_val_1,cmd_key_2=cmd_val_2",
+            additional_expected_fdt_properties,
+        )
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v0_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"dtb_slot", Some(b"a\0"))];
+        // V0 image doesn't have built-in dtb. We need to provide from dtb partition.
+        let parts = &[(c"dtb_a", "dtb_a.img")];
+        test_android_load_verify_fixup_v2_or_lower(0, 'a', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v0_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"dtb_slot", Some(b"a\0")),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a", "dtbo_a.img"), (c"dtb_a", "dtb_a.img")];
+        test_android_load_verify_fixup_v2_or_lower(0, 'a', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v0_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"dtb_slot", Some(b"b\0"))];
+        let parts = &[(c"dtb_b", "dtb_b.img")];
+        test_android_load_verify_fixup_v2_or_lower(0, 'b', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v0_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"dtb_slot", Some(b"b\0")),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b", "dtbo_b.img"), (c"dtb_b", "dtb_b.img")];
+        test_android_load_verify_fixup_v2_or_lower(0, 'b', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v1_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"dtb_slot", Some(b"a\0"))];
+        // V1 image doesn't have built-in dtb. We need to provide from dtb partition.
+        let parts = &[(c"dtb_a", "dtb_a.img")];
+        test_android_load_verify_fixup_v2_or_lower(1, 'a', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v1_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"dtb_slot", Some(b"a\0")),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a", "dtbo_a.img"), (c"dtb_a", "dtb_a.img")];
+        test_android_load_verify_fixup_v2_or_lower(1, 'a', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v1_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"dtb_slot", Some(b"b\0"))];
+        let parts = &[(c"dtb_b", "dtb_b.img")];
+        test_android_load_verify_fixup_v2_or_lower(1, 'b', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v1_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"dtb_slot", Some(b"b\0")),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b", "dtbo_b.img"), (c"dtb_b", "dtb_b.img")];
+        test_android_load_verify_fixup_v2_or_lower(1, 'b', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v2_slot_a() {
+        // V2 image has built-in dtb. We don't need to provide custom device tree.
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v2_or_lower(2, 'a', &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v2_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        test_android_load_verify_fixup_v2_or_lower(2, 'a', parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v2_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v2_or_lower(2, 'b', &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v2_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        test_android_load_verify_fixup_v2_or_lower(2, 'b', parts, fdt_prop);
+    }
+
+    /// Common helper for testing `android_load_verify_fixup` for v3/v4 boot image.
+    fn test_android_load_verify_fixup_v3_or_v4(
+        slot: char,
+        partitions: &[(CString, String)],
+        vbmeta_file: &str,
+        expected_vendor_bootconfig: &str,
+        additional_expected_fdt_properties: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let dtbo = partitions
+            .iter()
+            .any(|(name, _)| name.clone().into_string().unwrap().starts_with("dtbo_"));
+        let expected_ramdisk = [
+            read_test_data(format!("vendor_ramdisk_{slot}.img")),
+            read_test_data(format!("generic_ramdisk_{slot}.img")),
+        ]
+        .concat();
+        test_android_load_verify_fixup(
+            (u64::from(slot) - ('a' as u64)).try_into().unwrap(),
+            &partitions,
+            &read_test_data(format!("kernel_{slot}.img")),
+            &expected_ramdisk,
+            &make_expected_bootconfig(&vbmeta_file, slot, expected_vendor_bootconfig,
+                MakeExpectedBootconfigInclude { dtbo, dtb: false, ..Default::default() },
+                ),
+            "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2 cmd_key_1=cmd_val_1,cmd_key_2=cmd_val_2 cmd_vendor_key_1=cmd_vendor_val_1,cmd_vendor_key_2=cmd_vendor_val_2",
+            additional_expected_fdt_properties,
+        )
+    }
+
+    /// Helper for testing `android_load_verify_fixup` for v3/v4 boot image without init_boot.
+    fn test_android_load_verify_fixup_v3_or_v4_no_init_boot(
+        boot_ver: u32,
+        vendor_ver: u32,
+        slot: char,
+        expected_vendor_bootconfig: &str,
+        additional_parts: &[(CString, String)],
+        additional_expected_fdt_properties: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let vbmeta = format!("vbmeta_v{boot_ver}_v{vendor_ver}_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (CString::new(format!("boot_{slot}")).unwrap(), format!("boot_v{boot_ver}_{slot}.img")),
+            (
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v{vendor_ver}_{slot}.img"),
+            ),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_parts);
+        test_android_load_verify_fixup_v3_or_v4(
+            slot,
+            &parts,
+            &vbmeta,
+            expected_vendor_bootconfig,
+            additional_expected_fdt_properties,
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_no_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_no_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 3, 'a', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_no_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_no_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 3, 'b', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_no_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_no_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 3, 'a', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_no_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_no_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 3, 'b', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_no_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_no_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 4, 'a', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_no_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_no_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(3, 4, 'b', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 4, 'a', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_no_init_boot(4, 4, 'b', config, parts, fdt_prop);
+    }
+
+    /// Helper for testing `android_load_verify_fixup` with dttable vendor_boot
+    fn test_android_load_verify_fixup_v4_vendor_boot_dttable(
+        slot: char,
+        expected_vendor_bootconfig: &str,
+        additional_parts: &[(CString, String)],
+        additional_expected_fdt_properties: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let vbmeta = format!("vbmeta_v4_dttable_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (CString::new(format!("boot_{slot}")).unwrap(), format!("boot_v4_{slot}.img")),
             (
-                DeviceTreeComponentSource::Boot,
-                "boot_a",
-                offset.try_into().map_err(Error::from)?,
-                boot_dtb_size,
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v4_dttable_{slot}.img"),
+            ),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_parts);
+        test_android_load_verify_fixup_v3_or_v4(
+            slot,
+            &parts,
+            &vbmeta,
+            expected_vendor_bootconfig,
+            additional_expected_fdt_properties,
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_slot_dttable_vendor_boot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v4_vendor_boot_dttable('a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_no_init_boot_slot_dttable_vendor_boot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v4_vendor_boot_dttable('b', config, &[], fdt_prop);
+    }
+
+    /// Helper for testing `android_load_verify_fixup` for v3/v4 boot image with init_boot.
+    fn test_android_load_verify_fixup_v3_or_v4_init_boot(
+        boot_ver: u32,
+        vendor_ver: u32,
+        slot: char,
+        expected_vendor_bootconfig: &str,
+        additional_parts: &[(CString, String)],
+        additional_expected_fdt_properties: &[(&str, &CStr, Option<&[u8]>)],
+    ) {
+        let vbmeta = format!("vbmeta_v{boot_ver}_v{vendor_ver}_init_boot_{slot}.img");
+        let mut parts: Vec<(CString, String)> = vec![
+            (
+                CString::new(format!("boot_{slot}")).unwrap(),
+                format!("boot_no_ramdisk_v{boot_ver}_{slot}.img"),
+            ),
+            (
+                CString::new(format!("vendor_boot_{slot}")).unwrap(),
+                format!("vendor_boot_v{vendor_ver}_{slot}.img"),
+            ),
+            (CString::new(format!("init_boot_{slot}")).unwrap(), format!("init_boot_{slot}.img")),
+            (CString::new(format!("vbmeta_{slot}")).unwrap(), vbmeta.clone()),
+        ];
+        parts.extend_from_slice(additional_parts);
+        test_android_load_verify_fixup_v3_or_v4(
+            slot,
+            &parts,
+            &vbmeta,
+            expected_vendor_bootconfig,
+            additional_expected_fdt_properties,
+        );
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 3, 'a', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v3_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 3, 'b', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 3, 'a', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 3, 'a', "", &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v3_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 3, 'b', "", parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 4, 'a', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v3_v4_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(3, 4, 'b', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_init_boot_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_init_boot_dtbo_slot_a() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_a_property", Some(b"overlay_a_val\0")),
+        ];
+        let parts = &[(c"dtbo_a".into(), "dtbo_a.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 4, 'a', config, parts, fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_init_boot_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[("/chosen", c"builtin", Some(&[1]))];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 4, 'a', config, &[], fdt_prop);
+    }
+
+    #[test]
+    fn test_android_load_verify_fixup_v4_v4_init_boot_dtbo_slot_b() {
+        let fdt_prop: &[(&str, &CStr, Option<&[u8]>)] = &[
+            ("/chosen", c"builtin", Some(&[1])),
+            ("/chosen", c"overlay_b_property", Some(b"overlay_b_val\0")),
+        ];
+        let parts = &[(c"dtbo_b".into(), "dtbo_b.img".into())];
+        let config = TEST_VENDOR_BOOTCONFIG;
+        test_android_load_verify_fixup_v3_or_v4_init_boot(4, 4, 'b', config, parts, fdt_prop);
+    }
+
+    /// Helper for checking V2 image loaded from slot A and in normal mode.
+    pub(crate) fn checks_loaded_v2_slot_a_normal_mode(ramdisk: &[u8], kernel: &[u8]) {
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v2_a.img").len())
+            .digest(read_test_data_as_str("vbmeta_v2_a.digest.txt").strip_suffix("\n").unwrap())
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v2_a.boot.digest.txt").strip_suffix("\n").unwrap(),
             )
-        } else {
-            return Err(Error::NoFdt.into());
-        };
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .extra("androidboot.force_normal_boot=1\n")
+            .extra(format!("androidboot.slot_suffix=_a\n"))
+            .extra("androidboot.gbl.version=0\n")
+            .extra(format!("androidboot.gbl.build_number={TEST_DEFAULT_BUILD_ID}\n"))
+            .extra(FakeGblOps::GBL_TEST_BOOTCONFIG)
+            .build();
+        check_ramdisk(ramdisk, &read_test_data("generic_ramdisk_a.img"), &expected_bootconfig);
+        assert_eq!(kernel, read_test_data("kernel_a.img"));
+    }
 
-        let (fdt_buffer, load) = aligned_subslice(load, FDT_ALIGNMENT)?.split_at_mut(size);
-        ops.read_from_partition_sync(part, offset, fdt_buffer)?;
-        components.append(ops, source, fdt_buffer, load)?
-    } else {
-        load
-    };
+    /// Helper for checking V2 image loaded from slot A and in recovery mode.
+    fn checks_loaded_v2_slot_a_recovery_mode(ramdisk: &[u8], kernel: &[u8]) {
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v2_a.img").len())
+            .digest(read_test_data_as_str("vbmeta_v2_a.digest.txt").strip_suffix("\n").unwrap())
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v2_a.boot.digest.txt").strip_suffix("\n").unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .extra(format!("androidboot.slot_suffix=_a\n"))
+            .extra("androidboot.gbl.version=0\n")
+            .extra(format!("androidboot.gbl.build_number={TEST_DEFAULT_BUILD_ID}\n"))
+            .extra(FakeGblOps::GBL_TEST_BOOTCONFIG)
+            .build();
+        check_ramdisk(ramdisk, &read_test_data("generic_ramdisk_a.img"), &expected_bootconfig);
+        assert_eq!(kernel, read_test_data("kernel_a.img"));
+    }
 
-    // Parse init_boot header
-    let init_boot_header_buffer = &mut load[..PAGE_SIZE];
-    let (generic_ramdisk_size, init_boot_hdr_size) = match ops.partition_size("init_boot_a") {
-        Ok(Some(_sz)) => {
-            ops.read_from_partition_sync("init_boot_a", 0, init_boot_header_buffer)?;
-            let init_boot_header =
-                BootImage::parse(init_boot_header_buffer).map_err(Error::from)?;
-            match init_boot_header {
-                BootImage::V3(ref hdr) => (hdr.ramdisk_size as usize, PAGE_SIZE),
-                BootImage::V4(ref hdr) => (hdr._base.ramdisk_size as usize, PAGE_SIZE),
-                _ => {
-                    gbl_println!(ops, "V0/V1/V2 images are not supported");
-                    return Err(Error::UnsupportedVersion.into());
-                }
-            }
-        }
-        _ => (0, 0),
-    };
-    gbl_println!(ops, "init_boot image size: {}", generic_ramdisk_size);
-
-    // Load and prepare various images.
-    let images_buffer = aligned_subslice(load, KERNEL_ALIGNMENT)?;
-    let load = &mut images_buffer[..];
-
-    // Load kernel
-    // Kernel may need to reserve additional memory after itself. To avoid the risk of this
-    // memory overlapping with ramdisk. We place kernel after ramdisk. We first load it to the tail
-    // of the buffer and move it forward as much as possible after ramdisk and fdt are loaded,
-    // fixed-up and finalized.
-    let boot_img_load_offset: usize = {
-        let off = SafeNum::from(load.len()) - kernel_size - boot_ramdisk_size;
-        let off_idx: usize = off.try_into().map_err(Error::from)?;
-        let aligned_off = off - (&load[off_idx] as *const _ as usize % KERNEL_ALIGNMENT);
-        aligned_off.try_into().map_err(Error::from)?
-    };
-    let (load, boot_img_buffer) = load.split_at_mut(boot_img_load_offset);
-    ops.read_from_partition_sync(
-        "boot_a",
-        kernel_hdr_size.try_into().unwrap(),
-        &mut boot_img_buffer[..kernel_size + boot_ramdisk_size],
-    )?;
-
-    // Load vendor ramdisk
-    let mut ramdisk_load_curr = SafeNum::ZERO;
-    if vendor_ramdisk_size > 0 {
-        ops.read_from_partition_sync(
-            "vendor_boot_a",
-            u64::try_from(vendor_hdr_size).map_err(Error::from)?,
-            &mut load[ramdisk_load_curr.try_into().map_err(Error::from)?..][..vendor_ramdisk_size],
-        )?;
+    /// Helper for getting default FakeGblOps for tests.
+    pub(crate) fn default_test_gbl_ops(storage: &FakeGblOpsStorage) -> FakeGblOps {
+        let mut ops = FakeGblOps::new(&storage);
+        ops.avb_ops.unlock_state = Ok(false);
+        ops.avb_ops.rollbacks = HashMap::from([(TEST_ROLLBACK_INDEX_LOCATION, Ok(0))]);
+        ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));
+        ops.current_slot = Some(Ok(slot('a')));
+        ops.reboot_reason = Some(Ok(RebootReason::Normal));
+        ops
     }
-    ramdisk_load_curr += vendor_ramdisk_size;
 
-    // Load generic ramdisk
-    if generic_ramdisk_size > 0 {
-        ops.read_from_partition_sync(
-            "init_boot_a",
-            init_boot_hdr_size.try_into().unwrap(),
-            &mut load[ramdisk_load_curr.try_into().map_err(Error::from)?..][..generic_ramdisk_size],
-        )?;
-        ramdisk_load_curr += generic_ramdisk_size;
-    }
-
-    // Load ramdisk from boot image
-    if boot_ramdisk_size > 0 {
-        load[ramdisk_load_curr.try_into().map_err(Error::from)?..][..boot_ramdisk_size]
-            .copy_from_slice(&boot_img_buffer[kernel_size..][..boot_ramdisk_size]);
-        ramdisk_load_curr += boot_ramdisk_size;
-    }
-
-    // Prepare partition data for avb verification
-    let (vendor_boot_load_buffer, remains) = load.split_at_mut(vendor_ramdisk_size);
-    let (init_boot_load_buffer, remains) = remains.split_at_mut(generic_ramdisk_size);
-    let (_boot_ramdisk_load_buffer, remains) = remains.split_at_mut(boot_ramdisk_size);
-    // Prepare a BootConfigBuilder to add avb generated bootconfig.
-    let mut bootconfig_builder = BootConfigBuilder::new(remains)?;
-    // Perform avb verification.
-    avb_verify_slot(
-        ops,
-        boot_img_buffer,
-        vendor_boot_load_buffer,
-        init_boot_load_buffer,
-        dtbo_buffer.as_deref(),
-        &mut bootconfig_builder,
-    )?;
-
-    // Move kernel to end of the boot image buffer
-    let (_boot_img_buffer, kernel_tail_buffer) = {
-        let off = SafeNum::from(boot_img_buffer.len()) - kernel_size;
-        let off_idx: usize = off.try_into().map_err(Error::from)?;
-        let aligned_off = off - (&boot_img_buffer[off_idx] as *const _ as usize % KERNEL_ALIGNMENT);
-        let aligned_off_idx = aligned_off.try_into().map_err(Error::from)?;
-        boot_img_buffer.copy_within(0..kernel_size, aligned_off_idx);
-        boot_img_buffer.split_at_mut(aligned_off_idx)
-    };
+    #[test]
+    fn test_android_load_verify_fixup_recovery_mode() {
+        // Recovery mode is specified by the absence of bootconfig arg
+        // "androidboot.force_normal_boot=1\n" and therefore independent of image versions. We can
+        // pick any image version for test. Use v2 for simplicity.
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
 
-    // Add slot index
-    bootconfig_builder.add("androidboot.slot_suffix=_a\n")?;
+        let mut ops = default_test_gbl_ops(&storage);
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) =
+            android_load_verify_fixup(&mut ops, 0, true, &mut load_buffer).unwrap();
+        checks_loaded_v2_slot_a_recovery_mode(ramdisk, kernel)
+    }
 
-    match boot_mode {
-        // TODO(b/329716686): Support bootloader mode
-        AndroidBootMode::Normal | AndroidBootMode::BootloaderBootOnce => {
-            bootconfig_builder.add("androidboot.force_normal_boot=1\n")?
-        }
-        _ => {
-            // Do nothing
-        }
+    #[test]
+    fn test_android_main_bcb_normal_mode() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+
+        let mut ops = default_test_gbl_ops(&storage);
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel)
     }
 
-    // V4 image has vendor bootconfig.
-    if vendor_bootconfig_size > 0 {
-        let mut bootconfig_offset = SafeNum::from(vendor_hdr_size);
-        for image_size in [vendor_ramdisk_size, vendor_dtb_size, vendor_ramdisk_table_size] {
-            bootconfig_offset += SafeNum::from(image_size).round_up(vendor_page_size);
-        }
-        bootconfig_builder.add_with(|_, out| {
-            ops.read_from_partition_sync(
-                "vendor_boot_a",
-                bootconfig_offset.try_into()?,
-                &mut out[..vendor_bootconfig_size as usize],
-            )?;
-            Ok(vendor_bootconfig_size as usize)
-        })?;
+    #[test]
+    fn test_android_main_bcb_recovery_mode() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.write_to_partition_sync("misc", 0, &mut b"boot-recovery".to_vec()).unwrap();
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        checks_loaded_v2_slot_a_recovery_mode(ramdisk, kernel)
     }
 
-    // TODO(b/353272981): Handle buffer too small
-    bootconfig_builder.add_with(|bytes, out| {
-        // TODO(b/353272981): Verify provided bootconfig and fail here
-        Ok(ops.fixup_bootconfig(&bytes, out)?.map(|slice| slice.len()).unwrap_or(0))
-    })?;
-    gbl_println!(ops, "final bootconfig: \"{}\"", bootconfig_builder);
-
-    ramdisk_load_curr += bootconfig_builder.config_bytes().len();
-
-    // On ARM, we may need to decompress the kernel and re-split the buffer to the new kernel size.
-    #[cfg(target_arch = "aarch64")]
-    let (load, kernel_size, kernel_tail_buffer) = {
-        let kernel_size = kernel_tail_buffer.len();
-        let compressed_kernel_offset = images_buffer.len() - kernel_size;
-        let decompressed_kernel_offset =
-            decompress_kernel(ops, images_buffer, compressed_kernel_offset)?;
-        let (load, kernel_tail_buffer) = images_buffer.split_at_mut(decompressed_kernel_offset);
-        (load, kernel_tail_buffer.len(), kernel_tail_buffer)
-    };
+    #[test]
+    fn test_android_main_reboot_reason_recovery_mode() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
 
-    // Use the remaining load buffer for the FDT.
-    let (ramdisk_load_buffer, load) =
-        load.split_at_mut(ramdisk_load_curr.try_into().map_err(Error::from)?);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.reboot_reason = Some(Ok(RebootReason::Recovery));
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        checks_loaded_v2_slot_a_recovery_mode(ramdisk, kernel)
+    }
 
-    let (base, overlays): (&[u8], &[&[u8]]) = if let Some(custom_fdt) = ops.get_custom_device_tree()
-    {
-        (custom_fdt, &[])
-    } else {
-        ops.select_device_trees(&mut components)?;
-        components.selected()?
-    };
+    /// Helper for checking V2 image loaded from slot B and in normal mode.
+    pub(crate) fn checks_loaded_v2_slot_b_normal_mode(ramdisk: &[u8], kernel: &[u8]) {
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v2_b.img").len())
+            .digest(read_test_data_as_str("vbmeta_v2_b.digest.txt").strip_suffix("\n").unwrap())
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v2_b.boot.digest.txt").strip_suffix("\n").unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .extra("androidboot.force_normal_boot=1\n")
+            .extra(format!("androidboot.slot_suffix=_b\n"))
+            .extra("androidboot.gbl.version=0\n")
+            .extra(format!("androidboot.gbl.build_number={TEST_DEFAULT_BUILD_ID}\n"))
+            .extra(FakeGblOps::GBL_TEST_BOOTCONFIG)
+            .build();
+        check_ramdisk(ramdisk, &read_test_data("generic_ramdisk_b.img"), &expected_bootconfig);
+        assert_eq!(kernel, read_test_data("kernel_b.img"));
+    }
 
-    let fdt_buffer = aligned_subslice(load, FDT_ALIGNMENT)?;
-    let mut fdt = Fdt::new_from_init(fdt_buffer, base)?;
+    #[test]
+    fn test_android_main_slotted_gbl_slot_a() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
 
-    gbl_println!(ops, "Applying {} overlays", overlays.len());
-    fdt.multioverlay_apply(overlays)?;
-    gbl_println!(ops, "Overlays applied");
+        let mut ops = default_test_gbl_ops(&storage);
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        assert_eq!(ops.mark_boot_attempt_called, 0);
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel)
+    }
 
-    // Add ramdisk range to FDT
-    let ramdisk_addr: u64 =
-        (ramdisk_load_buffer.as_ptr() as usize).try_into().map_err(Error::from)?;
-    let ramdisk_end: u64 =
-        ramdisk_addr + u64::try_from(ramdisk_load_buffer.len()).map_err(Error::from)?;
-    fdt.set_property("chosen", c"linux,initrd-start", &ramdisk_addr.to_be_bytes())?;
-    fdt.set_property("chosen", c"linux,initrd-end", &ramdisk_end.to_be_bytes())?;
-    gbl_println!(ops, "linux,initrd-start: {:#x}", ramdisk_addr);
-    gbl_println!(ops, "linux,initrd-end: {:#x}", ramdisk_end);
+    #[test]
+    fn test_android_main_slotless_gbl_slot_a() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
 
-    // Update the FDT commandline.
-    let device_tree_commandline_length = match fdt.get_property("chosen", BOOTARGS_PROP) {
-        Ok(val) => CStr::from_bytes_until_nul(val).map_err(Error::from)?.to_bytes().len(),
-        Err(_) => 0,
-    };
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.current_slot = Some(Err(Error::Unsupported));
+        ops.next_slot = Some(Ok(slot('a')));
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        assert_eq!(ops.mark_boot_attempt_called, 1);
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel)
+    }
 
-    // Reserve 1024 bytes for separators and fixup.
-    let final_commandline_len =
-        device_tree_commandline_length + boot_cmdline.len() + vendor_cmdline.len() + 1024;
-    let final_commandline_buffer =
-        fdt.set_property_placeholder("chosen", BOOTARGS_PROP, final_commandline_len)?;
+    #[test]
+    fn test_android_main_slotted_gbl_slot_b() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_b", read_test_data("boot_v2_b.img"));
+        storage.add_raw_device(c"vbmeta_b", read_test_data("vbmeta_v2_b.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
 
-    let mut commandline_builder =
-        CommandlineBuilder::new_from_prefix(&mut final_commandline_buffer[..])?;
-    commandline_builder.add(boot_cmdline)?;
-    commandline_builder.add(vendor_cmdline)?;
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.current_slot = Some(Ok(slot('b')));
 
-    // TODO(b/353272981): Handle buffer too small
-    commandline_builder.add_with(|current, out| {
-        // TODO(b/353272981): Verify provided command line and fail here.
-        Ok(ops.fixup_os_commandline(current, out)?.map(|fixup| fixup.len()).unwrap_or(0))
-    })?;
-    gbl_println!(ops, "final cmdline: \"{}\"", commandline_builder.as_str());
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        assert_eq!(ops.mark_boot_attempt_called, 0);
+        checks_loaded_v2_slot_b_normal_mode(ramdisk, kernel)
+    }
 
-    // Make sure we provide an actual device tree size, so FW can calculate amount of space
-    // available for fixup.
-    fdt.shrink_to_fit()?;
-    // TODO(b/353272981): Make a copy of current device tree and verify provided fixup.
-    // TODO(b/353272981): Handle buffer too small
-    ops.fixup_device_tree(fdt.as_mut())?;
-    fdt.shrink_to_fit()?;
+    #[test]
+    fn test_android_main_slotless_gbl_slot_b() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_b", read_test_data("boot_v2_b.img"));
+        storage.add_raw_device(c"vbmeta_b", read_test_data("vbmeta_v2_b.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
 
-    // Move the kernel backward as much as possible to preserve more space after it. This is
-    // necessary in case the input buffer is at the end of address space.
-    let kernel_tail_buffer_size = kernel_tail_buffer.len();
-    let ramdisk_load_buffer_size = ramdisk_load_buffer.len();
-    let fdt_len = fdt.header_ref()?.actual_size();
-    // Split out the ramdisk.
-    let (ramdisk, remains) = images_buffer.split_at_mut(ramdisk_load_buffer_size);
-    // Split out the fdt.
-    let (fdt, kernel) = aligned_subslice(remains, FDT_ALIGNMENT)?.split_at_mut(fdt_len);
-    // Move the kernel backward as much as possible.
-    let kernel = aligned_subslice(kernel, KERNEL_ALIGNMENT)?;
-    let kernel_start = kernel.len().checked_sub(kernel_tail_buffer_size).unwrap();
-    kernel.copy_within(kernel_start..kernel_start.checked_add(kernel_size).unwrap(), 0);
-    // Split out the remaining buffer.
-    let (kernel, remains) = kernel.split_at_mut(kernel_size);
-
-    Ok((ramdisk, fdt, kernel, remains))
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.current_slot = Some(Err(Error::Unsupported));
+        ops.next_slot = Some(Ok(slot('b')));
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        assert_eq!(ops.mark_boot_attempt_called, 1);
+        checks_loaded_v2_slot_b_normal_mode(ramdisk, kernel);
+    }
+
+    #[test]
+    fn test_android_main_unsupported_slot_default_to_a() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.current_slot = Some(Err(Error::Unsupported));
+        ops.next_slot = Some(Err(Error::Unsupported));
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |_| {}).unwrap();
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel)
+    }
+
+    /// Helper for testing that fastboot mode is triggered.
+    fn test_fastboot_is_triggered<'a, 'b>(ops: &mut impl GblOps<'a, 'b>) {
+        let listener: SharedTestListener = Default::default();
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(ops, &mut load_buffer, |fb| {
+            listener.add_usb_input(b"getvar:max-fetch-size");
+            listener.add_usb_input(b"continue");
+            fb.run_n::<2>(
+                &mut vec![0u8; 256 * 1024],
+                Some(&mut TestLocalSession::default()),
+                Some(&listener),
+                Some(&listener),
+            )
+        })
+        .unwrap();
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(
+                &[b"OKAY0xffffffffffffffff", b"INFOSyncing storage...", b"OKAY",]
+            ),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel);
+    }
+
+    #[test]
+    fn test_android_main_bootonce_bootloader_bcb_command_is_cleared() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.write_to_partition_sync("misc", 0, &mut b"bootonce-bootloader".to_vec()).unwrap();
+        test_fastboot_is_triggered(&mut ops);
+
+        let mut bcb_buffer = [0u8; BootloaderMessage::SIZE_BYTES];
+        ops.read_from_partition_sync("misc", 0, &mut bcb_buffer[..]).unwrap();
+        let bcb = BootloaderMessage::from_bytes_ref(&bcb_buffer).unwrap();
+        assert_eq!(
+            bcb.boot_mode().unwrap(),
+            AndroidBootMode::Normal,
+            "BCB mode is expected to be cleared after bootonce-bootloader is handled"
+        );
+    }
+
+    #[test]
+    fn test_android_main_enter_fastboot_via_bcb() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.write_to_partition_sync("misc", 0, &mut b"bootonce-bootloader".to_vec()).unwrap();
+        test_fastboot_is_triggered(&mut ops);
+    }
+
+    #[test]
+    fn test_android_main_enter_fastboot_via_reboot_reason() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.reboot_reason = Some(Ok(RebootReason::Bootloader));
+        test_fastboot_is_triggered(&mut ops);
+    }
+
+    #[test]
+    fn test_android_main_enter_fastboot_via_should_stop_in_fastboot() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"boot_a", read_test_data("boot_v2_a.img"));
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.stop_in_fastboot = Some(Ok(true));
+        test_fastboot_is_triggered(&mut ops);
+    }
+
+    #[test]
+    fn test_android_main_fastboot_boot() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"vbmeta_a", read_test_data("vbmeta_v2_a.img"));
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.stop_in_fastboot = Some(Ok(true));
+        ops.current_slot = Some(Ok(slot('a')));
+
+        let listener: SharedTestListener = Default::default();
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = android_main(&mut ops, &mut load_buffer, |fb| {
+            let data = read_test_data(format!("boot_v2_a.img"));
+            listener.add_usb_input(format!("download:{:#x}", data.len()).as_bytes());
+            listener.add_usb_input(&data);
+            listener.add_usb_input(b"boot");
+            listener.add_usb_input(b"continue");
+            fb.run_n::<2>(
+                &mut vec![0u8; 256 * 1024],
+                Some(&mut TestLocalSession::default()),
+                Some(&listener),
+                Some(&listener),
+            )
+        })
+        .unwrap();
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[b"DATA00004000", b"OKAY", b"OKAYboot_command",]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel);
+    }
+
+    #[test]
+    fn test_android_main_reboot_if_set_active_to_different_slot() {
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"misc", vec![0u8; 4 * 1024 * 1024]);
+        let mut ops = default_test_gbl_ops(&storage);
+        ops.stop_in_fastboot = Some(Ok(true));
+        ops.current_slot = Some(Ok(slot('a')));
+
+        let listener: SharedTestListener = Default::default();
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        assert_eq!(
+            android_main(&mut ops, &mut load_buffer, |fb| {
+                listener.add_usb_input(b"set_active:b");
+                listener.add_usb_input(b"continue");
+                fb.run_n::<2>(
+                    &mut vec![0u8; 256 * 1024],
+                    Some(&mut TestLocalSession::default()),
+                    Some(&listener),
+                    Some(&listener),
+                )
+            })
+            .unwrap_err(),
+            Error::UnexpectedReturn.into()
+        );
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[b"OKAY", b"INFOSyncing storage...", b"OKAY",]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+    }
 }
diff --git a/gbl/libgbl/src/android_boot/vboot.rs b/gbl/libgbl/src/android_boot/vboot.rs
new file mode 100644
index 0000000..6da6185
--- /dev/null
+++ b/gbl/libgbl/src/android_boot/vboot.rs
@@ -0,0 +1,599 @@
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
+use crate::{
+    gbl_avb::{
+        ops::{GblAvbOps, AVB_DIGEST_KEY},
+        state::{BootStateColor, KeyValidationStatus},
+    },
+    gbl_print, gbl_println, GblOps, Result,
+};
+use abr::SlotIndex;
+use arrayvec::ArrayVec;
+use avb::{slot_verify, HashtreeErrorMode, Ops as _, SlotVerifyFlags};
+use bootparams::{bootconfig::BootConfigBuilder, entry::CommandlineParser};
+use core::{ffi::CStr, fmt::Write};
+use liberror::Error;
+
+// Maximum number of partition allowed for verification.
+//
+// The value is randomly chosen for now. We can update it as we see more usecases.
+const MAX_NUM_PARTITION: usize = 16;
+
+// Type alias for ArrayVec of size `MAX_NUM_PARTITION`:
+type ArrayMaxParts<T> = ArrayVec<T, MAX_NUM_PARTITION>;
+
+/// A container holding partitions for libavb verification
+pub(crate) struct PartitionsToVerify<'a> {
+    partitions: ArrayMaxParts<&'a CStr>,
+    preloaded: ArrayMaxParts<(&'a str, &'a [u8])>,
+}
+
+impl<'a> PartitionsToVerify<'a> {
+    /// Appends a partition to verify
+    #[cfg(test)]
+    pub fn try_push(&mut self, name: &'a CStr) -> Result<()> {
+        self.partitions.try_push(name).or(Err(Error::TooManyPartitions(MAX_NUM_PARTITION)))?;
+        Ok(())
+    }
+
+    /// Appends a partition, along with its preloaded data
+    pub fn try_push_preloaded(&mut self, name: &'a CStr, data: &'a [u8]) -> Result<()> {
+        let err = Err(Error::TooManyPartitions(MAX_NUM_PARTITION));
+        self.partitions.try_push(name).or(err)?;
+        self.preloaded.try_push((name.to_str().unwrap(), data)).or(err)?;
+        Ok(())
+    }
+
+    /// Appends partitions, along with preloaded data
+    pub fn try_extend_preloaded(&mut self, partitions: &PartitionsToVerify<'a>) -> Result<()> {
+        let err = Err(Error::TooManyPartitions(MAX_NUM_PARTITION));
+        self.partitions.try_extend_from_slice(partitions.partitions()).or(err)?;
+        self.preloaded.try_extend_from_slice(partitions.preloaded()).or(err)?;
+        Ok(())
+    }
+
+    fn partitions(&self) -> &[&'a CStr] {
+        &self.partitions
+    }
+
+    fn preloaded(&self) -> &[(&'a str, &'a [u8])] {
+        &self.preloaded
+    }
+}
+
+impl<'a> Default for PartitionsToVerify<'a> {
+    fn default() -> Self {
+        Self { partitions: ArrayMaxParts::new(), preloaded: ArrayMaxParts::new() }
+    }
+}
+
+/// Android verified boot flow.
+///
+/// All relevant images from disk must be preloaded and provided as `partitions`; in its final
+/// state `ops` will provide the necessary callbacks for where the images should go in RAM and
+/// which ones are preloaded.
+///
+/// # Arguments
+/// * `ops`: [GblOps] providing device-specific backend.
+/// * `slot`: The slot index.
+/// * `partitions`: [PartitionsToVerify] providing pre-loaded partitions.
+/// * `bootconfig_builder`: object to write the bootconfig data into.
+///
+/// # Returns
+/// `()` on success. Returns an error if verification process failed and boot cannot
+/// continue, or if parsing the command line or updating the boot configuration fail.
+pub(crate) fn avb_verify_slot<'a, 'b, 'c>(
+    ops: &mut impl GblOps<'a, 'b>,
+    slot: u8,
+    partitions: &PartitionsToVerify<'c>,
+    bootconfig_builder: &mut BootConfigBuilder,
+) -> Result<()> {
+    let slot = match slot {
+        0 => SlotIndex::A,
+        1 => SlotIndex::B,
+        _ => {
+            gbl_println!(ops, "AVB: Invalid slot index: {slot}");
+            return Err(Error::InvalidInput.into());
+        }
+    };
+
+    let mut avb_ops = GblAvbOps::new(ops, Some(slot), partitions.preloaded(), false);
+    let unlocked = avb_ops.read_is_device_unlocked()?;
+    let verify_result = slot_verify(
+        &mut avb_ops,
+        partitions.partitions(),
+        Some(slot.into()),
+        // TODO(b/337846185): Pass AVB_SLOT_VERIFY_FLAGS_RESTART_CAUSED_BY_HASHTREE_CORRUPTION in
+        // case verity corruption is detected by HLOS.
+        match unlocked {
+            true => SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_ALLOW_VERIFICATION_ERROR,
+            _ => SlotVerifyFlags::AVB_SLOT_VERIFY_FLAGS_NONE,
+        },
+        // TODO(b/337846185): For demo, we use the same setting as Cuttlefish u-boot.
+        // Pass AVB_HASHTREE_ERROR_MODE_MANAGED_RESTART_AND_EIO and handle EIO.
+        HashtreeErrorMode::AVB_HASHTREE_ERROR_MODE_RESTART_AND_INVALIDATE,
+    );
+    let (color, verify_data) = match verify_result {
+        Ok(ref verify_data) => {
+            let color = match unlocked {
+                false
+                    if avb_ops.key_validation_status()? == KeyValidationStatus::ValidCustomKey =>
+                {
+                    BootStateColor::Yellow
+                }
+                false => BootStateColor::Green,
+                true => BootStateColor::Orange,
+            };
+
+            gbl_println!(
+                avb_ops.gbl_ops,
+                "AVB verification passed. Device is unlocked: {unlocked}. Color: {color}"
+            );
+
+            (color, Some(verify_data))
+        }
+        // Non-fatal error, can continue booting since verify_data is available.
+        Err(ref e) if e.verification_data().is_some() && unlocked => {
+            let color = BootStateColor::Orange;
+
+            gbl_println!(
+                avb_ops.gbl_ops,
+                "AVB verification failed with {e}. Device is unlocked: {unlocked}. Color: {color}. \
+                Continue current boot attempt."
+            );
+
+            (color, Some(e.verification_data().unwrap()))
+        }
+        // Fatal error. Cannot boot.
+        Err(ref e) => {
+            let color = BootStateColor::Red;
+
+            gbl_println!(
+                avb_ops.gbl_ops,
+                "AVB verification failed with {e}. Device is unlocked: {unlocked}. Color: {color}. \
+                Cannot continue boot."
+            );
+
+            (color, None)
+        }
+    };
+
+    // Gets digest from the result command line.
+    let mut digest = None;
+    if let Some(ref verify_data) = verify_data {
+        for entry in CommandlineParser::new(verify_data.cmdline().to_str().unwrap()) {
+            let entry = entry?;
+            if entry.key == AVB_DIGEST_KEY {
+                digest = entry.value;
+            }
+            write!(bootconfig_builder, "{}\n", entry).or(Err(Error::BufferTooSmall(None)))?;
+        }
+    }
+
+    // Allowes FW to handle verification result.
+    avb_ops.handle_verification_result(verify_data, color, digest)?;
+
+    match color {
+        BootStateColor::Red => Err(verify_result.unwrap_err().without_verify_data().into()),
+        _ => {
+            write!(bootconfig_builder, "androidboot.verifiedbootstate={}\n", color)
+                .or(Err(Error::BufferTooSmall(None)))?;
+
+            Ok(())
+        }
+    }
+}
+
+#[cfg(test)]
+mod test {
+    use super::*;
+    use crate::{
+        android_boot::load::tests::{
+            dump_bootconfig, make_bootconfig, read_test_data, read_test_data_as_str,
+            AvbResultBootconfigBuilder, TEST_PUBLIC_KEY_DIGEST,
+        },
+        ops::test::{FakeGblOps, FakeGblOpsStorage},
+        IntegrationError::AvbIoError,
+    };
+    use avb::{IoError, SlotVerifyError};
+    use std::{collections::HashMap, ffi::CStr};
+
+    /// Helper for testing avb_verify_slot
+    fn test_avb_verify_slot<'a>(
+        partitions: &[(&CStr, &str)],
+        partitions_to_verify: &PartitionsToVerify<'a>,
+        device_unlocked: std::result::Result<bool, avb::IoError>,
+        rollback_result: std::result::Result<u64, avb::IoError>,
+        slot: u8,
+        expected_reported_color: Option<BootStateColor>,
+        expected_bootconfig: &[u8],
+    ) -> Result<()> {
+        let mut storage = FakeGblOpsStorage::default();
+        for (part, file) in partitions {
+            storage.add_raw_device(part, read_test_data(file));
+        }
+        let mut ops = FakeGblOps::new(&storage);
+        ops.avb_ops.unlock_state = device_unlocked;
+        ops.avb_ops.rollbacks = HashMap::from([(1, rollback_result)]);
+        let mut out_color = None;
+        let mut handler = |color,
+                           _: Option<&CStr>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>,
+                           _: Option<&[u8]>| {
+            out_color = Some(color);
+            Ok(())
+        };
+        ops.avb_handle_verification_result = Some(&mut handler);
+        ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));
+
+        let mut bootconfig_buffer = vec![0u8; 512 * 1024];
+        let mut bootconfig_builder = BootConfigBuilder::new(&mut bootconfig_buffer).unwrap();
+        let verify_result =
+            avb_verify_slot(&mut ops, slot, partitions_to_verify, &mut bootconfig_builder);
+        let bootconfig_bytes = bootconfig_builder.config_bytes();
+
+        assert_eq!(out_color, expected_reported_color);
+        assert_eq!(
+            bootconfig_bytes,
+            expected_bootconfig,
+            "\nexpect: \n{}\nactual: \n{}\n",
+            dump_bootconfig(expected_bootconfig),
+            dump_bootconfig(bootconfig_bytes),
+        );
+
+        verify_result
+    }
+
+    #[test]
+    fn test_avb_verify_slot_success() {
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push(c"boot").unwrap();
+        partitions_to_verify.try_push(c"init_boot").unwrap();
+        partitions_to_verify.try_push(c"vendor_boot").unwrap();
+        let partitions_data = [
+            (c"boot_a", "boot_no_ramdisk_v4_a.img"),
+            (c"init_boot_a", "init_boot_a.img"),
+            (c"vendor_boot_a", "vendor_boot_v4_a.img"),
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v4_v4_init_boot_a.img").len())
+            .digest(
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "init_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.init_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "vendor_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .build();
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(false),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Green),
+                // Expected bootcofnig
+                &expected_bootconfig,
+            ),
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_from_preloaded_success() {
+        let boot = read_test_data("boot_no_ramdisk_v4_a.img");
+        let init_boot = read_test_data("init_boot_a.img");
+        let vendor_boot = read_test_data("vendor_boot_v4_a.img");
+
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push_preloaded(c"boot", &boot).unwrap();
+        partitions_to_verify.try_push_preloaded(c"init_boot", &init_boot).unwrap();
+        partitions_to_verify.try_push_preloaded(c"vendor_boot", &vendor_boot).unwrap();
+        let partitions_data = [
+            // Required images aren't presented. Have to rely on preloaded.
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v4_v4_init_boot_a.img").len())
+            .digest(
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "init_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.init_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "vendor_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .build();
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(false),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Green),
+                // Expected bootcofnig
+                &expected_bootconfig,
+            ),
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_success_unlocked() {
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push(c"boot").unwrap();
+        partitions_to_verify.try_push(c"init_boot").unwrap();
+        partitions_to_verify.try_push(c"vendor_boot").unwrap();
+        let partitions_data = [
+            (c"boot_a", "boot_no_ramdisk_v4_a.img"),
+            (c"init_boot_a", "init_boot_a.img"),
+            (c"vendor_boot_a", "vendor_boot_v4_a.img"),
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v4_v4_init_boot_a.img").len())
+            .digest(
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "init_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.init_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "vendor_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .color(BootStateColor::Orange)
+            .unlocked(true)
+            .build();
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(true),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Orange),
+                // Expected bootconfig
+                &expected_bootconfig,
+            ),
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_verification_failed_unlocked() {
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push(c"boot").unwrap();
+        partitions_to_verify.try_push(c"init_boot").unwrap();
+        partitions_to_verify.try_push(c"vendor_boot").unwrap();
+        let partitions_data = [
+            (c"boot_a", "boot_no_ramdisk_v4_a.img"),
+            (c"init_boot_a", "init_boot_a.img"),
+            (c"vendor_boot_a", "vendor_boot_v4_a.img"),
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = AvbResultBootconfigBuilder::new()
+            .vbmeta_size(read_test_data("vbmeta_v4_v4_init_boot_a.img").len())
+            .digest(
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "init_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.init_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .partition_digest(
+                "vendor_boot",
+                read_test_data_as_str("vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt")
+                    .strip_suffix("\n")
+                    .unwrap(),
+            )
+            .public_key_digest(TEST_PUBLIC_KEY_DIGEST)
+            .color(BootStateColor::Orange)
+            .unlocked(true)
+            .build();
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(true),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Orange),
+                // Expected bootconfig
+                &expected_bootconfig,
+            ),
+            // Device is unlocked, so can continue boot
+            Ok(()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_verification_fatal_failed_unlocked() {
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push(c"boot").unwrap();
+        partitions_to_verify.try_push(c"init_boot").unwrap();
+        partitions_to_verify.try_push(c"vendor_boot").unwrap();
+        let partitions_data = [
+            (c"boot_a", "boot_no_ramdisk_v4_a.img"),
+            (c"init_boot_a", "init_boot_a.img"),
+            (c"vendor_boot_a", "vendor_boot_v4_a.img"),
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = make_bootconfig("");
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(true),
+                // Get rollback index is failed
+                Err(IoError::NoSuchValue),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Red),
+                // Expected bootconfig
+                &expected_bootconfig,
+            ),
+            // Fatal error, so cannot continue boot
+            Err(SlotVerifyError::Io.into()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_verification_failed_locked() {
+        let mut partitions_to_verify = PartitionsToVerify::default();
+        partitions_to_verify.try_push(c"boot").unwrap();
+        partitions_to_verify.try_push(c"init_boot").unwrap();
+        partitions_to_verify.try_push(c"vendor_boot").unwrap();
+        let partitions_data = [
+            // Wrong boot image, expect verification to fail.
+            (c"boot_a", "boot_v0_a.img"),
+            (c"init_boot_a", "init_boot_a.img"),
+            (c"vendor_boot_a", "vendor_boot_v4_a.img"),
+            (c"vbmeta_a", "vbmeta_v4_v4_init_boot_a.img"),
+        ];
+        let expected_bootconfig = make_bootconfig("");
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &partitions_data,
+                &partitions_to_verify,
+                // Unlocked result
+                Ok(false),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                Some(BootStateColor::Red),
+                // Expected bootconfig
+                &expected_bootconfig,
+            ),
+            // Cannot continue boot
+            Err(SlotVerifyError::Verification(None).into()),
+        );
+    }
+
+    #[test]
+    fn test_avb_verify_slot_verification_failed_obtain_lock_status() {
+        let partitions_to_verify = PartitionsToVerify::default();
+        let expected_bootconfig = make_bootconfig("");
+
+        assert_eq!(
+            test_avb_verify_slot(
+                &[],
+                &partitions_to_verify,
+                // Unlocked result
+                Err(avb::IoError::NoSuchValue),
+                // Rollback index result
+                Ok(0),
+                // Slot
+                0,
+                // Expected color
+                None,
+                // Expected bootconfig
+                &expected_bootconfig,
+            ),
+            // Cannot continue boot
+            Err(AvbIoError(IoError::NoSuchValue)),
+        );
+    }
+}
diff --git a/gbl/libgbl/src/constants.rs b/gbl/libgbl/src/constants.rs
index 4e195ec..03ff4f5 100644
--- a/gbl/libgbl/src/constants.rs
+++ b/gbl/libgbl/src/constants.rs
@@ -20,6 +20,8 @@ use core::fmt::{Debug, Display, Formatter};
 use liberror::Error;
 use static_assertions::const_assert_eq;
 
+/// Macro for defining Kibibyte-sized constants
+#[macro_export]
 macro_rules! KiB  (
     ($x:expr) => {
         $x*1024
@@ -28,6 +30,8 @@ macro_rules! KiB  (
 const_assert_eq!(KiB!(1), 1024);
 const_assert_eq!(KiB!(5), 5 * 1024);
 
+/// Macro for defining Mebibyte-sized constants
+#[macro_export]
 macro_rules! MiB  (
     ($x:expr) => {
         $x*KiB!(1024)
@@ -36,6 +40,9 @@ macro_rules! MiB  (
 const_assert_eq!(MiB!(1), 1024 * 1024);
 const_assert_eq!(MiB!(5), 5 * 1024 * 1024);
 
+pub use KiB;
+pub use MiB;
+
 /// Kernel image alignment requirement.
 pub const KERNEL_ALIGNMENT: usize = MiB!(2);
 
diff --git a/gbl/libgbl/src/decompress.rs b/gbl/libgbl/src/decompress.rs
index 6a9f63b..5db9815 100644
--- a/gbl/libgbl/src/decompress.rs
+++ b/gbl/libgbl/src/decompress.rs
@@ -14,8 +14,7 @@
 
 //! Image decompression support.
 
-// gzip [DeflateDecoder] requires heap allocation. LZ4 decompression currently uses the heap but
-// could potentially be adjusted to use preallocated buffers if necessary.
+// gzip [DeflateDecoder] requires heap allocation.
 extern crate alloc;
 
 use crate::{gbl_print, gbl_println, GblOps};
@@ -23,67 +22,125 @@ use liberror::{Error, Result};
 use lz4_flex::decompress_into;
 use zune_inflate::DeflateDecoder;
 
-/// Decompresses the given kernel if necessary
+const LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE: &str =
+    "Failed to handle next block of lz4-compressed kernel";
+
+/// Returns if the data is a gzip compressed data.
+fn is_gzip_compressed(data: &[u8]) -> bool {
+    data.starts_with(b"\x1f\x8b")
+}
+
+/// Returns if the data is a lz4 compressed data.
+fn is_lz4_compressed(data: &[u8]) -> bool {
+    data.starts_with(b"\x02\x21\x4c\x18")
+}
+
+/// To iterate over compressed blocks within lz4 structure.
+struct LZ4BlocksIterator<'a> {
+    data: &'a [u8],
+}
+
+impl<'a> LZ4BlocksIterator<'a> {
+    /// Creates a new iterator from lz4 payload.
+    fn new(data: &'a [u8]) -> Self {
+        LZ4BlocksIterator { data }
+    }
+}
+
+impl<'a> Iterator for LZ4BlocksIterator<'a> {
+    type Item = Result<&'a [u8]>;
+
+    fn next(&mut self) -> Option<Self::Item> {
+        if self.data.is_empty() {
+            return None;
+        }
+
+        let Some((block_size, data)) = self.data.split_at_checked(4) else {
+            return Some(Err(Error::Other(Some(LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE))));
+        };
+        self.data = data;
+
+        let block_size = u32::from_le_bytes(block_size.try_into().unwrap()).try_into().unwrap();
+        // Hit end marker
+        if block_size == 0 {
+            return None;
+        }
+
+        let Some((block_content, data)) = self.data.split_at_checked(block_size) else {
+            return Some(Err(Error::Other(Some(LZ4_NEXT_BLOCK_FAILED_ERROR_MESSAGE))));
+        };
+        self.data = data;
+
+        Some(Ok(block_content))
+    }
+}
+
+/// Decompresses lz4 `content` into `out`.
+fn decompress_lz4(content: &[u8], out: &mut [u8]) -> Result<usize> {
+    let blocks = LZ4BlocksIterator::new(content);
+    let mut out_pos = 0;
+
+    for block in blocks {
+        match block {
+            Ok(block) => {
+                out_pos += decompress_into(&block, &mut out[out_pos..])
+                    .map_err(|_| Error::Other(Some("Failed to decompress lz4 block")))?;
+            }
+            Err(e) => {
+                return Err(e);
+            }
+        }
+    }
+
+    Ok(out_pos)
+}
+
+/// Decompresses gzip `content` into `out`.
+///
+/// Dynamic allocation is used insize `decoder.decode_gzip()`.
+fn decompress_gzip(content: &[u8], out: &mut [u8]) -> Result<usize> {
+    let mut decoder = DeflateDecoder::new(content);
+
+    let decompressed_data =
+        decoder.decode_gzip().map_err(|_| Error::Other(Some("Failed to decompress gzip data")))?;
+
+    let decompressed_len = decompressed_data.len();
+    out.get_mut(..decompressed_len)
+        .ok_or(Error::BufferTooSmall(Some(decompressed_len)))?
+        .clone_from_slice(&decompressed_data);
+
+    Ok(decompressed_len)
+}
+
+/// Decompresses `kernel` into `out`.
 ///
-/// The possibly-compressed kernel starts in `buffer`. If it's compressed, it will be decompressed
-/// using heap memory and then copied back into the end of `buffer`.
+/// Supported formats: gzip, lz4, and plain (uncompressed).
+/// If the provided `kernel` is not compressed, it will be copied into `out`
+/// without decompression.
 ///
-/// # Returns
-/// The offset of the decompressed kernel in `buffer`. If the kernel was not compressed. this
-/// function is a no-op and will return `kernel_start` unchanged.
+/// Returns the size of the decompressed data copied into `out`.
 pub fn decompress_kernel<'a, 'b>(
     ops: &mut impl GblOps<'a, 'b>,
-    buffer: &mut [u8],
-    kernel_start: usize,
+    kernel: &[u8],
+    out: &mut [u8],
 ) -> Result<usize> {
-    if buffer[kernel_start..kernel_start + 2] == [0x1f, 0x8b] {
+    if is_gzip_compressed(kernel) {
         gbl_println!(ops, "kernel is gzip compressed");
-        let mut decoder = DeflateDecoder::new(&buffer[kernel_start..]);
-        let decompressed_data = match decoder.decode_gzip() {
-            Ok(decompressed_data) => decompressed_data,
-            _ => {
-                return Err(Error::InvalidInput.into());
-            }
-        };
-        gbl_println!(ops, "kernel decompressed size {}", decompressed_data.len());
-        let kernel_start = buffer.len() - decompressed_data.len();
-        // Move decompressed data to slice.
-        buffer[kernel_start..].clone_from_slice(&decompressed_data);
-        Ok(kernel_start)
-    } else if buffer[kernel_start..kernel_start + 4] == [0x02, 0x21, 0x4c, 0x18] {
+        let decompressed = decompress_gzip(kernel, out)?;
+        gbl_println!(ops, "kernel decompressed size: {decompressed}");
+        Ok(decompressed)
+    } else if is_lz4_compressed(kernel) {
         gbl_println!(ops, "kernel is lz4 compressed");
-        let kernel_tail_buffer = &buffer[kernel_start..];
-        let mut contents = &kernel_tail_buffer[4..];
-        let mut decompressed_kernel = alloc::vec::Vec::new();
-        loop {
-            if contents.len() < 4 {
-                if contents.len() != 0 {
-                    gbl_println!(ops, "Error: some leftover data in the content");
-                }
-                break;
-            }
-            let block_size: usize =
-                u32::from_le_bytes(contents[0..4].try_into().unwrap()).try_into().unwrap();
-            let block;
-            (block, contents) = contents.split_at(block_size + 4);
-            let block = &block[4..];
-            // extend decompressed kernel buffer by 8MB
-            let decompressed_kernel_len = decompressed_kernel.len();
-            decompressed_kernel.resize(decompressed_kernel_len + 8 * 1024 * 1024, 0);
-            // decompress the block
-            let decompressed_data_size =
-                decompress_into(&block, &mut decompressed_kernel[decompressed_kernel_len..])
-                    .unwrap();
-            // reduce the size of decompressed kernel buffer
-            decompressed_kernel.resize(decompressed_kernel_len + decompressed_data_size, 0);
-        }
-        gbl_println!(ops, "kernel decompressed size {}", decompressed_kernel.len());
-        let kernel_start = buffer.len() - decompressed_kernel.len();
-        // Move decompressed data to slice
-        buffer[kernel_start..].clone_from_slice(&decompressed_kernel);
-        Ok(kernel_start)
+        let without_magic = &kernel[4..];
+        let decompressed = decompress_lz4(without_magic, out)?;
+        gbl_println!(ops, "kernel decompressed size: {decompressed}");
+        Ok(decompressed)
     } else {
-        Ok(kernel_start)
+        // Uncompressed case. Just copy into out.
+        out.get_mut(..kernel.len())
+            .ok_or(Error::BufferTooSmall(Some(kernel.len())))?
+            .clone_from_slice(kernel);
+        Ok(kernel.len())
     }
 }
 
@@ -92,22 +149,48 @@ mod test {
     use super::*;
     use crate::ops::test::FakeGblOps;
 
+    // Asserts byte slice equality with clear error on first mismatch.
+    // Avoids full data dump from default assert, which can be very verbose.
+    fn assert_bytes_eq(actual: &[u8], expected: &[u8]) {
+        assert_eq!(actual.len(), expected.len());
+
+        for (i, (l, r)) in expected.iter().zip(actual.iter()).enumerate() {
+            assert_eq!(l, r, "Unmatched byte at index {i}")
+        }
+    }
+
+    fn test_decompress_kernel(input: &[u8], expected_output: &[u8]) {
+        let mut output_buffer = vec![0u8; input.len() * 10];
+
+        let decompressed_len =
+            decompress_kernel(&mut FakeGblOps::default(), input, &mut output_buffer).unwrap();
+
+        assert_bytes_eq(&output_buffer[..decompressed_len], expected_output);
+    }
+
+    #[test]
+    fn decompress_kernel_gzip() {
+        let compressed_gzip = include_bytes!("../testdata/android/gki_boot_gz_kernel").to_vec();
+        let expected_result =
+            include_bytes!("../testdata/android/gki_boot_gz_kernel_uncompressed").to_vec();
+
+        test_decompress_kernel(&compressed_gzip, &expected_result);
+    }
+
     #[test]
     fn decompress_kernel_lz4() {
-        let original_data = "Test TTTTTTTTT 123";
-        let compressed_data = [
-            0x02, 0x21, 0x4c, 0x18, 0x0f, 0x00, 0x00, 0x00, 0x63, 0x54, 0x65, 0x73, 0x74, 0x20,
-            0x54, 0x01, 0x00, 0x50, 0x54, 0x20, 0x31, 0x32, 0x33,
-        ];
-
-        // Create a buffer with the compressed data at the end.
-        let mut buffer = vec![0u8; 8 * 1024];
-        let compressed_offset = buffer.len() - compressed_data.len();
-        buffer[compressed_offset..].clone_from_slice(&compressed_data[..]);
-
-        let offset =
-            decompress_kernel(&mut FakeGblOps::default(), &mut buffer[..], compressed_offset)
-                .unwrap();
-        assert_eq!(&buffer[offset..], original_data.as_bytes());
+        let compressed_gzip = include_bytes!("../testdata/android/gki_boot_lz4_kernel").to_vec();
+        let expected_result =
+            include_bytes!("../testdata/android/gki_boot_lz4_kernel_uncompressed").to_vec();
+
+        test_decompress_kernel(&compressed_gzip, &expected_result);
+    }
+
+    #[test]
+    fn decompress_kernel_raw() {
+        let kernel = include_bytes!("../testdata/android/kernel_a.img").to_vec();
+        let expected_kernel = kernel.clone();
+
+        test_decompress_kernel(&kernel, &expected_kernel);
     }
 }
diff --git a/gbl/libgbl/src/device_tree.rs b/gbl/libgbl/src/device_tree.rs
index 5f9349c..0d5a0fb 100644
--- a/gbl/libgbl/src/device_tree.rs
+++ b/gbl/libgbl/src/device_tree.rs
@@ -14,15 +14,13 @@
 
 //! GblOps trait that defines device tree components helpers.
 
-use crate::{gbl_print, gbl_println, GblOps};
+use crate::{constants::FDT_ALIGNMENT, gbl_print, gbl_println, GblOps};
 use arrayvec::ArrayVec;
 use dttable::{DtTableImage, DtTableMetadata};
 use fdt::{Fdt, FdtHeader, FDT_HEADER_SIZE};
 use liberror::{Error, Result};
 use libutils::aligned_subslice;
 
-/// Device tree alignment.
-pub const FDT_ALIGNMENT: usize = 8;
 /// Maximum amount of device tree components GBL can handle to select from.
 /// TODO(b/353272981): Use dynamic memory to store components. Currently
 /// DeviceTreeComponentsRegistry takes about 18kb of stack, which can be slow and dangerous.
@@ -39,9 +37,9 @@ pub enum DeviceTreeComponentSource {
     /// Loaded from Vendor Boot partition.
     VendorBoot,
     /// Loaded from DTB partition.
-    Dtb(DtTableMetadata),
+    Dtb,
     /// Loaded from DTBO partition.
-    Dtbo(DtTableMetadata),
+    Dtbo,
 }
 
 impl core::fmt::Display for DeviceTreeComponentSource {
@@ -49,8 +47,8 @@ impl core::fmt::Display for DeviceTreeComponentSource {
         match self {
             DeviceTreeComponentSource::Boot => write!(f, "Boot"),
             DeviceTreeComponentSource::VendorBoot => write!(f, "VendorBoot"),
-            DeviceTreeComponentSource::Dtb(_) => write!(f, "Dtb"),
-            DeviceTreeComponentSource::Dtbo(_) => write!(f, "Dtbo"),
+            DeviceTreeComponentSource::Dtb => write!(f, "Dtb"),
+            DeviceTreeComponentSource::Dtbo => write!(f, "Dtbo"),
         }
     }
 }
@@ -60,6 +58,8 @@ impl core::fmt::Display for DeviceTreeComponentSource {
 pub struct DeviceTreeComponent<'a> {
     /// Source the component is loaded from.
     pub source: DeviceTreeComponentSource,
+    /// Metadata for entries loaded from dt_table structure.
+    pub metadata: Option<DtTableMetadata>,
     /// Device tree component payload. Must be 8 bytes aligned.
     pub dt: &'a [u8],
     /// Device tree component is selected.
@@ -82,11 +82,28 @@ impl<'a> DeviceTreeComponent<'a> {
             self.source,
             DeviceTreeComponentSource::Boot
                 | DeviceTreeComponentSource::VendorBoot
-                | DeviceTreeComponentSource::Dtb(_)
+                | DeviceTreeComponentSource::Dtb
         )
     }
 }
 
+fn try_dt_totalsize_from_unaligned_bytes_ref(header: &[u8], buffer: &mut [u8]) -> Result<usize> {
+    let aligned_buffer = aligned_subslice(buffer, FDT_ALIGNMENT)?;
+    let header_slice = aligned_buffer
+        .get_mut(..FDT_HEADER_SIZE)
+        .ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?;
+
+    // Fdt header must be aligned, so copy to an aligned buffer.
+    header_slice.copy_from_slice(
+        &header.get(..FDT_HEADER_SIZE).ok_or(Error::BufferTooSmall(Some(FDT_HEADER_SIZE)))?,
+    );
+
+    match FdtHeader::from_bytes_ref(&header_slice) {
+        Ok(header) => Ok(header.totalsize()),
+        Err(e) => Err(e),
+    }
+}
+
 impl<'a> DeviceTreeComponentsRegistry<'a> {
     /// Create new empty DeviceTreeComponentsRegistry.
     pub fn new() -> Self {
@@ -98,9 +115,9 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
 
     /// Load device tree components from a dt table image. Ensure components are 8 bytes
     /// aligned by using provided buffer to cut from. Returns remain buffer.
-    fn append_from_dttable<'b>(
+    pub fn append_from_dttable<'b>(
         &mut self,
-        is_dtb: bool,
+        source: DeviceTreeComponentSource,
         dttable: &DtTableImage<'b>,
         buffer: &'a mut [u8],
     ) -> Result<&'a mut [u8]> {
@@ -119,11 +136,8 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
             aligned_buffer.copy_from_slice(entry.dtb);
 
             self.components.push(DeviceTreeComponent {
-                source: if is_dtb {
-                    DeviceTreeComponentSource::Dtb(entry.metadata)
-                } else {
-                    DeviceTreeComponentSource::Dtbo(entry.metadata)
-                },
+                source: source,
+                metadata: Some(entry.metadata),
                 dt: aligned_buffer,
                 selected: false,
             });
@@ -134,16 +148,6 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
         Ok(remains)
     }
 
-    /// Load device tree components from a dtbo image. Ensure components are 8 bytes
-    /// aligned by using provided `buffer` to cut from. Returns remain buffer.
-    pub fn append_from_dtbo<'b>(
-        &mut self,
-        dttable: &DtTableImage<'b>,
-        buffer: &'a mut [u8],
-    ) -> Result<&'a mut [u8]> {
-        self.append_from_dttable(false, dttable, buffer)
-    }
-
     /// Append additional device trees from the buffer, where they are stored sequentially.
     /// Ensure components are 8 bytes aligned by using provided buffer to cut from. Returns remain
     /// buffer.
@@ -158,16 +162,10 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
         let mut components_added = 0;
         let mut data_remains = data;
         let mut buffer_remains = buffer;
-        while data_remains.len() >= FDT_HEADER_SIZE {
-            let aligned_buffer = aligned_subslice(buffer_remains, FDT_ALIGNMENT)?;
-
-            let header_slice = aligned_buffer.get_mut(..FDT_HEADER_SIZE).ok_or(Error::Other(
-                Some("Provided buffer is too small to ensure multidt entry is aligned"),
-            ))?;
-            // Fdt header must be aligned, so copy to an aligned buffer.
-            header_slice.copy_from_slice(&data_remains[..FDT_HEADER_SIZE]);
-            let next_fdt_size = FdtHeader::from_bytes_ref(header_slice)?.totalsize();
 
+        while let Ok(next_fdt_size) =
+            try_dt_totalsize_from_unaligned_bytes_ref(data_remains, buffer_remains)
+        {
             if self.components.is_full() {
                 return Err(Error::Other(Some(MAXIMUM_DEVICE_TREE_COMPONENTS_ERROR_MSG)));
             }
@@ -177,6 +175,7 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
                 data_remains.split_at_checked(next_fdt_size).ok_or(Error::Other(Some(
                     "Multidt structure has a valid header but doesn't have a device tree payload",
                 )))?;
+            let aligned_buffer = aligned_subslice(buffer_remains, FDT_ALIGNMENT)?;
             let (aligned_buffer, aligned_buffer_remains) =
                 aligned_buffer.split_at_mut_checked(next_fdt_size).ok_or(Error::Other(Some(
                     "Provided buffer is too small to ensure multidt entry is aligned",
@@ -186,6 +185,7 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
             Fdt::new(&aligned_buffer)?;
             self.components.push(DeviceTreeComponent {
                 source: source,
+                metadata: None,
                 dt: &aligned_buffer[..],
                 selected: false,
             });
@@ -229,6 +229,7 @@ impl<'a> DeviceTreeComponentsRegistry<'a> {
         let (fdt_buffer, fdt_remains) = fdt.split_at(header.totalsize());
         self.components.push(DeviceTreeComponent {
             source: source,
+            metadata: None,
             dt: fdt_buffer,
             selected: false,
         });
@@ -330,6 +331,35 @@ pub(crate) mod test {
             component,
             &DeviceTreeComponent {
                 source: DeviceTreeComponentSource::Boot,
+                metadata: None,
+                dt: &dt[..],
+                selected: false,
+            }
+        );
+        assert!(component.is_base_device_tree());
+    }
+
+    #[test]
+    fn test_components_registry_append_component_with_tail() {
+        let dt = include_bytes!("../../libfdt/test/data/base.dtb").to_vec();
+        let dt_with_tail = [dt.clone(), vec![0; 100]].concat();
+        let mut buffer = vec![0u8; 2 * 1024 * 1024]; // 2 MB
+        let mut gbl_ops = FakeGblOps::new(&[]);
+        let mut registry = DeviceTreeComponentsRegistry::new();
+
+        registry
+            .append(&mut gbl_ops, DeviceTreeComponentSource::Boot, &dt_with_tail[..], &mut buffer)
+            .unwrap();
+
+        assert_eq!(registry.components().count(), 1);
+
+        let component = registry.components().next().unwrap();
+
+        assert_eq!(
+            component,
+            &DeviceTreeComponent {
+                source: DeviceTreeComponentSource::Boot,
+                metadata: None,
                 dt: &dt[..],
                 selected: false,
             }
@@ -359,20 +389,23 @@ pub(crate) mod test {
     }
 
     #[test]
-    fn test_components_append_from_dtbo() {
+    fn test_components_append_from_dttable() {
         let dttable = include_bytes!("../../libdttable/test/data/dttable.img").to_vec();
         let mut buffer = vec![0u8; 2 * 1024 * 1024]; // 2 MB
         let mut registry = DeviceTreeComponentsRegistry::new();
 
         let table = DtTableImage::from_bytes(&dttable[..]).unwrap();
-        registry.append_from_dtbo(&table, &mut buffer[..]).unwrap();
+        registry
+            .append_from_dttable(DeviceTreeComponentSource::Dtbo, &table, &mut buffer[..])
+            .unwrap();
 
         // Check data is loaded
         let components: Vec<_> = registry.components().cloned().collect();
         let expected_components: Vec<DeviceTreeComponent> = table
             .entries()
             .map(|e| DeviceTreeComponent {
-                source: DeviceTreeComponentSource::Dtbo(e.metadata),
+                source: DeviceTreeComponentSource::Dtbo,
+                metadata: Some(e.metadata),
                 dt: e.dtb,
                 selected: false,
             })
@@ -393,9 +426,9 @@ pub(crate) mod test {
         let sources = [
             DeviceTreeComponentSource::VendorBoot,
             DeviceTreeComponentSource::Boot,
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
         ];
         let mut current_buffer = &mut buffer[..];
         for source in sources.iter() {
@@ -427,9 +460,9 @@ pub(crate) mod test {
         let sources = [
             DeviceTreeComponentSource::VendorBoot,
             DeviceTreeComponentSource::Boot,
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
         ];
         let mut current_buffer = &mut buffer[..];
         for source in sources.iter() {
@@ -455,9 +488,9 @@ pub(crate) mod test {
         let sources = [
             DeviceTreeComponentSource::VendorBoot,
             DeviceTreeComponentSource::Boot,
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
         ];
         let mut current_buffer = &mut buffer[..];
         for source in sources.iter() {
@@ -482,9 +515,9 @@ pub(crate) mod test {
         let sources = [
             DeviceTreeComponentSource::VendorBoot,
             DeviceTreeComponentSource::Boot,
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
         ];
         let mut current_buffer = &mut buffer[..];
         for source in sources.iter() {
@@ -508,9 +541,9 @@ pub(crate) mod test {
 
         let sources = [
             DeviceTreeComponentSource::VendorBoot,
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
-            DeviceTreeComponentSource::Dtbo(Default::default()),
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
+            DeviceTreeComponentSource::Dtbo,
         ];
         let mut current_buffer = &mut buffer[..];
         for source in sources.iter() {
@@ -570,12 +603,7 @@ pub(crate) mod test {
         let mut registry = DeviceTreeComponentsRegistry::new();
 
         registry
-            .append(
-                &mut gbl_ops,
-                DeviceTreeComponentSource::Dtbo(Default::default()),
-                &dt[..],
-                &mut buffer,
-            )
+            .append(&mut gbl_ops, DeviceTreeComponentSource::Dtbo, &dt[..], &mut buffer)
             .unwrap();
 
         assert!(registry.autoselect().is_err());
@@ -595,4 +623,19 @@ pub(crate) mod test {
 
         assert_eq!(registry.components().count(), 2);
     }
+
+    #[test]
+    fn test_components_append_from_multifd_with_tail() {
+        let half = include_bytes!("../../libfdt/test/data/base.dtb").to_vec();
+        let dt = [half.clone(), half, vec![0; 100]].concat();
+        let mut buffer = vec![0u8; 2 * 1024 * 1024]; // 2 MB
+        let mut gbl_ops = FakeGblOps::new(&[]);
+        let mut registry = DeviceTreeComponentsRegistry::new();
+
+        registry
+            .append(&mut gbl_ops, DeviceTreeComponentSource::VendorBoot, &dt[..], &mut buffer)
+            .unwrap();
+
+        assert_eq!(registry.components().count(), 2);
+    }
 }
diff --git a/gbl/libgbl/src/error.rs b/gbl/libgbl/src/error.rs
index 2e9ac12..13ec813 100644
--- a/gbl/libgbl/src/error.rs
+++ b/gbl/libgbl/src/error.rs
@@ -15,7 +15,10 @@
 //! Error types used in libgbl.
 
 use avb::{DescriptorError, IoError, SlotVerifyError};
-use core::fmt::{Debug, Display, Formatter};
+use core::{
+    fmt::{Debug, Display, Formatter},
+    num::TryFromIntError,
+};
 
 /// A helper macro for declaring a composite enum type that simply wraps other types as entries.
 /// It auto-generate `From<...>` implementation for each entry type. The type for each entry must
@@ -102,6 +105,7 @@ composite_enum! {
         AvbSlotVerifyError(SlotVerifyError<'static>),
         UnificationError(liberror::Error),
         ZbiError(zbi::ZbiError),
+        TryFromIntError(TryFromIntError),
     }
 }
 
diff --git a/gbl/libgbl/src/fastboot/mod.rs b/gbl/libgbl/src/fastboot/mod.rs
index ebcee8e..9762dc4 100644
--- a/gbl/libgbl/src/fastboot/mod.rs
+++ b/gbl/libgbl/src/fastboot/mod.rs
@@ -15,24 +15,28 @@
 //! Fastboot backend for libgbl.
 
 use crate::{
+    android_boot::{android_load_verify_fixup, get_boot_slot},
     fuchsia_boot::GblAbrOps,
     gbl_print, gbl_println,
+    ops::RambootOps,
     partition::{check_part_unique, GblDisk, PartitionIo},
     GblOps,
 };
 pub use abr::{mark_slot_active, set_one_shot_bootloader, set_one_shot_recovery, SlotIndex};
 use core::{
     array::from_fn, cmp::min, ffi::CStr, fmt::Write, future::Future, marker::PhantomData,
-    mem::take, ops::DerefMut, pin::Pin, str::from_utf8,
+    mem::take, ops::DerefMut, ops::Range, pin::Pin, str::from_utf8,
 };
 use fastboot::{
-    next_arg, next_arg_u64, process_next_command, run_tcp_session, snprintf, CommandError,
-    CommandResult, FastbootImplementation, FormattedBytes, InfoSender, OkaySender, RebootMode,
-    UploadBuilder, Uploader, VarInfoSender,
+    local_session::LocalSession, next_arg, next_arg_u64, process_next_command, run_tcp_session,
+    CommandError, CommandResult, FastbootImplementation, InfoSender, OkaySender, RebootMode,
+    UploadBuilder, Uploader, VarInfoSender, MAX_COMMAND_SIZE,
 };
 use gbl_async::{join, yield_now};
 use gbl_storage::{BlockIo, Disk, Gpt};
 use liberror::Error;
+use libutils::snprintf;
+use libutils::FormattedBytes;
 use safemath::SafeNum;
 use zbi::{ZbiContainer, ZbiType};
 
@@ -58,31 +62,112 @@ pub use fastboot::{TcpStream, Transport};
 /// Reserved name for indicating flashing GPT.
 const FLASH_GPT_PART: &str = "gpt";
 
-/// Represents a GBL Fastboot async task.
-enum Task<'a, 'b, B: BlockIo, P: BufferPool> {
+/// Represents the workload of a GBL Fastboot async task.
+enum TaskWorkload<'a, 'b, B: BlockIo, P: BufferPool> {
     /// Image flashing task. (partition io, downloaded data, data size)
     Flash(PartitionIo<'a, B>, ScopedBuffer<'b, P>, usize),
+    /// Sparse image flashing task. (partition io, downloaded data)
+    FlashSparse(PartitionIo<'a, B>, ScopedBuffer<'b, P>),
     // Image erase task.
     Erase(PartitionIo<'a, B>, ScopedBuffer<'b, P>),
     None,
 }
 
+impl<'a, 'b, B: BlockIo, P: BufferPool> TaskWorkload<'a, 'b, B, P> {
+    /// Runs the task and returns the result
+    async fn run(self) -> Result<(), Error> {
+        match self {
+            Self::Flash(mut io, mut data, sz) => io.write(0, &mut data[..sz]).await,
+            Self::FlashSparse(mut io, mut data) => io.write_sparse(0, &mut data).await,
+            Self::Erase(mut io, mut buffer) => io.zeroize(&mut buffer).await,
+            _ => Ok(()),
+        }
+    }
+}
+
+/// Represents a GBL Fastboot async task.
+struct Task<'a, 'b, B: BlockIo, P: BufferPool> {
+    workload: TaskWorkload<'a, 'b, B, P>,
+    context: [u8; MAX_COMMAND_SIZE],
+}
+
 impl<'a, 'b, B: BlockIo, P: BufferPool> Task<'a, 'b, B, P> {
-    // Runs the task.
+    /// Creates a new instance with the given workload.
+    fn new(workload: TaskWorkload<'a, 'b, B, P>) -> Self {
+        Self { workload, context: [0u8; MAX_COMMAND_SIZE] }
+    }
+
+    /// Sets the context string.
+    fn set_context(&mut self, mut f: impl FnMut(&mut dyn Write) -> Result<(), core::fmt::Error>) {
+        let _ = f(&mut FormattedBytes::new(&mut self.context[..]));
+    }
+
+    /// Runs the task and returns the result.
+    async fn run_checked(self) -> Result<(), Error> {
+        self.workload.run().await
+    }
+
+    /// Runs the task. Panics on error.
+    ///
+    /// The method is intended for use in the context of parallel/background async task where errors
+    /// can't be easily handled by the main routine.
     async fn run(self) {
-        let _ = async {
-            match self {
-                Self::Flash(mut part_io, mut download, data_size) => {
-                    match is_sparse_image(&download) {
-                        Ok(_) => part_io.write_sparse(0, &mut download).await,
-                        _ => part_io.write(0, &mut download[..data_size]).await,
-                    }
-                }
-                Self::Erase(mut part_io, mut buffer) => part_io.zeroize(&mut buffer).await,
-                _ => Ok(()),
-            }
+        match self.workload.run().await {
+            Err(e) => panic!(
+                "A Fastboot async task failed: {e:?}, context: {}",
+                from_utf8(&self.context[..]).unwrap_or("")
+            ),
+            _ => {}
         }
-        .await;
+    }
+}
+
+impl<'a, 'b, B: BlockIo, P: BufferPool> Default for Task<'a, 'b, B, P> {
+    fn default() -> Self {
+        // Creates a noop task. This is mainly used for type inference for inline declaration of
+        // pre-allocated task pool.
+        Self::new(TaskWorkload::None)
+    }
+}
+
+/// Contains the load buffer layout of images loaded by "fastboot boot".
+#[derive(Debug, Clone)]
+pub enum LoadedImageInfo {
+    /// Android loaded images.
+    Android {
+        /// Offset and length of ramdisk in `GblFastboot::load_buffer`.
+        ramdisk: Range<usize>,
+        /// Offset and length of fdt in `GblFastboot::load_buffer`.
+        fdt: Range<usize>,
+        /// Offset and length of kernel in `GblFastboot::load_buffer`.
+        kernel: Range<usize>,
+    },
+}
+
+/// Contains result data returned by GBL Fastboot.
+#[derive(Debug, Clone, Default)]
+pub struct GblFastbootResult {
+    /// Buffer layout for images loaded by "fastboot boot"
+    pub loaded_image_info: Option<LoadedImageInfo>,
+    /// Slot suffix that was last set active by "fastboot set_active"
+    pub last_set_active_slot: Option<char>,
+}
+
+impl GblFastbootResult {
+    /// Splits the given buffer into `(ramdisk, fdt, kernel, unused)` according to layout info in
+    ///  `Self::loaded_image_info` if it is a `Some(LoadedImageInfo::Android)`.
+    pub fn split_loaded_android<'a>(
+        &self,
+        load: &'a mut [u8],
+    ) -> Option<(&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8])> {
+        let Some(LoadedImageInfo::Android { ramdisk, fdt, kernel }) = &self.loaded_image_info
+        else {
+            return None;
+        };
+        let (ramdisk_buf, rem) = load[ramdisk.start..].split_at_mut(ramdisk.len());
+        let (fdt_buf, rem) = rem[fdt.start - ramdisk.end..].split_at_mut(fdt.len());
+        let (kernel_buf, rem) = rem[kernel.start - fdt.end..].split_at_mut(kernel.len());
+        Some((ramdisk_buf, fdt_buf, kernel_buf, rem))
     }
 }
 
@@ -128,7 +213,8 @@ where
     current_download_size: usize,
     enable_async_task: bool,
     default_block: Option<usize>,
-    bootimg_buf: &'b mut [u8],
+    load_buffer: &'b mut [u8],
+    result: GblFastbootResult,
     // Introduces marker type so that we can enforce constraint 'd <= min('b, 'c).
     // The constraint is expressed in the implementation block for the `FastbootImplementation`
     // trait.
@@ -173,7 +259,7 @@ where
         task_mapper: fn(Task<'a, 'b, B, P>) -> F,
         tasks: &'d Shared<C>,
         buffer_pool: &'b Shared<P>,
-        bootimg_buf: &'b mut [u8],
+        load_buffer: &'b mut [u8],
     ) -> Self {
         Self {
             gbl_ops,
@@ -185,7 +271,8 @@ where
             current_download_size: 0,
             enable_async_task: false,
             default_block: None,
-            bootimg_buf,
+            load_buffer,
+            result: Default::default(),
             _tasks_context_lifetime: PhantomData,
             _get_image_buffer_lifetime: PhantomData,
         }
@@ -196,14 +283,15 @@ where
         self.tasks
     }
 
-    /// Listens on the given USB/TCP channels and runs fastboot.
+    /// Listens on the given USB, TCP, and local session channels and runs fastboot.
     async fn run(
         &mut self,
+        mut local: Option<impl LocalSession>,
         mut usb: Option<impl GblUsbTransport>,
         mut tcp: Option<impl GblTcpStream>,
     ) {
-        if usb.is_none() && tcp.is_none() {
-            gbl_println!(self.gbl_ops, "No USB or TCP found for GBL Fastboot");
+        if usb.is_none() && tcp.is_none() && local.is_none() {
+            gbl_println!(self.gbl_ops, "No USB, TCP, or local session found for GBL Fastboot");
             return;
         }
         let tasks = self.tasks();
@@ -211,6 +299,16 @@ where
         let cmd_loop_end = Shared::from(false);
         let cmd_loop_task = async {
             loop {
+                if let Some(ref mut l) = local {
+                    let res = match process_next_command(l, self).await {
+                        Ok(true) => break,
+                        l => l,
+                    };
+                    if res.is_err() {
+                        gbl_println!(self.gbl_ops, "GBL Fastboot local session error: {:?}", res);
+                    }
+                }
+
                 if let Some(v) = usb.as_mut() {
                     if v.has_packet() {
                         let res = match process_next_command(v, self).await {
@@ -355,11 +453,7 @@ where
         loop {
             match self.disks[blk].partition_io(part) {
                 Err(Error::NotReady) => yield_now().await,
-                Ok(v) => {
-                    v.last_err()?;
-                    return Ok(v);
-                }
-                Err(e) => return Err(e.into()),
+                v => return Ok(v?),
             }
         }
     }
@@ -382,7 +476,7 @@ where
         task: Task<'a, 'b, B, P>,
         responder: &mut impl InfoSender,
     ) -> CommandResult<()> {
-        match self.enable_async_task {
+        Ok(match self.enable_async_task {
             true => {
                 let mut t = Some((self.task_mapper)(task));
                 self.tasks.borrow_mut().add_with(|| t.take().unwrap());
@@ -391,12 +485,12 @@ where
                     self.tasks.borrow_mut().add_with(|| t.take().unwrap());
                 }
                 self.tasks.borrow_mut().poll_all();
-                let info = "An IO task is launched. To sync manually, run \"oem gbl-sync-tasks\".";
+                let info =
+                    "An async task is launched. To sync manually, run \"oem gbl-sync-tasks\".";
                 responder.send_info(info).await?
             }
-            _ => task.run().await,
-        };
-        Ok(())
+            _ => task.run_checked().await?,
+        })
     }
 
     /// Waits for all block devices to be ready.
@@ -408,31 +502,17 @@ where
     }
 
     /// Implementation for "fastboot oem gbl-sync-tasks".
-    async fn oem_sync_blocks<'s>(
+    async fn oem_sync_tasks<'s>(
         &self,
-        mut responder: impl InfoSender,
-        res: &'s mut [u8],
+        mut _responder: impl InfoSender,
+        _res: &'s mut [u8],
     ) -> CommandResult<&'s [u8]> {
         self.sync_all_blocks().await?;
-        // Checks error.
-        let mut has_error = false;
-        for (i, ele) in self.disks.iter().enumerate() {
-            match ele.partition_io(None)?.last_err() {
-                Ok(_) => {}
-                Err(e) => {
-                    has_error = true;
-                    responder.send_info(snprintf!(res, "Block #{} error: {:?}.", i, e)).await?;
-                }
-            }
-        }
-        match has_error {
-            true => Err("Errors during async block IO. Please reset device.".into()),
-            _ => Ok(b""),
-        }
+        Ok(b"")
     }
 
     /// Syncs all storage devices and reboots.
-    async fn sync_block_and_reboot(
+    async fn sync_tasks_and_reboot(
         &mut self,
         mode: RebootMode,
         mut resp: impl InfoSender + OkaySender,
@@ -491,6 +571,27 @@ where
         )?;
         Ok(())
     }
+
+    /// Sets active slot.
+    async fn set_active_slot(&mut self, slot: &str) -> CommandResult<()> {
+        self.sync_all_blocks().await?;
+        match self.gbl_ops.expected_os_is_fuchsia()? {
+            // TODO(b/374776896): Prioritizes platform specific `set_active_slot`  if available.
+            true => Ok(mark_slot_active(
+                &mut GblAbrOps(self.gbl_ops),
+                match slot {
+                    "a" => SlotIndex::A,
+                    "b" => SlotIndex::B,
+                    _ => return Err("Invalid slot index for Fuchsia A/B/R".into()),
+                },
+            )?),
+            // We currently assume that slot indices are mapped to suffix 'a' to 'z' starting from
+            // 0. Revisit if we need to support arbitrary slot suffix to index mapping.
+            _ => Ok(self
+                .gbl_ops
+                .set_active_slot(u8::try_from(slot.chars().next().unwrap())? - b'a')?),
+        }
+    }
 }
 
 // See definition of [GblFastboot] for docs on lifetimes and generics parameters.
@@ -550,13 +651,14 @@ where
             };
         }
 
-        let (blk_idx, part_io) = self.parse_and_get_partition_io(part).await?;
-        let (download_buffer, data_size) = self.take_download().ok_or("No download")?;
-        let write_task = Task::Flash(part_io, download_buffer, data_size);
-        self.schedule_task(write_task, &mut responder).await?;
-        // Checks if block is ready already and returns errors. This can be the case when the
-        // operation is synchronous or runs into early errors.
-        Ok(disks[blk_idx].status().result()?)
+        let (_, part_io) = self.parse_and_get_partition_io(part).await?;
+        let (data, sz) = self.take_download().ok_or("No download")?;
+        let mut task = Task::new(match is_sparse_image(&data) {
+            Ok(v) => TaskWorkload::FlashSparse(part_io.sub(0, v.data_size())?, data),
+            _ => TaskWorkload::Flash(part_io.sub(0, sz.try_into().unwrap())?, data, sz),
+        });
+        task.set_context(|f| write!(f, "flash:{part}"));
+        Ok(self.schedule_task(task, &mut responder).await?)
     }
 
     async fn erase(&mut self, part: &str, mut responder: impl InfoSender) -> CommandResult<()> {
@@ -572,13 +674,11 @@ where
             };
         }
 
-        let (blk_idx, part_io) = self.parse_and_get_partition_io(part).await?;
+        let (_, part_io) = self.parse_and_get_partition_io(part).await?;
         self.get_download_buffer().await;
-        let erase_task = Task::Erase(part_io, self.take_download().unwrap().0);
-        self.schedule_task(erase_task, &mut responder).await?;
-        // Checks if block is ready already and returns errors. This can be the case when the
-        // operation is synchronous or runs into early errors.
-        Ok(disks[blk_idx].status().result()?)
+        let mut task = Task::new(TaskWorkload::Erase(part_io, self.take_download().unwrap().0));
+        task.set_context(|f| write!(f, "erase:{part}"));
+        Ok(self.schedule_task(task, &mut responder).await?)
     }
 
     async fn upload(&mut self, _: impl UploadBuilder) -> CommandResult<()> {
@@ -614,7 +714,7 @@ where
         mode: RebootMode,
         resp: impl InfoSender + OkaySender,
     ) -> CommandError {
-        match self.sync_block_and_reboot(mode, resp).await {
+        match self.sync_tasks_and_reboot(mode, resp).await {
             Err(e) => e,
             _ => "Unknown".into(),
         }
@@ -626,19 +726,14 @@ where
     }
 
     async fn set_active(&mut self, slot: &str, _: impl InfoSender) -> CommandResult<()> {
-        self.sync_all_blocks().await?;
-        match self.gbl_ops.expected_os_is_fuchsia()? {
-            // TODO(b/374776896): Prioritizes platform specific `set_active_slot`  if available.
-            true => Ok(mark_slot_active(
-                &mut GblAbrOps(self.gbl_ops),
-                match slot {
-                    "a" => SlotIndex::A,
-                    "b" => SlotIndex::B,
-                    _ => return Err("Invalid slot index for Fuchsia A/B/R".into()),
-                },
-            )?),
-            _ => Err("Not supported".into()),
+        if slot.len() > 1 {
+            return Err("Slot suffix must be one character".into());
         }
+
+        let slot_ch = slot.chars().next().ok_or("Invalid slot")?;
+        self.set_active_slot(slot).await?;
+        self.result.last_set_active_slot = Some(slot_ch);
+        Ok(())
     }
 
     async fn oem<'s>(
@@ -650,7 +745,7 @@ where
         let mut args = cmd.split(' ');
         let cmd = args.next().ok_or("Missing command")?;
         match cmd {
-            "gbl-sync-tasks" => self.oem_sync_blocks(responder, res).await,
+            "gbl-sync-tasks" => self.oem_sync_tasks(responder, res).await,
             "gbl-enable-async-task" => {
                 self.enable_async_task = true;
                 Ok(b"")
@@ -682,17 +777,34 @@ where
         }
     }
 
-    async fn boot(&mut self, mut resp: impl InfoSender + OkaySender) -> CommandResult<()> {
-        let len = core::cmp::min(self.bootimg_buf.len(), self.current_download_size);
-        let data = self.current_download_buffer.as_mut().ok_or("No file staged")?;
-        let data = &mut data[..self.current_download_size];
-
-        self.bootimg_buf[..len].copy_from_slice(&data[..len]);
-        resp.send_info("Boot into boot.img").await?;
+    async fn boot(&mut self, _: impl InfoSender + OkaySender) -> CommandResult<()> {
+        let (mut data, sz) = self.take_download().ok_or("No boot image staged")?;
+        let bootimg_buffer = &mut data[..sz];
+        let load_buffer_addr = self.load_buffer.as_ptr() as usize;
+        let slot_suffix = get_boot_slot(self.gbl_ops, false)?;
+        let mut boot_part = [0u8; 16];
+        let boot_part = snprintf!(boot_part, "boot_{slot_suffix}");
+        // We still need to specify slot because other components such as vendor_boot, dtb, dtbo and
+        // vbmeta still come from the disk.
+        let slot_idx = (u64::from(slot_suffix) - u64::from('a')).try_into().unwrap();
+        let mut ramboot_ops =
+            RambootOps { ops: self.gbl_ops, preloaded_partitions: &[(boot_part, bootimg_buffer)] };
+        let (ramdisk, fdt, kernel, _) =
+            android_load_verify_fixup(&mut ramboot_ops, slot_idx, false, self.load_buffer)?;
+        self.result.loaded_image_info = Some(LoadedImageInfo::Android {
+            ramdisk: to_range(ramdisk.as_ptr() as usize - load_buffer_addr, ramdisk.len()),
+            fdt: to_range(fdt.as_ptr() as usize - load_buffer_addr, fdt.len()),
+            kernel: to_range(kernel.as_ptr() as usize - load_buffer_addr, kernel.len()),
+        });
         Ok(())
     }
 }
 
+/// Helper to convert a offset and length to a range.
+fn to_range(off: usize, len: usize) -> Range<usize> {
+    off..off.checked_add(len).unwrap()
+}
+
 /// `GblUsbTransport` defines transport interfaces for running GBL fastboot over USB.
 pub trait GblUsbTransport: Transport {
     /// Checks whether there is a new USB packet.
@@ -727,15 +839,16 @@ pub async fn run_gbl_fastboot<'a: 'c, 'b: 'c, 'c, 'd>(
     gbl_ops: &mut impl GblOps<'a, 'd>,
     buffer_pool: &'b Shared<impl BufferPool>,
     tasks: impl PinFutContainer<'c> + 'c,
+    local: Option<impl LocalSession>,
     usb: Option<impl GblUsbTransport>,
     tcp: Option<impl GblTcpStream>,
-    bootimg_buf: &'b mut [u8],
-) {
+    load_buffer: &'b mut [u8],
+) -> GblFastbootResult {
     let tasks = tasks.into();
     let disks = gbl_ops.disks();
-    GblFastboot::new(gbl_ops, disks, Task::run, &tasks, buffer_pool, bootimg_buf)
-        .run(usb, tcp)
-        .await;
+    let mut fb = GblFastboot::new(gbl_ops, disks, Task::run, &tasks, buffer_pool, load_buffer);
+    fb.run(local, usb, tcp).await;
+    fb.result
 }
 
 /// Runs GBL fastboot on the given USB/TCP channels with N stack allocated worker tasks.
@@ -757,13 +870,14 @@ pub async fn run_gbl_fastboot<'a: 'c, 'b: 'c, 'c, 'd>(
 pub async fn run_gbl_fastboot_stack<'a, 'b, const N: usize>(
     gbl_ops: &mut impl GblOps<'a, 'b>,
     buffer_pool: impl BufferPool,
+    local: Option<impl LocalSession>,
     usb: Option<impl GblUsbTransport>,
     tcp: Option<impl GblTcpStream>,
-    bootimg_buf: &mut [u8],
-) {
+    load_buffer: &mut [u8],
+) -> GblFastbootResult {
     let buffer_pool = buffer_pool.into();
     // Creates N worker tasks.
-    let mut tasks: [_; N] = from_fn(|_| Task::None.run());
+    let mut tasks: [_; N] = from_fn(|_| Task::default().run());
     // It is possible to avoid the use of the unsafe `Pin::new_unchecked` by delaring the array and
     // manually pinning each element i.e.
     //
@@ -781,9 +895,9 @@ pub async fn run_gbl_fastboot_stack<'a, 'b, const N: usize>(
     let mut tasks: [_; N] = tasks.each_mut().map(|v| unsafe { Pin::new_unchecked(v) });
     let tasks = PinFutSlice::new(&mut tasks[..]).into();
     let disks = gbl_ops.disks();
-    GblFastboot::new(gbl_ops, disks, Task::run, &tasks, &buffer_pool, bootimg_buf)
-        .run(usb, tcp)
-        .await;
+    let mut fb = GblFastboot::new(gbl_ops, disks, Task::run, &tasks, &buffer_pool, load_buffer);
+    fb.run(local, usb, tcp).await;
+    fb.result
 }
 
 /// Pre-generates a Fuchsia Fastboot MDNS service broadcast packet.
@@ -836,10 +950,20 @@ pub fn fuchsia_fastboot_mdns_packet(node_name: &str, ipv6_addr: &[u8]) -> Result
 }
 
 #[cfg(test)]
-mod test {
+pub(crate) mod test {
     use super::*;
     use crate::{
-        ops::test::{FakeGblOps, FakeGblOpsStorage},
+        android_boot::{
+            load::tests::read_test_data,
+            tests::{
+                checks_loaded_v2_slot_a_normal_mode, checks_loaded_v2_slot_b_normal_mode,
+                default_test_gbl_ops,
+            },
+        },
+        constants::KiB,
+        constants::KERNEL_ALIGNMENT,
+        ops::test::{slot, FakeGblOps, FakeGblOpsStorage},
+        tests::AlignedBuffer,
         Os,
     };
     use abr::{
@@ -857,7 +981,7 @@ mod test {
     use spin::{Mutex, MutexGuard};
     use std::ffi::CString;
     use std::{collections::VecDeque, io::Read};
-    use zerocopy::AsBytes;
+    use zerocopy::IntoBytes;
 
     /// A test implementation of [InfoSender] and [OkaySender].
     #[derive(Default)]
@@ -921,7 +1045,7 @@ mod test {
 
     #[test]
     fn test_get_var_gbl() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let storage = FakeGblOpsStorage::default();
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
@@ -938,12 +1062,12 @@ mod test {
 
     #[test]
     fn test_get_var_partition_info() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
-        storage.add_raw_device(c"raw_0", [0xaau8; 4 * 1024]);
-        storage.add_raw_device(c"raw_1", [0x55u8; 8 * 1024]);
+        storage.add_raw_device(c"raw_0", [0xaau8; KiB!(4)]);
+        storage.add_raw_device(c"raw_1", [0x55u8; KiB!(8)]);
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
@@ -997,12 +1121,12 @@ mod test {
 
     #[test]
     fn test_get_var_all() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
-        storage.add_raw_device(c"raw_0", [0xaau8; 4 * 1024]);
-        storage.add_raw_device(c"raw_1", [0x55u8; 8 * 1024]);
+        storage.add_raw_device(c"raw_0", [0xaau8; KiB!(4)]);
+        storage.add_raw_device(c"raw_1", [0x55u8; KiB!(8)]);
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
@@ -1066,7 +1190,7 @@ mod test {
 
     #[test]
     fn test_fetch_invalid_partition_arg() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
@@ -1115,7 +1239,7 @@ mod test {
 
     #[test]
     fn test_fetch_raw_block() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         let disk_0 = include_bytes!("../../../libstorage/test/gpt_test_1.bin");
         let disk_1 = include_bytes!("../../../libstorage/test/gpt_test_2.bin");
@@ -1157,12 +1281,12 @@ mod test {
 
     #[test]
     fn test_fetch_partition() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
-        storage.add_raw_device(c"raw_0", [0xaau8; 4 * 1024]);
-        storage.add_raw_device(c"raw_1", [0x55u8; 8 * 1024]);
+        storage.add_raw_device(c"raw_0", [0xaau8; KiB!(4)]);
+        storage.add_raw_device(c"raw_1", [0x55u8; KiB!(8)]);
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
@@ -1181,16 +1305,16 @@ mod test {
         check_part_upload(&mut gbl_fb, "boot_b", off, size, Some(0), expect_boot_b);
         check_part_upload(&mut gbl_fb, "vendor_boot_a", off, size, Some(1), expect_vendor_boot_a);
         check_part_upload(&mut gbl_fb, "vendor_boot_b", off, size, Some(1), expect_vendor_boot_b);
-        check_part_upload(&mut gbl_fb, "raw_0", off, size, Some(2), &[0xaau8; 4 * 1024]);
-        check_part_upload(&mut gbl_fb, "raw_1", off, size, Some(3), &[0x55u8; 8 * 1024]);
+        check_part_upload(&mut gbl_fb, "raw_0", off, size, Some(2), &[0xaau8; KiB!(4)]);
+        check_part_upload(&mut gbl_fb, "raw_1", off, size, Some(3), &[0x55u8; KiB!(8)]);
 
         // No block device id
         check_part_upload(&mut gbl_fb, "boot_a", off, size, None, expect_boot_a);
         check_part_upload(&mut gbl_fb, "boot_b", off, size, None, expect_boot_b);
         check_part_upload(&mut gbl_fb, "vendor_boot_a", off, size, None, expect_vendor_boot_a);
         check_part_upload(&mut gbl_fb, "vendor_boot_b", off, size, None, expect_vendor_boot_b);
-        check_part_upload(&mut gbl_fb, "raw_0", off, size, None, &[0xaau8; 4 * 1024]);
-        check_part_upload(&mut gbl_fb, "raw_1", off, size, None, &[0x55u8; 8 * 1024]);
+        check_part_upload(&mut gbl_fb, "raw_0", off, size, None, &[0xaau8; KiB!(4)]);
+        check_part_upload(&mut gbl_fb, "raw_1", off, size, None, &[0x55u8; KiB!(8)]);
     }
 
     /// A helper function to get a bit-flipped copy of the input data.
@@ -1220,12 +1344,12 @@ mod test {
     fn test_flash_partition() {
         let disk_0 = include_bytes!("../../../libstorage/test/gpt_test_1.bin");
         let disk_1 = include_bytes!("../../../libstorage/test/gpt_test_2.bin");
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(disk_0);
         storage.add_gpt_device(disk_1);
-        storage.add_raw_device(c"raw_0", [0xaau8; 4 * 1024]);
-        storage.add_raw_device(c"raw_1", [0x55u8; 8 * 1024]);
+        storage.add_raw_device(c"raw_0", [0xaau8; KiB!(4)]);
+        storage.add_raw_device(c"raw_1", [0x55u8; KiB!(8)]);
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
@@ -1236,8 +1360,8 @@ mod test {
         let expect_boot_b = include_bytes!("../../../libstorage/test/boot_b.bin");
         check_flash_part(&mut gbl_fb, "boot_a", expect_boot_a);
         check_flash_part(&mut gbl_fb, "boot_b", expect_boot_b);
-        check_flash_part(&mut gbl_fb, "raw_0", &[0xaau8; 4 * 1024]);
-        check_flash_part(&mut gbl_fb, "raw_1", &[0x55u8; 8 * 1024]);
+        check_flash_part(&mut gbl_fb, "raw_0", &[0xaau8; KiB!(4)]);
+        check_flash_part(&mut gbl_fb, "raw_1", &[0x55u8; KiB!(8)]);
         check_flash_part(&mut gbl_fb, "/0", disk_0);
         check_flash_part(&mut gbl_fb, "/1", disk_1);
 
@@ -1254,7 +1378,7 @@ mod test {
     fn test_flash_partition_sparse() {
         let raw = include_bytes!("../../testdata/sparse_test_raw.bin");
         let sparse = include_bytes!("../../testdata/sparse_test.bin");
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_raw_device(c"raw", vec![0u8; raw.len()]);
         let mut gbl_ops = FakeGblOps::new(&storage);
@@ -1295,7 +1419,7 @@ mod test {
         gpt_builder.add("sparse", [1u8; GPT_GUID_LEN], [1u8; GPT_GUID_LEN], 0, None).unwrap();
         block_on(gpt_builder.persist()).unwrap();
         let mut gbl_ops = FakeGblOps::new(&storage);
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
         let mut gbl_fb =
@@ -1343,7 +1467,7 @@ mod test {
 
     #[test]
     fn test_async_flash_block_on_busy_blk() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
@@ -1394,14 +1518,17 @@ mod test {
     }
 
     #[test]
+    #[should_panic(
+        expected = "A Fastboot async task failed: Other(Some(\"test\")), context: flash:boot_a"
+    )]
     fn test_async_flash_error() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         let mut gbl_ops = FakeGblOps::new(&storage);
         // Injects an error.
         storage[0].partition_io(None).unwrap().dev().io().error =
-            liberror::Error::Other(None).into();
+            liberror::Error::Other(Some("test")).into();
         let tasks = vec![].into();
         let parts = gbl_ops.disks();
         let mut gbl_fb =
@@ -1417,16 +1544,11 @@ mod test {
         block_on(gbl_fb.flash("boot_a", &resp)).unwrap();
         // Schedules the disk IO tasks to completion.
         tasks.borrow_mut().run();
-        // New flash to "boot_a" should fail due to previous error
-        set_download(&mut gbl_fb, expect_boot_a.as_slice());
-        assert!(block_on(gbl_fb.flash("boot_a", &resp)).is_err());
-        // "oem gbl-sync-tasks" should fail.
-        assert!(block_on(oem(&mut gbl_fb, "gbl-sync-tasks", &resp)).is_err());
     }
 
     #[test]
     fn test_async_erase() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_raw_device(c"raw_0", [0xaau8; 4096]);
         storage.add_raw_device(c"raw_1", [0x55u8; 4096]);
@@ -1470,16 +1592,43 @@ mod test {
         );
     }
 
+    #[test]
+    #[should_panic(
+        expected = "A Fastboot async task failed: Other(Some(\"test\")), context: erase:boot_a"
+    )]
+    fn test_async_erase_error() {
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
+        let mut gbl_ops = FakeGblOps::new(&storage);
+        // Injects an error.
+        storage[0].partition_io(None).unwrap().dev().io().error =
+            liberror::Error::Other(Some("test")).into();
+        let tasks = vec![].into();
+        let parts = gbl_ops.disks();
+        let mut gbl_fb =
+            GblFastboot::new(&mut gbl_ops, parts, Task::run, &tasks, &dl_buffers, &mut []);
+        let tasks = gbl_fb.tasks();
+        let resp: TestResponder = Default::default();
+
+        // Enable async IO.
+        assert!(poll(&mut pin!(oem(&mut gbl_fb, "gbl-enable-async-task", &resp))).unwrap().is_ok());
+        // Erases boot_a partition.
+        block_on(gbl_fb.erase("boot_a", &resp)).unwrap();
+        // Schedules the disk IO tasks to completion.
+        tasks.borrow_mut().run();
+    }
+
     #[test]
     fn test_default_block() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 1]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 1]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         let disk_dup = include_bytes!("../../../libstorage/test/gpt_test_2.bin");
         storage.add_gpt_device(disk_dup);
         storage.add_gpt_device(disk_dup);
-        let raw_a = [0xaau8; 4 * 1024];
-        let raw_b = [0x55u8; 8 * 1024];
+        let raw_a = [0xaau8; KiB!(4)];
+        let raw_b = [0x55u8; KiB!(8)];
         storage.add_raw_device(c"raw", raw_a);
         storage.add_raw_device(c"raw", raw_b);
         let mut gbl_ops = FakeGblOps::new(&storage);
@@ -1537,7 +1686,7 @@ mod test {
 
     #[test]
     fn test_set_default_block_invalid_arg() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let storage = FakeGblOpsStorage::default();
         let mut gbl_ops = FakeGblOps::new(&storage);
         let tasks = vec![].into();
@@ -1555,7 +1704,7 @@ mod test {
 
     #[test]
     fn test_reboot_sync_all_blocks() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         let mut gbl_ops = FakeGblOps::new(&storage);
@@ -1590,7 +1739,7 @@ mod test {
 
     #[test]
     fn test_continue_sync_all_blocks() {
-        let dl_buffers = Shared::from(vec![vec![0u8; 128 * 1024]; 2]);
+        let dl_buffers = Shared::from(vec![vec![0u8; KiB!(128)]; 2]);
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         let mut gbl_ops = FakeGblOps::new(&storage);
@@ -1636,7 +1785,7 @@ mod test {
 
     /// A shared [TestListener].
     #[derive(Default)]
-    struct SharedTestListener(Mutex<TestListener>);
+    pub(crate) struct SharedTestListener(Mutex<TestListener>);
 
     impl SharedTestListener {
         /// Locks the listener
@@ -1645,32 +1794,32 @@ mod test {
         }
 
         /// Adds packet to USB input
-        fn add_usb_input(&self, packet: &[u8]) {
+        pub(crate) fn add_usb_input(&self, packet: &[u8]) {
             self.lock().usb_in_queue.push_back(packet.into());
         }
 
         /// Adds bytes to input stream.
-        fn add_tcp_input(&self, data: &[u8]) {
+        pub(crate) fn add_tcp_input(&self, data: &[u8]) {
             self.lock().tcp_in_queue.append(&mut data.to_vec().into());
         }
 
         /// Adds a length pre-fixed bytes stream.
-        fn add_tcp_length_prefixed_input(&self, data: &[u8]) {
+        pub(crate) fn add_tcp_length_prefixed_input(&self, data: &[u8]) {
             self.add_tcp_input(&length_prefixed(data));
         }
 
         /// Gets a copy of `Self::usb_out_queue`.
-        fn usb_out_queue(&self) -> VecDeque<Vec<u8>> {
+        pub(crate) fn usb_out_queue(&self) -> VecDeque<Vec<u8>> {
             self.lock().usb_out_queue.clone()
         }
 
         /// Gets a copy of `Self::tcp_out_queue`.
-        fn tcp_out_queue(&self) -> VecDeque<u8> {
+        pub(crate) fn tcp_out_queue(&self) -> VecDeque<u8> {
             self.lock().tcp_out_queue.clone()
         }
 
         /// A helper for decoding USB output packets as a string
-        fn dump_usb_out_queue(&self) -> String {
+        pub(crate) fn dump_usb_out_queue(&self) -> String {
             let mut res = String::from("");
             for v in self.lock().usb_out_queue.iter() {
                 let v = String::from_utf8(v.clone()).unwrap_or(format!("{:?}", v));
@@ -1680,7 +1829,7 @@ mod test {
         }
 
         /// A helper for decoding TCP output data as strings
-        fn dump_tcp_out_queue(&self) -> String {
+        pub(crate) fn dump_tcp_out_queue(&self) -> String {
             let mut data = self.lock();
             let mut v;
             let (_, mut remains) = data.tcp_out_queue.make_contiguous().split_at(4);
@@ -1735,7 +1884,7 @@ mod test {
     }
 
     /// A helper to make an expected stream of USB output.
-    fn make_expected_usb_out(data: &[&[u8]]) -> VecDeque<Vec<u8>> {
+    pub(crate) fn make_expected_usb_out(data: &[&[u8]]) -> VecDeque<Vec<u8>> {
         VecDeque::from(data.iter().map(|v| v.to_vec()).collect::<Vec<_>>())
     }
 
@@ -1746,10 +1895,47 @@ mod test {
         res
     }
 
+    #[derive(Default)]
+    pub(crate) struct TestLocalSession {
+        requests: VecDeque<&'static str>,
+        outgoing_packets: VecDeque<Vec<u8>>,
+    }
+
+    impl LocalSession for &mut TestLocalSession {
+        async fn update(&mut self, buf: &mut [u8]) -> Result<usize, Error> {
+            let Some(front) = self.requests.pop_front() else {
+                return Ok(0);
+            };
+            let front_len = front.len();
+            if front_len >= buf.len() {
+                self.requests.push_front(front);
+                return Err(Error::BufferTooSmall(Some(front_len)));
+            }
+            buf[..front_len].copy_from_slice(front.as_bytes());
+            buf[front_len] = b'\0';
+            Ok(front_len)
+        }
+
+        async fn process_outgoing_packet(&mut self, buf: &[u8]) {
+            self.outgoing_packets.push_back(buf.into());
+        }
+    }
+
+    impl From<&[&'static str]> for TestLocalSession {
+        fn from(elts: &[&'static str]) -> Self {
+            let elts = elts.into_iter();
+            let mut requests = VecDeque::with_capacity(elts.len());
+            for e in elts {
+                requests.push_back(*e);
+            }
+            Self { requests, outgoing_packets: VecDeque::new() }
+        }
+    }
+
     #[test]
     fn test_run_gbl_fastboot() {
         let storage = FakeGblOpsStorage::default();
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -1758,7 +1944,14 @@ mod test {
         listener.add_tcp_input(b"FB01");
         listener.add_tcp_length_prefixed_input(b"getvar:max-download-size");
         listener.add_tcp_length_prefixed_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -1775,29 +1968,58 @@ mod test {
         );
     }
 
+    #[test]
+    fn test_run_gbl_fastboot_local_session() {
+        let storage = FakeGblOpsStorage::default();
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = FakeGblOps::new(&storage);
+        let mut local = TestLocalSession::from(["reboot", "continue"].as_slice());
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut local),
+            None::<&SharedTestListener>,
+            None::<&SharedTestListener>,
+            &mut [],
+        ));
+
+        assert!(gbl_ops.rebooted);
+    }
+
     #[test]
     fn test_run_gbl_fastboot_parallel_task() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"raw_0", [0u8; 4 * 1024]);
-        storage.add_raw_device(c"raw_1", [0u8; 8 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"raw_0", [0u8; KiB!(4)]);
+        storage.add_raw_device(c"raw_1", [0u8; KiB!(8)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
-        let mut fb_fut =
-            pin!(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
-
-        listener.add_usb_input(b"oem gbl-enable-async-task");
-        listener.add_usb_input(format!("download:{:#x}", 4 * 1024).as_bytes());
-        listener.add_usb_input(&[0x55u8; 4 * 1024]);
-        listener.add_usb_input(b"flash:raw_0");
+        let mut local = TestLocalSession::from(["getvar:all"].as_slice());
 
-        listener.add_tcp_input(b"FB01");
-        listener.add_tcp_length_prefixed_input(format!("download:{:#x}", 8 * 1024).as_bytes());
-        listener.add_tcp_length_prefixed_input(&[0xaau8; 8 * 1024]);
-        listener.add_tcp_length_prefixed_input(b"flash:raw_1");
-
-        assert!(poll_n_times(&mut fb_fut, 100).is_none());
+        // New scope to release reference on local
+        {
+            let mut fb_fut = pin!(run_gbl_fastboot_stack::<3>(
+                &mut gbl_ops,
+                buffers,
+                Some(&mut local),
+                Some(usb),
+                Some(tcp),
+                &mut []
+            ));
+
+            listener.add_usb_input(b"oem gbl-enable-async-task");
+            listener.add_usb_input(format!("download:{:#x}", KiB!(4)).as_bytes());
+            listener.add_usb_input(&[0x55u8; KiB!(4)]);
+            listener.add_usb_input(b"flash:raw_0");
+
+            listener.add_tcp_input(b"FB01");
+            listener.add_tcp_length_prefixed_input(format!("download:{:#x}", KiB!(8)).as_bytes());
+            listener.add_tcp_length_prefixed_input(&[0xaau8; KiB!(8)]);
+            listener.add_tcp_length_prefixed_input(b"flash:raw_1");
+
+            assert!(poll_n_times(&mut fb_fut, 100).is_none());
+        }
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -1805,7 +2027,7 @@ mod test {
                 b"OKAY",
                 b"DATA00001000",
                 b"OKAY",
-                b"INFOAn IO task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
+                b"INFOAn async task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
                 b"OKAY",
             ]),
             "\nActual USB output:\n{}",
@@ -1817,24 +2039,47 @@ mod test {
             make_expected_tcp_out(&[
                 b"DATA00002000",
                 b"OKAY",
-                b"INFOAn IO task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
+                b"INFOAn async task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
                 b"OKAY",
             ]),
             "\nActual TCP output:\n{}",
             listener.dump_tcp_out_queue()
         );
 
+        assert_eq!(
+            local.outgoing_packets,
+            VecDeque::from(vec![
+                Vec::from(b"INFOmax-download-size: 0x20000"),
+                Vec::from(b"INFOversion-bootloader: 1.0"),
+                Vec::from(b"INFOmax-fetch-size: 0xffffffffffffffff"),
+                Vec::from(b"INFOblock-device:0:total-blocks: 0x1000"),
+                Vec::from(b"INFOblock-device:0:block-size: 0x1"),
+                Vec::from(b"INFOblock-device:0:status: idle"),
+                Vec::from(b"INFOblock-device:1:total-blocks: 0x2000"),
+                Vec::from(b"INFOblock-device:1:block-size: 0x1"),
+                Vec::from(b"INFOblock-device:1:status: idle"),
+                Vec::from(b"INFOgbl-default-block: None"),
+                Vec::from(b"INFOpartition-size:raw_0/0: 0x1000"),
+                Vec::from(b"INFOpartition-type:raw_0/0: raw"),
+                Vec::from(b"INFOpartition-size:raw_1/1: 0x2000"),
+                Vec::from(b"INFOpartition-type:raw_1/1: raw"),
+                Vec::from(b"INFOgbl-test-var:1: gbl-test-var-val:1"),
+                Vec::from(b"INFOgbl-test-var:2: gbl-test-var-val:2"),
+                Vec::from(b"OKAY"),
+            ])
+        );
+
         // Verifies flashed image on raw_0.
-        assert_eq!(storage[0].partition_io(None).unwrap().dev().io().storage, [0x55u8; 4 * 1024]);
+        assert_eq!(storage[0].partition_io(None).unwrap().dev().io().storage, [0x55u8; KiB!(4)]);
 
         // Verifies flashed image on raw_1.
-        assert_eq!(storage[1].partition_io(None).unwrap().dev().io().storage, [0xaau8; 8 * 1024]);
+        assert_eq!(storage[1].partition_io(None).unwrap().dev().io().storage, [0xaau8; KiB!(8)]);
     }
 
     #[test]
     fn test_oem_add_staged_bootloader_file() {
         let storage = FakeGblOpsStorage::default();
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.get_zbi_bootloader_files_buffer().unwrap().fill(0);
         let listener: SharedTestListener = Default::default();
@@ -1849,7 +2094,14 @@ mod test {
         listener.add_usb_input(b"oem add-staged-bootloader-file file_2");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         let buffer = gbl_ops.get_zbi_bootloader_files_buffer_aligned().unwrap();
         let container = ZbiContainer::parse(&buffer[..]).unwrap();
@@ -1862,7 +2114,7 @@ mod test {
     #[test]
     fn test_oem_add_staged_bootloader_file_missing_file_name() {
         let storage = FakeGblOpsStorage::default();
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -1872,7 +2124,14 @@ mod test {
         listener.add_usb_input(b"oem add-staged-bootloader-file");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -1891,7 +2150,7 @@ mod test {
     #[test]
     fn test_oem_add_staged_bootloader_file_missing_download() {
         let storage = FakeGblOpsStorage::default();
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -1899,7 +2158,14 @@ mod test {
         listener.add_usb_input(b"oem add-staged-bootloader-file file1");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -1954,7 +2220,7 @@ mod test {
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(&disk);
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -1977,7 +2243,14 @@ mod test {
 
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2050,7 +2323,7 @@ mod test {
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
         storage.add_gpt_device(&disk);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2068,7 +2341,14 @@ mod test {
         listener.add_usb_input(b"getvar:partition-size:boot_b");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2094,7 +2374,7 @@ mod test {
         let disk = include_bytes!("../../../libstorage/test/gpt_test_1.bin");
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(&disk);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2102,7 +2382,14 @@ mod test {
         listener.add_usb_input(b"flash:gpt/0");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2117,7 +2404,7 @@ mod test {
         let disk = include_bytes!("../../../libstorage/test/gpt_test_1.bin");
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(&disk);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2129,7 +2416,14 @@ mod test {
         listener.add_usb_input(b"flash:gpt/0");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2152,7 +2446,7 @@ mod test {
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(&disk_orig);
         storage.add_gpt_device(&disk_orig);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2167,7 +2461,14 @@ mod test {
         // Invalid option.
         listener.add_usb_input(b"flash:gpt/0/invalid-arg");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2189,8 +2490,8 @@ mod test {
     fn test_oem_update_gpt_fail_on_raw_blk() {
         let disk_orig = include_bytes!("../../../libstorage/test/gpt_test_1.bin");
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"raw_0", [0u8; 1024 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"raw_0", [0u8; KiB!(1024)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2200,7 +2501,14 @@ mod test {
         listener.add_usb_input(gpt);
         listener.add_usb_input(b"flash:gpt/0");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2222,7 +2530,7 @@ mod test {
         let mut storage = FakeGblOpsStorage::default();
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_1.bin"));
         storage.add_gpt_device(include_bytes!("../../../libstorage/test/gpt_test_2.bin"));
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
@@ -2237,7 +2545,14 @@ mod test {
         listener.add_usb_input(b"getvar:partition-size:vendor_boot_b");
         listener.add_usb_input(b"continue");
 
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2258,15 +2573,22 @@ mod test {
     #[test]
     fn test_oem_erase_gpt_fail_on_raw_blk() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"raw_0", [0u8; 1024 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"raw_0", [0u8; KiB!(1024)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
 
         listener.add_usb_input(b"erase:gpt/0");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2281,10 +2603,10 @@ mod test {
     }
 
     /// Helper for testing fastboot set_active in fuchsia A/B/R mode.
-    fn test_run_gbl_fastboot_set_active_fuchsia_abr(cmd: &str, slot: SlotIndex) {
+    fn test_run_gbl_fastboot_set_active_fuchsia_abr(slot_ch: char, slot: SlotIndex) {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"durable_boot", [0x00u8; 4 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"durable_boot", [0x00u8; KiB!(4)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.os = Some(Os::Fuchsia);
         let listener: SharedTestListener = Default::default();
@@ -2295,15 +2617,23 @@ mod test {
 
         // Flash some data to `durable_boot` after A/B/R metadata. This is for testing that sync
         // storage is done first.
-        let data = vec![0x55u8; 4 * 1024 - ABR_DATA_SIZE];
+        let data = vec![0x55u8; KiB!(4) - ABR_DATA_SIZE];
         listener.add_usb_input(b"oem gbl-enable-async-task");
-        listener.add_usb_input(format!("download:{:#x}", 4 * 1024 - ABR_DATA_SIZE).as_bytes());
+        listener.add_usb_input(format!("download:{:#x}", KiB!(4) - ABR_DATA_SIZE).as_bytes());
         listener.add_usb_input(&data);
         listener.add_usb_input(format!("flash:durable_boot//{:#x}", ABR_DATA_SIZE).as_bytes());
         // Issues set_active commands
-        listener.add_usb_input(cmd.as_bytes());
+        listener.add_usb_input(format!("set_active:{slot_ch}").as_bytes());
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        let res = block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
+        assert_eq!(res.last_set_active_slot, Some(slot_ch));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2311,7 +2641,7 @@ mod test {
                 b"OKAY",
                 b"DATA00000fe0",
                 b"OKAY",
-                b"INFOAn IO task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
+                b"INFOAn async task is launched. To sync manually, run \"oem gbl-sync-tasks\".",
                 b"OKAY",
                 b"OKAY",
                 b"INFOSyncing storage...",
@@ -2331,19 +2661,19 @@ mod test {
 
     #[test]
     fn test_run_gbl_fastboot_set_active_fuchsia_abr_a() {
-        test_run_gbl_fastboot_set_active_fuchsia_abr("set_active:a", SlotIndex::A);
+        test_run_gbl_fastboot_set_active_fuchsia_abr('a', SlotIndex::A);
     }
 
     #[test]
     fn test_run_gbl_fastboot_set_active_fuchsia_abr_b() {
-        test_run_gbl_fastboot_set_active_fuchsia_abr("set_active:b", SlotIndex::B);
+        test_run_gbl_fastboot_set_active_fuchsia_abr('b', SlotIndex::B);
     }
 
     #[test]
     fn test_run_gbl_fastboot_set_active_fuchsia_abr_invalid_slot() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"durable_boot", [0x00u8; 4 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"durable_boot", [0x00u8; KiB!(4)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.os = Some(Os::Fuchsia);
         let listener: SharedTestListener = Default::default();
@@ -2351,7 +2681,14 @@ mod test {
 
         listener.add_usb_input(b"set_active:r");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2365,11 +2702,70 @@ mod test {
         );
     }
 
+    #[test]
+    fn test_run_gbl_fastboot_set_active_android() {
+        let storage = FakeGblOpsStorage::default();
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = FakeGblOps::new(&storage);
+        gbl_ops.os = Some(Os::Android);
+        let listener: SharedTestListener = Default::default();
+        let (usb, tcp) = (&listener, &listener);
+
+        listener.add_usb_input(b"set_active:b");
+        listener.add_usb_input(b"continue");
+        block_on(run_gbl_fastboot_stack::<2>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[b"OKAY", b"INFOSyncing storage...", b"OKAY",]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+        assert_eq!(gbl_ops.last_set_active_slot, Some(1));
+    }
+
+    #[test]
+    fn test_run_gbl_fastboot_set_active_multichar_slot() {
+        let storage = FakeGblOpsStorage::default();
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = FakeGblOps::new(&storage);
+        let listener: SharedTestListener = Default::default();
+        let (usb, tcp) = (&listener, &listener);
+        listener.add_usb_input(b"set_active:ab");
+        listener.add_usb_input(b"continue");
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[
+                b"FAILSlot suffix must be one character",
+                b"INFOSyncing storage...",
+                b"OKAY",
+            ]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+    }
+
     #[test]
     fn test_run_gbl_fastboot_fuchsia_reboot_bootloader_abr() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"durable_boot", [0x00u8; 4 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"durable_boot", [0x00u8; KiB!(4)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.os = Some(Os::Fuchsia);
         let listener: SharedTestListener = Default::default();
@@ -2377,7 +2773,14 @@ mod test {
 
         listener.add_usb_input(b"reboot-bootloader");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2399,8 +2802,8 @@ mod test {
     #[test]
     fn test_run_gbl_fastboot_fuchsia_reboot_recovery_abr() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"durable_boot", [0x00u8; 4 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"durable_boot", [0x00u8; KiB!(4)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.os = Some(Os::Fuchsia);
         let listener: SharedTestListener = Default::default();
@@ -2408,7 +2811,14 @@ mod test {
 
         listener.add_usb_input(b"reboot-recovery");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2430,20 +2840,27 @@ mod test {
     }
 
     #[test]
-    fn test_legacy_fvm_partition_aliase() {
+    fn test_legacy_fvm_partition_alias() {
         let mut storage = FakeGblOpsStorage::default();
-        storage.add_raw_device(c"fuchsia-fvm", [0x00u8; 4 * 1024]);
-        let buffers = vec![vec![0u8; 128 * 1024]; 2];
+        storage.add_raw_device(c"fuchsia-fvm", [0x00u8; KiB!(4)]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
         let mut gbl_ops = FakeGblOps::new(&storage);
         gbl_ops.os = Some(Os::Fuchsia);
         let listener: SharedTestListener = Default::default();
         let (usb, tcp) = (&listener, &listener);
 
-        listener.add_usb_input(format!("download:{:#x}", 4 * 1024).as_bytes());
-        listener.add_usb_input(&[0xaau8; 4 * 1024]);
+        listener.add_usb_input(format!("download:{:#x}", KiB!(4)).as_bytes());
+        listener.add_usb_input(&[0xaau8; KiB!(4)]);
         listener.add_usb_input(b"flash:fvm");
         listener.add_usb_input(b"continue");
-        block_on(run_gbl_fastboot_stack::<2>(&mut gbl_ops, buffers, Some(usb), Some(tcp), &mut []));
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
 
         assert_eq!(
             listener.usb_out_queue(),
@@ -2458,4 +2875,121 @@ mod test {
             listener.dump_usb_out_queue()
         );
     }
+
+    #[test]
+    fn test_async_flash_early_errors() {
+        let sparse_raw = include_bytes!("../../testdata/sparse_test_raw.bin");
+        let sparse = include_bytes!("../../testdata/sparse_test.bin");
+        let mut storage = FakeGblOpsStorage::default();
+        storage.add_raw_device(c"raw", vec![0u8; sparse_raw.len() - 1]);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = FakeGblOps::new(&storage);
+        let listener: SharedTestListener = Default::default();
+        let (usb, tcp) = (&listener, &listener);
+        listener.add_usb_input(b"oem gbl-enable-async-task");
+        // Flashes an oversized image.
+        listener.add_usb_input(format!("download:{:#x}", sparse_raw.len()).as_bytes());
+        listener.add_usb_input(&vec![0xaau8; sparse_raw.len()]);
+        listener.add_usb_input(b"flash:raw");
+        // Flashes an oversized sparse image.
+        listener.add_usb_input(format!("download:{:#x}", sparse.len()).as_bytes());
+        listener.add_usb_input(sparse);
+        listener.add_usb_input(b"flash:raw");
+        listener.add_usb_input(b"continue");
+        block_on(run_gbl_fastboot_stack::<3>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut [],
+        ));
+
+        // The out-of-range errors should be caught before async task is launched.
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[
+                b"OKAY",
+                b"DATA0000e000",
+                b"OKAY",
+                b"FAILOutOfRange",
+                b"DATA00006080",
+                b"OKAY",
+                b"FAILOutOfRange",
+                b"INFOSyncing storage...",
+                b"OKAY",
+            ]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+    }
+
+    fn test_fastboot_boot_slot(
+        suffix: char,
+        load_buffer: &mut [u8],
+    ) -> (&mut [u8], &mut [u8], &mut [u8], &mut [u8]) {
+        let mut storage = FakeGblOpsStorage::default();
+        let vbmeta = CString::new(format!("vbmeta_{suffix}")).unwrap();
+        let vbmeta_img = read_test_data(format!("vbmeta_v2_{suffix}.img"));
+        storage.add_raw_device(&vbmeta, vbmeta_img);
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = default_test_gbl_ops(&storage);
+        gbl_ops.current_slot = Some(Ok(slot(suffix)));
+        let listener: SharedTestListener = Default::default();
+        let (usb, tcp) = (&listener, &listener);
+
+        let data = read_test_data(format!("boot_v2_{suffix}.img"));
+        listener.add_usb_input(format!("download:{:#x}", data.len()).as_bytes());
+        listener.add_usb_input(&data);
+        listener.add_usb_input(b"boot");
+        listener.add_usb_input(b"continue");
+
+        let res = block_on(run_gbl_fastboot_stack::<2>(
+            &mut gbl_ops,
+            buffers,
+            Some(&mut TestLocalSession::default()),
+            Some(usb),
+            Some(tcp),
+            &mut load_buffer[..],
+        ));
+
+        assert_eq!(
+            listener.usb_out_queue(),
+            make_expected_usb_out(&[b"DATA00004000", b"OKAY", b"OKAYboot_command",]),
+            "\nActual USB output:\n{}",
+            listener.dump_usb_out_queue()
+        );
+
+        res.split_loaded_android(&mut load_buffer[..]).unwrap()
+    }
+
+    #[test]
+    fn test_fastboot_boot_slot_a() {
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = test_fastboot_boot_slot('a', &mut load_buffer);
+        checks_loaded_v2_slot_a_normal_mode(ramdisk, kernel);
+    }
+
+    #[test]
+    fn test_fastboot_boot_slot_b() {
+        let mut load_buffer = AlignedBuffer::new(8 * 1024 * 1024, KERNEL_ALIGNMENT);
+        let (ramdisk, _, kernel, _) = test_fastboot_boot_slot('b', &mut load_buffer);
+        checks_loaded_v2_slot_b_normal_mode(ramdisk, kernel);
+    }
+
+    #[test]
+    fn test_fastboot_no_channels() {
+        let storage = FakeGblOpsStorage::default();
+        let buffers = vec![vec![0u8; KiB!(128)]; 2];
+        let mut gbl_ops = default_test_gbl_ops(&storage);
+
+        block_on(run_gbl_fastboot_stack::<2>(
+            &mut gbl_ops,
+            buffers,
+            None::<&mut TestLocalSession>,
+            None::<&SharedTestListener>,
+            None::<&SharedTestListener>,
+            &mut [],
+        ));
+    }
 }
diff --git a/gbl/libgbl/src/fastboot/sparse.rs b/gbl/libgbl/src/fastboot/sparse.rs
index 640eab9..ab80bf1 100644
--- a/gbl/libgbl/src/fastboot/sparse.rs
+++ b/gbl/libgbl/src/fastboot/sparse.rs
@@ -18,7 +18,7 @@ use core::{
 };
 use liberror::Error;
 use static_assertions::const_assert;
-use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, Ref};
 
 // TODO(b/331854173): Switch to use bindgen for the following type definitions once
 // system/core/libsparse is added to repo checkout.
@@ -33,7 +33,7 @@ const SPARSE_HEADER_MAJOR_VER: u16 = 1;
 const SPARSE_HEADER_MINOR_VER: u16 = 0;
 
 #[repr(C)]
-#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Default, Copy, Clone, Immutable, IntoBytes, FromBytes)]
 pub struct SparseHeader {
     pub magic: u32,
     pub major_version: u16,
@@ -54,7 +54,7 @@ impl SparseHeader {
 }
 
 #[repr(C)]
-#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Default, Copy, Clone, IntoBytes, FromBytes)]
 pub struct ChunkHeader {
     pub chunk_type: u16,
     pub reserved1: u16,
@@ -100,7 +100,7 @@ pub fn is_sparse_image(sparse_img: &[u8]) -> Result<SparseHeader, Error> {
 /// first pass, we are guaranteed to have at least 1/3 of the input buffer free to use as fill
 /// buffer.
 #[repr(C, packed)]
-#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Default, Copy, Clone, Immutable, IntoBytes, FromBytes)]
 struct FillInfo {
     // Number of blocks to fill.
     pub fill_blocks: u32,
@@ -212,7 +212,7 @@ pub async fn write_sparse_image(
 /// `FillUnit` is a packed C struct wrapping a u32. It is mainly used for filling a buffer of
 /// arbitrary alignment with a u32 value.
 #[repr(C, packed)]
-#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Default, Copy, Clone, Immutable, IntoBytes, FromBytes)]
 struct FillUnit(u32);
 
 /// `FillBuffer` manages a buffer and provides API for making a fill buffer with the given value.
@@ -258,7 +258,7 @@ fn get<L: TryInto<usize>, R: TryInto<usize>>(
 }
 
 /// A helper to return a copy of a zerocopy object from bytes.
-fn copy_from<T: AsBytes + FromBytes + Default>(bytes: &[u8]) -> Result<T, Error> {
+fn copy_from<T: IntoBytes + FromBytes + Default>(bytes: &[u8]) -> Result<T, Error> {
     let mut res: T = Default::default();
     res.as_bytes_mut().clone_from_slice(get(bytes, 0, size_of::<T>())?);
     Ok(res)
@@ -331,7 +331,7 @@ mod test {
     }
 
     /// A helper to copy a zerocopy object into a buffer
-    fn copy_to<T: AsBytes + FromBytes>(val: &T, bytes: &mut [u8]) {
+    fn copy_to<T: Immutable + IntoBytes + FromBytes>(val: &T, bytes: &mut [u8]) {
         bytes[..size_of::<T>()].clone_from_slice(val.as_bytes());
     }
 
diff --git a/gbl/libgbl/src/fastboot/vars.rs b/gbl/libgbl/src/fastboot/vars.rs
index c759532..5a45261 100644
--- a/gbl/libgbl/src/fastboot/vars.rs
+++ b/gbl/libgbl/src/fastboot/vars.rs
@@ -17,10 +17,11 @@ use crate::{
     fastboot::{BufferPool, GblFastboot},
     GblOps,
 };
-use core::{ffi::CStr, fmt::Write, future::Future, ops::DerefMut, str::from_utf8};
-use fastboot::{next_arg, next_arg_u64, snprintf, CommandResult, FormattedBytes, VarInfoSender};
+use core::{ffi::CStr, future::Future, ops::DerefMut, str::from_utf8};
+use fastboot::{next_arg, next_arg_u64, CommandResult, VarInfoSender};
 use gbl_async::{block_on, select, yield_now};
 use gbl_storage::BlockIo;
+use libutils::snprintf;
 
 // See definition of [GblFastboot] for docs on lifetimes and generics parameters.
 impl<'a: 'c, 'b: 'c, 'c, 'd, 'e, G, B, S, T, P, C, F>
diff --git a/gbl/libgbl/src/fuchsia_boot/mod.rs b/gbl/libgbl/src/fuchsia_boot/mod.rs
index ced081a..43c8b99 100644
--- a/gbl/libgbl/src/fuchsia_boot/mod.rs
+++ b/gbl/libgbl/src/fuchsia_boot/mod.rs
@@ -21,10 +21,10 @@ use liberror::{Error, Result};
 use libutils::aligned_subslice;
 use safemath::SafeNum;
 use zbi::{ZbiContainer, ZbiFlags, ZbiHeader, ZbiType};
-use zerocopy::AsBytes;
+use zerocopy::IntoBytes;
 
 mod vboot;
-use vboot::{copy_items_after_kernel, zircon_verify_kernel};
+use vboot::zircon_verify_kernel;
 
 /// Kernel load address alignment. Value taken from
 /// https://fuchsia.googlesource.com/fuchsia/+/4f204d8a0243e84a86af4c527a8edcc1ace1615f/zircon/kernel/target/arm64/boot-shim/BUILD.gn#38
@@ -202,10 +202,6 @@ pub fn zircon_load_verify<'a, 'd>(
     // Performs AVB verification.
     // TODO(b/379789161) verify that kernel buffer is big enough for the image and scratch buffer.
     zircon_verify_kernel(ops, slot, slot_booted_successfully, load, &mut zbi_items)?;
-    // TODO(b/380409163) make sure moved items are before appended one to facilitate overriding.
-    // It is not as efficient as moving kernel since ZBI items would contain file system and be
-    // bigger than kernel.
-    copy_items_after_kernel(load, &mut zbi_items)?;
 
     // Append additional ZBI items.
     match slot {
@@ -288,20 +284,21 @@ pub fn zircon_check_enter_fastboot<'a, 'b>(ops: &mut impl GblOps<'a, 'b>) -> boo
 #[cfg(test)]
 mod test {
     use super::*;
-    use crate::ops::{
-        test::{FakeGblOps, FakeGblOpsStorage, TestGblDisk},
-        CertPermanentAttributes,
+    use crate::{
+        ops::{
+            test::{FakeGblOps, FakeGblOpsStorage, TestGblDisk},
+            CertPermanentAttributes,
+        },
+        tests::AlignedBuffer,
     };
     use abr::{
         mark_slot_active, mark_slot_unbootable, set_one_shot_bootloader, ABR_MAX_TRIES_REMAINING,
     };
     use avb_bindgen::{AVB_CERT_PIK_VERSION_LOCATION, AVB_CERT_PSK_VERSION_LOCATION};
     use gbl_storage::as_uninit_mut;
-    use libutils::aligned_offset;
     use std::{
         collections::{BTreeSet, HashMap, LinkedList},
         fs,
-        ops::{Deref, DerefMut},
         path::Path,
     };
     use zbi::ZBI_ALIGNMENT_USIZE;
@@ -370,7 +367,7 @@ mod test {
         storage
     }
 
-    pub(crate) fn create_gbl_ops<'a>(partitions: &'a [TestGblDisk]) -> FakeGblOps<'a, '_> {
+    pub(crate) fn create_gbl_ops<'a>(partitions: &'a [TestGblDisk]) -> FakeGblOps<'a, 'static> {
         let mut ops = FakeGblOps::new(&partitions);
         ops.avb_ops.unlock_state = Ok(false);
         ops.avb_ops.rollbacks = HashMap::from([
@@ -390,43 +387,6 @@ mod test {
         ops
     }
 
-    // Helper object for allocating aligned buffer.
-    pub(crate) struct AlignedBuffer {
-        buffer: Vec<u8>,
-        size: usize,
-        alignment: usize,
-    }
-
-    impl AlignedBuffer {
-        /// Allocates a buffer.
-        pub(crate) fn new(size: usize, alignment: usize) -> Self {
-            Self { buffer: vec![0u8; alignment + size - 1], size, alignment }
-        }
-
-        /// Allocates a buffer and initializes with data.
-        pub(crate) fn new_with_data(data: &[u8], alignment: usize) -> Self {
-            let mut res = Self::new(data.len(), alignment);
-            res.clone_from_slice(data);
-            res
-        }
-    }
-
-    impl Deref for AlignedBuffer {
-        type Target = [u8];
-
-        fn deref(&self) -> &Self::Target {
-            let off = aligned_offset(&self.buffer, self.alignment).unwrap();
-            &self.buffer[off..][..self.size]
-        }
-    }
-
-    impl DerefMut for AlignedBuffer {
-        fn deref_mut(&mut self) -> &mut Self::Target {
-            let off = aligned_offset(&self.buffer, self.alignment).unwrap();
-            &mut self.buffer[off..][..self.size]
-        }
-    }
-
     /// Normalizes a ZBI container by converting each ZBI item into raw bytes and storing them in
     /// an ordered set. The function is mainly used for comparing two ZBI containers have identical
     /// set of items, disregarding order.
diff --git a/gbl/libgbl/src/fuchsia_boot/vboot.rs b/gbl/libgbl/src/fuchsia_boot/vboot.rs
index 8018bb4..71fc819 100644
--- a/gbl/libgbl/src/fuchsia_boot/vboot.rs
+++ b/gbl/libgbl/src/fuchsia_boot/vboot.rs
@@ -17,19 +17,9 @@ use crate::{
     gbl_avb::ops::GblAvbOps,
     gbl_print, GblOps, Result as GblResult,
 };
-use avb::{slot_verify, Descriptor, HashtreeErrorMode, Ops as _, SlotVerifyError, SlotVerifyFlags};
-use core::ffi::CStr;
+use avb::{slot_verify, Descriptor, HashtreeErrorMode, Ops as _, SlotVerifyFlags};
 use zbi::ZbiContainer;
-use zerocopy::ByteSliceMut;
-
-/// Helper for getting the A/B/R suffix.
-fn slot_suffix(slot: Option<SlotIndex>) -> Option<&'static CStr> {
-    Some(match slot? {
-        SlotIndex::A => c"_a",
-        SlotIndex::B => c"_b",
-        SlotIndex::R => c"_r",
-    })
-}
+use zerocopy::SplitByteSliceMut;
 
 /// Verifies a loaded ZBI kernel.
 ///
@@ -40,19 +30,26 @@ fn slot_suffix(slot: Option<SlotIndex>) -> Option<&'static CStr> {
 /// * slot_booted_successfully - if true, roll back indexes will be increased
 /// * zbi_kernel - preloaded kernel to verify
 /// * zbi_items - vbmeta items will be appended to this ZbiContainer
-pub(crate) fn zircon_verify_kernel<'a, 'b, 'c, B: ByteSliceMut + PartialEq>(
+pub(crate) fn zircon_verify_kernel<'a, 'b, 'c, B: SplitByteSliceMut + PartialEq>(
     gbl_ops: &mut impl GblOps<'b, 'c>,
     slot: Option<SlotIndex>,
     slot_booted_successfully: bool,
     zbi_kernel: &'a mut [u8],
     zbi_items: &mut ZbiContainer<B>,
 ) -> GblResult<()> {
+    // Copy ZBI items after kernel first. Because ordering matters, and new items should override
+    // older ones.
+    // TODO(b/379778252) It is not as efficient as moving kernel since ZBI items would contain file
+    // system and be bigger than kernel.
+    copy_items_after_kernel(zbi_kernel, zbi_items)?;
+
     let (kernel, _) = zbi_split_unused_buffer(&mut zbi_kernel[..])?;
 
     // Verifies the kernel.
     let part = zircon_part_name(slot);
-    let preloaded = [(part, &kernel[..])];
-    let mut avb_ops = GblAvbOps::new(gbl_ops, &preloaded[..], true);
+    let slotless_part = zircon_part_name(None);
+    let preloaded = [(slotless_part, &kernel[..])];
+    let mut avb_ops = GblAvbOps::new(gbl_ops, slot, &preloaded[..], true);
 
     // Determines verify flags and error mode.
     let unlocked = avb_ops.read_is_device_unlocked()?;
@@ -63,16 +60,16 @@ pub(crate) fn zircon_verify_kernel<'a, 'b, 'c, B: ByteSliceMut + PartialEq>(
     };
 
     // TODO(b/334962583): Supports optional additional partitions to verify.
-    let verify_res = slot_verify(&mut avb_ops, &[c"zircon"], slot_suffix(slot), flag, mode);
+    let verify_res = slot_verify(&mut avb_ops, &[c"zircon"], slot.map(|s| s.into()), flag, mode);
     let verified_success = verify_res.is_ok();
     let verify_data = match verify_res {
-        Ok(v) => {
+        Ok(ref v) => {
             gbl_print!(avb_ops.gbl_ops, "{} successfully verified.\r\n", part);
             v
         }
-        Err(SlotVerifyError::Verification(Some(v))) if unlocked => {
+        Err(ref e) if e.verification_data().is_some() && unlocked => {
             gbl_print!(avb_ops.gbl_ops, "Verification failed. Device is unlocked. Ignore.\r\n");
-            v
+            e.verification_data().unwrap()
         }
         Err(_) if unlocked => {
             gbl_print!(
@@ -121,7 +118,7 @@ pub(crate) fn zircon_verify_kernel<'a, 'b, 'c, B: ByteSliceMut + PartialEq>(
 }
 
 /// Copy ZBI items following kernel to separate container.
-pub fn copy_items_after_kernel<'a, B: ByteSliceMut + PartialEq>(
+pub fn copy_items_after_kernel<'a, B: SplitByteSliceMut + PartialEq>(
     zbi_kernel: &'a mut [u8],
     zbi_items: &mut ZbiContainer<B>,
 ) -> GblResult<()> {
@@ -135,12 +132,15 @@ pub fn copy_items_after_kernel<'a, B: ByteSliceMut + PartialEq>(
 #[cfg(test)]
 mod test {
     use super::*;
-    use crate::fuchsia_boot::{
-        test::{
-            append_cmd_line, corrupt_data, create_gbl_ops, create_storage, normalize_zbi,
-            read_test_data, AlignedBuffer, ZIRCON_A_ZBI_FILE,
+    use crate::{
+        fuchsia_boot::{
+            test::{
+                append_cmd_line, corrupt_data, create_gbl_ops, create_storage, normalize_zbi,
+                read_test_data, ZIRCON_A_ZBI_FILE,
+            },
+            ZIRCON_KERNEL_ALIGN,
         },
-        ZIRCON_KERNEL_ALIGN,
+        tests::AlignedBuffer,
     };
     use avb_bindgen::{AVB_CERT_PIK_VERSION_LOCATION, AVB_CERT_PSK_VERSION_LOCATION};
     use zbi::ZBI_ALIGNMENT_USIZE;
diff --git a/gbl/libgbl/src/gbl_avb/ops.rs b/gbl/libgbl/src/gbl_avb/ops.rs
index 1df1a73..9401587 100644
--- a/gbl/libgbl/src/gbl_avb/ops.rs
+++ b/gbl/libgbl/src/gbl_avb/ops.rs
@@ -18,10 +18,14 @@ use crate::{
     gbl_avb::state::{BootStateColor, KeyValidationStatus},
     gbl_print, gbl_println, GblOps,
 };
+use abr::SlotIndex;
+use arrayvec::ArrayString;
 use avb::{
     cert_validate_vbmeta_public_key, CertOps, CertPermanentAttributes, IoError, IoResult,
     Ops as AvbOps, PublicKeyForPartitionInfo, SlotVerifyData, SHA256_DIGEST_SIZE,
+    SHA512_DIGEST_SIZE,
 };
+use core::fmt::Write;
 use core::{
     cmp::{max, min},
     ffi::CStr,
@@ -30,6 +34,9 @@ use liberror::Error;
 use safemath::SafeNum;
 use uuid::Uuid;
 
+/// The digest key in commandline provided by libavb.
+pub const AVB_DIGEST_KEY: &str = "androidboot.vbmeta.digest";
+
 // AVB cert tracks versions for the PIK and PSK; PRK cannot be changed so has no version info.
 const AVB_CERT_NUM_KEY_VERSIONS: usize = 2;
 
@@ -37,6 +44,8 @@ const AVB_CERT_NUM_KEY_VERSIONS: usize = 2;
 pub struct GblAvbOps<'a, T> {
     /// The underlying [GblOps].
     pub gbl_ops: &'a mut T,
+    slot: Option<SlotIndex>,
+    /// Slotless partitions pre-loaded by the implementation. Provided to avoid redundant IO.
     preloaded_partitions: &'a [(&'a str, &'a [u8])],
     /// Used for storing key versions to be set (location, version).
     ///
@@ -57,11 +66,13 @@ impl<'a, 'p, 'q, T: GblOps<'p, 'q>> GblAvbOps<'a, T> {
     /// Creates a new [GblAvbOps].
     pub fn new(
         gbl_ops: &'a mut T,
+        slot: Option<SlotIndex>,
         preloaded_partitions: &'a [(&'a str, &'a [u8])],
         use_cert: bool,
     ) -> Self {
         Self {
             gbl_ops,
+            slot,
             preloaded_partitions,
             key_versions: [None; AVB_CERT_NUM_KEY_VERSIONS],
             use_cert,
@@ -80,14 +91,10 @@ impl<'a, 'p, 'q, T: GblOps<'p, 'q>> GblAvbOps<'a, T> {
     /// Allowes implementation side to handle verification result.
     pub fn handle_verification_result(
         &mut self,
-        slot_verify: &SlotVerifyData,
+        slot_verify: Option<&SlotVerifyData>,
         color: BootStateColor,
+        digest: Option<&str>,
     ) -> IoResult<()> {
-        let mut vbmeta = None;
-        let mut vbmeta_boot = None;
-        let mut vbmeta_system = None;
-        let mut vbmeta_vendor = None;
-
         // The Android build system automatically generates only the main vbmeta, but also allows
         // to have separate chained partitions like vbmeta_system (for system, product, system_ext,
         // etc.) or vbmeta_vendor (for vendor).
@@ -100,39 +107,63 @@ impl<'a, 'p, 'q, T: GblOps<'p, 'q>> GblAvbOps<'a, T> {
         // Custom chained partitions are also supported by the Android build system, but we expect
         // OEMs to follow about the same pattern.
         // https://android-review.googlesource.com/q/Id671e2c3aee9ada90256381cce432927df03169b
-        for data in slot_verify.vbmeta_data() {
-            match data.partition_name().to_str().unwrap_or_default() {
-                "vbmeta" => vbmeta = Some(data),
-                "boot" => vbmeta_boot = Some(data),
-                "vbmeta_system" => vbmeta_system = Some(data),
-                "vbmeta_vendor" => vbmeta_vendor = Some(data),
-                _ => {}
+        let (
+            boot_os_version,
+            boot_security_patch,
+            system_os_version,
+            system_security_patch,
+            vendor_os_version,
+            vendor_security_patch,
+        ) = match slot_verify {
+            Some(slot_verify) => {
+                let mut vbmeta = None;
+                let mut vbmeta_boot = None;
+                let mut vbmeta_system = None;
+                let mut vbmeta_vendor = None;
+
+                for data in slot_verify.vbmeta_data() {
+                    match data.partition_name().to_str().unwrap_or_default() {
+                        "vbmeta" => vbmeta = Some(data),
+                        "boot" => vbmeta_boot = Some(data),
+                        "vbmeta_system" => vbmeta_system = Some(data),
+                        "vbmeta_vendor" => vbmeta_vendor = Some(data),
+                        _ => {}
+                    }
+                }
+
+                let data = vbmeta.ok_or(IoError::NoSuchPartition)?;
+                let boot_data = vbmeta_boot.unwrap_or(data);
+                let system_data = vbmeta_system.unwrap_or(data);
+                let vendor_data = vbmeta_vendor.unwrap_or(data);
+
+                (
+                    boot_data.get_property_value("com.android.build.boot.os_version"),
+                    boot_data.get_property_value("com.android.build.boot.security_patch"),
+                    system_data.get_property_value("com.android.build.system.os_version"),
+                    system_data.get_property_value("com.android.build.system.security_patch"),
+                    vendor_data.get_property_value("com.android.build.vendor.os_version"),
+                    vendor_data.get_property_value("com.android.build.vendor.security_patch"),
+                )
             }
-        }
-
-        let data = vbmeta.ok_or(IoError::NoSuchPartition)?;
-        let boot_data = vbmeta_boot.unwrap_or(data);
-        let system_data = vbmeta_system.unwrap_or(data);
-        let vendor_data = vbmeta_vendor.unwrap_or(data);
-
-        let boot_os_version = boot_data.get_property_value("com.android.build.boot.os_version");
-        let boot_security_patch =
-            boot_data.get_property_value("com.android.build.boot.security_patch");
-
-        let system_os_version =
-            system_data.get_property_value("com.android.build.system.os_version");
-        let system_security_patch =
-            system_data.get_property_value("com.android.build.system.security_patch");
+            None => (None, None, None, None, None, None),
+        };
 
-        let vendor_os_version =
-            vendor_data.get_property_value("com.android.build.vendor.os_version");
-        let vendor_security_patch =
-            vendor_data.get_property_value("com.android.build.vendor.security_patch");
+        // Convert digest rust string to null-terminated string by copying it into separate buffer.
+        let mut digest_buffer = ArrayString::<{ 2 * SHA512_DIGEST_SIZE + 1 }>::new();
+        let digest_cstr = match digest {
+            Some(digest) => {
+                write!(digest_buffer, "{}\0", digest).or(Err(IoError::InvalidValueSize))?;
+                Some(
+                    CStr::from_bytes_until_nul(digest_buffer.as_bytes())
+                        .or(Err(IoError::InvalidValueSize))?,
+                )
+            }
+            None => None,
+        };
 
         self.gbl_ops.avb_handle_verification_result(
             color,
-            // TODO(b/337846185): extract VBH from the command line provided by libavb.
-            None,
+            digest_cstr,
             boot_os_version,
             boot_security_patch,
             system_os_version,
@@ -153,6 +184,23 @@ fn cstr_to_str<E>(s: &CStr, err: E) -> Result<&str, E> {
     Ok(s.to_str().or(Err(err))?)
 }
 
+/// A helper function to split partition into base name and slot index
+fn split_slotted(partition: &str) -> Result<(&str, SlotIndex), Error> {
+    // Attempt to split on the last underscore
+    let (partition_name, suffix) = partition.rsplit_once('_').ok_or(Error::InvalidInput)?;
+
+    // Ensure suffix has exactly one character
+    if suffix.len() != 1 {
+        return Err(Error::InvalidInput);
+    }
+
+    // Convert that single character into a SlotIndex
+    let slot_char = suffix.chars().next().unwrap();
+    let slot = slot_char.try_into().map_err(|_| Error::InvalidInput)?;
+
+    Ok((partition_name, slot))
+}
+
 /// # Lifetimes
 /// * `'a`: preloaded data lifetime
 /// * `'b`: [GblOps] partition lifetime
@@ -185,12 +233,27 @@ impl<'a, 'b, 'c, T: GblOps<'b, 'c>> AvbOps<'a> for GblAvbOps<'a, T> {
 
     fn get_preloaded_partition(&mut self, partition: &CStr) -> IoResult<&'a [u8]> {
         let part_str = cstr_to_str(partition, IoError::NotImplemented)?;
-        Ok(self
-            .preloaded_partitions
+
+        let partition_name = match self.slot {
+            // Extract partition slot and ensure it's matched.
+            Some(slot) => {
+                let (partition_name, partition_slot) =
+                    split_slotted(part_str).map_err(|_| IoError::NotImplemented)?;
+
+                if partition_slot != slot {
+                    return Err(IoError::NotImplemented);
+                }
+
+                partition_name
+            }
+            _ => part_str,
+        };
+
+        self.preloaded_partitions
             .iter()
-            .find(|(name, _)| *name == part_str)
-            .ok_or(IoError::NotImplemented)?
-            .1)
+            .find(|(name, _)| *name == partition_name)
+            .map(|(_, data)| *data)
+            .ok_or_else(|| IoError::NotImplemented)
     }
 
     fn validate_vbmeta_public_key(
@@ -384,7 +447,7 @@ mod test {
         storage.add_raw_device(c"test_part", test_data(512));
 
         let mut gbl_ops = FakeGblOps::new(&storage);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         // Positive offset.
         let mut out = [0u8; 4];
@@ -398,7 +461,7 @@ mod test {
         storage.add_raw_device(c"test_part", test_data(512));
 
         let mut gbl_ops = FakeGblOps::new(&storage);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         // Negative offset should wrap from the end
         let mut out = [0u8; 6];
@@ -412,7 +475,7 @@ mod test {
         storage.add_raw_device(c"test_part", test_data(512));
 
         let mut gbl_ops = FakeGblOps::new(&storage);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         // Reading past the end of the partition should truncate.
         let mut out = [0u8; 6];
@@ -426,7 +489,7 @@ mod test {
         storage.add_raw_device(c"test_part", test_data(512));
 
         let mut gbl_ops = FakeGblOps::new(&storage);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         // Reads starting out of bounds should fail.
         let mut out = [0u8; 4];
@@ -443,7 +506,7 @@ mod test {
     #[test]
     fn read_from_partition_unknown_part() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         let mut out = [0u8; 4];
         assert_eq!(
@@ -452,10 +515,98 @@ mod test {
         );
     }
 
+    /// Helper function to test reading pre-loaded partitions.
+    fn test_read_preloaded_partition(
+        preloaded_partition: &str,
+        slot: Option<SlotIndex>,
+        partition_to_read: &CStr,
+        expect_success: bool,
+    ) {
+        let mut gbl_ops = FakeGblOps::new(&[]);
+
+        let data = &test_data(512);
+        let slice = &data[..];
+        let preloaded = [(preloaded_partition, slice)];
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, slot, &preloaded, false);
+
+        match expect_success {
+            true => {
+                assert_eq!(
+                    avb_ops.get_size_of_partition(partition_to_read),
+                    Ok(data.len().try_into().unwrap())
+                );
+                assert_eq!(avb_ops.get_preloaded_partition(partition_to_read), Ok(slice));
+            }
+            false => {
+                assert_eq!(
+                    avb_ops.get_preloaded_partition(partition_to_read),
+                    Err(IoError::NotImplemented),
+                );
+            }
+        }
+    }
+
+    #[test]
+    fn read_from_preloaded_a_partition() {
+        test_read_preloaded_partition(
+            "test_partition",
+            Some(SlotIndex::A),
+            c"test_partition_a",
+            true,
+        );
+    }
+
+    #[test]
+    fn read_from_preloaded_b_partition() {
+        test_read_preloaded_partition(
+            "test_partition",
+            Some(SlotIndex::B),
+            c"test_partition_b",
+            true,
+        );
+    }
+
+    #[test]
+    fn read_from_preloaded_r_partition() {
+        test_read_preloaded_partition(
+            "test_partition",
+            Some(SlotIndex::R),
+            c"test_partition_r",
+            true,
+        );
+    }
+
+    #[test]
+    fn read_from_preloaded_slotless_partition() {
+        test_read_preloaded_partition("test_partition", None, c"test_partition", true);
+    }
+
+    #[test]
+    fn read_from_preloaded_partition_wrong_slot() {
+        // Ops are slotless but _a is used, so cannot read.
+        test_read_preloaded_partition("test_partition", None, c"test_partition_a", false);
+
+        // Ops are using A slot but slotless is getting read, so cannot read.
+        test_read_preloaded_partition(
+            "test_partition",
+            Some(SlotIndex::A),
+            c"test_partition",
+            false,
+        );
+
+        // Ops are using A slot but _b is getting read, so cannot read.
+        test_read_preloaded_partition(
+            "test_partition",
+            Some(SlotIndex::A),
+            c"test_partition_b",
+            false,
+        );
+    }
+
     #[test]
     fn set_key_version_default() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         assert_eq!(avb_ops.key_versions, [None, None]);
     }
@@ -463,7 +614,7 @@ mod test {
     #[test]
     fn set_key_version_once() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         avb_ops.set_key_version(5, 10);
         assert_eq!(avb_ops.key_versions, [Some((5, 10)), None]);
@@ -472,7 +623,7 @@ mod test {
     #[test]
     fn set_key_version_twice() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         avb_ops.set_key_version(5, 10);
         avb_ops.set_key_version(20, 40);
@@ -482,7 +633,7 @@ mod test {
     #[test]
     fn set_key_version_overwrite() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         avb_ops.set_key_version(5, 10);
         avb_ops.set_key_version(20, 40);
@@ -499,7 +650,7 @@ mod test {
     #[should_panic(expected = "Ran out of key version slots")]
     fn set_key_version_overflow() {
         let mut gbl_ops = FakeGblOps::new(&[]);
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         avb_ops.set_key_version(5, 10);
         avb_ops.set_key_version(20, 40);
@@ -511,7 +662,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Valid));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.validate_vbmeta_public_key(&[], None), Ok(true));
         assert_eq!(avb_ops.key_validation_status(), Ok(KeyValidationStatus::Valid));
     }
@@ -521,7 +672,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::ValidCustomKey));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.validate_vbmeta_public_key(&[], None), Ok(true));
         assert_eq!(avb_ops.key_validation_status(), Ok(KeyValidationStatus::ValidCustomKey));
     }
@@ -531,7 +682,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_key_validation_status = Some(Ok(KeyValidationStatus::Invalid));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.validate_vbmeta_public_key(&[], None), Ok(false));
         assert_eq!(avb_ops.key_validation_status(), Ok(KeyValidationStatus::Invalid));
     }
@@ -541,7 +692,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_key_validation_status = Some(Err(IoError::Io));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.validate_vbmeta_public_key(&[], None), Err(IoError::Io));
         assert!(avb_ops.key_validation_status().is_err());
     }
@@ -552,7 +703,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_key_validation_status = Some(Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         assert_eq!(avb_ops.validate_vbmeta_public_key(&[], None), Ok(true));
         assert_eq!(avb_ops.key_validation_status(), Ok(KeyValidationStatus::ValidCustomKey));
@@ -566,7 +717,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.rollbacks.insert(EXPECTED_INDEX, Ok(EXPECTED_VALUE));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.read_rollback_index(EXPECTED_INDEX), Ok(EXPECTED_VALUE));
     }
 
@@ -574,7 +725,7 @@ mod test {
     fn read_rollback_index_error_handled() {
         let mut gbl_ops = FakeGblOps::new(&[]);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.read_rollback_index(0), Err(IoError::Io));
     }
 
@@ -584,7 +735,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.rollbacks.insert(0, Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.read_rollback_index(0), Ok(0));
     }
 
@@ -595,7 +746,7 @@ mod test {
 
         let mut gbl_ops = FakeGblOps::new(&[]);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_rollback_index(EXPECTED_INDEX, EXPECTED_VALUE), Ok(()));
         assert_eq!(
             gbl_ops.avb_ops.rollbacks.get(&EXPECTED_INDEX),
@@ -608,7 +759,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.rollbacks.insert(0, Err(IoError::Io));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_rollback_index(0, 0), Err(IoError::Io));
     }
 
@@ -618,7 +769,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.rollbacks.insert(0, Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_rollback_index(0, 0), Ok(()));
     }
 
@@ -627,7 +778,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.unlock_state = Ok(true);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
 
         assert_eq!(avb_ops.read_is_device_unlocked(), Ok(true));
     }
@@ -637,7 +788,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.unlock_state = Err(IoError::Io);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.read_is_device_unlocked(), Err(IoError::Io));
     }
 
@@ -647,7 +798,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.unlock_state = Err(IoError::NotImplemented);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.read_is_device_unlocked(), Ok(true));
     }
 
@@ -659,7 +810,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Ok(EXPECTED_VALUE));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         let mut buffer = [0u8; EXPECTED_VALUE.len()];
         assert_eq!(
             avb_ops.read_persistent_value(EXPECTED_NAME, &mut buffer),
@@ -675,7 +826,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::Io));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         let mut buffer = [0u8; 4];
         assert_eq!(avb_ops.read_persistent_value(EXPECTED_NAME, &mut buffer), Err(IoError::Io));
     }
@@ -690,7 +841,7 @@ mod test {
             .avb_ops
             .add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         let mut buffer = [0u8; 0];
         assert_eq!(avb_ops.read_persistent_value(EXPECTED_NAME, &mut buffer), Ok(0));
     }
@@ -702,7 +853,7 @@ mod test {
 
         let mut gbl_ops = FakeGblOps::new(&[]);
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_persistent_value(EXPECTED_NAME, EXPECTED_VALUE), Ok(()));
 
         assert_eq!(
@@ -719,7 +870,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::Io));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_persistent_value(EXPECTED_NAME, EXPECTED_VALUE), Err(IoError::Io));
     }
 
@@ -734,7 +885,7 @@ mod test {
             .avb_ops
             .add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.write_persistent_value(EXPECTED_NAME, EXPECTED_VALUE), Ok(()));
     }
 
@@ -745,7 +896,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Ok(b"test"));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.erase_persistent_value(EXPECTED_NAME), Ok(()));
 
         assert!(!gbl_ops.avb_ops.persistent_values.contains_key(EXPECTED_NAME.to_str().unwrap()));
@@ -758,7 +909,7 @@ mod test {
         let mut gbl_ops = FakeGblOps::new(&[]);
         gbl_ops.avb_ops.add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::Io));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.erase_persistent_value(EXPECTED_NAME), Err(IoError::Io));
     }
 
@@ -772,7 +923,7 @@ mod test {
             .avb_ops
             .add_persistent_value(EXPECTED_NAME.to_str().unwrap(), Err(IoError::NotImplemented));
 
-        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, &[], false);
+        let mut avb_ops = GblAvbOps::new(&mut gbl_ops, None, &[], false);
         assert_eq!(avb_ops.erase_persistent_value(EXPECTED_NAME), Ok(()));
     }
 }
diff --git a/gbl/libgbl/src/gbl_avb/state.rs b/gbl/libgbl/src/gbl_avb/state.rs
index 57b953d..eab94ee 100644
--- a/gbl/libgbl/src/gbl_avb/state.rs
+++ b/gbl/libgbl/src/gbl_avb/state.rs
@@ -17,7 +17,7 @@
 use core::fmt::{Display, Formatter};
 
 /// https://source.android.com/docs/security/features/verifiedboot/boot-flow#communicating-verified-boot-state-to-users
-#[derive(Clone, Copy, PartialEq)]
+#[derive(Clone, Copy, PartialEq, Debug)]
 pub enum BootStateColor {
     /// Success .
     Green,
diff --git a/gbl/libgbl/src/lib.rs b/gbl/libgbl/src/lib.rs
index 88d7f26..6637d3e 100644
--- a/gbl/libgbl/src/lib.rs
+++ b/gbl/libgbl/src/lib.rs
@@ -36,7 +36,7 @@ extern crate gbl_storage;
 extern crate spin;
 extern crate zbi;
 
-use avb::{HashtreeErrorMode, SlotVerifyData, SlotVerifyError, SlotVerifyFlags};
+use avb::{HashtreeErrorMode, SlotVerifyData, SlotVerifyFlags};
 use core::ffi::CStr;
 use core::marker::PhantomData;
 
@@ -58,9 +58,8 @@ pub mod partition;
 pub mod slots;
 
 mod image_buffer;
-mod overlap;
 
-use slots::{BootTarget, BootToken, Cursor, OneShot, SuffixBytes, UnbootableReason};
+use slots::{BootTarget, BootToken, Cursor, SuffixBytes};
 
 pub use avb::Descriptor;
 pub use boot_mode::BootMode;
@@ -69,104 +68,6 @@ pub use error::{IntegrationError, Result};
 use liberror::Error;
 pub use ops::{GblOps, Os};
 
-use overlap::is_overlap;
-
-// TODO: b/312607649 - Replace placeholders with actual structures: https://r.android.com/2721974, etc
-/// TODO: b/312607649 - placeholder type
-pub struct Partition {}
-/// TODO: b/312607649 - placeholder type
-pub struct InfoStruct {}
-
-/// Structure representing partition and optional address it is required to be loaded.
-/// If no address is provided GBL will use default one.
-pub struct PartitionRamMap<'b, 'c> {
-    /// Partition details
-    pub partition: &'b Partition,
-
-    /// Optional memory region to load partitions.
-    /// If it's not provided default values will be used.
-    pub address: Option<&'c mut [u8]>,
-}
-
-/// Boot Image in memory
-#[allow(dead_code)]
-pub struct BootImage<'a>(&'a mut [u8]);
-
-/// Vendor Boot Image in memory
-pub struct VendorBootImage<'a>(&'a mut [u8]);
-
-/// Init Boot Image in memory
-pub struct InitBootImage<'a>(&'a mut [u8]);
-
-/// Kernel Image in memory
-#[allow(dead_code)]
-pub struct KernelImage<'a>(&'a mut [u8]);
-
-/// Ramdisk in memory
-pub struct Ramdisk<'a>(&'a mut [u8]);
-/// Bootconfig in memory
-#[allow(dead_code)]
-pub struct Bootconfig<'a>(&'a mut [u8]);
-/// DTB in memory
-#[allow(dead_code)]
-pub struct Dtb<'a>(&'a mut [u8]);
-
-/// Create Boot Image from corresponding partition for `partitions_ram_map` and `avb_descriptors`
-/// lists
-pub fn get_boot_image<'a: 'b, 'b: 'c, 'c, 'd>(
-    partitions_ram_map: &'a mut [PartitionRamMap<'b, 'c>],
-) -> (Option<BootImage<'c>>, &'a mut [PartitionRamMap<'b, 'c>]) {
-    match partitions_ram_map.len() {
-        0 => (None, partitions_ram_map),
-        _ => {
-            let (partition_map, tail) = partitions_ram_map.split_first_mut().unwrap();
-            (partition_map.address.take().map(BootImage), tail)
-        }
-    }
-}
-
-/// Create Vendor Boot Image from corresponding partition for `partitions_ram_map` and
-/// `avb_descriptors` lists
-pub fn get_vendor_boot_image<'a: 'b, 'b: 'c, 'c, 'd>(
-    partitions_ram_map: &'a mut [PartitionRamMap<'b, 'c>],
-) -> (Option<VendorBootImage<'c>>, &'a mut [PartitionRamMap<'b, 'c>]) {
-    match partitions_ram_map.len() {
-        0 => (None, partitions_ram_map),
-        _ => {
-            let (partition_map, tail) = partitions_ram_map.split_first_mut().unwrap();
-            (partition_map.address.take().map(VendorBootImage), tail)
-        }
-    }
-}
-
-/// Create Init Boot Image from corresponding partition for `partitions` and `avb_descriptors` lists
-pub fn get_init_boot_image<'a: 'b, 'b: 'c, 'c, 'd>(
-    partitions_ram_map: &'a mut [PartitionRamMap<'b, 'c>],
-) -> (Option<InitBootImage<'c>>, &'a mut [PartitionRamMap<'b, 'c>]) {
-    match partitions_ram_map.len() {
-        0 => (None, partitions_ram_map),
-        _ => {
-            let (partition_map, tail) = partitions_ram_map.split_first_mut().unwrap();
-            (partition_map.address.take().map(InitBootImage), tail)
-        }
-    }
-}
-
-/// Create separate image types from [avb::Descriptor]
-pub fn get_images<'a: 'b, 'b: 'c, 'c, 'd>(
-    partitions_ram_map: &'a mut [PartitionRamMap<'b, 'c>],
-) -> (
-    Option<BootImage<'c>>,
-    Option<InitBootImage<'c>>,
-    Option<VendorBootImage<'c>>,
-    &'a mut [PartitionRamMap<'b, 'c>],
-) {
-    let (boot_image, partitions_ram_map) = get_boot_image(partitions_ram_map);
-    let (init_boot_image, partitions_ram_map) = get_init_boot_image(partitions_ram_map);
-    let (vendor_boot_image, partitions_ram_map) = get_vendor_boot_image(partitions_ram_map);
-    (boot_image, init_boot_image, vendor_boot_image, partitions_ram_map)
-}
-
 /// GBL object that provides implementation of helpers for boot process.
 pub struct Gbl<'a, 'd, G>
 where
@@ -242,287 +143,62 @@ where
         let boot_token = self.boot_token.take().ok_or(Error::OperationProhibited)?;
         self.ops.load_slot_interface(persist, boot_token)
     }
+}
 
-    /// Info Load
-    ///
-    /// Unpack boot image in RAM
-    ///
-    /// # Arguments
-    ///   * `boot_image_buffer` - Buffer that contains (Optionally Verified) Boot Image
-    ///   * `boot_mode` - Boot Mode
-    ///   * `boot_target` - [Optional] Boot Target
-    ///
-    /// # Returns
-    ///
-    /// * `Ok(InfoStruct)` - Info Struct (Concatenated kernel commandline - includes slot,
-    /// bootconfig selection, normal_mode, Concatenated bootconfig) on success
-    /// * `Err(Error)` - on failure
-    pub fn unpack_boot_image(
-        &self,
-        boot_image_buffer: &BootImage,
-        boot_target: Option<BootTarget>,
-    ) -> Result<InfoStruct> {
-        unimplemented!();
-    }
+#[cfg(test)]
+mod tests {
+    extern crate avb_sysdeps;
+    extern crate avb_test;
+    extern crate libc_deps_posix;
 
-    /// Kernel Load
-    ///
-    /// Prepare kernel in RAM for booting
-    ///
-    /// # Arguments
-    ///   * `info` - Info Struct from Info Load
-    ///   * `image_buffer` - Buffer that contains (Verified) Boot Image
-    ///   * `load_buffer` - Kernel Load buffer
-    ///
-    /// # Returns
-    ///
-    /// * `Ok(())` - on success
-    /// * `Err(Error)` - on failure
-    pub fn kernel_load<'b>(
-        &self,
-        info: &InfoStruct,
-        image_buffer: BootImage,
-        load_buffer: &'b mut [u8],
-    ) -> Result<KernelImage<'b>> {
-        unimplemented!();
-    }
+    use super::*;
+    use crate::ops::test::FakeGblOps;
+    use avb::{CertPermanentAttributes, SlotVerifyError};
+    use avb_test::{FakeVbmetaKey, TestOps};
+    use libutils::aligned_offset;
+    use std::{
+        fs,
+        ops::{Deref, DerefMut},
+        path::Path,
+    };
+    use zerocopy::FromBytes;
 
-    /// Ramdisk + Bootconfig Load
-    ///
-    /// Kernel Load
-    /// (Could break this into a RD and Bootconfig specific function each, TBD)
-    /// Prepare ramdisk/bootconfig in RAM for booting
-    ///
-    /// # Arguments
-    ///   * `info` - Info Struct from Info Load
-    ///   * `vendor_boot_image` - Buffer that contains (Verified) Vendor Boot Image
-    ///   * `init_boot_image` - Buffer that contains (Verified) Init Boot Image
-    ///   * `ramdisk_load_buffer` - Ramdisk Load buffer (not compressed). It will be filled with
-    ///     a concatenation of `vendor_boot_image`, `init_boot_image` and bootconfig at the end.
-    ///
-    /// # Returns
-    ///
-    /// * `Ok(&str)` - on success returns Kernel command line
-    /// * `Err(Error)` - on failure
-    pub fn ramdisk_bootconfig_load(
-        &self,
-        info: &InfoStruct,
-        vendor_boot_image: &VendorBootImage,
-        init_boot_image: &InitBootImage,
-        ramdisk: &mut Ramdisk,
-    ) -> Result<&'static str> {
-        unimplemented!();
+    // Helper object for allocating aligned buffer.
+    pub(crate) struct AlignedBuffer {
+        buffer: Vec<u8>,
+        size: usize,
+        alignment: usize,
     }
 
-    /// DTB Update And Load
-    ///
-    /// Prepare DTB in RAM for booting
-    ///
-    /// # Arguments
-    ///   * `info` - Info Struct from Info Load
-    ///   * `vendor_boot_image_buffer` - Buffer that contains (Verified) Vendor Boot Image
-    ///
-    /// # Returns
-    ///
-    /// * `Ok()` - on success
-    /// * `Err(Error)` - on failure
-    pub fn dtb_update_and_load(
-        &self,
-        info: &InfoStruct,
-        vendor_boot_image_buffer: VendorBootImage,
-    ) -> Result<Dtb> {
-        unimplemented!();
-    }
+    impl AlignedBuffer {
+        /// Allocates a buffer.
+        pub(crate) fn new(size: usize, alignment: usize) -> Self {
+            Self { buffer: vec![0u8; alignment + size - 1], size, alignment }
+        }
 
-    /// Kernel Jump
-    ///
-    ///
-    /// # Arguments
-    ///   * `kernel_load_buffer` - Kernel Load buffer
-    ///   * `ramdisk_bootconfi_load_buffer` - Concatenated Ramdisk, (Bootconfig if present) Load
-    ///   buffer
-    ///   * `dtb_load_buffer` - DTB Load buffer
-    ///   * `boot_token` - Consumable boot token
-    ///
-    /// # Returns
-    ///
-    /// * doesn't return on success
-    /// * `Err(Error)` - on failure
-    // Nevertype could be used here when it is stable https://github.com/serde-rs/serde/issues/812
-    pub fn kernel_jump(
-        &self,
-        kernel_load_buffer: KernelImage,
-        ramdisk_load_buffer: Ramdisk,
-        dtb_load_buffer: Dtb,
-        boot_token: BootToken,
-    ) -> Result<()> {
-        unimplemented!();
+        /// Allocates a buffer and initializes with data.
+        pub(crate) fn new_with_data(data: &[u8], alignment: usize) -> Self {
+            let mut res = Self::new(data.len(), alignment);
+            res.clone_from_slice(data);
+            res
+        }
     }
 
-    /// Load, verify, and boot
-    ///
-    /// Wrapper around the above functions for devices that don't need custom behavior between each
-    /// step
-    ///
-    /// Warning: If the call to load_verify_boot fails, the device MUST
-    ///          be restarted in order to make forward boot progress.
-    ///          Callers MAY log the error, enter an interactive mode,
-    ///          or take other actions before rebooting.
-    ///
-    /// # Arguments
-    /// * `avb_ops` - implementation for `avb::Ops` that would be borrowed in result to prevent
-    ///   changes to partitions until it is out of scope.
-    /// * `partitions_to_verify` - names of all the partitions to verify with libavb.
-    /// * `partitions_ram_map` - Partitions to verify and optional address for them to be loaded.
-    /// * `slot_verify_flags` - AVB slot verification flags
-    /// * `slot_cursor` - Cursor object that manages interactions with boot slot management
-    /// * `kernel_load_buffer` - Buffer for loading the kernel.
-    /// * `ramdisk_load_buffer` - Buffer for loading the ramdisk.
-    /// * `fdt` - Buffer containing a flattened device tree blob.
-    ///
-    /// # Returns
-    /// * doesn't return on success
-    /// * `Err(Error)` - on failure
-    // Nevertype could be used here when it is stable https://github.com/serde-rs/serde/issues/812
-    #[allow(clippy::too_many_arguments)]
-    pub fn load_verify_boot<'b: 'c, 'c, 'd: 'b>(
-        &mut self,
-        avb_ops: &mut impl avb::Ops<'b>,
-        partitions_to_verify: &[&CStr],
-        partitions_ram_map: &'d mut [PartitionRamMap<'b, 'c>],
-        slot_verify_flags: SlotVerifyFlags,
-        slot_cursor: Cursor,
-        kernel_load_buffer: &mut [u8],
-        ramdisk_load_buffer: &mut [u8],
-        fdt: &mut [u8],
-    ) -> Result<()> {
-        let dtb = Dtb(&mut fdt[..]);
-        let mut ramdisk = Ramdisk(ramdisk_load_buffer);
-
-        // Call the inner method which consumes the cursor
-        // in order to properly manager cursor lifetime
-        // and cleanup.
-        let (kernel_image, token) = self.lvb_inner(
-            avb_ops,
-            &mut ramdisk,
-            kernel_load_buffer,
-            partitions_to_verify,
-            partitions_ram_map,
-            slot_verify_flags,
-            slot_cursor,
-        )?;
-
-        self.kernel_jump(kernel_image, ramdisk, dtb, token)
-    }
+    impl Deref for AlignedBuffer {
+        type Target = [u8];
 
-    fn is_unrecoverable_error(error: &IntegrationError) -> bool {
-        // Note: these ifs are nested instead of chained because multiple
-        //       expressions in an if-let is an unstable features
-        if let IntegrationError::AvbSlotVerifyError(ref avb_error) = error {
-            // These are the AVB errors that are not recoverable on a subsequent attempt.
-            // If necessary in the future, this helper function can be moved to the GblOps trait
-            // and customized for platform specific behavior.
-            if matches!(
-                avb_error,
-                SlotVerifyError::Verification(_)
-                    | SlotVerifyError::PublicKeyRejected
-                    | SlotVerifyError::RollbackIndex
-            ) {
-                return true;
-            }
+        fn deref(&self) -> &Self::Target {
+            let off = aligned_offset(&self.buffer, self.alignment).unwrap();
+            &self.buffer[off..][..self.size]
         }
-        false
     }
 
-    fn lvb_inner<'b: 'c, 'c, 'd: 'b, 'e>(
-        &mut self,
-        avb_ops: &mut impl avb::Ops<'b>,
-        ramdisk: &mut Ramdisk,
-        kernel_load_buffer: &'e mut [u8],
-        partitions_to_verify: &[&CStr],
-        partitions_ram_map: &'d mut [PartitionRamMap<'b, 'c>],
-        slot_verify_flags: SlotVerifyFlags,
-        slot_cursor: Cursor,
-    ) -> Result<(KernelImage<'e>, BootToken)> {
-        let oneshot_status = slot_cursor.ctx.get_oneshot_status();
-        slot_cursor.ctx.clear_oneshot_status();
-
-        let boot_target = match oneshot_status {
-            None | Some(OneShot::Bootloader) => slot_cursor.ctx.get_boot_target()?,
-            Some(OneShot::Continue(recovery)) => BootTarget::Recovery(recovery),
-        };
-
-        let verify_data = self
-            .load_and_verify_image(
-                avb_ops,
-                partitions_to_verify,
-                slot_verify_flags,
-                Some(boot_target),
-            )
-            .map_err(|e: IntegrationError| {
-                if let BootTarget::NormalBoot(slot) = boot_target {
-                    if Self::is_unrecoverable_error(&e) {
-                        let _ = slot_cursor.ctx.set_slot_unbootable(
-                            slot.suffix,
-                            UnbootableReason::VerificationFailure,
-                        );
-                    } else {
-                        // Note: the call to mark_boot_attempt will fail if any of the following occur:
-                        // * the target was already Unbootable before the call to load_and_verify_image
-                        // * policy, I/O, or other errors in mark_boot_attempt
-                        //
-                        // We don't really care about those circumstances.
-                        // The call here is a best effort attempt to decrement tries remaining.
-                        let _ = slot_cursor.ctx.mark_boot_attempt();
-                    }
-                }
-                e
-            })?;
-
-        let (boot_image, init_boot_image, vendor_boot_image, _) = get_images(partitions_ram_map);
-        let boot_image = boot_image.ok_or(Error::MissingImage)?;
-        let vendor_boot_image = vendor_boot_image.ok_or(Error::MissingImage)?;
-        let init_boot_image = init_boot_image.ok_or(Error::MissingImage)?;
-
-        if is_overlap(&[
-            boot_image.0,
-            vendor_boot_image.0,
-            init_boot_image.0,
-            &ramdisk.0,
-            kernel_load_buffer,
-        ]) {
-            return Err(IntegrationError::UnificationError(Error::BufferOverlap));
+    impl DerefMut for AlignedBuffer {
+        fn deref_mut(&mut self) -> &mut Self::Target {
+            let off = aligned_offset(&self.buffer, self.alignment).unwrap();
+            &mut self.buffer[off..][..self.size]
         }
-
-        let info_struct = self.unpack_boot_image(&boot_image, Some(boot_target))?;
-
-        let kernel_image = self.kernel_load(&info_struct, boot_image, kernel_load_buffer)?;
-
-        let cmd_line = self.ramdisk_bootconfig_load(
-            &info_struct,
-            &vendor_boot_image,
-            &init_boot_image,
-            ramdisk,
-        )?;
-
-        self.dtb_update_and_load(&info_struct, vendor_boot_image)?;
-
-        let token = slot_cursor.ctx.mark_boot_attempt().map_err(|_| Error::OperationProhibited)?;
-
-        Ok((kernel_image, token))
     }
-}
-
-#[cfg(test)]
-mod tests {
-    extern crate avb_sysdeps;
-    extern crate avb_test;
-    use super::*;
-    use crate::ops::test::FakeGblOps;
-    use avb::{CertPermanentAttributes, SlotVerifyError};
-    use avb_test::{FakeVbmetaKey, TestOps};
-    use std::{fs, path::Path};
-    use zerocopy::FromBytes;
 
     const TEST_ZIRCON_PARTITION_NAME: &str = "zircon_a";
     const TEST_ZIRCON_PARTITION_NAME_CSTR: &CStr = c"zircon_a";
@@ -693,7 +369,7 @@ mod tests {
         );
         assert_eq!(
             res.unwrap_err(),
-            IntegrationError::AvbSlotVerifyError(SlotVerifyError::PublicKeyRejected)
+            IntegrationError::AvbSlotVerifyError(SlotVerifyError::PublicKeyRejected(None))
         );
     }
 }
diff --git a/gbl/libgbl/src/ops.rs b/gbl/libgbl/src/ops.rs
index f2e11be..73aeeee 100644
--- a/gbl/libgbl/src/ops.rs
+++ b/gbl/libgbl/src/ops.rs
@@ -441,12 +441,242 @@ macro_rules! gbl_print {
 #[macro_export]
 macro_rules! gbl_println {
     ( $ops:expr, $( $x:expr ),* $(,)? ) => {
-        let newline = $ops.console_newline();
-        gbl_print!($ops, $($x,)*);
-        gbl_print!($ops, "{}", newline);
+        {
+            let newline = $ops.console_newline();
+            gbl_print!($ops, $($x,)*);
+            gbl_print!($ops, "{}", newline);
+        }
     };
 }
 
+/// Inherits everything from `ops` but override a few such as read boot_a from
+/// bootimg_buffer, avb_write_rollback_index(), slot operation etc
+pub(crate) struct RambootOps<'a, T> {
+    pub(crate) ops: &'a mut T,
+    pub(crate) preloaded_partitions: &'a [(&'a str, &'a [u8])],
+}
+
+impl<'a, 'd, T: GblOps<'a, 'd>> GblOps<'a, 'd> for RambootOps<'_, T> {
+    fn console_out(&mut self) -> Option<&mut dyn Write> {
+        self.ops.console_out()
+    }
+
+    fn should_stop_in_fastboot(&mut self) -> Result<bool, Error> {
+        self.ops.should_stop_in_fastboot()
+    }
+
+    fn reboot(&mut self) {
+        self.ops.reboot()
+    }
+
+    fn disks(
+        &self,
+    ) -> &'a [GblDisk<
+        Disk<impl BlockIo + 'a, impl DerefMut<Target = [u8]> + 'a>,
+        Gpt<impl DerefMut<Target = [u8]> + 'a>,
+    >] {
+        self.ops.disks()
+    }
+
+    fn expected_os(&mut self) -> Result<Option<Os>, Error> {
+        self.ops.expected_os()
+    }
+
+    fn zircon_add_device_zbi_items(
+        &mut self,
+        container: &mut ZbiContainer<&mut [u8]>,
+    ) -> Result<(), Error> {
+        self.ops.zircon_add_device_zbi_items(container)
+    }
+
+    fn get_zbi_bootloader_files_buffer(&mut self) -> Option<&mut [u8]> {
+        self.ops.get_zbi_bootloader_files_buffer()
+    }
+
+    fn load_slot_interface<'c>(
+        &'c mut self,
+        _fnmut: &'c mut dyn FnMut(&mut [u8]) -> Result<(), Error>,
+        _boot_token: crate::BootToken,
+    ) -> GblResult<slots::Cursor<'c>> {
+        self.ops.load_slot_interface(_fnmut, _boot_token)
+    }
+
+    fn avb_read_is_device_unlocked(&mut self) -> AvbIoResult<bool> {
+        self.ops.avb_read_is_device_unlocked()
+    }
+
+    fn avb_read_rollback_index(&mut self, _rollback_index_location: usize) -> AvbIoResult<u64> {
+        self.ops.avb_read_rollback_index(_rollback_index_location)
+    }
+
+    fn avb_write_rollback_index(&mut self, _: usize, _: u64) -> AvbIoResult<()> {
+        // We don't want to persist AVB related data such as updating antirollback indices.
+        Ok(())
+    }
+
+    fn avb_read_persistent_value(&mut self, name: &CStr, value: &mut [u8]) -> AvbIoResult<usize> {
+        self.ops.avb_read_persistent_value(name, value)
+    }
+
+    fn avb_write_persistent_value(&mut self, _: &CStr, _: &[u8]) -> AvbIoResult<()> {
+        // We don't want to persist AVB related data such as updating current VBH.
+        Ok(())
+    }
+
+    fn avb_erase_persistent_value(&mut self, _: &CStr) -> AvbIoResult<()> {
+        // We don't want to persist AVB related data such as updating current VBH.
+        Ok(())
+    }
+
+    fn avb_cert_read_permanent_attributes(
+        &mut self,
+        attributes: &mut CertPermanentAttributes,
+    ) -> AvbIoResult<()> {
+        self.ops.avb_cert_read_permanent_attributes(attributes)
+    }
+
+    fn avb_cert_read_permanent_attributes_hash(&mut self) -> AvbIoResult<[u8; SHA256_DIGEST_SIZE]> {
+        self.ops.avb_cert_read_permanent_attributes_hash()
+    }
+
+    fn get_image_buffer(
+        &mut self,
+        image_name: &str,
+        size: NonZeroUsize,
+    ) -> GblResult<ImageBuffer<'d>> {
+        self.ops.get_image_buffer(image_name, size)
+    }
+
+    fn get_custom_device_tree(&mut self) -> Option<&'a [u8]> {
+        self.ops.get_custom_device_tree()
+    }
+
+    fn fixup_os_commandline<'c>(
+        &mut self,
+        commandline: &CStr,
+        fixup_buffer: &'c mut [u8],
+    ) -> Result<Option<&'c str>, Error> {
+        self.ops.fixup_os_commandline(commandline, fixup_buffer)
+    }
+
+    fn fixup_bootconfig<'c>(
+        &mut self,
+        bootconfig: &[u8],
+        fixup_buffer: &'c mut [u8],
+    ) -> Result<Option<&'c [u8]>, Error> {
+        self.ops.fixup_bootconfig(bootconfig, fixup_buffer)
+    }
+
+    fn fixup_device_tree(&mut self, device_tree: &mut [u8]) -> Result<(), Error> {
+        self.ops.fixup_device_tree(device_tree)
+    }
+
+    fn select_device_trees(
+        &mut self,
+        components_registry: &mut device_tree::DeviceTreeComponentsRegistry,
+    ) -> Result<(), Error> {
+        self.ops.select_device_trees(components_registry)
+    }
+
+    fn read_from_partition_sync(
+        &mut self,
+        part: &str,
+        off: u64,
+        out: &mut (impl SliceMaybeUninit + ?Sized),
+    ) -> Result<(), Error> {
+        match self.preloaded_partitions.iter().find(|(name, _)| *name == part) {
+            Some((_, data)) => {
+                let buf = data
+                    .get(off.try_into()?..)
+                    .and_then(|v| v.get(..out.len()))
+                    .ok_or(Error::OutOfRange)?;
+                Ok(out.clone_from_slice(buf))
+            }
+            _ => self.ops.read_from_partition_sync(part, off, out),
+        }
+    }
+
+    fn avb_handle_verification_result(
+        &mut self,
+        color: BootStateColor,
+        digest: Option<&CStr>,
+        boot_os_version: Option<&[u8]>,
+        boot_security_patch: Option<&[u8]>,
+        system_os_version: Option<&[u8]>,
+        system_security_patch: Option<&[u8]>,
+        vendor_os_version: Option<&[u8]>,
+        vendor_security_patch: Option<&[u8]>,
+    ) -> AvbIoResult<()> {
+        self.ops.avb_handle_verification_result(
+            color,
+            digest,
+            boot_os_version,
+            boot_security_patch,
+            system_os_version,
+            system_security_patch,
+            vendor_os_version,
+            vendor_security_patch,
+        )
+    }
+
+    fn avb_validate_vbmeta_public_key(
+        &self,
+        public_key: &[u8],
+        public_key_metadata: Option<&[u8]>,
+    ) -> AvbIoResult<KeyValidationStatus> {
+        self.ops.avb_validate_vbmeta_public_key(public_key, public_key_metadata)
+    }
+
+    fn slots_metadata(&mut self) -> Result<SlotsMetadata, Error> {
+        // Ramboot is not suppose to call this interface.
+        unreachable!()
+    }
+
+    fn get_current_slot(&mut self) -> Result<Slot, Error> {
+        // Ramboot is slotless
+        Err(Error::Unsupported)
+    }
+
+    fn get_next_slot(&mut self, _: bool) -> Result<Slot, Error> {
+        // Ramboot is not suppose to call this interface.
+        unreachable!()
+    }
+
+    fn set_active_slot(&mut self, _: u8) -> Result<(), Error> {
+        // Ramboot is not suppose to call this interface.
+        unreachable!()
+    }
+
+    fn set_reboot_reason(&mut self, _: RebootReason) -> Result<(), Error> {
+        // Ramboot is not suppose to call this interface.
+        unreachable!()
+    }
+
+    fn get_reboot_reason(&mut self) -> Result<RebootReason, Error> {
+        // Assumes that ramboot use normal boot mode. But we might consider supporting recovery
+        // if there is a usecase.
+        Ok(RebootReason::Normal)
+    }
+
+    fn fastboot_variable<'arg>(
+        &mut self,
+        _: &CStr,
+        _: impl Iterator<Item = &'arg CStr> + Clone,
+        _: &mut [u8],
+    ) -> Result<usize, Error> {
+        // Ramboot should not need this.
+        unreachable!();
+    }
+
+    fn fastboot_visit_all_variables(
+        &mut self,
+        _: impl FnMut(&[&CStr], &CStr),
+    ) -> Result<(), Error> {
+        // Ramboot should not need this.
+        unreachable!();
+    }
+}
+
 #[cfg(test)]
 pub(crate) mod test {
     use super::*;
@@ -458,11 +688,11 @@ pub(crate) mod test {
     use core::{
         fmt::Write,
         ops::{Deref, DerefMut},
-        str::from_utf8,
     };
-    use fastboot::{snprintf, FormattedBytes};
+    use fdt::Fdt;
     use gbl_async::block_on;
     use gbl_storage::{new_gpt_max, Disk, GptMax, RamBlockIo};
+    use libutils::snprintf;
     use std::{
         collections::{HashMap, LinkedList},
         ffi::CString,
@@ -547,6 +777,42 @@ pub(crate) mod test {
 
         /// For return by `Self::get_image_buffer()`
         pub image_buffers: HashMap<String, LinkedList<ImageBuffer<'d>>>,
+
+        /// Custom device tree.
+        pub custom_device_tree: Option<&'a [u8]>,
+
+        /// Custom handler for `avb_handle_verification_result`
+        pub avb_handle_verification_result: Option<
+            &'a mut dyn FnMut(
+                BootStateColor,
+                Option<&CStr>,
+                Option<&[u8]>,
+                Option<&[u8]>,
+                Option<&[u8]>,
+                Option<&[u8]>,
+                Option<&[u8]>,
+                Option<&[u8]>,
+            ) -> AvbIoResult<()>,
+        >,
+
+        /// For returned by `get_current_slot`
+        //
+        // We wrap it in an `Option` so that if a test exercises code paths that use it but did not
+        // set it, it can panic with "unwrap()" which will give a clearer error and location
+        // message than a vague error such as `Error::Unimplemented`.
+        pub current_slot: Option<Result<Slot, Error>>,
+
+        /// For returned by `get_next_slot`
+        pub next_slot: Option<Result<Slot, Error>>,
+
+        /// Number of times `get_next_slot()` is called with `mark_boot_attempt` set to true.
+        pub mark_boot_attempt_called: usize,
+
+        /// slot index last set active by `set_active()`,
+        pub last_set_active_slot: Option<u8>,
+
+        /// For returned by `get_reboot_reason()`
+        pub reboot_reason: Option<Result<RebootReason, Error>>,
     }
 
     /// Print `console_out` output, which can be useful for debugging.
@@ -565,6 +831,7 @@ pub(crate) mod test {
         pub const TEST_BOOTLOADER_FILE_2: &'static [u8] = b"\x06test_2bar";
         pub const GBL_TEST_VAR: &'static str = "gbl-test-var";
         pub const GBL_TEST_VAR_VAL: &'static str = "gbl-test-var-val";
+        pub const GBL_TEST_BOOTCONFIG: &'static str = "arg1=val1\x0aarg2=val2\x0a";
 
         pub fn new(partitions: &'a [TestGblDisk]) -> Self {
             let mut res = Self {
@@ -705,16 +972,28 @@ pub(crate) mod test {
 
         fn avb_handle_verification_result(
             &mut self,
-            _color: BootStateColor,
-            _digest: Option<&CStr>,
-            _boot_os_version: Option<&[u8]>,
-            _boot_security_patch: Option<&[u8]>,
-            _system_os_version: Option<&[u8]>,
-            _system_security_patch: Option<&[u8]>,
-            _vendor_os_version: Option<&[u8]>,
-            _vendor_security_patch: Option<&[u8]>,
+            color: BootStateColor,
+            digest: Option<&CStr>,
+            boot_os_version: Option<&[u8]>,
+            boot_security_patch: Option<&[u8]>,
+            system_os_version: Option<&[u8]>,
+            system_security_patch: Option<&[u8]>,
+            vendor_os_version: Option<&[u8]>,
+            vendor_security_patch: Option<&[u8]>,
         ) -> AvbIoResult<()> {
-            unimplemented!();
+            match self.avb_handle_verification_result.as_mut() {
+                Some(f) => (*f)(
+                    color,
+                    digest,
+                    boot_os_version,
+                    boot_security_patch,
+                    system_os_version,
+                    system_security_patch,
+                    vendor_os_version,
+                    vendor_security_patch,
+                ),
+                _ => Ok(()),
+            }
         }
 
         fn get_image_buffer(
@@ -734,8 +1013,8 @@ pub(crate) mod test {
             ))))
         }
 
-        fn get_custom_device_tree(&mut self) -> Option<&'static [u8]> {
-            None
+        fn get_custom_device_tree(&mut self) -> Option<&'a [u8]> {
+            self.custom_device_tree
         }
 
         fn fixup_os_commandline<'c>(
@@ -743,26 +1022,34 @@ pub(crate) mod test {
             _commandline: &CStr,
             _fixup_buffer: &'c mut [u8],
         ) -> Result<Option<&'c str>, Error> {
-            unimplemented!();
+            Ok(None)
         }
 
         fn fixup_bootconfig<'c>(
             &mut self,
             _bootconfig: &[u8],
-            _fixup_buffer: &'c mut [u8],
+            fixup_buffer: &'c mut [u8],
         ) -> Result<Option<&'c [u8]>, Error> {
-            unimplemented!();
+            let (out, _) = fixup_buffer.split_at_mut(Self::GBL_TEST_BOOTCONFIG.len());
+            out.clone_from_slice(Self::GBL_TEST_BOOTCONFIG.as_bytes());
+            Ok(Some(out))
         }
 
-        fn fixup_device_tree(&mut self, _: &mut [u8]) -> Result<(), Error> {
-            unimplemented!();
+        fn fixup_device_tree(&mut self, fdt: &mut [u8]) -> Result<(), Error> {
+            Fdt::new_mut(fdt).unwrap().set_property("chosen", c"fixup", &[1])?;
+            Ok(())
         }
 
         fn select_device_trees(
             &mut self,
-            _: &mut device_tree::DeviceTreeComponentsRegistry,
+            device_tree: &mut device_tree::DeviceTreeComponentsRegistry,
         ) -> Result<(), Error> {
-            unimplemented!();
+            // Select the first dtbo.
+            match device_tree.components_mut().find(|v| !v.is_base_device_tree()) {
+                Some(v) => v.selected = true,
+                _ => {}
+            }
+            device_tree.autoselect()
         }
 
         fn fastboot_variable<'arg>(
@@ -799,15 +1086,17 @@ pub(crate) mod test {
         }
 
         fn get_current_slot(&mut self) -> Result<Slot, Error> {
-            unimplemented!()
+            self.current_slot.unwrap()
         }
 
-        fn get_next_slot(&mut self, _: bool) -> Result<Slot, Error> {
-            unimplemented!()
+        fn get_next_slot(&mut self, mark_boot_attempt: bool) -> Result<Slot, Error> {
+            self.mark_boot_attempt_called += usize::from(mark_boot_attempt);
+            self.next_slot.unwrap()
         }
 
-        fn set_active_slot(&mut self, _: u8) -> Result<(), Error> {
-            unimplemented!()
+        fn set_active_slot(&mut self, slot: u8) -> Result<(), Error> {
+            self.last_set_active_slot = Some(slot);
+            Ok(())
         }
 
         fn set_reboot_reason(&mut self, _: RebootReason) -> Result<(), Error> {
@@ -815,7 +1104,7 @@ pub(crate) mod test {
         }
 
         fn get_reboot_reason(&mut self) -> Result<RebootReason, Error> {
-            unimplemented!()
+            self.reboot_reason.unwrap()
         }
     }
 
@@ -863,4 +1152,9 @@ pub(crate) mod test {
         // One shot recovery is not set.
         assert_eq!(get_boot_slot(&mut GblAbrOps(&mut gbl_ops), true), (SlotIndex::A, false));
     }
+
+    /// Helper for creating a slot object.
+    pub(crate) fn slot(suffix: char) -> Slot {
+        Slot { suffix: suffix.into(), ..Default::default() }
+    }
 }
diff --git a/gbl/libgbl/src/overlap.rs b/gbl/libgbl/src/overlap.rs
deleted file mode 100644
index 20d129d..0000000
--- a/gbl/libgbl/src/overlap.rs
+++ /dev/null
@@ -1,121 +0,0 @@
-// Copyright 2024, The Android Open Source Project
-//
-// Licensed under the Apache License, Version 2.0 (the "License");
-// you may not use this file except in compliance with the License.
-// You may obtain a copy of the License at
-//
-//     http://www.apache.org/licenses/LICENSE-2.0
-//
-// Unless required by applicable law or agreed to in writing, software
-// distributed under the License is distributed on an "AS IS" BASIS,
-// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
-// See the License for the specific language governing permissions and
-// limitations under the License.
-
-//! Helper functions to verify image buffers
-use core::cmp::{max, min};
-extern crate itertools_noalloc;
-use itertools_noalloc::Itertools;
-
-/// Check if provided buffers overlap in any way.
-///
-/// Note that zero length buffer is considered to contain no elements.
-/// And would not overlap with any other buffer.
-///
-/// # Args
-///
-/// * `buffers`: slice of buffers to verify
-///
-/// # Returns
-///
-/// * true: if any of the buffers have common elements
-/// * false: if there are no common elements in buffers
-pub fn is_overlap(buffers: &[&[u8]]) -> bool {
-    // Compare each with each since we can't use alloc and sort buffers.
-    // Since the number of buffers we expect is not big, O(n^2) complexity will do.
-    //
-    // Note: this is nice way to find out if 2 ranges overlap:
-    // max(a_start, b_start) > min(a_end, b_end)) -> no overlap
-    buffers
-        .iter()
-        .filter(|buffer| !buffer.is_empty())
-        .map(|slice: &&[u8]| (slice.as_ptr(), slice.last_chunk::<1>().unwrap().as_ptr()))
-        .tuple_combinations()
-        .any(|((a_start, a_end), (b_start, b_end))| !(max(a_start, b_start) > min(a_end, b_end)))
-}
-
-#[cfg(test)]
-mod tests {
-    use super::*;
-    use itertools::Itertools;
-
-    // Creates slice of specified range: [first; last)
-    // Max range value is SIZE = 64;
-    fn get_range(first: usize, last: usize) -> &'static [u8] {
-        const SIZE: usize = 64;
-        assert!(first < SIZE);
-        assert!(last <= SIZE);
-        static BUFFER: &'static [u8; SIZE] = &[0; SIZE];
-        &BUFFER[first..last]
-    }
-
-    // Check if ranges overlap, testing all permutations
-    fn check_overlap(ranges_set: &[(usize, usize)]) -> bool {
-        ranges_set.iter().permutations(ranges_set.len()).all(|ranges| {
-            let ranges_slices: Vec<&[u8]> =
-                ranges.iter().map(|&(start, end)| get_range(*start, *end)).collect();
-            is_overlap(&ranges_slices)
-        })
-    }
-
-    // Check if ranges don't overlap, testing all permutations
-    fn check_not_overlap(ranges_set: &[(usize, usize)]) -> bool {
-        ranges_set.iter().permutations(ranges_set.len()).all(|ranges| {
-            let ranges_slices: Vec<&[u8]> =
-                ranges.iter().map(|&(start, end)| get_range(*start, *end)).collect();
-            !is_overlap(&ranges_slices)
-        })
-    }
-
-    #[test]
-    fn test_is_overlap_false() {
-        assert!(check_not_overlap(&[(10, 15), (20, 25), (30, 35)]));
-    }
-
-    #[test]
-    fn test_is_overlap_true() {
-        assert!(check_overlap(&[(10, 19), (15, 25)]));
-    }
-
-    #[test]
-    fn test_is_overlap_included() {
-        assert!(check_overlap(&[(10, 11), (10, 11)]));
-        assert!(check_overlap(&[(10, 12), (10, 12)]));
-        assert!(check_overlap(&[(10, 13), (11, 12)]));
-        assert!(check_overlap(&[(10, 14), (11, 13)]));
-        assert!(check_overlap(&[(10, 20), (15, 18)]));
-        assert!(check_overlap(&[(10, 20), (11, 19), (12, 18), (13, 17)]));
-    }
-
-    #[test]
-    fn test_is_overlap_touching() {
-        assert!(check_not_overlap(&[(10, 20), (20, 30), (30, 31)]));
-    }
-
-    #[test]
-    fn test_is_overlap_last_element() {
-        assert!(check_overlap(&[(10, 20), (19, 21)]));
-    }
-
-    #[test]
-    fn test_is_overlap_short() {
-        assert!(check_not_overlap(&[(10, 11), (11, 12), (12, 13)]));
-    }
-
-    #[test]
-    fn test_is_overlap_empty_slice() {
-        assert!(check_not_overlap(&[]));
-        assert!(check_not_overlap(&[(10, 10)]));
-        assert!(check_not_overlap(&[(10, 20), (10, 10), (20, 30), (11, 11), (23, 23)]));
-    }
-}
diff --git a/gbl/libgbl/src/partition.rs b/gbl/libgbl/src/partition.rs
index 1e23dba..f56107a 100644
--- a/gbl/libgbl/src/partition.rs
+++ b/gbl/libgbl/src/partition.rs
@@ -18,7 +18,6 @@ use crate::fastboot::sparse::{is_sparse_image, write_sparse_image, SparseRawWrit
 use core::cell::{RefCell, RefMut};
 use core::{
     ffi::CStr,
-    mem::swap,
     ops::{Deref, DerefMut},
 };
 use gbl_storage::{
@@ -29,7 +28,7 @@ use liberror::Error;
 use safemath::SafeNum;
 
 /// Maximum name length for raw partition.
-const RAW_PARTITION_NAME_LEN: usize = 72;
+pub const RAW_PARTITION_NAME_LEN: usize = 72;
 
 /// Wraps a bytes buffer containing a null-terminated C string
 #[derive(Copy, Clone, PartialEq, Debug)]
@@ -96,8 +95,6 @@ pub enum BlockStatus {
     Idle,
     /// An IO in progress.
     Pending,
-    /// Error.
-    Error(Error),
 }
 
 impl BlockStatus {
@@ -106,15 +103,6 @@ impl BlockStatus {
         match self {
             BlockStatus::Idle => "idle",
             BlockStatus::Pending => "IO pending",
-            BlockStatus::Error(_) => "error",
-        }
-    }
-
-    /// Converts to result.
-    pub fn result(&self) -> Result<(), Error> {
-        match self {
-            Self::Error(e) => Err(*e),
-            _ => Ok(()),
         }
     }
 }
@@ -122,14 +110,13 @@ impl BlockStatus {
 /// Represents a disk device that contains either GPT partitions or a single whole raw storage
 /// partition.
 pub struct GblDisk<D, G> {
-    // Contains a `Disk` for block IO and `Result` to track the most recent error.
-    // Wraps in `Mutex` as it will be used in parallel fastboot task.
+    // Contains a `Disk` for block IO.
     //
-    // `blk` and `partitions` are wrapped in RefCell because they may be shared by multiple async
+    // `disk` and `partitions` are wrapped in RefCell because they may be shared by multiple async
     // blocks for operations such as parallel fastboot download/flashing. They are also wrapped
     // separately in order to make operations on each independent and parallel for use cases such
     // as getting partition info for `fastboot getvar` when disk IO is busy.
-    disk: RefCell<(D, Result<(), Error>)>,
+    disk: RefCell<D>,
     partitions: RefCell<PartitionTable<G>>,
     info_cache: BlockInfo,
 }
@@ -143,18 +130,14 @@ where
     /// Creates a new instance as a GPT device.
     pub fn new_gpt(mut disk: Disk<B, S>, gpt: Gpt<T>) -> Self {
         let info_cache = disk.io().info();
-        Self {
-            disk: (disk, Ok(())).into(),
-            info_cache,
-            partitions: PartitionTable::Gpt(gpt).into(),
-        }
+        Self { disk: disk.into(), info_cache, partitions: PartitionTable::Gpt(gpt).into() }
     }
 
     /// Creates a new instance as a raw storage partition.
     pub fn new_raw(mut disk: Disk<B, S>, name: &CStr) -> Result<Self, Error> {
         let info_cache = disk.io().info();
         Ok(Self {
-            disk: (disk, Ok(())).into(),
+            disk: disk.into(),
             info_cache,
             partitions: PartitionTable::Raw(RawName::new(name)?, info_cache.total_size()?).into(),
         })
@@ -169,17 +152,13 @@ where
     pub fn status(&self) -> BlockStatus {
         match self.disk.try_borrow_mut().ok() {
             None => BlockStatus::Pending,
-            Some(v) if v.1.is_err() => BlockStatus::Error(v.1.unwrap_err()),
             _ => BlockStatus::Idle,
         }
     }
 
-    /// Borrows disk and last_err separately
-    fn get_disk_and_last_err(
-        &self,
-    ) -> Result<(RefMut<'_, Disk<B, S>>, RefMut<'_, Result<(), Error>>), Error> {
-        let res = self.disk.try_borrow_mut().map_err(|_| Error::NotReady)?;
-        Ok(RefMut::map_split(res, |v| (&mut v.0, &mut v.1)))
+    /// Borrows disk mutably.
+    fn get_disk(&self) -> Result<RefMut<'_, Disk<B, S>>, Error> {
+        self.disk.try_borrow_mut().map_err(|_| Error::NotReady)
     }
 
     /// Gets an instance of `PartitionIo` for a partition.
@@ -187,8 +166,7 @@ where
     /// If `part` is `None`, an IO for the whole block device is returned.
     pub fn partition_io(&self, part: Option<&str>) -> Result<PartitionIo<'_, B>, Error> {
         let (part_start, part_end) = self.find_partition(part)?.absolute_range()?;
-        let (disk, last_err) = self.get_disk_and_last_err()?;
-        Ok(PartitionIo { disk: Disk::from_ref_mut(disk), last_err, part_start, part_end })
+        Ok(PartitionIo { disk: Disk::from_ref_mut(self.get_disk()?), part_start, part_end })
     }
 
     /// Finds a partition.
@@ -239,7 +217,7 @@ where
             PartitionTable::Raw(_, _) => Ok(None),
             PartitionTable::Gpt(ref mut gpt) => {
                 let mut blk = self.disk.try_borrow_mut().map_err(|_| Error::NotReady)?;
-                Ok(Some(blk.0.sync_gpt(gpt).await?))
+                Ok(Some(blk.sync_gpt(gpt).await?))
             }
         }
     }
@@ -262,7 +240,7 @@ where
             PartitionTable::Raw(_, _) => Err(Error::Unsupported),
             PartitionTable::Gpt(ref mut gpt) => {
                 let mut blk = self.disk.try_borrow_mut().map_err(|_| Error::NotReady)?;
-                blk.0.update_gpt(mbr_primary, resize, gpt).await
+                blk.update_gpt(mbr_primary, resize, gpt).await
             }
         }
     }
@@ -278,7 +256,7 @@ where
             PartitionTable::Raw(_, _) => Err(Error::Unsupported),
             PartitionTable::Gpt(ref mut gpt) => {
                 let mut disk = self.disk.try_borrow_mut().map_err(|_| Error::NotReady)?;
-                disk.0.erase_gpt(gpt).await
+                disk.erase_gpt(gpt).await
             }
         }
     }
@@ -295,9 +273,7 @@ where
                     PartitionTable::Gpt(v) => v,
                     _ => unreachable!(),
                 });
-                let (disk, err) = self.get_disk_and_last_err()?;
-                (*err)?;
-                Ok(GptBuilder::new(disk, gpt)?.0)
+                Ok(GptBuilder::new(self.get_disk()?, gpt)?.0)
             }
         }
     }
@@ -306,7 +282,6 @@ where
 /// `PartitionIo` provides read/write APIs to a partition.
 pub struct PartitionIo<'a, B: BlockIo> {
     disk: Disk<RefMut<'a, B>, RefMut<'a, [u8]>>,
-    last_err: RefMut<'a, Result<(), Error>>,
     part_start: u64,
     part_end: u64,
 }
@@ -328,16 +303,15 @@ impl<'a, B: BlockIo> PartitionIo<'a, B> {
         let ab_range_end = SafeNum::from(self.part_start) + off + size.into();
         // Checks overflow by computing the difference between range end and partition end and
         // making sure it succeeds.
-        let _end_diff: u64 = (SafeNum::from(self.part_end) - ab_range_end).try_into()?;
-        Ok((SafeNum::from(self.part_start) + off).try_into()?)
+        (SafeNum::from(self.part_end) - ab_range_end)
+            .try_into()
+            .and_then(|_: u64| (SafeNum::from(self.part_start) + off).try_into())
+            .map_err(|_| Error::OutOfRange)
     }
 
     /// Writes to the partition.
     pub async fn write(&mut self, off: u64, data: &mut [u8]) -> Result<(), Error> {
-        let res =
-            async { self.disk.write(self.check_rw_range(off, data.len())?, data).await }.await;
-        *self.last_err = res.and(*self.last_err);
-        res
+        self.disk.write(self.check_rw_range(off, data.len())?, data).await
     }
 
     /// Reads from the partition.
@@ -346,27 +320,19 @@ impl<'a, B: BlockIo> PartitionIo<'a, B> {
         off: u64,
         out: &mut (impl SliceMaybeUninit + ?Sized),
     ) -> Result<(), Error> {
-        let res = async { self.disk.read(self.check_rw_range(off, out.len())?, out).await }.await;
-        *self.last_err = res.and(*self.last_err);
-        res
+        self.disk.read(self.check_rw_range(off, out.len())?, out).await
     }
 
     /// Writes zeroes to the partition.
     pub async fn zeroize(&mut self, scratch: &mut [u8]) -> Result<(), Error> {
-        let res = async { self.disk.fill(self.part_start, self.size(), 0, scratch).await }.await;
-        *self.last_err = res.and(*self.last_err);
-        *self.last_err
+        self.disk.fill(self.part_start, self.size(), 0, scratch).await
     }
 
     /// Writes sparse image to the partition.
     pub async fn write_sparse(&mut self, off: u64, img: &mut [u8]) -> Result<(), Error> {
-        let res = async {
-            let sz = is_sparse_image(img).map_err(|_| Error::InvalidInput)?.data_size();
-            write_sparse_image(img, &mut (self.check_rw_range(off, sz)?, &mut self.disk)).await
-        }
-        .await;
-        *self.last_err = res.map(|_| ()).and(*self.last_err);
-        *self.last_err
+        let sz = is_sparse_image(img).map_err(|_| Error::InvalidInput)?.data_size();
+        write_sparse_image(img, &mut (self.check_rw_range(off, sz)?, &mut self.disk)).await?;
+        Ok(())
     }
 
     /// Turns this IO into one for a subrange in the partition.
@@ -377,18 +343,6 @@ impl<'a, B: BlockIo> PartitionIo<'a, B> {
         sub.part_end = sub.part_start + sz;
         Ok(sub)
     }
-
-    /// Returns the most recent error.
-    pub fn last_err(&self) -> Result<(), Error> {
-        *self.last_err
-    }
-
-    /// Takes the error and resets it.
-    pub fn take_err(&mut self) -> Result<(), Error> {
-        let mut err = Ok(());
-        swap(&mut self.last_err as _, &mut err);
-        err
-    }
 }
 
 // Implements `SparseRawWriter` for tuple (<flash offset>, <block device>)
@@ -684,7 +638,6 @@ pub(crate) mod test {
         assert!(
             block_on(raw.partition_io(Some("raw")).unwrap().write_sparse(1, &mut sparse)).is_err()
         );
-        assert!(raw.partition_io(Some("raw")).unwrap().last_err().is_err());
     }
 
     #[test]
@@ -695,44 +648,6 @@ pub(crate) mod test {
         assert!(
             block_on(raw.partition_io(Some("raw")).unwrap().write_sparse(1, &mut sparse)).is_err()
         );
-        assert!(raw.partition_io(Some("raw")).unwrap().last_err().is_err());
-    }
-
-    #[test]
-    fn test_partiton_last_err_read() {
-        let raw = raw_disk(c"raw", vec![0u8; 1024]);
-        let mut part_io = raw.partition_io(Some("raw")).unwrap();
-        // Causes some error by read
-        assert!(block_on(part_io.read(1024, &mut [0][..])).is_err());
-        assert!(part_io.last_err().is_err());
-    }
-
-    #[test]
-    fn test_partiton_last_err_write() {
-        let raw = raw_disk(c"raw", vec![0u8; 1024]);
-        let mut part_io = raw.partition_io(Some("raw")).unwrap();
-        // Causes some error by write
-        assert!(block_on(part_io.write(1024, &mut [0])).is_err());
-        assert!(part_io.last_err().is_err());
-    }
-
-    #[test]
-    fn test_partiton_last_err_persist_through_operation() {
-        let raw = raw_disk(c"raw", vec![0u8; 1024]);
-        // Causes some error by read
-        assert!(block_on(raw.partition_io(Some("raw")).unwrap().read(1024, &mut [0][..])).is_err());
-        // Tracked error should persist regardless of how many times we get partition io.
-        assert!(raw.partition_io(Some("raw")).unwrap().last_err().is_err());
-        assert!(raw.partition_io(None).unwrap().last_err().is_err());
-        // Should persist even after successful operations.
-        block_on(raw.partition_io(Some("raw")).unwrap().read(1023, &mut [0][..])).unwrap();
-        assert!(raw.partition_io(Some("raw")).unwrap().last_err().is_err());
-        block_on(raw.partition_io(Some("raw")).unwrap().write(1023, &mut [0][..])).unwrap();
-        assert!(raw.partition_io(Some("raw")).unwrap().last_err().is_err());
-        assert!(raw.partition_io(None).unwrap().last_err().is_err());
-        // Taking error should reset it.
-        assert!(raw.partition_io(None).unwrap().take_err().is_err());
-        assert!(raw.partition_io(None).unwrap().last_err().is_ok());
     }
 
     #[test]
diff --git a/gbl/libgbl/src/slots/android.rs b/gbl/libgbl/src/slots/android.rs
index 2ce536a..af11c2e 100644
--- a/gbl/libgbl/src/slots/android.rs
+++ b/gbl/libgbl/src/slots/android.rs
@@ -25,7 +25,7 @@ use core::ops::{BitAnd, BitOr, Not, Shl, Shr};
 use crc32fast::Hasher;
 use liberror::Error;
 use zerocopy::byteorder::little_endian::U32 as LittleEndianU32;
-use zerocopy::{AsBytes, ByteSlice, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice};
 
 extern crate static_assertions;
 
@@ -68,7 +68,7 @@ const DEFAULT_RETRIES: u8 = 7;
 ///
 /// Does NOT contain unbootable reason information.
 #[repr(C, packed)]
-#[derive(Copy, Clone, Debug, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct SlotMetaData(u16);
 
 #[allow(dead_code)]
@@ -134,7 +134,9 @@ impl Default for SlotMetaData {
     }
 }
 
-#[derive(Copy, Clone, Debug, Default, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(
+    Copy, Clone, Debug, Default, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout,
+)]
 #[repr(C, packed)]
 struct ControlBits(u16);
 
@@ -196,7 +198,7 @@ const BOOT_CTRL_VERSION: u8 = 1;
 ///
 /// Does NOT support oneshots
 #[repr(C, packed)]
-#[derive(Copy, Clone, Debug, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct BootloaderControl {
     slot_suffix: [u8; 4],
     magic: u32,
@@ -242,7 +244,7 @@ impl Default for BootloaderControl {
 }
 
 impl MetadataBytes for BootloaderControl {
-    fn validate<B: ByteSlice>(buffer: B) -> Result<Ref<B, Self>, Error> {
+    fn validate<B: SplitByteSlice>(buffer: B) -> Result<Ref<B, Self>, Error> {
         let boot_control_data = Ref::<B, Self>::new_from_prefix(buffer)
             .ok_or(Error::BufferTooSmall(Some(size_of::<BootloaderControl>())))?
             .0;
diff --git a/gbl/libgbl/src/slots/fuchsia.rs b/gbl/libgbl/src/slots/fuchsia.rs
index b9e2236..4cc7011 100644
--- a/gbl/libgbl/src/slots/fuchsia.rs
+++ b/gbl/libgbl/src/slots/fuchsia.rs
@@ -27,13 +27,13 @@ use core::mem::size_of;
 use crc32fast::Hasher;
 use liberror::Error;
 use zerocopy::byteorder::big_endian::U32 as BigEndianU32;
-use zerocopy::{AsBytes, ByteSlice, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice};
 
 const DEFAULT_PRIORITY: u8 = 15;
 const DEFAULT_RETRIES: u8 = 7;
 
 #[repr(C, packed)]
-#[derive(Copy, Clone, Debug, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct AbrSlotData {
     priority: u8,
     tries: u8,
@@ -53,7 +53,7 @@ impl Default for AbrSlotData {
 }
 
 #[repr(C, packed)]
-#[derive(Copy, Clone, Debug, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct OneShotFlags(u8);
 
 bitflags! {
@@ -96,7 +96,7 @@ const ABR_VERSION_MAJOR: u8 = 2;
 const ABR_VERSION_MINOR: u8 = 3;
 
 #[repr(C, packed)]
-#[derive(Copy, Clone, Debug, PartialEq, Eq, AsBytes, FromBytes, FromZeroes)]
+#[derive(Copy, Clone, Debug, PartialEq, Eq, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct AbrData {
     magic: [u8; 4],
     version_major: u8,
@@ -119,7 +119,7 @@ impl AbrData {
 }
 
 impl MetadataBytes for AbrData {
-    fn validate<B: ByteSlice>(buffer: B) -> Result<Ref<B, AbrData>, Error> {
+    fn validate<B: SplitByteSlice>(buffer: B) -> Result<Ref<B, AbrData>, Error> {
         let abr_data = Ref::<B, AbrData>::new_from_prefix(buffer)
             .ok_or(Error::BufferTooSmall(Some(size_of::<AbrData>())))?
             .0;
diff --git a/gbl/libgbl/src/slots/partition.rs b/gbl/libgbl/src/slots/partition.rs
index 931c942..af362e5 100644
--- a/gbl/libgbl/src/slots/partition.rs
+++ b/gbl/libgbl/src/slots/partition.rs
@@ -13,7 +13,7 @@
 // limitations under the License.
 
 use super::BootToken;
-use zerocopy::{AsBytes, ByteSlice, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice};
 
 use liberror::Error;
 
@@ -28,14 +28,14 @@ pub enum CacheStatus {
 
 /// Trait that describes the operations all slot metadata implementations must support
 /// to be used as the backing store in a SlotBlock.
-pub trait MetadataBytes: Copy + AsBytes + FromBytes + FromZeroes + Default {
+pub trait MetadataBytes: Copy + Immutable + IntoBytes + FromBytes + KnownLayout + Default {
     /// Returns a zerocopy reference to Self if buffer
     /// represents a valid serialization of Self.
     /// Implementors should check for invariants,
     /// e.g. checksums, magic numbers, and version numbers.
     ///
     /// Returns Err if the buffer does not represent a valid structure.
-    fn validate<B: ByteSlice>(buffer: B) -> Result<Ref<B, Self>, Error>;
+    fn validate<B: SplitByteSlice>(buffer: B) -> Result<Ref<B, Self>, Error>;
 
     /// Called right before writing metadata back to disk.
     /// Implementors should restore invariants,
@@ -89,7 +89,7 @@ impl<'a, MB: MetadataBytes> SlotBlock<MB> {
     ///                 if there was an internal error.
     ///
     ///                 TODO(b/329116902): errors are logged
-    pub fn deserialize<B: ByteSlice>(buffer: B, boot_token: BootToken) -> Self {
+    pub fn deserialize<B: SplitByteSlice>(buffer: B, boot_token: BootToken) -> Self {
         // TODO(b/329116902): log failures
         // validate(buffer)
         // .inspect_err(|e| {
diff --git a/gbl/libgbl/testdata/BUILD b/gbl/libgbl/testdata/BUILD
index 8798319..b8ead03 100644
--- a/gbl/libgbl/testdata/BUILD
+++ b/gbl/libgbl/testdata/BUILD
@@ -13,3 +13,12 @@
 # limitations under the License.
 
 exports_files(glob(["**/*"]))
+
+filegroup(
+    name = "testdata",
+    srcs = glob(
+        ["**/*"],
+        exclude = [":gen_test_data.py"],
+    ),
+    visibility = ["//visibility:public"],
+)
diff --git a/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_a.img b/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_a.img
new file mode 100644
index 0000000..9152a34
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_b.img b/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_b.img
new file mode 100644
index 0000000..cdbbba6
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_no_ramdisk_v3_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_a.img b/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_a.img
new file mode 100644
index 0000000..a0a3838
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_b.img b/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_b.img
new file mode 100644
index 0000000..434db34
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_no_ramdisk_v4_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v0_a.img b/gbl/libgbl/testdata/android/boot_v0_a.img
new file mode 100644
index 0000000..47d02cf
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v0_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v0_b.img b/gbl/libgbl/testdata/android/boot_v0_b.img
new file mode 100644
index 0000000..7587922
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v0_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v1_a.img b/gbl/libgbl/testdata/android/boot_v1_a.img
new file mode 100644
index 0000000..ff24a4e
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v1_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v1_b.img b/gbl/libgbl/testdata/android/boot_v1_b.img
new file mode 100644
index 0000000..28b13fe
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v1_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v2_a.img b/gbl/libgbl/testdata/android/boot_v2_a.img
new file mode 100644
index 0000000..c2b0c8c
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v2_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v2_b.img b/gbl/libgbl/testdata/android/boot_v2_b.img
new file mode 100644
index 0000000..b7741c9
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v2_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v3_a.img b/gbl/libgbl/testdata/android/boot_v3_a.img
new file mode 100644
index 0000000..f852aa2
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v3_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v3_b.img b/gbl/libgbl/testdata/android/boot_v3_b.img
new file mode 100644
index 0000000..b3e33e9
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v3_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v4_a.img b/gbl/libgbl/testdata/android/boot_v4_a.img
new file mode 100644
index 0000000..bdae1f6
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v4_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v4_b.img b/gbl/libgbl/testdata/android/boot_v4_b.img
new file mode 100644
index 0000000..bca8775
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v4_b.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v4_gz_a.img b/gbl/libgbl/testdata/android/boot_v4_gz_a.img
new file mode 100644
index 0000000..cd74a95
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v4_gz_a.img differ
diff --git a/gbl/libgbl/testdata/android/boot_v4_lz4_a.img b/gbl/libgbl/testdata/android/boot_v4_lz4_a.img
new file mode 100644
index 0000000..2bdc049
Binary files /dev/null and b/gbl/libgbl/testdata/android/boot_v4_lz4_a.img differ
diff --git a/gbl/libgbl/testdata/android/device_tree.dtb b/gbl/libgbl/testdata/android/device_tree.dtb
new file mode 100644
index 0000000..edccb90
Binary files /dev/null and b/gbl/libgbl/testdata/android/device_tree.dtb differ
diff --git a/gbl/libgbl/testdata/android/device_tree.dts b/gbl/libgbl/testdata/android/device_tree.dts
new file mode 100644
index 0000000..916c616
--- /dev/null
+++ b/gbl/libgbl/testdata/android/device_tree.dts
@@ -0,0 +1,11 @@
+/dts-v1/;
+
+/ {
+    info = "test device tree";
+
+    chosen {
+        bootargs = "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2";
+        builtin = [01];
+        fixup = <0x0>;
+    };
+};
diff --git a/gbl/libgbl/testdata/android/device_tree_a.dtb b/gbl/libgbl/testdata/android/device_tree_a.dtb
new file mode 100644
index 0000000..20bce9a
Binary files /dev/null and b/gbl/libgbl/testdata/android/device_tree_a.dtb differ
diff --git a/gbl/libgbl/testdata/android/device_tree_a.dts b/gbl/libgbl/testdata/android/device_tree_a.dts
new file mode 100644
index 0000000..92deaff
--- /dev/null
+++ b/gbl/libgbl/testdata/android/device_tree_a.dts
@@ -0,0 +1,11 @@
+/dts-v1/;
+
+/ {
+    info = "test device tree from dtb partition";
+
+    chosen {
+        bootargs = "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2";
+        dtb_slot = "a";
+        fixup = <0x0>;
+    };
+};
diff --git a/gbl/libgbl/testdata/android/device_tree_b.dtb b/gbl/libgbl/testdata/android/device_tree_b.dtb
new file mode 100644
index 0000000..0bad154
Binary files /dev/null and b/gbl/libgbl/testdata/android/device_tree_b.dtb differ
diff --git a/gbl/libgbl/testdata/android/device_tree_b.dts b/gbl/libgbl/testdata/android/device_tree_b.dts
new file mode 100644
index 0000000..3b182ac
--- /dev/null
+++ b/gbl/libgbl/testdata/android/device_tree_b.dts
@@ -0,0 +1,11 @@
+/dts-v1/;
+
+/ {
+    info = "test device tree from dtb partition";
+
+    chosen {
+        bootargs = "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2";
+        dtb_slot = "b";
+        fixup = <0x0>;
+    };
+};
diff --git a/gbl/libgbl/testdata/android/device_tree_custom.dtb b/gbl/libgbl/testdata/android/device_tree_custom.dtb
new file mode 100644
index 0000000..b61150d
Binary files /dev/null and b/gbl/libgbl/testdata/android/device_tree_custom.dtb differ
diff --git a/gbl/libgbl/testdata/android/device_tree_custom.dts b/gbl/libgbl/testdata/android/device_tree_custom.dts
new file mode 100644
index 0000000..0d8b85a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/device_tree_custom.dts
@@ -0,0 +1,11 @@
+/dts-v1/;
+
+/ {
+    info = "test device tree";
+
+    chosen {
+        bootargs = "existing_arg_1=existing_val_1 existing_arg_2=existing_val_2";
+        fixup = <0x0>;
+        custom = "1";
+    };
+};
diff --git a/gbl/libgbl/testdata/android/dtb.img b/gbl/libgbl/testdata/android/dtb.img
new file mode 100644
index 0000000..1ea26fa
Binary files /dev/null and b/gbl/libgbl/testdata/android/dtb.img differ
diff --git a/gbl/libgbl/testdata/android/dtb_a.img b/gbl/libgbl/testdata/android/dtb_a.img
new file mode 100644
index 0000000..4afcd61
Binary files /dev/null and b/gbl/libgbl/testdata/android/dtb_a.img differ
diff --git a/gbl/libgbl/testdata/android/dtb_b.img b/gbl/libgbl/testdata/android/dtb_b.img
new file mode 100644
index 0000000..fbeccda
Binary files /dev/null and b/gbl/libgbl/testdata/android/dtb_b.img differ
diff --git a/gbl/libgbl/testdata/android/dtbo_a.img b/gbl/libgbl/testdata/android/dtbo_a.img
new file mode 100644
index 0000000..206d8a9
Binary files /dev/null and b/gbl/libgbl/testdata/android/dtbo_a.img differ
diff --git a/gbl/libgbl/testdata/android/dtbo_b.img b/gbl/libgbl/testdata/android/dtbo_b.img
new file mode 100644
index 0000000..3b7aa23
Binary files /dev/null and b/gbl/libgbl/testdata/android/dtbo_b.img differ
diff --git a/gbl/libgbl/testdata/android/generic_ramdisk_a.img b/gbl/libgbl/testdata/android/generic_ramdisk_a.img
new file mode 100644
index 0000000..6d0184e
Binary files /dev/null and b/gbl/libgbl/testdata/android/generic_ramdisk_a.img differ
diff --git a/gbl/libgbl/testdata/android/generic_ramdisk_b.img b/gbl/libgbl/testdata/android/generic_ramdisk_b.img
new file mode 100644
index 0000000..b7395a1
Binary files /dev/null and b/gbl/libgbl/testdata/android/generic_ramdisk_b.img differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_gz.img b/gbl/libgbl/testdata/android/gki_boot_gz.img
new file mode 100644
index 0000000..931e52a
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_gz.img differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_gz_kernel b/gbl/libgbl/testdata/android/gki_boot_gz_kernel
new file mode 100644
index 0000000..a90ef4d
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_gz_kernel differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_gz_kernel_uncompressed b/gbl/libgbl/testdata/android/gki_boot_gz_kernel_uncompressed
new file mode 100644
index 0000000..81fd044
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_gz_kernel_uncompressed differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_lz4.img b/gbl/libgbl/testdata/android/gki_boot_lz4.img
new file mode 100644
index 0000000..f0418a1
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_lz4.img differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_lz4_kernel b/gbl/libgbl/testdata/android/gki_boot_lz4_kernel
new file mode 100644
index 0000000..ba8ef98
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_lz4_kernel differ
diff --git a/gbl/libgbl/testdata/android/gki_boot_lz4_kernel_uncompressed b/gbl/libgbl/testdata/android/gki_boot_lz4_kernel_uncompressed
new file mode 100644
index 0000000..81fd044
Binary files /dev/null and b/gbl/libgbl/testdata/android/gki_boot_lz4_kernel_uncompressed differ
diff --git a/gbl/libgbl/testdata/android/init_boot_a.img b/gbl/libgbl/testdata/android/init_boot_a.img
new file mode 100644
index 0000000..19b56f1
Binary files /dev/null and b/gbl/libgbl/testdata/android/init_boot_a.img differ
diff --git a/gbl/libgbl/testdata/android/init_boot_b.img b/gbl/libgbl/testdata/android/init_boot_b.img
new file mode 100644
index 0000000..a24f376
Binary files /dev/null and b/gbl/libgbl/testdata/android/init_boot_b.img differ
diff --git a/gbl/libgbl/testdata/android/kernel_a.img b/gbl/libgbl/testdata/android/kernel_a.img
new file mode 100644
index 0000000..b313840
Binary files /dev/null and b/gbl/libgbl/testdata/android/kernel_a.img differ
diff --git a/gbl/libgbl/testdata/android/kernel_b.img b/gbl/libgbl/testdata/android/kernel_b.img
new file mode 100644
index 0000000..b524dd0
Binary files /dev/null and b/gbl/libgbl/testdata/android/kernel_b.img differ
diff --git a/gbl/libgbl/testdata/android/overlay_a.dtb b/gbl/libgbl/testdata/android/overlay_a.dtb
new file mode 100644
index 0000000..4391b80
Binary files /dev/null and b/gbl/libgbl/testdata/android/overlay_a.dtb differ
diff --git a/gbl/libgbl/testdata/android/overlay_a.dts b/gbl/libgbl/testdata/android/overlay_a.dts
new file mode 100644
index 0000000..dc5b682
--- /dev/null
+++ b/gbl/libgbl/testdata/android/overlay_a.dts
@@ -0,0 +1,12 @@
+/dts-v1/;
+/plugin/;
+
+/ {
+    // add a new node at the root level
+    fragment@0 {
+        target-path = "/chosen";
+        __overlay__ {
+            overlay_a_property = "overlay_a_val";
+        };
+    };
+};
diff --git a/gbl/libgbl/testdata/android/overlay_b.dtb b/gbl/libgbl/testdata/android/overlay_b.dtb
new file mode 100644
index 0000000..c7b4fbb
Binary files /dev/null and b/gbl/libgbl/testdata/android/overlay_b.dtb differ
diff --git a/gbl/libgbl/testdata/android/overlay_b.dts b/gbl/libgbl/testdata/android/overlay_b.dts
new file mode 100644
index 0000000..49e9905
--- /dev/null
+++ b/gbl/libgbl/testdata/android/overlay_b.dts
@@ -0,0 +1,12 @@
+/dts-v1/;
+/plugin/;
+
+/ {
+    // add a new node at the root level
+    fragment@0 {
+        target-path = "/chosen";
+        __overlay__ {
+            overlay_b_property = "overlay_b_val";
+        };
+    };
+};
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_a.boot.digest.txt
new file mode 100644
index 0000000..4294d89
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_a.boot.digest.txt
@@ -0,0 +1 @@
+a3b8af36cf80e844e14bd9a3a5de4202afbbe4ebcabb9ba56f00abae53b864e5
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_a.digest.txt
new file mode 100644
index 0000000..b7da618
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_a.digest.txt
@@ -0,0 +1 @@
+8cebef168617a32d627f43ae30e7d8e20413b9899e88a92bd6d0d4d3e311bba004930a7956a78b6ace1ceaca624cb965efb68eb14b19998fd6f7e4267c9ccfb6
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_a.img b/gbl/libgbl/testdata/android/vbmeta_v0_a.img
new file mode 100644
index 0000000..c2baec8
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v0_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_b.boot.digest.txt
new file mode 100644
index 0000000..a40f282
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_b.boot.digest.txt
@@ -0,0 +1 @@
+0c69400ce9d8248185fbda667a71f5dc67d4066a01373a2ed78072a878e0a1de
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_b.digest.txt
new file mode 100644
index 0000000..48e63f9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_b.digest.txt
@@ -0,0 +1 @@
+3feb5ded4d560d850d7a13cd020ac4deb7d2825d49d2c1d57dda363d346a796ad68c023612759bf9cc126e0e966c554d2ce06f4207dcfa223b50ab2ec73ad199
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v0_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v0_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v0_b.img b/gbl/libgbl/testdata/android/vbmeta_v0_b.img
new file mode 100644
index 0000000..da2f398
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v0_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_a.boot.digest.txt
new file mode 100644
index 0000000..285fd31
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_a.boot.digest.txt
@@ -0,0 +1 @@
+dd946c73d66bc155284aa63b7ba93da3d4dcf1db9e1d21eae317941d967d41bc
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_a.digest.txt
new file mode 100644
index 0000000..26d0d83
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_a.digest.txt
@@ -0,0 +1 @@
+30320c1499e033b61f59f9532bf827378e4f2a6bec7adde69a2b776d6a410b0deb53c0a04e7688920e53f62c1a27eddb6850898cd03fc88205841b7f1d3b0781
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_a.img b/gbl/libgbl/testdata/android/vbmeta_v1_a.img
new file mode 100644
index 0000000..bd9f7db
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v1_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_b.boot.digest.txt
new file mode 100644
index 0000000..8a35ceb
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_b.boot.digest.txt
@@ -0,0 +1 @@
+465b18c4c5d4ecebc263dccaaede64e9dca77a3fd041209f3ff1ee0db2bc932a
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_b.digest.txt
new file mode 100644
index 0000000..0f8110f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_b.digest.txt
@@ -0,0 +1 @@
+dff89db9ae5068974109d8704c67e89804ccdbb975e8a796273045df317cb27dddae38a26fd6233ff19609729c9fb0650b39ce00aad0e17995a9feb0cfc94a69
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v1_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v1_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v1_b.img b/gbl/libgbl/testdata/android/vbmeta_v1_b.img
new file mode 100644
index 0000000..e810499
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v1_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_a.boot.digest.txt
new file mode 100644
index 0000000..837b3e8
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_a.boot.digest.txt
@@ -0,0 +1 @@
+ffd15bfde9fbb434d17ecba7112887a4fffa766be5018d267bfcca8fd784d6ec
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_a.digest.txt
new file mode 100644
index 0000000..7b55cff
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_a.digest.txt
@@ -0,0 +1 @@
+70d478f639a2cc50f200a82a004f2016d9331d6973b571384c8ae25d20e6d3bb1c6a2aa128f8dcaaf1de691cc90c76de5e6d956be173d3dd08d0a05418120a17
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_a.img b/gbl/libgbl/testdata/android/vbmeta_v2_a.img
new file mode 100644
index 0000000..06ebf69
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v2_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_b.boot.digest.txt
new file mode 100644
index 0000000..2212ed7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_b.boot.digest.txt
@@ -0,0 +1 @@
+fe903a60e9a6262c86ceadf55ed65eb0d3de7b1f3ada95633f3e3de04648c3b7
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_b.digest.txt
new file mode 100644
index 0000000..ff6e3cc
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_b.digest.txt
@@ -0,0 +1 @@
+eeda048001594baf5e8bc8767ad5fe2f16664f82868cbbae4e7c7de53b4b9eab3d1d3b3d7edd39d17955f6bb08a13e4d43d0e4086f7a0dd8b33975c550b33786
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v2_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v2_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v2_b.img b/gbl/libgbl/testdata/android/vbmeta_v2_b.img
new file mode 100644
index 0000000..26b489a
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v2_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.boot.digest.txt
new file mode 100644
index 0000000..2bf0f10
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.boot.digest.txt
@@ -0,0 +1 @@
+bea1c8a317ec59fd640755109f99aaf91b25d3e652f752145ac3431ed379ce82
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.digest.txt
new file mode 100644
index 0000000..fbad95e
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.digest.txt
@@ -0,0 +1 @@
+e47f6dcba0f95be52e75a2543aeb4be6dfc02182525a21f921e9c381f1762fb418292d3ec1cec9f2f7815e1d986d89b1009fb22627d75a62120e6e94b9f0cbe5
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.img b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.img
new file mode 100644
index 0000000..bf9a873
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..fbc54f5
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+c81fde8b7626fbe39e1529e7bc5588aa490cf631ab5a342f6a25de0b6a8ea968
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.boot.digest.txt
new file mode 100644
index 0000000..262fd66
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.boot.digest.txt
@@ -0,0 +1 @@
+dd27279d7059e549e106b2ea18b88d95d0455bebf8c3079db5a7fded720b42af
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.digest.txt
new file mode 100644
index 0000000..b018df6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.digest.txt
@@ -0,0 +1 @@
+91ed48de6a9cb9e788ef739b55f77a4c423445b08015b1e62a8f9c91d522c40a03c4483065319ecaa19fd562bc3d642642adad09ddc68d926b50be9a05658b18
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.img b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.img
new file mode 100644
index 0000000..74931e3
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..7408640
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+907248ca1c2b3ed11fa1147af8a34a71ec4e83f6254af17c6d031f804153ed9a
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.boot.digest.txt
new file mode 100644
index 0000000..0c01406
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.boot.digest.txt
@@ -0,0 +1 @@
+e95c88cb742b7a4e456b6618564793d5980d9f4a94a995c09922269620773818
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.digest.txt
new file mode 100644
index 0000000..beb0e30
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.digest.txt
@@ -0,0 +1 @@
+a74bd2b97f77e60029bbf72bd432dadab3bb355678200c610ebece4101bfda3f3d0190af0b05ceb2614beac96a6c1b386b65d6402b0b85fec37e47b88d89fa7f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.img b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.img
new file mode 100644
index 0000000..b9deb72
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.init_boot.digest.txt
new file mode 100644
index 0000000..ed24f4a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.init_boot.digest.txt
@@ -0,0 +1 @@
+0d843d8d54a0c551dad06319548365817bbb199fbc8c8a7b10cc07a53499e590
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..fbc54f5
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+c81fde8b7626fbe39e1529e7bc5588aa490cf631ab5a342f6a25de0b6a8ea968
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.boot.digest.txt
new file mode 100644
index 0000000..d6c7373
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.boot.digest.txt
@@ -0,0 +1 @@
+420b5c1ca6f85ae1b532e22c2dc57356add25e4b30c06df144e40667c0134f89
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.digest.txt
new file mode 100644
index 0000000..7966a5f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.digest.txt
@@ -0,0 +1 @@
+0ed054b373033693f98dfd0a5ab64f3b21ba2625fa94148ec8cac265a2e5b8be28e940dba77abfe7afd516b7f385b6c5543d0bdb3710d6d394979ec8f499395d
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.img b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.img
new file mode 100644
index 0000000..69f18f9
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.init_boot.digest.txt
new file mode 100644
index 0000000..eb408b9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.init_boot.digest.txt
@@ -0,0 +1 @@
+010ad1c6aa987435bef2b5b65f8018c1ce5c10cc4681789ca928486852f03813
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..7408640
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v3_init_boot_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+907248ca1c2b3ed11fa1147af8a34a71ec4e83f6254af17c6d031f804153ed9a
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.boot.digest.txt
new file mode 100644
index 0000000..2bf0f10
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.boot.digest.txt
@@ -0,0 +1 @@
+bea1c8a317ec59fd640755109f99aaf91b25d3e652f752145ac3431ed379ce82
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.digest.txt
new file mode 100644
index 0000000..db120fc
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.digest.txt
@@ -0,0 +1 @@
+5bd5cc04647fbe176dd12c68425bb7b8b417e7bdd9bb22d4cf31264e086d97ac8752220ada16c1c4159ecd3ff2bd6109051e3751ba152216a787247d40063eed
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.img b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.img
new file mode 100644
index 0000000..c6d4579
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.boot.digest.txt
new file mode 100644
index 0000000..262fd66
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.boot.digest.txt
@@ -0,0 +1 @@
+dd27279d7059e549e106b2ea18b88d95d0455bebf8c3079db5a7fded720b42af
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.digest.txt
new file mode 100644
index 0000000..2fc6324
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.digest.txt
@@ -0,0 +1 @@
+ac49facebda99d6f07c37ee61d7324024a5b1b090e5781a06dbd45c2ee144e61d1434be056ff2f54e19a422cc717b84ebf4ebf2d80b416ef6ec4441c78df6508
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.img b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.img
new file mode 100644
index 0000000..6e53b17
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..58243fd
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+6b1ef1b1791351c7072cc16a6e9be876d88f4ad7744383f205e1be299202ecd8
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.boot.digest.txt
new file mode 100644
index 0000000..0c01406
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.boot.digest.txt
@@ -0,0 +1 @@
+e95c88cb742b7a4e456b6618564793d5980d9f4a94a995c09922269620773818
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.digest.txt
new file mode 100644
index 0000000..453655f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.digest.txt
@@ -0,0 +1 @@
+16fcf1b827e38ac448a0bf5bfc6b7a08d78b52038c0710e1835f86df7ce8bbdcd97a1f12a2ef2d9da4c8c0bdf428b83b1ca0a869bf1146d7dc38f16e51ac5e37
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.img b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.img
new file mode 100644
index 0000000..918af13
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.init_boot.digest.txt
new file mode 100644
index 0000000..ed24f4a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.init_boot.digest.txt
@@ -0,0 +1 @@
+0d843d8d54a0c551dad06319548365817bbb199fbc8c8a7b10cc07a53499e590
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.boot.digest.txt
new file mode 100644
index 0000000..d6c7373
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.boot.digest.txt
@@ -0,0 +1 @@
+420b5c1ca6f85ae1b532e22c2dc57356add25e4b30c06df144e40667c0134f89
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.digest.txt
new file mode 100644
index 0000000..4080c69
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.digest.txt
@@ -0,0 +1 @@
+ac736aca587cda643af8a182532d92b5ab6fb7f1948264188902092a5b76536a50599deb16364528350df40a251ff3286eef4edb0c2630fff5bbb5eec2fc6a58
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.img b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.img
new file mode 100644
index 0000000..0015e33
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.init_boot.digest.txt
new file mode 100644
index 0000000..eb408b9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.init_boot.digest.txt
@@ -0,0 +1 @@
+010ad1c6aa987435bef2b5b65f8018c1ce5c10cc4681789ca928486852f03813
diff --git a/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..58243fd
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v3_v4_init_boot_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+6b1ef1b1791351c7072cc16a6e9be876d88f4ad7744383f205e1be299202ecd8
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.boot.digest.txt
new file mode 100644
index 0000000..8cc8826
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.boot.digest.txt
@@ -0,0 +1 @@
+fe6845837f27613699770d58a19b2405c4b23c203fe1edb0133b30e3d496945c
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.digest.txt
new file mode 100644
index 0000000..c09919d
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.digest.txt
@@ -0,0 +1 @@
+450823eddf5bf1600790b612b24b32552d9454a1420188cdf7a279844431a3a2a82ecc367125d265c724066427993ffe2adc303782fb93850fef1cc10866b215
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.img
new file mode 100644
index 0000000..12f0ac8
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..8c33e8a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f9cad72ad63c87e97ca0ef89e00d5297b4731145a7916cf34cdcd6c03d68a0ca
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.boot.digest.txt
new file mode 100644
index 0000000..c7fb6e2
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.boot.digest.txt
@@ -0,0 +1 @@
+54c83f6d25648f1628b9049978f05eaac878523e2ad9da50e80e4591f709e8db
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.digest.txt
new file mode 100644
index 0000000..0ee67db
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.digest.txt
@@ -0,0 +1 @@
+7062df4c2e595c354a31e07ae33a627a0fdaae0bfd80b35ba569df0978165f7b4761184226f62efc479cff8fe85d032e2f5f9e7bced536dd5761ef054a0d8548
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.img b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.img
new file mode 100644
index 0000000..79c8c21
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..a2af6a3
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_dttable_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+1686ca796de1300d09238cbe1828d59405224b7e5dc913a653071734af6f01da
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.boot.digest.txt
new file mode 100644
index 0000000..17773dc
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.boot.digest.txt
@@ -0,0 +1 @@
+0dd6574d0a2190d7fdf0c46875b600eb4eb276f77b334bb691a17d9495296b94
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.digest.txt
new file mode 100644
index 0000000..bc8797e
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.digest.txt
@@ -0,0 +1 @@
+9a53c58824b82faef92dc4ae09caea4ffd1532d7daff2a4def512852baed7598df572541d935d84b2f0f7a7372b7395b52291641dea122e43fa5d84325f594b1
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.img
new file mode 100644
index 0000000..72ee8a7
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_gz_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.boot.digest.txt
new file mode 100644
index 0000000..1d0776b
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.boot.digest.txt
@@ -0,0 +1 @@
+7690d4dc0fa8bd49ae4ae26c346918117e7c86bc22ec9c99f922d6c192960e38
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.digest.txt
new file mode 100644
index 0000000..731caf0
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.digest.txt
@@ -0,0 +1 @@
+5516b383bbdba4776e03e4e2029f487e24bc9d6b265210365c1f67ac8794eacf6f24fbacfa2019b386e99e5168839e0a380585c2417e0476042617a8dca61a37
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.img
new file mode 100644
index 0000000..abdb92d
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_lz4_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.boot.digest.txt
new file mode 100644
index 0000000..8cc8826
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.boot.digest.txt
@@ -0,0 +1 @@
+fe6845837f27613699770d58a19b2405c4b23c203fe1edb0133b30e3d496945c
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.digest.txt
new file mode 100644
index 0000000..d3024e9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.digest.txt
@@ -0,0 +1 @@
+607d6b48a65b885ab7cd65045cefabc5f10920d9fe73e346765a586edb5acbb7cafcab2de30c1e4ede8f38d26456053212994a22ae1d1d786fd6c3acc55b083c
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.img
new file mode 100644
index 0000000..0ea7922
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..fbc54f5
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+c81fde8b7626fbe39e1529e7bc5588aa490cf631ab5a342f6a25de0b6a8ea968
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.boot.digest.txt
new file mode 100644
index 0000000..c7fb6e2
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.boot.digest.txt
@@ -0,0 +1 @@
+54c83f6d25648f1628b9049978f05eaac878523e2ad9da50e80e4591f709e8db
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.digest.txt
new file mode 100644
index 0000000..9b3c900
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.digest.txt
@@ -0,0 +1 @@
+7b0edd3640b9d0e0765dcb2eaf3aaa4464777cc017c4a28433fa2cb62860c441f601331bbb700102b7b1519714ef16b4f392f38a00913b282914ca3d41433e18
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.img b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.img
new file mode 100644
index 0000000..961015e
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..7408640
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+907248ca1c2b3ed11fa1147af8a34a71ec4e83f6254af17c6d031f804153ed9a
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.boot.digest.txt
new file mode 100644
index 0000000..86ddee3
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.boot.digest.txt
@@ -0,0 +1 @@
+ae41c9cf4f0ab6e7a6333d8e5c1283cfbbead4bcb9bad7013bbc5cd2cf313918
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.digest.txt
new file mode 100644
index 0000000..d3d3ec1
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.digest.txt
@@ -0,0 +1 @@
+c80674d0b5f695402a12bf0f0894277377dd75af29e928b90f151d4b6476e641993e354db80ee90597895537cd07bdacb193a3acdf0dcb72bad7e249a01063f9
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.img
new file mode 100644
index 0000000..ac30442
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.init_boot.digest.txt
new file mode 100644
index 0000000..ed24f4a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.init_boot.digest.txt
@@ -0,0 +1 @@
+0d843d8d54a0c551dad06319548365817bbb199fbc8c8a7b10cc07a53499e590
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..fbc54f5
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+c81fde8b7626fbe39e1529e7bc5588aa490cf631ab5a342f6a25de0b6a8ea968
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.boot.digest.txt
new file mode 100644
index 0000000..4132b5b
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.boot.digest.txt
@@ -0,0 +1 @@
+d339c452efb6a987dc227ce59f08346fe6b2e5b27bea15bb061e7f044327f238
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.digest.txt
new file mode 100644
index 0000000..c3375a8
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.digest.txt
@@ -0,0 +1 @@
+a2e4333bec295750074b5f3c9db38cd04ec0546be2be9dd2e02e375e67676aff5a3b5d0a1723e87e077ee483b38b662d46d9883a32b7b9799009272c149c7c72
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.img b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.img
new file mode 100644
index 0000000..4f2e9aa
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.init_boot.digest.txt
new file mode 100644
index 0000000..eb408b9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.init_boot.digest.txt
@@ -0,0 +1 @@
+010ad1c6aa987435bef2b5b65f8018c1ce5c10cc4681789ca928486852f03813
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..7408640
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v3_init_boot_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+907248ca1c2b3ed11fa1147af8a34a71ec4e83f6254af17c6d031f804153ed9a
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.boot.digest.txt
new file mode 100644
index 0000000..8cc8826
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.boot.digest.txt
@@ -0,0 +1 @@
+fe6845837f27613699770d58a19b2405c4b23c203fe1edb0133b30e3d496945c
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.digest.txt
new file mode 100644
index 0000000..cf49fee
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.digest.txt
@@ -0,0 +1 @@
+4fa8c1c121566f80b8477510a6b14a568bb32e0bb8f9e62fddbd70b8e18fb2341f2aa9c0f1fd596afead41212f47d47a343640c5f32e2a6a72023cbad9287c6f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.img
new file mode 100644
index 0000000..639786e
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.boot.digest.txt
new file mode 100644
index 0000000..c7fb6e2
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.boot.digest.txt
@@ -0,0 +1 @@
+54c83f6d25648f1628b9049978f05eaac878523e2ad9da50e80e4591f709e8db
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.digest.txt
new file mode 100644
index 0000000..5404d8a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.digest.txt
@@ -0,0 +1 @@
+b8c8c2a543646d17142b7f30ec4a274033e18e578a6baa4b58a3799ba0e4ced193272029482695e231c56b6fcc52d2619a8a83c5f02b04d0c87ecb92d4f5f326
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.img b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.img
new file mode 100644
index 0000000..831e48a
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..58243fd
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+6b1ef1b1791351c7072cc16a6e9be876d88f4ad7744383f205e1be299202ecd8
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.boot.digest.txt
new file mode 100644
index 0000000..86ddee3
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.boot.digest.txt
@@ -0,0 +1 @@
+ae41c9cf4f0ab6e7a6333d8e5c1283cfbbead4bcb9bad7013bbc5cd2cf313918
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.digest.txt
new file mode 100644
index 0000000..796ea72
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.digest.txt
@@ -0,0 +1 @@
+55bb0c5ed400434d63b0a824ef31769008762ebb9186ef5e25e4351f360f808cb034fc7323f04469ed1e3a84aa983a942c8d405e6f52fd882198995a2899d4d5
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtb.digest.txt
new file mode 100644
index 0000000..8460aa7
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtb.digest.txt
@@ -0,0 +1 @@
+74024f7c9577215434dba9b695c3501eb626f66b97c810ff5307912c7fac7938
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtbo.digest.txt
new file mode 100644
index 0000000..0013aed
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.dtbo.digest.txt
@@ -0,0 +1 @@
+18964fe84fd9214ae7d61c7f0d7d951412b6ce7f1c3e49a8f896a40da2ddde3f
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.img b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.img
new file mode 100644
index 0000000..f91bc51
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.init_boot.digest.txt
new file mode 100644
index 0000000..ed24f4a
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.init_boot.digest.txt
@@ -0,0 +1 @@
+0d843d8d54a0c551dad06319548365817bbb199fbc8c8a7b10cc07a53499e590
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt
new file mode 100644
index 0000000..0bb1af6
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_a.vendor_boot.digest.txt
@@ -0,0 +1 @@
+f368327144138f5736abb01dd976c8b7bf7af987aaf626de7612461e81cab955
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.boot.digest.txt
new file mode 100644
index 0000000..4132b5b
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.boot.digest.txt
@@ -0,0 +1 @@
+d339c452efb6a987dc227ce59f08346fe6b2e5b27bea15bb061e7f044327f238
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.digest.txt
new file mode 100644
index 0000000..fff2f60
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.digest.txt
@@ -0,0 +1 @@
+431f6394786c3883e9f93a2ca2a77ee9e976da7de69d781b91eae61742e8324cc019672b888150e648a36966f8eead415cd533555c92f3362ae3da09f586c301
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtb.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtb.digest.txt
new file mode 100644
index 0000000..22afb3f
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtb.digest.txt
@@ -0,0 +1 @@
+6227f3fbf15d3049f03c9829016372e1387cd07eb1b23bc8ae640545c0b3a398
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtbo.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtbo.digest.txt
new file mode 100644
index 0000000..74ca578
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.dtbo.digest.txt
@@ -0,0 +1 @@
+8e3d69eba96fb6723bb4f29a1fa4dd3737bc352d1b3c05a7946778e685307fe4
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.img b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.img
new file mode 100644
index 0000000..ef2bed2
Binary files /dev/null and b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.img differ
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.init_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.init_boot.digest.txt
new file mode 100644
index 0000000..eb408b9
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.init_boot.digest.txt
@@ -0,0 +1 @@
+010ad1c6aa987435bef2b5b65f8018c1ce5c10cc4681789ca928486852f03813
diff --git a/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.vendor_boot.digest.txt b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.vendor_boot.digest.txt
new file mode 100644
index 0000000..58243fd
--- /dev/null
+++ b/gbl/libgbl/testdata/android/vbmeta_v4_v4_init_boot_b.vendor_boot.digest.txt
@@ -0,0 +1 @@
+6b1ef1b1791351c7072cc16a6e9be876d88f4ad7744383f205e1be299202ecd8
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v3_a.img b/gbl/libgbl/testdata/android/vendor_boot_v3_a.img
new file mode 100644
index 0000000..e55f783
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v3_a.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v3_b.img b/gbl/libgbl/testdata/android/vendor_boot_v3_b.img
new file mode 100644
index 0000000..b6bb56b
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v3_b.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v4_a.img b/gbl/libgbl/testdata/android/vendor_boot_v4_a.img
new file mode 100644
index 0000000..ded56ce
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v4_a.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v4_b.img b/gbl/libgbl/testdata/android/vendor_boot_v4_b.img
new file mode 100644
index 0000000..3186ba7
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v4_b.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_a.img b/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_a.img
new file mode 100644
index 0000000..2ea1bfa
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_a.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_b.img b/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_b.img
new file mode 100644
index 0000000..941024f
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_boot_v4_dttable_b.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_ramdisk_a.img b/gbl/libgbl/testdata/android/vendor_ramdisk_a.img
new file mode 100644
index 0000000..de40d03
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_ramdisk_a.img differ
diff --git a/gbl/libgbl/testdata/android/vendor_ramdisk_b.img b/gbl/libgbl/testdata/android/vendor_ramdisk_b.img
new file mode 100644
index 0000000..f9e36df
Binary files /dev/null and b/gbl/libgbl/testdata/android/vendor_ramdisk_b.img differ
diff --git a/gbl/libgbl/testdata/gen_test_data.py b/gbl/libgbl/testdata/gen_test_data.py
index ea0589c..1c37d29 100755
--- a/gbl/libgbl/testdata/gen_test_data.py
+++ b/gbl/libgbl/testdata/gen_test_data.py
@@ -16,26 +16,55 @@
 """Generate test data files for libgbl tests"""
 
 import argparse
+import gzip
 import os
 import pathlib
 import random
+import re
 import shutil
 import subprocess
 import tempfile
-from typing import List
 
 SCRIPT_DIR = pathlib.Path(os.path.dirname(os.path.realpath(__file__)))
-GPT_TOOL = pathlib.Path(SCRIPT_DIR.parents[1]) / "tools" / "gen_gpt_disk.py"
-AVB_DIR = pathlib.Path(SCRIPT_DIR.parents[4]) / "external" / "avb"
+AOSP_ROOT = SCRIPT_DIR.parents[4]
+GBL_ROOT = SCRIPT_DIR.parents[1]
+ANDROID_OUT = SCRIPT_DIR / "android"
+GPT_TOOL = GBL_ROOT / "tools" / "gen_gpt_disk.py"
+AVB_DIR = AOSP_ROOT / "external" / "avb"
 AVB_TOOL = AVB_DIR / "avbtool.py"
+MKBOOTIMG_TOOL = AOSP_ROOT / "tools" / "mkbootimg" / "mkbootimg.py"
+UNPACKBOOTIMG_TOOL = AOSP_ROOT / "tools" / "mkbootimg" / "unpack_bootimg.py"
 AVB_TEST_DATA_DIR = AVB_DIR / "test" / "data"
+DTC_TOOL = (
+    AOSP_ROOT / "prebuilts" / "kernel-build-tools" / "linux-x86" / "bin" / "dtc"
+)
+MKDTBOIMG_TOOL = (
+    AOSP_ROOT
+    / "prebuilts"
+    / "kernel-build-tools"
+    / "linux-x86"
+    / "bin"
+    / "mkdtboimg"
+)
+LZ4_TOOL = "lz4"
 SZ_KB = 1024
 
+# Manually downloaded from Android CI:
+# https://android-build.corp.google.com/build_explorer/branch/aosp_kernel-common-android-mainline
+GKI_BOOT_GZ = ANDROID_OUT / "gki_boot_gz.img"
+GKI_BOOT_LZ4 = ANDROID_OUT / "gki_boot_lz4.img"
+
 # RNG seed values. Keep the same seed value for a given file to ensure
 # reproducibility as much as possible; this will prevent adding a bunch of
 # unnecessary test binaries to the git history.
 RNG_SEED_SPARSE_TEST_RAW = 1
 RNG_SEED_ZIRCON = {"a": 2, "b": 3, "r": 4, "slotless": 5}
+RNG_SEED_ANDROID = {"a": 6, "b": 7}
+
+# AVB related constants.
+PSK = AVB_TEST_DATA_DIR / "testkey_cert_psk.pem"
+TEST_ROLLBACK_INDEX_LOCATION = 1
+TEST_ROLLBACK_INDEX = 2
 
 
 # A helper for writing bytes to a file at a given offset.
@@ -44,6 +73,58 @@ def write_file(file, offset, data):
     file.write(data)
 
 
+# Unpack kernel from boot image
+def unpack_boot(boot, into):
+    subprocess.run(
+        [
+            UNPACKBOOTIMG_TOOL,
+            "--boot_img", boot,
+            "--out", into,
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+
+def uncompress_lz4(archive, into):
+    subprocess.run(
+        [
+            LZ4_TOOL,
+            "-f",  # always override
+            "-d", archive,
+            into,
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+
+def uncompress_gz(archive, into):
+    with gzip.open(archive, "rb") as input, open(into, "wb") as output:
+        shutil.copyfileobj(input, output)
+
+
+# Unpack and uncompress GKI boot images
+def unpack_gkis():
+    with tempfile.TemporaryDirectory() as temp_dir:
+        temp_dir = pathlib.Path(temp_dir)
+
+        if shutil.which(LZ4_TOOL) is not None:
+            unpack_boot(GKI_BOOT_LZ4, temp_dir)
+            shutil.copyfile(temp_dir / "kernel",
+                            ANDROID_OUT / "gki_boot_lz4_kernel")
+            uncompress_lz4(ANDROID_OUT / "gki_boot_lz4_kernel",
+                           ANDROID_OUT / "gki_boot_lz4_kernel_uncompressed")
+        else:
+            print("Warning: lz4 tool isn't presented, skipping unpack lz4 gki boot")
+
+        unpack_boot(GKI_BOOT_GZ, temp_dir)
+        shutil.copyfile(temp_dir / "kernel",
+                        ANDROID_OUT / "gki_boot_gz_kernel")
+        uncompress_gz(ANDROID_OUT / "gki_boot_gz_kernel",
+                      ANDROID_OUT / "gki_boot_gz_kernel_uncompressed")
+
+
 # Generates sparse image for flashing test
 def gen_sparse_test_file():
     out_file_raw = SCRIPT_DIR / "sparse_test_raw.bin"
@@ -80,22 +161,430 @@ def gen_sparse_test_file():
     )
 
 
+def gen_dtb(input_dts, output_dtb):
+    subprocess.run(
+        [DTC_TOOL, "-I", "dts", "-O", "dtb", "-o", output_dtb, input_dts],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+
+def gen_android_test_dtb():
+    out_dir = ANDROID_OUT
+    # Generates base test device tree.
+    gen_dtb(out_dir / "device_tree.dts", out_dir / "device_tree.dtb")
+    gen_dtb(
+        out_dir / "device_tree_custom.dts", out_dir / "device_tree_custom.dtb"
+    )
+    # Generates dtb to be used inside boot/vendor_boot
+    subprocess.run(
+        [
+            MKDTBOIMG_TOOL,
+            "create",
+            out_dir / "dtb.img",
+            "--id=0x1",
+            "--rev=0x0",
+            out_dir / "device_tree.dtb",
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+    # Generates dtb_a/dtb_b
+    gen_dtb(out_dir / "device_tree_a.dts", out_dir / "device_tree_a.dtb")
+    gen_dtb(out_dir / "device_tree_b.dts", out_dir / "device_tree_b.dtb")
+    subprocess.run(
+        [
+            MKDTBOIMG_TOOL,
+            "create",
+            out_dir / "dtb_a.img",
+            "--id=0x1",
+            "--rev=0x0",
+            out_dir / "device_tree_a.dtb",
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+    subprocess.run(
+        [
+            MKDTBOIMG_TOOL,
+            "create",
+            out_dir / "dtb_b.img",
+            "--id=0x1",
+            "--rev=0x0",
+            out_dir / "device_tree_b.dtb",
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+    # Generates overlay
+    gen_dtb(out_dir / "overlay_a.dts", out_dir / "overlay_a.dtb")
+    gen_dtb(out_dir / "overlay_b.dts", out_dir / "overlay_b.dtb")
+
+    subprocess.run(
+        [
+            MKDTBOIMG_TOOL,
+            "create",
+            out_dir / "dtbo_a.img",
+            "--id=0x1",
+            "--rev=0x0",
+            out_dir / "overlay_a.dtb",
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+    subprocess.run(
+        [
+            MKDTBOIMG_TOOL,
+            "create",
+            out_dir / "dtbo_b.img",
+            "--id=0x1",
+            "--rev=0x0",
+            out_dir / "overlay_b.dtb",
+        ],
+        stderr=subprocess.STDOUT,
+        check=True,
+    )
+
+
+# Generate vbmeta data for a set of images.
+def gen_android_test_vbmeta(partition_file_pairs, out_vbmeta):
+    with tempfile.TemporaryDirectory() as temp_dir:
+        desc_args = []
+        temp_dir = pathlib.Path(temp_dir)
+        for i, (part, image_file) in enumerate(partition_file_pairs):
+            out = temp_dir / f"{i}.vbmeta_desc"
+            desc_args += ["--include_descriptors_from_image", out]
+            subprocess.run(
+                [
+                    AVB_TOOL,
+                    "add_hash_footer",
+                    "--image",
+                    image_file,
+                    "--partition_name",
+                    part,
+                    "--do_not_append_vbmeta_image",
+                    "--output_vbmeta_image",
+                    out,
+                    "--salt",
+                    "9f06406a750581266f21865d115e63b54db441bc0d614195c78c14451b5ecb8abb14d8cd88d816c4750545ef89cb348a3834815aac4fa359e8b02a740483d975",
+                    "--partition_size",
+                    "209715200",  # Randomly chosen large enough value.
+                ],
+                stderr=subprocess.STDOUT,
+                check=True,
+            )
+
+        subprocess.run(
+            [
+                AVB_TOOL,
+                "make_vbmeta_image",
+                "--output",
+                out_vbmeta,
+                "--key",
+                PSK,
+                "--algorithm",
+                "SHA512_RSA4096",
+                "--rollback_index",
+                f"{TEST_ROLLBACK_INDEX}",
+                "--rollback_index_location",
+                f"{TEST_ROLLBACK_INDEX_LOCATION}",
+            ]
+            + desc_args,
+            stderr=subprocess.STDOUT,
+            check=True,
+        )
+
+        # Generates vbmeta digest file
+        out_digest = out_vbmeta.with_suffix(".digest.txt")
+        digest = subprocess.run(
+            [
+                AVB_TOOL,
+                "calculate_vbmeta_digest",
+                "--image",
+                out_vbmeta,
+                "--hash_algorithm",
+                "sha512",
+            ],
+
+
+            check=True,
+            text=True,
+            capture_output=True,
+        )
+        out_digest.write_text(digest.stdout)
+
+        extract_vbmeta_digests(out_vbmeta)
+
+
+# Extract digests from vbmeta data
+def extract_vbmeta_digests(vbmeta):
+    # Get vbmeta digests
+    digests = (
+        re.split(
+            "\n|: ",
+            subprocess.run(
+                [
+                    AVB_TOOL,
+                    "print_partition_digests",
+                    "--image",
+                    vbmeta,
+                ],
+
+
+                check=True,
+                text=True,
+                capture_output=True,
+            )
+            .stdout
+        )
+    )
+    digests = {digests[i]: digests[i+1] for i in range(0, len(digests), 2) if digests[i] in [
+        "boot", "vendor_boot", "init_boot", "dtbo", "dtb"]}
+
+    for key, value in digests.items():
+        out_digest = vbmeta.with_suffix(".{}.digest.txt".format(key))
+        out_digest.write_text(value + "\n")
+
+
+def gen_android_test_images():
+    unpack_gkis()
+    gen_android_test_dtb()
+
+    with tempfile.TemporaryDirectory() as temp_dir:
+        temp_dir = pathlib.Path(temp_dir)
+        out_dir = ANDROID_OUT
+        out_dir.mkdir(parents=True, exist_ok=True)
+        for slot in ["a", "b"]:
+            random.seed(RNG_SEED_ANDROID[slot])
+            kernel = out_dir / f"kernel_{slot}.img"
+            kernel.write_bytes(random.randbytes(4 * SZ_KB))
+
+            generic_ramdisk = out_dir / f"generic_ramdisk_{slot}.img"
+            generic_ramdisk.write_bytes(random.randbytes(8 * SZ_KB))
+
+            vendor_ramdisk = out_dir / f"vendor_ramdisk_{slot}.img"
+            vendor_ramdisk.write_bytes(random.randbytes(12 * SZ_KB))
+
+            vendor_bootconfig = temp_dir / f"vendor_bootconfig_{slot}.img"
+            vendor_bootconfig.write_bytes(
+                b"""\
+androidboot.config_1=val_1
+androidboot.config_2=val_2
+"""
+            )
+
+            boot_cmdline = "cmd_key_1=cmd_val_1,cmd_key_2=cmd_val_2"
+            vendor_cmdline = "cmd_vendor_key_1=cmd_vendor_val_1,cmd_vendor_key_2=cmd_vendor_val_2"
+
+            # Generate v3, v4 boot image without ramdisk (usecase for init_boot)
+            common = [
+                MKBOOTIMG_TOOL,
+                "--kernel",
+                kernel,
+                "--cmdline",
+                boot_cmdline,
+                "--dtb",
+                out_dir / "device_tree.dtb",
+            ]
+            for i in [3, 4]:
+                out = out_dir / f"boot_no_ramdisk_v{i}_{slot}.img"
+                subprocess.run(
+                    common + ["--header_version", f"{i}", "-o", out],
+                    check=True,
+                    stderr=subprocess.STDOUT,
+                )
+
+            # Generates v0 - v4 boot image that contains generic ramdisk.
+            common += [
+                "--ramdisk",
+                generic_ramdisk,
+            ]
+            for i in range(0, 5):
+                out = out_dir / f"boot_v{i}_{slot}.img"
+                subprocess.run(
+                    common + ["--header_version", f"{i}", "-o", out],
+                    check=True,
+                    stderr=subprocess.STDOUT,
+                )
+
+            # Generate v4 boot images for gzip and lz4 kernel compression.
+            if slot == "a":
+                for compression in ['gz', 'lz4']:
+                    out = out_dir / f"boot_v4_{compression}_{slot}.img"
+                    # Replace kernel
+                    common[2] = out_dir / f"gki_boot_{compression}_kernel"
+
+                    subprocess.run(
+                        common + ["--header_version", "4", "-o", out],
+                        check=True,
+                        stderr=subprocess.STDOUT,
+                    )
+
+            # Generates init_boot
+            subprocess.run(
+                [
+                    MKBOOTIMG_TOOL,
+                    "-o",
+                    out_dir / f"init_boot_{slot}.img",
+                    "--ramdisk",
+                    generic_ramdisk,
+                    # init_boot uses fixed version 4.
+                    "--header_version",
+                    "4",
+                ],
+                check=True,
+                stderr=subprocess.STDOUT,
+            )
+
+            # Generates vendor_boot images
+            common = [
+                MKBOOTIMG_TOOL,
+                "--vendor_cmdline",
+                vendor_cmdline,
+                "--vendor_ramdisk",
+                vendor_ramdisk,
+                "--dtb",
+                out_dir / "device_tree.dtb",
+            ]
+            # Generates vendor_boot v3 (no bootconfig)
+            subprocess.run(
+                common
+                + [
+                    "--dtb",
+                    out_dir / "device_tree.dtb",
+                    "--vendor_boot",
+                    out_dir / f"vendor_boot_v3_{slot}.img",
+                    "--header_version",
+                    "3",
+                ],
+                stderr=subprocess.STDOUT,
+                check=True,
+            )
+            # Generates vendor_boot v4
+            subprocess.run(
+                common
+                + [
+                    "--dtb",
+                    out_dir / "device_tree.dtb",
+                    "--vendor_boot",
+                    out_dir / f"vendor_boot_v4_{slot}.img",
+                    "--vendor_bootconfig",
+                    vendor_bootconfig,
+                    "--header_version",
+                    "4",
+                ],
+                stderr=subprocess.STDOUT,
+                check=True,
+            )
+            # Generates vendor_boot v4 with dttable structure
+            subprocess.run(
+                common
+                + [
+                    "--dtb",
+                    out_dir / "dtb.img",
+                    "--vendor_boot",
+                    out_dir / f"vendor_boot_v4_dttable_{slot}.img",
+                    "--vendor_bootconfig",
+                    vendor_bootconfig,
+                    "--header_version",
+                    "4",
+                ],
+                stderr=subprocess.STDOUT,
+                check=True,
+            )
+
+            # Generates a vbmeta data for v0 - v2 setup
+            for i in [0, 1, 2]:
+                parts = [
+                    (f"boot", out_dir / f"boot_v{i}_{slot}.img"),
+                    ("dtbo", out_dir / f"dtbo_{slot}.img"),
+                    ("dtb", out_dir / f"dtb_{slot}.img"),
+                ]
+                gen_android_test_vbmeta(
+                    parts, out_dir / f"vbmeta_v{i}_{slot}.img"
+                )
+
+            # Generates different combinations of v3/v4 boot/vendor_boot/init_boot setup.
+            for use_init_boot in [True, False]:
+                for boot_ver in [3, 4]:
+                    if use_init_boot:
+                        boot = (
+                            out_dir / f"boot_no_ramdisk_v{boot_ver}_{slot}.img"
+                        )
+                    else:
+                        boot = out_dir / f"boot_v{boot_ver}_{slot}.img"
+
+                    for vendor_ver in [3, 4]:
+                        vendor_boot = (
+                            out_dir / f"vendor_boot_v{vendor_ver}_{slot}.img"
+                        )
+
+                        parts = [
+                            (f"boot", boot),
+                            (f"vendor_boot", vendor_boot),
+                            ("dtbo", out_dir / f"dtbo_{slot}.img"),
+                            ("dtb", out_dir / f"dtb_{slot}.img"),
+                        ]
+                        prefix = f"vbmeta_v{boot_ver}_v{vendor_ver}"
+                        if use_init_boot:
+                            vbmeta_out = prefix + f"_init_boot_{slot}.img"
+                            parts += [
+                                (
+                                    "init_boot",
+                                    out_dir / f"init_boot_{slot}.img",
+                                )
+                            ]
+                        else:
+                            vbmeta_out = prefix + f"_{slot}.img"
+
+                        gen_android_test_vbmeta(parts, out_dir / vbmeta_out)
+
+            # Generate v4 vbmeta image for vendor_boot with dttable structure
+            vbmeta_out = out_dir / \
+                f"vbmeta_v4_dttable_{slot}.img"
+            parts = [
+                (f"boot", out_dir /
+                    f"boot_v4_{slot}.img"),
+                (f"vendor_boot", out_dir /
+                    f"vendor_boot_v4_dttable_{slot}.img"),
+                ("dtbo", out_dir / f"dtbo_{slot}.img"),
+                ("dtb", out_dir / f"dtb_{slot}.img"),
+            ]
+            gen_android_test_vbmeta(parts, vbmeta_out)
+
+            # Generate v4 vbmeta images for both gzip and lz4 kernel compression.
+            if slot == "a":
+                for compression in ["gz", "lz4"]:
+                    vbmeta_out = out_dir / \
+                        f"vbmeta_v4_{compression}_{slot}.img"
+                    parts = [
+                        (f"boot", out_dir /
+                         f"boot_v4_{compression}_{slot}.img"),
+                        (f"vendor_boot", out_dir /
+                         f"vendor_boot_v4_{slot}.img"),
+                        ("dtbo", out_dir / f"dtbo_{slot}.img"),
+                        ("dtb", out_dir / f"dtb_{slot}.img"),
+                    ]
+                    gen_android_test_vbmeta(parts, vbmeta_out)
+
+
 def gen_zircon_test_images(zbi_tool):
     if not zbi_tool:
         print(
-            "Warning: ZBI tool not provided. Skip regenerating zircon test images"
+            "Warning: ZBI tool not provided. Skip regenerating zircon test"
+            " images"
         )
         return
 
-    PSK = AVB_TEST_DATA_DIR / "testkey_cert_psk.pem"
     ATX_METADATA = AVB_TEST_DATA_DIR / "cert_metadata.bin"
-    TEST_ROLLBACK_INDEX_LOCATION = 1
-    TEST_ROLLBACK_INDEX = 2
+
     with tempfile.TemporaryDirectory() as temp_dir:
-        for suffix in ["a", "b", "r", "slotless"]:
+        for slot in ["a", "b", "r", "slotless"]:
             temp_dir = pathlib.Path(temp_dir)
-            random.seed(RNG_SEED_ZIRCON[suffix])
-            out_kernel_bin_file = temp_dir / f"zircon_{suffix}.bin"
+            random.seed(RNG_SEED_ZIRCON[slot])
+            out_kernel_bin_file = temp_dir / f"zircon_{slot}.bin"
             # The first 16 bytes are two u64 integers representing `entry` and
             # `reserve_memory_size`.
             # Set `entry` value to 2048 and `reserve_memory_size` to 1024.
@@ -104,8 +593,8 @@ def gen_zircon_test_images(zbi_tool):
             )
             kernel_bytes += random.randbytes(1 * SZ_KB - 16)
             out_kernel_bin_file.write_bytes(kernel_bytes)
-            out_zbi_file = SCRIPT_DIR / f"zircon_{suffix}.zbi"
-            # Put image in a zbi container.
+            out_zbi_file = SCRIPT_DIR / f"zircon_{slot}.zbi"
+            # Puts image in a zbi container.
             subprocess.run(
                 [
                     zbi_tool,
@@ -116,8 +605,8 @@ def gen_zircon_test_images(zbi_tool):
                 ]
             )
 
-            # Generate vbmeta descriptor.
-            vbmeta_desc = f"{temp_dir}/zircon_{suffix}.vbmeta.desc"
+            # Generates vbmeta descriptor.
+            vbmeta_desc = f"{temp_dir}/zircon_{slot}.vbmeta.desc"
             subprocess.run(
                 [
                     AVB_TOOL,
@@ -133,7 +622,7 @@ def gen_zircon_test_images(zbi_tool):
                     "209715200",
                 ]
             )
-            # Generate two cmdline ZBI items to add as property descriptors to
+            # Generates two cmdline ZBI items to add as property descriptors to
             # vbmeta image for test.
             vbmeta_prop_args = []
             for i in range(2):
@@ -157,8 +646,8 @@ def gen_zircon_test_images(zbi_tool):
                     "--prop_from_file",
                     f"vb_prop_{i}:{prop_zbi_payload}",
                 ]
-            # Generate vbmeta image
-            vbmeta_img = SCRIPT_DIR / f"vbmeta_{suffix}.bin"
+            # Generates vbmeta image
+            vbmeta_img = SCRIPT_DIR / f"vbmeta_{slot}.bin"
             subprocess.run(
                 [
                     AVB_TOOL,
@@ -226,7 +715,7 @@ def gen_vbmeta():
     hash_bytes = sha256_hash(SCRIPT_DIR / "cert_permanent_attributes.bin")
     (SCRIPT_DIR / "cert_permanent_attributes.hash").write_bytes(hash_bytes)
 
-    # Also create a corrupted version of the permanent attributes to test failure.
+    # Also creates a corrupted version of the permanent attributes to test failure.
     # This is a little bit of a pain but we don't have an easy way to do a SHA256 in Rust
     # at the moment so we can't generate it on the fly.
     bad_attrs = bytearray(
@@ -291,7 +780,7 @@ def gen_vbmeta():
             check=True,
         )
 
-        # Also create a vbmeta using the libavb_cert extension.
+        # Also creates a vbmeta using the libavb_cert extension.
         subprocess.run(
             [
                 AVB_TOOL,
@@ -329,3 +818,4 @@ if __name__ == "__main__":
     gen_sparse_test_file()
     gen_zircon_test_images(args.zbi_tool)
     gen_vbmeta()
+    gen_android_test_images()
diff --git a/gbl/libmisc/src/lib.rs b/gbl/libmisc/src/lib.rs
index 7f913fb..208dd88 100644
--- a/gbl/libmisc/src/lib.rs
+++ b/gbl/libmisc/src/lib.rs
@@ -24,7 +24,7 @@
 
 use core::ffi::CStr;
 
-use zerocopy::{AsBytes, FromBytes, FromZeroes, Ref};
+use zerocopy::{FromBytes, Immutable, IntoBytes, KnownLayout, Ref};
 
 use liberror::{Error, Result};
 
@@ -50,14 +50,20 @@ impl core::fmt::Display for AndroidBootMode {
     }
 }
 
+/// BCB command field offset within BCB block.
+pub const COMMAND_FIELD_OFFSET: usize = 0;
+
+/// BCB command field size in bytes.
+pub const COMMAND_FIELD_SIZE: usize = 32;
+
 /// Android bootloader message structure that usually placed in the first block of misc partition
 ///
 /// Reference code:
 /// https://cs.android.com/android/platform/superproject/main/+/95ec3cc1d879b92dd9db3bb4c4345c5fc812cdaa:bootable/recovery/bootloader_message/include/bootloader_message/bootloader_message.h;l=67
 #[repr(C, packed)]
-#[derive(AsBytes, FromBytes, FromZeroes, PartialEq, Copy, Clone, Debug)]
+#[derive(IntoBytes, FromBytes, Immutable, KnownLayout, PartialEq, Copy, Clone, Debug)]
 pub struct BootloaderMessage {
-    command: [u8; 32],
+    command: [u8; COMMAND_FIELD_SIZE],
     status: [u8; 32],
     recovery: [u8; 768],
     stage: [u8; 32],
@@ -70,10 +76,12 @@ impl BootloaderMessage {
 
     /// Extract BootloaderMessage reference from bytes
     pub fn from_bytes_ref(buffer: &[u8]) -> Result<&BootloaderMessage> {
-        Ok(Ref::<_, BootloaderMessage>::new_from_prefix(buffer)
-            .ok_or(Error::BufferTooSmall(Some(core::mem::size_of::<BootloaderMessage>())))?
-            .0
-            .into_ref())
+        Ok(Ref::into_ref(
+            Ref::<_, BootloaderMessage>::new_from_prefix(buffer)
+                .ok_or(Error::BufferTooSmall(Some(core::mem::size_of::<BootloaderMessage>())))?
+                .0
+                .into(),
+        ))
     }
 
     /// Extract AndroidBootMode from BCB command field
@@ -96,7 +104,7 @@ impl BootloaderMessage {
 mod test {
     use crate::AndroidBootMode;
     use crate::BootloaderMessage;
-    use zerocopy::AsBytes;
+    use zerocopy::IntoBytes;
 
     impl Default for BootloaderMessage {
         fn default() -> Self {
diff --git a/gbl/libsafemath/BUILD b/gbl/libsafemath/BUILD
index 7a7bfa1..8d2b61d 100644
--- a/gbl/libsafemath/BUILD
+++ b/gbl/libsafemath/BUILD
@@ -30,4 +30,5 @@ rust_test(
     name = "libsafemath_test",
     crate = ":libsafemath",
     rustc_flags = ANDROID_RUST_LINTS,
+    visibility = ["//visibility:public"],
 )
diff --git a/gbl/libsafemath/src/lib.rs b/gbl/libsafemath/src/lib.rs
index cd849f7..f7f4ed9 100644
--- a/gbl/libsafemath/src/lib.rs
+++ b/gbl/libsafemath/src/lib.rs
@@ -233,7 +233,7 @@ macro_rules! try_conversion_func {
 
             #[track_caller]
             fn try_from(val: SafeNum) -> Result<Self, Self::Error> {
-                Self::try_from(val.0?).map_err(|_| Location::caller().into())
+                Self::try_from(val.0?).ok().ok_or(Location::caller().into())
             }
         }
     };
@@ -256,7 +256,7 @@ macro_rules! conversion_func_maybe_error {
         impl From<$from_type> for SafeNum {
             #[track_caller]
             fn from(val: $from_type) -> Self {
-                Self(Primitive::try_from(val).map_err(|_| Location::caller().into()))
+                Self(Primitive::try_from(val).ok().ok_or(Location::caller().into()))
             }
         }
 
@@ -275,9 +275,7 @@ macro_rules! arithmetic_impl {
                 match (self.0, rhs.0) {
                     (Err(_), _) => self,
                     (_, Err(_)) => rhs,
-                    (Ok(lhs), Ok(rhs)) => {
-                        Self(lhs.$func(rhs).ok_or_else(|| Location::caller().into()))
-                    }
+                    (Ok(lhs), Ok(rhs)) => Self(lhs.$func(rhs).ok_or(Location::caller().into())),
                 }
             }
         }
diff --git a/gbl/libstorage/src/gpt.rs b/gbl/libstorage/src/gpt.rs
index 26adc21..2f768ef 100644
--- a/gbl/libstorage/src/gpt.rs
+++ b/gbl/libstorage/src/gpt.rs
@@ -28,7 +28,9 @@ use crc32fast::Hasher;
 use gbl_async::block_on;
 use liberror::{Error, GptError};
 use safemath::SafeNum;
-use zerocopy::{AsBytes, ByteSlice, FromBytes, FromZeroes, Ref};
+use zerocopy::{
+    ByteSlice, FromBytes, FromZeros, Immutable, IntoBytes, KnownLayout, Ref, SplitByteSlice,
+};
 
 /// Number of bytes in GUID.
 pub const GPT_GUID_LEN: usize = 16;
@@ -38,7 +40,9 @@ const GPT_NAME_LEN_U8: usize = 2 * GPT_GUID_LEN;
 
 /// The top-level GPT header.
 #[repr(C, packed)]
-#[derive(Debug, Default, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq, Eq)]
+#[derive(
+    Debug, Default, Copy, Clone, Immutable, IntoBytes, FromBytes, KnownLayout, PartialEq, Eq,
+)]
 pub struct GptHeader {
     /// Magic bytes; must be [GPT_MAGIC].
     pub magic: u64,
@@ -73,7 +77,7 @@ pub struct GptHeader {
 impl GptHeader {
     /// Casts a bytes slice into a mutable GptHeader structure.
     pub fn from_bytes_mut(bytes: &mut [u8]) -> &mut GptHeader {
-        Ref::<_, GptHeader>::new_from_prefix(bytes).unwrap().0.into_mut()
+        Ref::into_mut(Ref::<_, GptHeader>::new_from_prefix(bytes).unwrap().0)
     }
 
     /// Computes the actual crc32 value.
@@ -262,7 +266,7 @@ fn check_entries(header: &GptHeader, entries: &[u8]) -> Result<()> {
 
 /// GptEntry is the partition entry data structure in the GPT.
 #[repr(C, packed)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes, PartialEq)]
+#[derive(Debug, Copy, Clone, Immutable, IntoBytes, FromBytes, KnownLayout, PartialEq)]
 pub struct GptEntry {
     /// Partition type GUID.
     pub part_type: [u8; GPT_GUID_LEN],
@@ -465,12 +469,12 @@ impl core::fmt::Display for GptSyncResult {
 
 /// A packed wrapper of `Option<NonZeroU64>`
 #[repr(C, packed)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Copy, Clone, Immutable, IntoBytes, FromBytes, KnownLayout)]
 struct BlockSize(Option<NonZeroU64>);
 
 /// Represents the structure of a load buffer for loading/verifying/syncing up to N GPT entries.
 #[repr(C, packed)]
-#[derive(Debug, Copy, Clone, AsBytes, FromBytes, FromZeroes)]
+#[derive(Debug, Copy, Clone, Immutable, IntoBytes, FromBytes)]
 pub struct GptLoadBufferN<const N: usize> {
     // GPT doesn't care about block size. But it's easier to have it available for computing offset
     // and size in bytes for partitions. It's also used as a flag for indicating whether a valid
@@ -510,7 +514,7 @@ struct LoadBufferRef<B: ByteSlice> {
     secondary_entries: Ref<B, [GptEntry]>,
 }
 
-impl<B: ByteSlice> LoadBufferRef<B> {
+impl<B: SplitByteSlice> LoadBufferRef<B> {
     fn from(buffer: B) -> Self {
         let n = min(GPT_MAX_NUM_ENTRIES, max_supported_entries(&buffer[..]).unwrap());
         let (block_size, rest) = Ref::new_from_prefix(buffer).unwrap();
@@ -670,7 +674,7 @@ impl<B: DerefMut<Target = [u8]>> Gpt<B> {
         };
 
         // Loads the header
-        disk.read(header_start, header.as_bytes_mut()).await?;
+        disk.read(header_start, Ref::bytes_mut(&mut header)).await?;
         // Checks header.
         check_header(disk.io(), &header, matches!(hdr_type, HeaderType::Primary))?;
         // Loads the entries.
@@ -819,7 +823,7 @@ pub(crate) async fn update_gpt(
         .map(|v| v.split_at_mut_checked(blk_sz))
         .flatten()
         .ok_or(Error::BufferTooSmall(Some(blk_sz * 2)))?;
-    let header = Ref::<_, GptHeader>::new_from_prefix(&mut header[..]).unwrap().0.into_mut();
+    let header = Ref::into_mut(Ref::<_, GptHeader>::new_from_prefix(&mut header[..]).unwrap().0);
 
     // Adjusts last usable block according to this device in case the GPT was generated for a
     // different disk size. If this results in some partition being out of range, it will be
diff --git a/gbl/libutils/BUILD b/gbl/libutils/BUILD
index fe7e4f0..7ab96ee 100644
--- a/gbl/libutils/BUILD
+++ b/gbl/libutils/BUILD
@@ -33,4 +33,5 @@ rust_test(
     name = "test",
     crate = ":libutils",
     rustc_flags = ANDROID_RUST_LINTS,
+    visibility = ["//visibility:public"],
 )
diff --git a/gbl/libutils/src/lib.rs b/gbl/libutils/src/lib.rs
index ad5932e..f0a7fca 100644
--- a/gbl/libutils/src/lib.rs
+++ b/gbl/libutils/src/lib.rs
@@ -16,6 +16,7 @@
 
 #![cfg_attr(not(test), no_std)]
 
+use core::{cmp::min, str::from_utf8};
 use liberror::{Error, Result};
 use safemath::SafeNum;
 
@@ -63,6 +64,64 @@ where
     (addr.round_up(alignment) - addr).try_into().map_err(From::from)
 }
 
+/// A helper data structure for writing formatted string to fixed size bytes array.
+#[derive(Debug)]
+pub struct FormattedBytes<T>(T, usize);
+
+impl<T: AsMut<[u8]> + AsRef<[u8]>> FormattedBytes<T> {
+    /// Create an instance.
+    pub fn new(buf: T) -> Self {
+        Self(buf, 0)
+    }
+
+    /// Get the size of content.
+    pub fn size(&self) -> usize {
+        self.1
+    }
+
+    /// Appends the given `bytes` to the contents.
+    ///
+    /// If `bytes` exceeds the remaining buffer space, any excess bytes are discarded.
+    ///
+    /// Returns the resulting contents.
+    pub fn append(&mut self, bytes: &[u8]) -> &mut [u8] {
+        let buf = &mut self.0.as_mut()[self.1..];
+        // Only write as much as the size of the bytes buffer. Additional write is silently
+        // ignored.
+        let to_write = min(buf.len(), bytes.len());
+        buf[..to_write].clone_from_slice(&bytes[..to_write]);
+        self.1 += to_write;
+        &mut self.0.as_mut()[..self.1]
+    }
+
+    /// Converts to string.
+    pub fn to_str(&self) -> &str {
+        from_utf8(&self.0.as_ref()[..self.1]).unwrap_or("")
+    }
+}
+
+impl<T: AsMut<[u8]> + AsRef<[u8]>> core::fmt::Write for FormattedBytes<T> {
+    fn write_str(&mut self, s: &str) -> core::fmt::Result {
+        self.append(s.as_bytes());
+        Ok(())
+    }
+}
+
+/// A convenient macro that behaves similar to snprintf in C.
+///
+/// Panics if the written string is not UTF-8.
+#[macro_export]
+macro_rules! snprintf {
+    ( $arr:expr, $( $x:expr ),* ) => {
+        {
+            let mut bytes = $crate::FormattedBytes::new(&mut $arr[..]);
+            core::fmt::Write::write_fmt(&mut bytes, core::format_args!($($x,)*)).unwrap();
+            let size = bytes.size();
+            core::str::from_utf8(&$arr[..size]).unwrap()
+        }
+    };
+}
+
 #[cfg(test)]
 mod test {
     use super::*;
@@ -131,4 +190,11 @@ mod test {
 
         assert!(matches!(aligned_subslice(bytes, SafeNum::MAX), Err(Error::ArithmeticOverflow(_))));
     }
+
+    #[test]
+    fn test_formatted_bytes() {
+        let mut bytes = [0u8; 4];
+        assert_eq!(snprintf!(bytes, "abcde"), "abcd");
+        assert_eq!(&bytes, b"abcd");
+    }
 }
diff --git a/gbl/rewrite_rust_project_path.py b/gbl/rewrite_rust_project_path.py
index 220e0bb..7513175 100644
--- a/gbl/rewrite_rust_project_path.py
+++ b/gbl/rewrite_rust_project_path.py
@@ -16,6 +16,7 @@ import json
 import os
 import logging
 import tempfile
+import shutil
 
 # To generate rust-project.json from bazel, run
 # bazel run @rules_rust//tools/rust_analyzer:gen_rust_project --norepository_disable_download @gbl//efi:main
@@ -59,12 +60,10 @@ def main(argv):
     data = json.load(fp)
     traverse(data)
 
-  with tempfile.NamedTemporaryFile("w+") as fp:
+  with tempfile.NamedTemporaryFile("w+", delete=False) as fp:
     json.dump(data, fp.file, indent=True)
-    os.rename(fp.name, rust_project_json_path)
-    # create the tempfile again so deleting it works after exiting this scope
-    with open(fp.name, "w"):
-      pass
+    tmp_path = fp.name
+  shutil.move(tmp_path, rust_project_json_path)
 
 
 if __name__ == "__main__":
diff --git a/gbl/smoltcp/BUILD.smoltcp.bazel b/gbl/smoltcp/BUILD.smoltcp.bazel
index 81598ab..e01f6a1 100644
--- a/gbl/smoltcp/BUILD.smoltcp.bazel
+++ b/gbl/smoltcp/BUILD.smoltcp.bazel
@@ -125,7 +125,7 @@ rust_library(
         ":heapless",
         "@bitflags",
         "@byteorder",
-        "@cfg-if",
+        "@cfg_if",
         "@managed",
     ],
 )
diff --git a/gbl/tests/BUILD b/gbl/tests/BUILD
index 26dc38f..ab0cf8a 100644
--- a/gbl/tests/BUILD
+++ b/gbl/tests/BUILD
@@ -12,28 +12,44 @@
 # See the License for the specific language governing permissions and
 # limitations under the License.
 
+load("@gbl//toolchain:build_and_run_tests.bzl", "build_and_run_tests")
+
 test_suite(
     name = "tests",
+    tests = [
+        ":build_and_run_tests",
+        # Doc tests does not work for `build_and_run_tests` because it accesses
+        # `../rules_rust/util/process_wrapper` and its path can't be correctly provided as test
+        # data.
+        "@gbl//libstorage:libstorage_doc_test",
+    ],
+)
+
+build_and_run_tests(
+    name = "build_and_run_tests",
+    # We need to re-specify the runtime data needed by tests.
+    data = ["@gbl//libgbl/testdata"],
     tests = [
         "@gbl//:readme_test",
         "@gbl//efi:test",
-        "@gbl//libabr:libabr_tests",
+        "@gbl//libabr:libabr_test",
         "@gbl//libasync:cyclic_executor_test",
         "@gbl//libasync:libasync_test",
         "@gbl//libbootimg:libbootimg_test",
         "@gbl//libbootparams:test",
+        "@gbl//libc:libc_c_test",
         "@gbl//libc:libc_test",
         "@gbl//libdttable:libdttable_test",
         "@gbl//libefi:libefi_test",
         "@gbl//libefi:mocks_test",
         "@gbl//libefi_types:libefi_types_test",
+        "@gbl//libelf:relocation_test",
         "@gbl//liberror:liberror_test",
         "@gbl//libfastboot:libfastboot_test",
         "@gbl//libfdt:libfdt_test",
         "@gbl//libgbl:libgbl_test",
         "@gbl//libmisc:libmisc_test",
         "@gbl//libsafemath:libsafemath_test",
-        "@gbl//libstorage:libstorage_doc_test",
         "@gbl//libstorage:libstorage_test",
         "@gbl//libutils:test",
         "@zbi//:zbi_test",
diff --git a/gbl/tests/noop.sh b/gbl/tests/noop.sh
new file mode 100755
index 0000000..f84cab4
--- /dev/null
+++ b/gbl/tests/noop.sh
@@ -0,0 +1,19 @@
+#!/bin/bash
+#
+# Copyright (C) 2024 The Android Open Source Project
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
+#
+# This is a noop script used by `build_and_run_tests` rule.
+
+exit 0
diff --git a/gbl/toolchain/BUILD b/gbl/toolchain/BUILD
index d936e4c..40ac1b0 100644
--- a/gbl/toolchain/BUILD
+++ b/gbl/toolchain/BUILD
@@ -183,7 +183,12 @@ cc_flags_common = [
 # x86_64 UEFI targets
 gbl_clang_cc_toolchain(
     name = "x86_64_uefi_clang_cc_toolchain",
-    cc_flags = cc_flags_common,
+    cc_flags = cc_flags_common + [
+        # Adding this prevents the compiler from generating mmx, sse instructions such as
+        # "movsd (%esp),%xmm0" which likely isn't enabled during the bootloader stage and causes
+        # crash as a result.
+        "-mgeneral-regs-only",
+    ],
     target_cpu = "x86_64",
     target_system_triple = "x86_64-unknown-windows-msvc",
 )
diff --git a/gbl/toolchain/BUILD.android_rust_prebuilts.bazel b/gbl/toolchain/BUILD.android_rust_prebuilts.bazel
index c2fb655..b6beffc 100644
--- a/gbl/toolchain/BUILD.android_rust_prebuilts.bazel
+++ b/gbl/toolchain/BUILD.android_rust_prebuilts.bazel
@@ -98,7 +98,7 @@ rust_library(
         "mem",
     ],
     crate_name = "compiler_builtins",
-    edition = "2015",
+    edition = "2021",
     rustc_flags = ["--cap-lints=allow"],
     deps = ["libcore"],
 )
diff --git a/gbl/toolchain/build_and_run_tests.bzl b/gbl/toolchain/build_and_run_tests.bzl
new file mode 100644
index 0000000..d03413e
--- /dev/null
+++ b/gbl/toolchain/build_and_run_tests.bzl
@@ -0,0 +1,89 @@
+# Copyright (C) 2025 The Android Open Source Project
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
+"""
+This file defines `build_and_run_tests` rule
+"""
+
+load("@rules_shell//shell:sh_test.bzl", "sh_test")
+
+def _build_and_run_impl(ctx):
+    # Executable file from the attribute.
+    executable = ctx.executable.executable
+
+    # Output log file.
+    logfile = ctx.actions.declare_file("%s.txt" % ctx.attr.name)
+
+    ctx.actions.run_shell(
+        inputs = [executable] + ctx.files.data,
+        outputs = [logfile],
+        progress_message = "Running test %s" % executable.short_path,
+        command = """\
+        BIN="%s" && \
+        OUT="%s" && \
+        ($BIN > $OUT || \
+        if [ $? == 0 ]; then
+            true
+        else
+            echo "\n%s failed." && cat $OUT && false
+        fi)
+""" % (executable.path, logfile.path, executable.short_path),
+    )
+
+    return [DefaultInfo(files = depset([logfile]))]
+
+build_and_run = rule(
+    implementation = _build_and_run_impl,
+    attrs = {
+        "executable": attr.label(
+            executable = True,
+            cfg = "exec",
+            allow_files = True,
+            mandatory = True,
+        ),
+        "data": attr.label_list(
+            allow_files = True,
+            allow_empty = True,
+        ),
+    },
+)
+
+# TODO(b/382503065): This is a temporary workaround due to presubmit infra not blocking on test
+# failures and only on build failures. Removed once the issue is solved.
+def build_and_run_tests(name, tests, data):
+    """Create an `sh_test` target that run a set of unittests during build time.
+
+    Args:
+        name (String): name of the rust_library target.
+        tests (List of strings): List of test target.
+        data (List of strings): Runtime data needed by the tests.
+    """
+
+    all_tests = []
+    for idx, test in enumerate(tests):
+        subtest_name = "{}_subtest_{}".format(name, idx)
+        build_and_run(
+            name = subtest_name,
+            testonly = True,
+            executable = test,
+            data = data,
+        )
+
+        all_tests.append(":{}".format(subtest_name))
+
+    sh_test(
+        name = name,
+        srcs = ["@gbl//tests:noop.sh"],
+        data = all_tests,
+    )
diff --git a/gbl/toolchain/gbl_workspace_util.bzl b/gbl/toolchain/gbl_workspace_util.bzl
index 9751ad4..d14853a 100644
--- a/gbl/toolchain/gbl_workspace_util.bzl
+++ b/gbl/toolchain/gbl_workspace_util.bzl
@@ -127,7 +127,7 @@ gbl_llvm_prebuilts = repository_rule(
 
 # The current rust version used by GBL. This needs to be manually updated when new version of
 # prebuilts is uploaded to https://android.googlesource.com/platform/prebuilts/rust/
-GBL_RUST_VERSION = "1.81.0"
+GBL_RUST_VERSION = "1.83.0"
 
 def _android_rust_prebuilts_impl(repo_ctx):
     """Assemble a rust toolchain repo from the Android rust prebuilts repo.
diff --git a/vts/Android.bp b/vts/Android.bp
index caecc9f..b21d87d 100644
--- a/vts/Android.bp
+++ b/vts/Android.bp
@@ -31,3 +31,16 @@ cc_test {
     ],
     require_root: true,
 }
+
+cc_test {
+    name: "VtsGblTest",
+    srcs: ["VtsGblTest.cpp"],
+    shared_libs: ["libbase"],
+    static_libs: ["libgmock"],
+    test_suites: [
+        "vts",
+    ],
+    test_options: {
+        vsr_min_shipping_api_level: 202504,
+    },
+}
diff --git a/vts/VtsGblTest.cpp b/vts/VtsGblTest.cpp
new file mode 100644
index 0000000..d4a69e7
--- /dev/null
+++ b/vts/VtsGblTest.cpp
@@ -0,0 +1,56 @@
+/**
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
+#include <android-base/file.h>
+#include <android-base/parseint.h>
+#include <android-base/properties.h>
+#include <android-base/strings.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+class VtsGblTest : public testing::Test {};
+
+TEST_F(VtsGblTest, TestRunningProp) {
+  // TODO: Check assumptions. feature flag or API level?
+  const int32_t gbl_version =
+      android::base::GetIntProperty("ro.boot.gbl.version", -1);
+  const std::string build_number =
+      android::base::GetProperty("ro.boot.gbl.build_number", "");
+
+  if (gbl_version == -1) {
+    GTEST_SKIP() << "Device not booted with GBL";
+  }
+
+  GTEST_LOG_(INFO) << "GBL version: " << gbl_version;
+  GTEST_LOG_(INFO) << "GBL build_number: " << build_number;
+
+  if (android::base::StartsWith(build_number, "eng.")) {
+    GTEST_LOG_(WARNING) << "GBL is a local eng build";
+  }
+  ASSERT_THAT(build_number, testing::MatchesRegex("P?[0-9]+"))
+      << "Invalid build ID";
+  if (build_number[0] == 'P') {
+    GTEST_LOG_(INFO) << "GBL appears to be a presubmit build";
+  } else {
+    uint64_t build_incremental = 0;
+    EXPECT_TRUE(android::base::ParseUint(build_number, &build_incremental))
+        << "Failed to parse build id";
+    // TODO: Update this number after build script is updated to embed build id
+    // in artifact
+    // EXPECT_GE(build_incremental, 12345678)
+    //     << "GBL build number should be at least ...";
+  }
+}
```

