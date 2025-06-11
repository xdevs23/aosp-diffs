```diff
diff --git a/OWNERS b/OWNERS
index 362a419d5..c1d360de2 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,2 +1,3 @@
 # The GSC firmware teams own the code in this repo.
 include chromiumos/owners:v1:/firmware/OWNERS.cros_gsc
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/boot_param/BUILD.bazel b/boot_param/BUILD.bazel
new file mode 100644
index 000000000..1fa0b136f
--- /dev/null
+++ b/boot_param/BUILD.bazel
@@ -0,0 +1,33 @@
+load("@rules_cc//cc:defs.bzl", "cc_library")
+
+package(default_visibility = ["//visibility:public"])
+
+filegroup(
+    name = "boot_param_hdrs",
+    srcs = [
+        "boot_param.h",
+        "boot_param_platform.h",
+        "boot_param_types.h",
+    ],
+)
+
+filegroup(
+    name = "boot_param_srcs",
+    srcs = [
+        "boot_param.c",
+        "cbor_basic.h",
+        "cbor_boot_param.h",
+        "cdi.h",
+    ],
+)
+
+cc_library(
+    name = "boot_param",
+    srcs = [
+        ":boot_param_srcs"
+    ],
+    hdrs = [
+        ":boot_param_hdrs"
+    ],
+    linkstatic = True,
+)
diff --git a/boot_param/boot_param.c b/boot_param/boot_param.c
index adc92b1d9..bdf6ca8a8 100644
--- a/boot_param/boot_param.c
+++ b/boot_param/boot_param.c
@@ -29,7 +29,8 @@ union header_options_s {
  * signature.
  */
 _Static_assert(
-	sizeof(struct combined_hdr_s) >= sizeof(struct cdi_sig_struct_hdr_s)
+	sizeof(struct combined_hdr_s) >= sizeof(struct cdi_sig_struct_hdr_s),
+	"combined_hdr_s < cdi_sig_struct_hdr_s"
 );
 
 struct dice_handover_s {
@@ -40,7 +41,8 @@ struct dice_handover_s {
 };
 _Static_assert(
 	sizeof(struct dice_handover_s) - sizeof(struct dice_handover_hdr_s) ==
-	DICE_CHAIN_SIZE
+	DICE_CHAIN_SIZE,
+	"dice_handover_s != dice_handover_hdr_s + DICE_CHAIN_SIZE"
 );
 
 /* BootParam = {
@@ -63,7 +65,10 @@ struct boot_param_s {
 	uint8_t dice_handover_label;
 	struct dice_handover_s dice_handover;
 };
-_Static_assert(sizeof(struct boot_param_s) == BOOT_PARAM_SIZE);
+_Static_assert(
+	sizeof(struct boot_param_s) == BOOT_PARAM_SIZE,
+	"boot_param_s != BOOT_PARAM_SIZE"
+);
 
 /* Context to pass between functions that build the DICE handover structure
  */
@@ -781,6 +786,12 @@ static inline bool fill_config_details(
 		return false;
 	}
 
+	/* code hash value, could be all zeros in case the device does not */
+	/* support AP RO verification or verification is not provisioned. */
+	__platform_memcpy(cwt_claims->code_hash.value,
+			  ctx->cfg.code_digest,
+			  sizeof(cwt_claims->code_hash.value));
+
 	/* Calculate boot mode */
 	cwt_claims->mode.value = calc_mode(ctx);
 
@@ -906,6 +917,7 @@ size_t get_boot_param_bytes(
 		return 0;
 
 	__platform_memcpy(dest, src + offset, size);
+	__platform_memset(&ctx, 0, sizeof(struct dice_ctx_s)); /* zeroize */
 	return size;
 }
 
@@ -935,5 +947,6 @@ size_t get_dice_chain_bytes(
 		return 0;
 
 	__platform_memcpy(dest, src + offset, size);
+	__platform_memset(&ctx, 0, sizeof(struct dice_ctx_s)); /* zeroize */
 	return size;
 }
diff --git a/docs/case_closed_debugging_gsc.md b/docs/case_closed_debugging_gsc.md
index 96b505cae..b9a4ce030 100644
--- a/docs/case_closed_debugging_gsc.md
+++ b/docs/case_closed_debugging_gsc.md
@@ -236,6 +236,11 @@ CCD needs to be [`Open`].
     combinations to enter [Recovery Mode] and re-enable [Developer Mode].
     See [this bug] for details.
     ***
+    *** note
+    **note**: Chromeboxes without a monitor turn off when the power
+    button is pressed. You can connect a monitor to the DUT keep the AP on
+    while pressing the power button for CCD open.
+    ***
 
 1.  Use the `ccd` command on the GSC console to verify the state is [`Open`]:
 
diff --git a/docs/getting_started_quickly.md b/docs/getting_started_quickly.md
index aa80fb683..5d56fcb67 100644
--- a/docs/getting_started_quickly.md
+++ b/docs/getting_started_quickly.md
@@ -51,7 +51,7 @@ from the Chromium OS chroot:
 1.  Run
 
     ```bash
-    repo init -u https://chromium.googlesource.com/chromiumos/manifest.git --repo-url https://chromium.googlesource.com/external/repo.git -g minilayout
+    repo init https://chromium.googlesource.com/chromiumos/manifest.git -g minilayout
     ```
 
 1.  Edit `.repo/manifest.xml`, and add `groups="minilayout"` to the platform/ec
diff --git a/docs/ti50_firmware_releases.md b/docs/ti50_firmware_releases.md
index 55e7af8ae..edfe300c2 100644
--- a/docs/ti50_firmware_releases.md
+++ b/docs/ti50_firmware_releases.md
@@ -8,7 +8,11 @@ This document captures major feature differences between Ti50 firmware releases
 
 ChromeOS Version    | PrePVT version | Prod Version
 ------------------- | -------------- | ------------
-[ToT][ToT ebuild]   | 0.24.120       | 0.23.112
+[ToT][ToT ebuild]   | 0.24.140       | 0.23.140
+[M134][134 release] | 0.24.140       | 0.23.140
+[M133][133 release] | 0.24.140       | 0.23.122
+[M132][132 release] | 0.24.132       | 0.23.122
+[M131][131 release] | 0.24.121       | 0.23.112
 [M130][130 release] | 0.24.112       | 0.23.112
 [M129][129 release] | 0.24.112       | 0.23.112
 [M128][128 release] | 0.24.101       | 0.23.101
@@ -52,9 +56,12 @@ Feature Description                  | Feature Added | Feature Complete | Releas
 ZTE Serial Number                    |               | 0.22.6           | M107
 CCD Open preserved across deep sleep |               | 0.22.6           | M107
 AP RO WP Sense                       | 0.22.6        |                  | M107
-AP RO Verification (without reset)   | 0.24.0        |                  | M108
+AP RO Verification (without reset)   | 0.24.0        | 0.23.0           | M108
 Fix updates after PoR and deep sleep | 0.24.14       | 0.23.14          | M113
-AP RO Verification Enforcement       | 0.24.61       |                  | M121
+AP RO Verification Enforcement       | 0.24.61       | 0.23.71          | M122
+Reporting external WP assertion fix  | 0.24.131      | 0.23.140         | M133/M134
+Build uses Bazel artifacts           | 0.24.140      | 0.23.140         | M133/M134
+Support for NonInverted KSO          | 0.24.140      | 0.23.140         | M133/M134
 
 # RO revisions
 
@@ -826,6 +833,100 @@ Build:   ti50_common_mp-15980.B:v0.0.0-2b632158
     [b/329439532](https://b.corp.google.com/issues/329439532)
 *   Print AP RO verification latch state
 
+### 0.23.121 Released on 2024-10-28 in M132
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/5973937)
+
+Builder
+[firmware-ti50-mp-15980.B-branch/27](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-mp-15980.B-branch/27/overview)
+
+Artifacts:
+[15980.24.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-mp-15980.B-branch/R129-15980.24.0-1-8733266516965531265/ti50.tar.bz2)
+
+**Features**
+
+*   MISC SPI host improvements
+    [b/319124176](https://b.corp.google.com/issues/319124176)
+
+```
+Build:   ti50_common_mp-15980.B:v0.0.95-e057d336
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9676-30e7fe57c
+         ms-tpm-20-ref:v0.0.320-19310e0
+         @chromeos-ci-firmware-us-east1-d-x32-0-05ll 2024-10-10 10:46:07
+```
+
+### 0.23.122 Released on 2024-12-19 in M133 (cherry-picked to M132)
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6112096)
+
+M132 Cherry-Pick
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6113847)
+
+Builder
+[firmware-ti50-mp-15980.B-branch/35](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-mp-15980.B-branch/35/overview)
+
+Artifacts:
+[15980.32.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-mp-15980.B-branch/R129-15980.32.0-1-8728629894002971313/ti50.tar.bz2)
+
+**Features**
+
+*   Restrict updating EncStateful based on the PCR0 state
+    [b/373478634](https://b.corp.google.com/issues/373478634)
+
+```
+Build:   ti50_common_mp-15980.B:v0.0.97-837bb529
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9676-30e7fe57c
+         ms-tpm-20-ref:v0.0.320-19310e0
+         chrome-bot@chromeos-ci-firmware-us-east1-d-x32-0-okli 2024-12-13 13:30:38
+```
+
+### 0.23.140 Released on 2025-01-17 in M134
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6182216)
+
+Builder
+[firmware-ti50-mp-15980.B-branch/39](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-mp-15980.B-branch/39/overview)
+
+Artifacts:
+[15980.36.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-mp-15980.B-branch/R129-15980.36.0-1-8726835257518688593/dt-ti50.tar.bz2)
+
+**Bug Fixes**
+
+*   Fix AP boot issues resulting in 0x63 error
+    [b/372507391](https://b.corp.google.com/issues/372507391)
+*   Ensure WP_SENSE_L gpio polarity is correct after GSC FW updated
+    [b/254309086](https://b.corp.google.com/issues/254309086)
+
+**Features**
+
+*   Do not honor chassis open signal for 5 minutes for select models
+    [b/361060424](https://b.corp.google.com/issues/361060424)
+*   Update sysinfo rollback print format to match cr50, e.g. `info/a/b`
+*   Erase rollback bits to match active GSC FW on successful OS boot
+    [b/376859171](https://b.corp.google.com/issues/376859171)
+*   Add boot\_param implementation in tpm2
+    [b/376859171](https://b.corp.google.com/issues/376859171)
+*   Block PCR0 double extend
+    [b/385129891](https://b.corp.google.com/issues/385129891)
+*   Add RBOX 4th form factor for Non-Inverted KSO
+    [b/151064221](https://b.corp.google.com/issues/151064221)
+*   Fixes to improve pinweaver hardening
+    [b/325666144](https://b.corp.google.com/issues/325666144)
+*   First build to use bazel artifacts
+
+```
+Build:   ti50_common_mp-15980.B:v0.0.245-247cf69f
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9681-0d36270c8
+         ms-tpm-20-ref:v0.0.323-969d20e
+         chrome-bot@chromeos-ci-firmware-us-central2-d-x32-1-5qj0 2025-01-02 08:45:08
+```
+
 ## PrePVT images
 
 ### 0.22.0 Released 06/21/22
@@ -1826,6 +1927,11 @@ Artifacts:
     [b/319124176](https://b.corp.google.com/issues/319124176)
 *   Add misc debug prints for I2C and PMU
 
+**Known Issues**
+
+*   AP cannot boot due to error 0x63
+    [b/372507391](https://b.corp.google.com/issues/372507391)
+
 ```
 Build:   ti50_common_prepvt-15974.B:v0.0.92-7f6c1fcb
          libtock-rs:v0.0.925-1213708
@@ -1834,6 +1940,121 @@ Build:   ti50_common_prepvt-15974.B:v0.0.92-7f6c1fcb
          chrome-bot@chromeos-ci-firmware-us-central2-d-x32-1-csf8 2024-09-13 08:58:43
 ```
 
+### 0.24.121 Released on 2024-10-12 in M131
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/5927159)
+
+Builder
+[firmware-ti50-prepvt-15974.B-branch/22](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-prepvt-15974.B-branch/22/overview)
+
+Artifacts:
+[15974.22.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-prepvt-15974.B-branch/R129-15974.22.0-1-8734435191727581377/ti50.tar.bz2/)
+
+**Bug Fixes**
+
+*   Fix AP boot issues resulting in 0x63 error
+    [b/372507391](https://b.corp.google.com/issues/372507391)
+
+```
+Build:   ti50_common_prepvt-15974.B:v0.0.94-fc9e8d5c
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9676-524942299
+         ms-tpm-20-ref:v0.0.320-cc605af
+         chrome-bot@chromeos-ci-firmware-us-east1-d-x32-0-59nt 2024-10-10 11:54:43
+```
+
+### 0.24.131 Released on 2024-11-22 in M133
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6043342)
+
+Builder
+[firmware-ti50-prepvt-15974.B-branch/30](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-prepvt-15974.B-branch/30/overview)
+
+Artifacts:
+[15974.30.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-prepvt-15974.B-branch/R129-15974.30.0-1-8730825387367525809/dt-ti50.tar.bz2/)
+
+**Bug Fixes**
+
+*   Fix AP boot issues resulting in 0x63 error
+    [b/372507391](https://b.corp.google.com/issues/372507391)
+*   Ensure WP_SENSE_L gpio polarity is correct after GSC FW updated
+    [b/254309086](https://b.corp.google.com/issues/254309086)
+
+**Features**
+
+*   Do not honor chassis open signal for 5 minutes for select models
+    [b/361060424](https://b.corp.google.com/issues/361060424)
+*   Update sysinfo rollback print format to match cr50, e.g. `info/a/b`
+*   Erase rollback bits to match active GSC FW on successful OS boot
+    [b/376859171](https://b.corp.google.com/issues/376859171)
+*   Add boot\_param implementation in tpm2
+    [b/376859171](https://b.corp.google.com/issues/376859171)
+
+```
+Build:   ti50_common_prepvt-15974.B:v0.0.205-b42c10e8
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9681-d514a6986
+         ms-tpm-20-ref:v0.0.322-c1d3cdd
+         chrome-bot@chromeos-ci-firmware-us-east1-d-x32-0-2arp 2024-11-19 08:07:12
+```
+
+### 0.24.132 Released on 2024-12-18 in M133 (cherry-picked to M132)
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6104086)
+M132 Cherry-Pick
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6113848)
+
+Builder
+[firmware-ti50-prepvt-15974.B-branch/35](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-prepvt-15974.B-branch/35/overview)
+
+Artifacts:
+[15974.35.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-prepvt-15974.B-branch/R129-15974.35.0-1-8728624852836979185/dt-ti50.tar.bz2/)
+
+**Features**
+
+*   Restrict updating EncStateful based on the PCR0 state
+    [b/373478634](https://b.corp.google.com/issues/373478634)
+
+```
+Build:   ti50_common_prepvt-15974.B:v0.0.207-e79f9ffc
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9681-d514a6986
+         ms-tpm-20-ref:v0.0.322-c1d3cdd
+         chrome-bot@chromeos-ci-firmware-us-east1-d-x32-1-9dga 2024-12-13 15:07:37
+```
+
+### 0.24.140 Released on 2024-01-02 in M133
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6136105)
+
+Builder
+[firmware-ti50-prepvt-15974.B-branch/37](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-prepvt-15974.B-branch/37/overview)
+
+Artifacts:
+[15974.37.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware-ti50-prepvt-15974.B-branch/R129-15974.37.0-1-8728006437754332961/dt-ti50.tar.bz2/)
+
+**Features**
+
+*   Block PCR0 double extend
+    [b/385129891](https://b.corp.google.com/issues/385129891)
+*   Add RBOX 4th form factor for Non-Inverted KSO
+    [b/151064221](https://b.corp.google.com/issues/151064221)
+*   Fixes to improve pinweaver hardening
+    [b/325666144](https://b.corp.google.com/issues/325666144)
+*   First build to use bazel artifacts
+
+```
+Build:   ti50_common_prepvt-15974.B:v0.0.246-c837ddc5
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9681-d514a6986
+         ms-tpm-20-ref:v0.0.324-e325e3d
+         chrome-bot@chromeos-ci-firmware-us-central2-d-x32-1-41m2 2024-12-20 10:45:40
+```
+
 <!-- Links -->
 
 [105 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R105-14989.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
@@ -1862,4 +2083,8 @@ Build:   ti50_common_prepvt-15974.B:v0.0.92-7f6c1fcb
 [128 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R128-15964.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [129 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R129-16002.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [130 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R130-16033.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[131 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R131-16063.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[132 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R132-16093.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[133 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R133-16151.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[134 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R134-16181.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [ToT ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/main/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
diff --git a/extra/usb_updater/gsctool.c b/extra/usb_updater/gsctool.c
index e8284c22b..be8e8406e 100644
--- a/extra/usb_updater/gsctool.c
+++ b/extra/usb_updater/gsctool.c
@@ -306,17 +306,6 @@ struct options_map {
 	int *flag;
 };
 
-/*
- * Type of the GSC device. This is used to represent which type of GSC we are
- * connected to and to tag an image file for compatibility.
- * for downloading.
- */
-enum gsc_device {
-	GSC_DEVICE_H1,
-	GSC_DEVICE_DT,
-	GSC_DEVICE_NT,
-};
-
 /* Index to refer to a section within sections array */
 enum section {
 	RO_A,
@@ -1624,6 +1613,23 @@ static void get_version(struct transfer_descriptor *td, bool leave_pending)
 		send_done(&td->uep);
 }
 
+/*
+ * Gets a string of the currently detected GSC device type.
+ */
+static const char *device_string(enum gsc_device device)
+{
+	switch (device) {
+	case GSC_DEVICE_H1:
+		return "H1";
+	case GSC_DEVICE_DT:
+		return "DT";
+	case GSC_DEVICE_NT:
+		return "NT";
+	default:
+		return "Unknown";
+	}
+}
+
 static void setup_connection(struct transfer_descriptor *td)
 {
 	/* Send start request. */
@@ -1631,6 +1637,7 @@ static void setup_connection(struct transfer_descriptor *td)
 
 	get_version(td, true);
 
+	printf("device: %s\n", device_string(gsc_dev));
 	printf("keyids: RO 0x%08x, RW 0x%08x\n", targ.keyid[0], targ.keyid[1]);
 	printf("offsets: backup RO at %#x, backup RW at %#x\n", td->ro_offset,
 	       td->rw_offset);
@@ -1784,7 +1791,7 @@ uint32_t send_vendor_command(struct transfer_descriptor *td,
 		 * to be stripped from the actual response body by this
 		 * function.
 		 */
-		uint8_t temp_response[MAX_RX_BUF_SIZE];
+		uint8_t temp_response[MAX_RX_BUF_SIZE + 1];
 		size_t max_response_size;
 
 		if (!response_size) {
@@ -2307,12 +2314,15 @@ static int show_headers_versions(const struct image *image,
 	}
 
 	if (show_machine_output) {
+		print_machine_output("IMAGE_DEVICE_TYPE", "%s",
+				     device_string(image->type));
 		print_machine_output("IMAGE_RO_FW_VER", "%s", ro_fw_ver[0]);
 		print_machine_output("IMAGE_RW_FW_VER", "%s", rw_fw_ver[0]);
 		print_machine_output("IMAGE_BID_STRING", "%s", bid_string[0]);
 		print_machine_output("IMAGE_BID_MASK", "%08x", bid[0].mask);
 		print_machine_output("IMAGE_BID_FLAGS", "%08x", bid[0].flags);
 	} else {
+		printf("device: %s\n", device_string(image->type));
 		printf("RO_A:%s RW_A:%s[%s:%08x:%08x] ", ro_fw_ver[0],
 		       rw_fw_ver[0], bid_string[0], bid[0].mask, bid[0].flags);
 		printf("RO_B:%s RW_B:%s[%s:%08x:%08x]\n", ro_fw_ver[1],
@@ -4392,7 +4402,7 @@ static int get_crashlog(struct transfer_descriptor *td)
 	return 0;
 }
 
-static int get_console_logs(struct transfer_descriptor *td)
+static int get_console_logs(struct transfer_descriptor *td, bool *empty)
 {
 	uint32_t rv;
 	uint8_t response[2048] = { 0 };
@@ -4405,8 +4415,12 @@ static int get_console_logs(struct transfer_descriptor *td)
 		return 1;
 	}
 
+	if (empty)
+		*empty = response_size == 0;
+
 	printf("%s", response);
-	printf("\n");
+	if (empty && *empty)
+		printf("\n");
 	return 0;
 }
 
@@ -4667,6 +4681,7 @@ static int process_get_boot_trace(struct transfer_descriptor *td, bool erase,
 	size_t response_size = sizeof(boot_trace);
 	uint32_t rv;
 	uint64_t timespan = 0;
+	uint64_t absolute_ms = 0;
 	size_t i;
 
 	rv = send_vendor_command(td, VENDOR_CC_GET_BOOT_TRACE, &payload,
@@ -4680,8 +4695,11 @@ static int process_get_boot_trace(struct transfer_descriptor *td, bool erase,
 	if (response_size == 0)
 		return 0; /* Trace is empty. */
 
-	if (!show_machine_output)
+	if (!show_machine_output) {
 		printf("    got %zd bytes back:\n", response_size);
+		/* Print out header for event info that follows */
+		printf("                Event   Delta     Total\n");
+	}
 	if (response_size > 0) {
 		for (i = 0; i < response_size / sizeof(uint16_t); i++) {
 			uint16_t entry = boot_trace[i];
@@ -4702,9 +4720,11 @@ static int process_get_boot_trace(struct transfer_descriptor *td, bool erase,
 				timespan += (uint64_t)delta_time * MAX_TIME_MS;
 				continue;
 			}
-			printf(" %20s: %4" PRId64 " ms\n",
+			/* Accumulate the absolute time so we can report it */
+			absolute_ms += timespan + delta_time;
+			printf(" %20s %4" PRId64 " ms %6" PRId64 " ms\n",
 			       boot_tracer_stages[event_id],
-			       timespan + delta_time);
+			       timespan + delta_time, absolute_ms);
 			timespan = 0;
 		}
 		printf("\n");
@@ -4712,11 +4732,11 @@ static int process_get_boot_trace(struct transfer_descriptor *td, bool erase,
 	return 0;
 }
 
-struct get_chip_id_response {
-	uint32_t tpm_vid_pid;
-	uint32_t chip_id;
-};
-
+/*
+ * Gets the chip information. Note that Cr50 does not support this command yet
+ * and calling this produces UMA alerts events even if the error is
+ * appropriately handled in this layer.
+ */
 static struct get_chip_id_response get_chip_id_info(
 	struct transfer_descriptor *td)
 {
@@ -4733,7 +4753,7 @@ static struct get_chip_id_response get_chip_id_info(
 		debug("Unexpected response size. (%zu)\n", response_size);
 	} else {
 		/* Success, convert endianness then return */
-		response.tpm_vid_pid = be32toh(response.tpm_vid_pid);
+		response.tpm_did_vid = be32toh(response.tpm_did_vid);
 		response.chip_id = be32toh(response.chip_id);
 		return response;
 	}
@@ -4748,28 +4768,30 @@ static struct get_chip_id_response get_chip_id_info(
  */
 static enum gsc_device determine_gsc_type(struct transfer_descriptor *td)
 {
-	int epoch;
 	int major;
 	struct get_chip_id_response chip_id;
 
 	/*
-	 * Get the firmware version first. See if this is a specific GSC version
-	 * where the Ti50 FW does not response with an error code if the host
-	 * tries an unknown TPMV command over USB. This prevents a USB timeout
-	 * and shutting down of USB subsystem within gsctool (b/368631328).
+	 * If the major version is within the known ranges, stop there since
+	 * not all versions of Cr50 and Ti50 support the GET_CHIP_ID vendor
+	 * command, and if we call it when it isn't supported it will generate
+	 * an UMA alert even if we handle the error here (b/376500403).
+	 * There is also a USB issue to work around (b/368631328).
 	 */
 	get_version(td, false);
-	epoch = targ.shv[1].epoch;
 	major = targ.shv[1].major;
-	if ((epoch == 0 || epoch == 1) && (major >= 21 && major <= 26))
+	if (major >= 30 && major < 40)
+		return GSC_DEVICE_NT;
+	else if (major >= 20 && major < 30)
 		return GSC_DEVICE_DT;
+	else if (major < 10)
+		return GSC_DEVICE_H1;
 	/*
-	 * Try the newer TPMV command. If the command isn't supported,
-	 * then the GSC should respond with an error. If that happens we will
-	 * fall back to the GSC version as the indicator.
+	 * If the major version isn't in the known range, then use the TPMV
+	 * command, which should be supported at that point
 	 */
 	chip_id = get_chip_id_info(td);
-	switch (chip_id.tpm_vid_pid) {
+	switch (chip_id.tpm_did_vid) {
 	case 0x50666666:
 		return GSC_DEVICE_NT;
 	case 0x504a6666:
@@ -4778,21 +4800,12 @@ static enum gsc_device determine_gsc_type(struct transfer_descriptor *td)
 		return GSC_DEVICE_H1;
 	}
 
-	if (chip_id.tpm_vid_pid)
+	if (chip_id.tpm_did_vid)
 		fprintf(stderr, "Unregonized VID_PID 0x%X\n",
-			chip_id.tpm_vid_pid);
+			chip_id.tpm_did_vid);
 
-	/*
-	 * If TPMV command doesn't exist or VID_PID is unrecognized then,
-	 * use the firmware version to determine type.
-	 */
-	major = targ.shv[1].major;
-	if (major >= 30 && major < 40)
-		return GSC_DEVICE_NT;
-	else if (major >= 20 && major < 30)
-		return GSC_DEVICE_DT;
-	else
-		return GSC_DEVICE_H1;
+	/* We have to pick something, but this probably isn't correct */
+	return GSC_DEVICE_H1;
 }
 
 int main(int argc, char *argv[])
@@ -5385,8 +5398,22 @@ int main(int argc, char *argv[])
 	if (get_clog)
 		exit(get_crashlog(&td));
 
-	if (get_console)
-		exit(get_console_logs(&td));
+	if (get_console) {
+		/*
+		 * The console command needs to be bounded in time since
+		 * startup scripts call into this command to collect data. If
+		 * GSC continuously streams console data, we still need gsctool
+		 * to finish.
+		 */
+		int max_iteration = 10;
+		int rv = 0;
+		bool empty = false;
+
+		while (!empty && !rv && max_iteration--)
+			rv = get_console_logs(&td, &empty);
+
+		exit(rv);
+	}
 
 	if (factory_config) {
 		if (set_factory_config)
diff --git a/include/tpm_vendor_cmds.h b/include/tpm_vendor_cmds.h
index 38de78307..4264f423e 100644
--- a/include/tpm_vendor_cmds.h
+++ b/include/tpm_vendor_cmds.h
@@ -338,6 +338,23 @@ enum ap_ro_check_vc_errors {
 	ARCVE_BOARD_ID_BLOCKED = 12,
 };
 
+/* Returns info to identify the specific GSC chip type. */
+struct get_chip_id_response {
+	uint32_t tpm_did_vid;
+	uint32_t chip_id;
+};
+
+/*
+ * Type of the GSC device. This is used to represent which type of GSC we are
+ * connected to and to tag an image file for compatibility.
+ * for downloading.
+ */
+enum gsc_device {
+	GSC_DEVICE_H1,
+	GSC_DEVICE_DT,
+	GSC_DEVICE_NT,
+};
+
 /*****************************************************************************/
 /* Ti50 Specific Structs */
 struct ti50_stats_v0 {
diff --git a/proto/Android.bp b/proto/Android.bp
new file mode 100644
index 000000000..55447fe9f
--- /dev/null
+++ b/proto/Android.bp
@@ -0,0 +1,10 @@
+// Copyright 2025 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+rust_protobuf {
+    name: "libgsc_utils_proto_rs",
+    crate_name: "gsc_utils_proto",
+    protos: ["attestation_ca.proto"],
+    source_stem: "gsc_utils_proto",
+}
diff --git a/proto/attestation_ca.proto b/proto/attestation_ca.proto
new file mode 100644
index 000000000..6453264d6
--- /dev/null
+++ b/proto/attestation_ca.proto
@@ -0,0 +1,520 @@
+// Copyright 2015 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+syntax = "proto2";
+
+package attestation;
+
+option go_package = "attestation_proto";
+
+// Enumerates various certificate profiles supported by the Attestation CA.
+enum CertificateProfile {
+  // A certificate intended for enterprise-owned devices.  It has the following
+  // subjectName fields:
+  //   CN=<stable device identifier>
+  //   OU=state:[verified|developer]
+  //   O=Chrome Device Enterprise
+  ENTERPRISE_MACHINE_CERTIFICATE = 0;
+
+  // A certificate intended for enterprise-owned user accounts.  It has the
+  // following subjectName fields:
+  //   OU=state:[verified|developer]
+  //   O=Chrome Device Enterprise
+  ENTERPRISE_USER_CERTIFICATE = 1;
+
+  // A certificate intended for platform verification by providers of protected
+  // content.  It has the following subjectName fields:
+  //   O=Chrome Device Content Protection
+  CONTENT_PROTECTION_CERTIFICATE = 2;
+
+  // Like above, but it also includes a stable ID and origin.
+  //   CN=<origin-specific device identifier>
+  //   OU=<origin>
+  //   O=Chrome Device Content Protection
+  CONTENT_PROTECTION_CERTIFICATE_WITH_STABLE_ID = 3;
+
+  // A certificate intended for cast devices.
+  CAST_CERTIFICATE = 4;
+
+  GFSC_CERTIFICATE = 5;
+
+  JETSTREAM_CERTIFICATE = 6;
+
+  // A certificate for enterprise enrollment.
+  ENTERPRISE_ENROLLMENT_CERTIFICATE = 7;
+
+  // A certificate for signing Android Testsuite Results using CTS-in-a-box.
+  XTS_CERTIFICATE = 8;
+
+  // An EK certificate for vTPM
+  //   CN=CROS VTPM PRD EK ROOT CA
+  ENTERPRISE_VTPM_EK_CERTIFICATE = 9;
+
+  // A local authority certificate for binding software keys.
+  //   CN=Local Authority
+  //   O=Chrome Device Soft Bind
+  SOFT_BIND_CERTIFICATE = 10;
+
+  // A remote attestation certificate for proving device integrity.
+  //   CN=<An opaque device identifier string>
+  //   O=Chrome Device Setup
+  DEVICE_SETUP_CERTIFICATE = 11;
+
+  // The ARC TPM certifying key is a restricted key that is used to quote
+  // various TPM data, such as PCR quotation or NVRAM quotation.
+  // It is primarily used for Version Attestation in ARC Attestation.
+  ARC_TPM_CERTIFYING_KEY_CERTIFICATE = 12;
+
+  // The ARC Device Key is the Device Key used in Android Attestation for ARC.
+  // It is an unrestricted key.
+  ARC_ATTESTATION_DEVICE_KEY_CERTIFICATE = 13;
+
+  // A certificate intended for the Device Trust flow on enterprise-owned user
+  // accounts on unmanaged devices. It has the following subjectName fields:
+  //   OU=state:[verified|developer]
+  //   O=Chrome Device Enterprise
+  DEVICE_TRUST_USER_CERTIFICATE = 14;
+
+  // A certificate for an Android UDS public key.
+  UDS_CERTIFICATE = 15;
+}
+
+enum TpmVersion {
+  TPM_1_2 = 1;  // NOTE: This is the default. It must remain listed first.
+  TPM_2_0 = 2;
+}
+
+// Types of NVRAM quotes used for attestation.
+enum NVRAMQuoteType {
+  // Quote of the Cr50-backed BoardID.
+  BOARD_ID = 0;
+  // Quote of the Cr50-backed SN+RMA bits.
+  SN_BITS = 1;
+  // Quote of the Cr50-backed RSA public endorsement key certificate.
+  RSA_PUB_EK_CERT = 2;
+  // Quote of the Cr50-backed RSU device ID.
+  RSU_DEVICE_ID = 3;
+  // Quote of RMA bytes (a complement of RMA bits with optional leading zeroes).
+  RMA_BYTES = 4;
+  // Quote of the Cr50-backed G2f certificate.
+  G2F_CERT = 5;
+  // Quote of a DICE cert chain.
+  DICE_CERT_CHAIN = 6;
+}
+
+// Holds information about a quote generated by the TPM.
+message Quote {
+  // The quote; a signature generated with the AIK.
+  optional bytes quote = 1;
+  // The serialized data that was quoted; this assists in verifying the quote.
+  optional bytes quoted_data = 2;
+  // The value of the PCR(s) at the time the quote was generated.
+  optional bytes quoted_pcr_value = 3;
+  // Source data which was originally used to extend the PCR. If this field
+  // exists it can be expected that SHA1(pcr_source_hint) was extended into the
+  // PCR.
+  optional bytes pcr_source_hint = 4;
+}
+
+// Holds encrypted data and information required to decrypt it.
+message EncryptedData {
+  // A key that has been sealed to the TPM or wrapped by another key.
+  optional bytes wrapped_key = 2;
+  // The initialization vector used during encryption.
+  optional bytes iv = 3;
+  // MAC of (iv + encrypted_data).
+  optional bytes mac = 4;
+  optional bytes encrypted_data = 5;
+  // An identifier for the wrapping key to assist in decryption.
+  optional bytes wrapping_key_id = 6;
+}
+
+// The wrapper message of any data and its signature.
+message SignedData {
+  // The data to be signed.
+  optional bytes data = 1;
+  // The signature of the data field.
+  optional bytes signature = 2;
+}
+
+// The first two fields are suitable for passing to Tspi_TPM_ActivateIdentity()
+// directly when using TPM 1.2. For TPM 2.0 the first two fields are not used.
+message EncryptedIdentityCredential {
+  // TPM_ASYM_CA_CONTENTS, encrypted with EK public key.
+  optional bytes asym_ca_contents = 1;
+  // TPM_SYM_CA_ATTESTATION, encrypted with the key in aysm_ca_contents.
+  optional bytes sym_ca_attestation = 2;
+
+  optional TpmVersion tpm_version = 3;
+
+  // The following fields are used only for TPM 2.0. For details see the TPM 2.0
+  // specification Part 1 Rev 1.16:
+  // - Section 9.5.3.3: General description of the scheme.
+  // - Section 24: More details including how to use the seed to compute the
+  //               values for 'credential_mac' and 'wrapped_certificate->
+  //               wrapped_key'
+  // - Section B.10.4: Encrypting the seed with a RSA EK.
+  // - Section C.7.4: Encrypting the seed with an EC EK.
+
+  // A seed encrypted with the EK public key. The TPM will use this seed to
+  // derive both an HMAC key to verify the 'credential_mac' field and an AES key
+  // to unwrap the 'wrapped_certificate->wrapped_key' field.
+  optional bytes encrypted_seed = 4;
+
+  // An integrity value computed using HMAC-SHA256 over the
+  // 'wrapped_certificate.wrapped_key' field and the 'Name' of the identity key.
+  optional bytes credential_mac = 5;
+
+  // A certificate encrypted with a 'credential' that is decrypted by the TPM.
+  // The 'wrapped_key' field contains the encrypted credential which is
+  // encrypted using AES-256-CFB with a zero IV. The encryption of the
+  // certificate itself uses AES-256-CBC with PKCS #5 padding and a random IV.
+  // The encryption key is derived from the 'credential' using:
+  //   SHA256('ENCRYPT' + credential)
+  // The mac uses HMAC-SHA256 with a key derived using:
+  //   SHA256('MAC' + credential)
+  optional EncryptedData wrapped_certificate = 6;
+}
+
+// This message holds all information to be sent to the attestation server in
+// order to complete enrollment.
+message AttestationEnrollmentRequest {
+  // The EK cert, in X.509 form, encrypted using the server's public key with
+  // the following parameters:
+  //   Key encryption: RSA-OAEP with no custom parameters.
+  //   Data encryption: 256-bit key, AES-CBC with PKCS5 padding.
+  //   MAC: HMAC-SHA-512 using the AES key.
+  optional EncryptedData encrypted_endorsement_credential = 1;
+  // The AIK public key, the raw TPM format. (TPM_PUBKEY for TPM 1.2,
+  // TPMT_PUBLIC for TPM 2.0).
+  optional bytes identity_public_key = 2;
+  // PCR0 quoted by AIK.
+  optional Quote pcr0_quote = 3;
+  // PCR1 quoted by AIK.
+  optional Quote pcr1_quote = 4;
+  // DEN for enterprise zero-touch enrollment (crbug/624187).
+  optional bytes enterprise_enrollment_nonce = 5;
+  // The device TPM version.
+  optional TpmVersion tpm_version = 6;
+  // An encrypted quote of the RSA EK cert, in X.509 form, if the endorsement
+  // credential is not RSA.
+  optional EncryptedData encrypted_rsa_endorsement_quote = 7;
+}
+
+enum ResponseStatus {
+  OK = 0;
+  // Internal server error.
+  SERVER_ERROR = 1;
+  // The server cannot parse the request.
+  BAD_REQUEST = 2;
+  // The server rejects the request.
+  REJECT = 3;
+  // Only appears in enrollment response. The server returns the same generated
+  // id and reports the quota limit exceeded status when the number of reset
+  // action in a specified time window is more than self reset limitation.
+  QUOTA_LIMIT_EXCEEDED = 4;
+}
+
+// The response from the attestation server for the enrollment request.
+message AttestationEnrollmentResponse {
+  optional ResponseStatus status = 1;
+  // Short detail response message. Included when the result is not OK.
+  optional string detail = 2;
+  optional EncryptedIdentityCredential encrypted_identity_credential = 3;
+  // Extra details included when the result is not OK.
+  optional string extra_details = 4;
+}
+
+// `DEVICE_SETUP_CERTIFICATE` specific metadata.
+message DeviceSetupCertificateMetadata {
+  // This will eventually be a DUSI. For now, this will be a 36 character GUID.
+  // This will be used as the CN of the Remote Attestation certificate.
+  optional string id = 1;
+
+  // Unix timestamp (in seconds) of the generation of the request.
+  optional uint64 timestamp_seconds = 2;
+
+  // The generated certificate will be bound to this value. This is used to
+  // prevent replay attacks. Currently it is the FIDO credential id.
+  optional string content_binding = 3;
+}
+
+// The certificate request to be sent to the attestation server.
+message AttestationCertificateRequest {
+  // The AIK cert in X.509 format.
+  optional bytes identity_credential = 1;
+  // A certified public key in TPM_PUBKEY (TPMT_PUBLIC for TPM 2.0).
+  optional bytes certified_public_key = 3;
+  // The serialized TPM_CERTIFY_INFO (TPMS_ATTEST for TPM 2.0) for the
+  // certified key.
+  optional bytes certified_key_info = 4;
+  // The signature of the TPM_CERTIFY_INFO (TPMS_ATTEST for TPM 2.0) by the AIK.
+  optional bytes certified_key_proof = 5;
+  // A message identifier to be included in the response.
+  optional bytes message_id = 10;
+  // The certificate profile defines the type of certificate to issue.
+  optional CertificateProfile profile = 11;
+  // Information about the origin of the request which may be used depending on
+  // the certificate profile.
+  optional string origin = 12;
+  // The index of a temporal value.  This may be used or ignored depending on
+  // the certificate profile.
+  optional int32 temporal_index = 13;
+  // The device TPM version.
+  optional TpmVersion tpm_version = 14;
+  // NVRAM quoted by AIK. Keys are values of the NVRAMQuoteType. This is used
+  // by the following profiles:
+  //   - `ENTERPRISE_ENROLLMENT_CERTIFICATE`
+  //   - `ENTERPRISE_VTPM_EK_CERTIFICATE`
+  //   - `UDS_CERTIFICATE`
+  map<int32, Quote> nvram_quotes = 15;
+  // Certificate profile specific metadata.
+  oneof metadata {
+    // `DEVICE_SETUP_CERTIFICATE` specific metadata.
+    DeviceSetupCertificateMetadata device_setup_certificate_metadata = 16;
+  }
+  // ADID read from the VPD. Used as the host identifier incorporated in the
+  // certificates.
+  // Used for `ENTERPRISE_ENROLLMENT_CERTIFICATE` and
+  // `ENTERPRISE_VTPM_EK_CERTIFICATE` profiles only.
+  optional bytes attested_device_id = 17;
+}
+
+// The response from the attestation server for the certificate request.
+message AttestationCertificateResponse {
+  optional ResponseStatus status = 1;
+  // Short detail response message. Included when the result is not OK.
+  optional string detail = 2;
+  // The credential of the certified key in X.509 format.
+  optional bytes certified_key_credential = 3;
+  // The issuer intermediate CA certificate in X.509 format.
+  optional bytes intermediate_ca_cert = 5;
+  // A message identifier from the request this message is responding to.
+  optional bytes message_id = 6;
+  // Additional intermediate CA certificates that can help in validation.
+  // Certificate chaining order is from the leaf to the root. That is,
+  // |certified_key_credential| is signed by
+  // |intermediate_ca_cert|, which is signed by
+  // |additional_intermediate_ca_cert(0)|, which is signed by
+  // |additional_intermediate_ca_cert(1)|, ... and so on.
+  repeated bytes additional_intermediate_ca_cert = 7;
+  // Extra details included when the result is not OK.
+  optional string extra_details = 8;
+}
+
+// The reset request to be sent to the attestation server.
+message AttestationResetRequest {
+  // The AIK cert, in X.509 form, encrypted using the server's public key with
+  // the following parameters:
+  //   Key encryption: RSA-OAEP with no custom parameters.
+  //   Data encryption: 256-bit key, AES-CBC with PKCS5 padding.
+  //   MAC: HMAC-SHA-512 using the AES key.
+  optional EncryptedData encrypted_identity_credential = 1;
+
+  // The one time token to make sure the reset process can be triggered only
+  // once.
+  optional bytes token = 2;
+
+  // The EK cert, in X.509 form, encrypted using the server's public key with
+  // the following parameters:
+  //   Key encryption: RSA-OAEP with no custom parameters.
+  //   Data encryption: 256-bit key, AES-CBC with PKCS5 padding.
+  //   MAC: HMAC-SHA-512 using the AES key.
+  optional EncryptedData encrypted_endorsement_credential = 3;
+}
+
+// The response from the attestation server for the reset request.
+message AttestationResetResponse {
+  // The response status.
+  optional ResponseStatus status = 1;
+  // Short detail response message. Included when the result is not OK.
+  optional string detail = 2;
+  // Extra details included when the result is not OK.
+  optional string extra_details = 3;
+}
+
+// The challenge data (as in challenge-response) generated by the server.
+// Before transmitted to the client, this message will be wrapped as a
+// SignedData message, in which the data field is the serialized Challenge
+// message, and the signature field is the signature of the data field signed
+// by the enterprise server using a hard-coded key. The signature algorithm is
+// RSASSA-PKCS1-v1_5-SHA256.
+message Challenge {
+  // A string for the client to sanity check a legitimate challenge.
+  optional string prefix = 1;
+  // A 256-bit random value generated by the server.
+  optional bytes nonce = 2;
+  // A timestamp for a stateless server to limit the timeframe during which the
+  // challenge may be replayed.
+  optional int64 timestamp = 3;
+}
+
+// The response data (as in challenge-response) generated by the client.
+// Before transmitted to the server, this message will be wrapped as a
+// SignedData message, in which the data field is the serialized
+// ChallengeResponse message, and the signature field is the signature of the
+// data field signed by the client using the key being challenged. The
+// signature algorithm is RSASSA-PKCS1-v1_5-SHA256.
+message ChallengeResponse {
+  // The original challenge data.
+  optional SignedData challenge = 1;
+  // A 256-bit random value generated by the client. Mixing in this nonce
+  // prevents a caller from using a challenge to sign arbitrary data.
+  optional bytes nonce = 2;
+  // The KeyInfo message encrypted using a public encryption key, pushed via
+  // policy with the following parameters:
+  //   Key encryption: RSA-OAEP with no custom parameters.
+  //   Data encryption: 256-bit key, AES-CBC with PKCS5 padding.
+  //   MAC: HMAC-SHA-512 using the AES key.
+  optional EncryptedData encrypted_key_info = 3;
+}
+
+// The data type of the message decrypted from
+// ChallengeResponse.encrypted_key_info.encrypted_data field. This message holds
+// information required by the Verified Access server API (VA) to complete the
+// verification.
+message KeyInfo {
+  // Determines the verification flow on VA and the content of the VA response.
+  optional VerifiedAccessFlow flow_type = 1;
+  // Domain information about the device or user associated with the VA flow
+  // type. For `flow_type` ENTERPRISE_MACHINE, this value is the enrolled
+  // domain. For `flow_type` ENTERPRISE_USER, this value is the user's email
+  // address.
+  optional string domain = 2;
+  // The virtual device ID associated with the device or user.
+  optional bytes device_id = 3;
+  // If the `flow_type` is ENTERPRISE_MACHINE, this value is the PCA-issued
+  // certificate for the key.
+  optional bytes certificate = 4;
+  // If the `flow_type` is ENTERPRISE_USER, this value may hold a
+  // SignedPublicKeyAndChallenge with a random challenge.  The
+  // SignedPublicKeyAndChallenge specification is here:
+  // https://developer.mozilla.org/en-US/docs/HTML/Element/keygen.
+  optional bytes signed_public_key_and_challenge = 5;
+  // The identifier of the customer, as defined by the Google Admin SDK at
+  // https://developers.google.com/admin-sdk/directory/v1/guides/manage-customers
+  optional string customer_id = 6;
+  // A new field which contains public key generated by the CBCM-enrolled
+  // browser if key type is CBCM
+  optional bytes browser_instance_public_key = 7;
+  // A new field which indicated the signing scheme used for the outer
+  // SignedData message. We should populate this for any `flow_type`. For
+  // `flow_type` ENTERPRISE_USER/ENTERPRISE_MACHINE (ChromeOS use case), this
+  // will currently say "SHA256withRSA" at all times, but we should start
+  // supporting ECDSA signing in the near future as per 2020 OKRs. For
+  // `flow_type` CBCM, this will be one of the permitted_schemes from
+  // DeviceIdentity policy.
+  optional string signing_scheme = 8;
+  // Device Trust Signals
+  // Deprecated due to signals collection change to store signals in a
+  // dictionary and converting them to a JSON string. Use
+  // `device_trust_signals_json` instead.
+  reserved 9;
+  // Device Trust Signals
+  optional string device_trust_signals_json = 10;
+  // DM token to be used for this request.
+  optional string dm_token = 11;
+  // The identifier of the customer for the managed user, as defined by the
+  // Google Admin SDK at
+  // https://developers.google.com/admin-sdk/directory/v1/guides/manage-customers.
+  optional string user_customer_id = 12;
+  // Obfuscated gaia ID associated with the signed in managed user.
+  optional string obfuscated_gaia_id = 13;
+  // The ID of a profile on the device.
+  optional string profile_id = 14;
+}
+
+// Device Trust Signals
+message DeviceTrustSignals {
+  option deprecated = true;
+
+  // Device Id
+  optional string device_id = 1;
+  // Obfuscated CBCM-enrolled Customer Id
+  optional string obfuscated_customer_id = 2;
+  // Device serial number
+  optional string serial_number = 3;
+  // Human readable name for this device
+  optional string display_name = 4;
+  // OS running on the device (e.g. Chrome OS)
+  optional string os = 5;
+  // Device manufacturer (e.g. Dell)
+  optional string device_manufacturer = 6;
+  // Device model (e.g. iPhone 12 Max)
+  optional string device_model = 7;
+  // OS version (e.g. macOS 10.15.7)
+  optional string os_version = 8;
+  // IMEI
+  repeated string imei = 9;
+  // MEID
+  repeated string meid = 10;
+  // Hash of the EKPub certificate of the TPM on the device, if available.
+  optional string tpm_hash = 11;
+  // Is the disk encrypted
+  optional bool is_disk_encrypted = 12;
+  // Value of the AllowScreenLock policy.
+  // https://chromeenterprise.google/policies/?policy=AllowScreenLock
+  optional bool allow_screen_lock = 13;
+  // Is the access to the OS user protected by a password
+  optional bool is_protected_by_password = 14;
+  // Is the device jailbroken or modified
+  optional bool is_jailbroken = 15;
+  // The CBCM enrollment domain of the browser.
+  optional string enrollment_domain = 16;
+  // Browser Version
+  optional string browser_version = 17;
+  // Value of the SafeBrowsingProtectionLevel policy.
+  // https://chromeenterprise.google/policies/#SafeBrowsingProtectionLevel
+  optional int32 safe_browsing_protection_level = 18;
+  // Value of the SitePerProcess policy.
+  // https://chromeenterprise.google/policies/#SitePerProcess
+  optional bool site_isolation_enabled = 19;
+  // ThirdPartyBlockingEnabled
+  optional bool third_party_blocking_enabled = 20;
+  // To determine whether users can access other computers
+  // from Chrome using Chrome Remote Desktop
+  optional bool remote_desktop_available = 21;
+  // Signed in profile name
+  optional string signed_in_profile_name = 22;
+  // ChromeCleanupEnabled
+  optional bool chrome_cleanup_enabled = 23;
+  // PasswordProtectionWarningTrigger
+  optional int32 password_protection_warning_trigger = 24;
+  // DNS address
+  optional string dns_address = 25;
+  // BuiltInDnsClientEnabled
+  optional bool built_in_dns_client_enabled = 26;
+  // Whether the OS firewall is turned on
+  optional bool firewall_on = 27;
+  // The Windows domain the device has joined
+  optional string windows_domain = 28;
+}
+
+// Possible VA flows supported by the Verified Access server API and chromium.
+// The values will be used to distinguish between different prerequisites,
+// verification methods and contents of VA challenge response.
+enum VerifiedAccessFlow {
+  // The flow of creating a challenge response for enterprise machine
+  // verification. The VA challenge will be signed with the EMK. ChromeOS only.
+  // Uses CertificateProfile: ENTERPRISE_MACHINE_CERTIFICATE
+  // Uses AttestationKeyType: KEY_DEVICE
+  ENTERPRISE_MACHINE = 0;
+  // The flow of creating a challenge response for enterprise user verification.
+  // The VA challenge will be signed with the EUK. ChromeOS only.
+  // Uses CertificateProfile: ENTERPRISE_USER_CERTIFICATE
+  // Uses AttestationKeyType: KEY_USER
+  ENTERPRISE_USER = 1;
+  // The flow of creating a challenge response for verifying a managed Chrome
+  // Browser. It does not use remote attestation and instead relies on a key
+  // exchange to sign the VA challenge. Chrome Browser only.
+  // Uses CertificateProfile: n.a.
+  // Uses AttestationKeyType: n.a.
+  CBCM = 2;
+  // The flow of creating a challenge response for verification during the
+  // Device Trust Connector handshake. The VA challenge will be signed with a
+  // device key. ChromeOS only.
+  // Uses CertificateProfile: DEVICE_TRUST_USER_CERTIFICATE
+  // Uses AttestationKeyType: KEY_DEVICE
+  DEVICE_TRUST_CONNECTOR = 3;
+}
diff --git a/tpm_generated/Android.bp b/tpm_generated/Android.bp
index 1a475b18f..9d027007e 100644
--- a/tpm_generated/Android.bp
+++ b/tpm_generated/Android.bp
@@ -5,6 +5,24 @@
 // A library for generating TPM commands and parsing TPM responses. Derived from
 // the Chromium OS trunks daemon's TPM code.
 
+rust_library {
+    name: "libtpmclient",
+    crate_name: "tpmclient",
+    host_supported: true,
+    srcs: ["lib.rs"],
+    rustlibs: ["libcxx"],
+    shared_libs: ["libtpmgenerated"],
+}
+
+// cxxbridge generates C++ code that is included in libtpmgenerated.
+genrule {
+    name: "libtpmclient_bridge",
+    tools: ["cxxbridge"],
+    cmd: "$(location cxxbridge) $(in) > $(out)",
+    srcs: ["lib.rs"],
+    out: ["libtpmclient_cxx_generated.cc"],
+}
+
 cc_library {
     name: "libtpmgenerated",
     host_supported: true,
@@ -13,10 +31,15 @@ cc_library {
         "libcrypto",
     ],
     srcs: [
+        "ffi.cc",
         "hex.cc",
+        "multiple_authorization_delegate.cc",
+        "password_authorization_delegate.cc",
         "secure_hash.cc",
         "tpm_generated.cc",
     ],
+    generated_headers: ["cxx-bridge-header"],
+    generated_sources: ["libtpmclient_bridge"],
 }
 
 cc_test_host {
diff --git a/tpm_generated/ffi.cc b/tpm_generated/ffi.cc
new file mode 100644
index 000000000..c03b3105c
--- /dev/null
+++ b/tpm_generated/ffi.cc
@@ -0,0 +1,529 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "ffi.h"
+
+#include <android-base/logging.h>
+#include <openssl/bio.h>
+#include <openssl/bn.h>
+#include <openssl/cipher.h>
+#include <openssl/ecdsa.h>
+#include <openssl/hmac.h>
+#include <openssl/mem.h>
+#include <openssl/rand.h>
+#include <openssl/rsa.h>
+#include <openssl/sha.h>
+
+#include "multiple_authorization_delegate.h"
+#include "password_authorization_delegate.h"
+
+namespace trunks {
+
+namespace {
+
+constexpr TPMA_OBJECT kFixedTPM = 1U << 1;
+constexpr TPMA_OBJECT kFixedParent = 1U << 4;
+constexpr TPMA_OBJECT kSensitiveDataOrigin = 1U << 5;
+constexpr TPMA_OBJECT kUserWithAuth = 1U << 6;
+constexpr TPMA_OBJECT kNoDA = 1U << 10;
+constexpr TPMA_OBJECT kRestricted = 1U << 16;
+constexpr TPMA_OBJECT kDecrypt = 1U << 17;
+constexpr TPMA_OBJECT kSign = 1U << 18;
+
+// Returns a general public area for our keys. This default may be further
+// manipulated to produce the public area for specific keys (such as SRK or
+// AIK).
+TPMT_PUBLIC DefaultPublicArea() {
+  TPMT_PUBLIC public_area;
+  memset(&public_area, 0, sizeof(public_area));
+  public_area.type = TPM_ALG_ECC;
+  public_area.name_alg = TPM_ALG_SHA256;
+  public_area.auth_policy = Make_TPM2B_DIGEST("");
+  public_area.object_attributes = kFixedTPM | kFixedParent;
+  public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_NULL;
+  public_area.parameters.ecc_detail.symmetric.algorithm = TPM_ALG_NULL;
+  public_area.parameters.ecc_detail.curve_id = TPM_ECC_NIST_P256;
+  public_area.parameters.ecc_detail.kdf.scheme = TPM_ALG_NULL;
+  public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER("");
+  public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER("");
+  return public_area;
+}
+
+std::string GetOpenSSLError() {
+  BIO* bio = BIO_new(BIO_s_mem());
+  ERR_print_errors(bio);
+  char* data = nullptr;
+  int data_len = BIO_get_mem_data(bio, &data);
+  std::string error_string(data, data_len);
+  BIO_free(bio);
+  return error_string;
+}
+
+unsigned char* StringAsOpenSSLBuffer(std::string* s) {
+  return reinterpret_cast<unsigned char*>(std::data(*s));
+}
+
+// Converts a TPMT_SIGNATURE into a DER-encoded ECDSA signature.
+TPM_RC TpmSignatureToString(TPMT_SIGNATURE signature, std::string* encoded) {
+  std::string r =
+      StringFrom_TPM2B_ECC_PARAMETER(signature.signature.ecdsa.signature_r);
+  std::string s =
+      StringFrom_TPM2B_ECC_PARAMETER(signature.signature.ecdsa.signature_s);
+  BIGNUM* r_bn =
+      BN_bin2bn(reinterpret_cast<const uint8_t*>(r.data()), r.length(), NULL);
+  BIGNUM* s_bn =
+      BN_bin2bn(reinterpret_cast<const uint8_t*>(s.data()), s.length(), NULL);
+  ECDSA_SIG* sig = ECDSA_SIG_new();
+  if (r_bn == NULL || s_bn == NULL || sig == NULL) {
+    LOG(ERROR) << "BoringSSL allocation failure";
+    return TPM_RC_FAILURE;
+  }
+  // Note: if successful, this transfers ownership of r_bn and s_bin to sig.
+  if (ECDSA_SIG_set0(sig, r_bn, s_bn) != 1) {
+    LOG(ERROR) << "ECDSA_SIG_set0 failed";
+    ECDSA_SIG_free(sig);
+    BN_free(r_bn);
+    BN_free(s_bn);
+    return TPM_RC_FAILURE;
+  }
+  unsigned char* openssl_buffer = nullptr;
+  int size = i2d_ECDSA_SIG(sig, &openssl_buffer);
+  ECDSA_SIG_free(sig);
+  if (size < 0 || openssl_buffer == nullptr) {
+    LOG(ERROR) << "i2d_ECDSA_SIG failed";
+    return TPM_RC_FAILURE;
+  }
+  encoded->assign(reinterpret_cast<const char*>(openssl_buffer), size);
+  OPENSSL_free(openssl_buffer);
+  return TPM_RC_SUCCESS;
+}
+
+}  // namespace
+
+bool EncryptDataForCa(const std::string& data,
+                      const std::string& public_key_hex,
+                      const std::string& key_id, std::string& wrapped_key,
+                      std::string& iv, std::string& mac,
+                      std::string& encrypted_data,
+                      std::string& wrapping_key_id) {
+  const size_t kAesKeySize = 32;
+  const size_t kAesBlockSize = 16;
+  // The exponent of the attestation CA key pairs.
+  const unsigned int kWellKnownExponent = 65537;
+  RSA* rsa = nullptr;
+  BIGNUM* e = nullptr;
+  BIGNUM* n = nullptr;
+  EVP_CIPHER_CTX* encryption_context = nullptr;
+  // This lambda returns early in case of error. The values it allocates are
+  // cleaned up after it returns regardless of outcome.
+  bool out = [&]() {
+    rsa = RSA_new();
+    e = BN_new();
+    n = BN_new();
+    if (!rsa || !e || !n) {
+      LOG(ERROR) << "Failed to allocate RSA or BIGNUMs";
+      return false;
+    }
+    if (!BN_set_word(e, kWellKnownExponent)) {
+      LOG(ERROR) << "Failed to generate exponent";
+      return false;
+    }
+    if (!BN_hex2bn(&n, public_key_hex.c_str())) {
+      LOG(ERROR) << "Failed to generate modulus";
+      return false;
+    }
+    if (!RSA_set0_key(rsa, n, e, nullptr)) {
+      LOG(ERROR) << "Failed to set exponent or modulus";
+      return false;
+    }
+    // RSA_set0_key succeeded, so ownership of n and e are transferred into rsa.
+    // Reset e and n to avoid double-BN_free.
+    e = nullptr;
+    n = nullptr;
+    std::string key;
+    key.resize(kAesKeySize);
+    if (RAND_bytes(StringAsOpenSSLBuffer(&key), kAesKeySize) != 1) {
+      LOG(ERROR) << "RAND_bytes for key failed";
+      return false;
+    }
+    iv.resize(kAesBlockSize);
+    if (RAND_bytes(StringAsOpenSSLBuffer(&iv), kAesBlockSize) != 1) {
+      LOG(ERROR) << "RAND_bytes for iv failed";
+      return false;
+    }
+    // Allocate enough space for the output including padding.
+    encrypted_data.resize(data.size() + kAesBlockSize -
+                          (data.size() % kAesBlockSize));
+    encryption_context = EVP_CIPHER_CTX_new();
+    if (!encryption_context) {
+      LOG(ERROR) << "Failed to allocate EVP_CIPHER_CTX: " << GetOpenSSLError();
+      return false;
+    }
+    if (!EVP_EncryptInit_ex(encryption_context, EVP_aes_256_cbc(), nullptr,
+                            StringAsOpenSSLBuffer(&key),
+                            StringAsOpenSSLBuffer(&iv))) {
+      LOG(ERROR) << "EVP_EncryptInit_ex failed: " << GetOpenSSLError();
+      return false;
+    }
+    unsigned char* output_buffer = StringAsOpenSSLBuffer(&encrypted_data);
+    int update_size = 0;
+    const uint8_t* input_buffer =
+        reinterpret_cast<const uint8_t*>(std::data(data));
+    if (!EVP_EncryptUpdate(encryption_context, output_buffer, &update_size,
+                           input_buffer, data.size())) {
+      LOG(ERROR) << "EVP_EncryptUpdate failed: " << GetOpenSSLError();
+      return false;
+    }
+    output_buffer += update_size;
+    int final_size = 0;
+    if (!EVP_EncryptFinal_ex(encryption_context, output_buffer, &final_size)) {
+      LOG(ERROR) << "EVP_EncryptFinal_ex failed: " << GetOpenSSLError();
+      return false;
+    }
+    encrypted_data.resize(update_size + final_size);
+    mac.resize(SHA512_DIGEST_LENGTH);
+    std::string hmac_data = iv + encrypted_data;
+    HMAC(EVP_sha512(), key.data(), key.size(),
+         StringAsOpenSSLBuffer(&hmac_data), hmac_data.size(),
+         StringAsOpenSSLBuffer(&mac), nullptr);
+    wrapped_key.resize(RSA_size(rsa));
+    int length = RSA_public_encrypt(
+        key.size(), reinterpret_cast<const unsigned char*>(key.data()),
+        StringAsOpenSSLBuffer(&wrapped_key), rsa, RSA_PKCS1_OAEP_PADDING);
+    if (length < 0) {
+      LOG(ERROR) << "RSA_public_encrypt failed: " << GetOpenSSLError();
+      return false;
+    }
+    wrapping_key_id = key_id;
+    return true;
+  }();
+  if (rsa) {
+    RSA_free(rsa);
+  }
+  if (e) {
+    BN_free(e);
+  }
+  if (n) {
+    BN_free(n);
+  }
+  if (encryption_context) {
+    EVP_CIPHER_CTX_free(encryption_context);
+  }
+  return out;
+}
+
+std::unique_ptr<AuthorizationDelegate> PasswordAuthorizationDelegate_New(
+    const std::string& password) {
+  return std::make_unique<PasswordAuthorizationDelegate>(password);
+}
+
+TPM_RC SerializeCommand_Create(
+    const TPMI_DH_OBJECT& parent_handle, const std::string& parent_handle_name,
+    const TPM2B_SENSITIVE_CREATE& in_sensitive, const TPM2B_PUBLIC& in_public,
+    const TPM2B_DATA& outside_info, const TPML_PCR_SELECTION& creation_pcr,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_Create(
+      parent_handle, parent_handle_name, in_sensitive, in_public, outside_info,
+      creation_pcr, &serialized_command, authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_Create(
+    const std::string& response, std::string& out_private,
+    std::string& out_public, TPM2B_CREATION_DATA& creation_data,
+    TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_PRIVATE typed_private;
+  TPM2B_PUBLIC typed_public;
+  TPM_RC rc = Tpm::ParseResponse_Create(
+      response, &typed_private, &typed_public, &creation_data, &creation_hash,
+      &creation_ticket, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  out_private = StringFrom_TPM2B_PRIVATE(typed_private);
+  return Serialize_TPM2B_PUBLIC(typed_public, &out_public);
+}
+
+TPM_RC SerializeCommand_CreatePrimary(
+    const TPMI_RH_HIERARCHY& primary_handle,
+    const std::string& primary_handle_name,
+    const TPM2B_SENSITIVE_CREATE& in_sensitive, const TPM2B_PUBLIC& in_public,
+    const TPM2B_DATA& outside_info, const TPML_PCR_SELECTION& creation_pcr,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_CreatePrimary(
+      primary_handle, primary_handle_name, in_sensitive, in_public,
+      outside_info, creation_pcr, &serialized_command,
+      authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_CreatePrimary(
+    const std::string& response, TPM_HANDLE& object_handle,
+    TPM2B_PUBLIC& out_public, TPM2B_CREATION_DATA& creation_data,
+    TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket,
+    std::string& name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_NAME tpm2b_name;
+  TPM_RC rc = Tpm::ParseResponse_CreatePrimary(
+      response, &object_handle, &out_public, &creation_data, &creation_hash,
+      &creation_ticket, &tpm2b_name, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  return Serialize_TPM2B_NAME(tpm2b_name, &name);
+}
+
+TPM_RC SerializeCommand_Load(
+    const TPMI_DH_OBJECT& parent_handle, const std::string& parent_handle_name,
+    const std::string& in_private, const std::string& in_public,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  std::string buffer_public = in_public;
+  TPM2B_PUBLIC typed_public;
+  TPM_RC rc = Parse_TPM2B_PUBLIC(&buffer_public, &typed_public, nullptr);
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  return Tpm::SerializeCommand_Load(
+      parent_handle, parent_handle_name, Make_TPM2B_PRIVATE(in_private),
+      typed_public, &serialized_command, authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_Load(
+    const std::string& response, TPM_HANDLE& object_handle, std::string& name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_NAME typed_name;
+  TPM_RC rc = Tpm::ParseResponse_Load(response, &object_handle, &typed_name,
+                                      authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  name = StringFrom_TPM2B_NAME(typed_name);
+  return TPM_RC_SUCCESS;
+}
+
+TPM_RC SerializeCommand_NV_Certify(
+    const TPMI_DH_OBJECT& sign_handle, const std::string& sign_handle_name,
+    const TPMI_RH_NV_AUTH& auth_handle, const std::string& auth_handle_name,
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    const TPM2B_DATA& qualifying_data, const TPMT_SIG_SCHEME& in_scheme,
+    const UINT16& size, const UINT16& offset, std::string& serialized_command) {
+  PasswordAuthorizationDelegate password("");
+  MultipleAuthorizations authorizations;
+  authorizations.AddAuthorizationDelegate(&password);
+  authorizations.AddAuthorizationDelegate(&password);
+  return Tpm::SerializeCommand_NV_Certify(
+      sign_handle, sign_handle_name, auth_handle, auth_handle_name, nv_index,
+      nv_index_name, qualifying_data, in_scheme, size, offset,
+      &serialized_command, &authorizations);
+}
+
+TPM_RC ParseResponse_NV_Certify(const std::string& response,
+                                std::string& certify_info,
+                                std::string& signature) {
+  TPM2B_ATTEST certify_info_typed;
+  TPMT_SIGNATURE signature_typed;
+  PasswordAuthorizationDelegate password("");
+  MultipleAuthorizations authorizations;
+  authorizations.AddAuthorizationDelegate(&password);
+  authorizations.AddAuthorizationDelegate(&password);
+  TPM_RC rc = Tpm::ParseResponse_NV_Certify(response, &certify_info_typed,
+                                            &signature_typed, &authorizations);
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  certify_info = StringFrom_TPM2B_ATTEST(certify_info_typed);
+  return TpmSignatureToString(signature_typed, &signature);
+}
+
+TPM_RC SerializeCommand_NV_Read(
+    const TPMI_RH_NV_AUTH& auth_handle, const std::string& auth_handle_name,
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    const UINT16& size, const UINT16& offset, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_NV_Read(
+      auth_handle, auth_handle_name, nv_index, nv_index_name, size, offset,
+      &serialized_command, authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_NV_Read(
+    const std::string& response, std::string& data,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_MAX_NV_BUFFER buffer;
+  TPM_RC rc = Tpm::ParseResponse_NV_Read(response, &buffer,
+                                         authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  data = StringFrom_TPM2B_MAX_NV_BUFFER(buffer);
+  return TPM_RC_SUCCESS;
+}
+
+TPM_RC SerializeCommand_NV_ReadPublic(
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_NV_ReadPublic(nv_index, nv_index_name,
+                                             &serialized_command,
+                                             authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_NV_ReadPublic(
+    const std::string& response, uint16_t& nv_public_data_size,
+    std::string& nv_name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_NV_PUBLIC nv_public;
+  TPM2B_NAME nv_name_typed;
+  TPM_RC rc = Tpm::ParseResponse_NV_ReadPublic(
+      response, &nv_public, &nv_name_typed, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  nv_public_data_size = nv_public.nv_public.data_size;
+  nv_name = StringFrom_TPM2B_NAME(nv_name_typed);
+  return TPM_RC_SUCCESS;
+}
+
+TPM_RC SerializeCommand_Quote(
+    const TPMI_DH_OBJECT& sign_handle, const std::string& sign_handle_name,
+    const TPM2B_DATA& qualifying_data, const TPMT_SIG_SCHEME& in_scheme,
+    const TPML_PCR_SELECTION& pcrselect, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_Quote(
+      sign_handle, sign_handle_name, qualifying_data, in_scheme, pcrselect,
+      &serialized_command, authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_Quote(
+    const std::string& response, std::string& quoted, std::string& signature,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_ATTEST quoted_typed;
+  TPMT_SIGNATURE signature_typed;
+  TPM_RC rc = Tpm::ParseResponse_Quote(
+      response, &quoted_typed, &signature_typed, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  quoted = StringFrom_TPM2B_ATTEST(quoted_typed);
+  return TpmSignatureToString(signature_typed, &signature);
+}
+
+TPM_RC SerializeCommand_PCR_Read(
+    const TPML_PCR_SELECTION& pcr_selection_in, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_PCR_Read(pcr_selection_in, &serialized_command,
+                                        authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_PCR_Read(
+    const std::string& response, UINT32& pcr_update_counter,
+    TPML_PCR_SELECTION& pcr_selection_out, std::string& pcr_values,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPML_DIGEST pcr_values_typed;
+  TPM_RC rc = Tpm::ParseResponse_PCR_Read(response, &pcr_update_counter,
+                                          &pcr_selection_out, &pcr_values_typed,
+                                          authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  if (pcr_values_typed.count != 1) {
+    LOG(ERROR) << "Unexpected PCR count " << pcr_values_typed.count
+               << " in TPM2_PCR_Read reply.";
+    return TPM_RC_FAILURE;
+  }
+  pcr_values = StringFrom_TPM2B_DIGEST(pcr_values_typed.digests[0]);
+  return TPM_RC_SUCCESS;
+}
+
+std::unique_ptr<std::string> NameFromHandle(const TPM_HANDLE& handle) {
+  std::string name;
+  Serialize_TPM_HANDLE(handle, &name);
+  return std::make_unique<std::string>(std::move(name));
+}
+
+std::unique_ptr<TPM2B_CREATION_DATA> TPM2B_CREATION_DATA_New() {
+  return std::make_unique<TPM2B_CREATION_DATA>();
+}
+
+std::unique_ptr<TPM2B_DATA> TPM2B_DATA_New(const std::string& bytes) {
+  return std::make_unique<TPM2B_DATA>(Make_TPM2B_DATA(bytes));
+}
+
+std::unique_ptr<TPM2B_DIGEST> TPM2B_DIGEST_New() {
+  return std::make_unique<TPM2B_DIGEST>();
+}
+
+std::unique_ptr<TPM2B_PUBLIC> AttestationIdentityKeyTemplate() {
+  TPMT_PUBLIC public_area = DefaultPublicArea();
+  public_area.object_attributes |=
+      (kSensitiveDataOrigin | kUserWithAuth | kNoDA | kRestricted | kSign);
+  public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_ECDSA;
+  public_area.parameters.ecc_detail.scheme.details.ecdsa.hash_alg =
+      TPM_ALG_SHA256;
+  return std::make_unique<TPM2B_PUBLIC>(Make_TPM2B_PUBLIC(public_area));
+}
+
+std::unique_ptr<TPM2B_PUBLIC> StorageRootKeyTemplate() {
+  TPMT_PUBLIC public_area = DefaultPublicArea();
+  public_area.object_attributes |=
+      (kSensitiveDataOrigin | kUserWithAuth | kNoDA | kRestricted | kDecrypt);
+  public_area.parameters.asym_detail.symmetric.algorithm = TPM_ALG_AES;
+  public_area.parameters.asym_detail.symmetric.key_bits.aes = 128;
+  public_area.parameters.asym_detail.symmetric.mode.aes = TPM_ALG_CFB;
+  return std::make_unique<TPM2B_PUBLIC>(Make_TPM2B_PUBLIC(public_area));
+}
+
+TPM_RC Tpm2bPublicToTpmtPublic(const std::string& tpm2b_public,
+                               std::string& tpmt_public) {
+  std::string buffer_public = tpm2b_public;
+  TPM2B_PUBLIC typed_public;
+  TPM_RC rc = Parse_TPM2B_PUBLIC(&buffer_public, &typed_public, nullptr);
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  return Serialize_TPMT_PUBLIC(typed_public.public_area, &tpmt_public);
+}
+
+std::unique_ptr<TPM2B_SENSITIVE_CREATE> TPM2B_SENSITIVE_CREATE_New(
+    const std::string& user_auth, const std::string& data) {
+  TPMS_SENSITIVE_CREATE sensitive;
+  sensitive.user_auth = Make_TPM2B_DIGEST(user_auth);
+  sensitive.data = Make_TPM2B_SENSITIVE_DATA(data);
+  return std::make_unique<TPM2B_SENSITIVE_CREATE>(
+      Make_TPM2B_SENSITIVE_CREATE(sensitive));
+}
+
+std::unique_ptr<TPML_PCR_SELECTION> EmptyPcrSelection() {
+  TPML_PCR_SELECTION creation_pcrs = {};
+  creation_pcrs.count = 0;
+  return std::make_unique<TPML_PCR_SELECTION>(creation_pcrs);
+}
+
+std::unique_ptr<TPML_PCR_SELECTION> SinglePcrSelection(uint8_t pcr) {
+  TPML_PCR_SELECTION pcr_select;
+  pcr_select.count = 1;
+  pcr_select.pcr_selections[0].hash = TPM_ALG_SHA256;
+  pcr_select.pcr_selections[0].sizeof_select = PCR_SELECT_MIN;
+  memset(pcr_select.pcr_selections[0].pcr_select, 0, PCR_SELECT_MIN);
+  if (pcr / 8 >= PCR_SELECT_MIN) {
+    LOG(ERROR) << "Invalid PCR number " << pcr;
+    return nullptr;
+  }
+  pcr_select.pcr_selections[0].pcr_select[pcr / 8] = 1u << (pcr % 8);
+  return std::make_unique<TPML_PCR_SELECTION>(pcr_select);
+}
+
+std::unique_ptr<TPMT_SIG_SCHEME> Sha256EcdsaSigScheme() {
+  TPMT_SIG_SCHEME scheme;
+  scheme.details.any.hash_alg = TPM_ALG_SHA256;
+  scheme.scheme = TPM_ALG_ECDSA;
+  return std::make_unique<TPMT_SIG_SCHEME>(scheme);
+}
+
+std::unique_ptr<TPMT_TK_CREATION> TPMT_TK_CREATION_New() {
+  return std::make_unique<TPMT_TK_CREATION>();
+}
+
+}  // namespace trunks
diff --git a/tpm_generated/ffi.h b/tpm_generated/ffi.h
new file mode 100644
index 000000000..15862408c
--- /dev/null
+++ b/tpm_generated/ffi.h
@@ -0,0 +1,277 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef TPM_GENERATED_FFI_H_
+#define TPM_GENERATED_FFI_H_
+
+// The cxx Rust library cannot invoke all C++ methods -- for example, it cannot
+// invoke static methods, and there are many types it cannot pass by value.
+// These functions provide cxx-compatible access to the functionality of other
+// code in this directory.
+//
+// Because this entire library (libtpmgenerated) is a temporary measure
+// (long-term, we want to replace it with tpm-rs), these bindings are added
+// as-needed and do not always expose all the functionality that they could.
+
+#include <memory>
+#include <string>
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+
+namespace trunks {
+
+// Organization: each subsection is a type, ordered alphabetically.
+
+// -----------------------------------------------------------------------------
+// EncryptedData (referring to the CA protobuf's EncryptedData message type)
+// -----------------------------------------------------------------------------
+
+// Encrypts data for an attestation CA. The CA's public key is passed in as an
+// input. The output values correspond to the EncryptedData protobuf in
+// attestation_ca.proto. Returns true on success and false on failure.
+bool EncryptDataForCa(const std::string& data,
+                      const std::string& public_key_hex,
+                      const std::string& key_id, std::string& wrapped_key,
+                      std::string& iv, std::string& mac,
+                      std::string& encrypted_data,
+                      std::string& wrapping_key_id);
+
+// -----------------------------------------------------------------------------
+// PasswordAuthorizationDelegate
+// -----------------------------------------------------------------------------
+
+// Wraps the PasswordAuthorizationDelegate constructor. Returns an
+// AuthorizationDelegate pointer rather than a PasswordAuthorizationDelegate
+// pointer because Rust code doesn't know how to convert a
+// PasswordAuthorizationDelegate pointer into an AuthorizationDelegate pointer.
+std::unique_ptr<AuthorizationDelegate> PasswordAuthorizationDelegate_New(
+    const std::string& password);
+
+// -----------------------------------------------------------------------------
+// Tpm
+// -----------------------------------------------------------------------------
+
+// Wraps Tpm::SerializeCommand_Create. Serializes the TPM2_Create command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_Create(
+    const TPMI_DH_OBJECT& parent_handle, const std::string& parent_handle_name,
+    const TPM2B_SENSITIVE_CREATE& in_sensitive, const TPM2B_PUBLIC& in_public,
+    const TPM2B_DATA& outside_info, const TPML_PCR_SELECTION& creation_pcr,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_Create. Parses the response from a TPM2_Create
+// command.
+// out_public is in serialized form (because there is no
+// StringFrom_TPM2B_PUBLIC in tpm_generated).
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_Create(
+    const std::string& response, std::string& out_private,
+    std::string& out_public, TPM2B_CREATION_DATA& creation_data,
+    TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_CreatePrimary. Serializes the TPM2_CreatePrimary
+// command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_CreatePrimary(
+    const TPMI_RH_HIERARCHY& primary_handle,
+    const std::string& primary_handle_name,
+    const TPM2B_SENSITIVE_CREATE& in_sensitive, const TPM2B_PUBLIC& in_public,
+    const TPM2B_DATA& outside_info, const TPML_PCR_SELECTION& creation_pcr,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_CreatePrimary. Parses the response from a
+// TPM2_CreatePrimary command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_CreatePrimary(
+    const std::string& response, TPM_HANDLE& object_handle,
+    TPM2B_PUBLIC& out_public, TPM2B_CREATION_DATA& creation_data,
+    TPM2B_DIGEST& creation_hash, TPMT_TK_CREATION& creation_ticket,
+    std::string& name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_Load. Serializes the TPM2_Load command.
+// in_public should be in serialized form (as there is no direct string ->
+// TPM2B_PUBLIC conversion in tpm_generated other than parsing).
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_Load(
+    const TPMI_DH_OBJECT& parent_handle, const std::string& parent_handle_name,
+    const std::string& in_private, const std::string& in_public,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_Load. Parses the response from a TPM2_Load command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_Load(
+    const std::string& response, TPM_HANDLE& object_handle, std::string& name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_NV_Certify. Serializes the TPM2_NV_Certify
+// command.
+// The authorization_delegate argument was removed because NV_Certify requires
+// two authorizations, and adding MultipleAuthorizations to the CXX bridge would
+// require putting a lifetime argument on AuthorizationDelegate, which would
+// propagate everywhere. Instead, this is hardcoded to use empty password
+// authorization.
+TPM_RC SerializeCommand_NV_Certify(
+    const TPMI_DH_OBJECT& sign_handle, const std::string& sign_handle_name,
+    const TPMI_RH_NV_AUTH& auth_handle, const std::string& auth_handle_name,
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    const TPM2B_DATA& qualifying_data, const TPMT_SIG_SCHEME& in_scheme,
+    const UINT16& size, const UINT16& offset, std::string& serialized_command);
+
+// Wraps Tpm::ParseResponse_NV_Certify. Parses the response from a
+// TPM2_NV_Certify command.
+// authorization_delegate was omitted for the same reason as
+// SerializeCommand_NV_Certify.
+TPM_RC ParseResponse_NV_Certify(const std::string& response,
+                                std::string& certify_info,
+                                std::string& signature);
+
+// Wraps Tpm::SerializeCommand_NV_Read. Serializes the TPM2_NV_Read command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_NV_Read(
+    const TPMI_RH_NV_AUTH& auth_handle, const std::string& auth_handle_name,
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    const UINT16& size, const UINT16& offset, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_NV_Read. Parses the response of a TPM2_NV_Read
+// command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_NV_Read(
+    const std::string& response, std::string& data,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_NV_ReadPublic. Serializes the TPM2_NV_ReadPublic
+// command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_NV_ReadPublic(
+    const TPMI_RH_NV_INDEX& nv_index, const std::string& nv_index_name,
+    std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_NV_ReadPublic. Parses the response from a
+// TPM2_NV_ReadPublic command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_NV_ReadPublic(
+    const std::string& response, uint16_t& nv_public_data_size,
+    std::string& nv_name,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_Quote. Serializes the TPM2_Quote command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_Quote(
+    const TPMI_DH_OBJECT& sign_handle, const std::string& sign_handle_name,
+    const TPM2B_DATA& qualifying_data, const TPMT_SIG_SCHEME& in_scheme,
+    const TPML_PCR_SELECTION& pcrselect, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_Quote. Parses the response from a TPM2_Quote
+// command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_Quote(
+    const std::string& response, std::string& quoted, std::string& signature,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::SerializeCommand_PCR_Read. Serializes the TPM2_PCR_Read command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_PCR_Read(
+    const TPML_PCR_SELECTION& pcr_selection_in, std::string& serialized_command,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_PCR_Read. Parses the response from a TPM2_PCR_Read
+// command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_PCR_Read(
+    const std::string& response, UINT32& pcr_update_counter,
+    TPML_PCR_SELECTION& pcr_selection_out, std::string& pcr_values,
+    const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// -----------------------------------------------------------------------------
+// TPM_HANDLE
+// -----------------------------------------------------------------------------
+
+// Returns a serialized representation of the unmodified handle. This is useful
+// for predefined handle values, like TPM_RH_OWNER. For details on what types of
+// handles use this name formula see Table 3 in the TPM 2.0 Library Spec Part 1
+// (Section 16 - Names).
+std::unique_ptr<std::string> NameFromHandle(const TPM_HANDLE& handle);
+
+// -----------------------------------------------------------------------------
+// TPM2B_CREATION_DATA
+// -----------------------------------------------------------------------------
+
+// Creates a new empty TPM2B_CREATION_DATA.
+std::unique_ptr<TPM2B_CREATION_DATA> TPM2B_CREATION_DATA_New();
+
+// -----------------------------------------------------------------------------
+// TPM2B_DATA
+// -----------------------------------------------------------------------------
+
+// Creates a TPM2B_DATA with the given data.
+std::unique_ptr<TPM2B_DATA> TPM2B_DATA_New(const std::string& bytes);
+
+// -----------------------------------------------------------------------------
+// TPM2B_DIGEST
+// -----------------------------------------------------------------------------
+
+// Creates a new empty TPM2B_DIGEST.
+std::unique_ptr<TPM2B_DIGEST> TPM2B_DIGEST_New();
+
+// -----------------------------------------------------------------------------
+// TPM2B_PUBLIC
+// -----------------------------------------------------------------------------
+
+// Returns the public area template for the Attestation Identity Key.
+std::unique_ptr<TPM2B_PUBLIC> AttestationIdentityKeyTemplate();
+
+// Returns the public area template for the Storage Root Key.
+std::unique_ptr<TPM2B_PUBLIC> StorageRootKeyTemplate();
+
+// Converts a serialized TPM2B_PUBLIC (as returned by ParseResponse_Create) into
+// a serialized TPMT_PUBLIC (as required by the attestation CA).
+TPM_RC Tpm2bPublicToTpmtPublic(const std::string& tpm2b_public,
+                               std::string& tpmt_public);
+
+// -----------------------------------------------------------------------------
+// TPM2B_SENSITIVE_CREATE
+// -----------------------------------------------------------------------------
+
+// Creates a TPM2B_SENSITIVE_CREATE with the given auth and data values.
+std::unique_ptr<TPM2B_SENSITIVE_CREATE> TPM2B_SENSITIVE_CREATE_New(
+    const std::string& user_auth, const std::string& data);
+
+// -----------------------------------------------------------------------------
+// TPML_PCR_SELECTION
+// -----------------------------------------------------------------------------
+
+// Returns an empty PCR selection list.
+std::unique_ptr<TPML_PCR_SELECTION> EmptyPcrSelection();
+
+// Returns a PCR selection list that selects a single PCR, or nullptr if the pcr
+// number is too large.
+std::unique_ptr<TPML_PCR_SELECTION> SinglePcrSelection(uint8_t pcr);
+
+// -----------------------------------------------------------------------------
+// TPMT_SIG_SCHEME
+// -----------------------------------------------------------------------------
+
+// Creates a TPMT_SIGN_SCHEME with hash algorithm SHA-256 and signature
+// algorithm ECDSA.
+std::unique_ptr<TPMT_SIG_SCHEME> Sha256EcdsaSigScheme();
+
+// -----------------------------------------------------------------------------
+// TPMT_TK_CREATION
+// -----------------------------------------------------------------------------
+
+// Creates a new, empty TPMT_TK_CREATION.
+std::unique_ptr<TPMT_TK_CREATION> TPMT_TK_CREATION_New();
+
+}  // namespace trunks
+
+#endif  // TPM_GENERATED_FFI_H_
diff --git a/tpm_generated/lib.rs b/tpm_generated/lib.rs
new file mode 100644
index 000000000..1a9583eb5
--- /dev/null
+++ b/tpm_generated/lib.rs
@@ -0,0 +1,291 @@
+// Copyright 2024 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+//! TPM command encoding/decoding library.
+
+use cxx::{let_cxx_string, UniquePtr};
+use std::fmt::{self, Display, Formatter, Write};
+use std::num::NonZeroU32;
+
+pub use trunks::*;
+
+#[allow(clippy::too_many_arguments)]
+#[cxx::bridge(namespace = "trunks")]
+pub mod trunks {
+    unsafe extern "C++" {
+        include!("authorization_delegate.h");
+
+        type AuthorizationDelegate;
+
+        include!("tpm_generated.h");
+
+        type TPM2B_CREATION_DATA;
+        type TPM2B_DATA;
+        type TPM2B_DIGEST;
+        type TPM2B_PUBLIC;
+        type TPM2B_SENSITIVE_CREATE;
+        type TPMT_SIG_SCHEME;
+        type TPML_PCR_SELECTION;
+        type TPMT_TK_CREATION;
+
+        include!("ffi.h");
+
+        /// Encrypts data for an attestation CA. The CA's public key is passed
+        /// in as an input. The output values correspond to the EncryptedData
+        /// protobuf in attestation_ca.proto. Returns true on success and false
+        /// on failure.
+        fn EncryptDataForCa(
+            data: &CxxString,
+            public_key_hex: &CxxString,
+            key_id: &CxxString,
+            wrapped_key: Pin<&mut CxxString>,
+            iv: Pin<&mut CxxString>,
+            mac: Pin<&mut CxxString>,
+            encrypted_data: Pin<&mut CxxString>,
+            wrapping_key_id: Pin<&mut CxxString>,
+        ) -> bool;
+
+        /// Constructs a new PasswordAuthorizationDelegate with the given
+        /// password.
+        fn PasswordAuthorizationDelegate_New(
+            password: &CxxString,
+        ) -> UniquePtr<AuthorizationDelegate>;
+
+        /// See Tpm::SerializeCommand_Create for docs.
+        fn SerializeCommand_Create(
+            parent_handle: &u32,
+            parent_handle_name: &CxxString,
+            in_sensitive: &TPM2B_SENSITIVE_CREATE,
+            in_public: &TPM2B_PUBLIC,
+            outside_info: &TPM2B_DATA,
+            creation_pcr: &TPML_PCR_SELECTION,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_Create for docs.
+        fn ParseResponse_Create(
+            response: &CxxString,
+            out_private: Pin<&mut CxxString>,
+            out_public: Pin<&mut CxxString>,
+            creation_data: Pin<&mut TPM2B_CREATION_DATA>,
+            creation_hash: Pin<&mut TPM2B_DIGEST>,
+            creation_ticket: Pin<&mut TPMT_TK_CREATION>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_CreatePrimary for docs.
+        fn SerializeCommand_CreatePrimary(
+            primary_handle: &u32,
+            primary_handle_name: &CxxString,
+            in_sensitive: &TPM2B_SENSITIVE_CREATE,
+            in_public: &TPM2B_PUBLIC,
+            outside_info: &TPM2B_DATA,
+            creation_pcr: &TPML_PCR_SELECTION,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_CreatePrimary for docs.
+        fn ParseResponse_CreatePrimary(
+            response: &CxxString,
+            object_handle: Pin<&mut u32>,
+            out_public: Pin<&mut TPM2B_PUBLIC>,
+            creation_data: Pin<&mut TPM2B_CREATION_DATA>,
+            creation_hash: Pin<&mut TPM2B_DIGEST>,
+            creation_ticket: Pin<&mut TPMT_TK_CREATION>,
+            name: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_Load for docs.
+        fn SerializeCommand_Load(
+            parent_handle: &u32,
+            parent_handle_name: &CxxString,
+            in_private: &CxxString,
+            in_public: &CxxString,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_Load for docs.
+        fn ParseResponse_Load(
+            response: &CxxString,
+            object_handle: Pin<&mut u32>,
+            name: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_NV_Certify for docs.
+        fn SerializeCommand_NV_Certify(
+            sign_handle: &u32,
+            sign_handle_name: &CxxString,
+            auth_handle: &u32,
+            auth_handle_name: &CxxString,
+            nv_index: &u32,
+            nv_index_name: &CxxString,
+            qualifying_data: &TPM2B_DATA,
+            in_scheme: &TPMT_SIG_SCHEME,
+            size: &u16,
+            offset: &u16,
+            serialized_command: Pin<&mut CxxString>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_NV_Certify for docs.
+        fn ParseResponse_NV_Certify(
+            response: &CxxString,
+            certify_info: Pin<&mut CxxString>,
+            signature: Pin<&mut CxxString>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_NV_Read for docs.
+        fn SerializeCommand_NV_Read(
+            auth_handle: &u32,
+            auth_handle_name: &CxxString,
+            nv_index: &u32,
+            nv_index_name: &CxxString,
+            size: &u16,
+            offset: &u16,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_NV_Read for docs.
+        fn ParseResponse_NV_Read(
+            response: &CxxString,
+            data: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_NV_ReadPublic for docs.
+        fn SerializeCommand_NV_ReadPublic(
+            nv_index: &u32,
+            nv_index_name: &CxxString,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_NV_ReadPublic for docs.
+        fn ParseResponse_NV_ReadPublic(
+            response: &CxxString,
+            nv_public_data_size: &mut u16,
+            nv_name: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_Quote for docs.
+        fn SerializeCommand_Quote(
+            sign_handle: &u32,
+            sign_handle_name: &CxxString,
+            qualifying_data: &TPM2B_DATA,
+            in_scheme: &TPMT_SIG_SCHEME,
+            pcrselect: &TPML_PCR_SELECTION,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_Quote for docs.
+        fn ParseResponse_Quote(
+            response: &CxxString,
+            quoted: Pin<&mut CxxString>,
+            signature: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::SerializeCommand_PCR_Read for docs.
+        fn SerializeCommand_PCR_Read(
+            pcr_selection_id: &TPML_PCR_SELECTION,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_PCR_Read for docs.
+        fn ParseResponse_PCR_Read(
+            response: &CxxString,
+            pcr_update_counter: &mut u32,
+            pcr_selection_out: Pin<&mut TPML_PCR_SELECTION>,
+            pcr_values: Pin<&mut CxxString>,
+            authorization_delegate: &UniquePtr<AuthorizationDelegate>,
+        ) -> u32;
+
+        /// Returns a serialized representation of the unmodified handle. This
+        /// is useful for predefined handle values, like TPM_RH_OWNER. For
+        /// details on what types of handles use this name formula see Table 3
+        /// in the TPM 2.0 Library Spec Part 1 (Section 16 - Names).
+        fn NameFromHandle(handle: &u32) -> UniquePtr<CxxString>;
+
+        /// Creates a new empty TPM2B_CREATION_DATA.
+        fn TPM2B_CREATION_DATA_New() -> UniquePtr<TPM2B_CREATION_DATA>;
+
+        /// Creates a TPM2B_DATA with the given data.
+        fn TPM2B_DATA_New(bytes: &CxxString) -> UniquePtr<TPM2B_DATA>;
+
+        /// Creates a new empty TPM2B_DIGEST.
+        fn TPM2B_DIGEST_New() -> UniquePtr<TPM2B_DIGEST>;
+
+        /// Returns the public area template for the Attestation Identity Key.
+        fn AttestationIdentityKeyTemplate() -> UniquePtr<TPM2B_PUBLIC>;
+
+        /// Returns the public area template for the Storage Root Key.
+        fn StorageRootKeyTemplate() -> UniquePtr<TPM2B_PUBLIC>;
+
+        /// Converts a serialized TPM2B_PUBLIC (as returned by
+        /// ParseResponse_Create) into a serialized TPMT_PUBLIC (as required by
+        /// the attestation CA).
+        fn Tpm2bPublicToTpmtPublic(
+            tpm2b_public: &CxxString,
+            tpmt_public: Pin<&mut CxxString>,
+        ) -> u32;
+
+        /// Creates a new TPM2B_SENSITIVE_CREATE with the given auth and data
+        /// values.
+        fn TPM2B_SENSITIVE_CREATE_New(
+            user_auth: &CxxString,
+            data: &CxxString,
+        ) -> UniquePtr<TPM2B_SENSITIVE_CREATE>;
+
+        /// Returns an empty PCR selection list.
+        fn EmptyPcrSelection() -> UniquePtr<TPML_PCR_SELECTION>;
+
+        /// Returns a PCR selection list that selects a single PCR.
+        fn SinglePcrSelection(pcr: u8) -> UniquePtr<TPML_PCR_SELECTION>;
+
+        /// Creates a TPMT_SIGN_SCHEME with hash algorithm SHA-256 and signature
+        /// algorithm ECDSA.
+        fn Sha256EcdsaSigScheme() -> UniquePtr<TPMT_SIG_SCHEME>;
+
+        /// Makes an empty TPMT_TK_CREATION;
+        fn TPMT_TK_CREATION_New() -> UniquePtr<TPMT_TK_CREATION>;
+    }
+}
+
+/// An error code returned by a Tpm method.
+#[derive(Debug)]
+pub struct TpmError {
+    return_code: NonZeroU32,
+}
+
+impl TpmError {
+    /// Creates a TpmError for the given return code, or None if this is a
+    /// successful code.
+    pub fn from_tpm_return_code(return_code: u32) -> Option<TpmError> {
+        Some(TpmError { return_code: NonZeroU32::new(return_code)? })
+    }
+}
+
+impl Display for TpmError {
+    fn fmt(&self, f: &mut Formatter) -> Result<(), fmt::Error> {
+        write!(f, "{:#x}", self.return_code)
+    }
+}
+
+/// Converts the given byte array into a hex string (intended for debug prints).
+pub fn bytes_to_hex(bytes: &[u8]) -> String {
+    let expected_len = 2 * bytes.len();
+    let mut out = String::with_capacity(expected_len);
+    for b in bytes {
+        write!(out, "{:02x}", b).unwrap();
+    }
+    out
+}
diff --git a/tpm_generated/multiple_authorization_delegate.cc b/tpm_generated/multiple_authorization_delegate.cc
new file mode 100644
index 000000000..af459315c
--- /dev/null
+++ b/tpm_generated/multiple_authorization_delegate.cc
@@ -0,0 +1,80 @@
+// Copyright 2023 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "multiple_authorization_delegate.h"
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+
+namespace trunks {
+
+void MultipleAuthorizations::AddAuthorizationDelegate(
+    AuthorizationDelegate* delegate) {
+  delegates_.push_back(delegate);
+}
+
+bool MultipleAuthorizations::GetCommandAuthorization(
+    const std::string& command_hash,
+    bool is_command_parameter_encryption_possible,
+    bool is_response_parameter_encryption_possible,
+    std::string* authorization) {
+  std::string combined_authorization;
+  for (auto delegate : delegates_) {
+    std::string authorization;
+    if (!delegate->GetCommandAuthorization(
+            command_hash, is_command_parameter_encryption_possible,
+            is_response_parameter_encryption_possible, &authorization)) {
+      return false;
+    }
+    combined_authorization += authorization;
+  }
+  *authorization = combined_authorization;
+  return true;
+}
+
+bool MultipleAuthorizations::CheckResponseAuthorization(
+    const std::string& response_hash, const std::string& authorization) {
+  std::string mutable_authorization = authorization;
+  for (auto delegate : delegates_) {
+    if (!delegate->CheckResponseAuthorization(
+            response_hash,
+            ExtractSingleAuthorizationResponse(&mutable_authorization))) {
+      return false;
+    }
+  }
+  return true;
+}
+
+bool MultipleAuthorizations::EncryptCommandParameter(std::string* parameter) {
+  for (auto delegate : delegates_) {
+    if (!delegate->EncryptCommandParameter(parameter)) {
+      return false;
+    }
+  }
+  return true;
+}
+
+bool MultipleAuthorizations::DecryptResponseParameter(std::string* parameter) {
+  for (auto delegate : delegates_) {
+    if (!delegate->DecryptResponseParameter(parameter)) {
+      return false;
+    }
+  }
+  return true;
+}
+
+bool MultipleAuthorizations::GetTpmNonce(std::string* nonce) { return false; }
+
+std::string MultipleAuthorizations::ExtractSingleAuthorizationResponse(
+    std::string* all_responses) {
+  std::string response;
+  trunks::TPMS_AUTH_RESPONSE not_used;
+  if (TPM_RC_SUCCESS !=
+      Parse_TPMS_AUTH_RESPONSE(all_responses, &not_used, &response)) {
+    return std::string();
+  }
+  return response;
+}
+
+}  // namespace trunks
diff --git a/tpm_generated/multiple_authorization_delegate.h b/tpm_generated/multiple_authorization_delegate.h
new file mode 100644
index 000000000..e5b948c84
--- /dev/null
+++ b/tpm_generated/multiple_authorization_delegate.h
@@ -0,0 +1,46 @@
+// Copyright 2023 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef TRUNKS_MULTIPLE_AUTHORIZATION_DELEGATE_H_
+#define TRUNKS_MULTIPLE_AUTHORIZATION_DELEGATE_H_
+
+#include <string>
+#include <vector>
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+#include "trunks_export.h"
+
+namespace trunks {
+
+// An authorization delegate to manage multiple authorization sessions for a
+// single command.
+class TRUNKS_EXPORT MultipleAuthorizations : public AuthorizationDelegate {
+ public:
+  MultipleAuthorizations() = default;
+  ~MultipleAuthorizations() override = default;
+
+  // AuthorizationDelegate methods.
+  bool GetCommandAuthorization(const std::string& command_hash,
+                               bool is_command_parameter_encryption_possible,
+                               bool is_response_parameter_encryption_possible,
+                               std::string* authorization) override;
+  bool CheckResponseAuthorization(const std::string& response_hash,
+                                  const std::string& authorization) override;
+  bool EncryptCommandParameter(std::string* parameter) override;
+  bool DecryptResponseParameter(std::string* parameter) override;
+  bool GetTpmNonce(std::string* nonce) override;
+
+  // Adds an authrization delegate.
+  void AddAuthorizationDelegate(AuthorizationDelegate* delegate);
+
+ private:
+  std::string ExtractSingleAuthorizationResponse(std::string* all_responses);
+
+  std::vector<AuthorizationDelegate*> delegates_;
+};
+
+}  // namespace trunks
+
+#endif  // TRUNKS_MULTIPLE_AUTHORIZATION_DELEGATE_H_
diff --git a/tpm_generated/password_authorization_delegate.cc b/tpm_generated/password_authorization_delegate.cc
new file mode 100644
index 000000000..bdea97e32
--- /dev/null
+++ b/tpm_generated/password_authorization_delegate.cc
@@ -0,0 +1,85 @@
+// Copyright 2014 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "password_authorization_delegate.h"
+
+#include <android-base/logging.h>
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+
+namespace trunks {
+
+PasswordAuthorizationDelegate::PasswordAuthorizationDelegate(
+    const std::string& password) {
+  password_ = Make_TPM2B_DIGEST(password);
+}
+
+PasswordAuthorizationDelegate::~PasswordAuthorizationDelegate() {}
+
+bool PasswordAuthorizationDelegate::GetCommandAuthorization(
+    const std::string& command_hash,
+    bool is_command_parameter_encryption_possible,
+    bool is_response_parameter_encryption_possible,
+    std::string* authorization) {
+  TPMS_AUTH_COMMAND auth;
+  auth.session_handle = TPM_RS_PW;
+  auth.nonce.size = 0;
+  auth.session_attributes = kContinueSession;
+  auth.hmac = password_;
+
+  TPM_RC serialize_error = Serialize_TPMS_AUTH_COMMAND(auth, authorization);
+  if (serialize_error != TPM_RC_SUCCESS) {
+    LOG(ERROR) << __func__ << ": could not serialize command auth.";
+    return false;
+  }
+  return true;
+}
+
+bool PasswordAuthorizationDelegate::CheckResponseAuthorization(
+    const std::string& response_hash, const std::string& authorization) {
+  TPMS_AUTH_RESPONSE auth_response;
+  std::string mutable_auth_string(authorization);
+  std::string auth_bytes;
+  TPM_RC parse_error;
+  parse_error = Parse_TPMS_AUTH_RESPONSE(&mutable_auth_string, &auth_response,
+                                         &auth_bytes);
+  if (authorization.size() != auth_bytes.size()) {
+    LOG(ERROR) << __func__ << ": Authorization string was of wrong length.";
+    return false;
+  }
+  if (parse_error != TPM_RC_SUCCESS) {
+    LOG(ERROR) << __func__ << ": could not parse authorization response.";
+    return false;
+  }
+  if (auth_response.nonce.size != 0) {
+    LOG(ERROR) << __func__ << ": received a non zero length nonce.";
+    return false;
+  }
+  if (auth_response.hmac.size != 0) {
+    LOG(ERROR) << __func__ << ": received a non zero length hmac.";
+    return false;
+  }
+  if (auth_response.session_attributes != kContinueSession) {
+    LOG(ERROR) << __func__ << ": received wrong session attributes.";
+    return false;
+  }
+  return true;
+}
+
+bool PasswordAuthorizationDelegate::EncryptCommandParameter(
+    std::string* parameter) {
+  return true;
+}
+
+bool PasswordAuthorizationDelegate::DecryptResponseParameter(
+    std::string* parameter) {
+  return true;
+}
+
+bool PasswordAuthorizationDelegate::GetTpmNonce(std::string* nonce) {
+  return false;
+}
+
+}  // namespace trunks
diff --git a/tpm_generated/password_authorization_delegate.h b/tpm_generated/password_authorization_delegate.h
new file mode 100644
index 000000000..b0a3faf75
--- /dev/null
+++ b/tpm_generated/password_authorization_delegate.h
@@ -0,0 +1,47 @@
+// Copyright 2014 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef TRUNKS_PASSWORD_AUTHORIZATION_DELEGATE_H_
+#define TRUNKS_PASSWORD_AUTHORIZATION_DELEGATE_H_
+
+#include <string>
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+#include "trunks_export.h"
+
+namespace trunks {
+
+// PasswdAuthorizationDelegate is an implementation of the AuthorizationDelegate
+// interface. This delegate is used for password based authorization. Upon
+// initialization of this delegate, we feed in the plaintext password. This
+// password is then used to authorize the commands issued with this delegate.
+// This delegate performs no parameter encryption.
+class TRUNKS_EXPORT PasswordAuthorizationDelegate
+    : public AuthorizationDelegate {
+ public:
+  explicit PasswordAuthorizationDelegate(const std::string& password);
+  PasswordAuthorizationDelegate(const PasswordAuthorizationDelegate&) = delete;
+  PasswordAuthorizationDelegate& operator=(
+      const PasswordAuthorizationDelegate&) = delete;
+
+  ~PasswordAuthorizationDelegate() override;
+  // AuthorizationDelegate methods.
+  bool GetCommandAuthorization(const std::string& command_hash,
+                               bool is_command_parameter_encryption_possible,
+                               bool is_response_parameter_encryption_possible,
+                               std::string* authorization) override;
+  bool CheckResponseAuthorization(const std::string& response_hash,
+                                  const std::string& authorization) override;
+  bool EncryptCommandParameter(std::string* parameter) override;
+  bool DecryptResponseParameter(std::string* parameter) override;
+  bool GetTpmNonce(std::string* nonce) override;
+
+ private:
+  TPM2B_AUTH password_;
+};
+
+}  // namespace trunks
+
+#endif  // TRUNKS_PASSWORD_AUTHORIZATION_DELEGATE_H_
diff --git a/tpm_generated/tpm_generated.cc b/tpm_generated/tpm_generated.cc
index b4ff3e122..3de90515e 100644
--- a/tpm_generated/tpm_generated.cc
+++ b/tpm_generated/tpm_generated.cc
@@ -20,7 +20,11 @@
 #include "error_codes.h"
 
 // Redirect VLOG invocations written for libchrome to android-base's LOG macro.
-#define VLOG(x) LOG(INFO)
+// The severities are not compatible with each other (e.g. libchrome's INFO is 0
+// but android-base's is 2), so we drop the severity information. This code can
+// generate tons of output so we map everything to VERBOSE so it can easily be
+// filtered out.
+#define VLOG(x) LOG(VERBOSE)
 
 namespace trunks {
 
diff --git a/util/convert_signing_json.sh b/util/convert_signing_json.sh
new file mode 100755
index 000000000..68f4a6e60
--- /dev/null
+++ b/util/convert_signing_json.sh
@@ -0,0 +1,32 @@
+#!/bin/bash
+# Copyright 2025 The ChromiumOS Authors
+# Use of this source code is governed by a BSD-style license that can be
+# found in the LICENSE file.
+
+# This script lets you sanitize the signing json file. It removes the comments
+# and extra whitespace from the manifest.
+
+# Two command line parameters are required, the input json and the path
+# to store the sanitized file.
+
+set -ue
+
+# Sanatize the manifest
+main () {
+  local manifest="${1}"
+  local output="${2}"
+
+  if [[ -f ${manifest} ]] ; then
+    echo "sanitizing ${manifest}"
+  else
+    echo "${manifest} not found" >&2
+    exit 1
+  fi
+  if [[ -z ${output} ]] ; then
+    echo "supply MANIFEST OUTPUT_FILE" >&2
+    exit 1
+  fi
+  echo $(sed 's|\s*//.*$||g; /^\s*$/d' "${manifest}") > "${output}"
+}
+
+main "$@"
diff --git a/util/re-sign-gsc.sh b/util/re-sign-gsc.sh
index 1370c7881..3b763f69b 100755
--- a/util/re-sign-gsc.sh
+++ b/util/re-sign-gsc.sh
@@ -9,25 +9,34 @@
 # present in the respective ./build directory.
 #
 # Two command line parameters are required, the device IDs of the GSC.
+# The image to re-sign can be supplied as an optional third param.
 #
 # The generated binary is saved in {cr,ti}50.<sha>.<devid0>.<devid1>.bin where
-# <sha> is the git sha of the current source tree. The suffix '-dirty' is
-# added to the <sha> component in case there are changes in any of the files
-# under git control.
+# <sha> is the git sha of the original image. The suffix '-dirty' is added to
+# the <sha> component if "+" is in the {cr,ti}50 version string. "+" means that
+# there were changes in some of the files under git control when the original
+# image was built.
 
 set -ue
 
 SCRIPT_NAME="$(basename "$0")"
+SCRIPT_DIR="$(dirname "$0")"
 TMPD="$(mktemp -d "/tmp/${SCRIPT_NAME}.XXXXX")"
 NOCLEAN="${NOCLEAN:-}"
 if [[ -z ${NOCLEAN} ]]; then
   trap 'rm -rf "${TMPD}"' EXIT
 fi
 
+# PKCS11 connector library needed for codesigner to access keys in Cloud KMS.
+PKCS11_MODULE_PATH="/usr/lib64/libkmsp11.so"
+
+# Cloud KMS path to the location of the GSC signing keys.
+KMS_PROJECT_PATH="projects/gsc-cloud-kms-signing/locations/us/keyRings/gsc-node-locked-signing-keys/cryptoKeys"
+
 # Make sure there is a codesigner in the path.
 CODESIGNER=""
 for f in  cr50-codesigner \
-            ../../cr50-utils/software/tools/codesigner/codesigner \
+            "${SCRIPT_DIR}/../../cr50-utils/software/tools/codesigner/codesigner" \
             codesigner; do
   if command -v "${f}" > /dev/null 2>&1; then
     CODESIGNER="${f}"
@@ -39,6 +48,42 @@ if [[ -z ${CODESIGNER} ]]; then
   exit 1
 fi
 
+# Make sure there is a gsctool in the path.
+GSCTOOL=""
+for f in  gsctool \
+	    "${SCRIPT_DIR}/../extra/usb_updater/gsctool"; do
+  if command -v "${f}" > /dev/null 2>&1; then
+    GSCTOOL="${f}"
+    break
+  fi
+done
+if [[ -z ${GSCTOOL} ]]; then
+  echo "SCRIPT_NAME error: can't find gsctool" >&2
+  exit 1
+fi
+
+# Update the manifest
+update_manifest() {
+  local full_bin="${1}"
+  local manifest="${2}"
+  local epoch
+  local major
+  local minor
+  local rw_ver
+
+  # Remove the board id and info rollback bits.
+  sed -i -zE 's/"board_[^,]+,\s*//g;s/"info"[^}]+},\s*/"info": { },/' \
+	  "${manifest}"
+
+  rw_ver="$("${GSCTOOL}" "-M" "-b" "${full_bin}" | \
+	  awk -F= '/IMAGE_RW_FW_VER/ {print $2}')"
+  IFS='.' read -r epoch major minor <<<"${rw_ver}"
+  echo "RW: ${rw_ver}"
+  sed "s/epoch\": [0-9]*/epoch\": ${epoch}/" "${manifest}" -i
+  sed "s/major\": [0-9]*/major\": ${major}/" "${manifest}" -i
+  sed "s/minor\": [0-9]*/minor\": ${minor}/" "${manifest}" -i
+}
+
 # Re-sign a single RW section.
 re_sign_rw() {
   local tmp_file="$1"
@@ -89,37 +134,50 @@ main () {
   local dev_id1
   local flash_base
   local full_bin
+  local gsc_dir
   local manifest
   local output
   local prefix
   local rw_a_base
   local rw_b_base
   local rw_key
+  local rw_ver
   local sha
   local tmp_file
   local xml
 
-  if [[ $# -ne 2 ]]; then
+  full_bin=""
+  if [[ $# -eq 3 ]]; then
+    full_bin="$3"
+  elif [[ $# -ne 2 ]]; then
     echo "${SCRIPT_NAME} error:" >&2
     echo " Two command line arguments are required, dev_id0 and dev_id1" >&2
+    echo " The image path is an optional third argument" >&2
     exit 1
   fi
 
   dev_id0="$1"
   dev_id1="$2"
 
-  full_bin=""
-  for f in  build/ti50/dauntless/dauntless/full_image.signed.bin \
-    build/cr50/ec.bin; do
-    if [[ -f ${f} ]]; then
-      full_bin="${f}"
-      break
+  if [[ -z ${full_bin} ]] ; then
+    for f in  build/ti50/dauntless/dauntless/full_image.signed.bin \
+      build/cr50/ec.bin; do
+      if [[ -f ${f} ]]; then
+        full_bin="${f}"
+        break
+      fi
+    done
+    if [[ -z ${full_bin} ]]; then
+      echo "${SCRIPT_NAME} error: GSC binary not found" >&2
+      exit 1
+    fi
+  else
+    if [[ -f ${full_bin} ]] ; then
+      echo "resigning supplied bin ${full_bin}"
+    else
+      echo "could not find ${full_bin}"
+      exit 1
     fi
-  done
-
-  if [[ -z ${full_bin} ]]; then
-    echo "${SCRIPT_NAME} error: GSC binary not found" >&2
-    exit 1
   fi
 
   codesigner_params=(
@@ -136,12 +194,18 @@ main () {
   case "${bin_size}" in
     (524288) rw_a_base=16384 # RO area size is fixed at 16K
              rw_b_base=$(( bin_size / 2 + rw_a_base ))
-             rw_key="util/signer/cr50_rom0-dev-blsign.pem.pub"
-             manifest="util/signer/ec_RW-manifest-dev.json"
-             xml="util/signer/fuses.xml"
-             codesigner_params+=( --b )
+             gsc_dir="${SCRIPT_DIR}/../../cr50"
+	     key_name="cr50-hsm-backed-node-locked-key"
+             rw_key="${gsc_dir}/util/signer/${key_name}.pem.pub"
+             manifest="${gsc_dir}/util/signer/ec_RW-manifest-dev.json"
+             xml="${gsc_dir}/util/signer/fuses.xml"
+             codesigner_params+=(
+               --b
+               --pkcs11_engine="${PKCS11_MODULE_PATH}:0:${KMS_PROJECT_PATH}/${key_name}/cryptoKeyVersions/1"
+             )
              flash_base=262144
              prefix="cr50"
+             KMS_PKCS11_CONFIG="$(readlink -f "${gsc_dir}/chip/g/config.yaml")"
              ;;
     (1048576) local rw_bases
               # Third and sixths lines showing signed header magic are base
@@ -155,22 +219,31 @@ main () {
                    }')
               rw_a_base="${rw_bases[0]}"
               rw_b_base="${rw_bases[1]}"
-              rw_key="ports/dauntless/signing/ti50_dev.key"
-              manifest="ports/dauntless/signing/manifest.TOT.json"
-              xml="ports/dauntless/signing/fuses.xml"
-              codesigner_params+=( --dauntless )
+              gsc_dir="${SCRIPT_DIR}/../../ti50/common"
+              rw_key="${gsc_dir}/ports/dauntless/signing/ti50_dev.key"
+              manifest="${gsc_dir}/ports/dauntless/signing/manifest.TOT.json"
+              xml="${gsc_dir}/ports/dauntless/signing/fuses.xml"
+              codesigner_params+=(
+                --dauntless
+                --pkcs11_engine="${PKCS11_MODULE_PATH}:0:${KMS_PROJECT_PATH}/ti50-node-locked-key/cryptoKeyVersions/1"
+              )
               flash_base=524288
               prefix="ti50"
+              KMS_PKCS11_CONFIG="$(readlink -f "${gsc_dir}/ports/dauntless/config.yaml")"
               ;;
     (*) echo "What is ${full_bin}?" >&2
         exit 1
         ;;
   esac
 
-  # Determine the current git tree state. This would match the binary image's
-  # version string if it was built from this tree.
-  sha="$(git rev-parse --short HEAD)"
-  if git status --porcelain 2>&1 | grep -qv '^ *?'; then
+  # Extract the sha from the original image version string. Find the version
+  # string from the image. Use the sha from the ti50 or cr50 repo.
+  rw_ver="$(strings "${full_bin}" | grep -m 1 "${prefix}_.*tpm" | \
+	  sed -E "s/.*(${prefix}\S*).*/\1/")"
+  sha="${rw_ver/*[-+]/}"
+  # If the rw version contains a "+" then the repo was not clean when the image
+  # was built. Always re-sign these images.
+  if [[ "${rw_ver}" =~ \+ ]] ; then
     sha="${sha}-dirty"
   fi
 
@@ -189,13 +262,14 @@ main () {
     fi
   done
 
-  # Clean up the manifest.
-  sed -zE 's/"board_[^,]+,\s*//g;s/"info"[^}]+},\s*/"info": { },/' \
-      "${manifest}" > "${TMPD}/manifest.json"
-
   tmp_file="${TMPD}/full.bin"
   cp "${full_bin}" "${tmp_file}"
 
+  cp "${manifest}" "${TMPD}/manifest.json"
+  # Clear the board id and rollback info mask. Update the manifest to use
+  # the same version as the original image.
+  update_manifest "${tmp_file}" "${TMPD}/manifest.json"
+
   codesigner_params+=(
       --json "${TMPD}/manifest.json"
     --key "${rw_key}"
@@ -204,12 +278,15 @@ main () {
 
   echo "Re-signing a ${prefix} image"
 
+  export KMS_PKCS11_CONFIG
+
   re_sign_rw "${tmp_file}" "${flash_base}" "${rw_a_base}" \
              "${codesigner_params[@]}"
   re_sign_rw "${tmp_file}" "${flash_base}" "${rw_b_base}" \
              "${codesigner_params[@]}"
 
   cp "${tmp_file}" "${output}"
+  echo "signed image at ${output}"
 }
 
 main "$@"
```

