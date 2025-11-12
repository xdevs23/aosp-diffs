```diff
diff --git a/docs/ti50_firmware_releases.md b/docs/ti50_firmware_releases.md
index edfe300c2..93053894a 100644
--- a/docs/ti50_firmware_releases.md
+++ b/docs/ti50_firmware_releases.md
@@ -8,7 +8,9 @@ This document captures major feature differences between Ti50 firmware releases
 
 ChromeOS Version    | PrePVT version | Prod Version
 ------------------- | -------------- | ------------
-[ToT][ToT ebuild]   | 0.24.140       | 0.23.140
+[ToT][ToT ebuild]   | 0.24.160       | 0.23.160
+[M136][136 release] | 0.24.160       | 0.23.160
+[M135][135 release] | 0.24.160       | 0.23.140
 [M134][134 release] | 0.24.140       | 0.23.140
 [M133][133 release] | 0.24.140       | 0.23.122
 [M132][132 release] | 0.24.132       | 0.23.122
@@ -62,6 +64,7 @@ AP RO Verification Enforcement       | 0.24.61       | 0.23.71          | M122
 Reporting external WP assertion fix  | 0.24.131      | 0.23.140         | M133/M134
 Build uses Bazel artifacts           | 0.24.140      | 0.23.140         | M133/M134
 Support for NonInverted KSO          | 0.24.140      | 0.23.140         | M133/M134
+Boot param support                   | 0.24.160      | 0.23.160         | M135/M136
 
 # RO revisions
 
@@ -927,6 +930,40 @@ Build:   ti50_common_mp-15980.B:v0.0.245-247cf69f
          chrome-bot@chromeos-ci-firmware-us-central2-d-x32-1-5qj0 2025-01-02 08:45:08
 ```
 
+### 0.23.160 Released on 2025-03-13 in M136
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6324650)
+
+Builder
+[firmware-ti50-mp-15980.B-branch/49](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-mp-15980.B-branch/49/overview)
+
+Artifacts:
+[15980.46.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware/firmware-ti50-mp-15980.B-branch/R129-15980.46.0-1-8722404580531733729/)
+
+**Bug Fixes**
+
+*   Fix "Console Busy!" error
+    [b/375956711](https://b.corp.google.com/issues/375956711)
+
+**Features**
+
+*   Switch to ufmt for Ti50 console prints.
+    [b/286213031](https://b.corp.google.com/issues/286213031)
+*   Add TMPV monotonic counter
+    [b/376271752](https://b.corp.google.com/issues/376271752)
+*   Add DICE support
+    [b/365780607](https://b.corp.google.com/issues/365780607)
+
+```
+Build:   ti50_common_mp-15980.B:v0.0.328-7c83fd38
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9683-365e099a2
+         ms-tpm-20-ref:v0.0.325-f4283c6
+         chrome-bot@chromeos-ci-firmware-us-central1-b-x32-0-440b 2025-02-19 16:31:35
+```
+
+
 ## PrePVT images
 
 ### 0.22.0 Released 06/21/22
@@ -2026,7 +2063,7 @@ Build:   ti50_common_prepvt-15974.B:v0.0.207-e79f9ffc
          chrome-bot@chromeos-ci-firmware-us-east1-d-x32-1-9dga 2024-12-13 15:07:37
 ```
 
-### 0.24.140 Released on 2024-01-02 in M133
+### 0.24.140 Released on 2025-01-02 in M133
 
 Release
 [CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6136105)
@@ -2055,6 +2092,39 @@ Build:   ti50_common_prepvt-15974.B:v0.0.246-c837ddc5
          chrome-bot@chromeos-ci-firmware-us-central2-d-x32-1-41m2 2024-12-20 10:45:40
 ```
 
+### 0.24.160 Released on 2025-02-19 in M135
+
+Release
+[CL](https://chromium-review.googlesource.com/c/chromiumos/overlays/chromiumos-overlay/+/6281713)
+
+Builder
+[firmware-ti50-prepvt-15974.B-branch/50](https://ci.chromium.org/ui/p/chromeos/builders/firmware/firmware-ti50-prepvt-15974.B-branch/50/overview)
+
+Artifacts:
+[15974.50.0](https://pantheon.corp.google.com/storage/browser/chromeos-releases/firmware/firmware-ti50-prepvt-15974.B-branch/R129-15974.50.0-1-8723197558197525585/)
+
+**Bug Fixes**
+
+*   Fix "Console Busy!" error
+    [b/375956711](https://b.corp.google.com/issues/375956711)
+
+**Features**
+
+*   Switch to ufmt for Ti50 console prints.
+    [b/286213031](https://b.corp.google.com/issues/286213031)
+*   Add TMPV monotonic counter
+    [b/376271752](https://b.corp.google.com/issues/376271752)
+*   Add DICE support
+    [b/365780607](https://b.corp.google.com/issues/365780607)
+
+```
+Build:   ti50_common_prepvt-15974.B:v0.0.331-0cceb66e
+         libtock-rs:v0.0.925-1213708
+         tock:v0.0.9683-a16ba4f3b
+         ms-tpm-20-ref:v0.0.326-45d67aa
+         chrome-bot@chromeos-ci-firmware-us-central1-b-x32-0-be1m 2025-02-10 10:15:30
+```
+
 <!-- Links -->
 
 [105 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R105-14989.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
@@ -2087,4 +2157,6 @@ Build:   ti50_common_prepvt-15974.B:v0.0.246-c837ddc5
 [132 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R132-16093.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [133 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R133-16151.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [134 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R134-16181.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[135 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R135-16209.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
+[136 release]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/release-R136-16238.B/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
 [ToT ebuild]: https://chromium.googlesource.com/chromiumos/overlays/chromiumos-overlay/+/refs/heads/main/chromeos-base/chromeos-ti50/chromeos-ti50-0.0.1.ebuild
diff --git a/extra/usb_updater/gsctool.c b/extra/usb_updater/gsctool.c
index be8e8406e..a3e2e913c 100644
--- a/extra/usb_updater/gsctool.c
+++ b/extra/usb_updater/gsctool.c
@@ -517,6 +517,9 @@ static const struct option_container cmd_line_options[] = {
 	{ { "boot_trace", optional_argument, NULL, 'J' },
 	  "[erase]%Retrieve boot trace from the chip, optionally erasing "
 	  "the trace buffer" },
+	{ { "owner_config", no_argument, NULL, 'j' },
+	  "<binary image> is a 2kB blob containing new owners configuration,"
+	  " OpenTitan only" },
 	{ { "get_value", required_argument, NULL, 'K' },
 	  "[chassis_open|dev_ids]%Get properties values" },
 	{ { "ccd_lock", no_argument, NULL, 'k' }, "Lock CCD" },
@@ -1489,6 +1492,19 @@ static void pick_sections(struct transfer_descriptor *td, struct image *image)
 						sections[RO_B].offset;
 			if ((i == RW_B) == active_rw_slot_b)
 				continue;
+
+			/*
+			 * Block NT (Z1 -> A1) FW update by looking at version
+			 * numbers.
+			 * TODO(b/409779012): Remove this check after Q3 2025.
+			 */
+			if (targ.shv[1].major == 36 &&
+			    targ.shv[1].minor < 20 &&
+			    sections[i].shv.minor >= 20) {
+				printf("NT Z1 -> A1 transition blocked\n");
+				continue;
+			}
+
 			/*
 			 * Ok, this would be the RW section to transfer to the
 			 * device. Is it newer in the new image than the
@@ -1726,6 +1742,69 @@ static int supports_reordered_section_updates(struct signed_header_version *rw)
 	}
 }
 
+/*
+ * Owner configuration updates on the NT chip can be triggered by placing a
+ * properly signed ownership config blob into a certain INFO page on the
+ * device.
+ *
+ * The signed config blob is expected to be stored in the passed in file. This
+ * function always terminates the program with exit code indicating
+ * success/failure.
+ */
+static void send_owner_config(struct transfer_descriptor *td,
+			      const char *file_name)
+{
+	struct stat st;
+	const size_t config_size = 2048;
+	uint8_t config[config_size];
+	FILE *f;
+	uint32_t fake_addr;
+
+	/* Make sure the file is there and passes basic sаnity test. */
+	if (stat(file_name, &st) != 0) {
+		fprintf(stderr, "File %s not found\n", file_name);
+		exit(1);
+	}
+
+	if (st.st_size != config_size) {
+		fprintf(stderr, "Unexpected size %zd of %s\n", st.st_size,
+			file_name);
+		exit(1);
+	}
+
+	f = fopen(file_name, "rb");
+	if (!f) {
+		fprintf(stderr, "Failed to open  %s\n", file_name);
+		exit(1);
+	}
+	if (fread(config, 1, config_size, f) != config_size) {
+		fclose(f);
+		fprintf(stderr, "Failed to read  %s\n", file_name);
+		exit(1);
+	}
+	fclose(f);
+
+	setup_connection(td);
+
+	/*
+	 * Encode the destination Info page into the flat 32 bit value passed
+	 * as the address in the PDU header.
+	 *
+	 * The encoding is as follows:
+	 * Bit 31 set to 1 means that this is an Info page address
+	 * Bit 30 indicates the flash bank, 0 or 1
+	 * Bits 26..29 indicate the page number in the bank
+	 * Bits 0..25 are used for offset in the page, 11 bits is enough to
+	 *     cover the entire page address range (2k)
+	 *
+	 * The info page used for storing owners config updates is Page 3 in
+	 * Bank 1
+	 */
+	fake_addr = (1 << 31) + (1 << 30) + (3 << 26);
+	transfer_section(td, config, fake_addr, config_size);
+	exit(0);
+}
+
 /* Returns number of successfully transmitted image sections. */
 static int transfer_image(struct transfer_descriptor *td, struct image *image)
 {
@@ -4879,25 +4958,20 @@ int main(int argc, char *argv[])
 	bool get_chassis_open = false;
 	bool get_dev_ids = false;
 	bool get_aprov_reset_counts = false;
+	int upload_owner_config = 0;
 
 	/*
 	 * All options which result in setting a Boolean flag to True, along
 	 * with addresses of the flags. Terminated by a zeroed entry.
 	 */
 	const struct options_map omap[] = {
-		{ 'b', &binary_vers },
-		{ 'c', &corrupt_inactive_rw },
-		{ 'f', &show_fw_ver },
-		{ 'g', &get_boot_mode },
-		{ 'H', &erase_ap_ro_hash },
-		{ 'k', &ccd_lock },
-		{ 'o', &ccd_open },
-		{ 'P', &password },
-		{ 'p', &td.post_reset },
-		{ 'U', &ccd_unlock },
-		{ 'u', &td.upstart_mode },
-		{ 'V', &verbose_mode },
-		{},
+		{ 'b', &binary_vers },	    { 'c', &corrupt_inactive_rw },
+		{ 'f', &show_fw_ver },	    { 'g', &get_boot_mode },
+		{ 'H', &erase_ap_ro_hash }, { 'j', &upload_owner_config },
+		{ 'k', &ccd_lock },	    { 'o', &ccd_open },
+		{ 'P', &password },	    { 'p', &td.post_reset },
+		{ 'U', &ccd_unlock },	    { 'u', &td.upstart_mode },
+		{ 'V', &verbose_mode },	    {},
 	};
 
 	/*
@@ -5222,7 +5296,8 @@ int main(int argc, char *argv[])
 	    !password && !reboot_gsc && !rma && !set_capability &&
 	    !show_fw_ver && !sn_bits && !sn_inc_rma && !start_apro_verify &&
 	    !openbox_desc_file && !tstamp && !tpm_mode && (wp == WP_NONE) &&
-	    !get_chassis_open && !get_dev_ids && !get_aprov_reset_counts) {
+	    !get_chassis_open && !get_dev_ids && !get_aprov_reset_counts &&
+	    !upload_owner_config) {
 		num_images = argc - optind;
 		if (num_images <= 0) {
 			fprintf(stderr,
@@ -5266,10 +5341,11 @@ int main(int argc, char *argv[])
 	     !!ccd_unlock + !!ccd_lock + !!ccd_info + !!get_flog +
 	     !!get_boot_mode + !!openbox_desc_file + !!factory_mode +
 	     (wp != WP_NONE) + !!get_endorsement_seed + !!erase_ap_ro_hash +
-	     !!set_capability + !!get_clog + !!get_console) > 1) {
+	     !!set_capability + !!get_clog + !!get_console +
+	     !!upload_owner_config) > 1) {
 		fprintf(stderr,
 			"Error: options "
-			"-e, -F, -g, -H, -I, -i, -k, -L, -l, -O, -o, -P, -r,"
+			"-e, -F, -g, -H, -I, -i, -j -k, -L, -l, -O, -o, -P, -r,"
 			"-U, -x and -w are mutually exclusive\n");
 		exit(update_error);
 	}
@@ -5312,6 +5388,22 @@ int main(int argc, char *argv[])
 	/* Perform run selection of GSC device now that we have a connection */
 	gsc_dev = determine_gsc_type(&td);
 
+	if (upload_owner_config) {
+		if (gsc_dev != GSC_DEVICE_NT) {
+			fprintf(stderr, "Owner's config can be uploaded only "
+					"on opentitan devices\n");
+			exit(1);
+		}
+
+		if ((argc - optind) != 1) {
+			fprintf(stderr,
+				"A single owner's config file is required\n");
+			exit(1);
+		}
+
+		send_owner_config(&td, argv[optind]);
+	}
+
 	if (openbox_desc_file)
 		return verify_ro(&td, openbox_desc_file, show_machine_output);
 
diff --git a/proto/Android.bp b/proto/Android.bp
index 55447fe9f..7550990b4 100644
--- a/proto/Android.bp
+++ b/proto/Android.bp
@@ -5,6 +5,7 @@
 rust_protobuf {
     name: "libgsc_utils_proto_rs",
     crate_name: "gsc_utils_proto",
+    host_supported: true,
     protos: ["attestation_ca.proto"],
     source_stem: "gsc_utils_proto",
 }
diff --git a/tpm_generated/Android.bp b/tpm_generated/Android.bp
index 9d027007e..4302bc2f4 100644
--- a/tpm_generated/Android.bp
+++ b/tpm_generated/Android.bp
@@ -33,6 +33,7 @@ cc_library {
     srcs: [
         "ffi.cc",
         "hex.cc",
+        "hmac_authorization_delegate.cc",
         "multiple_authorization_delegate.cc",
         "password_authorization_delegate.cc",
         "secure_hash.cc",
diff --git a/tpm_generated/ffi.cc b/tpm_generated/ffi.cc
index c03b3105c..5f4749b62 100644
--- a/tpm_generated/ffi.cc
+++ b/tpm_generated/ffi.cc
@@ -15,6 +15,7 @@
 #include <openssl/rsa.h>
 #include <openssl/sha.h>
 
+#include "hmac_authorization_delegate.h"
 #include "multiple_authorization_delegate.h"
 #include "password_authorization_delegate.h"
 
@@ -26,11 +27,21 @@ constexpr TPMA_OBJECT kFixedTPM = 1U << 1;
 constexpr TPMA_OBJECT kFixedParent = 1U << 4;
 constexpr TPMA_OBJECT kSensitiveDataOrigin = 1U << 5;
 constexpr TPMA_OBJECT kUserWithAuth = 1U << 6;
+constexpr TPMA_OBJECT kAdminWithPolicy = 1U << 7;
 constexpr TPMA_OBJECT kNoDA = 1U << 10;
 constexpr TPMA_OBJECT kRestricted = 1U << 16;
 constexpr TPMA_OBJECT kDecrypt = 1U << 17;
 constexpr TPMA_OBJECT kSign = 1U << 18;
 
+// Auth policy used in RSA and ECC templates for EK keys generation.
+// From TCG Credential Profile EK 2.0. Section 2.1.5.
+constexpr char kEKTemplateAuthPolicy[] = {
+    '\x83', '\x71', '\x97', '\x67', '\x44', '\x84', '\xB3', '\xF8',
+    '\x1A', '\x90', '\xCC', '\x8D', '\x46', '\xA5', '\xD7', '\x24',
+    '\xFD', '\x52', '\xD7', '\x6E', '\x06', '\x52', '\x0B', '\x64',
+    '\xF2', '\xA1', '\xDA', '\x1B', '\x33', '\x14', '\x69', '\xAA',
+};
+
 // Returns a general public area for our keys. This default may be further
 // manipulated to produce the public area for specific keys (such as SRK or
 // AIK).
@@ -213,11 +224,67 @@ bool EncryptDataForCa(const std::string& data,
   return out;
 }
 
+std::unique_ptr<AuthorizationDelegate> HmacAuthorizationDelegate_New(
+    TPM_HANDLE session_handle, const std::string& tpm_nonce,
+    const std::string& caller_nonce, const std::string& salt,
+    const std::string& bind_auth_value, bool enable_parameter_encryption) {
+  std::unique_ptr<HmacAuthorizationDelegate> delegate =
+      std::make_unique<HmacAuthorizationDelegate>();
+  if (!delegate->InitSession(session_handle, Make_TPM2B_DIGEST(tpm_nonce),
+                             Make_TPM2B_DIGEST(caller_nonce), salt,
+                             bind_auth_value, enable_parameter_encryption)) {
+    LOG(ERROR) << "HmacAuthorizationDelegate::InitSession failed";
+    return nullptr;
+  }
+  return delegate;
+}
+
 std::unique_ptr<AuthorizationDelegate> PasswordAuthorizationDelegate_New(
     const std::string& password) {
   return std::make_unique<PasswordAuthorizationDelegate>(password);
 }
 
+TPM_RC SerializeCommand_ActivateCredential(
+    const TPMI_DH_OBJECT& activate_handle,
+    const std::string& activate_handle_name, const TPMI_DH_OBJECT& key_handle,
+    const std::string& key_handle_name, const std::string& credential_mac,
+    const std::string& wrapped_key, const std::string& secret,
+    std::string& serialized_command, AuthorizationDelegate& key_authorization) {
+  std::string credential_blob;
+  TPM_RC rc = Serialize_TPM2B_DIGEST(Make_TPM2B_DIGEST(credential_mac),
+                                     &credential_blob);
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  credential_blob += wrapped_key;
+  MultipleAuthorizations authorizations;
+  PasswordAuthorizationDelegate password("");
+  authorizations.AddAuthorizationDelegate(&password);
+  authorizations.AddAuthorizationDelegate(&key_authorization);
+  return Tpm::SerializeCommand_ActivateCredential(
+      activate_handle, activate_handle_name, key_handle, key_handle_name,
+      Make_TPM2B_ID_OBJECT(credential_blob),
+      Make_TPM2B_ENCRYPTED_SECRET(secret), &serialized_command,
+      &authorizations);
+}
+
+TPM_RC ParseResponse_ActivateCredential(
+    const std::string& response, std::string& cert_info,
+    AuthorizationDelegate& key_authorization) {
+  TPM2B_DIGEST typed_cert_info;
+  MultipleAuthorizations authorizations;
+  PasswordAuthorizationDelegate password("");
+  authorizations.AddAuthorizationDelegate(&password);
+  authorizations.AddAuthorizationDelegate(&key_authorization);
+  TPM_RC rc = Tpm::ParseResponse_ActivateCredential(response, &typed_cert_info,
+                                                    &authorizations);
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  cert_info = StringFrom_TPM2B_DIGEST(typed_cert_info);
+  return TPM_RC_SUCCESS;
+}
+
 TPM_RC SerializeCommand_Create(
     const TPMI_DH_OBJECT& parent_handle, const std::string& parent_handle_name,
     const TPM2B_SENSITIVE_CREATE& in_sensitive, const TPM2B_PUBLIC& in_public,
@@ -272,7 +339,8 @@ TPM_RC ParseResponse_CreatePrimary(
   if (rc != TPM_RC_SUCCESS) {
     return rc;
   }
-  return Serialize_TPM2B_NAME(tpm2b_name, &name);
+  name = StringFrom_TPM2B_NAME(tpm2b_name);
+  return TPM_RC_SUCCESS;
 }
 
 TPM_RC SerializeCommand_Load(
@@ -386,6 +454,39 @@ TPM_RC ParseResponse_NV_ReadPublic(
   return TPM_RC_SUCCESS;
 }
 
+TPM_RC SerializeCommand_PolicySecret(
+    const TPMI_DH_ENTITY& auth_handle, const std::string& auth_handle_name,
+    const TPMI_SH_POLICY& policy_session,
+    const std::string& policy_session_name, const std::string& nonce_tpm,
+    const std::string& cp_hash_a, const std::string& policy_ref,
+    const uint32_t& expiration, std::string& serialized_command,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  return Tpm::SerializeCommand_PolicySecret(
+      auth_handle, auth_handle_name, policy_session, policy_session_name,
+      Make_TPM2B_DIGEST(nonce_tpm), Make_TPM2B_DIGEST(cp_hash_a),
+      Make_TPM2B_DIGEST(policy_ref), expiration, &serialized_command,
+      authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_PolicySecret(
+    const std::string& response, std::string& timeout,
+    uint16_t& policy_ticket_tag, uint32_t& policy_ticket_hierarchy,
+    std::string& policy_ticket_digest,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_TIMEOUT typed_timeout;
+  TPMT_TK_AUTH policy_ticket;
+  TPM_RC rc = Tpm::ParseResponse_PolicySecret(
+      response, &typed_timeout, &policy_ticket, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  timeout = StringFrom_TPM2B_TIMEOUT(typed_timeout);
+  policy_ticket_tag = policy_ticket.tag;
+  policy_ticket_hierarchy = policy_ticket.hierarchy;
+  policy_ticket_digest = StringFrom_TPM2B_DIGEST(policy_ticket.digest);
+  return TPM_RC_SUCCESS;
+}
+
 TPM_RC SerializeCommand_Quote(
     const TPMI_DH_OBJECT& sign_handle, const std::string& sign_handle_name,
     const TPM2B_DATA& qualifying_data, const TPMT_SIG_SCHEME& in_scheme,
@@ -437,6 +538,35 @@ TPM_RC ParseResponse_PCR_Read(
   return TPM_RC_SUCCESS;
 }
 
+TPM_RC SerializeCommand_StartAuthSession(
+    const TPMI_DH_OBJECT& tpm_key, const std::string& tpm_key_name,
+    const TPMI_DH_ENTITY& bind, const std::string& bind_name,
+    const std::string& nonce_caller, const std::string& encrypted_salt,
+    const uint8_t& session_type, const uint16_t& auth_hash,
+    std::string& serialized_command,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPMT_SYM_DEF symmetric;
+  symmetric.algorithm = TPM_ALG_NULL;
+  return Tpm::SerializeCommand_StartAuthSession(
+      tpm_key, tpm_key_name, bind, bind_name, Make_TPM2B_DIGEST(nonce_caller),
+      Make_TPM2B_ENCRYPTED_SECRET(encrypted_salt), session_type, symmetric,
+      auth_hash, &serialized_command, authorization_delegate.get());
+}
+
+TPM_RC ParseResponse_StartAuthSession(
+    const std::string& response, TPMI_SH_AUTH_SESSION& session_handle,
+    std::string& nonce_tpm,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate) {
+  TPM2B_NONCE nonce;
+  TPM_RC rc = Tpm::ParseResponse_StartAuthSession(
+      response, &session_handle, &nonce, authorization_delegate.get());
+  if (rc != TPM_RC_SUCCESS) {
+    return rc;
+  }
+  nonce_tpm = StringFrom_TPM2B_DIGEST(nonce);
+  return TPM_RC_SUCCESS;
+}
+
 std::unique_ptr<std::string> NameFromHandle(const TPM_HANDLE& handle) {
   std::string name;
   Serialize_TPM_HANDLE(handle, &name);
@@ -465,6 +595,24 @@ std::unique_ptr<TPM2B_PUBLIC> AttestationIdentityKeyTemplate() {
   return std::make_unique<TPM2B_PUBLIC>(Make_TPM2B_PUBLIC(public_area));
 }
 
+std::unique_ptr<TPM2B_PUBLIC> EndorsementKeyTemplate() {
+  TPMT_PUBLIC public_area = DefaultPublicArea();
+  public_area.object_attributes = kFixedTPM | kFixedParent |
+                                  kSensitiveDataOrigin | kAdminWithPolicy |
+                                  kRestricted | kDecrypt;
+  public_area.auth_policy = Make_TPM2B_DIGEST(
+      std::string(kEKTemplateAuthPolicy, std::size(kEKTemplateAuthPolicy)));
+  public_area.parameters.ecc_detail.symmetric.algorithm = TPM_ALG_AES;
+  public_area.parameters.ecc_detail.symmetric.key_bits.aes = 128;
+  public_area.parameters.ecc_detail.symmetric.mode.aes = TPM_ALG_CFB;
+  public_area.parameters.ecc_detail.scheme.scheme = TPM_ALG_NULL;
+  public_area.parameters.ecc_detail.curve_id = TPM_ECC_NIST_P256;
+  public_area.parameters.ecc_detail.kdf.scheme = TPM_ALG_NULL;
+  public_area.unique.ecc.x = Make_TPM2B_ECC_PARAMETER(std::string(32, 0));
+  public_area.unique.ecc.y = Make_TPM2B_ECC_PARAMETER(std::string(32, 0));
+  return std::make_unique<TPM2B_PUBLIC>(Make_TPM2B_PUBLIC(public_area));
+}
+
 std::unique_ptr<TPM2B_PUBLIC> StorageRootKeyTemplate() {
   TPMT_PUBLIC public_area = DefaultPublicArea();
   public_area.object_attributes |=
diff --git a/tpm_generated/ffi.h b/tpm_generated/ffi.h
index 15862408c..7669ab1e3 100644
--- a/tpm_generated/ffi.h
+++ b/tpm_generated/ffi.h
@@ -38,6 +38,18 @@ bool EncryptDataForCa(const std::string& data,
                       std::string& encrypted_data,
                       std::string& wrapping_key_id);
 
+// -----------------------------------------------------------------------------
+// HmacAuthorizationDelegate
+// -----------------------------------------------------------------------------
+
+// Creates a new HmacAuthorizationDelegate. On error, logs an error message and
+// returns a null unique_ptr. See PasswordAuthorizationDelegate for why this
+// returns an AuthorizationDelegate rather than a HmacAuthorizationDelegate.
+std::unique_ptr<AuthorizationDelegate> HmacAuthorizationDelegate_New(
+    TPM_HANDLE session_handle, const std::string& tpm_nonce,
+    const std::string& caller_nonce, const std::string& salt,
+    const std::string& bind_auth_value, bool enable_parameter_encryption);
+
 // -----------------------------------------------------------------------------
 // PasswordAuthorizationDelegate
 // -----------------------------------------------------------------------------
@@ -53,6 +65,21 @@ std::unique_ptr<AuthorizationDelegate> PasswordAuthorizationDelegate_New(
 // Tpm
 // -----------------------------------------------------------------------------
 
+// Wraps Tpm::SerializeCommand_ActivateCredential. Serializes the
+// TPM2_ActivateCredential command.
+TPM_RC SerializeCommand_ActivateCredential(
+    const TPMI_DH_OBJECT& activate_handle,
+    const std::string& activate_handle_name, const TPMI_DH_OBJECT& key_handle,
+    const std::string& key_handle_name, const std::string& credential_mac,
+    const std::string& wrapped_key, const std::string& secret,
+    std::string& serialized_command, AuthorizationDelegate& key_authorization);
+
+// Wraps Tpm::ParseResponse_ActivateCredential. Parses the response of a
+// TPM2_ActivateCredential command.
+TPM_RC ParseResponse_ActivateCredential(
+    const std::string& response, std::string& cert_info,
+    AuthorizationDelegate& key_authorization);
+
 // Wraps Tpm::SerializeCommand_Create. Serializes the TPM2_Create command.
 // authorization_delegate is nullable.
 TPM_RC SerializeCommand_Create(
@@ -163,6 +190,26 @@ TPM_RC ParseResponse_NV_ReadPublic(
     std::string& nv_name,
     const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
 
+// Wraps Tpm::SerializeCommand_PolicySecret. Serializes a TPM2_PolicySecret
+// command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_PolicySecret(
+    const TPMI_DH_ENTITY& auth_handle, const std::string& auth_handle_name,
+    const TPMI_SH_POLICY& policy_session,
+    const std::string& policy_session_name, const std::string& nonce_tpm,
+    const std::string& cp_hash_a, const std::string& policy_ref,
+    const uint32_t& expiration, std::string& serialized_command,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_PolicySecret. Parses the response from a
+// TPM2_PolicySecret command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_PolicySecret(
+    const std::string& response, std::string& timeout,
+    uint16_t& policy_ticket_tag, uint32_t& policy_ticket_hierarchy,
+    std::string& policy_ticket_digest,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
 // Wraps Tpm::SerializeCommand_Quote. Serializes the TPM2_Quote command.
 // authorization_delegate is nullable.
 TPM_RC SerializeCommand_Quote(
@@ -192,6 +239,25 @@ TPM_RC ParseResponse_PCR_Read(
     TPML_PCR_SELECTION& pcr_selection_out, std::string& pcr_values,
     const std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
 
+// Wraps Tpm::SerializeCommand_StartAuthSession. Serializes the
+// TPM2_StartAuthSession command.
+// authorization_delegate is nullable.
+TPM_RC SerializeCommand_StartAuthSession(
+    const TPMI_DH_OBJECT& tpm_key, const std::string& tpm_key_name,
+    const TPMI_DH_ENTITY& bind, const std::string& bind_name,
+    const std::string& nonce_caller, const std::string& encrypted_salt,
+    const uint8_t& session_type, const uint16_t& auth_hash,
+    std::string& serialized_command,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
+// Wraps Tpm::ParseResponse_StartAuthSession. Parses the response from a
+// TPM2_StartAuthSession command.
+// authorization_delegate is nullable.
+TPM_RC ParseResponse_StartAuthSession(
+    const std::string& response, TPMI_SH_AUTH_SESSION& session_handle,
+    std::string& nonce_tpm,
+    std::unique_ptr<AuthorizationDelegate>& authorization_delegate);
+
 // -----------------------------------------------------------------------------
 // TPM_HANDLE
 // -----------------------------------------------------------------------------
@@ -230,6 +296,9 @@ std::unique_ptr<TPM2B_DIGEST> TPM2B_DIGEST_New();
 // Returns the public area template for the Attestation Identity Key.
 std::unique_ptr<TPM2B_PUBLIC> AttestationIdentityKeyTemplate();
 
+// Returns the public area template for the Endorsement Key.
+std::unique_ptr<TPM2B_PUBLIC> EndorsementKeyTemplate();
+
 // Returns the public area template for the Storage Root Key.
 std::unique_ptr<TPM2B_PUBLIC> StorageRootKeyTemplate();
 
diff --git a/tpm_generated/hmac_authorization_delegate.cc b/tpm_generated/hmac_authorization_delegate.cc
new file mode 100644
index 000000000..8115a1a23
--- /dev/null
+++ b/tpm_generated/hmac_authorization_delegate.cc
@@ -0,0 +1,313 @@
+// Copyright 2014 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include "hmac_authorization_delegate.h"
+
+#include <android-base/logging.h>
+#include <openssl/aes.h>
+#include <openssl/hmac.h>
+#include <openssl/mem.h>
+#include <openssl/rand.h>
+
+namespace trunks {
+
+namespace {
+
+const uint32_t kDigestBits = 256;
+const uint16_t kNonceMinSize = 16;
+const uint16_t kNonceMaxSize = 32;
+const uint8_t kDecryptSession = 1 << 5;
+const uint8_t kEncryptSession = 1 << 6;
+const uint8_t kLabelSize = 4;
+const size_t kAesIVSize = 16;
+const uint32_t kTpmBufferSize = 4096;
+
+}  // namespace
+
+HmacAuthorizationDelegate::HmacAuthorizationDelegate()
+    : session_handle_(0),
+      is_parameter_encryption_enabled_(false),
+      nonce_generated_(false),
+      future_authorization_value_set_(false),
+      use_entity_authorization_for_encryption_only_(false) {
+  tpm_nonce_.size = 0;
+  caller_nonce_.size = 0;
+}
+
+HmacAuthorizationDelegate::~HmacAuthorizationDelegate() {}
+
+bool HmacAuthorizationDelegate::GetCommandAuthorization(
+    const std::string& command_hash,
+    bool is_command_parameter_encryption_possible,
+    bool is_response_parameter_encryption_possible,
+    std::string* authorization) {
+  if (!session_handle_) {
+    authorization->clear();
+    LOG(ERROR) << "Delegate being used before Initialization,";
+    return false;
+  }
+  TPMS_AUTH_COMMAND auth;
+  auth.session_handle = session_handle_;
+  if (!nonce_generated_) {
+    RegenerateCallerNonce();
+  }
+  auth.nonce = caller_nonce_;
+  auth.session_attributes = kContinueSession;
+  if (is_parameter_encryption_enabled_) {
+    if (is_command_parameter_encryption_possible) {
+      auth.session_attributes |= kDecryptSession;
+    }
+    if (is_response_parameter_encryption_possible) {
+      auth.session_attributes |= kEncryptSession;
+    }
+  }
+  // We reset the |nonce_generated| flag in preparation of the next command.
+  nonce_generated_ = false;
+  std::string attributes_bytes;
+  CHECK_EQ(Serialize_TPMA_SESSION(auth.session_attributes, &attributes_bytes),
+           TPM_RC_SUCCESS)
+      << "Error serializing session attributes.";
+
+  std::string hmac_data;
+  std::string hmac_key;
+  if (!use_entity_authorization_for_encryption_only_) {
+    hmac_key = session_key_ + entity_authorization_value_;
+  } else {
+    hmac_key = session_key_;
+  }
+  hmac_data.append(command_hash);
+  hmac_data.append(reinterpret_cast<const char*>(caller_nonce_.buffer),
+                   caller_nonce_.size);
+  hmac_data.append(reinterpret_cast<const char*>(tpm_nonce_.buffer),
+                   tpm_nonce_.size);
+  hmac_data.append(attributes_bytes);
+  std::string digest = HmacSha256(hmac_key, hmac_data);
+  auth.hmac = Make_TPM2B_DIGEST(digest);
+
+  TPM_RC serialize_error = Serialize_TPMS_AUTH_COMMAND(auth, authorization);
+  if (serialize_error != TPM_RC_SUCCESS) {
+    LOG(ERROR) << "Could not serialize command auth.";
+    return false;
+  }
+  return true;
+}
+
+bool HmacAuthorizationDelegate::CheckResponseAuthorization(
+    const std::string& response_hash, const std::string& authorization) {
+  if (!session_handle_) {
+    return false;
+  }
+  TPMS_AUTH_RESPONSE auth_response;
+  std::string mutable_auth_string(authorization);
+  TPM_RC parse_error;
+  std::string auth_bytes;
+  parse_error = Parse_TPMS_AUTH_RESPONSE(&mutable_auth_string, &auth_response,
+                                         &auth_bytes);
+  if (authorization.size() != auth_bytes.size()) {
+    LOG(ERROR) << "Authorization string was of wrong length.";
+    return false;
+  }
+  if (parse_error != TPM_RC_SUCCESS) {
+    LOG(ERROR) << "Could not parse authorization response.";
+    return false;
+  }
+  if (!mutable_auth_string.empty()) {
+    LOG(ERROR) << "Authorization string was of wrong length.";
+    return false;
+  }
+  if (auth_response.hmac.size != kHashDigestSize) {
+    LOG(ERROR) << "TPM auth hmac was incorrect size.";
+    return false;
+  }
+  if (auth_response.nonce.size < kNonceMinSize ||
+      auth_response.nonce.size > kNonceMaxSize) {
+    LOG(ERROR) << "TPM_nonce is not the correct length.";
+    return false;
+  }
+  tpm_nonce_ = auth_response.nonce;
+  std::string attributes_bytes;
+  CHECK_EQ(Serialize_TPMA_SESSION(auth_response.session_attributes,
+                                  &attributes_bytes),
+           TPM_RC_SUCCESS)
+      << "Error serializing session attributes.";
+
+  std::string hmac_data;
+  std::string hmac_key;
+  if (!use_entity_authorization_for_encryption_only_) {
+    // In a special case with TPM2_HierarchyChangeAuth, we need to use the
+    // auth_value that was set.
+    if (future_authorization_value_set_) {
+      hmac_key = session_key_ + future_authorization_value_;
+      future_authorization_value_set_ = false;
+    } else {
+      hmac_key = session_key_ + entity_authorization_value_;
+    }
+  } else {
+    hmac_key = session_key_;
+  }
+  hmac_data.append(response_hash);
+  hmac_data.append(reinterpret_cast<const char*>(tpm_nonce_.buffer),
+                   tpm_nonce_.size);
+  hmac_data.append(reinterpret_cast<const char*>(caller_nonce_.buffer),
+                   caller_nonce_.size);
+  hmac_data.append(attributes_bytes);
+  std::string digest = HmacSha256(hmac_key, hmac_data);
+  CHECK_EQ(digest.size(), auth_response.hmac.size);
+  if (CRYPTO_memcmp(digest.data(), auth_response.hmac.buffer, digest.size())) {
+    LOG(ERROR) << "Authorization response hash did not match expected value.";
+    return false;
+  }
+  return true;
+}
+
+bool HmacAuthorizationDelegate::EncryptCommandParameter(
+    std::string* parameter) {
+  CHECK(parameter);
+  if (!session_handle_) {
+    LOG(ERROR) << __func__ << ": Invalid session handle.";
+    return false;
+  }
+  if (!is_parameter_encryption_enabled_) {
+    // No parameter encryption enabled.
+    return true;
+  }
+  if (parameter->size() > kTpmBufferSize) {
+    LOG(ERROR) << "Parameter size is too large for TPM decryption.";
+    return false;
+  }
+  RegenerateCallerNonce();
+  nonce_generated_ = true;
+  AesOperation(parameter, caller_nonce_, tpm_nonce_, AES_ENCRYPT);
+  return true;
+}
+
+bool HmacAuthorizationDelegate::DecryptResponseParameter(
+    std::string* parameter) {
+  CHECK(parameter);
+  if (!session_handle_) {
+    LOG(ERROR) << __func__ << ": Invalid session handle.";
+    return false;
+  }
+  if (!is_parameter_encryption_enabled_) {
+    // No parameter decryption enabled.
+    return true;
+  }
+  if (parameter->size() > kTpmBufferSize) {
+    LOG(ERROR) << "Parameter size is too large for TPM encryption.";
+    return false;
+  }
+  AesOperation(parameter, tpm_nonce_, caller_nonce_, AES_DECRYPT);
+  return true;
+}
+
+bool HmacAuthorizationDelegate::GetTpmNonce(std::string* nonce) {
+  if (!tpm_nonce_.size) {
+    return false;
+  }
+  nonce->assign(tpm_nonce_.buffer, tpm_nonce_.buffer + tpm_nonce_.size);
+  return true;
+}
+
+bool HmacAuthorizationDelegate::InitSession(TPM_HANDLE session_handle,
+                                            const TPM2B_NONCE& tpm_nonce,
+                                            const TPM2B_NONCE& caller_nonce,
+                                            const std::string& salt,
+                                            const std::string& bind_auth_value,
+                                            bool enable_parameter_encryption) {
+  session_handle_ = session_handle;
+  if (caller_nonce.size < kNonceMinSize || caller_nonce.size > kNonceMaxSize ||
+      tpm_nonce.size < kNonceMinSize || tpm_nonce.size > kNonceMaxSize) {
+    LOG(INFO) << "Session Nonces have to be between 16 and 32 bytes long.";
+    return false;
+  }
+  tpm_nonce_ = tpm_nonce;
+  caller_nonce_ = caller_nonce;
+  std::string session_key_label("ATH", kLabelSize);
+  is_parameter_encryption_enabled_ = enable_parameter_encryption;
+  if (salt.length() == 0 && bind_auth_value.length() == 0) {
+    // SessionKey is set to the empty string for unsalted and
+    // unbound sessions.
+    session_key_ = std::string();
+  } else {
+    session_key_ = CreateKey(bind_auth_value + salt, session_key_label,
+                             tpm_nonce_, caller_nonce_);
+  }
+  return true;
+}
+
+void HmacAuthorizationDelegate::set_future_authorization_value(
+    const std::string& auth_value) {
+  future_authorization_value_ = auth_value;
+  future_authorization_value_set_ = true;
+}
+
+std::string HmacAuthorizationDelegate::CreateKey(
+    const std::string& hmac_key, const std::string& label,
+    const TPM2B_NONCE& nonce_newer, const TPM2B_NONCE& nonce_older) {
+  std::string counter;
+  std::string digest_size_bits;
+  if (Serialize_uint32_t(1, &counter) != TPM_RC_SUCCESS ||
+      Serialize_uint32_t(kDigestBits, &digest_size_bits) != TPM_RC_SUCCESS) {
+    LOG(ERROR) << "Error serializing uint32_t during session key generation.";
+    return std::string();
+  }
+  CHECK_EQ(counter.size(), sizeof(uint32_t));
+  CHECK_EQ(digest_size_bits.size(), sizeof(uint32_t));
+  CHECK_EQ(label.size(), kLabelSize);
+
+  std::string data;
+  data.append(counter);
+  data.append(label);
+  data.append(reinterpret_cast<const char*>(nonce_newer.buffer),
+              nonce_newer.size);
+  data.append(reinterpret_cast<const char*>(nonce_older.buffer),
+              nonce_older.size);
+  data.append(digest_size_bits);
+  std::string key = HmacSha256(hmac_key, data);
+  return key;
+}
+
+std::string HmacAuthorizationDelegate::HmacSha256(const std::string& key,
+                                                  const std::string& data) {
+  unsigned char digest[EVP_MAX_MD_SIZE];
+  unsigned int digest_length;
+  HMAC(EVP_sha256(), key.data(), key.size(),
+       reinterpret_cast<const unsigned char*>(data.data()), data.size(), digest,
+       &digest_length);
+  CHECK_EQ(digest_length, kHashDigestSize);
+  return std::string(reinterpret_cast<char*>(digest), digest_length);
+}
+
+void HmacAuthorizationDelegate::AesOperation(std::string* parameter,
+                                             const TPM2B_NONCE& nonce_newer,
+                                             const TPM2B_NONCE& nonce_older,
+                                             int operation_type) {
+  std::string label("CFB", kLabelSize);
+  std::string compound_key =
+      CreateKey(session_key_ + entity_authorization_value_, label, nonce_newer,
+                nonce_older);
+  CHECK_EQ(compound_key.size(), kAesKeySize + kAesIVSize);
+  unsigned char aes_key[kAesKeySize];
+  unsigned char aes_iv[kAesIVSize];
+  memcpy(aes_key, &compound_key[0], kAesKeySize);
+  memcpy(aes_iv, &compound_key[kAesKeySize], kAesIVSize);
+  AES_KEY key;
+  int iv_offset = 0;
+  AES_set_encrypt_key(aes_key, kAesKeySize * 8, &key);
+  unsigned char decrypted[kTpmBufferSize];
+  AES_cfb128_encrypt(reinterpret_cast<const unsigned char*>(parameter->data()),
+                     decrypted, parameter->size(), &key, aes_iv, &iv_offset,
+                     operation_type);
+  memcpy(std::data(*parameter), decrypted, parameter->size());
+}
+
+void HmacAuthorizationDelegate::RegenerateCallerNonce() {
+  CHECK(session_handle_);
+  // RAND_bytes takes a signed number, but since nonce_size is guaranteed to be
+  // less than 32 bytes and greater than 16 we dont have to worry about it.
+  CHECK_EQ(RAND_bytes(caller_nonce_.buffer, caller_nonce_.size), 1)
+      << "Error regenerating a cryptographically random nonce.";
+}
+
+}  // namespace trunks
diff --git a/tpm_generated/hmac_authorization_delegate.h b/tpm_generated/hmac_authorization_delegate.h
new file mode 100644
index 000000000..b866dded8
--- /dev/null
+++ b/tpm_generated/hmac_authorization_delegate.h
@@ -0,0 +1,137 @@
+// Copyright 2014 The ChromiumOS Authors
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef TRUNKS_HMAC_AUTHORIZATION_DELEGATE_H_
+#define TRUNKS_HMAC_AUTHORIZATION_DELEGATE_H_
+
+#include <string>
+
+#include "authorization_delegate.h"
+#include "tpm_generated.h"
+#include "trunks_export.h"
+
+namespace trunks {
+
+const size_t kAesKeySize = 16;      // 128 bits is minimum AES key size.
+const size_t kHashDigestSize = 32;  // 256 bits is SHA256 digest size.
+
+// HmacAuthorizationDelegate is an implementation of the AuthorizationDelegate
+// interface. It provides the necessary Auth data for HMAC sessions.
+// This delegate also does parameter encryption on sessions that support it.
+
+// Usage:
+// 1) After running the StartAuthSession command on the TPM2.0, we declare this
+// delegate using the constructor. We can specify if we want parameter
+// obfuscation enabled or not.
+// 2) We initialize the session using |InitSession|. We feed in the handle and
+// tpm_nonce returned by StartAuthSession. Additionally we inject the
+// caller_nonce, salt and auth_value of the bound entity we fed into
+// StartAuthSession.
+// 3) Pass a pointer to this delegate to any TPM command that needs
+// authorization using this delegate.
+
+// Sample control flow:
+//  TrunksProxy proxy;
+//  proxy.Init();
+//  Tpm tpm(&proxy);
+//  tpm.StartAuthSession(...);
+//  HmacAuthorizationDelegate hmac();
+//  hmac.InitSession(...);
+//  tpm.Create(..., &hmac);
+//  hmac.set_entity_authorization_value(...);
+//  tpm.Load(..., &hmac);
+class TRUNKS_EXPORT HmacAuthorizationDelegate : public AuthorizationDelegate {
+ public:
+  HmacAuthorizationDelegate();
+  HmacAuthorizationDelegate(const HmacAuthorizationDelegate&) = delete;
+  HmacAuthorizationDelegate& operator=(const HmacAuthorizationDelegate&) =
+      delete;
+
+  ~HmacAuthorizationDelegate() override;
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
+  // This function is called with the return data of |StartAuthSession|. It
+  // will initialize the session to start providing auth information. It can
+  // only be called once per delegate, and must be called before the delegate
+  // is used for any operation. The boolean arg |enable_parameter_encryption|
+  // specifies if parameter encryption should be enabled for this delegate.
+  // |salt| and |bind_auth_value| specify the injected auth values into this
+  // delegate.
+  bool InitSession(TPM_HANDLE session_handle, const TPM2B_NONCE& tpm_nonce,
+                   const TPM2B_NONCE& caller_nonce, const std::string& salt,
+                   const std::string& bind_auth_value,
+                   bool enable_parameter_encryption);
+
+  // This method sets the FutureAuthorizationValue. This value is used in
+  // computing the HMAC response of TPM2_HierarchyChangeAuth.
+  void set_future_authorization_value(const std::string& auth_value);
+
+  std::string future_authorization_value() {
+    return future_authorization_value_;
+  }
+
+  // This method is used to inject an auth_value associated with an entity.
+  // This auth_value is then used when generating HMACs and encryption keys.
+  // Note: This value will be used for all commands until explicitly reset.
+  void set_entity_authorization_value(const std::string& auth_value) {
+    entity_authorization_value_ = auth_value;
+  }
+
+  std::string entity_authorization_value() const {
+    return entity_authorization_value_;
+  }
+
+  TPM_HANDLE session_handle() const { return session_handle_; }
+
+  void set_use_entity_authorization_for_encryption_only(bool value) {
+    use_entity_authorization_for_encryption_only_ = value;
+  }
+
+ private:
+  // This method implements the key derivation function used in the TPM.
+  // NOTE: It only returns 32 byte keys.
+  std::string CreateKey(const std::string& hmac_key, const std::string& label,
+                        const TPM2B_NONCE& nonce_newer,
+                        const TPM2B_NONCE& nonce_older);
+  // This method performs a FIPS198 HMAC operation on |data| using |key|
+  std::string HmacSha256(const std::string& key, const std::string& data);
+  // This method performs an AES operation using a 128 bit key.
+  // |operation_type| can be either AES_ENCRYPT or AES_DECRYPT and it
+  // determines if the operation is an encryption or decryption.
+  void AesOperation(std::string* parameter, const TPM2B_NONCE& nonce_newer,
+                    const TPM2B_NONCE& nonce_older, int operation_type);
+  // This method regenerates the caller nonce. The new nonce is the same
+  // length as the previous nonce. The buffer is filled with random data using
+  // openssl's |RAND_bytes| function.
+  // NOTE: This operation is DESTRUCTIVE, and rewrites the caller_nonce_ field.
+  void RegenerateCallerNonce();
+
+  TPM_HANDLE session_handle_;
+  TPM2B_NONCE caller_nonce_;
+  TPM2B_NONCE tpm_nonce_;
+  bool is_parameter_encryption_enabled_;
+  bool nonce_generated_;
+  std::string session_key_;
+  std::string entity_authorization_value_;
+  bool future_authorization_value_set_;
+  std::string future_authorization_value_;
+  // This boolean flag determines if the entity_authorization_value_ is needed
+  // when computing the hmac_key to create the authorization hmac. Defaults
+  // to false, but policy sessions may set this flag to true.
+  bool use_entity_authorization_for_encryption_only_;
+};
+
+}  // namespace trunks
+
+#endif  // TRUNKS_HMAC_AUTHORIZATION_DELEGATE_H_
diff --git a/tpm_generated/lib.rs b/tpm_generated/lib.rs
index 1a9583eb5..803403ecc 100644
--- a/tpm_generated/lib.rs
+++ b/tpm_generated/lib.rs
@@ -46,12 +46,45 @@ pub mod trunks {
             wrapping_key_id: Pin<&mut CxxString>,
         ) -> bool;
 
+        /// Creates a new HmacAuthorizationDelegate. On error, logs an error
+        /// message and returns a null unique_ptr.
+        fn HmacAuthorizationDelegate_New(
+            session_handle: u32,
+            tpm_nonce: &CxxString,
+            caller_nonce: &CxxString,
+            salt: &CxxString,
+            bind_auth_value: &CxxString,
+            enable_parameter_encryption: bool,
+        ) -> UniquePtr<AuthorizationDelegate>;
+
         /// Constructs a new PasswordAuthorizationDelegate with the given
         /// password.
         fn PasswordAuthorizationDelegate_New(
             password: &CxxString,
         ) -> UniquePtr<AuthorizationDelegate>;
 
+        /// Wraps Tpm::SerializeCommand_ActivateCredential. Serializes the
+        /// TPM2_ActivateCredential command.
+        fn SerializeCommand_ActivateCredential(
+            activate_handle: &u32,
+            activate_handle_name: &CxxString,
+            key_handle: &u32,
+            key_handle_name: &CxxString,
+            credential_mac: &CxxString,
+            wrapped_key: &CxxString,
+            secret: &CxxString,
+            serialized_command: Pin<&mut CxxString>,
+            key_authorization: Pin<&mut AuthorizationDelegate>,
+        ) -> u32;
+
+        /// Wraps Tpm::ParseResponse_ActivateCredential. Parses the response of
+        /// a TPM2_ActivateCredential command.
+        fn ParseResponse_ActivateCredential(
+            response: &CxxString,
+            cert_info: Pin<&mut CxxString>,
+            key_authorization: Pin<&mut AuthorizationDelegate>,
+        ) -> u32;
+
         /// See Tpm::SerializeCommand_Create for docs.
         fn SerializeCommand_Create(
             parent_handle: &u32,
@@ -174,6 +207,32 @@ pub mod trunks {
             authorization_delegate: &UniquePtr<AuthorizationDelegate>,
         ) -> u32;
 
+        /// See Tpm::SerializeCommand_PolicySecret for docs.
+        fn SerializeCommand_PolicySecret(
+            auth_handle: &u32,
+            auth_handle_name: &CxxString,
+            policy_session: &u32,
+            policy_session_name: &CxxString,
+            nonce_tpm: &CxxString,
+            cp_hash_a: &CxxString,
+            policy_ref: &CxxString,
+            expiration: &u32,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: Pin<&mut UniquePtr<AuthorizationDelegate>>,
+        ) -> u32;
+
+        /// Wraps Tpm::ParseResponse_PolicySecret. Parses the response from a
+        /// TPM2_PolicySecret command.
+        /// authorization_delegate is nullable.
+        fn ParseResponse_PolicySecret(
+            response: &CxxString,
+            timeout: Pin<&mut CxxString>,
+            policy_ticket_tag: &mut u16,
+            policy_ticket_hierarchy: &mut u32,
+            policy_ticket_digest: Pin<&mut CxxString>,
+            authorization_delegate: Pin<&mut UniquePtr<AuthorizationDelegate>>,
+        ) -> u32;
+
         /// See Tpm::SerializeCommand_Quote for docs.
         fn SerializeCommand_Quote(
             sign_handle: &u32,
@@ -209,6 +268,28 @@ pub mod trunks {
             authorization_delegate: &UniquePtr<AuthorizationDelegate>,
         ) -> u32;
 
+        /// See Tpm::SerializeCommand_StartAuthSession for docs.
+        fn SerializeCommand_StartAuthSession(
+            tpm_key: &u32,
+            tpm_key_name: &CxxString,
+            bind: &u32,
+            bind_name: &CxxString,
+            nonce_caller: &CxxString,
+            encrypted_salt: &CxxString,
+            session_type: &u8,
+            auth_hash: &u16,
+            serialized_command: Pin<&mut CxxString>,
+            authorization_delegate: Pin<&mut UniquePtr<AuthorizationDelegate>>,
+        ) -> u32;
+
+        /// See Tpm::ParseResponse_StartAuthSession for docs.
+        fn ParseResponse_StartAuthSession(
+            response: &CxxString,
+            session_handle: &mut u32,
+            nonce_tpm: Pin<&mut CxxString>,
+            authorization_delegate: Pin<&mut UniquePtr<AuthorizationDelegate>>,
+        ) -> u32;
+
         /// Returns a serialized representation of the unmodified handle. This
         /// is useful for predefined handle values, like TPM_RH_OWNER. For
         /// details on what types of handles use this name formula see Table 3
@@ -227,6 +308,9 @@ pub mod trunks {
         /// Returns the public area template for the Attestation Identity Key.
         fn AttestationIdentityKeyTemplate() -> UniquePtr<TPM2B_PUBLIC>;
 
+        /// Returns the public area template for the Endorsement Key.
+        fn EndorsementKeyTemplate() -> UniquePtr<TPM2B_PUBLIC>;
+
         /// Returns the public area template for the Storage Root Key.
         fn StorageRootKeyTemplate() -> UniquePtr<TPM2B_PUBLIC>;
 
```

