```diff
diff --git a/Android.bp b/Android.bp
index f924e41..3480184 100644
--- a/Android.bp
+++ b/Android.bp
@@ -184,7 +184,6 @@ cc_defaults {
     name: "nos_cc_defaults",
 
     cflags: [
-        "-pedantic",
         "-Wall",
         "-Wextra",
         "-Werror",
diff --git a/OWNERS b/OWNERS
index 2110bb5..0e826e7 100644
--- a/OWNERS
+++ b/OWNERS
@@ -5,3 +5,4 @@ wfrichar@google.com
 tommychiu@google.com
 zhakevin@google.com
 kroot@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/nugget/include/app_nugget.h b/nugget/include/app_nugget.h
index 70f9649..e44e7b0 100644
--- a/nugget/include/app_nugget.h
+++ b/nugget/include/app_nugget.h
@@ -674,6 +674,21 @@ enum nugget_app_selftest_cmd {
  * AP-side implementation to translate into the info required for the power
  * stats service.
  */
+struct nugget_app_low_power_stats_v0 { /* version 0 */
+  /* All times in usecs */
+  uint64_t hard_reset_count;                    /* Cleared by power loss */
+  uint64_t time_since_hard_reset;
+  /* Below are only since the last hard reset */
+  uint64_t wake_count;
+  uint64_t time_at_last_wake;
+  uint64_t time_spent_awake;
+  uint64_t deep_sleep_count;
+  uint64_t time_at_last_deep_sleep;
+  uint64_t time_spent_in_deep_sleep;
+  uint64_t time_at_ap_reset;
+  uint64_t time_at_ap_bootloader_done;
+} __packed;
+
 #define NUGGET_APP_LOW_POWER_STATS_MAGIC 0xC0DEACE1
 struct nugget_app_low_power_stats { /* version 1 */
   /* All times in usecs */
diff --git a/nugget/include/citadel_events.h b/nugget/include/citadel_events.h
index 00780ad..b8ee69f 100644
--- a/nugget/include/citadel_events.h
+++ b/nugget/include/citadel_events.h
@@ -63,7 +63,7 @@ enum event_id {
   EVENT_ALERT = 1,         // Globalsec alert fired.
   EVENT_REBOOTED = 2,      // Device rebooted.
   EVENT_UPGRADED = 3,      // Device has upgraded.
-  EVENT_ALERT_V2 = 4,      // Globalsec Alertv2 fired
+  EVENT_ALERT_V2 = 4,      // Globalsec Alertv2 fired (Dauntless)
   EVENT_SEC_CH_STATE = 5,  // Update GSA-GSC secure channel state.
   EVENT_V1_NO_SUPPORT =
       6  // Report a VXX event that can't fit in struct event_report.
@@ -75,7 +75,11 @@ enum event_id {
 enum upgrade_state_def {
   UPGRADE_SUCCESS = 0,
   UPGRADE_PW_MISMATCH = 1,
-  UPGRADE_EN_FW_FAIL =2,
+  UPGRADE_EN_FW_FAIL = 2,
+  /* Extended defines to distinguish RO upgrades from RW ones */
+  UPGRADE_SUCCESS_RO = 3,
+  UPGRADE_PW_MISMATCH_RO = 4,
+  UPGRADE_EN_FW_FAIL_RO = 5,
 };
 
 /*
diff --git a/nugget/proto/nugget/app/keymaster/keymaster.proto b/nugget/proto/nugget/app/keymaster/keymaster.proto
index 077fd76..8f1afe9 100644
--- a/nugget/proto/nugget/app/keymaster/keymaster.proto
+++ b/nugget/proto/nugget/app/keymaster/keymaster.proto
@@ -158,6 +158,12 @@ service Keymaster {
    * RKP v3 implementation
    */
   rpc GenerateRkpCsrV2(GenerateRkpCsrV2Request) returns (GenerateRkpCsrV2Response);
+
+  /*
+   * V4 of the HAL.
+   */
+  rpc SetAdditionalAttestationInfo(SetAdditionalAttestationInfoRequest)
+      returns (SetAdditionalAttestationInfoResponse);
   // These are implemented with a enum, so new RPCs must be appended, and
   // deprecated RPCs need placeholders.
 }
@@ -659,3 +665,11 @@ message GenerateRkpCsrV2Response{
   bytes dice_cert_chain = 4;
   bytes signature = 5;
 }
+
+message SetAdditionalAttestationInfoRequest{
+  KeyParameters params = 1;
+}
+
+message SetAdditionalAttestationInfoResponse{
+  ErrorCode error_code = 1;
+}
diff --git a/nugget/proto/nugget/app/keymaster/keymaster_defs.proto b/nugget/proto/nugget/app/keymaster/keymaster_defs.proto
index 642c14c..1ba72d2 100644
--- a/nugget/proto/nugget/app/keymaster/keymaster_defs.proto
+++ b/nugget/proto/nugget/app/keymaster/keymaster_defs.proto
@@ -100,6 +100,7 @@ enum Tag {
   IDENTITY_CREDENTIAL_KEY = 0x702d1;    // (TagType:BOOL | 721)
   STORAGE_KEY = 0x702d2;                // (TagType:BOOL | 722)
   ATTESTATION_ID_SECOND_IMEI = 0x902d3; // (TagType:BYTES | 723)
+  MODULE_HASH = 0x902d4; // (TagType:BYTES | 724)
   ASSOCIATED_DATA = 0x903e8; // (TagType:BYTES | 1000)
   NONCE = 0x903e9; // (TagType:BYTES | 1001)
   /* RESERVED: AUTH_TOKEN = 0x903ea; // (TagType:BYTES | 1002) */
@@ -272,6 +273,7 @@ enum ErrorCode {
   PRODUCTION_KEY_IN_TEST_REQUEST = 85;    // RKP specific.
   TEST_KEY_IN_PRODUCTION_REQUEST = 86;    // RKP specific.
   INVALID_EEK = 87;                       // RKP specific.
+  MODULE_HASH_ALREADY_SET = 88;
 };
 
 enum SecurityLevel {
```

