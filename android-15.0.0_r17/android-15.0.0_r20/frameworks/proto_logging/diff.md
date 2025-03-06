```diff
diff --git a/OWNERS b/OWNERS
index 13fe861a..bfb14022 100644
--- a/OWNERS
+++ b/OWNERS
@@ -15,3 +15,9 @@ per-file settings_enums.proto=edgarwang@google.com
 per-file adservices_enums.proto=binhnguyen@google.com,pdevpura@google.com
 per-file adservices_cel_enums.proto=binhnguyen@google.com,pdevpura@google.com
 
+# Input Framework
+per-file stats/enums/input/... = file:platform/frameworks/base:/INPUT_OWNERS
+
+# Health Connect
+per-file stats/enums/healthfitness/ui/enums.proto=mridulagarwal@google.com
+
diff --git a/stats/Android.bp b/stats/Android.bp
index 0f35118b..753f88dd 100644
--- a/stats/Android.bp
+++ b/stats/Android.bp
@@ -31,6 +31,7 @@ shared_enum_protos = [
 
 enum_protos = [
     "enums/accessibility/*.proto",
+    "enums/accounts/*.proto",
     "enums/adservices/common/*.proto",
     "enums/adservices/enrollment/*.proto",
     "enums/adservices/fledge/*.proto",
@@ -41,12 +42,15 @@ enum_protos = [
     "enums/appsearch/*.proto",
     "enums/art/*.proto",
     "enums/autofill/**/*.proto",
+    "enums/conscrypt/**/*.proto",
     "enums/contexthub/*.proto",
+    "enums/coregraphics/*.proto",
     "enums/corenetworking/**/*.proto",
     "enums/debug/*.proto",
     "enums/devicepolicy/*.proto",
     "enums/dnd/*.proto",
     "enums/federatedcompute/*.proto",
+    "enums/framework/compat/*.proto",
     "enums/hardware/**/*.proto",
     "enums/healthfitness/**/*.proto",
     "enums/hotword/*.proto",
@@ -59,8 +63,10 @@ enum_protos = [
     "enums/neuralnetworks/*.proto",
     "enums/nfc/*.proto",
     "enums/os/*.proto",
+    "enums/performance/*.proto",
     "enums/photopicker/*.proto",
     "enums/pdf/*.proto",
+    "enums/ranging/*.proto",
     "enums/server/*.proto",
     "enums/server/display/*.proto",
     "enums/server/job/*.proto",
@@ -96,6 +102,7 @@ enum_protos = [
     "enums/wear/connectivity/*.proto",
     "enums/wear/media/*.proto",
     "enums/wear/modes/*.proto",
+    "enums/wear/setupwizard/*.proto",
     "enums/wear/time/*.proto",
     "enums/wifi/*.proto",
     "enums/telephony/iwlan/*.proto",
@@ -116,13 +123,16 @@ atom_protos = [
     "atoms.proto",
     "attribution_node.proto",
     "atoms/accessibility/*.proto",
+    "atoms/accounts/*.proto",
     "atoms/adpf/*.proto",
     "atoms/agif/*.proto",
     "atoms/apex/*.proto",
     "atoms/aiwallpapers/*.proto",
     "atoms/art/*.proto",
     "atoms/appsearch/*.proto",
+    "atoms/backported_fixes/*.proto",
     "atoms/bluetooth/*.proto",
+    "atoms/conscrypt/**/*.proto",
     "atoms/corenetworking/**/*.proto",
     "atoms/autofill/*.proto",
     "atoms/credentials/*.proto",
@@ -170,6 +180,7 @@ atom_protos = [
     "atoms/adservices/*.proto",
     "atoms/wear/modes/*.proto",
     "atoms/wear/time/*.proto",
+    "atoms/wear/setupwizard/*.proto",
     "atoms/wearpas/*.proto",
     "atoms/statsd/*.proto",
     "atoms/telecomm/*.proto",
@@ -199,6 +210,12 @@ atom_protos = [
     "atoms/broadcasts/*.proto",
     "atoms/telephony/iwlan/*.proto",
     "atoms/performance/*.proto",
+    "atoms/coregraphics/*.proto",
+    "atoms/automotive/carsystemui/*.proto",
+    "atoms/automotive/carsettings/*.proto",
+    "atoms/automotive/carqclib/*.proto",
+    "atoms/ranging/*.proto",
+    "atoms/appfunctions/*.proto",
 ]
 
 cc_library_host_shared {
diff --git a/stats/atom_field_options.proto b/stats/atom_field_options.proto
index bfd50ad5..2484c4ae 100644
--- a/stats/atom_field_options.proto
+++ b/stats/atom_field_options.proto
@@ -127,6 +127,30 @@ message FieldRestrictionOption {
     optional bool demographic_classification = 9;
 }
 
+message HistogramBinOption {
+    message ExplicitBins {
+        repeated float bin = 1;
+    }
+
+    message GeneratedBins {
+        enum Strategy {
+            UNKNOWN = 0;
+            LINEAR = 1;
+            EXPONENTIAL = 2;
+        }
+
+        optional float min = 1;
+        optional float max = 2;
+        optional int32 count = 3;
+        optional Strategy strategy = 4;
+    }
+
+    oneof binning_strategy {
+        GeneratedBins generated_bins = 1;
+        ExplicitBins explicit_bins = 2;
+    }
+}
+
 extend google.protobuf.FieldOptions {
     // Flags to decorate an atom that presents a state change.
     optional StateAtomFieldOption state_field_option = 50000;
@@ -143,4 +167,6 @@ extend google.protobuf.FieldOptions {
     optional RestrictionCategory restriction_category = 50006;
 
     optional FieldRestrictionOption field_restriction_option = 50007;
+
+    optional HistogramBinOption histogram_bin_option = 50008;
 }
diff --git a/stats/atoms.proto b/stats/atoms.proto
index 31b9044d..98dbf52f 100644
--- a/stats/atoms.proto
+++ b/stats/atoms.proto
@@ -42,10 +42,9 @@ import "frameworks/proto_logging/stats/atoms/sysui/sysui_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/usb/usb_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/view/inputmethod/inputmethod_atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/enums/adservices/fledge/enums.proto";
-import "frameworks/proto_logging/stats/enums/adservices/measurement/enums.proto";
 import "frameworks/proto_logging/stats/enums/anr/enums.proto";
 import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_op_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/job/job_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/remoteprovisioner_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/settings_enums.proto";
@@ -95,7 +94,6 @@ import "frameworks/proto_logging/stats/enums/stats/intelligence/enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/location/location_enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/mediametrics/mediametrics.proto";
 import "frameworks/proto_logging/stats/enums/stats/mediaprovider/mediaprovider_enums.proto";
-import "frameworks/proto_logging/stats/enums/stats/mobiledatadownload/enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/privacysignals/enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/safetycenter/enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/storage/storage_enums.proto";
@@ -1267,17 +1265,73 @@ message Atom {
     extensions 933; // ContentOrFileUriEventReported content_or_file_uri_event_reported
     extensions 934; // CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
     extensions 935; // DesktopModeTaskSizeUpdated desktop_mode_task_size_updated
-    extensions 936; // WsBugreportRequested ws_bugreport_requested
-    extensions 937; // WsBugreportTriggered ws_bugreport_triggered
-    extensions 938; // WsBugreportFinished ws_bugreport_finished
-    extensions 939; // WsBugreportResultReceived ws_bugreport_result_received
+    extensions 940; // DeviceIdleTempAllowlistUpdated device_idle_temp_allowlist_updated
+    extensions 941; // WsNotificationManagedDismissalSync ws_notification_managed_dismissal_sync
+    extensions 942; // PeripheralTutorialLaunched peripheral_tutorial_launched
+    extensions 943; // AppOpNoteOpOrCheckOpBinderApiCalled app_op_note_op_or_check_op_binder_api_called
+    extensions 944; // BiometricUnenrolled biometric_unenrolled
+    extensions 945; // BiometricEnumerated biometric_enumerated
+    extensions 946; // HardwareRendererEvent hardware_renderer_event
+    extensions 947; // TextureViewEvent texture_view_event
+    extensions 948; // SurfaceControlEvent surface_control_event
+    extensions 949; // SysproxyServiceStateUpdated sysproxy_service_state_updated
+    extensions 950; // JankFrameCountByWidgetReported jank_frame_count_by_widget_reported
+    extensions 951; // AccountManagerEvent account_manager_event
+    extensions 952; // OnDevicePersonalizationTraceEvent ondevicepersonalization_trace_event
+    extensions 953; // WearSetupWizardDeviceStatusReported wear_setup_wizard_device_status_reported
+    extensions 954; // WearSetupWizardPairingCompleted wear_setup_wizard_pairing_completed
+    extensions 955; // WearSetupWizardConnectionEstablished wear_setup_wizard_connection_established
+    extensions 956; // WearSetupWizardCheckinCompleted wear_setup_wizard_checkin_completed
+    extensions 957; // WearSetupWizardCompanionTimeReported wear_setup_wizard_companion_time_reported
+    extensions 958; // WearSetupWizardStatusReported wear_setup_wizard_status_reported
+    extensions 959; // WearSetupWizardHeartbeatReported wear_setup_wizard_hearbeat_reported
+    extensions 960; // WearSetupWizardFrpTriggered wear_setup_wizard_frp_triggered
+    extensions 961; // WearSetupWizardSystemUpdateTriggered wear_setup_wizard_system_update_triggered
+    extensions 962; // WearSetupWizardPhoneSwitchTriggered wear_setup_wizard_phone_switch_triggered
+    extensions 963; // HealthConnectPermissionStats health_connect_permission_stats
+    extensions 964; // WsBugreportEventReported ws_bugreport_event_reported
+    extensions 965; // ConscryptServiceUsed conscrypt_service_used
+    extensions 966; // MediaControlApiUsageReported media_control_api_usage_reported
+    extensions 967; // ScheduledCustomAudienceUpdateScheduleAttempted scheduled_custom_audience_update_schedule_attempted
+    extensions 968; // ScheduledCustomAudienceUpdatePerformed scheduled_custom_audience_update_performed
+    extensions 969; // ScheduledCustomAudienceUpdatePerformedAttemptedFailureReported scheduled_custom_audience_update_performed_attempted_failure_reported
+    extensions 970; // ScheduledCustomAudienceUpdateBackgroundJobRan scheduled_custom_audience_update_background_job_ran
+    extensions 971; // ContextualEducationTriggered contextual_education_triggered
+    extensions 972; // CertificateTransparencyLogListUpdateFailed certificate_transparency_log_list_update_failed
+    extensions 973; // Reserved for b/375457523
+    extensions 974; // CarSystemUiDataSubscriptionEventReported car_system_ui_data_subscription_event_reported
+    extensions 975; // CarSettingsDataSubscriptionEventReported car_settings_data_subscription_event_reported
+    extensions 976; // CarQcLibEventReported car_qc_lib_event_reported
+    extensions 977; // ImageDecoded image_decoded
+    extensions 978; // IntentCreatorTokenAdded intent_creator_token_added
+    extensions 979; // CoreNetworkingTerribleErrorOccurred core_networking_terrible_error_occurred
+    extensions 980; // HealthConnectPhrApiInvoked health_connect_phr_api_invoked
+    extensions 981; // HealthConnectPhrUsageStats health_connect_phr_usage_stats
+    extensions 982; // BluetoothRfcommConnectionReportedAtClose bluetooth_rfcomm_connection_reported_at_close
+    extensions 983; // NotificationChannelClassification notification_channel_classification
+    extensions 984; // HealthConnectPhrStorageStats health_connect_phr_storage_stats
+    extensions 985; // HealthConnectRestrictedEcosystemStats health_connect_restricted_ecosystem_stats
+    extensions 986; // HealthConnectEcosystemStats health_connect_ecosystem_stats
+    extensions 987; // BackportedFixStatusReported backported_fix_status_reported
+    extensions 988; // BluetoothLeConnection bluetooth_le_connection
+    extensions 989; // CertificateTransparencyVerificationReported certificate_transparency_verification_reported
+    extensions 990; // MediaSubscriptionChanged media_subscription_changed
+    extensions 991; // HdmiPowerStateChangeOnActiveSourceLostToggled hdmi_power_state_change_on_active_source_lost_toggled
+    extensions 992; // FederatedComputeTraceEventReported federated_compute_trace_event_reported
+    extensions 993; // RangingSessionConfigured ranging_session_configured
+    extensions 994; // RangingSessionStarted ranging_session_started
+    extensions 995; // RangingSessionClosed ranging_session_closed
+    extensions 996; // RangingTechnologyStarted ranging_technology_started
+    extensions 997; // RangingTechnologyStopped ranging_technology_stopped
+    extensions 998; // AppFunctionsRequestReported app_functions_request_reported
+    extensions 999; // CameraStatusForCompatibilityChanged camera_status_for_compatibility_changed
     extensions 9999; // Atom9999 atom_9999
 
     // StatsdStats tracks platform atoms with ids up to 900.
     // Update StatsdStats::kMaxPushedAtomId when atom ids here approach that value.
 
     // Pulled events will start at field 10000.
-    // Next: 10230
+    // Next: 10231
     oneof pulled {
         WifiBytesTransfer wifi_bytes_transfer = 10000 [(module) = "framework"];
         WifiBytesTransferByFgBg wifi_bytes_transfer_by_fg_bg = 10001 [(module) = "framework"];
@@ -1543,12 +1597,13 @@ message Atom {
     extensions 10227; // WsWatchFaceCustomizationSnapshot ws_watch_face_customization_snapshot
     // 10228 is reserved due to removing the old atom
     extensions 10229; // PressureStallInformation pressure_stall_information
+    extensions 10230; // FrameworkWakelockInfo framework_wakelock_info
     extensions 99999; // Atom99999 atom_99999
 
     // DO NOT USE field numbers above 100,000 in AOSP.
     // Field numbers 100,000 - 199,999 are reserved for non-AOSP (e.g. OEMs) to use.
     // Field numbers 200,000 and above are reserved for future use; do not use them at all.
-    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 10008, 10036, 10040, 10041, 10228, 21004, 21005;
+    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 936, 937, 938, 939, 10008, 10036, 10040, 10041, 10228, 21004, 21005;
 }
 
 /*
@@ -2523,7 +2578,7 @@ message DeferredJobStatsReported {
  *   frameworks/base/services/core/java/com/android/server/job/JobSchedulerService.java
  *   frameworks/base/services/core/java/com/android/server/job/JobServiceContext.java
  *
- * Next tag: 54
+ * Next tag: 57
  */
 message ScheduledJobStateChanged {
     repeated AttributionNode attribution_node = 1;
@@ -2712,6 +2767,21 @@ message ScheduledJobStateChanged {
     // JobInfo.Builder.addDebugTag(). Basic PII filtering has been applied,
     // but further filtering should be done by clients.
     repeated string filtered_debug_tags = 53;
+
+    // Number of reschedules due to job being abandoned.
+    optional int32 num_reschedules_due_to_abandonment = 54;
+
+    // Back off policy applied to the job that gets rescheduled.
+    // This is defined in JobInfo.java (See JobInfo.BACKOFF_POLICY_*).
+    enum BackOffPolicyType {
+        UNKNOWN_POLICY = 0;
+        LINEAR = 1;
+        EXPONENTIAL = 2;
+    }
+    // Back off policy applied to the job that gets rescheduled.
+    optional BackOffPolicyType back_off_policy_type  = 55;
+    // Is back off policy restriction applied due to abandoned job.
+    optional bool is_back_off_policy_restriction_applied = 56;
 }
 
 /**
@@ -2851,7 +2921,8 @@ message InteractiveStateChanged {
         OFF = 0;
         ON = 1;
     }
-    optional State state = 1;
+    optional State state = 1
+            [(state_field_option).exclusive_state = true, (state_field_option).nested = false];
 }
 
 /**
@@ -3076,7 +3147,8 @@ message WifiLockStateChanged {
  */
 message WifiSignalStrengthChanged {
     // Signal strength, from frameworks/proto_logging/stats/enums/telephony/enums.proto.
-    optional android.telephony.SignalStrengthEnum signal_strength = 1;
+    optional android.telephony.SignalStrengthEnum signal_strength = 1
+            [(state_field_option).exclusive_state = true, (state_field_option).nested = false];
 }
 
 /**
@@ -4813,12 +4885,16 @@ message ThermalThrottlingSeverityStateChanged {
 /**
  * Logs phone signal strength changes.
  *
+ * The atom doesn't tell which SIM had signal strength changed -- use with caution when there are
+ * multiple SIMs present.
+ *
  * Logged from:
  *   frameworks/base/core/java/com/android/internal/os/BatteryStatsImpl.java
  */
 message PhoneSignalStrengthChanged {
     // Signal strength, from frameworks/proto_logging/stats/enums/telephony/enums.proto.
-    optional android.telephony.SignalStrengthEnum signal_strength = 1;
+    optional android.telephony.SignalStrengthEnum signal_strength = 1
+            [(state_field_option).exclusive_state = true, (state_field_option).nested = false];
 }
 
 
@@ -6508,6 +6584,8 @@ message BiometricEnrolled {
     optional float ambient_light_lux = 6;
     // The source for where this enrollment came frame
     optional android.hardware.biometrics.EnrollmentSourceEnum enroll_source = 7;
+    // Numerical ID for enrolled template that increments with every new enrollment. Eg: 1, 2...
+    optional int32 template_id = 8;
 }
 
 
@@ -9658,6 +9736,7 @@ message BatteryUsageStatsAtomsProto {
                 FOREGROUND = 1;
                 BACKGROUND = 2;
                 FOREGROUND_SERVICE = 3;
+                // Keep in sync with BatteryUsageStatsPerUid.ProcessState.
             }
 
             optional ProcessState process_state = 2;
@@ -9684,6 +9763,7 @@ message BatteryUsageStatsAtomsProto {
                 FOREGROUND = 1;
                 BACKGROUND = 2;
                 FOREGROUND_SERVICE = 3;
+                // Keep in sync with BatteryUsageStatsPerUid.ProcessState.
             }
 
             optional ProcessState process_state = 1;
@@ -14589,7 +14669,7 @@ message PerfettoUploaded {
     // "PERFETTO_CMD" prefix to make clear they are specific to perfetto_cmd.
     // This state exists because of legacy reasons (i.e. these values existed
     // before go/perfetto-monitoring was a thing).
-    // Next id: 57.
+    // Next id: 60.
     enum Event {
         PERFETTO_UNDEFINED = 0;
 
@@ -14599,6 +14679,8 @@ message PerfettoUploaded {
         PERFETTO_CMD_CLONE_TRACE_BEGIN = 55;
         PERFETTO_CMD_CLONE_TRIGGER_TRACE_BEGIN = 56;
         PERFETTO_ON_CONNECT = 3;
+        PERFETTO_CMD_ON_SESSION_CLONE = 58;
+        PERFETTO_CMD_ON_TRIGGER_CLONE = 59;
 
         // Guardrails inside perfetto_cmd before tracing is finished.
         PERFETTO_ON_TIMEOUT = 16;
@@ -14703,17 +14785,22 @@ message PerfettoTrigger {
     enum Event {
         PERFETTO_UNDEFINED = 0;
 
-        PERFETTO_CMD_TRIGGER = 1;
-        PERFETTO_CMD_TRIGGER_FAIL = 2;
-
-        PERFETTO_TRIGGER_PERFETTO_TRIGGER = 3;
-        PERFETTO_TRIGGER_PERFETTO_TRIGGER_FAIL = 4;
-
         PERFETTO_TRACED_LIMIT_PROBABILITY = 5;
         PERFETTO_TRACED_LIMIT_MAX_PER_24_H = 6;
 
-        PERFETTO_PROBES_PRODUCER_TRIGGER = 7;
-        PERFETTO_PROBES_PRODUCER_TRIGGER_FAIL = 8;
+        PERFETTO_TRACED_TRIGGER = 9;
+
+        // Contained events of logging triggers through perfetto_cmd, probes and
+        // trigger_perfetto. Obsolete because of logging dirctly in traced instead.
+        // Removed in W (Oct 2024) and replaced by |kTracedTrigger|.
+        PERFETTO_CMD_TRIGGER = 1 [deprecated = true];
+        PERFETTO_CMD_TRIGGER_FAIL = 2 [deprecated = true];
+
+        PERFETTO_TRIGGER_PERFETTO_TRIGGER = 3 [deprecated = true];
+        PERFETTO_TRIGGER_PERFETTO_TRIGGER_FAIL = 4 [deprecated = true];
+
+        PERFETTO_PROBES_PRODUCER_TRIGGER = 7 [deprecated = true];
+        PERFETTO_PROBES_PRODUCER_TRIGGER_FAIL = 8 [deprecated = true];
     }
 
     // The event which fired.
@@ -18277,6 +18364,17 @@ message HdmiCecMessageReported {
 
     // The reason for the feature abort.
     optional android.stats.hdmi.FeatureAbortReason feature_abort_reason = 9;
+
+    // The physical address in <Report Physical Address> messages. Consists of
+    // four hexadecimal nibbles. Examples: 0x1234, 0x0000 (root device). 0xFFFF
+    // represents an unknown or invalid address.
+    //
+    // Physical address is assigned to each device through a discovery process.
+    // It indicates the connection hierarchy, for example, 1:2:0:0 is under
+    // 1:0:0:0, which is under 0:0:0:0.
+    //
+    // See section 8.7 in the HDMI 1.4b spec for details.
+    optional int32 physical_address = 10;
 }
 
 /**
@@ -21930,8 +22028,10 @@ message MobileBundledAppInfoGathered {
         UPDATED_PRELOAD = 2;
         NEW_MBA = 3;
         UPDATED_NEW_MBA = 4;
+        DOWNGRADED_PRELOADED = 5;
+        UNINSTALLED_MBA = 6;
     }
-    // whether or not the MBA is preloaded or dynamically installed
+    // whether the MBA is preloaded, dynamically installed, or uninstalled/downgraded
     optional MBAStatus mba_status = 6;
     // the package that initiated the installation of this MBA
     optional string initiator = 7;
@@ -24273,6 +24373,7 @@ message WsTileListChanged {
         EVENT_UNKNOWN = 0;
         TILE_ADDED = 1;
         TILE_REMOVED = 2;
+        TILE_UPDATED = 3;  // go/wear-dd-tiles-oem-metadata
     }
     // Component package for the tile that is being changed.
     optional int32 component_package_uid = 1 [(is_uid) = true];
@@ -24303,6 +24404,13 @@ message WsTileSnapshot {
 
     // Class name for the tiles.
     repeated string component_class_name = 2;
+
+    // The size in bytes of the vendor-specific metadata associated with this
+    // tile.  It will be zero (or not present) if no vendor-specific metadata is
+    // associated with the tile or the associated metadata is empty.
+    //
+    // See go/wear-dd-tiles-oem-metadata for details.
+    repeated int32 vendor_metadata_size_bytes = 3;
 }
 /*
 * Logs calls to getType of a contentProvider, where the caller has potentially no access to
diff --git a/stats/atoms/accounts/accounts_extension_atoms.proto b/stats/atoms/accounts/accounts_extension_atoms.proto
new file mode 100644
index 00000000..0309f219
--- /dev/null
+++ b/stats/atoms/accounts/accounts_extension_atoms.proto
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
+syntax = "proto2";
+
+package android.os.statsd.accounts;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/accounts/enums.proto";
+
+option java_package = "com.android.os.accounts";
+option java_multiple_files = true;
+
+extend Atom {
+    optional AccountManagerEvent account_manager_event = 951 [(module) = "framework"];
+}
+/**
+ * AccountManagerService logs.
+ *
+ * Logged from:
+ *  services/core/java/com/android/server/accounts/
+ */
+message AccountManagerEvent {
+  optional string account_type = 1; // AccountManager.KEY_ACCOUNT_TYPE
+  optional int32 calling_uid = 2 [(is_uid) = true];
+  optional AccountEventType event_type = 3;
+}
diff --git a/stats/atoms/adservices/adservices_extension_atoms.proto b/stats/atoms/adservices/adservices_extension_atoms.proto
index 2ab69688..eee08529 100644
--- a/stats/atoms/adservices/adservices_extension_atoms.proto
+++ b/stats/atoms/adservices/adservices_extension_atoms.proto
@@ -216,6 +216,15 @@ extend Atom {
 
   optional TopicsScheduleEpochJobSettingReported topics_schedule_epoch_job_setting_reported = 930
   [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional ScheduledCustomAudienceUpdateScheduleAttempted scheduled_custom_audience_update_schedule_attempted = 967
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional ScheduledCustomAudienceUpdatePerformed scheduled_custom_audience_update_performed = 968
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional ScheduledCustomAudienceUpdatePerformedAttemptedFailureReported scheduled_custom_audience_update_performed_attempted_failure_reported = 969
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional ScheduledCustomAudienceUpdateBackgroundJobRan scheduled_custom_audience_update_background_job_ran = 970
+  [(module) = "adservices", (truncate_timestamp) = true];
 }
 
 /**
@@ -1131,6 +1140,12 @@ message UpdateSignalsApiCalled {
  * Logs per encoding background job run
  */
 message EncodingJobRun {
+    enum EncodingSourceType {
+      UNSET = 0;
+      PAS_ENCODING_JOB_SERVICE = 1;
+      PAS_SERVICE_IMPL = 2;
+    }
+
     // The number of adtechs who successfully encoded in this background job run
     optional int32 signal_encoding_successes = 1;
 
@@ -1139,6 +1154,9 @@ message EncodingJobRun {
 
     // The number of adtechs skipped due to their signals being unmodified
     optional int32 signal_encoding_skips = 3;
+
+    // The encoding resource type
+    optional EncodingSourceType encoding_source_type = 4;
 }
 
 /*
@@ -1457,6 +1475,7 @@ message AdServicesMeasurementRegistrations {
   optional int32 num_entities_deleted = 14;
   optional bool is_event_level_epsilon_configured = 15;
   optional bool is_trigger_aggregatable_value_filters_configured = 16;
+  optional bool is_trigger_filtering_id_configured = 17;
 }
 
 
@@ -2104,3 +2123,119 @@ message TopicsScheduleEpochJobSettingReported {
   // The epoch job setting when scheduling the epoch job in EpochJobService.scheduleIfNeeded().
   optional EpochJobBatteryConstraint schedule_if_needed_epoch_job_status = 4;
 }
+
+/**
+ * Logs when an update for custom audience is scheduled using ScheduledCustomAudienceUpdate API.
+ *
+ * Pushed from:
+ *   packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/customaudience/ScheduleCustomAudienceUpdateImpl.java
+ */
+message ScheduledCustomAudienceUpdateScheduleAttempted {
+  // Denotes the existing status before the update is performed.
+  enum ExistingUpdateStatus {
+    UNKNOWN = 0;
+    DID_OVERWRITE_EXISTING_UPDATE = 1;
+    NO_EXISTING_UPDATE = 2;
+    REJECTED_BY_EXISTING_UPDATE = 3;
+  }
+
+  // Number of partial custom audiences in the schedule CA update.
+  optional int32 num_partial_custom_audiences = 1;
+
+  // Delay in minutes after which custom audiences are scheduled to be updated.
+  optional int32 min_delay_minutes = 2;
+
+  // Field denoting if there was an already pending update in the database.
+  optional ExistingUpdateStatus existing_update_status = 3;
+
+  // Number of leave custom audience in the schedule CA update.
+  optional int32 num_leave_custom_audiences = 4;
+
+  // boolean denoting if the schedule CA update scheduled is for the second hop.
+  optional bool is_second_hop = 5;
+}
+
+/**
+ * Logs for ScheduledCustomAudienceUpdate after the update is performed.
+ *
+ * Pushed from:
+ *   packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/customaudience/ScheduleUpdatesHandler.java
+ */
+message ScheduledCustomAudienceUpdatePerformed {
+  // number of partial custom audience in the schedule ca update request.
+  optional int32 num_partial_custom_audiences_in_request = 1;
+
+  // number of custom audiences to be joined in the response from the server.
+  optional int32 num_join_custom_audiences_in_response = 2;
+
+  // number of custom audiences actually joined.
+  optional int32 num_custom_audiences_joined = 3;
+
+  // number of custom audiences to leave in schedule ca update request.
+  optional int32 num_leave_custom_audiences_in_request = 4;
+
+  // number of custom audience to in the response from the server.
+  optional int32 num_leave_custom_audiences_in_response = 5;
+
+  // number of actual custom audiences left.
+  optional int32 num_custom_audiences_left = 6;
+
+  // boolean denoting if the schedule CA update performed was the initial hop.
+  optional bool was_initial_hop = 7;
+
+  // number of schedule CA updates in the response from the server.
+  optional int32 num_schedule_updates_in_response = 8;
+
+  // number of CA schedules for a update.
+  optional int32 num_updates_scheduled = 9;
+}
+
+/**
+ * Logs for the scheduleCustomAudienceUpdate background job.
+ *
+ * Pushed from:
+ *   packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/customaudience/ScheduleUpdatesHandler.java
+ *
+ * Estimated Logging Rate:
+ *  Peak: 1 time in 1 hour | Avg: 24 per device per day.
+ */
+message ScheduledCustomAudienceUpdateBackgroundJobRan {
+  // number of schedule custom audience update found in the queue (database).
+  optional int32 num_updates_found = 1;
+
+  // number of schedule custom audience updates performed successfully.
+  optional int32 num_successful_updates = 2;
+}
+
+/**
+ * Logs for failure during updating Scheduled custom audience.
+ *
+ * Pushed from:
+ *   packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/customaudience/ScheduleUpdatesHandler.java
+ */
+message ScheduledCustomAudienceUpdatePerformedAttemptedFailureReported {
+  // Enum denoting the type of failure logged.
+  enum FailureType {
+    UNKNOWN = 0;
+    HTTP_UNKNOWN = 1;
+    HTTP_TOO_MANY_REQUESTS = 2;
+    HTTP_REDIRECTION = 3;
+    HTTP_CLIENT_ERROR = 4;
+    HTTP_SERVER_ERROR = 5;
+    JSON_PARSING_ERROR = 6;
+    INTERNAL_ERROR = 7;
+    HTTP_IO_EXCEPTION = 8;
+    HTTP_CONTENT_SIZE_EXCEPTION = 9;
+  }
+  /// Enum denoting the action that caused the failure.
+  enum FailureAction {
+    HTTP_CALL = 0;
+    LEAVE_CUSTOM_AUDIENCE = 1;
+    JOIN_CUSTOM_AUDIENCE = 2;
+    SCHEDULE_CUSTOM_AUDIENCE = 3;
+  }
+
+  optional FailureType failure_type = 1;
+  optional FailureAction failure_action = 2;
+}
+
diff --git a/stats/atoms/appfunctions/app_functions_extension_atoms.proto b/stats/atoms/appfunctions/app_functions_extension_atoms.proto
new file mode 100644
index 00000000..7f6cccb7
--- /dev/null
+++ b/stats/atoms/appfunctions/app_functions_extension_atoms.proto
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
+syntax = "proto2";
+
+package android.os.statsd.appfunctions;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.appfunctions";
+option java_multiple_files = true;
+
+extend Atom {
+  optional AppFunctionsRequestReported app_functions_request_reported = 998 [(module) = "appfunctions"];
+}
+
+/** Logs information on AppFunction execution requests. */
+message AppFunctionsRequestReported {
+  // Uid of the agent app.
+  optional int32 caller_package_uid = 1 [(is_uid) = true];
+  // Uid of the app that hosts the function.
+  optional int32 target_package_uid = 2 [(is_uid) = true];
+  // The error code of the response, or -1 if no error is present.
+  optional int32 error_code = 3;
+  // The size of the request in bytes.
+  optional int32 request_size_bytes = 4;
+  // The size of the response in bytes.
+  optional int32 response_size_bytes = 5;
+  // The duration of the request in milliseconds.
+  optional int64 request_duration_ms = 6;
+}
diff --git a/stats/atoms/appsearch/appsearch_extension_atoms.proto b/stats/atoms/appsearch/appsearch_extension_atoms.proto
index a6f60d52..67101d5e 100644
--- a/stats/atoms/appsearch/appsearch_extension_atoms.proto
+++ b/stats/atoms/appsearch/appsearch_extension_atoms.proto
@@ -304,4 +304,13 @@ message AppSearchAppsIndexerStatsReported {
   // Timestamps
   optional int64 update_start_wallclock_timestamp_millis = 12;
   optional int64 last_app_updated_wallclock_timestamp_millis = 13;
+
+  // App Function counts
+  optional int32 number_of_functions_added = 14;
+  optional int32 number_of_functions_removed = 15;
+  optional int32 number_of_functions_updated = 16;
+  optional int32 number_of_functions_unchanged = 17;
+
+  // App Function removal latency
+  optional int64 remove_functions_from_appsearch_appsearch_latency_millis = 18;
 }
diff --git a/stats/atoms/automotive/carqclib/carqclib_extension_atoms.proto b/stats/atoms/automotive/carqclib/carqclib_extension_atoms.proto
new file mode 100644
index 00000000..ff260ee0
--- /dev/null
+++ b/stats/atoms/automotive/carqclib/carqclib_extension_atoms.proto
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
+syntax = "proto2";
+
+package android.os.statsd.automotive.carqclib;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.automotive.carqclib";
+option java_multiple_files = true;
+
+extend Atom {
+  optional CarQcLibEventReported car_qc_lib_event_reported = 976 [(module) = "carqclib"];
+}
+
+/**
+ * Logs when an event happens in car quick controls.
+ *
+ * Logged from package: packages/apps/Car/systemlibs/car-qc-lib
+ */
+
+message CarQcLibEventReported {
+  // Quick Control element types
+  enum ElementType {
+    UNSPECIFIED_ELEMENT_TYPE = 0;
+    QC_TYPE_LIST = 1;
+    QC_TYPE_ROW = 2;
+    QC_TYPE_TILE = 3;
+    QC_TYPE_SLIDER = 4;
+    QC_TYPE_ACTION_SWITCH = 5;
+    QC_TYPE_ACTION_TOGGLE = 6;
+  }
+
+  // The uid of the quick control provider package
+  optional int32 package_uid = 1 [(is_uid) = true];
+  // The SHA-256 hashed tag of the quick control element.
+  optional string qc_hashed_tag = 2;
+  optional ElementType element_type = 3;
+  // The value of the qc element (e.g, a slider can have value from 1-100)
+  optional int32 qc_value = 4;
+  // The state of the qc element (e.g, a switch can have on/off state)
+  optional bool qc_state = 5;
+}
diff --git a/stats/atoms/automotive/carsettings/carsettings_extension_atoms.proto b/stats/atoms/automotive/carsettings/carsettings_extension_atoms.proto
new file mode 100644
index 00000000..2b255124
--- /dev/null
+++ b/stats/atoms/automotive/carsettings/carsettings_extension_atoms.proto
@@ -0,0 +1,39 @@
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
+syntax = "proto2";
+
+package android.os.statsd.automotive.carsettings;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.automotive.carsettingss";
+option java_multiple_files = true;
+
+extend Atom {
+  optional CarSettingsDataSubscriptionEventReported car_settings_data_subscription_event_reported = 975 [(module) = "carsettings"];
+}
+
+/**
+ * Logs when a data subscription event happens in carsettings.
+ *
+ * Logged from package: packages/apps/Car/Settings
+ * Estimated Logging Rate:
+ * Peak: 1 times in 30000 ms | Avg: 10 per device per day
+ */
+
+message CarSettingsDataSubscriptionEventReported {
+}
diff --git a/stats/atoms/automotive/carsystemui/carsystemui_extension_atoms.proto b/stats/atoms/automotive/carsystemui/carsystemui_extension_atoms.proto
new file mode 100644
index 00000000..4e755c8e
--- /dev/null
+++ b/stats/atoms/automotive/carsystemui/carsystemui_extension_atoms.proto
@@ -0,0 +1,65 @@
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
+syntax = "proto2";
+
+package android.os.statsd.automotive.carsystemui;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.automotive.carsystemui";
+option java_multiple_files = true;
+
+extend Atom {
+  optional CarSystemUiDataSubscriptionEventReported car_system_ui_data_subscription_event_reported = 974 [(module) = "carsystemui"];
+}
+
+/**
+ * Logs when a data subscription event occurs in carsystemui.
+ *
+ * Logged from package: packages/apps/Car/SystemUI
+ *  Estimated Logging Rate:
+ *  Peak: 1 times in 30000 ms | Avg: 10 per device per day
+ */
+
+message CarSystemUiDataSubscriptionEventReported {
+    // Describes current type of data subscription event
+    enum DataSubscriptionEventType {
+    // Unknown data subscrition event type
+    UNSPECIFIED_EVENT_TYPE = 0;
+    // Event starts (e.g. popup appears)
+    SESSION_STARTED = 1;
+    // Event fisnishes (e.g. popup dismisses)
+    SESSION_FINISHED = 2;
+    // The user clicks on the button in the popup
+    BUTTON_CLICKED = 3;
+  }
+
+    // Describes the current type of the data subscription message
+    enum DataSubscriptionMessageType {
+    // Unknown data subscription message type
+    UNSPECIFIED_MESSAGE_TYPE = 0;
+    // Proactive message type
+    PROACTIVE = 1;
+    // Reactive message type
+    REACTIVE = 2;
+  }
+
+  // session of one data subscription cycle, marked a start event to a finish event
+  optional int64 session_id = 1;
+  optional DataSubscriptionEventType event_type = 2;
+  optional DataSubscriptionMessageType message_type = 3;
+}
diff --git a/stats/atoms/backported_fixes/backported_fixes_extension_atoms.proto b/stats/atoms/backported_fixes/backported_fixes_extension_atoms.proto
new file mode 100644
index 00000000..4cf61617
--- /dev/null
+++ b/stats/atoms/backported_fixes/backported_fixes_extension_atoms.proto
@@ -0,0 +1,50 @@
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
+syntax = "proto2";
+
+package android.os.statsd.backportedfixes;
+
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/os/enums.proto";
+
+extend Atom {
+  optional BackportedFixStatusReported backported_fix_status_reported = 987
+      [(module) = "framework"];
+}
+/**
+ * Logs the response of a call to Build.getBackportedFixStatus()
+ *
+ * Since android BAKLAVA
+ */
+message BackportedFixStatusReported {
+
+  // The uid of the app that requested the critical issue status.
+  optional int32 uid = 1 [(is_uid) = true];
+
+  /**
+   * The id of the known issue.
+   *
+   * https://issuetracker.google.com/issues/{id}
+   */
+  optional int64 id = 2;
+
+  /**
+   * The status of the known issue on the device.
+   */
+  optional android.os.BackportedFixStatus status = 3;
+}
diff --git a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
index 5422c71d..139e40b8 100644
--- a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
+++ b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
@@ -70,6 +70,10 @@ extend Atom {
         = 927 [(module) = "bluetooth"];
     optional BroadcastAudioSyncReported broadcast_audio_sync_reported
         = 928 [(module) = "bluetooth"];
+    optional BluetoothRfcommConnectionReportedAtClose bluetooth_rfcomm_connection_reported_at_close
+        = 982 [(module) = "bluetooth"];
+    optional BluetoothLeConnection bluetooth_le_connection
+        = 988 [(module) = "bluetooth"];
 }
 
 /**
@@ -255,6 +259,20 @@ message BluetoothProfileConnectionAttempted {
   optional BluetoothRemoteDeviceInformation remote_device_information = 6 [(log_mode) = MODE_BYTES];
 }
 
+/**
+ * Logs LE connection success or failure.
+ *
+ * Logged from:
+ *     packages/modules/Bluetooth
+ */
+message BluetoothLeConnection {
+  // Result of LE connection
+  optional android.bluetooth.LeConnectionResult result = 1;
+
+  // Remote Device Information
+  optional BluetoothRemoteDeviceInformation remote_device_information = 2 [(log_mode) = MODE_BYTES];
+}
+
 /**
  * Logs content profiles' caught exceptions or logs (ERROR, WARN)
  *
@@ -518,6 +536,8 @@ message A2dpSessionReported {
   optional int64 codec_id = 10;
   // Indicates whether the session is offloaded or not.
   optional bool offload = 11;
+  // Identifier for the remote device.
+  optional int32 metric_id = 12;
 }
 
 /**
@@ -605,4 +625,29 @@ message BroadcastAudioSyncReported {
 
   // Remote Device Information
   optional BluetoothRemoteDeviceInformation remote_device_information = 7 [(log_mode) = MODE_BYTES];
-}
\ No newline at end of file
+}
+
+/**
+  * Logs RFCOMM connection attempts from the native layer after the connection closes
+  *
+  * Logged from:
+  *     packages/modules/Bluetooth
+  *
+  * Estimated Logging Rate:
+  *     Peak: 5 times in 30 seconds | Avg: 4 per device per day
+  *
+*/
+message BluetoothRfcommConnectionReportedAtClose {
+  // Reason for error or closure
+  optional android.bluetooth.rfcomm.PortResult close_reason = 1;
+  // security level of the connection
+  optional android.bluetooth.rfcomm.SocketConnectionSecurity security = 2;
+  // two states prior to "CLOSED"
+  optional android.bluetooth.rfcomm.RfcommPortState second_previous_state = 3;
+  // state prior to "CLOSED"
+  optional android.bluetooth.rfcomm.RfcommPortState previous_state = 4;
+  // duration that the socket was opened, 0 if connection failed
+  optional int32 open_duration_ms = 5;
+  // uid of the app that called connect
+  optional int32 uid = 6 [(is_uid) = true];
+}
diff --git a/stats/atoms/conscrypt/conscrypt_extension_atoms.proto b/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
index cc0b4e66..e127de1c 100644
--- a/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
+++ b/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
@@ -4,28 +4,20 @@ package android.os.statsd.conscrypt;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/conscrypt/ct/enums.proto";
 
 option java_package = "com.android.os.conscrypt";
 
 extend Atom {
     optional CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed = 934 [(module) = "conscrypt"];
-}
-
-enum LogListStatus {
-    STATUS_UNKNOWN = 0;
-    STATUS_SUCCESS = 1;           // The list was loaded successfully.
-    STATUS_NOT_FOUND = 2;         // The list file was not found.
-    STATUS_PARSING_FAILED = 3;    // The list file failed to parse.
-    STATUS_EXPIRED = 4;           // The timestamp on the list is older than expected for the policy.
-}
-
-enum LogListCompatibilityVersion {
-    COMPAT_VERSION_UNKNOWN = 0;
-    COMPAT_VERSION_V1 = 1;
+    optional ConscryptServiceUsed conscrypt_service_used = 965 [(module) = "conscrypt"];
+    optional CertificateTransparencyVerificationReported certificate_transparency_verification_reported = 989 [(module) = "conscrypt"];
 }
 
 /*
  * Pushed atom on how successful was the loading of the log list.
+ * Pushed from:
+ *   external/conscrypt/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
  */
 message CertificateTransparencyLogListStateChanged {
     // The status of the log list.
@@ -34,11 +26,88 @@ message CertificateTransparencyLogListStateChanged {
     // The compatibility version.
     optional LogListCompatibilityVersion loaded_compat_version = 2;
 
-    // All compatibility versions available.
-    repeated LogListCompatibilityVersion available_compat_versions = 3 [packed = true];
+    // The minimum compatibility version available.
+    optional LogListCompatibilityVersion min_compat_version = 3;
 
     // Log list version.
     optional int32 major_version = 4;
     optional int32 minor_version = 5;
 }
 
+/*
+ * Pushed atom on certificate transparency verification outcome.
+ * Pushed from:
+ *   external/conscrypt/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
+ */
+message CertificateTransparencyVerificationReported {
+  // The outcome of the verification.
+  optional VerificationResult result = 1;
+
+  // Why was the verification triggered? Is it a default or opt-in by the app?
+  optional VerificationReason reason = 2;
+
+  // Log list version and the compatibility version.
+  optional LogListCompatibilityVersion policy_compatibility_version = 3;
+  optional int32 major_version = 4;
+  optional int32 minor_version = 5;
+
+  // The number of SCTs found for each origin.
+  optional int32 num_cert_scts = 6;
+  optional int32 num_ocsp_scts = 7;
+  optional int32 num_tls_scts = 8;
+}
+
+/**
+ * Pushed algorithm usage counters from Conscrypt.
+ * Pushed from:
+ *   external/conscrypt/common/src/main/java/org/conscrypt/metrics/StatsLogImpl.java
+ */
+
+enum Algorithm {
+  UNKNOWN_ALGORITHM = 0;
+  CIPHER = 1;
+  SIGNATURE = 2;
+}
+
+enum Cipher {
+  UNKNOWN_CIPHER = 0;
+  AES = 1;
+  DES = 2;
+  DESEDE = 3;
+  DSA = 4;
+  BLOWFISH = 5;
+  CHACHA20 = 6;
+  RSA = 7;
+  ARC4 = 8;
+}
+
+enum Mode {
+  NO_MODE = 0;
+  CBC = 1;
+  CTR = 2;
+  ECB = 3;
+  CFB = 4;
+  CTS = 5;
+  GCM = 6;
+  GCM_SIV = 7;
+  OFB = 8;
+  POLY1305 = 9;
+}
+
+enum Padding {
+  NO_PADDING = 0;
+  OAEP_SHA512 = 1;
+  OAEP_SHA384 = 2;
+  OAEP_SHA256 = 3;
+  OAEP_SHA224 = 4;
+  OAEP_SHA1 = 5;
+  PKCS1 = 6;
+  PKCS5 = 7;
+  ISO10126 = 8;
+}
+message ConscryptServiceUsed {
+  optional Algorithm algorithm = 1;
+  optional Cipher cipher = 2;
+  optional Mode mode = 3;
+  optional Padding padding = 4;
+}
diff --git a/stats/atoms/coregraphics/coregraphics_extension_atoms.proto b/stats/atoms/coregraphics/coregraphics_extension_atoms.proto
new file mode 100644
index 00000000..7abc9b0b
--- /dev/null
+++ b/stats/atoms/coregraphics/coregraphics_extension_atoms.proto
@@ -0,0 +1,138 @@
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
+syntax = "proto2";
+
+package android.os.statsd.coregraphics;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/coregraphics/enums.proto";
+
+option java_multiple_files = true;
+option java_package = "com.android.os.coregraphics";
+
+extend Atom {
+  optional HardwareRendererEvent hardware_renderer_event = 946 [(module) = "hwui"];
+  optional TextureViewEvent texture_view_event = 947 [(module) = "hwui"];
+  optional SurfaceControlEvent surface_control_event = 948 [(module) = "surfaceflinger"];
+  optional ImageDecoded image_decoded = 977 [(module) = "hwui"];
+}
+
+/**
+ * An event logged from HardwareRenderer describing a subset of the HardwareRenderer's state
+ * immediately prior to logging this event.
+
+ * Logged from HardwareRenderer.java
+
+ * Estimated Logging Rate:
+ *    Peak: 1 time in 16ms | Avg: 1000 per device per day
+ * The peak logging rate is pessimally estimated from one color mode change per frame
+ * rendered on a 60Hz device.
+ * The average logging rate is estimated from typical usage, where an app's color
+ * mode changes once open being opened, so this assumes that a user opens
+ * 1000 applications per day.
+ */
+message HardwareRendererEvent {
+    // UID of the application rendering to the ViewRoot
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // Duration in milliseconds of how far in the past the ViewRoot state was
+    // updated
+    optional int64 time_since_last_event_millis = 2;
+
+    // The window's color mode, controlling the colorspace the ViewRoot is
+    // rendering into
+    enum ColorMode {
+        DEFAULT = 0;
+        WIDE_COLOR = 1;
+        HDR = 2;
+    }
+    // The previous color mode for the window
+    optional ColorMode previous_color_mode = 3;
+}
+
+/**
+ * An event logged from TextureView describing a subset of the TextureView's content
+ * immediately prior to logging this event.
+ *
+ * Logged from DeferredLayerUpdater.cpp
+ *
+ * Estimated Logging Rate:
+ *    Peak: 1 time in 16ms | Avg: 500 per device per day
+ * The peak logging rate is pessimally estimated from one dataspace change per video
+ * frame decoded from 60Hz video source files
+ * The average logging rate is estimated from typical usage, where the dataspace
+ * exactly once per video file, so this assumes that a user is watching ~500 videos,
+ * including short-form video, per day.
+ */
+message TextureViewEvent {
+    // UID of the application using the TextureView.
+    optional int32 uid = 1 [(is_uid) = true];
+    // Duration in milliseconds of how far in the past the TextureView state was
+    // updated
+    optional int64 time_since_last_event_millis = 2;
+    // The previous dataspace of the TextureView's content
+    optional int32 previous_dataspace = 3;
+}
+
+/**
+ * An event logged from SurfaceFlinger describing a subset of a SurfaceControl's state
+ * immediately prior to logging this event.
+ *
+ * Logged from system_server, routed from SurfaceFlinger
+ *
+ * Estimated Logging Rate:
+ *    Peak: 1 time in 16ms | Avg: 1000 per device per day
+ * The peak logging rate is pessimally estimated from one dataspace change per layer
+ * updated on a 60Hz device.
+ * The average logging rate is estimated from typical usage, where a layer's dataspace
+ * changes exactly once while it is on-screen. A typical app sends 1 layer to the screen,
+ * so this assumes that a user opens ~1000 apps per day.
+ */
+message SurfaceControlEvent {
+    // UID of the application owning the SurfaceControl
+    optional int32 uid = 1 [(is_uid) = true];
+    // Duration in milliseconds of how far in the past the SurfaceControl state was
+    // updated
+    optional int64 time_since_last_event_millis = 2;
+    // The previous dataspace of the SurfaceControl's content
+    optional int32 previous_dataspace = 3;
+}
+
+/**
+ * An event logged whenever an application decodes an image.
+ *
+ * Logged from ImageDecoder, AImageDecoder, and BitmapFactory
+ *
+ * Estimated Logging Rate:
+ *    Peak: 4 times in 50ms | Avg: 11000 per device per day
+ * The peak logging rate is estimated from decoding 4 jpegs in 50ms over 4
+ * cores.
+ * The average logging rate is estimated from typical usage, where an app's icon
+ * is decoded, the app shows decodes 10 images as part of its UI, and a user
+ * opens ~1000 apps per day.
+ */
+message ImageDecoded {
+    // UID of the application decoding the image
+    optional int32 uid = 1 [(is_uid) = true];
+    // Color transfer of the image.
+    optional android.coregraphics.ColorSpaceTransfer color_space_transfer = 2;
+    // Whether the image has a gainmap
+    optional bool has_gainmap = 3;
+    // The underlying format of the image
+    optional android.coregraphics.BitmapFormat format = 4;
+}
diff --git a/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto b/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto
new file mode 100644
index 00000000..4ea66ee0
--- /dev/null
+++ b/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto
@@ -0,0 +1,58 @@
+syntax = "proto2";
+
+package android.os.statsd.corenetworking.certificatetransparency;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.corenetworking.certificatetransparency";
+
+extend Atom {
+    optional CertificateTransparencyLogListUpdateFailed certificate_transparency_log_list_update_failed = 972 [(module) = "certificate_transparency"];
+}
+
+enum LogListUpdateStatus {
+    STATUS_UNKNOWN = 0;
+    // Log list was successfully updated.
+    SUCCESS = 1;
+    // Log list failed to update for unknown reasons.
+    FAILURE_UNKNOWN = 2;
+    // Device has been offline, preventing the log list file from being updated.
+    FAILURE_DEVICE_OFFLINE = 3;
+    // Device experienced an issue at the HTTP level and/or received an unhandled
+    // HTTP code.
+    FAILURE_HTTP_ERROR = 4;
+    // Device experienced too many redirects when accessing the log list domain.
+    FAILURE_TOO_MANY_REDIRECTS = 5;
+    // A transient error occurred that prevents the download from resuming.
+    FAILURE_DOWNLOAD_CANNOT_RESUME = 6;
+    // Log list domain is blocked by the device's network configuration.
+    FAILURE_DOMAIN_BLOCKED = 7;
+    // Device does not have enough disk space to store the log list file.
+    // Extremely unlikely to occur, and might not be able to reliably log this.
+    FAILURE_NO_DISK_SPACE = 8;
+    // Public key is missing for signature verification.
+    FAILURE_SIGNATURE_NOT_FOUND = 9;
+    // Log list signature verification failed.
+    FAILURE_SIGNATURE_VERIFICATION = 10;
+    // Device is waiting for a Wi-Fi connection to proceed with the download, as it
+    // exceeds the size limit for downloads over the mobile network.
+    PENDING_WAITING_FOR_WIFI = 11;
+}
+
+/*
+ * Pushed atom on why the log list failed to update.
+ *
+ * Logged from:
+ * packages/modules/Connectivity/networksecurity/service/src/com/android/server/net/ct/CertificateTransparencyDownloader.java
+ *
+ * Estimated Logging Rate:
+ * 1-2 times per device per day
+ */
+message CertificateTransparencyLogListUpdateFailed {
+  // The reason why the log list failed to update.
+  optional LogListUpdateStatus failure_reason = 1;
+
+  // The number of failures since the last successful log list update.
+  optional int32 failure_count = 2;
+}
\ No newline at end of file
diff --git a/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto b/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto
new file mode 100644
index 00000000..ecfe08f1
--- /dev/null
+++ b/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto
@@ -0,0 +1,48 @@
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
+syntax = "proto2";
+
+package android.os.statsd.corenetworking.connectivity;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/corenetworking/connectivity/enums.proto";
+
+option java_package = "com.android.os.corenetworking.connectivity";
+option java_multiple_files = true;
+
+extend Atom {
+    optional CoreNetworkingTerribleErrorOccurred core_networking_terrible_error_occurred =
+        979 [(module) = "connectivity", (module) = "network_stack", (module) = "resolv"];
+}
+
+/**
+ * This message will replace the Log.wtf() calls in the core networking
+ * code, as Log.wtf() output is not collected by Pitot in production environments.
+ *
+ * Logged from:
+ * packages/modules/Connectivity/
+ * packages/modules/NetworkStack/
+ * packages/modules/DnsResolver/
+ *
+ * Estimated Logging Rate:
+ * Peak: 10 times in 60 mins | Avg: < 1 per device per day
+ */
+message CoreNetworkingTerribleErrorOccurred {
+    // Type of terrible error.
+    optional android.corenetworking.connectivity.TerribleErrorType error_type = 1;
+}
diff --git a/stats/atoms/cpu/cpu_atoms.proto b/stats/atoms/cpu/cpu_atoms.proto
index 808aece4..93e1d364 100644
--- a/stats/atoms/cpu/cpu_atoms.proto
+++ b/stats/atoms/cpu/cpu_atoms.proto
@@ -30,14 +30,19 @@ extend Atom {
 
 /**
  * Logs information related to CPU policies such as frequency limits.
+ * This atom is pushed when scaling_max_freq_khz changes.
  */
 message CpuPolicy {
     // The cpufreq policy ID.
     optional int32 policy = 1;
 
-    // The current maximum frequency.
+    // To reduce power consumption, the kernel or firmware governors may lower
+    // the CPU frequency.  This is the maximum allowed frequency by the governors.
     optional int32 scaling_max_freq_khz = 2;
 
-    // The normal maximum frequency.
+    // If kernel frequency scaling is enabled, this is the maximum frequency of
+    // the CPU that the governors can activate.  If kernel frequency scaling is
+    // disabled, this is the frequency that the CPU has been locked to.
+    //   scaling_max_freq_khz <= cpuinfo_max_freq_khz
     optional int32 cpuinfo_max_freq_khz = 3;
 }
\ No newline at end of file
diff --git a/stats/atoms/credentials/credentials_extension_atoms.proto b/stats/atoms/credentials/credentials_extension_atoms.proto
index 20814cdc..977a6844 100644
--- a/stats/atoms/credentials/credentials_extension_atoms.proto
+++ b/stats/atoms/credentials/credentials_extension_atoms.proto
@@ -238,7 +238,7 @@ message CredentialManagerFinalNoUidReported {
     // The chain of clicked entries regardless of provider
     repeated EntryEnum clicked_entries = 16;
     // The provider associated with the clicked entry element in 'clicked_entries'
-    repeated int32 per_entry_provider_uids = 17;
+    repeated int32 per_entry_provider_uids = 17 [(is_uid) = true];
     // Final Information
     // The api result status
     optional ApiStatus api_status = 18;
@@ -407,7 +407,7 @@ message CredentialManagerFinalPhaseReported {
     // The chain of clicked entries regardless of provider
     repeated EntryEnum clicked_entries = 18;
     // The provider associated with the clicked entry above
-    repeated int32 provider_of_clicked_entry = 19;
+    repeated int32 provider_of_clicked_entry = 19 [(is_uid) = true];
     // Final Information
     // The api result status
     optional ApiStatus api_status = 20;
diff --git a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
index 5f7cf2fd..612aa57e 100644
--- a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
+++ b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
@@ -63,6 +63,7 @@ message DesktopModeUIChanged {
     RETURN_HOME_OR_OVERVIEW = 4; // user swiped up to go to overview, or home screen
     TASK_FINISHED = 5; // the task finished or dismissed
     SCREEN_OFF = 6;
+    TASK_MINIMIZED = 7; // the task gets minimized
   }
 
   optional Event event = 1;
@@ -87,6 +88,7 @@ message DesktopModeSessionTaskUpdate {
     TASK_ADDED = 1;
     TASK_REMOVED = 2;
     TASK_INFO_CHANGED = 3; // covers both size and position changes of the app
+    TASK_INIT_STATSD = 4;  // Used to initialise state field in statsd
   }
 
   // The reason a task was minimized
@@ -169,6 +171,12 @@ message DesktopModeTaskSizeUpdated {
     // Snap a resizable task to the right half of the screen by clicking on the
     // snap right menu on the app header
     SNAP_RIGHT_MENU_RESIZE_TRIGGER = 9;
+    // Resize task to fit stable bounds by clicking on the maximize menu that
+    // appears when the app header button is long pressed or hovered over
+    MAXIMIZE_MENU_RESIZE_TRIGGER = 10;
+    // Resize task to fit the stable bounds by dragging the task to the top of the
+    // screen
+    DRAG_TO_TOP_RESIZE_TRIGGER = 11;
   }
 
   // The stage at which a task is being resized
diff --git a/stats/atoms/expresslog/expresslog_extension_atoms.proto b/stats/atoms/expresslog/expresslog_extension_atoms.proto
index d2172e29..62397c27 100644
--- a/stats/atoms/expresslog/expresslog_extension_atoms.proto
+++ b/stats/atoms/expresslog/expresslog_extension_atoms.proto
@@ -26,7 +26,7 @@ option java_multiple_files = true;
 
 extend Atom {
     optional ExpressEventReported express_event_reported =
-            528 [(module) = "framework", (module) = "expresslog"];
+            528 [(module) = "framework", (module) = "expresslog", (module) = "statsdtest"];
     optional ExpressHistogramSampleReported express_histogram_sample_reported =
             593 [(module) = "framework", (module) = "expresslog"];
     optional ExpressUidEventReported express_uid_event_reported =
diff --git a/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto b/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
index 01bcfa77..71cfb627 100644
--- a/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
+++ b/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
@@ -32,6 +32,8 @@ extend Atom {
             771 [(module) = "ondevicepersonalization", (truncate_timestamp) = true];
   optional ExampleIteratorNextLatencyReported example_iterator_next_latency_reported =
             838 [(module) = "ondevicepersonalization", (truncate_timestamp) = true];
+  optional FederatedComputeTraceEventReported federated_compute_trace_event_reported =
+            992 [(module) = "ondevicepersonalization", (truncate_timestamp) = true];
 }
 
 /**
@@ -136,3 +138,16 @@ message ExampleIteratorNextLatencyReported {
 
   optional int64 get_next_latency_nanos = 3;
 }
+
+/**
+ * Logs trace events from internal processing in the FCP services and jobs.
+ * Next ID = 4
+ */
+message FederatedComputeTraceEventReported {
+  // event type to trace for internal processing in FCP services
+  optional android.federatedcompute.TraceEventKind trace_kind = 1;
+  // status of the operation
+  optional int32 status = 2;
+  // end to end latency of the operation
+  optional int64 latency_millis = 3;
+}
diff --git a/stats/atoms/framework/framework_extension_atoms.proto b/stats/atoms/framework/framework_extension_atoms.proto
index 5e0afa28..307dfc66 100644
--- a/stats/atoms/framework/framework_extension_atoms.proto
+++ b/stats/atoms/framework/framework_extension_atoms.proto
@@ -22,6 +22,9 @@ import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/enums/hardware/biometrics/enums.proto";
 import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_op_enums.proto";
+import "frameworks/proto_logging/stats/enums/framework/compat/enums.proto";
+import "frameworks/proto_logging/stats/enums/os/enums.proto";
 
 option java_package = "com.android.os.framework";
 
@@ -53,6 +56,13 @@ extend Atom {
     optional PowerSaveTempAllowlistChanged power_save_temp_allowlist_changed = 926 [(module) = "framework"];
     optional AppOpAccessTracked app_op_access_tracked = 931 [(module) = "framework"];
     optional ContentOrFileUriEventReported content_or_file_uri_event_reported = 933 [(module) = "framework"];
+    optional DeviceIdleTempAllowlistUpdated device_idle_temp_allowlist_updated = 940 [(module) = "framework"];
+    optional AppOpNoteOpOrCheckOpBinderApiCalled app_op_note_op_or_check_op_binder_api_called = 943 [(module) = "framework"];
+    optional FrameworkWakelockInfo framework_wakelock_info = 10230 [(module) = "framework"];
+    optional JankFrameCountByWidgetReported jank_frame_count_by_widget_reported = 950 [(module)="framework"];
+    optional IntentCreatorTokenAdded intent_creator_token_added = 978 [(module)="framework"];
+    optional NotificationChannelClassification notification_channel_classification = 983 [(module) = "framework"];
+    optional CameraStatusForCompatibilityChanged camera_status_for_compatibility_changed = 999 [(module) = "framework"];
 }
 
 /**
@@ -335,6 +345,10 @@ message MediaProjectionStateChanged {
   // Only present when in state MEDIA_PROJECTION_STATE_INITIATED.
   optional SessionCreationSource creation_source = 7;
 
+  // Where this session stopped.
+  // Only present when in state MEDIA_PROJECTION_STATE_STOPPED.
+  optional SessionStopSource stop_source = 8;
+
   // Possible states for a MediaProjection session.
   enum MediaProjectionState {
     MEDIA_PROJECTION_STATE_UNKNOWN = 0;
@@ -371,6 +385,31 @@ message MediaProjectionStateChanged {
     // Created through Cast SDK, e.g. screencast quick settings tile.
     CREATION_SOURCE_CAST = 3;
   }
+
+  // The possible exit points for the session.
+  enum SessionStopSource {
+    STOP_SOURCE_UNKNOWN = 0;
+    // Stopped through calling MediaProjection#stop()
+    STOP_SOURCE_HOST_APP_STOP = 1;
+    // Stopped by the capture target calling onRemoved() after being exited
+    STOP_SOURCE_TASK_APP_CLOSE = 2;
+    // Stopped by the device keyguard being locked
+    STOP_SOURCE_DEVICE_LOCK = 3;
+    // Stopped via the MediaProjection status bar privacy chip
+    STOP_SOURCE_STATUS_BAR_CHIP_STOP = 4;
+    // Stopped via the Quick Settings cast tile
+    STOP_SOURCE_QS_TILE = 5;
+    // Stopped due to the device switching users
+    STOP_SOURCE_USER_SWITCH = 6;
+    // Stopped due to a change in the MediaProjection foreground service
+    STOP_SOURCE_FOREGROUND_SERVICE_CHANGE = 7;
+    // Stopped due to a new MediaProjection coming to replace the currently active projection
+    STOP_SOURCE_NEW_PROJECTION = 8;
+    // Stopped due to a new MediaRoute being chosen while casting
+    STOP_SOURCE_NEW_MEDIA_ROUTE = 9;
+    // Stopped due to some error affecting the MediaProjection capture process
+    STOP_SOURCE_ERROR = 10;
+  }
 }
 
 /**
@@ -390,6 +429,9 @@ message MediaProjectionTargetChanged {
   // An incrementing integer that persists across device reboots.
   optional int32 session_id = 1 [(state_field_option).primary_field = true];
 
+  // The classification for the type of change applied to the capture target
+  optional TargetChangeType target_change_type = 10;
+
   // The area that is being captured.
   optional TargetType target_type = 2;
 
@@ -409,6 +451,22 @@ message MediaProjectionTargetChanged {
     (state_field_option).nested = false
   ];
 
+  optional int32 width = 6;
+  optional int32 height = 7;
+  optional int32 center_x = 8;
+  optional int32 center_y = 9;
+
+  // Enum that represents the type of change happening to the capture target
+  enum TargetChangeType {
+    TARGET_CHANGE_TYPE_UNKNOWN = 0;
+    // The target has updated its windowing mode (full screen, split screen, freeform, etc.)
+    TARGET_CHANGE_WINDOWING_MODE = 1;
+    // The target has changed the position it is centered at (size remains unchanged)
+    TARGET_CHANGE_POSITION = 2;
+    // The target has changed its bounds (changed size and centered position)
+    TARGET_CHANGE_BOUNDS = 3;
+  }
+
   // Enum that represents the type of area that is being captured.
   enum TargetType {
     TARGET_TYPE_UNKNOWN = 0;
@@ -756,6 +814,21 @@ message PowerSaveTempAllowlistChanged {
     optional bool add_to_allowlist = 2;
 }
 
+/**
+ * Records invocations of ActivityManagerService$LocalService.updateDeviceIdleTempAllowlist
+ *
+ * Logged via Hummingbird
+ */
+message DeviceIdleTempAllowlistUpdated {
+    optional int32 changing_uid = 1 [(is_uid) = true];
+    optional bool adding = 2;
+    optional int64 duration_ms = 3;
+    optional int32 type = 4;
+    optional int32 reason_code = 5;
+    optional string reason = 6;
+    optional int32 calling_uid = 7 [(is_uid) = true];
+}
+
 /**
  * [Pushed Atom] Logs when an AppOp is accessed through noteOp, startOp, finishOp and that access
  * history can be stored in the AppOp discrete access data store.
@@ -799,6 +872,33 @@ message AppOpAccessTracked {
     optional int32 attribution_chain_id = 8;
 }
 
+/**
+ * [Pushed Atom] Logs when AppOp checkOperation and noteOperation binder APIs are called in
+ * AppOpsService
+ *
+ * Logged from: frameworks/base/services/core/java/com/android/server/appop/AppOpsService.java
+ */
+message AppOpNoteOpOrCheckOpBinderApiCalled {
+    enum BinderApi {
+        UNKNOWN = 0;
+        CHECK_OPERATION = 1;
+        NOTE_OPERATION = 2;
+        NOTE_PROXY_OPERATION = 3;
+    }
+
+    // Uid of the package requesting the op
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // AppOp code
+    optional android.app.AppOpEnum op_id = 2 [default = APP_OP_NONE];
+
+    // One of the BinderApi
+    optional BinderApi binder_api = 3;
+
+    // Whether the binder call has attribution tag in the arguments
+    optional bool has_attribution_tag = 4;
+}
+
 /**
  * Logs when specific content and file URIs are encountered in several locations. See EventType for
  * more details.
@@ -829,3 +929,168 @@ message ContentOrFileUriEventReported {
   optional string uri_type = 9;
   optional string uri_mime_type = 10;
 }
+
+/**
+ * Logs aggregate time and count of framework wakelocks.
+ */
+message FrameworkWakelockInfo {
+  // The primary (index 0) uid for this WakeLock in the attribution chain.
+  optional int32 attribution_uid = 1 [(is_uid) = true];
+  optional string attribution_tag = 2;
+
+  // The type (level) of the wakelock; e.g. a partial wakelock or a full wakelock.
+  // From frameworks/proto_logging/stats/enums/os/enums.proto.
+  optional android.os.WakeLockLevelEnum type = 3;
+
+  // Accumulated uptime attributed to this WakeLock since boot, where overlap
+  // between WakeLocks with the same UID and tag is ignored. Specifically, if two
+  // WakeLocks with the same UID and tag were acquired at exactly the same time and
+  // held for 100 ms, the total contribution of the two WakeLocks to uptime_millis
+  // is 100 ms.
+  optional int64 uptime_millis = 4;
+
+  // Count of WakeLocks that have been acquired and then released.
+  optional int64 completed_count = 5;
+}
+/**
+ * [Pushed atom] Logged after a set number of JankData batches have been processed or when an Activity is
+ * paused.
+ *
+ * Pushed from:
+ *   frameworks/base/core/java/android/app/jank/JankDataProcessor.java
+ *
+ * Estimated Logging Rate:
+ *  Peak: 25 times every 20 sec while frames are being rendered.
+ *  Avg: 500 times per device per day.
+ */
+message JankFrameCountByWidgetReported {
+  // UID of the app
+  optional int32 uid = 1 [(is_uid) = true];
+
+  // The name of the activity that is currently collecting frame metrics.
+  optional string activity_name = 2;
+
+  // The id that has been set for the widget.
+  optional string widget_id = 3;
+
+  // The refresh rate of the display when logged.
+  optional int32 refresh_rate = 4;
+
+  // High level categories to group functionally similar UI elements.
+  enum WidgetCategory {
+    // Category not set.
+    WIDGET_CATEGORY_UNSPECIFIED = 0;
+    // UI elements that facilitate scrolling.
+    SCROLL = 1;
+    // UI elements that facilitate playing animations.
+    ANIMATION = 2;
+    // UI elements that facilitate media playback or streaming.
+    MEDIA = 3;
+    // UI elements that facilitate in app navigation.
+    NAVIGATION = 4;
+    // UI elements that facilitate displaying, hiding or interacting with keyboard.
+    KEYBOARD = 5;
+    // UI elements that facilitate predictive back gesture navigation.
+    PREDICTIVE_BACK = 6;
+    // UI elements that don't fall in on of the other categories.
+    OTHER = 7;
+  }
+  optional WidgetCategory widget_type = 5;
+
+  // The states that the UI elements can report
+  enum WidgetState {
+    // State not set.
+    WIDGET_STATE_UNSPECIFIED = 0;
+    // Element that is idle or not in any active state.
+    NONE = 1;
+    // Element that is currently scrolling.
+    SCROLLING = 2;
+    // Element that is currently being flung.
+    FLINGING = 3;
+    // Element that is currently being swiped.
+    SWIPING = 4;
+    // Element that is currently being dragged.
+    DRAGGING = 5;
+    // Element that is currently zooming.
+    ZOOMING = 6;
+    // Element that is currently animating.
+    ANIMATING = 7;
+    // Element that is currently engaging in media playback.
+    PLAYBACK = 8;
+    // Element that is currently being tapped on.
+    TAPPING = 9;
+  }
+  optional WidgetState widget_state = 6;
+
+  // The number of frames reported during this state.
+  optional int64 total_frames = 7;
+
+  // Total number of frames determined to be janky during the reported state.
+  optional int64 janky_frames = 8;
+
+  // Histogram of frame duration overruns.
+  repeated int32 frame_overrun_histogram = 9;
+}
+
+/**
+ * [Pushed atom] Logged when an IntentCreatorToken is added to an Intent.
+ *
+ * Pushed from:
+ *   frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
+ *      #addCreatorToken
+ *
+ * Estimated Logging Rate:
+ *  Peak: 100 times per device per day.
+ *  Avg: 20 times per device per day.
+ */
+message IntentCreatorTokenAdded {
+  // creator uid
+  optional int32 creator_uid = 1 [(is_uid) = true];
+  // true if the creator and top level intent target share the same package
+  optional bool is_optimized = 2;
+}
+
+/**
+ * Reports a notification got an Adjustment with the KEY_TYPE value set
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/notification/
+ * Estimated Logging Rate:
+ *   Peak: 300 times per device per day. | Avg: 40 times per device per day.
+ *
+ */
+message NotificationChannelClassification {
+    // Was the notification reclassified to a new channel after it was already posted.
+    optional bool receive_adjustment_after_post = 1;
+
+    // Was the notification high enough priority to be "alerting" before it got reclassified.
+    optional bool was_alerting = 2;
+
+    // The new channel type the notification has been reclassified as (e.g., Adjustment.TYPE_NEWS).
+    optional int32 type = 3;
+
+    // The length of the lifetime of the notification up to when it got reclassified.
+    optional int32 latency_ms = 4;
+}
+
+/**
+ * Reports that a camera compatibility status has changed.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/wm/CameraStateMonitor.java
+ * Estimated Logging Rate:
+ *   Peak: 10 times per device per day. | Avg: 1 time per device per day.
+ *
+ */
+message CameraStatusForCompatibilityChanged {
+    // The freeform camera compatibility mode the activity is in at the time the
+    // camera opened or closed signal is received.
+    optional android.framework.compat.FreeformCameraCompatMode freeform_camera_compat_mode_state = 1;
+
+    // Whether this state is logged on camera opened or closed.
+    optional android.framework.compat.CameraState camera_state = 2;
+
+    // The latency of the camera compat mode setup - from the time the camera
+    // opened signal was received for the first time, to the time the camera
+    // compat mode was set up, camera restarted, and the camera opened signal
+    // was received again.
+    optional int32 latency_ms = 3;
+}
diff --git a/stats/atoms/hardware/biometrics/biometrics_extension_atoms.proto b/stats/atoms/hardware/biometrics/biometrics_extension_atoms.proto
new file mode 100644
index 00000000..e25f0339
--- /dev/null
+++ b/stats/atoms/hardware/biometrics/biometrics_extension_atoms.proto
@@ -0,0 +1,68 @@
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
+syntax = "proto2";
+
+package android.os.statsd.hardware.biometrics;
+
+option java_package = "com.android.os.hardware.biometrics";
+option java_multiple_files = true;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/hardware/biometrics/enums.proto";
+
+extend Atom {
+  optional BiometricUnenrolled biometric_unenrolled = 944 [(module) = "framework"];
+  optional BiometricEnumerated biometric_enumerated = 945 [(module) = "framework"];
+}
+
+/**
+ * Logs when a biometric template is unenrolled.
+ *
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/biometrics
+ */
+message BiometricUnenrolled {
+    // Biometric modality for which a template was unenrolled.
+    optional android.hardware.biometrics.ModalityEnum modality = 1;
+    // The associated user. Eg: 0 for owners, 10+ for others. Defined in android/os/UserHandle.java
+    optional int32 user = 2;
+    // Reason why template was unenrolled.
+    optional android.hardware.biometrics.UnenrollReasonEnum unenroll_reason = 3;
+    // Numerical ID for unenrolled template. Ids increment with every new enrollment. Eg: 1, 2...
+    optional int32 template_id = 4;
+}
+
+/**
+ * Logs when templates are enumerated for a user.
+ *
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/biometrics
+ */
+message BiometricEnumerated {
+    // Biometric modality for which templates were enumerated.
+    optional android.hardware.biometrics.ModalityEnum modality = 1;
+    // The associated user. Eg: 0 for owners, 10+ for others. Defined in android/os/UserHandle.java
+    optional int32 user = 2;
+    // Result of enumeration. Eg: OK (templates match), mismatch from dangling template etc.
+    optional android.hardware.biometrics.EnumerationResultEnum enumeration_result = 3;
+    // Numerical IDs for templates reported by HAL. Ids increment with every new enrollment. Eg: 1, 2...
+    repeated int32 template_ids_hal = 4;
+    // Numerical IDs for templates reported by HAL. Ids increment with every new enrollment. Eg: 1, 2...
+    repeated int32 template_ids_framework = 5;
+}
+
diff --git a/stats/atoms/hdmi/hdmi_extension_atoms.proto b/stats/atoms/hdmi/hdmi_extension_atoms.proto
index e1ba773d..b8686c10 100644
--- a/stats/atoms/hdmi/hdmi_extension_atoms.proto
+++ b/stats/atoms/hdmi/hdmi_extension_atoms.proto
@@ -29,6 +29,8 @@ extend Atom {
   optional HdmiEarcStatusReported hdmi_earc_status_reported = 701 [(module) = "framework"];
   optional HdmiSoundbarModeStatusReported hdmi_soundbar_mode_status_reported
       = 724 [(module) = "framework"];
+  optional HdmiPowerStateChangeOnActiveSourceLostToggled
+      hdmi_power_state_change_on_active_source_lost_toggled = 991 [(module) = "framework"];
 }
 /**
 * Push atom that logs the status of the eARC feature in 3 dimensions: whether the
@@ -67,3 +69,25 @@ message HdmiSoundbarModeStatusReported {
   // the event that triggered the log.
   optional android.stats.hdmi.DynamicSoundbarModeLogReason log_reason = 3;
 }
+
+/**
+* Push atom that logs the status of POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST in 2 dimensions:
+* whether the setting is enabled and connected device manufacturer information (PNP Id, year,
+* week).
+*
+* Logged whenever the setting is toggled.
+**/
+
+message HdmiPowerStateChangeOnActiveSourceLostToggled {
+  // whether the setting is enabled.
+  optional bool is_enabled = 1;
+  // the event that triggered the log.
+  optional android.stats.hdmi.PowerStateChangeOnActiveSourceLostToggleReason log_reason = 2;
+  // stores the PNP Id reported in the EDID by the connected device. The PNP Id can be
+  // decoded here - https://uefi.org/PNP_ID_List.
+  optional string manufacturer_device_pnp_id = 3;
+  // stores the manufacturer year reported in the EDID by the connected device
+  optional int32 manufacturer_device_year = 4;
+  // stores the manufacturer week reported in the EDID by the connected device
+  optional int32 manufacturer_device_week = 5;
+}
diff --git a/stats/atoms/healthfitness/api/api_extension_atoms.proto b/stats/atoms/healthfitness/api/api_extension_atoms.proto
index c40f5b40..71dc5025 100644
--- a/stats/atoms/healthfitness/api/api_extension_atoms.proto
+++ b/stats/atoms/healthfitness/api/api_extension_atoms.proto
@@ -41,6 +41,18 @@ extend Atom {
   optional HealthConnectImportInvoked health_connect_import_invoked = 918 [(module) = "healthfitness"];
 
   optional HealthConnectExportImportStatsReported health_connect_export_import_stats_reported = 919 [(module) = "healthfitness"];
+
+  optional HealthConnectPermissionStats health_connect_permission_stats = 963 [(module) = "healthfitness"];
+
+  optional HealthConnectPhrApiInvoked health_connect_phr_api_invoked = 980 [(module) = "healthfitness", (restriction_category) = RESTRICTION_DIAGNOSTIC];
+
+  optional HealthConnectPhrUsageStats health_connect_phr_usage_stats = 981 [(module) = "healthfitness"];
+
+  optional HealthConnectPhrStorageStats health_connect_phr_storage_stats = 984 [(module) = "healthfitness"];
+
+  optional HealthConnectRestrictedEcosystemStats health_connect_restricted_ecosystem_stats = 985 [(module) = "healthfitness", (restriction_category) = RESTRICTION_DIAGNOSTIC];
+
+  optional HealthConnectEcosystemStats health_connect_ecosystem_stats = 986 [(module) = "healthfitness"];
 }
 
 // Track HealthDataService API operations.
@@ -66,6 +78,9 @@ message HealthConnectApiCalled {
 
   // The API caller's foreground status
   optional android.healthfitness.api.ForegroundState caller_foreground_state = 7;
+
+  // Package calling the API. We will remove any package with less than certain number of installs (500k for now) from aggregations.
+  optional string package_name = 8;
 }
 
 // Track if users are connecting apps with Health Connect
@@ -82,6 +97,25 @@ message HealthConnectUsageStats {
 
 }
 
+// Track if users are connecting personal health record apps with Health Connect
+message HealthConnectPhrUsageStats {
+
+  // Number of connected medical data sources
+  optional int32 connected_medical_datasource_count = 1;
+
+  // Number of stored medical resources.
+  optional int32 medical_resource_count = 2;
+
+  // Set true if the user has one read medical resources API call in past 30
+  // days. PHR stands for Personal Health Record.
+  optional bool is_monthly_active_phr_user = 3;
+
+  // Number of apps that have been granted at least one medical data read
+  // permission. PHR stands for Personal Health Record.
+  optional int32 granted_phr_apps_count = 4;
+
+}
+
 /**
  *  Tracks the daily usage stats of the Health Connect export/import feature.
  *
@@ -116,7 +150,11 @@ message HealthConnectStorageStats {
 
   // Total number of changelog counts.
   optional int64 changelog_count = 5;
+}
 
+// Monitor PHR database in HC (PHR stands for Personal Health Record)
+message HealthConnectPhrStorageStats {
+  optional int64 phr_data_size = 1;
 }
 
 // Track when ExerciseRoute is being read/written.
@@ -207,3 +245,75 @@ message HealthConnectApiInvoked {
   [(field_restriction_option).health_connect = true];
 
 }
+
+// Track Health Connect API operations stats.
+message HealthConnectPhrApiInvoked {
+
+  // API method invoked.
+  optional android.healthfitness.api.ApiMethod api_method = 1;
+
+  // Status whether the API call executed successfully or not.
+  optional android.healthfitness.api.ApiStatus api_status = 2;
+
+  // Package name of the client that invoked the API.
+  optional string package_name = 3;
+
+  // Medical resource type under consideration in the API call (if any).
+  // When there are multiple resource types in an API call, multiple HealthConnectPhrApiInvoked
+  // messages will be created and logged.
+  optional android.healthfitness.api.MedicalResourceType medical_resource_type = 4
+    [(field_restriction_option).health_connect = true];
+}
+
+/**
+ * Information about a permission granted to each package using HC.
+ */
+message HealthConnectPermissionStats {
+
+  // Name of package. We will remove any package with less than certain number of installs (500k for now) from aggregations.
+  optional string package_name = 1;
+
+  // Health Connect permission granted to the given package
+  repeated string permission_name = 2;
+}
+
+/**
+ * Information about Health Connect Ecosystem for the user.
+ */
+message HealthConnectEcosystemStats {
+
+  // Datatypes read or written in past 30 days
+  repeated android.healthfitness.api.DataType read_or_write = 1;
+
+  // Datatypes read in past 30 days
+  repeated android.healthfitness.api.DataType read = 2;
+
+  // Datatypes written in past 30 days
+  repeated android.healthfitness.api.DataType write = 3;
+
+  // Datatypes shared in past 30 days
+  repeated android.healthfitness.api.DataType shared = 4;
+
+}
+
+/**
+ * Sensitive Ecosystem metrics being collected via PWW.
+ */
+message HealthConnectRestrictedEcosystemStats {
+
+  // Package name writing data in directional pairings.
+  // First package name alphabetically for non-directional pairings.
+  optional string package_name_one = 1;
+
+  // Package name reading data in directional pairings.
+  // Second package name alphabetically for non-directional pairings.
+  optional string package_name_two = 2;
+
+  // Data type being shared among packages.
+  optional android.healthfitness.api.DataType data_type = 3
+  [(field_restriction_option).health_connect = true];
+
+  // Enum telling which metric is being represented by the atom.
+  optional android.healthfitness.api.MetricType metric_type = 4;
+
+}
diff --git a/stats/atoms/nfc/nfc_extension_atoms.proto b/stats/atoms/nfc/nfc_extension_atoms.proto
index 2ac34308..918da90c 100644
--- a/stats/atoms/nfc/nfc_extension_atoms.proto
+++ b/stats/atoms/nfc/nfc_extension_atoms.proto
@@ -83,4 +83,5 @@ message NfcProprietaryCapabilitiesReported {
   optional bool is_polling_frame_notification_supported = 2;
   optional bool is_power_saving_mode_supported = 3;
   optional bool is_autotransact_polling_loop_filter_supported = 4;
+  optional int32 number_of_exit_frames_supported = 5;
 }
diff --git a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
index 21ae1e77..0f3a71bc 100644
--- a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+++ b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
@@ -24,8 +24,12 @@ extend Atom {
   optional OnDevicePersonalizationApiCalled ondevicepersonalization_api_called =
             711 [(module) = "ondevicepersonalization", (truncate_timestamp) = true];
 }
+extend Atom {
+    optional OnDevicePersonalizationTraceEvent ondevicepersonalization_trace_event =
+      952 [(module) = "ondevicepersonalization", (truncate_timestamp) = true];
+}
 /**
- * Logs when an OnDevicePersonalization api is called.
+ * Logs when a public ODP api is called.
  */
 message OnDevicePersonalizationApiCalled {
     enum OnDevicePersonalizationApiClassType {
@@ -78,3 +82,34 @@ message OnDevicePersonalizationApiCalled {
     // Log the sdk package name that passed by app in API request.
     optional string sdk_package_name = 9;
 }
+
+/**
+ * Logs trace events from internal processing in the ODP service.
+ */
+message OnDevicePersonalizationTraceEvent {
+    enum TaskType {
+        TASK_TYPE_UNKNOWN = 0;
+        EXECUTE = 1;
+        RENDER = 2;
+        DOWNLOAD = 3;
+        WEBVIEW = 4;
+        TRAINING = 5;
+        MAINTENANCE = 6;
+        WEB_TRIGGER = 7;
+    }
+    enum EventType {
+        UNKNOWN = 0;
+        WRITE_REQUEST_LOG = 1;
+        WRITE_EVENT_LOG = 2;
+    }
+    // task type to trace for internal processing in ODP service
+    optional TaskType task_type = 1;
+    // event type to trace for internal processing in ODP service
+    optional EventType event_type = 2;
+    // status of the operation
+    optional int32 status = 3;
+    // end to end latency of the operation
+    optional int32 latency_millis = 4;
+    // isolated service package name
+    optional string service_package_name = 5;
+}
diff --git a/stats/atoms/performance/performance_extension_atoms.proto b/stats/atoms/performance/performance_extension_atoms.proto
index db9c5cf4..12cf8897 100644
--- a/stats/atoms/performance/performance_extension_atoms.proto
+++ b/stats/atoms/performance/performance_extension_atoms.proto
@@ -20,15 +20,19 @@ package android.os.statsd.performance;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/performance/enums.proto";
+
+option java_package = "com.android.os.performance";
 
 extend Atom {
-    optional PressureStallInformation pressure_stall_information = 10229 [(module) = "performance"];
+    optional PressureStallInformation pressure_stall_information = 10229 [(module) = "framework"];
 }
 
 // Pressure stall information for a given resource.
 // See https://docs.kernel.org/accounting/psi.html
 message PressureStallInformation {
-    optional Resource resource = 1;
+    // The resource that is being monitored for pressure stall information.
+    optional android.performance.PsiResource psi_resource = 1;
 
     // The average percent of time in the last N seconds that some tasks were
     // stalled on the particular resource. Expressed as x.xx%.
@@ -47,11 +51,4 @@ message PressureStallInformation {
     // The total number of microseconds that all tasks were
     // stalled on the particular resource.
     optional int64 full_total_usec = 9;
-
-    enum Resource {
-        UNKNOWN = 0;
-        CPU = 1;
-        MEMORY = 2;
-        IO = 3;
-    }
 }
diff --git a/stats/atoms/photopicker/photopicker_extension_atoms.proto b/stats/atoms/photopicker/photopicker_extension_atoms.proto
index 35393408..dfaa7699 100644
--- a/stats/atoms/photopicker/photopicker_extension_atoms.proto
+++ b/stats/atoms/photopicker/photopicker_extension_atoms.proto
@@ -88,7 +88,9 @@ message PhotopickerApiInfoReported {
   optional bool is_ordered_selection_set = 8;
   optional bool is_accent_color_set = 9;
   optional bool is_default_tab_set = 10;
-  optional bool is_search_enabled = 11;
+  optional bool is_search_enabled = 11 [deprecated = true];
+  optional bool is_cloud_search_enabled = 12;
+  optional bool is_local_search_enabled = 13;
 }
 
 /*
@@ -197,9 +199,9 @@ message PhotopickerSearchInfoReported {
   optional int32 session_id = 1;
   optional android.photopicker.SearchMethod search_method = 2;
   // items picked in a particular search method
-  optional int32 picked_items = 3;
-  optional int32 start_time_millis = 4;
-  optional int32 end_time_millis = 5;
+  optional int32 picked_items = 3 [deprecated = true];
+  optional int32 start_time_millis = 4 [deprecated = true];
+  optional int32 end_time_millis = 5 [deprecated = true];
 }
 
 /*
diff --git a/stats/atoms/ranging/ranging_extension_atoms.proto b/stats/atoms/ranging/ranging_extension_atoms.proto
new file mode 100644
index 00000000..145614b9
--- /dev/null
+++ b/stats/atoms/ranging/ranging_extension_atoms.proto
@@ -0,0 +1,121 @@
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
+syntax = "proto2";
+
+package android.os.statsd.ranging;
+
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/ranging/enums.proto";
+
+option java_package = "com.android.os.ranging";
+option java_multiple_files = true;
+
+extend Atom {
+  optional RangingSessionConfigured ranging_session_configured = 993 [(module) = "ranging"];
+  optional RangingSessionStarted ranging_session_started = 994 [(module) = "ranging"];
+  optional RangingSessionClosed ranging_session_closed = 995 [(module) = "ranging"];
+  optional RangingTechnologyStarted ranging_technology_started = 996 [(module) = "ranging"];
+  optional RangingTechnologyStopped ranging_technology_stopped = 997 [(module) = "ranging"];
+}
+
+/*
+ * A ranging session has been configured, either after OOB negotiation or directly from raw
+ * parameters.
+ */
+message RangingSessionConfigured {
+  // Unique identifier for the session.
+  optional int64 session_id = 1;
+
+  // The duration it took to do OOB in milliseconds. Omitted if the session was configured directly.
+  optional int64 oob_duration_ms = 2;
+
+  // Whether the configuration was reached via OOB negotiation or provided directly through the API.
+  optional android.ranging.SessionType type = 3;
+
+  // The role of the local device in this session.
+  optional android.ranging.DeviceRole device_role = 4;
+
+  // Number of peers to range with as specified in the configuration.
+  optional int32 num_peers = 5;
+}
+
+/*
+ * A ranging session has started.
+ */
+message RangingSessionStarted {
+  // Unique identifier for the session.
+  optional int64 session_id = 1;
+
+  // UID of the process that requested ranging through the API.
+  optional int32 uid = 2 [(is_uid) = true];
+
+  // The duration it took to start the session after configuring in milliseconds.
+  optional int64 start_latency_ms = 3;
+}
+
+/*
+ * A ranging session has been closed.
+ */
+message RangingSessionClosed {
+  // Unique identifier for the session.
+  optional int64 session_id = 1;
+
+  // State the session was in before it closed.
+  optional android.ranging.SessionState last_state = 2;
+
+  // Duration the session was in the 'last_state' before closing, in milliseconds.
+  optional int64 last_state_duration_ms = 3;
+
+  // Reason why the session closed.
+  optional android.ranging.ClosedReason reason = 4;
+}
+
+/*
+ * A ranging technology has started within a session.
+ */
+message RangingTechnologyStarted {
+  // Unique identifier for the session.
+  optional int64 session_id = 1;
+
+  // Technology that started.
+  optional android.ranging.Technology technology = 2;
+
+  // Number of peers that started using this technology.
+  optional int32 num_peers = 3;
+}
+
+/*
+ * A ranging technology has stopped within a session.
+ */
+message RangingTechnologyStopped {
+  // Unique identifier for the session.
+  optional int64 session_id = 1;
+
+  // Technology that stopped.
+  optional android.ranging.Technology technology = 2;
+
+  // State the session was in when this technology stopped.
+  optional android.ranging.SessionState state = 3;
+
+  // Reason why this technology stopped.
+  optional android.ranging.StoppedReason reason = 4;
+
+  // Number of peers that stopped using this technology.
+  optional int32 num_peers = 5;
+}
\ No newline at end of file
diff --git a/stats/atoms/sysui/sysui_extension_atoms.proto b/stats/atoms/sysui/sysui_extension_atoms.proto
index 81107f41..e1f51120 100644
--- a/stats/atoms/sysui/sysui_extension_atoms.proto
+++ b/stats/atoms/sysui/sysui_extension_atoms.proto
@@ -31,6 +31,8 @@ extend Atom {
   optional NotificationListenerService notification_listener_service = 829 [(module) = "sysui"];
   optional NavHandleTouchPoints nav_handle_touch_points = 869 [(module) = "sysui"];
   optional CommunalHubWidgetEventReported communal_hub_widget_event_reported = 908 [(module) = "sysui"];
+  optional PeripheralTutorialLaunched peripheral_tutorial_launched = 942 [(module) = "sysui"];
+  optional ContextualEducationTriggered contextual_education_triggered = 971 [(module) = "sysui"];
   optional CommunalHubSnapshot communal_hub_snapshot = 10226 [(module) = "sysui"];
 }
 
@@ -239,6 +241,8 @@ message CommunalHubWidgetEventReported {
     REMOVE = 2;
     // User taps a widget in the communal hub.
     TAP = 3;
+    // User resizes a widget
+    RESIZE = 4;
   }
 
   // The action that triggered the event.
@@ -249,8 +253,82 @@ message CommunalHubWidgetEventReported {
 
   // The rank or order of the widget in the communal hub.
   optional int32 rank = 3;
+
+  // The height of the widget, defined in number of grid cells
+  optional int32 span_y = 4;
+}
+
+/**
+ * Pushed atom. Logs from where the contextual education is triggered.
+ *
+ * Logged from:
+ *  frameworks/base/packages/SystemUI/src/com/android/systemui/education/domain/interactor/KeyboardTouchpadEduInteractor.kt
+ *
+ * Estimated Logging Rate:
+ *   Avg: < 1 per device per day
+ */
+
+message ContextualEducationTriggered {
+    enum EducationType {
+        EDU_TYPE_UNSPECIFIED = 0;
+        TOAST = 1;
+        NOTIFICATION = 2;
+    }
+
+    enum GestureType {
+        GESTURE_TYPE_UNSPECIFIED = 0;
+        BACK = 1;
+        HOME = 2;
+        OVERVIEW = 3;
+        ALL_APPS = 4;
+    }
+
+    // The education type being triggered.
+    optional EducationType education_type = 1;
+
+    // The gesture type of the education.
+    optional GestureType gesture_type = 2;
 }
 
+/**
+ * Pushed atom. Logs from where the keyboard/touchpad tutorial is launched.
+ *
+ * Logged from:
+ *  frameworks/base/packages/SystemUI/src/com/android/systemui/inputdevice/tutorial/ui/view/KeyboardTouchpadTutorialActivity.kt
+ *  frameworks/base/packages/SystemUI/src/com/android/systemui/touchpad/tutorial/ui/view/TouchpadTutorialActivity.kt
+ *
+ * Estimated Logging Rate:
+ *   Avg: < 1 per device per day
+*/
+
+message PeripheralTutorialLaunched {
+    enum EntryPoint {
+        UNSPECIFIED_ENTRY = 0;
+        // Launched from Settings
+        SETTINGS = 1;
+        // Launched from scheduled notification
+        SCHEDULED = 2;
+        // Launched from contextual education notification
+        CONTEXTUAL_EDU = 3;
+        // Launched from Companion App
+        APP = 4;
+    }
+
+    enum TutorialType {
+        UNSPECIFIED_TYPE = 0;
+        KEYBOARD = 1;
+        TOUCHPAD = 2;
+        BOTH = 3;
+    }
+
+    // The entry point that triggered the tutorial.
+    optional EntryPoint entry_point = 1;
+
+    // The type of tutorial launched.
+    optional TutorialType tutorial_type = 2;
+}
+
+
 /**
  * Pulled atom. Logs a snapshot of content in the communal hub.
  *
diff --git a/stats/atoms/telecomm/telecom_extension_atom.proto b/stats/atoms/telecomm/telecom_extension_atom.proto
index c7782b66..6a4673a8 100644
--- a/stats/atoms/telecomm/telecom_extension_atom.proto
+++ b/stats/atoms/telecomm/telecom_extension_atom.proto
@@ -137,11 +137,11 @@ message TelecomApiStats {
 message TelecomErrorStats {
     // The sub module name
     // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
-    optional android.telecom.SubmoduleNameEnum submodule_name = 1;
+    optional android.telecom.SubmoduleEnum submodule = 1;
 
     // The error name
     // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
-    optional android.telecom.ErrorNameEnum error_name = 2;
+    optional android.telecom.ErrorEnum error = 2;
 
     // The number of times this error occurs
     optional int32 count = 3;
diff --git a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
index b60a1f28..e711a443 100644
--- a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
+++ b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
@@ -128,6 +128,12 @@ message SatelliteController {
   optional int32 count_of_successful_location_queries = 32;
   // Count of failed location queries
   optional int32 count_of_failed_location_queries = 33;
+  // Number of times the notification indicating P2P SMS availability was shown.
+  optional int32 count_of_p2p_sms_available_notification_shown = 34;
+  // Number of times the notification indicating P2P SMS availability was removed.
+  optional int32 count_of_p2p_sms_available_notification_removed = 35;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 36;
 }
 
 /**
@@ -172,6 +178,12 @@ message SatelliteSession {
   optional int32 count_of_auto_exit_due_to_screen_off = 16;
   // Total number of times exit P2P message service automatically when a TN network is detected during idle scanning mode
   optional int32 count_of_auto_exit_due_to_tn_network = 17;
+  // Whether this session is enabled for emergency.
+  optional bool is_emergency = 18;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 19;
+  // Max user inactivity duration in seconds
+  optional int32 max_inactivity_duration_sec = 20;
 }
 
 /**
@@ -191,6 +203,8 @@ message SatelliteIncomingDatagram {
   optional bool is_demo_mode = 4;
   // Carrier id of the subscription connected to non-terrestrial network
   optional int32 carrier_id = 5;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 6;
 }
 
 /**
@@ -212,6 +226,8 @@ message SatelliteOutgoingDatagram {
   optional bool is_demo_mode = 5;
   // Carrier id of the subscription connected to non-terrestrial network
   optional int32 carrier_id = 6;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 7;
 }
 
 /**
@@ -229,6 +245,8 @@ message SatelliteProvision {
   optional bool is_canceled = 4;
   // Carrier id of the subscription connected to non-terrestrial network
   optional int32 carrier_id = 5;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 6;
 }
 
 /**
@@ -255,6 +273,8 @@ message SatelliteSosMessageRecommender {
   optional bool is_wifi_connected = 9;
   // Carrier id of the subscription connected to non-terrestrial network
   optional int32 carrier_id = 10;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 11;
 }
 
 /**
@@ -390,4 +410,6 @@ message SatelliteAccessController {
   optional int32 carrier_id = 10;
   // From which reason the Satellite Access Controller operation was triggered.
   optional android.telephony.TriggeringEvent triggering_event = 11;
+  // Whether this satellite service is from NTN only carrier.
+  optional bool is_ntn_only_carrier = 12;
 }
diff --git a/stats/atoms/threadnetwork/threadnetwork_atoms.proto b/stats/atoms/threadnetwork/threadnetwork_atoms.proto
index 70bcfb46..a3dfa944 100644
--- a/stats/atoms/threadnetwork/threadnetwork_atoms.proto
+++ b/stats/atoms/threadnetwork/threadnetwork_atoms.proto
@@ -231,6 +231,12 @@ message ThreadnetworkTelemetryDataReported {
     SRP_SERVER_ADDRESS_MODE_STATE_ANYCAST = 2;
   }
 
+  enum UpstreamDnsQueryState {
+    UPSTREAMDNS_QUERY_STATE_UNSPECIFIED = 0;
+    UPSTREAMDNS_QUERY_STATE_ENABLED = 1;
+    UPSTREAMDNS_QUERY_STATE_DISABLED = 2;
+  }
+
   message SrpServerInfo {
     // The state of the SRP server
     optional SrpServerState state = 1;
@@ -268,6 +274,15 @@ message ThreadnetworkTelemetryDataReported {
 
     // The number of other responses
     optional uint32 other_count = 6;
+
+    // The number of queries handled by Upstream DNS server.
+    optional uint32 upstream_dns_queries = 7;
+
+    // The number of responses handled by Upstream DNS server.
+    optional uint32 upstream_dns_responses = 8;
+
+    // The number of upstream DNS failures.
+    optional uint32 upstream_dns_failures = 9;
   }
 
   message DnsServerInfo {
@@ -276,6 +291,9 @@ message ThreadnetworkTelemetryDataReported {
 
     // The number of DNS queries resolved at the local SRP server
     optional uint32 resolved_by_local_srp_count = 2;
+
+    // The state of upstream DNS query
+    optional UpstreamDnsQueryState upstream_dns_query_state = 3;
   }
 
   message MdnsResponseCounters {
@@ -345,6 +363,93 @@ message ThreadnetworkTelemetryDataReported {
     optional Nat64State translator_state = 2;
   }
 
+  message TrelPacketCounters {
+    // The number of packets successfully transmitted through TREL
+    optional uint64 trel_tx_packets = 1;
+
+    // The number of bytes successfully transmitted through TREL
+    optional uint64 trel_tx_bytes = 2;
+
+    // The number of packet transmission failures through TREL
+    optional uint64 trel_tx_packets_failed = 3;
+
+    // The number of packets successfully received through TREL
+    optional uint64 trel_rx_packets = 4;
+
+    // The number of bytes successfully received through TREL
+    optional uint64 trel_rx_bytes = 5;
+  }
+
+  message TrelInfo {
+    // Whether TREL is enabled.
+    optional bool is_trel_enabled = 1;
+
+    // The number of TREL peers.
+    optional uint32 num_trel_peers = 2;
+
+    // TREL packet counters
+    optional TrelPacketCounters counters = 3;
+  }
+
+  message BorderAgentCounters {
+    // The number of ePSKc activations
+    optional uint32 epskc_activations = 1;
+
+    // The number of ePSKc deactivations due to cleared via API
+    optional uint32 epskc_deactivation_clears = 2;
+
+    // The number of ePSKc deactivations due to timeout
+    optional uint32 epskc_deactivation_timeouts = 3;
+
+    // The number of ePSKc deactivations due to max connection attempts reached
+    optional uint32 epskc_deactivation_max_attempts = 4;
+
+    // The number of ePSKc deactivations due to commissioner disconnected
+    optional uint32 epskc_deactivation_disconnects = 5;
+
+    // The number of ePSKc activation failures caused by invalid border agent
+    // state
+    optional uint32 epskc_invalid_ba_state_errors = 6;
+
+    // The number of ePSKc activation failures caused by invalid argument
+    optional uint32 epskc_invalid_args_errors = 7;
+
+    // The number of ePSKc activation failures caused by failed to start secure
+    // session
+    optional uint32 epskc_start_secure_session_errors = 8;
+
+    // The number of successful secure session establishment with ePSKc
+    optional uint32 epskc_secure_session_successes = 9;
+
+    // The number of failed secure session establishement with ePSKc
+    optional uint32 epskc_secure_session_failures = 10;
+
+    // The number of active commissioner petitioned over secure session
+    // establishment with ePSKc
+    optional uint32 epskc_commissioner_petitions = 11;
+
+    // The number of successful secure session establishment with PSKc
+    optional uint32 pskc_secure_session_successes = 12;
+
+    // The number of failed secure session establishement with PSKc
+    optional uint32 pskc_secure_session_failures = 13;
+
+    // The number of active commissioner petitioned over secure session
+    // establishment with PSKc
+    optional uint32 pskc_commissioner_petitions = 14;
+
+    // The number of MGMT_ACTIVE_GET.req received
+    optional uint32 mgmt_active_get_reqs = 15;
+
+    // The number of MGMT_PENDING_GET.req received
+    optional uint32 mgmt_pending_get_reqs = 16;
+  }
+
+  message BorderAgentInfo {
+    // The border agent counters
+    optional BorderAgentCounters border_agent_counters = 1;
+  }
+
   message WpanBorderRouter {
     // Border routing counters
     optional BorderRoutingCounters border_routing_counters = 1;
@@ -360,6 +465,12 @@ message ThreadnetworkTelemetryDataReported {
 
     // Information about the state of components of NAT64
     optional BorderRoutingNat64State nat64_state = 5;
+
+    // Information about TREL.
+    optional TrelInfo trel_info = 6;
+
+    // Information about the Border Agent
+    optional BorderAgentInfo border_agent_info = 7;
   }
 
   message RcpStabilityStatistics {
diff --git a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
index 52e97fb3..34d069c6 100644
--- a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
+++ b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
@@ -33,6 +33,8 @@ extend Atom {
       [(module) = "wearconnectivity"];
   optional WearCompanionConnectionState wear_companion_connection_state = 921
       [(module) = "wearconnectivity"];
+  optional SysproxyServiceStateUpdated sysproxy_service_state_updated = 949
+      [(module) = "wearconnectivity"];
 }
 
 /**
@@ -110,6 +112,37 @@ message SysproxyConnectionUpdated {
   optional int64 reason_timestamp_millis = 6;
 }
 
+/**
+ * Captures Sysproxy service state updates, such as service bringup/teardown. Also captures
+ * additional details on the sysproxy service state, such as iptables rules states.
+ */
+message SysproxyServiceStateUpdated {
+  // The Sysproxy service state. e.g. SERVICE_STARTUP_FINISHED, SERVICE_SHUTDOWN_FINISHED.
+  optional com.google.android.wearable.connectivity.SysproxyServiceState service_state = 1;
+
+  // The iptables config state for sysproxy. e.g. RULES_SETUP_SUCCESS, RULES_SETUP_FAILURE.
+  optional com.google.android.wearable.connectivity.SysproxyIptablesState iptables_state = 2;
+
+  // The error code for the iptables operation(setup, teardown, etc.).
+  // If the operation didn't fail, 0 is logged.
+  // If there are multiple cmds failed in the operation, the first failed cmd error code is logged.
+  optional int64 iptables_failure_error_code = 3;
+
+  // The index of the failed iptables cmd in the setup/teardown cmd list.
+  // If all cmds succeeded, -1 is logged.
+  optional int32 iptables_first_failed_cmd_index = 4;
+
+  // Total count of cmds failed(even after retry) in the iptables operation(iptables setup/teardown).
+  optional int32 iptables_failed_cmd_count = 5;
+
+  // Total count of cmds retried in the iptables operation.
+  // Compare with iptables_failed_cmd_count to understand how many cmds succeeded with retry.
+  optional int32 iptables_retried_cmd_count = 6;
+
+  // Total count of iptables recovery attempted in the background since the service is started.
+  optional int32 iptables_recovery_attempt_count = 7;
+}
+
 /**
  * Captures updates of the connections to the companion phone.
  * Only the one used for important data connectivity (Sysproxy, Comms, Assistant, etc.) is logged
diff --git a/stats/atoms/wear/media/wear_media_extension_atoms.proto b/stats/atoms/wear/media/wear_media_extension_atoms.proto
index 8c20292e..37a92003 100644
--- a/stats/atoms/wear/media/wear_media_extension_atoms.proto
+++ b/stats/atoms/wear/media/wear_media_extension_atoms.proto
@@ -38,6 +38,12 @@ extend Atom {
   optional MediaSessionStateChanged media_session_state_changed = 677
       [(module) = "wearmedia"];
 
+  optional MediaControlApiUsageReported media_control_api_usage_reported = 966
+      [(module) = "wearmedia"];
+
+  optional MediaSubscriptionChanged media_subscription_changed = 990
+      [(module) = "wearmedia"];
+
   optional WearMediaOutputSwitcherDeviceScanApiLatency
       wear_media_output_switcher_device_scan_api_latency = 757 [(module) = "MediaOutputSwitcher"];
 
@@ -142,6 +148,27 @@ message MediaSessionStateChanged {
 
 }
 
+/**
+ * Logs when the watch changes the media subscription of the Adaptive Media
+ * Bridging (go/wear-dd-adaptive-media-bridging) implementation.
+ *
+ * Adaptive Media Bridging changes the amount of media data to be bridged to the
+ * watch depending on whether the user is actively controlling phone media on
+ * the watch. Every time the subscription changes, the watch will log this atom.
+ *
+ * This will help estimate the power drain of Adaptive Media Bridging, and
+ * whether Adaptive Media Bridging is enabled.
+ *
+ * Logged from:
+ * package: vendor/google_clockwork/packages/Media
+ * Estimated Logging Rate:
+ * Peak: 10 times in 30s | Avg: 20 per device per day
+ */
+message MediaSubscriptionChanged {
+  // Version of the media session apk installed in the device.
+  optional int64 version_code = 1;
+}
+
 /**
  * Logs the latency of different device scan APIs used in OutputSwitcher.
  *
@@ -181,3 +208,38 @@ message WearMediaOutputSwitcherFastPairApiTimeout {
   // Name of the media app package from where Output Switcher got triggered.
   optional string triggering_package_name = 1;
 }
+
+/**
+ * Logs data when media control API is called.
+ *
+ * Logged from:
+ * package: vendor/google_clockwork/packages/Media
+ */
+message MediaControlApiUsageReported {
+  // Type of the API called.
+  enum MediaControlApiType {
+    API_TYPE_UNKNOWN = 0;
+    REQUEST_MEDIA_SESSION = 1;
+    REQUEST_MEDIA_SESSION_AND_REGISTER_LISTENER = 2;
+    UNREGISTER_MEDIA_SESSION_LIST_LISTENER = 3;
+    MEDIA_ACTION = 4;
+  }
+
+  // Status of the API.
+  enum MediaControlApiStatus {
+    STATUS_UNKNOWN = 0;
+    ACKNOWLEDGED = 1;
+    INVALID_SESSION_TOKEN = 2;
+    INVALID_LISTENER = 3;
+    UNKNOWN_ERROR = 4;
+  }
+
+  // Name of the package which called the API.
+  optional int32 caller_package_name = 1 [(is_uid) = true];
+
+  // The API which was called.
+  optional MediaControlApiType media_control_api_type = 2;
+
+  // Result status of the API call.
+  optional MediaControlApiStatus media_control_api_status = 3;
+}
diff --git a/stats/atoms/wear/setupwizard/wear_setup_wizard_extension_atoms.proto b/stats/atoms/wear/setupwizard/wear_setup_wizard_extension_atoms.proto
new file mode 100644
index 00000000..68be788d
--- /dev/null
+++ b/stats/atoms/wear/setupwizard/wear_setup_wizard_extension_atoms.proto
@@ -0,0 +1,213 @@
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
+syntax = "proto2";
+
+package android.os.statsd.wear.setupwizard;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/wear/setupwizard/enums.proto";
+
+option java_package = "com.android.os.wear.setupwizard";
+option java_multiple_files = true;
+
+/**
+ * All logs are logged from packages:
+ * vendor/google_clockwork/packages/SetupWizard/src/com/google/google/android/wearable/setupwizard
+ * vendor/google_clockwork/libs/setup
+ */
+
+extend Atom {
+  optional  WearSetupWizardDeviceStatusReported wear_setup_wizard_device_status_reported
+    = 953 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardPairingCompleted wear_setup_wizard_pairing_completed
+    = 954 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardConnectionEstablished wear_setup_wizard_connection_established
+    = 955 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardCheckinCompleted wear_setup_wizard_checkin_completed
+    = 956 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardCompanionTimeReported wear_setup_wizard_companion_time_reported
+    = 957 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardStatusReported wear_setup_wizard_status_reported
+    = 958 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardHeartbeatReported wear_setup_wizard_heartbeat_reported
+    = 959 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardFrpTriggered wear_setup_wizard_frp_triggered
+    = 960 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardSystemUpdateTriggered wear_setup_wizard_system_update_triggered
+    = 961 [(module) = "wear_setupwizard"];
+  optional  WearSetupWizardPhoneSwitchTriggered wear_setup_wizard_phone_switch_triggered
+    = 962 [(module) = "wear_setupwizard"];
+}
+
+/**
+ * Logged at the start and end of OOBE
+ */
+message WearSetupWizardDeviceStatusReported {
+  // The battery level of the watch
+  optional int32 battery_level = 1;
+
+  // Thermal status of the watch
+  // either LIGHT, MODERATE, SEVERE, CRITICAL, EMERGENCY, or SHUTDOWN
+  optional com.google.android.clockwork.setup.ThermalStatus thermal_status = 2;
+
+  // Whether the watch was on charger
+  optional bool is_on_charger = 3;
+
+  // Tether configuration set during OOBE
+  // either UNKNOWN, STANDALONE, TETHERED, or RESTRICTED
+  optional com.google.android.clockwork.setup.TetherConfiguration tether_configuration = 4;
+
+  // Wrist orientation set on companion during OOBE
+  // either LEFT_WRIST_WRIST_ORIENTATION_0, LEFT_WRIST_ORIENTATION_180, RIGHT_ORIENTATION_0, RIGHT_ORIENTATION_180
+  optional com.google.android.clockwork.setup.WristOrientation wrist_orientation = 5;
+
+  // SetupWizard application status
+  // either NOT_COMPLETED (in the OOBE process) or COMPLETED
+  optional com.google.android.clockwork.setup.SetupWizardStatus setup_wizard_status = 6;
+}
+
+/**
+ * Logged at pairing step
+ */
+message WearSetupWizardPairingCompleted {
+  // How pairing started / at which screen did pairing take place on the watch
+  // either FASTPAIR, LOCALE, or REGULARPAIR
+  optional com.google.android.clockwork.setup.PairingType pairing_type = 1;
+
+  // The companion OS type that is pairing with the watch
+  // either ANDROID or IOS
+  optional com.google.android.clockwork.setup.CompanionOsType companion_os_type = 2;
+
+  // Pairing step status
+  // either NOT_COMPLETED (in the pairing step) or COMPLETED
+  optional com.google.android.clockwork.setup.PairingStatus pairing_status  = 3;
+}
+
+/**
+ * Logged when comms connection established (done in WearServices)
+ * Essential during OOBE for message exchange between watch and companion
+ */
+message WearSetupWizardConnectionEstablished {
+  // Connection status between watch and companion
+  // either NOT_ESTABLISHED (comms in progress) or ESTABLISHED
+  optional com.google.android.clockwork.setup.ConnectionStatus connection_status = 1;
+}
+
+/**
+ * Logged at checkin step
+ */
+message WearSetupWizardCheckinCompleted {
+  // Number of attempts it took for successful checkin
+  optional int32 num_attempts = 1;
+
+  // Watch checkin status
+  // either NOT_COMPLETED (checkin in progress) or COMPLETED
+  optional com.google.android.clockwork.setup.CheckinStatus checkin_status = 2;
+}
+
+/**
+ * Logged when companion sends a message to sync time (watch syncs to companion time)
+ */
+message WearSetupWizardCompanionTimeReported {
+  // Companion current time expressed in ms
+  optional int64 companion_time_ms = 1;
+
+  // Watch current time expressed in ms
+  optional int64 watch_time_ms = 2;
+}
+
+/**
+ * Logged during status message exchange between watch and companion
+ */
+message WearSetupWizardStatusReported {
+  // Role of the watch during message exchange
+  // Either SENDER if watch sends a status, or RECEIVER upon receiving status
+  optional com.google.android.clockwork.setup.MessageRole message_role = 1;
+
+  // Status of the message sent or received
+  // Refer to frameworks/proto_logging/stats/atoms/wear/setupwizard atoms.proto file for possible message status types
+  optional com.google.android.clockwork.setup.MessageStatus message_status = 2;
+}
+
+/**
+ * Logged during heartbeat message exchange between watch and companion (only if resumable OOBE is triggered)
+ */
+message WearSetupWizardHeartbeatReported {
+  // Role of the watch during message exchange
+  // Either SENDER if watch sends a status, or RECEIVER upon receiving status
+  optional com.google.android.clockwork.setup.MessageRole message_role  = 1;
+
+  // Heartbeat message type of the message sent or received
+  // Either REQUEST, RESPONSE, or UNSUPPORTED_COMMAND
+  optional com.google.android.clockwork.setup.HeartbeatMessageType
+    heartbeat_message_type = 2;
+}
+
+/**
+ * Logged at FRP step (if triggered)
+ * Triggered under the conditions of
+ * 1. Watch previously setup
+ * 2. During watch setup user provided a google account
+ * 3. Factory resetting the watch was triggered from companion
+ */
+message WearSetupWizardFrpTriggered {
+  // Statuses encountered during FRP
+  // Refer to frameworks/proto_logging/stats/atoms/wear/setupwizard atoms.proto file for possible frp status types
+  optional com.google.android.clockwork.setup.FrpStatus frp_status = 1;
+}
+
+/**
+ * Logged during system update step (if triggered)
+ * Triggered if pending day 0 OTA is detected
+ */
+message WearSetupWizardSystemUpdateTriggered {
+  // Whether the OTA detected is day 0
+  // True if it is a day 0 OTA (watch needs to be updated during setup) and false otherwise
+  optional bool is_day_zero_ota = 1;
+
+  // Whether the OTA has completed successfully
+  // True if OTA status reaches a successful terminal status
+  // False if OTA status reached a failure terminal status
+  optional bool is_successful = 2;
+
+  // System update progress status
+  // either NOT_COMPLETED (system update in progress) or COMPLETED
+  optional com.google.android.clockwork.setup.SystemUpdateProgressStatus
+    system_update_progress_status = 3;
+}
+
+/**
+ * Logged during phone switching
+ */
+message WearSetupWizardPhoneSwitchTriggered {
+  // How phone switching was triggered
+  // either NONE, WATCH, COMPANION_USER_CONFIRMATION, or COMPANION
+  // COMPANION_USER_CONFIRMATION is when a new phone is going through setup and user transfer devices from an old phone to the new phone
+  optional com.google.android.clockwork.setup.PhoneSwitchingRequestSource
+    phone_switching_request_source = 1;
+
+  // Statuses encountered during phone switching
+  // Refer to frameworks/proto_logging/stats/atoms/wear/setupwizard atoms.proto file for possible phone switching statuses
+  optional com.google.android.clockwork.setup.PhoneSwitchingStatus
+    phone_switching_status = 2;
+
+  // Companion OS change after phone switching is completed
+  // Either ANDROID_TO_ANDROID, IOS_TO_ANDROID, or IOS_TO_IOS
+  optional com.google.android.clockwork.setup.PhoneSwitchingCompanionOsTypeChange
+    phone_switching_companion_os_type_change = 3;
+}
diff --git a/stats/atoms/wearservices/wearservices_atoms.proto b/stats/atoms/wearservices/wearservices_atoms.proto
index 3eb1490f..7a6f25d2 100644
--- a/stats/atoms/wearservices/wearservices_atoms.proto
+++ b/stats/atoms/wearservices/wearservices_atoms.proto
@@ -122,6 +122,13 @@ message WsNotificationUpdated {
   // Whether this notification has set FLAG_FOREGROUND_SERVICE. Which means the
   // notification may be frequently updated.
   optional bool is_foreground_service = 21;
+
+  // Whether this notification has set FLAG_PROMOTED_ONGOING.
+  optional bool is_promoted_ongoing = 22;
+
+  // Whether this notification has promotable characteristics, taken from
+  // Notification#hasPromotableCharacteristics().
+  optional bool has_promotable_characteristics = 23;
 }
 
 /** Logged when a notification is updated in the WearServices application. */
diff --git a/stats/atoms/wearservices/wearservices_extension_atoms.proto b/stats/atoms/wearservices/wearservices_extension_atoms.proto
index efc6d639..146021d9 100644
--- a/stats/atoms/wearservices/wearservices_extension_atoms.proto
+++ b/stats/atoms/wearservices/wearservices_extension_atoms.proto
@@ -63,16 +63,10 @@ extend Atom {
   optional WsRemoteEventUsageReported ws_remote_event_usage_reported = 920
       [(module) = "wearservices"];
 
-    optional WsBugreportRequested ws_bugreport_requested = 936
+  optional WsNotificationManagedDismissalSync ws_notification_managed_dismissal_sync = 941
       [(module) = "wearservices"];
 
-  optional WsBugreportTriggered ws_bugreport_triggered = 937
-      [(module) = "wearservices"];
-
-  optional WsBugreportFinished ws_bugreport_finished = 938
-      [(module) = "wearservices"];
-
-  optional WsBugreportResultReceived ws_bugreport_result_received = 939
+  optional WsBugreportEventReported ws_bugreport_event_reported = 964
       [(module) = "wearservices"];
 
   // Pulled Atom
@@ -385,41 +379,54 @@ message WsRemoteEventUsageReported {
   optional android.app.wearservices.RemoteEventType remote_event_type = 1;
 
   // Indicates the status of the remote event being sent.
-  optional bool is_successful = 2;
-}
+  // Note: This field is deprecated.
+  optional bool is_successful = 2 [deprecated = true];
 
-/** Logged when WearServices triggers a bugreport to be captured. */
-message WsBugreportTriggered {
+  // Indicates the state of the remote event.
+  optional android.app.wearservices.RemoteEventState remote_event_state = 3;
 }
 
-/** Logged when WearServices receives a request to capture a bugreport. */
-message WsBugreportRequested {
-
-  // Depicts the request source of the bugreport
-  // Values: (BUGREPORT_COMPONENT_UNKNOWN, BUGREPORT_COMPONENT_COMPANION_APP, BUGREPORT_COMPONENT_WATCH_UI)
-  optional android.app.wearservices.BugreportComponent requester = 1;
-
+/** Logged when a bugreport event takes place. */
+message WsBugreportEventReported {
+
+  // Depicts the event that is being reported.
+  // Values: (EVENT_BUGREPORT_UNKNOWN, EVENT_BUGREPORT_REQUESTED, EVENT_BUGREPORT_TRIGGERED, EVENT_BUGREPORT_FINISHED, EVENT_BUGREPORT_RESULT_RECEIVED)
+  optional android.app.wearservices.BugreportEvent event = 1;
+
+  // Depicts the component involved in the bugreport flow.
+  // In the case of EVENT_BUGREPORT_REQUESTED, it refers to the component that requested the
+  // bugreport.
+  // In the case of EVENT_BUGREPORT_RESULT_RECEIVED, it refers to the component that received the
+  // bugreport result.
+  // It's set to BUGREPORT_COMPONENT_UNSET when the event is EVENT_BUGREPORT_TRIGGERED or
+  // EVENT_BUGREPORT_FINISHED.
+  // Values: (BUGREPORT_COMPONENT_UNKNOWN, BUGREPORT_COMPONENT_UNSET, BUGREPORT_COMPONENT_COMPANION_APP, BUGREPORT_COMPONENT_WATCH_UI)
+  optional android.app.wearservices.BugreportComponent component = 2;
+
+  // Depicts the result of the bugreport.
+  // It's set to BUGREPORT_RESULT_UNSET when the event is EVENT_BUGREPORT_REQUESTED or
+  // EVENT_BUGREPORT_TRIGGERED.
+  // Values: (BUGREPORT_RESULT_UNKNOWN, BUGREPORT_RESULT_UNSET, BUGREPORT_RESULT_SUCCESS, BUGREPORT_RESULT_FAILURE)
+  optional android.app.wearservices.BugreportResult result = 3;
+
+  // Depicts the size of the bugreport in kilobytes
+  // It's set to 0 when the event is EVENT_BUGREPORT_REQUESTED or EVENT_BUGREPORT_TRIGGERED.
+  optional int32 bugreport_size_kilobytes = 4;
+
+  // Depicts the duration of the bugreport event in seconds.
+  // It's set only for EVENT_BUGREPORT_FINISHED and EVENT_BUGREPORT_RESULT_RECEIVED.
+  optional int32 bugreport_event_duration_seconds = 5;
 }
 
-/** Logged when WearServices receives back the captured bugreport. */
-message WsBugreportFinished {
+/** Logged when notification ID dismissal was synchronised between devices. */
+message WsNotificationManagedDismissalSync {
+  // Package name of the application that created the notification.
+  // We use package name instead of uid as the application may not be installed on the device.
+  optional string package_name = 1;
 
-  // Depicts the result of the bugreport
-  // Values: (BUGREPORT_RESULT_UNKNOWN, BUGREPORT_RESULT_SUCCESS, BUGREPORT_RESULT_FAILURE)
-  optional android.app.wearservices.BugreportResult result = 1;
+  // Device that initiated the synchronisation.
+  optional android.app.wearservices.RequestSource source_device = 2;
 
-  // Depicts the size of the bugreport in bytes
-  optional int32 bugreport_size_bytes = 2;
+  // Size of the payload in bytes
+  optional int32 payload_size_bytes = 3;
 }
-
-/** Logged when a component receives back the captured bugreport. */
-message WsBugreportResultReceived {
-
-  // Depicts the receiver of the bugreport
-  // Values: (BUGREPORT_COMPONENT_UNKNOWN, BUGREPORT_COMPONENT_COMPANION_APP, BUGREPORT_COMPONENT_WATCH_UI)
-  optional android.app.wearservices.BugreportComponent receiver = 1;
-
-  // Depicts the result of the bugreport
-  // Values: (BUGREPORT_RESULT_UNKNOWN, BUGREPORT_RESULT_SUCCESS, BUGREPORT_RESULT_FAILURE)
-  optional android.app.wearservices.BugreportResult result = 2;
-}
\ No newline at end of file
diff --git a/stats/atoms/wearsysui/wearsysui_extension_atoms.proto b/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
index 3946fe1d..d159c4bd 100644
--- a/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
+++ b/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
@@ -67,10 +67,8 @@ message FirstOverlayStateChanged {
     }
 
     optional OverlayState overlay_state = 1;
-    // The time when first overlay is shown, in milliseconds since the system was booted.
-    optional int64 time_to_overlay_shown_ms = 2;
-    // The time when first overlay is dismissed, in milliseconds since the system was booted.
-    optional int64 time_to_overlay_dismissed_ms = 3;
+    // The time when first overlay state change has occurred, in milliseconds since the system was booted.
+    optional int64 state_change_time_ms = 2;
     // Indicates whether the lock screen is enabled
-    optional bool is_locked_screen_active = 4;
+    optional bool is_locked_screen_active = 3;
 }
diff --git a/stats/atoms/wifi/wifi_extension_atoms.proto b/stats/atoms/wifi/wifi_extension_atoms.proto
index 87cdf4f3..fbd381a5 100644
--- a/stats/atoms/wifi/wifi_extension_atoms.proto
+++ b/stats/atoms/wifi/wifi_extension_atoms.proto
@@ -479,6 +479,8 @@ message WifiSettingInfo {
         WIFI_ENHANCED_MAC_RANDOMIZATION = 6;
         WIFI_NETWORKS_AVAILABLE_NOTIFICATION = 7;
         LOCATION_MODE = 8;
+        // A flag controlled by DeviceConfig to dry run external scorer or not.
+        EXTERNAL_SCORER_DRY_RUN = 9;
     }
 
     // Name of the Wifi setting
diff --git a/stats/enums/accounts/enums.proto b/stats/enums/accounts/enums.proto
new file mode 100644
index 00000000..11f53169
--- /dev/null
+++ b/stats/enums/accounts/enums.proto
@@ -0,0 +1,36 @@
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
+syntax = "proto2";
+
+package android.os.statsd.accounts;
+
+option java_outer_classname = "AccountsProtoEnums";
+option java_multiple_files = true;
+
+// Logging constants for AccountManagerService.
+enum AccountEventType {
+  ACCOUNT_EVENT_TYPE_UNKNOWN = 0;
+  // New app with authenticator is found - insertOrReplaceMetaAuthTypeAndUid
+  AUTHENTICATOR_ADDED = 1;
+  ACCOUNT_ADDED = 2;
+  ACCOUNT_REMOVED = 3;
+  PASSWORD_CHANGED = 4;
+  PASSWORD_REMOVED = 5;
+  USER_DATA_CHANGED = 6;
+  // Token is stored in AccountManagerService cache.
+  TOKEN_CACHED = 7;
+}
diff --git a/stats/enums/adservices/common/adservices_api_metrics_enums.proto b/stats/enums/adservices/common/adservices_api_metrics_enums.proto
index 62684fa1..449569db 100644
--- a/stats/enums/adservices/common/adservices_api_metrics_enums.proto
+++ b/stats/enums/adservices/common/adservices_api_metrics_enums.proto
@@ -52,6 +52,11 @@ option java_multiple_files = true;
 //
 // PAS
 //   * updateSignals()
+//
+// ODP
+//   * scheduleTraining()
+//   * recordImpression()
+//   * recordClick()
 
 enum AdServicesApiClassType {
   UNKNOWN = 0;
@@ -62,6 +67,7 @@ enum AdServicesApiClassType {
   APPSETID = 5;
   ADEXT_DATA_SERVICE = 6;
   COMMON = 7;
+  ON_DEVICE_PERSONALIZATION = 8;
 }
 
 enum AdServicesApiName {
@@ -99,4 +105,7 @@ enum AdServicesApiName {
   PERSIST_AD_SELECTION_RESULT = 31;
   UPDATE_SIGNALS = 32;
   SCHEDULE_CUSTOM_AUDIENCE_UPDATE = 33;
+  SCHEDULE_TRAINING = 34;
+  RECORD_IMPRESSION = 35;
+  RECORD_CLICK = 36;
 }
\ No newline at end of file
diff --git a/stats/enums/adservices/common/adservices_cel_enums.proto b/stats/enums/adservices/common/adservices_cel_enums.proto
index 07e8db64..0b4d34b5 100644
--- a/stats/enums/adservices/common/adservices_cel_enums.proto
+++ b/stats/enums/adservices/common/adservices_cel_enums.proto
@@ -111,6 +111,27 @@ enum ErrorCode {
   // Error code is present multiple times in the custom sampling proto
   ERROR_CODE_PRESENT_MULTIPLE_TIMES_IN_PROTO = 26;
 
+  // Package Deny process failure unknown.
+  PACKAGE_DENY_PROCESS_ERROR_FAILURE_UNKNOWN = 27;
+
+  // Package Deny process failure due to no file found.
+  PACKAGE_DENY_PROCESS_ERROR_NO_FILE_FOUND = 28;
+
+  // Package Deny process failure due to reading file.
+  PACKAGE_DENY_PROCESS_ERROR_FAILED_READING_FILE = 29;
+
+  // Package Deny process failure in filtering installed packages.
+  PACKAGE_DENY_PROCESS_ERROR_FAILED_FILTERING_INSTALLED_PACKAGES = 30;
+
+  // Package Deny process failure due to updating cache.
+  PACKAGE_DENY_PROCESS_ERROR_FAILED_UPDATING_CACHE = 31;
+
+  // Package Deny process failure due failure reading cache.
+  PACKAGE_DENY_PROCESS_ERROR_FAILED_READING_CACHE = 32;
+
+  // Package Deny process failure service disabled.
+  PACKAGE_DENY_PROCESS_ERROR_DISABLED = 33;
+
   // SPE Errors: 901 - 1000
   // Get an unavailable job execution start timestamp when calculating the execution latency.
   SPE_UNAVAILABLE_JOB_EXECUTION_START_TIMESTAMP = 901;
@@ -808,6 +829,410 @@ enum ErrorCode {
   // Exception because all APIs consent disabled for Fledge API.
   FLEDGE_CONSENT_FILTER_ALL_APIS_CONSENT_DISABLED = 3142;
 
+  // Error occurred because interaction URI length exceeds the maximum allowed
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_INTERACTION_URI_EXCEEDS_MAXIMUM_LIMIT = 3143;
+
+  // Error occurred when a revoke consent error is silently handled with notifying an empty success.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_EMPTY_SUCCESS_SILENT_CONSENT_FAILURE = 3144;
+
+  // Error occurs when a Custom Audience API was called with null parameters.
+  CUSTOM_AUDIENCE_SERVICE_NULL_ARGUMENT = 3145;
+
+  // Error occurs when a Custom Audience API failed to get the UID of the caller app.
+  CUSTOM_AUDIENCE_SERVICE_GET_CALLING_UID_ILLEGAL_STATE = 3146;
+
+  // Error occurs when a Custom Audience API failed to notify success to the caller.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_SUCCESS_TO_CALLER_FAILED = 3147;
+
+  // Error occurs when a Custom Audience API failed because of invalid arguments.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_INVALID_ARGUMENT = 3148;
+
+  // Error occurs when a Custom Audience API is called by a background caller.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_BACKGROUND_CALLER = 3149;
+
+  // Error occurs when a Custom Audience API is called by an unauthorized caller.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_UNAUTHORIZED = 3150;
+
+  // Error occurs when a caller of a Custom Audience API is not allowed.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_CALLER_NOT_ALLOWED = 3151;
+
+  // Error occurs when a call to a Custom Audience API reached the rate limit.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_RATE_LIMIT_REACHED = 3152;
+
+  // Error occurs when a call to Custom Audience API runs into an unexpected error.
+  CUSTOM_AUDIENCE_SERVICE_NOTIFY_FAILURE_INTERNAL_ERROR = 3153;
+
+  // Error occurs when a coming call to a FLEDGE API is throttled.
+  FLEDGE_API_THROTTLE_FILTER_RATE_LIMIT_REACHED = 3154;
+
+  // Error occurs when a caller crossed the user boundary,
+  APP_IMPORTANCE_FILTER_IMPORTANCE_CALLER_NOT_ALLOWED_TO_CROSS_USER_BOUNDARIES = 3155;
+
+  // Error occurs when a caller's importance value is too high.
+  // The higher the importance, the less possible it is from foreground.
+  APP_IMPORTANCE_FILTER_IMPORTANCE_EXCEEDED_THRESHOLD = 3156;
+
+  // Error occurs when the caller package is not in the FLEDGE allow-list.
+  FLEDGE_ALLOW_LISTS_FILTER_PACKAGE_NOT_IN_ALLOW_LIST = 3157;
+
+  // Error occurs when the total  owners of CAs on a device reached max allowed value.
+  CUSTOM_AUDIENCE_QUANTITY_CHECKER_REACHED_MAX_NUMBER_OF_OWNER = 3158;
+
+  // Error occurs when the CA counts on a device reached max allowed value.
+  CUSTOM_AUDIENCE_QUANTITY_CHECKER_REACHED_MAX_NUMBER_OF_TOTAL_CUSTOM_AUDIENCE = 3159;
+
+  // Error occurs when the per owner CA counts on a device reached max allowed value.
+  CUSTOM_AUDIENCE_QUANTITY_CHECKER_REACHED_MAX_NUMBER_OF_CUSTOM_AUDIENCE_PER_OWNER = 3160;
+
+  // Error occurs when fetchCustomAudience is disabled.
+  FETCH_CUSTOM_AUDIENCE_IMPL_DISABLED = 3161;
+
+  // Error occurs when the associated owner-buyer pair is quarantined.
+  FETCH_CUSTOM_AUDIENCE_IMPL_QUARANTINED = 3162;
+
+  // Error occurs when the header of a fetch Custom Audience request is too large.
+  FETCH_CUSTOM_AUDIENCE_IMPL_REQUEST_CUSTOM_HEADER_EXCEEDS_SIZE_LIMIT = 3163;
+
+  // Error occurs when fails to parse the fetch Custom Audience response string as a JSONObject.
+  FETCH_CUSTOM_AUDIENCE_IMPL_INVALID_JSON_RESPONSE = 3164;
+
+  // Error occurs when the fused Custom Audience object is missing field values.
+  FETCH_CUSTOM_AUDIENCE_IMPL_INCOMPLETE_FUSED_CUSTOM_AUDIENCE = 3165;
+
+  // Error occurs when the fused Custom Audience object exceeded max allows byte length.
+  FETCH_CUSTOM_AUDIENCE_IMPL_FUSED_CUSTOM_AUDIENCE_EXCEEDS_SIZE_LIMIT = 3166;
+
+  // Error occurs when the failed to send fetch CA success notification to caller.
+  FETCH_CUSTOM_AUDIENCE_IMPL_UNABLE_TO_SEND_SUCCESSFUL_RESULT_TO_CALLBACK = 3167;
+
+  // Error occurs when the failed to notify fetch CA failure to caller.
+  FETCH_CUSTOM_AUDIENCE_IMPL_UNABLE_TO_SEND_FAILURE_TO_CALLBACK = 3168;
+
+  // Error occurs when the user consent is revoked while fetching CA.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3169;
+
+  // Error occurs when the caller of fetch CA is from background.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3170;
+
+  // Error occurs when the caller of fetch CA is not allowed.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3171;
+
+  // Error occurs when the caller of fetch CA is unauthorized.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3172;
+
+  // Error occurs when the caller of fetch CA reached the rate limit.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3173;
+
+  // Error occurs when fetch CA call captured invalid arguments.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_ILLEGAL_ARGUMENT_ERROR = 3174;
+
+  // Error occurs when fetch CA call captured invalid  objects.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_INVALID_OBJECT_ERROR = 3175;
+
+  // Error occurs when fetch CA call reached server rate limit.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_SERVER_RATE_LIMIT_REACHED = 3176;
+
+  // Error occurs when fetch CA call captured unexpected error.
+  FETCH_CUSTOM_AUDIENCE_IMPL_NOTIFY_FAILURE_INTERNAL_ERROR = 3177;
+
+  // Error occurs when failed to parse an Ad selection signal string to JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_PARSING_AD_SELECTION_SIGNALS_STRING_TO_JSON = 3178;
+
+  // Error occurs when failed to initiate an AdSelectionSignals instance from a JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_INITIATING_AD_SELECTION_SIGNALS_FROM_JSON = 3179;
+
+  // Error occurs when failed to get a string value from a JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_STRING_VALUE_FROM_JSON_BY_KEY = 3180;
+
+  // Error occurs when failed to get a time instant value from a JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_TIME_INSTANT_FROM_JSON_BY_KEY = 3181;
+
+  // Error occurs when failed to initiate a TrustedBiddingData instance fomr JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_TRUSTED_BIDDING_DATA_FROM_JSON = 3182;
+
+  // Error occurs when failed to get a string value from a JSONArray given index.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_STRING_FROM_JSON_ARRAY = 3183;
+
+  // Error occurs when getting a null value from a JSONArray given index.
+  CUSTOM_AUDIENCE_BLOB_NULL_ARGUMENT = 3184;
+
+  // Error occurs when failed to create a JSONObject from a TrustedBiddingData instance.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_TRUSTED_BIDDING_DATA_AS_JSON_OBJECT = 3185;
+
+  // Error occurs when failed to create a list of AdData instances from a JSONObject.
+  CUSTOM_AUDIENCE_BLOB_FAILED_GETTING_ADS_FROM_JSON_OBJECT = 3186;
+
+  // Error occurs when failed to get a string valure representing a render URI from a JSONObject given the key.
+  CUSTOM_AUDIENCE_BLOB_FAILED_PARSING_RENDER_URI_IN_ADS_JSON_ARRAY = 3187;
+
+  // Error occurs when Quarantine table maximum has been reached.
+  CUSTOM_AUDIENCE_DAO_QUARANTINE_TABLE_MAX_REACHED = 3188;
+
+  // Error occurs when caught invalid JSON invoking seller script during reporting impression.
+  IMPRESSION_REPORTER_INVALID_JSON_SELLER = 3189;
+
+  // Error occurs when caught invalid JSON invoking buyer script during reporting impression.
+  IMPRESSION_REPORTER_INVALID_JSON_BUYER = 3190;
+
+  // Error occurs when failed to fetch buyer script given a URI.
+  IMPRESSION_REPORTER_ERROR_FETCHING_BUYER_SCRIPT_FROM_URI = 3191;
+
+  // Error occurs when the seller's reporting URI is invalid.
+  IMPRESSION_REPORTER_INVALID_SELLER_REPORTING_URI = 3192;
+
+  // Error occurs when the buyer's reporting URI is invalid.
+  IMPRESSION_REPORTER_INVALID_BUYER_REPORTING_URI = 3193;
+
+  // Error occurs when failed to notify success to caller of reportImpression.
+  IMPRESSION_REPORTER_NOTIFY_SUCCESS_TO_CALLER_FAILED = 3194;
+
+  // Error occurs when GET call to a reporting URI failed.
+  IMPRESSION_REPORTER_HTTP_GET_REPORTING_URL_FAILED = 3195;
+
+  // Error occurs when report impression failed due to IO error.
+  IMPRESSION_REPORTER_FAILED_DUE_TO_IO_ERROR_DURING_REPORTING = 3196;
+
+  // Error occurs when report impression failed.
+  IMPRESSION_REPORTER_FAILED_DURING_REPORTING = 3197;
+
+  // Error occurs when the user consent is revoked while reporting impression.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3198;
+
+  // Error occurs when the caller of reporting impression is from background.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3199;
+
+  // Error occurs when the caller of reporting impression is not allowed.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3200;
+
+  // Error occurs when the caller of reporting impression is unauthorized.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3201;
+
+  // Error occurs when the caller of reporting impression reached the rate limit.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3202;
+
+  // Error occurs when reporting impressioncall captured invalid arguments.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_INVALID_ARGUMENT = 3203;
+
+  // Error occurs when reporting impression call captured unexpected error.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_INTERNAL_ERROR = 3204;
+
+  // Error occurs when failed to notify failure to caller during reporting impression call.
+  IMPRESSION_REPORTER_NOTIFY_FAILURE_TO_CALLER_FAILED = 3205;
+
+  // Error occurs when the interaction key size exceeded max during reporting impression call.
+  IMPRESSION_REPORTER_INTERACTION_KEY_SIZE_EXCEEDS_MAX = 3206;
+
+  // Error occurs when the reporting URI size exceeded max during reporting impression call.
+  IMPRESSION_REPORTER_INTERACTION_REPORTING_URI_SIZE_EXCEEDS_MAX = 3207;
+
+  // Error occurs when the interaction URI is invalid during reporting impression call.
+  IMPRESSION_REPORTER_INVALID_INTERACTION_URI = 3208;
+
+  // Error occurs when the outcome selection logic is missing fetching seller reporting logic.
+  JS_FETCHER_SELLER_MISSING_OUTCOME_SELECTION_LOGIC = 3209;
+
+  // Error occurs when the outcome selection logic is missing fetching buyer reporting logic.
+  JS_FETCHER_BUYER_MISSING_OUTCOME_SELECTION_LOGIC = 3210;
+
+  // Error occurs when caught invalid JSON invoking seller script during reporting impression using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_INVALID_JSON = 3211;
+
+  // Error occurs when failed to fetch buyer script given a URI using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_FETCHING_BUYER_SCRIPT_FAILED = 3212;
+
+  // Error occurs when failed to notify success to caller of reportImpression using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_SUCCESS_TO_CALLER_FAILED = 3213;
+
+  // Error occurs when GET call to a reporting URI failed using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_GETTING_REPORTING_URL_FAILED = 3214;
+
+  // Error occurs when the seller's reporting URI is invalid using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_INVALID_SELLER_REPORTING_URI = 3215;
+
+  // Error occurs when the buyer's reporting URI is invalid using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_INVALID_BUYER_REPORTING_URI = 3216;
+
+  // Error occurs when report impression failed due to IO error using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_FAILED_DUE_TO_IO_ERROR = 3217;
+
+  // Error occurs when report impression failed using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_FAILED = 3218;
+
+  // Error occurs when the user consent is revoked while reporting impression using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3219;
+
+  // Error occurs when the caller of reporting impression is from background using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3220;
+
+  // Error occurs when the caller of reporting impression is not allowed using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3221;
+
+  // Error occurs when the caller of reporting impression is unauthorized using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3222;
+
+  // Error occurs when the caller of reporting impression reached the rate limit using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3223;
+
+  // Error occurs when reporting impressioncall captured invalid arguments using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_INVALID_ARGUMENT = 3224;
+
+  // Error occurs when reporting impression call captured unexpected error using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_INTERNAL_ERROR = 3225;
+
+  // Error occurs when failed to notify failure to caller during reporting impression call using the legacy reporter.
+  IMPRESSION_REPORTER_LEGACY_NOTIFY_FAILURE_TO_CALLER_FAILED = 3226;
+
+  // Error occurs when caught a malformed URI in https client.
+  AD_SERVICES_HTTPS_CLIENT_URI_IS_MALFORMED = 3227;
+
+  // Error occurs when failed to initiate connection with URL in https client.
+  AD_SERVICES_HTTPS_CLIENT_OPENING_URL_FAILED = 3228;
+
+  // Error occurs when caught a regular error in the response in https client.
+  AD_SERVICES_HTTPS_CLIENT_HTTP_REQUEST_ERROR = 3229;
+
+  // Error occurs when caught a retriable error in the response in https client.
+  AD_SERVICES_HTTPS_CLIENT_HTTP_REQUEST_RETRIABLE_ERROR = 3230;
+
+  // Error occurs when connection timeout reading response in https client.
+  AD_SERVICES_HTTPS_CLIENT_TIMEOUT_READING_RESPONSE = 3231;
+
+  // Error occurs when a null URI is passed to EnrollmentDao.
+  ENROLLMENT_DAO_URI_INVALID = 3232;
+
+  // Error occurs when a null API is passed to EnrollmentDao.
+  ENROLLMENT_DAO_PRIVACY_API_INVALID = 3233;
+
+  // Error occurs when failed to match an enrollment in EnrollmentDao.
+  ENROLLMENT_DAO_URI_ENROLLMENT_MATCH_FAILED = 3234;
+
+  // Error occurs when failed to get FLEDGE enrollment data from DB.
+  ENROLLMENT_DAO_GET_FLEDGE_ENROLLMENT_DATA_FROM_DB_FAILED = 3235;
+
+  // Error occurs when failed to get PAS enrollment data from DB.
+  ENROLLMENT_DAO_GET_PAS_ENROLLMENT_DATA_FROM_DB_FAILED = 3236;
+
+  // Error occurs when got llegal result returned by our calling function during report impression.
+  REPORT_IMPRESSION_SCRIPT_ENGINE_ILLEGAL_RESULT_RETURNED_BY_CALLING_FUNCTION = 3237;
+
+  // Error occurs when report result output has unexpected structure during report impression.
+  REPORT_IMPRESSION_SCRIPT_ENGINE_UNEXPECTED_RESULT_STRUCTURE = 3238;
+
+  // Error occurs when caught JS reference error during report impression.
+  REPORT_IMPRESSION_SCRIPT_ENGINE_JS_REFERENCE_ERROR = 3239;
+
+  // Error occurs when caught other JS error during report impression.
+  REPORT_IMPRESSION_SCRIPT_ENGINE_JS_OTHER_ERROR = 3240;
+
+  // Error occurs when failed to notify success to caller during an event reporting.
+  EVENT_REPORTER_NOTIFY_SUCCESS_TO_CALLER_FAILED = 3241;
+
+  // Error occurs when the user consent is revoked during an event reporting.
+  EVENT_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3242;
+
+  // Error occurs when the caller of event reporting is from background.
+  EVENT_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3243;
+
+  // Error occurs when the caller of event reporting is not allowed.
+  EVENT_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3244;
+
+  // Error occurs when the caller of event reporting is unauthorized.
+  EVENT_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3245;
+
+  // Error occurs when the caller of event reporting reached the rate limit.
+  EVENT_REPORTER_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3246;
+
+  // Error occurs when event reporting captured invalid arguments.
+  EVENT_REPORTER_NOTIFY_FAILURE_INVALID_ARGUMENT = 3247;
+
+  // Error occurs when event reporting call captured unexpected error.
+  EVENT_REPORTER_NOTIFY_FAILURE_INTERNAL_ERROR = 3248;
+
+  // Error occurs when failed to notify failure to caller during event reporting.
+  EVENT_REPORTER_NOTIFY_FAILURE_TO_CALLER_FAILED = 3249;
+
+  // Error occurs when failed to register an event during event reporting.
+  REPORT_AND_REGISTER_EVENT_IMPL_REGISTER_EVENT_FAILED = 3250;
+
+  // Error occurs when failed to report and register event due to IO exception.
+  REPORT_AND_REGISTER_EVENT_IMPL_FAILED_DUE_TO_IO_EXCEPTION = 3251;
+
+  // Error occurs when failed to report and register event due to unexpected error.
+  REPORT_AND_REGISTER_EVENT_IMPL_FAILED_DUE_TO_INTERNAL_ERROR = 3252;
+
+  // Error occurs when failed to report and register event due to IO exception using fallback.
+  REPORT_AND_REGISTER_EVENT_FALLBACK_IMPL_FAILED_DUE_TO_IO_EXCEPTION = 3253;
+
+  // Error occurs when failed to report and register event due to unexpected error using fallback.
+  REPORT_AND_REGISTER_EVENT_FALLBACK_IMPL_FAILED_DUE_TO_INTERNAL_ERROR = 3254;
+
+  // Error occurs when failed to report event due to IO exception using fallback.
+  REPORT_EVENT_IMPL_FAILED_DUE_TO_IO_EXCEPTION = 3255;
+
+  // Error occurs when failed to report event due to unexpected error using fallback.
+  REPORT_EVENT_IMPL_FAILED_DUE_TO_INTERNAL_ERROR = 3256;
+
+  // Error occurs when the version in the header of fetch JS response is not a numeric value.
+  JS_FETCHER_NON_NUMERIC_VERSION_FOR_JS_PAYLOAD = 3257;
+
+  // Error occurred when API type is unknown while trying to get enrollment data for an Ad tech.
+  FLEDGE_AUTHORIZATION_FILTER_INVALID_API_TYPE = 3258;
+
+  // Error occurred when failed to fetch enrollment data for an Ad tech.
+  FLEDGE_AUTHORIZATION_FILTER_ENROLLMENT_NOT_FOUND = 3259;
+
+  // Error occurred when an Ad tech from given URI is blocked.
+  FLEDGE_AUTHORIZATION_FILTER_NOT_ALLOWED_ENROLLMENT_FROM_URI_BLOCKED = 3260;
+
+  // Error occurred when the feature of scheduling an CA update is disabled.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_DISABLED = 3261;
+
+  // Error occurred when the user consent is revoked when attempting to schedule an CA update.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_USER_CONSENT_REVOKED = 3262;
+
+  // Error occurred when failed to filter a schedule CA update request.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_FILTER_EXCEPTION = 3263;
+
+  // Error occurred when failed schedule an CA update due to a pending schedule.
+  CUSTOM_AUDIENCE_DAO_FAILED_DUE_TO_PENDING_SCHEDULE = 3264;
+
+  // Error occurred when failed to notify success after scheduled an CA update.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_SUCCESS_TO_CALLER_FAILED = 3265;
+
+  // Error occurred when failed to schedule an CA update because the user consent is revoked.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3266;
+
+  // Error occurred when failed to schedule an CA update because the caller is from background.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3267;
+
+  // Error occurred when failed to schedule an CA update because the caller package is not allowed.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3268;
+
+  // Error occurred when failed to schedule an CA update because the caller is not authorized.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3269;
+
+  // Error occurred when failed to schedule an CA update because the caller exceeded rate limit.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3270;
+
+  // Error occurred when failed to schedule an CA update because of an invalid object.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_INVALID_OBJECT = 3271;
+
+  // Error occurred when failed to schedule an CA update because request reached server rate limit.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_SERVER_RATE_LIMIT_REACHED = 3272;
+
+  // Error occurred when failed to schedule an CA update because of an invalid argument.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_INVALID_ARGUMENT = 3273;
+
+  // Error occurred when failed to schedule an CA update because of a pending schedule.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_UPDATE_ALREADY_PENDING_ERROR = 3274;
+
+  // Error occurred when failed to schedule an CA update because of an unexpected error.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_INTERNAL_ERROR = 3275;
+
+  // Error occurred when failed to schedule an CA update when fail to notify failure to the caller.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_TO_CALLER_FAILED = 3276;
+
   // UX errors: 4001-5000
   CONSENT_REVOKED_ERROR = 4001;
 
diff --git a/stats/enums/adservices/common/adservices_enums.proto b/stats/enums/adservices/common/adservices_enums.proto
index 20243137..b31de9c9 100644
--- a/stats/enums/adservices/common/adservices_enums.proto
+++ b/stats/enums/adservices/common/adservices_enums.proto
@@ -91,6 +91,18 @@ enum PpapiName {
   GET_AD_SELECTION_DATA = 12;
   // Represents PersistAdSelectionResult API of B&A.
   PERSIST_AD_SELECTION_RESULT = 13;
+  // Represents reportImpression API of B&A
+  REPORT_IMPRESSION = 14;
+  // Represents reportInteraction API of B&A
+  REPORT_INTERACTION = 15;
+  // Represents joinCustomAudience API of FLEDGE.
+  JOIN_CUSTOM_AUDIENCE = 16;
+  // Represents leaveCustomAudience API of FLEDGE.
+  LEAVE_CUSTOM_AUDIENCE = 17;
+  // Represents fetchAndJoinCustomAudience API of FLEDGE.
+  FETCH_AND_JOIN_CUSTOM_AUDIENCE = 18;
+  // Represents scheduleCustomAudienceUpdate API of FLEDGE.
+  SCHEDULE_CUSTOM_AUDIENCE_UPDATE = 19;
 }
 
 /**
@@ -247,6 +259,9 @@ enum Command {
   reserved 301;
   COMMAND_APP_SIGNALS_GENERATE_INPUT_FOR_ENCODING = 302;
   COMMAND_APP_SIGNALS_TRIGGER_ENCODING = 303;
+
+  // Attribution-reporting commands: 401-500
+  COMMAND_ATTRIBUTION_REPORTING_LIST_SOURCE_REGISTRATIONS = 401;
 }
 
 // Result of the shell command
diff --git a/stats/enums/adservices/measurement/enums.proto b/stats/enums/adservices/measurement/enums.proto
index 2e1e1451..47806eeb 100644
--- a/stats/enums/adservices/measurement/enums.proto
+++ b/stats/enums/adservices/measurement/enums.proto
@@ -51,6 +51,7 @@ enum Status {
   AGGREGATE_REPORT_GENERATED_SUCCESS_STATUS = 3;
   EVENT_REPORT_GENERATED_SUCCESS_STATUS = 4;
   AGGREGATE_AND_EVENT_REPORTS_GENERATED_SUCCESS_STATUS = 5;
+  NULL_AGGREGATE_REPORT_GENERATED_SUCCESS_STATUS = 6;
 }
 
 /**
diff --git a/stats/enums/app/job/job_enums.proto b/stats/enums/app/job/job_enums.proto
index 518f053e..35401295 100644
--- a/stats/enums/app/job/job_enums.proto
+++ b/stats/enums/app/job/job_enums.proto
@@ -41,6 +41,7 @@ enum InternalStopReasonEnum {
     INTERNAL_STOP_REASON_SUCCESSFUL_FINISH = 10;
     INTERNAL_STOP_REASON_USER_UI_STOP = 11;
     INTERNAL_STOP_REASON_ANR = 12;
+    INTERNAL_STOP_REASON_TIMEOUT_ABANDONED = 13;
 }
 
 // Public stop reasons returned through JobParameters.getStopReason()
@@ -61,4 +62,5 @@ enum StopReasonEnum {
     STOP_REASON_USER = 13;
     STOP_REASON_SYSTEM_PROCESSING = 14;
     STOP_REASON_ESTIMATED_APP_LAUNCH_TIME_CHANGED = 15;
+    STOP_REASON_TIMEOUT_ABANDONED = 16;
 }
diff --git a/stats/enums/app/settings_enums.proto b/stats/enums/app/settings_enums.proto
index 9507f841..00af214f 100644
--- a/stats/enums/app/settings_enums.proto
+++ b/stats/enums/app/settings_enums.proto
@@ -1916,12 +1916,86 @@ enum Action {
     // CATEGORY: SETTINGS
     // OS: V
     ACTION_PRIVATE_SPACE_SETUP_SPACE_ERRORS = 1964;
+
+    // ACTION: Settings > System > Languages > Regional preferences
+    //         > Measurement system > Set the preferred measurement system.
+    // CATEGORY: SETTINGS
+    // OS: W
+    ACTION_SET_MEASUREMENT_SYSTEM = 1965;
+
+    // ACTION: Settings > Connected devices > Bluetooth > Pair new device > failed
+    //         > retry A2DP profile connection
+    //  SUBTYPE: 0 is fail, 1 is success
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BLUETOOTH_PROFILE_CONNECTION_A2DP_RETRY_TRIGGERED = 1966;
+
+    // ACTION: Settings > Connected devices > Bluetooth > Pair new device > failed
+    //         > retry HEADSET profile connection
+    //  SUBTYPE: 0 is fail, 1 is success
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BLUETOOTH_PROFILE_CONNECTION_HEADSET_RETRY_TRIGGERED = 1967;
+
+    // Action: Settings > System > Touchpad & Mouse > Three finger tap
+    // VALUE: boolean
+    // OS: V
+    ACTION_TOUCHPAD_THREE_FINGER_TAP_CUSTOMIZATION_CHANGED = 1968;
+
+    // ACTION: Settings > Connected devices > Bluetooth device details > item shown
+    //  SUBTYPE: 0 is invisible, 1 is visible
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BLUETOOTH_DEVICE_DETAILS_ITEM_SHOWN = 1969;
+
+    // ACTION: Settings > Connected devices > Bluetooth device details > item clicked
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BLUETOOTH_DEVICE_DETAILS_ITEM_CLICKED = 1970;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Toggle On/Off "Sticky keys"
+    // CATEGORY: SETTINGS
+    ACTION_STICKY_KEYS_ENABLED = 1971;
+    ACTION_STICKY_KEYS_DISABLED = 1972;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Toggle On/Off "Bounce keys"
+    // CATEGORY: SETTINGS
+    ACTION_BOUNCE_KEYS_ENABLED = 1973;
+    ACTION_BOUNCE_KEYS_DISABLED = 1974;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Toggle On/Off "Slow keys"
+    // CATEGORY: SETTINGS
+    ACTION_SLOW_KEYS_ENABLED = 1975;
+    ACTION_SLOW_KEYS_DISABLED = 1976;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Toggle On/Off "Mouse keys"
+    // CATEGORY: SETTINGS
+    ACTION_MOUSE_KEYS_ENABLED = 1977;
+    ACTION_MOUSE_KEYS_DISABLED = 1978;
+
+    // ACTION: Settings > Connected devices > Bluetooth device details > turn on LE Audio
+    // CATEGORY: SETTINGS
+    //  SUBTYPE: default connection policy, false is forbidden, true is allowed
+    // OS: V
+    ACTION_BLUETOOTH_PROFILE_LE_AUDIO_ON = 1979;
+
+    // ACTION: Settings > Connected devices > Bluetooth device details > turn off LE Audio
+    // CATEGORY: SETTINGS
+    //  SUBTYPE: default connection policy, false is forbidden, true is allowed
+    // OS: V
+    ACTION_BLUETOOTH_PROFILE_LE_AUDIO_OFF = 1980;
 }
 
 /**
  * Id for Settings pages. Each page must have its own unique Id.
  */
 enum PageId {
+    reserved 2123 to 2130;
+
     // Unknown page. Should not be used in production code.
     PAGE_UNKNOWN = 0;
 
@@ -5147,6 +5221,49 @@ enum PageId {
     // CATEGORY: SETTINGS
     // OS: V
     ACCESSIBILITY_POINTER_COLOR_CUSTOMIZATION = 2115;
+
+    // OPEN: Settings > Connected Devices > Bluetooth > (click on details link for a paired device)
+    //       > More Settings
+    // CATEGORY: SETTINGS
+    // OS: V
+    BLUETOOTH_DEVICE_DETAILS_MORE_SETTINGS = 2116;
+
+    // ACTION: Settings > Apps > Contacts storage > Select an account to set as default contacts account.
+    // CATEGORY: SETTINGS
+    // OS: V
+    CONTACTS_STORAGE = 2117;
+
+    // OPEN: Settings > Developer Options > Enable Linux terminal
+    // CATEGORY: SETTINGS
+    // OS: W
+    LINUX_TERMINAL_DASHBOARD = 2118;
+
+    // OPEN: Settings > System > Language > Regional preferences > Measurement system
+    // CATEGORY: SETTINGS
+    // OS: W
+    MEASUREMENT_SYSTEM_PREFERENCE = 2119;
+
+    // ACTION: Settings > Notifications > Bundle notifications
+    // CATEGORY: SETTINGS
+    // OS: B
+    BUNDLED_NOTIFICATIONS = 2120;
+
+    // Settings -> Keyboard -> Mouse
+    // CATEGORY: SETTINGS
+    SETTINGS_KEYBOARD_MOUSE = 2121;
+
+    // Settings -> Keyboard -> Physical keyboard -> Physical Keyboard accessibility -> Mouse Keys
+    // CATEGORY: SETTINGS
+    SETTINGS_PHYSICAL_KEYBOARD_MOUSE_KEYS = 2122;
+
+    // OPEN: Settings > System -> Touchpad
+    // CATEGORY: SETTINGS
+    // OS: V
+    TOUCHPAD_THREE_FINGER_TAP = 2131;
+
+    // OPEN: Settings > Notifications > Notifications on lock screen
+    // CATEGORY: SETTINGS
+    SETTINGS_NOTIFICATIONS_ON_LOCK_SCREEN = 2132;
 }
 
 // Battery Saver schedule types.
diff --git a/stats/enums/app/tvsettings_enums.proto b/stats/enums/app/tvsettings_enums.proto
index 91071fa1..8460b457 100644
--- a/stats/enums/app/tvsettings_enums.proto
+++ b/stats/enums/app/tvsettings_enums.proto
@@ -1061,24 +1061,66 @@ enum ItemId {
     // TvSettings > System > Accessibility > Color Correction > Grayscale
     SYSTEM_A11Y_COLOR_CORRECTION_GRAYSCALE = 0x178C5000;
 
-    // TvSettings > System > Accessibility > Time to take action
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action
     SYSTEM_A11Y_TIMEOUT = 0x178D0000;
 
-    // TvSettings > System > Accessibility > Time to take action > Default
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action > Default
     SYSTEM_A11Y_TIMEOUT_DEFAULT = 0x178D1000;
 
-    // TvSettings > System > Accessibility > Time to take action > 10 seconds
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action > 10 seconds
     SYSTEM_A11Y_TIMEOUT_TEN_SECONDS = 0x178D2000;
 
-    // TvSettings > System > Accessibility > Time to take action > 30 seconds
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action > 30 seconds
     SYSTEM_A11Y_TIMEOUT_THIRTY_SECONDS = 0x178D3000;
 
-    // TvSettings > System > Accessibility > Time to take action > 1 minute
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action > 1 minute
     SYSTEM_A11Y_TIMEOUT_ONE_MINUTE = 0x178D4000;
 
-    // TvSettings > System > Accessibility > Time to take action > 2 minute
+    // TvSettings > System > Accessibility > Keyboard accessibility > Time to take action > 2 minute
     SYSTEM_A11Y_TIMEOUT_TWO_MINUTE = 0x178D5000;
 
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay
+    SYSTEM_A11Y_KEY_REPEAT = 0x178E0000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Delay before repeat
+    SYSTEM_A11Y_KEY_REPEAT_DELAY = 0x178E1000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Delay before repeat > Default
+    SYSTEM_A11Y_KEY_REPEAT_DELAY_DEFAULT = 0x178E1100;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Delay before repeat > 3 seconds
+    SYSTEM_A11Y_KEY_REPEAT_DELAY_THREE_SECONDS = 0x178E1200;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Delay before repeat > 5 seconds
+    SYSTEM_A11Y_KEY_REPEAT_DELAY_FIVE_SECONDS = 0x178E1300;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Repeat rate
+    SYSTEM_A11Y_KEY_REPEAT_RATE = 0x178E2000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Repeat rate > Default
+    SYSTEM_A11Y_KEY_REPEAT_RATE_DEFAULT = 0x178E2100;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Repeat rate > Slow
+    SYSTEM_A11Y_KEY_REPEAT_RATE_SLOW = 0x178E2200;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Key repeat delay > Repeat rate > Fast
+    SYSTEM_A11Y_KEY_REPEAT_RATE_FAST = 0x178E2300;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Bounce keys
+    SYSTEM_A11Y_BOUNCE_KEYS = 0x178F0000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Bounce keys > OFF
+    SYSTEM_A11Y_BOUNCE_KEYS_OFF = 0x178F1000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Bounce keys > ON > 0.5 seconds
+    SYSTEM_A11Y_BOUNCE_KEYS_HALF_SECONDS = 0x178F2000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Bounce keys > ON > 1 second
+    SYSTEM_A11Y_BOUNCE_KEYS_ONE_SECONDS = 0x178F3000;
+
+    // TvSettings > System > Accessibility > Keyboard accessibility > Bounce keys > ON > 2 second
+    SYSTEM_A11Y_BOUNCE_KEYS_TWO_SECONDS = 0x178F4000;
+
     // TvSettings > System > Reboot
     SYSTEM_REBOOT = 0x17900000;
 
diff --git a/stats/enums/app/wearservices/OWNERS b/stats/enums/app/wearservices/OWNERS
new file mode 100644
index 00000000..3b4b182f
--- /dev/null
+++ b/stats/enums/app/wearservices/OWNERS
@@ -0,0 +1,8 @@
+shijianli@google.com
+krskad@google.com
+xjchen@google.com
+yashasvig@google.com
+bmaulana@google.com
+sichu@google.com
+anubhakushwaha@google.com
+emmajames@google.com
diff --git a/stats/enums/app/wearservices/wearservices_enums.proto b/stats/enums/app/wearservices/wearservices_enums.proto
index fe1a59a4..e69494e8 100644
--- a/stats/enums/app/wearservices/wearservices_enums.proto
+++ b/stats/enums/app/wearservices/wearservices_enums.proto
@@ -259,7 +259,7 @@ enum NotificationGroupType {
 }
 
 // The style of the notification.
-// Next ID: 7
+// Next ID: 9
 enum NotificationStyle {
   // Unknown value.
   NOTIFICATION_STYLE_UNKNOWN = 0;
@@ -267,6 +267,9 @@ enum NotificationStyle {
   // The notification has not specific any style.
   NOTIFICATION_STYLE_UNSPECIFIED = 1;
 
+  // All other notification styles not listed by this enum.
+  NOTIFICATION_STYLE_OTHER = 8;
+
   // The notification is InboxStyle.
   NOTIFICATION_STYLE_INBOX = 2;
 
@@ -281,6 +284,9 @@ enum NotificationStyle {
 
   // The notification is MediaStyle.
   NOTIFICATION_STYLE_MEDIA = 6;
+
+  // The notification is ProgressStyle.
+  NOTIFICATION_STYLE_PROGRESS = 7;
 }
 
 // The categories for the notification.
@@ -554,7 +560,7 @@ enum NotificationActionType {
 }
 
 // Defines the notification flow component for which the latency is to be calculated.
-// Next ID: 3
+// Next ID: 4
 enum NotificationFlowComponent {
   // Unknown value.
   NOTIFICATION_FLOW_COMPONENT_UNKNOWN = 0;
@@ -564,10 +570,13 @@ enum NotificationFlowComponent {
 
   // Notification flow representing flow when a notification is dismissed.
   NOTIFICATION_FLOW_COMPONENT_DISMISS_NOTIFICATION = 2;
+
+  // Notification flow representing flow when an action was executed.
+  NOTIFICATION_FLOW_COMPONENT_ACTION_EXECUTION = 3;
 }
 
 // Defines which component the latency is being calculated for.
-// Next ID: 4
+// Next ID: 7
 enum ComponentName {
   // Unknown value.
   COMPONENT_NAME_UNKNOWN = 0;
@@ -580,6 +589,15 @@ enum ComponentName {
 
   // The component is SysUI.
   COMPONENT_NAME_SYSUI = 3;
+
+  // The component is Framework.
+  COMPONENT_NAME_FRAMEWORK = 4;
+
+  // Components in one way RPC transfer.
+  COMPONENT_NAME_TRANSFER_ONE_WAY = 5;
+
+  // Components in a roundtrip RPC transfer.
+  COMPONENT_NAME_TRANSFER_ROUNDTRIP = 6;
 }
 
 // This enum depicts an action taken on a call
@@ -819,8 +837,54 @@ enum RemoteEventType {
   EVENT_TYPE_LOCALE_SETTINGS_DEEPLINK = 7;
 }
 
+// This enum depicts the state of the remote event.
+// Next ID: 13
+enum RemoteEventState {
+  // Depicts an unknown remote event state.
+  REMOTE_EVENT_STATE_UNKNOWN = 0;
+
+  // Depicts total number of times remote event API is invoked.
+  REMOTE_EVENT_API_INVOKED = 1;
+
+  // Depicts a successful remote event response.
+  REMOTE_EVENT_RESPONSE_SUCCESS = 2;
+
+  // Remote event with generic failure condition response which doesn't fail into any other
+  // condition.
+  REMOTE_EVENT_RESPONSE_FAILURE = 3;
+
+  // Remote event with failure response caused by caused by exceeding max message size.
+  REMOTE_EVENT_RESPONSE_MAX_SIZE_EXCEEDED = 4;
+
+  // Remote event with response caused by WearServices not being able to communicate with
+  // the Companion.
+  REMOTE_EVENT_RESPONSE_REMOTE_NOT_REACHABLE = 5;
+
+  // Remote event with response not being received within the timeout period.
+  REMOTE_EVENT_RESPONSE_TIMEOUT = 6;
+
+  // Remote event with response caused by a caller not having necessary permissions or signature
+  // to trigger this remote event.
+  REMOTE_EVENT_RESPONSE_SECURITY_EXCEPTION = 7;
+
+  // The RemoteEvent triggered by the caller is not recognized/supported by the Companion.
+  REMOTE_EVENT_RESPONSE_INVALID_REMOTE_EVENT_TYPE = 8;
+
+  // Failure when trying to execute the RemoteEvent on the phone.
+  REMOTE_EVENT_RESPONSE_REMOTE_EXECUTION_EXCEPTION = 9;
+
+  // Calling app exceeded the maximum number of allowed triggers for this remote event type.
+  REMOTE_EVENT_RESPONSE_MAX_REMOTE_EVENT_TRIGGERS_EXCEEDED = 10;
+
+  // Companion failed to deserialize the RemoteEvent object.
+  REMOTE_EVENT_RESPONSE_DESERIALIZATION_EXCEPTION = 11;
+
+  // Remote event with no connected Companion supports RemoteEvents response.
+  REMOTE_EVENT_RESPONSE_REMOTE_NOT_SUPPORTED = 12;
+}
+
 // This enum depicts different components of the bugreport flow
-// Next ID: 3
+// Next ID: 5
 enum BugreportComponent {
   // Depicts an unknown component
   BUGREPORT_COMPONENT_UNKNOWN = 0;
@@ -830,10 +894,16 @@ enum BugreportComponent {
 
   // Depicts the watch UI
   BUGREPORT_COMPONENT_WATCH_UI = 2;
+
+  // Depicts when the component is not set
+  BUGREPORT_COMPONENT_UNSET = 3;
+
+  // Atoms created by WCS auto upload feature
+  BUGREPORT_COMPONENT_WCS_AUTO_UPLOAD = 4;
 }
 
 // This enum depicts the result of the bugreport
-// Next ID: 3
+// Next ID: 4
 enum BugreportResult {
   // Depicts an unknown bugreport result
   BUGREPORT_RESULT_UNKNOWN = 0;
@@ -843,4 +913,17 @@ enum BugreportResult {
 
   // Depicts a failure bugreport result
   BUGREPORT_RESULT_FAILURE = 2;
+
+  // Depicts an empty bugreport result
+  BUGREPORT_RESULT_UNSET = 3;
+}
+
+// This enum depicts a bugreport event
+// Next ID: 5
+enum BugreportEvent {
+  EVENT_BUGREPORT_UNKNOWN = 0;
+  EVENT_BUGREPORT_REQUESTED = 1;
+  EVENT_BUGREPORT_TRIGGERED = 2;
+  EVENT_BUGREPORT_FINISHED = 3;
+  EVENT_BUGREPORT_RESULT_RECEIVED = 4;
 }
diff --git a/stats/enums/app/wearsettings_enums.proto b/stats/enums/app/wearsettings_enums.proto
index c412eab5..1bd14a60 100644
--- a/stats/enums/app/wearsettings_enums.proto
+++ b/stats/enums/app/wearsettings_enums.proto
@@ -36,7 +36,7 @@ enum Action {
 }
 
 // IDs for settings UI elements.
-// Next ID: 525
+// Next ID: 528
 enum ItemId {
   // An unknown settings item. This may be set if no preference key is mapped to an enum value or as
   // a catch-all for values not yet added to this proto file.
@@ -104,6 +104,7 @@ enum ItemId {
   AUDIO_BALANCE_LEFT_RIGHT_TEXT = 411;
   BATTERY_SAVER_AUTO_BATTERY_SAVER_ENABLED = 324;
   BATTERY_SAVER_BATTERY_SAVER = 315;
+  BLUETOOTH_DEVICE_TYPE = 527;
   BLUETOOTH_ENABLED = 135;
   BLUETOOTH_HFP = 136;
   BLUETOOTH_HFP_EXPLANATION = 404;
@@ -167,6 +168,7 @@ enum ItemId {
   CONNECTIVITY_UWB = 499;
   DATE_TIME_AUTO_DATE_TIME = 129;
   DATE_TIME_AUTO_TIME_ZONE = 130;
+  DATE_TIME_LOCATION_TIME_ZONE_DETECTION = 525;
   DATE_TIME_HOUR_FORMAT = 198;
   DATE_TIME_MANUAL_DATE = 211;
   DATE_TIME_MANUAL_TIME = 212;
@@ -212,6 +214,7 @@ enum ItemId {
   DEVICE_VERSION_BUILD = 140;
   DISPLAY_ALWAYS_ON_SCREEN = 126;
   DISPLAY_BRIGHTNESS = 287;
+  DISPLAY_COLOR_THEME = 526;
   DISPLAY_FONT_SIZE = 289;
   DISPLAY_MANUAL_BRIGHTNESS_SLIDER = 380;
   // Item for high brightness-mode/sunlight boost
@@ -425,4 +428,5 @@ enum ItemId {
   PRIVACY_DASHBOARD = 495;
   SOUND_NOTIFICATION_VOLUME = 508;
   SOUND_RING_AND_NOTIFICATIONS_VOLUME = 509;
+  FORCE_GLOBAL_AMBIACTIVE = 600;
 }
diff --git a/stats/enums/app_shared/OWNERS b/stats/enums/app_shared/OWNERS
new file mode 100644
index 00000000..aeab36a5
--- /dev/null
+++ b/stats/enums/app_shared/OWNERS
@@ -0,0 +1 @@
+per-file app_op_enums.proto = file:platform/frameworks/base:/core/java/android/permission/OWNERS
diff --git a/stats/enums/app_shared/app_enums.proto b/stats/enums/app_shared/app_enums.proto
index 87160e78..732b0f04 100644
--- a/stats/enums/app_shared/app_enums.proto
+++ b/stats/enums/app_shared/app_enums.proto
@@ -134,160 +134,6 @@ enum OomChangeReasonEnum {
     OOM_ADJ_REASON_FOLLOW_UP = 23;
 }
 
-// AppOpsManager.java - operation ids for logging
-enum AppOpEnum {
-    APP_OP_NONE = -1;
-    APP_OP_COARSE_LOCATION = 0;
-    APP_OP_FINE_LOCATION = 1;
-    APP_OP_GPS = 2;
-    APP_OP_VIBRATE = 3;
-    APP_OP_READ_CONTACTS = 4;
-    APP_OP_WRITE_CONTACTS = 5;
-    APP_OP_READ_CALL_LOG = 6;
-    APP_OP_WRITE_CALL_LOG = 7;
-    APP_OP_READ_CALENDAR = 8;
-    APP_OP_WRITE_CALENDAR = 9;
-    APP_OP_WIFI_SCAN = 10;
-    APP_OP_POST_NOTIFICATION = 11;
-    APP_OP_NEIGHBORING_CELLS = 12;
-    APP_OP_CALL_PHONE = 13;
-    APP_OP_READ_SMS = 14;
-    APP_OP_WRITE_SMS = 15;
-    APP_OP_RECEIVE_SMS = 16;
-    APP_OP_RECEIVE_EMERGENCY_SMS = 17;
-    APP_OP_RECEIVE_MMS = 18;
-    APP_OP_RECEIVE_WAP_PUSH = 19;
-    APP_OP_SEND_SMS = 20;
-    APP_OP_READ_ICC_SMS = 21;
-    APP_OP_WRITE_ICC_SMS = 22;
-    APP_OP_WRITE_SETTINGS = 23;
-    APP_OP_SYSTEM_ALERT_WINDOW = 24;
-    APP_OP_ACCESS_NOTIFICATIONS = 25;
-    APP_OP_CAMERA = 26;
-    APP_OP_RECORD_AUDIO = 27;
-    APP_OP_PLAY_AUDIO = 28;
-    APP_OP_READ_CLIPBOARD = 29;
-    APP_OP_WRITE_CLIPBOARD = 30;
-    APP_OP_TAKE_MEDIA_BUTTONS = 31;
-    APP_OP_TAKE_AUDIO_FOCUS = 32;
-    APP_OP_AUDIO_MASTER_VOLUME = 33;
-    APP_OP_AUDIO_VOICE_VOLUME = 34;
-    APP_OP_AUDIO_RING_VOLUME = 35;
-    APP_OP_AUDIO_MEDIA_VOLUME = 36;
-    APP_OP_AUDIO_ALARM_VOLUME = 37;
-    APP_OP_AUDIO_NOTIFICATION_VOLUME = 38;
-    APP_OP_AUDIO_BLUETOOTH_VOLUME = 39;
-    APP_OP_WAKE_LOCK = 40;
-    APP_OP_MONITOR_LOCATION = 41;
-    APP_OP_MONITOR_HIGH_POWER_LOCATION = 42;
-    APP_OP_GET_USAGE_STATS = 43;
-    APP_OP_MUTE_MICROPHONE = 44;
-    APP_OP_TOAST_WINDOW = 45;
-    APP_OP_PROJECT_MEDIA = 46;
-    APP_OP_ACTIVATE_VPN = 47;
-    APP_OP_WRITE_WALLPAPER = 48;
-    APP_OP_ASSIST_STRUCTURE = 49;
-    APP_OP_ASSIST_SCREENSHOT = 50;
-    APP_OP_READ_PHONE_STATE = 51;
-    APP_OP_ADD_VOICEMAIL = 52;
-    APP_OP_USE_SIP = 53;
-    APP_OP_PROCESS_OUTGOING_CALLS = 54;
-    APP_OP_USE_FINGERPRINT = 55;
-    APP_OP_BODY_SENSORS = 56;
-    APP_OP_READ_CELL_BROADCASTS = 57;
-    APP_OP_MOCK_LOCATION = 58;
-    APP_OP_READ_EXTERNAL_STORAGE = 59;
-    APP_OP_WRITE_EXTERNAL_STORAGE = 60;
-    APP_OP_TURN_SCREEN_ON = 61;
-    APP_OP_GET_ACCOUNTS = 62;
-    APP_OP_RUN_IN_BACKGROUND = 63;
-    APP_OP_AUDIO_ACCESSIBILITY_VOLUME = 64;
-    APP_OP_READ_PHONE_NUMBERS = 65;
-    APP_OP_REQUEST_INSTALL_PACKAGES = 66;
-    APP_OP_PICTURE_IN_PICTURE = 67;
-    APP_OP_INSTANT_APP_START_FOREGROUND = 68;
-    APP_OP_ANSWER_PHONE_CALLS = 69;
-    APP_OP_RUN_ANY_IN_BACKGROUND = 70;
-    APP_OP_CHANGE_WIFI_STATE = 71;
-    APP_OP_REQUEST_DELETE_PACKAGES = 72;
-    APP_OP_BIND_ACCESSIBILITY_SERVICE = 73;
-    APP_OP_ACCEPT_HANDOVER = 74;
-    APP_OP_MANAGE_IPSEC_TUNNELS = 75;
-    APP_OP_START_FOREGROUND = 76;
-    APP_OP_BLUETOOTH_SCAN = 77;
-    APP_OP_USE_BIOMETRIC = 78;
-    APP_OP_ACTIVITY_RECOGNITION = 79;
-    APP_OP_SMS_FINANCIAL_TRANSACTIONS = 80;
-    APP_OP_READ_MEDIA_AUDIO = 81;
-    APP_OP_WRITE_MEDIA_AUDIO = 82;
-    APP_OP_READ_MEDIA_VIDEO = 83;
-    APP_OP_WRITE_MEDIA_VIDEO = 84;
-    APP_OP_READ_MEDIA_IMAGES = 85;
-    APP_OP_WRITE_MEDIA_IMAGES = 86;
-    APP_OP_LEGACY_STORAGE = 87;
-    APP_OP_ACCESS_ACCESSIBILITY = 88;
-    APP_OP_READ_DEVICE_IDENTIFIERS = 89;
-    APP_OP_ACCESS_MEDIA_LOCATION = 90;
-    APP_OP_QUERY_ALL_PACKAGES = 91;
-    APP_OP_MANAGE_EXTERNAL_STORAGE = 92;
-    APP_OP_INTERACT_ACROSS_PROFILES = 93;
-    APP_OP_ACTIVATE_PLATFORM_VPN = 94;
-    APP_OP_LOADER_USAGE_STATS = 95;
-    APP_OP_DEPRECATED_1 = 96 [deprecated = true];
-    APP_OP_AUTO_REVOKE_PERMISSIONS_IF_UNUSED = 97;
-    APP_OP_AUTO_REVOKE_MANAGED_BY_INSTALLER = 98;
-    APP_OP_NO_ISOLATED_STORAGE = 99;
-    APP_OP_PHONE_CALL_MICROPHONE = 100;
-    APP_OP_PHONE_CALL_CAMERA = 101;
-    APP_OP_RECORD_AUDIO_HOTWORD = 102;
-    APP_OP_MANAGE_ONGOING_CALLS = 103;
-    APP_OP_MANAGE_CREDENTIALS = 104;
-    APP_OP_USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER = 105;
-    APP_OP_RECORD_AUDIO_OUTPUT = 106;
-    APP_OP_SCHEDULE_EXACT_ALARM = 107;
-    APP_OP_FINE_LOCATION_SOURCE = 108;
-    APP_OP_COARSE_LOCATION_SOURCE = 109;
-    APP_OP_MANAGE_MEDIA = 110;
-    APP_OP_BLUETOOTH_CONNECT = 111;
-    APP_OP_UWB_RANGING = 112;
-    APP_OP_ACTIVITY_RECOGNITION_SOURCE = 113;
-    APP_OP_BLUETOOTH_ADVERTISE = 114;
-    APP_OP_RECORD_INCOMING_PHONE_AUDIO = 115;
-    APP_OP_NEARBY_WIFI_DEVICES = 116;
-    APP_OP_ESTABLISH_VPN_SERVICE = 117;
-    APP_OP_ESTABLISH_VPN_MANAGER = 118;
-    APP_OP_ACCESS_RESTRICTED_SETTINGS = 119;
-    APP_OP_RECEIVE_AMBIENT_TRIGGER_AUDIO = 120;
-    APP_OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO = 121;
-    APP_OP_RUN_USER_INITIATED_JOBS = 122;
-    APP_OP_READ_MEDIA_VISUAL_USER_SELECTED = 123;
-    APP_OP_SYSTEM_EXEMPT_FROM_SUSPENSION = 124;
-    APP_OP_SYSTEM_EXEMPT_FROM_DISMISSIBLE_NOTIFICATIONS = 125;
-    APP_OP_READ_WRITE_HEALTH_DATA = 126;
-    APP_OP_FOREGROUND_SERVICE_SPECIAL_USE = 127;
-    APP_OP_SYSTEM_EXEMPT_FROM_POWER_RESTRICTIONS = 128;
-    APP_OP_SYSTEM_EXEMPT_FROM_HIBERNATION = 129;
-    APP_OP_SYSTEM_EXEMPT_FROM_ACTIVITY_BG_START_RESTRICTION = 130;
-    APP_OP_CAPTURE_CONSENTLESS_BUGREPORT_ON_USERDEBUG_BUILD = 131;
-    APP_OP_BODY_SENSORS_WRIST_TEMPERATURE = 132 [deprecated = true];
-    APP_OP_USE_FULL_SCREEN_INTENT = 133;
-    APP_OP_CAMERA_SANDBOXED = 134;
-    APP_OP_RECORD_AUDIO_SANDBOXED = 135;
-    APP_OP_RECEIVE_SANDBOX_TRIGGER_AUDIO = 136;
-    APP_OP_RECEIVE_SANDBOXED_DETECTION_TRAINING_DATA = 137 [deprecated = true];
-    APP_OP_CREATE_ACCESSIBILITY_OVERLAY = 138;
-    APP_OP_MEDIA_ROUTING_CONTROL = 139;
-    APP_OP_ENABLE_MOBILE_DATA_BY_USER = 140;
-    APP_OP_RESERVED_FOR_TESTING = 141;
-    APP_OP_RAPID_CLEAR_NOTIFICATIONS_BY_LISTENER = 142;
-    APP_OP_READ_SYSTEM_GRAMMATICAL_GENDER = 143;
-    APP_OP_RUN_BACKUP_JOBS = 144 [deprecated = true];
-    APP_OP_ARCHIVE_ICON_OVERLAY = 145;
-    APP_OP_UNARCHIVAL_CONFIRMATION = 146;
-    APP_OP_EMERGENCY_LOCATION = 147;
-    APP_OP_RECEIVE_SENSITIVE_NOTIFICATIONS = 148;
-}
-
 /**
  * The reason code that why app process is killed.
  */
diff --git a/stats/enums/app_shared/app_op_enums.proto b/stats/enums/app_shared/app_op_enums.proto
new file mode 100644
index 00000000..117a681a
--- /dev/null
+++ b/stats/enums/app_shared/app_op_enums.proto
@@ -0,0 +1,183 @@
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
+syntax = "proto2";
+
+package android.app;
+
+option java_outer_classname = "AppOpEnums";
+option java_multiple_files = true;
+
+// AppOpsManager.java - operation ids for logging
+enum AppOpEnum {
+    APP_OP_NONE = -1;
+    APP_OP_COARSE_LOCATION = 0;
+    APP_OP_FINE_LOCATION = 1;
+    APP_OP_GPS = 2;
+    APP_OP_VIBRATE = 3;
+    APP_OP_READ_CONTACTS = 4;
+    APP_OP_WRITE_CONTACTS = 5;
+    APP_OP_READ_CALL_LOG = 6;
+    APP_OP_WRITE_CALL_LOG = 7;
+    APP_OP_READ_CALENDAR = 8;
+    APP_OP_WRITE_CALENDAR = 9;
+    APP_OP_WIFI_SCAN = 10;
+    APP_OP_POST_NOTIFICATION = 11;
+    APP_OP_NEIGHBORING_CELLS = 12;
+    APP_OP_CALL_PHONE = 13;
+    APP_OP_READ_SMS = 14;
+    APP_OP_WRITE_SMS = 15;
+    APP_OP_RECEIVE_SMS = 16;
+    APP_OP_RECEIVE_EMERGENCY_SMS = 17;
+    APP_OP_RECEIVE_MMS = 18;
+    APP_OP_RECEIVE_WAP_PUSH = 19;
+    APP_OP_SEND_SMS = 20;
+    APP_OP_READ_ICC_SMS = 21;
+    APP_OP_WRITE_ICC_SMS = 22;
+    APP_OP_WRITE_SETTINGS = 23;
+    APP_OP_SYSTEM_ALERT_WINDOW = 24;
+    APP_OP_ACCESS_NOTIFICATIONS = 25;
+    APP_OP_CAMERA = 26;
+    APP_OP_RECORD_AUDIO = 27;
+    APP_OP_PLAY_AUDIO = 28;
+    APP_OP_READ_CLIPBOARD = 29;
+    APP_OP_WRITE_CLIPBOARD = 30;
+    APP_OP_TAKE_MEDIA_BUTTONS = 31;
+    APP_OP_TAKE_AUDIO_FOCUS = 32;
+    APP_OP_AUDIO_MASTER_VOLUME = 33;
+    APP_OP_AUDIO_VOICE_VOLUME = 34;
+    APP_OP_AUDIO_RING_VOLUME = 35;
+    APP_OP_AUDIO_MEDIA_VOLUME = 36;
+    APP_OP_AUDIO_ALARM_VOLUME = 37;
+    APP_OP_AUDIO_NOTIFICATION_VOLUME = 38;
+    APP_OP_AUDIO_BLUETOOTH_VOLUME = 39;
+    APP_OP_WAKE_LOCK = 40;
+    APP_OP_MONITOR_LOCATION = 41;
+    APP_OP_MONITOR_HIGH_POWER_LOCATION = 42;
+    APP_OP_GET_USAGE_STATS = 43;
+    APP_OP_MUTE_MICROPHONE = 44;
+    APP_OP_TOAST_WINDOW = 45;
+    APP_OP_PROJECT_MEDIA = 46;
+    APP_OP_ACTIVATE_VPN = 47;
+    APP_OP_WRITE_WALLPAPER = 48;
+    APP_OP_ASSIST_STRUCTURE = 49;
+    APP_OP_ASSIST_SCREENSHOT = 50;
+    APP_OP_READ_PHONE_STATE = 51;
+    APP_OP_ADD_VOICEMAIL = 52;
+    APP_OP_USE_SIP = 53;
+    APP_OP_PROCESS_OUTGOING_CALLS = 54;
+    APP_OP_USE_FINGERPRINT = 55;
+    APP_OP_BODY_SENSORS = 56;
+    APP_OP_READ_CELL_BROADCASTS = 57;
+    APP_OP_MOCK_LOCATION = 58;
+    APP_OP_READ_EXTERNAL_STORAGE = 59;
+    APP_OP_WRITE_EXTERNAL_STORAGE = 60;
+    APP_OP_TURN_SCREEN_ON = 61;
+    APP_OP_GET_ACCOUNTS = 62;
+    APP_OP_RUN_IN_BACKGROUND = 63;
+    APP_OP_AUDIO_ACCESSIBILITY_VOLUME = 64;
+    APP_OP_READ_PHONE_NUMBERS = 65;
+    APP_OP_REQUEST_INSTALL_PACKAGES = 66;
+    APP_OP_PICTURE_IN_PICTURE = 67;
+    APP_OP_INSTANT_APP_START_FOREGROUND = 68;
+    APP_OP_ANSWER_PHONE_CALLS = 69;
+    APP_OP_RUN_ANY_IN_BACKGROUND = 70;
+    APP_OP_CHANGE_WIFI_STATE = 71;
+    APP_OP_REQUEST_DELETE_PACKAGES = 72;
+    APP_OP_BIND_ACCESSIBILITY_SERVICE = 73;
+    APP_OP_ACCEPT_HANDOVER = 74;
+    APP_OP_MANAGE_IPSEC_TUNNELS = 75;
+    APP_OP_START_FOREGROUND = 76;
+    APP_OP_BLUETOOTH_SCAN = 77;
+    APP_OP_USE_BIOMETRIC = 78;
+    APP_OP_ACTIVITY_RECOGNITION = 79;
+    APP_OP_SMS_FINANCIAL_TRANSACTIONS = 80;
+    APP_OP_READ_MEDIA_AUDIO = 81;
+    APP_OP_WRITE_MEDIA_AUDIO = 82;
+    APP_OP_READ_MEDIA_VIDEO = 83;
+    APP_OP_WRITE_MEDIA_VIDEO = 84;
+    APP_OP_READ_MEDIA_IMAGES = 85;
+    APP_OP_WRITE_MEDIA_IMAGES = 86;
+    APP_OP_LEGACY_STORAGE = 87;
+    APP_OP_ACCESS_ACCESSIBILITY = 88;
+    APP_OP_READ_DEVICE_IDENTIFIERS = 89;
+    APP_OP_ACCESS_MEDIA_LOCATION = 90;
+    APP_OP_QUERY_ALL_PACKAGES = 91;
+    APP_OP_MANAGE_EXTERNAL_STORAGE = 92;
+    APP_OP_INTERACT_ACROSS_PROFILES = 93;
+    APP_OP_ACTIVATE_PLATFORM_VPN = 94;
+    APP_OP_LOADER_USAGE_STATS = 95;
+    APP_OP_DEPRECATED_1 = 96 [deprecated = true];
+    APP_OP_AUTO_REVOKE_PERMISSIONS_IF_UNUSED = 97;
+    APP_OP_AUTO_REVOKE_MANAGED_BY_INSTALLER = 98;
+    APP_OP_NO_ISOLATED_STORAGE = 99;
+    APP_OP_PHONE_CALL_MICROPHONE = 100;
+    APP_OP_PHONE_CALL_CAMERA = 101;
+    APP_OP_RECORD_AUDIO_HOTWORD = 102;
+    APP_OP_MANAGE_ONGOING_CALLS = 103;
+    APP_OP_MANAGE_CREDENTIALS = 104;
+    APP_OP_USE_ICC_AUTH_WITH_DEVICE_IDENTIFIER = 105;
+    APP_OP_RECORD_AUDIO_OUTPUT = 106;
+    APP_OP_SCHEDULE_EXACT_ALARM = 107;
+    APP_OP_FINE_LOCATION_SOURCE = 108;
+    APP_OP_COARSE_LOCATION_SOURCE = 109;
+    APP_OP_MANAGE_MEDIA = 110;
+    APP_OP_BLUETOOTH_CONNECT = 111;
+    APP_OP_UWB_RANGING = 112;
+    APP_OP_ACTIVITY_RECOGNITION_SOURCE = 113;
+    APP_OP_BLUETOOTH_ADVERTISE = 114;
+    APP_OP_RECORD_INCOMING_PHONE_AUDIO = 115;
+    APP_OP_NEARBY_WIFI_DEVICES = 116;
+    APP_OP_ESTABLISH_VPN_SERVICE = 117;
+    APP_OP_ESTABLISH_VPN_MANAGER = 118;
+    APP_OP_ACCESS_RESTRICTED_SETTINGS = 119;
+    APP_OP_RECEIVE_AMBIENT_TRIGGER_AUDIO = 120;
+    APP_OP_RECEIVE_EXPLICIT_USER_INTERACTION_AUDIO = 121;
+    APP_OP_RUN_USER_INITIATED_JOBS = 122;
+    APP_OP_READ_MEDIA_VISUAL_USER_SELECTED = 123;
+    APP_OP_SYSTEM_EXEMPT_FROM_SUSPENSION = 124;
+    APP_OP_SYSTEM_EXEMPT_FROM_DISMISSIBLE_NOTIFICATIONS = 125;
+    APP_OP_READ_WRITE_HEALTH_DATA = 126;
+    APP_OP_FOREGROUND_SERVICE_SPECIAL_USE = 127;
+    APP_OP_SYSTEM_EXEMPT_FROM_POWER_RESTRICTIONS = 128;
+    APP_OP_SYSTEM_EXEMPT_FROM_HIBERNATION = 129;
+    APP_OP_SYSTEM_EXEMPT_FROM_ACTIVITY_BG_START_RESTRICTION = 130;
+    APP_OP_CAPTURE_CONSENTLESS_BUGREPORT_ON_USERDEBUG_BUILD = 131;
+    APP_OP_BODY_SENSORS_WRIST_TEMPERATURE = 132 [deprecated = true];
+    APP_OP_USE_FULL_SCREEN_INTENT = 133;
+    APP_OP_CAMERA_SANDBOXED = 134;
+    APP_OP_RECORD_AUDIO_SANDBOXED = 135;
+    APP_OP_RECEIVE_SANDBOX_TRIGGER_AUDIO = 136;
+    APP_OP_RECEIVE_SANDBOXED_DETECTION_TRAINING_DATA = 137 [deprecated = true];
+    APP_OP_CREATE_ACCESSIBILITY_OVERLAY = 138;
+    APP_OP_MEDIA_ROUTING_CONTROL = 139;
+    APP_OP_ENABLE_MOBILE_DATA_BY_USER = 140;
+    APP_OP_RESERVED_FOR_TESTING = 141;
+    APP_OP_RAPID_CLEAR_NOTIFICATIONS_BY_LISTENER = 142;
+    APP_OP_READ_SYSTEM_GRAMMATICAL_GENDER = 143;
+    APP_OP_RUN_BACKUP_JOBS = 144 [deprecated = true];
+    APP_OP_ARCHIVE_ICON_OVERLAY = 145;
+    APP_OP_UNARCHIVAL_CONFIRMATION = 146;
+    APP_OP_EMERGENCY_LOCATION = 147;
+    APP_OP_RECEIVE_SENSITIVE_NOTIFICATIONS = 148;
+    APP_OP_READ_HEART_RATE = 149;
+    APP_OP_READ_SKIN_TEMPERATURE = 150;
+    APP_OP_RANGING = 151;
+    APP_OP_READ_OXYGEN_SATURATION = 152;
+    APP_OP_WRITE_SYSTEM_PREFERENCES = 153;
+    APP_OP_CONTROL_AUDIO = 154;
+    APP_OP_CONTROL_AUDIO_PARTIAL = 155;
+}
diff --git a/stats/enums/bluetooth/OWNERS b/stats/enums/bluetooth/OWNERS
new file mode 100644
index 00000000..3098972c
--- /dev/null
+++ b/stats/enums/bluetooth/OWNERS
@@ -0,0 +1,3 @@
+girardier@google.com
+ahujapalash@google.com
+rghanti@google.com
\ No newline at end of file
diff --git a/stats/enums/bluetooth/enums.proto b/stats/enums/bluetooth/enums.proto
index 63e91911..337272a9 100644
--- a/stats/enums/bluetooth/enums.proto
+++ b/stats/enums/bluetooth/enums.proto
@@ -489,6 +489,12 @@ enum ProfileConnectionReason {
     REASON_INCOMING_CONN_REJECTED = 4;
 }
 
+enum LeConnectionResult {
+    LE_CONNECTION_RESULT_UNKNOWN = 0;
+    LE_CONNECTION_RESULT_SUCCESS = 1;
+    LE_CONNECTION_RESULT_FAILURE = 2;
+}
+
 // Comment added to those whose enum names do not match the actual file names.
 enum ContentProfileFileName {
   BLUETOOTH_FILE_NAME_UNKNOWN = 0;
@@ -567,6 +573,35 @@ enum EventType {
   AUTHENTICATION_COMPLETE_FAIL = 14;
   BONDING = 15;
   INITIATOR_CONNECTION = 16;
+  BOND = 17;
+  PROFILE_CONNECTION_A2DP = 18;
+  PROFILE_CONNECTION_A2DP_SINK = 19;
+  PROFILE_CONNECTION_HEADSET = 20;
+  PROFILE_CONNECTION_HEADSET_CLIENT = 21;
+  PROFILE_CONNECTION_MAP_CLIENT = 22;
+  PROFILE_CONNECTION_HID_HOST = 23;
+  PROFILE_CONNECTION_PAN = 24;
+  PROFILE_CONNECTION_PBAP_CLIENT = 25;
+  PROFILE_CONNECTION_HEARING_AID = 26;
+  PROFILE_CONNECTION_HAP_CLIENT = 27;
+  PROFILE_CONNECTION_VOLUME_CONTROL = 28;
+  PROFILE_CONNECTION_CSIP_SET_COORDINATOR = 29;
+  PROFILE_CONNECTION_LE_AUDIO = 30;
+  PROFILE_CONNECTION_LE_AUDIO_BROADCAST_ASSISTANT = 31;
+  PROFILE_CONNECTION_BATTERY = 32;
+  TRANSPORT = 33;
+  BOND_RETRY = 34;
+  SMP_PAIRING_OUTGOING = 35;
+  SMP_PAIRING_INCOMING = 36;
+  LE_ACL_CONNECTION_INITIATOR = 37;
+  LE_ACL_CONNECTION_RESPONDER = 38;
+  LE_ACL_DISCONNECTION_INITIATOR = 39;
+  LE_ACL_DISCONNECTION_RESPONDER = 40;
+  GATT_CONNECT_JAVA = 41;
+  GATT_CONNECT_NATIVE = 42;
+  LE_DEVICE_IN_ACCEPT_LIST = 43;
+  GATT_DISCONNECT_JAVA = 44;
+  GATT_DISCONNECT_NATIVE = 45;
 }
 
 enum State {
@@ -591,6 +626,76 @@ enum State {
   CONNECTION_TIMEOUT = 18;
   CONNECTION_ACCEPT_TIMEOUT = 19;
   TRANSACTION_RESPONSE_TIMEOUT = 20;
+  STATE_NONE = 21;
+  STATE_BONDED = 22;
+  CLASSIC = 23;
+  LE = 24;
+  HARDWARE_FAILURE = 25;
+  MEMORY_CAPACITY_EXCEEDED = 26;
+  CONNECTION_LIMIT_EXCEEDED = 27;
+  SYNCHRONOUS_CONNECTION_LIMIT_EXCEEDED = 28;
+  CONNECTION_REJECTED_SECURITY_REASONS = 29;
+  CONNECTION_REJECTED_UNACCEPTABLE_BD_ADDR = 30;
+  UNSUPPORTED_FEATURE_OR_PARAMETER_VALUE = 31;
+  INVALID_HCI_COMMAND_PARAMETERS = 32;
+  UNSUPPORTED_REMOTE_OR_LMP_FEATURE = 33;
+  SCO_OFFSET_REJECTED = 34;
+  SCO_INTERVAL_REJECTED = 35;
+  SCO_AIR_MODE_REJECTED = 36;
+  INVALID_LMP_OR_LL_PARAMETERS = 37;
+  UNSPECIFIED_ERROR = 38;
+  UNSUPPORTED_LMP_OR_LL_PARAMETER = 39;
+  ROLE_CHANGE_NOT_ALLOWED = 40;
+  LINK_LAYER_COLLISION = 41;
+  LMP_PDU_NOT_ALLOWED = 42;
+  ENCRYPTION_MODE_NOT_ACCEPTABLE = 43;
+  LINK_KEY_CANNOT_BE_CHANGED = 44;
+  REQUESTED_QOS_NOT_SUPPORTED = 45;
+  INSTANT_PASSED = 46;
+  PAIRING_WITH_UNIT_KEY_NOT_SUPPORTED = 47;
+  DIFFERENT_TRANSACTION_COLLISION = 48;
+  QOS_UNACCEPTABLE_PARAMETERS = 49;
+  QOS_REJECTED = 50;
+  CHANNEL_ASSESSMENT_NOT_SUPPORTED = 51;
+  INSUFFICIENT_SECURITY = 52;
+  PARAMETER_OUT_OF_MANDATORY_RANGE = 53;
+  ROLE_SWITCH_PENDING = 54;
+  RESERVED_SLOT_VIOLATION = 55;
+  ROLE_SWITCH_FAILED = 56;
+  EXTENDED_INQUIRY_RESPONSE_TOO_LARGE = 57;
+  SECURE_SIMPLE_PAIRING_NOT_SUPPORTED_BY_HOST = 58;
+  HOST_BUSY_PAIRING = 59;
+  CONNECTION_REJECTED_NO_SUITABLE_CHANNEL_FOUND = 60;
+  CONTROLLER_BUSY = 61;
+  UNACCEPTABLE_CONNECTION_PARAMETERS = 62;
+  ADVERTISING_TIMEOUT = 63;
+  CONNECTION_TERMINATED_DUE_TO_MIC_FAILURE = 64;
+  CONNECTION_FAILED_ESTABLISHMENT = 65;
+  COARSE_CLOCK_ADJUSTMENT_REJECTED = 66;
+  TYPE0_SUBMAP_NOT_DEFINED = 67;
+  UNKNOWN_ADVERTISING_IDENTIFIER = 68;
+  LIMIT_REACHED = 69;
+  OPERATION_CANCELLED_BY_HOST = 70;
+  PACKET_TOO_LONG = 71;
+  CONNECTION_TERMINATED_BY_LOCAL_HOST = 72;
+  PASSKEY_ENTRY_FAIL = 73;
+  OOB_FAIL = 74;
+  CONFIRM_VALUE_ERROR = 75;
+  ENC_KEY_SIZE = 76;
+  INVALID_CMD = 77;
+  INVALID_PARAMETERS = 78;
+  DHKEY_CHK_FAIL = 79;
+  NUMERIC_COMPARISON_FAIL = 80;
+  BR_PAIRING_IN_PROGRESS = 81;
+  CROSS_TRANSPORT_NOT_ALLOWED = 82;
+  INTERNAL_ERROR = 83;
+  UNKNOWN_IO_CAP = 84;
+  ENCRYPTION_FAIL = 85;
+  RESPONSE_TIMEOUT = 86;
+  SIRK_DEVICE_INVALID = 87;
+  USER_CANCELLATION = 88;
+  DIRECT_CONNECT = 89;
+  INDIRECT_CONNECT = 90;
 }
 
 enum RemoteDeviceTypeMetadata {
@@ -628,4 +733,4 @@ enum BroadcastSyncStatus {
    SYNC_STATUS_PA_SYNC_NO_PAST = 5;
    SYNC_STATUS_BIG_DECRYPT_FAILED = 6;
    SYNC_STATUS_AUDIO_SYNC_FAILED = 7;
-}
\ No newline at end of file
+}
diff --git a/stats/enums/bluetooth/rfcomm/enums.proto b/stats/enums/bluetooth/rfcomm/enums.proto
index f3770064..41fe52bd 100644
--- a/stats/enums/bluetooth/rfcomm/enums.proto
+++ b/stats/enums/bluetooth/rfcomm/enums.proto
@@ -36,3 +36,43 @@ enum SocketConnectionSecurity {
   SOCKET_SECURITY_SECURE = 1;
   SOCKET_SECURITY_INSECURE = 2;
 }
+
+enum PortResult {
+  PORT_RESULT_UNDEFINED = 0;
+  PORT_RESULT_SUCCESS = 1;
+  PORT_RESULT_UNKNOWN_ERROR = 2;
+  PORT_RESULT_ALREADY_OPENED = 3;
+  PORT_RESULT_CMD_PENDING = 4;
+  PORT_RESULT_APP_NOT_REGISTERED = 5;
+  PORT_RESULT_NO_MEM = 6;
+  PORT_RESULT_NO_RESOURCES = 7;
+  PORT_RESULT_BAD_BD_ADDR = 8;
+  PORT_RESULT_BAD_HANDLE = 9;
+  PORT_RESULT_NOT_OPENED = 10;
+  PORT_RESULT_LINE_ERR = 11;
+  PORT_RESULT_START_FAILED = 12;
+  PORT_RESULT_PAR_NEG_FAILED = 13;
+  PORT_RESULT_PORT_NEG_FAILED = 14;
+  PORT_RESULT_SEC_FAILED = 15;
+  PORT_RESULT_PEER_CONNECTION_FAILED = 16;
+  PORT_RESULT_PEER_FAILED = 17;
+  PORT_RESULT_PEER_TIMEOUT = 18;
+  PORT_RESULT_CLOSED = 19;
+  PORT_RESULT_TX_FULL = 20;
+  PORT_RESULT_LOCAL_CLOSED = 21;
+  PORT_RESULT_LOCAL_TIMEOUT = 22;
+  PORT_RESULT_TX_QUEUE_DISABLED = 23;
+  PORT_RESULT_PAGE_TIMEOUT = 24;
+  PORT_RESULT_INVALID_SCN = 25;
+  PORT_RESULT_ERR_MAX = 26;
+}
+
+enum RfcommPortState{
+  PORT_STATE_UNKNOWN = 0;
+  PORT_STATE_SABME_WAIT_UA = 1;
+  PORT_STATE_ORIG_WAIT_SEC_CHECK = 2;
+  PORT_STATE_TERM_WAIT_SEC_CHECK = 3;
+  PORT_STATE_OPENED = 4;
+  PORT_STATE_DISC_WAIT_UA = 5;
+  PORT_STATE_CLOSED = 6;
+}
diff --git a/stats/enums/conscrypt/OWNERS b/stats/enums/conscrypt/OWNERS
new file mode 100644
index 00000000..87a5dbee
--- /dev/null
+++ b/stats/enums/conscrypt/OWNERS
@@ -0,0 +1 @@
+include platform/libcore:/OWNERS
diff --git a/stats/enums/conscrypt/ct/enums.proto b/stats/enums/conscrypt/ct/enums.proto
new file mode 100644
index 00000000..78e7c2ea
--- /dev/null
+++ b/stats/enums/conscrypt/ct/enums.proto
@@ -0,0 +1,35 @@
+syntax = "proto2";
+
+package android.os.statsd.conscrypt;
+
+option java_package = "com.android.os.conscrypt";
+
+enum LogListStatus {
+    STATUS_UNKNOWN = 0;
+    STATUS_SUCCESS = 1;           // The list was loaded successfully.
+    STATUS_NOT_FOUND = 2;         // The list file was not found.
+    STATUS_PARSING_FAILED = 3;    // The list file failed to parse.
+    STATUS_EXPIRED = 4;           // The timestamp on the list is older than expected for the policy.
+}
+
+enum LogListCompatibilityVersion {
+    COMPAT_VERSION_UNKNOWN = 0;
+    COMPAT_VERSION_V1 = 1;
+}
+enum VerificationResult {
+    RESULT_UNKNOWN = 0;
+    RESULT_SUCCESS = 1;
+    RESULT_GENERIC_FAILURE = 2;
+    RESULT_FAILURE_NO_SCTS_FOUND = 3;
+    RESULT_FAILURE_SCTS_NOT_COMPLIANT = 4;
+    RESULT_FAIL_OPEN_NO_LOG_LIST_AVAILABLE = 5;
+    RESULT_FAIL_OPEN_LOG_LIST_NOT_COMPLIANT = 6;
+}
+
+enum VerificationReason {
+    REASON_UNKNOWN = 0;
+    REASON_DEVICE_WIDE_ENABLED = 1;
+    REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
+    REASON_NSCONFIG_APP_OPT_IN = 3;
+    REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
+}
diff --git a/stats/enums/coregraphics/enums.proto b/stats/enums/coregraphics/enums.proto
new file mode 100644
index 00000000..3b75bfc7
--- /dev/null
+++ b/stats/enums/coregraphics/enums.proto
@@ -0,0 +1,44 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+syntax = "proto2";
+
+package android.coregraphics;
+
+option java_package = "com.android.os.coregraphics";
+option java_multiple_files = true;
+
+// ColorSpace transfer
+// The ColorSpace transfer corresponds to skcms types, so these are not exact
+// transfers. E.g., SRGB is really a transfer curve that "looks" like an sRGB
+// transfer, but may use different constants
+enum ColorSpaceTransfer {
+    COLOR_SPACE_TRANSFER_UNKNOWN = 0;
+    COLOR_SPACE_TRANSFER_SRGBISH = 1;
+    COLOR_SPACE_TRANSFER_PQISH = 2;
+    COLOR_SPACE_TRANSFER_HLGISH = 3;
+}
+
+// Bitmap formats
+// Deprecated formats like ARGB4444 map to UNKNOWN
+enum BitmapFormat {
+    BITMAP_FORMAT_UNKNOWN = 0;
+    BITMAP_FORMAT_A_8 = 1;
+    BITMAP_FORMAT_RGB_565 = 2;
+    BITMAP_FORMAT_ARGB_8888 = 3;
+    BITMAP_FORMAT_RGBA_F16 = 4;
+    BITMAP_FORMAT_RGBA_1010102 = 5;
+}
diff --git a/stats/enums/corenetworking/connectivity/enums.proto b/stats/enums/corenetworking/connectivity/enums.proto
index 8b338ff3..8595aa01 100644
--- a/stats/enums/corenetworking/connectivity/enums.proto
+++ b/stats/enums/corenetworking/connectivity/enums.proto
@@ -75,3 +75,11 @@ enum FastDataInputState {
   FDIS_ENABLED= 1;
   FDIS_DISABLED = 2;
 }
+
+// Type of terrible error.
+enum TerribleErrorType {
+  TYPE_UNKNOWN = 0;
+  // Indicate the error state that the NetworkAgent sent messages to
+  // connectivity service before it is connected.
+  TYPE_MESSAGE_QUEUED_BEFORE_CONNECT = 1;
+}
diff --git a/stats/enums/federatedcompute/OWNERS b/stats/enums/federatedcompute/OWNERS
new file mode 100644
index 00000000..3ee2ab12
--- /dev/null
+++ b/stats/enums/federatedcompute/OWNERS
@@ -0,0 +1,4 @@
+# make sure everyone listed in OWNERS read http://go/ww-own-enums
+qiaoli@google.com
+yanning@google.com
+fumengyao@google.com
\ No newline at end of file
diff --git a/stats/enums/federatedcompute/enums.proto b/stats/enums/federatedcompute/enums.proto
index 7dd4009a..367eff42 100644
--- a/stats/enums/federatedcompute/enums.proto
+++ b/stats/enums/federatedcompute/enums.proto
@@ -21,7 +21,7 @@ option java_outer_classname = "FederatedComputeProtoEnums";
 option java_multiple_files = true;
 
 // Enum used to track federated computation job stages.
-// Next Tag: 73
+// Next Tag: 79
 enum TrainingEventKind {
   // Undefined value.
   TRAIN_UNDEFINED = 0;
@@ -278,4 +278,32 @@ enum TrainingEventKind {
 
   // Additional conditions chaeck failed.
   TRAIN_RUN_FAILED_CONDITIONS_FAILED = 61;
+
+  // Failed to fetch encryption keys due to timeout.
+  TRAIN_ENCRYPTION_KEY_FETCH_TIMEOUT_ERROR = 73;
+
+  // Fetch encryption keys started.
+  TRAIN_ENCRYPTION_KEY_FETCH_START = 74;
+
+  // Failed to fetch encryption keys due to empty fetch URI.
+  TRAIN_ENCRYPTION_KEY_FETCH_FAILED_EMPTY_URI = 75;
+
+  // Failed to fetch encryption keys due to http request creation failure.
+  TRAIN_ENCRYPTION_KEY_FETCH_REQUEST_CREATION_FAILED = 76;
+
+  // Failed to fetch encryption keys due response parsing failure.
+  TRAIN_ENCRYPTION_KEY_FETCH_INVALID_PAYLOAD = 77;
+
+  // Fetch encryption keys finished successfully.
+  TRAIN_ENCRYPTION_KEY_FETCH_SUCCESS = 78;
 }
+
+// Enum used to track federated computation trace events.
+// Next Tag: 2
+enum TraceEventKind {
+  // Undefined value.
+  TRACE_EVENT_KIND_UNSPECIFIED = 0;
+
+  // Trace for key fetch background job.
+  BACKGROUND_ENCRYPTION_KEY_FETCH = 1;
+}
\ No newline at end of file
diff --git a/stats/enums/framework/compat/OWNERS b/stats/enums/framework/compat/OWNERS
new file mode 100644
index 00000000..1658a933
--- /dev/null
+++ b/stats/enums/framework/compat/OWNERS
@@ -0,0 +1,7 @@
+mcarli@google.com
+minagranic@google.com
+gracielawputri@google.com
+eevlachavas@google.com
+lihongyu@google.com
+riddlehsu@google.com
+mariiasand@google.com
diff --git a/stats/enums/framework/compat/enums.proto b/stats/enums/framework/compat/enums.proto
new file mode 100644
index 00000000..1b22ff14
--- /dev/null
+++ b/stats/enums/framework/compat/enums.proto
@@ -0,0 +1,39 @@
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
+syntax = "proto2";
+
+package android.framework.compat;
+
+option java_outer_classname = "FrameworkCompatEnums";
+option java_multiple_files = true;
+
+// The freeform camera compatibility mode the activity is in at the time the
+// camera opened or closed signal is received.
+enum FreeformCameraCompatMode {
+  NONE = 0;
+  PORTRAIT_DEVICE_IN_LANDSCAPE = 1;
+  LANDSCAPE_DEVICE_IN_LANDSCAPE = 2;
+  PORTRAIT_DEVICE_IN_PORTRAIT = 3;
+  LANDSCAPE_DEVICE_IN_PORTRAIT = 4;
+}
+
+// Whether this state is logged on camera opened or closed.
+enum CameraState {
+  CAMERA_STATE_UNKNOWN = 0;
+  CAMERA_OPENED = 1;
+  CAMERA_CLOSED = 2;
+}
diff --git a/stats/enums/hardware/biometrics/enums.proto b/stats/enums/hardware/biometrics/enums.proto
index 79d1f57e..85e10222 100644
--- a/stats/enums/hardware/biometrics/enums.proto
+++ b/stats/enums/hardware/biometrics/enums.proto
@@ -150,15 +150,31 @@ enum SensorTypeEnum {
 }
 
 enum EnrollmentSourceEnum {
-   ENROLLMENT_SOURCE_UNKNOWN = 0;
-   ENROLLMENT_SOURCE_SUW = 1;
-   ENROLLMENT_SOURCE_SETTINGS = 2;
-   ENROLLMENT_SOURCE_FRR_NOTIFICATION = 3;
+    ENROLLMENT_SOURCE_UNKNOWN = 0;
+    ENROLLMENT_SOURCE_SUW = 1;
+    ENROLLMENT_SOURCE_SETTINGS = 2;
+    ENROLLMENT_SOURCE_FRR_NOTIFICATION = 3;
 }
 
 enum FRRNotificationAction {
-  FRR_NOTIFICATION_ACTION_UNKNOWN = 0;
-  FRR_NOTIFICATION_ACTION_SHOWN = 1;
-  FRR_NOTIFICATION_ACTION_CLICKED = 2;
-  FRR_NOTIFICATION_ACTION_DISMISSED = 3;
+    FRR_NOTIFICATION_ACTION_UNKNOWN = 0;
+    FRR_NOTIFICATION_ACTION_SHOWN = 1;
+    FRR_NOTIFICATION_ACTION_CLICKED = 2;
+    FRR_NOTIFICATION_ACTION_DISMISSED = 3;
 }
+
+enum UnenrollReasonEnum {
+    UNENROLL_REASON_UNKNOWN = 0;
+    UNENROLL_REASON_DANGLING_HAL = 1;
+    UNENROLL_REASON_DANGLING_FRAMEWORK = 2;
+    UNENROLL_REASON_USER_REQUEST = 3;
+}
+
+enum EnumerationResultEnum {
+    ENUMERATION_RESULT_UNKNOWN = 0;
+    ENUMERATION_RESULT_OK = 1;
+    ENUMERATION_RESULT_DANGLING_HAL = 2;
+    ENUMERATION_RESULT_DANGLING_FRAMEWORK = 3;
+    ENUMERATION_RESULT_DANGLING_BOTH = 4;
+    EMUMERATION_RESULT_TIMEOUT = 5;
+}
\ No newline at end of file
diff --git a/stats/enums/healthfitness/api/enums.proto b/stats/enums/healthfitness/api/enums.proto
index 81c9192d..de6bcc4f 100644
--- a/stats/enums/healthfitness/api/enums.proto
+++ b/stats/enums/healthfitness/api/enums.proto
@@ -32,6 +32,17 @@ enum ApiMethod {
   READ_DATA = 7;
   REVOKE_ALL_PERMISSIONS = 8;
   UPDATE_DATA = 9;
+  // PHR data source APIs
+  CREATE_MEDICAL_DATA_SOURCE = 10;
+  GET_MEDICAL_DATA_SOURCES_BY_IDS = 11;
+  GET_MEDICAL_DATA_SOURCES_BY_REQUESTS = 12;
+  DELETE_MEDICAL_DATA_SOURCE_WITH_DATA = 13;
+  // PHR medical resource APIs
+  UPSERT_MEDICAL_RESOURCES = 14;
+  READ_MEDICAL_RESOURCES_BY_IDS = 15;
+  READ_MEDICAL_RESOURCES_BY_REQUESTS = 16;
+  DELETE_MEDICAL_RESOURCES_BY_IDS = 17;
+  DELETE_MEDICAL_RESOURCES_BY_REQUESTS = 18;
 }
 
 enum ApiStatus {
@@ -146,6 +157,23 @@ enum DataType {
   INTERMENSTRUAL_BLEEDING = 40;
   MENSTRUATION_PERIOD = 41;
   SLEEP_SESSION = 42;
+  ACTIVITY_INTENSITY = 43;
+}
+
+enum MedicalResourceType {
+  MEDICAL_RESOURCE_TYPE_UNKNOWN = 0;
+  MEDICAL_RESOURCE_TYPE_VACCINES = 1;
+  MEDICAL_RESOURCE_TYPE_ALLERGIES_INTOLERANCES = 2;
+  MEDICAL_RESOURCE_TYPE_PREGNANCY = 3;
+  MEDICAL_RESOURCE_TYPE_SOCIAL_HISTORY = 4;
+  MEDICAL_RESOURCE_TYPE_VITAL_SIGNS = 5;
+  MEDICAL_RESOURCE_TYPE_LABORATORY_RESULTS = 6;
+  MEDICAL_RESOURCE_TYPE_CONDITIONS = 7;
+  MEDICAL_RESOURCE_TYPE_PROCEDURES = 8;
+  MEDICAL_RESOURCE_TYPE_MEDICATIONS = 9;
+  MEDICAL_RESOURCE_TYPE_PERSONAL_DETAILS = 10;
+  MEDICAL_RESOURCE_TYPE_PRACTITIONER_DETAILS = 11;
+  MEDICAL_RESOURCE_TYPE_VISITS = 12;
 }
 
 enum ForegroundState {
@@ -154,3 +182,10 @@ enum ForegroundState {
   BACKGROUND = 2;
 }
 
+enum MetricType {
+  METRIC_TYPE_DIRECTIONAL_PAIRING_PER_DATA_TYPE = 0;
+  METRIC_TYPE_DIRECTIONAL_PAIRING = 1;
+  METRIC_TYPE_NON_DIRECTIONAL_PAIRING = 2;
+}
+
+
diff --git a/stats/enums/healthfitness/ui/enums.proto b/stats/enums/healthfitness/ui/enums.proto
index d7b467bc..350b6b9f 100644
--- a/stats/enums/healthfitness/ui/enums.proto
+++ b/stats/enums/healthfitness/ui/enums.proto
@@ -396,7 +396,27 @@ enum ElementId {
     SEE_COMPATIBLE_APPS_BANNER_DISMISS_BUTTON = 274;
     SEE_COMPATIBLE_APPS_BANNER_APP_STORE_BUTTON = 275;
 
-    // Next available: 276;
+    // Start of PHR
+    // Onboarding page
+    ONBOARDING_MESSAGE_WITH_PHR = 276;
+    // Home page
+    BROWSE_HEALTH_RECORDS_BUTTON = 277;
+    // Combined app access page
+    FITNESS_PERMISSIONS_BUTTON = 279;
+    MEDICAL_PERMISSIONS_BUTTON = 280;
+    REMOVE_ALL_PERMISSIONS_BUTTON = 281;
+    // Lock screen banner
+    LOCK_SCREEN_BANNER = 282;
+    LOCK_SCREEN_BANNER_BUTTON = 283;
+    LOCK_SCREEN_BANNER_DISMISS_BUTTON = 284;
+    // Raw Fhir sceen
+    RAW_FHIR_RESOURCE = 285;
+    // Request write medical permission screen
+    ALLOW_WRITE_HEALTH_RECORDS_BUTTON = 286;
+    CANCEL_WRITE_HEALTH_RECORDS_BUTTON = 287;
+    // End of PHR
+
+    // Next available: 288;
 }
 
 enum PageId {
@@ -454,7 +474,19 @@ enum PageId {
     APP_DATA_PAGE = 44;
     APP_ENTRIES_PAGE = 45;
 
-    // Next available: 46;
+    // PHR
+    ALL_MEDICAL_DATA_PAGE = 46;
+    TAB_MEDICAL_ENTRIES_PAGE = 47;
+    TAB_MEDICAL_ACCESS_PAGE = 48;
+    RAW_FHIR_PAGE = 49;
+    REQUEST_MEDICAL_PERMISSIONS_PAGE = 50;
+    COMBINED_APP_ACCESS_PAGE = 51;
+    MEDICAL_APP_ACCESS_PAGE = 52;
+    SETTINGS_MANAGE_COMBINED_APP_PERMISSIONS_PAGE = 53;
+    SETTINGS_MANAGE_MEDICAL_APP_PERMISSIONS_PAGE = 54;
+    REQUEST_WRITE_MEDICAL_PERMISSION_PAGE = 55;
+
+    // Next available: 56;
 }
 
 enum Action {
diff --git a/stats/enums/input/enums.proto b/stats/enums/input/enums.proto
index c658874f..33bec20d 100644
--- a/stats/enums/input/enums.proto
+++ b/stats/enums/input/enums.proto
@@ -116,6 +116,21 @@ enum KeyboardSystemEvent {
     MULTI_WINDOW_NAVIGATION = 49;
     // Change split screen focus
     CHANGE_SPLITSCREEN_FOCUS = 50;
+    // Move a task into next display
+    MOVE_TO_NEXT_DISPLAY = 51;
+    // Resize a freeform window to fit the left half of the screen in desktop mode
+    SNAP_LEFT_FREEFORM_WINDOW = 52;
+    // Resize a freeform window to fit the right half of the screen in desktop mode
+    SNAP_RIGHT_FREEFORM_WINDOW = 53;
+    // Maximize a freeform window to the stable bounds in desktop mode
+    MAXIMIZE_FREEFORM_WINDOW = 54;
+    // Restore a freeform window size to its previous bounds in desktop mode
+    RESTORE_FREEFORM_WINDOW_SIZE = 55 [deprecated=true];
+    // Toggle between maximizing a freeform window to the stable bounds in
+    // desktop mode and restoring to its previous bounds
+    TOGGLE_MAXIMIZE_FREEFORM_WINDOW = 56;
+    // Minimize a window in desktop mode
+    MINIMIZE_FREEFORM_WINDOW = 57;
 }
 
 /**
diff --git a/stats/enums/jank/enums.proto b/stats/enums/jank/enums.proto
index 3d5c312d..e25125a8 100644
--- a/stats/enums/jank/enums.proto
+++ b/stats/enums/jank/enums.proto
@@ -132,6 +132,7 @@ enum InteractionType {
     DESKTOP_MODE_ENTER_APP_HANDLE_DRAG_RELEASE = 116;
     DESKTOP_MODE_EXIT_MODE_ON_LAST_WINDOW_CLOSE = 117;
     DESKTOP_MODE_SNAP_RESIZE = 118;
+    DESKTOP_MODE_UNMAXIMIZE_WINDOW = 119;
 
     reserved 2;
     reserved 73 to 78; // For b/281564325.
diff --git a/stats/enums/media/audio/enums.proto b/stats/enums/media/audio/enums.proto
index 3517a7d4..1203e990 100644
--- a/stats/enums/media/audio/enums.proto
+++ b/stats/enums/media/audio/enums.proto
@@ -274,6 +274,7 @@ enum Encoding {
   AUDIO_FORMAT_APTX = 0x20000000;
   AUDIO_FORMAT_APTX_HD = 0x21000000;
   AUDIO_FORMAT_AC4 = 0x22000000;
+  AUDIO_FORMAT_AC4_L4 = 0x22000001;
   AUDIO_FORMAT_LDAC = 0x23000000;
   AUDIO_FORMAT_MAT = 0x24000000;
   AUDIO_FORMAT_MAT_1_0 = 0x24000001;
diff --git a/stats/enums/os/enums.proto b/stats/enums/os/enums.proto
index e125339a..f9303897 100644
--- a/stats/enums/os/enums.proto
+++ b/stats/enums/os/enums.proto
@@ -20,6 +20,29 @@ package android.os;
 option java_outer_classname = "OsProtoEnums";
 option java_multiple_files = true;
 
+/**
+ * The status of a backported fix for a known issue on this device.
+ *
+ * Keep in sync with frameworks/base/core/java/android/os/Build.java
+ *
+ * Since android BAKLAVA
+ */
+enum BackportedFixStatus {
+    /** The status of the known issue on this device is not known. */
+    BACKPORTED_FIX_STATUS_UNKNOWN = 0;
+    /** The known issue is fixed on this device. */
+    BACKPORTED_FIX_STATUS_FIXED = 1;
+    /**
+     * The known issue is not applicable to this device.
+     *
+     * For example if the issue only affects a specific brand, devices from other brands would
+     * report not applicable.
+     */
+    BACKPORTED_FIX_STATUS_NOT_APPLICABLE = 2;
+    /** The known issue is not fixed on this device. */
+    BACKPORTED_FIX_STATUS_NOT_FIXED = 3;
+}
+
 // These constants are defined in hardware/interfaces/health/1.0/types.hal
 // They are primarily used by android/os/BatteryManager.java.
 enum BatteryHealthEnum {
diff --git a/stats/enums/performance/enums.proto b/stats/enums/performance/enums.proto
new file mode 100644
index 00000000..8a7a4154
--- /dev/null
+++ b/stats/enums/performance/enums.proto
@@ -0,0 +1,27 @@
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
+syntax = "proto2";
+
+package android.performance;
+
+// The resource that is being monitored for pressure stall information.
+enum PsiResource {
+  PSI_RESOURCE_UNKNOWN = 0;
+  PSI_RESOURCE_CPU = 1;
+  PSI_RESOURCE_MEMORY = 2;
+  PSI_RESOURCE_IO = 3;
+}
\ No newline at end of file
diff --git a/stats/enums/photopicker/OWNERS b/stats/enums/photopicker/OWNERS
new file mode 100644
index 00000000..fd36bf8a
--- /dev/null
+++ b/stats/enums/photopicker/OWNERS
@@ -0,0 +1,4 @@
+# Bug component: 95221
+
+include platform/frameworks/base:/core/java/android/os/storage/OWNERS
+
diff --git a/stats/enums/photopicker/enums.proto b/stats/enums/photopicker/enums.proto
index c9df2093..84a692ee 100644
--- a/stats/enums/photopicker/enums.proto
+++ b/stats/enums/photopicker/enums.proto
@@ -184,8 +184,10 @@ enum MediaStatus {
 enum MediaLocation {
   MAIN_GRID = 0;
   ALBUM = 1;
-  GROUP = 2;
+  GROUP = 2 [deprecated = true];
   UNSET_MEDIA_LOCATION = 3;
+  CATEGORY = 4;
+  SEARCH_GRID = 5;
 }
 
 /*
@@ -242,7 +244,8 @@ enum UserBannerInteraction {
  */
 enum SearchMethod {
   SEARCH_QUERY = 0;
-  COLLECTION = 1;
+  COLLECTION = 1 [deprecated = true];
   SUGGESTED_SEARCHES = 2;
   UNSET_SEARCH_METHOD = 3;
-}
\ No newline at end of file
+  CATEGORY_SEARCH = 4;
+}
diff --git a/stats/enums/ranging/enums.proto b/stats/enums/ranging/enums.proto
new file mode 100644
index 00000000..822718a4
--- /dev/null
+++ b/stats/enums/ranging/enums.proto
@@ -0,0 +1,68 @@
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
+syntax = "proto2";
+
+package android.ranging;
+
+option java_outer_classname = "RangingProtoEnums";
+option java_multiple_files = true;
+
+enum Technology {
+  TECHNOLOGY_UNKNOWN = 0;
+  TECHNOLOGY_UWB = 1;
+  TECHNOLOGY_BLE_CS = 2;
+  TECHNOLOGY_WIFI_NAN_RTT = 3;
+  TECHNOLOGY_BLE_RSSI = 4;
+}
+
+enum SessionState {
+  STATE_UNKNOWN = 0;
+  STATE_OOB = 1;
+  STATE_STARTING = 2;
+  STATE_RANGING = 3;
+}
+
+enum SessionType {
+  TYPE_UNKNOWN = 0;
+  TYPE_RAW = 1;
+  TYPE_OOB = 2;
+}
+
+enum DeviceRole {
+  ROLE_UNKNOWN = 0;
+  ROLE_RESPONDER = 1;
+  ROLE_INITIATOR = 2;
+}
+
+
+enum ClosedReason {
+  CLOSED_REASON_UNKNOWN = 0;
+  CLOSED_REASON_LOCAL_REQUEST = 1;
+  CLOSED_REASON_REMOTE_REQUEST = 2;
+  CLOSED_REASON_UNSUPPORTED = 3;
+  CLOSED_REASON_SYSTEM_POLICY = 4;
+  CLOSED_REASON_NO_PEERS_FOUND = 5;
+}
+
+enum StoppedReason {
+  STOPPED_REASON_UNKNOWN = 0;
+  STOPPED_REASON_ERROR = 1;
+  STOPPED_REASON_REQUESTED = 2;
+  STOPPED_REASON_UNSUPPORTED = 3;
+  STOPPED_REASON_SYSTEM_POLICY = 4;
+  STOPPED_REASON_LOST_CONNECTION = 5;
+}
\ No newline at end of file
diff --git a/stats/enums/stats/hdmi/enums.proto b/stats/enums/stats/hdmi/enums.proto
index a7dc59ab..db79de7d 100644
--- a/stats/enums/stats/hdmi/enums.proto
+++ b/stats/enums/stats/hdmi/enums.proto
@@ -149,4 +149,12 @@ enum DynamicSoundbarModeLogReason {
     LOG_REASON_DSM_UNKNOWN = 0;
     LOG_REASON_DSM_WAKE = 1;
     LOG_REASON_DSM_SETTING_TOGGLED = 2;
+}
+
+// Reason parameter of the POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST setting toggled
+// logging.
+enum PowerStateChangeOnActiveSourceLostToggleReason {
+    LOG_REASON_POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_TOGGLE_UNKNOWN = 0;
+    LOG_REASON_POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_TOGGLE_POP_UP = 1;
+    LOG_REASON_POWER_STATE_CHANGE_ON_ACTIVE_SOURCE_LOST_TOGGLE_SETTING = 2;
 }
\ No newline at end of file
diff --git a/stats/enums/telecomm/enums.proto b/stats/enums/telecomm/enums.proto
index 3a832a05..309fc577 100644
--- a/stats/enums/telecomm/enums.proto
+++ b/stats/enums/telecomm/enums.proto
@@ -286,66 +286,66 @@ enum CallAudioEnum {
  * Indicating the API name
  */
 enum ApiNameEnum {
-    UNSPECIFIED = 0;
-    ACCEPT_HANDOVER = 1;
-    ACCEPT_RINGING_CALL = 2;
-    ACCEPT_RINGING_CALL_WITH_VIDEO_STATE = 3;
-    ADD_CALL = 4;
-    ADD_NEW_INCOMING_CALL = 5;
-    ADD_NEW_INCOMING_CONFERENCE = 6;
-    ADD_NEW_UNKNOWN_CALL = 7;
-    CANCEL_MISSED_CALLS_NOTIFICATION = 8;
-    CLEAR_ACCOUNTS = 9;
-    CREATE_LAUNCH_EMERGENCY_DIALER_INTENT = 10;
-    CREATE_MANAGE_BLOCKED_NUMBERS_INTENT = 11;
-    DUMP = 12;
-    DUMP_CALL_ANALYTICS = 13;
-    ENABLE_PHONE_ACCOUNT = 14;
-    END_CALL = 15;
-    GET_ADN_URI_FOR_PHONE_ACCOUNT = 16;
-    GET_ALL_PHONE_ACCOUNT_HANDLES = 17;
-    GET_ALL_PHONE_ACCOUNTS = 18;
-    GET_ALL_PHONE_ACCOUNTS_COUNT = 19;
-    GET_CALL_CAPABLE_PHONE_ACCOUNTS = 20;
-    GET_CALL_STATE = 21;
-    GET_CALL_STATE_USING_PACKAGE = 22;
-    GET_CURRENT_TTY_MODE = 23;
-    GET_DEFAULT_DIALER_PACKAGE = 24;
-    GET_DEFAULT_DIALER_PACKAGE_FOR_USER = 25;
-    GET_DEFAULT_OUTGOING_PHONE_ACCOUNT = 26;
-    GET_DEFAULT_PHONE_APP = 27;
-    GET_LINE1_NUMBER = 28;
-    GET_OWN_SELF_MANAGED_PHONE_ACCOUNTS = 29;
-    GET_PHONE_ACCOUNT = 30;
-    GET_PHONE_ACCOUNTS_FOR_PACKAGE = 31;
-    GET_PHONE_ACCOUNTS_SUPPORTING_SCHEME = 32;
-    GET_REGISTERED_PHONE_ACCOUNTS = 33;
-    GET_SELF_MANAGED_PHONE_ACCOUNTS = 34;
-    GET_SIM_CALL_MANAGER = 35;
-    GET_SIM_CALL_MANAGER_FOR_USER = 36;
-    GET_SYSTEM_DIALER_PACKAGE = 37;
-    GET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 38;
-    GET_VOICE_MAIL_NUMBER = 39;
-    HANDLE_PIN_MMI = 40;
-    HANDLE_PIN_MMI_FOR_PHONE_ACCOUNT = 41;
-    HAS_MANAGE_ONGOING_CALLS_PERMISSION = 42;
-    IS_IN_CALL = 43;
-    IS_IN_EMERGENCY_CALL = 44;
-    IS_IN_MANAGED_CALL = 45;
-    IS_IN_SELF_MANAGED_CALL = 46;
-    IS_INCOMING_CALL_PERMITTED = 47;
-    IS_OUTGOING_CALL_PERMITTED = 48;
-    IS_RINGING = 49;
-    IS_TTY_SUPPORTED = 50;
-    IS_VOICE_MAIL_NUMBER = 51;
-    PLACE_CALL = 52;
-    REGISTER_PHONE_ACCOUNT = 53;
-    SET_DEFAULT_DIALER = 54;
-    SET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 55;
-    SHOW_IN_CALL_SCREEN = 56;
-    SILENCE_RINGER = 57;
-    START_CONFERENCE = 58;
-    UNREGISTER_PHONE_ACCOUNT = 59;
+    API_UNSPECIFIED = 0;
+    API_ACCEPT_HANDOVER = 1;
+    API_ACCEPT_RINGING_CALL = 2;
+    API_ACCEPT_RINGING_CALL_WITH_VIDEO_STATE = 3;
+    API_ADD_CALL = 4;
+    API_ADD_NEW_INCOMING_CALL = 5;
+    API_ADD_NEW_INCOMING_CONFERENCE = 6;
+    API_ADD_NEW_UNKNOWN_CALL = 7;
+    API_CANCEL_MISSED_CALLS_NOTIFICATION = 8;
+    API_CLEAR_ACCOUNTS = 9;
+    API_CREATE_LAUNCH_EMERGENCY_DIALER_INTENT = 10;
+    API_CREATE_MANAGE_BLOCKED_NUMBERS_INTENT = 11;
+    API_DUMP = 12;
+    API_DUMP_CALL_ANALYTICS = 13;
+    API_ENABLE_PHONE_ACCOUNT = 14;
+    API_END_CALL = 15;
+    API_GET_ADN_URI_FOR_PHONE_ACCOUNT = 16;
+    API_GET_ALL_PHONE_ACCOUNT_HANDLES = 17;
+    API_GET_ALL_PHONE_ACCOUNTS = 18;
+    API_GET_ALL_PHONE_ACCOUNTS_COUNT = 19;
+    API_GET_CALL_CAPABLE_PHONE_ACCOUNTS = 20;
+    API_GET_CALL_STATE = 21;
+    API_GET_CALL_STATE_USING_PACKAGE = 22;
+    API_GET_CURRENT_TTY_MODE = 23;
+    API_GET_DEFAULT_DIALER_PACKAGE = 24;
+    API_GET_DEFAULT_DIALER_PACKAGE_FOR_USER = 25;
+    API_GET_DEFAULT_OUTGOING_PHONE_ACCOUNT = 26;
+    API_GET_DEFAULT_PHONE_APP = 27;
+    API_GET_LINE1_NUMBER = 28;
+    API_GET_OWN_SELF_MANAGED_PHONE_ACCOUNTS = 29;
+    API_GET_PHONE_ACCOUNT = 30;
+    API_GET_PHONE_ACCOUNTS_FOR_PACKAGE = 31;
+    API_GET_PHONE_ACCOUNTS_SUPPORTING_SCHEME = 32;
+    API_GET_REGISTERED_PHONE_ACCOUNTS = 33;
+    API_GET_SELF_MANAGED_PHONE_ACCOUNTS = 34;
+    API_GET_SIM_CALL_MANAGER = 35;
+    API_GET_SIM_CALL_MANAGER_FOR_USER = 36;
+    API_GET_SYSTEM_DIALER_PACKAGE = 37;
+    API_GET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 38;
+    API_GET_VOICE_MAIL_NUMBER = 39;
+    API_HANDLE_PIN_MMI = 40;
+    API_HANDLE_PIN_MMI_FOR_PHONE_ACCOUNT = 41;
+    API_HAS_MANAGE_ONGOING_CALLS_PERMISSION = 42;
+    API_IS_IN_CALL = 43;
+    API_IS_IN_EMERGENCY_CALL = 44;
+    API_IS_IN_MANAGED_CALL = 45;
+    API_IS_IN_SELF_MANAGED_CALL = 46;
+    API_IS_INCOMING_CALL_PERMITTED = 47;
+    API_IS_OUTGOING_CALL_PERMITTED = 48;
+    API_IS_RINGING = 49;
+    API_IS_TTY_SUPPORTED = 50;
+    API_IS_VOICE_MAIL_NUMBER = 51;
+    API_PLACE_CALL = 52;
+    API_REGISTER_PHONE_ACCOUNT = 53;
+    API_SET_DEFAULT_DIALER = 54;
+    API_SET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 55;
+    API_SHOW_IN_CALL_SCREEN = 56;
+    API_SILENCE_RINGER = 57;
+    API_START_CONFERENCE = 58;
+    API_UNREGISTER_PHONE_ACCOUNT = 59;
 }
 
 /**
@@ -361,33 +361,33 @@ enum ApiResultEnum {
 /**
  * Indicating the sub module name
  */
-enum SubmoduleNameEnum {
-    SUB_MODULE_UNKNOWN = 0;
-    SUB_MODULE_CALL_AUDIO = 1;
-    SUB_MODULE_CALL_LOGS = 2;
-    SUB_MODULE_CALL_MANAGER = 3;
-    SUB_MODULE_CONNECTION_SERVICE = 4;
-    SUB_MODULE_EMERGENCY_CALL = 5;
-    SUB_MODULE_IN_CALL_SERVICE = 6;
-    SUB_MODULE_MISC = 7;
-    SUB_MODULE_PHONE_ACCOUNT = 8;
-    SUB_MODULE_SYSTEM_SERVICE = 9;
-    SUB_MODULE_TELEPHONY = 10;
-    SUB_MODULE_UI = 11;
-    SUB_MODULE_VOIP_CALL = 12;
+enum SubmoduleEnum {
+    SUB_UNKNOWN = 0;
+    SUB_CALL_AUDIO = 1;
+    SUB_CALL_LOGS = 2;
+    SUB_CALL_MANAGER = 3;
+    SUB_CONNECTION_SERVICE = 4;
+    SUB_EMERGENCY_CALL = 5;
+    SUB_IN_CALL_SERVICE = 6;
+    SUB_MISC = 7;
+    SUB_PHONE_ACCOUNT = 8;
+    SUB_SYSTEM_SERVICE = 9;
+    SUB_TELEPHONY = 10;
+    SUB_UI = 11;
+    SUB_VOIP_CALL = 12;
 }
 
 /**
  * Indicating the error name
  */
-enum ErrorNameEnum {
+enum ErrorEnum {
     ERROR_UNKNOWN = 0;
     ERROR_EXTERNAL_EXCEPTION = 1;
     ERROR_INTERNAL_EXCEPTION = 2;
     ERROR_AUDIO_ROUTE_RETRY_REJECTED = 3;
     ERROR_BT_GET_SERVICE_FAILURE = 4;
     ERROR_BT_REGISTER_CALLBACK_FAILURE = 5;
-    ERROR_DOCK_NOT_AVAILABLE = 6;
+    ERROR_AUDIO_ROUTE_UNAVAILABLE = 6;
     ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE = 7;
     ERROR_NOTIFY_CALL_STREAM_START_FAILURE = 8;
     ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE = 9;
@@ -397,4 +397,13 @@ enum ErrorNameEnum {
     ERROR_SET_MUTED_FAILURE = 13;
     ERROR_VIDEO_PROVIDER_SET_FAILURE = 14;
     ERROR_WIRED_HEADSET_NOT_AVAILABLE = 15;
+    ERROR_LOG_CALL_FAILURE = 16;
+    ERROR_RETRIEVING_ACCOUNT_EMERGENCY = 17;
+    ERROR_RETRIEVING_ACCOUNT = 18;
+    ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT = 19;
+    ERROR_DEFAULT_MO_ACCOUNT_MISMATCH = 20;
+    ERROR_ESTABLISHING_CONNECTION = 21;
+    ERROR_REMOVING_CALL = 22;
+    ERROR_STUCK_CONNECTING_EMERGENCY = 23;
+    ERROR_STUCK_CONNECTING = 24;
 }
diff --git a/stats/enums/telephony/enums.proto b/stats/enums/telephony/enums.proto
index e52bbd50..ab1376bf 100644
--- a/stats/enums/telephony/enums.proto
+++ b/stats/enums/telephony/enums.proto
@@ -90,6 +90,7 @@ enum NetworkTypeEnum {
     NETWORK_TYPE_IWLAN = 18;
     NETWORK_TYPE_LTE_CA = 19;
     NETWORK_TYPE_NR = 20;
+    NETWORK_TYPE_NB_IOT_NTN = 21;
 }
 
 // Cellular radio power state, see android/telephony/TelephonyManager.java for definitions.
diff --git a/stats/enums/view/inputmethod/enums.proto b/stats/enums/view/inputmethod/enums.proto
index 7b1f137b..67967a4f 100644
--- a/stats/enums/view/inputmethod/enums.proto
+++ b/stats/enums/view/inputmethod/enums.proto
@@ -80,6 +80,9 @@ enum SoftInputShowHideReasonEnum {
     REASON_SHOW_SOFT_INPUT_IME_TOGGLE_SOFT_INPUT = 53;
     REASON_SHOW_SOFT_INPUT_IMM_DEPRECATION = 54;
     REASON_CONTROL_WINDOW_INSETS_ANIMATION = 55;
+    REASON_SHOW_INPUT_TARGET_CHANGED = 56;
+    REASON_HIDE_INPUT_TARGET_CHANGED = 57;
+    REASON_HIDE_WINDOW_LOST_FOCUS = 58;
 }
 
 // The type of the IME request, used by android/view/inputmethod/ImeTracker.java.
@@ -265,5 +268,16 @@ enum ImeRequestPhaseEnum {
     PHASE_WM_INVOKING_IME_REQUESTED_LISTENER = 64;
     // IME is requested to be hidden, but already hidden. Don't hide to avoid another animation.
     PHASE_CLIENT_ALREADY_HIDDEN = 65;
+    // The view's handler is needed to check if we're running on a different thread. We can't
+    // continue without.
+    PHASE_CLIENT_VIEW_HANDLER_AVAILABLE = 66;
+    // ImeInsetsSourceProvider sets the reported visibility of the caller/client  window (either the
+    // app or the RemoteInsetsControlTarget).
+    PHASE_SERVER_UPDATE_CLIENT_VISIBILITY = 67;
+    // DisplayImeController received the requested visibility for the IME and stored it.
+    PHASE_WM_DISPLAY_IME_CONTROLLER_SET_IME_REQUESTED_VISIBLE = 68;
+    // The control target reported its requestedVisibleTypes back to WindowManagerService.
+    PHASE_WM_UPDATE_DISPLAY_WINDOW_REQUESTED_VISIBLE_TYPES = 69;
+
 }
 
diff --git a/stats/enums/wear/connectivity/OWNERS b/stats/enums/wear/connectivity/OWNERS
new file mode 100644
index 00000000..41143578
--- /dev/null
+++ b/stats/enums/wear/connectivity/OWNERS
@@ -0,0 +1 @@
+hongyiz@google.com
\ No newline at end of file
diff --git a/stats/enums/wear/connectivity/enums.proto b/stats/enums/wear/connectivity/enums.proto
index fa75b19d..820b5375 100644
--- a/stats/enums/wear/connectivity/enums.proto
+++ b/stats/enums/wear/connectivity/enums.proto
@@ -187,6 +187,7 @@ enum Reason {
     OFF_NO_DATA_ENABLED = 50;
     OFF_POOR_SIGNAL = 51;
     ON_PEEK_SIGNAL = 52;
+    ON_MODE_MANAGER = 53;
 }
 
 /**
@@ -222,6 +223,40 @@ enum SysproxyConnectionChangeReason {
     PROXY_OFF_DATA_SETTING_ENABLED = 11 [deprecated=true]; // replaced with 13
     PROXY_OFF_DEVICE_SETTING_DISABLED = 12;
     PROXY_OFF_DATA_SETTING_DISABLED = 13;
+
+    //native service self-termination
+    SERVICE_STOP_COMPANION_SHARD_REQUEST = 14;
+    SERVICE_STOP_CONNECT_FAILED = 15;
+    SERVICE_STOP_CREATE_CONTROL_PORT_FAILED = 16;
+    SERVICE_STOP_CREATE_TCP_PORT_FAILED = 17;
+    SERVICE_STOP_CREATE_UDP_PORT_FAILED = 18;
+    SERVICE_STOP_ARG_COUNT_INVALID = 19;
+    SERVICE_STOP_ARG_VERSION_INVALID = 20;
+    SERVICE_STOP_ARG_PROTO_DECODE_FAILED = 21;
+    SERVICE_STOP_SELF_TERM_REASON_UNKNOWN = 22;
+    SERVICE_STOP_REACTOR_START_FAILED = 23;
+    SERVICE_STOP_BT_UNABLE_TO_DRAIN_WRITE_BUFFER = 24;
+    SERVICE_STOP_BT_WRITE_TIMEOUT = 25;
+    SERVICE_STOP_BT_READ_ERR = 26;
+    SERVICE_STOP_BT_READ_EMPTY = 27;
+    SERVICE_STOP_BT_HANDSHAKE_ERR = 28;
+    SERVICE_STOP_STOP_BY_CONTROL_SERVER = 29;
+
+}
+
+enum SysproxyServiceState {
+    SYSPROXY_SERVICE_STATE_UNKNOWN = 0;
+    SERVICE_STARTUP_FINISHED = 1;
+    SERVICE_SHUTDOWN_FINISHED = 2;
+    SERVICE_IPTABLES_RECOVERY_ATTEMPTED = 3;
+}
+
+enum SysproxyIptablesState {
+    SYSPROXY_IPTABLES_STATE_UNKNOWN = 0;
+    IPTABLES_RULES_SETUP_SUCCESS = 1;
+    IPTABLES_RULES_SETUP_FAILURE = 2;
+    IPTABLES_RULES_TEARDOWN_SUCCESS = 3;
+    IPTABLES_RULES_TEARDOWN_FAILURE = 4;
 }
 
 /**
@@ -237,6 +272,8 @@ enum CompanionConnectionType {
     COMPANION_CONNECTION_TYPE_UNKNOWN = 0;
     BLE_ACL = 1;
     BTC_ACL = 2;
+    BTC_COMMS = 3;
+    BLE_COMMS = 4;
 }
 
 enum CompanionConnectionChange {
diff --git a/stats/enums/wear/setupwizard/enums.proto b/stats/enums/wear/setupwizard/enums.proto
new file mode 100644
index 00000000..16a57c3b
--- /dev/null
+++ b/stats/enums/wear/setupwizard/enums.proto
@@ -0,0 +1,204 @@
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
+syntax = "proto2";
+
+package com.google.android.clockwork.setup;
+
+/**
+ * Indicates the thermal status of the watch
+ */
+enum ThermalStatus {
+  THERMAL_STATUS_NONE = 0;
+  THERMAL_STATUS_LIGHT = 1;
+  THERMAL_STATUS_MODERATE = 2;
+  THERMAL_STATUS_SEVERE = 3;
+  THERMAL_STATUS_CRITICAL = 4;
+  THERMAL_STATUS_EMERGENCY = 5;
+  THERMAL_STATUS_SHUTDOWN = 6;
+}
+
+/**
+ * Indicates the tether configuration of the watch
+ */
+enum TetherConfiguration {
+  TETHER_CONFIGURATION_UNKNOWN = 0;
+  TETHER_CONFIGURATION_STANDALONE = 1;
+  TETHER_CONFIGURATION_TETHERED = 2;
+  TETHER_CONFIGURATION_RESTRICTED = 3;
+}
+
+/**
+ * Indicates the wrist orientation set of the watch
+ */
+enum WristOrientation {
+  WRIST_ORIENTATION_UNKNOWN = 0;
+  WRIST_ORIENTATION_LEFT_WRIST_ROTATION_0 = 1;
+  WRIST_ORIENTATION_LEFT_WRIST_ROTATION_180 = 2;
+  WRIST_ORIENTATION_RIGHT_WRIST_ROTATION_0 = 3;
+  WRIST_ORIENTATION_RIGHT_WRIST_ROTATION_180 = 4;
+}
+
+/**
+ * Indicates setupwizard application status
+ */
+enum SetupWizardStatus {
+  SETUP_WIZARD_STATUS_NOT_COMPLETED = 0;
+  SETUP_WIZARD_STATUS_COMPLETED = 1;
+}
+
+
+/**
+ * Indicates how pairing started between watch and companion
+ */
+enum PairingType {
+  PAIRING_TYPE_UNKNOWN = 0;
+  PAIRING_TYPE_FASTPAIR = 1;
+  PAIRING_TYPE_LOCALE = 2;
+  PAIRING_TYPE_REGULARPAIR = 3;
+}
+
+/**
+ * Indicates pairing status
+ */
+enum PairingStatus {
+  PAIRING_STATUS_NOT_COMPLETED = 0;
+  PAIRING_STATUS_COMPLETED = 1;
+}
+
+/**
+ * Indicates companion OS  type
+ */
+enum CompanionOsType {
+  COMPANION_OS_TYPE_UNKNOWN = 0;
+  COMPANION_OS_TYPE_ANDROID = 1;
+  COMPANION_OS_TYPE_IOS = 2;
+}
+
+/**
+ * Indicates connection status between watch and companion
+ */
+enum ConnectionStatus {
+  CONNECTION_STATUS_NOT_ESTABLISHED = 0;
+  CONNECTION_STATUS_ESTABLISHED = 1;
+}
+
+/**
+ * Indicates watch Checkin status
+ */
+enum CheckinStatus {
+  CHECKIN_STATUS_NOT_COMPLETED = 0;
+  CHECKIN_STATUS_COMPLETED = 1;
+}
+
+/**
+ * Indicates the watch's role when exchanging messages with companion
+ */
+enum MessageRole {
+  MESSAGE_ROLE_UNKNOWN = 0;
+  MESSAGE_ROLE_SENDER = 1;
+  MESSAGE_ROLE_RECEIVER = 2;
+}
+
+/**
+ * Indicates the status of the phone or the watch during the status
+ * exchange in setup
+ */
+enum MessageStatus {
+  MESSAGE_STATUS_STATE_UNKNOWN = 0;
+  MESSAGE_STATUS_READY = 1;
+  MESSAGE_STATUS_COMPLETE_PENDING = 2;
+  MESSAGE_STATUS_COMPLETE = 3;
+  MESSAGE_STATUS_UPDATING = 4;
+  MESSAGE_STATUS_OOBE_DONE = 5;
+  MESSAGE_STATUS_READY_RESUMABLE_OOBE = 6;
+  MESSAGE_STATUS_START_RESUMABLE_OOBE = 7;
+  MESSAGE_STATUS_CRITICAL_PHASE_COMPLETE = 8;
+  MESSAGE_STATUS_EXITING_TO_WATCHFACE = 9;
+  MESSAGE_STATUS_WATCH_FAILURE = 10;
+  MESSAGE_STATUS_PHONE_FAILURE = 11;
+}
+
+/**
+ * Indicates heartbeat message type when resumable OOBE is enabled
+ */
+enum HeartbeatMessageType {
+  HEARTBEAT_MESSAGE_TYPE_UNKNOWN = 0;
+  HEARTBEAT_MESSAGE_TYPE_REQUEST = 1;
+  HEARTBEAT_MESSAGE_TYPE_RESPONSE = 2;
+  HEARTBEAT_MESSAGE_TYPE_UNSUPPORTED_COMMAND= 3;
+}
+
+/**
+ * Indicates end statuses of FRP
+ */
+enum FrpStatus {
+  FRP_STATUS_UNKNOWN = 0;
+  FRP_STATUS_PIN_PATTERN_SUCCESS = 1;
+  FRP_STATUS_PIN_PATTERN_MISMATCH_FAILURE = 2;
+  FRP_STATUS_PIN_PATTERN_UNKNOWN_ERROR = 3;
+  FRP_STATUS_ACCOUNT_SUCCESS = 4;
+  FRP_STATUS_ACCOUNT_MISMATCH_FAILURE = 5;
+  FRP_STATUS_MEDIATOR_SERVICE_NULL_ERROR = 6;
+  FRP_STATUS_UNLOCK_FRP_FOR_WEAR_ERROR = 7;
+}
+
+/**
+ *  Indicates system update progress status
+ */
+enum SystemUpdateProgressStatus {
+  SYSTEM_UPDATE_PROGRESS_STATUS_NOT_COMPLETED = 0;
+  SYSTEM_UPDATE_PROGRESS_STATUS_COMPLETED = 1;
+}
+
+/**
+ * Indicates how phone switching was initiated
+ */
+enum PhoneSwitchingRequestSource {
+  PHONE_SWITCHING_REQUEST_SOURCE_NONE = 0;
+  PHONE_SWITCHING_REQUEST_SOURCE_WATCH = 1;
+  PHONE_SWITCHING_REQUEST_SOURCE_COMPANION_USER_CONFIRMATION = 2;
+  PHONE_SWITCHING_REQUEST_SOURCE_COMPANION = 3;
+}
+
+/**
+ * Indicates phone switching status throughout the flow
+ */
+enum PhoneSwitchingStatus {
+  PHONE_SWITCHING_STATUS_NOT_STARTED = 0;
+  PHONE_SWITCHING_STATUS_STARTED = 1;
+  PHONE_SWITCHING_STATUS_SUCCESS = 2;
+  PHONE_SWITCHING_STATUS_CANCELLED = 3;
+  PHONE_SWITCHING_STATUS_FAILED = 4;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_ADVERTISING = 5;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_BONDED = 6;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_PHONE_COMPLETE = 7;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_MIGRATION = 8;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_MIGRATION_FAILED = 9;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_MIGRATION_CANCELLED = 10;
+  PHONE_SWITCHING_STATUS_IN_PROGRESS_MIGRATION_SUCCESS = 11;
+  PHONE_SWITCHING_STATUS_ACCOUNTS_MATCHED = 12;
+}
+
+/**
+ * Indicates companion OS type change at the end of phone switching
+ */
+enum PhoneSwitchingCompanionOsTypeChange {
+  PHONE_SWITCHING_COMPANION_OS_TYPE_CHANGE_UNKNOWN = 0;
+  PHONE_SWITCHING_COMPANION_OS_TYPE_CHANGE_ANDROID_TO_ANDROID = 1;
+  PHONE_SWITCHING_COMPANION_OS_TYPE_CHANGE_IOS_TO_ANDROID = 2;
+  PHONE_SWITCHING_COMPANION_OS_TYPE_CHANGE_IOS_TO_IOS = 3;
+}
\ No newline at end of file
diff --git a/stats/express/catalog/health_services.cfg b/stats/express/catalog/health_services.cfg
deleted file mode 100644
index 7f7576e1..00000000
--- a/stats/express/catalog/health_services.cfg
+++ /dev/null
@@ -1,8 +0,0 @@
-express_metric {
-    id: "health_services.value_hal_crash_counter"
-    type: COUNTER
-    display_name: "HAL crash counter metric"
-    description: "Count of HealthServices HAL crashes"
-    owner_email: "whs-eng@google.com"
-    unit: UNIT_COUNT
-}
diff --git a/stats/express/catalog/input.cfg b/stats/express/catalog/input.cfg
index 2e6067c5..c71c7d7a 100644
--- a/stats/express/catalog/input.cfg
+++ b/stats/express/catalog/input.cfg
@@ -6,3 +6,12 @@ express_metric {
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
 }
+
+express_metric {
+    id: "input.value_rotary_input_device_full_rotation_count"
+    display_name: "Rotary input device rotation count"
+    description: "Number of full rotations on a rotary input device."
+    owner_email: "wear-frameworks@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
diff --git a/stats/express/catalog/job_scheduler.cfg b/stats/express/catalog/job_scheduler.cfg
index fad90764..937f0385 100644
--- a/stats/express/catalog/job_scheduler.cfg
+++ b/stats/express/catalog/job_scheduler.cfg
@@ -6,6 +6,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -16,6 +17,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -26,6 +28,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -36,6 +39,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -46,6 +50,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -56,6 +61,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -66,6 +72,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -76,6 +83,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -86,6 +94,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -96,6 +105,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -106,6 +116,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -116,6 +127,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -126,6 +138,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -136,6 +149,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -146,6 +160,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -156,6 +171,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -166,6 +182,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -176,6 +193,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -186,6 +204,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -196,6 +215,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -206,6 +226,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -216,6 +237,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -226,6 +248,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -236,6 +259,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -246,6 +270,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -256,6 +281,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
 
 express_metric {
@@ -266,6 +292,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -284,6 +311,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -302,6 +330,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -320,6 +349,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -338,6 +368,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         uniform_bins {
             count: 100
@@ -355,6 +386,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 15
@@ -373,6 +405,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -391,6 +424,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -409,6 +443,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -427,6 +462,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 50
@@ -445,6 +481,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: HISTOGRAM_WITH_UID
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 20
@@ -463,6 +500,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: HISTOGRAM_WITH_UID
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 25
@@ -481,6 +519,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM_WITH_UID
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 25
@@ -499,6 +538,7 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_KILOBYTE
     type: HISTOGRAM_WITH_UID
+    disabled: true
     histogram_options {
         scaled_bins {
             count: 25
@@ -518,6 +558,7 @@ express_metric {
     owner_email: "yanmin@google.com"
     unit: UNIT_COUNT
     type: COUNTER
+    disabled: true
 }
 
 express_metric {
@@ -528,4 +569,5 @@ express_metric {
     owner_email: "kwekua@google.com"
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
+    disabled: true
 }
diff --git a/stats/express/catalog/vibrator.cfg b/stats/express/catalog/vibrator.cfg
index 1f35a5fb..abec9bb7 100644
--- a/stats/express/catalog/vibrator.cfg
+++ b/stats/express/catalog/vibrator.cfg
@@ -89,3 +89,78 @@ express_metric {
     }
 }
 
+express_metric {
+    id: "vibrator.value_vibration_vendor_effect_requests"
+    type: COUNTER_WITH_UID
+    display_name: "Counter of vibration requests for createVendorEffect()"
+    description:
+      "Number of times vendors requested vibrations created via"
+      " VibrationEffect.createVendorEffect(), per uid."
+    owner_email: "lsandrade@google.com"
+    owner_email: "android-haptics@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "vibrator.value_vibration_vendor_effect_size"
+    type: HISTOGRAM_WITH_UID
+    display_name: "Vendor vibration effect size"
+    description:
+      "Size of PersistableBundle vendor data in"
+      " createVendorEffect() requests, per uid"
+    owner_email: "lsandrade@google.com"
+    owner_email: "android-haptics@google.com"
+    unit: UNIT_KILOBYTE
+    histogram_options: {
+        scaled_bins { # 1KB to ~4.5MB
+            count: 25
+            min_value: 0
+            first_bin_width: 1
+            scale: 1.4
+        }
+    }
+}
+
+express_metric {
+    id: "vibrator.value_vibration_vendor_session_started"
+    type: COUNTER_WITH_UID
+    display_name: "Counter of successful startVendorSession()"
+    description:
+      "Number of times vendors sessions were successfully started via"
+      " Vibrator.startVendorSession(), per uid."
+    owner_email: "lsandrade@google.com"
+    owner_email: "android-haptics@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "vibrator.value_vibration_vendor_session_interrupted"
+    type: COUNTER_WITH_UID
+    display_name: "Counter of vendor vibration sessions interrupted"
+    description:
+      "Number of times vendor vibration sessions are interrupted"
+      " by the platform, per uid."
+    owner_email: "lsandrade@google.com"
+    owner_email: "android-haptics@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "vibrator.value_vibration_vendor_session_vibrations"
+    type: HISTOGRAM_WITH_UID
+    display_name: "Vendor session vibration request count"
+    description:
+      "Number of times vendors requested vibrations in a session, per uid."
+    owner_email: "lsandrade@google.com"
+    owner_email: "android-haptics@google.com"
+    unit: UNIT_COUNT
+    histogram_options: {
+        scaled_bins { # 1 to ~840
+            count: 20
+            min_value: 0
+            first_bin_width: 1
+            scale: 1.4
+        }
+    }
+}
+
diff --git a/stats/express/catalog/wear_frameworks.cfg b/stats/express/catalog/wear_frameworks.cfg
new file mode 100644
index 00000000..33a3946a
--- /dev/null
+++ b/stats/express/catalog/wear_frameworks.cfg
@@ -0,0 +1,17 @@
+express_metric {
+    id: "wear_frameworks.value_power_key_down_count"
+    display_name: "Number of DOWN key events on the power key"
+    description: "Counts the number of DOWN key events on the power key."
+    owner_email: "wear-frameworks@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
+express_metric {
+    id: "wear_frameworks.value_stem_primary_key_down_count"
+    display_name: "Number of DOWN key events on the STEM primary key"
+    description: "Counts the number of DOWN key events on the STEM primary key."
+    owner_email: "wear-frameworks@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
\ No newline at end of file
diff --git a/stats/express/express_config.proto b/stats/express/express_config.proto
index f43bcbe0..5d272ec2 100644
--- a/stats/express/express_config.proto
+++ b/stats/express/express_config.proto
@@ -80,6 +80,9 @@ message ExpressMetric {
     oneof options {
         HistogramOptions histogram_options = 7;
     }
+
+    // Collection is disabled. Logging may still happen.
+    optional bool disabled = 8;
 }
 
 message ExpressMetricConfigFile {
diff --git a/stats/express/expresscatalog-code-gen/codegen_java.cpp b/stats/express/expresscatalog-code-gen/codegen_java.cpp
index 3ff2d90f..e6a0b296 100644
--- a/stats/express/expresscatalog-code-gen/codegen_java.cpp
+++ b/stats/express/expresscatalog-code-gen/codegen_java.cpp
@@ -74,6 +74,7 @@ bool CodeGeneratorJava::generateCodeImpl(FILE* fd, const MetricInfoMap& metricsI
     fprintf(fd, "public final class %s {\n\n", mClassName.c_str());
 
     // TODO: auto-generate enum int constants
+    fprintf(fd, "public static final long INVALID_METRIC_ID = 0;\n");
     fprintf(fd, "public static final int METRIC_TYPE_UNKNOWN = 0;\n");
     fprintf(fd, "public static final int METRIC_TYPE_COUNTER = 1;\n");
     fprintf(fd, "public static final int METRIC_TYPE_HISTOGRAM = 2;\n");
@@ -93,12 +94,8 @@ bool CodeGeneratorJava::generateCodeImpl(FILE* fd, const MetricInfoMap& metricsI
 
     fprintf(fd, "static long getMetricIdHash(String metricId, int type) {\n");
     fprintf(fd, "    MetricInfo info = metricIds.get(metricId);\n");
-    fprintf(fd, "    if(info == null) {\n");
-    fprintf(fd,
-            "        throw new IllegalArgumentException(\"Metric is undefined \" + metricId);\n");
-    fprintf(fd, "    }\n");
-    fprintf(fd, "    if(info.mType != type) {\n");
-    fprintf(fd, "        throw new InputMismatchException(\"Metric type is not \" + type);\n");
+    fprintf(fd, "    if(info == null || info.mType != type) {\n");
+    fprintf(fd, "        return INVALID_METRIC_ID;\n");
     fprintf(fd, "    }\n");
     fprintf(fd, "    return info.mHash;\n");
     fprintf(fd, "}\n\n");
diff --git a/stats/stats_log_api_gen/java_writer.cpp b/stats/stats_log_api_gen/java_writer.cpp
index f958934a..6798640f 100644
--- a/stats/stats_log_api_gen/java_writer.cpp
+++ b/stats/stats_log_api_gen/java_writer.cpp
@@ -371,6 +371,7 @@ int write_stats_log_java(FILE* out, const Atoms& atoms, const AtomDecl& attribut
     fprintf(out, "\n");
     fprintf(out, "/**\n");
     fprintf(out, " * Utility class for logging statistics events.\n");
+    fprintf(out, " * @hide\n");
     fprintf(out, " */\n");
     fprintf(out, "public final class %s {\n", javaClass.c_str());
 
diff --git a/stats/stats_log_api_gen/main.cpp b/stats/stats_log_api_gen/main.cpp
index f18b9553..a5a8beca 100644
--- a/stats/stats_log_api_gen/main.cpp
+++ b/stats/stats_log_api_gen/main.cpp
@@ -240,7 +240,7 @@ static int run(int argc, char const* const* argv) {
         }
     }
 
-    // Collate the parameters
+    // Collate the parameters.
     int errorCount = 0;
 
     Atoms atoms;
diff --git a/stats/stats_log_api_gen/native_writer.cpp b/stats/stats_log_api_gen/native_writer.cpp
index 37cace9b..6f11beac 100644
--- a/stats/stats_log_api_gen/native_writer.cpp
+++ b/stats/stats_log_api_gen/native_writer.cpp
@@ -227,13 +227,20 @@ static int write_native_stats_write_methods(FILE* out, const SignatureInfoMap& s
             const FieldNumberToAtomDeclSet::const_iterator fieldNumberToAtomDeclSetIt =
                     fieldNumberToAtomDeclSet.find(ATOM_ID_FIELD_NUMBER);
             if (fieldNumberToAtomDeclSet.end() != fieldNumberToAtomDeclSetIt) {
-                fprintf(stderr, "Bootstrap atoms do not support annotations\n");
+                fprintf(stderr, "Top-level bootstrap atoms do not support annotations\n");
                 return 1;
             }
             int argIndex = 1;
-            const char* atomVal = "::android::os::StatsBootstrapAtomValue::";
+            const char* atomVal = "::android::os::StatsBootstrapAtomValue";
+            const char* primitiveVal = "::android::os::StatsBootstrapAtomValue::Primitive::";
+            const char* annotationVal = "::android::os::StatsBootstrapAtomValue::Annotation";
+            const char* annotationIdVal =
+                    "::android::os::StatsBootstrapAtomValue::Annotation::Id::";
+            const char* annotationPrimitiveVal =
+                    "::android::os::StatsBootstrapAtomValue::Annotation::Primitive::";
             for (vector<java_type_t>::const_iterator arg = signature.begin();
                  arg != signature.end(); arg++) {
+                fprintf(out, "    %s value%d;\n", atomVal, argIndex);
                 switch (*arg) {
                     case JAVA_TYPE_BYTE_ARRAY:
                         fprintf(out,
@@ -241,52 +248,93 @@ static int write_native_stats_write_methods(FILE* out, const SignatureInfoMap& s
                                 "uint8_t*>(arg%d.arg);\n",
                                 argIndex, argIndex);
                         fprintf(out,
-                                "    "
-                                "atom.values.push_back(%smake<%sbytesValue>(std::vector(arg%dbyte, "
-                                "arg%dbyte + arg%d.arg_length)));\n",
-                                atomVal, atomVal, argIndex, argIndex, argIndex);
+                                "    value%d.value = %smake<%sbytesValue>(std::vector(arg%dbyte, "
+                                "arg%dbyte + arg%d.arg_length));\n",
+                                argIndex, primitiveVal, primitiveVal, argIndex, argIndex, argIndex);
                         break;
                     case JAVA_TYPE_BOOLEAN:
-                        fprintf(out, "    atom.values.push_back(%smake<%sboolValue>(arg%d));\n",
-                                atomVal, atomVal, argIndex);
+                        fprintf(out, "    value%d.value = %smake<%sboolValue>(arg%d);\n", argIndex,
+                                primitiveVal, primitiveVal, argIndex);
                         break;
                     case JAVA_TYPE_INT:  // Fall through.
                     case JAVA_TYPE_ENUM:
-                        fprintf(out, "    atom.values.push_back(%smake<%sintValue>(arg%d));\n",
-                                atomVal, atomVal, argIndex);
+                        fprintf(out, "    value%d.value = %smake<%sintValue>(arg%d);\n", argIndex,
+                                primitiveVal, primitiveVal, argIndex);
                         break;
                     case JAVA_TYPE_FLOAT:
-                        fprintf(out, "    atom.values.push_back(%smake<%sfloatValue>(arg%d));\n",
-                                atomVal, atomVal, argIndex);
+                        fprintf(out, "    value%d.value = %smake<%sfloatValue>(arg%d);\n", argIndex,
+                                primitiveVal, primitiveVal, argIndex);
                         break;
                     case JAVA_TYPE_LONG:
-                        fprintf(out, "    atom.values.push_back(%smake<%slongValue>(arg%d));\n",
-                                atomVal, atomVal, argIndex);
+                        fprintf(out, "    value%d.value = %smake<%slongValue>(arg%d);\n", argIndex,
+                                primitiveVal, primitiveVal, argIndex);
                         break;
                     case JAVA_TYPE_STRING:
                         fprintf(out,
-                                "    atom.values.push_back(%smake<%sstringValue>("
-                                "::android::String16(arg%d)));\n",
-                                atomVal, atomVal, argIndex);
+                                "    value%d.value = %smake<%sstringValue>("
+                                "::android::String16(arg%d));\n",
+                                argIndex, primitiveVal, primitiveVal, argIndex);
+                        break;
+                    case JAVA_TYPE_STRING_ARRAY:
+                        fprintf(out,
+                                "    value%d.value = %smake<%sstringArrayValue>("
+                                "arg%d.begin(), arg%d.end());\n",
+                                argIndex, primitiveVal, primitiveVal, argIndex, argIndex);
                         break;
                     default:
                         // Unsupported types: OBJECT, DOUBLE, ATTRIBUTION_CHAIN,
                         // and all repeated fields
-                        fprintf(stderr, "Encountered unsupported type.\n");
+                        fprintf(stderr, "Encountered unsupported type. %d, %d\n", *arg, argIndex);
                         return 1;
                 }
                 const FieldNumberToAtomDeclSet::const_iterator fieldNumberToAtomDeclSetIt =
                         fieldNumberToAtomDeclSet.find(argIndex);
+                // Scrub for any annotations that aren't UIDs
                 if (fieldNumberToAtomDeclSet.end() != fieldNumberToAtomDeclSetIt) {
-                    fprintf(stderr, "Bootstrap atoms do not support annotations\n");
-                    return 1;
+                    const AtomDeclSet& atomDeclSet = fieldNumberToAtomDeclSetIt->second;
+                    for (const shared_ptr<AtomDecl>& atomDecl : atomDeclSet) {
+                        const string atomConstant = make_constant_name(atomDecl->name);
+                        fprintf(out, "    if (%s == code) {\n", atomConstant.c_str());
+                        int32_t annotationIndex = 0;
+                        for (const shared_ptr<Annotation>& annotation :
+                             atomDecl->fieldNumberToAnnotations.at(argIndex)) {
+                            if (annotation->annotationId != ANNOTATION_ID_IS_UID) {
+                                fprintf(stderr,
+                                        "Bootstrap atom fields do not support non-UID "
+                                        "annotations\n");
+                                return 1;
+                            }
+
+                            if (annotationIndex >= 1) {
+                                fprintf(stderr,
+                                        "Bootstrap atom fields do not support multiple "
+                                        "annotations\n");
+                                return 1;
+                            }
+
+                            fprintf(out, "        %s annotation%d;\n", annotationVal,
+                                    annotationIndex);
+                            fprintf(out, "        annotation%d.id = %sIS_UID;\n", annotationIndex,
+                                    annotationIdVal);
+                            fprintf(out,
+                                    "        annotation%d.value = "
+                                    "%smake<%sboolValue>(true);\n",
+                                    annotationIndex, annotationPrimitiveVal,
+                                    annotationPrimitiveVal);
+                            fprintf(out, "        value%d.annotations.push_back(annotation%d);\n",
+                                    argIndex, annotationIndex);
+                            annotationIndex++;
+                        }
+                        fprintf(out, "    }\n");
+                    }
                 }
+                fprintf(out, "    atom.values.push_back(value%d);\n", argIndex);
                 argIndex++;
             }
             fprintf(out,
                     "    bool success = "
                     "::android::os::stats::StatsBootstrapAtomClient::reportBootstrapAtom(atom);\n");
-            fprintf(out, "    return success? 0 : -1;\n");
+            fprintf(out, "    return success ? 0 : -1;\n");
 
         } else if (minApiLevel == API_Q) {
             int argIndex = 1;
```

