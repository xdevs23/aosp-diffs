```diff
diff --git a/OWNERS b/OWNERS
index 441f92f3..13fe861a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -13,3 +13,5 @@ per-file settings_enums.proto=edgarwang@google.com
 
 # Adservices
 per-file adservices_enums.proto=binhnguyen@google.com,pdevpura@google.com
+per-file adservices_cel_enums.proto=binhnguyen@google.com,pdevpura@google.com
+
diff --git a/stats/Android.bp b/stats/Android.bp
index 023a6248..0f35118b 100644
--- a/stats/Android.bp
+++ b/stats/Android.bp
@@ -24,18 +24,22 @@ package {
 // Enum protos can be reused in multiple libraries (pixelatoms.proto, etc)
 // Due to size grownth constraints proposed to reuse only what really imported
 shared_enum_protos = [
-    "enums/app/**/*.proto",
+    "enums/app_shared/*.proto",
     "enums/display/*.proto",
+    "enums/hardware/biometrics/*.proto",
 ]
 
 enum_protos = [
+    "enums/accessibility/*.proto",
     "enums/adservices/common/*.proto",
     "enums/adservices/enrollment/*.proto",
     "enums/adservices/fledge/*.proto",
     "enums/adservices/measurement/*.proto",
     "enums/anr/*.proto",
     "enums/apex/*.proto",
+    "enums/app/**/*.proto",
     "enums/appsearch/*.proto",
+    "enums/art/*.proto",
     "enums/autofill/**/*.proto",
     "enums/contexthub/*.proto",
     "enums/corenetworking/**/*.proto",
@@ -92,7 +96,9 @@ enum_protos = [
     "enums/wear/connectivity/*.proto",
     "enums/wear/media/*.proto",
     "enums/wear/modes/*.proto",
+    "enums/wear/time/*.proto",
     "enums/wifi/*.proto",
+    "enums/telephony/iwlan/*.proto",
     ":data_stall_event_proto",
     ":device_policy_proto",
     ":dns_resolver_proto",
@@ -109,6 +115,7 @@ enum_protos = [
 atom_protos = [
     "atoms.proto",
     "attribution_node.proto",
+    "atoms/accessibility/*.proto",
     "atoms/adpf/*.proto",
     "atoms/agif/*.proto",
     "atoms/apex/*.proto",
@@ -120,6 +127,7 @@ atom_protos = [
     "atoms/autofill/*.proto",
     "atoms/credentials/*.proto",
     "atoms/cronet/*.proto",
+    "atoms/conscrypt/*.proto",
     "atoms/devicepolicy/*.proto",
     "atoms/display/*.proto",
     "atoms/dnd/*.proto",
@@ -129,12 +137,14 @@ atom_protos = [
     "atoms/gps/*.proto",
     "atoms/grammaticalinflection/*.proto",
     "atoms/hardware/biometrics/*.proto",
+    "atoms/hardware/health/*.proto",
     "atoms/hdmi/*.proto",
     "atoms/healthfitness/**/*.proto",
     "atoms/hotword/*.proto",
     "atoms/ike/*.proto",
     "atoms/input/*.proto",
     "atoms/locale/*.proto",
+    "atoms/microxr/*.proto",
     "atoms/wearsysui/*.proto",
     "atoms/location/*.proto",
     "atoms/view/inputmethod/*.proto",
@@ -159,6 +169,7 @@ atom_protos = [
     "atoms/media/*.proto",
     "atoms/adservices/*.proto",
     "atoms/wear/modes/*.proto",
+    "atoms/wear/time/*.proto",
     "atoms/wearpas/*.proto",
     "atoms/statsd/*.proto",
     "atoms/telecomm/*.proto",
@@ -184,6 +195,10 @@ atom_protos = [
     "atoms/adaptiveauth/*.proto",
     "atoms/automotive/carpower/*.proto",
     "atoms/camera/*.proto",
+    "atoms/uprobestats/*.proto",
+    "atoms/broadcasts/*.proto",
+    "atoms/telephony/iwlan/*.proto",
+    "atoms/performance/*.proto",
 ]
 
 cc_library_host_shared {
diff --git a/stats/atoms.proto b/stats/atoms.proto
index 493a2c9f..31b9044d 100644
--- a/stats/atoms.proto
+++ b/stats/atoms.proto
@@ -45,7 +45,7 @@ import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/enums/adservices/fledge/enums.proto";
 import "frameworks/proto_logging/stats/enums/adservices/measurement/enums.proto";
 import "frameworks/proto_logging/stats/enums/anr/enums.proto";
-import "frameworks/proto_logging/stats/enums/app/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/job/job_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/remoteprovisioner_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/settings_enums.proto";
@@ -688,7 +688,7 @@ message Atom {
         ClipboardCleared clipboard_cleared = 408 [(module) = "framework"];
         VmCreationRequested vm_creation_requested = 409 [(module) = "virtualizationservice"];
         NearbyDeviceScanStateChanged nearby_device_scan_state_changed = 410 [(module) = "nearby"];
-        CameraCompatControlEventReported camera_compat_control_event_reported = 411 [(module) = "framework"];
+        // reserved 411 for a deprecated CameraCompatControlEventReported.
         ApplicationLocalesChanged application_locales_changed = 412 [(module) = "framework"];
         MediametricsAudioTrackStatusReported mediametrics_audiotrackstatus_reported =
             413 [(module) = "media_metrics"];
@@ -1232,12 +1232,52 @@ message Atom {
     extensions 898; // SearchDataExtractionDetailsReported search_data_extraction_details_reported
     extensions 899; // EmbeddedPhotopickerInfoReported embedded_photopicker_info_reported
     extensions 900; // CameraFeatureCombinationQueryEvent camera_feature_combination_query_event
+    extensions 901; // MicroXRDeviceBootCompleteReported microxr_device_boot_complete_reported
+    extensions 902; // AdServicesCobaltLoggerEventReported ad_services_cobalt_logger_event_reported
+    extensions 903; // AdServicesCobaltPeriodicJobEventReported ad_services_cobalt_periodic_job_event_reported
+    extensions 904; // A2dpSessionReported a2dp_session_reported
+    extensions 905; // UpdateSignalsProcessReported update_signals_process_reported
+    extensions 906; // DeviceOrientationChanged device_orientation_changed
+    extensions 907; // HealthConnectExportInvoked
+    extensions 908; // CommunalHubWidgetEventReported communal_hub_widget_event_reported
+    extensions 909; // AppSearchAppsIndexerStatsReported app_search_apps_indexer_stats_reported
+    extensions 910; // AccessibilityCheckResultReported accessibility_check_result_reported
+    extensions 911; // WearTimeSyncRequested wear_time_sync_requested
+    extensions 912; // WearTimeUpdateStarted wear_time_update_started
+    extensions 913; // WearTimeSyncAttemptCompleted wear_time_sync_attempt_completed
+    extensions 914; // WearTimeChanged wear_time_changed
+    extensions 915; // TestUprobeStatsAtomReported
+    extensions 916; // BluetoothCrossLayerEventReported bluetooth_cross_layer_event_reported
+    extensions 917; // FirstOverlayStateChanged first_overlay_state_changed
+    extensions 918; // HealthConnectImportInvoked
+    extensions 919; // HealthConnectExportImportStatsReported
+    extensions 920; // WsRemoteEventUsageReported ws_remote_event_usage_reported
+    extensions 921; // WearCompanionConnectionState
+    extensions 922; // BroadcastSent broadcast_sent
+    extensions 923; // IwlanUnderlyingNetworkValidationResultReported iwlan_underlying_network_validation_result_reported
+    extensions 924; // PostGcMemorySnapshot postgc_memory_snapshot
+    extensions 925; // TetheringActiveSessionsReported
+    extensions 926; // PowerSaveTempAllowlistChanged power_save_temp_allowlist_changed
+    extensions 927; // BroadcastAudioSessionReported broadcast_audio_session_reported
+    extensions 928; // BroadcastAudioSyncReported broadcast_audio_sync_reported
+    extensions 929; // ArtDex2OatReported art_dex2oat_reported
+    extensions 930; // TopicsScheduleEpochJobSettingReported topics_schedule_epoch_job_setting_reported
+    extensions 931; // AppOpAccessTracked app_op_access_tracked
+    extensions 932; // InputEventLatencyReported input_event_latency_reported
+    extensions 933; // ContentOrFileUriEventReported content_or_file_uri_event_reported
+    extensions 934; // CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed
+    extensions 935; // DesktopModeTaskSizeUpdated desktop_mode_task_size_updated
+    extensions 936; // WsBugreportRequested ws_bugreport_requested
+    extensions 937; // WsBugreportTriggered ws_bugreport_triggered
+    extensions 938; // WsBugreportFinished ws_bugreport_finished
+    extensions 939; // WsBugreportResultReceived ws_bugreport_result_received
     extensions 9999; // Atom9999 atom_9999
+
     // StatsdStats tracks platform atoms with ids up to 900.
     // Update StatsdStats::kMaxPushedAtomId when atom ids here approach that value.
 
     // Pulled events will start at field 10000.
-    // Next: 10218
+    // Next: 10230
     oneof pulled {
         WifiBytesTransfer wifi_bytes_transfer = 10000 [(module) = "framework"];
         WifiBytesTransferByFgBg wifi_bytes_transfer_by_fg_bg = 10001 [(module) = "framework"];
@@ -1482,7 +1522,7 @@ message Atom {
     extensions 10206; // WsFavouriteWatchFaceSnapshot ws_favorite_watch_face_snapshot
     extensions 10207; // DataNetworkValidation data_network_validation
     // 10208 is reserved due to removing the old atom.
-    extensions 10209; // Reserved for b/324602949
+    extensions 10209; // BatteryUsageStatsPerUid battery_usage_stats_per_uid
     extensions 10210; // Reserved for b/339008431
     extensions 10211; // CarrierRoamingSatelliteSession carrier_roaming_satellite_session
     extensions 10212; // CarrierRoamingSatelliteControllerStats carrier_roaming_satellite_controller_stats
@@ -1493,12 +1533,22 @@ message Atom {
     extensions 10217; // DevicePolicyPolicyState
     extensions 10218; // AdpfSessionSnapshot adpf_session_snapshot
     extensions 10219; // SatelliteAccessController satellite_access_controller
+    extensions 10220; // AndroidHardwareHealthBattery android_hardware_health_battery
+    extensions 10221; // CallStats call_stats
+    extensions 10222; // CallAudioRouteStats call_audio_route_stats
+    extensions 10223; // TelecomApiStats telecom_api_stats
+    extensions 10224; // TelecomErrorStats telecom_error_stats
+    extensions 10225; // WsPhotosWatchFaceFeatureSnapshot ws_photos_watch_face_feature_snapshot
+    extensions 10226; // CommunalHubSnapshot communal_hub_snapshot
+    extensions 10227; // WsWatchFaceCustomizationSnapshot ws_watch_face_customization_snapshot
+    // 10228 is reserved due to removing the old atom
+    extensions 10229; // PressureStallInformation pressure_stall_information
     extensions 99999; // Atom99999 atom_99999
 
     // DO NOT USE field numbers above 100,000 in AOSP.
     // Field numbers 100,000 - 199,999 are reserved for non-AOSP (e.g. OEMs) to use.
     // Field numbers 200,000 and above are reserved for future use; do not use them at all.
-    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 10008, 10036, 10040, 10041, 21004, 21005;
+    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 10008, 10036, 10040, 10041, 10228, 21004, 21005;
 }
 
 /*
@@ -1658,7 +1708,7 @@ message ActivityActionBlocked {
 message UidProcessStateChanged {
     optional int32 uid = 1 [(state_field_option).primary_field = true, (is_uid) = true];
 
-    // The state, from frameworks/proto_logging/stats/enums/app/app_enums.proto.
+    // The state, from frameworks/proto_logging/stats/enums/app_shared/app_enums.proto.
     optional android.app.ProcessStateEnum state = 2
             [(state_field_option).exclusive_state = true, (state_field_option).nested = false];
 }
@@ -1670,12 +1720,12 @@ message UidProcessStateChanged {
  *   frameworks/base/services/core/java/com/android/server/am/ProcessRecord.java
  */
 message ProcessStateChanged {
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     optional string process_name = 2;
     optional string package_name = 3;
     // TODO: remove this when validation is done
     optional int64 version = 5;
-    // The state, from frameworks/proto_logging/stats/enums/app/app_enums.proto.
+    // The state, from frameworks/proto_logging/stats/enums/app_shared/app_enums.proto.
     optional android.app.ProcessStateEnum state = 4;
 }
 
@@ -1783,7 +1833,7 @@ message MemoryFactorStateChanged {
  *   frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
  */
 message ExcessiveCpuUsageReported {
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     optional string process_name = 2;
     optional string package_name = 3;
     // package version. TODO: remove this when validation is done
@@ -1797,7 +1847,7 @@ message ExcessiveCpuUsageReported {
  *   frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
  */
 message CachedKillReported {
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     optional string process_name = 2;
     optional string package_name = 3;
     // TODO: remove this when validation is done
@@ -1846,7 +1896,7 @@ message WifiHealthStatReported {
     optional int32 rx_kbps = 7 [default = -1];
    // External scorer UID if external scorer is enabled. Otherwise WIFI_UID for
    // AOSP scorer.
-   optional int32 scorer_uid = 8;
+   optional int32 scorer_uid = 8 [(is_uid) = true];
    // Whether or not Wi-Fi is predicted as usable by the scorer
    // Note: 'is_wifi_predicted_as_usable' is deprectaed by 'wifi_predicted_usability_state'.
    optional bool is_wifi_predicted_as_usable = 9;
@@ -2305,7 +2355,7 @@ message BedtimeModeStateChanged {
  *   frameworks/base/services/core/java/com/android/server/am/ProcessRecord.java
  */
 message ProcessMemoryStatReported {
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     optional string process_name = 2;
     optional string package_name = 3;
     //TODO: remove this when validation is done
@@ -4487,7 +4537,7 @@ message BluetoothCodePathCounter {
  *
  */
 message BluetoothLeBatchScanReportDelay {
-    optional int32 application_uid = 1;
+    optional int32 application_uid = 1 [(is_uid) = true];
     optional int64 application_report_delay_millis = 2;
 }
 
@@ -5075,7 +5125,7 @@ message AppCrashOccurred {
     // UID of the process that tried to read a page from the app but failed.
     // This shows whether the read was initiated by the system, the app itself, or some other apps.
     // -1 means there was no read error or the app is not installed on Incremental.
-    optional int32 last_read_error_uid = 19;
+    optional int32 last_read_error_uid = 19 [(is_uid) = true];
 
     // Duration since that last read failure.
     // -1 means there was no read error or the app is not installed on Incremental.
@@ -5184,7 +5234,7 @@ message ANROccurred {
     // UID of the process that tried to read a page from the app but failed.
     // This shows whether the read was initiated by the system, the app itself, or some other apps.
     // -1 means there was no read error or the app is not installed on Incremental.
-    optional int32 last_read_error_uid = 19;
+    optional int32 last_read_error_uid = 19 [(is_uid) = true];
 
     // Duration since that last read failure.
     // -1 means there was no read error or the app is not installed on Incremental.
@@ -5232,15 +5282,27 @@ message VibratorStateChanged {
  * Logged from:
  *      frameworks/base/services/core/java/com/android/server/vibrator/VibratorManagerService.java
  */
-// Next tag: 27
+// Next tag: 28
 message VibrationReported {
   repeated AttributionNode attribution_node = 1;
 
   enum VibrationType {
+
+    // Unknown vibration type.
     UNKNOWN = 0;
+
+    // One-off vibration effect/pattern.
     SINGLE = 1;
+
+    // Infinitely repeating vibration pattern.
     REPEATED = 2;
+
+    // Vibration defined in the platform outside the vibrator service
+    // (e.g. from audio-coupled haptics or haptic generator).
     EXTERNAL = 3;
+
+    // Vibration defined by vendor apps/services.
+    VENDOR = 4;
   }
 
   // Vibration identifiers for aggregation.
@@ -5284,6 +5346,7 @@ message VibrationReported {
   optional int32 hal_perform_count = 17;
   optional int32 hal_set_amplitude_count = 18;
   optional int32 hal_set_external_control_count = 19;
+  optional int32 hal_perform_vendor_count = 27;
 
   // Vibrator hardware HAL API constants used (deduped).
   // Values from CompositionPrimitive.aidl successfully triggered by this vibration at least once.
@@ -5655,36 +5718,6 @@ message SizeCompatRestartButtonEventReported {
     optional Event event = 2;
 }
 
-/**
- * Logs events reported for the Camera App Compat control, which is used to
- * correct stretched viewfinder in apps that don't handle all possible
- * configurations, and changes between them, correctly.
- *
- * Logged from:
- *   frameworks/base/services/core/java/com/android/server/wm/ActivityMetricsLogger.java
- */
-message CameraCompatControlEventReported {
-  // UID of the package that has the control.
-  optional int32 uid = 1 [(is_uid) = true];
-
-  enum Event {
-    UNKNOWN = 0;
-    // Button to apply the treatment appeared.
-    APPEARED_APPLY_TREATMENT = 1;
-    // Button to revert the treatment appeared.
-    APPEARED_REVERT_TREATMENT = 2;
-    // Users clicked on the button to apply the treatment.
-    CLICKED_APPLY_TREATMENT = 3;
-    // Users clicked on the button to revert the treatment.
-    CLICKED_REVERT_TREATMENT = 4;
-    // Users clicked on the button to dismiss the control.
-    CLICKED_DISMISS = 5;
-  }
-
-  // The event that was reported.
-  optional Event event = 2;
-}
-
 /**
  * Logs a picture-in-picture action
  * Logged from:
@@ -5758,12 +5791,12 @@ message ForegroundServiceStateChanged {
     // FGS service's targetSdkVersion.
     optional int32 target_sdk_version = 6;
     // uid of the app that start/bind this service.
-    optional int32 calling_uid = 7;
+    optional int32 calling_uid = 7 [(is_uid) = true];
     // targetSdkVersion of the app that start/bind this service.
     optional int32 caller_target_sdk_version = 8;
     // uid of the app that set the temp-allowlist, INVALID_UID (-1) if not in any
     // temp-allowlist.
-    optional int32 temp_allow_list_calling_uid = 9;
+    optional int32 temp_allow_list_calling_uid = 9 [(is_uid) = true];
     // FGS notification was deferred.
     optional bool fgs_notification_deferred = 10;
     // FGS notification was shown before the FGS finishes, or it wasn't deferred in the first place.
@@ -5932,11 +5965,10 @@ message ForegroundServiceAppOpSessionEnded {
  */
 message IsolatedUidChanged {
     // The host UID. Generally, we should attribute metrics from the isolated uid to the host uid.
-    // NOTE: DO NOT annotate uid field in this atom. This atom is specially handled in statsd.
     // This field is ignored when event == REMOVED.
-    optional int32 parent_uid = 1;
+    optional int32 parent_uid = 1 [(is_uid) = true];
 
-    optional int32 isolated_uid = 2;
+    optional int32 isolated_uid = 2 [(is_uid) = true];
 
     // We expect an isolated uid to be removed before if it's used for another parent uid.
     enum Event {
@@ -6382,6 +6414,8 @@ message BiometricAuthenticated {
     optional android.hardware.biometrics.WakeReasonEnum wake_reason = 19;
     // Additional modality-specific details that caused a biometric to be activated (often associated with a device wake_reason).
     repeated android.hardware.biometrics.WakeReasonDetailsEnum wake_reason_details = 20;
+    // If the authentication is due to identity check being enabled
+    optional bool identity_check = 21;
 }
 
 /**
@@ -6433,6 +6467,8 @@ message BiometricErrorOccurred {
     optional android.hardware.biometrics.WakeReasonEnum wake_reason = 19;
     // Additional modality-specific details that caused a biometric to be activated (often associated with a device wake_reason).
     repeated android.hardware.biometrics.WakeReasonDetailsEnum wake_reason_details = 20;
+    // If the authentication is due to identity check being enabled
+    optional bool identity_check = 21;
 }
 
 /**
@@ -6554,7 +6590,7 @@ message AuthEnrollActionInvoked {
      // The deprecated API feature that was used.
      optional APIEnum deprecated_api = 1;
      // The UID of the application that used the deprecated API.
-     optional int32 app_uid = 2;
+     optional int32 app_uid = 2 [(is_uid) = true];
      // The target SDK version (API level) of the application that used the deprecated API.
      optional int32 target_sdk = 3;
  }
@@ -7156,7 +7192,7 @@ message TombStoneOccurred {
  */
 message RoleRequestResultReported {
     // UID of application requesting the role
-    optional int32 requesting_uid = 1;
+    optional int32 requesting_uid = 1 [(is_uid) = true];
 
     // Package name of application requesting the role
     optional string requesting_package_name = 2;
@@ -7168,14 +7204,14 @@ message RoleRequestResultReported {
     optional int32 qualifying_count = 4;
 
     // UID of application current granted the role
-    optional int32 current_uid = 5;
+    optional int32 current_uid = 5 [(is_uid) = true];
 
     // Package name of application current granted the role
     optional string current_package_name = 6;
 
     // UID of another application that user chose to grant the role to, instead of the requesting
     // application
-    optional int32 granted_another_uid = 7;
+    optional int32 granted_another_uid = 7 [(is_uid) = true];
 
     // Package name of another application that user chose to grant the role to, instead of the
     // requesting application
@@ -8584,7 +8620,7 @@ message BinderCalls {
     // If not set, the value will be -1.
     optional int32 uid = 1 [(is_uid) = true];
     // UID of the process executing the binder transaction.
-    optional int32 direct_caller_uid = 14;
+    optional int32 direct_caller_uid = 14 [(is_uid) = true];
     // Fully qualified class name of the API call.
     //
     // This is a system server class name.
@@ -11682,7 +11718,7 @@ message MediametricsAudiotrackReported {
  */
 message MediametricsMidiDeviceCloseReported {
     // The UID of the app or service that disconnects the device
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     // Device Id from MidiDeviceInfo. After a restart, this starts at 1 for the first device.
     // This increments each time a new MIDI device is added.
     // See Id in frameworks/base/media/java/android/media/midi/MidiDeviceInfo.java
@@ -12331,6 +12367,7 @@ message CarPowerStateChanged {
        WAIT_FOR_FINISH = 3;
        SUSPEND = 4;
        SIMULATE_SLEEP = 5;
+       SIMULATE_HIBERNATION = 6;
     }
     optional State state = 1;
 }
@@ -12814,7 +12851,7 @@ message LocationAccessCheckNotificationAction {
     optional int64 session_id = 1;
 
     // Uid of package for which location access check is presented
-    optional int32 package_uid = 2;
+    optional int32 package_uid = 2 [(is_uid) = true];
 
     // Name of package for which location access check is presented
     optional string package_name = 3;
@@ -14746,6 +14783,9 @@ message GraphicsStats {
     // The version code of the app
     optional int64 version_code = 2;
 
+    // The uid of the app
+    optional int32 uid = 17 [(is_uid) = true];
+
     // The start & end timestamps in UTC as
     // milliseconds since January 1, 1970
     // Compatible with java.util.Date#setTime()
@@ -14800,6 +14840,8 @@ message GraphicsStats {
     // day (yesterday). Stats from yesterday stay constant, while stats from today may change as
     // more apps are running / rendering.
     optional bool is_today = 16;
+
+    // next id = 18
 }
 
 /**
@@ -14948,9 +14990,13 @@ message CellBroadcastMessageReported {
     // The source of the report
     optional ReportSource source = 2;
     // The Message Identifier, as defined in 3GPP 23.041 clause 9.4.1.2.1
-    optional int32 serial_number = 3;
+    optional int32 serial_number = 3 [ deprecated = true ];
     // The Message Identifier, as defined in 3GPP 23.041 clause 9.4.1.2.2
     optional int32 message_id = 4;
+    // The roaming case will show mcc value, if not empty string
+    optional string roaming_mcc_mnc = 5;
+    // The language indicator, as defined in ISO 639 language codes set 1
+    optional string language_indicator = 6;
 }
 
 /**
@@ -14996,7 +15042,7 @@ message CellBroadcastMessageFiltered {
     // The source of the report
     optional FilterReason filter = 2;
     // The Message Identifier, as defined in 3GPP 23.041 clause 9.4.1.2.1
-    optional int32 serial_number = 3;
+    optional int32 serial_number = 3 [ deprecated = true ];
     // The Message Identifier, as defined in 3GPP 23.041 clause 9.4.1.2.2
     optional int32 message_id = 4;
 }
@@ -15563,6 +15609,10 @@ message VoiceCallSession {
 
     // The user-set status for enriched calling with call composer
     optional android.telephony.CallComposerStatus call_composer_status = 44;
+
+    // The call state on call setup
+    optional android.telephony.CallState call_state_on_setup = 45;
+
 }
 
 /**
@@ -19686,7 +19736,7 @@ message LongRebootBlockingReported {
     optional string component_name = 2;
 
     // The uid of an app that is running in the background.
-    optional int32 uid = 3;
+    optional int32 uid = 3 [(is_uid) = true];
 }
 
 /**
@@ -20152,7 +20202,7 @@ message AlarmScheduled {
     }
     optional ReasonCode exact_alarm_allowed_reason = 7;
     optional bool is_rtc = 8;
-    // The state of the callingUid, from frameworks/proto_logging/stats/enums/app/app_enums.proto.
+    // The state of the callingUid, from frameworks/proto_logging/stats/enums/app_shared/app_enums.proto.
     optional android.app.ProcessStateEnum calling_process_state = 9;
 }
 
@@ -20284,6 +20334,7 @@ message PermissionUsageFragmentInteraction {
         MICROPHONE_ACCESS_TIMELINE_VIEWED = 4;
         SHOW_SYSTEM_CLICKED = 5;
         SEE_OTHER_PERMISSIONS_CLICKED = 6;
+        SHOW_7DAYS_CLICKED = 7;
     }
 
     // The action the user took to interact with the fragment
@@ -20305,6 +20356,9 @@ message PermissionDetailsInteraction {
         UNDEFINED = 0;
         SHOW_SYSTEM_CLICKED = 1;
         INFO_ICON_CLICKED = 2;
+        TIMELINE_ROW_CLICKED = 3;
+        SHOW_7DAYS_CLICKED = 4;
+        MANAGE_PERMISSIONS_CLICKED = 5;
     }
 
     // Package name for which the info icon was clicked.
@@ -22323,6 +22377,8 @@ message MmsSmsDatabaseHelperOnUpgradeFailed {
  *
  * Logged from:
  * frameworks/base/services/autofill/java/com/android/server/autofill/
+ *
+ * Next ID: 52
  */
 message AutofillPresentationEventReported {
   enum PresentationEventResult {
@@ -22483,6 +22539,10 @@ message AutofillPresentationEventReported {
   // True if the response is from webview requesting credential autofill service.
   optional bool webview_requested_credential = 32;
 
+  // Count of views that are filtered because they are not in current session
+  // before autofill framework calls AutofillManager.autofill().
+  optional int64 views_fillable_excluded_by_session_count = 46;
+
   // Count of views that can be filled as per the provider service.
   // views_fillable_total_count = views_filled_failure_count +
   //     views_filled_success_count + views_with_no_callback
@@ -22541,6 +22601,23 @@ message AutofillPresentationEventReported {
 
   // Length of text already in the field when the event is logged
   optional int32 field_last_length = 45;
+
+  // Count of views that failed prior to refill attempt
+  optional int32 view_failed_prior_to_refill_count = 47;
+
+  // Count of views that were able to be filled during refill
+  // Note that this doesn't include views that were filled successfully prior
+  // to refill.
+  optional int32 view_filled_on_refill_count = 48;
+
+  // Count of views that failed in refill attempt
+  optional int32 view_failed_on_refill_count = 49;
+
+  // Count of times response wasn't expired due to pending authentication.
+  optional int32 fix_expire_response_auth_count = 50;
+
+  // Count of times notifyViewEntered wasn't done due to pending authentication
+  optional int32 notify_view_entered_ignored_auth_count = 51;
 }
 
 // Tells how Autofill dataset was/will-be displayed.
@@ -24328,7 +24405,7 @@ message UnsafeIntentEventReported {
     // Type of matching event.
     optional EventType event_type = 1;
     // The calling UID.
-    optional int32 calling_uid = 2;
+    optional int32 calling_uid = 2 [(is_uid) = true];
     // The component name of the intent.
     optional string component_name = 3;
     // The package name of the intent.
diff --git a/stats/atoms/accessibility/accessibility_extension_atoms.proto b/stats/atoms/accessibility/accessibility_extension_atoms.proto
new file mode 100644
index 00000000..44a3abca
--- /dev/null
+++ b/stats/atoms/accessibility/accessibility_extension_atoms.proto
@@ -0,0 +1,40 @@
+syntax = "proto2";
+
+package android.os.statsd.accessibility;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/accessibility/enums.proto";
+
+option java_package = "com.android.os.accessibility";
+option java_multiple_files = true;
+
+extend Atom {
+    optional AccessibilityCheckResultReported accessibility_check_result_reported = 910
+    [(module) = "accessibility", (restriction_category) = RESTRICTION_DIAGNOSTIC];
+}
+
+/** Logs the result of an AccessibilityCheck. */
+message AccessibilityCheckResultReported {
+    // Package name of the app containing the checked View.
+    optional string package_name = 1;
+    // Version code of the app containing the checked View.
+    optional int64 app_version = 2;
+    // The path of the View starting from the root element in the window. Each element is
+    // represented by the View's resource id, when available, or the View's class name.
+    optional string ui_element_path = 3;
+    // Class name of the activity containing the checked View.
+    optional string activity_name = 4;
+    // Title of the window containing the checked View.
+    optional string window_title = 5;
+    // The flattened component name of the app running the AccessibilityService which provided the a11y node.
+    optional string source_component_name = 6;
+    // Version code of the app running the AccessibilityService that provided the a11y node.
+    optional int64 source_version = 7;
+    // Class Name of the AccessibilityCheck that produced the result.
+    optional android.accessibility.AccessibilityCheckClass result_check_class = 8;
+    // Result type of the AccessibilityCheckResult.
+    optional android.accessibility.AccessibilityCheckResultType result_type = 9;
+    // Result ID of the AccessibilityCheckResult.
+    optional int32 result_id = 10;
+}
diff --git a/stats/atoms/adpf/adpf_atoms.proto b/stats/atoms/adpf/adpf_atoms.proto
index d2b94f2a..60cd4433 100644
--- a/stats/atoms/adpf/adpf_atoms.proto
+++ b/stats/atoms/adpf/adpf_atoms.proto
@@ -23,6 +23,13 @@ enum AdpfSessionTag {
     APP = 4;
 }
 
+enum FmqStatus {
+    OTHER_STATUS = 0;
+    SUPPORTED = 1;
+    UNSUPPORTED = 2;
+    HAL_VERSION_NOT_MET = 3;
+}
+
 /**
  * Logs information related to Android Dynamic Performance Framework (ADPF).
  */
@@ -50,4 +57,7 @@ message ADPFSystemComponentInfo {
 
     // True if HWUI hint is enabled on the device.
     optional bool hwui_hint_enabled = 2;
+
+    // True if FMQ is supported and used on the device.
+    optional FmqStatus fmq_supported = 3;
 }
diff --git a/stats/atoms/adpf/adpf_extension_atoms.proto b/stats/atoms/adpf/adpf_extension_atoms.proto
index 05859ea4..f3c5ff55 100644
--- a/stats/atoms/adpf/adpf_extension_atoms.proto
+++ b/stats/atoms/adpf/adpf_extension_atoms.proto
@@ -149,18 +149,18 @@ message AdpfSessionSnapshot {
     // Uid of the session, this uid is per-app
     optional int32 uid = 1 [(is_uid) = true];
 
-    // Uid process state (foreground, background)
-    optional AdpfSessionUidState uid_state = 2;
+    // Session tag of the snapshot. One uid can generate session with different tags.
+    optional AdpfSessionTag session_tag = 2;
 
-    // Number of threads of this session
-    optional int32 tid_count = 3;
+    // Maximum number of sessions that concurrently existed
+    optional int32 max_concurrent_session = 3;
 
-    // Session tag of this session
-    optional AdpfSessionTag session_tag = 4;
-
-    // Session state (pause, resume)
-    optional AdpfSessionState session_state = 5;
+    // Maximum number of threads created in one session
+    optional int32 max_tid_count = 4;
 
     // Power efficiency mode status
-    optional bool is_power_efficient = 6;
+    optional int32 num_power_efficient_session = 5;
+
+    // list of different target durations requested
+    repeated int64 target_duration_ns = 6;
 }
diff --git a/stats/atoms/adservices/adservices_extension_atoms.proto b/stats/atoms/adservices/adservices_extension_atoms.proto
index 308cf9cd..2ab69688 100644
--- a/stats/atoms/adservices/adservices_extension_atoms.proto
+++ b/stats/atoms/adservices/adservices_extension_atoms.proto
@@ -22,6 +22,7 @@ import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/enums/adservices/common/adservices_enums.proto";
 import "frameworks/proto_logging/stats/enums/adservices/common/adservices_api_metrics_enums.proto";
+import "frameworks/proto_logging/stats/enums/adservices/common/adservices_cel_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/job/job_enums.proto";
 import "frameworks/proto_logging/stats/enums/adservices/enrollment/enums.proto";
 import "frameworks/proto_logging/stats/enums/adservices/measurement/enums.proto";
@@ -205,6 +206,16 @@ extend Atom {
   [(module) = "adservices", (truncate_timestamp) = true];
   optional AdServicesEnrollmentTransactionStats ad_services_enrollment_transaction_stats = 885
   [(module) = "adservices", (truncate_timestamp) = true];
+  optional AdServicesCobaltLoggerEventReported ad_services_cobalt_logger_event_reported = 902
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional AdServicesCobaltPeriodicJobEventReported ad_services_cobalt_periodic_job_event_reported = 903
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional UpdateSignalsProcessReported update_signals_process_reported = 905
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional TopicsScheduleEpochJobSettingReported topics_schedule_epoch_job_setting_reported = 930
+  [(module) = "adservices", (truncate_timestamp) = true];
 }
 
 /**
@@ -276,7 +287,7 @@ message AdServicesMeasurementDebugKeys {
  * Logs AdServices errors/exceptions.
  */
 message AdServicesErrorReported {
-  optional android.adservices.ErrorCode error_code = 1;
+  optional android.adservices.common.ErrorCode error_code = 1;
 
   // Name of the PPAPI if possible where error is occurring.
   optional android.adservices.PpapiName ppapi_name = 2;
@@ -1029,6 +1040,21 @@ message GetAdSelectionDataApiCalled {
 
   // The source of the coordinator used, i.e., DEFAULT or provided via API
   optional android.adservices.service.ServerAuctionCoordinatorSource coordinator_source = 4;
+
+  // Maximum size set by the seller
+  optional int32 seller_max_size_kb = 5;
+
+  // Result of payload optimization
+  optional android.adservices.service.PayloadOptimizationResult payload_optimization_result = 6;
+
+  // Latency of buyer input generation
+  optional int32 input_generation_latency_ms = 7;
+
+  // Version of compressed buyer input creator
+  optional int32 compressed_buyer_input_creator_version = 8;
+
+  // Number of times the entire payload was recompressed to update the current size estimation
+  optional int32 num_re_estimations = 9;
 }
 
 /**
@@ -1428,6 +1454,9 @@ message AdServicesMeasurementRegistrations {
   optional int32 http_response_code = 11;
   optional bool is_redirect = 12;
   optional bool is_pa_request = 13;
+  optional int32 num_entities_deleted = 14;
+  optional bool is_event_level_epsilon_configured = 15;
+  optional bool is_trigger_aggregatable_value_filters_configured = 16;
 }
 
 
@@ -1983,4 +2012,95 @@ message AdServicesApiCalled {
 
   // response_code is the error code for the given api.
   optional int32 response_code = 6;
-}
\ No newline at end of file
+}
+
+/**
+ * Logs Cobalt logging events in AdServices. This provides information about
+ * Cobalt operational metrics.
+ */
+message AdServicesCobaltLoggerEventReported{
+  // The Cobalt metric id of the event that is being logged. The metric id is defined in
+  // packages/modules/AdServices/adservices/libraries/cobalt/proto/metric_definition.proto
+  optional int32 metric_id = 1;
+
+  // The Cobalt report id of the event that is being logged. The report id is defined in
+  // packages/modules/AdServices/adservices/libraries/cobalt/proto/report_definition.proto
+  optional int32 report_id = 2;
+
+  // Logging event which is over the defined threshold in the registry.
+  optional android.adservices.CobaltLoggingEvent cobalt_logging_event = 3;
+}
+
+/**
+ * Logs Cobalt periodic job execution events in AdServices. The periodic job
+ * event contains
+ * Cobalt metrics upload status.
+ */
+message AdServicesCobaltPeriodicJobEventReported {
+  optional android.adservices.CobaltPeriodicJobEvent cobalt_periodic_job_event = 1;
+}
+
+// Logs when updateSignals api is called.
+message UpdateSignalsProcessReported {
+  // The updated signals process latency in milliseconds for this API call.
+  optional int32 update_signals_process_latency_millis = 1;
+
+  // Adservices api status code for this API call.
+  optional int32 adservices_api_status_code = 2;
+
+  // Number of signals written for this API call.
+  optional int32 signals_written_count = 3;
+
+  // Number of keys from downloaded JSON for this API call.
+  optional int32 keys_stored_count = 4;
+
+  // Number of values from downloaded JSON for this API call.
+  optional int32 values_stored_count = 5;
+
+  // Number of eviction rules for this API call.
+  optional int32 eviction_rules_count = 6;
+
+  // The bucketed size of the buyer who called the APIs signals.
+  optional android.adservices.service.Size per_buyer_signal_size = 7;
+
+  // The average size of raw protected signals per buyer in bytes.
+  optional float mean_raw_protected_signals_size_bytes = 8;
+
+  // The maximum size of raw protected signals per buyer in bytes.
+  optional float max_raw_protected_signals_size_bytes = 9;
+
+  // The minimum size of raw protected signals per buyer in bytes.
+  optional float min_raw_protected_signals_size_bytes = 10;
+}
+
+/** Logs for Topics epoch job setting during scheduling EpochJobService. */
+message TopicsScheduleEpochJobSettingReported {
+  // Status when forcing reschedule EpochJob.
+  enum RescheduleEpochJobStatus {
+    STATUS_UNSET = 0;
+    RESCHEDULE_SUCCESS = 1;
+    SKIP_RESCHEDULE_EMPTY_JOB_SCHEDULER = 2;
+    SKIP_RESCHEDULE_EMPTY_PENDING_JOB = 3;
+  }
+
+  // Epoch job setting of the EpochJob.
+  enum EpochJobBatteryConstraint {
+    UNKNOWN_SETTING = 0;
+    REQUIRES_CHARGING = 1;
+    REQUIRES_BATTERY_NOT_LOW = 2;
+  }
+
+  // Status when forcing reschedule EpochJob.
+  optional RescheduleEpochJobStatus reschedule_epoch_job_status = 1;
+
+  // The previous epoch job setting.
+  // This field will be UNKNOWN_SETTING when reschedule_epoch_job_status is not RESCHEDULE_SUCCESS.
+  optional EpochJobBatteryConstraint previous_epoch_job_setting = 2;
+
+  // The current epoch job setting.
+  // This field will be UNKNOWN_SETTING when reschedule_epoch_job_status is not RESCHEDULE_SUCCESS.
+  optional EpochJobBatteryConstraint current_epoch_job_setting = 3;
+
+  // The epoch job setting when scheduling the epoch job in EpochJobService.scheduleIfNeeded().
+  optional EpochJobBatteryConstraint schedule_if_needed_epoch_job_status = 4;
+}
diff --git a/stats/atoms/agif/agif_atoms.proto b/stats/atoms/agif/agif_atoms.proto
index 3a8848ef..fe6c9b9e 100644
--- a/stats/atoms/agif/agif_atoms.proto
+++ b/stats/atoms/agif/agif_atoms.proto
@@ -19,7 +19,7 @@ syntax = "proto2";
 package android.os.statsd.agif;
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/enums/app/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 
 option java_package = "com.android.os.agif";
 option java_multiple_files = true;
diff --git a/stats/atoms/appsearch/appsearch_extension_atoms.proto b/stats/atoms/appsearch/appsearch_extension_atoms.proto
index ef694a1a..a6f60d52 100644
--- a/stats/atoms/appsearch/appsearch_extension_atoms.proto
+++ b/stats/atoms/appsearch/appsearch_extension_atoms.proto
@@ -37,6 +37,9 @@ extend Atom {
   optional AppSearchUsageSearchIntentRawQueryStatsReported
           app_search_usage_search_intent_raw_query_stats_reported = 826
           [(module) = "appsearch", (restriction_category) = RESTRICTION_SYSTEM_INTELLIGENCE];
+
+  optional AppSearchAppsIndexerStatsReported
+          app_search_apps_indexer_stats_reported = 909 [(module) = "appsearch"];
 }
 
 /**
@@ -261,3 +264,44 @@ message AppSearchUsageSearchIntentRawQueryStatsReported {
     // intent.
     optional android.appsearch.QueryCorrectionType query_correction_type = 8;
 }
+
+/**
+ * Reported when AppSearch Apps Indexer syncs apps from PackageManager to AppSearch.
+ *
+ * Logged from:
+ *   packages/modules/AppSearch/service/java/com/android/server/appsearch/appsindexer/AppsIndexerManagerService.java
+ * Estimated Logging Rate:
+ *    Peak: 20 times in 10*1000 ms | Avg: 1 per device per day
+ *
+ * Next tag: 14
+ */
+message AppSearchAppsIndexerStatsReported {
+  enum UpdateType {
+    UNKNOWN = 0;
+    FULL = 1;
+  }
+
+  // Type of the update. An additional "package intent" update type may be added
+  optional UpdateType update_type = 1;
+
+  // Status codes for inserting/updating apps. If everything succeeds, this only contains [0]. If
+  // something fails, this contains all the error codes we got.
+  repeated int32 update_status_codes = 2;
+
+  // Update counts
+  optional int32 number_of_apps_added = 3;
+  optional int32 number_of_apps_removed = 4;
+  optional int32 number_of_apps_updated = 5;
+  optional int32 number_of_apps_unchanged = 6;
+
+  // Latencies
+  optional int64 total_latency_millis = 7;
+  optional int64 package_manager_latency_millis = 8;
+  optional int64 get_all_apps_from_appsearch_latency_millis = 9;
+  optional int64 set_schema_for_all_apps_latency_millis = 10;
+  optional int64 index_all_apps_to_appsearch_latency_millis = 11;
+
+  // Timestamps
+  optional int64 update_start_wallclock_timestamp_millis = 12;
+  optional int64 last_app_updated_wallclock_timestamp_millis = 13;
+}
diff --git a/stats/atoms/art/art_extension_atoms.proto b/stats/atoms/art/art_extension_atoms.proto
index 127b1186..0e8d3586 100644
--- a/stats/atoms/art/art_extension_atoms.proto
+++ b/stats/atoms/art/art_extension_atoms.proto
@@ -4,6 +4,8 @@ package android.os.statsd.art;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/art/art_enums.proto";
+import "frameworks/proto_logging/stats/enums/art/common_enums.proto";
 
 option java_package = "com.android.os.art";
 option java_multiple_files = true;
@@ -14,219 +16,12 @@ extend Atom {
     // Deprecated in favour of the ArtDeviceStatus pulled atom
     optional ArtDeviceDatumReported art_device_datum_reported = 550 [(module) = "art", deprecated = true];
     optional ArtDatumDeltaReported art_datum_delta_reported = 565 [(module) = "art"];
+    optional ArtDex2OatReported art_dex2oat_reported = 929 [(module) = "art"];
 
     // Pulled atoms
     optional ArtDeviceStatus art_device_status = 10205 [(module) = "art"];
 }
 
-// Indicates which compile filter was used for the package being loaded in an ART session.
-enum ArtCompileFilter {
-    ART_COMPILATION_FILTER_UNSPECIFIED = 0;
-    ART_COMPILATION_FILTER_ERROR = 1;
-    ART_COMPILATION_FILTER_UNKNOWN = 2;
-    ART_COMPILATION_FILTER_ASSUMED_VERIFIED = 3;
-    ART_COMPILATION_FILTER_EXTRACT = 4;
-    ART_COMPILATION_FILTER_VERIFY = 5;
-    ART_COMPILATION_FILTER_QUICKEN = 6;
-    ART_COMPILATION_FILTER_SPACE_PROFILE = 7;
-    ART_COMPILATION_FILTER_SPACE = 8;
-    ART_COMPILATION_FILTER_SPEED_PROFILE = 9;
-    ART_COMPILATION_FILTER_SPEED = 10;
-    ART_COMPILATION_FILTER_EVERYTHING_PROFILE = 11;
-    ART_COMPILATION_FILTER_EVERYTHING = 12;
-    ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK = 13;
-    ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK_FALLBACK = 14;
-    ART_COMPILATION_FILTER_FAKE_RUN_FROM_VDEX_FALLBACK = 15;
-}
-
-// Indicates what triggered the compilation of the package.
-enum ArtCompilationReason {
-    ART_COMPILATION_REASON_UNSPECIFIED = 0;
-    ART_COMPILATION_REASON_ERROR = 1;
-    ART_COMPILATION_REASON_UNKNOWN = 2;
-    ART_COMPILATION_REASON_FIRST_BOOT = 3;
-    ART_COMPILATION_REASON_BOOT = 4;
-    ART_COMPILATION_REASON_INSTALL = 5;
-    ART_COMPILATION_REASON_BG_DEXOPT = 6;
-    ART_COMPILATION_REASON_AB_OTA = 7;
-    ART_COMPILATION_REASON_INACTIVE = 8;
-    ART_COMPILATION_REASON_SHARED = 9;
-    ART_COMPILATION_REASON_INSTALL_WITH_DEX_METADATA = 10;
-    ART_COMPILATION_REASON_POST_BOOT = 11;
-    ART_COMPILATION_REASON_INSTALL_FAST = 12;
-    ART_COMPILATION_REASON_INSTALL_BULK = 13;
-    ART_COMPILATION_REASON_INSTALL_BULK_SECONDARY = 14;
-    ART_COMPILATION_REASON_INSTALL_BULK_DOWNGRADED = 15;
-    ART_COMPILATION_REASON_INSTALL_BULK_SECONDARY_DOWNGRADED = 16;
-    ART_COMPILATION_REASON_BOOT_AFTER_OTA = 17;
-    ART_COMPILATION_REASON_PREBUILT = 18;
-    ART_COMPILATION_REASON_CMDLINE = 19;
-    ART_COMPILATION_REASON_VDEX = 20;
-    ART_COMPILATION_REASON_BOOT_AFTER_MAINLINE_UPDATE = 21;
-}
-
-// Indicates which kind of measurement ART is reporting.
-//
-// Where it makes sense, the datum ID ends with the type of datum (counter or histogram) and the
-// units.
-// Note: Histograms are not yet reported by statsd.
-enum ArtDatumId {
-    ART_DATUM_INVALID = 0;
-    ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS = 1;
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_TIME_HISTO_MILLIS = 2;
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_COUNT = 3;
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_TIME_HISTO_MILLIS = 4;
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_COUNT = 5;
-    ART_DATUM_JIT_METHOD_COMPILE_TIME_MICROS = 6;
-    ART_DATUM_AOT_COMPILE_TIME = 7;
-    ART_DATUM_CLASS_VERIFICATION_TIME_COUNTER_MICROS = 8;
-    ART_DATUM_CLASS_LOADING_TIME_COUNTER_MICROS = 9;
-
-    // Metrics IDs for dex2oat.
-    ART_DATUM_DEX2OAT_RESULT_CODE = 10 [deprecated = true];
-    ART_DATUM_DEX2OAT_DEX_CODE_COUNTER_BYTES = 11 [deprecated = true];
-    ART_DATUM_DEX2OAT_TOTAL_TIME_COUNTER_MILLIS = 12 [deprecated = true];
-    ART_DATUM_DEX2OAT_VERIFY_DEX_FILE_TIME_COUNTER_MILLIS = 13 [deprecated = true];
-    ART_DATUM_DEX2OAT_FAST_VERIFY_TIME_COUNTER_MILLIS = 14 [deprecated = true];
-    ART_DATUM_DEX2OAT_RESOLVE_METHODS_AND_FIELDS_TIME_COUNTER_MILLIS = 15 [deprecated = true];
-
-    ART_DATUM_CLASS_VERIFICATION_COUNT = 16;
-    ART_DATUM_GC_TOTAL_BYTES_ALLOCATED = 17;
-    ART_DATUM_GC_TOTAL_METADATA_SIZE_BYTES = 18 [deprecated=true];
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_HISTO_MB_PER_SEC = 19;
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_HISTO_MB_PER_SEC = 20;
-    ART_DATUM_JIT_METHOD_COMPILE_COUNT = 21;
-    ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_HISTO_MB_PER_SEC = 22;
-    ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_HISTO_MB_PER_SEC = 23;
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC = 24;
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC = 25;
-    ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC = 26;
-    ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC = 27;
-    ART_DATUM_GC_TOTAL_COLLECTION_TIME_MS = 28;
-
-    // New metrics to support averages reported as sum (numerator) and count (denominator),
-    // in order to make it easier to be reported as Value Metrics.
-
-    // numerator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
-    ART_DATUM_GC_WORLD_STOP_TIME_US = 29;
-    // denominator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
-    ART_DATUM_GC_WORLD_STOP_COUNT = 30;
-    // numerator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_SCANNED_BYTES = 31;
-    // numerator from ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_FREED_BYTES = 32;
-    // denominator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    // and ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_DURATION_MS = 33;
-    // numerator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_SCANNED_BYTES = 34;
-    // numerator from ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_FREED_BYTES = 35;
-    // denominator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    // and ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_GC_FULL_HEAP_COLLECTION_DURATION_MS = 36;
-}
-
-// Indicates which kind of measurement ART is reporting as increments / deltas.
-// Next ID: 37
-enum ArtDatumDeltaId {
-    ART_DATUM_DELTA_INVALID = 0;
-
-    // These IDs are the equivalent of the ArtDatumId values,
-    // but for reporting increments / deltas.
-    ART_DATUM_DELTA_CLASS_VERIFICATION_COUNT = 16;
-    ART_DATUM_DELTA_CLASS_VERIFICATION_TIME_MICROS = 8;
-    ART_DATUM_DELTA_CLASS_LOADING_TIME_MICROS = 9;
-    ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_COUNT = 5;
-    ART_DATUM_DELTA_GC_TOTAL_BYTES_ALLOCATED = 17;
-    ART_DATUM_DELTA_GC_TOTAL_COLLECTION_TIME_MS = 28;
-    ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_COUNT = 3;
-    ART_DATUM_DELTA_JIT_METHOD_COMPILE_COUNT = 21;
-    ART_DATUM_DELTA_JIT_METHOD_COMPILE_TIME_MICROS = 6;
-
-    // numerator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
-    ART_DATUM_DELTA_GC_WORLD_STOP_TIME_US = 29;
-    // denominator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
-    ART_DATUM_DELTA_GC_WORLD_STOP_COUNT = 30;
-    // numerator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_SCANNED_BYTES = 31;
-    // numerator from ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_FREED_BYTES = 32;
-    // denominator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    // and ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_DURATION_MS = 33;
-    // numerator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_SCANNED_BYTES = 34;
-    // numerator from ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_FREED_BYTES = 35;
-    // denominator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
-    // and ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
-    ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_DURATION_MS = 36;
-    // The number of milliseconds since the last time metrics were reported.
-    ART_DATUM_DELTA_TIME_ELAPSED_MS = 37;
-
-    reserved 1, 2, 4, 7, 10, 11, 12, 13, 14, 15, 18, 19, 20, 22, 23, 24, 25, 26, 27;
-}
-
-// DEPRECATED - Used to indicate what class of thread the reported values apply to.
-// Deprecated in Jan 2024 as the corresponding filter is no longer needed.
-enum ArtThreadType {
-    ART_THREAD_UNKNOWN = 0;
-    ART_THREAD_MAIN = 1;
-    ART_THREAD_BACKGROUND = 2;
-}
-
-// DEPRECATED - Used to indicate the type of dex metadata.
-// Deprecated in Jan 2024 as the corresponding filter is no longer needed.
-enum ArtDexMetadataType {
-  ART_DEX_METADATA_TYPE_UNKNOWN = 0;
-  ART_DEX_METADATA_TYPE_PROFILE = 1;
-  ART_DEX_METADATA_TYPE_VDEX = 2;
-  ART_DEX_METADATA_TYPE_PROFILE_AND_VDEX = 3;
-  ART_DEX_METADATA_TYPE_NONE = 4;
-  ART_DEX_METADATA_TYPE_ERROR = 5;
-}
-
-// DEPRECATED - Used to indicate the type of the apk.
-// Deprecated in Jan 2024 as the corresponding filter is no longer needed.
-enum ArtApkType {
-    ART_APK_TYPE_UNKNOWN = 0;
-    ART_APK_TYPE_BASE = 1;
-    ART_APK_TYPE_SPLIT = 2;
-}
-
-// Indicates the ISA.
-enum ArtIsa {
-    ART_ISA_UNKNOWN = 0;
-    ART_ISA_ARM = 1;
-    ART_ISA_ARM64 = 2;
-    ART_ISA_X86 = 3;
-    ART_ISA_X86_64 = 4;
-    ART_ISA_MIPS = 5;
-    ART_ISA_MIPS64 = 6;
-    ART_ISA_RISCV64 = 7;
-}
-
-// Indicates the GC collector type.
-enum ArtGcCollectorType {
-    ART_GC_COLLECTOR_TYPE_UNKNOWN = 0;
-    ART_GC_COLLECTOR_TYPE_MARK_SWEEP = 1;
-    ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_SWEEP = 2;
-    ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_COMPACT = 3;
-    ART_GC_COLLECTOR_TYPE_SEMI_SPACE = 4;
-    ART_GC_COLLECTOR_TYPE_CONCURRENT_COPYING = 5;
-    ART_GC_COLLECTOR_TYPE_CONCURRENT_COPYING_BACKGROUND = 6;
-    ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_COMPACT_BACKGROUND = 7;
-}
-
-// Indicates support for userfaultfd and minor fault mode.
-enum ArtUffdSupport {
-    ART_UFFD_SUPPORT_UNKNOWN = 0;
-    ART_UFFD_SUPPORT_UFFD_NOT_SUPPORTED = 1;
-    ART_UFFD_SUPPORT_MINOR_FAULT_MODE_NOT_SUPPORTED = 2;
-    ART_UFFD_SUPPORT_MINOR_FAULT_MODE_SUPPORTED = 3;
-}
-
 message ArtDatumReported {
     // The session ID is used to correlate this report with others from the same ART instance.
     optional int64 session_id = 1;
@@ -311,6 +106,41 @@ message ArtDatumDeltaReported {
     optional ArtUffdSupport uffd_support = 13;
 }
 
+message ArtDex2OatReported {
+    // The UID of the app that ART is running on behalf of.
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // The target compiler filter, passed as the `--compiler-filer` option to dex2oat.
+    optional ArtCompileFilter compiler_filter = 2;
+
+    // The compilation reason, passed as the `--compilation-reason` option to dex2oat.
+    optional ArtCompilationReason compilation_reason = 3;
+
+    // The type of DM file.
+    optional ArtDexMetadataType dex_metadata_type = 4;
+
+    // The type of the APK file.
+    optional ArtApkType apk_type = 5;
+
+    // The ISA (instruction set architecture) of the device.
+    optional ArtIsa isa = 6;
+
+    // Status for the dex2oat run.
+    optional ExecResultStatus result_status = 7;
+
+    // Exit code for the dex2oat run if status is EXEC_RESULT_STATUS_EXITED, else -1.
+    optional int32 result_exit_code = 8;
+
+    // Signal for the dex2oat run if status is EXEC_RESULT_STATUS_SIGNALED, else 0.
+    optional int32 result_signal = 9;
+
+    // Total size of dex2oat artifacts, in kilobytes.
+    optional int32 artifacts_size_kb = 10;
+
+    // Total compilation time, in milliseconds.
+    optional int32 compilation_time_millis = 11;
+}
+
 /**
  * Logs ART metrics that are device-specific (as opposed to app-specific ones logged by
  * ArtDatumReported).
@@ -319,17 +149,6 @@ message ArtDatumDeltaReported {
  *   art/runtime/metrics/statsd.cc
  */
  message ArtDeviceDatumReported {
-    enum BootImageStatus {
-        // Unknown value.
-        STATUS_UNSPECIFIED = 0;
-        // Boot image(s) are fully usable.
-        STATUS_FULL = 1;
-        // Only the minimal boot image is usable.
-        STATUS_MINIMAL = 2;
-        // No boot image is usable.
-        STATUS_NONE = 3;
-    }
-
     optional BootImageStatus boot_image_status = 1;
 }
 
@@ -338,15 +157,5 @@ message ArtDatumDeltaReported {
  * ArtDatumReported).
  */
 message ArtDeviceStatus {
-    enum BootImageStatus {
-        // Unknown value.
-        STATUS_UNSPECIFIED = 0;
-        // Boot image(s) are fully usable.
-        STATUS_FULL = 1;
-        // Only the minimal boot image is usable.
-        STATUS_MINIMAL = 2;
-        // No boot image is usable.
-        STATUS_NONE = 3;
-    }
     optional BootImageStatus boot_image_status = 1;
 }
diff --git a/stats/atoms/art/background_extension_dexopt_atoms.proto b/stats/atoms/art/background_dexopt_extension_atoms.proto
similarity index 100%
rename from stats/atoms/art/background_extension_dexopt_atoms.proto
rename to stats/atoms/art/background_dexopt_extension_atoms.proto
diff --git a/stats/atoms/art/odrefresh_extension_atoms.proto b/stats/atoms/art/odrefresh_extension_atoms.proto
index 273b2f67..0c0f7226 100644
--- a/stats/atoms/art/odrefresh_extension_atoms.proto
+++ b/stats/atoms/art/odrefresh_extension_atoms.proto
@@ -4,6 +4,8 @@ package android.os.statsd.art;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/art/common_enums.proto";
+import "frameworks/proto_logging/stats/enums/art/odrefresh_enums.proto";
 
 option java_package = "com.android.os.art";
 option java_multiple_files = true;
@@ -22,83 +24,9 @@ extend Atom {
  */
  message OdrefreshReported {
     optional int64 art_apex_version = 1;
-
-    // Keep in sync with the Trigger enum defined in art/odrefresh/odr_metrics.h
-    enum Trigger {
-        // A placeholder for unknown values.
-        TRIGGER_UNKNOWN = 0;
-
-        // ART APEX version has changed since time artifacts were generated.
-        TRIGGER_APEX_VERSION_MISMATCH = 1;
-
-        // Dex files on the boot classpath or system_server classpath have changed.
-        TRIGGER_DEX_FILES_CHANGED = 2;
-
-        // Missing artifacts.
-        TRIGGER_MISSING_ARTIFACTS = 3;
-    }
-
-    optional Trigger trigger = 2;
-
-    // Keep in sync with the Stage enum defined in art/odrefresh/odr_metrics.h
-    enum Stage {
-        // A placeholder for unknown values.
-        STAGE_UNKNOWN = 0;
-
-        // Checking stage.
-        STAGE_CHECK = 10;
-
-        // Preparation for compilation.
-        STAGE_PREPARATION = 20;
-
-        // Compilation of the boot classpath for the primary architecture
-        // ("primary boot classpath").
-        STAGE_PRIMARY_BOOT_CLASSPATH = 30;
-
-        // Compilation of the boot classpath for the secondary architecture
-        // ("secondary boot classpath"), if any.
-        STAGE_SECONDARY_BOOT_CLASSPATH = 40;
-
-        // Compilation of system_server classpath.
-        STAGE_SYSTEM_SERVER_CLASSPATH = 50;
-
-        // All stages completed.
-        STAGE_COMPLETE = 60;
-    }
-
-    optional Stage stage_reached = 3;
-
-    // Keep in sync with the Status enum defined in art/odrefresh/odr_metrics.h
-    enum Status {
-        // A placeholder for unknown values.
-        STATUS_UNKNOWN = 0;
-
-        // OK, no problems encountered.
-        STATUS_OK = 1;
-
-        // Insufficient space.
-        STATUS_NO_SPACE = 2;
-
-        // Storage operation failed.
-        STATUS_IO_ERROR = 3;
-
-        // Dex2oat reported an error.
-        STATUS_DEX2OAT_ERROR = 4;
-
-        reserved 5; // was STATUS_TIME_LIMIT_EXCEEDED
-
-        // Failure creating staging area.
-        STATUS_STAGING_FAILED = 6;
-
-        // Installation of artifacts failed.
-        STATUS_INSTALL_FAILED = 7;
-
-        // Failed to access the dalvik-cache directory due to lack of
-        // permission.
-        STATUS_DALVIK_CACHE_PERMISSION_DENIED = 8;
-    }
-
-    optional Status status = 4;
+    optional OdrefreshTrigger trigger = 2;
+    optional OdrefreshStage stage_reached = 3;
+    optional OdrefreshStatus status = 4;
 
     // Compilation time of the boot classpath for the primary architecture
     // ("primary boot classpath"), in seconds.
@@ -128,22 +56,6 @@ extend Atom {
     // Compilation time of system_server classpath, in milliseconds.
     optional int32 system_server_compilation_millis = 12;
 
-    // Keep in sync with the ExecResult enum defined in art/runtime/exec_utils.h
-    enum ExecResultStatus {
-        // Unable to get the status.
-        EXEC_RESULT_STATUS_UNKNOWN = 0;
-        // Process exited normally with an exit code.
-        EXEC_RESULT_STATUS_EXITED = 1;
-        // Process terminated by a signal.
-        EXEC_RESULT_STATUS_SIGNALED = 2;
-        // Process timed out and killed.
-        EXEC_RESULT_STATUS_TIMED_OUT = 3;
-        // Failed to start the process.
-        EXEC_RESULT_STATUS_START_FAILED = 4;
-        // Process was not run.
-        EXEC_RESULT_STATUS_NOT_RUN = 5;
-    }
-
     // Status for the compilation of the boot
     // classpath for the primary architecture.
     optional ExecResultStatus primary_bcp_dex2oat_result_status = 13;
@@ -179,17 +91,8 @@ extend Atom {
     // system_server if status is EXEC_RESULT_STATUS_SIGNALED, else 0.
     optional int32 system_server_dex2oat_result_signal = 21;
 
-    // Keep in sync with the BcpCompilationType enum defined in art/odrefresh/odr_metrics.h
-    enum BcpCompilationType {
-        BCP_COMPILATION_TYPE_UNKNOWN = 0;
-        // Compiles for both the primary boot image and the mainline extension.
-        BCP_COMPILATION_TYPE_PRIMARY_AND_MAINLINE = 1;
-        // Only compiles for the mainline extension.
-        BCP_COMPILATION_TYPE_MAINLINE = 2;
-    }
-
-    optional BcpCompilationType primary_bcp_compilation_type = 22;
-    optional BcpCompilationType secondary_bcp_compilation_type = 23;
+    optional OdrefreshBcpCompilationType primary_bcp_compilation_type = 22;
+    optional OdrefreshBcpCompilationType secondary_bcp_compilation_type = 23;
 };
 
 /**
@@ -222,4 +125,4 @@ extend Atom {
     }
 
     optional Status status = 1;
-}
\ No newline at end of file
+}
diff --git a/stats/atoms/autofill/autofill_extension_atoms.proto b/stats/atoms/autofill/autofill_extension_atoms.proto
index b11151b0..2a547d9c 100644
--- a/stats/atoms/autofill/autofill_extension_atoms.proto
+++ b/stats/atoms/autofill/autofill_extension_atoms.proto
@@ -204,7 +204,7 @@ message AutofillSaveEventReported {
  */
 message AutofillSessionCommitted {
   optional int32 session_id = 1;
-  optional int32 component_package_uid = 2;
+  optional int32 component_package_uid = 2 [(is_uid) = true];
   optional int64 request_count = 3;
   // Commit reason
   optional AutofillCommitReason commit_reason = 4;
diff --git a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
index 64fcc447..5422c71d 100644
--- a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
+++ b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
@@ -62,6 +62,14 @@ extend Atom {
         = 874 [(module) = "bluetooth"];
     optional LeAdvErrorReported le_adv_error_reported
         = 875 [(module) = "bluetooth"];
+    optional A2dpSessionReported a2dp_session_reported
+        = 904 [(module) = "bluetooth"];
+    optional BluetoothCrossLayerEventReported bluetooth_cross_layer_event_reported
+        = 916 [(module) = "bluetooth"];
+    optional BroadcastAudioSessionReported broadcast_audio_session_reported
+        = 927 [(module) = "bluetooth"];
+    optional BroadcastAudioSyncReported broadcast_audio_sync_reported
+        = 928 [(module) = "bluetooth"];
 }
 
 /**
@@ -285,6 +293,9 @@ message BluetoothRemoteDeviceInformation {
 
   // The first three bytes of MAC address
   optional int32 oui = 3;
+
+  // Device type metadata
+  optional android.bluetooth.RemoteDeviceTypeMetadata device_type_metadata = 4;
 }
 
 /**
@@ -372,7 +383,7 @@ message LeAppScanStateChanged {
 message LeRadioScanStopped {
   // Attribution of the app with most aggressive scanning parameters, which
   // will be used by the LE radio for the scanning.
-  repeated AttributionNode attribution_node_most_aggressive_app = 1;
+  repeated AttributionNode attribution_node = 1;
   optional android.bluetooth.le.LeScanType le_scan_type_most_aggressive_app = 2;
   optional android.bluetooth.le.LeScanMode le_scan_mode_most_aggressive_app = 3;
   // Radio scan interval in milliseconds.
@@ -467,3 +478,131 @@ message LeAdvErrorReported {
   // The status code of internal state.
   optional android.bluetooth.le.LeAdvStatusCode status_code = 3;
 }
+
+/**
+ * Logs A2DP session information when the session ends.
+ *
+ * Logged from:
+ *     packages/modules/Bluetooth
+ */
+message A2dpSessionReported {
+  // Full duration of the session in milliseconds.
+  optional int64 duration_ms = 1;
+  // Minimum duration of the media timer in milliseconds.
+  optional int32 min_timer_duration_ms = 2;
+  // Maximum duration of the media timer in milliseconds.
+  optional int32 max_timer_duration_ms = 3;
+  // Average duration of the media timer in milliseconds.
+  optional int32 average_timer_duration_ms = 4;
+  // Total number of times the media timer was scheduled.
+  optional int32 total_scheduling_count = 5;
+  // Counts the maximum number of audio frames dropped simultaneously due
+  // to TX buffer overruns during the session.
+  optional int32 max_buffer_overrun = 6;
+  // Counts the total number of audio frames that were dropped due to TX buffer
+  // overruns during the session.
+  optional int32 total_buffer_overrun = 7;
+  // Counts the average number of bytes of underflow when reading fromt the
+  // PCM audio stream.
+  optional float average_buffer_underrun = 8;
+  // Total number of bytes of underflow when reading from the PCM audio stream.
+  optional int32 total_buffer_underrun = 9;
+  // Unique identifier of the codec used for the session. The codec identifier
+  // is 40 bits,
+  // - Bits 0-7: Audio Codec ID, as defined by [ID 6.5.1]
+  //    0x00: SBC
+  //    0x02: AAC
+  //    0xFF: Vendor
+  // - Bits 8-23: Company ID, set to 0, if octet 0 is not 0xFF.
+  // - Bits 24-39: Vendor-defined codec ID, set to 0, if octet 0 is not 0xFF.
+  optional int64 codec_id = 10;
+  // Indicates whether the session is offloaded or not.
+  optional bool offload = 11;
+}
+
+/**
+  * Logs a Bluetooth Event
+  *
+  * Logged from:
+  *     packages/modules/Bluetooth
+*/
+message BluetoothCrossLayerEventReported {
+  // Type of Bluetooth Event
+  optional android.bluetooth.EventType event_type = 1;
+
+  // Addition Details about the event, specific to the event type
+  optional android.bluetooth.State state = 2;
+
+  // Identifier for the app that initiates the CUJ (if applicable)
+  optional int32 uid = 3 [(is_uid) = true];
+
+  // Identifier for the remote device/metric id
+  optional int32 metric_id = 4;
+
+  // Remote Device Information
+  optional BluetoothRemoteDeviceInformation remote_device_information = 5
+     [(log_mode) = MODE_BYTES];
+}
+
+/**
+  * Logs LE Audio Broadcast Audio Session
+  *
+  * Logged from:
+  *     packages/modules/Bluetooth
+*/
+message BroadcastAudioSessionReported {
+  // Identifier randomly generated for every broadcast session
+  // Default: -1 if the broadcast id is unknown
+  optional int32 broadcast_id = 1;
+
+  // Number of audio groups in this broadcast session
+  optional int32 audio_group_size = 2;
+
+  // Broadcast audio quality configuration for all subgroups
+  repeated android.bluetooth.BroadcastAudioQualityType audio_quality = 3;
+
+  // Number of devices in this broadcast session
+  optional int32 group_size = 4;
+
+  // Broadcast session duration
+  optional int64 duration_ms = 5;
+
+  // Broadcast session in configured state latency
+  optional int64 latency_broadcast_configured_ms = 6;
+
+  // Broadcast session in streaming state latency
+  optional int64 latency_broadcast_streaming_ms = 7;
+
+  // Status of broadcast session setup
+  optional android.bluetooth.BroadcastSessionSetupStatus session_setup_status = 8;
+}
+
+/**
+  * Logs LE Audio Broadcast Audio Sync
+  *
+  * Logged from:
+  *     packages/modules/Bluetooth
+*/
+message BroadcastAudioSyncReported {
+  // Identifier randomly generated for every broadcast session
+  // Default: -1 if the broadcast id is unknown
+  optional int32 broadcast_id = 1;
+
+  // Local broadcast or external broadcast
+  optional bool is_local_broadcast = 2;
+
+  // Broadcast session duration
+  optional int64 duration_ms = 3;
+
+  // Latency from adding source to PA synced
+  optional int64 latency_pa_sync_ms = 4;
+
+  // Latency from adding source to BIS synced
+  optional int64 latency_bis_sync_ms = 5;
+
+  // Status of broadcast sync
+  optional android.bluetooth.BroadcastSyncStatus sync_status = 6;
+
+  // Remote Device Information
+  optional BluetoothRemoteDeviceInformation remote_device_information = 7 [(log_mode) = MODE_BYTES];
+}
\ No newline at end of file
diff --git a/stats/atoms/broadcasts/broadcasts_extension_atoms.proto b/stats/atoms/broadcasts/broadcasts_extension_atoms.proto
new file mode 100644
index 00000000..fc624fae
--- /dev/null
+++ b/stats/atoms/broadcasts/broadcasts_extension_atoms.proto
@@ -0,0 +1,79 @@
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
+package android.os.statsd.broadcasts;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
+
+option java_package = "com.android.os.broadcasts";
+option java_multiple_files = true;
+
+extend Atom {
+  optional BroadcastSent broadcast_sent = 922 [(module) = "framework"];
+}
+
+/**
+ * Logged when a broadcast is sent.
+ *
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
+ *
+ * Logging frequency (based on the data from traces):
+ *   Max count / min - 858
+ *   P99 count / min - 442
+ */
+message BroadcastSent {
+    // The action of the broadcast intent
+    optional string intent_action = 1;
+    // The flags used for the broadcast intent. These could be any flags that can be set
+    // via Intent#setFlags() API.
+    optional int32 intent_flags = 2;
+    // The flags that are set in the broadcast intent by the sender. These could be any flags
+    // that can be set via Intent#setFlags() API.
+    optional int32 original_intent_flags = 3;
+    // The uid of the broadcast sender
+    optional int32 sender_uid = 4 [(is_uid) = true];
+    // The uid of the real broadcast sender if the broadcast is triggered from PendingIntent
+    optional int32 real_sender_uid = 5 [(is_uid) = true];
+    // Whether the broadcast is targeting a package
+    optional bool package_targeted = 6;
+    // Whether the broadcast is targeting a component
+    optional bool component_targeted = 7;
+    // No. of target broadcast receivers
+    optional int32 num_receivers = 8;
+
+    enum Result {
+        UNKNOWN = 0;
+        SUCCESS = 1;
+        FAILED_STICKY_CANT_HAVE_PERMISSION = 2;
+        FAILED_USER_STOPPED = 3;
+    }
+    // The result of sending a broadcast
+    optional Result result = 9;
+
+    // The delivery group policy set for the broadcast
+    optional android.app.BroadcastDeliveryGroupPolicy delivery_group_policy = 10;
+    // The procstate of the sender process
+    optional android.app.ProcessStateEnum sender_proc_state = 11;
+    // The procstate of the sender uid
+    optional android.app.ProcessStateEnum sender_uid_state = 12;
+    // Type of broadcast
+    repeated android.app.BroadcastType broadcast_types = 13;
+}
\ No newline at end of file
diff --git a/stats/atoms/conscrypt/conscrypt_extension_atoms.proto b/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
new file mode 100644
index 00000000..cc0b4e66
--- /dev/null
+++ b/stats/atoms/conscrypt/conscrypt_extension_atoms.proto
@@ -0,0 +1,44 @@
+syntax = "proto2";
+
+package android.os.statsd.conscrypt;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.conscrypt";
+
+extend Atom {
+    optional CertificateTransparencyLogListStateChanged certificate_transparency_log_list_state_changed = 934 [(module) = "conscrypt"];
+}
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
+
+/*
+ * Pushed atom on how successful was the loading of the log list.
+ */
+message CertificateTransparencyLogListStateChanged {
+    // The status of the log list.
+    optional LogListStatus status = 1;
+
+    // The compatibility version.
+    optional LogListCompatibilityVersion loaded_compat_version = 2;
+
+    // All compatibility versions available.
+    repeated LogListCompatibilityVersion available_compat_versions = 3 [packed = true];
+
+    // Log list version.
+    optional int32 major_version = 4;
+    optional int32 minor_version = 5;
+}
+
diff --git a/stats/atoms/corenetworking/connectivity/connectivity_extension_atoms.proto b/stats/atoms/corenetworking/connectivity/connectivity_extension_atoms.proto
index ae891135..a302a533 100644
--- a/stats/atoms/corenetworking/connectivity/connectivity_extension_atoms.proto
+++ b/stats/atoms/corenetworking/connectivity/connectivity_extension_atoms.proto
@@ -28,6 +28,7 @@ import "frameworks/proto_logging/stats/enums/corenetworking/connectivity/enums.p
 extend Atom {
     optional DailykeepaliveInfoReported daily_keepalive_info_reported = 650 [(module) = "connectivity"];
     optional NetworkRequestStateChanged network_request_state_changed = 779 [(module) = "connectivity"];
+    optional TetheringActiveSessionsReported tethering_active_sessions_reported = 925 [(module) = "connectivity"];
 }
 
 /**
@@ -143,3 +144,14 @@ message NetworkRequestStateChanged {
     // Duration in millis of the network request since it was received
     optional int32 duration_ms = 6;
 }
+
+/**
+ * Logs the information to observe the number of Tethering active sessions.
+ * Logged from:
+ * packages/modules/Connectivity/Tethering/src/com/android/networkstack/
+ * tethering/BpfCoordinator.java
+ */
+message TetheringActiveSessionsReported {
+    // The maximum number of sessions last 5 minute.
+    optional int32 last_max_session_count = 1;
+}
diff --git a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
index 479154d1..5f7cf2fd 100644
--- a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
+++ b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
@@ -25,6 +25,7 @@ import "frameworks/proto_logging/stats/atom_field_options.proto";
 extend Atom {
   optional DesktopModeUIChanged desktop_mode_ui_changed = 818 [(module) = "framework"];
   optional DesktopModeSessionTaskUpdate desktop_mode_session_task_update = 819 [(module) = "framework"];
+  optional DesktopModeTaskSizeUpdated desktop_mode_task_size_updated = 935 [(module) = "framework"];
 }
 
 /**
@@ -87,12 +88,32 @@ message DesktopModeSessionTaskUpdate {
     TASK_REMOVED = 2;
     TASK_INFO_CHANGED = 3; // covers both size and position changes of the app
   }
+
+  // The reason a task was minimized
+  enum MinimizeReason {
+    // Unset means the task did not get minimized
+    UNSET_MINIMIZE = 0;
+    MINIMIZE_TASK_LIMIT = 1;
+    MINIMIZE_BUTTON = 2;
+  }
+
+  // The reason a task was unminimized
+  enum UnminimizeReason {
+    // Unset means the task did not get minimized
+    UNSET_UNMINIMIZE = 0;
+    // Unknown means we don't know what caused the unminimize action
+    UNMINIMIZE_UNKNOWN = 1;
+    UNMINIMIZE_TASKBAR_TAP = 2;
+    UNMINIMIZE_ALT_TAB = 3;
+    UNMINIMIZE_TASK_LAUNCH = 4;
+  }
+
   // The event associated with this app update
   optional TaskEvent task_event = 1;
   // The instance_id of this task
   optional int32 instance_id = 2;
   // The uid of the app associated with this task
-  optional int32 uid = 3;
+  optional int32 uid = 3 [(is_uid) = true];
   // The height of this task in px
   optional int32 task_height = 4;
   // The width of this task in px
@@ -103,4 +124,89 @@ message DesktopModeSessionTaskUpdate {
   optional int32 task_y = 7;
   // An id used to identify a desktop mode instance
   optional int32 session_id = 8;
+  // The reason the task was minimized
+  optional MinimizeReason minimize_reason = 9;
+  // The reason the task was unminimized
+  optional UnminimizeReason unminimize_reason = 10;
+  // The number of visible tasks
+  optional int32 visible_task_count = 11 [
+    (state_field_option).exclusive_state = true,
+    (state_field_option).nested = false
+  ];
+}
+
+/**
+* Logged when a task size is updated (resizing, snapping or maximizing to
+* stable bounds) during a desktop mode session.
+*
+* Logged from
+* frameworks/base/libs/WindowManager/Shell/src/com/android/wm/shell/desktopmode/DesktopModeEventLogger.kt
+*/
+message DesktopModeTaskSizeUpdated {
+  // The trigger for task resize
+  enum ResizeTrigger {
+    UNKNOWN_RESIZE_TRIGGER = 0;
+    // Resize task from its corner bounds
+    CORNER_RESIZE_TRIGGER = 1;
+    // Resize task from its edges
+    EDGE_RESIZE_TRIGGER = 2;
+    // Resize two tiled apps simultaneously using the divider
+    TILING_DIVIDER_RESIZE_TRIGGER = 3;
+    // Resize task to fit the stable bounds by clicking on the maximize button
+    // on the app header
+    MAXIMIZE_BUTTON_RESIZE_TRIGGER = 4;
+    // Resize task to fit the stable bounds by double tapping the app header
+    DOUBLE_TAP_APP_HEADER_RESIZE_TRIGGER = 5;
+    // Snap a resizable task to the left half of the screen by dragging the task
+    // to the left
+    DRAG_LEFT_RESIZE_TRIGGER = 6;
+    // Snap a resizable task to the right half of the screen by dragging the
+    // task to the right
+    DRAG_RIGHT_RESIZE_TRIGGER = 7;
+    // Snap a resizable task to the left half of the screen by clicking on the
+    // snap left menu on the app header
+    SNAP_LEFT_MENU_RESIZE_TRIGGER = 8;
+    // Snap a resizable task to the right half of the screen by clicking on the
+    // snap right menu on the app header
+    SNAP_RIGHT_MENU_RESIZE_TRIGGER = 9;
+  }
+
+  // The stage at which a task is being resized
+  enum ResizingStage {
+    UNKNOWN_RESIZING_STAGE = 0;
+    // Stage before the task was resized
+    START_RESIZING_STAGE = 1;
+    // Stage when task resize is complete
+    END_RESIZING_STAGE = 2;
+  }
+
+  // The input method for resizing the task
+  enum InputMethod {
+    UNKNOWN_INPUT_METHOD = 0;
+    TOUCH_INPUT_METHOD = 1;
+    STYLUS_INPUT_METHOD = 2;
+    MOUSE_INPUT_METHOD = 3;
+    TOUCHPAD_INPUT_METHOD = 4;
+    // Only tiling and maximizing window actions have keyboard shortcuts
+    KEYBOARD_INPUT_METHOD = 5;
+  }
+
+  // How this task was resized
+  optional ResizeTrigger resize_trigger = 1;
+  // The stage of resizing this task
+  optional ResizingStage resizing_stage = 2;
+  // The input method for resizing this task
+  optional InputMethod input_method = 3;
+  // ID used to identify the Desktop mode session
+  optional int32 desktop_mode_session_id = 4;
+  // The instance_id of this task
+  optional int32 instance_id = 5;
+  // The UID of the app associated with this task
+  optional int32 uid = 6 [(is_uid) = true];
+  // The height of this task in dp
+  optional int32 task_height = 7;
+  // The width of this task in dp
+  optional int32 task_width = 8;
+  // The display area of the device in dp^2
+  optional int32 display_area = 9;
 }
diff --git a/stats/atoms/dnd/dnd_extension_atoms.proto b/stats/atoms/dnd/dnd_extension_atoms.proto
index ceda6753..8d98d60a 100644
--- a/stats/atoms/dnd/dnd_extension_atoms.proto
+++ b/stats/atoms/dnd/dnd_extension_atoms.proto
@@ -69,4 +69,7 @@ message DNDStateChanged {
 
   // The types of rules that are currently active.
   repeated android.stats.dnd.ActiveRuleType active_rule_types = 10;
+
+  // The ZenModeConfig.ConfigChangeOrigin that is the source of this state change.
+  optional android.stats.dnd.ChangeOrigin change_origin = 11;
 }
diff --git a/stats/atoms/framework/framework_extension_atoms.proto b/stats/atoms/framework/framework_extension_atoms.proto
index 0960923d..5e0afa28 100644
--- a/stats/atoms/framework/framework_extension_atoms.proto
+++ b/stats/atoms/framework/framework_extension_atoms.proto
@@ -21,7 +21,7 @@ package android.os.statsd.framework;
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/enums/hardware/biometrics/enums.proto";
-import "frameworks/proto_logging/stats/enums/app/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 
 option java_package = "com.android.os.framework";
 
@@ -29,6 +29,7 @@ extend Atom {
     optional FullScreenIntentLaunched full_screen_intent_launched = 631 [(module) = "framework"];
     optional BalAllowed bal_allowed = 632 [(module) = "framework"];
     optional InTaskActivityStarted in_task_activity_started = 685 [(module) = "framework"];
+    optional DeviceOrientationChanged device_orientation_changed = 906 [(module) = "framework"];
     optional CachedAppsHighWaterMark cached_apps_high_watermark = 10189 [(module) = "framework"];
     optional StylusPredictionMetricsReported stylus_prediction_metrics_reported = 718 [(module) = "libinput"];
     optional UserRiskEventReported user_risk_event_reported = 725 [(module) = "framework"];
@@ -47,6 +48,11 @@ extend Atom {
             [(module) = "framework"];
     optional SensitiveContentAppProtection sensitive_content_app_protection = 835 [(module) = "framework"];
     optional AppRestrictionStateChanged app_restriction_state_changed = 866 [(module) = "framework"];
+    optional BatteryUsageStatsPerUid battery_usage_stats_per_uid = 10209 [(module) = "framework"];
+    optional PostGCMemorySnapshot postgc_memory_snapshot = 924 [(module) = "framework"];
+    optional PowerSaveTempAllowlistChanged power_save_temp_allowlist_changed = 926 [(module) = "framework"];
+    optional AppOpAccessTracked app_op_access_tracked = 931 [(module) = "framework"];
+    optional ContentOrFileUriEventReported content_or_file_uri_event_reported = 933 [(module) = "framework"];
 }
 
 /**
@@ -81,17 +87,20 @@ message BalAllowed {
 
     enum Status {
         BAL_STATUS_UNKNOWN = 0;
-        BAL_ALLOW_DEFAULT = 1;
+        BAL_ALLOW_DEFAULT = 1; // never serialized
         BAL_ALLOW_ALLOWLISTED_UID = 2;
         BAL_ALLOW_ALLOWLISTED_COMPONENT = 3;
         BAL_ALLOW_VISIBLE_WINDOW = 4;
-        BAL_ALLOW_PENDING_INTENT = 5;
+        BAL_ALLOW_PENDING_INTENT = 5; // obsolete
         BAL_ALLOW_BAL_PERMISSION = 6;
         BAL_ALLOW_SAW_PERMISSION = 7;
         BAL_ALLOW_GRACE_PERIOD = 8;
         BAL_ALLOW_FOREGROUND = 9;
         BAL_ALLOW_SDK_SANDBOX = 10;
         BAL_ALLOW_NON_APP_VISIBLE_WINDOW = 11;
+        BAL_ALLOW_TOKEN = 12;
+        BAL_ALLOW_BOUND_BY_FOREGROUND = 13;
+        BAL_BLOCKED = 127; // largest int32 serializable as 1 byte
     }
 
 }
@@ -127,6 +136,24 @@ message InTaskActivityStarted {
     optional int64 activity_start_timestamp_millis = 6;
 }
 
+/**
+ * Logs when the device (i.e. default display) orientation is changed.
+ * Logged from: com.android.server.wm.ActivityTaskManagerService
+ * Estimated Logging Rate:
+ *   Peak: 6 times in 1 min | Avg: 8 times per device per day
+ */
+message DeviceOrientationChanged {
+    enum Orientation {
+        UNDEFINED = 0;
+        PORTRAIT = 1;
+        LANDSCAPE = 2;
+    }
+    optional Orientation orientation = 1 [
+        (state_field_option).exclusive_state = true,
+        (state_field_option).nested = false
+    ];
+}
+
 /**
  * Logs the cached apps high water mark.
  */
@@ -614,3 +641,191 @@ message AppRestrictionStateChanged {
   // The source of the change - initiated by the user, the system automatically, etc.
   optional RestrictionChangeSource source = 7;
 }
+
+/**
+ * Pulls detailed battery attribution slices.
+ *
+ * Pulled from:
+ *   frameworks/base/services/core/java/com/android/server/am/BatteryStatsService.java
+ *
+ * The charging_state and screen_state (and other states potentially) can be used as a dimensions
+ * for corresponding metrics to pull this atom and rely on statsd tracking of states instead
+ */
+message BatteryUsageStatsPerUid {
+
+  enum ProcessState {
+    UNSPECIFIED = 0;
+    FOREGROUND = 1;
+    BACKGROUND = 2;
+    FOREGROUND_SERVICE = 3;
+    CACHED = 4;
+  }
+
+  // Overall SessionStats data
+
+  // The session start timestamp in UTC milliseconds since January 1, 1970, per Date#getTime().
+  // All data is no older than this time.
+  optional int64 session_start_millis = 1;
+
+  // The session end timestamp in UTC milliseconds since January 1, 1970, per Date#getTime().
+  // All data is no more recent than this time.
+  optional int64 session_end_millis = 2;
+
+  // Length that the reported data covered. This usually will be equal to the entire session,
+  // session_end_millis - session_start_millis, but may not be if some data during this time frame
+  // is missing.
+  optional int64 session_duration_millis = 3;
+
+  // Sum of all discharge percentage point drops during the reported session.
+  // Reported by Health HAL - as an integer ranging from 0 to 100
+  optional int32 session_discharge_percentage = 4;
+
+  // Total amount of time battery was discharging during the reported session
+  optional int64 session_discharge_duration_millis = 5;
+
+  // Per Uid BatteryConsumer data
+
+  optional int32 uid = 6 [(is_uid) = true];    // for device-wide atom Process.INVALID_UID (-1)
+  optional ProcessState proc_state = 7;        // for device-wide atom ProcessState.UNSPECIFIED
+  optional int64 time_in_state_millis = 8;
+
+  optional string power_component_name = 9;
+  optional float total_consumed_power_mah = 10;
+  optional float consumed_power_mah = 11;
+  optional int64 duration_millis = 12;
+}
+
+/**
+ * Logs the post-GC memory state for a process
+ */
+message PostGCMemorySnapshot {
+    // The process uid
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // The process name.
+    optional string process_name = 2;
+
+    // The pid of the process.
+    // Allows to disambiguate instances of the process.
+    optional int32 pid = 3;
+
+    // The current OOM score adjustment value.
+    // Placeholder -1001 (OOM_SCORE_ADJ_MIN - 1, outside of allowed range) for native ones.
+    optional int32 oom_score_adj = 4;
+
+    // The current RSS of the process.
+    // VmRSS from /proc/pid/status.
+    optional int32 rss_in_kb = 5;
+
+    // The current anon RSS of the process.
+    // RssAnon from /proc/pid/status.
+    optional int32 anon_rss_in_kb = 6;
+
+    // The current swap size of the process.
+    // VmSwap from /proc/pid/status.
+    optional int32 swap_in_kb = 7;
+
+    // The sum of rss_in_kilobytes and swap_in_kilobytes.
+    optional int32 anon_rss_and_swap_in_kb = 8;
+
+    // Names of the classes with native allocations registered
+    repeated string native_allocation_class = 9;
+
+    // Numbers of malloced native allocations registered
+    repeated int64  native_allocation_malloced_count = 10;
+
+    // Memory sizes in bytes of malloced native allocations registered
+    repeated int64  native_allocation_malloced_bytes = 11;
+
+    // Numbers of nonmalloced native allocations registered
+    repeated int64  native_allocation_nonmalloced_count = 12;
+
+    // Memory sizes in bytes of nonmalloced native allocations registered
+    repeated int64  native_allocation_nonmalloced_bytes = 13;
+}
+
+/**
+ * A PowerSaveTempAllowlistChanged atom indicates that an app is added to or removed from
+ * the temp allowlist, which contains a list of apps that are allowed to bypass
+ * certain power or process management restrictions.
+ *
+ * Logged from: OomAdjuster.setUidTempAllowlistStateLSP via Hummingbird
+ */
+message PowerSaveTempAllowlistChanged {
+    optional int32 uid = 1 [(is_uid) = true];
+    optional bool add_to_allowlist = 2;
+}
+
+/**
+ * [Pushed Atom] Logs when an AppOp is accessed through noteOp, startOp, finishOp and that access
+ * history can be stored in the AppOp discrete access data store.
+ *
+ * Logged from: frameworks/base/services/core/java/com/android/server/appop/DiscreteRegistry.java
+ */
+message AppOpAccessTracked {
+    enum AccessType {
+        UNKNOWN = 0;
+        NOTE_OP = 1;
+        START_OP = 2;
+        FINISH_OP = 3;
+        PAUSE_OP = 4;
+        RESUME_OP = 5;
+    }
+
+    // Uid of the package requesting the op
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // operation id
+    optional android.app.AppOpEnum op_id = 2 [default = APP_OP_NONE];
+
+    // One of the access types
+    optional AccessType access_type = 3 ;
+
+    // The uid state of the package performing the op
+    optional int32 uid_state = 4;
+
+    // The flags of the op
+    optional int32 op_flag = 5;
+
+    // The flags of the attribution chain
+    optional int32 attribution_flag = 6;
+
+    // attribution_tag; provided by developer when accessing related API, limited at 50 chars by
+    // API. Attributions must be provided through manifest using <attribution> tag available in R
+    // and above.
+    optional string attribution_tag = 7;
+
+    // Chain Id that is used to link a finish_op to a start_op
+    optional int32 attribution_chain_id = 8;
+}
+
+/**
+ * Logs when specific content and file URIs are encountered in several locations. See EventType for
+ * more details.
+ */
+message ContentOrFileUriEventReported {
+  enum EventType {
+    UNKNOWN = 0;
+    // When the caller tries to launch an activity with a Content URI it doesn't have read access to
+    // and the callee has requireContentUriPermissionFromCaller as "none"
+    CONTENT_URI_WITHOUT_CALLER_READ_PERMISSION = 1;
+    // When the ContentResolver receives a File URI
+    FILE_URI_IN_CONTENT_RESOLVER = 2;
+    // When the Icon receives a non Content URI
+    NON_CONTENT_URI_IN_ICON = 3;
+    // When the NotificationRecord receives a non Content URI
+    NON_CONTENT_URI_IN_NOTIFICATION_RECORD = 4;
+    // When the MediaDataManager receives a non Content URI
+    NON_CONTENT_URI_IN_MEDIA_DATA_MANAGER = 5;
+  }
+  optional EventType event_type = 1;
+  optional string action_type = 2;
+  optional int32 caller_uid = 3 [(is_uid) = true];
+  optional string caller_activity_class_name = 4;
+  optional int32 callee_uid = 5 [(is_uid) = true];
+  optional string callee_activity_class_name = 6;
+  optional bool is_start_activity_for_result = 7;
+  optional string uri_authority = 8;
+  optional string uri_type = 9;
+  optional string uri_mime_type = 10;
+}
diff --git a/stats/atoms/gps/gps_atoms.proto b/stats/atoms/gps/gps_atoms.proto
index 0232a11f..dc6f8d27 100644
--- a/stats/atoms/gps/gps_atoms.proto
+++ b/stats/atoms/gps/gps_atoms.proto
@@ -18,6 +18,7 @@ syntax = "proto2";
 
 package android.os.statsd.gps;
 
+import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/attribution_node.proto";
 
 option java_package = "com.android.os.gps";
@@ -36,6 +37,6 @@ message GpsScanStateChanged {
         OFF = 0;
         ON = 1;
     }
-    optional State state = 2;
+    optional State state = 2 [(state_field_option).exclusive_state = true];
 }
 
diff --git a/stats/atoms/hardware/health/battery_extension_atoms.proto b/stats/atoms/hardware/health/battery_extension_atoms.proto
new file mode 100644
index 00000000..4a0edf45
--- /dev/null
+++ b/stats/atoms/hardware/health/battery_extension_atoms.proto
@@ -0,0 +1,60 @@
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
+package android.os.statsd.hardware.health;
+
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/hardware/health/enums.proto";
+
+option java_package = "com.android.os.hardware.health";
+option java_multiple_files = true;
+
+extend Atom {
+  optional BatteryHealth battery_health = 10220 [(module) = "framework"];
+}
+
+/*
+ * Data reported by the android.hardware.health HAL.
+ */
+message BatteryHealth {
+  /*
+   * Monday of the week the battery was manufactured, in YYYYMMDD format.
+   */
+  optional int32 battery_manufacturing_date = 1;
+  /*
+   * Monday of the week the battery was first used, in YYYYMMDD format.
+   */
+  optional int32 battery_first_usage_date = 2;
+  /*
+   * Measured battery state of health (remaining estimate full charge capacity
+   * relative to the rated capacity in %).
+   * This value is in the range 0 to 100, where the special value 0 refers to *
+   un UNKNOWN state of the battery.
+   */
+  optional int32 battery_state_of_health = 3;
+  /*
+   * Last byte of the hashed battery serial number.
+   */
+  optional int32 battery_serial_number_hash = 4;
+  optional android.hardware.health.BatteryPartStatus battery_part_status = 5;
+  optional android.hardware.health.BatteryChargingState battery_charging_state =
+      6;
+  optional android.hardware.health.BatteryChargingPolicy
+      battery_charging_policy = 7;
+}
diff --git a/stats/atoms/healthfitness/api/api_extension_atoms.proto b/stats/atoms/healthfitness/api/api_extension_atoms.proto
index fe02cf44..c40f5b40 100644
--- a/stats/atoms/healthfitness/api/api_extension_atoms.proto
+++ b/stats/atoms/healthfitness/api/api_extension_atoms.proto
@@ -35,6 +35,12 @@ extend Atom {
   optional HealthConnectApiInvoked health_connect_api_invoked = 643 [(module) = "healthfitness", (restriction_category) = RESTRICTION_DIAGNOSTIC];
 
   optional ExerciseRouteApiCalled exercise_route_api_called = 654 [(module) = "healthfitness", (restriction_category) = RESTRICTION_DIAGNOSTIC];
+
+  optional HealthConnectExportInvoked health_connect_export_invoked = 907 [(module) = "healthfitness"];
+
+  optional HealthConnectImportInvoked health_connect_import_invoked = 918 [(module) = "healthfitness"];
+
+  optional HealthConnectExportImportStatsReported health_connect_export_import_stats_reported = 919 [(module) = "healthfitness"];
 }
 
 // Track HealthDataService API operations.
@@ -73,6 +79,24 @@ message HealthConnectUsageStats {
 
   // Set true is the user has one app reading or writing in past 30 days
   optional bool is_monthly_active_user = 3;
+
+}
+
+/**
+ *  Tracks the daily usage stats of the Health Connect export/import feature.
+ *
+ *  Logged from:
+ *  packages/modules/HealthFitness/service/java/com/android/server/healthconnect/logging/UsageStatsLogger.java
+ *
+ *  Estimated Logging Rate:
+ *  Avg: 1 per device per day
+ *
+ */
+message HealthConnectExportImportStatsReported {
+
+  // Configured export frequency of the user
+  optional int32 export_frequency = 1;
+
 }
 
 // Monitor Health Connect database
@@ -109,6 +133,42 @@ message ExerciseRouteApiCalled {
 
 }
 
+/**
+ * Tracks when a data export is started or changes status.
+ */
+message HealthConnectExportInvoked {
+
+  // Status of the export (started/success/failure)
+  optional android.healthfitness.api.ExportStatus status = 1;
+
+  // Time taken between the start of the export and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the original data before it is compressed for the export.
+  optional int32 original_data_size_kb = 3;
+
+  // Size of the compressed data being exported.
+  optional int32 compressed_data_size_kb = 4;
+}
+
+/**
+ * Tracks when a data import is started or changes status.
+ */
+message HealthConnectImportInvoked {
+
+  // Status of the import (started/success/failure)
+  optional android.healthfitness.api.ImportStatus status = 1;
+
+  // Time taken between the start of the import and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the original data after it is decompressed after the import.
+  optional int32 original_data_size_kb = 3;
+
+  // Size of the compressed data being imported.
+  optional int32 compressed_data_size_kb = 4;
+}
+
 // Track Health Connect API operations stats.
 message HealthConnectApiInvoked {
 
diff --git a/stats/atoms/input/input_extension_atoms.proto b/stats/atoms/input/input_extension_atoms.proto
index cb226f21..a769d410 100644
--- a/stats/atoms/input/input_extension_atoms.proto
+++ b/stats/atoms/input/input_extension_atoms.proto
@@ -29,6 +29,7 @@ extend Atom {
     optional KeyboardConfigured keyboard_configured = 682 [(module) = "framework"];
     optional KeyboardSystemsEventReported keyboard_systems_event_reported = 683 [(module) = "framework"];
     optional InputDeviceUsageReported inputdevice_usage_reported = 686 [(module) = "framework"];
+    optional InputEventLatencyReported input_event_latency_reported = 932 [(module) = "framework"];
 
     optional TouchpadUsage touchpad_usage = 10191 [(module) = "framework"];
 }
@@ -177,3 +178,41 @@ message TouchpadUsage {
     // The number of pinch gestures recognized by the framework.
     optional int32 pinch_gesture_count = 10;
 }
+
+/**
+ * Logs input event latency statistics using histograms on a per device granular level.
+ *
+ * This atom will be pushed every 6 hours.
+ * The data gathered is cleared and the counters (histogram_counts) are reset after each push.
+ *
+ * If an input device was used and then disconnected, the latency data related to it is stored on
+ * the Android device until the atom is pushed.
+ * Histograms are created in memory for an input device only if that device is connected and
+ * produces input events. If an input device is connected and disconnected multiple times before
+ * pushing the atom, counters aren't reset, so we continue counting the latencies where we left
+ * off before the device was disconnected.
+ *
+ * Logged from:
+ *     frameworks/native/services/inputflinger
+ */
+
+message InputEventLatencyReported {
+    // The input device Vendor ID
+    optional int32 vendor_id = 1;
+    // The input device Product ID
+    optional int32 product_id = 2;
+    // Source(s) of the input device
+    repeated android.input.InputDeviceUsageType sources = 3;
+    // Type of Input Event: can be either a Key Event (Up and Down), or some specific Motion Event
+    // action type (Down/Move/Up/...)
+    optional android.input.InputEventType input_event_type = 4;
+    // The latency stage for which latency metric is collected
+    optional android.input.LatencyStage latency_stage = 5;
+    // Histogram version. This version number is mapped to an array
+    // containing the boundary values between histogram bins.
+    // Each bucket represents a range of latency values (in hundreds of microseconds).
+    optional int32 histogram_version = 6;
+    // The latency value counts for each of the histogram bins
+    // Expected number of fields: 20
+    repeated int32 histogram_counts = 7;
+}
diff --git a/stats/atoms/kernel/kernel_atoms.proto b/stats/atoms/kernel/kernel_atoms.proto
index 48409a56..7ace12e0 100644
--- a/stats/atoms/kernel/kernel_atoms.proto
+++ b/stats/atoms/kernel/kernel_atoms.proto
@@ -19,7 +19,7 @@ syntax = "proto2";
 package android.os.statsd.kernel;
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/enums/app/app_enums.proto";
+import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 
 option java_package = "com.android.os.kernel";
 option java_multiple_files = true;
diff --git a/stats/atoms/microxr/microxr_extension_atoms.proto b/stats/atoms/microxr/microxr_extension_atoms.proto
new file mode 100644
index 00000000..5614dc3e
--- /dev/null
+++ b/stats/atoms/microxr/microxr_extension_atoms.proto
@@ -0,0 +1,40 @@
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
+syntax = "proto2";
+
+package android.os.statsd.microxr;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.statsd.microxr";
+option java_multiple_files = true;
+
+extend Atom {
+  // Pushed Atom
+  optional MicroXRDeviceBootCompleteReported microxr_device_boot_complete_reported = 901
+  [(module) = "microxr"];
+}
+
+/*
+ *  Logs when a MicroXR Device is done booting.
+ */
+message MicroXRDeviceBootCompleteReported {
+  // Device ready elapsed time in milliseconds.
+  // Logged from microxr-system-ui.
+  optional int64 device_ready_time_millis = 1;
+}
diff --git a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
index af5bd1fa..21ae1e77 100644
--- a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+++ b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
@@ -59,6 +59,7 @@ message OnDevicePersonalizationApiCalled {
         MODEL_MANAGER_RUN = 20;
         FEDERATED_COMPUTE_CANCEL = 21;
         NOTIFY_MEASUREMENT_EVENT = 22;
+        ADSERVICES_GET_COMMON_STATES = 23;
     }
     optional OnDevicePersonalizationApiClassType api_class = 1;
     optional OnDevicePersonalizationApiName api_name = 2;
diff --git a/stats/atoms/performance/performance_extension_atoms.proto b/stats/atoms/performance/performance_extension_atoms.proto
new file mode 100644
index 00000000..db9c5cf4
--- /dev/null
+++ b/stats/atoms/performance/performance_extension_atoms.proto
@@ -0,0 +1,57 @@
+/*
+ * Copyright (C) 2024 The Android Open Source Project
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
+ syntax = "proto2";
+
+package android.os.statsd.performance;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+extend Atom {
+    optional PressureStallInformation pressure_stall_information = 10229 [(module) = "performance"];
+}
+
+// Pressure stall information for a given resource.
+// See https://docs.kernel.org/accounting/psi.html
+message PressureStallInformation {
+    optional Resource resource = 1;
+
+    // The average percent of time in the last N seconds that some tasks were
+    // stalled on the particular resource. Expressed as x.xx%.
+    optional float some_avg_10s_pct = 2;
+    optional float some_avg_60s_pct = 3;
+    optional float some_avg_300s_pct = 4;
+    // The total number of microseconds that some tasks were
+    // stalled on the particular resource.
+    optional int64 some_total_usec = 5;
+
+    // The average percent of time in the last N seconds that all tasks were
+    // stalled on the particular resource. Expressed as x.xx%.
+    optional float full_avg_10s_pct = 6;
+    optional float full_avg_60s_pct = 7;
+    optional float full_avg_300s_pct = 8;
+    // The total number of microseconds that all tasks were
+    // stalled on the particular resource.
+    optional int64 full_total_usec = 9;
+
+    enum Resource {
+        UNKNOWN = 0;
+        CPU = 1;
+        MEMORY = 2;
+        IO = 3;
+    }
+}
diff --git a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
index 8f5be506..49658927 100644
--- a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
+++ b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
@@ -153,7 +153,7 @@ message AppDataSharingUpdatesFragmentActionReported {
  */
 message EnhancedConfirmationDialogResultReported {
   // UID of the restricted app
-  optional int32 uid = 1;
+  optional int32 uid = 1 [(is_uid) = true];
 
   // Identifier of the restricted setting
   optional string setting_identifier = 2;
@@ -193,5 +193,5 @@ message EnhancedConfirmationDialogResultReported {
  */
 message EnhancedConfirmationRestrictionCleared {
   // UID of the restricted app
-  optional int32 uid = 1;
+  optional int32 uid = 1 [(is_uid) = true];
 }
diff --git a/stats/atoms/photopicker/photopicker_extension_atoms.proto b/stats/atoms/photopicker/photopicker_extension_atoms.proto
index c2ce6ae3..35393408 100644
--- a/stats/atoms/photopicker/photopicker_extension_atoms.proto
+++ b/stats/atoms/photopicker/photopicker_extension_atoms.proto
@@ -62,9 +62,9 @@ extend Atom {
  */
 message PhotopickerSessionInfoReported {
   optional int32 session_id = 1;
-  optional int32 package_uid = 2;
+  optional int32 package_uid = 2 [(is_uid) = true];
   optional android.photopicker.PickerPermittedSelection picker_permitted_selection= 3;
-  optional int32 cloud_provider_uid = 4;
+  optional int32 cloud_provider_uid = 4 [(is_uid) = true];
   optional android.photopicker.UserProfile user_profile = 5;
   optional android.photopicker.PickerStatus picker_status = 6;
   optional int32 picked_items_count = 7;
@@ -97,7 +97,7 @@ message PhotopickerApiInfoReported {
  */
 message PhotopickerUIEventLogged {
   optional int32 session_id = 1;
-  optional int32 package_uid = 2;
+  optional int32 package_uid = 2 [(is_uid) = true];
   optional android.photopicker.UiEvent ui_event = 3;
 }
 
@@ -131,7 +131,7 @@ Logs the user's interaction with the photopicker menu
  */
 message PhotopickerMenuInteractionLogged {
   optional int32 session_id = 1;
-  optional int32 package_uid = 2;
+  optional int32 package_uid = 2 [(is_uid) = true];
   optional android.photopicker.MenuItemSelected menu_item_selected = 3;
 }
 
@@ -149,13 +149,13 @@ message PhotopickerBannerInteractionLogged {
  */
 message PhotopickerMediaLibraryInfoLogged {
   optional int32 session_id = 1;
-  optional int32 cloud_provider_uid = 2;
+  optional int32 cloud_provider_uid = 2 [(is_uid) = true];
   optional int32 library_size = 3;
   optional int32 media_count = 4;
 }
 
 /*
-  Ccaptures the picker's paging details: can give an estimate of how far the user scrolled and
+  Captures the picker's paging details: can give an estimate of how far the user scrolled and
   the items loaded in.
  */
 message PhotopickerPageInfoLogged {
@@ -220,6 +220,6 @@ message SearchDataExtractionDetailsReported {
 message EmbeddedPhotopickerInfoReported {
   optional int32 session_id = 1;
   optional bool is_surface_package_creation_successful = 2;
-  optional int32 surface_package_delivery_start_time = 3;
-  optional int32 surface_package_delivery_end_time = 4;
+  optional int32 surface_package_delivery_start_time_millis = 3;
+  optional int32 surface_package_delivery_end_time_millis = 4;
 }
diff --git a/stats/atoms/providers/mediaprovider/media_provider_atoms.proto b/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
index a1120845..61d2069c 100644
--- a/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
+++ b/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
@@ -41,5 +41,20 @@ message MediaProviderVolumeRecoveryReported {
     optional int64 rows_recovered = 3;
     // Dirty rows count
     optional int64 dirty_rows_found = 4;
-}
+    // Count of rows in level db batch
+    optional int64 total_leveldb_rows = 5;
+    // Count of insertion failures
+    optional int64 insertionFailures = 6;
 
+    enum Status {
+        STATUS_UNKNOWN = 0;
+        SUCCESS = 1;
+        BACKUP_MISSING = 2;
+        VOLUME_NOT_ATTACHED = 3;
+        FUSE_DAEMON_TIMEOUT = 4;
+        GET_BACKUP_DATA_FAILURE = 5;
+        OTHER_ERROR = 6;
+    }
+    // Status code of volume recovery event
+    optional Status status = 7;
+}
diff --git a/stats/atoms/sdksandbox/sdksandbox_extension_atoms.proto b/stats/atoms/sdksandbox/sdksandbox_extension_atoms.proto
index e6ae65ac..77080027 100644
--- a/stats/atoms/sdksandbox/sdksandbox_extension_atoms.proto
+++ b/stats/atoms/sdksandbox/sdksandbox_extension_atoms.proto
@@ -162,10 +162,10 @@ message SandboxActivityEventOccurred {
   optional int32 latency_millis = 3;
 
   // Uid of the client app for which the activity is created
-  optional int32 client_uid = 4;
+  optional int32 client_uid = 4 [(is_uid) = true];
 
   // Uid of the SDK that's loaded into client's sandbox process and for which the activity is created
-  optional int32 sdk_uid = 5;
+  optional int32 sdk_uid = 5 [(is_uid) = true];
 }
 
 message ActivityStartRequest {
diff --git a/stats/atoms/sysui/sysui_atoms.proto b/stats/atoms/sysui/sysui_atoms.proto
index cf3326c2..45cd7133 100644
--- a/stats/atoms/sysui/sysui_atoms.proto
+++ b/stats/atoms/sysui/sysui_atoms.proto
@@ -514,6 +514,13 @@ message Notification {
         SECTION_ALERTING = 4;
         SECTION_SILENT = 5;
         SECTION_FOREGROUND_SERVICE = 6;
+        SECTION_PRIORITY_PEOPLE = 7;
+        SECTION_TOP_ONGOING = 8;
+        SECTION_TOP_UNSEEN = 9;
+        SECTION_NEWS = 10;
+        SECTION_SOCIAL = 11;
+        SECTION_RECS = 12;
+        SECTION_PROMO = 13;
     }
     optional NotificationSection section = 6;
 }
@@ -530,7 +537,7 @@ message NotificationList {
  */
 message NotificationMemoryUse {
     // UID if the application (can be mapped to package and version)
-    optional int32 uid = 1;
+    optional int32 uid = 1 [(is_uid) = true];
     // Integer enum value showing aggregated notification style.
     optional int32 style = 2;
     // Number of notifications that were aggregated into this metric.
diff --git a/stats/atoms/sysui/sysui_extension_atoms.proto b/stats/atoms/sysui/sysui_extension_atoms.proto
index 04d4e3a8..81107f41 100644
--- a/stats/atoms/sysui/sysui_extension_atoms.proto
+++ b/stats/atoms/sysui/sysui_extension_atoms.proto
@@ -30,6 +30,8 @@ extend Atom {
   optional DisplaySwitchLatencyTracked display_switch_latency_tracked = 753 [(module) = "sysui"];
   optional NotificationListenerService notification_listener_service = 829 [(module) = "sysui"];
   optional NavHandleTouchPoints nav_handle_touch_points = 869 [(module) = "sysui"];
+  optional CommunalHubWidgetEventReported communal_hub_widget_event_reported = 908 [(module) = "sysui"];
+  optional CommunalHubSnapshot communal_hub_snapshot = 10226 [(module) = "sysui"];
 }
 
 /**
@@ -218,3 +220,47 @@ message NavHandleTouchPoints {
     // This is the motion action event associated with (x,y) touch. See https://developer.android.com/reference/android/view/MotionEvent#constants_1 for the motion events code.
     repeated int32 action = 6;
 }
+
+/**
+ * Pushed atom. Logs an event for widgets in the communal hub.
+ *
+ * Logged from:
+ *   frameworks/base/packages/SystemUI/src/com/android/systemui/communal/
+ * Estimated Logging Rate:
+ *   Avg: 5 per device per day
+ */
+message CommunalHubWidgetEventReported {
+  enum Action {
+    // Action is unknown.
+    UNKNOWN = 0;
+    // User adds a widget in the communal hub.
+    ADD = 1;
+    // User removes a widget from the communal hub.
+    REMOVE = 2;
+    // User taps a widget in the communal hub.
+    TAP = 3;
+  }
+
+  // The action that triggered the event.
+  optional Action action = 1;
+
+  // The component name of the widget in the communal hub.
+  optional string component_name = 2;
+
+  // The rank or order of the widget in the communal hub.
+  optional int32 rank = 3;
+}
+
+/**
+ * Pulled atom. Logs a snapshot of content in the communal hub.
+ *
+ * Logged from:
+ *   frameworks/base/packages/SystemUI/src/com/android/systemui/communal/
+ */
+message CommunalHubSnapshot {
+  // A list of component names of first party widgets in the communal hub.
+  repeated string component_names = 1;
+
+  // The total number of widgets in the communal hub.
+  optional int32 widget_count = 2;
+}
diff --git a/stats/atoms/telecomm/telecom_extension_atom.proto b/stats/atoms/telecomm/telecom_extension_atom.proto
index c59243b6..c7782b66 100644
--- a/stats/atoms/telecomm/telecom_extension_atom.proto
+++ b/stats/atoms/telecomm/telecom_extension_atom.proto
@@ -20,12 +20,17 @@ package android.os.statsd.telecom;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/telecomm/enums.proto";
 
 option java_package = "com.android.os.telecom";
 option java_multiple_files = true;
 
 extend Atom {
     optional EmergencyNumberDialed emergency_number_dialed = 637 [(module) = "telecom"];
+    optional CallStats call_stats = 10221 [(module) = "telecom"];
+    optional CallAudioRouteStats call_audio_route_stats = 10222 [(module) = "telecom"];
+    optional TelecomApiStats telecom_api_stats = 10223 [(module) = "telecom"];
+    optional TelecomErrorStats telecom_error_stats = 10224 [(module) = "telecom"];
 }
 
 /**
@@ -43,4 +48,101 @@ message EmergencyNumberDialed {
 
     // mcc mnc of the latched network to make emergency call
     optional string network_mccmnc = 4;
-}
\ No newline at end of file
+}
+
+/**
+ * Pulled atom to capture stats of the calls
+ */
+message CallStats {
+    // The call direction. Eg. INCOMING, OUTGOING, UNKNOWN
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallDirectionEnum call_direction = 1;
+
+    // True if call is external. External calls are calls on connected Wear
+    // devices but show up in Telecom so the user can pull them onto the device.
+    optional bool external_call = 2;
+
+    // True if call is emergency call.
+    optional bool emergency_call = 3;
+
+    // True if there are multiple audio routes available
+    optional bool multiple_audio_available = 4;
+
+    // The account type of the call. Eg. SIM, Managed, SelfManaged, VoipApi
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.AccountTypeEnum account_type = 5;
+
+
+    // UID of the package to init the call. This should always be -1/unknown for
+    // the private space calls
+    optional int32 uid = 6 [(is_uid) = true];
+
+    // Total number of the calls
+    optional int32 count = 7;
+
+    // Average elapsed time between CALL_STATE_ACTIVE to CALL_STATE_DISCONNECTED.
+    optional int32 average_duration_ms = 8;
+}
+
+/**
+ * Pulled atom to capture stats of the call audio route
+ */
+message CallAudioRouteStats {
+    // The source the call audio route. The types include CALL_AUDIO_ROUTE_UNSPECIFIED,
+    // CALL_AUDIO_ROUTE_PHONE_SPEAKER, CALL_AUDIO_ROUTE_WATCH_SPEAKER,
+    // CALL_AUDIO_ROUTE_BLUETOOTH, CALL_AUDIO_ROUTE_AUTO, or
+    // CALL_AUDIO_ROUTE_BLUETOOTH_LE from
+    // frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallAudioEnum route_source = 1;
+
+    // The destination of the audio route. The types are defined in
+    // frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallAudioEnum route_dest = 2;
+
+    // True if the route is successful.
+    optional bool success = 3;
+
+    // True if the route is revert
+    optional bool revert = 4;
+
+    // Total number of the audio route
+    optional int32 count = 5;
+
+    // Average time from the audio route start to complete
+    optional int32 average_latency_ms = 6;
+}
+
+/**
+ * Pulled atom to capture stats of Telecom API usage
+ */
+message TelecomApiStats {
+    // The api name
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.ApiNameEnum api_name = 1;
+
+    // UID of the caller. This is always -1/unknown for the private space.
+    optional int32 uid = 2 [(is_uid) = true];
+
+    // The result of the API call
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.ApiResultEnum api_result = 3;
+
+    // The number of times this event occurs
+    optional int32 count = 4;
+}
+
+/**
+ * Pulled atom to capture stats of Telecom module errors
+ */
+message TelecomErrorStats {
+    // The sub module name
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.SubmoduleNameEnum submodule_name = 1;
+
+    // The error name
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.ErrorNameEnum error_name = 2;
+
+    // The number of times this error occurs
+    optional int32 count = 3;
+}
diff --git a/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto b/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto
new file mode 100644
index 00000000..8bb9659b
--- /dev/null
+++ b/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto
@@ -0,0 +1,51 @@
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
+package android.os.statsd.telephony.iwlan;
+
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/telephony/iwlan/enums.proto";
+
+option java_package = "com.android.os.telephony.iwlan";
+option java_multiple_files = true;
+
+extend Atom {
+  optional IwlanUnderlyingNetworkValidationResultReported iwlan_underlying_network_validation_result_reported = 923
+  [(module) = "iwlan"];
+}
+
+/**
+ * Logs when Iwlan trigger underlying network validation. pushed
+ *
+ * Logged from:
+ *   packages/services/Iwlan/src/com/google/android/iwlan/epdg/EpdgTunnelManager.java
+ */
+message IwlanUnderlyingNetworkValidationResultReported {
+  // Underlying network validation trigger event
+  optional android.telephony.iwlan.UnderlyingNetworkValidationEvent trigger_event = 1;
+
+  // Underlying network validation result
+  optional android.telephony.iwlan.UnderlyingNetworkValidationResult validation_result = 2;
+
+  // Underlying network transport type
+  optional android.telephony.iwlan.TransportType transport_type = 3;
+
+  // Time for receiving the validation result
+  optional int32 validation_duration_millis = 4;
+}
diff --git a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
index f28cf41d..b60a1f28 100644
--- a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
+++ b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
@@ -94,6 +94,9 @@ message SatelliteController {
   // The total duration of the battery being charged while satellite modem is on
   optional int32 total_battery_charged_time_sec = 17;
   // Count of successful satellite service enablement in demo mode
+  // Demo mode is a service that allows users to practise in a safe environment,
+  // considering that the first use of the satellite service is likely to be in
+  // an emergency.
   optional int32 count_of_demo_mode_satellite_service_enablements_success = 18;
   // Count of failed satellite service enablement in demo mode
   optional int32 count_of_demo_mode_satellite_service_enablements_fail = 19;
@@ -115,6 +118,16 @@ message SatelliteController {
   optional int32 count_of_disallowed_satellite_access = 27;
   // Total count of failed checking event for satellite access.
   optional int32 count_of_satellite_access_check_fail = 28;
+  // Whether this device is provisioned or not.
+  optional bool is_provisioned = 29;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 30;
+  // Count of satellite allowed state changed events
+  optional int32 count_of_satellite_allowed_state_changed_events = 31;
+  // Count of successful location queries
+  optional int32 count_of_successful_location_queries = 32;
+  // Count of failed location queries
+  optional int32 count_of_failed_location_queries = 33;
 }
 
 /**
@@ -145,9 +158,20 @@ message SatelliteSession {
   // the number of failed incoming datagram transmission while the session is enabled
   optional int32 count_of_incoming_datagram_failed = 11;
   // Whether this session is enabled for demo mode, code {true} if it is demo mode
+  // Demo mode is a service that allows users to practise in a safe environment,
+  // considering that the first use of the satellite service is likely to be in
+  // an emergency.
   optional bool is_demo_mode = 12;
   // Max Ntn signal strength while the satellite session is enabled
   optional int32 max_ntn_signal_strength_level = 13;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 14;
+  // Total number of times the user is notified that the device is eligible for satellite service
+  optional int32 count_of_satellite_notification_displayed = 15;
+  // Total number of times exit P2P message service automatically due to screen is off and timer is expired
+  optional int32 count_of_auto_exit_due_to_screen_off = 16;
+  // Total number of times exit P2P message service automatically when a TN network is detected during idle scanning mode
+  optional int32 count_of_auto_exit_due_to_tn_network = 17;
 }
 
 /**
@@ -161,7 +185,12 @@ message SatelliteIncomingDatagram {
   // The amount of time took to receive the datagram.
   optional int64 datagram_transfer_time_millis = 3;
   // Whether it is transferred in demo mode or not. if true, transferred in demo mode.
+  // Demo mode is a service that allows users to practise in a safe environment,
+  // considering that the first use of the satellite service is likely to be in
+  // an emergency.
   optional bool is_demo_mode = 4;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 5;
 }
 
 /**
@@ -177,7 +206,12 @@ message SatelliteOutgoingDatagram {
   // The amount of time took to send the datagram.
   optional int64 datagram_transfer_time_millis = 4;
   // Whether it is transferred in demo mode or not. if true, transferred in demo mode.
+  // Demo mode is a service that allows users to practise in a safe environment,
+  // considering that the first use of the satellite service is likely to be in
+  // an emergency.
   optional bool is_demo_mode = 5;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 6;
 }
 
 /**
@@ -193,6 +227,8 @@ message SatelliteProvision {
   optional bool is_provision_request = 3;
   // Whether the provisioning request was canceled.
   optional bool is_canceled = 4;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 5;
 }
 
 /**
@@ -215,6 +251,10 @@ message SatelliteSosMessageRecommender {
   optional android.telephony.RecommendingHandoverType recommending_handover_type = 7;
   // Whether satellite communication is allowed in current location.
   optional bool is_satellite_allowed_in_current_location = 8;
+  // Whether Wi-Fi is available when the emergency call attempted.
+  optional bool is_wifi_connected = 9;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 10;
 }
 
 /**
@@ -273,6 +313,10 @@ message CarrierRoamingSatelliteControllerStats {
   optional int32 satellite_session_gap_avg_sec = 6;
   // Maximum gap between satellite sessions
   optional int32 satellite_session_gap_max_sec = 7;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 8;
+  // Whether this device is entitled or not.
+  optional bool is_device_entitled = 9;
 }
 
 /**
@@ -280,6 +324,8 @@ message CarrierRoamingSatelliteControllerStats {
  */
 message ControllerStatsPerPackage {
   optional int32 uid = 1  [(is_uid) = true];
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 2;
 }
 
 /**
@@ -329,8 +375,19 @@ message SatelliteAccessController {
   // Result code of the request for checking if satellite communication is allowed at the current
   // location.
   optional android.telephony.SatelliteError result_code = 7;
-  // Country codes where the device resides.
+  // ISO 3166-1 alpha-2 uppercase country codes representing the device's
+  // location.
+  // Country codes are determined based on the device's current location
+  // information, obtained from the cellular network.
+  // Country code can be obtained only when there is available cellular network,
+  // or empty list will be given.
+  // Cellular networks may provide multiple codes at locations near country
+  // borders.
   repeated string country_codes = 8;
   // Source of geofencing config data
   optional android.telephony.ConfigDataSource config_data_source = 9;
+  // Carrier id of the subscription connected to non-terrestrial network
+  optional int32 carrier_id = 10;
+  // From which reason the Satellite Access Controller operation was triggered.
+  optional android.telephony.TriggeringEvent triggering_event = 11;
 }
diff --git a/stats/atoms/uprobestats/uprobestats_extension_atoms.proto b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
new file mode 100644
index 00000000..02e06893
--- /dev/null
+++ b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
@@ -0,0 +1,35 @@
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
+package android.os.statsd.uprobestats;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+
+option java_package = "com.android.os.uprobestats";
+option java_multiple_files = true;
+
+extend Atom {
+  optional TestUprobeStatsAtomReported test_uprobestats_atom_reported = 915;
+}
+
+/* Test atom, specifically for UprobeStats tests, not logged anywhere */
+message TestUprobeStatsAtomReported {
+    optional int64 first_field = 1;
+    optional int64 second_field = 2;
+    optional int64 third_field = 3;
+}
diff --git a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
index a16e6cec..52e97fb3 100644
--- a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
+++ b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
@@ -31,6 +31,8 @@ extend Atom {
       [(module) = "wearconnectivity"];
   optional SysproxyConnectionUpdated sysproxy_connection_updated = 786
       [(module) = "wearconnectivity"];
+  optional WearCompanionConnectionState wear_companion_connection_state = 921
+      [(module) = "wearconnectivity"];
 }
 
 /**
@@ -54,6 +56,15 @@ message MediatorUpdated {
 
   // Timestamp of the event log time in ElapsedRealtime
   optional int64 timestamp_millis = 5;
+
+  // Timestamp(ElapsedRealtime) of when the last linger(the one that actually fired) before the mediator starts the action.
+  // A "Linger" is a delay that sometimes the mediator applies before actually turning off the radio after the mediator
+  // decides to turn off the radio due to certain signals(e.g. proxy reconnected), for various purposes, such as
+  // avoid proxy connection thrashing causing the mediator to frequently toggle the radio.
+  optional int64 last_linger_start_timestamp_millis = 6;
+
+  // Count of times the linger canceled before the action was actually performed.
+  optional int32 linger_canceled_count = 7;
 }
 
 /**
@@ -98,3 +109,19 @@ message SysproxyConnectionUpdated {
   // timestamp when reason was determined
   optional int64 reason_timestamp_millis = 6;
 }
+
+/**
+ * Captures updates of the connections to the companion phone.
+ * Only the one used for important data connectivity (Sysproxy, Comms, Assistant, etc.) is logged
+ * even when both are connected. Specifically, before the BLE migration is activated on the
+ * device(go/wear-ble), BTC_ACL is logged, after that, BLE_ACL is logged.
+ * Note that this atom does NOT aim to comprehensively log all the ongoing BT connection between
+ * the watch and the companion phone, but only limited to the logs described above. Connections(for
+ * example, BTC ACL after BLE migration) not being logged in this atom does NOT mean it's
+ * not connected(or not disconnected).
+ */
+message WearCompanionConnectionState {
+  optional com.google.android.wearable.connectivity.CompanionConnectionType connection_type = 1;
+
+  optional com.google.android.wearable.connectivity.CompanionConnectionChange connection_change = 2;
+}
diff --git a/stats/atoms/wear/media/wear_media_extension_atoms.proto b/stats/atoms/wear/media/wear_media_extension_atoms.proto
index 1c834e5f..8c20292e 100644
--- a/stats/atoms/wear/media/wear_media_extension_atoms.proto
+++ b/stats/atoms/wear/media/wear_media_extension_atoms.proto
@@ -61,7 +61,7 @@ message MediaActionReported {
 
   // Package name of the app that the user used to perform the action (eg: UMO
   // or a 3p media app)
-  optional int32 media_controls_package_uid = 2;
+  optional int32 media_controls_package_uid = 2 [(is_uid) = true];
 
   // Package name of the app that owns the media session. (This app is on the
   // paired phone, and not on the watch, hence cannot use uid)
diff --git a/stats/atoms/wear/time/wear_time_sync_extension_atoms.proto b/stats/atoms/wear/time/wear_time_sync_extension_atoms.proto
new file mode 100644
index 00000000..bd594de9
--- /dev/null
+++ b/stats/atoms/wear/time/wear_time_sync_extension_atoms.proto
@@ -0,0 +1,105 @@
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
+package android.os.statsd.wear.time;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/wear/time/enums.proto";
+
+option java_package = "com.android.os.wear.time";
+option java_multiple_files = true;
+
+/**
+ * All logs are logged from package:
+ * vendor/google_clockwork/packages/Settings/src/com/google/android/clockwork/settings/time/
+ */
+
+extend Atom {
+  optional WearTimeSyncRequested wear_time_sync_requested = 911 [(module) = "wear_settings"];
+  optional WearTimeUpdateStarted wear_time_update_started = 912 [(module) = "wear_settings"];
+  optional WearTimeSyncAttemptCompleted wear_time_sync_attempt_completed = 913 [(module) = "wear_settings"];
+  optional WearTimeChanged wear_time_changed = 914 [(module) = "wear_settings"];
+}
+
+/**
+ * Logged whenever there is a call to TimeService onHandleIntent for time sync.
+ */
+message WearTimeSyncRequested {
+
+  // The type of time sync request that initiated this sync call
+  // either an EVALUATE, a POLL, or COMPANION_CONNECTION event
+  optional com.google.android.apps.wearable.settings.RequestTypeEnum request_type = 1;
+
+  // The location from which the time sync service was started
+  // either BOOT, OOBE, COMPANION_CONNECTION, TOGGLE, or PERIODIC_JOB
+  optional com.google.android.apps.wearable.settings.SourceTypeEnum source_type = 2;
+}
+
+/**
+ * Logged whenever a time sync is actually triggered from a specific origin.
+ */
+message WearTimeUpdateStarted {
+
+  // The origin of the update ie. the source of the time that will be used in the update
+  // either COMPANION, NETWORK, NITZ, or GNSS
+  optional com.google.android.apps.wearable.settings.OriginTypeEnum origin_type = 1;
+
+  // Whether the watch is standalone
+  optional bool is_standalone = 2;
+
+  // Whether or not sync from companion was attempted prior to fallbacks
+  // If origin type for this event is COMPANION, this field will default to true
+  // If device is standalone or didn't have a connection to its companion, this will be false
+  optional bool is_phone_sync_attempted = 3;
+}
+
+/**
+ * Logged whenever an attempt to time sync completes.
+ */
+message WearTimeSyncAttemptCompleted {
+
+  // The origin of the update ie. the source of the time that was used in the update
+  // either COMPANION, NETWORK, NITZ, or GNSS
+  optional com.google.android.apps.wearable.settings.OriginTypeEnum origin_type = 1;
+
+  // Whether the attempt to time sync was successful
+  optional bool is_success = 2;
+
+  // How many times sync was attempted prior to this event, for this request
+  optional int32 number_of_retries = 3;
+
+  // Reason why the sync failed, if the attempt was a failure
+  // either TIMEOUT, LATENCY, or COMPANION_INVALID_RESPONSE
+  // null if the attempt was successful
+  optional com.google.android.apps.wearable.settings.FailureReasonEnum failure_reason = 4;
+}
+
+/**
+ * Logged whenever time sync actually updates the time on the device.
+ */
+message WearTimeChanged {
+
+  // The origin of the update ie. the source of the time that was used in the update
+  // either COMPANION, NETWORK, NITZ, or GNSS
+  optional com.google.android.apps.wearable.settings.OriginTypeEnum origin_type = 1;
+
+  // The absolute difference (skew) in timestamps between the old and new times
+  optional int64 time_difference_ms = 2;
+}
+
diff --git a/stats/atoms/wearservices/wearservices_extension_atoms.proto b/stats/atoms/wearservices/wearservices_extension_atoms.proto
index ae8b01e2..efc6d639 100644
--- a/stats/atoms/wearservices/wearservices_extension_atoms.proto
+++ b/stats/atoms/wearservices/wearservices_extension_atoms.proto
@@ -60,12 +60,33 @@ extend Atom {
     ws_complications_impacted_notification_event_reported = 804
       [(module) = "wearservices"];
 
+  optional WsRemoteEventUsageReported ws_remote_event_usage_reported = 920
+      [(module) = "wearservices"];
+
+    optional WsBugreportRequested ws_bugreport_requested = 936
+      [(module) = "wearservices"];
+
+  optional WsBugreportTriggered ws_bugreport_triggered = 937
+      [(module) = "wearservices"];
+
+  optional WsBugreportFinished ws_bugreport_finished = 938
+      [(module) = "wearservices"];
+
+  optional WsBugreportResultReceived ws_bugreport_result_received = 939
+      [(module) = "wearservices"];
+
   // Pulled Atom
   optional WsStandaloneModeSnapshot ws_standalone_mode_snapshot = 10197
       [(module) = "wearservices"];
 
   optional WsFavouriteWatchFaceSnapshot ws_favorite_watch_face_snapshot = 10206
       [(module) = "wearservices"];
+
+  optional WsPhotosWatchFaceFeatureSnapshot ws_photos_watch_face_feature_snapshot = 10225
+      [(module) = "wearservices"];
+
+  optional WsWatchFaceCustomizationSnapshot ws_watch_face_customization_snapshot = 10227
+      [(module) = "wearservices"];
 }
 
 /**
@@ -193,6 +214,7 @@ message WsWearTimeSession {
  */
 message WsOnBodyStateChanged {
   optional android.app.wearservices.OnBodyState on_body_state = 1;
+  optional int64 sensor_event_timestamp_nanos = 2;
 }
 
 /**
@@ -271,6 +293,37 @@ message WsFavouriteWatchFaceSnapshot {
   optional bool is_restricted = 8;
 }
 
+/**
+ * Snapshot for the types of watch face customizations done by the user till date.
+ */
+message WsWatchFaceCustomizationSnapshot {
+  // Indicates that the user customized a WF any time in the past.
+  optional bool customized_wf = 1;
+
+  // Indicates that the user switched to a pre-installed WF any time in the past.
+  optional bool switched_to_pre_installed_wf = 2;
+
+  // Indicates that the user switched to a non preinstalled WF any time in the past.
+  optional bool switched_to_non_preinstalled_wf = 3;
+}
+
+/**
+ * Snapshot of a photos watch face feature for the watch face favorite.
+ */
+message WsPhotosWatchFaceFeatureSnapshot {
+  // Watch face package uid.
+  optional int32 watch_face_package_uid = 1 [(is_uid) = true];
+
+  // An ID number generated on a watch to uniquely identify watch face instances.
+  // An Androidx watch face can be added multiple times to the favorites list and this field is used
+  // to differentiate each instance, without leaking any information about the watch face itself.
+  // Note: equals to -1 in case of WSL watch faces.
+  optional int32 favorite_id = 2;
+
+  // Contains types for photo selection.
+  optional android.app.wearservices.PhotoSelectionType photo_selection_type = 3;
+}
+
 /**
  * Logged whenever a user adds a watch face to the list of favorites and it contains
  * restricted default complications.
@@ -319,3 +372,54 @@ message WsComplicationsImpactedNotificationEventReported {
   }
   optional Event event = 1;
 }
+
+/**
+ * Logged whenever a remote event is being sent to the companion.
+ *
+ * Logged from package :
+ * vendor/google_clockwork_partners/packages/WearServices
+ */
+message WsRemoteEventUsageReported {
+
+  // Indicates the type of remote event being reported.
+  optional android.app.wearservices.RemoteEventType remote_event_type = 1;
+
+  // Indicates the status of the remote event being sent.
+  optional bool is_successful = 2;
+}
+
+/** Logged when WearServices triggers a bugreport to be captured. */
+message WsBugreportTriggered {
+}
+
+/** Logged when WearServices receives a request to capture a bugreport. */
+message WsBugreportRequested {
+
+  // Depicts the request source of the bugreport
+  // Values: (BUGREPORT_COMPONENT_UNKNOWN, BUGREPORT_COMPONENT_COMPANION_APP, BUGREPORT_COMPONENT_WATCH_UI)
+  optional android.app.wearservices.BugreportComponent requester = 1;
+
+}
+
+/** Logged when WearServices receives back the captured bugreport. */
+message WsBugreportFinished {
+
+  // Depicts the result of the bugreport
+  // Values: (BUGREPORT_RESULT_UNKNOWN, BUGREPORT_RESULT_SUCCESS, BUGREPORT_RESULT_FAILURE)
+  optional android.app.wearservices.BugreportResult result = 1;
+
+  // Depicts the size of the bugreport in bytes
+  optional int32 bugreport_size_bytes = 2;
+}
+
+/** Logged when a component receives back the captured bugreport. */
+message WsBugreportResultReceived {
+
+  // Depicts the receiver of the bugreport
+  // Values: (BUGREPORT_COMPONENT_UNKNOWN, BUGREPORT_COMPONENT_COMPANION_APP, BUGREPORT_COMPONENT_WATCH_UI)
+  optional android.app.wearservices.BugreportComponent receiver = 1;
+
+  // Depicts the result of the bugreport
+  // Values: (BUGREPORT_RESULT_UNKNOWN, BUGREPORT_RESULT_SUCCESS, BUGREPORT_RESULT_FAILURE)
+  optional android.app.wearservices.BugreportResult result = 2;
+}
\ No newline at end of file
diff --git a/stats/atoms/wearsysui/wearsysui_extension_atoms.proto b/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
index abf7551e..3946fe1d 100644
--- a/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
+++ b/stats/atoms/wearsysui/wearsysui_extension_atoms.proto
@@ -30,6 +30,8 @@ extend Atom {
   [(module) = "framework"];
   optional WearAssistantOpened wear_assistant_opened = 755
   [(module) = "framework"];
+  optional FirstOverlayStateChanged first_overlay_state_changed = 917
+  [(module) = "framework"];
 }
 
 /**
@@ -49,4 +51,26 @@ message WearPowerMenuOpened {
  */
 message WearAssistantOpened {
   optional bool in_retail_mode = 1;
-}
\ No newline at end of file
+}
+
+/**
+ * Logs for First Overlay State Changes
+ *
+ */
+message FirstOverlayStateChanged {
+    enum OverlayState {
+        UNKNOWN = 0;
+        // The overlay is shown during boot.
+        SHOWN = 1;
+        // The overlay is dismissed to indicate boot is complete.
+        DISMISSED = 2;
+    }
+
+    optional OverlayState overlay_state = 1;
+    // The time when first overlay is shown, in milliseconds since the system was booted.
+    optional int64 time_to_overlay_shown_ms = 2;
+    // The time when first overlay is dismissed, in milliseconds since the system was booted.
+    optional int64 time_to_overlay_dismissed_ms = 3;
+    // Indicates whether the lock screen is enabled
+    optional bool is_locked_screen_active = 4;
+}
diff --git a/stats/atoms/wifi/wifi_extension_atoms.proto b/stats/atoms/wifi/wifi_extension_atoms.proto
index fdc3d85e..87cdf4f3 100644
--- a/stats/atoms/wifi/wifi_extension_atoms.proto
+++ b/stats/atoms/wifi/wifi_extension_atoms.proto
@@ -233,6 +233,8 @@ message SoftApStarted {
     optional android.net.wifi.StaStatus sta_status = 7;
     // Authentication type of the Soft AP
     optional android.net.wifi.WifiAuthType auth_type = 8;
+    // The uid of the caller
+    optional int32 uid = 9 [(is_uid) = true];
 }
 
 /**
@@ -727,11 +729,23 @@ message ScorerPredictionResultReported {
     }
     enum DeviceState {
         STATE_UNKNOWN = 0;
-        STATE_PREDICT_ONLY = 1; // Measures theoretical performance. Collected when adaptive connectivity is off.
-        STATE_CELLULAR_OFF = 2; // Cellular data is disabled.
-        STATE_CELLULAR_UNAVAILABLE = 3; // Measures actual performance based on a subset of data collected cellular data is toggled on, but unavailable.
-        STATE_LINGERING = 4;
-        STATE_OTHERS = 5;
+        STATE_NO_CELLULAR_MODEM = 1; // Cellular modem not available
+        STATE_NO_SIM_INSERTED = 2; // SIM not inserted
+        STATE_SCORING_DISABLED = 3; // Measures theoretical performance. Collected when adaptive connectivity is toggled off on Pixel, or scoring is disabled.
+        STATE_CELLULAR_OFF = 4; // Cellular data is disabled.
+        STATE_CELLULAR_UNAVAILABLE = 5; // Measures actual performance based on a subset of data collected cellular data is toggled on, but unavailable.
+        STATE_OTHERS = 6;
+    }
+    enum WifiFrameworkState {
+        FRAMEWORK_STATE_UNKNOWN = 0;
+        FRAMEWORK_STATE_AWAKENING = 1; // WiFi framework just woke up and this is the first RSSI poll.
+        FRAMEWORK_STATE_CONNECTED = 2; // Normal operation (most of the time is spent in this state).
+        FRAMEWORK_STATE_LINGERING = 3; // We are in the lingering period. i.e. We have recommended a switch to cellular but have not forecefully closed the WiFi connection yet.
+    }
+    enum TrueFalseUnknown {
+        UNKNOWN = 0;
+        TRUE = 1;
+        FALSE = 2;
     }
     // The AttributionNode to identify the caller
     repeated AttributionNode attribution_node = 1;
@@ -745,4 +759,14 @@ message ScorerPredictionResultReported {
     optional DeviceState device_state = 5;
     // RSSI polling interval, which affects the scorer's prediction interval.
     optional int32 rssi_polling_interval_ms = 6;
+    // Current state of the WiFi framework.
+    optional WifiFrameworkState wifi_framework_state = 7;
+    // NetworkCapabilities calculated link speed is sufficient in the downstream direction.
+    optional TrueFalseUnknown speed_sufficient_network_capabilities_ds = 8;
+    // NetworkCapabilities calculated link speed is sufficient in the upstream direction.
+    optional TrueFalseUnknown speed_sufficient_network_capabilities_us = 9;
+    // ThroughputPredictor calculated link speed is sufficient in the downstream direction.
+    optional TrueFalseUnknown speed_sufficient_throughput_predictor_ds = 10;
+    // ThroughputPredictor calculated link speed is sufficient in the upstream direction.
+    optional TrueFalseUnknown speed_sufficient_throughput_predictor_us = 11;
 }
diff --git a/stats/enums/accessibility/Android.bp b/stats/enums/accessibility/Android.bp
new file mode 100644
index 00000000..8ab703e3
--- /dev/null
+++ b/stats/enums/accessibility/Android.bp
@@ -0,0 +1,28 @@
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
+java_library_static {
+    name: "accessibility_protos_lite",
+    sdk_version: "core_current",
+    proto: {
+        type: "lite",
+    },
+    srcs: [
+        "*.proto",
+    ],
+}
diff --git a/stats/enums/accessibility/enums.proto b/stats/enums/accessibility/enums.proto
new file mode 100644
index 00000000..e61491f8
--- /dev/null
+++ b/stats/enums/accessibility/enums.proto
@@ -0,0 +1,31 @@
+syntax = "proto2";
+
+package android.accessibility;
+
+option java_outer_classname = "AccessibilityEnums";
+option java_multiple_files = true;
+
+/** The AccessibilityCheck class. */
+enum AccessibilityCheckClass {
+  UNKNOWN_CHECK = 0;
+  CLASS_NAME_CHECK = 1;
+  CLICKABLE_SPAN_CHECK = 2;
+  DUPLICATE_CLICKABLE_BOUNDS_CHECK = 3;
+  DUPLICATE_SPEAKABLE_TEXT_CHECK = 4;
+  EDITABLE_CONTENT_DESC_CHECK = 5;
+  IMAGE_CONTRAST_CHECK = 6;
+  LINK_PURPOSE_UNCLEAR_CHECK = 7;
+  REDUNDANT_DESCRIPTION_CHECK = 8;
+  SPEAKABLE_TEXT_PRESENT_CHECK = 9;
+  TEXT_CONTRAST_CHECK = 10;
+  TEXT_SIZE_CHECK = 11;
+  TOUCH_TARGET_SIZE_CHECK = 12;
+  TRAVERSAL_ORDER_CHECK = 13;
+}
+
+/** The type of AccessibilityCheckResult */
+enum AccessibilityCheckResultType {
+  UNKNOWN_CHECK_RESULT_TYPE = 0;
+  ERROR_CHECK_RESULT_TYPE = 1;
+  WARNING_CHECK_RESULT_TYPE = 2;
+}
diff --git a/stats/enums/adservices/common/adservices_cel_enums.proto b/stats/enums/adservices/common/adservices_cel_enums.proto
new file mode 100644
index 00000000..07e8db64
--- /dev/null
+++ b/stats/enums/adservices/common/adservices_cel_enums.proto
@@ -0,0 +1,934 @@
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
+syntax = "proto2";
+package android.adservices.common;
+
+option java_multiple_files = true;
+
+/**
+ * Enum representing an error/exception.  These errors can be common to all
+ * PPAPIs or specific to a particular API. We will group enums in blocks of
+ * 1000 like this below:
+ * - Common errors: 1-1000
+ * - Topics errors: 1001-2000
+ * - Measurement errors: 2001-3000
+ * - Fledge errors: 3001-4000
+ * - UX errors: 4001-5000
+ * - FederatedCompute errors: 5001-6000
+ * - Back Compat errors: 6001-7000
+ * - IAPC errors: 7001 - 8000
+ * - ODP errors: 8001-9000
+ *
+ * NOTE: AdId / AdSetId don't have a range yet (because they're just using common codes)
+ */
+enum ErrorCode {
+  // Common Errors: 1-1000
+  ERROR_CODE_UNSPECIFIED = 0;
+  DATABASE_READ_EXCEPTION = 1;
+  DATABASE_WRITE_EXCEPTION = 2;
+  API_REMOTE_EXCEPTION = 3;
+
+  // Error occurred when unable to send result to the callback.
+  API_CALLBACK_ERROR = 4;
+
+  // Error occurred when failed to call the callback on Rate Limit Reached.
+  RATE_LIMIT_CALLBACK_FAILURE = 5;
+
+  // Error occurred when calling package name is not found.
+  PACKAGE_NAME_NOT_FOUND_EXCEPTION = 6;
+
+  // Shared pref update failure.
+  SHARED_PREF_UPDATE_FAILURE = 7;
+
+  // Shared pref reset failure.
+  SHARED_PREF_RESET_FAILURE = 8;
+
+  // Remote exception when calling the Cobalt upload API.
+  COBALT_UPLOAD_API_REMOTE_EXCEPTION = 9;
+
+  // Exception occurred when parsing the Adservices Config XML provided by an app.
+  APP_MANIFEST_CONFIG_PARSING_ERROR = 10;
+
+  // Generic exception when dealing with shared prefs.
+  SHARED_PREF_EXCEPTION = 11;
+
+  // Error logging an API check using Adservices Config XML provided by an app.
+  APP_MANIFEST_CONFIG_LOGGING_ERROR = 12;
+
+  // Incorrect version of the json file.
+  ENCRYPTION_KEYS_INCORRECT_JSON_VERSION = 13;
+
+  // JSON parsing error for the key.
+  ENCRYPTION_KEYS_JSON_PARSING_ERROR = 14;
+
+  // Failed to delete an expired encryption key.
+  ENCRYPTION_KEYS_FAILED_DELETE_EXPIRED_KEY = 15;
+
+  // Failed to load Encryption Keys MDD filegroup
+  ENCRYPTION_KEYS_FAILED_MDD_FILEGROUP = 16;
+
+  // Encryption Keys no MDD files available.
+  ENCRYPTION_KEYS_MDD_NO_FILE_AVAILABLE = 17;
+
+  // JobScheduler is not available.
+  JOB_SCHEDULER_IS_UNAVAILABLE = 18;
+
+  // Failed to encrypt data in Cobalt.
+  COBALT_ENCRYPTION_FAILED_EXCEPTION = 19;
+
+  // Failed to fabricate Cobalt observations.
+  COBALT_PRIVACY_GENERATION_EXCEPTION = 20;
+
+  // Cobalt logger initialization failed in AppNameApiErrorLogger.
+  COBALT_API_ERROR_LOGGER_INITIALIZATION_EXCEPTION = 21;
+
+  // Write to atomic file datastore failed.
+  ATOMIC_FILE_DATASTORE_WRITE_FAILURE = 22;
+
+  // Read from atomic file datastore failed.
+  ATOMIC_FILE_DATASTORE_READ_FAILURE = 23;
+
+  // Error while parsing bytes to proto failure.
+  PROTO_PARSER_INVALID_PROTO_ERROR = 24;
+
+  // Error while decoding Base64 encoded string to bytes.
+  PROTO_PARSER_DECODE_BASE64_ENCODED_STRING_TO_BYTES_ERROR = 25;
+
+  // Error code is present multiple times in the custom sampling proto
+  ERROR_CODE_PRESENT_MULTIPLE_TIMES_IN_PROTO = 26;
+
+  // SPE Errors: 901 - 1000
+  // Get an unavailable job execution start timestamp when calculating the execution latency.
+  SPE_UNAVAILABLE_JOB_EXECUTION_START_TIMESTAMP = 901;
+
+  // Get an invalid execution period during the calculation.
+  SPE_INVALID_EXECUTION_PERIOD = 902;
+
+  // Failed to persist execution start time in the storage.
+  SPE_FAIL_TO_COMMIT_JOB_EXECUTION_START_TIME = 903;
+
+  // Failed to persist execution stop time in the storage.
+  SPE_FAIL_TO_COMMIT_JOB_EXECUTION_STOP_TIME = 904;
+
+  // Execution failure.
+  SPE_JOB_EXECUTION_FAILURE = 905;
+
+  // JobScheduler is not available.
+  SPE_JOB_SCHEDULER_IS_UNAVAILABLE = 906;
+
+  // Invalid Job Policy configured in the server.
+  SPE_INVALID_JOB_POLICY_SYNC = 907;
+
+  // Job is not configured correctly.
+  SPE_JOB_NOT_CONFIGURED_CORRECTLY = 908;
+
+  // Scheduling Failure.
+  SPE_JOB_SCHEDULING_FAILURE = 909;
+
+  // Failure of the customized logic in onStopJob().
+  SPE_JOB_ON_STOP_EXECUTION_FAILURE = 910;
+
+  // Error during future cancellation process.
+  SPE_FUTURE_CANCELLATION_ERROR = 911;
+
+  // Topics errors: 1001-2000
+  // Remote exception when calling get topics.
+  GET_TOPICS_REMOTE_EXCEPTION = 1001;
+
+  // Topics API is disabled.
+  TOPICS_API_DISABLED = 1002;
+
+  // SQLException occurred when failed to persist classified Topics.
+  TOPICS_PERSIST_CLASSIFIED_TOPICS_FAILURE = 1003;
+
+  // SQLException occurred when failed to persist Top Topics.
+  TOPICS_PERSIST_TOP_TOPICS_FAILURE = 1004;
+
+  // SQLException occurred when failed to record App-Sdk usage history.
+  TOPICS_RECORD_APP_SDK_USAGE_FAILURE = 1005;
+
+  // SQLException occurred when failed to record App Only usage history.
+  TOPICS_RECORD_APP_USAGE_FAILURE = 1006;
+
+  // SQLException occurred when failed to record can learn topic.
+  TOPICS_RECORD_CAN_LEARN_TOPICS_FAILURE = 1007;
+
+  // SQLException occurred when failed to record returned topic.
+  TOPICS_RECORD_RETURNED_TOPICS_FAILURE = 1008;
+
+  // SQLException occurred when failed to record returned topic.
+  TOPICS_RECORD_BLOCKED_TOPICS_FAILURE = 1009;
+
+  // SQLException occurred when failed to remove blocked topic.
+  TOPICS_DELETE_BLOCKED_TOPICS_FAILURE = 1010;
+
+  // SQLException occurred when failed to delete old epochs.
+  TOPICS_DELETE_OLD_EPOCH_FAILURE = 1011;
+
+  // SQLException occurred when failed to delete a column in table
+  TOPICS_DELETE_COLUMN_FAILURE = 1012;
+
+  // SQLException occurred when failed to persist topic contributors.
+  TOPICS_PERSIST_TOPICS_CONTRIBUTORS_FAILURE = 1013;
+
+  // SQLException occurred when failed to delete all entries from table.
+  TOPICS_DELETE_ALL_ENTRIES_IN_TABLE_FAILURE = 1014;
+
+  // Exception occurred when classify call failed.
+  TOPICS_ON_DEVICE_CLASSIFY_FAILURE = 1015;
+
+  // Exception occurred ML model did not return a topic id.
+  TOPICS_ON_DEVICE_NUMBER_FORMAT_EXCEPTION = 1016;
+
+  // Exception occurred when failed to load ML model.
+  TOPICS_LOAD_ML_MODEL_FAILURE = 1017;
+
+  // Exception occurred when unable to retrieve topics id to topics name.
+  TOPICS_ID_TO_NAME_LIST_READ_FAILURE = 1018;
+
+  // Exception occurred when unable to read classifier asset file.
+  TOPICS_READ_CLASSIFIER_ASSET_FILE_FAILURE = 1019;
+
+  // NoSuchAlgorithmException occurred when unable to find correct message.
+  // digest algorithm.
+  TOPICS_MESSAGE_DIGEST_ALGORITHM_NOT_FOUND = 1020;
+
+  // Error occurred when failed to find downloaded classifier model file.
+  DOWNLOADED_CLASSIFIER_MODEL_FILE_NOT_FOUND = 1021;
+
+  // No downloaded or bundled classifier model available.
+  NO_CLASSIFIER_MODEL_AVAILABLE = 1022;
+
+  // Error occurred when failed to read labels file.
+  READ_LABELS_FILE_FAILURE = 1023;
+
+  // Error occurred when failed to read precomuted labels.
+  READ_PRECOMUTRED_LABELS_FAILURE = 1024;
+
+  // Error occurred when failed to read top apps file.
+  READ_TOP_APPS_FILE_FAILURE = 1025;
+
+  // Error occurred when saving a topic not in labels file.
+  INVALID_TOPIC_ID = 1026;
+
+  // Error occurred when failed to read precomuted app topics list.
+  READ_PRECOMUTRED_APP_TOPICS_LIST_FAILURE = 1027;
+
+  // Error occurred when failed to read bundled metadata file.
+  READ_BUNDLED_METADATA_FILE_FAILURE = 1028;
+
+  // Error occurred when reading redundant metadata property.
+  CLASSIFIER_METADATA_REDUNDANT_PROPERTY = 1029;
+
+  // Error occurred when reading redundant metadata asset.
+  CLASSIFIER_METADATA_REDUNDANT_ASSET = 1030;
+
+  // Error occurred when parsing metadata json missing property or asset_name.
+  CLASSIFIER_METADATA_MISSING_PROPERTY_OR_ASSET_NAME = 1031;
+
+  // Error occurred when failed to read classifier assets metadata file.
+  READ_CLASSIFIER_ASSETS_METADATA_FAILURE = 1032;
+
+  // Error occurred when failed to load downloaded file by file Id.
+  DOWNLOADED_CLASSIFIER_MODEL_FILE_LOAD_FAILURE = 1033;
+
+  // RuntimeException occurred when use invalid type of blocked topics
+  // source of truth.
+  TOPICS_INVALID_BLOCKED_TOPICS_SOURCE_OF_TRUTH = 1034;
+
+  // RuntimeException occurred when unable to remove the blocked topic.
+  TOPICS_REMOVE_BLOCKED_TOPIC_FAILURE = 1035;
+
+  // RuntimeException occurred when unable to get all blocked topics.
+  TOPICS_GET_BLOCKED_TOPIC_FAILURE = 1036;
+
+  // RuntimeException occurred when unable to clear all blocked topics
+  // in system server.
+  TOPICS_CLEAR_ALL_BLOCKED_TOPICS_IN_SYSTEM_SERVER_FAILURE = 1037;
+
+  // Error occurred when unable to handle JobService.
+  TOPICS_HANDLE_JOB_SERVICE_FAILURE = 1038;
+
+  // Error occurred when unable to fetch job scheduler.
+  TOPICS_FETCH_JOB_SCHEDULER_FAILURE = 1039;
+
+  // Error occurred while deleting a table for Topics.
+  TOPICS_DELETE_TABLE_FAILURE = 1040;
+
+  // Cobalt initialisation failure for Topics.
+  TOPICS_COBALT_LOGGER_INITIALIZATION_FAILURE = 1041;
+
+  // Failure to convert plaintext topic object to encrypted topic.
+  TOPICS_ENCRYPTION_FAILURE = 1042;
+
+  // Topics encryption key with invalid length.
+  TOPICS_ENCRYPTION_INVALID_KEY_LENGTH = 1043;
+
+  // Topics encryption with invalid response length.
+  TOPICS_ENCRYPTION_INVALID_RESPONSE_LENGTH = 1044;
+
+  // Topics encryption key failed to decode with Base64 decoder.
+  TOPICS_ENCRYPTION_KEY_DECODE_FAILURE = 1045;
+
+  // Topics encryption received null params in request for the encrypter.
+  TOPICS_ENCRYPTION_NULL_REQUEST = 1046;
+
+  // Topics encryption received null response from the encrypter.
+  TOPICS_ENCRYPTION_NULL_RESPONSE = 1047;
+
+  // Topics encryption received error while serialization to JSON.
+  TOPICS_ENCRYPTION_SERIALIZATION_ERROR = 1048;
+
+  // Topics encryption public key is missing.
+  TOPICS_ENCRYPTION_KEY_MISSING = 1049;
+
+  // Topics API request has empty sdk name.
+  TOPICS_REQUEST_EMPTY_SDK_NAME = 1050;
+
+  // Measurement errors: 2001-3000
+  // Error occurred when inserting enrollment data to DB.
+  ENROLLMENT_DATA_INSERT_ERROR = 2001;
+
+  // Error occurred when deleting enrollment data to DB.
+  ENROLLMENT_DATA_DELETE_ERROR = 2002;
+
+  // Measurement foreground unknown failure.
+  MEASUREMENT_FOREGROUND_UNKNOWN_FAILURE = 2003;
+
+  // Measurement datastore failure.
+  MEASUREMENT_DATASTORE_FAILURE = 2004;
+
+  // Measurement datastore unknown failure.
+  MEASUREMENT_DATASTORE_UNKNOWN_FAILURE = 2005;
+
+  // Measurement invalid parameter fetching public keys.
+  MEASUREMENT_PUBLIC_KEY_FETCHER_INVALID_PARAMETER = 2006;
+
+  // Measurement IO exception while fetching public keys.
+  MEASUREMENT_PUBLIC_KEY_FETCHER_IO_ERROR = 2007;
+
+  // Measurement error while parsing public keys.
+  MEASUREMENT_PUBLIC_KEY_FETCHER_PARSING_ERROR = 2008;
+
+  // Failure to save seed in SharedPreferences
+  ENROLLMENT_SHARED_PREFERENCES_SEED_SAVE_FAILURE = 2009;
+
+  // When report deliver fails due to a network issue (IOException).
+  MEASUREMENT_REPORTING_NETWORK_ERROR = 2010;
+
+  // When report delivery fails due to report building as JSON.
+  MEASUREMENT_REPORTING_PARSING_ERROR = 2011;
+
+  // When encryption of aggregate report fails.
+  MEASUREMENT_REPORTING_ENCRYPTION_ERROR = 2012;
+
+  // Reporting errors should have specific error codes.
+  MEASUREMENT_REPORTING_UNKNOWN_ERROR = 2013;
+
+  // When parsing of enrollment file fails.
+  ENROLLMENT_FAILED_PARSING = 2014;
+
+  // Error occurred when encountering invalid enrollment.
+  ENROLLMENT_INVALID = 2015;
+
+  // Error occurred when trying to get instance of an ODP system event manager
+  MEASUREMENT_REGISTRATION_ODP_GET_MANAGER_ERROR = 2016;
+
+  // Error due to the ODP header being in an invalid format
+  MEASUREMENT_REGISTRATION_ODP_INVALID_HEADER_FORMAT_ERROR = 2017;
+
+  // Error due to the ODP header missing a required field
+  MEASUREMENT_REGISTRATION_ODP_MISSING_REQUIRED_HEADER_FIELD_ERROR = 2018;
+
+  // Error due to the ODP header containing a field with an invalid value
+  MEASUREMENT_REGISTRATION_ODP_INVALID_HEADER_FIELD_VALUE_ERROR = 2019;
+
+  // Error occurred when trying to parse the ODP header (JSON Exception)
+  MEASUREMENT_REGISTRATION_ODP_JSON_PARSING_ERROR = 2020;
+
+  // Error occurred when trying to parse the ODP header (Unknown Exception)
+  MEASUREMENT_REGISTRATION_ODP_PARSING_UNKNOWN_ERROR = 2021;
+
+  // Error occurred when trying to initialize cobalt logger for measurement metrics.
+  MEASUREMENT_COBALT_LOGGER_INITIALIZATION_FAILURE = 2022;
+
+  // Fledge (PA), PAS errors: 3001 - 4000
+  // Exception while PAS unable to find the service.
+  PAS_UNABLE_FIND_SERVICES = 3001;
+
+  // Error occurred when ProtectedSignalsManager get a remote exception.
+  PAS_MANAGER_REMOTE_EXCEPTION = 3002;
+
+  // Exception while ProtectedSignalsServiceImpl has a null argument.
+  PAS_SERVICE_IMPL_NULL_ARGUMENT = 3003;
+
+  // FilterException because user consent revoked.
+  PAS_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3004;
+
+  // FilterException because background caller happened.
+  PAS_FILTER_EXCEPTION_BACKGROUND_CALLER = 3005;
+
+  // FilterException because caller not allowed.
+  PAS_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3006;
+
+  // FilterException because unauthorized.
+  PAS_FILTER_EXCEPTION_UNAUTHORIZED = 3007;
+
+  // FilterException because rate limit reached.
+  PAS_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3008;
+
+  // FilterException because internal error happened.
+  PAS_FILTER_EXCEPTION_INTERNAL_ERROR = 3009;
+
+  // Exception while failed to get enrollment data for buyer.
+  PAS_GET_ENROLLMENT_AD_TECH_ID_FAILURE = 3010;
+
+  // Error occurred when Fledge consent revoked.
+  PAS_FLEDGE_CONSENT_NOT_GIVEN = 3011;
+
+  // Error occurred when Fledge consent revoked for app after setting Fledge use.
+  PAS_FLEDGE_CONSENT_REVOKED_FOR_APP_AFTER_SETTING_FLEDGE_USE = 3012;
+
+  // Error encountered in updateSignals, unpacking from ExecutionException and notifying caller.
+  PAS_EXECUTION_EXCEPTION = 3013;
+
+  // Exception while unable to send result to the callback.
+  PAS_UNABLE_SEND_RESULT_TO_CALLBACK = 3014;
+
+  // Exception while PAS get illegal calling UID.
+  PAS_GET_CALLING_UID_ILLEGAL_STATE = 3015;
+
+  // FilterException occurred in PAS notifyFailure because user consent revoked.
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3016;
+
+  // FilterException occurred in PAS notifyFailure because background caller happened.
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3017;
+
+  // FilterException occurred in PAS notifyFailure because caller not allowed.
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3018;
+
+  // FilterException occurred in PAS notifyFailure because unauthorized.
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3019;
+
+  // FilterException occurred in PAS notifyFailure because rate limit reached
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3020;
+
+  // FilterException occurred in PAS notifyFailure because internal error happened.
+  PAS_NOTIFY_FAILURE_FILTER_EXCEPTION_INTERNAL_ERROR = 3021;
+
+  // Exception occurred in PAS notifyFailure because invalid argument.
+  PAS_NOTIFY_FAILURE_INVALID_ARGUMENT = 3022;
+
+  // Unexpected error during PAS operation.
+  PAS_UNEXPECTED_ERROR_DURING_OPERATION = 3023;
+
+  // Exception while PPAPI only Fledge consent check failed in ConsentManager.
+  FLEDGE_CONSENT_MANAGER_PPAPI_ONLY_FLEDGE_CONSENT_CHECK_FAILED = 3024;
+
+  // Exception while PPAPI and system server Fledge consent check failed in ConsentManager.
+  FLEDGE_CONSENT_MANAGER_PPAPI_AND_SYSTEM_SERVER_FLEDGE_CONSENT_CHECK_FAILED = 3025;
+
+  // Exception while PPAPI and ExtService consent failed in ConsentManager.
+  FLEDGE_CONSENT_MANAGER_PPAPI_AND_ADEXT_SERVICE_CONSENT_FAILED = 3026;
+
+  // Exception while invalid consent source of truth in ConsentManager.
+  FLEDGE_CONSENT_MANAGER_INVALID_CONSENT_SOURCE_OF_TRUTH = 3027;
+
+  // Exception because PAS validate and persist encoded payload failure.
+  PAS_VALIDATE_AND_PERSIST_ENCODED_PAYLOAD_FAILURE = 3028;
+
+  // Exception because PAS encoded payload size exceeds limits.
+  PAS_ENCODED_PAYLOAD_SIZE_EXCEEDS_LIMITS = 3029;
+
+  // Exception because of failed per buyer encoding of PAS.
+  PAS_FAILED_PER_BUYER_ENCODING = 3030;
+
+  // Exception when processing JSON version of signals.
+  PAS_PROCESSING_JSON_VERSION_OF_SIGNALS_FAILURE = 3031;
+
+  // Exception because null PAS null encoding script result.
+  PAS_NULL_ENCODING_SCRIPT_RESULT = 3032;
+
+  // Exception because PAS empty script result.
+  PAS_EMPTY_SCRIPT_RESULT = 3033;
+
+  // Exception because PAS JS execution is unsuccessful.
+  PAS_JS_EXECUTION_STATUS_UNSUCCESSFUL = 3034;
+
+  // Exception because PAS malformed encoded payload.
+  PAS_MALFORMED_ENCODED_PAYLOAD = 3035;
+
+  // Exception because PAS could not extract the encoded payload result.
+  PAS_PROCESS_ENCODED_PAYLOAD_RESULT_FAILURE = 3036;
+
+  // Exception because semantic error during PAS JSON processing.
+  PAS_JSON_PROCESSING_STATUS_SEMANTIC_ERROR = 3037;
+
+  // Exception because PAS unpack signal updates JSON failure.
+  PAS_UNPACK_SIGNAL_UPDATES_JSON_FAILURE = 3038;
+
+  // Error occurred because PAS collision error.
+  PAS_COLLISION_ERROR = 3039;
+
+  // Error occurred when converting updateSignals response body to JSON.
+  PAS_CONVERTING_UPDATE_SIGNALS_RESPONSE_TO_JSON_ERROR = 3040;
+
+  // Error occurred because empty response from client for downloading PAS encoder.
+  PAS_EMPTY_RESPONSE_FROM_CLIENT_DOWNLOADING_ENCODER = 3041;
+
+  // Error occurred because invalid or missing encoder version.
+  PAS_INVALID_OR_MISSING_ENCODER_VERSION = 3042;
+
+  // Error occurred because updating for encoding logic on persistence layer failed.
+  PAS_UPDATE_FOR_ENCODING_LOGIC_ON_PERSISTENCE_LAYER_FAILED = 3043;
+
+  // Exception because GetAdSelectionData auction server API not available.
+  GET_AD_SELECTION_DATA_AUCTION_SERVER_API_NOT_AVAILABLE = 3044;
+
+  // Exception because null argument in GetAdSelectionData.
+  GET_AD_SELECTION_DATA_NULL_ARGUMENT = 3045;
+
+  // Exception because PersistAdSelectionResult auction server API not available.
+  PERSIST_AD_SELECTION_RESULT_AUCTION_SERVER_API_NOT_AVAILABLE = 3046;
+
+  // Exception because null argument in PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_NULL_ARGUMENT = 3047;
+
+  // Exception because GetAdSelectionData get illegal calling UID.
+  GET_AD_SELECTION_DATA_GET_CALLING_UID_ILLEGAL_STATE = 3048;
+
+  // Exception because PersistAdSelectionResult get illegal calling UID.
+  PERSIST_AD_SELECTION_RESULT_GET_CALLING_UID_ILLEGAL_STATE = 3049;
+
+  // Exception because no match found, failing calling package name match in GetAdSelectionData.
+  GET_AD_SELECTION_DATA_NO_MATCH_PACKAGE_NAME = 3050;
+
+  // Exception because no match found, failing calling package name match
+  // in PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_NO_MATCH_PACKAGE_NAME = 3051;
+
+  // Exception because one permission not declared by caller in GetAdSelectionData.
+  GET_AD_SELECTION_DATA_PERMISSION_FAILURE = 3052;
+
+  // Exception because one permission not declared by caller in PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_PERMISSION_FAILURE = 3053;
+
+  // Exception because any permission not declared by caller in GetAdSelectionData.
+  GET_AD_SELECTION_DATA_ANY_PERMISSION_FAILURE = 3054;
+
+  // Exception because any permission not declared by caller in PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_ANY_PERMISSION_FAILURE = 3055;
+
+  // Exception because enrollment data match not found for ad tech while calling GetAdSelectionData.
+  GET_AD_SELECTION_DATA_ENROLLMENT_DATA_MATCH_NOT_FOUND = 3056;
+
+  // Exception because enrollment data match not found for ad tech while calling
+  // PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_ENROLLMENT_DATA_MATCH_NOT_FOUND = 3057;
+
+  // Error occurred because app package name with ad tech identifier not authorized
+  // to call GetAdSelectionData.
+  GET_AD_SELECTION_DATA_AD_TECH_NOT_AUTHORIZED_BY_APP = 3058;
+
+  // Error occurred because app package name with ad tech identifier not authorized
+  // to call PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_AD_TECH_NOT_AUTHORIZED_BY_APP = 3059;
+
+  // Error occurred because enrollment is in block list to call GetAdSelectionData.
+  GET_AD_SELECTION_DATA_NOT_ALLOWED_ENROLLMENT_BLOCKLISTED = 3060;
+
+  // Error occurred because enrollment is in block list to call PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_NOT_ALLOWED_ENROLLMENT_BLOCKLISTED = 3061;
+
+  // Exception because user consent for GetAdSelectionData is not given.
+  GET_AD_SELECTION_DATA_USER_CONSENT_FOR_API_IS_NOT_GIVEN = 3062;
+
+  // Exception because user consent for PersistAdSelectionResult is not given.
+  PERSIST_AD_SELECTION_RESULT_USER_CONSENT_FOR_API_IS_NOT_GIVEN = 3063;
+
+  // Exception because user consent for PAS is not given.
+  PAS_CONSENT_REVOKED_FOR_APP = 3064;
+
+  // Exception because of PAS missing any notification displayed.
+  PAS_MISSING_ANY_NOTIFICATION_DISPLAYED = 3065;
+
+  // Exception because of GetAdSelectionData missing any notification displayed.
+  GET_AD_SELECTION_DATA_MISSING_ANY_NOTIFICATION_DISPLAYED = 3066;
+
+  // Exception because of PersistAdSelectionResult missing any notification displayed.
+  PERSIST_AD_SELECTION_RESULT_MISSING_ANY_NOTIFICATION_DISPLAYED = 3067;
+
+  // Exception because all APIs consent disabled for PAS.
+  PAS_ALL_APIS_CONSENT_DISABLED = 3068;
+
+  // Exception because all APIs consent disabled for GetAdSelectionData.
+  GET_AD_SELECTION_DATA_ALL_APIS_CONSENT_DISABLED = 3069;
+
+  // Exception because all APIs consent disabled for PersistAdSelectionResult.
+  PERSIST_AD_SELECTION_RESULT_ALL_APIS_CONSENT_DISABLED = 3070;
+
+  // Exception because filter and revoked consent exception in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_FILTER_AND_REVOKED_CONSENT_EXCEPTION = 3071;
+
+  // Exception because AdServices exception in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_ADSERVICES_EXCEPTION = 3072;
+
+  // Exception because unsupported payload size in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_UNSUPPORTED_PAYLOAD_SIZE_EXCEPTION = 3073;
+
+  // Exception because runOutcomeSelection fails fast with exception in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_RUNNER_OUTCOME_SELECTION_FAILURE = 3074;
+
+  // Exception because GetAdSelectionDataRunner exceeded allowed time limit.
+  GET_AD_SELECTION_DATA_RUNNER_EXCEEDED_ALLOWED_TIME_LIMIT = 3075;
+
+  // Error occurred when creating response with AssetFileDescriptor in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_CREATE_ASSET_FILE_DESCRIPTOR_ERROR = 3076;
+
+  // Exception during notifying GetAdSelectionDataCallback success in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_SUCCESS_CALLBACK_ERROR = 3077;
+
+  // Exception during notifying GetAdSelectionDataCallback empty success
+  // in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_EMPTY_SUCCESS_CALLBACK_ERROR = 3078;
+
+  // Exception during notifying GetAdSelectionDataCallback failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_CALLBACK_ERROR = 3079;
+
+  // Exception of timeout during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_TIMEOUT = 3080;
+
+  // Exception of JS sandbox unavailable during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_JS_SANDBOX_UNAVAILABLE = 3081;
+
+  // Exception of invalid argument during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_INVALID_ARGUMENT = 3082;
+
+  // Exception of internal error during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_INTERNAL_ERROR = 3083;
+
+  // Exception of user consent revoked during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3084;
+
+  // Exception of background caller during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3085;
+
+  // Exception of caller not allowed during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3086;
+
+  // Exception of unauthorized during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3087;
+
+  // Exception of rate limit reached during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3088;
+
+  // Exception of internal error during notifying failure in GetAdSelectionDataRunner.
+  GET_AD_SELECTION_DATA_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_INTERNAL_ERROR = 3089;
+
+  // Exception because filter and revoked consent exception in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_REVOKED_CONSENT_FILTER_EXCEPTION = 3090;
+
+  // Exception because AdServices exception in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_ADSERVICES_EXCEPTION = 3091;
+
+  // Exception because PersistAdSelectionResult fails fast.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_FAST_FAILURE = 3092;
+
+  // Error while processing new messages for KAnon in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_PROCESSING_KANON_ERROR = 3093;
+
+  // Error of AuctionResult in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_AUCTION_RESULT_HAS_ERROR = 3094;
+
+  // Error because result is chaff in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_RESULT_IS_CHAFF = 3095;
+
+  // Error because AuctionResult type is unknown in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_AUCTION_RESULT_UNKNOWN = 3096;
+
+  // Error because invalid object of AuctionResult in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_AUCTION_RESULT_INVALID_OBJECT = 3097;
+
+  // Error because undefined ad type in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_UNDEFINED_AD_TYPE = 3098;
+
+  // Error because CA is not found in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOT_FOUND_CA = 3099;
+
+  // Error because CA has a null or empty list of ads in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NULL_OR_EMPTY_ADS_FOR_CA = 3100;
+
+  // Error because winning ad is not found in CA's list of ads in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOT_FOUND_WINNING_AD = 3101;
+
+  // Exception because PersistAdSelectionResult timeout.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_TIMEOUT = 3102;
+
+  // Error during parsing AuctionResult proto in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_PARSING_AUCTION_RESULT_INVALID_PROTO_ERROR = 3103;
+
+  // Error encountered updating ad counter histogram with win event
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_UPDATING_AD_COUNTER_WIN_HISTOGRAM_ERROR = 3104;
+
+  // Error of invalid ad tech URI in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_INVALID_AD_TECH_URI = 3105;
+
+  // Error of invalid interaction URI in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_INVALID_INTERACTION_URI = 3106;
+
+  // Error occurred because interaction key size exceeds the maximum allowed
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_INTERACTION_KEY_EXCEEDS_MAXIMUM_LIMIT = 3107;
+
+  // Exception because initialization info cannot be found for the given ad selection id
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NULL_INITIALIZATION_INFO = 3108;
+
+  // Exception because initialization info in db doesn't match the request
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_MISMATCH_INITIALIZATION_INFO = 3109;
+
+  // Exception during notifying PersistAdSelectionResultRunner success
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_SUCCESS_CALLBACK_ERROR = 3110;
+
+  // Exception during notifying PersistAdSelectionResultRunner empty success
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_EMPTY_SUCCESS_CALLBACK_ERROR = 3111;
+
+  // Exception during notifying PersistAdSelectionResultRunner failure
+  // in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_CALLBACK_ERROR = 3112;
+
+  // Exception of timeout during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_TIMEOUT = 3113;
+
+  // Exception of JS sandbox unavailable during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_JS_SANDBOX_UNAVAILABLE = 3114;
+
+  // Exception of invalid argument during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_INVALID_ARGUMENT = 3115;
+
+  // Exception of internal error during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_INTERNAL_ERROR = 3116;
+
+  // Exception of user consent revoked during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_USER_CONSENT_REVOKED = 3117;
+
+  // Exception of background caller during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_BACKGROUND_CALLER = 3118;
+
+  // Exception of caller not allowed during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_CALLER_NOT_ALLOWED = 3119;
+
+  // Exception of unauthorized during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_UNAUTHORIZED = 3120;
+
+  // Exception of rate limit reached during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_RATE_LIMIT_REACHED = 3121;
+
+  // Exception of internal error during notifying failure in PersistAdSelectionResultRunner.
+  PERSIST_AD_SELECTION_RESULT_RUNNER_NOTIFY_FAILURE_FILTER_EXCEPTION_INTERNAL_ERROR = 3122;
+
+  // Exception of decryption invalid key in ObliviousHttpEncryptorImpl.
+  OBLIVIOUS_HTTP_ENCRYPTOR_DECRYPTION_INVALID_KEY_SPEC_EXCEPTION = 3123;
+
+  // Exception of decryption unsupported HPKE algorithm in ObliviousHttpEncryptorImpl.
+  OBLIVIOUS_HTTP_ENCRYPTOR_DECRYPTION_UNSUPPORTED_HPKE_ALGORITHM_EXCEPTION = 3124;
+
+  // Exception of decryption IO error in ObliviousHttpEncryptorImpl.
+  OBLIVIOUS_HTTP_ENCRYPTOR_DECRYPTION_IO_EXCEPTION = 3125;
+
+  // Exception of encryption unsupported HPKE algorithm in ObliviousHttpEncryptorImpl.
+  OBLIVIOUS_HTTP_ENCRYPTOR_ENCRYPTION_UNSUPPORTED_HPKE_ALGORITHM_EXCEPTION = 3126;
+
+  // Exception of encryption IO error in ObliviousHttpEncryptorImpl.
+  OBLIVIOUS_HTTP_ENCRYPTOR_ENCRYPTION_IO_EXCEPTION = 3127;
+
+  // Exception because ad tech not allowed in AuctionResultValidator.
+  AUCTION_RESULT_VALIDATOR_AD_TECH_NOT_ALLOWED = 3128;
+
+  // Exception because URI to fetch active key of type is null in AdSelectionEncryptionKeyManager.
+  AD_SELECTION_ENCRYPTION_KEY_MANAGER_NULL_FETCH_URI = 3129;
+
+  // Exception because Fledge API not available in AdSelectionService.
+  AD_SELECTION_SERVICE_AUCTION_SERVER_API_NOT_AVAILABLE = 3130;
+
+  // Exception while AdSelectionService has a null argument.
+  AD_SELECTION_SERVICE_NULL_ARGUMENT = 3131;
+
+  // Exception because AdSelectionService get illegal calling UID.
+  AD_SELECTION_SERVICE_GET_CALLING_UID_ILLEGAL_STATE = 3132;
+
+  // Exception because no match found, failing calling package name match
+  // in FledgeAuthorizationFilter.
+  FLEDGE_AUTHORIZATION_FILTER_NO_MATCH_PACKAGE_NAME = 3133;
+
+  // Exception because one permission not declared by caller in FledgeAuthorizationFilter.
+  FLEDGE_AUTHORIZATION_FILTER_PERMISSION_FAILURE = 3134;
+
+  // Exception because any permission not declared by caller in FledgeAuthorizationFilter.
+  FLEDGE_AUTHORIZATION_FILTER_ANY_PERMISSION_FAILURE = 3135;
+
+  // Exception because enrollment data match not found for ad tech while
+  // calling FledgeAuthorizationFilter.
+  FLEDGE_AUTHORIZATION_FILTER_ENROLLMENT_DATA_MATCH_NOT_FOUND = 3136;
+
+  // Error occurred because app package name with ad tech identifier not authorized
+  // to call Fledge API.
+  FLEDGE_AUTHORIZATION_FILTER_AD_TECH_NOT_AUTHORIZED_BY_APP = 3137;
+
+  // Error occurred because enrollment is in block list to call Fledge API.
+  FLEDGE_AUTHORIZATION_FILTER_NOT_ALLOWED_ENROLLMENT_BLOCKLISTED = 3138;
+
+  // Exception because user consent for Fledge API is not given.
+  FLEDGE_CONSENT_FILTER_USER_CONSENT_FOR_API_IS_NOT_GIVEN = 3139;
+
+  // Exception because user consent for Fledge API is revoked.
+  FLEDGE_CONSENT_FILTER_CONSENT_REVOKED_FOR_APP = 3140;
+
+  // Exception because of Fledge API missing any notification displayed.
+  FLEDGE_CONSENT_FILTER_MISSING_ANY_NOTIFICATION_DISPLAYED = 3141;
+
+  // Exception because all APIs consent disabled for Fledge API.
+  FLEDGE_CONSENT_FILTER_ALL_APIS_CONSENT_DISABLED = 3142;
+
+  // UX errors: 4001-5000
+  CONSENT_REVOKED_ERROR = 4001;
+
+  // Error occurred when failed to get downloaded OTA file URI.
+  DOWNLOADED_OTA_FILE_ERROR = 4002;
+
+  // Exception while trying to add ResourcesProvider.
+  RESOURCES_PROVIDER_ADD_ERROR = 4003;
+
+  // Exception occurred when unable to load MDD file group
+  LOAD_MDD_FILE_GROUP_FAILURE = 4004;
+
+  // Dismiss notification error
+  DISMISS_NOTIFICATION_FAILURE = 4005;
+
+  // Datastore exception while get content
+  DATASTORE_EXCEPTION_WHILE_GET_CONTENT = 4006;
+
+  // Datastore exception while recording notification
+  DATASTORE_EXCEPTION_WHILE_RECORDING_NOTIFICATION = 4007;
+
+  // Datastore exception while recording default consent.
+  DATASTORE_EXCEPTION_WHILE_RECORDING_DEFAULT_CONSENT = 4008;
+
+  // Exception while recording manual consent interaction
+  DATASTORE_EXCEPTION_WHILE_RECORDING_MANUAL_CONSENT_INTERACTION = 4009;
+
+  // Exception while saving privacy sandbox feature.
+  PRIVACY_SANDBOX_SAVE_FAILURE = 4010;
+
+  // Error message indicating invalid consent source of truth.
+  INVALID_CONSENT_SOURCE_OF_TRUTH = 4011;
+
+  // Error message while calling get consent.
+  ERROR_WHILE_GET_CONSENT = 4012;
+
+  // App search consent data migration failure.
+  APP_SEARCH_DATA_MIGRATION_FAILURE = 4013;
+
+  // Adservices entry point failure.
+  AD_SERVICES_ENTRY_POINT_FAILURE = 4014;
+
+  // Used to be MEASUREMENT_FOREGROUND_UNKNOWN_FAILURE but renamed in
+  // commit 94af8756d2f03ff17924721ee1b7c4a4520377ff
+  RESERVED_ERROR_CODE_4015 = 4015;
+
+  // UX Enum is unsupported
+  UNSUPPORTED_UX = 4016;
+
+  // FederatedCompute errors: 5001-6000
+  // Datastore exception while deleting a federated task.
+  DELETE_TASK_FAILURE = 5001;
+
+  // Exception while trying to close file descriptor.
+  FILE_DESCRIPTOR_CLOSE_ERROR = 5002;
+
+  // Error message indicating invalid federated job plan type.
+  CLIENT_PLAN_SPEC_ERROR = 5003;
+
+  // Exception when trying to parse protobuf message.
+  INVALID_PROTOBUF_ERROR = 5004;
+
+  // Exception occurred when isolated training process runs.
+  ISOLATED_TRAINING_PROCESS_ERROR = 5005;
+
+  // Exception while trying to iterate data.
+  ITERATOR_NEXT_FAILURE = 5006;
+
+  // Timeout exception while trying to iterate data.
+  ITERATOR__NEXT_TIMEOUT = 5007;
+
+  // Back Compat errors: 6001-7000
+  // AdExtDataService get failed
+  GET_ADEXT_DATA_SERVICE_ERROR = 6001;
+
+  // AdExtDataService put failed
+  PUT_ADEXT_DATA_SERVICE_ERROR = 6002;
+
+  // Failed to cancel background jobs in back compat init.
+  BACK_COMPAT_INIT_CANCEL_JOB_FAILURE = 6003;
+
+  // Failed to update UI activity enabled setting in back compat init.
+  BACK_COMPAT_INIT_UPDATE_ACTIVITY_FAILURE = 6004;
+
+  // Failed to update service enabled setting in back compat init.
+  BACK_COMPAT_INIT_UPDATE_SERVICE_FAILURE = 6005;
+
+  // Failed to enable package changed receiver in back compat init.
+  BACK_COMPAT_INIT_ENABLE_RECEIVER_FAILURE = 6006;
+
+  // Failed to disable package changed receiver in back compat init.
+  BACK_COMPAT_INIT_DISABLE_RECEIVER_FAILURE = 6007;
+
+  // Failed to run back compat init in boot completed receiver.
+  BACK_COMPAT_INIT_BOOT_COMPLETED_RECEIVER_FAILURE = 6008;
+
+  // IAPC errors: 7001-8000
+  // AdIdProviderService is not available.
+  IAPC_AD_ID_PROVIDER_NOT_AVAILABLE = 7001;
+  // Exception when calling UpdateAdId API in service side.
+  IAPC_UPDATE_AD_ID_API_ERROR = 7002;
+
+  // ODP errors: 8001-9000
+  // ODP generic error
+  ON_DEVICE_PERSONALIZATION_ERROR = 8001;
+
+  // ODP execute Isolated service error
+  ISOLATED_SERVICE_EXECUTE_ERROR = 8002;
+
+  // ODP download Isolated service error
+  ISOLATED_SERVICE_DOWNLOAD_ERROR = 8003;
+
+  // ODP render Isolated service error
+  ISOLATED_SERVICE_RENDER_ERROR = 8004;
+
+  // ODP web view event Isolated service error
+  ISOLATED_SERVICE_EVENT_ERROR = 8005;
+
+  // ODP training example Isolated service error
+  ISOLATED_SERVICE_TRAINING_EXAMPLE_ERROR = 8006;
+
+  // ODP web trigger Isolated service error
+  ISOLATED_SERVICE_WEB_TRIGGER_ERROR = 8007;
+}
diff --git a/stats/enums/adservices/common/adservices_enums.proto b/stats/enums/adservices/common/adservices_enums.proto
index e447585c..20243137 100644
--- a/stats/enums/adservices/common/adservices_enums.proto
+++ b/stats/enums/adservices/common/adservices_enums.proto
@@ -66,457 +66,6 @@ enum AttributionType {
   WEB_WEB = 4;
 }
 
-/**
- * Enum representing an error/exception.  These errors can be common to all
- * PPAPIs or specific to a particular API. We will group enums in blocks of
- * 1000 like this below:
- * - Common errors: 1-1000
- * - Topics errors: 1001-2000
- * - Measurement errors: 2001-3000
- * - Fledge errors: 3001-4000
- * - UX errors: 4001-5000
- * - FederatedCompute errors: 5001-6000
- * - Back Compat errors: 6001-7000
- * - IAPC errors: 7001 - 8000
- * - ODP errors: 8001-9000
- *
- * NOTE: AdId / AdSetId don't have a range yet (because they're just using common codes)
- */
-enum ErrorCode {
-  // Common Errors: 1-1000
-  ERROR_CODE_UNSPECIFIED = 0;
-  DATABASE_READ_EXCEPTION = 1;
-  DATABASE_WRITE_EXCEPTION = 2;
-  API_REMOTE_EXCEPTION = 3;
-
-  // Error occurred when unable to send result to the callback.
-  API_CALLBACK_ERROR = 4;
-
-  // Error occurred when failed to call the callback on Rate Limit Reached.
-  RATE_LIMIT_CALLBACK_FAILURE = 5;
-
-  // Error occurred when calling package name is not found.
-  PACKAGE_NAME_NOT_FOUND_EXCEPTION = 6;
-
-  // Shared pref update failure.
-  SHARED_PREF_UPDATE_FAILURE = 7;
-
-  // Shared pref reset failure.
-  SHARED_PREF_RESET_FAILURE = 8;
-
-  // Remote exception when calling the Cobalt upload API.
-  COBALT_UPLOAD_API_REMOTE_EXCEPTION = 9;
-
-  // Exception occurred when parsing the Adservices Config XML provided by an app.
-  APP_MANIFEST_CONFIG_PARSING_ERROR = 10;
-
-  // Generic exception when dealing with shared prefs.
-  SHARED_PREF_EXCEPTION = 11;
-
-  // Error logging an API check using Adservices Config XML provided by an app.
-  APP_MANIFEST_CONFIG_LOGGING_ERROR = 12;
-
-  // Incorrect version of the json file.
-  ENCRYPTION_KEYS_INCORRECT_JSON_VERSION = 13;
-
-  // JSON parsing error for the key.
-  ENCRYPTION_KEYS_JSON_PARSING_ERROR = 14;
-
-  // Failed to delete an expired encryption key.
-  ENCRYPTION_KEYS_FAILED_DELETE_EXPIRED_KEY = 15;
-
-  // Failed to load Encryption Keys MDD filegroup
-  ENCRYPTION_KEYS_FAILED_MDD_FILEGROUP = 16;
-
-  // Encryption Keys no MDD files available.
-  ENCRYPTION_KEYS_MDD_NO_FILE_AVAILABLE = 17;
-
-  // JobScheduler is not available.
-  JOB_SCHEDULER_IS_UNAVAILABLE = 18;
-
-  // Failed to encrypt data in Cobalt.
-  COBALT_ENCRYPTION_FAILED_EXCEPTION = 19;
-
-  // Failed to fabricate Cobalt observations.
-  COBALT_PRIVACY_GENERATION_EXCEPTION = 20;
-
-  // Cobalt logger initialization failed in AppNameApiErrorLogger.
-  COBALT_API_ERROR_LOGGER_INITIALIZATION_EXCEPTION = 21;
-
-  // SPE Errors: 901 - 1000
-  // Get an unavailable job execution start timestamp when calculating the execution latency.
-  SPE_UNAVAILABLE_JOB_EXECUTION_START_TIMESTAMP = 901;
-
-  // Get an invalid execution period during the calculation.
-  SPE_INVALID_EXECUTION_PERIOD = 902;
-
-  // Failed to persist execution start time in the storage.
-  SPE_FAIL_TO_COMMIT_JOB_EXECUTION_START_TIME = 903;
-
-  // Failed to persist execution stop time in the storage.
-  SPE_FAIL_TO_COMMIT_JOB_EXECUTION_STOP_TIME = 904;
-
-  // Execution failure.
-  SPE_JOB_EXECUTION_FAILURE = 905;
-
-  // JobScheduler is not available.
-  SPE_JOB_SCHEDULER_IS_UNAVAILABLE = 906;
-
-  // Invalid Job Policy configured in the server.
-  SPE_INVALID_JOB_POLICY_SYNC = 907;
-
-  // Job is not configured correctly.
-  SPE_JOB_NOT_CONFIGURED_CORRECTLY = 908;
-
-  // Scheduling Failure.
-  SPE_JOB_SCHEDULING_FAILURE = 909;
-
-  // Failure of the customized logic in onStopJob().
-  SPE_JOB_ON_STOP_EXECUTION_FAILURE = 910;
-
-  // Topics errors: 1001-2000
-  // Remote exception when calling get topics.
-  GET_TOPICS_REMOTE_EXCEPTION = 1001;
-
-  // Topics API is disabled.
-  TOPICS_API_DISABLED = 1002;
-
-  // SQLException occurred when failed to persist classified Topics.
-  TOPICS_PERSIST_CLASSIFIED_TOPICS_FAILURE = 1003;
-
-  // SQLException occurred when failed to persist Top Topics.
-  TOPICS_PERSIST_TOP_TOPICS_FAILURE = 1004;
-
-  // SQLException occurred when failed to record App-Sdk usage history.
-  TOPICS_RECORD_APP_SDK_USAGE_FAILURE = 1005;
-
-  // SQLException occurred when failed to record App Only usage history.
-  TOPICS_RECORD_APP_USAGE_FAILURE = 1006;
-
-  // SQLException occurred when failed to record can learn topic.
-  TOPICS_RECORD_CAN_LEARN_TOPICS_FAILURE = 1007;
-
-  // SQLException occurred when failed to record returned topic.
-  TOPICS_RECORD_RETURNED_TOPICS_FAILURE = 1008;
-
-  // SQLException occurred when failed to record returned topic.
-  TOPICS_RECORD_BLOCKED_TOPICS_FAILURE = 1009;
-
-  // SQLException occurred when failed to remove blocked topic.
-  TOPICS_DELETE_BLOCKED_TOPICS_FAILURE = 1010;
-
-  // SQLException occurred when failed to delete old epochs.
-  TOPICS_DELETE_OLD_EPOCH_FAILURE = 1011;
-
-  // SQLException occurred when failed to delete a column in table
-  TOPICS_DELETE_COLUMN_FAILURE = 1012;
-
-  // SQLException occurred when failed to persist topic contributors.
-  TOPICS_PERSIST_TOPICS_CONTRIBUTORS_FAILURE = 1013;
-
-  // SQLException occurred when failed to delete all entries from table.
-  TOPICS_DELETE_ALL_ENTRIES_IN_TABLE_FAILURE = 1014;
-
-  // Exception occurred when classify call failed.
-  TOPICS_ON_DEVICE_CLASSIFY_FAILURE = 1015;
-
-  // Exception occurred ML model did not return a topic id.
-  TOPICS_ON_DEVICE_NUMBER_FORMAT_EXCEPTION = 1016;
-
-  // Exception occurred when failed to load ML model.
-  TOPICS_LOAD_ML_MODEL_FAILURE = 1017;
-
-  // Exception occurred when unable to retrieve topics id to topics name.
-  TOPICS_ID_TO_NAME_LIST_READ_FAILURE = 1018;
-
-  // Exception occurred when unable to read classifier asset file.
-  TOPICS_READ_CLASSIFIER_ASSET_FILE_FAILURE = 1019;
-
-  // NoSuchAlgorithmException occurred when unable to find correct message.
-  // digest algorithm.
-  TOPICS_MESSAGE_DIGEST_ALGORITHM_NOT_FOUND = 1020;
-
-  // Error occurred when failed to find downloaded classifier model file.
-  DOWNLOADED_CLASSIFIER_MODEL_FILE_NOT_FOUND = 1021;
-
-  // No downloaded or bundled classifier model available.
-  NO_CLASSIFIER_MODEL_AVAILABLE = 1022;
-
-  // Error occurred when failed to read labels file.
-  READ_LABELS_FILE_FAILURE = 1023;
-
-  // Error occurred when failed to read precomuted labels.
-  READ_PRECOMUTRED_LABELS_FAILURE = 1024;
-
-  // Error occurred when failed to read top apps file.
-  READ_TOP_APPS_FILE_FAILURE = 1025;
-
-  // Error occurred when saving a topic not in labels file.
-  INVALID_TOPIC_ID = 1026;
-
-  // Error occurred when failed to read precomuted app topics list.
-  READ_PRECOMUTRED_APP_TOPICS_LIST_FAILURE = 1027;
-
-  // Error occurred when failed to read bundled metadata file.
-  READ_BUNDLED_METADATA_FILE_FAILURE = 1028;
-
-  // Error occurred when reading redundant metadata property.
-  CLASSIFIER_METADATA_REDUNDANT_PROPERTY = 1029;
-
-  // Error occurred when reading redundant metadata asset.
-  CLASSIFIER_METADATA_REDUNDANT_ASSET = 1030;
-
-  // Error occurred when parsing metadata json missing property or asset_name.
-  CLASSIFIER_METADATA_MISSING_PROPERTY_OR_ASSET_NAME = 1031;
-
-  // Error occurred when failed to read classifier assets metadata file.
-  READ_CLASSIFIER_ASSETS_METADATA_FAILURE = 1032;
-
-  // Error occurred when failed to load downloaded file by file Id.
-  DOWNLOADED_CLASSIFIER_MODEL_FILE_LOAD_FAILURE = 1033;
-
-  // RuntimeException occurred when use invalid type of blocked topics
-  // source of truth.
-  TOPICS_INVALID_BLOCKED_TOPICS_SOURCE_OF_TRUTH = 1034;
-
-  // RuntimeException occurred when unable to remove the blocked topic.
-  TOPICS_REMOVE_BLOCKED_TOPIC_FAILURE = 1035;
-
-  // RuntimeException occurred when unable to get all blocked topics.
-  TOPICS_GET_BLOCKED_TOPIC_FAILURE = 1036;
-
-  // RuntimeException occurred when unable to clear all blocked topics
-  // in system server.
-  TOPICS_CLEAR_ALL_BLOCKED_TOPICS_IN_SYSTEM_SERVER_FAILURE = 1037;
-
-  // Error occurred when unable to handle JobService.
-  TOPICS_HANDLE_JOB_SERVICE_FAILURE = 1038;
-
-  // Error occurred when unable to fetch job scheduler.
-  TOPICS_FETCH_JOB_SCHEDULER_FAILURE = 1039;
-
-  // Error occurred while deleting a table for Topics.
-  TOPICS_DELETE_TABLE_FAILURE = 1040;
-
-  // Cobalt initialisation failure for Topics.
-  TOPICS_COBALT_LOGGER_INITIALIZATION_FAILURE = 1041;
-
-  // Failure to convert plaintext topic object to encrypted topic.
-  TOPICS_ENCRYPTION_FAILURE = 1042;
-
-  // Topics encryption key with invalid length.
-  TOPICS_ENCRYPTION_INVALID_KEY_LENGTH = 1043;
-
-  // Topics encryption with invalid response length.
-  TOPICS_ENCRYPTION_INVALID_RESPONSE_LENGTH = 1044;
-
-  // Topics encryption key failed to decode with Base64 decoder.
-  TOPICS_ENCRYPTION_KEY_DECODE_FAILURE = 1045;
-
-  // Topics encryption received null params in request for the encrypter.
-  TOPICS_ENCRYPTION_NULL_REQUEST = 1046;
-
-  // Topics encryption received null response from the encrypter.
-  TOPICS_ENCRYPTION_NULL_RESPONSE = 1047;
-
-  // Topics encryption received error while serialization to JSON.
-  TOPICS_ENCRYPTION_SERIALIZATION_ERROR = 1048;
-
-  // Topics encryption public key is missing.
-  TOPICS_ENCRYPTION_KEY_MISSING = 1049;
-
-  // Topics API request has empty sdk name.
-  TOPICS_REQUEST_EMPTY_SDK_NAME = 1050;
-
-  // Measurement errors: 2001-3000
-  // Error occurred when inserting enrollment data to DB.
-  ENROLLMENT_DATA_INSERT_ERROR = 2001;
-
-  // Error occurred when deleting enrollment data to DB.
-  ENROLLMENT_DATA_DELETE_ERROR = 2002;
-
-  // Measurement foreground unknown failure.
-  MEASUREMENT_FOREGROUND_UNKNOWN_FAILURE = 2003;
-
-  // Measurement datastore failure.
-  MEASUREMENT_DATASTORE_FAILURE = 2004;
-
-  // Measurement datastore unknown failure.
-  MEASUREMENT_DATASTORE_UNKNOWN_FAILURE = 2005;
-
-  // Measurement invalid parameter fetching public keys.
-  MEASUREMENT_PUBLIC_KEY_FETCHER_INVALID_PARAMETER = 2006;
-
-  // Measurement IO exception while fetching public keys.
-  MEASUREMENT_PUBLIC_KEY_FETCHER_IO_ERROR = 2007;
-
-  // Measurement error while parsing public keys.
-  MEASUREMENT_PUBLIC_KEY_FETCHER_PARSING_ERROR = 2008;
-
-  // Failure to save seed in SharedPreferences
-  ENROLLMENT_SHARED_PREFERENCES_SEED_SAVE_FAILURE = 2009;
-
-  // When report deliver fails due to a network issue (IOException).
-  MEASUREMENT_REPORTING_NETWORK_ERROR = 2010;
-
-  // When report delivery fails due to report building as JSON.
-  MEASUREMENT_REPORTING_PARSING_ERROR = 2011;
-
-  // When encryption of aggregate report fails.
-  MEASUREMENT_REPORTING_ENCRYPTION_ERROR = 2012;
-
-  // Reporting errors should have specific error codes.
-  MEASUREMENT_REPORTING_UNKNOWN_ERROR = 2013;
-
-  // When parsing of enrollment file fails.
-  ENROLLMENT_FAILED_PARSING = 2014;
-
-  // Error occurred when encountering invalid enrollment.
-  ENROLLMENT_INVALID = 2015;
-
-  // Error occurred when trying to get instance of an ODP system event manager
-  MEASUREMENT_REGISTRATION_ODP_GET_MANAGER_ERROR = 2016;
-
-  // Error due to the ODP header being in an invalid format
-  MEASUREMENT_REGISTRATION_ODP_INVALID_HEADER_FORMAT_ERROR = 2017;
-
-  // Error due to the ODP header missing a required field
-  MEASUREMENT_REGISTRATION_ODP_MISSING_REQUIRED_HEADER_FIELD_ERROR = 2018;
-
-  // Error due to the ODP header containing a field with an invalid value
-  MEASUREMENT_REGISTRATION_ODP_INVALID_HEADER_FIELD_VALUE_ERROR = 2019;
-
-  // Error occurred when trying to parse the ODP header (JSON Exception)
-  MEASUREMENT_REGISTRATION_ODP_JSON_PARSING_ERROR = 2020;
-
-  // Error occurred when trying to parse the ODP header (Unknown Exception)
-  MEASUREMENT_REGISTRATION_ODP_PARSING_UNKNOWN_ERROR = 2021;
-
-  // Error occurred when trying to initialize cobalt logger for measurement metrics.
-  MEASUREMENT_COBALT_LOGGER_INITIALIZATION_FAILURE = 2022;
-
-  // UX errors: 4001-5000
-  CONSENT_REVOKED_ERROR = 4001;
-
-  // Error occurred when failed to get downloaded OTA file URI.
-  DOWNLOADED_OTA_FILE_ERROR = 4002;
-
-  // Exception while trying to add ResourcesProvider.
-  RESOURCES_PROVIDER_ADD_ERROR = 4003;
-
-  // Exception occurred when unable to load MDD file group
-  LOAD_MDD_FILE_GROUP_FAILURE = 4004;
-
-  // Dismiss notification error
-  DISMISS_NOTIFICATION_FAILURE = 4005;
-
-  // Datastore exception while get content
-  DATASTORE_EXCEPTION_WHILE_GET_CONTENT = 4006;
-
-  // Datastore exception while recording notification
-  DATASTORE_EXCEPTION_WHILE_RECORDING_NOTIFICATION = 4007;
-
-  // Datastore exception while recording default consent.
-  DATASTORE_EXCEPTION_WHILE_RECORDING_DEFAULT_CONSENT = 4008;
-
-  // Exception while recording manual consent interaction
-  DATASTORE_EXCEPTION_WHILE_RECORDING_MANUAL_CONSENT_INTERACTION = 4009;
-
-  // Exception while saving privacy sandbox feature.
-  PRIVACY_SANDBOX_SAVE_FAILURE = 4010;
-
-  // Error message indicating invalid consent source of truth.
-  INVALID_CONSENT_SOURCE_OF_TRUTH = 4011;
-
-  // Error message while calling get consent.
-  ERROR_WHILE_GET_CONSENT = 4012;
-
-  // App search consent data migration failure.
-  APP_SEARCH_DATA_MIGRATION_FAILURE = 4013;
-
-  // Adservices entry point failure.
-  AD_SERVICES_ENTRY_POINT_FAILURE = 4014;
-
-  // Used to be MEASUREMENT_FOREGROUND_UNKNOWN_FAILURE but renamed in
-  // commit 94af8756d2f03ff17924721ee1b7c4a4520377ff
-  RESERVED_ERROR_CODE_4015 = 4015;
-
-  // FederatedCompute errors: 5001-6000
-  // Datastore exception while deleting a federated task.
-  DELETE_TASK_FAILURE = 5001;
-
-  // Exception while trying to close file descriptor.
-  FILE_DESCRIPTOR_CLOSE_ERROR = 5002;
-
-  // Error message indicating invalid federated job plan type.
-  CLIENT_PLAN_SPEC_ERROR = 5003;
-
-  // Exception when trying to parse protobuf message.
-  INVALID_PROTOBUF_ERROR = 5004;
-
-  // Exception occurred when isolated training process runs.
-  ISOLATED_TRAINING_PROCESS_ERROR = 5005;
-
-  // Exception while trying to iterate data.
-  ITERATOR_NEXT_FAILURE = 5006;
-
-  // Timeout exception while trying to iterate data.
-  ITERATOR__NEXT_TIMEOUT = 5007;
-
-  // Back Compat errors: 6001-7000
-  // AdExtDataService get failed
-  GET_ADEXT_DATA_SERVICE_ERROR = 6001;
-
-  // AdExtDataService put failed
-  PUT_ADEXT_DATA_SERVICE_ERROR = 6002;
-
-  // Failed to cancel background jobs in back compat init.
-  BACK_COMPAT_INIT_CANCEL_JOB_FAILURE = 6003;
-
-  // Failed to update UI activity enabled setting in back compat init.
-  BACK_COMPAT_INIT_UPDATE_ACTIVITY_FAILURE = 6004;
-
-  // Failed to update service enabled setting in back compat init.
-  BACK_COMPAT_INIT_UPDATE_SERVICE_FAILURE = 6005;
-
-  // Failed to enable package changed receiver in back compat init.
-  BACK_COMPAT_INIT_ENABLE_RECEIVER_FAILURE = 6006;
-
-  // Failed to disable package changed receiver in back compat init.
-  BACK_COMPAT_INIT_DISABLE_RECEIVER_FAILURE = 6007;
-
-  // Failed to run back compat init in boot completed receiver.
-  BACK_COMPAT_INIT_BOOT_COMPLETED_RECEIVER_FAILURE = 6008;
-
-  // IAPC errors: 7001-8000
-  // AdIdProviderService is not available.
-  IAPC_AD_ID_PROVIDER_NOT_AVAILABLE = 7001;
-  // Exception when calling UpdateAdId API in service side.
-  IAPC_UPDATE_AD_ID_API_ERROR = 7002;
-
-  // ODP errors: 8001-9000
-  // ODP generic error
-  ON_DEVICE_PERSONALIZATION_ERROR = 8001;
-
-  // ODP execute Isolated service error
-  ISOLATED_SERVICE_EXECUTE_ERROR = 8002;
-
-  // ODP download Isolated service error
-  ISOLATED_SERVICE_DOWNLOAD_ERROR = 8003;
-
-  // ODP render Isolated service error
-  ISOLATED_SERVICE_RENDER_ERROR = 8004;
-
-  // ODP web view event Isolated service error
-  ISOLATED_SERVICE_EVENT_ERROR = 8005;
-
-  // ODP training example Isolated service error
-  ISOLATED_SERVICE_TRAINING_EXAMPLE_ERROR = 8006;
-
-  // ODP web trigger Isolated service error
-  ISOLATED_SERVICE_WEB_TRIGGER_ERROR = 8007;
-}
-
 /**
  * Adservices API names.
  */
@@ -536,6 +85,12 @@ enum PpapiName {
   ADEXT_DATA_SERVICE = 9;
   // Represents ondevicepersonalization APK of OnDevicePersonalization module.
   ODP = 10;
+  // Represents Protected App Signals API.
+  PAS = 11;
+  // Represents GetAdSelectionData API of B&A.
+  GET_AD_SELECTION_DATA = 12;
+  // Represents PersistAdSelectionResult API of B&A.
+  PERSIST_AD_SELECTION_RESULT = 13;
 }
 
 /**
@@ -670,6 +225,9 @@ enum Command {
   COMMAND_IS_ALLOWED_CUSTOM_AUDIENCE_ACCESS = 4;
   COMMAND_IS_ALLOWED_AD_SELECTION_ACCESS = 5;
   COMMAND_IS_ALLOWED_TOPICS_ACCESS = 6;
+  COMMAND_ENABLE_ADSERVICES = 7;
+  COMMAND_RESET_CONSENT_DATA = 8;
+  COMMAND_DEV_SESSION = 9;  // Command to enable or disable adservices developer mode.
 
   // Custom audience commands: 101-200
   COMMAND_CUSTOM_AUDIENCE_VIEW = 101;
@@ -683,10 +241,12 @@ enum Command {
   COMMAND_AD_SELECTION_CONSENTED_DEBUG_HELP = 204;
   COMMAND_AD_SELECTION_GET_AD_SELECTION_DATA = 205;
   COMMAND_AD_SELECTION_MOCK_AUCTION = 206;
+  COMMAND_AD_SELECTION_VIEW_AUCTION_RESULT = 207;
 
   // Protected App Signals commands: 301-400
   reserved 301;
   COMMAND_APP_SIGNALS_GENERATE_INPUT_FOR_ENCODING = 302;
+  COMMAND_APP_SIGNALS_TRIGGER_ENCODING = 303;
 }
 
 // Result of the shell command
@@ -700,3 +260,17 @@ enum CommandResult {
   COMMAND_RESULT_NOT_ENABLED = 6;
 }
 
+// Cobalt logging event
+enum CobaltLoggingEvent {
+  LOGGING_EVENT_UNSPECIFIED = 0;
+  LOGGING_EVENT_OVER_STRING_BUFFER_MAX = 1;
+  LOGGING_EVENT_OVER_EVENT_VECTOR_BUFFER_MAX = 2;
+  LOGGING_EVENT_OVER_MAX_VALUE = 3;
+}
+
+// Cobalt upload event
+enum CobaltPeriodicJobEvent {
+  UPLOAD_EVENT_UNSPECIFIED = 0;
+  UPLOAD_EVENT_SUCCESS = 1;
+  UPLOAD_EVENT_FAILURE = 2;
+}
diff --git a/stats/enums/adservices/fledge/enums.proto b/stats/enums/adservices/fledge/enums.proto
index cee596d2..52aba9ea 100644
--- a/stats/enums/adservices/fledge/enums.proto
+++ b/stats/enums/adservices/fledge/enums.proto
@@ -143,3 +143,11 @@ enum JsRunStatus {
     REFERENCE_ERROR = 9;
 }
 
+// Denotes the result of the getAdSelectionDataPayload optimization
+enum PayloadOptimizationResult {
+  PAYLOAD_OPTIMIZATION_RESULT_UNKNOWN = 0;
+  // there was still data available on the device but ran out of space
+  PAYLOAD_TRUNCATED_FOR_REQUESTED_MAX = 1;
+  // there was not enough data on the device so the max was not reached
+  PAYLOAD_WITHIN_REQUESTED_MAX = 2;
+}
diff --git a/stats/enums/apex/enums.proto b/stats/enums/apex/enums.proto
index b4debcb9..0a0ca4c4 100644
--- a/stats/enums/apex/enums.proto
+++ b/stats/enums/apex/enums.proto
@@ -42,4 +42,5 @@ enum PreinstallPartition {
     PARTITION_SYSTEM = 3;
     PARTITION_SYSTEM_EXT = 4;
     PARTITION_VENDOR = 5;
+    PARTITION_ODM = 6;
 }
diff --git a/stats/enums/app/settings_enums.proto b/stats/enums/app/settings_enums.proto
index 2fefbb7c..9507f841 100644
--- a/stats/enums/app/settings_enums.proto
+++ b/stats/enums/app/settings_enums.proto
@@ -1545,9 +1545,9 @@ enum Action {
     // OS: U-QPR3
     ACTION_KEYBOARD_VIBRATION_CHANGED = 1900;
 
-    // ACTION: Settings > Accessibility > Easy read > Enable easy read
-    // VALUE: false is off, true is on
-    // OS: U-QPR3
+    // ACTION: Settings > Accessibility > Simple View > Use Simple View
+    // VALUE: integer which is from SimpleViewUsageTimeType
+    // OS: V
     ACTION_EASY_MODE_CHANGED = 1901;
 
     // OPEN: Settings > Security&Privacy > Private Space >
@@ -1875,6 +1875,47 @@ enum Action {
     // CATEGORY: SETTINGS
     // OS: V
     ACTION_AUDIO_STREAM_JOIN_FAILED_WAIT_FOR_SYNC_TIMEOUT = 1956;
+
+    // ACTION: Settings > Security > Device Unlock > [Fingerprint] > Delete
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_FINGERPRINT_DELETE = 1957;
+
+    // ACTION: Settings > Security > Device Unlock > [Fingerprint] > Rename
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_FINGERPRINT_RENAME = 1958;
+
+    // Action: Settings > System > Touchpad & Mouse > Pointer Fill
+    // VALUE: fill style
+    // OS: V
+    ACTION_POINTER_ICON_FILL_STYLE_CHANGED = 1959;
+
+    // Action: Settings > System > Touchpad & Mouse > Pointer Stroke
+    // VALUE: stroke style
+    // OS: V
+    ACTION_POINTER_ICON_STROKE_STYLE_CHANGED = 1960;
+
+    // Action: Settings > System > Touchpad & Mouse > Pointer Scale
+    // VALUE: scale
+    // OS: V
+    ACTION_POINTER_ICON_SCALE_CHANGED = 1961;
+
+    // ACTION: Settings > Display > Robust open/close detection
+    //  SUBTYPE: 0 is off, 1 is on
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_ROBUST_OPEN_CLOSE_DETECTION_CHANGED = 1962;
+
+    // ACTION: Welcome > Set up with Simple View > Use Simple View
+    // VALUE: integer which is from SimpleViewUsageTimeType
+    // OS: V
+    ACTION_EASY_MODE_CHANGED_VIA_SETUPWIZARD = 1963;
+
+    // OPEN: Settings > Security&Privacy > Private Space > Set up > Wait 15 sec
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_PRIVATE_SPACE_SETUP_SPACE_ERRORS = 1964;
 }
 
 /**
@@ -5013,6 +5054,99 @@ enum PageId {
     // CATEGORY: SETTINGS
     // OS: V
     DIALOG_AUDIO_STREAM_MAIN_JOIN_FAILED_TIMEOUT = 2098;
+
+    // OPEN: Settings > Network & internet > Internet > Click a connected Wifi Network > Share
+    // CATEGORY: SETTINGS
+    // OS: V
+    SETTINGS_WIFI_DPP_QR_SHARING = 2099;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_PRIORITY_MODES_LIST = 2100;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > (Choose a Mode)
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_PRIORITY_MODE = 2101;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > Create your own mode
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_NEW_TYPE_CHOOSER_DIALOG = 2102;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > Create your own mode
+    //       > (Choose a Type) > Custom
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_ADD_NEW = 2103;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > (Choose a Custom Mode)
+    //       > Options Menu > Rename
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_EDIT_NAME_ICON = 2104;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes
+    //       > (Choose a Schedule/Calendar-based mode) > Set a Schedule
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_SCHEDULE_CHOOSER_DIALOG = 2105;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > (Choose a Mode)
+    //       > Apps > Selected Apps > Select more Apps > (Choose an App)
+    // CATEGORY: SETTINGS
+    // OS: V
+    NOTIFICATION_ZEN_MODE_OVERRIDING_APP_CHANNELS = 2106;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes > (Choose a Mode) > Display settings
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_DISPLAY_SETTINGS = 2107;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes
+    //       > (Choose a disabled Mode of Type not Bedtime or Driving) > Interstitial
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_INTERSTITIAL = 2108;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes
+    //       > (Choose a disabled Mode of Type Bedtime) > Interstitial
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_INTERSTITIAL_BEDTIME = 2109;
+
+    // OPEN: Settings > Sound / Notifications > Priority Modes
+    //       > (Choose a disabled Mode of Type Driving) > Interstitial
+    // CATEGORY: SETTINGS
+    // OS: V
+    ZEN_MODE_INTERSTITIAL_DRIVING = 2110;
+
+    // ACTION: Settings > Sound / Notifications > Priority Modes
+    //         > (Choose Mode that can be disabled) > Toggle On/Off "When to turn on Automatically"
+    //   SUBTYPE: false is disabled, true is enabled
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_ZEN_MODE_ENABLE_TOGGLE = 2111;
+
+    // Settings -> Keyboard -> Physical keyboard -> Keyboard & touchpad accessibility
+    // CATEGORY: SETTINGS
+    PHYSICAL_KEYBOARD_A11Y = 2112;
+
+    // OPEN Settings > Bluetooth > Attempt to connect to device, but failed due to key missing.
+    // CATEGORY: SETTINGS
+    // OS: V
+    BLUETOOTH_KEY_MISSING_DIALOG_FRAGMENT = 2113;
+
+    // OPEN: Settings > Accessibility -> Pointer and Touchpad
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACCESSIBILITY_POINTER_TOUCHPAD = 2114;
+
+    // OPEN: Settings > Accessibility -> Pointer and Touchpad -> Pointer Color Customization
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACCESSIBILITY_POINTER_COLOR_CUSTOMIZATION = 2115;
 }
 
 // Battery Saver schedule types.
@@ -5046,3 +5180,19 @@ enum EntryPointType {
     // access physical keyboard settings through connected devices settings entry point
     CONNECTED_DEVICES_SETTINGS = 2;
 }
+
+// Simple view usage time types
+enum SimpleViewUsageTimeType {
+    // started to access simple view
+    SIMPLE_VIEW_USAGE_TYPE_ENABLED = 0;
+    // disabled simple view within 5 minutes
+    SIMPLE_VIEW_USAGE_TYPE_DISABLED_WITHIN_FIVE_MINUTES = 1;
+    // disabled simple view within 1 hour
+    SIMPLE_VIEW_USAGE_TYPE_DISABLED_WITHIN_ONE_HOUR = 2;
+    // disabled simple view within 1 day
+    SIMPLE_VIEW_USAGE_TYPE_DISABLED_WITHIN_ONE_DAY = 3;
+    // disabled simple view within 1 week
+    SIMPLE_VIEW_USAGE_TYPE_DISABLED_WITHIN_ONE_WEEK = 4;
+    // disabled simple view over 1 week
+    SIMPLE_VIEW_USAGE_TYPE_DISABLED_OVER_ONE_WEEK = 5;
+}
diff --git a/stats/enums/app/wearservices/wearservices_enums.proto b/stats/enums/app/wearservices/wearservices_enums.proto
index c019158b..fe1a59a4 100644
--- a/stats/enums/app/wearservices/wearservices_enums.proto
+++ b/stats/enums/app/wearservices/wearservices_enums.proto
@@ -791,3 +791,56 @@ enum WatchFaceType {
   // Declarative watch face type.
   WATCH_FACE_TYPE_DWF = 3;
 }
+
+// Contains types for photo selection for the photos watch face feature.
+enum PhotoSelectionType {
+  // Unknown value, maps to MULTIPLE in Companion if not specified
+  PHOTO_SELECTION_NOT_SPECIFIED = 0;
+
+  // Single image supported
+  PHOTO_SELECTION_SELECT_SINGLE = 1;
+
+  // Multiple images supported
+  PHOTO_SELECTION_SELECT_MULTIPLE = 2;
+}
+
+// This enum represents the type of remote event that is being reported, they
+// are corresponding to
+// vendor/google_clockwork/libs/contract/companion/remoteevent/remoteeventtype.proto
+// Next ID: 8
+enum RemoteEventType {
+  EVENT_TYPE_UNKNOWN = 0;
+  EVENT_TYPE_ACCOUNT_DEEPLINK = 1;
+  EVENT_TYPE_OTA_NOTIFICATION = 2;
+  EVENT_TYPE_PHOTO_PICKER_DEEPLINK = 3;
+  EVENT_TYPE_BATTERY_FULLY_CHARGED = 4;
+  EVENT_TYPE_WATCH_OFF_CHARGER = 5;
+  EVENT_TYPE_SEND_SMS = 6;
+  EVENT_TYPE_LOCALE_SETTINGS_DEEPLINK = 7;
+}
+
+// This enum depicts different components of the bugreport flow
+// Next ID: 3
+enum BugreportComponent {
+  // Depicts an unknown component
+  BUGREPORT_COMPONENT_UNKNOWN = 0;
+
+  // Depicts the companion app
+  BUGREPORT_COMPONENT_COMPANION_APP = 1;
+
+  // Depicts the watch UI
+  BUGREPORT_COMPONENT_WATCH_UI = 2;
+}
+
+// This enum depicts the result of the bugreport
+// Next ID: 3
+enum BugreportResult {
+  // Depicts an unknown bugreport result
+  BUGREPORT_RESULT_UNKNOWN = 0;
+
+  // Depicts a successful bugreport result
+  BUGREPORT_RESULT_SUCCESS = 1;
+
+  // Depicts a failure bugreport result
+  BUGREPORT_RESULT_FAILURE = 2;
+}
diff --git a/stats/enums/app/wearsettings_enums.proto b/stats/enums/app/wearsettings_enums.proto
index f7d0a2c6..c412eab5 100644
--- a/stats/enums/app/wearsettings_enums.proto
+++ b/stats/enums/app/wearsettings_enums.proto
@@ -36,7 +36,7 @@ enum Action {
 }
 
 // IDs for settings UI elements.
-// Next ID: 511
+// Next ID: 525
 enum ItemId {
   // An unknown settings item. This may be set if no preference key is mapped to an enum value or as
   // a catch-all for values not yet added to this proto file.
@@ -86,6 +86,7 @@ enum ItemId {
   APP_DETAILS_ADVANCED_PERMISSIONS_DRAW_OVERLAY = 117;
   APP_DETAILS_ADVANCED_PERMISSIONS_WRITE_SETTINGS = 118;
   APP_DETAILS_ADVANCED_PERMISSIONS_EXACT_ALARM = 507;
+  APP_DETAILS_ALLOW_RESTRICTED_SETTINGS = 511;
   APP_DETAILS_CACHE = 142;
   APP_DETAILS_CLEAR_CACHE = 155;
   APP_DETAILS_CLEAR_DATA = 156;
@@ -287,6 +288,19 @@ enum ItemId {
   MAIN_SOUND_NOTIFICATION = 254;
   MAIN_SYSTEM = 298;
   MAIN_VIBRATION = 364;
+  MAIN_PRIORITY_MODES = 512;
+  PRIORITY_MODES_DO_NOT_DISTURB = 513;
+  PRIORITY_MODES_BEDTIME_MODE = 516;
+  PRIORITY_MODES_DND_SWITCH = 514;
+  PRIORITY_MODES_DND_CUSTOMIZE = 515;
+  PRIORITY_MODES_BEDTIME_CUSTOMIZE = 517;
+  PRIORITY_MODES_THEATER_MODE = 518;
+  PRIORITY_MODES_THEATER_CUSTOMIZE = 519;
+  PRIORITY_MODES_THEATER_SWITCH = 520;
+  PRIORITY_MODES_CUSTOMIZE_STARRED_CALLERS = 521;
+  PRIORITY_MODES_CUSTOMIZE_REPEAT_CALLERS = 522;
+  PRIORITY_MODES_CUSTOMIZE_ALARMS = 523;
+  PRIORITY_MODES_CUSTOMIZE_MEDIA_SOUNDS = 524;
   NFC_TAP_AND_PAY = 258;
   POWER_OFF = 299;
   PREPAIR_ACCESSIBILITY = 300;
diff --git a/stats/enums/app/app_enums.proto b/stats/enums/app_shared/app_enums.proto
similarity index 100%
rename from stats/enums/app/app_enums.proto
rename to stats/enums/app_shared/app_enums.proto
diff --git a/stats/enums/art/art_enums.proto b/stats/enums/art/art_enums.proto
new file mode 100644
index 00000000..268b3cdc
--- /dev/null
+++ b/stats/enums/art/art_enums.proto
@@ -0,0 +1,136 @@
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
+package android.os.statsd.art;
+
+option java_package = "com.android.os.art";
+option java_multiple_files = true;
+
+// Indicates which kind of measurement ART is reporting as increments / deltas.
+// Next ID: 37
+enum ArtDatumDeltaId {
+  ART_DATUM_DELTA_INVALID = 0;
+
+  // These IDs are the equivalent of the ArtDatumId values,
+  // but for reporting increments / deltas.
+  ART_DATUM_DELTA_CLASS_VERIFICATION_COUNT = 16;
+  ART_DATUM_DELTA_CLASS_VERIFICATION_TIME_MICROS = 8;
+  ART_DATUM_DELTA_CLASS_LOADING_TIME_MICROS = 9;
+  ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_COUNT = 5;
+  ART_DATUM_DELTA_GC_TOTAL_BYTES_ALLOCATED = 17;
+  ART_DATUM_DELTA_GC_TOTAL_COLLECTION_TIME_MS = 28;
+  ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_COUNT = 3;
+  ART_DATUM_DELTA_JIT_METHOD_COMPILE_COUNT = 21;
+  ART_DATUM_DELTA_JIT_METHOD_COMPILE_TIME_MICROS = 6;
+
+  // numerator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
+  ART_DATUM_DELTA_GC_WORLD_STOP_TIME_US = 29;
+  // denominator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
+  ART_DATUM_DELTA_GC_WORLD_STOP_COUNT = 30;
+  // numerator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_SCANNED_BYTES = 31;
+  // numerator from ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_FREED_BYTES = 32;
+  // denominator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  // and ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_YOUNG_GENERATION_COLLECTION_DURATION_MS = 33;
+  // numerator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_SCANNED_BYTES = 34;
+  // numerator from ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_FREED_BYTES = 35;
+  // denominator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  // and ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_DELTA_GC_FULL_HEAP_COLLECTION_DURATION_MS = 36;
+  // The number of milliseconds since the last time metrics were reported.
+  ART_DATUM_DELTA_TIME_ELAPSED_MS = 37;
+
+  reserved 1, 2, 4, 7, 10, 11, 12, 13, 14, 15, 18, 19, 20, 22, 23, 24, 25, 26, 27;
+}
+
+// Indicates which kind of measurement ART is reporting.
+//
+// Where it makes sense, the datum ID ends with the type of datum (counter or histogram) and the
+// units.
+// Note: Histograms are not yet reported by statsd.
+enum ArtDatumId {
+  ART_DATUM_INVALID = 0;
+  ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS = 1;
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_TIME_HISTO_MILLIS = 2;
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_COUNT = 3;
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_TIME_HISTO_MILLIS = 4;
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_COUNT = 5;
+  ART_DATUM_JIT_METHOD_COMPILE_TIME_MICROS = 6;
+  ART_DATUM_AOT_COMPILE_TIME = 7;
+  ART_DATUM_CLASS_VERIFICATION_TIME_COUNTER_MICROS = 8;
+  ART_DATUM_CLASS_LOADING_TIME_COUNTER_MICROS = 9;
+
+  // Metrics IDs for dex2oat.
+  ART_DATUM_DEX2OAT_RESULT_CODE = 10 [deprecated = true];
+  ART_DATUM_DEX2OAT_DEX_CODE_COUNTER_BYTES = 11 [deprecated = true];
+  ART_DATUM_DEX2OAT_TOTAL_TIME_COUNTER_MILLIS = 12 [deprecated = true];
+  ART_DATUM_DEX2OAT_VERIFY_DEX_FILE_TIME_COUNTER_MILLIS = 13 [deprecated = true];
+  ART_DATUM_DEX2OAT_FAST_VERIFY_TIME_COUNTER_MILLIS = 14 [deprecated = true];
+  ART_DATUM_DEX2OAT_RESOLVE_METHODS_AND_FIELDS_TIME_COUNTER_MILLIS = 15 [deprecated = true];
+
+  ART_DATUM_CLASS_VERIFICATION_COUNT = 16;
+  ART_DATUM_GC_TOTAL_BYTES_ALLOCATED = 17;
+  ART_DATUM_GC_TOTAL_METADATA_SIZE_BYTES = 18 [deprecated=true];
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_HISTO_MB_PER_SEC = 19;
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_HISTO_MB_PER_SEC = 20;
+  ART_DATUM_JIT_METHOD_COMPILE_COUNT = 21;
+  ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_HISTO_MB_PER_SEC = 22;
+  ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_HISTO_MB_PER_SEC = 23;
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC = 24;
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC = 25;
+  ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC = 26;
+  ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC = 27;
+  ART_DATUM_GC_TOTAL_COLLECTION_TIME_MS = 28;
+
+  // New metrics to support averages reported as sum (numerator) and count (denominator),
+  // in order to make it easier to be reported as Value Metrics.
+
+  // numerator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
+  ART_DATUM_GC_WORLD_STOP_TIME_US = 29;
+  // denominator from ART_DATUM_GC_WORLD_STOP_TIME_AVG_MICROS
+  ART_DATUM_GC_WORLD_STOP_COUNT = 30;
+  // numerator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_SCANNED_BYTES = 31;
+  // numerator from ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_FREED_BYTES = 32;
+  // denominator from ART_DATUM_GC_YOUNG_GENERATION_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  // and ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_YOUNG_GENERATION_COLLECTION_DURATION_MS = 33;
+  // numerator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_SCANNED_BYTES = 34;
+  // numerator from ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_FREED_BYTES = 35;
+  // denominator from ART_DATUM_GC_FULL_HEAP_TRACING_THROUGHPUT_AVG_MB_PER_SEC
+  // and ART_DATUM_GC_FULL_HEAP_COLLECTION_THROUGHPUT_AVG_MB_PER_SEC
+  ART_DATUM_GC_FULL_HEAP_COLLECTION_DURATION_MS = 36;
+}
+
+enum BootImageStatus {
+  // Unknown value.
+  STATUS_UNSPECIFIED = 0;
+  // Boot image(s) are fully usable.
+  STATUS_FULL = 1;
+  // Only the minimal boot image is usable.
+  STATUS_MINIMAL = 2;
+  // No boot image is usable.
+  STATUS_NONE = 3;
+}
diff --git a/stats/enums/art/common_enums.proto b/stats/enums/art/common_enums.proto
new file mode 100644
index 00000000..f9ceaf15
--- /dev/null
+++ b/stats/enums/art/common_enums.proto
@@ -0,0 +1,148 @@
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
+package android.os.statsd.art;
+
+option java_package = "com.android.os.art";
+option java_multiple_files = true;
+
+// Indicates the type of the APK.
+enum ArtApkType {
+  ART_APK_TYPE_UNKNOWN = 0;
+  // Primary DEX file in a base APK.
+  ART_APK_TYPE_BASE = 1;
+  // Primary DEX file in a split APK.
+  ART_APK_TYPE_SPLIT = 2;
+  // Secondary DEX file.
+  ART_APK_TYPE_SECONDARY = 3;
+}
+
+// Indicates which compile filter was used for the package being loaded in an ART session.
+enum ArtCompileFilter {
+  ART_COMPILATION_FILTER_UNSPECIFIED = 0;
+  ART_COMPILATION_FILTER_ERROR = 1;
+  ART_COMPILATION_FILTER_UNKNOWN = 2;
+  ART_COMPILATION_FILTER_ASSUMED_VERIFIED = 3;
+  ART_COMPILATION_FILTER_EXTRACT = 4;
+  ART_COMPILATION_FILTER_VERIFY = 5;
+  ART_COMPILATION_FILTER_QUICKEN = 6;
+  ART_COMPILATION_FILTER_SPACE_PROFILE = 7;
+  ART_COMPILATION_FILTER_SPACE = 8;
+  ART_COMPILATION_FILTER_SPEED_PROFILE = 9;
+  ART_COMPILATION_FILTER_SPEED = 10;
+  ART_COMPILATION_FILTER_EVERYTHING_PROFILE = 11;
+  ART_COMPILATION_FILTER_EVERYTHING = 12;
+  ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK = 13;
+  ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK_FALLBACK = 14;
+  ART_COMPILATION_FILTER_FAKE_RUN_FROM_VDEX_FALLBACK = 15;
+}
+
+
+// Indicates what triggered the compilation of the package.
+enum ArtCompilationReason {
+  ART_COMPILATION_REASON_UNSPECIFIED = 0;
+  ART_COMPILATION_REASON_ERROR = 1;
+  ART_COMPILATION_REASON_UNKNOWN = 2;
+  ART_COMPILATION_REASON_FIRST_BOOT = 3;
+  ART_COMPILATION_REASON_BOOT = 4;
+  ART_COMPILATION_REASON_INSTALL = 5;
+  ART_COMPILATION_REASON_BG_DEXOPT = 6;
+  ART_COMPILATION_REASON_AB_OTA = 7;
+  ART_COMPILATION_REASON_INACTIVE = 8;
+  ART_COMPILATION_REASON_SHARED = 9;
+  ART_COMPILATION_REASON_INSTALL_WITH_DEX_METADATA = 10;
+  ART_COMPILATION_REASON_POST_BOOT = 11;
+  ART_COMPILATION_REASON_INSTALL_FAST = 12;
+  ART_COMPILATION_REASON_INSTALL_BULK = 13;
+  ART_COMPILATION_REASON_INSTALL_BULK_SECONDARY = 14;
+  ART_COMPILATION_REASON_INSTALL_BULK_DOWNGRADED = 15;
+  ART_COMPILATION_REASON_INSTALL_BULK_SECONDARY_DOWNGRADED = 16;
+  ART_COMPILATION_REASON_BOOT_AFTER_OTA = 17;
+  ART_COMPILATION_REASON_PREBUILT = 18;
+  ART_COMPILATION_REASON_CMDLINE = 19;
+  ART_COMPILATION_REASON_VDEX = 20;
+  ART_COMPILATION_REASON_BOOT_AFTER_MAINLINE_UPDATE = 21;
+}
+
+// Indicates the type of DEX metadata.
+enum ArtDexMetadataType {
+  ART_DEX_METADATA_TYPE_UNKNOWN = 0;
+  ART_DEX_METADATA_TYPE_PROFILE = 1;
+  ART_DEX_METADATA_TYPE_VDEX = 2;
+  ART_DEX_METADATA_TYPE_PROFILE_AND_VDEX = 3;
+  ART_DEX_METADATA_TYPE_NONE = 4;
+  ART_DEX_METADATA_TYPE_ERROR = 5;
+}
+
+// Indicates the GC collector type.
+enum ArtGcCollectorType {
+  ART_GC_COLLECTOR_TYPE_UNKNOWN = 0;
+  ART_GC_COLLECTOR_TYPE_MARK_SWEEP = 1;
+  ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_SWEEP = 2;
+  ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_COMPACT = 3;
+  ART_GC_COLLECTOR_TYPE_SEMI_SPACE = 4;
+  ART_GC_COLLECTOR_TYPE_CONCURRENT_COPYING = 5;
+  ART_GC_COLLECTOR_TYPE_CONCURRENT_COPYING_BACKGROUND = 6;
+  ART_GC_COLLECTOR_TYPE_CONCURRENT_MARK_COMPACT_BACKGROUND = 7;
+}
+
+// Indicates the ISA (Instruction Set Architecture).
+enum ArtIsa {
+  ART_ISA_UNKNOWN = 0;
+  ART_ISA_ARM = 1;
+  ART_ISA_ARM64 = 2;
+  ART_ISA_X86 = 3;
+  ART_ISA_X86_64 = 4;
+  ART_ISA_MIPS = 5;
+  ART_ISA_MIPS64 = 6;
+  ART_ISA_RISCV64 = 7;
+}
+
+// DEPRECATED - Used to indicate what class of thread the reported values apply to.
+// Deprecated in Jan 2024 as the corresponding filter is no longer needed.
+enum ArtThreadType {
+  ART_THREAD_UNKNOWN = 0;
+  ART_THREAD_MAIN = 1;
+  ART_THREAD_BACKGROUND = 2;
+}
+
+// Indicates support for userfaultfd and minor fault mode.
+enum ArtUffdSupport {
+  ART_UFFD_SUPPORT_UNKNOWN = 0;
+  ART_UFFD_SUPPORT_UFFD_NOT_SUPPORTED = 1;
+  ART_UFFD_SUPPORT_MINOR_FAULT_MODE_NOT_SUPPORTED = 2;
+  ART_UFFD_SUPPORT_MINOR_FAULT_MODE_SUPPORTED = 3;
+}
+
+// Keep in sync with the ExecResult enum defined in art/runtime/exec_utils.h
+enum ExecResultStatus {
+  // Unable to get the status.
+  EXEC_RESULT_STATUS_UNKNOWN = 0;
+  // Process exited normally with an exit code.
+  EXEC_RESULT_STATUS_EXITED = 1;
+  // Process terminated by a signal.
+  EXEC_RESULT_STATUS_SIGNALED = 2;
+  // Process timed out and killed.
+  EXEC_RESULT_STATUS_TIMED_OUT = 3;
+  // Failed to start the process.
+  EXEC_RESULT_STATUS_START_FAILED = 4;
+  // Process was not run.
+  EXEC_RESULT_STATUS_NOT_RUN = 5;
+  // Process was cancelled.
+  EXEC_RESULT_STATUS_CANCELLED = 6;
+}
diff --git a/stats/enums/art/odrefresh_enums.proto b/stats/enums/art/odrefresh_enums.proto
new file mode 100644
index 00000000..331f43bd
--- /dev/null
+++ b/stats/enums/art/odrefresh_enums.proto
@@ -0,0 +1,102 @@
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
+package android.os.statsd.art;
+
+option java_package = "com.android.os.art";
+option java_multiple_files = true;
+
+// Keep in sync with the BcpCompilationType enum defined in art/odrefresh/odr_metrics.h
+enum OdrefreshBcpCompilationType {
+  ODREFRESH_BCP_COMPILATION_TYPE_UNKNOWN = 0;
+  // Compiles for both the primary boot image and the mainline extension.
+  ODREFRESH_BCP_COMPILATION_TYPE_PRIMARY_AND_MAINLINE = 1;
+  // Only compiles for the mainline extension.
+  ODREFRESH_BCP_COMPILATION_TYPE_MAINLINE = 2;
+}
+
+// Keep in sync with the Stage enum defined in art/odrefresh/odr_metrics.h
+enum OdrefreshStage {
+  // A placeholder for unknown values.
+  ODREFRESH_STAGE_UNKNOWN = 0;
+
+  // Checking stage.
+  ODREFRESH_STAGE_CHECK = 10;
+
+  // Preparation for compilation.
+  ODREFRESH_STAGE_PREPARATION = 20;
+
+  // Compilation of the boot classpath for the primary architecture
+  // ("primary boot classpath").
+  ODREFRESH_STAGE_PRIMARY_BOOT_CLASSPATH = 30;
+
+  // Compilation of the boot classpath for the secondary architecture
+  // ("secondary boot classpath"), if any.
+  ODREFRESH_STAGE_SECONDARY_BOOT_CLASSPATH = 40;
+
+  // Compilation of system_server classpath.
+  ODREFRESH_STAGE_SYSTEM_SERVER_CLASSPATH = 50;
+
+  // All stages completed.
+  ODREFRESH_STAGE_COMPLETE = 60;
+}
+
+// Keep in sync with the Status enum defined in art/odrefresh/odr_metrics.h
+enum OdrefreshStatus {
+  // A placeholder for unknown values.
+  ODREFRESH_STATUS_UNKNOWN = 0;
+
+  // OK, no problems encountered.
+  ODREFRESH_STATUS_OK = 1;
+
+  // Insufficient space.
+  ODREFRESH_STATUS_NO_SPACE = 2;
+
+  // Storage operation failed.
+  ODREFRESH_STATUS_IO_ERROR = 3;
+
+  // Dex2oat reported an error.
+  ODREFRESH_STATUS_DEX2OAT_ERROR = 4;
+
+  reserved 5; // was STATUS_TIME_LIMIT_EXCEEDED
+
+  // Failure creating staging area.
+  ODREFRESH_STATUS_STAGING_FAILED = 6;
+
+  // Installation of artifacts failed.
+  ODREFRESH_STATUS_INSTALL_FAILED = 7;
+
+  // Failed to access the dalvik-cache directory due to lack of
+  // permission.
+  ODREFRESH_STATUS_DALVIK_CACHE_PERMISSION_DENIED = 8;
+}
+
+// Keep in sync with the Trigger enum defined in art/odrefresh/odr_metrics.h
+enum OdrefreshTrigger {
+  // A placeholder for unknown values.
+  ODREFRESH_TRIGGER_UNKNOWN = 0;
+
+  // ART APEX version has changed since time artifacts were generated.
+  ODREFRESH_TRIGGER_APEX_VERSION_MISMATCH = 1;
+
+  // Dex files on the boot classpath or system_server classpath have changed.
+  ODREFRESH_TRIGGER_DEX_FILES_CHANGED = 2;
+
+  // Missing artifacts.
+  ODREFRESH_TRIGGER_MISSING_ARTIFACTS = 3;
+}
diff --git a/stats/enums/bluetooth/enums.proto b/stats/enums/bluetooth/enums.proto
index 7faaaa78..63e91911 100644
--- a/stats/enums/bluetooth/enums.proto
+++ b/stats/enums/bluetooth/enums.proto
@@ -548,3 +548,84 @@ enum ContentProfileFileName {
 
   // Will be added more if needed in future.
 }
+
+enum EventType {
+  EVENT_TYPE_UNKNOWN = 0;
+  ACL_CONNECTION_RESPONDER = 1;
+  ACL_CONNECTION_INITIATOR = 2;
+  PROFILE_CONNECTION = 3;
+  AUTHENTICATION_REQUEST = 4;
+  IO_CAPABILITY_REQUEST = 5;
+  USER_CONF_REQUEST = 6;
+  USER_CONF_POSITIVE_REPLY = 7;
+  USER_CONF_NEGATIVE_REPLY = 8;
+  AUTHENTICATION_COMPLETE = 9;
+  SERVICE_DISCOVERY = 10;
+  REMOTE_NAME_REQUEST = 11;
+  ACL_DISCONNECTION_INITIATOR = 12;
+  ACL_DISCONNECTION_RESPONDER = 13;
+  AUTHENTICATION_COMPLETE_FAIL = 14;
+  BONDING = 15;
+  INITIATOR_CONNECTION = 16;
+}
+
+enum State {
+  STATE_UNKNOWN = 0;
+  START = 1;
+  END = 2;
+  SUCCESS = 3;
+  FAIL = 4;
+  ALREADY_CONNECTED = 5;
+  TIMEOUT = 6;
+  REMOTE_USER_TERMINATED_CONNECTION = 7;
+  KEY_MISSING = 8;
+  MEMORY_EXCEEDED = 9;
+  BUSY_PAIRING = 10;
+  REPEATED_ATTEMPTS = 11;
+  PAIRING_NOT_ALLOWED = 12;
+  RESOURCES_EXCEEDED = 13;
+  AUTH_FAILURE = 14;
+  LOCAL_DEVICE_TERMINATED_CONNECTION = 15;
+  TRANSACTION_COLLISION = 16;
+  PAGE_TIMEOUT = 17;
+  CONNECTION_TIMEOUT = 18;
+  CONNECTION_ACCEPT_TIMEOUT = 19;
+  TRANSACTION_RESPONSE_TIMEOUT = 20;
+}
+
+enum RemoteDeviceTypeMetadata {
+    WATCH = 0;
+    UNTETHERED_HEADSET = 1;
+    STYLUS = 2;
+    SPEAKER = 3;
+    HEADSET = 4;
+    CARKIT = 5;
+    DEFAULT = 6;
+    NOT_AVAILABLE = 7;
+}
+
+enum BroadcastAudioQualityType {
+   QUALITY_UNKNOWN = 0;
+   QUALITY_STANDARD = 1;
+   QUALITY_HIGH = 2;
+}
+
+enum BroadcastSessionSetupStatus {
+   SETUP_STATUS_UNKNOWN = 0;
+   SETUP_STATUS_REQUESTED = 1;
+   SETUP_STATUS_CREATED = 2;
+   SETUP_STATUS_STREAMING = 3;
+   SETUP_STATUS_CREATE_FAILED = 4;
+   SETUP_STATUS_STREAMING_FAILED = 5;
+}
+
+enum BroadcastSyncStatus {
+   SYNC_STATUS_UNKNOWN = 0;
+   SYNC_STATUS_SYNC_REQUESTED = 1;
+   SYNC_STATUS_PA_SYNC_SUCCESS = 2;
+   SYNC_STATUS_AUDIO_SYNC_SUCCESS = 3;
+   SYNC_STATUS_PA_SYNC_FAILED = 4;
+   SYNC_STATUS_PA_SYNC_NO_PAST = 5;
+   SYNC_STATUS_BIG_DECRYPT_FAILED = 6;
+   SYNC_STATUS_AUDIO_SYNC_FAILED = 7;
+}
\ No newline at end of file
diff --git a/stats/enums/dnd/dnd_enums.proto b/stats/enums/dnd/dnd_enums.proto
index 92aec986..0d45a734 100644
--- a/stats/enums/dnd/dnd_enums.proto
+++ b/stats/enums/dnd/dnd_enums.proto
@@ -87,3 +87,17 @@ enum ActiveRuleType {
   // Intentional gap for future automatic rule types.
   TYPE_MANUAL = 999;
 }
+
+// Enum used in DNDStateChanged to represent the source of the change.
+// Mirrors values in ZenModeConfig.ConfigOrigin as defined in
+// frameworks/base/core/java/android/service/notification/ZenModeConfig.java.
+enum ChangeOrigin {
+  ORIGIN_UNKNOWN = 0;
+  ORIGIN_INIT = 1;
+  ORIGIN_INIT_USER = 2;
+  ORIGIN_USER_IN_SYSTEMUI = 3;
+  ORIGIN_APP = 4;
+  ORIGIN_SYSTEM = 5;
+  ORIGIN_RESTORE_BACKUP = 6;
+  ORIGIN_USER_IN_APP = 7;
+}
diff --git a/stats/enums/federatedcompute/enums.proto b/stats/enums/federatedcompute/enums.proto
index ba5dacb9..7dd4009a 100644
--- a/stats/enums/federatedcompute/enums.proto
+++ b/stats/enums/federatedcompute/enums.proto
@@ -21,7 +21,7 @@ option java_outer_classname = "FederatedComputeProtoEnums";
 option java_multiple_files = true;
 
 // Enum used to track federated computation job stages.
-// Next Tag: 53
+// Next Tag: 73
 enum TrainingEventKind {
   // Undefined value.
   TRAIN_UNDEFINED = 0;
@@ -109,6 +109,9 @@ enum TrainingEventKind {
   // Client was rejected from a checkin request.
   // Always preceded by TRAIN_DOWNLOAD_STARTED.
   TRAIN_DOWNLOAD_TURNED_AWAY = 18;
+  TRAIN_DOWNLOAD_TURNED_AWAY_NO_TASK_AVAILABLE = 70;
+  TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHORIZED = 71;
+  TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHENTICATED = 72;
 
   // Client started eligibility eval computation.
   TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED = 19;
@@ -142,6 +145,20 @@ enum TrainingEventKind {
   // Always preceded by TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED.
   TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ELIGIBLE = 51;
 
+  // The status of FCP binds to client implemented ExampleStoreService.
+  TRAIN_EXAMPLE_STORE_BIND_START = 62;
+  TRAIN_EXAMPLE_STORE_BIND_SUCCESS = 63;
+  TRAIN_EXAMPLE_STORE_BIND_ERROR = 64;
+
+  // The status of ExampleStoreService.startQuery API.
+  TRAIN_EXAMPLE_STORE_START_QUERY_START = 65;
+  TRAIN_EXAMPLE_STORE_START_QUERY_TIMEOUT = 66;
+  // Indicates all failure cases except timeout when call ExampleStoreService.startQuery API.
+  TRAIN_EXAMPLE_STORE_START_QUERY_ERROR = 67;
+  TRAIN_EXAMPLE_STORE_START_QUERY_SUCCESS = 68;
+  // General error for uncaught failure cases for example store stage.
+  TRAIN_EXAMPLE_STORE_ERROR = 69;
+
   // Client started computation.
   TRAIN_COMPUTATION_STARTED = 26;
 
@@ -234,4 +251,31 @@ enum TrainingEventKind {
 
   // Client successfully finishes one round of training.
   TRAIN_RUN_COMPLETE = 52;
+
+  // Log the fact that a trainging job was started.
+  TRAIN_RUN_STARTED = 53;
+
+  // If any throwable was caught during worker executing training logic.
+  TRAIN_RUN_FAILED_WITH_EXCEPTION = 54;
+
+  // Train failed during checkin at task assignment step.
+  TRAIN_RUN_FAILED_WITH_REJECTION = 55;
+
+  // Eligibility check failed during checkin.
+  TRAIN_RUN_FAILED_NOT_ELIGIBLE = 56;
+
+  // Model and plan download failed during checkin.
+  TRAIN_RUN_FAILED_DOWNLOAD_FAILED = 57;
+
+  // Actual ML computation failed.
+  TRAIN_RUN_FAILED_COMPUTATION_FAILED = 58;
+
+  // Report success to server failed.
+  TRAIN_RUN_FAILED_REPORT_FAILED = 59;
+
+  // Failed to fetch encryption keys.
+  TRAIN_RUN_FAILED_ENCRYPTION_KEY_FETCH_FAILED = 60;
+
+  // Additional conditions chaeck failed.
+  TRAIN_RUN_FAILED_CONDITIONS_FAILED = 61;
 }
diff --git a/stats/enums/hardware/biometrics/enums.proto b/stats/enums/hardware/biometrics/enums.proto
index 4036dd4a..79d1f57e 100644
--- a/stats/enums/hardware/biometrics/enums.proto
+++ b/stats/enums/hardware/biometrics/enums.proto
@@ -57,6 +57,8 @@ enum IssueEnum {
     ISSUE_UNKNOWN_TEMPLATE_ENROLLED_HAL = 3;
     // When the HAL has not sent ERROR_CANCELED within the specified timeout.
     ISSUE_CANCEL_TIMED_OUT = 4;
+    // When there is fingerprint loss of enrollment happens.
+    ISSUE_FINGERPRINTS_LOE = 5;
 }
 
 enum SessionTypeEnum {
diff --git a/stats/enums/hardware/health/enums.proto b/stats/enums/hardware/health/enums.proto
new file mode 100644
index 00000000..1652f657
--- /dev/null
+++ b/stats/enums/hardware/health/enums.proto
@@ -0,0 +1,81 @@
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
+package android.hardware.health;
+
+option java_outer_classname = "HealthProtoEnums";
+option java_multiple_files = true;
+
+enum BatteryPartStatus {
+  /*
+   * Device cannot differentiate an original battery from a replaced battery.
+   */
+  BATTERY_PART_STATUS_UNSUPPORTED = 0;
+  /*
+   * Device has the original battery it was manufactured with.
+   */
+  BATTERY_PART_STATUS_ORIGINAL = 1;
+  /*
+   * Device has a replaced battery.
+   */
+  BATTERY_PART_STATUS_REPLACED = 2;
+}
+
+enum BatteryChargingState {
+  BATTERY_CHARGING_STATE_INVALID = 0;
+  /*
+   * Default state.
+   */
+  BATTERY_CHARGING_STATE_NORMAL = 1;
+  /*
+   * Reported when the battery is too cold to charge at a normal
+   * rate or stopped charging due to low temperature.
+   */
+  BATTERY_CHARGING_STATE_TOO_COLD = 2;
+  /*
+   * Reported when the battery is too hot to charge at a normal
+   * rate or stopped charging due to hot temperature.
+   */
+  BATTERY_CHARGING_STATE_TOO_HOT = 3;
+  /*
+   * The device is using a special charging profile that designed
+   * to prevent accelerated aging.
+   */
+  BATTERY_CHARGING_STATE_LONG_LIFE = 4;
+  /*
+   * The device is using a special charging profile designed to
+   * improve battery cycle life, performances or both.
+   */
+  BATTERY_CHARGING_STATE_ADAPTIVE = 5;
+}
+
+enum BatteryChargingPolicy {
+  BATTERY_CHARGING_POLICY_INVALID = 0;
+  /*
+   * default policy
+   */
+  BATTERY_CHARGING_POLICY_DEFAULT = 1;
+  /*
+   * @see BatteryChargingState.LONG_LIFE
+   */
+  BATTERY_CHARGING_POLICY_LONG_LIFE = 2;
+  /*
+   * @see BatteryChargingState.ADAPTIVE
+   */
+  BATTERY_CHARGING_POLICY_ADAPTIVE = 3;
+}
diff --git a/stats/enums/healthfitness/api/enums.proto b/stats/enums/healthfitness/api/enums.proto
index 113b1b2e..81c9192d 100644
--- a/stats/enums/healthfitness/api/enums.proto
+++ b/stats/enums/healthfitness/api/enums.proto
@@ -77,6 +77,30 @@ enum Operation {
   OPERATION_UPSERT = 1;
 }
 
+// Each of these represents a value in ExportStatus.java.
+enum ExportStatus {
+  EXPORT_STATUS_UNSPECIFIED = 0;
+
+  EXPORT_STATUS_STARTED = 1;
+  EXPORT_STATUS_ERROR_NONE = 2;
+  EXPORT_STATUS_ERROR_UNKNOWN = 3;
+
+  EXPORT_STATUS_ERROR_LOST_FILE_ACCESS = 4;
+  EXPORT_STATUS_ERROR_OUT_OF_STORAGE = 5;
+}
+
+// Each of these represents a value in ImportStatus.java.
+enum ImportStatus {
+  IMPORT_STATUS_UNSPECIFIED = 0;
+
+  IMPORT_STATUS_STARTED = 1;
+  IMPORT_STATUS_ERROR_NONE = 2;
+  IMPORT_STATUS_ERROR_UNKNOWN = 3;
+
+  IMPORT_STATUS_ERROR_WRONG_FILE = 4;
+  IMPORT_STATUS_ERROR_VERSION_MISMATCH = 5;
+}
+
 enum DataType {
   DATA_TYPE_UNKNOWN = 0;
   DATA_TYPE_NOT_ASSIGNED = 1;
@@ -116,6 +140,12 @@ enum DataType {
   WHEELCHAIR_PUSHES = 34;
   SKIN_TEMPERATURE =  35;
   PLANNED_EXERCISE_SESSION =  36;
+  MINDFULNESS_SESSION = 37;
+  BODY_WATER_MASS = 38;
+  HEART_RATE_VARIABILITY_RMSSD = 39;
+  INTERMENSTRUAL_BLEEDING = 40;
+  MENSTRUATION_PERIOD = 41;
+  SLEEP_SESSION = 42;
 }
 
 enum ForegroundState {
diff --git a/stats/enums/healthfitness/ui/enums.proto b/stats/enums/healthfitness/ui/enums.proto
index 52bd6302..d7b467bc 100644
--- a/stats/enums/healthfitness/ui/enums.proto
+++ b/stats/enums/healthfitness/ui/enums.proto
@@ -34,6 +34,8 @@ enum ElementId {
     SEE_ALL_RECENT_ACCESS_BUTTON = 3;
     RECENT_ACCESS_ENTRY = 4;
     MANAGE_DATA_BUTTON = 153;
+    EXPORT_ERROR_BANNER = 229;
+    EXPORT_ERROR_BANNER_BUTTON = 238;
 
     // Onboarding page
     ONBOARDING_COMPLETED_BUTTON = 6;
@@ -283,6 +285,7 @@ enum ElementId {
     BACKUP_DATA_BUTTON = 5;
     DATA_SOURCES_AND_PRIORITY_BUTTON = 154;
     SET_UNITS_BUTTON = 155;
+    BACKUP_AND_RESTORE_BUTTON = 212;
 
     // Data sources page
     DATA_TYPE_SPINNER_BUTTON = 156;
@@ -311,8 +314,89 @@ enum ElementId {
     BACKGROUND_READ_BUTTON = 204;
     HISTORY_READ_BUTTON = 205;
 
-    // Next available: 212;
-
+    // Backup and restore page
+    SCHEDULED_EXPORT_BUTTON = 213;
+    RESTORE_DATA_BUTTON = 214;
+    IMPORT_GENERAL_ERROR_BANNER = 230;
+    IMPORT_GENERAL_ERROR_BANNER_BUTTON = 239;
+    IMPORT_VERSION_MISMATCH_ERROR_BANNER = 231;
+    IMPORT_VERSION_MISMATCH_ERROR_BANNER_BUTTON = 240;
+    IMPORT_WRONG_FILE_ERROR_BANNER = 232;
+    IMPORT_WRONG_FILE_ERROR_BANNER_BUTTON = 241;
+
+    // Export frequency page
+    EXPORT_FREQUENCY_DAILY_BUTTON = 215;
+    EXPORT_FREQUENCY_WEEKLY_BUTTON = 216;
+    EXPORT_FREQUENCY_MONTHLY_BUTTON = 217;
+    EXPORT_FREQUENCY_BACK_BUTTON = 218;
+    EXPORT_FREQUENCY_NEXT_BUTTON = 219;
+
+    // Export destination page
+    EXPORT_DESTINATION_BACK_BUTTON = 220;
+    EXPORT_DESTINATION_NEXT_BUTTON = 221;
+    EXPORT_DESTINATION_DOCUMENT_PROVIDER_BUTTON = 222;
+
+    // Import source location page
+    IMPORT_SOURCE_LOCATION_CANCEL_BUTTON = 223;
+    IMPORT_SOURCE_LOCATION_NEXT_BUTTON = 224;
+    IMPORT_SOURCE_LOCATION_DOCUMENT_PROVIDER_BUTTON = 225;
+
+    // Import confirmation page
+    IMPORT_CONFIRMATION_CANCEL_BUTTON = 226;
+    IMPORT_CONFIRMATION_DONE_BUTTON = 227;
+    IMPORT_CONFIRMATION_CONTAINER = 228;
+
+    // Export settings page
+    EXPORT_CONTROL_SWITCH_ON = 233;
+    EXPORT_CONTROL_SWITCH_OFF = 234;
+    EXPORT_SETTINGS_FREQUENCY_DAILY = 235;
+    EXPORT_SETTINGS_FREQUENCY_WEEKLY = 236;
+    EXPORT_SETTINGS_FREQUENCY_MONTHLY = 237;
+
+    // New Information Architecture
+    BROWSE_DATA_BUTTON = 242;
+    PERMISSION_TYPE_BUTTON_WITH_CHECKBOX = 243;
+    PERMISSION_TYPE_BUTTON_NO_CHECKBOX = 244;
+    SELECT_ALL_BUTTON = 245;
+    SUCCESS_DELETION_DIALOG_SEE_CONNECTED_APPS_BUTTON = 246;
+
+    DATA_SOURCES_MENU_BUTTON = 247;
+    ENTER_DELETION_STATE_MENU_BUTTON = 248;
+    EXIT_DELETION_STATE_MENU_BUTTON = 249;
+    DELETE_MENU_BUTTON = 250;
+
+    ENTRY_BUTTON_WITH_CHECKBOX = 251;
+    ENTRY_BUTTON_NO_CHECKBOX = 252;
+    DATE_VIEW_SPINNER_DAY = 253;
+    DATE_VIEW_SPINNER_WEEK = 254;
+    DATE_VIEW_SPINNER_YEAR = 255;
+
+    SEE_APP_DATA_BUTTON = 256;
+
+    // Categorised UNKNOWN elements to reduce default value dependency
+    UNKNOWN_BANNER = 257;
+    UNKNOWN_BANNER_BUTTON = 258;
+    UNKNOWN_HEALTH_PREFERENCE = 259;
+    UNKNOWN_DIALOG = 260;
+    UNKNOWN_DIALOG_POSITIVE_BUTTON = 261;
+    UNKNOWN_DIALOG_NEGATIVE_BUTTON = 262;
+    UNKNOWN_DIALOG_NEUTRAL_BUTTON = 263;
+    UNKNOWN_SWITCH_ACTIVE_PREFERENCE = 264;
+    UNKNOWN_SWITCH_INACTIVE_PREFERENCE = 265;
+    UNKNOWN_BUTTON = 266;
+
+    // Onboarding
+    START_USING_HC_BANNER = 267;
+    START_USING_HC_BANNER_DISMISS_BUTTON = 268;
+    START_USING_HC_BANNER_SET_UP_BUTTON = 269;
+    CONNECT_MORE_APPS_BANNER = 270;
+    CONNECT_MORE_APPS_BANNER_DISMISS_BUTTON = 271;
+    CONNECT_MORE_APPS_BANNER_SET_UP_BUTTON = 272;
+    SEE_COMPATIBLE_APPS_BANNER = 273;
+    SEE_COMPATIBLE_APPS_BANNER_DISMISS_BUTTON = 274;
+    SEE_COMPATIBLE_APPS_BANNER_APP_STORE_BUTTON = 275;
+
+    // Next available: 276;
 }
 
 enum PageId {
@@ -358,8 +442,19 @@ enum PageId {
     // Additional Access
     ADDITIONAL_ACCESS_PAGE = 30;
     SEARCH_APPS_PAGE = 32;
-
-    // Next available: 36;
+    BACKUP_AND_RESTORE_PAGE = 36;
+    EXPORT_FREQUENCY_PAGE = 37;
+    EXPORT_DESTINATION_PAGE = 38;
+    EXPORT_SETTINGS_PAGE = 39;
+    IMPORT_SOURCE_LOCATION_PAGE = 40;
+
+    ALL_DATA_PAGE = 41;
+    TAB_ENTRIES_PAGE = 42;
+    TAB_ACCESS_PAGE = 43;
+    APP_DATA_PAGE = 44;
+    APP_ENTRIES_PAGE = 45;
+
+    // Next available: 46;
 }
 
 enum Action {
@@ -367,6 +462,7 @@ enum Action {
     ACTION_CLICK = 1;
     ACTION_TOGGLE_ON = 2;
     ACTION_TOGGLE_OFF = 3;
+    ACTION_DISMISS = 4;
 }
 
 enum Source {
diff --git a/stats/enums/input/enums.proto b/stats/enums/input/enums.proto
index 09f3634d..c658874f 100644
--- a/stats/enums/input/enums.proto
+++ b/stats/enums/input/enums.proto
@@ -226,3 +226,56 @@ enum InputDeviceBus {
     // Universal Stylus Initiative (USI) protocol (https://universalstylus.org)
     USI = 3;
 }
+
+/**
+ * Contains input event types we want to record latency values for.
+ * Logged in InputEventLatencyReported atom.
+ */
+enum InputEventType {
+    UNKNOWN_INPUT_EVENT = 0;
+    // Motion events for ACTION_DOWN (when the pointer first goes down)
+    MOTION_ACTION_DOWN = 1;
+    // Motion events for ACTION_MOVE (characterizes scrolling motion)
+    MOTION_ACTION_MOVE = 2;
+    // Motion events for ACTION_UP (when the pointer first goes up)
+    MOTION_ACTION_UP = 3;
+    // Motion events for ACTION_HOVER_MOVE (pointer position on screen changes but pointer is not
+    // down)
+    MOTION_ACTION_HOVER_MOVE = 4;
+    // Motion events for ACTION_SCROLL (moving the mouse wheel)
+    MOTION_ACTION_SCROLL = 5;
+    // Key events for both ACTION_DOWN and ACTION_UP (key press and key release)
+    KEY = 6;
+}
+
+/**
+ * Contains the different stages of the input pipeline defined to capture the latency of input
+   events.
+ * Logged in InputEventLatencyReported atom.
+ */
+enum LatencyStage {
+    UNKNOWN_LATENCY_STAGE = 0;
+    // Start: the input event was created (an interrupt received in the driver)
+    // End: the event was read in userspace (in EventHub)
+    EVENT_TO_READ = 1;
+    // Start: the event was read in EventHub
+    // End: the event was sent to the app via the InputChannel (written to the socket)
+    READ_TO_DELIVER = 2;
+    // Start: the input event was sent to the app
+    // End: the app consumed the input event
+    DELIVER_TO_CONSUME = 3;
+    // Start: the app consumed the event
+    // End: the app's 'finishInputEvent' call was received in inputflinger
+    // The end point can also be called "the app finished processing input event"
+    CONSUME_TO_FINISH = 4;
+    // Start: the app consumed the input event
+    // End: the app produced a buffer
+    CONSUME_TO_GPU_COMPLETE = 5;
+    // Start: the app produced a buffer
+    // End: the frame was shown on the display
+    GPU_COMPLETE_TO_PRESENT = 6;
+    // The end-to-end latency
+    // Start: the input event was created (an interrupt received in the driver)
+    // End: the frame was presented on the display
+    END_TO_END = 7;
+}
diff --git a/stats/enums/jank/enums.proto b/stats/enums/jank/enums.proto
index 0d781846..3d5c312d 100644
--- a/stats/enums/jank/enums.proto
+++ b/stats/enums/jank/enums.proto
@@ -117,6 +117,21 @@ enum InteractionType {
     LAUNCHER_WIDGET_EDU_SHEET_CLOSE_BACK = 101;
     LAUNCHER_PRIVATE_SPACE_LOCK = 102;
     LAUNCHER_PRIVATE_SPACE_UNLOCK = 103;
+    DESKTOP_MODE_MAXIMIZE_WINDOW = 104;
+    FOLD_ANIM = 105;
+    DESKTOP_MODE_RESIZE_WINDOW = 106;
+    DESKTOP_MODE_ENTER_APP_HANDLE_DRAG_HOLD = 107;
+    DESKTOP_MODE_EXIT_MODE = 108;
+    DESKTOP_MODE_MINIMIZE_WINDOW = 109;
+    DESKTOP_MODE_DRAG_WINDOW = 110;
+    STATUS_BAR_LAUNCH_DIALOG_FROM_CHIP = 111;
+    DESKTOP_MODE_ENTER_MODE_APP_HANDLE_MENU = 112;
+    LAUNCHER_KEYBOARD_QUICK_SWITCH_OPEN = 113;
+    LAUNCHER_KEYBOARD_QUICK_SWITCH_CLOSE = 114;
+    LAUNCHER_KEYBOARD_QUICK_SWITCH_APP_LAUNCH = 115;
+    DESKTOP_MODE_ENTER_APP_HANDLE_DRAG_RELEASE = 116;
+    DESKTOP_MODE_EXIT_MODE_ON_LAST_WINDOW_CLOSE = 117;
+    DESKTOP_MODE_SNAP_RESIZE = 118;
 
     reserved 2;
     reserved 73 to 78; // For b/281564325.
@@ -176,4 +191,5 @@ enum ActionType {
     ACTION_BACK_SYSTEM_ANIMATION = 29;
     ACTION_NOTIFICATIONS_HIDDEN_FOR_MEASURE = 30;
     ACTION_NOTIFICATIONS_HIDDEN_FOR_MEASURE_WITH_SHADE_OPEN = 31;
+    ACTION_KEYGUARD_FACE_UNLOCK_TO_HOME = 32;
 }
diff --git a/stats/enums/photopicker/enums.proto b/stats/enums/photopicker/enums.proto
index 5fdc7600..c9df2093 100644
--- a/stats/enums/photopicker/enums.proto
+++ b/stats/enums/photopicker/enums.proto
@@ -27,6 +27,7 @@ option java_multiple_files = true;
 enum PickerPermittedSelection {
   SINGLE = 0;
   MULTIPLE = 1;
+  UNSET_PICKER_PERMITTED_SELECTION = 2;
 }
 
 /*
@@ -37,6 +38,7 @@ enum UserProfile {
   PERSONAL = 1;
   PRIVATE_SPACE = 2;
   UNKNOWN = 3;
+  UNSET_USER_PROFILE = 4;
 }
 
 /*
@@ -46,6 +48,7 @@ enum PickerStatus {
   OPENED = 0;
   CANCELED = 1;
   CONFIRMED = 2;
+  UNSET_PICKER_STATUS = 3;
 }
 
 /*
@@ -55,6 +58,7 @@ enum PickerMode {
   REGULAR_PICKER = 0;
   EMBEDDED_PICKER = 1;
   PERMISSION_MODE_PICKER = 2;
+  UNSET_PICKER_MODE = 3;
 }
 
 /*
@@ -64,6 +68,8 @@ enum PickerCloseMethod {
   SWIPE_DOWN = 0;
   CROSS_BUTTON  =1;
   BACK_BUTTON = 2;
+  PICKER_SELECTION_CONFIRMED = 3;
+  UNSET_PICKER_CLOSE_METHOD = 4;
 }
 
 /*
@@ -72,6 +78,7 @@ enum PickerCloseMethod {
 enum PickerSize {
   COLLAPSED = 0;
   EXPANDED = 1;
+  UNSET_PICKER_SIZE = 2;
 }
 
 /*
@@ -80,6 +87,8 @@ enum PickerSize {
 enum PickerIntentAction {
   ACTION_PICK_IMAGES = 0;
   ACTION_GET_CONTENT = 1;
+  ACTION_USER_SELECT = 2;
+  UNSET_PICKER_INTENT_ACTION = 3;
 }
 
 /*
@@ -88,9 +97,11 @@ enum PickerIntentAction {
 enum MediaType {
   PHOTO = 0;
   VIDEO = 1;
-  GIF = 2;
-  LIVE_PHOTO = 3;
-  OTHER = 4;
+  PHOTO_VIDEO = 2;
+  GIF = 3;
+  LIVE_PHOTO = 4;
+  OTHER = 5;
+  UNSET_MEDIA_TYPE = 6;
 }
 
 /*
@@ -100,6 +111,7 @@ enum SelectedTab {
   PHOTOS = 0;
   ALBUMS = 1;
   COLLECTIONS = 2;
+  UNSET_SELECTED_TAB = 3;
 }
 
 /*
@@ -113,6 +125,7 @@ enum SelectedAlbum {
   VIDEOS = 4;
   UNDEFINED_LOCAL = 5;
   UNDEFINED_CLOUD = 6;
+  UNSET_SELECTED_ALBUM = 7;
 }
 
 /*
@@ -153,6 +166,7 @@ enum UiEvent {
   PICKER_BROWSE_DOCUMENTS_UI = 31;
   ENTER_PICKER_SEARCH = 32;
   SELECT_SEARCH_CATEGORY = 33;
+  UNSET_UI_EVENT = 34;
 }
 
 /*
@@ -161,6 +175,7 @@ enum UiEvent {
 enum MediaStatus {
   SELECTED = 0;
   UNSELECTED = 1;
+  UNSET_MEDIA_STATUS = 2;
 }
 
 /*
@@ -170,6 +185,7 @@ enum MediaLocation {
   MAIN_GRID = 0;
   ALBUM = 1;
   GROUP = 2;
+  UNSET_MEDIA_LOCATION = 3;
 }
 
 /*
@@ -178,6 +194,7 @@ enum MediaLocation {
 enum PreviewModeEntry {
   VIEW_SELECTED = 0;
   LONG_PRESS = 1;
+  UNSET_PREVIEW_MODE_ENTRY = 2;
 }
 
 /*
@@ -187,14 +204,16 @@ enum VideoPlayBackInteractions {
   PLAY = 0;
   PAUSE = 1;
   MUTE = 2;
+  UNSET_VIDEO_PLAYBACK_INTERACTION = 3;
 }
 
 /*
- Picket menu item options
+ Picker menu item options
  */
 enum MenuItemSelected {
   BROWSE = 0;
   CLOUD_SETTINGS = 1;
+  UNSET_MENU_ITEM_SELECTED = 2;
 }
 
 /*
@@ -205,6 +224,7 @@ enum BannerType {
   ACCOUNT_UPDATED = 1;
   CHOOSE_ACCOUNT = 2;
   CHOOSE_APP = 3;
+  UNSET_BANNER_TYPE = 4;
 }
 
 /*
@@ -214,6 +234,7 @@ enum UserBannerInteraction {
   CLICK_BANNER_ACTION_BUTTON = 0;
   CLICK_BANNER_DISMISS_BUTTON = 1;
   CLICK_BANNER = 2;
+  UNSET_USER_BANNER_INTERACTION = 3;
 }
 
 /*
@@ -223,4 +244,5 @@ enum SearchMethod {
   SEARCH_QUERY = 0;
   COLLECTION = 1;
   SUGGESTED_SEARCHES = 2;
+  UNSET_SEARCH_METHOD = 3;
 }
\ No newline at end of file
diff --git a/stats/enums/stats/connectivity/network_stack.proto b/stats/enums/stats/connectivity/network_stack.proto
index 9782e00a..c465f07e 100644
--- a/stats/enums/stats/connectivity/network_stack.proto
+++ b/stats/enums/stats/connectivity/network_stack.proto
@@ -193,6 +193,8 @@ enum NetworkQuirkEvent {
     QE_APF_INSTALL_FAILURE = 2;
     QE_APF_OVER_SIZE_FAILURE = 3;
     QE_APF_GENERATE_FILTER_EXCEPTION = 4;
+    QE_DHCP6_HEURISTIC_TRIGGERED = 5;
+    QE_DHCP6_PD_PROVISIONED = 6;
 }
 
 enum IpType {
@@ -270,7 +272,7 @@ enum CounterName {
    CN_DROPPED_IPV6_MULTICAST_PING = 23;
    CN_DROPPED_IPV6_NON_ICMP_MULTICAST = 24;
    CN_DROPPED_802_3_FRAME = 25;
-   CN_DROPPED_ETHERTYPE_DENYLISTED = 26;
+   CN_DROPPED_ETHERTYPE_DENYLISTED = 26 [deprecated = true];
    CN_DROPPED_ARP_REPLY_SPA_NO_HOST = 27;
    CN_DROPPED_IPV4_KEEPALIVE_ACK = 28;
    CN_DROPPED_IPV6_KEEPALIVE_ACK = 29;
@@ -278,6 +280,22 @@ enum CounterName {
    CN_DROPPED_MDNS = 31;
    CN_DROPPED_ARP_NON_IPV4 = 32;
    CN_DROPPED_ARP_UNKNOWN = 33;
+   CN_PASSED_ARP_BROADCAST_REPLY = 34;
+   CN_PASSED_ARP_REQUEST = 35;
+   CN_PASSED_IPV4_FROM_DHCPV4_SERVER = 36;
+   CN_PASSED_IPV6_NS_DAD = 37;
+   CN_PASSED_IPV6_NS_NO_ADDRESS = 38;
+   CN_PASSED_IPV6_NS_NO_SLLA_OPTION = 39;
+   CN_PASSED_IPV6_NS_TENTATIVE = 40;
+   CN_PASSED_MLD = 41;
+   CN_DROPPED_ETHERTYPE_NOT_ALLOWED = 42;
+   CN_DROPPED_IPV4_NON_DHCP4 = 43;
+   CN_DROPPED_IPV6_NS_INVALID = 44;
+   CN_DROPPED_IPV6_NS_OTHER_HOST = 45;
+   CN_DROPPED_IPV6_NS_REPLIED_NON_DAD = 46;
+   CN_DROPPED_ARP_REQUEST_ANYHOST = 47;
+   CN_DROPPED_ARP_REQUEST_REPLIED = 48;
+   CN_DROPPED_ARP_V6_ONLY = 49;
 }
 
 message NetworkStackEventData {
diff --git a/stats/enums/telecomm/enums.proto b/stats/enums/telecomm/enums.proto
index f84b8e43..3a832a05 100644
--- a/stats/enums/telecomm/enums.proto
+++ b/stats/enums/telecomm/enums.proto
@@ -246,3 +246,155 @@ enum CallFailureCauseEnum {
      */
     FAILURE_CAUSE_MAX_SELF_MANAGED_CALLS = 7;
 }
+
+/**
+ * Indicating the call direction
+ */
+enum CallDirectionEnum {
+    DIR_UNKNOWN = 0;
+    DIR_INCOMING = 1;
+    DIR_OUTGOING = 2;
+}
+
+/**
+ * Indicating the account type
+ */
+enum AccountTypeEnum {
+     ACCOUNT_UNKNOWN = 0;
+     ACCOUNT_MANAGED = 1;
+     ACCOUNT_SELFMANAGED = 2;
+     ACCOUNT_SIM = 3;
+     ACCOUNT_VOIP_API = 4;
+}
+
+/**
+ * Indicating the call audio events
+ */
+enum CallAudioEnum {
+    CALL_AUDIO_UNSPECIFIED = 0;
+    CALL_AUDIO_PHONE_SPEAKER = 1;
+    CALL_AUDIO_WATCH_SPEAKER = 2;
+    CALL_AUDIO_BLUETOOTH = 3;
+    CALL_AUDIO_AUTO = 4;
+    CALL_AUDIO_EARPIECE = 5;
+    CALL_AUDIO_WIRED_HEADSET = 6;
+    CALL_AUDIO_HEARING_AID = 7;
+    CALL_AUDIO_BLUETOOTH_LE = 8;
+}
+
+/**
+ * Indicating the API name
+ */
+enum ApiNameEnum {
+    UNSPECIFIED = 0;
+    ACCEPT_HANDOVER = 1;
+    ACCEPT_RINGING_CALL = 2;
+    ACCEPT_RINGING_CALL_WITH_VIDEO_STATE = 3;
+    ADD_CALL = 4;
+    ADD_NEW_INCOMING_CALL = 5;
+    ADD_NEW_INCOMING_CONFERENCE = 6;
+    ADD_NEW_UNKNOWN_CALL = 7;
+    CANCEL_MISSED_CALLS_NOTIFICATION = 8;
+    CLEAR_ACCOUNTS = 9;
+    CREATE_LAUNCH_EMERGENCY_DIALER_INTENT = 10;
+    CREATE_MANAGE_BLOCKED_NUMBERS_INTENT = 11;
+    DUMP = 12;
+    DUMP_CALL_ANALYTICS = 13;
+    ENABLE_PHONE_ACCOUNT = 14;
+    END_CALL = 15;
+    GET_ADN_URI_FOR_PHONE_ACCOUNT = 16;
+    GET_ALL_PHONE_ACCOUNT_HANDLES = 17;
+    GET_ALL_PHONE_ACCOUNTS = 18;
+    GET_ALL_PHONE_ACCOUNTS_COUNT = 19;
+    GET_CALL_CAPABLE_PHONE_ACCOUNTS = 20;
+    GET_CALL_STATE = 21;
+    GET_CALL_STATE_USING_PACKAGE = 22;
+    GET_CURRENT_TTY_MODE = 23;
+    GET_DEFAULT_DIALER_PACKAGE = 24;
+    GET_DEFAULT_DIALER_PACKAGE_FOR_USER = 25;
+    GET_DEFAULT_OUTGOING_PHONE_ACCOUNT = 26;
+    GET_DEFAULT_PHONE_APP = 27;
+    GET_LINE1_NUMBER = 28;
+    GET_OWN_SELF_MANAGED_PHONE_ACCOUNTS = 29;
+    GET_PHONE_ACCOUNT = 30;
+    GET_PHONE_ACCOUNTS_FOR_PACKAGE = 31;
+    GET_PHONE_ACCOUNTS_SUPPORTING_SCHEME = 32;
+    GET_REGISTERED_PHONE_ACCOUNTS = 33;
+    GET_SELF_MANAGED_PHONE_ACCOUNTS = 34;
+    GET_SIM_CALL_MANAGER = 35;
+    GET_SIM_CALL_MANAGER_FOR_USER = 36;
+    GET_SYSTEM_DIALER_PACKAGE = 37;
+    GET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 38;
+    GET_VOICE_MAIL_NUMBER = 39;
+    HANDLE_PIN_MMI = 40;
+    HANDLE_PIN_MMI_FOR_PHONE_ACCOUNT = 41;
+    HAS_MANAGE_ONGOING_CALLS_PERMISSION = 42;
+    IS_IN_CALL = 43;
+    IS_IN_EMERGENCY_CALL = 44;
+    IS_IN_MANAGED_CALL = 45;
+    IS_IN_SELF_MANAGED_CALL = 46;
+    IS_INCOMING_CALL_PERMITTED = 47;
+    IS_OUTGOING_CALL_PERMITTED = 48;
+    IS_RINGING = 49;
+    IS_TTY_SUPPORTED = 50;
+    IS_VOICE_MAIL_NUMBER = 51;
+    PLACE_CALL = 52;
+    REGISTER_PHONE_ACCOUNT = 53;
+    SET_DEFAULT_DIALER = 54;
+    SET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT = 55;
+    SHOW_IN_CALL_SCREEN = 56;
+    SILENCE_RINGER = 57;
+    START_CONFERENCE = 58;
+    UNREGISTER_PHONE_ACCOUNT = 59;
+}
+
+/**
+ * Indicating the result of the API call
+ */
+enum ApiResultEnum {
+    RESULT_UNKNOWN = 0;
+    RESULT_SUCCESS = 1;
+    RESULT_PERMISSION = 2;
+    RESULT_EXCEPTION = 3;
+}
+
+/**
+ * Indicating the sub module name
+ */
+enum SubmoduleNameEnum {
+    SUB_MODULE_UNKNOWN = 0;
+    SUB_MODULE_CALL_AUDIO = 1;
+    SUB_MODULE_CALL_LOGS = 2;
+    SUB_MODULE_CALL_MANAGER = 3;
+    SUB_MODULE_CONNECTION_SERVICE = 4;
+    SUB_MODULE_EMERGENCY_CALL = 5;
+    SUB_MODULE_IN_CALL_SERVICE = 6;
+    SUB_MODULE_MISC = 7;
+    SUB_MODULE_PHONE_ACCOUNT = 8;
+    SUB_MODULE_SYSTEM_SERVICE = 9;
+    SUB_MODULE_TELEPHONY = 10;
+    SUB_MODULE_UI = 11;
+    SUB_MODULE_VOIP_CALL = 12;
+}
+
+/**
+ * Indicating the error name
+ */
+enum ErrorNameEnum {
+    ERROR_UNKNOWN = 0;
+    ERROR_EXTERNAL_EXCEPTION = 1;
+    ERROR_INTERNAL_EXCEPTION = 2;
+    ERROR_AUDIO_ROUTE_RETRY_REJECTED = 3;
+    ERROR_BT_GET_SERVICE_FAILURE = 4;
+    ERROR_BT_REGISTER_CALLBACK_FAILURE = 5;
+    ERROR_DOCK_NOT_AVAILABLE = 6;
+    ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE = 7;
+    ERROR_NOTIFY_CALL_STREAM_START_FAILURE = 8;
+    ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE = 9;
+    ERROR_NOTIFY_CALL_STREAM_STOP_FAILURE = 10;
+    ERROR_RTT_STREAM_CLOSE_FAILURE = 11;
+    ERROR_RTT_STREAM_CREATE_FAILURE = 12;
+    ERROR_SET_MUTED_FAILURE = 13;
+    ERROR_VIDEO_PROVIDER_SET_FAILURE = 14;
+    ERROR_WIRED_HEADSET_NOT_AVAILABLE = 15;
+}
diff --git a/stats/enums/telephony/enums.proto b/stats/enums/telephony/enums.proto
index 6c30fc6b..e52bbd50 100644
--- a/stats/enums/telephony/enums.proto
+++ b/stats/enums/telephony/enums.proto
@@ -679,3 +679,21 @@ enum CallComposerStatus {
     CALL_COMPOSER_STATUS_ON = 2;
     CALL_COMPOSER_STATUS_BUSINESS_ONLY = 3;
 }
+
+/**
+ * enum for call state
+ * See frameworks/base/telephony/java/android/telephony/PreciseCallState.java
+ */
+enum CallState {
+    CALL_STATE_UNKNOWN = 0;
+    CALL_STATE_IDLE = 1;
+    CALL_STATE_ACTIVE = 2;
+    CALL_STATE_HOLDING = 3;
+    CALL_STATE_DIALING = 4;
+    CALL_STATE_ALERTING = 5;
+    CALL_STATE_INCOMING = 6;
+    CALL_STATE_WAITING = 7;
+    CALL_STATE_DISCONNECTED = 8;
+    CALL_STATE_DISCONNECTING = 9;
+    CALL_STATE_INCOMING_SETUP = 10;
+}
diff --git a/stats/enums/telephony/iwlan/OWNERS b/stats/enums/telephony/iwlan/OWNERS
new file mode 100644
index 00000000..242d2765
--- /dev/null
+++ b/stats/enums/telephony/iwlan/OWNERS
@@ -0,0 +1,2 @@
+ktchow@google.com
+pochunlee@google.com
\ No newline at end of file
diff --git a/stats/enums/telephony/iwlan/enums.proto b/stats/enums/telephony/iwlan/enums.proto
new file mode 100644
index 00000000..d8913c50
--- /dev/null
+++ b/stats/enums/telephony/iwlan/enums.proto
@@ -0,0 +1,70 @@
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
+package android.telephony.iwlan;
+
+option java_outer_classname = "IwlanProtoEnums";
+option java_multiple_files = true;
+
+// Events which trigger underlying network validation
+enum UnderlyingNetworkValidationEvent {
+  // Unspecified event
+  NETWORK_VALIDATION_EVENT_UNSPECIFIED = 0;
+
+  // Trigger network validation when making a call.
+  NETWORK_VALIDATION_EVENT_MAKING_CALL = 1;
+
+  // Trigger network validation when screen on.
+  NETWORK_VALIDATION_EVENT_SCREEN_ON = 2;
+
+  // Trigger network validation when no response on network.
+  NETWORK_VALIDATION_EVENT_NO_RESPONSE = 3;
+}
+
+// Results for underlying network validation
+enum UnderlyingNetworkValidationResult {
+  // Unspecified validation result
+  NETWORK_VALIDATION_RESULT_UNSPECIFIED = 0;
+
+  // The overall status of the network is that it is invalid; it neither provides connectivity nor
+  // has been exempted from validation.
+  NETWORK_VALIDATION_RESULT_INVALID = 1;
+
+  // The overall status of the network is that it is valid, this may be because it provides full
+  // Internet access (all probes succeeded), or because other properties of the network caused
+  // probes not to be run.
+  NETWORK_VALIDATION_RESULT_VALID = 2;
+
+  // The overall status of the network is that it provides partial connectivity; some probed
+  // services succeeded but others failed.
+  NETWORK_VALIDATION_RESULT_PARTIALLY_VALID = 3;
+
+  // Due to the properties of the network, validation was not performed.
+  NETWORK_VALIDATION_RESULT_SKIPPED = 4;
+}
+
+// Transport types for the underlying network
+enum TransportType {
+  // Unspecified transport type
+  TRANSPORT_TYPE_UNSPECIFIED = 0;
+
+  // Indicates the network uses a Cellular transport.
+  TRANSPORT_TYPE_CELLULAR = 1;
+
+  // Indicates the network uses a Wi-Fi transport.
+  TRANSPORT_TYPE_WIFI = 2;
+}
\ No newline at end of file
diff --git a/stats/enums/telephony/satellite/enums.proto b/stats/enums/telephony/satellite/enums.proto
index c5652523..4147686f 100644
--- a/stats/enums/telephony/satellite/enums.proto
+++ b/stats/enums/telephony/satellite/enums.proto
@@ -32,32 +32,47 @@ enum DatagramType {
   // Datagram type indicating that keep the device in satellite connected state or check if there is
   // any incoming message.
   DATAGRAM_TYPE_KEEP_ALIVE = 3;
+  // Datagram type indicating that the datagram to be sent or received is of type SOS message and
+  // is the last message to emergency service provider indicating still needs help.
+  DATAGRAM_TYPE_LAST_SOS_MESSAGE_STILL_NEED_HELP = 4;
+  // Datagram type indicating that the datagram to be sent or received is of type SOS message and
+  // is the last message to emergency service provider indicating no more help is needed.
+  DATAGRAM_TYPE_LAST_SOS_MESSAGE_NO_HELP_NEEDED = 5;
+  // Datagram type indicating that the message to be sent or received is of type SMS.
+  DATAGRAM_TYPE_SMS = 6;
 }
 
 // Result code of Incoming / Outgoing satellite datagram
 // SatelliteServiceResultEnum is not completed yet, it'll be updated once design is fixed
 enum SatelliteError {
-  SATELLITE_ERROR_NONE = 0;
-  SATELLITE_ERROR = 1;
-  SATELLITE_SERVER_ERROR = 2;
-  SATELLITE_SERVICE_ERROR = 3;
-  SATELLITE_MODEM_ERROR = 4;
-  SATELLITE_NETWORK_ERROR = 5;
-  SATELLITE_INVALID_TELEPHONY_STATE = 6;
-  SATELLITE_INVALID_MODEM_STATE = 7;
-  SATELLITE_INVALID_ARGUMENTS = 8;
-  SATELLITE_REQUEST_FAILED = 9;
-  SATELLITE_RADIO_NOT_AVAILABLE = 10;
-  SATELLITE_REQUEST_NOT_SUPPORTED = 11;
-  SATELLITE_NO_RESOURCES = 12;
-  SATELLITE_SERVICE_NOT_PROVISIONED = 13;
-  SATELLITE_SERVICE_PROVISION_IN_PROGRESS = 14;
-  SATELLITE_REQUEST_ABORTED = 15;
-  SATELLITE_ACCESS_BARRED = 16;
-  SATELLITE_NETWORK_TIMEOUT = 17;
-  SATELLITE_NOT_REACHABLE = 18;
-  SATELLITE_NOT_AUTHORIZED = 19;
-  SATELLITE_NOT_SUPPORTED = 20;
+  SATELLITE_RESULT_SUCCESS = 0;
+  SATELLITE_RESULT_ERROR = 1;
+  SATELLITE_RESULT_SERVER_ERROR = 2;
+  SATELLITE_RESULT_SERVICE_ERROR = 3;
+  SATELLITE_RESULT_MODEM_ERROR = 4;
+  SATELLITE_RESULT_NETWORK_ERROR = 5;
+  SATELLITE_RESULT_INVALID_TELEPHONY_STATE = 6;
+  SATELLITE_RESULT_INVALID_MODEM_STATE = 7;
+  SATELLITE_RESULT_INVALID_ARGUMENTS = 8;
+  SATELLITE_RESULT_REQUEST_FAILED = 9;
+  SATELLITE_RESULT_RADIO_NOT_AVAILABLE = 10;
+  SATELLITE_RESULT_REQUEST_NOT_SUPPORTED = 11;
+  SATELLITE_RESULT_NO_RESOURCES = 12;
+  SATELLITE_RESULT_SERVICE_NOT_PROVISIONED = 13;
+  SATELLITE_RESULT_SERVICE_PROVISION_IN_PROGRESS = 14;
+  SATELLITE_RESULT_REQUEST_ABORTED = 15;
+  SATELLITE_RESULT_ACCESS_BARRED = 16;
+  SATELLITE_RESULT_NETWORK_TIMEOUT = 17;
+  SATELLITE_RESULT_NOT_REACHABLE = 18;
+  SATELLITE_RESULT_NOT_AUTHORIZED = 19;
+  SATELLITE_RESULT_NOT_SUPPORTED = 20;
+  SATELLITE_RESULT_REQUEST_IN_PROGRESS = 21;
+  SATELLITE_RESULT_MODEM_BUSY = 22;
+  SATELLITE_RESULT_ILLEGAL_STATE = 23;
+  SATELLITE_RESULT_MODEM_TIMEOUT = 24;
+  SATELLITE_RESULT_LOCATION_DISABLED = 25;
+  SATELLITE_RESULT_LOCATION_NOT_AVAILABLE = 26;
+  SATELLITE_RESULT_EMERGENCY_CALL_IN_PROGRESS = 27;
 }
 
 // Technology of Satellite Communication
@@ -134,3 +149,14 @@ enum AccessControlType {
   ACCESS_CONTROL_TYPE_CACHED_COUNTRY_CODE = 4;
 }
 
+// Satellite access controller triggering event
+enum TriggeringEvent {
+  // Unknown reason.
+  TRIGGERING_EVENT_UNKNOWN = 0;
+  // Satellite Access Controller has been triggered by an external event.
+  TRIGGERING_EVENT_EXTERNAL_REQUEST = 1;
+  // Satellite Access Controller has been triggered by an MCC change event.
+  TRIGGERING_EVENT_MCC_CHANGED = 2;
+  //Satellite Access Controller has been triggered due to the location setting being enabled
+  TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED = 3;
+}
diff --git a/stats/enums/view/inputmethod/enums.proto b/stats/enums/view/inputmethod/enums.proto
index 3a409b06..7b1f137b 100644
--- a/stats/enums/view/inputmethod/enums.proto
+++ b/stats/enums/view/inputmethod/enums.proto
@@ -229,5 +229,41 @@ enum ImeRequestPhaseEnum {
     PHASE_IME_PRIVILEGED_OPERATIONS = 46;
     // Checked that the calling IME is the currently active IME.
     PHASE_SERVER_CURRENT_ACTIVE_IME = 47;
+    // Reporting the new requested visible types.
+    PHASE_CLIENT_REPORT_REQUESTED_VISIBLE_TYPES = 48;
+    // Setting the IME visibility for the RemoteInsetsControlTarget.
+    PHASE_WM_SET_REMOTE_TARGET_IME_VISIBILITY = 49;
+    // IME has no insets pending and is server visible. Notify about changed controls.
+    PHASE_WM_POST_LAYOUT_NOTIFY_CONTROLS_CHANGED = 50;
+    // Handling the dispatch of the IME visibility change.
+    PHASE_CLIENT_HANDLE_DISPATCH_IME_VISIBILITY_CHANGED = 51;
+    // Notifying that the IME visibility change.
+    PHASE_CLIENT_NOTIFY_IME_VISIBILITY_CHANGED = 52;
+    // Updating the requested visible types.
+    PHASE_CLIENT_UPDATE_REQUESTED_VISIBLE_TYPES = 53;
+    // Reached the remote insets control target's setImeInputTargetRequestedVisibility method.
+    PHASE_WM_REMOTE_INSETS_CONTROL_TARGET_SET_REQUESTED_VISIBILITY = 54;
+    // Received a new insets source control with a leash.
+    PHASE_WM_GET_CONTROL_WITH_LEASH = 55;
+    // Updating the requested visible types in the WindowState and sending them to state controller.
+    PHASE_WM_UPDATE_REQUESTED_VISIBLE_TYPES = 56;
+    // Setting the requested IME visibility of a window.
+    PHASE_SERVER_SET_VISIBILITY_ON_FOCUSED_WINDOW = 57;
+    // Reached the redirect of InputMethodManager to InsetsController show/hide.
+    PHASE_CLIENT_HANDLE_SET_IME_VISIBILITY = 58;
+    // Reached the InputMethodManager Handler call to send the visibility.
+    PHASE_CLIENT_SET_IME_VISIBILITY = 59;
+    // Calling into the listener to show/hide the IME from the ImeInsetsSourceProvider.
+    PHASE_WM_DISPATCH_IME_REQUESTED_CHANGED = 60;
+    // An ongoing user animation will not be interrupted by a IMM#showSoftInput.
+    PHASE_CLIENT_NO_ONGOING_USER_ANIMATION = 61;
+    // Dispatching the token to the ImeInsetsSourceProvider.
+    PHASE_WM_NOTIFY_IME_VISIBILITY_CHANGED_FROM_CLIENT = 62;
+    // Now posting the IME visibility to the WMS handler.
+    PHASE_WM_POSTING_CHANGED_IME_VISIBILITY = 63;
+    // Inside the WMS handler calling into the listener that calls into IMMS show/hide.
+    PHASE_WM_INVOKING_IME_REQUESTED_LISTENER = 64;
+    // IME is requested to be hidden, but already hidden. Don't hide to avoid another animation.
+    PHASE_CLIENT_ALREADY_HIDDEN = 65;
 }
 
diff --git a/stats/enums/wear/connectivity/enums.proto b/stats/enums/wear/connectivity/enums.proto
index 7a0f8bcb..fa75b19d 100644
--- a/stats/enums/wear/connectivity/enums.proto
+++ b/stats/enums/wear/connectivity/enums.proto
@@ -196,6 +196,8 @@ enum SysproxyConnectionAction {
     SYSPROXY_CONNECTION_ACTION_UNKNOWN = 0;
     SYSPROXY_CONNECTED = 1;
     SYSPROXY_DISCONNECTED = 2;
+    SYSPROXY_CONNECT_NATIVE_SERVICE_FAILED = 3;
+    SYSPROXY_CONNECT_NATIVE_SERVICE_TIMEOUT = 4;
 }
 
 /**
@@ -230,3 +232,15 @@ enum BluetoothConnectionChange {
     ACL_CONNECT = 1;
     ACL_DISCONNECT = 2;
 }
+
+enum CompanionConnectionType {
+    COMPANION_CONNECTION_TYPE_UNKNOWN = 0;
+    BLE_ACL = 1;
+    BTC_ACL = 2;
+}
+
+enum CompanionConnectionChange {
+    COMPANION_CONNECTION_CHANGE_UNKNOWN = 0;
+    CONNECTED = 1;
+    DISCONNECTED = 2;
+}
diff --git a/stats/enums/wear/time/enums.proto b/stats/enums/wear/time/enums.proto
new file mode 100644
index 00000000..475a6552
--- /dev/null
+++ b/stats/enums/wear/time/enums.proto
@@ -0,0 +1,64 @@
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
+package com.google.android.apps.wearable.settings;
+
+/**
+ * Indicates the type of intent that kicked off sync.
+ */
+enum RequestTypeEnum {
+  REQUEST_TYPE_UNSPECIFIED = 0;
+  REQUEST_TYPE_POLL = 1;
+  REQUEST_TYPE_EVALUATE = 2;
+  REQUEST_TYPE_COMPANION = 3;
+}
+
+/**
+ * Indicates the location from which the sync was started.
+ */
+enum SourceTypeEnum {
+  SOURCE_TYPE_UNSPECIFIED = 0;
+  SOURCE_TYPE_BOOT = 1;
+  SOURCE_TYPE_OOBE = 2;
+  SOURCE_TYPE_COMPANION_CONNECTION = 3;
+  SOURCE_TYPE_TOGGLE = 4;
+  SOURCE_TYPE_PERIODIC_JOB = 5;
+}
+
+/**
+ * Indicates the source of information the sync uses to get its result.
+ */
+enum OriginTypeEnum {
+  ORIGIN_TYPE_UNSPECIFIED = 0;
+  ORIGIN_TYPE_COMPANION = 1;
+  ORIGIN_TYPE_NETWORK = 2;
+  ORIGIN_TYPE_NITZ = 3;
+  ORIGIN_TYPE_GNSS = 4;
+  ORIGIN_TYPE_MANUAL = 5;
+}
+
+/**
+ * Indicates the reason for the sync operation failure.
+ */
+enum FailureReasonEnum {
+  FAILURE_REASON_UNSPECIFIED = 0;
+  FAILURE_REASON_TIMEOUT = 1;
+  FAILURE_REASON_LATENCY = 2;
+  FAILURE_REASON_COMPANION_INVALID_RESPONSE = 3;
+  FAILURE_REASON_DISCONNECTED = 4;
+}
diff --git a/stats/express/catalog/accessibility.cfg b/stats/express/catalog/accessibility.cfg
index 2291cb2f..a2e8874c 100644
--- a/stats/express/catalog/accessibility.cfg
+++ b/stats/express/catalog/accessibility.cfg
@@ -41,3 +41,37 @@ express_metric {
     # the accessibility shortcut feature(s).
     type: COUNTER_WITH_UID
 }
+
+express_metric {
+    id: "accessibility.value_full_triple_tap_first_interval"
+    type: HISTOGRAM
+    display_name: "Magnification First Interval of Triple Tap on Fullscreen"
+    description: "Time interval between the first and second taps in a triple-tap gesture used to trigger Magnification."
+    owner_email: "chenjean@google.com"
+    owner_email: "low-vision-eng@google.com"
+    unit: UNIT_TIME_MILLIS
+    histogram_options {
+        uniform_bins {
+            count: 25
+            min: 0
+            max: 250
+        }
+    }
+}
+
+express_metric {
+    id: "accessibility.value_full_triple_tap_second_interval"
+    type: HISTOGRAM
+    display_name: "Magnification Second Interval of Triple Tap on Fullscreen"
+    description: "Time interval between the first and second taps in a triple-tap gesture used to trigger Magnification."
+    owner_email: "chenjean@google.com"
+    owner_email: "low-vision-eng@google.com"
+    unit: UNIT_TIME_MILLIS
+    histogram_options {
+        uniform_bins {
+            count: 25
+            min: 0
+            max: 250
+        }
+    }
+}
diff --git a/stats/express/catalog/biometric.cfg b/stats/express/catalog/biometric.cfg
index 952570c6..01ed5a1e 100644
--- a/stats/express/catalog/biometric.cfg
+++ b/stats/express/catalog/biometric.cfg
@@ -7,3 +7,13 @@ express_metric {
     unit: UNIT_COUNT
     type: COUNTER
 }
+
+express_metric {
+    id: "biometric.value_biometric_scheduler_operation_state_error_count"
+    display_name: "Biometric scheduler operation state error counter"
+    description: "Number of times the state of the client was incorrect for biometric scheduler operation to either start, cancel or abort."
+    owner_email: "android-biometrics-core+apc@google.com"
+    owner_email: "diyab@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
\ No newline at end of file
diff --git a/stats/express/catalog/bluetooth.cfg b/stats/express/catalog/bluetooth.cfg
index 4ae79172..7f9f763b 100644
--- a/stats/express/catalog/bluetooth.cfg
+++ b/stats/express/catalog/bluetooth.cfg
@@ -50,6 +50,60 @@ express_metric {
     unit: UNIT_COUNT
 }
 
+express_metric {
+    id: "bluetooth.value_sbc_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- SBC"
+    description: "Counter on how many times SBC is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "bluetooth.value_aac_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- AAC"
+    description: "Counter on how many times AAC is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "bluetooth.value_aptx_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- AptX"
+    description: "Counter on how many times AptX is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "bluetooth.value_aptx_hd_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- AptX HD"
+    description: "Counter on how many times Aptx HD is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "bluetooth.value_ldac_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- LDAC"
+    description: "Counter on how many times LDAC is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "bluetooth.value_opus_codec_usage_over_a2dp"
+    type: COUNTER
+    display_name: "A2DP codec usage -- Opus"
+    description: "Counter on how many times Opus is used for A2DP."
+    owner_email: "henrichataing@google.com"
+    unit: UNIT_COUNT
+}
+
 express_metric {
     id: "bluetooth.value_auto_on_supported"
     type: COUNTER
@@ -94,3 +148,19 @@ express_metric {
     owner_email: "wescande@google.com"
     unit: UNIT_COUNT
 }
+
+express_metric {
+    id: "bluetooth.value_shutdown_latency"
+    type: HISTOGRAM
+    display_name: "Bluetooth app shutdown time"
+    description: "Latency to shutdown entirely the Bluetooth app"
+    owner_email: "wescande@google.com"
+    unit: UNIT_TIME_MILLIS
+    histogram_options: {
+        uniform_bins: {
+            count: 50
+            min: 0
+            max: 3000
+        }
+    }
+}
diff --git a/stats/express/catalog/core_networking.cfg b/stats/express/catalog/core_networking.cfg
new file mode 100644
index 00000000..97aaca73
--- /dev/null
+++ b/stats/express/catalog/core_networking.cfg
@@ -0,0 +1,19 @@
+express_metric {
+    id: "core_networking.value_nud_failure_queried"
+    type: COUNTER
+    display_name: "Nud failure query count"
+    description: "Counting how many times IpClient queried nud failure."
+    owner_email: "yuyanghuang@google.com"
+    owner_email: "xiaom@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "core_networking.value_nud_failure_ignored"
+    type: COUNTER
+    display_name: "Nud failure ignore count"
+    description: "Counting how many times nud failure was ignored."
+    owner_email: "yuyanghuang@google.com"
+    owner_email: "xiaom@google.com"
+    unit: UNIT_COUNT
+}
diff --git a/stats/express/catalog/intents.cfg b/stats/express/catalog/intents.cfg
new file mode 100644
index 00000000..6d11ed92
--- /dev/null
+++ b/stats/express/catalog/intents.cfg
@@ -0,0 +1,27 @@
+express_metric {
+    id: "intents.value_explicit_uri_grant_for_image_capture_action"
+    display_name: "Image Capture action intent with explicit URI grant"
+    description: "Total number of times an intent is launched with image capture action, where activity starter had to explicitly set the URI grant."
+    owner_email: "android-permission-core@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
+express_metric {
+    id: "intents.value_explicit_uri_grant_for_send_multiple_action"
+    display_name: "SEND_MULTIPLE action intent with explicit URI grant"
+    description: "Total number of times an intent is launched with SEND_MULTIPLE action, where activity starter had to explicitly set the URI grant."
+    owner_email: "android-permission-core@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
+express_metric {
+    id: "intents.value_explicit_uri_grant_for_send_action"
+    display_name: "SEND action intent with explicit URI grant"
+    description: "Total number of times an intent is launched with SEND action, where activity starter had to explicitly set the URI grant."
+    owner_email: "android-permission-core@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
diff --git a/stats/express/catalog/media_audio.cfg b/stats/express/catalog/media_audio.cfg
new file mode 100644
index 00000000..62b0b69f
--- /dev/null
+++ b/stats/express/catalog/media_audio.cfg
@@ -0,0 +1,90 @@
+express_metric {
+    id: "media_audio.value_audio_focus_gain_appops_denial"
+    display_name: "Audio Focus GAIN appOps denial"
+    description: "Counter indicating the audio focus GAIN request was denied by appOps"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_appops_denial"
+    display_name: "Audio Focus GAIN_TRANSIENT appOps denial"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT request was denied by appOps"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_duck_appops_denial"
+    display_name: "Audio Focus GAIN_TRANSIENT_MAY_DUCK appOps denial"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT_MAY_DUCK request was denied by appOps"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_excl_appops_denial"
+    display_name: "Audio Focus GAIN_TRANSIENT_EXCLUSIVE appOps denial"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT_EXCLUSIVE request was denied by appOps"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_granted"
+    display_name: "Audio Focus GAIN granted"
+    description: "Counter indicating the audio focus GAIN request was granted"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_granted"
+    display_name: "Audio Focus GAIN_TRANSIENT granted"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT request was granted"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_duck_granted"
+    display_name: "Audio Focus GAIN_TRANSIENT_MAY_DUCK granted"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT_MAY_DUCK request was granted"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id: "media_audio.value_audio_focus_gain_transient_excl_granted"
+    display_name: "Audio Focus GAIN_TRANSIENT_EXCLUSIVE granted"
+    description: "Counter indicating the audio focus GAIN_TRANSIENT_EXCLUSIVE request was granted"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id:"media_audio.value_audio_focus_grant_hardening_waived_by_sdk"
+    display_name: "Audio Focus grant hardening waived"
+    description: "Audio Focus was granted due to older SDK, newer would have been blocked"
+    owner_email: "jmtrivi@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
diff --git a/stats/express/catalog/virtual_devices.cfg b/stats/express/catalog/virtual_devices.cfg
index 032bfb0f..8ba8d5cf 100644
--- a/stats/express/catalog/virtual_devices.cfg
+++ b/stats/express/catalog/virtual_devices.cfg
@@ -70,6 +70,14 @@ express_metric {
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
 }
+express_metric {
+    id: "virtual_devices.value_virtual_rotary_created_count"
+    display_name: "Virtual rotary created count"
+    description: "Number of times a VirtualDevice adds rotary input support."
+    owner_email: "if-vdm@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
 express_metric {
     id: "virtual_devices.value_virtual_camera_created_count"
     display_name: "Virtual camera created count"
diff --git a/stats/express/catalog/wear_notifications.cfg b/stats/express/catalog/wear_notifications.cfg
index f0186288..16b18620 100644
--- a/stats/express/catalog/wear_notifications.cfg
+++ b/stats/express/catalog/wear_notifications.cfg
@@ -15,3 +15,75 @@ express_metric {
         }
     }
 }
+express_metric {
+    id: "wear_notifications.value_local_notification_orphans"
+    type: COUNTER_WITH_UID
+    display_name: "Local notification orphan count"
+    description: "Number of local notification orphans across all watches"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_local_notification_widows"
+    type: COUNTER_WITH_UID
+    display_name: "Local notification widow count"
+    description: "Number of local notification widows across all watches"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_local_notification_orphan_candidates"
+    type: COUNTER_WITH_UID
+    display_name: "Local notification orphan candidate count"
+    description: "Number of local notification potential orphans across all watches"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_local_notification_widow_candidates"
+    type: COUNTER_WITH_UID
+    display_name: "Local notification widow candidate count"
+    description: "Number of local notification potential widows across all watches"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_notification_unhide"
+    type: COUNTER_WITH_UID
+    display_name: "Notification unhidden count"
+    description: "Number of notifications that changed status from hidden to not hidden"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_notification_unhide_from_dismissed"
+    type: COUNTER_WITH_UID
+    display_name: "Notification unhidden from dismissed count"
+    description: "Number of notifications that changed status from hidden (dismissed) to not hidden"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_notification_unhide_from_blocked"
+    type: COUNTER_WITH_UID
+    display_name: "Notification unhidden from blocked count"
+    description: "Number of notifications that changed status from hidden (app blocked) to not hidden"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
+express_metric {
+    id: "wear_notifications.value_notification_unhide_from_filtered"
+    type: COUNTER_WITH_UID
+    display_name: "Notification unhidden from filtered count"
+    description: "Number of notifications that changed status from hidden (filtered) to not hidden"
+    owner_email: "wcs-notification@google.com"
+    owner_email: "bmaulana@google.com"
+    unit: UNIT_COUNT
+}
diff --git a/stats/express/expresscatalogvalidator/Android.bp b/stats/express/expresscatalogvalidator/Android.bp
index fe3f7a17..123eeb46 100644
--- a/stats/express/expresscatalogvalidator/Android.bp
+++ b/stats/express/expresscatalogvalidator/Android.bp
@@ -15,7 +15,7 @@
 //
 
 package {
-    default_team: "trendy_team_android_telemetry_infra",
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
diff --git a/stats/stats_log_api_gen/Android.bp b/stats/stats_log_api_gen/Android.bp
index bea75ce2..146dc481 100644
--- a/stats/stats_log_api_gen/Android.bp
+++ b/stats/stats_log_api_gen/Android.bp
@@ -18,7 +18,7 @@
 // Build the host executable: stats-log-api-gen
 // ==========================================================
 package {
-    default_team: "trendy_team_android_telemetry_infra",
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -130,6 +130,10 @@ cc_test_host {
         ":libstats_internal_protos",
         "test_external.proto",
     ],
+
+    test_options: {
+        unit_test: true,
+    },
 }
 
 // Filegroup for stats-log-api-gen test proto.
diff --git a/stats/stats_log_api_gen/native_writer.cpp b/stats/stats_log_api_gen/native_writer.cpp
index 835b0583..37cace9b 100644
--- a/stats/stats_log_api_gen/native_writer.cpp
+++ b/stats/stats_log_api_gen/native_writer.cpp
@@ -460,7 +460,7 @@ int write_stats_log_cpp(FILE* out, const Atoms& atoms, const AtomDecl& attributi
 int write_stats_log_header(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                            const string& cppNamespace, const int minApiLevel, bool bootstrap) {
     const bool includePull = !atoms.pulledAtomsSignatureInfoMap.empty() && !bootstrap;
-    write_native_header_preamble(out, cppNamespace, includePull);
+    write_native_header_preamble(out, cppNamespace, includePull, bootstrap);
     write_native_atom_constants(out, atoms, attributionDecl);
     write_native_atom_enums(out, atoms);
 
diff --git a/stats/stats_log_api_gen/native_writer_vendor.cpp b/stats/stats_log_api_gen/native_writer_vendor.cpp
index f0fe0d33..ac839355 100644
--- a/stats/stats_log_api_gen/native_writer_vendor.cpp
+++ b/stats/stats_log_api_gen/native_writer_vendor.cpp
@@ -319,7 +319,8 @@ int write_stats_log_cpp_vendor(FILE* out, const Atoms& atoms, const AtomDecl& at
 
 int write_stats_log_header_vendor(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                                   const string& cppNamespace) {
-    write_native_header_preamble(out, cppNamespace, false, /*isVendorAtomLogging=*/true);
+    write_native_header_preamble(out, cppNamespace, /*includePull=*/false, /*bootstrap=*/false,
+                                 /*isVendorAtomLogging=*/true);
     write_native_atom_constants(out, atoms, attributionDecl, "createVendorAtom(",
                                 /*isVendorAtomLogging=*/true);
 
diff --git a/stats/stats_log_api_gen/test_java/Android.bp b/stats/stats_log_api_gen/test_java/Android.bp
index 39f07aef..33de14e7 100644
--- a/stats/stats_log_api_gen/test_java/Android.bp
+++ b/stats/stats_log_api_gen/test_java/Android.bp
@@ -15,7 +15,7 @@
 //
 
 package {
-    default_team: "trendy_team_android_telemetry_infra",
+    default_team: "trendy_team_android_telemetry_client_infra",
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
@@ -34,7 +34,7 @@ android_test {
         "compatibility-device-util-axt",
     ],
     libs: [
-        "android.test.runner",
+        "android.test.runner.stubs.system",
     ],
 }
 
diff --git a/stats/stats_log_api_gen/utils.cpp b/stats/stats_log_api_gen/utils.cpp
index 94efdca3..54c6c667 100644
--- a/stats/stats_log_api_gen/utils.cpp
+++ b/stats/stats_log_api_gen/utils.cpp
@@ -247,6 +247,15 @@ bool is_repeated_field(java_type_t type) {
     }
 }
 
+static bool contains_repeated_field(const vector<java_type_t>& signature) {
+    for (const java_type_t& javaType : signature) {
+        if (is_repeated_field(javaType)) {
+            return true;
+        }
+    }
+    return false;
+}
+
 bool is_primitive_field(java_type_t type) {
     switch (type) {
         case JAVA_TYPE_BOOLEAN:
@@ -402,13 +411,15 @@ void write_native_method_header(FILE* out, const string& methodName,
                                        const AtomDecl& attributionDecl,
                                        bool isVendorAtomLogging) {
     for (const auto& [signature, _] : signatureInfoMap) {
-        write_native_method_signature(out, methodName, signature, attributionDecl, ";",
+        string closer = contains_repeated_field(signature) ?
+                            "\n__INTRODUCED_IN(__ANDROID_API_T__);" : ";";
+        write_native_method_signature(out, methodName, signature, attributionDecl, closer,
                                       isVendorAtomLogging);
     }
 }
 
 void write_native_header_preamble(FILE* out, const string& cppNamespace, bool includePull,
-                                     bool isVendorAtomLogging) {
+                                     bool bootstrap, bool isVendorAtomLogging) {
     // Print prelude
     fprintf(out, "// This file is autogenerated\n");
     fprintf(out, "\n");
@@ -425,7 +436,16 @@ void write_native_header_preamble(FILE* out, const string& cppNamespace, bool in
     if (isVendorAtomLogging) {
         fprintf(out, "#include <aidl/android/frameworks/stats/VendorAtom.h>\n");
     }
-
+    if (!bootstrap && !isVendorAtomLogging) {
+        fprintf(out, "#include <stddef.h>\n");
+        fprintf(out, "\n");
+        fprintf(out, "#ifndef __ANDROID_API_T__\n");
+        fprintf(out, "#define __ANDROID_API_T__ 33\n");
+        fprintf(out, "#endif\n");
+        fprintf(out, "#ifndef __INTRODUCED_IN\n");
+        fprintf(out, "#define __INTRODUCED_IN(api_level)\n");
+        fprintf(out, "#endif\n");
+    }
     fprintf(out, "\n");
 
     write_namespace(out, cppNamespace);
@@ -655,22 +675,6 @@ static bool contains_restricted(const AtomDeclSet& atomDeclSet) {
     return false;
 }
 
-static bool contains_repeated_field(const vector<java_type_t>& signature) {
-    for (const java_type_t& javaType : signature) {
-        switch (javaType) {
-            case JAVA_TYPE_BOOLEAN_ARRAY:
-            case JAVA_TYPE_INT_ARRAY:
-            case JAVA_TYPE_FLOAT_ARRAY:
-            case JAVA_TYPE_LONG_ARRAY:
-            case JAVA_TYPE_STRING_ARRAY:
-                return true;
-            default:
-                break;
-        }
-    }
-    return false;
-}
-
 int get_max_requires_api_level(int minApiLevel, const AtomDeclSet* atomDeclSet,
                                const vector<java_type_t>& signature) {
     if (atomDeclSet != nullptr && contains_restricted(*atomDeclSet)) {
diff --git a/stats/stats_log_api_gen/utils.h b/stats/stats_log_api_gen/utils.h
index 75f61233..1e9ffe47 100644
--- a/stats/stats_log_api_gen/utils.h
+++ b/stats/stats_log_api_gen/utils.h
@@ -97,7 +97,7 @@ void write_native_method_header(FILE* out, const string& methodName,
                                 const AtomDecl& attributionDecl, bool isVendorAtomLogging = false);
 
 void write_native_header_preamble(FILE* out, const string& cppNamespace, bool includePull,
-                                  bool isVendorAtomLogging = false);
+                                  bool bootstrap, bool isVendorAtomLogging = false);
 
 void write_native_header_epilogue(FILE* out, const string& cppNamespace);
 
```

