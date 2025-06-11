```diff
diff --git a/OWNERS b/OWNERS
index bfb14022..7d938eb9 100644
--- a/OWNERS
+++ b/OWNERS
@@ -21,3 +21,5 @@ per-file stats/enums/input/... = file:platform/frameworks/base:/INPUT_OWNERS
 # Health Connect
 per-file stats/enums/healthfitness/ui/enums.proto=mridulagarwal@google.com
 
+# Accessibility
+per-file stats/enums/stats/accessibility/accessibility_enums.proto = danielnorman@google.com, chunkulin@google.com
diff --git a/stats/Android.bp b/stats/Android.bp
index 753f88dd..259f7e09 100644
--- a/stats/Android.bp
+++ b/stats/Android.bp
@@ -30,6 +30,18 @@ shared_enum_protos = [
 ]
 
 enum_protos = [
+    // go/keep-sorted start
+    ":connectivity_service_proto",
+    ":data_stall_event_proto",
+    ":device_policy_proto",
+    ":dns_resolver_proto",
+    ":launcher_proto",
+    ":network_stack_proto",
+    ":srcs_bluetooth_leaudio_protos",
+    ":srcs_bluetooth_protos",
+    ":style_proto",
+    ":tethering_proto",
+    ":text_classifier_proto",
     "enums/accessibility/*.proto",
     "enums/accounts/*.proto",
     "enums/adservices/common/*.proto",
@@ -57,16 +69,19 @@ enum_protos = [
     "enums/input/*.proto",
     "enums/jank/*.proto",
     "enums/media/**/*.proto",
+    "enums/memory/*.proto",
     "enums/mms/*.proto",
     "enums/nearby/*.proto",
     "enums/net/*.proto",
     "enums/neuralnetworks/*.proto",
     "enums/nfc/*.proto",
+    "enums/notification/*.proto",
     "enums/os/*.proto",
+    "enums/pdf/*.proto",
     "enums/performance/*.proto",
     "enums/photopicker/*.proto",
-    "enums/pdf/*.proto",
     "enums/ranging/*.proto",
+    "enums/security/advancedprotection/*.proto",
     "enums/server/*.proto",
     "enums/server/display/*.proto",
     "enums/server/job/*.proto",
@@ -93,6 +108,7 @@ enum_protos = [
     "enums/system/**/*.proto",
     "enums/telecomm/*.proto",
     "enums/telephony/*.proto",
+    "enums/telephony/iwlan/*.proto",
     "enums/telephony/qns/*.proto",
     "enums/telephony/satellite/*.proto",
     "enums/telephony/security/*.proto",
@@ -105,44 +121,50 @@ enum_protos = [
     "enums/wear/setupwizard/*.proto",
     "enums/wear/time/*.proto",
     "enums/wifi/*.proto",
-    "enums/telephony/iwlan/*.proto",
-    ":data_stall_event_proto",
-    ":device_policy_proto",
-    ":dns_resolver_proto",
-    ":launcher_proto",
-    ":network_stack_proto",
-    ":connectivity_service_proto",
-    ":srcs_bluetooth_protos",
-    ":srcs_bluetooth_leaudio_protos",
-    ":style_proto",
-    ":tethering_proto",
-    ":text_classifier_proto",
+    // go/keep-sorted end
 ]
 
 atom_protos = [
+    // go/keep-sorted start
     "atoms.proto",
-    "attribution_node.proto",
     "atoms/accessibility/*.proto",
     "atoms/accounts/*.proto",
+    "atoms/adaptiveauth/*.proto",
     "atoms/adpf/*.proto",
+    "atoms/adservices/*.proto",
     "atoms/agif/*.proto",
-    "atoms/apex/*.proto",
     "atoms/aiwallpapers/*.proto",
-    "atoms/art/*.proto",
+    "atoms/apex/*.proto",
+    "atoms/appfunctions/*.proto",
     "atoms/appsearch/*.proto",
+    "atoms/art/*.proto",
+    "atoms/autofill/*.proto",
+    "atoms/automotive/carlauncher/*.proto",
+    "atoms/automotive/carpower/*.proto",
+    "atoms/automotive/carqclib/*.proto",
+    "atoms/automotive/carsettings/*.proto",
+    "atoms/automotive/carsystemui/*.proto",
+    "atoms/automotive/caruilib/*.proto",
+    "atoms/automotive/sensitiveapplock/*.proto",
     "atoms/backported_fixes/*.proto",
     "atoms/bluetooth/*.proto",
+    "atoms/broadcasts/*.proto",
+    "atoms/camera/*.proto",
     "atoms/conscrypt/**/*.proto",
+    "atoms/coregraphics/*.proto",
     "atoms/corenetworking/**/*.proto",
-    "atoms/autofill/*.proto",
+    "atoms/cpu/*.proto",
     "atoms/credentials/*.proto",
     "atoms/cronet/*.proto",
-    "atoms/conscrypt/*.proto",
+    "atoms/desktopmode/*.proto",
+    "atoms/devicelock/*.proto",
+    "atoms/devicelogs/*.proto",
     "atoms/devicepolicy/*.proto",
     "atoms/display/*.proto",
     "atoms/dnd/*.proto",
     "atoms/dream/*.proto",
     "atoms/expresslog/*.proto",
+    "atoms/federatedcompute/*.proto",
     "atoms/framework/*.proto",
     "atoms/gps/*.proto",
     "atoms/grammaticalinflection/*.proto",
@@ -153,69 +175,57 @@ atom_protos = [
     "atoms/hotword/*.proto",
     "atoms/ike/*.proto",
     "atoms/input/*.proto",
+    "atoms/kernel/*.proto",
     "atoms/locale/*.proto",
-    "atoms/microxr/*.proto",
-    "atoms/wearsysui/*.proto",
     "atoms/location/*.proto",
-    "atoms/view/inputmethod/*.proto",
+    "atoms/media/*.proto",
+    "atoms/memory/*.proto",
+    "atoms/memorysafety/*.proto",
+    "atoms/microxr/*.proto",
     "atoms/nfc/*.proto",
+    "atoms/notification/*.proto",
+    "atoms/ondevicepersonalization/*.proto",
     "atoms/packagemanager/*.proto",
     "atoms/pdf/*.proto",
+    "atoms/performance/*.proto",
     "atoms/permissioncontroller/*.proto",
+    "atoms/photopicker/*.proto",
     "atoms/placeholder/*.proto",
     "atoms/power/*.proto",
+    "atoms/providers/mediaprovider/*.proto",
+    "atoms/ranging/*.proto",
     "atoms/rkpd/*.proto",
+    "atoms/sdksandbox/*.proto",
+    "atoms/selinux/*.proto",
     "atoms/settings/*.proto",
-    "atoms/sysui/*.proto",
-    "atoms/tv/*.proto",
-    "atoms/usb/*.proto",
-    "atoms/providers/mediaprovider/*.proto",
-    "atoms/photopicker/*.proto",
-    "atoms/devicelogs/*.proto",
-    "atoms/kernel/*.proto",
-    "atoms/wearservices/*.proto",
-    "atoms/wear/media/*.proto",
-    "atoms/wear/prototiles/*.proto",
-    "atoms/media/*.proto",
-    "atoms/adservices/*.proto",
-    "atoms/wear/modes/*.proto",
-    "atoms/wear/time/*.proto",
-    "atoms/wear/setupwizard/*.proto",
-    "atoms/wearpas/*.proto",
     "atoms/statsd/*.proto",
+    "atoms/sysui/*.proto",
     "atoms/telecomm/*.proto",
-    "atoms/telephony/qns/*.proto",
     "atoms/telephony/*.proto",
-    "atoms/memorysafety/*.proto",
-    "atoms/wifi/*.proto",
+    "atoms/telephony/iwlan/*.proto",
+    "atoms/telephony/qns/*.proto",
     "atoms/telephony/satellite/*.proto",
     "atoms/telephony/security/*.proto",
-    "atoms/automotive/caruilib/*.proto",
-    "atoms/uwb/*.proto",
-    "atoms/ondevicepersonalization/*.proto",
-    "atoms/federatedcompute/*.proto",
-    "atoms/wear/connectivity/*.proto",
-    "atoms/devicelock/*.proto",
-    "atoms/cpu/*.proto",
-    "atoms/sdksandbox/*.proto",
-    "atoms/selinux/*.proto",
     "atoms/threadnetwork/*.proto",
-    "atoms/automotive/carlauncher/*.proto",
     "atoms/transparency/*.proto",
-    "atoms/desktopmode/*.proto",
-    "atoms/adaptiveauth/*.proto",
-    "atoms/automotive/carpower/*.proto",
-    "atoms/camera/*.proto",
+    "atoms/tv/*.proto",
     "atoms/uprobestats/*.proto",
-    "atoms/broadcasts/*.proto",
-    "atoms/telephony/iwlan/*.proto",
-    "atoms/performance/*.proto",
-    "atoms/coregraphics/*.proto",
-    "atoms/automotive/carsystemui/*.proto",
-    "atoms/automotive/carsettings/*.proto",
-    "atoms/automotive/carqclib/*.proto",
-    "atoms/ranging/*.proto",
-    "atoms/appfunctions/*.proto",
+    "atoms/usb/*.proto",
+    "atoms/uwb/*.proto",
+    "atoms/view/inputmethod/*.proto",
+    "atoms/wear/connectivity/*.proto",
+    "atoms/wear/media/*.proto",
+    "atoms/wear/modes/*.proto",
+    "atoms/wear/prototiles/*.proto",
+    "atoms/wear/setupwizard/*.proto",
+    "atoms/wear/time/*.proto",
+    "atoms/wearpas/*.proto",
+    "atoms/wearservices/*.proto",
+    "atoms/wearsysui/*.proto",
+    "atoms/wifi/*.proto",
+    "atoms/xr/recorder/*.proto",
+    "attribution_node.proto",
+    // go/keep-sorted end
 ]
 
 cc_library_host_shared {
diff --git a/stats/TEST_MAPPING b/stats/TEST_MAPPING
index 468045c7..bd718b7c 100644
--- a/stats/TEST_MAPPING
+++ b/stats/TEST_MAPPING
@@ -4,12 +4,15 @@
       "name": "stats-log-api-gen-test"
     },
     {
-      "name": "VendorAtomCodeGenJavaTest",
+      "name": "StatsCodeGenJavaTest",
       "options": [
         {
           "exclude-annotation": "org.junit.Ignore"
         }
       ]
+    },
+    {
+      "name": "stats_code_gen_cc_test"
     }
   ]
 }
diff --git a/stats/atom_field_options.proto b/stats/atom_field_options.proto
index 2484c4ae..776f3e4f 100644
--- a/stats/atom_field_options.proto
+++ b/stats/atom_field_options.proto
@@ -134,7 +134,7 @@ message HistogramBinOption {
 
     message GeneratedBins {
         enum Strategy {
-            UNKNOWN = 0;
+            STRATEGY_UNKNOWN = 0;
             LINEAR = 1;
             EXPONENTIAL = 2;
         }
diff --git a/stats/atoms.proto b/stats/atoms.proto
index 98dbf52f..d5ccb340 100644
--- a/stats/atoms.proto
+++ b/stats/atoms.proto
@@ -47,10 +47,10 @@ import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 import "frameworks/proto_logging/stats/enums/app_shared/app_op_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/job/job_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/remoteprovisioner_enums.proto";
-import "frameworks/proto_logging/stats/enums/app/settings_enums.proto";
+import "frameworks/proto_logging/stats/enums/app/settings/settings_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/wearservices/wearservices_enums.proto";
 import "frameworks/proto_logging/stats/enums/app/tvsettings_enums.proto";
-import "frameworks/proto_logging/stats/enums/app/wearsettings_enums.proto";
+import "frameworks/proto_logging/stats/enums/app/wearsettings/wearsettings_enums.proto";
 import "frameworks/proto_logging/stats/enums/autofill/enums.proto";
 import "frameworks/proto_logging/stats/enums/bluetooth/a2dp/enums.proto";
 import "frameworks/proto_logging/stats/enums/bluetooth/enums.proto";
@@ -72,6 +72,7 @@ import "frameworks/proto_logging/stats/enums/nearby/enums.proto";
 import "frameworks/proto_logging/stats/enums/net/enums.proto";
 import "frameworks/proto_logging/stats/enums/neuralnetworks/enums.proto";
 import "frameworks/proto_logging/stats/enums/nfc/enums.proto";
+import "frameworks/proto_logging/stats/enums/notification/enums.proto";
 import "frameworks/proto_logging/stats/enums/os/enums.proto";
 import "frameworks/proto_logging/stats/enums/server/connectivity/data_stall_event.proto";
 import "frameworks/proto_logging/stats/enums/server/display/enums.proto";
@@ -226,10 +227,10 @@ message Atom {
                 68 [(module) = "bluetooth"];
         GpsSignalQualityChanged gps_signal_quality_changed = 69 [(module) = "framework"];
         UsbConnectorStateChanged usb_connector_state_changed = 70 [(module) = "framework"];
-        SpeakerImpedanceReported speaker_impedance_reported = 71;
-        HardwareFailed hardware_failed = 72;
-        PhysicalDropDetected physical_drop_detected = 73;
-        ChargeCyclesReported charge_cycles_reported = 74;
+        SpeakerImpedanceReported speaker_impedance_reported = 71 [(module) = "statshidl"];
+        HardwareFailed hardware_failed = 72 [(module) = "statshidl"];
+        PhysicalDropDetected physical_drop_detected = 73 [(module) = "statshidl"];
+        ChargeCyclesReported charge_cycles_reported = 74 [(module) = "statshidl"];
         MobileConnectionStateChanged mobile_connection_state_changed = 75 [(module) = "telephony"];
         MobileRadioTechnologyChanged mobile_radio_technology_changed = 76 [(module) = "telephony"];
         UsbDeviceAttached usb_device_attached = 77 [(module) = "framework"];
@@ -249,9 +250,9 @@ message Atom {
             (module) = "sysui",
             (module) = "mediaprovider"
         ];
-        BatteryHealthSnapshot battery_health_snapshot = 91;
-        SlowIo slow_io = 92;
-        BatteryCausedShutdown battery_caused_shutdown = 93;
+        BatteryHealthSnapshot battery_health_snapshot = 91 [(module) = "statshidl"];
+        SlowIo slow_io = 92 [(module) = "statshidl"];
+        BatteryCausedShutdown battery_caused_shutdown = 93 [(module) = "statshidl"];
         PhoneServiceStateChanged phone_service_state_changed = 94 [(module) = "framework"];
         PhoneStateChanged phone_state_changed = 95 [(module) = "framework"];
         UserRestrictionChanged user_restriction_changed = 96;
@@ -301,7 +302,7 @@ message Atom {
         LowStorageStateChanged low_storage_state_changed = 130 [(module) = "framework"];
         GnssNfwNotificationReported gnss_nfw_notification_reported = 131 [(module) = "framework"];
         GnssConfigurationReported gnss_configuration_reported = 132 [(module) = "framework"];
-        UsbPortOverheatEvent usb_port_overheat_event_reported = 133;
+        UsbPortOverheatEvent usb_port_overheat_event_reported = 133 [(module) = "statshidl"];
         NfcErrorOccurred nfc_error_occurred = 134 [(module) = "nfc"];
         NfcStateChanged nfc_state_changed = 135 [(module) = "nfc"];
         NfcBeamOccurred nfc_beam_occurred = 136 [(module) = "nfc"];
@@ -315,7 +316,7 @@ message Atom {
         AttentionManagerServiceResultReported attention_manager_service_result_reported =
                 143 [(module) = "framework"];
         AdbConnectionChanged adb_connection_changed = 144 [(module) = "framework"];
-        SpeechDspStatReported speech_dsp_stat_reported = 145;
+        SpeechDspStatReported speech_dsp_stat_reported = 145 [(module) = "statshidl"];
         UsbContaminantReported usb_contaminant_reported = 146 [(module) = "framework"];
         WatchdogRollbackOccurred watchdog_rollback_occurred =
                 147 [(module) = "framework", (module) = "crashrecovery", (module) = "statsd"];
@@ -581,7 +582,7 @@ message Atom {
                 316 [(module) = "media_metrics"];
         TlsHandshakeReported tls_handshake_reported = 317 [(module) = "conscrypt"];
         TextClassifierApiUsageReported text_classifier_api_usage_reported = 318  [(module) = "textclassifier"];
-        CarWatchdogKillStatsReported car_watchdog_kill_stats_reported = 319 [(module) = "car"];
+        CarWatchdogKillStatsReported car_watchdog_kill_stats_reported = 319 [(module) = "car", (module) = "framework"];
         MediametricsPlaybackReported mediametrics_playback_reported = 320 [(module) = "media_metrics"];
         MediaNetworkInfoChanged media_network_info_changed = 321 [(module) = "media_metrics"];
         MediaPlaybackStateChanged media_playback_state_changed = 322 [(module) = "media_metrics"];
@@ -1297,7 +1298,7 @@ message Atom {
     extensions 969; // ScheduledCustomAudienceUpdatePerformedAttemptedFailureReported scheduled_custom_audience_update_performed_attempted_failure_reported
     extensions 970; // ScheduledCustomAudienceUpdateBackgroundJobRan scheduled_custom_audience_update_background_job_ran
     extensions 971; // ContextualEducationTriggered contextual_education_triggered
-    extensions 972; // CertificateTransparencyLogListUpdateFailed certificate_transparency_log_list_update_failed
+    extensions 972; // CertificateTransparencyLogListUpdateStateChanged certificate_transparency_log_list_update_state_changed
     extensions 973; // Reserved for b/375457523
     extensions 974; // CarSystemUiDataSubscriptionEventReported car_system_ui_data_subscription_event_reported
     extensions 975; // CarSettingsDataSubscriptionEventReported car_settings_data_subscription_event_reported
@@ -1325,13 +1326,62 @@ message Atom {
     extensions 997; // RangingTechnologyStopped ranging_technology_stopped
     extensions 998; // AppFunctionsRequestReported app_functions_request_reported
     extensions 999; // CameraStatusForCompatibilityChanged camera_status_for_compatibility_changed
+    extensions 1000; // NotificationBundleInteracted notification_bundle_interacted
+    extensions 1001; // SettingsExtApiReported settings_extapi_reported
+    extensions 1002; // PopulationDensityProviderLoadingReported population_density_provider_loading_reported
+    extensions 1003; // DensityBasedCoarseLocationsUsageReported density_based_coarse_locations_usage_reported
+    extensions 1004; // DensityBasedCoarseLocationsProviderQueryReported density_based_coarse_locations_provider_query_reported
+    extensions 1005; // WsNotificationApiUsageReported ws_notification_api_usage_reported
+    extensions 1006; // AdServicesProcessLifecycleReported ad_services_process_lifecycle_reported
+    extensions 1007; // AdServicesProcessStableFlagsReported ad_services_process_stable_flags_reported
+    extensions 1008; // AdServicesFlagUpdateReported ad_services_flag_update_reported
+    extensions 1009; // SqliteDiscreteOpEventReported sqlite_discrete_op_event_reported
+    extensions 1010; // WifiSoftApCallbackOnClientsDisconnected wifi_soft_ap_callback_on_clients_disconnected
+    extensions 1011; // DeviceStateAutoRotateSettingIssueReported device_state_auto_rotate_setting_issue_reported
+    extensions 1012; // WsRemoteInteractionsApiUsageReported ws_remote_interactions_api_usage_reported
+    extensions 1013; // ReportingWithDestinationPerformed reporting_with_destination_performed
+    extensions 1014; // NumberOfTypesOfReportingUrlsReceived number_of_types_of_reporting_url_received
+    extensions 1015; // ZramMaintenanceExecuted zram_maintenance_executed
+    extensions 1016; // ProcessTextActionLaunchedReported process_text_action_launched_reported
+    extensions 1017; // MediaRouterEventReported media_router_event_reported
+    extensions 1018; // SetComponentEnabledSettingReported set_component_enabled_setting_reported
+    extensions 1019; // BalProcessControllerAddBoundClientUidReported bal_process_controller_add_bound_client_uid_reported
+    extensions 1020; // RoleSettingsFragmentActionReported role_settings_fragment_action_reported
+    extensions 1021; // HearingDeviceActiveEventReported hearing_device_active_event_reported
+    extensions 1022; // Reserved for b/377302168
+    extensions 1023; // HealthConnectDataBackupInvoked health_connect_data_backup_invoked
+    extensions 1024; // HealthConnectSettingsBackupInvoked health_connect_settings_backup_invoked
+    extensions 1025; // HealthConnectDataRestoreInvoked health_connect_data_restore_invoked
+    extensions 1026; // HealthConnectSettingsRestoreInvoked health_connect_settings_restore_invoked
+    extensions 1027; // HealthConnectRestoreEligibilityChecked health_connect_restore_eligibility_checked
+    extensions 1028; // BroadcastProcessed broadcast_processed
+    extensions 1029; // ZramSetupExecuted zram_setup_executed
+    extensions 1030; // SensitiveAppLockStateChanged sensitive_app_lock_state_changed
+    extensions 1031; // MobileDataDownloadLatencyReported mobile_data_download_latency_reported
+    extensions 1032; // OtpNotificationDisplayed otp_notification_displayed
+    extensions 1033; // XrRecorderSessionStatusReported xr_recorder_session_status_reported
+    extensions 1034; // EcmRestrictionQueryInCall ecm_restriction_query_in_call
+    extensions 1035; // CallWithEcmInteraction call_with_ecm_restriction
+    extensions 1036; // NfcExitFrameTableChanged nfc_exit_frame_table_changed
+    extensions 1037; // IntentRedirectBlocked intent_redirect_blocked
+    extensions 1038; // NfcAutoTransactReported nfc_auto_transact_reported
+    extensions 1039; // AndroidGraphicsBitmapAllocated android_graphics_bitmap_allocated
+    extensions 1040; // AdvancedProtectionStateChanged advanced_protection_state_changed
+    extensions 1041; // AdvancedProtectionSupportDialogDisplayed advanced_protection_support_dialog_displayed
+    extensions 1042; // ExtraIntentKeysCollectedOnServer extra_intent_keys_collected_on_server
+    extensions 1043; // PhotopickerAppMediaCapabilitiesReported photopicker_app_media_capabilities_reported
+    extensions 1044; // PhotopickerVideoTranscodingDetailsLogged photopicker_video_transcoding_details_logged
+    extensions 1045; // BindServiceLockedWithBalFlagsReported bind_service_locked_with_bal_flags_reported
+    extensions 1046; // AdservicesMeasurementBackgroundJobInfo adservices_measurement_background_job_info
+    extensions 1047; // AppSearchVmPayloadStatsReported app_search_vm_payload_stats_reported
+    extensions 1048; // ClipboardGetEventReported clipboard_get_event_reported
     extensions 9999; // Atom9999 atom_9999
 
-    // StatsdStats tracks platform atoms with ids up to 900.
+    // StatsdStats tracks platform atoms with ids up to 1500.
     // Update StatsdStats::kMaxPushedAtomId when atom ids here approach that value.
 
     // Pulled events will start at field 10000.
-    // Next: 10231
+    // Next: 10237
     oneof pulled {
         WifiBytesTransfer wifi_bytes_transfer = 10000 [(module) = "framework"];
         WifiBytesTransferByFgBg wifi_bytes_transfer_by_fg_bg = 10001 [(module) = "framework"];
@@ -1563,6 +1613,7 @@ message Atom {
     extensions 10193; // WifiModuleInfo wifi_module_info
     extensions 10194; // WifiSettingInfo wifi_setting_info
     extensions 10195; // WifiComplexSettingInfo wifi_complex_setting_info
+    // Deprecated, use proxy_bytes_transfer_by_fg_bg (10200) instead.
     extensions 10196; // SysproxyBluetoothBytesTransfer sysproxy_bluetooth_bytes_transfer
     extensions 10197; // WsStandaloneModeSnapshot ws_standalone_mode_snapshot
     extensions 10198; // WifiConfiguredNetworkInfo wifi_configured_network_info;
@@ -1598,6 +1649,12 @@ message Atom {
     // 10228 is reserved due to removing the old atom
     extensions 10229; // PressureStallInformation pressure_stall_information
     extensions 10230; // FrameworkWakelockInfo framework_wakelock_info
+    extensions 10231; // NotificationBundlePreferences notification_bundle_preferences
+    extensions 10232; // ZramMmStatMmd zram_mm_stat_mmd
+    extensions 10233; // ZramBdStatMmd zram_bd_stat_mmd
+    extensions 10234; // WidgetMemoryStats
+    extensions 10235; // TelecomEventStats telecom_event_stats
+    extensions 10236; // AdvancedProtectionStateInfo advanced_protection_state_info
     extensions 99999; // Atom99999 atom_99999
 
     // DO NOT USE field numbers above 100,000 in AOSP.
@@ -1957,6 +2014,12 @@ message WifiHealthStatReported {
    optional bool is_wifi_predicted_as_usable = 9;
    // Wi-Fi usability state as predicted by the scorer
    optional android.net.wifi.WifiPredictedUsabilityState wifi_predicted_usability_state = 10;
+   // Wi-Fi Tx link speed
+   optional int32 txLinkSpeed = 11;
+   // Wi-Fi Rx link speed
+   optional int32 rxLinkSpeed = 12;
+   // Supported bandwidth in current connection channel
+   optional android.net.wifi.WifiChannelWidth channel_width_mhz = 13;
 }
 
 /**
@@ -2067,6 +2130,12 @@ message WifiConnectionResultReported {
     optional android.net.wifi.TofuConfiguration tofu_configuration = 18;
     // uid of the caller who initiated this connection
     optional int32 connection_uid = 19 [(is_uid) = true];
+    // connection channel frequency
+    optional int32 frequency = 20;
+    // L2 connecting time duration in millis
+    optional int64 l2_connecting_duration_ms = 21;
+    // L3 connecting time duration in millis
+    optional int64 l3_connecting_duration_ms = 22;
 }
 
 /**
@@ -4454,6 +4523,17 @@ message BluetoothSocketConnectionStateChanged {
     // session for the same remote device.
     // Default: 0 if the device's metric id is unknown.
     optional int32 metric_id = 10;
+    // Duration of socket connection in milliseconds
+    // Default 0, only logged when the state changes to SOCKET_CONNECTION_STATE_DISCONNECTED
+    optional int64 connection_duration_ms = 11;
+    // Error code of socket failures
+    // Use SOCKET_ERROR_NONE if no error
+    optional android.bluetooth.SocketErrorEnum error_code = 12;
+    // Whether this is a offload socket
+    // Offload socket utilizes offload stack running on a low-power processor for Bluetooth
+    // communication, while non-offload socket uses the main Bluetooth stack running on the
+    // application processor.
+    optional bool is_hardware_offload = 13;
 }
 
 /**
@@ -6330,6 +6410,10 @@ message NotificationReported {
 
     // Age of the notification in minutes.
     optional int32 age_in_minutes = 29;
+
+    // Whether the notification was promoted and whether it was promotable.
+    optional bool is_promoted_ongoing = 30;
+    optional bool has_promotable_characteristics = 31;
 }
 
 /**
@@ -9309,6 +9393,10 @@ message PackageNotificationPreferences {
     // True if the current full screen intent permission state for this package was set by the user.
     // This is only set when the FSI permission is requested by the app.
     optional bool is_fsi_permission_user_set = 7;
+    // Which types of bundles (groupings by category) are allowed for this package. Bundle types are
+    // a limited set, so this repeated field will never be larger than the total number of bundle
+    // types.
+    repeated android.stats.notification.BundleTypes allowed_bundle_types = 8;
 }
 
 /**
@@ -10755,8 +10843,8 @@ message GnssPsdsDownloadReported {
 /**
  * Logs when a NFC device's error occurred.
  * Logged from:
- *     system/nfc/src/nfc/nfc/nfc_ncif.cc
- *     packages/apps/Nfc/src/com/android/nfc/cardemulation/AidRoutingManager.java
+ *     packages/modules/Nfc/libnfc-nci/src/nfc/nfc/nfc_ncif.cc
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/cardemulation/AidRoutingManager.java
  */
 message NfcErrorOccurred {
     enum Type {
@@ -10779,7 +10867,7 @@ message NfcErrorOccurred {
 /**
  * Logs when a NFC device's state changed event
  * Logged from:
- *     packages/apps/Nfc/src/com/android/nfc/NfcService.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/NfcService.java
  */
 message NfcStateChanged {
     enum State {
@@ -10798,7 +10886,7 @@ message NfcStateChanged {
 /**
  * Logs when a NFC Beam Transaction occurred.
  * Logged from:
- *     packages/apps/Nfc/src/com/android/nfc/P2pLinkManager.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/P2pLinkManager.java
  */
 message NfcBeamOccurred {
     enum Operation {
@@ -10812,8 +10900,8 @@ message NfcBeamOccurred {
 /**
  * Logs when a NFC Card Emulation Transaction occurred.
  * Logged from:
- *     packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java
- *     packages/apps/Nfc/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/cardemulation/HostNfcFEmulationManager.java
  */
 message NfcCardemulationOccurred {
     enum Category {
@@ -10843,7 +10931,7 @@ message NfcCardemulationOccurred {
 /**
  * Logs when a NFC Tag event occurred.
  * Logged from:
- *     packages/apps/Nfc/src/com/android/nfc/NfcDispatcher.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/NfcDispatcher.java
  */
 message NfcTagOccurred {
     enum Type {
@@ -10880,7 +10968,7 @@ message NfcTagOccurred {
 /**
  * Logs NFC tag type when tag occurred
  * Logged from:
- *     packages/apps/Nfc/nci/jni/NfcTag.cpp
+ *     packages/modules/Nfc/NfcNci/nci/jni/NfcTag.cpp
  */
 message NfcTagTypeOccurred {
     optional android.nfc.NfcTagType type = 1;
@@ -10889,7 +10977,7 @@ message NfcTagTypeOccurred {
 /**
  * Logs when Hce transaction triggered
  * Logged from:
- *     system/nfc/src/nfc/nfc/nfc_ncif.cc
+ *     packages/modules/Nfc/libnfc-nci/src/nfc/nfc/nfc_ncif.cc
  */
 message NfcHceTransactionOccurred {
     // The latency period(in microseconds) it took for the first HCE data
@@ -10900,7 +10988,7 @@ message NfcHceTransactionOccurred {
 /**
  * Logs when AID conflict occurred
  * Logged from:
- * packages/apps/Nfc/src/com/android/nfc/cardemulation/HostEmulationManager.java
+ * packages/modules/Nfc/NfcNci/src/com/android/nfc/cardemulation/HostEmulationManager.java
 */
 message NfcAIDConflictOccurred {
     optional string conflicting_aid = 1;
@@ -10909,7 +10997,7 @@ message NfcAIDConflictOccurred {
 /**
  * Logs when reader app conflict occurred
  * Logged from:
- *     packages/apps/Nfc/src/com/android/nfc/NfcDispatcher.java
+ *     packages/modules/Nfc/NfcNci/src/com/android/nfc/NfcDispatcher.java
 */
 message NfcReaderConflictOccurred {
 }
@@ -13496,6 +13584,8 @@ message RebootEscrowRebootReported {
 
 /**
  * Logs stats for AppSearch function calls
+ *
+ * Next tag: 13
  */
 message AppSearchCallStatsReported {
     // The sampling interval for this specific type of stats
@@ -13539,10 +13629,16 @@ message AppSearchCallStatsReported {
 
     // Number of actual API calls reported in this atom.
     optional int32 num_reported_calls = 11;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 12;
 }
 
 /**
  * Logs detailed stats for putting a single document in AppSearch
+ *
+ * Next tag: 17
  */
 message AppSearchPutDocumentStatsReported {
     // The sampling interval for this specific type of stats
@@ -13596,10 +13692,16 @@ message AppSearchPutDocumentStatsReported {
 
     // Whether the max number of tokens exceeded.
     optional bool native_exceeded_max_num_tokens = 15;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 16;
 }
 
 /**
  * Logs detailed stats for AppSearch Initialize
+ *
+ * Next tag: 22
  */
 message AppSearchInitializeStatsReported {
     // The sampling interval for this specific type of stats
@@ -13672,12 +13774,16 @@ message AppSearchInitializeStatsReported {
     // Needs to be sync with AppSearchResult#ResultCode in
     // frameworks/base/apex/appsearch/framework/java/android/app/appsearch/AppSearchResult.java
     optional int32 reset_status_code = 20;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 21;
 }
 
 /**
  * Logs detailed stats for querying in AppSearch
  *
- * Next tag: 34
+ * Next tag: 35
  */
 message AppSearchQueryStatsReported {
     // The sampling interval for this specific type of stats
@@ -13795,10 +13901,16 @@ message AppSearchQueryStatsReported {
 
     //  The Hash of the tag to indicate the query source of this search
     optional int32 query_source_log_tag = 33;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 34;
 }
 
 /**
  * Logs detailed stats for remove in AppSearch
+ *
+ * Next tag: 10
  */
 message AppSearchRemoveStatsReported {
     // The sampling interval for this specific type of stats
@@ -13834,6 +13946,10 @@ message AppSearchRemoveStatsReported {
 
     // Number of documents deleted by this call.
     optional int32 native_num_documents_deleted = 9;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 10;
 }
 
 /**
@@ -13842,7 +13958,7 @@ message AppSearchRemoveStatsReported {
  * stats pushed from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 14
+ * Next tag: 15
  */
 message AppSearchOptimizeStatsReported {
     // The sampling interval for this specific type of stats
@@ -13889,6 +14005,10 @@ message AppSearchOptimizeStatsReported {
 
     // The amount of time in millis since the last optimization ran.
     optional int64 native_time_since_last_optimize_millis = 13;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 14;
 }
 
 // Reports information in external/icing/proto/icing/proto/storage.proto#DocumentStorageInfoProto
@@ -14005,7 +14125,7 @@ message AppSearchIndexStorageInfo {
  * Pulled from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 6
+ * Next tag: 7
  */
 message AppSearchStorageInfo {
     // The associated user (for multi-user feature). Defined in android/os/UserHandle.java
@@ -14028,6 +14148,10 @@ message AppSearchStorageInfo {
     // Storage information of the index.
     optional AppSearchIndexStorageInfo index_storage_info = 5
         [(android.os.statsd.log_mode) = MODE_BYTES];
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 6;
 }
 
 
@@ -15424,6 +15548,11 @@ message ContactsProviderStatusReported {
         ADD_SIM_ACCOUNTS = 1;
         REMOVE_SIM_ACCOUNTS = 2;
         GET_SIM_ACCOUNTS = 3;
+        SET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS = 4;
+        GET_DEFAULT_ACCOUNT_FOR_NEW_CONTACTS = 5;
+        MOVE_LOCAL_CONTACTS_TO_DEFAULT_ACCOUNT = 6;
+        MOVE_SIM_CONTACTS_TO_DEFAULT_ACCOUNT = 7;
+        GET_ELIGIBLE_CLOUD_ACCOUNTS = 8;
     }
 
     enum ResultType {
@@ -15432,6 +15561,9 @@ message ContactsProviderStatusReported {
         FAIL = 2;
         ILLEGAL_ARGUMENT = 3;
         UNSUPPORTED_OPERATION = 4;
+
+        // Operation is targeting an incorrect account.
+        INCORRECT_ACCOUNT = 5;
     }
 
     enum CallerType {
@@ -15538,6 +15670,8 @@ message AppFreezeChanged {
         UFR_EXECUTING_SERVICE = 27;
         UFR_RESTRICTION_CHANGE = 28;
         UFR_COMPONENT_DISABLED = 29;
+        UFR_OOM_ADJ_FOLLOW_UP = 30;
+        UFR_OOM_ADJ_RECONFIGURATION = 31;
     }
 
     optional UnfreezeReason unfreeze_reason_v2 = 6;
@@ -15699,7 +15833,6 @@ message VoiceCallSession {
 
     // The call state on call setup
     optional android.telephony.CallState call_state_on_setup = 45;
-
 }
 
 /**
@@ -15793,7 +15926,13 @@ message CellularServiceState {
 
     // Whether the device is using non-terrestrial networks.
     optional bool is_ntn = 16;
-}
+
+    // Whether the call is over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 17;
+
+    // Whether the subscription is an opportunistic (can change CBRS network when available).
+    optional bool is_opportunistic = 18;
+ }
 
 /**
  * Pulls the number of times cellular data service state switches.
@@ -15824,6 +15963,9 @@ message CellularDataServiceSwitch {
 
     // Number of switches from rat_from to rat_to.
     optional int32 switch_count = 6;
+
+    // // Whether the subscription is an opportunistic (can change CBRS network when available).
+    optional bool is_opportunistic = 7;
 }
 
 /**
@@ -16008,6 +16150,9 @@ message IncomingSms {
 
     // Whether the message is an emergency or not.
     optional bool is_emergency = 18;
+
+    // Whether the message was received over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 19;
 }
 
 /**
@@ -16094,6 +16239,12 @@ message OutgoingSms {
 
     // Whether the message was sent over non-terrestrial networks.
     optional bool is_ntn = 20;
+
+    // Whether the message is an MT SMS polling.
+    optional bool is_mt_sms_polling = 21;
+
+    // Whether the message was sent over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 22;
 }
 
 /**
@@ -16280,6 +16431,9 @@ message DataCallSession {
 
     // Determines if current data call was over provisioning profile or not
     optional bool is_provisioning_profile = 26;
+
+    // Whether the call is over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 27;
 }
 
 /**
@@ -17895,19 +18049,27 @@ message KeystoreKeyEventReported {
 }
 
 /**
- * Logs: key creation events with Algorithm, Origin, Error and Attestation info.
+ * Logs a key creation, with information about the parameters and outcome.
+ *
+ * Note that each key creation results in multiple atoms being emitted due
+ * to the cardinality of the fields related to key creations that we are
+ * interested in collecting. See the messages with names starting with
+ * "Keystore2KeyCreation" for the others.
+ *
  * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2KeyCreationWithGeneralInfo {
-
-    // Algorithm associated with the key
+    // Algorithm associated with the key.
     optional android.system.security.keystore2.Algorithm algorithm = 1;
 
-    // Size of the key, based on the algorithm used.
+    // Size of the key in bits. Set to -1 if algorithm=EC.
     optional int32 key_size = 2;
 
+    // Mirror of
+    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/EcCurve.aidl
+    // except that an unspecified value with enum tag number 0 is added and the
+    // enum tag numbers of all other values are incremented by 1.
     enum EcCurve {
-        // Unspecified takes 0. Other values are incremented by 1 compared to keymint spec.
         EC_CURVE_UNSPECIFIED = 0;
         P_224 = 1;
         P_256 = 2;
@@ -17915,199 +18077,219 @@ message Keystore2KeyCreationWithGeneralInfo {
         P_521 = 4;
         CURVE_25519 = 5;
     };
-    // Which ec curve was selected if elliptic curve cryptography is in use
+    // Elliptic curve (EC) used, if algorithm=EC. Otherwise, this is set to
+    // EC_CURVE_UNSPECIFIED.
     optional EcCurve ec_curve = 3;
 
+    // Mirror of
+    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyOrigin.aidl
+    // except that an unspecified value with enum tag number 0 is added and the
+    // enum tag numbers of all other values are incremented by 1.
     enum KeyOrigin {
-        // Unspecified takes 0. Other values are incremented by 1 compared to keymint spec.
         ORIGIN_UNSPECIFIED = 0;
-        // Generated in keymaster.  Should not exist outside the TEE.
         GENERATED = 1;
-        // Derived inside keymaster.  Likely exists off-device.
         DERIVED = 2;
-        // Imported into keymaster.  Existed as cleartext in Android.
         IMPORTED = 3;
-        // Previously used for another purpose that is now obsolete.
         RESERVED = 4;
-        // Securely imported into Keymaster.
         SECURELY_IMPORTED = 5;
     };
-    // Logs whether the key was generated, imported, securely imported, or derived.
     optional KeyOrigin key_origin = 4;
 
-    /**
-     * Response code (system/hardware/interfaces/keystore2/aidl/../ResponseCode.aidl)
-     * or
-     * error code (hardware/interfaces/security/keymint/aidl/../ErrorCode.aidl)
-     */
+    // Error code if key creation failed:
+    // - Integers >1 indicate an error from Keystore (the error code is the
+    //   enum tag number from
+    //   system/hardware/interfaces/keystore2/aidl/android/system/keystore2/ResponseCode.aidl)
+    // - Integers <=0 indicate an error from KeyMint (the error code is the
+    //   enum tag number from
+    //   hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/ErrorCode.aidl)
+    // If key creation succeeded, this is set to 1.
     optional int32 error_code = 5;
 
-    // Indicates whether key attestation is requested in creation
+    // Indicates whether an attestation challenge was provided.
     optional bool attestation_requested = 6;
 
-    // Count of a particular combination of field values of this atom
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 7;
 }
 
 /**
- * Logs: key creation events with authentication info.
+ * Logs a key creation, with information about the user authentication
+ * constraints on the key's usage and the security level of the KeyMint
+ * instance that created the key.
+ *
+ * Note that each key creation results in multiple atoms being emitted due
+ * to the cardinality of the fields related to key creations that we are
+ * interested in collecting. See the messages with names starting with
+ * "Keystore2KeyCreation" for the others.
+ *
  * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2KeyCreationWithAuthInfo {
-
+    // Mirror of
+    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/HardwareAuthenticatorType.aidl
+    // with some exceptions. See the metrics-specific variant of that AIDL enum in
+    // system/security/keystore2/aidl/android/security/metrics/HardwareAuthenticatorType.aidl for
+    // details.
     enum HardwareAuthenticatorType {
-        // Unspecified takes 0. Other values are incremented by 1 compared to keymint spec.
         AUTH_TYPE_UNSPECIFIED = 0;
         NONE = 1;
         PASSWORD = 2;
         FINGERPRINT = 3;
+        PASSWORD_OR_FINGERPRINT = 4;
         ANY = 5;
+        NO_AUTH_TYPE = 6;
     };
-    /**
-     * What auth types does this key require? If none,
-     * then no auth required.
-     */
+    // How the user must authenticate themself (if at all) in order to use the
+    // key.
     optional HardwareAuthenticatorType user_auth_type = 1;
 
-    /**
-     * If user authentication is required, is the requirement time based? If it
-     * is time based then this field indicates the base 10 logarithm of time out in seconds.
-     * Logarithm is taken in order to reduce the cardinaltiy.
-     */
+    // Base 10 logarithm of the user authentication timeout in seconds, or -1
+    // if no timeout was specified. The logarithm is used to reduce the
+    // cardinality.
+    // The timeout is specified as an integral number of seconds during key
+    // creation, so a value of 0 in this field indicates a timeout in the range
+    // [0, 10), a value of 1 indicates a timeout in the range [10, 100), etc. A
+    // timeout of 0 means that authentication is required each time the key is
+    // used.
     optional int32 log_auth_timeout_seconds = 2;
 
-    // Security level of the Keymint instance which creates the key.
+    // Security level of the KeyMint instance that created the key.
     optional android.system.security.keystore2.SecurityLevelEnum security_level = 3;
 
-    // Count of a particular combination of field values of this atom
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 4;
 }
 
 /**
- * Logs: key creation events with purpose and modes info.
+ * Logs a key creation, with information about the key's algorithm, purpose(s),
+ * mode(s), and digest(s).
+ *
+ * Note that each key creation results in multiple atoms being emitted due
+ * to the cardinality of the fields related to key creations that we are
+ * interested in collecting. See the messages with names starting with
+ * "Keystore2KeyCreation" for the others.
+ *
  * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2KeyCreationWithPurposeAndModesInfo {
-    // Algorithm associated with the key
+    // Algorithm associated with the key.
     optional android.system.security.keystore2.Algorithm algorithm = 1;
 
-	/**
-     * Track which purpose is being used.
-     * Bitmap composition is given by KeyPurposeBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the key purpose(s) specified during key creation.
+    // Bitmap composition is given by the KeyPurposeBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 purpose_bitmap = 2;
 
-    /**
-     * Track which padding mode is being used.
-     * Bitmap composition is given by PaddingModeBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the padding mode(s) specified during key creation.
+    // Bitmap composition is given by the PaddingModeBitPosition enum defined
+    // in system/security/keystore2/src/metrics_store.rs.
     optional int32 padding_mode_bitmap = 3;
 
-    /**
-     * Track which digest is being used.
-     * Bitmap composition is given by DigestBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the digest(s) specified during key creation.
+    // Bitmap composition is given by the DigestBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 digest_bitmap = 4;
 
-    /**
-     * Track which block mode is being used.
-     * Bitmap composition is given by BlockModeBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the block mode(s) specified during key creation.
+    // Bitmap composition is given by the BlockModeBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 block_mode_bitmap = 5;
 
-    // Count of a particular combination of field values of this atom
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 6;
 }
 
 /**
- * Logs the atom id of the atoms associated with key creation/operation events, that have reached
- * the maximum storage limit allocated for different atom objects of that atom,
- * in keystore in-memory store.
+ * Logs when an atom exceeds the maximum size for atoms stored in Keystore2's
+ * in-memory store.
+ *
+ * The Keystore2 atoms are designed such that their expected cardinalities are
+ * within statsd's limits. This atom is used to track cases where atoms stored
+ * in Keystore2's in-memory store have a larger than expected cardinality and
+ * exceed the maximum size per atom (defined by SINGLE_ATOM_STORE_MAX_SIZE in
+ * system/security/keystore2/src/metrics_store.rs). This can happen if many
+ * unexpected combinations of field values are emitted by devices in the field.
  *
- * Size of the storage bucket for each atom is limited considering their expected cardinaltity.
- * This limit may exceed if the dimensions of the atoms take a large number of unexpected
- * combinations. This atom is used to track such cases.
+ * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2AtomWithOverflow {
-
-    // Atom id as defined in atoms.proto
+    // Atom ID as defined in
+    // system/security/keystore2/aidl/android/security/metrics/AtomID.aidl.
     optional int32 atom_id = 1;
 
-    // Count of the objects of this atom type that have overflowed.
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 2;
 }
 
 /**
- * Logs: key operations events with purpose and modes info.
+ * Logs a key operation, with information about the purpose, mode(s), and
+ * digest(s).
+ *
+ * Note that each key operation results in multiple atoms being emitted due
+ * to the cardinality of the fields related to key operations that we are
+ * interested in collecting. See the messages with names starting with
+ * "Keystore2KeyOperation" for the others.
+ *
  * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2KeyOperationWithPurposeAndModesInfo {
-
+    // Mirror of
+    // hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/KeyPurpose.aidl
+    // except that an unspecified value with enum tag number 0 is added and the
+    // enum tag numbers of all other values are incremented by 1.
     enum KeyPurpose {
-        // Unspecified takes 0. Other values are incremented by 1 compared to keymint spec.
         KEY_PURPOSE_UNSPECIFIED = 0;
-
-        // Usable with RSA, 3DES and AES keys.
         ENCRYPT = 1;
-
-        // Usable with RSA, 3DES and AES keys.
         DECRYPT = 2;
-
-        // Usable with RSA, EC and HMAC keys.
         SIGN = 3;
-
-        // Usable with RSA, EC and HMAC keys.
         VERIFY = 4;
-
         // 5 is reserved
-        // Usable with RSA keys.
         WRAP_KEY = 6;
-
-        // Key Agreement, usable with EC keys.
         AGREE_KEY = 7;
-
-        // Usable as an attestation signing key.
         ATTEST_KEY = 8;
     }
-    // Purpose of the key operation
+    // Purpose of the key operation.
     optional KeyPurpose purpose = 1;
 
-    /**
-     * Track which padding mode is being used.
-     * Bitmap composition is given by PaddingModeBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the padding mode(s) specified during the key operation's
+    // lifecycle.
+    // Bitmap composition is given by the PaddingModeBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 padding_mode_bitmap = 2;
 
-    /**
-     * Track which digest is being used.
-     * Bitmap composition is given by DigestBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the digest(s) specified during the key operation's lifecycle.
+    // Bitmap composition is given by the DigestBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 digest_bitmap = 3;
 
-    /**
-     * Track which block mode is being used.
-     * Bitmap composition is given by BlockModeBitPosition enum
-     * defined in system/security/keystore2/metrics.rs.
-     */
+    // Bitmap of the block mode(s) specified during the key operation's
+    // lifecycle.
+    // Bitmap composition is given by the BlockModeBitPosition enum defined in
+    // system/security/keystore2/src/metrics_store.rs.
     optional int32 block_mode_bitmap = 4;
 
-    // Count of a particular combination of field values of this atom
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 5;
 }
 
 /**
- * Logs key operations events with outcome, error_code, security level and whether the key is
- * upgraded during the operation.
+ * Logs a key operation, with information about the outcome, error code,
+ * security level of the KeyMint instance performing the operation, and whether
+ * the key is upgraded during the operation.
+ *
+ * Note that each key operation results in multiple atoms being emitted due
+ * to the cardinality of the fields related to key operations that we are
+ * interested in collecting. See the messages with names starting with
+ * "Keystore2KeyOperation" for the others.
+ *
  * Logged from: system/security/keystore2/metrics.rs
  */
 message Keystore2KeyOperationWithGeneralInfo {
-
     enum Outcome {
         OUTCOME_UNSPECIFIED = 0;
         DROPPED = 1;
@@ -18116,25 +18298,34 @@ message Keystore2KeyOperationWithGeneralInfo {
         PRUNED = 4;
         ERROR = 5;
     }
-    // Outcome of the operation
+    // Outcome of the key operation.
     optional Outcome outcome = 1;
 
-    // Response code or error code in case of error outcome
+    // Error code if key creation failed:
+    // - Integers >1 indicate an error from Keystore (the error code is the
+    //   enum tag number from
+    //   system/hardware/interfaces/keystore2/aidl/android/system/keystore2/ResponseCode.aidl)
+    // - Integers <=0 indicate an error from KeyMint (the error code is the
+    //   enum tag number from
+    //   hardware/interfaces/security/keymint/aidl/android/hardware/security/keymint/ErrorCode.aidl)
+    // If the key operation succeeded, this is set to 1.
     optional int32 error_code = 2;
 
-    // Indicates whether the key was upgraded during the operation
+    // Indicates whether the key was upgraded during the operation.
     optional bool key_upgraded = 3;
 
-    // Security level of the Keymint instance which performs the operation.
+    // Security level of the KeyMint instance which performs the operation.
     optional android.system.security.keystore2.SecurityLevelEnum security_level = 4;
 
-    // Count of a particular combination of field values of this atom
+    // Number of occurrences of a particular combination of all the other
+    // fields in this proto message.
     optional int32 count = 5;
 }
 
 /**
- * Logs: Keystore 2 storage statistics.
- * Logged from: system/security/keystore2
+ * Logs Keystore2 storage statistics.
+ *
+ * Logged from: system/security/keystore2/src/metrics.rs
  */
 message Keystore2StorageStats {
     enum Storage {
@@ -18151,15 +18342,17 @@ message Keystore2StorageStats {
        GRANT = 10;
        AUTH_TOKEN = 11;
        BLOB_METADATA = 12;
-       BLOB_METADATA_BLOB_ENTRY_ID_INDEX =13;
+       BLOB_METADATA_BLOB_ENTRY_ID_INDEX = 13;
        METADATA = 14;
        DATABASE = 15;
        LEGACY_STORAGE = 16;
     }
-    // Type of the storage (database table or legacy storage) of which the size is reported.
+    // Type of storage.
     optional Storage storage_type = 1;
-    // Storage size in bytes
+
+    // Storage size, in bytes.
     optional int64 size = 2;
+
     // Unused space, in bytes. The total storage size may be larger, indicating
     // inefficiencies in the packing of data in the database.
     optional int64 unused_size = 3;
@@ -18836,9 +19029,11 @@ message IsolatedCompilationEnded {
  *
  * Keep in sync with proto file at
  * packages/services/Car/service/src/com/android/car/watchdog/proto/atoms.proto
+ * frameworks/opt/car/services/builtInServices/proto/src/atoms.proto
  *
  * Pushed from:
  *  packages/services/Car/service/src/com/android/car/watchdog/WatchdogPerfHandler.java
+ *  frameworks/opt/car/services/builtInServices/src/com/android/internal/car/CarServiceHelperService.java
  */
 message CarWatchdogKillStatsReported {
     // Linux process uid for the package.
@@ -19429,6 +19624,12 @@ message PackageInstallationSessionReported {
     optional bool is_move_install = 25;
     // Whether this is a staged installation
     optional bool is_staged = 26;
+
+    // Set when this session was configured to automatically install any missing dependencies.
+    optional bool is_install_dependencies_enabled = 27;
+    // Number of dependencies that are missing and are required for this install to be successful.
+    // Provided when is_install_dependencies_enabled is set.
+    optional int32 missing_dependencies_count = 28;
 }
 
 message PackageUninstallationReported {
@@ -21551,6 +21752,8 @@ message UwbSessionClosed {
     optional int32 rx_to_upper_layer_count = 20;
     // Ranging Measurement Type
     optional android.uwb.RangingType ranging_type = 21;
+    // The UID of the process that started the ranging session.
+    optional int32 uid = 22 [(is_uid) = true];
 }
 
 /*
@@ -21573,6 +21776,8 @@ message UwbStartRanging {
     optional bool is_out_of_band = 6;
     // The status code of ranging start.
     optional android.uwb.RangingStatus status = 7;
+    // The UID of the process that started the ranging session.
+    optional int32 uid = 8 [(is_uid) = true];
 }
 
 /*
@@ -21620,6 +21825,8 @@ message UwbRangingMeasurementReceived {
     optional int32 filtered_elevation_degree = 19;
     // The filtered figure of merit of elevation angle measurement.
     optional int32 filtered_elevation_fom = 20;
+    // The UID of the process that started the ranging session.
+    optional int32 uid = 21 [(is_uid) = true];
 }
 
 /*
@@ -21633,6 +21840,8 @@ message UwbFirstRangingReceived {
     optional int32 latency_ms = 2;
     // The ranging latency in 200ms.
     optional int32 latency_200ms = 3;
+    // The UID of the process that started the ranging session.
+    optional int32 uid = 4 [(is_uid) = true];
 }
 
 /*
@@ -22478,7 +22687,7 @@ message MmsSmsDatabaseHelperOnUpgradeFailed {
  * Logged from:
  * frameworks/base/services/autofill/java/com/android/server/autofill/
  *
- * Next ID: 52
+ * Next ID: 55
  */
 message AutofillPresentationEventReported {
   enum PresentationEventResult {
@@ -22718,6 +22927,20 @@ message AutofillPresentationEventReported {
 
   // Count of times notifyViewEntered wasn't done due to pending authentication
   optional int32 notify_view_entered_ignored_auth_count = 51;
+
+  // Following three fields are only logged if improve_fill_dialog is enabled.
+  //
+  // Fill dialog not shown reason.
+  optional android.os.statsd.autofill.FillDialogNotShownReason
+    fill_dialog_not_shown_reason = 52;
+
+  // Timestamp (relative to session start) of when the fill dialog is ready to
+  // show.
+  optional int64 fill_dialog_ready_to_show_ms = 53;
+
+  // Timestamp (relative to session start) of when the IME animation is
+  // finished.
+  optional int64 ime_animation_finish_ms = 54;
 }
 
 // Tells how Autofill dataset was/will-be displayed.
@@ -22751,6 +22974,8 @@ message CdmAssociationAction {
         DEVICE_PROFILE_COMPUTER = 4;
         DEVICE_PROFILE_GLASSES = 5;
         DEVICE_PROFILE_NEARBY_DEVICE_STREAMING = 6;
+        DEVICE_PROFILE_VIRTUAL_DEVICE = 7;
+        DEVICE_PROFILE_WEARABLE_SENSING = 8;
     }
 
     // Action taken on the CDM association been created by companion apps.
@@ -23284,6 +23509,9 @@ message IncomingMms {
 
     // Whether the MMS was received over non-terrestrial networks.
     optional bool is_ntn = 13;
+
+    // Whether the MMS was received over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 14;
 }
 
 /**
@@ -23340,6 +23568,9 @@ message OutgoingMms {
 
     // Whether the MMS was sent over non-terrestrial networks.
     optional bool is_ntn = 14;
+
+    // Whether the MMS was sent over Carrier Roaming NB-Iot NTN network.
+    optional bool is_nb_iot_ntn = 15;
 }
 
 message PrivacySignalNotificationInteraction {
diff --git a/stats/atoms/adpf/adpf_extension_atoms.proto b/stats/atoms/adpf/adpf_extension_atoms.proto
index f3c5ff55..ef9c27c4 100644
--- a/stats/atoms/adpf/adpf_extension_atoms.proto
+++ b/stats/atoms/adpf/adpf_extension_atoms.proto
@@ -21,7 +21,6 @@ package android.os.statsd.adpf;
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atoms/adpf/adpf_atoms.proto";
-import "frameworks/proto_logging/stats/attribution_node.proto";
 import "frameworks/proto_logging/stats/enums/os/enums.proto";
 
 option java_package = "com.android.os.adpf";
diff --git a/stats/atoms/adservices/adservices_extension_atoms.proto b/stats/atoms/adservices/adservices_extension_atoms.proto
index eee08529..86b1a832 100644
--- a/stats/atoms/adservices/adservices_extension_atoms.proto
+++ b/stats/atoms/adservices/adservices_extension_atoms.proto
@@ -225,6 +225,24 @@ extend Atom {
   [(module) = "adservices", (truncate_timestamp) = true];
   optional ScheduledCustomAudienceUpdateBackgroundJobRan scheduled_custom_audience_update_background_job_ran = 970
   [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional AdServicesProcessLifecycleReported ad_services_process_lifecycle_reported = 1006
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional AdServicesProcessStableFlagsReported ad_services_process_stable_flags_reported = 1007
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional AdServicesFlagUpdateReported ad_services_flag_update_reported = 1008
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional ReportingWithDestinationPerformed reporting_with_destination_performed = 1013
+  [(module) = "adservices", (truncate_timestamp) = true];
+  optional NumberOfTypesOfReportingUrlsReceived number_of_types_of_reporting_url_received = 1014
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional MobileDataDownloadLatencyReported mobile_data_download_latency_reported = 1031
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional AdservicesMeasurementBackgroundJobInfo adservices_measurement_background_job_info = 1046
+  [(module) = "adservices", (truncate_timestamp) = true];
 }
 
 /**
@@ -473,7 +491,8 @@ message AdServicesEnrollmentTransactionStats {
   optional int32 datasource_record_count_pre = 6;
   optional int32 datasource_record_count_post = 7;
   optional int32 enrollment_file_latest_build_id = 8;
-  }
+  optional int32 latency_ms = 9;
+}
 
 /**
  * Logs for AdServices Consent Migration after OTA.
@@ -1105,6 +1124,9 @@ message GetAdSelectionDataBuyerInputGenerated {
 
   // Min size of encoded signals payloads
   optional int32 encoded_signals_size_min = 12;
+
+  // Number of custom audiences in this buyer input sending component ads
+  optional int32 num_custom_audiences_with_component_ads = 13;
 }
 
 /*
@@ -1218,6 +1240,9 @@ message PersistAdSelectionResultCalled {
 
     // The type of auction winner
     optional WinnerType winner = 1;
+
+    // Number of component ads in winner
+    optional int32 num_component_ads = 2;
 }
 
 /** Logs for Topics encryption during epoch computation */
@@ -1476,6 +1501,7 @@ message AdServicesMeasurementRegistrations {
   optional bool is_event_level_epsilon_configured = 15;
   optional bool is_trigger_aggregatable_value_filters_configured = 16;
   optional bool is_trigger_filtering_id_configured = 17;
+  optional bool is_trigger_context_id_configured = 18;
 }
 
 
@@ -1953,6 +1979,24 @@ message MobileDataDownloadFileGroupStats {
   // Note: we do not have owner_package since that's already transmitted.
 }
 
+/** Download latency stats logged after download completes. */
+message MobileDataDownloadLatencyReported {
+  // The number of download attempts needed to fully download the file group.
+  optional int32 download_attempt_count = 1;
+
+  // The download latency in milliseconds, which is the time elapsed between
+  // download started and download complete.
+  optional int64 download_latency_ms = 2;
+
+  // The total MDD download latency in milliseconds, which is the time elapsed
+  // between new config received and download complete.
+  // True E2E download latency = Flag propagation latency + MDD total download
+  // latency. Here we are talking about the later.
+  optional int64 total_latency_ms = 3;
+  optional MobileDataDownloadFileGroupStats file_group_stats = 4
+  [(log_mode) = MODE_BYTES];
+}
+
 /**
  * Logs when an AdServices measurement reports are being uploaded.
  */
@@ -1992,6 +2036,7 @@ message AdServicesMeasurementReportsUploaded {
     VERBOSE_DEBUG_TRIGGER_EVENT_ATTRIBUTIONS_PER_SOURCE_DESTINATION_LIMIT = 31;
     VERBOSE_DEBUG_TRIGGER_AGG_ATTRIBUTIONS_PER_SOURCE_DESTINATION_LIMIT = 32;
     VERBOSE_DEBUG_HEADER_ERROR = 33;
+    AGGREGATE_DEBUG_REPORT = 34;
     VERBOSE_DEBUG_UNKNOWN = 9999;
   }
 
@@ -2012,6 +2057,7 @@ message AdServicesMeasurementReportsUploaded {
   optional int32 retry_count = 7;
   optional int32 http_response_code = 8;
   optional bool is_marked_for_deletion = 9;
+  optional bool is_fake_report = 10;
 }
 
 /**
@@ -2239,3 +2285,123 @@ message ScheduledCustomAudienceUpdatePerformedAttemptedFailureReported {
   optional FailureAction failure_action = 2;
 }
 
+/**
+ * Logs for the stats of AdServices process lifecycle.
+ */
+message AdServicesProcessLifecycleReported {
+  // The type of an AdServices process event. It should be used to log the count of different types
+  // of AdServices process events and will be aggregated to imply the frequency of each event.
+  enum EventType {
+    UNKNOWN = 0;
+
+    // The AdServices process restarts.
+    RESTART = 1;
+
+    // The memory level of the AdServices process drops to a certain threshold.
+    LOW_MEMORY_LEVEL = 2;
+  }
+
+  // The type of an AdServices process event.
+  optional EventType event_type = 1;
+}
+
+/**
+ * Logs for the stats for AdServices Process Stable Flags framework.
+ */
+message AdServicesProcessStableFlagsReported {
+  // The latency to initialize flag values in microsecond.
+  optional int64 initialization_latency_us = 1;
+}
+
+/**
+ * Logs for the stats of AdServices flags updates.
+ */
+message AdServicesFlagUpdateReported {
+  // The number of cache missed flags in an event of AdServices flag update.
+  optional int32 num_of_cache_miss_flags = 1;
+}
+
+/**
+ Logs the number of report impression requests for each destination along with its status.
+*/
+message ReportingWithDestinationPerformed {
+  /* Type of reporting api: either report impression or report event */
+  optional android.adservices.service.ReportingType reportingType = 1;
+
+  /* Destination of this Report Impression call. */
+  optional android.adservices.service.ReportingCallDestination destination = 2;
+
+  /* Status of this Report Impression call. */
+  optional android.adservices.service.ReportingCallStatus status = 3;
+}
+
+/**
+Logs the number of different of reporting url returned by B&A
+*/
+message NumberOfTypesOfReportingUrlsReceived {
+  /* Number of top level seller reporting urls. */
+  optional int32 numberOfTopLevelSellerReportingUrl = 1;
+
+  /* Number of buyer reporting urls. */
+  optional int32 numberOfBuyerReportingUrl = 2;
+
+  /* Number of component seller reporting urls. */
+  optional int32 numberOfComponentSellerReportingUrl = 3;
+
+  /* Number of buyer event reporting urls. */
+  optional int32 numberOfBuyerEventReportingUrl = 4;
+
+  /* Number of top level seller event reporting urls. */
+  optional int32 numberOfTopLevelSellerEventReportingUrl = 5;
+
+  /* Number of component event reporting urls. */
+  optional int32 numberOfComponentEventReportingUrl = 6;
+}
+
+/** Logs the number of items processed per type per measurement background job. */
+message MeasurementBackgroundItemsInfo {
+  // Type of the items.
+  optional int32 item_type = 1;
+
+  // Number of items processed per type.
+  optional int32 number_of_items = 2;
+
+  // Timestamp of the oldest item processed per type per job.
+  optional int64 oldest_item_timestamp = 3;
+}
+
+/** Wrapper to log the nested number of items processed per type per measurement background job. */
+message RepeatedMeasurementBackgroundItemsInfo {
+   repeated MeasurementBackgroundItemsInfo items_info = 1;
+}
+
+/**
+ * Logging for Adservice's measurement background jobs information. Provides data for analyzing
+ * measurement background jobs' health and workload.
+ */
+message AdservicesMeasurementBackgroundJobInfo {
+  // A unique identifier for a background job
+  optional int32 job_id = 1;
+
+  // Information about items in the database before processing.
+  optional RepeatedMeasurementBackgroundItemsInfo database_items_before_processing = 2
+  [(log_mode) = MODE_BYTES];
+
+  // Information about items being processed in the background job.
+  // The number of items being processed doesn't always equal to items in the database before
+  // processing because there may be redirects and retries.
+  optional RepeatedMeasurementBackgroundItemsInfo items_processed = 3 [(log_mode) = MODE_BYTES];
+
+  // Time interval from the start to the end of an execution of a background job.
+  // It is on a milli-second basis.
+  optional int32 job_duration = 4;
+
+  // Type of the result code that implies different execution results of Adservices background jobs.
+  optional android.adservices.ExecutionResultCode execution_result_code = 5;
+
+  // The publicly returned reason onStopJob() was called.
+  // This is only applicable when the state is FINISHED, but may be undefined if
+  // JobService.onStopJob() was never called for the job.
+  // The default value is STOP_REASON_UNDEFINED.
+  optional android.app.job.StopReasonEnum public_stop_reason = 6;
+}
diff --git a/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto b/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
index 18432738..62501466 100644
--- a/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
+++ b/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
@@ -4,7 +4,6 @@ package android.os.statsd.aiwallpapers;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/attribution_node.proto";
 
 option java_package = "com.android.os.aiwallpapers";
 option java_multiple_files = true;
diff --git a/stats/atoms/appfunctions/app_functions_extension_atoms.proto b/stats/atoms/appfunctions/app_functions_extension_atoms.proto
index 7f6cccb7..bb97e4c4 100644
--- a/stats/atoms/appfunctions/app_functions_extension_atoms.proto
+++ b/stats/atoms/appfunctions/app_functions_extension_atoms.proto
@@ -40,6 +40,8 @@ message AppFunctionsRequestReported {
   optional int32 request_size_bytes = 4;
   // The size of the response in bytes.
   optional int32 response_size_bytes = 5;
-  // The duration of the request in milliseconds.
+  // The e2e latency of the request in milliseconds.
   optional int64 request_duration_ms = 6;
+  // The overhead duration of the request in milliseconds.
+  optional int64 request_overhead_ms = 7;
 }
diff --git a/stats/atoms/appsearch/appsearch_extension_atoms.proto b/stats/atoms/appsearch/appsearch_extension_atoms.proto
index 67101d5e..f3d11c92 100644
--- a/stats/atoms/appsearch/appsearch_extension_atoms.proto
+++ b/stats/atoms/appsearch/appsearch_extension_atoms.proto
@@ -40,6 +40,16 @@ extend Atom {
 
   optional AppSearchAppsIndexerStatsReported
           app_search_apps_indexer_stats_reported = 909 [(module) = "appsearch"];
+
+  optional AppSearchVmPayloadStatsReported
+          app_search_vm_payload_stats_reported = 1047 [(module) = "appsearch"];
+}
+
+// Keep in sync with
+// packages/modules/AppSearch/framework/java/external/android/app/appsearch/stats/BaseStats.java
+enum AppSearchEnabledFeatures {
+    APP_SEARCH_ENABLED_UNKNOWN = 0;
+    APP_SEARCH_ENABLED_LAUNCH_VM = 0x0001; // 1 << 0
 }
 
 /**
@@ -48,7 +58,7 @@ extend Atom {
  * stats pushed from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 26
+ * Next tag: 27
  */
 message AppSearchSetSchemaStatsReported {
     // The sampling interval for this specific type of stats
@@ -133,6 +143,10 @@ message AppSearchSetSchemaStatsReported {
     // This is in sync with
     // packages/modules/AppSearch/service/java/com/android/server/appsearch/external/localstorage/stats/SetSchemaStats.java
     optional int32 schema_migration_call_type = 25;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 26;
 }
 
 /**
@@ -141,7 +155,7 @@ message AppSearchSetSchemaStatsReported {
  * stats pushed from:
  *   packages/modules/AppSearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 15
+ * Next tag: 16
  */
 message AppSearchSchemaMigrationStatsReported {
     // The sampling interval for this specific type of stats
@@ -191,6 +205,10 @@ message AppSearchSchemaMigrationStatsReported {
 
     // Number of migration failure during schema migration
     optional int32 schema_migration_failure_count = 14;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 15;
 }
 
 /**
@@ -199,7 +217,7 @@ message AppSearchSchemaMigrationStatsReported {
  * stats pushed from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 10
+ * Next tag: 11
  */
 message AppSearchUsageSearchIntentStatsReported {
     // Package UID of the application.
@@ -226,6 +244,10 @@ message AppSearchUsageSearchIntentStatsReported {
     repeated int64 clicks_time_stay_on_result_millis = 7;
     repeated int32 clicks_result_rank_in_block = 8;
     repeated int32 clicks_result_rank_global = 9;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 10;
 }
 
 /**
@@ -235,7 +257,7 @@ message AppSearchUsageSearchIntentStatsReported {
  * stats pushed from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 9
+ * Next tag: 10
  */
 message AppSearchUsageSearchIntentRawQueryStatsReported {
     // Package name of the application.
@@ -263,6 +285,10 @@ message AppSearchUsageSearchIntentRawQueryStatsReported {
     // The correction type of the query in this search intent compared with the previous search
     // intent.
     optional android.appsearch.QueryCorrectionType query_correction_type = 8;
+
+    // The bitmask for all enabled features on this device. Must be one or a combination of the
+    // types AppSearchEnabledFeatures.
+    optional int64 enabled_features = 9;
 }
 
 /**
@@ -273,7 +299,7 @@ message AppSearchUsageSearchIntentRawQueryStatsReported {
  * Estimated Logging Rate:
  *    Peak: 20 times in 10*1000 ms | Avg: 1 per device per day
  *
- * Next tag: 14
+ * Next tag: 19
  */
 message AppSearchAppsIndexerStatsReported {
   enum UpdateType {
@@ -314,3 +340,46 @@ message AppSearchAppsIndexerStatsReported {
   // App Function removal latency
   optional int64 remove_functions_from_appsearch_appsearch_latency_millis = 18;
 }
+
+/**
+ * Reported when AppSearch VM payload statistics are collected and reported.
+ *
+ * This message encapsulates various metrics related to the execution and outcome of
+ * a pVM payload.
+ *
+ * Next tag: 7
+ */
+message AppSearchVmPayloadStatsReported {
+
+  // The sampling interval for this specific type of stats
+  // For example, sampling_interval=10 means that one out of every 10 stats was logged.
+  optional int32 sampling_interval = 1;
+
+  // # of previous skipped sample for this specific type of stats
+  // We can't push atoms too closely, so some samples might be skipped
+  // In order to extrapolate the counts, we need to save the number of skipped stats and add it back
+  // For example, the true count of an event could be estimated as:
+  //   SUM(sampling_interval * (num_skipped_sample + 1)) as est_count
+  optional int32 num_skipped_sample = 2;
+
+  /**  The type of VMCallback that triggered this report.  */
+  optional int32 callback_type = 3;
+
+  /**
+   * The exit code of the AppSearch {@code IsolateStorageService.VMCallback#onPayloadFinished()}
+   * call.
+   */
+  optional int32 exit_code = 4;
+
+  /**
+   * The error code associated with the AppSearch {@code IsolateStorageService.VMCallback.onError()}
+   * call.
+   */
+  optional int32 error_code = 5;
+
+  /**
+   * The reason for stopping the AppSearch {@code IsolateStorageService.VMCallback.onStopped()}
+   * call.
+   */
+  optional int32 stop_reason = 6;
+}
diff --git a/stats/atoms/automotive/sensitiveapplock/sensitiveapplock_extension_atoms.proto b/stats/atoms/automotive/sensitiveapplock/sensitiveapplock_extension_atoms.proto
new file mode 100644
index 00000000..171cd51c
--- /dev/null
+++ b/stats/atoms/automotive/sensitiveapplock/sensitiveapplock_extension_atoms.proto
@@ -0,0 +1,40 @@
+/*
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
+syntax = "proto2";
+
+package android.os.statsd.automotive.sensitiveapplock;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.automotive.sensitiveapplock";
+option java_multiple_files = true;
+
+extend Atom {
+  optional SensitiveAppLockStateChanged sensitive_app_lock_state_changed = 1030 [(module) = "sensitiveapplock"];
+}
+
+/**
+ * Logs when the user enables or disables app locking for an app.
+ */
+message SensitiveAppLockStateChanged {
+  // True if the user has enabled app locking.
+  optional bool app_lock_enabled = 1;
+  // List of package uids that have app lock enabled.
+  repeated int32 packages_uid = 2 [(is_uid) = true];
+  // True if the user has profile lock enabled.
+  optional bool profile_lock_enabled = 3;
+}
diff --git a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
index 139e40b8..3684a452 100644
--- a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
+++ b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
@@ -74,6 +74,8 @@ extend Atom {
         = 982 [(module) = "bluetooth"];
     optional BluetoothLeConnection bluetooth_le_connection
         = 988 [(module) = "bluetooth"];
+    optional HearingDeviceActiveEventReported hearing_device_active_event_reported
+        = 1021 [(module) = "bluetooth"];
 }
 
 /**
@@ -389,6 +391,13 @@ message LeAppScanStateChanged {
   optional bool is_screen_on = 11;
   // Whether the app is dead when the scan started or stopped.
   optional bool is_app_dead = 12;
+  // App importance compared to foreground service when the scan started or stopped.
+  optional android.bluetooth.le.AppImportance app_importance = 13;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 14;
+
 }
 
 /**
@@ -413,6 +422,13 @@ message LeRadioScanStopped {
   optional bool is_screen_on = 6;
   // Delta time of radio scan start and stop in milliseconds.
   optional int64 scan_duration_ms = 7;
+  // Importance of app with most aggressive scanning parameters compared to foreground service when
+  // the radio scan started.
+  optional android.bluetooth.le.AppImportance app_importance = 8;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 9;
 }
 
 /**
@@ -430,6 +446,10 @@ message LeScanResultReceived {
   // True for STATE_ON, false for any other state as defined in
   // android.view.Display.
   optional bool is_screen_on = 4;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 5;
 }
 
 
@@ -451,6 +471,10 @@ message LeScanAbused{
   // getTotalNumOfTrackableAdvertisements() in AdapterService.java for
   // REASON_TRACKING_HW_FILTER_NOT_AVAILABLE.
   optional int64 le_scan_abuse_reason_details = 4;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 5;
 }
 
 /**
@@ -481,6 +505,12 @@ message LeAdvStateChanged {
   // Adv duration when adv stops (adv stop timestamp - adv start timestamp),
   // in milliseconds. Use 0 for adv start.
   optional int64 adv_duration_ms = 10;
+  // App importance compared to foreground service when the advertisement started or stopped.
+  optional android.bluetooth.le.AppImportance app_importance = 11;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 12;
 }
 
 /**
@@ -495,6 +525,10 @@ message LeAdvErrorReported {
   optional android.bluetooth.le.LeAdvOpCode le_adv_op_code = 2;
   // The status code of internal state.
   optional android.bluetooth.le.LeAdvStatusCode status_code = 3;
+  // The Attribution tag to identify the last caller in the attribution chain, which could be
+  // missing in attribution_node due to incomplete attribution in the Worksource.
+  // Missing tag leads to incomplete attribution data.
+  optional string attribution_tag = 4;
 }
 
 /**
@@ -642,12 +676,52 @@ message BluetoothRfcommConnectionReportedAtClose {
   optional android.bluetooth.rfcomm.PortResult close_reason = 1;
   // security level of the connection
   optional android.bluetooth.rfcomm.SocketConnectionSecurity security = 2;
-  // two states prior to "CLOSED"
-  optional android.bluetooth.rfcomm.RfcommPortState second_previous_state = 3;
+  // last event processed by port state machine
+  optional android.bluetooth.rfcomm.RfcommPortEvent last_event = 3;
   // state prior to "CLOSED"
   optional android.bluetooth.rfcomm.RfcommPortState previous_state = 4;
   // duration that the socket was opened, 0 if connection failed
   optional int32 open_duration_ms = 5;
   // uid of the app that called connect
   optional int32 uid = 6 [(is_uid) = true];
+  // locally generated id for event matching
+  optional int32 metric_id = 7;
+  // sdp status, UNKNOWN if irrelevant
+  optional android.bluetooth.BtaStatus sdp_status = 8;
+  // true if device initiated connection as server, false otherwise
+  optional bool is_server = 9;
+  // true if device initiated SDP service discovery
+  optional bool sdp_initiated = 10;
+  // time in milliseconds between start and end of SDP, 0 if no SDP
+  optional int32 sdp_duration_ms = 11;
+}
+
+/**
+  * Logs hearing devices active event when profiles connected.
+  *
+  * Logged from:
+  *     packages/modules/Bluetooth
+  *
+  * Estimated Logging Rate:
+  *     Peak: 3 times in 1 day | Avg: 1 per device per day
+*/
+message HearingDeviceActiveEventReported {
+  enum DeviceType {
+    UNKNOWN_TYPE = 0;
+    CLASSIC = 1;
+    ASHA = 2;
+    LE_AUDIO = 3;
+  }
+  enum TimePeriod {
+    UNKNOWN_TIME_PERIOD = 0;
+    DAY = 1;
+    WEEK = 2;
+    MONTH = 3;
+  }
+  // The type of the hearing device
+  optional DeviceType device_type = 1;
+  // The time period of the active event
+  optional TimePeriod time_period = 2;
+  // Remote Device Information
+  optional BluetoothRemoteDeviceInformation remote_device_information = 3 [(log_mode) = MODE_BYTES];
 }
diff --git a/stats/atoms/broadcasts/broadcasts_extension_atoms.proto b/stats/atoms/broadcasts/broadcasts_extension_atoms.proto
index fc624fae..ac5aed0f 100644
--- a/stats/atoms/broadcasts/broadcasts_extension_atoms.proto
+++ b/stats/atoms/broadcasts/broadcasts_extension_atoms.proto
@@ -27,6 +27,7 @@ option java_multiple_files = true;
 
 extend Atom {
   optional BroadcastSent broadcast_sent = 922 [(module) = "framework"];
+  optional BroadcastProcessed broadcast_processed = 1028 [(module) = "framework"];
 }
 
 /**
@@ -76,4 +77,32 @@ message BroadcastSent {
     optional android.app.ProcessStateEnum sender_uid_state = 12;
     // Type of broadcast
     repeated android.app.BroadcastType broadcast_types = 13;
-}
\ No newline at end of file
+}
+
+/**
+ * Logged when a process completely finishes processing of a broadcast.
+ *
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/am/BroadcastQueueImpl.java
+ *
+ * Logging frequency (based on the existing metrics):
+ * Avg frequency per device: 30K per day.
+ */
+message BroadcastProcessed {
+    // The action of the broadcast intent.
+    optional string intent_action = 1;
+    // The uid of the broadcast sender.
+    optional int32 sender_uid = 2 [(is_uid) = true];
+    // The uid of the broadcast receiver.
+    optional int32 receiver_uid = 3 [(is_uid) = true];
+    // Total number of receivers for this intent_action inside a process.
+    optional int32 num_receivers = 4;
+    // The name of the process receiving this broadcast.
+    optional string receiver_process_name = 5;
+    // Time taken by all the receivers to process this broadcast.
+    optional int64 total_time_millis = 6;
+    // Maximum time taken by a receiver to process this broadcast.
+    optional int64 max_time_millis = 7;
+    // Type of broadcast.
+    repeated android.app.BroadcastType broadcast_types = 8;
+}
diff --git a/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto b/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto
index 4ea66ee0..239f3d70 100644
--- a/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto
+++ b/stats/atoms/corenetworking/certificatetransparency/certificate_transparency_extension_atoms.proto
@@ -2,46 +2,20 @@ syntax = "proto2";
 
 package android.os.statsd.corenetworking.certificatetransparency;
 
-import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/corenetworking/certificatetransparency/enums.proto";
 
 option java_package = "com.android.os.corenetworking.certificatetransparency";
 
 extend Atom {
-    optional CertificateTransparencyLogListUpdateFailed certificate_transparency_log_list_update_failed = 972 [(module) = "certificate_transparency"];
-}
-
-enum LogListUpdateStatus {
-    STATUS_UNKNOWN = 0;
-    // Log list was successfully updated.
-    SUCCESS = 1;
-    // Log list failed to update for unknown reasons.
-    FAILURE_UNKNOWN = 2;
-    // Device has been offline, preventing the log list file from being updated.
-    FAILURE_DEVICE_OFFLINE = 3;
-    // Device experienced an issue at the HTTP level and/or received an unhandled
-    // HTTP code.
-    FAILURE_HTTP_ERROR = 4;
-    // Device experienced too many redirects when accessing the log list domain.
-    FAILURE_TOO_MANY_REDIRECTS = 5;
-    // A transient error occurred that prevents the download from resuming.
-    FAILURE_DOWNLOAD_CANNOT_RESUME = 6;
-    // Log list domain is blocked by the device's network configuration.
-    FAILURE_DOMAIN_BLOCKED = 7;
-    // Device does not have enough disk space to store the log list file.
-    // Extremely unlikely to occur, and might not be able to reliably log this.
-    FAILURE_NO_DISK_SPACE = 8;
-    // Public key is missing for signature verification.
-    FAILURE_SIGNATURE_NOT_FOUND = 9;
-    // Log list signature verification failed.
-    FAILURE_SIGNATURE_VERIFICATION = 10;
-    // Device is waiting for a Wi-Fi connection to proceed with the download, as it
-    // exceeds the size limit for downloads over the mobile network.
-    PENDING_WAITING_FOR_WIFI = 11;
+  optional CertificateTransparencyLogListUpdateStateChanged
+      certificate_transparency_log_list_update_state_changed = 972
+      [(module) = "certificate_transparency"];
 }
 
 /*
- * Pushed atom on why the log list failed to update.
+ * Pushed atom on when a log list update is attempted.
  *
  * Logged from:
  * packages/modules/Connectivity/networksecurity/service/src/com/android/server/net/ct/CertificateTransparencyDownloader.java
@@ -49,10 +23,19 @@ enum LogListUpdateStatus {
  * Estimated Logging Rate:
  * 1-2 times per device per day
  */
-message CertificateTransparencyLogListUpdateFailed {
-  // The reason why the log list failed to update.
-  optional LogListUpdateStatus failure_reason = 1;
+message CertificateTransparencyLogListUpdateStateChanged {
+  // The status of the log list update (e.g. success, failure, etc.).
+  optional LogListUpdateStatus update_status = 1;
 
   // The number of failures since the last successful log list update.
   optional int32 failure_count = 2;
-}
\ No newline at end of file
+
+  // The HTTP error status code received from the server, if applicable.
+  optional int32 http_error_status_code = 3;
+
+  // The signature of the log list.
+  optional string signature = 4;
+
+  // Timestamp included in the parsed log list.
+  optional int64 log_list_timestamp_ms = 5;
+}
diff --git a/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto b/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto
index ecfe08f1..a08dfef2 100644
--- a/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto
+++ b/stats/atoms/corenetworking/connectivity/terrible_error_extension_atoms.proto
@@ -27,7 +27,8 @@ option java_multiple_files = true;
 
 extend Atom {
     optional CoreNetworkingTerribleErrorOccurred core_networking_terrible_error_occurred =
-        979 [(module) = "connectivity", (module) = "network_stack", (module) = "resolv"];
+        979 [(module) = "connectivity", (module) = "network_stack",
+            (module) = "resolv", (module) = "network_tethering"];
 }
 
 /**
diff --git a/stats/atoms/credentials/credentials_extension_atoms.proto b/stats/atoms/credentials/credentials_extension_atoms.proto
index 977a6844..5fe4dde9 100644
--- a/stats/atoms/credentials/credentials_extension_atoms.proto
+++ b/stats/atoms/credentials/credentials_extension_atoms.proto
@@ -84,6 +84,7 @@ enum ApiStatus {
     API_STATUS_FAILURE = 2;
     API_STATUS_USER_CANCELED = 3;
     API_STATUS_CLIENT_CANCELED = 4;
+    API_STATUS_BINDER_DIED = 5;
 }
 
 // The atoms below are a part of 'track 1', and have the same session id
@@ -116,6 +117,8 @@ message CredentialManagerInitialPhaseReported {
     optional int32 autofill_session_id = 10;
     // The autofill session's request id
     optional int32 autofill_request_id = 11;
+    // Indicates if this API call used the prepare flow
+    optional bool api_used_prepare_flow = 12;
 }
 
 /**
@@ -254,6 +257,9 @@ message CredentialManagerFinalNoUidReported {
     // Status of attempting to use config_oemCredentialManagerDialogComponent to fulfill the
     // request.
     optional OemUiUsageStatus oem_ui_usage_status = 22;
+    // Indicates the chosen classtype of the final tapped credential or create
+    // entry
+    optional string chosen_classtype = 23;
 }
 
 // The atoms below are a part of 'track 2', and have the same session id, separate
@@ -308,6 +314,8 @@ message CredentialManagerCandidatePhaseReported {
     optional ApiName api_name = 19;
     // Indicates for all returned candidates if that candidate was primary
     repeated bool primary_candidates_indicated = 20;
+    // Indicates if this API call used the prepare flow
+    optional bool api_used_prepare_flow = 21;
 }
 
 /**
@@ -424,6 +432,9 @@ message CredentialManagerFinalPhaseReported {
     optional string framework_exception_unique_classtype = 25;
     // Indicates if the chosen provider was a primary provider
     optional bool primary_indicated = 26;
+    // Indicates the chosen classtype of the final tapped credential or create
+    // entry
+    optional string chosen_classtype = 27;
 }
 
 // The atoms below are a part of 'track 3', and have no session id
diff --git a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
index 612aa57e..94c5c179 100644
--- a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
+++ b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
@@ -64,6 +64,7 @@ message DesktopModeUIChanged {
     TASK_FINISHED = 5; // the task finished or dismissed
     SCREEN_OFF = 6;
     TASK_MINIMIZED = 7; // the task gets minimized
+    TASK_MOVED_TO_BACK = 8; // The task moved to back due to back gesture or button.
   }
 
   optional Event event = 1;
@@ -97,6 +98,7 @@ message DesktopModeSessionTaskUpdate {
     UNSET_MINIMIZE = 0;
     MINIMIZE_TASK_LIMIT = 1;
     MINIMIZE_BUTTON = 2;
+    MINIMIZE_KEY_GESTURE = 3;
   }
 
   // The reason a task was unminimized
@@ -108,6 +110,16 @@ message DesktopModeSessionTaskUpdate {
     UNMINIMIZE_TASKBAR_TAP = 2;
     UNMINIMIZE_ALT_TAB = 3;
     UNMINIMIZE_TASK_LAUNCH = 4;
+    UNMINIMIZE_APP_HANDLE_MENU_BUTTON = 5;
+    UNMINIMIZE_TASKBAR_MANAGE_WINDOW = 6;
+  }
+
+  // The reason a task was focused
+  enum FocusReason {
+    // Unset means there is no focus reason (the task did not get focused)
+    UNSET_FOCUS = 0;
+    // Unknown means we don't know what caused the focus change
+    FOCUS_UNKNOWN = 1;
   }
 
   // The event associated with this app update
@@ -135,6 +147,8 @@ message DesktopModeSessionTaskUpdate {
     (state_field_option).exclusive_state = true,
     (state_field_option).nested = false
   ];
+  // The reason this task was focused
+  optional FocusReason focus_reason = 12;
 }
 
 /**
diff --git a/stats/atoms/dream/dream_extension_atoms.proto b/stats/atoms/dream/dream_extension_atoms.proto
index a1b7bc01..dcbb631a 100644
--- a/stats/atoms/dream/dream_extension_atoms.proto
+++ b/stats/atoms/dream/dream_extension_atoms.proto
@@ -82,6 +82,9 @@ enum WhenToDream{
 
     // Dream when device is charging or docked.
     WHEN_TO_DREAM_EITHER_CHARGING_OR_DOCKED = 3;
+
+    // Dream when device is stationary and upright.
+    WHEN_TO_DREAM_WHILE_POSTURED_ONLY = 4;
 }
 
 // Type of dream setting.
diff --git a/stats/atoms/federatedcompute/OWNERS b/stats/atoms/federatedcompute/OWNERS
new file mode 100644
index 00000000..6de30c03
--- /dev/null
+++ b/stats/atoms/federatedcompute/OWNERS
@@ -0,0 +1,5 @@
+fumengyao@google.com
+karthikmahesh@google.com
+lmohanan@google.com
+qiaoli@google.com
+yanning@google.com
\ No newline at end of file
diff --git a/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto b/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
index 71cfb627..c59fba7b 100644
--- a/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
+++ b/stats/atoms/federatedcompute/federatedcompute_extension_atoms.proto
@@ -48,6 +48,7 @@ message FederatedComputeApiCalled {
         API_NAME_UNKNOWN = 0;
         SCHEDULE = 1;
         CANCEL = 2;
+        IS_FEATURE_ENABLED = 3;
     }
 
     optional FederatedComputeApiClassType api_class = 1;
diff --git a/stats/atoms/framework/framework_extension_atoms.proto b/stats/atoms/framework/framework_extension_atoms.proto
index 307dfc66..9e45981a 100644
--- a/stats/atoms/framework/framework_extension_atoms.proto
+++ b/stats/atoms/framework/framework_extension_atoms.proto
@@ -25,6 +25,7 @@ import "frameworks/proto_logging/stats/enums/app_shared/app_enums.proto";
 import "frameworks/proto_logging/stats/enums/app_shared/app_op_enums.proto";
 import "frameworks/proto_logging/stats/enums/framework/compat/enums.proto";
 import "frameworks/proto_logging/stats/enums/os/enums.proto";
+import "frameworks/proto_logging/stats/enums/security/advancedprotection/enums.proto";
 
 option java_package = "com.android.os.framework";
 
@@ -63,6 +64,19 @@ extend Atom {
     optional IntentCreatorTokenAdded intent_creator_token_added = 978 [(module)="framework"];
     optional NotificationChannelClassification notification_channel_classification = 983 [(module) = "framework"];
     optional CameraStatusForCompatibilityChanged camera_status_for_compatibility_changed = 999 [(module) = "framework"];
+    optional NotificationBundleInteracted notification_bundle_interacted = 1000 [(module) = "framework"];
+    optional SqliteDiscreteOpEventReported sqlite_discrete_op_event_reported = 1009 [(module) = "framework"];
+    optional DeviceStateAutoRotateSettingIssueReported device_state_auto_rotate_setting_issue_reported = 1011 [(module) = "framework"];
+    optional ProcessTextActionLaunchedReported process_text_action_launched_reported = 1016 [(module) = "framework"];
+    optional IntentRedirectBlocked intent_redirect_blocked = 1037 [(module) = "framework"];
+    optional AndroidGraphicsBitmapAllocated android_graphics_bitmap_allocated =
+            1039 [(module) = "framework"];
+    optional WidgetMemoryStats widget_memory_stats = 10234 [(module) = "framework"];
+    optional AdvancedProtectionStateChanged advanced_protection_state_changed = 1040 [(module) = "framework"];
+    optional AdvancedProtectionSupportDialogDisplayed advanced_protection_support_dialog_displayed = 1041 [(module) = "framework"];
+    optional ExtraIntentKeysCollectedOnServer extra_intent_keys_collected_on_server = 1042 [(module) = "framework"];
+    optional ClipboardGetEventReported clipboard_get_event_reported = 1048 [(module) = "framework"];
+    optional AdvancedProtectionStateInfo advanced_protection_state_info = 10236 [(module) = "framework"];
 }
 
 /**
@@ -829,6 +843,20 @@ message DeviceIdleTempAllowlistUpdated {
     optional int32 calling_uid = 7 [(is_uid) = true];
 }
 
+/**
+ * Records Bitmap allocations.
+ *
+ * Logged via Hummingbird for probes at android.graphics.Bitmap constructor.
+ *
+ * Estimated Logging Rate:
+ *   Peak: 100 times in a minute | Avg: O(hundreds) per device per day
+ */
+message AndroidGraphicsBitmapAllocated {
+    optional int32 uid = 1 [(is_uid) = true];
+    optional int32 width = 2;
+    optional int32 height = 3;
+}
+
 /**
  * [Pushed Atom] Logs when an AppOp is accessed through noteOp, startOp, finishOp and that access
  * history can be stored in the AppOp discrete access data store.
@@ -899,6 +927,39 @@ message AppOpNoteOpOrCheckOpBinderApiCalled {
     optional bool has_attribution_tag = 4;
 }
 
+/**
+ * Pushed atom. Logs the duration between device state change and device state
+ * based auto rotate setting change if the duration is less than certain
+ * threshold.
+ *
+ * Logged from:
+ *  frameworks/base/services/core/java/com/android/server/wm/DeviceStateAutoRotateSettingIssueLogger.java
+ *
+ * Estimated Logging Rate:
+ *   Avg: < 1 per device per day
+*/
+message DeviceStateAutoRotateSettingIssueReported {
+  // Duration between device state change and device state based auto rotate
+  // setting change.
+  optional int32 duration_ms = 1;
+  // Boolean is true if the device state change is the first one to happen
+  // followed by device state based auto rotate setting change.
+  // False if the device state based auto rotate setting change is the first one
+  // to happen followed by device state change.
+  optional bool is_device_state_change_first = 2;
+}
+
+/**
+ * [Pushed Atom] Log discrete ops performance results for sqlite implementation.
+ *
+ * Logged from: frameworks/base/services/core/java/com/android/server/appop/DiscreteOpsSqlRegistry.java
+ */
+message SqliteDiscreteOpEventReported {
+  optional int64 read_time_millis = 1 ;
+  optional int64 write_time_millis = 2 ;
+  optional int64 storage_bytes = 3 ;
+}
+
 /**
  * Logs when specific content and file URIs are encountered in several locations. See EventType for
  * more details.
@@ -990,10 +1051,8 @@ message JankFrameCountByWidgetReported {
     NAVIGATION = 4;
     // UI elements that facilitate displaying, hiding or interacting with keyboard.
     KEYBOARD = 5;
-    // UI elements that facilitate predictive back gesture navigation.
-    PREDICTIVE_BACK = 6;
     // UI elements that don't fall in on of the other categories.
-    OTHER = 7;
+    OTHER = 6;
   }
   optional WidgetCategory widget_type = 5;
 
@@ -1019,6 +1078,8 @@ message JankFrameCountByWidgetReported {
     PLAYBACK = 8;
     // Element that is currently being tapped on.
     TAPPING = 9;
+    // Element that is currently performing a back navigation gesture.
+    PREDICTIVE_BACK = 10;
   }
   optional WidgetState widget_state = 6;
 
@@ -1051,12 +1112,62 @@ message IntentCreatorTokenAdded {
 }
 
 /**
- * Reports a notification got an Adjustment with the KEY_TYPE value set
+ * [Pushed atom] Logged when an intent redirect attack is blocked.
+ *
+ * Pushed from:
+ *   frameworks/base/services/core/java/com/android/server/am/ActivityStarter.java
+ *      #Request.resolveActivity
+ *      #executeRequest
+ *   frameworks/base/services/core/java/com/android/server/am/ActivityStartController.java
+ *      #startActivities
+ *
+ * Estimated Logging Rate:
+ *  Peak: 10 times per device per day.
+ *  Avg: 0 times per device per day.
+ */
+message IntentRedirectBlocked {
+  // creator uid
+  optional int32 creator_uid = 1 [(is_uid) = true];
+  // calling uid
+  optional int32 calling_uid = 2 [(is_uid) = true];
+  // reason code
+  optional Reason reason = 3;
+  enum Reason {
+    INTENT_REDIRECT_BLOCKED_UNSPECIFIED = 0;
+    INTENT_REDIRECT_EXCEPTION_MISSING_OR_INVALID_TOKEN = 1;
+    INTENT_REDIRECT_EXCEPTION_GRANT_URI_PERMISSION = 2;
+    INTENT_REDIRECT_EXCEPTION_START_ANY_ACTIVITY_PERMISSION = 3;
+    INTENT_REDIRECT_ABORT_START_ANY_ACTIVITY_PERMISSION = 4;
+    INTENT_REDIRECT_ABORT_INTENT_FIREWALL_START_ACTIVITY = 5;
+    INTENT_REDIRECT_ABORT_PERMISSION_POLICY_START_ACTIVITY = 6;
+  }
+}
+
+/**
+ * [Pushed atom] Logged when extra intent keys have to be collected on the system server.
+ *
+ * Pushed from:
+ *   frameworks/base/services/core/java/com/android/server/am/ActivityManagerService.java
+ *      #addCreatorToken
+ *
+ * Estimated Logging Rate:
+ *  Peak: 10 times per device per day.
+ *  Avg: 0 times per device per day.
+ */
+message ExtraIntentKeysCollectedOnServer {
+  // creator uid
+  optional int32 creator_uid = 1 [(is_uid) = true];
+}
+
+/**
+ * Reports a notification got an Adjustment with the KEY_TYPE value set. These adjustments generally
+ * mean a notification has been classified as belonging to a particular type (e.g., news).
+ * (go/sysui-notification-bundle-metrics)
+ *
  * Logged from:
  *   frameworks/base/services/core/java/com/android/server/notification/
  * Estimated Logging Rate:
  *   Peak: 300 times per device per day. | Avg: 40 times per device per day.
- *
  */
 message NotificationChannelClassification {
     // Was the notification reclassified to a new channel after it was already posted.
@@ -1070,6 +1181,44 @@ message NotificationChannelClassification {
 
     // The length of the lifetime of the notification up to when it got reclassified.
     optional int32 latency_ms = 4;
+
+    // As for UiEventReported; used to indicate the event which caused the reclassification.
+    optional int32 event_id = 5;
+
+    // The instance ID of the notification whose channel has been classified.
+    optional int32 instance_id = 6;
+
+    // The uid of the activity which posted the notification.
+    optional int32 uid = 7 [(is_uid) = true];
+}
+
+/**
+ * Reports that an instance of a notification bundle was interacted with.
+ * (go/sysui-notification-bundle-metrics)
+ *
+ * A notification bundle is a grouping of a number of notifications, based on their type, rather
+ * than based on the app that posted them. For example, a number of notifications from different
+ * apps that are all news related may be categorized as such, and grouped together in a UI element
+ * that groups, or "bundles" them.
+ *
+ * This proto indicates that a particular bundle was interacted with in some way; for example, a
+ * user may choose to dismiss an entire bundle, which would log a NotificationBundleInteracted
+ * with an event_id that represents bundle dismissal.
+ *
+ * Logged from:
+ *   frameworks/base/packages/SystemUI/src/com/android/systemui/
+ * Estimated Logging Rate:
+ *   Peak: 300 times per device per day. | Avg: <40 times per device per day.
+ */
+message NotificationBundleInteracted {
+    // As for UiEventReported; used to indicate the modification made.
+    optional int32 event_id = 1;
+
+    // The channel type of the bundle (e.g., TYPE_NEWS).
+    optional int32 type = 2;
+
+    // Whether the full contents of this bundle have ever been shown to the user.
+    optional bool contents_shown = 3;
 }
 
 /**
@@ -1094,3 +1243,137 @@ message CameraStatusForCompatibilityChanged {
     // was received again.
     optional int32 latency_ms = 3;
 }
+
+/**
+ * Reports that an activity has been launched from the PROCESS_TEXT activity
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/wm/ActivityMetricsLogger.java
+ * Estimated Logging Rate:
+ *   Peak: 25 times per device per day | Avg: Between 0 and 1 times per device per day
+ */
+message ProcessTextActionLaunchedReported {
+    // The uid of the app that is calling the PROCESS_TEXT action.
+    optional int32 calling_uid = 1 [(is_uid) = true];
+
+    // The uid of the app that is launched.
+    optional int32 launched_uid = 2 [(is_uid) = true];
+}
+
+/**
+ * Logs the bitmap memory usage in system_server of a bound widget.
+ *
+ * Logged from:
+ *   frameworks/base/services/appwidget/java/com/android/server/appwidget/AppWidgetServiceImpl.java
+ */
+message WidgetMemoryStats {
+    // The uid of the app that provides this widget.
+    optional int32 uid = 1 [(is_uid) = true];
+
+    // The app widget ID. Used to disambiguate multiple widgets from the same provider.
+    optional int32 app_widget_id = 2;
+
+    // The bitmap memory usage in bytes.
+    optional int64 bitmap_memory_bytes = 3;
+}
+
+
+/**
+ * Reports that the Advanced Protection setting has changed.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/security/advancedprotection/AdvancedProtectionService.java
+ * Estimated Logging Rate:
+ *   Peak: 2 times per device per day. | Avg: 1 time per device (total)
+ */
+message AdvancedProtectionStateChanged {
+    // The new state of Advanced Protection
+    optional bool enabled = 1;
+    // The number of hours since the last time this atom was logged
+    optional int32 hours_since_last_change = 2;
+    // The last dialog shown.
+    // AdvancedProtectionSupportDialogDisplayed.FeatureId
+    optional android.security.advancedprotection.FeatureId last_dialog_feature_id = 3;
+    // Why the last dialog was shown
+    optional android.security.advancedprotection.DialogueType last_dialogue_type = 4;
+    // Whether the learn more button was clicked in the last dialog shown
+    optional bool last_dialog_learn_more_clicked = 5;
+    optional int32 last_dialog_hours_since_enabled = 6;
+}
+
+/**
+ * Reports that the Advanced Protection support dialog has been displayed.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/security/advancedprotection/AdvancedProtectionService.java
+ * Estimated Logging Rate:
+ *   Peak: 10 times per device per day. | Avg: <1 time per device per day.
+ */
+message AdvancedProtectionSupportDialogDisplayed {
+    // The feature id of the dialog shown
+    optional android.security.advancedprotection.FeatureId feature_id = 1;
+    // Why the dialog was shown
+    optional android.security.advancedprotection.DialogueType dialogue_type = 2;
+    // Whether the learn more button was clicked in the dialog
+    optional bool learn_more_clicked = 3;
+    optional int32 hours_since_enabled = 4;
+}
+
+/** Pull atom for the current state of Advanced Protection.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/security/advancedprotection/AdvancedProtectionService.java
+ * Estimated Logging Rate:
+ *   Peak: 1 times per device per day. | Avg: <1 time per device per day.
+*/
+message AdvancedProtectionStateInfo {
+    optional bool enabled = 1;
+    optional int32 hours_since_last_change = 2;
+}
+
+/**
+ * Logged by clipboard service when the user pastes clips from the system clipboard.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/clipboard/ClipboardService.java
+ * Estimated Logging Rate:
+ *   Peak: 100 times per device per day. | Avg: 10 time per device per day.
+ */
+message ClipboardGetEventReported {
+    /**
+     * The types of clip data.
+     *
+     * Keep it in sync with frameworks/base/core/java/android/content/ClipDescription.java
+     */
+    enum ClipDataType {
+        MIMETYPE_UNKNOWN = 0;
+        MIMETYPE_TEXT_PLAIN = 1;
+        MIMETYPE_TEXT_HTML = 2;
+        MIMETYPE_TEXT_URILIST = 3;
+        MIMETYPE_TEXT_INTENT = 4;
+        MIMETYPE_APPLICATION_ACTIVITY = 5;
+        MIMETYPE_APPLICATION_SHORTCUT = 6;
+        MIMETYPE_APPLICATION_TASK = 7;
+    }
+
+    /**
+     * The source app where this clip data comes from.
+     */
+    optional int32 source_uid = 1 [(is_uid) = true];
+
+    /**
+     * The target app where this clip data is pasting into.
+     */
+    optional int32 target_uid = 2 [(is_uid) = true];
+
+    /**
+     * The target app's process state.
+     */
+    optional android.app.ProcessStateEnum target_process_state = 3;
+
+    /**
+     * The types of the clip data types, it should be the combination of enum ClipDataType.
+     */
+    repeated ClipDataType clip_data_type = 4;
+
+    /**
+     * Time between the clip data is set and the clip data is retrieved,
+     * measured in seconds, including the device asleep time.
+     */
+    optional int32 time_since_set_in_secs = 5;
+}
diff --git a/stats/atoms/healthfitness/api/api_extension_atoms.proto b/stats/atoms/healthfitness/api/api_extension_atoms.proto
index 71dc5025..6536e87c 100644
--- a/stats/atoms/healthfitness/api/api_extension_atoms.proto
+++ b/stats/atoms/healthfitness/api/api_extension_atoms.proto
@@ -53,6 +53,16 @@ extend Atom {
   optional HealthConnectRestrictedEcosystemStats health_connect_restricted_ecosystem_stats = 985 [(module) = "healthfitness", (restriction_category) = RESTRICTION_DIAGNOSTIC];
 
   optional HealthConnectEcosystemStats health_connect_ecosystem_stats = 986 [(module) = "healthfitness"];
+
+  optional HealthConnectDataBackupInvoked health_connect_data_backup_invoked = 1023 [(module) = "healthfitness"];
+
+  optional HealthConnectSettingsBackupInvoked health_connect_settings_backup_invoked = 1024 [(module) = "healthfitness"];
+
+  optional HealthConnectDataRestoreInvoked health_connect_data_restore_invoked = 1025 [(module) = "healthfitness"];
+
+  optional HealthConnectSettingsRestoreInvoked health_connect_settings_restore_invoked = 1026 [(module) = "healthfitness"];
+
+  optional HealthConnectRestoreEligibilityChecked health_connect_restore_eligibility_checked = 1027 [(module) = "healthfitness"];
 }
 
 // Track HealthDataService API operations.
@@ -187,6 +197,11 @@ message HealthConnectExportInvoked {
 
   // Size of the compressed data being exported.
   optional int32 compressed_data_size_kb = 4;
+
+  // The number of export attempts that have failed with the same error code
+  // as the current export attempt. It is 0 if the current export is a regular
+  // scheduled export rather than a retry.
+  optional int32 repeat_error_on_retry_count = 5;
 }
 
 /**
@@ -207,6 +222,94 @@ message HealthConnectImportInvoked {
   optional int32 compressed_data_size_kb = 4;
 }
 
+/**
+ * Track when a Backup and Restore data backup is invoked.
+ * Logged from:
+ * packages/modules/HealthFitness/service/java/com/android/server/healthconnect/logging/BackupRestoreLogger.java
+ *
+ * Estimated Logging Rate:
+ * Avg: 1 per device per day
+ */
+message HealthConnectDataBackupInvoked {
+
+  // Status of the data backup (started/success/failure)
+  optional android.healthfitness.api.DataBackupStatus status = 1;
+
+  // Time taken between the start of the data backup and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the data being backed up.
+  optional int32 data_size_kb = 3;
+
+  // Data backup type (full/incremental).
+  optional android.healthfitness.api.DataBackupType backup_type = 4;
+}
+
+/**
+ * Track when a Backup and Restore settings backup is invoked.
+ * Logged from:
+ * packages/modules/HealthFitness/service/java/com/android/server/healthconnect/logging/BackupRestoreLogger.java
+ *
+ * Estimated Logging Rate:
+ * Avg: 1 per device per day
+ */
+message HealthConnectSettingsBackupInvoked {
+
+  // Status of the settings backup (started/success/failure)
+  optional android.healthfitness.api.SettingsBackupStatus status = 1;
+
+  // Time taken between the start of the settings backup and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the settings being backed up.
+  optional int32 settings_size_kb = 3;
+}
+
+/**
+ * Track when a Backup and Restore data restore is invoked.
+ * Logged from:
+ * packages/modules/HealthFitness/service/java/com/android/server/healthconnect/logging/BackupRestoreLogger.java
+ *
+ * Estimated Logging Rate:
+ * Avg: <1 per device per day
+ */
+message HealthConnectDataRestoreInvoked {
+
+  // Status of the data restore (started/success/failure)
+  optional android.healthfitness.api.DataRestoreStatus status = 1;
+
+  // Time taken between the start of the data restore and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the data being restored.
+  optional int32 data_size_kb = 3;
+}
+
+/**
+ * Track when a Backup and Restore settings restore is invoked.
+ * Logged from:
+ * packages/modules/HealthFitness/service/java/com/android/server/healthconnect/logging/BackupRestoreLogger.java
+ *
+ * Estimated Logging Rate:
+ * Avg: <1 per device per day
+ */
+message HealthConnectSettingsRestoreInvoked {
+
+  // Status of the settings restore (started/success/failure)
+  optional android.healthfitness.api.SettingsRestoreStatus status = 1;
+
+  // Time taken between the start of the settings restore and its conclusion.
+  optional int32 time_to_succeed_or_fail_millis = 2;
+
+  // Size of the settings being restored.
+  optional int32 settings_size_kb = 3;
+}
+
+// Track when the eligibility of a Backup and Restore restore is checked.
+message HealthConnectRestoreEligibilityChecked {
+  optional bool is_eligible = 1;
+}
+
 // Track Health Connect API operations stats.
 message HealthConnectApiInvoked {
 
@@ -294,6 +397,9 @@ message HealthConnectEcosystemStats {
   // Datatypes shared in past 30 days
   repeated android.healthfitness.api.DataType shared = 4;
 
+  // Number of apps sharing data
+  optional int32 number_of_app_pairings = 5;
+
 }
 
 /**
diff --git a/stats/atoms/location/location_extension_atoms.proto b/stats/atoms/location/location_extension_atoms.proto
index 736434fa..5c9aa15b 100644
--- a/stats/atoms/location/location_extension_atoms.proto
+++ b/stats/atoms/location/location_extension_atoms.proto
@@ -31,6 +31,18 @@ extend Atom {
 
  optional ChreSignificantMotionStateChanged
       chre_significant_motion_state_changed = 868 [(module) = "chre"];
+
+  optional PopulationDensityProviderLoadingReported
+      population_density_provider_loading_reported = 1002
+      [(module) = "framework"];
+
+  optional DensityBasedCoarseLocationsUsageReported
+      density_based_coarse_locations_usage_reported = 1003
+      [(module) = "framework"];
+
+  optional DensityBasedCoarseLocationsProviderQueryReported
+      density_based_coarse_locations_provider_query_reported = 1004
+      [(module) = "framework"];
 }
 
 /**
@@ -54,3 +66,62 @@ message EmergencyStateChanged {
 message ChreSignificantMotionStateChanged {
   optional android.contexthub.ContextHubSignificantMotionState state = 1;
 }
+
+/**
+ * Logs when the LocationManagerService finds and instantiates a
+ * IPopulationDensityProvider, based on the XML configuration.
+ * Logged from:
+ *    frameworks/base/services/core/java/com/android/server/location/
+ *    LocationManagerService.java
+ * Estimated Logging Rate:
+ *    Peak: 1 times in 5 min (once per boot) | Avg: ~1 per device per day
+ */
+message PopulationDensityProviderLoadingReported {
+
+  // Is true if the provider isn't found, or if any error occurs when creating
+  // the provider.
+  optional bool provider_null = 1;
+
+  // The latency between the framework creating the
+  // ProxyPopulationDensityProvider and the Binder interface being ready.
+  optional int32 provider_start_time_millis = 2;
+}
+
+/**
+ * Logs when the LocationFudger uses the new density-based coarse locations.
+ * Logged from:
+ *    frameworks/base/services/core/java/com/android/server/location/fudger/
+ *    LocationFudgerCache.java
+ * Estimated Logging Rate:
+ *    Peak: 1 times in 10 min (rate-limited) | Avg: ~100 per device per day
+ */
+message DensityBasedCoarseLocationsUsageReported {
+
+  // If the new algo is skipped because the cache has no default.
+  optional bool skipped_no_default = 1;
+
+  // If the answer to the query was already in cache (default isn't used).
+  optional bool is_cache_hit = 2;
+
+  // Returns the default stored in the cache (used on cache miss).
+  optional int32 default_coarsening_level = 3;
+}
+
+/**
+ * Logs when the LocationFudger uses the new density-based coarse locations.
+ * Logged from:
+ *    frameworks/base/services/core/java/com/android/server/location/fudger/
+ *    LocationFudgerCache.java
+ * Estimated Logging Rate:
+ *    Peak: 1 times in 10 min (once per S2 cell at level 12. Peak is if the
+ *    device is continually changing cells, which are ~6km²).
+ *    Avg: ~100 per device per day
+ */
+ message DensityBasedCoarseLocationsProviderQueryReported {
+
+  // The latency between firing the query and receiving an answer.
+  optional int32 query_duration_millis = 1;
+
+  // Is true if querying the provider returned any error.
+  optional bool is_error = 2;
+}
diff --git a/stats/atoms/media/media_router_extension_atoms.proto b/stats/atoms/media/media_router_extension_atoms.proto
new file mode 100644
index 00000000..1459062f
--- /dev/null
+++ b/stats/atoms/media/media_router_extension_atoms.proto
@@ -0,0 +1,44 @@
+/*
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
+syntax = "proto2";
+
+package android.os.statsd.media;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/media/router/enums.proto";
+
+option java_package = "com.android.os.media";
+option java_multiple_files = true;
+
+extend Atom {
+  optional MediaRouterEventReported media_router_event_reported = 1017
+      [(module) = "mediarouter"];
+}
+
+/**
+ * Pushed atom. Logs an event for media router.
+ *
+ * Logged from:
+ *   frameworks/base/media/java/android/media/
+ * Estimated Logging Rate:
+ *   Avg: 10 per device per day
+ */
+message MediaRouterEventReported {
+  optional android.media.router.EventType event_type = 1;
+  optional android.media.router.Result result = 2;
+}
diff --git a/stats/atoms/memory/zram_extension_atoms.proto b/stats/atoms/memory/zram_extension_atoms.proto
new file mode 100644
index 00000000..26d1e83f
--- /dev/null
+++ b/stats/atoms/memory/zram_extension_atoms.proto
@@ -0,0 +1,140 @@
+/*
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
+syntax = "proto2";
+
+package android.os.statsd.memory;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/memory/enums.proto";
+
+option java_package = "com.android.os.memory";
+option java_multiple_files = true;
+
+extend Atom {
+    optional ZramMaintenanceExecuted zram_maintenance_executed = 1015 [(module) = "framework"];
+    optional ZramSetupExecuted zram_setup_executed = 1029 [(module) = "framework"];
+
+    optional ZramMmStatMmd zram_mm_stat_mmd = 10232 [(module) = "framework"];
+    optional ZramBdStatMmd zram_bd_stat_mmd = 10233 [(module) = "framework"];
+}
+
+/**
+ * Logged when zram maintenance is executed in mmd.
+ *
+ * Logged from:
+ *   * system/memory/mmd
+ *
+ * Estimated Logging Rate:
+ *   ZramMaintenance is triggered at most once per 1 hour
+ *
+ * Next Tag: 13
+ */
+message ZramMaintenanceExecuted {
+    optional android.memory.ZramWritebackResult writeback_result = 1;
+    optional int64 writeback_huge_idle_pages = 2;
+    optional int64 writeback_idle_pages = 3;
+    optional int64 writeback_huge_pages = 4;
+    optional int64 writeback_latency_millis = 5;
+    optional int64 writeback_limit_kb = 6;
+    optional int64 writeback_daily_limit_kb = 7;
+    optional int64 writeback_actual_limit_kb = 8;
+    optional int64 writeback_total_kb = 9;
+
+    optional android.memory.ZramRecompressionResult recompression_result = 10;
+    optional int64 recompress_latency_millis = 11;
+
+    optional int64 interval_from_previous_seconds = 12;
+}
+
+
+/**
+ * Zram stats from /sys/block/zram0/mm_stat
+ *
+ * Logged from:
+ *   * system/memory/mmd
+ *
+ * Next Tag: 10
+ */
+message ZramMmStatMmd {
+    // Uncompressed size of data stored in this disk. This excludes
+    // same-element-filled pages (same_pages) since no memory is allocated for
+    // them.
+    optional int64 orig_data_kb = 1;
+    // Compressed size of data stored in this disk.
+    optional int64 compr_data_kb = 2;
+    // The amount of memory allocated for this disk. This includes allocator
+    // fragmentation and metadata overhead, allocated for this disk. So,
+    // allocator space efficiency can be calculated using compr_data_size and
+    // this statistic.
+    optional int64 mem_used_total_kb = 3;
+    // The maximum amount of memory ZRAM can use to store The compressed data.
+    optional int64 mem_limit_kb = 4;
+    // The maximum amount of memory zram have consumed to store the data.
+    //
+    // In zram_drv.h we define max_used_pages as atomic_long_t which could be
+    // negative, but negative value does not make sense for the variable.
+    optional int64 mem_used_max_kb = 5;
+    // The number of same element filled pages written to this disk. No memory
+    // is allocated for such pages.
+    optional int64 same_pages_kb = 6;
+    // The number of pages freed during compaction.
+    optional int64 pages_compacted_kb = 7;
+    // The number of incompressible pages.
+    // Start supporting from v4.19.
+    optional int64 huge_pages_kb = 8;
+    // The number of huge pages since zram set up.
+    // Start supporting from v5.15.
+    optional int64 huge_pages_since_kb = 9;
+}
+
+/**
+ * Zram writeback stats from /sys/block/zram0/bd_stat
+ *
+ * Logged from:
+ *   * system/memory/mmd
+ *
+ * Next Tag: 4
+ */
+message ZramBdStatMmd {
+    /// Size of data written in backing device.
+    optional int64 bd_count_kb = 1;
+    /// The number of reads from backing device.
+    optional int64 bd_reads_kb = 2;
+    /// The number of writes to backing device.
+    optional int64 bd_writes_kb = 3;
+}
+
+/**
+ * Logged when zram setup is executed in mmd.
+ *
+ * Logged from:
+ *   * system/memory/mmd
+ *
+ * Estimated Logging Rate:
+ *   ZramSetup is triggered at most once per boot.
+ *
+ * Next Tag: 7
+ */
+message ZramSetupExecuted {
+    optional android.memory.ZramSetupResult zram_setup_result = 1;
+    optional android.memory.ZramCompAlgorithmSetupResult comp_algorithm_setup_result = 2;
+    optional android.memory.ZramWritebackSetupResult writeback_setup_result = 3;
+    optional android.memory.ZramRecompressionSetupResult recompression_setup_result = 4;
+    optional int64 zram_size_mb = 5;
+    optional int64 writeback_size_mb = 6;
+}
diff --git a/stats/atoms/nfc/nfc_extension_atoms.proto b/stats/atoms/nfc/nfc_extension_atoms.proto
index 918da90c..c937e392 100644
--- a/stats/atoms/nfc/nfc_extension_atoms.proto
+++ b/stats/atoms/nfc/nfc_extension_atoms.proto
@@ -20,6 +20,7 @@ package android.os.statsd.nfc;
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/nfc/enums.proto";
 
 option java_package = "com.android.nfc";
 
@@ -28,6 +29,8 @@ extend Atom {
     optional NfcFieldChanged nfc_field_changed = 856 [(module) = "nfc"];
     optional NfcPollingLoopNotificationReported  nfc_polling_loop_notification_reported = 857 [(module) = "nfc"];
     optional NfcProprietaryCapabilitiesReported  nfc_proprietary_capabilities_reported = 858 [(module) = "nfc"];
+    optional NfcExitFrameTableChanged nfc_exit_frame_table_changed = 1036 [(module) = "nfc"];
+    optional NfcAutoTransactReported nfc_auto_transact_reported = 1038 [(module) = "nfc"];
 }
 
 message NfcObserveModeStateChanged {
@@ -42,6 +45,7 @@ message NfcObserveModeStateChanged {
     WALLET_ROLE_HOLDER = 1;
     FOREGROUND_APP = 2;
     AUTO_TRANSACT = 3;
+    AUTO_TRANSACT_NFCC = 4;
   }
 
   optional State state = 1;
@@ -85,3 +89,21 @@ message NfcProprietaryCapabilitiesReported {
   optional bool is_autotransact_polling_loop_filter_supported = 4;
   optional int32 number_of_exit_frames_supported = 5;
 }
+
+message NfcExitFrameTableChanged {
+  optional int32 table_size = 1;      // the number of entries in the table
+  optional int32 timeout_millis = 2;  // timeout chosen to restore observe mode (ms)
+}
+
+message NfcAutoTransactReported {
+  enum AutoTransactProcessor {
+    PROCESSOR_UNKNOWN = 0;
+    HOST = 1;
+    NFCC = 2;
+  }
+
+  optional AutoTransactProcessor auto_transact_processor = 1;
+  // This measures the number of bytes in the frame that triggered the auto-transact.
+  optional int32 frame_size = 2;
+  optional android.nfc.NfcProprietaryFrameType frame_type = 3;
+}
diff --git a/stats/atoms/notification/notification_extension_atoms.proto b/stats/atoms/notification/notification_extension_atoms.proto
new file mode 100644
index 00000000..87e84e44
--- /dev/null
+++ b/stats/atoms/notification/notification_extension_atoms.proto
@@ -0,0 +1,49 @@
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
+package android.os.statsd.notification;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/notification/enums.proto";
+
+option java_package = "com.android.os.notification";
+option java_multiple_files = true;
+
+extend Atom {
+  optional NotificationBundlePreferences notification_bundle_preferences = 10231 [(module) = "framework"];
+}
+
+/**
+ * Atom that records a list of a user's notification bundle preferences. Bundles are system-provided
+ * groupings of notifications based on notifications being classified as belonging to a particular
+ * type (e.g., news). Users can choose to allow or disallow their notifications from being bundled
+ * via settings.
+ *
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/notification/NotificationManagerService.java
+ */
+message NotificationBundlePreferences {
+  // The event_id (as for UiEventReported).
+  optional int32 event_id = 1;
+  // Whether bundling is allowed at all. Opting-out of bundling sets to false.
+  optional bool bundles_allowed = 2;
+  // Which types of bundles are allowed. Bundle types are a limited set, so this
+  // repeated field will never be larger than the total number of bundle types.
+  repeated android.stats.notification.BundleTypes allowed_bundle_types = 3;
+}
\ No newline at end of file
diff --git a/stats/atoms/ondevicepersonalization/OWNERS b/stats/atoms/ondevicepersonalization/OWNERS
new file mode 100644
index 00000000..6de30c03
--- /dev/null
+++ b/stats/atoms/ondevicepersonalization/OWNERS
@@ -0,0 +1,5 @@
+fumengyao@google.com
+karthikmahesh@google.com
+lmohanan@google.com
+qiaoli@google.com
+yanning@google.com
\ No newline at end of file
diff --git a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
index 0f3a71bc..383f48e1 100644
--- a/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
+++ b/stats/atoms/ondevicepersonalization/ondevicepersonalization_extension_atoms.proto
@@ -64,6 +64,7 @@ message OnDevicePersonalizationApiCalled {
         FEDERATED_COMPUTE_CANCEL = 21;
         NOTIFY_MEASUREMENT_EVENT = 22;
         ADSERVICES_GET_COMMON_STATES = 23;
+        IS_FEATURE_ENABLED = 24;
     }
     optional OnDevicePersonalizationApiClassType api_class = 1;
     optional OnDevicePersonalizationApiName api_name = 2;
diff --git a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
index 49658927..d937058a 100644
--- a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
+++ b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
@@ -40,6 +40,12 @@ extend Atom {
         827 [(module) = "permissioncontroller"];
     optional EnhancedConfirmationRestrictionCleared enhanced_confirmation_restriction_cleared =
         828 [(module) = "permissioncontroller"];
+    optional RoleSettingsFragmentActionReported role_settings_fragment_action_reported =
+        1020 [(module) = "permissioncontroller"];
+    optional EcmRestrictionQueryInCallReported ecm_restriction_query_in_call_reported =
+        1034 [(module) = "permissioncontroller"];
+    optional CallWithEcmInteractionReported call_with_ecm_interaction_reported =
+        1035 [(module) = "permissioncontroller"];
 }
 
 /**
@@ -195,3 +201,60 @@ message EnhancedConfirmationRestrictionCleared {
   // UID of the restricted app
   optional int32 uid = 1 [(is_uid) = true];
 }
+
+/**
+ * Reports that User has changed a default app for a role in settings.
+ * Logged from:
+ *   packages/modules/Permission/PermissionController/src/com/android/permissioncontroller/role/ui/DefaultAppChildFragment.java
+ * Estimated Logging Rate:
+ *   Peak: few times per device per week | Avg: Between 0 and 1 times per device per day
+ */
+message RoleSettingsFragmentActionReported {
+  // UID of application assigned the role
+  optional int32 uid = 1 [(is_uid) = true];
+
+  // Package name of application assigned the role
+  optional string package_name = 2;
+
+  optional string role_name = 3;
+}
+
+/*
+ * Reports that the Enhanced Confirmation Service has received a query to the restriction state of
+ * a setting that is restricted while in an untrusted call.
+ * Logs from: com.android.ecm.EnhancedConfirmationService
+ */
+message EcmRestrictionQueryInCallReported {
+  // UID of the possibly restricted app
+  optional int32 uid = 1 [(is_uid) = true];
+
+  // The setting being checked
+  optional string setting_identifier = 2;
+
+  // Whether or not the setting was allowed (vs. restricted)
+  optional bool allowed = 3;
+
+  // Whether a call was in progress at the time of this restriction check
+  optional bool call_in_progress = 4;
+
+  // Whether the call was incoming. False, if there was no call
+  optional bool call_incoming = 5;
+
+  // Whether the call was trusted. True, if there was no call
+  optional bool call_trusted = 6;
+
+  // Whether a block had happened in the past hour for the given call. False if there is no call.
+  optional bool call_back_after_block = 7;
+}
+
+/*
+ * Reports that a call happened, during which the EnhancedConfirmation Service was queried for the
+ * restriction state of a setting that is restricted while in an untrusted call.
+ * Logs from: com.android.ecm.EnhancedConfirmationService
+ */
+message CallWithEcmInteractionReported {
+    // Whether any setting was blocked during the call
+    optional bool any_setting_blocked = 1;
+    // The call duration, in seconds
+    optional int32 duration_secs = 2;
+}
diff --git a/stats/atoms/photopicker/photopicker_extension_atoms.proto b/stats/atoms/photopicker/photopicker_extension_atoms.proto
index dfaa7699..d6a3b8ac 100644
--- a/stats/atoms/photopicker/photopicker_extension_atoms.proto
+++ b/stats/atoms/photopicker/photopicker_extension_atoms.proto
@@ -55,6 +55,10 @@ extend Atom {
   [(module) = "mediaprovider"];
   optional EmbeddedPhotopickerInfoReported embedded_photopicker_info_reported = 899
   [(module) = "mediaprovider"];
+  optional PhotopickerAppMediaCapabilitiesReported photopicker_app_media_capabilities_reported = 1043
+  [(module) = "mediaprovider"];
+  optional PhotopickerVideoTranscodingDetailsLogged photopicker_video_transcoding_details_logged = 1044
+  [(module) = "mediaprovider"];
 }
 
 /*
@@ -91,6 +95,7 @@ message PhotopickerApiInfoReported {
   optional bool is_search_enabled = 11 [deprecated = true];
   optional bool is_cloud_search_enabled = 12;
   optional bool is_local_search_enabled = 13;
+  optional bool is_transcoding_requested = 14;
 }
 
 /*
@@ -225,3 +230,23 @@ message EmbeddedPhotopickerInfoReported {
   optional int32 surface_package_delivery_start_time_millis = 3;
   optional int32 surface_package_delivery_end_time_millis = 4;
 }
+
+/*
+ Logs Application Media Capabilities for Transcoding support
+ */
+message PhotopickerAppMediaCapabilitiesReported {
+  optional int32 session_id = 1;
+  repeated android.photopicker.AppMediaCapabilityHdrType supported_hdr_types = 2;
+  repeated android.photopicker.AppMediaCapabilityHdrType unsupported_hdr_types = 3;
+}
+
+/*
+ Logs Transcoding video details
+*/
+message PhotopickerVideoTranscodingDetailsLogged {
+  optional int32 session_id = 1;
+  optional int32 duration = 2;
+  optional int32 colorStandard = 3;
+  optional int32 colorTransfer = 4;
+  optional android.photopicker.VideoMimeType mimeType = 5;
+}
diff --git a/stats/atoms/ranging/ranging_extension_atoms.proto b/stats/atoms/ranging/ranging_extension_atoms.proto
index 145614b9..e001cb12 100644
--- a/stats/atoms/ranging/ranging_extension_atoms.proto
+++ b/stats/atoms/ranging/ranging_extension_atoms.proto
@@ -53,6 +53,9 @@ message RangingSessionConfigured {
 
   // Number of peers to range with as specified in the configuration.
   optional int32 num_peers = 5;
+
+  // UID of the process that started this session through the API.
+  optional int32 uid = 6 [(is_uid) = true];
 }
 
 /*
@@ -67,6 +70,9 @@ message RangingSessionStarted {
 
   // The duration it took to start the session after configuring in milliseconds.
   optional int64 start_latency_ms = 3;
+
+  // Whether the process that requested ranging is privileged.
+  optional bool is_privileged = 4;
 }
 
 /*
@@ -83,7 +89,10 @@ message RangingSessionClosed {
   optional int64 last_state_duration_ms = 3;
 
   // Reason why the session closed.
-  optional android.ranging.ClosedReason reason = 4;
+  optional android.ranging.Reason reason = 4;
+
+  // UID of the process that started this session through the API.
+  optional int32 uid = 5 [(is_uid) = true];
 }
 
 /*
@@ -98,6 +107,9 @@ message RangingTechnologyStarted {
 
   // Number of peers that started using this technology.
   optional int32 num_peers = 3;
+
+  // UID of the process that started this session through the API.
+  optional int32 uid = 4 [(is_uid) = true];
 }
 
 /*
@@ -114,8 +126,11 @@ message RangingTechnologyStopped {
   optional android.ranging.SessionState state = 3;
 
   // Reason why this technology stopped.
-  optional android.ranging.StoppedReason reason = 4;
+  optional android.ranging.Reason reason = 4;
 
   // Number of peers that stopped using this technology.
   optional int32 num_peers = 5;
+
+  // UID of the process that started this session through the API.
+  optional int32 uid = 6 [(is_uid) = true];
 }
\ No newline at end of file
diff --git a/stats/atoms/settings/settings_extension_atoms.proto b/stats/atoms/settings/settings_extension_atoms.proto
index c39237f4..cf750d45 100644
--- a/stats/atoms/settings/settings_extension_atoms.proto
+++ b/stats/atoms/settings/settings_extension_atoms.proto
@@ -20,13 +20,14 @@ package android.os.statsd.settings;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/enums/app/settings_enums.proto";
+import "frameworks/proto_logging/stats/enums/app/settings/settings_enums.proto";
 
 option java_package = "com.android.os.settings";
 option java_multiple_files = true;
 
 extend Atom {
   optional SettingsSpaReported settings_spa_reported = 622 [(module) = "settings"];
+  optional SettingsExtApiReported settings_extapi_reported = 1001 [(module) = "settings"];
 }
 
 
@@ -61,4 +62,33 @@ message SettingsSpaReported {
 
   // Data about elapsed time since setup wizard finished.
   optional int64 elapsed_time_millis = 8;
-}
\ No newline at end of file
+}
+
+/**
+ * Logs when Settings External API has been requested.
+ *
+ * Logged from:
+ *   framework/base/packages/SettingsLib/Graph
+ *
+ * Estimated Logging Rate:
+ *   Peak: 5 times in 1 min | Avg: 40 times per device per day
+ */
+message SettingsExtApiReported {
+  // Package calling the API.
+  optional string package_name = 1;
+
+  // Setting ID assembled by screen name and setting key.
+  optional string setting_id = 2;
+
+  // Settings external API request type.
+  optional android.app.settings.ExtApiRequestType type = 3;
+
+  // Settings external API result type.
+  optional android.app.settings.ExtApiResultType result = 4;
+
+  // Latency between the request and result made by the external API.
+  optional int64 latency_millis = 5;
+
+  // Action enum associated with the preference.
+  optional android.app.settings.Action action = 6;
+}
diff --git a/stats/atoms/statsd/statsd_extension_atoms.proto b/stats/atoms/statsd/statsd_extension_atoms.proto
index dbfd9ecd..8e87844c 100644
--- a/stats/atoms/statsd/statsd_extension_atoms.proto
+++ b/stats/atoms/statsd/statsd_extension_atoms.proto
@@ -59,6 +59,25 @@ message TestExtensionAtomReported {
     repeated string repeated_string_field = 12;
     repeated bool repeated_boolean_field = 13;
     repeated State repeated_enum_field = 14;
+    repeated int32 linear_histogram = 15 [(histogram_bin_option).generated_bins = {
+      min: 0
+      max: 100
+      count: 10
+      strategy: LINEAR
+    }];
+    repeated int32 exponential_histogram = 16 [(histogram_bin_option).generated_bins = {
+      min: 5
+      max: 160
+      count: 5
+      strategy: EXPONENTIAL
+    }];
+    repeated int32 explicit_histogram = 17 [(histogram_bin_option).explicit_bins = {
+      bin: -10
+      bin: -7
+      bin: 0
+      bin: 19
+      bin: 100
+    }];
 }
 
 /* Test restricted atom, is not logged anywhere */
diff --git a/stats/atoms/sysui/sysui_extension_atoms.proto b/stats/atoms/sysui/sysui_extension_atoms.proto
index e1f51120..19f6bad7 100644
--- a/stats/atoms/sysui/sysui_extension_atoms.proto
+++ b/stats/atoms/sysui/sysui_extension_atoms.proto
@@ -33,6 +33,7 @@ extend Atom {
   optional CommunalHubWidgetEventReported communal_hub_widget_event_reported = 908 [(module) = "sysui"];
   optional PeripheralTutorialLaunched peripheral_tutorial_launched = 942 [(module) = "sysui"];
   optional ContextualEducationTriggered contextual_education_triggered = 971 [(module) = "sysui"];
+  optional OtpNotificationDisplayed otp_notification_displayed = 1032 [(module) = "sysui"];
   optional CommunalHubSnapshot communal_hub_snapshot = 10226 [(module) = "sysui"];
 }
 
@@ -100,7 +101,7 @@ message LauncherImpressionEventV2 {
 /**
  * Logs for Display Switch Latency Tracking.
  *
- * Next Tag: 22
+ * Next Tag: 24
 */
 message DisplaySwitchLatencyTracked {
 
@@ -154,6 +155,10 @@ message DisplaySwitchLatencyTracked {
     optional int32 onscreenturningon_to_ondrawn_ms = 20;
     // The time elapsed between the onDrawn callback and the onScreenTurnedOn call in SystemUI.
     optional int32 ondrawn_to_onscreenturnedon_ms = 21;
+    // Result of latency tracking - was it successful or what went wrong
+    optional TrackingResult tracking_result = 22;
+    // Status of screen wakelock in the system
+    optional ScreenWakelockStatus screen_wakelock_status = 23;
 
     enum StateEnum {
       // The device is in none of the above mentioned states.
@@ -180,6 +185,26 @@ message DisplaySwitchLatencyTracked {
       SCREEN_OFF = 9;
     }
 
+    enum ScreenWakelockStatus {
+      // Unknown status
+      SCREEN_WAKELOCK_STATUS_UNKNOWN = 0;
+      // There are no screen wakelocks causing the screen to be on
+      SCREEN_WAKELOCK_STATUS_NO_WAKELOCKS = 1;
+      // There are wakelocks causing the screen to be on
+      SCREEN_WAKELOCK_STATUS_HAS_SCREEN_WAKELOCKS = 2;
+    }
+
+    enum TrackingResult {
+      // Unknown result
+      UNKNOWN_RESULT = 0;
+      // Tracking was successful
+      SUCCESS = 1;
+      // Tracking entered corrupted state, latency tracking result is not correct
+      CORRUPTED = 2;
+      // Tracking timed out, latency tracking result is not correct
+      TIMED_OUT = 3;
+    }
+
 }
 
 /*
@@ -342,3 +367,37 @@ message CommunalHubSnapshot {
   // The total number of widgets in the communal hub.
   optional int32 widget_count = 2;
 }
+
+/**
+ * Pushed atom. Logs information about a notification with a detected OTP, and whether system ui
+ * redacted it.
+ *
+ * Peak: 10 times in 1 minute | Avg: 5 per device per day
+ *
+ * Logged from frameworks/base/packages/SystemUI/src/com/android/systemui/statusbar/
+ * NotificationLockscreenUserManagerImpl
+ */
+message OtpNotificationDisplayed {
+    // Whether the notification got the OTP redaction
+    optional bool redacted = 1;
+
+    // The difference between the notification's "when" time and the earliest message timestamp in
+    // the sensitive notification. 0 if there are no messages attached to the notification.
+    optional int32 notification_earliest_time_diff = 2;
+
+    // Whether or not the device is locked
+    optional bool locked = 3;
+
+    // The difference between the last locked time of the device and the notification's
+    // earliest message time (or "when" time if there are no messages)
+    optional int32 last_lock_time_diff = 4;
+
+    // Whether the device is currently in a trusted place (currently just "connected to a wifi
+    // network"
+    optional bool in_trusted_place = 5;
+
+    // The difference between the last time the device registered as being in a trusted location
+    // (currently just "connected to a wifi network") of the device and the notification's
+    // earliest message time (or "when" time if there are no messages)
+    optional int32 last_trusted_location_time_diff = 6;
+}
diff --git a/stats/atoms/telecomm/telecom_extension_atom.proto b/stats/atoms/telecomm/telecom_extension_atom.proto
index 6a4673a8..295aba3b 100644
--- a/stats/atoms/telecomm/telecom_extension_atom.proto
+++ b/stats/atoms/telecomm/telecom_extension_atom.proto
@@ -31,6 +31,7 @@ extend Atom {
     optional CallAudioRouteStats call_audio_route_stats = 10222 [(module) = "telecom"];
     optional TelecomApiStats telecom_api_stats = 10223 [(module) = "telecom"];
     optional TelecomErrorStats telecom_error_stats = 10224 [(module) = "telecom"];
+    optional TelecomEventStats telecom_event_stats = 10235 [(module) = "telecom"];
 }
 
 /**
@@ -72,7 +73,6 @@ message CallStats {
     // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
     optional android.telecom.AccountTypeEnum account_type = 5;
 
-
     // UID of the package to init the call. This should always be -1/unknown for
     // the private space calls
     optional int32 uid = 6 [(is_uid) = true];
@@ -82,6 +82,18 @@ message CallStats {
 
     // Average elapsed time between CALL_STATE_ACTIVE to CALL_STATE_DISCONNECTED.
     optional int32 average_duration_ms = 8;
+
+    // The disconnect cause of the call. Eg. ERROR, LOCAL, REMOTE, etc.
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.DisconnectCauseEnum disconnect_cause = 9;
+
+    // The type of simultaneous call type. Eg. SINGLE, DUAL_SAME_ACCOUNT,
+    // DUAL_DIFF_ACCOUNT, etc.
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.SimultaneousTypeEnum simultaneous_type = 10;
+
+    // True if it is a video call
+    optional bool video_call = 11;
 }
 
 /**
@@ -146,3 +158,22 @@ message TelecomErrorStats {
     // The number of times this error occurs
     optional int32 count = 3;
 }
+
+/**
+ * Pulled atom to capture stats of Telecom critical events
+ */
+message TelecomEventStats {
+    // The event name
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.EventEnum event = 1;
+
+    // UID of the caller. This is always -1/unknown for the private space.
+    optional int32 uid = 2 [(is_uid) = true];
+
+    // The cause related to the event
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.EventCauseEnum event_cause = 3;
+
+    // The number of times this event occurs
+    optional int32 count = 4;
+}
diff --git a/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto b/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto
index 8bb9659b..dbb1fb6b 100644
--- a/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto
+++ b/stats/atoms/telephony/iwlan/iwlan_extension_atoms.proto
@@ -48,4 +48,7 @@ message IwlanUnderlyingNetworkValidationResultReported {
 
   // Time for receiving the validation result
   optional int32 validation_duration_millis = 4;
+
+  // Whether a new instance of validation check is triggered
+  optional bool validation_triggered = 5;
 }
diff --git a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
index e711a443..4c023e58 100644
--- a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
+++ b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
@@ -134,6 +134,20 @@ message SatelliteController {
   optional int32 count_of_p2p_sms_available_notification_removed = 35;
   // Whether this satellite service is from NTN only carrier.
   optional bool is_ntn_only_carrier = 36;
+  // Version of satellite access config data.
+  optional int32 version_of_satellite_access_config = 37;
+  // Total count of successful attempts for receiving SOS SMS.
+  optional int32 count_of_incoming_datagram_type_sos_sms_success = 38;
+  // Total count of failed attempts for receiving SOS SMS.
+  optional int32 count_of_incoming_datagram_type_sos_sms_fail = 39;
+  // Total count of successful attempts for transferring P2P SMS.
+  optional int32 count_of_outgoing_datagram_type_sms_success = 40;
+  // Total count of failed attempts for transferring P2P SMS.
+  optional int32 count_of_outgoing_datagram_type_sms_fail = 41;
+  // Total count of successful attempts for receiving P2P SMS.
+  optional int32 count_of_incoming_datagram_type_sms_success = 42;
+  // Total count of failed attempts for receiving P2P SMS.
+  optional int32 count_of_incoming_datagram_type_sms_fail = 43;
 }
 
 /**
@@ -313,6 +327,16 @@ message CarrierRoamingSatelliteSession {
   optional int32 count_of_incoming_mms = 15;
   // Total number of outgoing mms sent during the session
   optional int32 count_of_outgoing_mms = 16;
+  // satellite supported services
+  repeated int32 supported_satellite_services = 17;
+  // Data Supported mode at satellite session
+  optional int32 service_data_policy = 18;
+  // Total data consumed per satellite session
+  optional int64 satellite_data_consumed_bytes = 19;
+  // Whether device is in DSDS mode
+  optional bool is_multi_sim = 20;
+  // Whether the service is Carrier Roaming NB-Iot NTN network or not.
+  optional bool is_nb_iot_ntn = 21;
 }
 
 /**
@@ -337,6 +361,12 @@ message CarrierRoamingSatelliteControllerStats {
   optional int32 carrier_id = 8;
   // Whether this device is entitled or not.
   optional bool is_device_entitled = 9;
+  // Whether device is in DSDS mode
+  optional bool is_multi_sim = 10;
+  // Count of how many satellite sessions have been opened
+  optional int32 count_of_satellite_sessions = 11;
+  // Whether the service is Carrier Roaming NB-Iot NTN network or not.
+  optional bool is_nb_iot_ntn = 12;
 }
 
 /**
@@ -362,6 +392,12 @@ message SatelliteEntitlement {
   optional bool is_retry = 4;
   // Total number of times this event has occurred
   optional int32 count = 5;
+  // allowed service entitlement status
+  optional bool is_allowed_service_entitlement = 6;
+  // service type entitlement
+  repeated int32 entitlement_service_type = 7;
+  // data policy entitlement
+  optional android.telephony.SatelliteEntitlementServicePolicy entitlement_data_policy = 8;
 }
 
 /**
diff --git a/stats/atoms/telephony/security/security_extension_atoms.proto b/stats/atoms/telephony/security/security_extension_atoms.proto
index b9be626d..47d7bbc8 100644
--- a/stats/atoms/telephony/security/security_extension_atoms.proto
+++ b/stats/atoms/telephony/security/security_extension_atoms.proto
@@ -20,7 +20,6 @@ package android.os.statsd.telephony;
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/atoms.proto";
-import "frameworks/proto_logging/stats/enums/telephony/enums.proto";
 import "frameworks/proto_logging/stats/enums/telephony/security/enums.proto";
 
 option java_package = "com.android.os.telephony";
diff --git a/stats/atoms/uprobestats/uprobestats_extension_atoms.proto b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
index 02e06893..b3ffed08 100644
--- a/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
+++ b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
@@ -19,12 +19,16 @@ syntax = "proto2";
 package android.os.statsd.uprobestats;
 
 import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
 
 option java_package = "com.android.os.uprobestats";
 option java_multiple_files = true;
 
 extend Atom {
   optional TestUprobeStatsAtomReported test_uprobestats_atom_reported = 915;
+  optional SetComponentEnabledSettingReported set_component_enabled_setting_reported = 1018 [(module) = "uprobestats"];
+  optional BalProcessControllerAddBoundClientUidReported bal_process_controller_add_bound_client_uid_reported = 1019 [deprecated = true];
+  optional BindServiceLockedWithBalFlagsReported bind_service_locked_with_bal_flags_reported = 1045;
 }
 
 /* Test atom, specifically for UprobeStats tests, not logged anywhere */
@@ -33,3 +37,101 @@ message TestUprobeStatsAtomReported {
     optional int64 second_field = 2;
     optional int64 third_field = 3;
 }
+
+/**
+  * Logged by uprobestats on sampled devices, when
+  * components have been enabled/disabled.
+  *
+  * This event happens quite frequently (multiple times per second) on boot,
+  * and rarely thereafter. Implementation filters out packages in the
+  * android and com.android namespaces, and states lower than
+  * COMPONENT_ENABLED_STATE_DISABLED, which suppresses
+  * nearly all of those early boot events.
+  *
+  * Given the above, expected logging rate is on the order of tens
+  * in a day.
+  */
+message SetComponentEnabledSettingReported {
+    optional string package_name = 1;
+    optional string class_name = 2;
+    optional int32 new_state = 3;
+    optional string calling_package_name = 4;
+}
+
+/**
+  * DEPRECATED - this message was never usesd and is replaced by
+  * BindServiceLockedWithBalFlagsReported.
+  *
+  * Logged by uprobestats on sampled devices, when
+  * unprivileged apps bind to privileged apps that
+  * are allowed to do BAL (e.g. apps managing companion devices).
+  *
+  * Expected logging rate is on the order of tens in a day.
+  */
+message BalProcessControllerAddBoundClientUidReported {
+    optional int32 client_uid = 1 [(is_uid) = true];
+    optional string client_package_name = 2;
+    optional int32 bind_flags = 3;
+}
+
+/**
+  * Flags that can be passed to Context.bindService.
+  *
+  * This should be kept in sync with the `BIND_` flags in
+  * frameworks/base/core/java/android/content/Context.java.
+  */
+enum BindServiceFlags {
+    UNSPECIFIED = 0;
+    BIND_AUTO_CREATE = 0x0001;
+    BIND_DEBUG_UNBIND = 0x0002;
+    BIND_NOT_FOREGROUND = 0x0004;
+    BIND_ABOVE_CLIENT = 0x0008;
+    BIND_ALLOW_OOM_MANAGEMENT = 0x0010;
+    BIND_WAIVE_PRIORITY = 0x0020;
+    BIND_IMPORTANT = 0x0040;
+    BIND_ADJUST_WITH_ACTIVITY = 0x0080;
+    BIND_NOT_PERCEPTIBLE = 0x00000100;
+    BIND_ALLOW_ACTIVITY_STARTS = 0X000000200;
+    BIND_INCLUDE_CAPABILITIES = 0x000001000;
+    BIND_SHARED_ISOLATED_PROCESS = 0x00002000;
+    BIND_PACKAGE_ISOLATED_PROCESS = 0x4000; // 1 << 14
+    BIND_NOT_APP_COMPONENT_USAGE = 0x00008000;
+    BIND_ALMOST_PERCEPTIBLE = 0x000010000;
+    BIND_BYPASS_POWER_NETWORK_RESTRICTIONS = 0x00020000;
+    BIND_ALLOW_FOREGROUND_SERVICE_STARTS_FROM_BACKGROUND = 0x00040000;
+    BIND_SCHEDULE_LIKE_TOP_APP = 0x00080000;
+    BIND_ALLOW_BACKGROUND_ACTIVITY_STARTS = 0x00100000;
+    BIND_RESTRICT_ASSOCIATIONS = 0x00200000;
+    BIND_ALLOW_INSTANT = 0x00400000;
+    BIND_IMPORTANT_BACKGROUND = 0x00800000;
+    BIND_ALLOW_WHITELIST_MANAGEMENT = 0x01000000;
+    BIND_FOREGROUND_SERVICE_WHILE_AWAKE = 0x02000000;
+    BIND_FOREGROUND_SERVICE = 0x04000000;
+    BIND_TREAT_LIKE_ACTIVITY = 0x08000000;
+    // @deprecated Repurposed to {@link #BIND_TREAT_LIKE_VISIBLE_FOREGROUND_SERVICE}.
+    // BIND_VISIBLE = 0x10000000;
+    BIND_TREAT_LIKE_VISIBLE_FOREGROUND_SERVICE = 0x10000000;
+    BIND_SHOWING_UI = 0x20000000;
+    BIND_NOT_VISIBLE = 0x40000000;
+    // java.lang.Long flags that are not supported by proto enum.
+    // BIND_EXTERNAL_SERVICE = 0x80000000;
+    // BIND_EXTERNAL_SERVICE_LONG = 0x4000000000000000; // 1L << 62
+    // BIND_BYPASS_USER_NETWORK_RESTRICTIONS = 0x100000000; // 0x1_0000_0000L
+    // BIND_MATCH_QUARANTINED_COMPONENTS = 0x200000000 // 0x2_0000_0000L
+    // BIND_ALLOW_FREEZE = 0x400000000; // 0x4_0000_0000L
+}
+
+/**
+  * Logged by uprobestats on sampled devices, when
+  * unprivileged apps bind to privileged apps that
+  * are allowed to do BAL (e.g. apps managing companion devices).
+  *
+  * Expected logging rate is on the order of tens in a day.
+  */
+message BindServiceLockedWithBalFlagsReported {
+    optional string intent_package_name = 1;
+    // The flags passed to the bindServiceLocked call.
+    // Must be one or a combination of the types in BindServiceFlags enum above.
+    optional int64 flags = 2;
+    optional string calling_package_name = 3;
+}
diff --git a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
index 34d069c6..9f7e6a11 100644
--- a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
+++ b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
@@ -27,8 +27,9 @@ option java_multiple_files = true;
 
 extend Atom {
   optional MediatorUpdated mediator_updated = 721 [(module) = "wearconnectivity"];
+  // Deprecated, use proxy_bytes_transfer_by_fg_bg (10200) instead.
   optional SysproxyBluetoothBytesTransfer sysproxy_bluetooth_bytes_transfer = 10196
-      [(module) = "wearconnectivity"];
+      [(module) = "wearconnectivity", deprecated = true];
   optional SysproxyConnectionUpdated sysproxy_connection_updated = 786
       [(module) = "wearconnectivity"];
   optional WearCompanionConnectionState wear_companion_connection_state = 921
@@ -67,6 +68,10 @@ message MediatorUpdated {
 
   // Count of times the linger canceled before the action was actually performed.
   optional int32 linger_canceled_count = 7;
+
+  // Bluetooth Transport used for Sysproxy on this device. This does NOT imply whether Sysproxy is
+  // connected or not.
+  optional com.google.android.wearable.connectivity.SysproxyTransportType sysproxy_transport_type = 8;
 }
 
 /**
@@ -110,6 +115,9 @@ message SysproxyConnectionUpdated {
 
   // timestamp when reason was determined
   optional int64 reason_timestamp_millis = 6;
+
+  // Bluetooth Transport used for the current Sysproxy connection
+  optional com.google.android.wearable.connectivity.SysproxyTransportType transport_type = 7;
 }
 
 /**
diff --git a/stats/atoms/wearservices/wearservices_extension_atoms.proto b/stats/atoms/wearservices/wearservices_extension_atoms.proto
index 146021d9..011851f0 100644
--- a/stats/atoms/wearservices/wearservices_extension_atoms.proto
+++ b/stats/atoms/wearservices/wearservices_extension_atoms.proto
@@ -69,6 +69,12 @@ extend Atom {
   optional WsBugreportEventReported ws_bugreport_event_reported = 964
       [(module) = "wearservices"];
 
+  optional WsNotificationApiUsageReported ws_notification_api_usage_reported = 1005
+      [(module) = "wearservices"];
+
+  optional WsRemoteInteractionsApiUsageReported ws_remote_interactions_api_usage_reported = 1012
+      [(module) = "wearservices"];
+
   // Pulled Atom
   optional WsStandaloneModeSnapshot ws_standalone_mode_snapshot = 10197
       [(module) = "wearservices"];
@@ -416,6 +422,9 @@ message WsBugreportEventReported {
   // Depicts the duration of the bugreport event in seconds.
   // It's set only for EVENT_BUGREPORT_FINISHED and EVENT_BUGREPORT_RESULT_RECEIVED.
   optional int32 bugreport_event_duration_seconds = 5;
+
+  // Depics the failure reason in case the bugreport event contains a failure.
+  optional android.app.wearservices.BugreportFailureReason failure_reason = 6;
 }
 
 /** Logged when notification ID dismissal was synchronised between devices. */
@@ -430,3 +439,31 @@ message WsNotificationManagedDismissalSync {
   // Size of the payload in bytes
   optional int32 payload_size_bytes = 3;
 }
+
+/**
+ * Logged when notification API is called.
+ *
+ * Logged from:
+ * vendor/google_clockwork_partners/packages/WearServices/src/com/google/wear/services/notification/api/NotificationApiImpl.java
+ */
+message WsNotificationApiUsageReported {
+  // Name of the Notification API usage reported.
+  optional android.app.wearservices.NotificationApiName api_name = 1;
+
+  // Status of the Notification API usage reported.
+  optional android.app.wearservices.NotificationApiStatus api_status = 2;
+}
+
+/**
+ * Logged when remote interactions API is called.
+ *
+ * Logged from:
+ * vendor/google_clockwork_partners/packages/WearServices/src/com/google/wear/services/remoteinteractions
+ */
+message WsRemoteInteractionsApiUsageReported {
+  // Package uid of the application that created the remote interactions request.
+  optional int32 remote_interactions_package_uid = 1 [(is_uid) = true];
+
+  // Indicates the state of the remote interactions.
+  optional android.app.wearservices.RemoteInteractionsState remote_interactions_state = 2;
+}
diff --git a/stats/atoms/wifi/wifi_extension_atoms.proto b/stats/atoms/wifi/wifi_extension_atoms.proto
index fbd381a5..28ee34f9 100644
--- a/stats/atoms/wifi/wifi_extension_atoms.proto
+++ b/stats/atoms/wifi/wifi_extension_atoms.proto
@@ -52,6 +52,8 @@ extend Atom {
     optional WifiApCapabilitiesReported wifi_ap_capabilities_reported= 723 [(module) = "wifi"];
     optional SoftApStateChanged soft_ap_state_changed = 805 [(module) = "wifi"];
     optional ScorerPredictionResultReported scorer_prediction_result_reported = 884 [(module) = "wifi"];
+    optional WifiSoftApCallbackOnClientsDisconnected wifi_soft_ap_callback_on_clients_disconnected
+        = 1010 [(module) = "wifi"];
 
     // Pull metrics
     optional WifiAwareCapabilities wifi_aware_capabilities = 10190 [(module) = "wifi"];
@@ -772,3 +774,81 @@ message ScorerPredictionResultReported {
     // ThroughputPredictor calculated link speed is sufficient in the upstream direction.
     optional TrueFalseUnknown speed_sufficient_throughput_predictor_us = 11;
 }
+
+/**
+ * Logged when clients disconnect from a soft AP instance.
+ */
+message WifiSoftApCallbackOnClientsDisconnected {
+    /**
+     * Reason for disconnection.
+     * @see: packages/modules/Wifi/framework/java/android/net/wifi/DeauthenticationReasonCode.java
+     */
+    enum DisconnectReason {
+        UNKNOWN = 0;
+        UNSPECIFIED = 1;
+        PREV_AUTH_NOT_VALID = 2;
+        DEAUTH_LEAVING = 3;
+        DISASSOC_DUE_TO_INACTIVITY = 4;
+        DISASSOC_AP_BUSY = 5;
+        CLASS2_FRAME_FROM_NONAUTH_STA = 6;
+        CLASS3_FRAME_FROM_NONASSOC_STA = 7;
+        DISASSOC_STA_HAS_LEFT = 8;
+        STA_REQ_ASSOC_WITHOUT_AUTH = 9;
+        PWR_CAPABILITY_NOT_VALID = 10;
+        SUPPORTED_CHANNEL_NOT_VALID = 11;
+        BSS_TRANSITION_DISASSOC = 12;
+        INVALID_IE = 13;
+        MICHAEL_MIC_FAILURE = 14;
+        FOURWAY_HANDSHAKE_TIMEOUT = 15;
+        GROUP_KEY_UPDATE_TIMEOUT = 16;
+        IE_IN_4WAY_DIFFERS = 17;
+        GROUP_CIPHER_NOT_VALID = 18;
+        PAIRWISE_CIPHER_NOT_VALID = 19;
+        AKMP_NOT_VALID = 20;
+        UNSUPPORTED_RSN_IE_VERSION = 21;
+        INVALID_RSN_IE_CAPAB = 22;
+        IEEE_802_1X_AUTH_FAILED = 23;
+        CIPHER_SUITE_REJECTED = 24;
+        TDLS_TEARDOWN_UNREACHABLE = 25;
+        TDLS_TEARDOWN_UNSPECIFIED = 26;
+        SSP_REQUESTED_DISASSOC = 27;
+        NO_SSP_ROAMING_AGREEMENT = 28;
+        BAD_CIPHER_OR_AKM = 29;
+        NOT_AUTHORIZED_THIS_LOCATION = 30;
+        SERVICE_CHANGE_PRECLUDES_TS = 31;
+        UNSPECIFIED_QOS_REASON = 32;
+        NOT_ENOUGH_BANDWIDTH = 33;
+        DISASSOC_LOW_ACK = 34;
+        EXCEEDED_TXOP = 35;
+        STA_LEAVING = 36;
+        END_TS_BA_DLS = 37;
+        UNKNOWN_TS_BA = 38;
+        TIMEOUT = 39;
+        PEERKEY_MISMATCH = 45;
+        AUTHORIZED_ACCESS_LIMIT_REACHED = 46;
+        EXTERNAL_SERVICE_REQUIREMENTS = 47;
+        INVALID_FT_ACTION_FRAME_COUNT = 48;
+        INVALID_PMKID = 49;
+        INVALID_MDE = 50;
+        INVALID_FTE = 51;
+        MESH_PEERING_CANCELLED = 52;
+        MESH_MAX_PEERS = 53;
+        MESH_CONFIG_POLICY_VIOLATION = 54;
+        MESH_CLOSE_RCVD = 55;
+        MESH_MAX_RETRIES = 56;
+        MESH_CONFIRM_TIMEOUT = 57;
+        MESH_INVALID_GTK = 58;
+        MESH_INCONSISTENT_PARAMS = 59;
+        MESH_INVALID_SECURITY_CAP = 60;
+        MESH_PATH_ERROR_NO_PROXY_INFO = 61;
+        MESH_PATH_ERROR_NO_FORWARDING_INFO = 62;
+        MESH_PATH_ERROR_DEST_UNREACHABLE = 63;
+        MAC_ADDRESS_ALREADY_EXISTS_IN_MBSS = 64;
+        MESH_CHANNEL_SWITCH_REGULATORY_REQ = 65;
+        MESH_CHANNEL_SWITCH_UNSPECIFIED = 66;
+    }
+    // Disconnect reason from WifiClient
+    optional DisconnectReason disconnect_reason = 1;
+    // The uid of the SoftAp creator
+    optional int32 uid = 2 [(is_uid) = true];
+}
diff --git a/stats/atoms/xr/recorder/xr_recorder_extension_atoms.proto b/stats/atoms/xr/recorder/xr_recorder_extension_atoms.proto
new file mode 100644
index 00000000..77d986d6
--- /dev/null
+++ b/stats/atoms/xr/recorder/xr_recorder_extension_atoms.proto
@@ -0,0 +1,57 @@
+/*
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
+syntax = "proto2";
+
+package android.os.statsd.wifi.xr.recorder;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.xr.recorder";
+option java_multiple_files = true;
+
+extend Atom {
+  // Push metrics
+  optional XrRecorderSessionStatusReported xr_recorder_session_status_reported = 1033
+      [(module) = "xr"];
+}
+
+/*
+ * Logs when the Recorder changes state. Only called if the Recorder is being
+ * used.
+ *
+ * Logged from:
+ * google3/vr/perception/tracking/head/apps/moohan_data_capture/java/com/google/android/goggles/apps/recorder/RecorderActivity.java
+ *
+ * Estimated Logging Rate:
+ * Peak: 2 times in 1 second | Avg: 10 per device per day (assuming feature is
+ * used, otherwise 0)
+ *
+ */
+message XrRecorderSessionStatusReported {
+
+  optional XrRecorderSessionState session_state = 1;
+
+  // Time elapsed since the session started
+  optional int64 duration_ms = 2;
+}
+
+enum XrRecorderSessionState {
+  XR_RECORDER_SESSION_UNSPECIFIED = 0;
+  XR_RECORDER_SESSION_START = 1;
+  XR_RECORDER_SESSION_STOP = 2;
+}
diff --git a/stats/enums/accounts/enums.proto b/stats/enums/accounts/enums.proto
index 11f53169..4cef26aa 100644
--- a/stats/enums/accounts/enums.proto
+++ b/stats/enums/accounts/enums.proto
@@ -33,4 +33,6 @@ enum AccountEventType {
   USER_DATA_CHANGED = 6;
   // Token is stored in AccountManagerService cache.
   TOKEN_CACHED = 7;
+  // Logged from AccountManagerService.checkKeyIntent
+  CHECK_KEY_INTENT_FAILED = 8;
 }
diff --git a/stats/enums/adservices/common/OWNERS b/stats/enums/adservices/common/OWNERS
new file mode 100644
index 00000000..bbf707fd
--- /dev/null
+++ b/stats/enums/adservices/common/OWNERS
@@ -0,0 +1,22 @@
+abmehta@google.com
+adarshsridhar@google.com
+adigupt@google.com
+arpanah@google.com
+binhnguyen@google.com
+feifeiji@google.com
+felipeal@google.com
+fumengyao@google.com
+galarragas@google.com
+giladbarkan@google.com
+hanlixy@google.com
+jorgesaldivar@google.com
+karthikmahesh@google.com
+ktjen@google.com
+lmohanan@google.com
+niagra@google.com
+qiaoli@google.com
+shwetachahar@google.com
+tccyp@google.com
+vikassahu@google.com
+yangwangyw@google.com
+zelarabaty@google.com
\ No newline at end of file
diff --git a/stats/enums/adservices/common/adservices_api_metrics_enums.proto b/stats/enums/adservices/common/adservices_api_metrics_enums.proto
index 449569db..6cdf616d 100644
--- a/stats/enums/adservices/common/adservices_api_metrics_enums.proto
+++ b/stats/enums/adservices/common/adservices_api_metrics_enums.proto
@@ -108,4 +108,9 @@ enum AdServicesApiName {
   SCHEDULE_TRAINING = 34;
   RECORD_IMPRESSION = 35;
   RECORD_CLICK = 36;
+  GET_BEST_VALUE = 37;
+  RECORD_CONVERSION = 38;
+  RUN_MODEL_INFERENCE = 39;
+  APP_TO_WEB_CONVERSION = 40;
+  CUSTOMIZE_ERROR_CODE = 41;
 }
\ No newline at end of file
diff --git a/stats/enums/adservices/common/adservices_cel_enums.proto b/stats/enums/adservices/common/adservices_cel_enums.proto
index 0b4d34b5..742f8181 100644
--- a/stats/enums/adservices/common/adservices_cel_enums.proto
+++ b/stats/enums/adservices/common/adservices_cel_enums.proto
@@ -132,7 +132,7 @@ enum ErrorCode {
   // Package Deny process failure service disabled.
   PACKAGE_DENY_PROCESS_ERROR_DISABLED = 33;
 
-  // SPE Errors: 901 - 1000
+  // SPE Errors: 901 - 930
   // Get an unavailable job execution start timestamp when calculating the execution latency.
   SPE_UNAVAILABLE_JOB_EXECUTION_START_TIMESTAMP = 901;
 
@@ -166,6 +166,17 @@ enum ErrorCode {
   // Error during future cancellation process.
   SPE_FUTURE_CANCELLATION_ERROR = 911;
 
+  // Error when JobScheduler tries to schedule a job but the app has scheduled more than 150 jobs.
+  SPE_JOB_SCHEDULING_FAILURE_ON_TOO_MANY_SCHEDULED_JOBS = 912;
+
+  // Process Stable Flags Error: 931 - 940
+  // The flag initialization takes too long and exceeds the threshold.
+  PROCESS_STABLE_FLAGS_FLAG_INIT_TIMEOUT = 931;
+  // The flag initialization encounters error.
+  PROCESS_STABLE_FLAGS_FLAG_INIT_ERROR = 932;
+  // The flag initialization future encounters issue when calling get().
+  PROCESS_STABLE_FLAGS_INIT_FUTURE_GET_ERROR = 933;
+
   // Topics errors: 1001-2000
   // Remote exception when calling get topics.
   GET_TOPICS_REMOTE_EXCEPTION = 1001;
@@ -387,6 +398,9 @@ enum ErrorCode {
   // Error occurred when trying to initialize cobalt logger for measurement metrics.
   MEASUREMENT_COBALT_LOGGER_INITIALIZATION_FAILURE = 2022;
 
+  // Error occurred when trying to validate the UID of the calling app.
+  MEASUREMENT_UID_CHECK_FAILURE = 2023;
+
   // Fledge (PA), PAS errors: 3001 - 4000
   // Exception while PAS unable to find the service.
   PAS_UNABLE_FIND_SERVICES = 3001;
@@ -1233,6 +1247,18 @@ enum ErrorCode {
   // Error occurred when failed to schedule an CA update when fail to notify failure to the caller.
   SCHEDULE_CUSTOM_AUDIENCE_UPDATE_IMPL_NOTIFY_FAILURE_TO_CALLER_FAILED = 3276;
 
+  // Error during decryption because context was not found in the database.
+  OBLIVIOUS_HTTP_ENCRYPTOR_CONTEXT_NOT_FOUND = 3277;
+
+  // Error during parsing auction result: data compression of given version is not found.
+  PERSIST_AD_SELECTION_RESULT_PARSING_RESPONSE_DATA_COMPRESSION_NOT_FOUND = 3278;
+
+  // Error during parsing auction result: payload extractor  of given version is not found.
+  PERSIST_AD_SELECTION_RESULT_PARSING_RESPONSE_PAYLOAD_EXTRACTOR_NOT_FOUND = 3279;
+
+  // Error during parsing auction result: data size is greater than payload size.
+  PERSIST_AD_SELECTION_RESULT_PARSING_RESPONSE_DATA_SIZE_GREATER_THAN_PAYLOAD_SIZE = 3280;
+
   // UX errors: 4001-5000
   CONSENT_REVOKED_ERROR = 4001;
 
diff --git a/stats/enums/adservices/common/adservices_enums.proto b/stats/enums/adservices/common/adservices_enums.proto
index b31de9c9..95f923ce 100644
--- a/stats/enums/adservices/common/adservices_enums.proto
+++ b/stats/enums/adservices/common/adservices_enums.proto
@@ -94,6 +94,8 @@ enum PpapiName {
   // Represents reportImpression API of B&A
   REPORT_IMPRESSION = 14;
   // Represents reportInteraction API of B&A
+  // The name reportInteraction maps to AdSelectionServiceImpl#reportInteraction, while the caller
+  // is AdSelectionManager#reportEvent.
   REPORT_INTERACTION = 15;
   // Represents joinCustomAudience API of FLEDGE.
   JOIN_CUSTOM_AUDIENCE = 16;
@@ -240,6 +242,8 @@ enum Command {
   COMMAND_ENABLE_ADSERVICES = 7;
   COMMAND_RESET_CONSENT_DATA = 8;
   COMMAND_DEV_SESSION = 9;  // Command to enable or disable adservices developer mode.
+  COMMAND_SET_USER_CHOICES = 10;
+  COMMAND_SET_MODULE_STATES = 11;
 
   // Custom audience commands: 101-200
   COMMAND_CUSTOM_AUDIENCE_VIEW = 101;
@@ -262,6 +266,10 @@ enum Command {
 
   // Attribution-reporting commands: 401-500
   COMMAND_ATTRIBUTION_REPORTING_LIST_SOURCE_REGISTRATIONS = 401;
+  COMMAND_ATTRIBUTION_REPORTING_LIST_TRIGGER_REGISTRATIONS = 402;
+  COMMAND_ATTRIBUTION_REPORTING_LIST_EVENT_REPORTS = 403;
+  COMMAND_ATTRIBUTION_REPORTING_LIST_AGGREGATE_REPORTS = 404;
+  COMMAND_ATTRIBUTION_REPORTING_LIST_DEBUG_REPORTS = 405;
 }
 
 // Result of the shell command
@@ -273,6 +281,7 @@ enum CommandResult {
   COMMAND_RESULT_TIMEOUT_ERROR = 4;
   COMMAND_RESULT_INVALID_COMMAND = 5;
   COMMAND_RESULT_NOT_ENABLED = 6;
+  COMMAND_RESULT_DEV_MODE_UNCONFIRMED = 7;
 }
 
 // Cobalt logging event
diff --git a/stats/enums/adservices/fledge/enums.proto b/stats/enums/adservices/fledge/enums.proto
index 52aba9ea..486414f7 100644
--- a/stats/enums/adservices/fledge/enums.proto
+++ b/stats/enums/adservices/fledge/enums.proto
@@ -151,3 +151,31 @@ enum PayloadOptimizationResult {
   // there was not enough data on the device so the max was not reached
   PAYLOAD_WITHIN_REQUESTED_MAX = 2;
 }
+
+/** Enum denoting the type of reporting. */
+enum ReportingType {
+  UNSET_REPORTING_TYPE = 0;
+  REPORT_IMPRESSION = 1;
+  REPORT_EVENT = 2;
+}
+
+/** Enum denoting the status of the Report Impression / Report Event call. */
+enum ReportingCallStatus {
+  UNSET_REPORTING_CALL_STATUS = 0;
+  SUCCESSFUL = 1;
+  HTTP_TOO_MANY_REQUESTS = 2;
+  HTTP_REDIRECTION = 3;
+  HTTP_CLIENT_ERROR = 4;
+  HTTP_SERVER_ERROR = 5;
+  HTTP_IO_EXCEPTION = 6;
+  FAILURE_HTTP_NETWORK_NOT_AVAILABLE = 7;
+  FAILURE_UNKNOWN = 8;
+}
+
+/** Enum representing the destination for the Report Impression / Report Event call. */
+enum ReportingCallDestination {
+  UNSET_REPORTING_CALL_DESTINATION = 0;
+  SELLER = 1;
+  BUYER = 2;
+  COMPONENT_SELLER = 3;
+}
diff --git a/stats/enums/app/settings/OWNERS b/stats/enums/app/settings/OWNERS
new file mode 100644
index 00000000..dae5079b
--- /dev/null
+++ b/stats/enums/app/settings/OWNERS
@@ -0,0 +1,2 @@
+noshinmir@google.com
+akaustubh@google.com
diff --git a/stats/enums/app/settings_enums.proto b/stats/enums/app/settings/settings_enums.proto
similarity index 91%
rename from stats/enums/app/settings_enums.proto
rename to stats/enums/app/settings/settings_enums.proto
index 00af214f..7edd4d76 100644
--- a/stats/enums/app/settings_enums.proto
+++ b/stats/enums/app/settings/settings_enums.proto
@@ -23,6 +23,10 @@ option java_multiple_files = true;
  * The action performed in this event
  */
 enum Action {
+
+    // Reserved for biometrics
+    reserved 2145 to 2151;
+
     ACTION_UNKNOWN = 0;
     PAGE_VISIBLE = 1;
     PAGE_HIDE = 2;
@@ -1988,6 +1992,267 @@ enum Action {
     //  SUBTYPE: default connection policy, false is forbidden, true is allowed
     // OS: V
     ACTION_BLUETOOTH_PROFILE_LE_AUDIO_OFF = 1980;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Bounce keys > Bounce keys dialog
+    // CATEGORY: SETTINGS
+    ACTION_BOUNCE_KEYS_CUSTOM_VALUE_CHANGE = 1981;
+
+    // ACTION: Settings > Keyboard > Physical keyboard
+    //         > Physical Keyboard accessibility > Slow keys > Slow keys dialog
+    // CATEGORY: SETTINGS
+    ACTION_SLOW_KEYS_CUSTOM_VALUE_CHANGE = 1982;
+
+    // OPEN: Settings > System > Mouse -> Swap primary mouse button
+    // CATEGORY: SETTINGS
+    ACTION_MOUSE_SWAP_PRIMARY_BUTTON_ENABLED = 1983;
+    ACTION_MOUSE_SWAP_PRIMARY_BUTTON_DISABLED = 1984;
+
+    // OPEN: Settings > System > Mouse -> Reverse scrolling
+    // CATEGORY: SETTINGS
+    ACTION_MOUSE_REVERSE_VERTICAL_SCROLLING_ENABLED = 1985;
+    ACTION_MOUSE_REVERSE_VERTICAL_SCROLLING_DISABLED = 1986;
+
+    // OPEN: Settings > System > Language & region > Region > Change the region
+    //                > Show dialog > Click positive button
+    // CATEGORY: SETTINGS
+    ACTION_CHANGE_REGION_DIALOG_POSITIVE_BTN_CLICKED = 1987;
+
+    // OPEN: Settings > System > Language & region > Region > Change the region
+    //                > Show dialog > Click negative button
+    // CATEGORY: SETTINGS
+    ACTION_CHANGE_REGION_DIALOG_NEGATIVE_BTN_CLICKED = 1988;
+
+    // OPEN: Use ACTION_REGION_SETTINGS to open Settings > System
+    //       > Language & region > Region
+    // CATEGORY: SETTINGS
+    ACTION_OPEN_REGION_OUTSIDE_SETTINGS = 1989;
+
+    // OPEN: Use ACTION_FIRST_DAY_OF_WEEK_SETTINGS to open Settings > System
+    //       > Language & region > First day of week
+    // CATEGORY: SETTINGS
+    ACTION_OPEN_FIRST_DAY_OF_WEEK_OUTSIDE_SETTINGS = 1990;
+
+    // OPEN: Use ACTION_TEMPERATURE_UNIT_SETTINGS to open Settings > System
+    //       > Language & region > Temperature
+    // CATEGORY: SETTINGS
+    ACTION_OPEN_TEMPERATURE_UNIT_OUTSIDE_SETTINGS = 1991;
+
+    // OPEN: Use ACTION_NUMBERING_SYSTEM_SETTINGS to open Settings > System
+    //       > Language & region > Numbers preferences
+    // CATEGORY: SETTINGS
+    ACTION_OPEN_NUMBERING_SYSTEM_OUTSIDE_SETTINGS = 1992;
+
+    // OPEN: Use ACTION_MEASUREMENT_SYSTEM_SETTINGS to open Settings > System
+    //       > Language & region > Measurement system
+    // CATEGORY: SETTINGS
+    ACTION_OPEN_MEASUREMENT_SYSTEM_OUTSIDE_SETTINGS = 1993;
+
+    // OPEN: Settings > System > Mouse -> Controlled scrolling
+    // CATEGORY: SETTINGS
+    ACTION_MOUSE_SCROLLING_ACCELERATION_ENABLED = 1994;
+    ACTION_MOUSE_SCROLLING_ACCELERATION_DISABLED = 1995;
+
+    // OPEN: Settings > System > Mouse -> Scrolling speed
+    // CATEGORY: SETTINGS
+    // VALUE: mouse scrolling speed
+    ACTION_MOUSE_SCROLLING_SPEED_CHANGED = 1996;
+
+    // ACTION: Settings > Network & internet > SIMs > Mobile data
+    // CATEGORY: SETTINGS
+    ACTION_MOBILE_DATA = 1997;
+
+    // ACTION: Settings > Network & internet > SIMs > {network} > Wi-Fi calling > Use Wi-Fi calling
+    // CATEGORY: SETTINGS
+    ACTION_WIFI_CALLING = 1998;
+
+    // ACTION: Settings > Network & Internet > Adaptive connectivity > Use Adaptive connectivity
+    // CATEGORY: SETTINGS
+    ACTION_ADAPTIVE_CONNECTIVITY = 1999;
+
+    // ACTION: Settings > Network & Internet > Internet > Wi-Fi
+    // CATEGORY: SETTINGS
+    ACTION_WIFI = 2000;
+
+    // ACTION: Settings > Network & Internet > Hotspot & tethering > Wi-Fi hotspot
+    // CATEGORY: SETTINGS
+    ACTION_WIFI_HOTSPOT = 2001;
+
+    // ACTION: Settings > Battery > Battery Saver > Use Battery Saver
+    // CATEGORY: SETTINGS
+    ACTION_BATTERY_SAVER = 2002;
+
+    // ACTION: Settings > Battery > Battery Saver > Use Adaptive Battery
+    // CATEGORY: SETTINGS
+    ACTION_ADAPTIVE_BATTERY = 2003;
+
+    // ACTION: Settings > Battery > Battery Saver > Extreme Battery Saver
+    // CATEGORY: SETTINGS
+    ACTION_EXTREME_BATTERY_SAVER = 2004;
+
+    // ACTION: Settings > Battery
+    // CATEGORY: SETTINGS
+    ACTION_BATTERY_LEVEL = 2005;
+
+    // ACTION: Settings > Display & touch > Brightness level
+    // CATEGORY: SETTINGS
+    ACTION_BRIGHTNESS_LEVEL = 2006;
+
+    // ACTION: Settings > Display & touch > Adaptive brightness
+    // CATEGORY: SETTINGS
+    ACTION_ADAPTIVE_BRIGHTNESS = 2007;
+
+    // ACTION: Settings > Display & touch > Smooth display
+    // CATEGORY: SETTINGS
+    ACTION_SMOOTH_DISPLAY = 2008;
+
+    // ACTION: Settings > Display & touch > Dark theme
+    // CATEGORY: SETTINGS
+    ACTION_DARK_THEME = 2009;
+
+    // ACTION: Settings > Display & touch > Lock screen > Always show time and info
+    // CATEGORY: SETTINGS
+    ACTION_AMBIENT_DISPLAY_ALWAYS_ON = 2010;
+
+    // ACTION: Settings > Sound & vibration > Vibration & haptics > Use Vibration & haptics
+    // CATEGORY: SETTINGS
+    ACTION_VIBRATION_HAPTICS = 2011;
+
+    // ACTION: Settings > Sound & vibration > Media Volume
+    // CATEGORY: SETTINGS
+    ACTION_MEDIA_VOLUME = 2012;
+
+    // ACTION: Settings > Sound & vibration > Call volume
+    // CATEGORY: SETTINGS
+    ACTION_CALL_VOLUME = 2013;
+
+    // ACTION: Settings > Sound & vibration > Ring volume
+    // CATEGORY: SETTINGS
+    ACTION_RING_VOLUME = 2014;
+
+    // ACTION: Settings > Accessibility > Color and motion > Remove Animation
+    // CATEGORY: SETTINGS
+    ACTION_REMOVE_ANIMATION = 2015;
+
+    // ACTION: Bluetooth Sharing is triggered and Nearby Share entrypoint is shown
+    // CATEGORY: SETTINGS
+    ACTION_NEARBY_SHARE_ENTRYPOINT_SHOWN = 2016;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    ACTION_CHECK_FINGERPRINT_SETTINGS = 2017;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    ACTION_FINGERPRINTS_ENABLED_ON_KEYGUARD_SETTINGS = 2018;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    ACTION_FINGERPRINT_ENABLED_FOR_APP_SETTINGS = 2019;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    ACTION_FACE_ENABLED_ON_KEYGUARD_SETTINGS = 2020;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    ACTION_FACE_ENABLED_FOR_APP_SETTINGS = 2021;
+
+    // OPEN: Face Enroll SUW > Education
+    // CATEGORY: SETTINGS
+    ACTION_FACE_REQUIRE_ATTENTION_FROM_SUW = 2022;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    ACTION_FACE_REQUIRE_ATTENTION_FROM_SETTINGS = 2023;
+
+    // ACTION: Settings > Sound & vibration > Media > Pin media player
+    // CATEGORY: SETTINGS
+    ACTION_PIN_MEDIA_PLAYER = 2024;
+
+    // ACTION: Settings > Sound & vibration > Media > Show media on lock screen
+    // CATEGORY: SETTINGS
+    ACTION_SHOW_MEDIA_ON_LOCK_SCREEN = 2025;
+
+    // ACTION: Settings > Network & Internet > Adaptive connectivity > Auto-switch Wi-Fi to Cellular
+    // CATEGORY: SETTINGS
+    ACTION_ADAPTIVE_WIFI_SCORER = 2026;
+
+    // ACTION: Settings > Network & Internet > Adaptive connectivity > Auto-switch mobile network for battery life
+    // CATEGORY: SETTINGS
+    ACTION_ADAPTIVE_MOBILE_NETWORK = 2027;
+
+    // OPEN: Settings > System > Language & region > Region > Change the region
+    //                > Show dialog for the preferred language
+    //                > Click positive button
+    // CATEGORY: SETTINGS
+    ACTION_CHANGE_PREFERRED_LANGUAGE_REGION_POSITIVE_BTN_CLICKED = 2028;
+
+    // OPEN: Settings > System > Language & region > Region > Change the region
+    //                > Show dialog for the preferred language
+    //                > Click negative button
+    // CATEGORY: SETTINGS
+    ACTION_CHANGE_PREFERRED_LANGUAGE_REGION_NEGATIVE_BTN_CLICKED = 2029;
+
+    // OPEN: Settings > System > Language & region > System Languages
+    //                > Add a language > Search language
+    //                > Choose a language
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_LANGUAGE_AFTER_SEARCH_LANGUAGE = 2030;
+
+    // OPEN: Settings > System > Language & region > System Languages
+    //                > Add a language > Choose a language
+    //                > Search region > Choose a region
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_REGION_AFTER_SEARCH_REGION = 2031;
+
+    // OPEN: Settings > System > Language & region > System Languages
+    //                > Add a language > Search language
+    //                > No preferred language(click back key)
+    // CATEGORY: SETTINGS
+    ACTION_NO_PREFERRED_LANGUAGE_AFTER_SEARCH_LANGUAGE = 2032;
+
+    // OPEN: Settings > System > Language & region > System Languages
+    //                > Add a language > Choose a language
+    //                > Search region > No preferred region(click back key)
+    // CATEGORY: SETTINGS
+    ACTION_NO_PREFERRED_REGION_AFTER_SEARCH_REGION = 2033;
+
+    // OPEN: SUW Welcome Screen > Language picker page > region picker page
+    //                          > search region page > search region
+    //                          > Choose a region
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_REGION_AFTER_SEARCH_REGION_IN_SUW = 2034;
+
+    // OPEN: SUW Welcome Screen > Language picker page > region picker page
+    //                          > search region page > search region
+    //                          > No preferred region(click back key)
+    // CATEGORY: SETTINGS
+    ACTION_NO_PREFERRED_REGION_AFTER_SEARCH_REGION_IN_SUW = 2035;
+
+    // OPEN: SUW Welcome Screen > Language picker page
+    //                          > Choose a language from the suggested list
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_PREFERRED_LANGUAGE_FROM_SUGGESTED_LIST_IN_SUW = 2036;
+
+    // OPEN: SUW Welcome Screen > Language picker page > region picker page
+    //                          > Choose a region from the suggested list
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_PREFERRED_REGION_FROM_SUGGESTED_LIST_IN_SUW = 2037;
+
+    // OPEN: SUW Welcome Screen > Language picker page
+    //                          > Choose a language from the all languages list
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_PREFERRED_LANGUAGE_FROM_ALL_LIST_IN_SUW = 2038;
+
+    // OPEN: SUW Welcome Screen > Language picker page > region picker page
+    //                          > Choose a region from the all region list
+    // CATEGORY: SETTINGS
+    ACTION_CHOOSE_PREFERRED_REGION_FROM_ALL_LIST_IN_SUW = 2039;
+
+    // OPEN: SUW Welcome Screen > Set up using another device
+    // CATEGORY: SETTINGS
+    ACTION_RESTORE_SIMPLE_VIEW_RESULT_IN_SUW = 2040;
 }
 
 /**
@@ -5264,6 +5529,134 @@ enum PageId {
     // OPEN: Settings > Notifications > Notifications on lock screen
     // CATEGORY: SETTINGS
     SETTINGS_NOTIFICATIONS_ON_LOCK_SCREEN = 2132;
+
+    // OPEN: Settings -> Connected Devices -> Connection Preferences -> (select device)
+    // CATEGORY: SETTINGS
+    VIRTUAL_DEVICE_DETAILS = 2133;
+
+    // OPEN: Settings -> Connected Devices -> Connection Preferences -> (select device) -> Forget
+    // CATEGORY: SETTINGS
+    DIALOG_VIRTUAL_DEVICE_FORGET = 2134;
+
+    // Settings -> Keyboard -> Physical keyboard -> Physical keyboard accessibility -> Repeat keys
+    // CATEGORY: SETTINGS
+    PHYSICAL_KEYBOARD_REPEAT_KEYS = 2135;
+
+    // OPEN: Settings > System > Language & region > Region > Region settings
+    // CATEGORY: SETTINGS
+    REGION_SETTINGS = 2136;
+
+    // OPEN: Settings > System > Language & region > Region > Change the region
+    //                > Show dialog
+    // CATEGORY: SETTINGS
+    CHANGE_REGION_DIALOG = 2137;
+
+    // ACTION: Settings > Network & internet > Hotspot & tethering > Wi-Fi hotspot toggle
+    //   SUBTYPE: 0 is off, 1 is on
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to Action.ACTION_WIFI_HOTSPOT
+    ACTION_WIFI_HOTSPOT_TOGGLE = 2138 [deprecated = true];
+
+    // Settings -> Supervision
+    // CATEGORY: SETTINGS
+    SUPERVISION_DASHBOARD = 2139;
+
+    // ACTION: Settings > Notifications > Summarized notifications
+    // CATEGORY: SETTINGS
+    SUMMARIZED_NOTIFICATIONS = 2140;
+
+    // OPEN: Settings > Network & internet > Ethernet
+    // CATEGORY: SETTINGS
+    ETHERNET_SETTINGS = 2141;
+
+    // OPEN: Settings > Network & internet > SIMs > {network} > Satellite messaging -> see all apps
+    // CATEGORY: SETTINGS
+    SATELLITE_APPS_LIST = 2142;
+
+    // OPEN: Settings > Audio stream confirm dialog > Turn off talkback dialog
+    // CATEGORY: SETTINGS
+    DIALOG_AUDIO_STREAM_CONFIRM_TURN_OFF_TALKBACK = 2143;
+
+    // OPEN: Settings > Connected devices > Connection preferences > Audio sharing > Audio stream
+    //       > Turn off talkback dialog
+    // CATEGORY: SETTINGS
+    DIALOG_AUDIO_STREAM_MAIN_TURN_OFF_TALKBACK = 2144;
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_CHECK_FINGERPRINT_SETTINGS
+    ACTION_CHECK_FINGERPRINT = 2145 [deprecated = true];
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FINGERPRINT_ENABLED_ON_KEYGUARD_SETTINGS
+    ACTION_FINGERPRINT_ENABLED_ON_KEYGUARD = 2146 [deprecated = true];
+
+    // ACTION: Settings > Security & privacy > Device unlock > Fingerprint
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FINGERPRINT_ENABLED_FOR_APP_SETTINGS
+    ACTION_FINGERPRINT_ENABLED_FOR_APP = 2147 [deprecated = true];
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FACE_ENABLED_ON_KEYGUARD_SETTINGS
+    ACTION_FACE_ENABLED_ON_KEYGUARD = 2148 [deprecated = true];
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FACE_ENABLED_FOR_APP_SETTINGS
+    ACTION_FACE_ENABLED_FOR_APP = 2149 [deprecated = true];
+
+    // OPEN: Face Enroll SUW > Education
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FACE_REQUIRE_ATTENTION_FROM_SUW
+    ACTION_FACE_REQUIRE_ATTENTION_SUW = 2150 [deprecated = true];
+
+    // ACTION: Settings > Security & privacy > Device unlock > Face
+    // CATEGORY: SETTINGS
+    // DEPRECATED: This was added as page id by mistake, moved to
+    // Action.ACTION_FACE_REQUIRE_ATTENTION_FROM_SETTINGS
+    ACTION_FACE_REQUIRE_ATTENTION_SETTINGS = 2151 [deprecated = true];
+
+    // OPEN: Settings > Accessibility > Magnification > Cursor following
+    // CATEGORY: SETTINGS
+    DIALOG_MAGNIFICATION_CURSOR_FOLLOWING = 2152;
+
+    // OPEN: Settings > Display > Widgets on lock screen
+    // CATEGORY: SETTINGS
+    WIDGETS_ON_LOCK_SCREEN = 2153;
+
+    // OPEN: Settings > Display > Widgets on lockscreen > When to automatically
+    // show
+    // CATEGORY: SETTINGS
+    WHEN_TO_SHOW_WIDGETS_ON_LOCKSCREEN = 2154;
+
+    // OPEN: Settings > Audio stream confirm dialog > Audio sharing going on dialog
+    // CATEGORY: SETTINGS
+    DIALOG_AUDIO_STREAM_CONFIRM_TURN_OFF_AUDIO_SHARING = 2155;
+
+    // OPEN: SUW Welcome Screen > Language picker page
+    // CATEGORY: SETTINGS
+    LANGUAGE_PICKER_IN_SUW = 2156;
+
+    // OPEN: SUW Welcome Screen > Language picker page > Region picker
+    // CATEGORY: SETTINGS
+    REGION_PICKER_IN_SUW = 2157;
+
+    // OPEN: SUW Welcome Screen > Language picker page > Region picker
+    //                          > Search region
+    // CATEGORY: SETTINGS
+    REGION_SEARCH_IN_SUW = 2158;
+
+    // OPEN: Settings > Connected devices
+    // CATEGORY: SETTINGS
+    SETTINGS_CONNECTED_DEVICES_ENTRYPOINT = 2159;
 }
 
 // Battery Saver schedule types.
@@ -5313,3 +5706,29 @@ enum SimpleViewUsageTimeType {
     // disabled simple view over 1 week
     SIMPLE_VIEW_USAGE_TYPE_DISABLED_OVER_ONE_WEEK = 5;
 }
+
+// Settings External APIs request types
+enum ExtApiRequestType {
+    UNKNOWN_REQUEST = 0;
+    ACTION_READ = 1;
+    ACTION_WRITE = 2;
+    ACTION_GET_METADATA = 3;
+}
+
+// Result of requesting Settings data (ResultCode from GetSettingsValue and SetSettings)
+enum ExtApiResultType {
+    UNKNOWN_RESULT = 0;
+    RESULT_OK = 1;
+    // For all failures do not match below failure reason
+    RESULT_FAILURE = 2;
+    // Failures from read/write settings request
+    RESULT_FAILURE_UNSUPPORTED = 3;
+    RESULT_FAILURE_UNAVAILABLE = 4;
+    RESULT_FAILURE_REQUIRE_APP_PERMISSION = 5;
+    RESULT_FAILURE_DISALLOW = 6;
+    RESULT_FAILURE_INVALID_REQUEST = 7;
+    RESULT_FAILURE_INTERNAL_ERROR = 8;
+    RESULT_FAILURE_DISABLED = 9;
+    RESULT_FAILURE_RESTRICTED = 10;
+    RESULT_FAILURE_REQUIRE_USER_CONSENT = 11;
+}
diff --git a/stats/enums/app/wearservices/wearservices_enums.proto b/stats/enums/app/wearservices/wearservices_enums.proto
index e69494e8..c7e2325d 100644
--- a/stats/enums/app/wearservices/wearservices_enums.proto
+++ b/stats/enums/app/wearservices/wearservices_enums.proto
@@ -575,6 +575,58 @@ enum NotificationFlowComponent {
   NOTIFICATION_FLOW_COMPONENT_ACTION_EXECUTION = 3;
 }
 
+/** Defines the name for Notification API usage reported.
+ *
+ * API names are based on:
+ * vendor/google_clockwork_partners/packages/WearServices/src/com/google/wear/services/notification/api/NotificationApiImpl.java
+ *
+ * Next ID: 18
+ */
+enum NotificationApiName {
+  // Unknown value for backward compatibility
+  NOTIFICATION_API_NAME_UNKNOWN = 0;
+
+  NOTIFICATION_API_NAME_REGISTER_NOTIFICATION_EVENT_LISTENER = 1;
+  NOTIFICATION_API_NAME_UNREGISTER_NOTIFICATION_EVENT_LISTENER = 2;
+
+  NOTIFICATION_API_NAME_GET_ACTIVE_NOTIFICATIONS = 3;
+  NOTIFICATION_API_NAME_GET_ACTIVE_NOTIFICATIONS_BY_IDS = 4;
+
+  NOTIFICATION_API_NAME_GET_CURRENT_INTERRUPTION_FILTER = 5;
+  NOTIFICATION_API_NAME_REQUEST_INTERRUPTION_FILTER_UPDATE = 6;
+
+  NOTIFICATION_API_NAME_GET_CURRENT_LISTENER_HINTS = 7;
+  NOTIFICATION_API_NAME_REQUEST_LISTENER_HINTS_UPDATE = 8;
+
+  NOTIFICATION_API_NAME_GET_CURRENT_RANKING = 9;
+
+  NOTIFICATION_API_NAME_GET_NOTIFICATION_COUNT_DATA = 10;
+
+  NOTIFICATION_API_NAME_DISMISS_ALL = 11;
+  NOTIFICATION_API_NAME_DISMISS_MULTIPLE_FROM_UI = 12;
+
+  NOTIFICATION_API_NAME_IS_APP_MUTED = 13;
+  NOTIFICATION_API_NAME_GET_MUTED_APPS = 14;
+  NOTIFICATION_API_NAME_MUTE_APP = 15;
+  NOTIFICATION_API_NAME_UNMUTE_APP = 16;
+  NOTIFICATION_API_NAME_CAN_MUTE_APP = 17;
+}
+
+
+// Defines the notification api status for api usage reported.
+// Next ID: 3
+enum NotificationApiStatus {
+  // Unknown value for backward compatibility
+  NOTIFICATION_API_STATUS_UNKNOWN = 0;
+
+  // Notification status when API call is invoked
+  NOTIFICATION_API_STATUS_START = 1;
+
+  // Notification status when API call completes successfully
+  NOTIFICATION_API_STATUS_SUCCESS = 2;
+}
+
+
 // Defines which component the latency is being calculated for.
 // Next ID: 7
 enum ComponentName {
@@ -849,7 +901,7 @@ enum RemoteEventState {
   // Depicts a successful remote event response.
   REMOTE_EVENT_RESPONSE_SUCCESS = 2;
 
-  // Remote event with generic failure condition response which doesn't fail into any other
+  // Remote event with generic failure condition response which doesn't fall into any other
   // condition.
   REMOTE_EVENT_RESPONSE_FAILURE = 3;
 
@@ -883,6 +935,28 @@ enum RemoteEventState {
   REMOTE_EVENT_RESPONSE_REMOTE_NOT_SUPPORTED = 12;
 }
 
+// This enum depicts the state of the remote interactions.
+enum RemoteInteractionsState {
+  // Depicts an unknown remote interactions state.
+  REMOTE_INTERACTIONS_RESPONSE_UNKNOWN = 0;
+
+  // Depicts total number of times remote interactions API is invoked.
+  REMOTE_INTERACTIONS_API_INVOKED = 1;
+
+  // Depicts a successful remote interactions response.
+  REMOTE_INTERACTIONS_RESPONSE_SUCCESS = 2;
+
+  // Remote interactions coming from a background service are disallowed.
+  REMOTE_INTERACTIONS_RESPONSE_BACKGROUND_REQUEST_DISALLOWED = 3;
+
+  // Remote interactions with response not being received within the timeout period.
+  REMOTE_INTERACTIONS_RESPONSE_TIMEOUT = 4;
+
+  // Remote interactions with generic failure condition response which doesn't fall into any other
+  // condition.
+  REMOTE_INTERACTIONS_RESPONSE_FAILURE = 5;
+}
+
 // This enum depicts different components of the bugreport flow
 // Next ID: 5
 enum BugreportComponent {
@@ -926,4 +1000,54 @@ enum BugreportEvent {
   EVENT_BUGREPORT_TRIGGERED = 2;
   EVENT_BUGREPORT_FINISHED = 3;
   EVENT_BUGREPORT_RESULT_RECEIVED = 4;
+  // User consent is requested to upload a bug report.
+  // Only logged by WCS_AUTO_UPLOAD component.
+  EVENT_BUGREPORT_UPLOAD_CONSENT_REQUESTED = 5;
+  // Result of the user consent request is received.
+  // Only logged by WCS_AUTO_UPLOAD component.
+  EVENT_BUGREPORT_UPLOAD_CONSENT_RESULT_RECEIVED = 6;
+  // Bug report upload started.
+  // Only logged by WCS_AUTO_UPLOAD component.
+  EVENT_BUGREPORT_UPLOAD_STARTED = 7;
+  // Bug report upload finished.
+  // Only logged by WCS_AUTO_UPLOAD component.
+  EVENT_BUGREPORT_UPLOAD_FINISHED = 8;
+  // A stale bug report file is discarded without being uploaded.
+  // Only logged by WCS_AUTO_UPLOAD component.
+  EVENT_BUGREPORT_DISCARDED = 9;
+}
+
+// This enum depicts a bugreport failure reason
+// Only logged by WCS_AUTO_UPLOAD component.
+// Next ID: 13
+enum BugreportFailureReason {
+  // The failure reason is not specified.
+  BUGREPORT_FAILURE_REASON_UNKNOWN = 0;
+  // The event does not contain any failure.
+  BUGREPORT_FAILURE_REASON_EMPTY = 1;
+  // The request is rejected due to rate limiting.
+  BUGREPORT_FAILURE_REASON_TOO_MANY_REQUESTS = 2;
+  // The event failed because it is not possible to create an authentication
+  // token.
+  BUGREPORT_FAILURE_REASON_AUTHENTICATION_FAILED = 3;
+  // The event failed because the app does not have the required permission to
+  // use BugreportManager APIs.
+  BUGREPORT_FAILURE_REASON_PERMISSION_ERROR = 4;
+  // BugreportManager APIs failed while generating the bug report.
+  BUGREPORT_FAILURE_REASON_REPORT_GENERATION_ERROR = 5;
+  // BugreportManager APIs failed to generate or retrieve the bug report as
+  // another report generation is in progress.
+  BUGREPORT_FAILURE_REASON_ANOTHER_REPORT_GENERATION_IN_PROGRESS = 6;
+  // The user denied the consent to upload the bug report.
+  BUGREPORT_FAILURE_REASON_USER_DENIED_CONSENT = 7;
+  // The user didn't respond to the consent request in time.
+  BUGREPORT_FAILURE_REASON_USER_CONSENT_TIMED_OUT = 8;
+  // Bug report file to retrieve was not found.
+  BUGREPORT_FAILURE_REASON_FILE_NOT_FOUND = 9;
+  // Creating a Buganizer issue failed.
+  BUGREPORT_FAILURE_REASON_BUG_CREATION_FAILED = 10;
+  // Attaching the bug report file to Buganizer failed.
+  BUGREPORT_FAILURE_REASON_ATTACHMENT_UPLOAD_FAILED = 11;
+  // The bug report upload was canceled before it finished.
+  BUGREPORT_FAILURE_REASON_CANCELED = 12;
 }
diff --git a/stats/enums/app/wearsettings/OWNERS b/stats/enums/app/wearsettings/OWNERS
new file mode 100644
index 00000000..b3a1bf4d
--- /dev/null
+++ b/stats/enums/app/wearsettings/OWNERS
@@ -0,0 +1,10 @@
+# SysUI Apps team
+zenga@google.com
+haik@google.com
+mtsmall@google.com
+
+# Core OS Team
+garvitnarang@google.com
+shreerag@google.com
+yeabkal@google.com
+
diff --git a/stats/enums/app/wearsettings_enums.proto b/stats/enums/app/wearsettings/wearsettings_enums.proto
similarity index 98%
rename from stats/enums/app/wearsettings_enums.proto
rename to stats/enums/app/wearsettings/wearsettings_enums.proto
index 1bd14a60..d2842705 100644
--- a/stats/enums/app/wearsettings_enums.proto
+++ b/stats/enums/app/wearsettings/wearsettings_enums.proto
@@ -36,7 +36,7 @@ enum Action {
 }
 
 // IDs for settings UI elements.
-// Next ID: 528
+// Next ID: 531
 enum ItemId {
   // An unknown settings item. This may be set if no preference key is mapped to an enum value or as
   // a catch-all for values not yet added to this proto file.
@@ -429,4 +429,7 @@ enum ItemId {
   SOUND_NOTIFICATION_VOLUME = 508;
   SOUND_RING_AND_NOTIFICATIONS_VOLUME = 509;
   FORCE_GLOBAL_AMBIACTIVE = 600;
+  PRIORITY_MODES_CUSTOMIZE_DISPLAY_CONTROL_NIGHTLIGHT = 528;
+  PRIORITY_MODES_CUSTOMIZE_DISPLAY_CONTROL_GRAYSCALE = 529;
+  PRIORITY_MODES_CUSTOMIZE_DISPLAY_CONTROL_DEFAULT = 530;
 }
diff --git a/stats/enums/app_shared/app_enums.proto b/stats/enums/app_shared/app_enums.proto
index 732b0f04..1bfd8e92 100644
--- a/stats/enums/app_shared/app_enums.proto
+++ b/stats/enums/app_shared/app_enums.proto
@@ -132,6 +132,7 @@ enum OomChangeReasonEnum {
     OOM_ADJ_REASON_RESTRICTION_CHANGE = 21;
     OOM_ADJ_REASON_COMPONENT_DISABLED = 22;
     OOM_ADJ_REASON_FOLLOW_UP = 23;
+    OOM_ADJ_REASON_RECONFIGURATION = 24;
 }
 
 /**
diff --git a/stats/enums/app_shared/app_op_enums.proto b/stats/enums/app_shared/app_op_enums.proto
index 117a681a..58bad2d0 100644
--- a/stats/enums/app_shared/app_op_enums.proto
+++ b/stats/enums/app_shared/app_op_enums.proto
@@ -180,4 +180,11 @@ enum AppOpEnum {
     APP_OP_WRITE_SYSTEM_PREFERENCES = 153;
     APP_OP_CONTROL_AUDIO = 154;
     APP_OP_CONTROL_AUDIO_PARTIAL = 155;
+    APP_OP_EYE_TRACKING_COARSE = 156;
+    APP_OP_EYE_TRACKING_FINE = 157;
+    APP_OP_FACE_TRACKING = 158;
+    APP_OP_HAND_TRACKING = 159;
+    APP_OP_HEAD_TRACKING = 160;
+    APP_OP_SCENE_UNDERSTANDING_COARSE = 161;
+    APP_OP_SCENE_UNDERSTANDING_FINE = 162;
 }
diff --git a/stats/enums/art/OWNERS b/stats/enums/art/OWNERS
new file mode 100644
index 00000000..3c4438fc
--- /dev/null
+++ b/stats/enums/art/OWNERS
@@ -0,0 +1,5 @@
+jiakaiz@google.com
+mast@google.com
+ngeoffray@google.com
+rpl@google.com
+scianciulli@google.com
diff --git a/stats/enums/art/art_enums.proto b/stats/enums/art/art_enums.proto
index 268b3cdc..47843cae 100644
--- a/stats/enums/art/art_enums.proto
+++ b/stats/enums/art/art_enums.proto
@@ -22,7 +22,7 @@ option java_package = "com.android.os.art";
 option java_multiple_files = true;
 
 // Indicates which kind of measurement ART is reporting as increments / deltas.
-// Next ID: 37
+// Next ID: 40
 enum ArtDatumDeltaId {
   ART_DATUM_DELTA_INVALID = 0;
 
@@ -59,6 +59,9 @@ enum ArtDatumDeltaId {
   // The number of milliseconds since the last time metrics were reported.
   ART_DATUM_DELTA_TIME_ELAPSED_MS = 37;
 
+  ART_DATUM_DELTA_GC_APP_SLOW_PATH_DURING_YOUNG_GENERATION_COLLECTION_DURATION_MILLIS = 38;
+  ART_DATUM_DELTA_GC_APP_SLOW_PATH_DURING_FULL_HEAP_COLLECTION_DURATION_MILLIS = 39;
+
   reserved 1, 2, 4, 7, 10, 11, 12, 13, 14, 15, 18, 19, 20, 22, 23, 24, 25, 26, 27;
 }
 
diff --git a/stats/enums/art/common_enums.proto b/stats/enums/art/common_enums.proto
index f9ceaf15..fdfd8730 100644
--- a/stats/enums/art/common_enums.proto
+++ b/stats/enums/art/common_enums.proto
@@ -50,6 +50,7 @@ enum ArtCompileFilter {
   ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK = 13;
   ART_COMPILATION_FILTER_FAKE_RUN_FROM_APK_FALLBACK = 14;
   ART_COMPILATION_FILTER_FAKE_RUN_FROM_VDEX_FALLBACK = 15;
+  ART_COMPILATION_FILTER_SKIP = 16;
 }
 
 
diff --git a/stats/enums/autofill/enums.proto b/stats/enums/autofill/enums.proto
index 586846fc..acba8bcc 100644
--- a/stats/enums/autofill/enums.proto
+++ b/stats/enums/autofill/enums.proto
@@ -139,3 +139,24 @@ enum FieldClassificationRequestStatus {
   STATUS_FAIL = 2;
   STATUS_CANCELLED = 3;
 }
+
+// Enum for fill dialog not shown reason.
+enum FillDialogNotShownReason {
+  REASON_UNKNOWN = 0;
+  // Fill dialog has already been shown once since the last fill request.
+  REASON_FILL_DIALOG_DISABLED = 1;
+  REASON_SCREEN_HAS_CREDMAN_FIELD = 2;
+  REASON_LAST_TRIGGERED_ID_CHANGED = 3;
+  // Fill dialog is not shown because it kept waiting for IME animation to
+  // end.
+  REASON_WAIT_FOR_IME_ANIMATION = 4;
+  // Fill dialog's ready-to-show timestamp (relative to IME animation end time)
+  // exceeds the threshold defined by fill_dialog_timeout_ms.
+  REASON_TIMEOUT_SINCE_IME_ANIMATED = 5;
+  REASON_DELAY_AFTER_ANIMATION_END = 6;
+  // When fill dialog is ready to show, the IME animation is not ended or hasn't
+  // waited fill_dialog_min_wait_after_animation_end_ms yet. After the
+  // additional delay, its new ready-to-show timestamp (relative to IME
+  // animation end time) exceeds fill_dialog_timeout_ms.
+  REASON_TIMEOUT_AFTER_DELAY = 7;
+}
diff --git a/stats/enums/bluetooth/Android.bp b/stats/enums/bluetooth/Android.bp
index a7f726e5..14e42806 100644
--- a/stats/enums/bluetooth/Android.bp
+++ b/stats/enums/bluetooth/Android.bp
@@ -34,9 +34,7 @@ cc_library_static {
         "rfcomm/enums.proto",
         "smp/enums.proto",
     ],
-    apex_available: [
-        "com.android.btservices",
-    ],
+    apex_available: ["com.android.bt"],
     min_sdk_version: "30",
 }
 
diff --git a/stats/enums/bluetooth/enums.proto b/stats/enums/bluetooth/enums.proto
index 337272a9..aa9ad08f 100644
--- a/stats/enums/bluetooth/enums.proto
+++ b/stats/enums/bluetooth/enums.proto
@@ -22,477 +22,507 @@ option java_multiple_files = true;
 
 // Bluetooth connection states.
 enum ConnectionStateEnum {
-    CONNECTION_STATE_DISCONNECTED = 0;
-    CONNECTION_STATE_CONNECTING = 1;
-    CONNECTION_STATE_CONNECTED = 2;
-    CONNECTION_STATE_DISCONNECTING = 3;
+  CONNECTION_STATE_DISCONNECTED = 0;
+  CONNECTION_STATE_CONNECTING = 1;
+  CONNECTION_STATE_CONNECTED = 2;
+  CONNECTION_STATE_DISCONNECTING = 3;
 }
 
 // Bluetooth Adapter Enable and Disable Reasons
 enum EnableDisableReasonEnum {
-    ENABLE_DISABLE_REASON_UNSPECIFIED = 0;
-    ENABLE_DISABLE_REASON_APPLICATION_REQUEST = 1;
-    ENABLE_DISABLE_REASON_AIRPLANE_MODE = 2;
-    ENABLE_DISABLE_REASON_DISALLOWED = 3;
-    ENABLE_DISABLE_REASON_RESTARTED = 4;
-    ENABLE_DISABLE_REASON_START_ERROR = 5;
-    ENABLE_DISABLE_REASON_SYSTEM_BOOT = 6;
-    ENABLE_DISABLE_REASON_CRASH = 7;
-    ENABLE_DISABLE_REASON_USER_SWITCH = 8;
-    ENABLE_DISABLE_REASON_RESTORE_USER_SETTING = 9;
-    ENABLE_DISABLE_REASON_FACTORY_RESET = 10;
-    ENABLE_DISABLE_REASON_INIT_FLAGS_CHANGED = 11;
-    ENABLE_DISABLE_REASON_SATELLITE_MODE = 12;
+  ENABLE_DISABLE_REASON_UNSPECIFIED = 0;
+  ENABLE_DISABLE_REASON_APPLICATION_REQUEST = 1;
+  ENABLE_DISABLE_REASON_AIRPLANE_MODE = 2;
+  ENABLE_DISABLE_REASON_DISALLOWED = 3;
+  ENABLE_DISABLE_REASON_RESTARTED = 4;
+  ENABLE_DISABLE_REASON_START_ERROR = 5;
+  ENABLE_DISABLE_REASON_SYSTEM_BOOT = 6;
+  ENABLE_DISABLE_REASON_CRASH = 7;
+  ENABLE_DISABLE_REASON_USER_SWITCH = 8;
+  ENABLE_DISABLE_REASON_RESTORE_USER_SETTING = 9;
+  ENABLE_DISABLE_REASON_FACTORY_RESET = 10;
+  ENABLE_DISABLE_REASON_INIT_FLAGS_CHANGED = 11;
+  ENABLE_DISABLE_REASON_SATELLITE_MODE = 12;
 }
 
 enum DirectionEnum {
-    DIRECTION_UNKNOWN = 0;
-    DIRECTION_OUTGOING = 1;
-    DIRECTION_INCOMING = 2;
+  DIRECTION_UNKNOWN = 0;
+  DIRECTION_OUTGOING = 1;
+  DIRECTION_INCOMING = 2;
 }
 
 // First item is the default value, other values follow Bluetooth spec definition
 enum LinkTypeEnum {
-    // Link type is at most 1 byte (0xFF), thus 0xFFF must not be a valid value
-    LINK_TYPE_UNKNOWN = 0xFFF;
-    LINK_TYPE_SCO = 0x00;
-    LINK_TYPE_ACL = 0x01;
-    LINK_TYPE_ESCO = 0x02;
+  // Link type is at most 1 byte (0xFF), thus 0xFFF must not be a valid value
+  LINK_TYPE_UNKNOWN = 0xFFF;
+  LINK_TYPE_SCO = 0x00;
+  LINK_TYPE_ACL = 0x01;
+  LINK_TYPE_ESCO = 0x02;
 }
 
 enum DeviceInfoSrcEnum {
-    DEVICE_INFO_SRC_UNKNOWN = 0;
-    // Within Android Bluetooth stack
-    DEVICE_INFO_INTERNAL = 1;
-    // Outside Android Bluetooth stack
-    DEVICE_INFO_EXTERNAL = 2;
+  DEVICE_INFO_SRC_UNKNOWN = 0;
+  // Within Android Bluetooth stack
+  DEVICE_INFO_INTERNAL = 1;
+  // Outside Android Bluetooth stack
+  DEVICE_INFO_EXTERNAL = 2;
 }
 
 enum DeviceTypeEnum {
-    DEVICE_TYPE_UNKNOWN = 0;
-    DEVICE_TYPE_CLASSIC = 1;
-    DEVICE_TYPE_LE = 2;
-    DEVICE_TYPE_DUAL = 3;
+  DEVICE_TYPE_UNKNOWN = 0;
+  DEVICE_TYPE_CLASSIC = 1;
+  DEVICE_TYPE_LE = 2;
+  DEVICE_TYPE_DUAL = 3;
 }
 
 // Defined in frameworks/base/core/java/android/bluetooth/BluetoothDevice.java
 enum TransportTypeEnum {
-    TRANSPORT_TYPE_AUTO = 0;
-    TRANSPORT_TYPE_BREDR = 1;
-    TRANSPORT_TYPE_LE = 2;
+  TRANSPORT_TYPE_AUTO = 0;
+  TRANSPORT_TYPE_BREDR = 1;
+  TRANSPORT_TYPE_LE = 2;
 }
 
 // Bond state enum
 // Defined in frameworks/base/core/java/android/bluetooth/BluetoothDevice.java
 enum BondStateEnum {
-    BOND_STATE_UNKNOWN = 0;
-    BOND_STATE_NONE = 10;
-    BOND_STATE_BONDING = 11;
-    BOND_STATE_BONDED = 12;
+  BOND_STATE_UNKNOWN = 0;
+  BOND_STATE_NONE = 10;
+  BOND_STATE_BONDING = 11;
+  BOND_STATE_BONDED = 12;
 }
 
 // Sub states within the bonding general state
 enum BondSubStateEnum {
-    BOND_SUB_STATE_UNKNOWN = 0;
-    BOND_SUB_STATE_LOCAL_OOB_DATA_PROVIDED = 1;
-    BOND_SUB_STATE_LOCAL_PIN_REQUESTED = 2;
-    BOND_SUB_STATE_LOCAL_PIN_REPLIED = 3;
-    BOND_SUB_STATE_LOCAL_SSP_REQUESTED = 4;
-    BOND_SUB_STATE_LOCAL_SSP_REPLIED = 5;
-    BOND_SUB_STATE_LOCAL_BOND_STATE_INTENT_SENT = 6;
-    BOND_SUB_STATE_LOCAL_START_PAIRING = 7;
-    BOND_SUB_STATE_LOCAL_START_PAIRING_OOB = 8;
+  BOND_SUB_STATE_UNKNOWN = 0;
+  BOND_SUB_STATE_LOCAL_OOB_DATA_PROVIDED = 1;
+  BOND_SUB_STATE_LOCAL_PIN_REQUESTED = 2;
+  BOND_SUB_STATE_LOCAL_PIN_REPLIED = 3;
+  BOND_SUB_STATE_LOCAL_SSP_REQUESTED = 4;
+  BOND_SUB_STATE_LOCAL_SSP_REPLIED = 5;
+  BOND_SUB_STATE_LOCAL_BOND_STATE_INTENT_SENT = 6;
+  BOND_SUB_STATE_LOCAL_START_PAIRING = 7;
+  BOND_SUB_STATE_LOCAL_START_PAIRING_OOB = 8;
 }
 
 enum UnbondReasonEnum {
-    UNBOND_REASON_UNKNOWN = 0;
-    UNBOND_REASON_AUTH_FAILED = 1;
-    UNBOND_REASON_AUTH_REJECTED = 2;
-    UNBOND_REASON_AUTH_CANCELED = 3;
-    UNBOND_REASON_REMOTE_DEVICE_DOWN = 4;
-    UNBOND_REASON_DISCOVERY_IN_PROGRESS = 5;
-    UNBOND_REASON_AUTH_TIMEOUT = 6;
-    UNBOND_REASON_REPEATED_ATTEMPTS = 7;
-    UNBOND_REASON_REMOTE_AUTH_CANCELED = 8;
-    UNBOND_REASON_REMOVED = 9;
+  UNBOND_REASON_UNKNOWN = 0;
+  UNBOND_REASON_AUTH_FAILED = 1;
+  UNBOND_REASON_AUTH_REJECTED = 2;
+  UNBOND_REASON_AUTH_CANCELED = 3;
+  UNBOND_REASON_REMOTE_DEVICE_DOWN = 4;
+  UNBOND_REASON_DISCOVERY_IN_PROGRESS = 5;
+  UNBOND_REASON_AUTH_TIMEOUT = 6;
+  UNBOND_REASON_REPEATED_ATTEMPTS = 7;
+  UNBOND_REASON_REMOTE_AUTH_CANCELED = 8;
+  UNBOND_REASON_REMOVED = 9;
 }
 
 enum SocketTypeEnum {
-    SOCKET_TYPE_UNKNOWN = 0;
-    SOCKET_TYPE_RFCOMM = 1;
-    SOCKET_TYPE_SCO = 2;
-    SOCKET_TYPE_L2CAP_BREDR = 3;
-    SOCKET_TYPE_L2CAP_LE = 4;
+  SOCKET_TYPE_UNKNOWN = 0;
+  SOCKET_TYPE_RFCOMM = 1;
+  SOCKET_TYPE_SCO = 2;
+  SOCKET_TYPE_L2CAP_BREDR = 3;
+  SOCKET_TYPE_L2CAP_LE = 4;
 }
 
 enum SocketConnectionstateEnum {
-    SOCKET_CONNECTION_STATE_UNKNOWN = 0;
-    // Socket acts as a server waiting for connection
-    SOCKET_CONNECTION_STATE_LISTENING = 1;
-    // Socket acts as a client trying to connect
-    SOCKET_CONNECTION_STATE_CONNECTING = 2;
-    // Socket is connected
-    SOCKET_CONNECTION_STATE_CONNECTED = 3;
-    // Socket tries to disconnect from remote
-    SOCKET_CONNECTION_STATE_DISCONNECTING = 4;
-    // This socket is closed
-    SOCKET_CONNECTION_STATE_DISCONNECTED = 5;
+  SOCKET_CONNECTION_STATE_UNKNOWN = 0;
+  // Socket acts as a server waiting for connection
+  SOCKET_CONNECTION_STATE_LISTENING = 1;
+  // Socket acts as a client trying to connect
+  SOCKET_CONNECTION_STATE_CONNECTING = 2;
+  // Socket is connected
+  SOCKET_CONNECTION_STATE_CONNECTED = 3;
+  // Socket tries to disconnect from remote
+  SOCKET_CONNECTION_STATE_DISCONNECTING = 4;
+  // This socket is closed
+  SOCKET_CONNECTION_STATE_DISCONNECTED = 5;
 }
 
 enum SocketRoleEnum {
-    SOCKET_ROLE_UNKNOWN = 0;
-    SOCKET_ROLE_LISTEN = 1;
-    SOCKET_ROLE_CONNECTION = 2;
+  SOCKET_ROLE_UNKNOWN = 0;
+  SOCKET_ROLE_LISTEN = 1;
+  SOCKET_ROLE_CONNECTION = 2;
+}
+
+enum SocketErrorEnum {
+  SOCKET_ERROR_UNKNOWN = 0;
+  SOCKET_ERROR_NONE = 1;
+  SOCKET_ERROR_SERVER_START_FAILURE = 2;
+  SOCKET_ERROR_CLIENT_INIT_FAILURE = 3;
+  SOCKET_ERROR_LISTEN_FAILURE = 4;
+  SOCKET_ERROR_CONNECTION_FAILURE = 5;
+  SOCKET_ERROR_OPEN_FAILURE = 6;
+  SOCKET_ERROR_OFFLOAD_SERVER_NOT_ACCEPTING = 7;
+  SOCKET_ERROR_OFFLOAD_HAL_OPEN_FAILURE = 8;
+  SOCKET_ERROR_SEND_TO_APP_FAILURE = 9;
+  SOCKET_ERROR_RECEIVE_DATA_FAILURE = 10;
+  SOCKET_ERROR_READ_SIGNALED_FAILURE = 11;
+  SOCKET_ERROR_WRITE_SIGNALED_FAILURE = 12;
+  // Server Channel Number (SCN) in RFCOMM is a dynamically assigned port-like identifier that
+  // allows clients to connect to a specific service on a Bluetooth device via the Service
+  // Discovery Protocol (SDP).
+  // This error occurs when the system fails to transmit the SCN to the application.
+  SOCKET_ERROR_SEND_SCN_FAILURE = 13;
+  // This error occurs when the system fails to allocate an SCN.
+  SOCKET_ERROR_SCN_ALLOCATION_FAILURE = 14;
+  // Service Discovery Protocol (SDP) is used to discover available services on remote devices and
+  // retrieve essential information, such as the Server Channel Number (SCN) for RFCOMM-based
+  // connections.
+  // This error occurs when the system fails to add an SDP record to the SDP database.
+  SOCKET_ERROR_ADD_SDP_FAILURE = 15;
+  // This error occurs when the SDP service discovery process fails to complete.
+  SOCKET_ERROR_SDP_DISCOVERY_FAILURE = 16;
 }
 
 enum L2capCocConnectionResult {
-    RESULT_L2CAP_CONN_UNKNOWN = 0;
-    RESULT_L2CAP_CONN_SUCCESS = 1;
-    RESULT_L2CAP_CONN_ACL_FAILURE = 2;
-    RESULT_L2CAP_CONN_CL_SEC_FAILURE = 3;
-    RESULT_L2CAP_CONN_INSUFFICIENT_AUTHENTICATION = 4;
-    RESULT_L2CAP_CONN_INSUFFICIENT_AUTHORIZATION = 5;
-    RESULT_L2CAP_CONN_INSUFFICIENT_ENCRYP_KEY_SIZE = 6;
-    RESULT_L2CAP_CONN_INSUFFICIENT_ENCRYP = 7;
-    RESULT_L2CAP_CONN_INVALID_SOURCE_CID = 8;
-    RESULT_L2CAP_CONN_SOURCE_CID_ALREADY_ALLOCATED = 9;
-    RESULT_L2CAP_CONN_UNACCEPTABLE_PARAMETERS = 10;
-    RESULT_L2CAP_CONN_INVALID_PARAMETERS = 11;
-    RESULT_L2CAP_CONN_NO_RESOURCES = 12;
-    RESULT_L2CAP_CONN_NO_PSM = 13;
-    RESULT_L2CAP_CONN_TIMEOUT = 14;
-    RESULT_L2CAP_CONN_BLUETOOTH_OFF = 15;
-
-    // Modify the curresponding value of BluetoothSocket.java
-    RESULT_L2CAP_CONN_BLUETOOTH_SOCKET_CONNECTION_FAILED = 1000;
-    RESULT_L2CAP_CONN_BLUETOOTH_SOCKET_CONNECTION_CLOSED = 1001;
-    RESULT_L2CAP_CONN_BLUETOOTH_UNABLE_TO_SEND_RPC = 1002;
-    RESULT_L2CAP_CONN_BLUETOOTH_NULL_BLUETOOTH_DEVICE = 1003;
-    RESULT_L2CAP_CONN_BLUETOOTH_GET_SOCKET_MANAGER_FAILED = 1004;
-    RESULT_L2CAP_CONN_BLUETOOTH_NULL_FILE_DESCRIPTOR = 1005;
-
-    // Modify the curresponding value of BluetoothServerSocket.java
-    RESULT_L2CAP_CONN_SERVER_FAILURE= 2000;
+  RESULT_L2CAP_CONN_UNKNOWN = 0;
+  RESULT_L2CAP_CONN_SUCCESS = 1;
+  RESULT_L2CAP_CONN_ACL_FAILURE = 2;
+  RESULT_L2CAP_CONN_CL_SEC_FAILURE = 3;
+  RESULT_L2CAP_CONN_INSUFFICIENT_AUTHENTICATION = 4;
+  RESULT_L2CAP_CONN_INSUFFICIENT_AUTHORIZATION = 5;
+  RESULT_L2CAP_CONN_INSUFFICIENT_ENCRYP_KEY_SIZE = 6;
+  RESULT_L2CAP_CONN_INSUFFICIENT_ENCRYP = 7;
+  RESULT_L2CAP_CONN_INVALID_SOURCE_CID = 8;
+  RESULT_L2CAP_CONN_SOURCE_CID_ALREADY_ALLOCATED = 9;
+  RESULT_L2CAP_CONN_UNACCEPTABLE_PARAMETERS = 10;
+  RESULT_L2CAP_CONN_INVALID_PARAMETERS = 11;
+  RESULT_L2CAP_CONN_NO_RESOURCES = 12;
+  RESULT_L2CAP_CONN_NO_PSM = 13;
+  RESULT_L2CAP_CONN_TIMEOUT = 14;
+  RESULT_L2CAP_CONN_BLUETOOTH_OFF = 15;
+
+  // Modify the curresponding value of BluetoothSocket.java
+  RESULT_L2CAP_CONN_BLUETOOTH_SOCKET_CONNECTION_FAILED = 1000;
+  RESULT_L2CAP_CONN_BLUETOOTH_SOCKET_CONNECTION_CLOSED = 1001;
+  RESULT_L2CAP_CONN_BLUETOOTH_UNABLE_TO_SEND_RPC = 1002;
+  RESULT_L2CAP_CONN_BLUETOOTH_NULL_BLUETOOTH_DEVICE = 1003;
+  RESULT_L2CAP_CONN_BLUETOOTH_GET_SOCKET_MANAGER_FAILED = 1004;
+  RESULT_L2CAP_CONN_BLUETOOTH_NULL_FILE_DESCRIPTOR = 1005;
+
+  // Modify the curresponding value of BluetoothServerSocket.java
+  RESULT_L2CAP_CONN_SERVER_FAILURE= 2000;
 }
 
 enum CodePathCounterKeyEnum {
-    COUNTER_KEY_UNKNOWN = 0;
-    // Reserver smaller counters for very important bt features
-
-    // [100,000 - 120,000) profile connection related
-
-        // [100,000 - 100,100) L2CAP
-        L2CAP_SUCCESS = 100000;
-        L2CAP_CONNECT_CONFIRM_NEG= 100001;
-        L2CAP_NO_COMPATIBLE_CHANNEL_AT_CSM_CLOSED = 100002;
-        L2CAP_SECURITY_NEG_AT_CSM_CLOSED= 100003;
-        L2CAP_TIMEOUT_AT_CSM_CLOSED = 100004;
-        L2CAP_CREDIT_BASED_CONNECT_RSP_NEG = 100005;
-        L2CAP_CONNECT_RSP_NEG = 100006;
-        L2CAP_INFO_NO_COMPATIBLE_CHANNEL_AT_RSP = 100007;
-        L2CAP_CONFIG_REQ_FAILURE = 100008;
-        L2CAP_CONFIG_RSP_NEG = 100009;
-        L2CAP_NO_COMPATIBLE_CHANNEL_AT_W4_SEC = 100010;
-        L2CAP_SECURITY_NEG_AT_W4_SEC= 100011;
-        L2CAP_TIMEOUT_AT_CONNECT_RSP = 100012;
-        L2CAP_CONN_OTHER_ERROR_AT_CONNECT_RSP = 100013;
-
-        // [100,100 - 100,200) SDP
-        SDP_SUCCESS = 100100;
-        SDP_FAILURE = 100101;
-        SDP_SENDING_DELAYED_UUID = 100102;
-        SDP_NOT_SENDING_DELAYED_UUID = 100103;
-        SDP_SENT_UUID = 100104;
-        SDP_UUIDS_EQUAL_SKIP = 100105;
-        SDP_ADD_UUID_WITH_INTENT = 100106;
-        SDP_ADD_UUID_WITH_NO_INTENT = 100107;
-        SDP_DROP_UUID = 100108;
-        SDP_FETCH_UUID_SKIP_ALREADY_CACHED = 100109;
-        SDP_FETCH_UUID_SKIP_ALREADY_BONDED = 100110;
-        SDP_INVOKE_SDP_CYCLE = 100111;
-        SDP_FETCH_UUID_REQUEST = 100112;
-
-
-        // [101,000 - 102,000) HFP
-
-            // [101,000 - 101,100) RFCOMM
-            RFCOMM_CONNECTION_SUCCESS_IND = 101000;
-            RFCOMM_CONNECTION_SUCCESS_CNF = 101001;
-            RFCOMM_PORT_START_CNF_FAILED = 101002;
-            RFCOMM_PORT_START_CLOSE = 101003;
-            RFCOMM_PORT_START_FAILED = 101004;
-            RFCOMM_PORT_NEG_FAILED = 101005;
-            RFCOMM_PORT_CLOSED = 101006;
-            RFCOMM_PORT_PEER_CONNECTION_FAILED = 101007;
-            RFCOMM_PORT_PEER_TIMEOUT = 101008;
-
-            // [101,100 - 101,200) HFP (btif)
-            HFP_COLLISON_AT_AG_OPEN = 101101;
-            HFP_COLLISON_AT_CONNECTING = 101102;
-            HFP_SELF_INITIATED_AG_FAILED = 101103;
-            HFP_SLC_SETUP_FAILED = 101104;
-
-        // [102,000 - 103,000) A2DP
-        A2DP_CONNECTION_SUCCESS = 102000;
-        A2DP_CONNECTION_ACL_DISCONNECTED = 102001;
-        A2DP_CONNECTION_REJECT_EVT = 102002;
-        A2DP_CONNECTION_FAILURE = 102003;
-        A2DP_CONNECTION_UNKNOWN_EVENT = 102004;
-        A2DP_ALREADY_CONNECTING = 102005;
-        A2DP_OFFLOAD_START_REQ_FAILURE = 102006;
-        A2DP_CONNECTION_CLOSE = 102007;
-        A2DP_CONNECTION_DISCONNECTED = 102008;
-        A2DP_CONNECTION_TIMEOUT = 102009;
-
-        // [103,000 - 103,100) HIDD
-        HID_PLUG_FAILURE = 103001;
-        HIDD_REGISTER_DESCRIPTOR_MALFORMED = 103002;
-
-        HIDD_ERR_NOT_REGISTERED_AT_INITIATE = 103003;
-        HIDD_ERR_NO_RESOURCES = 103004;
-        HIDD_ERR_NO_CONNECTION_AT_SEND_DATA = 103005;
-        HIDD_ERR_NO_CONNECTION_AT_DISCONNECT = 103006;
-        HIDD_ERR_INVALID_PARAM = 103007;
-        HIDD_ERR_CONGESTED_AT_DATA_WRITE = 103008;
-        HIDD_ERR_CONGESTED_AT_FLAG_CHECK = 103009;
-        HIDD_ERR_CONN_IN_PROCESS = 103010;
-        HIDD_ERR_ALREADY_CONN = 103011;
-        HIDD_ERR_DISCONNECTING = 103012;
-        HIDD_ERR_L2CAP_NOT_STARTED_INCOMING = 103013;
-        HIDD_ERR_L2CAP_FAILED_INITIATE = 103014;
-        HIDD_ERR_L2CAP_FAILED_CONTROL = 103015;
-        HIDD_ERR_L2CAP_FAILED_INTERRUPT = 103016;
-        HIDD_ERR_HOST_CALLBACK_NULL = 103017;
-        HIDD_ERR_INVALID_PARAM_SEND_REPORT = 103018;
-        HIDD_ERR_DEVICE_NOT_IN_USE_AT_CONNECT = 103019;
-        HIDD_ERR_DEVICE_NOT_IN_USE_AT_DISCONNECT = 103020;
-        HIDD_ERR_NOT_REGISTERED_AT_CONNECT = 103021;
-        HIDD_ERR_NOT_REGISTERED_AT_DISCONNECT = 103022;
-        HIDD_ERR_NOT_REGISTERED_AT_GET_DEVICE = 103023;
-        HIDD_ERR_NOT_REGISTERED_AT_DEREGISTER = 103024;
-        HIDD_ERR_NOT_REGISTERED_DUE_TO_DESCRIPTOR_LENGTH = 103025;
-        HIDD_ERR_NOT_REGISTERED_DUE_TO_BUFFER_ALLOCATION = 103026;
-        HIDD_ERR_NOT_REGISTERED_AT_SDP = 103027;
-        HIDD_ERR_ALREADY_REGISTERED = 103028;
-
-        // [103,100 - 103,200) HIDH
-        HIDH_ERR_ALREADY_REGISTERED = 103101;
-        HIDH_ERR_NO_RESOURCES_SDP = 103102;
-        HIDH_ERR_NO_RESOURCES_ADD_DEVICE = 103103;
-        HIDH_ERR_NO_CONNECTION_AT_SEND_DATA = 103104;
-        HIDH_ERR_NO_CONNECTION_AT_HOST_WRITE_DEV = 103105;
-        HIDH_ERR_NO_CONNECTION_AT_HOST_CLOSE_DEV = 103106;
-
-        HIDH_ERR_INVALID_PARAM_AT_SEND_DATA = 103107;
-        HIDH_ERR_INVALID_PARAM_AT_HOST_REGISTER = 103108;
-        HIDH_ERR_INVALID_PARAM_AT_HOST_REMOVE_DEV = 103109;
-        HIDH_ERR_INVALID_PARAM_AT_HOST_OPEN_DEV = 103110;
-        HIDH_ERR_INVALID_PARAM_AT_HOST_CLOSE_DEV = 103111;
-        HIDH_ERR_INVALID_PARAM_AT_HOST_WRITE_DEV = 103112;
-
-        HIDH_ERR_CONGESTED_AT_SEND_DATA = 103113;
-        HIDH_ERR_CONGESTED_AT_FLAG_CHECK = 103114;
-        HIDH_ERR_CONN_IN_PROCESS = 103115;
-        HIDH_ERR_ALREADY_CONN = 103116;
-
-        HIDH_ERR_L2CAP_FAILED_AT_INITIATE = 103117;
-        HIDH_ERR_L2CAP_FAILED_AT_REGISTER_CONTROL = 103118;
-        HIDH_ERR_L2CAP_FAILED_AT_REGISTER_INTERRUPT = 103119;
-
-        HIDH_ERR_AUTH_FAILED = 103120;
-        HIDH_ERR_SDP_BUSY = 103121;
-
-        //Native and Java
-        HIDH_COUNT_MAX_ADDED_DEVICE_LIMIT_REACHED = 103122;
-        HIDH_COUNT_VIRTUAL_UNPLUG_REQUESTED_BY_REMOTE_DEVICE = 103123;
-        HIDH_COUNT_CONNECT_REQ_WHEN_MAX_DEVICE_LIMIT_REACHED = 103124;
-        HIDH_COUNT_WRONG_REPORT_TYPE = 103125;
-        HIDH_COUNT_INCOMING_CONNECTION_REJECTED = 103126;
-        HIDH_COUNT_CONNECTION_POLICY_DISABLED = 103127;
-        HIDH_COUNT_SUPPORT_BOTH_HID_AND_HOGP = 103128;
-        HIDH_COUNT_SUPPORT_ONLY_HID_OR_HOGP = 103129;
-
-
-    // [120,000 - 120,500) LE scan related
-        // [120,000 - 120,100) LE scan enable/disable count
-        LE_SCAN_COUNT_TOTAL_ENABLE = 120000;
-        LE_SCAN_COUNT_TOTAL_DISABLE = 120001;
-        LE_SCAN_COUNT_FILTERED_ENABLE = 120002;
-        LE_SCAN_COUNT_FILTERED_DISABLE = 120003;
-        LE_SCAN_COUNT_UNFILTERED_ENABLE = 120004;
-        LE_SCAN_COUNT_UNFILTERED_DISABLE = 120005;
-        LE_SCAN_COUNT_BATCH_ENABLE = 120006;
-        LE_SCAN_COUNT_BATCH_DISABLE = 120007;
-        LE_SCAN_COUNT_AUTO_BATCH_ENABLE = 120008;
-        LE_SCAN_COUNT_AUTO_BATCH_DISABLE =  120009;
-
-        // [120,100 - 120,200) LE scan duration bucket count
-        LE_SCAN_DURATION_COUNT_REGULAR_10S = 120100;
-        LE_SCAN_DURATION_COUNT_REGULAR_1M = 120101;
-        LE_SCAN_DURATION_COUNT_REGULAR_10M = 120102;
-        LE_SCAN_DURATION_COUNT_REGULAR_1H =120103;
-        LE_SCAN_DURATION_COUNT_REGULAR_1HP =120104;
-        LE_SCAN_DURATION_COUNT_BATCH_10S = 120105;
-        LE_SCAN_DURATION_COUNT_BATCH_1M = 120106;
-        LE_SCAN_DURATION_COUNT_BATCH_10M = 120107;
-        LE_SCAN_DURATION_COUNT_BATCH_1H = 120108;
-        LE_SCAN_DURATION_COUNT_BATCH_1HP = 120109;
-
-        // [120,200 - 120,250) LE scan radio active duration
-        LE_SCAN_RADIO_DURATION_ALL = 120200;
-        LE_SCAN_RADIO_DURATION_REGULAR = 120201;
-        LE_SCAN_RADIO_DURATION_BATCH = 120202;
-        LE_SCAN_RADIO_DURATION_REGULAR_SCREEN_ON = 120203;
-        LE_SCAN_RADIO_DURATION_REGULAR_SCREEN_OFF = 120204;
-        LE_SCAN_RADIO_DURATION_BATCH_SCREEN_ON = 120205;
-        LE_SCAN_RADIO_DURATION_BATCH_SCREEN_OFF = 120206;
-
-        // [120,250 - 120,300) LE scan radio scan mode count
-        LE_SCAN_RADIO_SCAN_MODE_OPPORTUNISTIC_COUNT = 120250;
-        LE_SCAN_RADIO_SCAN_MODE_LOW_POWER_COUNT = 120251;
-        LE_SCAN_RADIO_SCAN_MODE_BALANCED_COUNT = 120252;
-        LE_SCAN_RADIO_SCAN_MODE_LOW_LATENCY_COUNT = 120253;
-        LE_SCAN_RADIO_SCAN_MODE_AMBIENT_DISCOVERY_COUNT = 120254;
-        LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_COUNT = 120255;
-        LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_BALANCED_COUNT = 120256;
-        LE_SCAN_RADIO_SCAN_MODE_OPPORTUNISTIC_COUNT_SCREEN_OFF = 120257;
-        LE_SCAN_RADIO_SCAN_MODE_LOW_POWER_COUNT_SCREEN_OFF = 120258;
-        LE_SCAN_RADIO_SCAN_MODE_BALANCED_COUNT_SCREEN_OFF = 120259;
-        LE_SCAN_RADIO_SCAN_MODE_LOW_LATENCY_COUNT_SCREEN_OFF = 120260;
-        LE_SCAN_RADIO_SCAN_MODE_AMBIENT_DISCOVERY_COUNT_SCREEN_OFF = 120261;
-        LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_COUNT_SCREEN_OFF = 120262;
-        LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_BALANCED_COUNT_SCREEN_OFF = 120263;
-
-        // [120,300 - 120,400) LE scan results count
-        LE_SCAN_RESULTS_COUNT_ALL = 120300;
-        LE_SCAN_RESULTS_COUNT_REGULAR = 120301;
-        LE_SCAN_RESULTS_COUNT_BATCH = 120302;
-        LE_SCAN_RESULTS_COUNT_REGULAR_SCREEN_ON = 120303;
-        LE_SCAN_RESULTS_COUNT_REGULAR_SCREEN_OFF =  120304;
-        LE_SCAN_RESULTS_COUNT_BATCH_SCREEN_ON = 120305;
-        LE_SCAN_RESULTS_COUNT_BATCH_SCREEN_OFF = 120306;
-        LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE = 120307;
-        LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE_SCREEN_ON = 120308;
-        LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE_SCREEN_OFF = 120309;
-
-        // [120,400 - 120,500) LE scan abuse count
-        LE_SCAN_ABUSE_COUNT_SCAN_TIMEOUT = 120400;
-        LE_SCAN_ABUSE_COUNT_HW_FILTER_NOT_AVAILABLE = 120401;
-        LE_SCAN_ABUSE_COUNT_TRACKING_HW_FILTER_NOT_AVAILABLE = 120402;
-
-    // [120,500 - 121,000) LE advertise related
-        // [120,500 - 120,600) LE advertise enable/disable count
-        LE_ADV_COUNT_ENABLE = 120500;
-        LE_ADV_COUNT_DISABLE = 120501;
-        LE_ADV_COUNT_CONNECTABLE_ENABLE = 120502;
-        LE_ADV_COUNT_CONNECTABLE_DISABLE = 120503;
-        LE_ADV_COUNT_PERIODIC_ENABLE = 120504;
-        LE_ADV_COUNT_PERIODIC_DISABLE = 120505;
-
-        // [120,600 - 120,700) LE advertise instance bucket count
-        LE_ADV_INSTANCE_COUNT_5 = 120600;
-        LE_ADV_INSTANCE_COUNT_10 = 120601;
-        LE_ADV_INSTANCE_COUNT_15 = 120602;
-        LE_ADV_INSTANCE_COUNT_15P = 120603;
-
-        // [120,700 - 120,800) LE advertise duration bucket count
-        LE_ADV_DURATION_COUNT_TOTAL_1M = 120700;
-        LE_ADV_DURATION_COUNT_TOTAL_30M = 120701;
-        LE_ADV_DURATION_COUNT_TOTAL_1H = 120702;
-        LE_ADV_DURATION_COUNT_TOTAL_3H = 120703;
-        LE_ADV_DURATION_COUNT_TOTAL_3HP = 120704;
-        LE_ADV_DURATION_COUNT_CONNECTABLE_1M = 120705;
-        LE_ADV_DURATION_COUNT_CONNECTABLE_30M = 120706;
-        LE_ADV_DURATION_COUNT_CONNECTABLE_1H = 120707;
-        LE_ADV_DURATION_COUNT_CONNECTABLE_3H = 120708;
-        LE_ADV_DURATION_COUNT_CONNECTABLE_3HP = 120709;
-        LE_ADV_DURATION_COUNT_PERIODIC_1M = 120710;
-        LE_ADV_DURATION_COUNT_PERIODIC_30M = 120711;
-        LE_ADV_DURATION_COUNT_PERIODIC_1H = 120712;
-        LE_ADV_DURATION_COUNT_PERIODIC_3H = 120713;
-        LE_ADV_DURATION_COUNT_PERIODIC_3HP = 120714;
-
-        // [120,800 - 120,900) LE advertise error count
-        LE_ADV_ERROR_ON_START_COUNT = 120800;
-
-   // [120,900 - 121,000) GATT Related Count
-        GATT_CLIENT_CONNECT_IS_DIRECT = 120900;
-        GATT_CLIENT_CONNECT_IS_AUTOCONNECT = 120901;
-        GATT_CLIENT_CONNECT_IS_DIRECT_IN_FOREGROUND = 120902;
-        GATT_CLIENT_CONNECT_IS_DIRECT_NOT_IN_FOREGROUND = 120903;
-        GATT_CLIENT_CONNECT_IS_AUTOCONNECT_IN_FOREGROUND = 120904;
-        GATT_CLIENT_CONNECT_IS_AUTOCONNECT_NOT_IN_FOREGROUND = 120905;
-        GATT_SERVER_CONNECT_IS_DIRECT_IN_FOREGROUND = 120906;
-        GATT_SERVER_CONNECT_IS_DIRECT_NOT_IN_FOREGROUND = 120907;
-        GATT_SERVER_CONNECT_IS_AUTOCONNECT_IN_FOREGROUND = 120908;
-        GATT_SERVER_CONNECT_IS_AUTOCONNECT_NOT_IN_FOREGROUND = 120909;
-
-   // [121,000 - 121,100) System state related
-        // [121,000 - 121,010) Screen on/off count
-        SCREEN_ON_EVENT = 121000;
-        SCREEN_OFF_EVENT = 121001;
-
-    // [121,100 - 122,000) Le Audio related
-        // [121,100 - 121,200) device/group health status count
-        LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_GOOD = 121100;
-        LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD = 121101;
-        LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_DB = 121102;
-        LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_CSIS = 121103;
-        LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_GOOD = 121104;
-        LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD = 121105;
-        LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_DB = 121106;
-        LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_CSIS = 121107;
-        LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_GOOD = 121108;
-        LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_TRENDING_BAD = 121109;
-        LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD = 121110;
-        LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_CIS_FAILED = 121111;
-        LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_SIGNALING_FAILED = 121112;
-        LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_GOOD = 121113;
-        LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_TRENDING_BAD = 121114;
-        LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD = 121115;
-        LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_CIS_FAILED = 121116;
-        LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_SIGNALING_FAILED = 121117;
+  COUNTER_KEY_UNKNOWN = 0;
+  // Reserve smaller counters for very important bt features
+
+  // [100,000 - 120,000) profile connection related
+
+    // [100,000 - 100,100) L2CAP
+    L2CAP_SUCCESS = 100000;
+    L2CAP_CONNECT_CONFIRM_NEG= 100001;
+    L2CAP_NO_COMPATIBLE_CHANNEL_AT_CSM_CLOSED = 100002;
+    L2CAP_SECURITY_NEG_AT_CSM_CLOSED= 100003;
+    L2CAP_TIMEOUT_AT_CSM_CLOSED = 100004;
+    L2CAP_CREDIT_BASED_CONNECT_RSP_NEG = 100005;
+    L2CAP_CONNECT_RSP_NEG = 100006;
+    L2CAP_INFO_NO_COMPATIBLE_CHANNEL_AT_RSP = 100007;
+    L2CAP_CONFIG_REQ_FAILURE = 100008;
+    L2CAP_CONFIG_RSP_NEG = 100009;
+    L2CAP_NO_COMPATIBLE_CHANNEL_AT_W4_SEC = 100010;
+    L2CAP_SECURITY_NEG_AT_W4_SEC= 100011;
+    L2CAP_TIMEOUT_AT_CONNECT_RSP = 100012;
+    L2CAP_CONN_OTHER_ERROR_AT_CONNECT_RSP = 100013;
+
+    // [100,100 - 100,200) SDP
+    SDP_SUCCESS = 100100;
+    SDP_FAILURE = 100101;
+    SDP_SENDING_DELAYED_UUID = 100102;
+    SDP_NOT_SENDING_DELAYED_UUID = 100103;
+    SDP_SENT_UUID = 100104;
+    SDP_UUIDS_EQUAL_SKIP = 100105;
+    SDP_ADD_UUID_WITH_INTENT = 100106;
+    SDP_ADD_UUID_WITH_NO_INTENT = 100107;
+    SDP_DROP_UUID = 100108;
+    SDP_FETCH_UUID_SKIP_ALREADY_CACHED = 100109;
+    SDP_FETCH_UUID_SKIP_ALREADY_BONDED = 100110;
+    SDP_INVOKE_SDP_CYCLE = 100111;
+    SDP_FETCH_UUID_REQUEST = 100112;
+
+
+    // [101,000 - 102,000) HFP
+
+      // [101,000 - 101,100) RFCOMM
+      RFCOMM_CONNECTION_SUCCESS_IND = 101000;
+      RFCOMM_CONNECTION_SUCCESS_CNF = 101001;
+      RFCOMM_PORT_START_CNF_FAILED = 101002;
+      RFCOMM_PORT_START_CLOSE = 101003;
+      RFCOMM_PORT_START_FAILED = 101004;
+      RFCOMM_PORT_NEG_FAILED = 101005;
+      RFCOMM_PORT_CLOSED = 101006;
+      RFCOMM_PORT_PEER_CONNECTION_FAILED = 101007;
+      RFCOMM_PORT_PEER_TIMEOUT = 101008;
+
+      // [101,100 - 101,200) HFP (btif)
+      HFP_COLLISON_AT_AG_OPEN = 101101;
+      HFP_COLLISON_AT_CONNECTING = 101102;
+      HFP_SELF_INITIATED_AG_FAILED = 101103;
+      HFP_SLC_SETUP_FAILED = 101104;
+
+    // [102,000 - 103,000) A2DP
+    A2DP_CONNECTION_SUCCESS = 102000;
+    A2DP_CONNECTION_ACL_DISCONNECTED = 102001;
+    A2DP_CONNECTION_REJECT_EVT = 102002;
+    A2DP_CONNECTION_FAILURE = 102003;
+    A2DP_CONNECTION_UNKNOWN_EVENT = 102004;
+    A2DP_ALREADY_CONNECTING = 102005;
+    A2DP_OFFLOAD_START_REQ_FAILURE = 102006;
+    A2DP_CONNECTION_CLOSE = 102007;
+    A2DP_CONNECTION_DISCONNECTED = 102008;
+    A2DP_CONNECTION_TIMEOUT = 102009;
+
+    // [103,000 - 103,100) HIDD
+    HID_PLUG_FAILURE = 103001;
+    HIDD_REGISTER_DESCRIPTOR_MALFORMED = 103002;
+
+    HIDD_ERR_NOT_REGISTERED_AT_INITIATE = 103003;
+    HIDD_ERR_NO_RESOURCES = 103004;
+    HIDD_ERR_NO_CONNECTION_AT_SEND_DATA = 103005;
+    HIDD_ERR_NO_CONNECTION_AT_DISCONNECT = 103006;
+    HIDD_ERR_INVALID_PARAM = 103007;
+    HIDD_ERR_CONGESTED_AT_DATA_WRITE = 103008;
+    HIDD_ERR_CONGESTED_AT_FLAG_CHECK = 103009;
+    HIDD_ERR_CONN_IN_PROCESS = 103010;
+    HIDD_ERR_ALREADY_CONN = 103011;
+    HIDD_ERR_DISCONNECTING = 103012;
+    HIDD_ERR_L2CAP_NOT_STARTED_INCOMING = 103013;
+    HIDD_ERR_L2CAP_FAILED_INITIATE = 103014;
+    HIDD_ERR_L2CAP_FAILED_CONTROL = 103015;
+    HIDD_ERR_L2CAP_FAILED_INTERRUPT = 103016;
+    HIDD_ERR_HOST_CALLBACK_NULL = 103017;
+    HIDD_ERR_INVALID_PARAM_SEND_REPORT = 103018;
+    HIDD_ERR_DEVICE_NOT_IN_USE_AT_CONNECT = 103019;
+    HIDD_ERR_DEVICE_NOT_IN_USE_AT_DISCONNECT = 103020;
+    HIDD_ERR_NOT_REGISTERED_AT_CONNECT = 103021;
+    HIDD_ERR_NOT_REGISTERED_AT_DISCONNECT = 103022;
+    HIDD_ERR_NOT_REGISTERED_AT_GET_DEVICE = 103023;
+    HIDD_ERR_NOT_REGISTERED_AT_DEREGISTER = 103024;
+    HIDD_ERR_NOT_REGISTERED_DUE_TO_DESCRIPTOR_LENGTH = 103025;
+    HIDD_ERR_NOT_REGISTERED_DUE_TO_BUFFER_ALLOCATION = 103026;
+    HIDD_ERR_NOT_REGISTERED_AT_SDP = 103027;
+    HIDD_ERR_ALREADY_REGISTERED = 103028;
+
+    // [103,100 - 103,200) HIDH
+    HIDH_ERR_ALREADY_REGISTERED = 103101;
+    HIDH_ERR_NO_RESOURCES_SDP = 103102;
+    HIDH_ERR_NO_RESOURCES_ADD_DEVICE = 103103;
+    HIDH_ERR_NO_CONNECTION_AT_SEND_DATA = 103104;
+    HIDH_ERR_NO_CONNECTION_AT_HOST_WRITE_DEV = 103105;
+    HIDH_ERR_NO_CONNECTION_AT_HOST_CLOSE_DEV = 103106;
+
+    HIDH_ERR_INVALID_PARAM_AT_SEND_DATA = 103107;
+    HIDH_ERR_INVALID_PARAM_AT_HOST_REGISTER = 103108;
+    HIDH_ERR_INVALID_PARAM_AT_HOST_REMOVE_DEV = 103109;
+    HIDH_ERR_INVALID_PARAM_AT_HOST_OPEN_DEV = 103110;
+    HIDH_ERR_INVALID_PARAM_AT_HOST_CLOSE_DEV = 103111;
+    HIDH_ERR_INVALID_PARAM_AT_HOST_WRITE_DEV = 103112;
+
+    HIDH_ERR_CONGESTED_AT_SEND_DATA = 103113;
+    HIDH_ERR_CONGESTED_AT_FLAG_CHECK = 103114;
+    HIDH_ERR_CONN_IN_PROCESS = 103115;
+    HIDH_ERR_ALREADY_CONN = 103116;
+
+    HIDH_ERR_L2CAP_FAILED_AT_INITIATE = 103117;
+    HIDH_ERR_L2CAP_FAILED_AT_REGISTER_CONTROL = 103118;
+    HIDH_ERR_L2CAP_FAILED_AT_REGISTER_INTERRUPT = 103119;
+
+    HIDH_ERR_AUTH_FAILED = 103120;
+    HIDH_ERR_SDP_BUSY = 103121;
+
+    //Native and Java
+    HIDH_COUNT_MAX_ADDED_DEVICE_LIMIT_REACHED = 103122;
+    HIDH_COUNT_VIRTUAL_UNPLUG_REQUESTED_BY_REMOTE_DEVICE = 103123;
+    HIDH_COUNT_CONNECT_REQ_WHEN_MAX_DEVICE_LIMIT_REACHED = 103124;
+    HIDH_COUNT_WRONG_REPORT_TYPE = 103125;
+    HIDH_COUNT_INCOMING_CONNECTION_REJECTED = 103126;
+    HIDH_COUNT_CONNECTION_POLICY_DISABLED = 103127;
+    HIDH_COUNT_SUPPORT_BOTH_HID_AND_HOGP = 103128;
+    HIDH_COUNT_SUPPORT_ONLY_HID_OR_HOGP = 103129;
+
+
+  // [120,000 - 120,500) LE scan related
+    // [120,000 - 120,100) LE scan enable/disable count
+    LE_SCAN_COUNT_TOTAL_ENABLE = 120000;
+    LE_SCAN_COUNT_TOTAL_DISABLE = 120001;
+    LE_SCAN_COUNT_FILTERED_ENABLE = 120002;
+    LE_SCAN_COUNT_FILTERED_DISABLE = 120003;
+    LE_SCAN_COUNT_UNFILTERED_ENABLE = 120004;
+    LE_SCAN_COUNT_UNFILTERED_DISABLE = 120005;
+    LE_SCAN_COUNT_BATCH_ENABLE = 120006;
+    LE_SCAN_COUNT_BATCH_DISABLE = 120007;
+    LE_SCAN_COUNT_AUTO_BATCH_ENABLE = 120008;
+    LE_SCAN_COUNT_AUTO_BATCH_DISABLE =  120009;
+
+    // [120,100 - 120,200) LE scan duration bucket count
+    LE_SCAN_DURATION_COUNT_REGULAR_10S = 120100;
+    LE_SCAN_DURATION_COUNT_REGULAR_1M = 120101;
+    LE_SCAN_DURATION_COUNT_REGULAR_10M = 120102;
+    LE_SCAN_DURATION_COUNT_REGULAR_1H =120103;
+    LE_SCAN_DURATION_COUNT_REGULAR_1HP =120104;
+    LE_SCAN_DURATION_COUNT_BATCH_10S = 120105;
+    LE_SCAN_DURATION_COUNT_BATCH_1M = 120106;
+    LE_SCAN_DURATION_COUNT_BATCH_10M = 120107;
+    LE_SCAN_DURATION_COUNT_BATCH_1H = 120108;
+    LE_SCAN_DURATION_COUNT_BATCH_1HP = 120109;
+
+    // [120,200 - 120,250) LE scan radio active duration
+    LE_SCAN_RADIO_DURATION_ALL = 120200;
+    LE_SCAN_RADIO_DURATION_REGULAR = 120201;
+    LE_SCAN_RADIO_DURATION_BATCH = 120202;
+    LE_SCAN_RADIO_DURATION_REGULAR_SCREEN_ON = 120203;
+    LE_SCAN_RADIO_DURATION_REGULAR_SCREEN_OFF = 120204;
+    LE_SCAN_RADIO_DURATION_BATCH_SCREEN_ON = 120205;
+    LE_SCAN_RADIO_DURATION_BATCH_SCREEN_OFF = 120206;
+
+    // [120,250 - 120,300) LE scan radio scan mode count
+    LE_SCAN_RADIO_SCAN_MODE_OPPORTUNISTIC_COUNT = 120250;
+    LE_SCAN_RADIO_SCAN_MODE_LOW_POWER_COUNT = 120251;
+    LE_SCAN_RADIO_SCAN_MODE_BALANCED_COUNT = 120252;
+    LE_SCAN_RADIO_SCAN_MODE_LOW_LATENCY_COUNT = 120253;
+    LE_SCAN_RADIO_SCAN_MODE_AMBIENT_DISCOVERY_COUNT = 120254;
+    LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_COUNT = 120255;
+    LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_BALANCED_COUNT = 120256;
+    LE_SCAN_RADIO_SCAN_MODE_OPPORTUNISTIC_COUNT_SCREEN_OFF = 120257;
+    LE_SCAN_RADIO_SCAN_MODE_LOW_POWER_COUNT_SCREEN_OFF = 120258;
+    LE_SCAN_RADIO_SCAN_MODE_BALANCED_COUNT_SCREEN_OFF = 120259;
+    LE_SCAN_RADIO_SCAN_MODE_LOW_LATENCY_COUNT_SCREEN_OFF = 120260;
+    LE_SCAN_RADIO_SCAN_MODE_AMBIENT_DISCOVERY_COUNT_SCREEN_OFF = 120261;
+    LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_COUNT_SCREEN_OFF = 120262;
+    LE_SCAN_RADIO_SCAN_MODE_SCREEN_OFF_BALANCED_COUNT_SCREEN_OFF = 120263;
+
+    // [120,300 - 120,400) LE scan results count
+    LE_SCAN_RESULTS_COUNT_ALL = 120300;
+    LE_SCAN_RESULTS_COUNT_REGULAR = 120301;
+    LE_SCAN_RESULTS_COUNT_BATCH = 120302;
+    LE_SCAN_RESULTS_COUNT_REGULAR_SCREEN_ON = 120303;
+    LE_SCAN_RESULTS_COUNT_REGULAR_SCREEN_OFF =  120304;
+    LE_SCAN_RESULTS_COUNT_BATCH_SCREEN_ON = 120305;
+    LE_SCAN_RESULTS_COUNT_BATCH_SCREEN_OFF = 120306;
+    LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE = 120307;
+    LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE_SCREEN_ON = 120308;
+    LE_SCAN_RESULTS_COUNT_BATCH_BUNDLE_SCREEN_OFF = 120309;
+
+    // [120,400 - 120,500) LE scan abuse count
+    LE_SCAN_ABUSE_COUNT_SCAN_TIMEOUT = 120400;
+    LE_SCAN_ABUSE_COUNT_HW_FILTER_NOT_AVAILABLE = 120401;
+    LE_SCAN_ABUSE_COUNT_TRACKING_HW_FILTER_NOT_AVAILABLE = 120402;
+
+  // [120,500 - 121,000) LE advertise related
+    // [120,500 - 120,600) LE advertise enable/disable count
+    LE_ADV_COUNT_ENABLE = 120500;
+    LE_ADV_COUNT_DISABLE = 120501;
+    LE_ADV_COUNT_CONNECTABLE_ENABLE = 120502;
+    LE_ADV_COUNT_CONNECTABLE_DISABLE = 120503;
+    LE_ADV_COUNT_PERIODIC_ENABLE = 120504;
+    LE_ADV_COUNT_PERIODIC_DISABLE = 120505;
+
+    // [120,600 - 120,700) LE advertise instance bucket count
+    LE_ADV_INSTANCE_COUNT_5 = 120600;
+    LE_ADV_INSTANCE_COUNT_10 = 120601;
+    LE_ADV_INSTANCE_COUNT_15 = 120602;
+    LE_ADV_INSTANCE_COUNT_15P = 120603;
+
+    // [120,700 - 120,800) LE advertise duration bucket count
+    LE_ADV_DURATION_COUNT_TOTAL_1M = 120700;
+    LE_ADV_DURATION_COUNT_TOTAL_30M = 120701;
+    LE_ADV_DURATION_COUNT_TOTAL_1H = 120702;
+    LE_ADV_DURATION_COUNT_TOTAL_3H = 120703;
+    LE_ADV_DURATION_COUNT_TOTAL_3HP = 120704;
+    LE_ADV_DURATION_COUNT_CONNECTABLE_1M = 120705;
+    LE_ADV_DURATION_COUNT_CONNECTABLE_30M = 120706;
+    LE_ADV_DURATION_COUNT_CONNECTABLE_1H = 120707;
+    LE_ADV_DURATION_COUNT_CONNECTABLE_3H = 120708;
+    LE_ADV_DURATION_COUNT_CONNECTABLE_3HP = 120709;
+    LE_ADV_DURATION_COUNT_PERIODIC_1M = 120710;
+    LE_ADV_DURATION_COUNT_PERIODIC_30M = 120711;
+    LE_ADV_DURATION_COUNT_PERIODIC_1H = 120712;
+    LE_ADV_DURATION_COUNT_PERIODIC_3H = 120713;
+    LE_ADV_DURATION_COUNT_PERIODIC_3HP = 120714;
+
+    // [120,800 - 120,900) LE advertise error count
+    LE_ADV_ERROR_ON_START_COUNT = 120800;
+
+    // [120,900 - 121,000) GATT Related Count
+    GATT_CLIENT_CONNECT_IS_DIRECT = 120900;
+    GATT_CLIENT_CONNECT_IS_AUTOCONNECT = 120901;
+    GATT_CLIENT_CONNECT_IS_DIRECT_IN_FOREGROUND = 120902;
+    GATT_CLIENT_CONNECT_IS_DIRECT_NOT_IN_FOREGROUND = 120903;
+    GATT_CLIENT_CONNECT_IS_AUTOCONNECT_IN_FOREGROUND = 120904;
+    GATT_CLIENT_CONNECT_IS_AUTOCONNECT_NOT_IN_FOREGROUND = 120905;
+    GATT_SERVER_CONNECT_IS_DIRECT_IN_FOREGROUND = 120906;
+    GATT_SERVER_CONNECT_IS_DIRECT_NOT_IN_FOREGROUND = 120907;
+    GATT_SERVER_CONNECT_IS_AUTOCONNECT_IN_FOREGROUND = 120908;
+    GATT_SERVER_CONNECT_IS_AUTOCONNECT_NOT_IN_FOREGROUND = 120909;
+
+  // [121,000 - 121,100) System state related
+    // [121,000 - 121,010) Screen on/off count
+    SCREEN_ON_EVENT = 121000;
+    SCREEN_OFF_EVENT = 121001;
+
+  // [121,100 - 122,000) Le Audio related
+    // [121,100 - 121,200) device/group health status count
+    LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_GOOD = 121100;
+    LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD = 121101;
+    LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_DB = 121102;
+    LE_AUDIO_ALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_CSIS = 121103;
+    LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_GOOD = 121104;
+    LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD = 121105;
+    LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_DB = 121106;
+    LE_AUDIO_NONALLOWLIST_DEVICE_HEALTH_STATUS_BAD_INVALID_CSIS = 121107;
+    LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_GOOD = 121108;
+    LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_TRENDING_BAD = 121109;
+    LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD = 121110;
+    LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_CIS_FAILED = 121111;
+    LE_AUDIO_ALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_SIGNALING_FAILED = 121112;
+    LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_GOOD = 121113;
+    LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_TRENDING_BAD = 121114;
+    LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD = 121115;
+    LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_CIS_FAILED = 121116;
+    LE_AUDIO_NONALLOWLIST_GROUP_HEALTH_STATUS_BAD_ONCE_SIGNALING_FAILED = 121117;
 }
 
 enum AddressTypeEnum {
-    ADDRESS_TYPE_PUBLIC = 0;
-    ADDRESS_TYPE_RANDOM = 1;
-    ADDRESS_TYPE_UNKNOWN = 0xFFFF;
+  ADDRESS_TYPE_PUBLIC = 0;
+  ADDRESS_TYPE_RANDOM = 1;
+  ADDRESS_TYPE_UNKNOWN = 0xFFFF;
 }
 
 // Major Class from packages/modules/Bluetooth/framework/java/android/bluetooth/BluetoothClass.java
 enum MajorClassEnum {
-    MAJOR_CLASS_UNCATEGORIZED = 0x1F00;
-    MAJOR_CLASS_MISC = 0x0000;
-    MAJOR_CLASS_COMPUTER = 0x0100;
-    MAJOR_CLASS_PHONE = 0x0200;
-    MAJOR_CLASS_NETWORKING = 0x0300;
-    MAJOR_CLASS_AUDIO_VIDEO = 0x0400;
-    MAJOR_CLASS_PERIPHERAL = 0x0500;
-    MAJOR_CLASS_IMAGING = 0x0600;
-    MAJOR_CLASS_WEARABLE = 0x0700;
-    MAJOR_CLASS_TOY = 0x0800;
-    MAJOR_CLASS_HEALTH = 0x0900;
+  MAJOR_CLASS_UNCATEGORIZED = 0x1F00;
+  MAJOR_CLASS_MISC = 0x0000;
+  MAJOR_CLASS_COMPUTER = 0x0100;
+  MAJOR_CLASS_PHONE = 0x0200;
+  MAJOR_CLASS_NETWORKING = 0x0300;
+  MAJOR_CLASS_AUDIO_VIDEO = 0x0400;
+  MAJOR_CLASS_PERIPHERAL = 0x0500;
+  MAJOR_CLASS_IMAGING = 0x0600;
+  MAJOR_CLASS_WEARABLE = 0x0700;
+  MAJOR_CLASS_TOY = 0x0800;
+  MAJOR_CLASS_HEALTH = 0x0900;
 }
 
 enum ProfileConnectionResult {
-    RESULT_UNKNOWN = 0;
-    RESULT_SUCCESS = 1;
-    RESULT_FAILURE = 2;
+  RESULT_UNKNOWN = 0;
+  RESULT_SUCCESS = 1;
+  RESULT_FAILURE = 2;
 }
 
 enum ProfileConnectionReason {
-    REASON_UNKNOWN = 0;
-    REASON_SUCCESS = 1;
-    REASON_UNEXPECTED_STATE = 2;
-    REASON_NATIVE_LAYER_REJECTED = 3;
-    REASON_INCOMING_CONN_REJECTED = 4;
+  REASON_UNKNOWN = 0;
+  REASON_SUCCESS = 1;
+  REASON_UNEXPECTED_STATE = 2;
+  REASON_NATIVE_LAYER_REJECTED = 3;
+  REASON_INCOMING_CONN_REJECTED = 4;
 }
 
 enum LeConnectionResult {
-    LE_CONNECTION_RESULT_UNKNOWN = 0;
-    LE_CONNECTION_RESULT_SUCCESS = 1;
-    LE_CONNECTION_RESULT_FAILURE = 2;
+  LE_CONNECTION_RESULT_UNKNOWN = 0;
+  LE_CONNECTION_RESULT_SUCCESS = 1;
+  LE_CONNECTION_RESULT_FAILURE = 2;
 }
 
 // Comment added to those whose enum names do not match the actual file names.
@@ -602,6 +632,15 @@ enum EventType {
   LE_DEVICE_IN_ACCEPT_LIST = 43;
   GATT_DISCONNECT_JAVA = 44;
   GATT_DISCONNECT_NATIVE = 45;
+  TRANSPORT_MATCH = 46;
+  HFP_SESSION = 47;
+  HFP_AG_VERSION = 48;
+  HFP_HF_VERSION = 49;
+  HFP_HF_FEATURES = 50;
+  SCO_SESSION = 51;
+  SCO_CODEC = 52;
+  TRANSITION = 53;
+  LE_CONNECTION_REJECTED = 54;
 }
 
 enum State {
@@ -696,41 +735,128 @@ enum State {
   USER_CANCELLATION = 88;
   DIRECT_CONNECT = 89;
   INDIRECT_CONNECT = 90;
+  HFP_CONNECTED = 91;
+  HFP_SLC_FAIL_CONNECTION = 92;
+  HFP_RFCOMM_CHANNEL_FAIL = 93;
+  HFP_RFCOMM_COLLISION_FAIL = 94;
+  HFP_RFCOMM_AG_OPEN_FAIL = 95;
+  HFP_CONNECT_FAIL = 96;
+  SCO_TELECOM_INITIATED_START = 97;
+  SCO_VIRTUAL_VOICE_INITIATED_START = 98;
+  SCO_VOICE_RECOGNITION_INITIATED_START = 99;
+  SCO_CONNECT_AUDIO_START = 100;
+  SCO_LINK_CREATED = 101;
+  SCO_AUDIO_CONNECTED = 102;
+  SCO_LINK_REMOVED = 103;
+  SCO_TELECOM_INITIATED_END = 104;
+  SCO_VIRTUAL_VOICE_INITIATED_END = 105;
+  SCO_VOICE_RECOGNITION_INITIATED_END = 106;
+  SCO_DISCONNECT_AUDIO_END = 107;
+  ILLEGAL_COMMAND = 108;
+  NO_CONNECTION = 109;
+  HW_FAILURE = 110;
+  MEMORY_FULL = 111;
+  MAX_NUMBER_OF_CONNECTIONS = 112;
+  MAX_NUM_OF_SCOS = 113;
+  CONNECTION_EXISTS = 114;
+  COMMAND_DISALLOWED = 115;
+  HOST_REJECT_RESOURCES = 116;
+  HOST_REJECT_SECURITY = 117;
+  ILLEGAL_PARAMETER_FMT = 118;
+  PEER_USER = 119;
+  REMOTE_LOW_RESOURCE = 120;
+  REMOTE_POWER_OFF = 121;
+  CONN_CAUSE_LOCAL_HOST = 122;
+  HOST_REJECT_DEVICE = 123;
+  UNSUPPORTED_REM_FEATURE = 124;
+  UNSPECIFIED = 125;
+  UNACCEPT_CONN_INTERVAL = 126;
+  UNIT_KEY_USED = 127;
+  DIFF_TRANSACTION_COLLISION = 128;
+  LMP_ERR_TRANS_COLLISION = 129;
+  CANCELLED_BY_LOCAL_HOST = 130;
+  MAX_ERR = 131;
+  UNDEFINED = 132;
+  BOND_BONDED_TO_ACTION_KEY_MISSING = 133;
+  ACTION_KEY_MISSING_TO_ENCRYPTION_CHANGE = 134;
+  ACTION_KEY_MISSING_TO_BOND_NONE = 135;
+  UNKNOWN_HCI_COMMAND = 136;
+  REMOTE_DEVICE_TERMINATED_CONNECTION_LOW_RESOURCES = 137;
+  REMOTE_DEVICE_TERMINATED_CONNECTION_POWER_OFF = 138;
+  UNKNOWN_LMP_PDU = 139;
+  VERSION_1_0 = 140;
+  VERSION_1_1 = 141;
+  VERSION_1_2 = 142;
+  VERSION_1_3 = 143;
+  VERSION_1_4 = 144;
+  VERSION_1_5 = 145;
+  VERSION_1_6 = 146;
+  VERSION_1_7 = 147;
+  VERSION_1_8 = 148;
+  VERSION_1_9 = 149;
+  VERSION_UNKNOWN = 150;
+  START_LOCAL_INITIATED = 151;
+  START_REMOTE_INITIATED = 152;
+  HFP_CONNECT_REJECT_FAIL = 153;
+  HFP_ACL_CONNECT_FAIL = 154;
+  ATTEMPT_IN_PROGRESS = 155;
+  CODEC_CVSD = 156;
+  CODEC_MSBC = 157;
+  CODEC_LC3 = 158;
+  CODEC_UNKNOWN = 159;
+  SCO_LINK_LOSS = 160;
+  CODEC_APTX_SWB_SETTINGS_Q0_MASK = 161;
+  CODEC_APTX_SWB_SETTINGS_Q1_MASK = 162;
+  CODEC_APTX_SWB_SETTINGS_Q2_MASK = 163;
+  CODEC_APTX_SWB_SETTINGS_Q3_MASK = 164;
+  SCO_VOICE_RECOGNITION_HEADSET_START = 165;
+  SCO_VOICE_RECOGNITION_HEADSET_END = 166;
+  SCO_VOICE_RECOGNITION_HEADSET_TIMEOUT = 167;
+  AUDIO_PORT_START_STREAM = 168;
+  AUDIO_PORT_STOP_STREAM = 169;
+  AUDIO_PROVIDER_STREAM_STARTED = 170;
 }
 
 enum RemoteDeviceTypeMetadata {
-    WATCH = 0;
-    UNTETHERED_HEADSET = 1;
-    STYLUS = 2;
-    SPEAKER = 3;
-    HEADSET = 4;
-    CARKIT = 5;
-    DEFAULT = 6;
-    NOT_AVAILABLE = 7;
+  WATCH = 0;
+  UNTETHERED_HEADSET = 1;
+  STYLUS = 2;
+  SPEAKER = 3;
+  HEADSET = 4;
+  CARKIT = 5;
+  DEFAULT = 6;
+  NOT_AVAILABLE = 7;
 }
 
 enum BroadcastAudioQualityType {
-   QUALITY_UNKNOWN = 0;
-   QUALITY_STANDARD = 1;
-   QUALITY_HIGH = 2;
+  QUALITY_UNKNOWN = 0;
+  QUALITY_STANDARD = 1;
+  QUALITY_HIGH = 2;
 }
 
 enum BroadcastSessionSetupStatus {
-   SETUP_STATUS_UNKNOWN = 0;
-   SETUP_STATUS_REQUESTED = 1;
-   SETUP_STATUS_CREATED = 2;
-   SETUP_STATUS_STREAMING = 3;
-   SETUP_STATUS_CREATE_FAILED = 4;
-   SETUP_STATUS_STREAMING_FAILED = 5;
+  SETUP_STATUS_UNKNOWN = 0;
+  SETUP_STATUS_REQUESTED = 1;
+  SETUP_STATUS_CREATED = 2;
+  SETUP_STATUS_STREAMING = 3;
+  SETUP_STATUS_CREATE_FAILED = 4;
+  SETUP_STATUS_STREAMING_FAILED = 5;
 }
 
 enum BroadcastSyncStatus {
-   SYNC_STATUS_UNKNOWN = 0;
-   SYNC_STATUS_SYNC_REQUESTED = 1;
-   SYNC_STATUS_PA_SYNC_SUCCESS = 2;
-   SYNC_STATUS_AUDIO_SYNC_SUCCESS = 3;
-   SYNC_STATUS_PA_SYNC_FAILED = 4;
-   SYNC_STATUS_PA_SYNC_NO_PAST = 5;
-   SYNC_STATUS_BIG_DECRYPT_FAILED = 6;
-   SYNC_STATUS_AUDIO_SYNC_FAILED = 7;
+  SYNC_STATUS_UNKNOWN = 0;
+  SYNC_STATUS_SYNC_REQUESTED = 1;
+  SYNC_STATUS_PA_SYNC_SUCCESS = 2;
+  SYNC_STATUS_AUDIO_SYNC_SUCCESS = 3;
+  SYNC_STATUS_PA_SYNC_FAILED = 4;
+  SYNC_STATUS_PA_SYNC_NO_PAST = 5;
+  SYNC_STATUS_BIG_DECRYPT_FAILED = 6;
+  SYNC_STATUS_AUDIO_SYNC_FAILED = 7;
+}
+
+enum BtaStatus {
+  BTA_STATUS_UNKNOWN = 0;
+  BTA_STATUS_SUCCESS = 1;
+  BTA_STATUS_FAILURE = 2;
+  BTA_STATUS_BUSY = 3;
 }
diff --git a/stats/enums/bluetooth/le/enums.proto b/stats/enums/bluetooth/le/enums.proto
index 0374153f..c5ae84dd 100644
--- a/stats/enums/bluetooth/le/enums.proto
+++ b/stats/enums/bluetooth/le/enums.proto
@@ -147,3 +147,12 @@ enum LeAdvStatusCode {
   ADV_STATUS_FAILED_INTERNAL_ERROR = 5;
   ADV_STATUS_FAILED_FEATURE_UNSUPPORTED = 6;
 }
+
+// App importance compared to foreground service (FGS).
+// Refer to ScanManager.java for the usage of the app importance
+enum AppImportance {
+  IMPORTANCE_UNKNOWN = 0;
+  IMPORTANCE_LOWER_THAN_FGS = 1;
+  IMPORTANCE_EQUAL_TO_FGS = 2;
+  IMPORTANCE_HIGHER_THAN_FGS = 3;
+}
diff --git a/stats/enums/bluetooth/rfcomm/enums.proto b/stats/enums/bluetooth/rfcomm/enums.proto
index 41fe52bd..7398936c 100644
--- a/stats/enums/bluetooth/rfcomm/enums.proto
+++ b/stats/enums/bluetooth/rfcomm/enums.proto
@@ -67,7 +67,7 @@ enum PortResult {
   PORT_RESULT_ERR_MAX = 26;
 }
 
-enum RfcommPortState{
+enum RfcommPortState {
   PORT_STATE_UNKNOWN = 0;
   PORT_STATE_SABME_WAIT_UA = 1;
   PORT_STATE_ORIG_WAIT_SEC_CHECK = 2;
@@ -76,3 +76,19 @@ enum RfcommPortState{
   PORT_STATE_DISC_WAIT_UA = 5;
   PORT_STATE_CLOSED = 6;
 }
+
+enum RfcommPortEvent {
+  PORT_EVENT_UNKNOWN = 0;
+  PORT_EVENT_SABME = 1;
+  PORT_EVENT_UA = 2;
+  PORT_EVENT_DM = 3;
+  PORT_EVENT_DISC = 4;
+  PORT_EVENT_UIH = 5;
+  PORT_EVENT_TIMEOUT = 6;
+  PORT_EVENT_OPEN = 7;
+  PORT_EVENT_ESTABLISH_RSP = 8;
+  PORT_EVENT_CLOSE = 9;
+  PORT_EVENT_CLEAR = 10;
+  PORT_EVENT_DATA = 11;
+  PORT_EVENT_SEC_COMPLETE = 12;
+}
diff --git a/stats/enums/corenetworking/OWNERS b/stats/enums/corenetworking/OWNERS
new file mode 100644
index 00000000..73a592f6
--- /dev/null
+++ b/stats/enums/corenetworking/OWNERS
@@ -0,0 +1 @@
+file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
diff --git a/stats/enums/corenetworking/certificatetransparency/OWNERS b/stats/enums/corenetworking/certificatetransparency/OWNERS
new file mode 100644
index 00000000..62cf4c0e
--- /dev/null
+++ b/stats/enums/corenetworking/certificatetransparency/OWNERS
@@ -0,0 +1,4 @@
+brambonne@google.com
+sandrom@google.com
+tweek@google.com
+bessiej@google.com
diff --git a/stats/enums/corenetworking/certificatetransparency/enums.proto b/stats/enums/corenetworking/certificatetransparency/enums.proto
new file mode 100644
index 00000000..bcedbc3c
--- /dev/null
+++ b/stats/enums/corenetworking/certificatetransparency/enums.proto
@@ -0,0 +1,47 @@
+syntax = "proto2";
+
+package android.os.statsd.corenetworking.certificatetransparency;
+
+option java_package = "com.android.os.corenetworking.certificatetransparency";
+
+// Next ID: 18
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
+    // Signature is missing for signature verification.
+    FAILURE_SIGNATURE_NOT_FOUND = 9;
+    // Log list signature verification failed.
+    FAILURE_SIGNATURE_VERIFICATION = 10;
+    // Log list version already exists on device. Install unable to be completed.
+    FAILURE_VERSION_ALREADY_EXISTS = 12;
+    // Public key for signature verification is missing.
+    FAILURE_PUBLIC_KEY_NOT_FOUND = 13;
+    // Log list signature is invalid (e.g. wrong format or algorithm).
+    FAILURE_SIGNATURE_INVALID = 14;
+    // Log list is invalid (e.g. not in JSON format).
+    FAILURE_LOG_LIST_INVALID = 15;
+    // Public key is not in the PEM allowlist.
+    FAILURE_PUBLIC_KEY_NOT_ALLOWED = 16;
+    // Public key is invalid (e.g. wrong format).
+    FAILURE_PUBLIC_KEY_INVALID = 17;
+    // Device is waiting for a Wi-Fi connection to proceed with the download, as
+    // it exceeds the size limit for downloads over the mobile network.
+    PENDING_WAITING_FOR_WIFI = 11;
+}
diff --git a/stats/enums/corenetworking/connectivity/enums.proto b/stats/enums/corenetworking/connectivity/enums.proto
index 8595aa01..78a880a2 100644
--- a/stats/enums/corenetworking/connectivity/enums.proto
+++ b/stats/enums/corenetworking/connectivity/enums.proto
@@ -82,4 +82,26 @@ enum TerribleErrorType {
   // Indicate the error state that the NetworkAgent sent messages to
   // connectivity service before it is connected.
   TYPE_MESSAGE_QUEUED_BEFORE_CONNECT = 1;
+  // Indicate the error state that the ConnectivityService attempts to
+  // cleanup the bypassing VPN permission for a delegate UID, however,
+  // netd doesn't know about this UID and allowBypassVpnOnNetwork API
+  // returns ENOENT.
+  TYPE_DISALLOW_BYPASS_VPN_FOR_DELEGATE_UID_ENOENT = 2;
+  // Indicate the error state that the legacy TetheringManager#tether API was called for Wifi.
+  TYPE_LEGACY_TETHER_WITH_TYPE_WIFI = 3;
+  // Indicate the error state that the legacy TetheringManager#tether API was called for Wifi P2P.
+  TYPE_LEGACY_TETHER_WITH_TYPE_WIFI_P2P = 4;
+  // Indicate the error state that the legacy TetheringManager#tether API was called for Wifi and
+  // tethering succeeded.
+  TYPE_LEGACY_TETHER_WITH_TYPE_WIFI_SUCCESS = 5;
+  // Indicate the error state that the legacy TetheringManager#tether API was called for Wifi P2P
+  // and tethering succeeded.
+  TYPE_LEGACY_TETHER_WITH_TYPE_WIFI_P2P_SUCCESS = 6;
+  // Indicate the error state that the entitlement check failed to
+  // createContextAsUser because the tethering package is not installed
+  // on that user.
+  TYPE_ENTITLEMENT_CREATE_CONTEXT_AS_USER_THROWS = 7;
+  // Indicate the error state that tethering was started with a placeholder request (i.e. we
+  // couldn't find a pending request for the link layer event).
+  TYPE_TETHER_WITH_PLACEHOLDER_REQUEST = 8;
 }
diff --git a/stats/enums/federatedcompute/enums.proto b/stats/enums/federatedcompute/enums.proto
index 367eff42..04da1d22 100644
--- a/stats/enums/federatedcompute/enums.proto
+++ b/stats/enums/federatedcompute/enums.proto
@@ -21,7 +21,7 @@ option java_outer_classname = "FederatedComputeProtoEnums";
 option java_multiple_files = true;
 
 // Enum used to track federated computation job stages.
-// Next Tag: 79
+// Next Tag: 87
 enum TrainingEventKind {
   // Undefined value.
   TRAIN_UNDEFINED = 0;
@@ -145,6 +145,16 @@ enum TrainingEventKind {
   // Always preceded by TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED.
   TRAIN_ELIGIBILITY_EVAL_COMPUTATION_ELIGIBLE = 51;
 
+  // Eligibility check failed during check-in due to min separation policy.
+  // Always preceded by TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED.
+  TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_SEPARATION = 85;
+
+  // Eligibility check failed during check-in due to data availability policy
+  // i.e. does not have minimum examples.
+  // Always preceded by TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED.
+  TRAIN_ELIGIBILITY_EVAL_COMPUTATION_NOT_ELIGIBLE_MIN_EXAMPLE = 86;
+
+
   // The status of FCP binds to client implemented ExampleStoreService.
   TRAIN_EXAMPLE_STORE_BIND_START = 62;
   TRAIN_EXAMPLE_STORE_BIND_SUCCESS = 63;
@@ -246,6 +256,13 @@ enum TrainingEventKind {
   // Client is authorized to report result.
   TRAIN_INITIATE_REPORT_RESULT_AUTH_SUCCEEDED = 48;
 
+  // Enums related to key attestation phase.
+  TRAIN_KEY_ATTESTATION_NO_SUCH_ALGORITHM_EXCEPTION = 79;
+  TRAIN_KEY_ATTESTATION_NO_SUCH_PROVIDER_EXCEPTION = 80;
+  TRAIN_KEY_ATTESTATION_IO_EXCEPTION = 81;
+  TRAIN_KEY_ATTESTATION_KEYSTORE_EXCEPTION = 82;
+  TRAIN_KEY_ATTESTATION_CERTIFICATE_EXCEPTION = 83;
+  TRAIN_KEY_ATTESTATION_ERROR = 84;
   // Client successfully generates an attestation record.
   TRAIN_KEY_ATTESTATION_SUCCEEDED = 49;
 
diff --git a/stats/enums/framework/compat/enums.proto b/stats/enums/framework/compat/enums.proto
index 1b22ff14..f39c773e 100644
--- a/stats/enums/framework/compat/enums.proto
+++ b/stats/enums/framework/compat/enums.proto
@@ -24,11 +24,12 @@ option java_multiple_files = true;
 // The freeform camera compatibility mode the activity is in at the time the
 // camera opened or closed signal is received.
 enum FreeformCameraCompatMode {
-  NONE = 0;
-  PORTRAIT_DEVICE_IN_LANDSCAPE = 1;
-  LANDSCAPE_DEVICE_IN_LANDSCAPE = 2;
-  PORTRAIT_DEVICE_IN_PORTRAIT = 3;
-  LANDSCAPE_DEVICE_IN_PORTRAIT = 4;
+  MODE_UNSPECIFIED = 0;
+  NONE = 1;
+  PORTRAIT_DEVICE_IN_LANDSCAPE = 2;
+  LANDSCAPE_DEVICE_IN_LANDSCAPE = 3;
+  PORTRAIT_DEVICE_IN_PORTRAIT = 4;
+  LANDSCAPE_DEVICE_IN_PORTRAIT = 5;
 }
 
 // Whether this state is logged on camera opened or closed.
diff --git a/stats/enums/healthfitness/api/enums.proto b/stats/enums/healthfitness/api/enums.proto
index de6bcc4f..24413ccb 100644
--- a/stats/enums/healthfitness/api/enums.proto
+++ b/stats/enums/healthfitness/api/enums.proto
@@ -112,6 +112,61 @@ enum ImportStatus {
   IMPORT_STATUS_ERROR_VERSION_MISMATCH = 5;
 }
 
+// START: Backup and Restore enums
+
+// Each of these represents a value in DataBackupType.java.
+enum DataBackupType {
+  DATA_BACKUP_TYPE_UNSPECIFIED = 0;
+  DATA_BACKUP_TYPE_FULL = 1;
+  DATA_BACKUP_TYPE_INCREMENTAL = 2;
+}
+
+// Each of these represents a value in DataBackupStatus.java.
+enum DataBackupStatus {
+  DATA_BACKUP_STATUS_ERROR_UNSPECIFIED = 0;
+
+  DATA_BACKUP_STATUS_ERROR_NONE = 1;
+  DATA_BACKUP_STATUS_ERROR_UNKNOWN = 2;
+  DATA_BACKUP_STATUS_ERROR_PARTIAL_BACKUP = 3;
+  DATA_BACKUP_STATUS_STARTED = 4;
+  DATA_BACKUP_STATUS_ERROR_INVALID_REQUEST = 5;
+}
+
+// Each of these represents a value in SettingsBackupStatus.java.
+enum SettingsBackupStatus {
+  SETTINGS_BACKUP_STATUS_ERROR_UNSPECIFIED = 0;
+
+  SETTINGS_BACKUP_STATUS_ERROR_NONE = 1;
+  SETTINGS_BACKUP_STATUS_ERROR_UNKNOWN = 2;
+  SETTINGS_BACKUP_STATUS_ERROR_COLLATION_FAILED = 3;
+  SETTINGS_BACKUP_STATUS_ERROR_PARTIAL_BACKUP = 4;
+  SETTINGS_BACKUP_STATUS_STARTED = 5;
+}
+
+// Each of these represents a value in DataRestoreStatus.java.
+enum DataRestoreStatus {
+  DATA_RESTORE_STATUS_ERROR_UNSPECIFIED = 0;
+
+  DATA_RESTORE_STATUS_ERROR_NONE = 1;
+  DATA_RESTORE_STATUS_ERROR_UNKNOWN = 2;
+  DATA_RESTORE_STATUS_ERROR_CONVERSION_FAILED = 3;
+  DATA_RESTORE_STATUS_ERROR_PARTIAL_RESTORE = 4;
+  DATA_RESTORE_STATUS_STARTED = 5;
+}
+
+// Each of these represents a value in SettingsRestoreStatus.java.
+enum SettingsRestoreStatus {
+  SETTINGS_RESTORE_STATUS_ERROR_UNSPECIFIED = 0;
+
+  SETTINGS_RESTORE_STATUS_ERROR_NONE = 1;
+  SETTINGS_RESTORE_STATUS_ERROR_UNKNOWN = 2;
+  SETTINGS_RESTORE_STATUS_ERROR_CONVERSION_FAILED = 3;
+  SETTINGS_RESTORE_STATUS_ERROR_PARTIAL_RESTORE = 4;
+  SETTINGS_RESTORE_STATUS_STARTED = 5;
+}
+
+// END: Backup and Restore enums
+
 enum DataType {
   DATA_TYPE_UNKNOWN = 0;
   DATA_TYPE_NOT_ASSIGNED = 1;
@@ -158,6 +213,7 @@ enum DataType {
   MENSTRUATION_PERIOD = 41;
   SLEEP_SESSION = 42;
   ACTIVITY_INTENSITY = 43;
+  NICOTINE_INTAKE = 44;
 }
 
 enum MedicalResourceType {
@@ -185,7 +241,8 @@ enum ForegroundState {
 enum MetricType {
   METRIC_TYPE_DIRECTIONAL_PAIRING_PER_DATA_TYPE = 0;
   METRIC_TYPE_DIRECTIONAL_PAIRING = 1;
-  METRIC_TYPE_NON_DIRECTIONAL_PAIRING = 2;
+
+  reserved 2;
 }
 
 
diff --git a/stats/enums/healthfitness/ui/enums.proto b/stats/enums/healthfitness/ui/enums.proto
index 350b6b9f..a3c97b90 100644
--- a/stats/enums/healthfitness/ui/enums.proto
+++ b/stats/enums/healthfitness/ui/enums.proto
@@ -177,6 +177,7 @@ enum ElementId {
     DISCONNECT_ALL_APPS_DIALOG_CONTAINER = 85;
     DISCONNECT_ALL_APPS_DIALOG_CANCEL_BUTTON = 86;
     DISCONNECT_ALL_APPS_DIALOG_REMOVE_ALL_BUTTON = 87;
+    DISCONNECT_ALL_APPS_DIALOG_DELETE_CHECKBOX = 288;
 
     // Request permissions
     ALLOW_PERMISSIONS_BUTTON = 88;
@@ -184,6 +185,7 @@ enum ElementId {
     ALLOW_ALL_SWITCH = 90;
     PERMISSION_SWITCH = 91;
     APP_RATIONALE_LINK = 92;
+    REQUEST_PERMISSIONS_HEADER = 297;
 
     // Request additional permissions
     ALLOW_COMBINED_ADDITIONAL_PERMISSIONS_BUTTON = 198;
@@ -295,6 +297,10 @@ enum ElementId {
     EDIT_SOURCE_LIST_BUTTON = 160;
     REORDER_APP_SOURCE_BUTTON = 162;
     REMOVE_APP_SOURCE_BUTTON = 163;
+    OPEN_APP_SOURCE_MENU_BUTTON = 289;
+    MOVE_APP_SOURCE_DOWN_MENU_BUTTON = 290;
+    MOVE_APP_SOURCE_UP_MENU_BUTTON = 291;
+    REMOVE_APP_SOURCE_MENU_BUTTON = 292;
 
     // Add an app page
     POTENTIAL_PRIORITY_APP_BUTTON = 161;
@@ -340,6 +346,10 @@ enum ElementId {
     IMPORT_SOURCE_LOCATION_CANCEL_BUTTON = 223;
     IMPORT_SOURCE_LOCATION_NEXT_BUTTON = 224;
     IMPORT_SOURCE_LOCATION_DOCUMENT_PROVIDER_BUTTON = 225;
+    IMPORT_SOURCE_LOCATION_ACCOUNT_PICKER_DIAGLOG_CONTAINER = 293;
+    IMPORT_SOURCE_LOCATION_ACCOUNT_PICKER_RADIO_BUTTON = 294;
+    IMPORT_SOURCE_LOCATION_ACCOUNT_PICKER_DIALOG_CANCEL_BUTTON = 295;
+    IMPORT_SOURCE_LOCATION_ACCOUNT_PICKER_DIALOG_CONFIRM_BUTTON = 296;
 
     // Import confirmation page
     IMPORT_CONFIRMATION_CANCEL_BUTTON = 226;
@@ -416,7 +426,7 @@ enum ElementId {
     CANCEL_WRITE_HEALTH_RECORDS_BUTTON = 287;
     // End of PHR
 
-    // Next available: 288;
+    // Next available: 298;
 }
 
 enum PageId {
diff --git a/stats/enums/jank/TEST_MAPPING b/stats/enums/jank/TEST_MAPPING
index 9d0b6042..1ab5d2de 100644
--- a/stats/enums/jank/TEST_MAPPING
+++ b/stats/enums/jank/TEST_MAPPING
@@ -1,24 +1,7 @@
 {
   "presubmit": [
     {
-      "name": "FrameworksCoreTests",
-      "options": [
-        {
-          "include-filter": "com.android.internal.jank.InteractionJankMonitorTest"
-        },
-        {
-          "include-filter": "com.android.internal.jank.FrameTrackerTest"
-        },
-        {
-          "include-filter": "com.android.internal.util.LatencyTrackerTest"
-        },
-        {
-          "exclude-annotation": "androidx.test.filters.FlakyTest"
-        },
-        {
-          "exclude-annotation": "org.junit.Ignore"
-        }
-      ],
+      "name": "FrameworksCoreTests_jank",
       "file_patterns": [
         "enums.proto"
       ]
diff --git a/stats/enums/jank/enums.proto b/stats/enums/jank/enums.proto
index e25125a8..f81cd79d 100644
--- a/stats/enums/jank/enums.proto
+++ b/stats/enums/jank/enums.proto
@@ -133,6 +133,17 @@ enum InteractionType {
     DESKTOP_MODE_EXIT_MODE_ON_LAST_WINDOW_CLOSE = 117;
     DESKTOP_MODE_SNAP_RESIZE = 118;
     DESKTOP_MODE_UNMAXIMIZE_WINDOW = 119;
+    DESKTOP_MODE_ENTER_FROM_OVERVIEW_MENU = 120;
+    LAUNCHER_OVERVIEW_TASK_DISMISS = 121;
+    DESKTOP_MODE_CLOSE_TASK = 122;
+    DESKTOP_MODE_APP_LAUNCH_FROM_INTENT = 123;
+    DESKTOP_MODE_APP_LAUNCH_FROM_ICON = 124;
+    DESKTOP_MODE_KEYBOARD_QUICK_SWITCH_APP_LAUNCH = 125;
+    LAUNCHER_WORK_UTILITY_VIEW_EXPAND = 126;
+    LAUNCHER_WORK_UTILITY_VIEW_SHRINK = 127;
+    DEFAULT_TASK_TO_TASK_ANIMATION = 128;
+    DESKTOP_MODE_MOVE_WINDOW_TO_DISPLAY = 129;
+    STATUS_BAR_APP_RETURN_TO_CALL_CHIP = 130;
 
     reserved 2;
     reserved 73 to 78; // For b/281564325.
@@ -193,4 +204,8 @@ enum ActionType {
     ACTION_NOTIFICATIONS_HIDDEN_FOR_MEASURE = 30;
     ACTION_NOTIFICATIONS_HIDDEN_FOR_MEASURE_WITH_SHADE_OPEN = 31;
     ACTION_KEYGUARD_FACE_UNLOCK_TO_HOME = 32;
+    ACTION_SHADE_WINDOW_DISPLAY_CHANGE = 33;
+    ACTION_DESKTOP_MODE_ENTER_APP_HANDLE_DRAG = 34;
+    ACTION_DESKTOP_MODE_ENTER_APP_HANDLE_MENU = 35;
+    ACTION_DESKTOP_MODE_EXIT_MODE = 36;
 }
diff --git a/stats/enums/media/router/OWNERS b/stats/enums/media/router/OWNERS
new file mode 100644
index 00000000..57974cb8
--- /dev/null
+++ b/stats/enums/media/router/OWNERS
@@ -0,0 +1,5 @@
+corakwue@google.com
+justinmcclain@google.com
+tkourim@google.com
+asapperstein@google.com
+aquilescanta@google.com
\ No newline at end of file
diff --git a/stats/enums/media/router/enums.proto b/stats/enums/media/router/enums.proto
new file mode 100644
index 00000000..2f00380e
--- /dev/null
+++ b/stats/enums/media/router/enums.proto
@@ -0,0 +1,53 @@
+/*
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
+syntax = "proto2";
+
+package android.media.router;
+option java_multiple_files = true;
+
+enum Result {
+  RESULT_UNSPECIFIED = 0;
+  RESULT_SUCCESS = 1;
+  RESULT_UNKNOWN_ERROR = 2;
+  RESULT_REJECTED = 3;
+  RESULT_NETWORK_ERROR = 4;
+  RESULT_ROUTE_NOT_AVAILABLE = 5;
+  RESULT_INVALID_COMMAND = 6;
+  RESULT_UNIMPLEMENTED = 7;
+  RESULT_FAILED_TO_REROUTE_SYSTEM_MEDIA = 8;
+  RESULT_PERMISSION_DENIED = 9;
+  RESULT_INVALID_ROUTE_ID = 10;
+  RESULT_INVALID_SESSION_ID = 11;
+  RESULT_DUPLICATE_SESSION_ID = 12;
+  RESULT_PROVIDER_CALLBACK_ERROR = 13;
+  RESULT_SYSTEM_SERVICE_ERROR = 14;
+  RESULT_MEDIA_STREAM_CREATION_FAILED = 15;
+  RESULT_MANAGER_RECORD_NOT_FOUND = 16;
+  RESULT_ROUTER_RECORD_NOT_FOUND = 17;
+}
+
+enum EventType {
+  EVENT_TYPE_UNSPECIFIED = 0;
+  EVENT_TYPE_CREATE_SESSION = 1;
+  EVENT_TYPE_CREATE_SYSTEM_ROUTING_SESSION = 2;
+  EVENT_TYPE_RELEASE_SESSION = 3;
+  EVENT_TYPE_SELECT_ROUTE = 4;
+  EVENT_TYPE_DESELECT_ROUTE = 5;
+  EVENT_TYPE_TRANSFER_TO_ROUTE = 6;
+  EVENT_TYPE_SCANNING_STARTED = 7;
+  EVENT_TYPE_SCANNING_STOPPED = 8;
+}
diff --git a/stats/enums/memory/enums.proto b/stats/enums/memory/enums.proto
new file mode 100644
index 00000000..34a0138c
--- /dev/null
+++ b/stats/enums/memory/enums.proto
@@ -0,0 +1,117 @@
+/*
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
+syntax = "proto2";
+
+package android.memory;
+
+option java_outer_classname = "MemoryEnums";
+option java_multiple_files = true;
+
+/**
+ * Result of zram writeback attempt.
+ *
+ * Next tag: 11
+ */
+enum ZramWritebackResult {
+    WRITEBACK_UNSPECIFIED = 0;
+    WRITEBACK_NOT_SUPPORTED = 1;
+    WRITEBACK_SUCCESS = 2;
+    WRITEBACK_BACKOFF_TIME = 3;
+    WRITEBACK_CALCULATE_IDLE_FAIL = 4;
+    WRITEBACK_MARK_IDLE_FAIL = 5;
+    WRITEBACK_TRIGGER_FAIL = 6;
+    WRITEBACK_LIMIT = 7;
+    WRITEBACK_INVALID_LIMIT = 8;
+    WRITEBACK_ACCESS_WRITEBACK_LIMIT_FAIL = 9;
+    WRITEBACK_LOAD_STATS_FAIL = 10;
+}
+
+/**
+ * Result of zram recompression attempt.
+ *
+ * Next tag: 7
+ */
+enum ZramRecompressionResult {
+    RECOMPRESSION_UNSPECIFIED = 0;
+    RECOMPRESSION_NOT_SUPPORTED = 1;
+    RECOMPRESSION_SUCCESS = 2;
+    RECOMPRESSION_BACKOFF_TIME = 3;
+    RECOMPRESSION_CALCULATE_IDLE_FAIL = 4;
+    RECOMPRESSION_MARK_IDLE_FAIL = 5;
+    RECOMPRESSION_TRIGGER_FAIL = 6;
+}
+
+/**
+ * Result of zram setup attempt.
+ *
+ * Next tag: 8
+ */
+enum ZramSetupResult {
+    ZRAM_SETUP_UNSPECIFIED = 0;
+    ZRAM_SETUP_SUCCESS = 1;
+    ZRAM_SETUP_CHECK_STATUS = 2;
+    ZRAM_SETUP_ACTIVATED = 3;
+    ZRAM_SETUP_PARSE_SPEC = 4;
+    ZRAM_SETUP_UPDATE_DISK_SIZE_FAIL = 5;
+    ZRAM_SETUP_SWAP_ON_FAIL = 6;
+    ZRAM_SETUP_MK_SWAP_FAIL = 7;
+}
+
+/**
+ * Result of zram compression algorithm update attempt.
+ *
+ * Next tag: 3
+ */
+enum ZramCompAlgorithmSetupResult {
+    COMP_ALGORITHM_SETUP_UNSPECIFIED = 0;
+    COMP_ALGORITHM_SETUP_SUCCESS = 1;
+    COMP_ALGORITHM_SETUP_FAIL = 2;
+}
+
+/**
+ * Result of zram writeback device setup attempt.
+ *
+ * Next tag: 12
+ */
+enum ZramWritebackSetupResult {
+    WRITEBACK_SETUP_UNSPECIFIED = 0;
+    WRITEBACK_SETUP_SUCCESS = 1;
+    WRITEBACK_SETUP_CHECK_STATUS = 2;
+    WRITEBACK_SETUP_NOT_SUPPORTED = 3;
+    WRITEBACK_SETUP_ACTIVATED = 4;
+    WRITEBACK_SETUP_PARSE_SPEC = 5;
+    WRITEBACK_SETUP_DEVICE_SIZE_ZERO = 6;
+    WRITEBACK_SETUP_SET_ACTUAL_DEVICE_SIZE_FAIL = 7;
+    WRITEBACK_SETUP_CREATE_BACKING_FILE_FAIL = 8;
+    WRITEBACK_SETUP_CREATE_BACKING_DEVICE_FAIL = 9;
+    WRITEBACK_SETUP_SET_WRITEBACK_DEVICE_FAIL = 10;
+    WRITEBACK_SETUP_WRITEBACK_LIMIT_ENABLE_FAIL = 11;
+}
+
+/**
+ * Result of zram recompression setup attempt.
+ *
+ * Next tag: 6
+ */
+enum ZramRecompressionSetupResult {
+    RECOMPRESSION_SETUP_UNSPECIFIED = 0;
+    RECOMPRESSION_SETUP_SUCCESS = 1;
+    RECOMPRESSION_SETUP_CHECK_STATUS = 2;
+    RECOMPRESSION_SETUP_NOT_SUPPORTED = 3;
+    RECOMPRESSION_SETUP_ACTIVATED = 4;
+    RECOMPRESSION_SETUP_SET_RECOMP_ALGORITHM_FAIL = 5;
+}
diff --git a/stats/enums/nfc/enums.proto b/stats/enums/nfc/enums.proto
index fffd8926..92fa0d2b 100644
--- a/stats/enums/nfc/enums.proto
+++ b/stats/enums/nfc/enums.proto
@@ -49,3 +49,10 @@ enum NfcTagType {
     TAG_MIFARE_CLASSIC = 7;
     TAG_KOVIO_BARCODE = 8;
 }
+
+// Proprietary NFC Frame Types
+enum NfcProprietaryFrameType {
+    NFC_FRAME_UNKNOWN = 0;
+    NFC_FRAME_ECP_V1 = 1;
+    NFC_FRAME_ECP_V2 = 2;
+}
diff --git a/stats/enums/notification/enums.proto b/stats/enums/notification/enums.proto
new file mode 100644
index 00000000..dba6b2ad
--- /dev/null
+++ b/stats/enums/notification/enums.proto
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
+package android.stats.notification;
+
+option java_package = "com.android.os.notification";
+option java_multiple_files = true;
+option java_outer_classname = "NotificationProtoEnums";
+
+/**
+ * Enum used in NotificationBundlePreferences.
+ * Keep in sync with frameworks/base/core/java/android/service/notification/Adjustment.java#Types
+ */
+enum BundleTypes {
+    TYPE_OTHER = 0;
+    TYPE_PROMOTION = 1;
+    TYPE_SOCIAL_MEDIA = 2;
+    TYPE_NEWS = 3;
+    TYPE_CONTENT_RECOMMENDATION = 4;
+}
\ No newline at end of file
diff --git a/stats/enums/photopicker/enums.proto b/stats/enums/photopicker/enums.proto
index 84a692ee..2e5cd79a 100644
--- a/stats/enums/photopicker/enums.proto
+++ b/stats/enums/photopicker/enums.proto
@@ -167,6 +167,19 @@ enum UiEvent {
   ENTER_PICKER_SEARCH = 32;
   SELECT_SEARCH_CATEGORY = 33;
   UNSET_UI_EVENT = 34;
+  SELECT_SEARCH_RESULT = 35;
+  PICKER_CATEGORIES_INTERACTION = 36;
+  CATEGORIES_PEOPLEPET_OPEN = 37;
+  CATEGORIES_MEDIA_SETS_OPEN = 38;
+  UI_LOADED_CATEGORIES_AND_ALBUMS = 39;
+  UI_LOADED_MEDIA_SETS = 40;
+  UI_LOADED_MEDIA_SETS_CONTENTS = 41;
+  UI_LOADED_SEARCH_SUGGESTIONS = 42;
+  UI_LOADED_SEARCH_RESULTS = 43;
+  UI_LOADED_EMPTY_STATE = 44;
+  PICKER_TRANSCODING_STARTED = 45;
+  PICKER_TRANSCODING_FINISHED = 46;
+  PICKER_TRANSCODING_FAILED = 47;
 }
 
 /*
@@ -249,3 +262,23 @@ enum SearchMethod {
   UNSET_SEARCH_METHOD = 3;
   CATEGORY_SEARCH = 4;
 }
+
+/*
+ Different video HDR formats
+ */
+enum AppMediaCapabilityHdrType {
+  TYPE_UNSPECIFIED= 0;
+  TYPE_DOLBY_VISION = 1;
+  TYPE_HDR10 = 2;
+  TYPE_HDR10_PLUS = 3;
+  TYPE_HLG = 4;
+}
+
+/*
+ Different video mime types
+*/
+enum VideoMimeType {
+  MIME_UNSPECIFIED = 0;
+  MIME_DOLBY = 1;
+  MIME_HEVC = 2;
+}
diff --git a/stats/enums/ranging/enums.proto b/stats/enums/ranging/enums.proto
index 822718a4..0f38a324 100644
--- a/stats/enums/ranging/enums.proto
+++ b/stats/enums/ranging/enums.proto
@@ -48,21 +48,14 @@ enum DeviceRole {
   ROLE_INITIATOR = 2;
 }
 
-
-enum ClosedReason {
-  CLOSED_REASON_UNKNOWN = 0;
-  CLOSED_REASON_LOCAL_REQUEST = 1;
-  CLOSED_REASON_REMOTE_REQUEST = 2;
-  CLOSED_REASON_UNSUPPORTED = 3;
-  CLOSED_REASON_SYSTEM_POLICY = 4;
-  CLOSED_REASON_NO_PEERS_FOUND = 5;
-}
-
-enum StoppedReason {
-  STOPPED_REASON_UNKNOWN = 0;
-  STOPPED_REASON_ERROR = 1;
-  STOPPED_REASON_REQUESTED = 2;
-  STOPPED_REASON_UNSUPPORTED = 3;
-  STOPPED_REASON_SYSTEM_POLICY = 4;
-  STOPPED_REASON_LOST_CONNECTION = 5;
+enum Reason {
+  REASON_UNKNOWN = 0;
+  REASON_LOCAL_REQUEST = 1;
+  REASON_REMOTE_REQUEST = 2;
+  REASON_UNSUPPORTED = 3;
+  REASON_SYSTEM_POLICY = 4;
+  REASON_NO_PEERS_FOUND = 5;
+  REASON_INTERNAL_ERROR = 6;
+  REASON_BACKGROUND_RANGING_POLICY = 7;
+  REASON_PEER_CAPABILITIES_MISMATCH = 8;
 }
\ No newline at end of file
diff --git a/stats/enums/security/advancedprotection/OWNERS b/stats/enums/security/advancedprotection/OWNERS
new file mode 100644
index 00000000..9bf5e58c
--- /dev/null
+++ b/stats/enums/security/advancedprotection/OWNERS
@@ -0,0 +1 @@
+file:platform/frameworks/base:main:/core/java/android/security/advancedprotection/OWNERS
diff --git a/stats/enums/security/advancedprotection/enums.proto b/stats/enums/security/advancedprotection/enums.proto
new file mode 100644
index 00000000..7b777866
--- /dev/null
+++ b/stats/enums/security/advancedprotection/enums.proto
@@ -0,0 +1,38 @@
+/*
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
+syntax = "proto2";
+
+package android.security.advancedprotection;
+
+option java_outer_classname = "AdvancedProtectionProtoEnums";
+option java_multiple_files = true;
+
+// Enum should be the same as in AdvancedProtectionManager.java
+enum FeatureId {
+    FEATURE_ID_UNKNOWN = 0;
+    FEATURE_ID_DISALLOW_CELLULAR_2G = 1;
+    FEATURE_ID_DISALLOW_INSTALL_UNKNOWN_SOURCES = 2;
+    FEATURE_ID_DISALLOW_USB = 3;
+    FEATURE_ID_DISALLOW_WEP = 4;
+    FEATURE_ID_ENABLE_MTE = 5;
+}
+
+enum DialogueType {
+    DIALOGUE_TYPE_UNKNOWN = 0;
+    DIALOGUE_TYPE_BLOCKED_INTERACTION = 1;
+    DIALOGUE_TYPE_DISABLED_SETTING = 2;
+}
diff --git a/stats/enums/stats/accessibility/accessibility_enums.proto b/stats/enums/stats/accessibility/accessibility_enums.proto
index a55e4c69..4b9e1d20 100644
--- a/stats/enums/stats/accessibility/accessibility_enums.proto
+++ b/stats/enums/stats/accessibility/accessibility_enums.proto
@@ -72,5 +72,6 @@ enum TextReadingEntry {
   TEXT_READING_SUW_ANYTHING_ELSE = 2;
   TEXT_READING_DISPLAY_SETTINGS = 3;
   TEXT_READING_ACCESSIBILITY_SETTINGS = 4;
+  TEXT_READING_HIGH_CONTRAST_TEXT_NOTIFICATION = 5;
 }
 
diff --git a/stats/enums/stats/connectivity/OWNERS b/stats/enums/stats/connectivity/OWNERS
new file mode 100644
index 00000000..73a592f6
--- /dev/null
+++ b/stats/enums/stats/connectivity/OWNERS
@@ -0,0 +1 @@
+file:platform/packages/modules/Connectivity:main:/OWNERS_core_networking
diff --git a/stats/enums/stats/connectivity/network_stack.proto b/stats/enums/stats/connectivity/network_stack.proto
index c465f07e..98a09f2b 100644
--- a/stats/enums/stats/connectivity/network_stack.proto
+++ b/stats/enums/stats/connectivity/network_stack.proto
@@ -296,6 +296,23 @@ enum CounterName {
    CN_DROPPED_ARP_REQUEST_ANYHOST = 47;
    CN_DROPPED_ARP_REQUEST_REPLIED = 48;
    CN_DROPPED_ARP_V6_ONLY = 49;
+   CN_DROPPED_IPV4_TCP_PORT7_UNICAST = 50;
+   CN_DROPPED_IPV4_ICMP_INVALID = 51;
+   CN_DROPPED_IPV4_PING_REQUEST_REPLIED = 52;
+   CN_DROPPED_IGMP_INVALID = 53;
+   CN_DROPPED_IGMP_V3_GENERAL_QUERY_REPLIED = 54;
+   CN_DROPPED_IGMP_V2_GENERAL_QUERY_REPLIED = 55;
+   CN_DROPPED_IGMP_REPORT = 56;
+   CN_PASSED_OUR_SRC_MAC = 57;
+   CN_PASSED_IPV6_HOPOPTS = 58;
+   CN_DROPPED_ETHER_OUR_SRC_MAC = 59;
+   CN_DROPPED_IPV6_ICMP6_ECHO_REQUEST_INVALID = 60;
+   CN_DROPPED_IPV6_ICMP6_ECHO_REQUEST_REPLIED = 61;
+   CN_DROPPED_IPV6_MLD_INVALID = 62;
+   CN_DROPPED_IPV6_MLD_REPORT = 63;
+   CN_DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED = 64;
+   CN_DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED = 65;
+   CN_DROPPED_MDNS_REPLIED = 66;
 }
 
 message NetworkStackEventData {
diff --git a/stats/enums/telecomm/enums.proto b/stats/enums/telecomm/enums.proto
index 309fc577..1fc9247b 100644
--- a/stats/enums/telecomm/enums.proto
+++ b/stats/enums/telecomm/enums.proto
@@ -265,6 +265,15 @@ enum AccountTypeEnum {
      ACCOUNT_SELFMANAGED = 2;
      ACCOUNT_SIM = 3;
      ACCOUNT_VOIP_API = 4;
+     /**
+      * A VoIP call that was made without the telecom framework.
+      */
+     ACCOUNT_NON_TELECOM_VOIP = 5;
+     /**
+      * A VoIP call that was made without the telecom framework where the app has declared support
+      * for telecom but chose not to use it.
+      */
+     ACCOUNT_NON_TELECOM_VOIP_WITH_TELECOM_SUPPORT = 6;
 }
 
 /**
@@ -407,3 +416,41 @@ enum ErrorEnum {
     ERROR_STUCK_CONNECTING_EMERGENCY = 23;
     ERROR_STUCK_CONNECTING = 24;
 }
+
+/**
+ * Indicating the simultaneous call type
+ */
+enum SimultaneousTypeEnum {
+    TYPE_UNKNOWN = 0;
+    TYPE_SIMULTANEOUS_DISABLED_SAME_ACCOUNT = 1;
+    TYPE_SIMULTANEOUS_DISABLED_DIFF_ACCOUNT = 2;
+    TYPE_DUAL_SAME_ACCOUNT = 3;
+    TYPE_DUAL_DIFF_ACCOUNT = 4;
+}
+
+/**
+ * Indicating telecom key event name
+ */
+enum EventEnum {
+    EVENT_UNKNOWN = 0;
+    EVENT_INIT = 1;
+    EVENT_DEFAULT_DIALER_CHANGED = 2;
+    EVENT_ADD_CALL = 3;
+}
+
+/**
+ * Indicating the cause of telecom key event
+ */
+enum EventCauseEnum {
+    CAUSE_UNKNOWN = 0;
+    CAUSE_GENERIC_SUCCESS = 1;
+    CAUSE_GENERIC_FAILURE = 2;
+    // [1,000 - 1,100) Call transaction result
+    CALL_TRANSACTION_SUCCESS = 1000;
+    CALL_TRANSACTION_ERROR_UNKNOWN = 1001;
+    CALL_TRANSACTION_CANNOT_HOLD_CURRENT_ACTIVE_CALL = 1002;
+    CALL_TRANSACTION_CALL_IS_NOT_BEING_TRACKED = 1003;
+    CALL_TRANSACTION_CALL_CANNOT_BE_SET_TO_ACTIVE = 1004;
+    CALL_TRANSACTION_CALL_NOT_PERMITTED_AT_PRESENT_TIME = 1005;
+    CALL_TRANSACTION_CODE_OPERATION_TIMED_OUT = 1006;
+}
diff --git a/stats/enums/telephony/enums.proto b/stats/enums/telephony/enums.proto
index ab1376bf..e52bbd50 100644
--- a/stats/enums/telephony/enums.proto
+++ b/stats/enums/telephony/enums.proto
@@ -90,7 +90,6 @@ enum NetworkTypeEnum {
     NETWORK_TYPE_IWLAN = 18;
     NETWORK_TYPE_LTE_CA = 19;
     NETWORK_TYPE_NR = 20;
-    NETWORK_TYPE_NB_IOT_NTN = 21;
 }
 
 // Cellular radio power state, see android/telephony/TelephonyManager.java for definitions.
diff --git a/stats/enums/telephony/iwlan/enums.proto b/stats/enums/telephony/iwlan/enums.proto
index d8913c50..d8277136 100644
--- a/stats/enums/telephony/iwlan/enums.proto
+++ b/stats/enums/telephony/iwlan/enums.proto
@@ -17,6 +17,7 @@
 syntax = "proto2";
 package android.telephony.iwlan;
 
+option java_package = "com.android.os.telephony.iwlan";
 option java_outer_classname = "IwlanProtoEnums";
 option java_multiple_files = true;
 
diff --git a/stats/enums/telephony/satellite/enums.proto b/stats/enums/telephony/satellite/enums.proto
index 4147686f..3f3fdf20 100644
--- a/stats/enums/telephony/satellite/enums.proto
+++ b/stats/enums/telephony/satellite/enums.proto
@@ -159,4 +159,19 @@ enum TriggeringEvent {
   TRIGGERING_EVENT_MCC_CHANGED = 2;
   //Satellite Access Controller has been triggered due to the location setting being enabled
   TRIGGERING_EVENT_LOCATION_SETTINGS_ENABLED = 3;
+  // Satellite Access Controller has been triggered due to the location setting being disabled.
+   TRIGGERING_EVENT_LOCATION_SETTINGS_DISABLED = 4;
+  // Satellite Access Controller has been triggered due to the config data updated.
+  TRIGGERING_EVENT_CONFIG_DATA_UPDATED = 5;
+}
+
+enum SatelliteEntitlementServicePolicy {
+  // Satellite service policy entitlement status is Unknown
+  SATELLITE_ENTITLEMENT_SERVICE_POLICY_UNKNOWN = 0;
+  // Satellite service policy entitlement status is restricted
+  SATELLITE_ENTITLEMENT_SERVICE_POLICY_RESTRICTED = 1;
+  // Satellite service policy entitlement is constrained
+  SATELLITE_ENTITLEMENT_SERVICE_POLICY_CONSTRAINED = 2;
+  // Satellite service policy entitlement is unconstrained
+  SATELLITE_ENTITLEMENT_SERVICE_POLICY_SUPPORT_ALL = 3;
 }
diff --git a/stats/enums/view/inputmethod/enums.proto b/stats/enums/view/inputmethod/enums.proto
index 67967a4f..580bfb94 100644
--- a/stats/enums/view/inputmethod/enums.proto
+++ b/stats/enums/view/inputmethod/enums.proto
@@ -83,6 +83,7 @@ enum SoftInputShowHideReasonEnum {
     REASON_SHOW_INPUT_TARGET_CHANGED = 56;
     REASON_HIDE_INPUT_TARGET_CHANGED = 57;
     REASON_HIDE_WINDOW_LOST_FOCUS = 58;
+    REASON_IME_REQUESTED_CHANGED_LISTENER = 59;
 }
 
 // The type of the IME request, used by android/view/inputmethod/ImeTracker.java.
@@ -278,6 +279,23 @@ enum ImeRequestPhaseEnum {
     PHASE_WM_DISPLAY_IME_CONTROLLER_SET_IME_REQUESTED_VISIBLE = 68;
     // The control target reported its requestedVisibleTypes back to WindowManagerService.
     PHASE_WM_UPDATE_DISPLAY_WINDOW_REQUESTED_VISIBLE_TYPES = 69;
-
+    // The requestedVisibleTypes have not been changed, so this request is not continued.
+    PHASE_WM_REQUESTED_VISIBLE_TYPES_NOT_CHANGED = 70;
+    // Updating the currently animating types on the client side.
+    PHASE_CLIENT_UPDATE_ANIMATING_TYPES = 71;
+    // Updating the animating types in the WindowState on the WindowManager side.
+    PHASE_WM_UPDATE_ANIMATING_TYPES = 72;
+    // Animating types of the WindowState have changed, now sending them to state controller.
+    PHASE_WM_WINDOW_ANIMATING_TYPES_CHANGED = 73;
+    // ImeInsetsSourceProvider got notified that the hide animation is finished.
+    PHASE_WM_NOTIFY_HIDE_ANIMATION_FINISHED = 74;
+    // The control target reported its animatingTypes back to WindowManagerService.
+    PHASE_WM_UPDATE_DISPLAY_WINDOW_ANIMATING_TYPES = 75;
+    // InsetsController received a control for the IME.
+    PHASE_CLIENT_ON_CONTROLS_CHANGED = 76;
+    // Reached the IME invoker on the server.
+    PHASE_SERVER_IME_INVOKER = 77;
+    // Reached the IME client invoker on the server.
+    PHASE_SERVER_CLIENT_INVOKER = 78;
 }
 
diff --git a/stats/enums/wear/connectivity/enums.proto b/stats/enums/wear/connectivity/enums.proto
index 820b5375..36fb699a 100644
--- a/stats/enums/wear/connectivity/enums.proto
+++ b/stats/enums/wear/connectivity/enums.proto
@@ -202,7 +202,7 @@ enum SysproxyConnectionAction {
 }
 
 /**
- * Keep sorted order in each block. Last enum num is 13
+ * Keep sorted order in each block. Last enum num is 32
  */
 enum SysproxyConnectionChangeReason {
     SYSPROXY_CONNECTION_CHANGE_REASON_UNKNOWN = 0;
@@ -215,6 +215,7 @@ enum SysproxyConnectionChangeReason {
     PROXY_ON_PSM_UPDATE = 5;
     PROXY_ON_V2_PARAMS_CHANGED = 6;
     PROXY_ON_UUID_LIST_CHANGED = 7;
+    PROXY_ON_SOCKET_SWITCH = 30;
 
     //stopProxyShard
     PROXY_OFF_ACL_DISCONNECT = 8;
@@ -241,6 +242,7 @@ enum SysproxyConnectionChangeReason {
     SERVICE_STOP_BT_READ_EMPTY = 27;
     SERVICE_STOP_BT_HANDSHAKE_ERR = 28;
     SERVICE_STOP_STOP_BY_CONTROL_SERVER = 29;
+    SERVICE_STOP_BT_DATA_CORRUPTED = 31;
 
 }
 
@@ -259,6 +261,12 @@ enum SysproxyIptablesState {
     IPTABLES_RULES_TEARDOWN_FAILURE = 4;
 }
 
+enum SysproxyTransportType {
+    SYSPROXY_TRANSPORT_TYPE_UNKNOWN = 0;
+    BLE = 1;
+    BTC = 2;
+}
+
 /**
  * Keep sorted order in each block. Last enum num is 2
  */
diff --git a/stats/enums/wifi/OWNERS b/stats/enums/wifi/OWNERS
index 0a0f201f..d3967205 100644
--- a/stats/enums/wifi/OWNERS
+++ b/stats/enums/wifi/OWNERS
@@ -1,5 +1,4 @@
 # make sure everyone listed in OWNERS read http://go/ww-own-enums
 xshu@google.com
-etancohen@google.com
 arabawy@google.com
 satk@google.com
diff --git a/stats/enums/wifi/enums.proto b/stats/enums/wifi/enums.proto
index 6e7e6636..b1f3d87b 100644
--- a/stats/enums/wifi/enums.proto
+++ b/stats/enums/wifi/enums.proto
@@ -48,6 +48,12 @@ enum WifiModeEnum {
      * Wi-Fi will operate with a priority to achieve low latency.
      */
     WIFI_MODE_FULL_LOW_LATENCY = 4;
+
+    /**
+     * Wi-Fi will not filter packets addressed to multicast addresses. This allows the device
+     * to receive multicast packets, but can lead to noticeable battery drain.
+     */
+    WIFI_MODE_MULTICAST_FILTERING_DISABLED = 5;
 }
 
 /**
diff --git a/stats/express/catalog/accessibility.cfg b/stats/express/catalog/accessibility.cfg
index a2e8874c..e9d0bbf7 100644
--- a/stats/express/catalog/accessibility.cfg
+++ b/stats/express/catalog/accessibility.cfg
@@ -75,3 +75,33 @@ express_metric {
         }
     }
 }
+
+express_metric {
+    id: "accessibility.value_hct_notification_posted"
+    display_name: "High Contrast Text Notification Posted"
+    description: "Counter indicating the notification for HCT migration was posted for this user"
+    owner_email: "danielnorman@google.com"
+    owner_email: "low-vision-eng@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
+express_metric {
+    id: "accessibility.value_hct_notification_opened_settings"
+    display_name: "High Contrast Text Notification Opened Settings"
+    description: "Counter indicating the notification for HCT migration was tapped by this user to open the HCT Settings page"
+    owner_email: "danielnorman@google.com"
+    owner_email: "low-vision-eng@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
+
+express_metric {
+    id: "accessibility.value_hct_notification_dismissed"
+    display_name: "High Contrast Text Notification Dismissed"
+    description: "Counter indicating the notification for HCT migration was dismissed for this user"
+    owner_email: "chenjean@google.com"
+    owner_email: "low-vision-eng@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER
+}
\ No newline at end of file
diff --git a/stats/express/catalog/core_networking.cfg b/stats/express/catalog/core_networking.cfg
index 97aaca73..2292534a 100644
--- a/stats/express/catalog/core_networking.cfg
+++ b/stats/express/catalog/core_networking.cfg
@@ -17,3 +17,12 @@ express_metric {
     owner_email: "xiaom@google.com"
     unit: UNIT_COUNT
 }
+
+express_metric {
+    id: "core_networking.value_httpengine_preload_attempt_count"
+    type: COUNTER
+    display_name: "HttpEngine#Preload calls count"
+    description: "Count how many times HttpEngine#preload got called."
+    owner_email: "aymanm@google.com"
+    unit: UNIT_COUNT
+}
diff --git a/stats/express/catalog/media_audio.cfg b/stats/express/catalog/media_audio.cfg
index 62b0b69f..624628bd 100644
--- a/stats/express/catalog/media_audio.cfg
+++ b/stats/express/catalog/media_audio.cfg
@@ -88,3 +88,53 @@ express_metric {
     unit: UNIT_COUNT
     type: COUNTER_WITH_UID
 }
+
+express_metric {
+    id:"media_audio.value_audio_playback_hardening_partial_restriction"
+    display_name: "Audio playback hardening partial restriction"
+    description: "Playback was muted due to partial playback hardening restrictions"
+    owner_email: "atneya@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id:"media_audio.value_audio_playback_hardening_strict_would_restrict"
+    display_name: "Audio playback hardening strict would restrict"
+    description: "Playback would be muted with full hardening restrictions in place"
+    owner_email: "atneya@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id:"media_audio.value_audio_volume_hardening_allowed"
+    display_name: "Volume modification API app access"
+    description: "Volume modification APIs accessed without privileged permissions"
+    owner_email: "atneya@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id:"media_audio.value_audio_volume_hardening_partial_restriction"
+    display_name: "Volume modification partial restriction"
+    description: "Volume modification APIs accessed without permissions restricted due to fgd-ness"
+    owner_email: "atneya@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
+
+express_metric {
+    id:"media_audio.value_audio_volume_hardening_strict_restriction"
+    display_name: "Volume modification strict restriction"
+    description: "Volume modification APIs accessed without permissions restricted due to caps"
+    owner_email: "atneya@google.com"
+    owner_email: "team-android-audio@google.com"
+    unit: UNIT_COUNT
+    type: COUNTER_WITH_UID
+}
diff --git a/stats/express/catalog/notifications.cfg b/stats/express/catalog/notifications.cfg
new file mode 100644
index 00000000..fe72aaba
--- /dev/null
+++ b/stats/express/catalog/notifications.cfg
@@ -0,0 +1,19 @@
+express_metric {
+    id: "notifications.value_client_throttled_notify_update"
+    type: COUNTER_WITH_UID
+    display_name: "NotificationManager throttled notify (update)"
+    description: "NotificationManager discarded a notify() call because the package was enqueueing notification updates too fast. This event won't be reported more than once per second per package."
+    owner_email: "matiashe@google.com"
+    owner_email: "android-notifications-eng@google.com"
+    unit: UNIT_COUNT
+}
+
+express_metric {
+    id: "notifications.value_client_throttled_cancel_duplicate"
+    type: COUNTER_WITH_UID
+    display_name: "NotificationManager throttled cancel (duplicate)"
+    description: "NotificationManager discarded a cancel() call because (as far as it knows) the notification was not posted (or already canceled) and the API was being called too fast. This event won't be reported more than once per second per package."
+    owner_email: "matiashe@google.com"
+    owner_email: "android-notifications-eng@google.com"
+    unit: UNIT_COUNT
+}
diff --git a/stats/stats_log_api_gen/Android.bp b/stats/stats_log_api_gen/Android.bp
index 146dc481..c278d1c2 100644
--- a/stats/stats_log_api_gen/Android.bp
+++ b/stats/stats_log_api_gen/Android.bp
@@ -22,10 +22,31 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
+cc_defaults {
+    name: "stats-log-api-gen-defaults",
+    srcs: [
+        "Collation.cpp",
+        "settings_provider.cpp",
+        "utils.cpp",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wno-deprecated-declarations",
+    ],
+    shared_libs: [
+        "libstats_proto_host",
+        "libprotobuf-cpp-full",
+    ],
+    proto: {
+        type: "full",
+    },
+}
+
 cc_binary_host {
     name: "stats-log-api-gen",
+    defaults: ["stats-log-api-gen-defaults"],
     srcs: [
-        "Collation.cpp",
         "java_writer.cpp",
         "java_writer_q.cpp",
         "java_writer_vendor.cpp",
@@ -33,24 +54,24 @@ cc_binary_host {
         "native_writer.cpp",
         "native_writer_vendor.cpp",
         "rust_writer.cpp",
-        "utils.cpp",
     ],
     cflags: [
-        "-Wall",
-        "-Werror",
-        "-Wno-deprecated-declarations",
         "-DWITH_VENDOR",
+        "-DJAVA_INCLUDE_SRCS_DIR=\"java/\"",
+        "-DCC_INCLUDE_HDRS_DIR=\"cc_hdrs/\"",
+        "-DCC_INCLUDE_SRCS_DIR=\"cc_srcs/\"",
+
     ],
 
     shared_libs: [
-        "libstats_proto_host",
-        "libprotobuf-cpp-full",
         "libbase",
     ],
 
-    proto: {
-        type: "full",
-    },
+    required: [
+        "stats-log-api-gen-copy-java-srcs",
+        "stats-log-api-gen-copy-cc-hdrs",
+        "stats-log-api-gen-copy-cc-srcs",
+    ],
 
     tidy: true,
 
@@ -79,31 +100,59 @@ cc_binary_host {
     ],
 }
 
+prebuilt_etc_host {
+    name: "stats-log-api-gen-copy-java-srcs",
+    srcs: [":stats-log-api-gen-java-srcs"],
+    sub_dir: "stats-log-api-gen/java",
+}
+
+prebuilt_etc_host {
+    name: "stats-log-api-gen-copy-cc-hdrs",
+    srcs: ["include_cc_hdrs/*.h"],
+    sub_dir: "stats-log-api-gen/cc_hdrs",
+}
+
+prebuilt_etc_host {
+    name: "stats-log-api-gen-copy-cc-srcs",
+    srcs: ["include_cc_srcs/*.cpp"],
+    sub_dir: "stats-log-api-gen/cc_srcs",
+}
+
+filegroup {
+    name: "stats-log-api-gen-java-srcs",
+    srcs: ["include_java/*.java"],
+    path: "include_java",
+}
+
+cc_test_library {
+    name: "stats-log-api-gen-cc-lib",
+    srcs: ["include_cc_srcs/StatsHistogram.cpp"],
+    export_include_dirs: ["include_cc_hdrs"],
+    host_supported: true,
+    device_supported: false,
+}
+
 // ==========================================================
 // Build the host test executable: stats-log-api-gen-test
 // ==========================================================
 cc_test_host {
     name: "stats-log-api-gen-test",
+    defaults: ["stats-log-api-gen-defaults"],
     test_suites: [
         "general-tests",
     ],
     cflags: [
-        "-Wall",
         "-Wextra",
-        "-Werror",
         "-g",
         "-DUNIT_TEST",
-        "-Wno-deprecated-declarations",
     ],
     srcs: [
-        "Collation.cpp",
         "test_api_gen.cpp",
         "test_api_gen_vendor.cpp",
         "test_collation.cpp",
         "test.proto",
         "test_feature_atoms.proto",
         "test_vendor_atoms.proto",
-        "utils.cpp",
     ],
 
     static_libs: [
@@ -113,13 +162,10 @@ cc_test_host {
 
     shared_libs: [
         "android.frameworks.stats-V2-ndk",
-        "libstats_proto_host",
-        "libprotobuf-cpp-full",
         "libstatslog",
     ],
 
     proto: {
-        type: "full",
         include_dirs: [
             "external/protobuf/src",
         ],
@@ -285,6 +331,7 @@ rust_library {
         "libthiserror",
     ],
     apex_available: [
+        "//apex_available:platform",
         "com.android.resolv",
         "com.android.virt",
     ],
@@ -300,6 +347,9 @@ genrule {
     ],
 }
 
+// libstatslog_rust is available from "//apex_available:platform" only.
+// If you want to support libstatslog from Rust in other apex, you should create
+// a new libstatslog_<module>_rust library (e.g. libstatslog_dns_resolver_rust).
 rust_library {
     name: "libstatslog_rust",
     crate_name: "statslog_rust",
@@ -311,9 +361,7 @@ rust_library {
         "libstatslog_rust_header",
         "libstatspull_bindgen",
     ],
-    apex_available: [
-        "com.android.resolv",
-        "com.android.virt",
+    flags: [
+        "-A clippy::needless-lifetimes",
     ],
-    min_sdk_version: "29",
 }
diff --git a/stats/stats_log_api_gen/Collation.cpp b/stats/stats_log_api_gen/Collation.cpp
index bc360e47..cab8238d 100644
--- a/stats/stats_log_api_gen/Collation.cpp
+++ b/stats/stats_log_api_gen/Collation.cpp
@@ -21,6 +21,7 @@
 #include <stdio.h>
 
 #include <map>
+#include <string_view>
 
 #include "frameworks/proto_logging/stats/atom_field_options.pb.h"
 #include "frameworks/proto_logging/stats/atoms.pb.h"
@@ -85,9 +86,9 @@ static void print_error(const FieldDescriptor& field, const char* format, ...) {
     if (field.GetSourceLocation(&loc)) {
         // TODO(b/162454173): this will work if we can figure out how to pass
         // --include_source_info to protoc
-        fprintf(stderr, "%s:%d: ", file->name().c_str(), loc.start_line);
+        fprintf(stderr, "%s:%d: ", std::string(file->name()).c_str(), loc.start_line);
     } else {
-        fprintf(stderr, "%s: ", file->name().c_str());
+        fprintf(stderr, "%s: ", std::string(file->name()).c_str());
     }
     va_list args;
     va_start(args, format);
@@ -240,6 +241,53 @@ static int collate_field_restricted_annotations(AtomDecl& atomDecl, const FieldD
     return errorCount;
 }
 
+static int collate_histogram_bin_option(AtomDecl& atomDecl, const FieldDescriptor& field,
+                                        const java_type_t& javaType) {
+    if (!field.options().HasExtension(os::statsd::histogram_bin_option)) {
+        return 0;
+    }
+
+    int errorCount = 0;
+    if (javaType != JAVA_TYPE_INT_ARRAY) {
+        print_error(field,
+                    "histogram annotations can only be applied to repeated int32 fields: '%s'\n",
+                    atomDecl.message.c_str());
+        errorCount++;
+    }
+
+    const os::statsd::HistogramBinOption& histogramBinOption =
+            field.options().GetExtension(os::statsd::histogram_bin_option);
+    if (histogramBinOption.has_generated_bins()) {
+        const os::statsd::HistogramBinOption::GeneratedBins& generatedBins =
+                histogramBinOption.generated_bins();
+        if (!generatedBins.has_min() || !generatedBins.has_max() || !generatedBins.has_count() ||
+            !generatedBins.has_strategy() ||
+            generatedBins.strategy() ==
+                    os::statsd::HistogramBinOption::GeneratedBins::STRATEGY_UNKNOWN) {
+            print_error(field,
+                        "For generated bins, all of min, max, count, and strategy need to be "
+                        "specified: '%s',\n",
+                        atomDecl.message.c_str());
+            errorCount++;
+        }
+    } else if (histogramBinOption.has_explicit_bins()) {
+        const os::statsd::HistogramBinOption::ExplicitBins& explicitBins =
+                histogramBinOption.explicit_bins();
+        if (explicitBins.bin().empty()) {
+            print_error(field, "For explicit bins, at least 1 bin needs to be specified: '%s',\n",
+                        atomDecl.message.c_str());
+            errorCount++;
+        }
+    } else {
+        print_error(field, "binning_strategy needs to be specified: '%s',\n",
+                    atomDecl.message.c_str());
+        errorCount++;
+    }
+
+    atomDecl.fieldNameToHistBinOption[std::string(field.name())] = histogramBinOption;
+    return errorCount;
+}
+
 static int collate_field_annotations(AtomDecl& atomDecl, const FieldDescriptor& field,
                                      const int fieldNumber, const java_type_t& javaType) {
     int errorCount = 0;
@@ -356,6 +404,8 @@ static int collate_field_annotations(AtomDecl& atomDecl, const FieldDescriptor&
                                 AnnotationValue(true));
     }
 
+    errorCount += collate_histogram_bin_option(atomDecl, field, javaType);
+
     return errorCount;
 }
 
@@ -383,7 +433,7 @@ int collate_atom(const Descriptor& atom, AtomDecl& atomDecl, vector<java_type_t>
             print_error(field,
                         "Fields must be numbered consecutively starting at 1:"
                         " '%s' is %d but should be %d\n",
-                        field.name().c_str(), number, expectedNumber);
+                        std::string(field.name()).c_str(), number, expectedNumber);
             errorCount++;
             expectedNumber = number;
             continue;
@@ -392,7 +442,7 @@ int collate_atom(const Descriptor& atom, AtomDecl& atomDecl, vector<java_type_t>
     }
 
     // Check if atom is in uint type allowlist.
-    std::string atomName = atom.name();
+    std::string_view atomName = atom.name();
     bool isUintAllowed = !(find(begin(UINT_ATOM_ALLOWLIST), end(UINT_ATOM_ALLOWLIST), atomName) ==
                            end(UINT_ATOM_ALLOWLIST));
 
@@ -408,34 +458,38 @@ int collate_atom(const Descriptor& atom, AtomDecl& atomDecl, vector<java_type_t>
         if (javaType == JAVA_TYPE_UNKNOWN_OR_INVALID) {
             if (field.is_repeated()) {
                 print_error(field, "Repeated field type %s is not allowed for field: %s\n",
-                            field.type_name(), field.name().c_str());
+                            std::string(field.type_name()).c_str(),
+                            std::string(field.name()).c_str());
             } else {
                 print_error(field, "Field type %s is not allowed for field: %s\n",
-                            field.type_name(), field.name().c_str());
+                            std::string(field.type_name()).c_str(),
+                            std::string(field.name()).c_str());
             }
             errorCount++;
             continue;
         } else if (javaType == JAVA_TYPE_OBJECT) {
             // Allow attribution chain, but only at position 1.
             print_error(field, "Message type not allowed for field without mode_bytes: %s\n",
-                        field.name().c_str());
+                        std::string(field.name()).c_str());
             errorCount++;
             continue;
         } else if (javaType == JAVA_TYPE_BYTE_ARRAY && !isBinaryField) {
-            print_error(field, "Raw bytes type not allowed for field: %s\n", field.name().c_str());
+            print_error(field, "Raw bytes type not allowed for field: %s\n",
+                        std::string(field.name()).c_str());
             errorCount++;
             continue;
         }
 
         if (isBinaryField && javaType != JAVA_TYPE_BYTE_ARRAY) {
-            print_error(field, "Cannot mark field %s as bytes.\n", field.name().c_str());
+            print_error(field, "Cannot mark field %s as bytes.\n",
+                        std::string(field.name()).c_str());
             errorCount++;
             continue;
         }
 
         if (atomDecl.restricted && !is_primitive_field(javaType)) {
             print_error(field, "Restricted atom '%s' cannot have nonprimitive field: '%s'\n",
-                        atomDecl.message.c_str(), field.name().c_str());
+                        atomDecl.message.c_str(), std::string(field.name()).c_str());
             errorCount++;
             continue;
         }
@@ -451,7 +505,7 @@ int collate_atom(const Descriptor& atom, AtomDecl& atomDecl, vector<java_type_t>
             if (javaType == JAVA_TYPE_ATTRIBUTION_CHAIN) {
                 print_error(field,
                             "AttributionChain fields must have field id 1, in message: '%s'\n",
-                            atom.name().c_str());
+                            std::string(atom.name()).c_str());
                 errorCount++;
             }
         }
@@ -465,7 +519,7 @@ int collate_atom(const Descriptor& atom, AtomDecl& atomDecl, vector<java_type_t>
         const bool isBinaryField = field.options().GetExtension(os::statsd::log_mode) ==
                                    os::statsd::LogMode::MODE_BYTES;
 
-        AtomField atField(field.name(), javaType);
+        AtomField atField(std::string(field.name()), javaType);
 
         if (javaType == JAVA_TYPE_ENUM || javaType == JAVA_TYPE_ENUM_ARRAY) {
             atField.enumTypeName = field.enum_type()->name();
@@ -524,7 +578,7 @@ bool get_non_chained_node(const Descriptor& atom, AtomDecl& atomDecl,
             has_attribution_node = true;
 
         } else {
-            AtomField atField(field.name(), javaType);
+            AtomField atField(std::string(field.name()), javaType);
             if (javaType == JAVA_TYPE_ENUM) {
                 // All enums are treated as ints when it comes to function signatures.
                 signature.push_back(JAVA_TYPE_INT);
@@ -575,14 +629,15 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
         // This atom is not in the module we're interested in; skip it.
         if (!moduleFound) {
             if (dbg) {
-                printf("   Skipping %s (%d)\n", atomField.name().c_str(), atomField.number());
+                printf("   Skipping %s (%d)\n", std::string(atomField.name()).c_str(),
+                       atomField.number());
             }
             return errorCount;
         }
     }
 
     if (dbg) {
-        printf("   %s (%d)\n", atomField.name().c_str(), atomField.number());
+        printf("   %s (%d)\n", std::string(atomField.name()).c_str(), atomField.number());
     }
 
     // StatsEvent only has one oneof, which contains only messages. Don't allow
@@ -591,7 +646,7 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
         print_error(atomField,
                     "Bad type for atom. StatsEvent can only have message type "
                     "fields: %s\n",
-                    atomField.name().c_str());
+                    std::string(atomField.name()).c_str());
         errorCount++;
         return errorCount;
     }
@@ -599,21 +654,21 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
     const AtomType atomType = getAtomType(atomField);
 
     const Descriptor& atom = *atomField.message_type();
-    const shared_ptr<AtomDecl> atomDecl =
-            make_shared<AtomDecl>(atomField.number(), atomField.name(), atom.name(), atomType);
+    const shared_ptr<AtomDecl> atomDecl = make_shared<AtomDecl>(
+            atomField.number(), std::string(atomField.name()), std::string(atom.name()), atomType);
 
     if (atomField.options().GetExtension(os::statsd::truncate_timestamp)) {
         addAnnotationToAtomDecl(*atomDecl, ATOM_ID_FIELD_NUMBER, ANNOTATION_ID_TRUNCATE_TIMESTAMP,
                                 ANNOTATION_TYPE_BOOL, AnnotationValue(true));
         if (dbg) {
-            printf("%s can have timestamp truncated\n", atomField.name().c_str());
+            printf("%s can have timestamp truncated\n", std::string(atomField.name()).c_str());
         }
     }
 
     if (atomField.options().HasExtension(os::statsd::restriction_category)) {
         if (atomType == ATOM_TYPE_PULLED) {
             print_error(atomField, "Restricted atoms cannot be pulled: '%s'\n",
-                        atomField.name().c_str());
+                        std::string(atomField.name()).c_str());
             errorCount++;
             return errorCount;
         }
@@ -628,7 +683,7 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
     errorCount += collate_atom(atom, *atomDecl, signature);
     if (!atomDecl->primaryFields.empty() && atomDecl->exclusiveField == 0) {
         print_error(atomField, "Cannot have a primary field without an exclusive field: %s\n",
-                    atomField.name().c_str());
+                    std::string(atomField.name()).c_str());
         errorCount++;
         return errorCount;
     }
@@ -640,8 +695,8 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
 
     atoms.decls.insert(atomDecl);
 
-    const shared_ptr<AtomDecl> nonChainedAtomDecl =
-            make_shared<AtomDecl>(atomField.number(), atomField.name(), atom.name(), atomType);
+    const shared_ptr<AtomDecl> nonChainedAtomDecl = make_shared<AtomDecl>(
+            atomField.number(), std::string(atomField.name()), std::string(atom.name()), atomType);
     vector<java_type_t> nonChainedSignature;
     if (get_non_chained_node(atom, *nonChainedAtomDecl, nonChainedSignature)) {
         FieldNumberToAtomDeclSet& nonChainedFieldNumberToAtomDeclSet =
@@ -653,7 +708,7 @@ static int collate_from_field_descriptor(const FieldDescriptor& atomField, const
 
     if (atomField.options().HasExtension(os::statsd::field_restriction_option)) {
         print_error(atomField, "field_restriction_option must be a field-level annotation: '%s'\n",
-                    atomField.name().c_str());
+                    std::string(atomField.name()).c_str());
         errorCount++;
     }
 
diff --git a/stats/stats_log_api_gen/Collation.h b/stats/stats_log_api_gen/Collation.h
index b5095f8d..728f1885 100644
--- a/stats/stats_log_api_gen/Collation.h
+++ b/stats/stats_log_api_gen/Collation.h
@@ -172,6 +172,8 @@ using AnnotationSet = set<shared_ptr<Annotation>, SharedComparator>;
 
 using FieldNumberToAnnotations = map<int, AnnotationSet>;
 
+using FieldNameToHistogramBinOption = map<std::string, os::statsd::HistogramBinOption>;
+
 /**
  * The name and type for an atom field.
  */
@@ -213,6 +215,7 @@ struct AtomDecl {
     AtomType atomType;
 
     FieldNumberToAnnotations fieldNumberToAnnotations;
+    FieldNameToHistogramBinOption fieldNameToHistBinOption;
 
     vector<int> primaryFields;
     int exclusiveField = 0;
diff --git a/stats/stats_log_api_gen/include_cc_hdrs/StatsHistogram.h b/stats/stats_log_api_gen/include_cc_hdrs/StatsHistogram.h
new file mode 100644
index 00000000..0b00244a
--- /dev/null
+++ b/stats/stats_log_api_gen/include_cc_hdrs/StatsHistogram.h
@@ -0,0 +1,82 @@
+/*
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
+#pragma once
+
+// HEADER_BEGIN
+#include <initializer_list>
+#include <limits>
+#include <memory>
+#include <vector>
+// HEADER_END
+
+namespace android {
+namespace util {
+namespace statslogapigen {
+
+// BODY_BEGIN
+constexpr float UNDERFLOW_BIN = std::numeric_limits<float>::lowest();
+
+class StatsHistogram final {
+public:
+    constexpr StatsHistogram(std::vector<float> bins)
+        : mBins(std::move(bins)), mBinCounts(mBins.size(), 0) {
+    }
+
+    /**
+     * Create StatsHistogram with uniform-width bins.
+     **/
+    static std::unique_ptr<StatsHistogram> createLinearBins(float min, float max, int count);
+
+    /**
+     * Create StatsHistogram with bin-widths increasing exponentially.
+     **/
+    static std::unique_ptr<StatsHistogram> createExponentialBins(float min, float max, int count);
+
+    /**
+     * Create StatsHistogram with bin-widths specified by adjacent values in explicitBins
+     **/
+    static std::unique_ptr<StatsHistogram> createExplicitBins(std::initializer_list<float> bins);
+
+    /**
+     * Add a single value to this StatsHistogram.
+     **/
+    void addValue(float value);
+
+    /**
+     * Clear all bin counts
+     **/
+    void clear();
+
+    /**
+     * Get counts for all bins.
+     **/
+    const std::vector<int>& getBinCounts() const;
+
+    /**
+     * Get all the bin boundaries for the histogram
+     **/
+    const std::vector<float>& getBins() const;
+
+private:
+    const std::vector<float> mBins;
+    std::vector<int> mBinCounts;
+};
+// BODY_END
+
+}  // namespace statslogapigen
+}  // namespace util
+}  // namespace android
diff --git a/stats/stats_log_api_gen/include_cc_hdrs/TEST_MAPPING b/stats/stats_log_api_gen/include_cc_hdrs/TEST_MAPPING
new file mode 100644
index 00000000..97c45fdb
--- /dev/null
+++ b/stats/stats_log_api_gen/include_cc_hdrs/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "presubmit": [
+    {
+      "name": "stats_code_gen_srcs_cc_host_test"
+    }
+  ]
+}
diff --git a/stats/stats_log_api_gen/include_cc_srcs/StatsHistogram.cpp b/stats/stats_log_api_gen/include_cc_srcs/StatsHistogram.cpp
new file mode 100644
index 00000000..628717e0
--- /dev/null
+++ b/stats/stats_log_api_gen/include_cc_srcs/StatsHistogram.cpp
@@ -0,0 +1,102 @@
+/*
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
+#include "StatsHistogram.h"
+
+// HEADER_BEGIN
+#include <algorithm>
+#include <cmath>
+#include <cstdlib>
+// HEADER_END
+
+namespace android {
+namespace util {
+namespace statslogapigen {
+
+// BODY_BEGIN
+std::unique_ptr<StatsHistogram> StatsHistogram::createLinearBins(float min, float max, int count) {
+    // 2 extra bins for underflow and overflow.
+    std::vector<float> bins(count + 2);
+    bins[0] = UNDERFLOW_BIN;
+    bins[1] = min;
+    bins.back() = max;
+
+    const float binWidth = (max - min) / count;
+    float curBin = min;
+
+    // Generate values starting from 3rd element to (n-1)th element.
+    std::generate(bins.begin() + 2, bins.end() - 1,
+                  [&curBin, binWidth]() { return curBin += binWidth; });
+
+    return std::make_unique<StatsHistogram>(bins);
+}
+
+std::unique_ptr<StatsHistogram> StatsHistogram::createExponentialBins(float min, float max,
+                                                                      int count) {
+    // 2 extra bins for underflow and overflow.
+    std::vector<float> bins(count + 2);
+    bins[0] = UNDERFLOW_BIN;
+    bins[1] = min;
+    bins.back() = max;
+
+    // Determine the scale factor f, such that max = min * f^count.
+    // So, f = (max / min)^(1 / count) ie. f is the count'th-root of max / min.
+    const float factor = std::pow(max / min, 1.0 / count);
+
+    // Generate values starting from 3rd element to (n-1)th element.
+    float curBin = bins[1];
+    std::generate(bins.begin() + 2, bins.end() - 1,
+                  [&curBin, factor]() { return curBin *= factor; });
+
+    return std::make_unique<StatsHistogram>(bins);
+}
+
+std::unique_ptr<StatsHistogram> StatsHistogram::createExplicitBins(
+        std::initializer_list<float> bins) {
+    // 1 extra bin for underflow.
+    std::vector<float> actualBins(bins.size() + 1);
+    actualBins[0] = UNDERFLOW_BIN;
+    std::copy(bins.begin(), bins.end(), actualBins.begin() + 1);
+
+    return std::make_unique<StatsHistogram>(actualBins);
+}
+
+void StatsHistogram::addValue(float value) {
+    size_t index = 0;
+    for (; index < mBins.size() - 1; index++) {
+        if (value < mBins[index + 1]) {
+            break;
+        }
+    }
+    mBinCounts[index]++;
+}
+
+void StatsHistogram::clear() {
+    std::fill(mBinCounts.begin(), mBinCounts.end(), 0);
+}
+
+const std::vector<int>& StatsHistogram::getBinCounts() const {
+    return mBinCounts;
+}
+
+const std::vector<float>& StatsHistogram::getBins() const {
+    return mBins;
+}
+// BODY_END
+
+}  // namespace statslogapigen
+}  // namespace util
+}  // namespace android
diff --git a/stats/stats_log_api_gen/include_cc_srcs/TEST_MAPPING b/stats/stats_log_api_gen/include_cc_srcs/TEST_MAPPING
new file mode 100644
index 00000000..97c45fdb
--- /dev/null
+++ b/stats/stats_log_api_gen/include_cc_srcs/TEST_MAPPING
@@ -0,0 +1,7 @@
+{
+  "presubmit": [
+    {
+      "name": "stats_code_gen_srcs_cc_host_test"
+    }
+  ]
+}
diff --git a/stats/stats_log_api_gen/include_java/StatsHistogram.java b/stats/stats_log_api_gen/include_java/StatsHistogram.java
new file mode 100644
index 00000000..0f15b2a8
--- /dev/null
+++ b/stats/stats_log_api_gen/include_java/StatsHistogram.java
@@ -0,0 +1,123 @@
+/*
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
+package android.util.statslogapigen;
+
+// HEADER_BEGIN
+import java.util.Arrays;
+// HEADER_END
+
+/**
+ * @hide
+ **/
+// BODY_BEGIN
+public final class StatsHistogram {
+    private final float[] mBins;
+    private final int[] mBinCounts;
+
+    public static final float UNDERFLOW = -Float.MAX_VALUE;
+
+    private StatsHistogram(final float[] bins) {
+        mBins = bins;
+        mBinCounts = new int[bins.length];
+    }
+
+    /**
+     * Create StatsHistogram with uniform-width bins.
+     **/
+    public static StatsHistogram createLinearBins(float min, float max, int count) {
+        // 2 extra bins for underflow and overflow.
+        float[] bins = new float[count + 2];
+        bins[0] = UNDERFLOW;
+        bins[1] = min;
+        bins[bins.length - 1] = max;
+
+        float binWidth = (max - min) / count;
+        for (int i = 2; i < bins.length - 1; i++) {
+            bins[i] = bins[i - 1] + binWidth;
+        }
+
+        return new StatsHistogram(bins);
+    }
+
+    /**
+     * Create StatsHistogram with bin-widths increasing exponentially.
+     **/
+    public static StatsHistogram createExponentialBins(float min, float max, int count) {
+        // 2 extra bins for underflow and overflow
+        float[] bins = new float[count + 2];
+        bins[0] = UNDERFLOW;
+        bins[1] = min;
+        bins[bins.length - 1] = max;
+
+        // Determine the scale factor f, such that max = min * f^count.
+        // So, f = (max / min)^(1 / count) ie. f is the count'th-root of max / min.
+        float factor = (float) Math.pow(max / min, 1.0 / count);
+        for (int i = 2; i < bins.length - 1; i++) {
+            bins[i] = bins[i - 1] * factor;
+        }
+
+        return new StatsHistogram(bins);
+    }
+
+    /**
+     * Create StatsHistogram with bin-widths specified by adjacent values in explicitBins
+     **/
+    public static StatsHistogram createExplicitBins(float... explicitBins) {
+        // 1 extra bin for underflow.
+        float[] bins = new float[explicitBins.length + 1];
+        bins[0] = UNDERFLOW;
+        System.arraycopy(explicitBins, 0, bins, 1, explicitBins.length);
+
+        return new StatsHistogram(bins);
+    }
+
+    /**
+     * Add a single value to this StatsHistogram.
+     **/
+    public void addValue(float value) {
+        int i = 0;
+        for (; i < mBins.length - 1; i++) {
+            if (value < mBins[i + 1]) {
+                break;
+            }
+        }
+
+        mBinCounts[i]++;
+    }
+
+    /**
+     * Clear all bin counts
+     **/
+    public void clear() {
+        Arrays.fill(mBinCounts, 0);
+    }
+
+    /**
+     * Get counts for all bins.
+     **/
+    public int[] getBinCounts() {
+        return mBinCounts;
+    }
+
+    /**
+     * Get all the bin boundaries for the histogram
+     **/
+    public float[] getBins() {
+        return mBins;
+    }
+}
+// BODY_END
diff --git a/stats/stats_log_api_gen/include_java/TEST_MAPPING b/stats/stats_log_api_gen/include_java/TEST_MAPPING
new file mode 100644
index 00000000..9eb08fdc
--- /dev/null
+++ b/stats/stats_log_api_gen/include_java/TEST_MAPPING
@@ -0,0 +1,12 @@
+{
+  "presubmit": [
+    {
+      "name": "StatsCodeGenSrcsJavaHostTest",
+      "options": [
+        {
+          "exclude-annotation": "org.junit.Ignore"
+        }
+      ]
+    }
+  ]
+}
diff --git a/stats/stats_log_api_gen/java_writer.cpp b/stats/stats_log_api_gen/java_writer.cpp
index 6798640f..add72a62 100644
--- a/stats/stats_log_api_gen/java_writer.cpp
+++ b/stats/stats_log_api_gen/java_writer.cpp
@@ -239,14 +239,16 @@ static void write_requires_api_annotation(FILE* out, int minApiLevel,
 }
 
 static int write_java_pushed_methods(FILE* out, const SignatureInfoMap& signatureInfoMap,
-                                     const AtomDecl& attributionDecl, const int minApiLevel) {
+                                     const AtomDecl& attributionDecl, const int minApiLevel,
+                                     const bool staticMethods) {
+    const char* methodPrefix = staticMethods ? "static " : "";
     for (auto signatureInfoMapIt = signatureInfoMap.begin();
          signatureInfoMapIt != signatureInfoMap.end(); signatureInfoMapIt++) {
         const FieldNumberToAtomDeclSet& fieldNumberToAtomDeclSet = signatureInfoMapIt->second;
         const vector<java_type_t>& signature = signatureInfoMapIt->first;
         write_requires_api_annotation(out, minApiLevel, fieldNumberToAtomDeclSet, signature);
         // Print method signature.
-        fprintf(out, "    public static void write(int code");
+        fprintf(out, "    public %svoid write(int code", methodPrefix);
         write_java_method_signature(out, signature, attributionDecl);
         fprintf(out, ") {\n");
 
@@ -299,14 +301,16 @@ static int write_java_pushed_methods(FILE* out, const SignatureInfoMap& signatur
 }
 
 static int write_java_pulled_methods(FILE* out, const SignatureInfoMap& signatureInfoMap,
-                                     const AtomDecl& attributionDecl, const int minApiLevel) {
+                                     const AtomDecl& attributionDecl, const int minApiLevel,
+                                     const bool staticMethods) {
+    const char* methodPrefix = staticMethods ? "static " : "";
     for (auto signatureInfoMapIt = signatureInfoMap.begin();
          signatureInfoMapIt != signatureInfoMap.end(); signatureInfoMapIt++) {
         const vector<java_type_t>& signature = signatureInfoMapIt->first;
         const FieldNumberToAtomDeclSet& fieldNumberToAtomDeclSet = signatureInfoMapIt->second;
         write_requires_api_annotation(out, minApiLevel, fieldNumberToAtomDeclSet, signature);
         // Print method signature.
-        fprintf(out, "    public static StatsEvent buildStatsEvent(int code");
+        fprintf(out, "    public %sStatsEvent buildStatsEvent(int code", methodPrefix);
         int ret = write_java_method_signature(out, signature, attributionDecl);
         if (ret != 0) {
             return ret;
@@ -346,7 +350,7 @@ static int get_max_requires_api_level(int minApiLevel, const SignatureInfoMap& s
 
 int write_stats_log_java(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                          const string& javaClass, const string& javaPackage, const int minApiLevel,
-                         const bool supportWorkSource) {
+                         const bool supportWorkSource, const bool staticMethods) {
     // Print prelude
     fprintf(out, "// This file is autogenerated\n");
     fprintf(out, "\n");
@@ -367,30 +371,50 @@ int write_stats_log_java(FILE* out, const Atoms& atoms, const AtomDecl& attribut
         fprintf(out, "import androidx.annotation.RequiresApi;\n");
     }
 
+    int errors = 0;
+
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    const bool hasHistograms = has_histograms(atoms.decls);
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    errors += write_srcs_header(out, JAVA_INCLUDE_SRCS_DIR, excludeList);
+#endif
+
     fprintf(out, "\n");
     fprintf(out, "\n");
     fprintf(out, "/**\n");
     fprintf(out, " * Utility class for logging statistics events.\n");
     fprintf(out, " * @hide\n");
     fprintf(out, " */\n");
-    fprintf(out, "public final class %s {\n", javaClass.c_str());
+
+    fprintf(out, "public class %s {\n", javaClass.c_str());
 
     write_java_atom_codes(out, atoms);
     write_java_enum_values(out, atoms);
     write_java_annotation_constants(out, minApiLevel);
 
-    int errors = 0;
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    if (hasHistograms) {
+        errors += write_java_histogram_helpers(out, atoms.decls, staticMethods);
+    }
+#endif
 
     // Print write methods.
     fprintf(out, "    // Write methods\n");
-    errors += write_java_pushed_methods(out, atoms.signatureInfoMap, attributionDecl, minApiLevel);
-    errors += write_java_non_chained_methods(out, atoms.nonChainedSignatureInfoMap);
+    errors += write_java_pushed_methods(out, atoms.signatureInfoMap, attributionDecl, minApiLevel,
+                                        staticMethods);
+    errors += write_java_non_chained_methods(out, atoms.nonChainedSignatureInfoMap,
+                                             staticMethods);
     errors += write_java_pulled_methods(out, atoms.pulledAtomsSignatureInfoMap, attributionDecl,
-                                        minApiLevel);
+                                        minApiLevel, staticMethods);
     if (supportWorkSource) {
         errors += write_java_work_source_methods(out, atoms.signatureInfoMap);
     }
 
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    errors += write_java_srcs_classes(out, JAVA_INCLUDE_SRCS_DIR, excludeList);
+#endif
+
     if (minApiLevel == API_Q) {
         errors += write_java_q_logger_class(out, atoms.signatureInfoMap, attributionDecl);
     }
diff --git a/stats/stats_log_api_gen/java_writer.h b/stats/stats_log_api_gen/java_writer.h
index dea06f8c..d523f72e 100644
--- a/stats/stats_log_api_gen/java_writer.h
+++ b/stats/stats_log_api_gen/java_writer.h
@@ -31,7 +31,7 @@ namespace stats_log_api_gen {
 
 int write_stats_log_java(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                          const string& javaClass, const string& javaPackage, const int minApiLevel,
-                         const bool supportWorkSource);
+                         const bool supportWorkSource, const bool staticMethods);
 
 }  // namespace stats_log_api_gen
 }  // namespace android
diff --git a/stats/stats_log_api_gen/java_writer_vendor.cpp b/stats/stats_log_api_gen/java_writer_vendor.cpp
index 11eb7545..d785d3d1 100644
--- a/stats/stats_log_api_gen/java_writer_vendor.cpp
+++ b/stats/stats_log_api_gen/java_writer_vendor.cpp
@@ -308,11 +308,13 @@ static int write_method_body_vendor(FILE* out, const vector<java_type_t>& signat
     return 0;
 }
 
-static int write_java_pushed_methods_vendor(FILE* out, const SignatureInfoMap& signatureInfoMap) {
+static int write_java_pushed_methods_vendor(FILE* out, const SignatureInfoMap& signatureInfoMap,
+                                            const bool staticMethods) {
+    const char* methodPrefix = staticMethods ? "static " : "";
     for (auto signatureInfoMapIt = signatureInfoMap.begin();
          signatureInfoMapIt != signatureInfoMap.end(); signatureInfoMapIt++) {
         // Print method signature.
-        fprintf(out, "    public static VendorAtom createVendorAtom(int atomId");
+        fprintf(out, "    public %sVendorAtom createVendorAtom(int atomId", methodPrefix);
         const vector<java_type_t>& signature = signatureInfoMapIt->first;
         const AtomDecl emptyAttributionDecl;
         int ret = write_java_method_signature(out, signature, emptyAttributionDecl);
@@ -368,7 +370,7 @@ static void write_java_enum_values_vendor(FILE* out, const Atoms& atoms) {
 }
 
 int write_stats_log_java_vendor(FILE* out, const Atoms& atoms, const string& javaClass,
-                                const string& javaPackage) {
+                                const string& javaPackage, const bool staticMethods) {
     // Print prelude
     fprintf(out, "// This file is autogenerated\n");
     fprintf(out, "\n");
@@ -384,18 +386,36 @@ int write_stats_log_java_vendor(FILE* out, const Atoms& atoms, const string& jav
 
     fprintf(out, "import java.util.ArrayList;\n");
 
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    const bool hasHistograms = has_histograms(atoms.decls);
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_srcs_header(out, JAVA_INCLUDE_SRCS_DIR, excludeList);
+#endif
+
     fprintf(out, "\n");
     fprintf(out, "/**\n");
     fprintf(out, " * Utility class for logging statistics events.\n");
     fprintf(out, " */\n");
-    fprintf(out, "public final class %s {\n", javaClass.c_str());
+    const char* finalPrefix = staticMethods ? "final " : "";
+    fprintf(out, "public %sclass %s {\n", finalPrefix, javaClass.c_str());
 
     write_java_atom_codes(out, atoms);
     write_java_enum_values_vendor(out, atoms);
 
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    if (hasHistograms) {
+        write_java_histogram_helpers(out, atoms.decls, staticMethods);
+    }
+#endif
+
     // Print write methods.
     fprintf(out, "    // Write methods\n");
-    const int errors = write_java_pushed_methods_vendor(out, atoms.signatureInfoMap);
+    const int errors = write_java_pushed_methods_vendor(out, atoms.signatureInfoMap, staticMethods);
+
+#ifdef JAVA_INCLUDE_SRCS_DIR
+    write_java_srcs_classes(out, JAVA_INCLUDE_SRCS_DIR, excludeList);
+#endif
 
     fprintf(out, "}\n");
 
diff --git a/stats/stats_log_api_gen/java_writer_vendor.h b/stats/stats_log_api_gen/java_writer_vendor.h
index bb8916da..032f8595 100644
--- a/stats/stats_log_api_gen/java_writer_vendor.h
+++ b/stats/stats_log_api_gen/java_writer_vendor.h
@@ -30,7 +30,7 @@ namespace android {
 namespace stats_log_api_gen {
 
 int write_stats_log_java_vendor(FILE* out, const Atoms& atoms, const string& javaClass,
-                                const string& javaPackage);
+                                const string& javaPackage, const bool staticMethods);
 
 }  // namespace stats_log_api_gen
 }  // namespace android
diff --git a/stats/stats_log_api_gen/main.cpp b/stats/stats_log_api_gen/main.cpp
index a5a8beca..55a735b0 100644
--- a/stats/stats_log_api_gen/main.cpp
+++ b/stats/stats_log_api_gen/main.cpp
@@ -55,6 +55,7 @@ static void print_usage() {
     fprintf(stderr, "  --javaPackage PACKAGE             the package for the java file.\n");
     fprintf(stderr, "                                    required for java with module\n");
     fprintf(stderr, "  --javaClass CLASS    the class name of the java class.\n");
+    fprintf(stderr, "  --nonStatic          generate java classes with non-static methods\n");
     fprintf(stderr, "  --minApiLevel API_LEVEL           lowest API level to support.\n");
     fprintf(stderr, "                                    Default is \"current\".\n");
     fprintf(stderr,
@@ -90,6 +91,7 @@ static int run(int argc, char const* const* argv) {
     bool supportWorkSource = false;
     int minApiLevel = API_LEVEL_CURRENT;
     bool bootstrap = false;
+    bool javaStaticMethods = true;
 
     int index = 1;
     while (index < argc) {
@@ -173,6 +175,8 @@ static int run(int argc, char const* const* argv) {
                 return 1;
             }
             javaClass = argv[index];
+        } else if (0 == strcmp("--nonStatic", argv[index])) {
+            javaStaticMethods = false;
         } else if (0 == strcmp("--supportQ", argv[index])) {
             minApiLevel = API_Q;
         } else if (0 == strcmp("--worksource", argv[index])) {
@@ -360,7 +364,7 @@ static int run(int argc, char const* const* argv) {
         if (vendorProto.empty()) {
             errorCount = android::stats_log_api_gen::write_stats_log_java(
                     out, atoms, attributionDecl, javaClass, javaPackage, minApiLevel,
-                    supportWorkSource);
+                    supportWorkSource, javaStaticMethods);
         } else {
 #ifdef WITH_VENDOR
             if (supportWorkSource) {
@@ -369,7 +373,7 @@ static int run(int argc, char const* const* argv) {
             }
 
             errorCount = android::stats_log_api_gen::write_stats_log_java_vendor(out, atoms,
-                    javaClass, javaPackage);
+                    javaClass, javaPackage, javaStaticMethods);
 #endif
         }
 
diff --git a/stats/stats_log_api_gen/native_writer.cpp b/stats/stats_log_api_gen/native_writer.cpp
index 6f11beac..8811696d 100644
--- a/stats/stats_log_api_gen/native_writer.cpp
+++ b/stats/stats_log_api_gen/native_writer.cpp
@@ -480,11 +480,34 @@ int write_stats_log_cpp(FILE* out, const Atoms& atoms, const AtomDecl& attributi
         fprintf(out, "#include <utils/String16.h>\n");
     }
 
+#ifdef CC_INCLUDE_SRCS_DIR
+    const bool hasHistograms = has_histograms(atoms.decls);
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_srcs_header(out, CC_INCLUDE_SRCS_DIR, excludeList);
+#endif
+
     fprintf(out, "\n");
     write_namespace(out, cppNamespace);
 
-    int ret = write_native_stats_write_methods(out, atoms.signatureInfoMap, attributionDecl,
-                                               minApiLevel, bootstrap);
+    int ret = 0;
+#ifdef CC_INCLUDE_SRCS_DIR
+    ret = write_cc_srcs_classes(out, CC_INCLUDE_SRCS_DIR, excludeList);
+    if (ret != 0) {
+        return ret;
+    }
+
+    // Write histogram helper definitions if any histogram annotations are present.
+    if (hasHistograms) {
+        ret = write_native_histogram_helper_definitions(out, atoms.decls);
+        if (ret != 0) {
+            return ret;
+        }
+    }
+#endif
+
+    ret = write_native_stats_write_methods(out, atoms.signatureInfoMap, attributionDecl,
+                                           minApiLevel, bootstrap);
     if (ret != 0) {
         return ret;
     }
@@ -508,7 +531,8 @@ int write_stats_log_cpp(FILE* out, const Atoms& atoms, const AtomDecl& attributi
 int write_stats_log_header(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                            const string& cppNamespace, const int minApiLevel, bool bootstrap) {
     const bool includePull = !atoms.pulledAtomsSignatureInfoMap.empty() && !bootstrap;
-    write_native_header_preamble(out, cppNamespace, includePull, bootstrap);
+    const bool hasHistograms = has_histograms(atoms.decls);
+    write_native_header_preamble(out, cppNamespace, includePull, hasHistograms, bootstrap);
     write_native_atom_constants(out, atoms, attributionDecl);
     write_native_atom_enums(out, atoms);
 
@@ -525,6 +549,17 @@ int write_stats_log_header(FILE* out, const Atoms& atoms, const AtomDecl& attrib
     fprintf(out, "};\n");
     fprintf(out, "\n");
 
+#ifdef CC_INCLUDE_HDRS_DIR
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_cc_srcs_classes(out, CC_INCLUDE_HDRS_DIR, excludeList);
+
+    // Write histogram helper declarations if any histogram annotations are present.
+    if (hasHistograms) {
+        write_native_histogram_helper_declarations(out, atoms.decls);
+    }
+#endif
+
     // Print write methods
     fprintf(out, "//\n");
     fprintf(out, "// Write methods\n");
diff --git a/stats/stats_log_api_gen/native_writer_vendor.cpp b/stats/stats_log_api_gen/native_writer_vendor.cpp
index ac839355..04638957 100644
--- a/stats/stats_log_api_gen/native_writer_vendor.cpp
+++ b/stats/stats_log_api_gen/native_writer_vendor.cpp
@@ -296,6 +296,13 @@ int write_stats_log_cpp_vendor(FILE* out, const Atoms& atoms, const AtomDecl& at
     fprintf(out, "#include <%s>\n", importHeader.c_str());
     fprintf(out, "#include <aidl/android/frameworks/stats/VendorAtom.h>\n");
 
+#ifdef CC_INCLUDE_SRCS_DIR
+    const bool hasHistograms = has_histograms(atoms.decls);
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_srcs_header(out, CC_INCLUDE_SRCS_DIR, excludeList);
+#endif
+
     fprintf(out, "\n");
     write_namespace(out, cppNamespace);
     fprintf(out, "\n");
@@ -305,8 +312,23 @@ int write_stats_log_cpp_vendor(FILE* out, const Atoms& atoms, const AtomDecl& at
     fprintf(out, "using std::vector;\n");
     fprintf(out, "using std::string;\n");
 
-    const int ret =
-            write_native_create_vendor_atom_methods(out, atoms.signatureInfoMap, attributionDecl);
+    int ret = 0;
+#ifdef CC_INCLUDE_SRCS_DIR
+    ret = write_cc_srcs_classes(out, CC_INCLUDE_SRCS_DIR, excludeList);
+    if (ret != 0) {
+        return ret;
+    }
+
+    // Write histogram helper definitions if any histogram annotations are present.
+    if (hasHistograms) {
+        ret = write_native_histogram_helper_definitions(out, atoms.decls);
+        if (ret != 0) {
+            return ret;
+        }
+    }
+#endif
+
+    ret = write_native_create_vendor_atom_methods(out, atoms.signatureInfoMap, attributionDecl);
     if (ret != 0) {
         return ret;
     }
@@ -319,11 +341,23 @@ int write_stats_log_cpp_vendor(FILE* out, const Atoms& atoms, const AtomDecl& at
 
 int write_stats_log_header_vendor(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                                   const string& cppNamespace) {
-    write_native_header_preamble(out, cppNamespace, /*includePull=*/false, /*bootstrap=*/false,
-                                 /*isVendorAtomLogging=*/true);
+    const bool hasHistograms = has_histograms(atoms.decls);
+    write_native_header_preamble(out, cppNamespace, /*includePull=*/false, hasHistograms,
+                                 /*bootstrap=*/false, /*isVendorAtomLogging=*/true);
     write_native_atom_constants(out, atoms, attributionDecl, "createVendorAtom(",
                                 /*isVendorAtomLogging=*/true);
 
+#ifdef CC_INCLUDE_HDRS_DIR
+    const vector<string> excludeList =
+            hasHistograms ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_cc_srcs_classes(out, CC_INCLUDE_HDRS_DIR, excludeList);
+
+    // Write histogram helper declarations if any histogram annotations are present.
+    if (hasHistograms) {
+        write_native_histogram_helper_declarations(out, atoms.decls);
+    }
+#endif
+
     for (AtomDeclSet::const_iterator atomIt = atoms.decls.begin(); atomIt != atoms.decls.end();
          atomIt++) {
         set<string> processedEnums;
diff --git a/stats/stats_log_api_gen/settings_provider.cpp b/stats/stats_log_api_gen/settings_provider.cpp
new file mode 100644
index 00000000..68a406b6
--- /dev/null
+++ b/stats/stats_log_api_gen/settings_provider.cpp
@@ -0,0 +1,29 @@
+/*
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
+#include "settings_provider.h"
+
+namespace android {
+namespace stats_log_api_gen {
+
+using std::string;
+
+string get_data_dir_path(const string& relativePath) {
+    return "tools/out/etc/stats-log-api-gen/" + relativePath;
+}
+
+}  // namespace stats_log_api_gen
+}  // namespace android
diff --git a/stats/stats_log_api_gen/settings_provider.h b/stats/stats_log_api_gen/settings_provider.h
new file mode 100644
index 00000000..733d3aad
--- /dev/null
+++ b/stats/stats_log_api_gen/settings_provider.h
@@ -0,0 +1,27 @@
+/*
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
+#pragma once
+
+#include <string>
+
+namespace android {
+namespace stats_log_api_gen {
+
+std::string get_data_dir_path(const std::string& relativePath);
+
+}  // namespace stats_log_api_gen
+}  // namespace android
diff --git a/stats/stats_log_api_gen/test_cc/Android.bp b/stats/stats_log_api_gen/test_cc/Android.bp
new file mode 100644
index 00000000..f726451f
--- /dev/null
+++ b/stats/stats_log_api_gen/test_cc/Android.bp
@@ -0,0 +1,104 @@
+/*
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
+package {
+    default_team: "trendy_team_android_telemetry_client_infra",
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+cc_test {
+    name: "stats_code_gen_cc_test",
+    srcs: [
+        "AtomCodeGen_test.cpp",
+    ],
+    generated_headers: [
+        "test_atom_cc_gen_hdrs",
+        "cts_atom_cc_gen_hdrs",
+    ],
+    generated_sources: [
+        "test_atom_cc_gen_srcs",
+        "cts_atom_cc_gen_srcs",
+    ],
+    test_suites: [
+        "device-tests",
+    ],
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+        "-g",
+        "-Wno-deprecated-declarations",
+    ],
+    shared_libs: [
+        "libstatssocket",
+        "libstatspull",
+    ],
+    static_libs: [
+        "libgmock",
+    ],
+}
+
+cc_test_host {
+    name: "stats_code_gen_srcs_cc_host_test",
+    test_suites: ["general-tests"],
+    srcs: ["host/StatsHistogram_test.cpp"],
+    cflags: [
+        "-Wall",
+        "-Wextra",
+        "-Werror",
+        "-g",
+        "-Wno-deprecated-declarations",
+    ],
+    static_libs: [
+        "stats-log-api-gen-cc-lib",
+        "libgmock_host",
+    ],
+    test_options: {
+        unit_test: true,
+    },
+}
+
+genrule {
+    name: "test_atom_cc_gen_hdrs",
+    tools: ["stats-log-api-gen"],
+    out: ["statslog_test.h"],
+    cmd: "$(location stats-log-api-gen) --header $(genDir)/statslog_test.h --module statsdtest" +
+        "  --namespace android,stats",
+}
+
+genrule {
+    name: "test_atom_cc_gen_srcs",
+    tools: ["stats-log-api-gen"],
+    out: ["statslog_test.cpp"],
+    cmd: "$(location stats-log-api-gen) --cpp $(genDir)/statslog_test.cpp --module statsdtest" +
+        "  --namespace android,stats --importHeader statslog_test.h",
+}
+
+genrule {
+    name: "cts_atom_cc_gen_hdrs",
+    tools: ["stats-log-api-gen"],
+    out: ["statslog_cts.h"],
+    cmd: "$(location stats-log-api-gen) --header $(genDir)/statslog_cts.h --module cts" +
+        "  --namespace android,stats,cts",
+}
+
+genrule {
+    name: "cts_atom_cc_gen_srcs",
+    tools: ["stats-log-api-gen"],
+    out: ["statslog_cts.cpp"],
+    cmd: "$(location stats-log-api-gen) --cpp $(genDir)/statslog_cts.cpp --module cts" +
+        "  --namespace android,stats,cts --importHeader statslog_cts.h",
+}
diff --git a/stats/stats_log_api_gen/test_cc/AtomCodeGen_test.cpp b/stats/stats_log_api_gen/test_cc/AtomCodeGen_test.cpp
new file mode 100644
index 00000000..a6470f9b
--- /dev/null
+++ b/stats/stats_log_api_gen/test_cc/AtomCodeGen_test.cpp
@@ -0,0 +1,67 @@
+/*
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
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <limits>
+
+#include "statslog_cts.h"
+#include "statslog_test.h"
+
+#ifdef __ANDROID__
+
+namespace {
+
+using namespace testing;
+using std::unique_ptr;
+
+TEST(AtomCodeGenTest, AtomConstants) {
+    ASSERT_EQ(android::stats::BLE_SCAN_STATE_CHANGED, 2);
+    ASSERT_EQ(android::stats::cts::TEST_ATOM_REPORTED, 205);
+}
+
+TEST(AtomCodeGenTest, CreateLinearHistogram) {
+    unique_ptr<android::stats::StatsHistogram> hist =
+            android::stats::create_test_extension_atom_reported__linear_histogram_histogram();
+
+    EXPECT_THAT(hist->getBins(), ElementsAre(android::stats::UNDERFLOW_BIN, 0, 10, 20, 30, 40, 50,
+                                             60, 70, 80, 90, 100));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0));
+}
+
+TEST(AtomCodeGenTest, CreateExponentialHistogram) {
+    unique_ptr<android::stats::StatsHistogram> hist =
+            android::stats::create_test_extension_atom_reported__exponential_histogram_histogram();
+
+    EXPECT_THAT(hist->getBins(),
+                ElementsAre(android::stats::UNDERFLOW_BIN, 5, 10, 20, 40, 80, 160));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0, 0));
+}
+
+TEST(AtomCodeGenTest, CreateExplicitHistogram) {
+    unique_ptr<android::stats::StatsHistogram> hist =
+            android::stats::create_test_extension_atom_reported__explicit_histogram_histogram();
+
+    EXPECT_THAT(hist->getBins(), ElementsAre(android::stats::UNDERFLOW_BIN, -10, -7, 0, 19, 100));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0));
+}
+
+}  // namespace
+
+#else
+GTEST_LOG_(INFO) << "This test does nothing.\n";
+#endif
diff --git a/stats/stats_log_api_gen/test_cc/host/StatsHistogram_test.cpp b/stats/stats_log_api_gen/test_cc/host/StatsHistogram_test.cpp
new file mode 100644
index 00000000..3a8d30fa
--- /dev/null
+++ b/stats/stats_log_api_gen/test_cc/host/StatsHistogram_test.cpp
@@ -0,0 +1,172 @@
+/*
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
+#include <StatsHistogram.h>
+#include <gmock/gmock.h>
+#include <gtest/gtest.h>
+
+#include <memory>
+
+namespace android {
+namespace util {
+namespace statslogapigen {
+namespace {
+
+using namespace testing;
+using std::string;
+using std::unique_ptr;
+using std::vector;
+
+struct TestCase {
+    string name;
+    unique_ptr<StatsHistogram> (*histCreator)();
+};
+
+void PrintTo(const TestCase& testCase, std::ostream* os) {
+    *os << testCase.name;
+}
+
+class StatsHistogramTestParameterized : public TestWithParam<TestCase> {
+protected:
+    unique_ptr<StatsHistogram> hist;
+
+    void SetUp() override {
+        hist = GetParam().histCreator();
+    }
+};
+
+const vector<TestCase> testCases = {
+        {"linear", []() { return StatsHistogram::createLinearBins(0, 50, 5); }},
+        {"exponential", []() { return StatsHistogram::createExponentialBins(5, 160, 5); }},
+        {"explicit", []() { return StatsHistogram::createExplicitBins({-10, -7, 0, 19, 100}); }}};
+
+INSTANTIATE_TEST_SUITE_P(StatsHistogramTestParameterized, StatsHistogramTestParameterized,
+                         ValuesIn(testCases));
+
+TEST(StatsHistogramTest, InitialStateLinear) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createLinearBins(0, 50, 5);
+    EXPECT_THAT(hist->getBins(), ElementsAre(UNDERFLOW_BIN, 0, 10, 20, 30, 40, 50));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0, 0));
+}
+
+TEST(StatsHistogramTest, InitialStateExponential) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExponentialBins(5, 160, 5);
+    EXPECT_THAT(hist->getBins(), ElementsAre(UNDERFLOW_BIN, 5, 10, 20, 40, 80, 160));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0, 0));
+}
+
+TEST(StatsHistogramTest, InitialStateExplicit) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExplicitBins({-10, -7, 0, 19, 100});
+    EXPECT_THAT(hist->getBins(), ElementsAre(UNDERFLOW_BIN, -10, -7, 0, 19, 100));
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 0));
+}
+
+TEST(StatsHistogramTest, SingleEntryLinear) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createLinearBins(0, 50, 5);
+    hist->addValue(18);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 1, 0, 0, 0, 0));
+}
+
+TEST(StatsHistogramTest, SingleEntryExponential) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExponentialBins(5, 160, 5);
+    hist->addValue(101);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 0, 1, 0));
+}
+
+TEST(StatsHistogramTest, SingleEntryExplicit) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExplicitBins({-10, -7, 0, 19, 100});
+    hist->addValue(0);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 1, 0, 0));
+}
+
+TEST_P(StatsHistogramTestParameterized, Underflow) {
+    hist->addValue(-100);
+
+    const vector<int> binCounts = hist->getBinCounts();
+    EXPECT_EQ(binCounts[0], 1);
+
+    const vector<int> remainingBins(binCounts.begin() + 1, binCounts.end());
+    EXPECT_THAT(remainingBins, Each(Eq(0)));
+}
+
+TEST_P(StatsHistogramTestParameterized, Overflow) {
+    hist->addValue(200);
+
+    const vector<int> binCounts = hist->getBinCounts();
+    EXPECT_EQ(binCounts.back(), 1);
+
+    const vector<int> remainingBins(binCounts.begin(), binCounts.end() - 1);
+    EXPECT_THAT(remainingBins, Each(Eq(0)));
+}
+
+TEST_P(StatsHistogramTestParameterized, UnderflowMarker) {
+    hist->addValue(UNDERFLOW_BIN);
+
+    const vector<int> binCounts = hist->getBinCounts();
+    EXPECT_EQ(binCounts[0], 1);
+
+    const vector<int> remainingBins(binCounts.begin() + 1, binCounts.end());
+    EXPECT_THAT(remainingBins, Each(Eq(0)));
+}
+
+TEST(StatsHistogramTest, MultipleEntriesLinear) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createLinearBins(0, 50, 5);
+    hist->addValue(18);
+    hist->addValue(40);
+    hist->addValue(45);
+    hist->addValue(19.99999);
+    hist->addValue(27);
+    hist->addValue(0.0000001);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 1, 2, 1, 0, 2, 0));
+}
+
+TEST(StatsHistogramTest, MultipleEntriesExponential) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExponentialBins(5, 160, 5);
+    hist->addValue(101);
+    hist->addValue(40);
+    hist->addValue(45);
+    hist->addValue(159.99999);
+    hist->addValue(160.000001);
+    hist->addValue(80);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 0, 0, 0, 2, 3, 1));
+}
+
+TEST(StatsHistogramTest, MultipleEntriesExplicit) {
+    unique_ptr<StatsHistogram> hist = StatsHistogram::createExplicitBins({-10, -7, 0, 19, 100});
+    hist->addValue(0);
+    hist->addValue(-10);
+    hist->addValue(1);
+    hist->addValue(25);
+    hist->addValue(49);
+    hist->addValue(-2);
+    EXPECT_THAT(hist->getBinCounts(), ElementsAre(0, 1, 1, 2, 2, 0));
+}
+
+TEST_P(StatsHistogramTestParameterized, Clear) {
+    for (float v = -20; v <= 200; v += 3) {
+        hist->addValue(v);
+    }
+    hist->clear();
+
+    // Check that all elements are 0.
+    const vector<int> binCounts = hist->getBinCounts();
+    EXPECT_THAT(binCounts, Each(Eq(0)));
+}
+
+}  // namespace
+}  // namespace statslogapigen
+}  // namespace util
+}  // namespace android
diff --git a/stats/stats_log_api_gen/test_java/Android.bp b/stats/stats_log_api_gen/test_java/Android.bp
index 33de14e7..58bde7e2 100644
--- a/stats/stats_log_api_gen/test_java/Android.bp
+++ b/stats/stats_log_api_gen/test_java/Android.bp
@@ -20,12 +20,14 @@ package {
 }
 
 android_test {
-    name: "VendorAtomCodeGenJavaTest",
+    name: "StatsCodeGenJavaTest",
     test_suites: [
         "general-tests",
     ],
     srcs: [
         "src/**/*.java",
+        ":cts-atom-java-gen",
+        ":test-atom-java-gen",
         ":test-vendor-atom-java-gen",
     ],
     static_libs: [
@@ -38,6 +40,22 @@ android_test {
     ],
 }
 
+java_test_host {
+    name: "StatsCodeGenSrcsJavaHostTest",
+    test_suites: [
+        "general-tests",
+    ],
+    srcs: [
+        "host/src/**/*.java",
+        ":stats-log-api-gen-java-srcs",
+    ],
+    static_libs: [
+        "TestParameterInjector",
+        "junit",
+        "truth",
+    ],
+}
+
 genrule {
     name: "test-vendor-atom-java-gen",
     tools: ["stats-log-api-gen"],
@@ -55,3 +73,25 @@ genrule {
         ":libstats_atom_options_protos",
     ],
 }
+
+testPackage = "com.android.test.statslogapigen"
+genrule {
+    name: "test-atom-java-gen",
+    tools: ["stats-log-api-gen"],
+    out: ["com/android/test/statslogapigen/TestAtomsLog.java"],
+    cmd: "$(location stats-log-api-gen) --java $(out)" +
+        " --module statsdtest" +
+        " --javaPackage com.android.test.statslogapigen" +
+        " --javaClass TestAtomsLog",
+}
+
+ctsPackage = "com.android.cts.statslogapigen"
+genrule {
+    name: "cts-atom-java-gen",
+    tools: ["stats-log-api-gen"],
+    out: ["com/android/cts/statslogapigen/CtsAtomsLog.java"],
+    cmd: "$(location stats-log-api-gen) --java $(out)" +
+        " --module cts" +
+        " --javaPackage com.android.cts.statslogapigen" +
+        " --javaClass CtsAtomsLog",
+}
diff --git a/stats/stats_log_api_gen/test_java/host/src/com/android/test/statslogapigen/StatsHistogramTest.java b/stats/stats_log_api_gen/test_java/host/src/com/android/test/statslogapigen/StatsHistogramTest.java
new file mode 100644
index 00000000..4fad1819
--- /dev/null
+++ b/stats/stats_log_api_gen/test_java/host/src/com/android/test/statslogapigen/StatsHistogramTest.java
@@ -0,0 +1,175 @@
+/*
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
+package com.android.test.statslogapigen;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.google.common.collect.ImmutableList;
+import com.google.testing.junit.testparameterinjector.TestParameterInjector;
+import com.google.testing.junit.testparameterinjector.TestParameter;
+import com.google.testing.junit.testparameterinjector.TestParameterValuesProvider;
+
+import android.util.statslogapigen.StatsHistogram;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+
+import java.util.Arrays;
+
+@RunWith(TestParameterInjector.class)
+public class StatsHistogramTest {
+
+    private static final class StatsHistogramProvider extends TestParameterValuesProvider {
+        @Override
+        protected ImmutableList<?> provideValues(Context context) {
+            return ImmutableList.of(
+                value(StatsHistogram.createLinearBins(0f, 50f, 5)).withName("linear"),
+                value(StatsHistogram.createExponentialBins(5f, 160f, 5)).withName("exponential"),
+                value(StatsHistogram.createExplicitBins(-10, -7, 0, 19, 100)).withName("explicit"));
+        }
+    }
+
+    @Test
+    public void testLinearInitialState() throws Exception {
+        StatsHistogram hist = StatsHistogram.createLinearBins(0f, 50f, 5);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[7]);
+        assertThat(hist.getBins()).isEqualTo(
+                new float[] {StatsHistogram.UNDERFLOW, 0, 10, 20, 30, 40, 50});
+    }
+
+    @Test
+    public void testExponentialInitialState() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExponentialBins(5f, 160f, 5);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[7]);
+        assertThat(hist.getBins()).isEqualTo(
+                new float[] {StatsHistogram.UNDERFLOW, 5, 10, 20, 40, 80, 160});
+    }
+
+    @Test
+    public void testExplicitInitialState() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExplicitBins(-10, -7, 0, 19, 100);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[6]);
+        assertThat(hist.getBins()).isEqualTo(
+                new float[] {StatsHistogram.UNDERFLOW, -10, -7, 0, 19, 100});
+    }
+
+    @Test
+    public void testSingleEntryLinear() throws Exception {
+        StatsHistogram hist = StatsHistogram.createLinearBins(0f, 50f, 5);
+        hist.addValue(18);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 0, 1, 0, 0, 0, 0});
+    }
+
+    @Test
+    public void testSingleEntryExponential() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExponentialBins(5f, 160f, 5);
+        hist.addValue(101);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 0, 0, 0, 0, 1, 0});
+    }
+
+    @Test
+    public void testSingleEntryExplicit() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExplicitBins(-10, -7, 0, 19, 100);
+        hist.addValue(0);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 0, 0, 1, 0, 0});
+    }
+
+    @Test
+    public void testUnderflow(
+            @TestParameter(valuesProvider = StatsHistogramProvider.class) StatsHistogram hist)
+            throws Exception {
+        hist.addValue(-100);
+        int[] binCounts = hist.getBinCounts();
+        assertThat(binCounts[0]).isEqualTo(1);
+
+        // Check that all elements after first element are 0.
+        assertThat(Arrays.stream(binCounts).skip(1).distinct()).containsExactly(0);
+    }
+
+    @Test
+    public void testOverflow(
+            @TestParameter(valuesProvider = StatsHistogramProvider.class) StatsHistogram hist)
+            throws Exception {
+        hist.addValue(200);
+        int[] binCounts = hist.getBinCounts();
+        assertThat(binCounts[binCounts.length - 1]).isEqualTo(1);
+
+        // Check that all elements before last element are 0.
+        assertThat(Arrays.stream(binCounts)
+                .limit(binCounts.length - 1).distinct()).containsExactly(0);
+    }
+
+    @Test
+    public void testAddUnderflowMarker(
+            @TestParameter(valuesProvider = StatsHistogramProvider.class) StatsHistogram hist)
+            throws Exception {
+        hist.addValue(StatsHistogram.UNDERFLOW);
+        int[] binCounts = hist.getBinCounts();
+        assertThat(binCounts[0]).isEqualTo(1);
+
+        // Check that all elements after first element are 0.
+        assertThat(Arrays.stream(binCounts).skip(1).distinct()).containsExactly(0);
+    }
+
+    @Test
+    public void testMultipleEntriesLinear() throws Exception {
+        StatsHistogram hist = StatsHistogram.createLinearBins(0f, 50f, 5);
+        hist.addValue(18);
+        hist.addValue(40);
+        hist.addValue(45);
+        hist.addValue(19.99999f);
+        hist.addValue(27);
+        hist.addValue(0.0000001f);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 1, 2, 1, 0, 2, 0});
+    }
+
+    @Test
+    public void testMultipleEntriesExponential() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExponentialBins(5f, 160f, 5);
+        hist.addValue(101);
+        hist.addValue(40);
+        hist.addValue(45);
+        hist.addValue(159.99999f);
+        hist.addValue(160.000001f);
+        hist.addValue(80);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 0, 0, 0, 2, 3, 1});
+    }
+
+    @Test
+    public void testMultipleEntriesExplicit() throws Exception {
+        StatsHistogram hist = StatsHistogram.createExplicitBins(-10, -7, 0, 19, 100);
+        hist.addValue(0);
+        hist.addValue(-10);
+        hist.addValue(1);
+        hist.addValue(25);
+        hist.addValue(49);
+        hist.addValue(-2);
+        assertThat(hist.getBinCounts()).isEqualTo(new int[] {0, 1, 1, 2, 2, 0});
+    }
+
+    @Test
+    public void testClear(
+            @TestParameter(valuesProvider = StatsHistogramProvider.class) StatsHistogram hist)
+            throws Exception {
+        for (float v = -20; v <= 200; v += 3) {
+            hist.addValue(v);
+        }
+        hist.clear();
+
+        // Check that all elements are 0.
+        assertThat(Arrays.stream(hist.getBinCounts()).distinct()).containsExactly(0);
+    }
+}
diff --git a/stats/stats_log_api_gen/test_java/src/com/android/test/statslogapigen/AtomCodeGenTest.java b/stats/stats_log_api_gen/test_java/src/com/android/test/statslogapigen/AtomCodeGenTest.java
new file mode 100644
index 00000000..2c8485d6
--- /dev/null
+++ b/stats/stats_log_api_gen/test_java/src/com/android/test/statslogapigen/AtomCodeGenTest.java
@@ -0,0 +1,67 @@
+/*
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
+package com.android.test.statslogapigen;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import com.android.cts.statslogapigen.CtsAtomsLog;
+import com.android.test.statslogapigen.TestAtomsLog;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+
+/**
+ * Runs the stats-log-api-gen tests for atoms java generated code
+ */
+@RunWith(JUnit4.class)
+public class AtomCodeGenTest {
+    @Test
+    public void testAtomConstants() throws Exception {
+        assertThat(TestAtomsLog.BLE_SCAN_STATE_CHANGED).isEqualTo(2);
+        assertThat(CtsAtomsLog.TEST_ATOM_REPORTED).isEqualTo(205);
+    }
+
+    @Test
+    public void testCreateLinearHistogram() throws Exception {
+        TestAtomsLog.StatsHistogram hist =
+                TestAtomsLog.createTestExtensionAtomReported_LinearHistogramHistogram();
+        assertThat(hist.getBinCounts()).isEqualTo(new int[12]);
+        assertThat(hist.getBins())
+                .isEqualTo(new float[] {TestAtomsLog.StatsHistogram.UNDERFLOW, 0, 10, 20, 30, 40,
+                        50, 60, 70, 80, 90, 100});
+    }
+
+    @Test
+    public void testCreateExponentialHistogram() throws Exception {
+        TestAtomsLog.StatsHistogram hist =
+                TestAtomsLog.createTestExtensionAtomReported_ExponentialHistogramHistogram();
+        assertThat(hist.getBinCounts()).isEqualTo(new int[7]);
+        assertThat(hist.getBins())
+                .isEqualTo(new float[] {
+                        TestAtomsLog.StatsHistogram.UNDERFLOW, 5, 10, 20, 40, 80, 160});
+    }
+
+    @Test
+    public void testCreateExplicitHistogram() throws Exception {
+        TestAtomsLog.StatsHistogram hist =
+                TestAtomsLog.createTestExtensionAtomReported_ExplicitHistogramHistogram();
+        assertThat(hist.getBinCounts()).isEqualTo(new int[6]);
+        assertThat(hist.getBins())
+                .isEqualTo(
+                        new float[] {TestAtomsLog.StatsHistogram.UNDERFLOW, -10, -7, 0, 19, 100});
+    }
+}
diff --git a/stats/stats_log_api_gen/utils.cpp b/stats/stats_log_api_gen/utils.cpp
index 54c6c667..1016456f 100644
--- a/stats/stats_log_api_gen/utils.cpp
+++ b/stats/stats_log_api_gen/utils.cpp
@@ -18,6 +18,12 @@
 
 #include <stdio.h>
 
+#include <algorithm>
+#include <cctype>
+#include <cstdlib>
+#include <filesystem>
+#include <fstream>
+#include <functional>
 #include <map>
 #include <string>
 #include <utility>
@@ -25,10 +31,14 @@
 
 #include "Collation.h"
 #include "frameworks/proto_logging/stats/atom_field_options.pb.h"
+#include "settings_provider.h"
 
 namespace android {
 namespace stats_log_api_gen {
 
+namespace fs = std::filesystem;
+
+using std::ifstream;
 using std::map;
 using std::string;
 using std::vector;
@@ -52,6 +62,175 @@ static vector<string> Split(const string& s, const string& delimiters) {
     return result;
 }
 
+static void write_native_histogram_helper_signature(FILE* out, const string& atomName,
+                                                    const string& fieldName) {
+    fprintf(out,
+            "std::unique_ptr<%s> "
+            "create_%s__%s_histogram()",
+            HISTOGRAM_STEM.c_str(), atomName.c_str(), fieldName.c_str());
+}
+
+static int write_native_histogram_helper_definition(
+        FILE* out, const string& atomName, const string& fieldName,
+        const os::statsd::HistogramBinOption& histBinOption) {
+    int errorCount = 0;
+
+    // Print method signature.
+    write_native_histogram_helper_signature(out, atomName, fieldName);
+    fprintf(out, " {\n");
+
+    fprintf(out, "%*sreturn %s::create", 8, "", HISTOGRAM_STEM.c_str());
+    if (histBinOption.has_generated_bins()) {
+        const os::statsd::HistogramBinOption::GeneratedBins& genBins =
+                histBinOption.generated_bins();
+        switch (genBins.strategy()) {
+            case os::statsd::HistogramBinOption::GeneratedBins::LINEAR:
+                fprintf(out, "Linear");
+                break;
+            case os::statsd::HistogramBinOption::GeneratedBins::EXPONENTIAL:
+                fprintf(out, "Exponential");
+                break;
+            default:
+                errorCount++;
+        }
+        fprintf(out, "Bins(%f, %f, %d);\n", genBins.min(), genBins.max(), genBins.count());
+    } else if (histBinOption.has_explicit_bins()) {
+        const os::statsd::HistogramBinOption::ExplicitBins& explicitBins =
+                histBinOption.explicit_bins();
+        fprintf(out, "ExplicitBins({");
+        const char* separator = "";
+        for (const float bin : explicitBins.bin()) {
+            fprintf(out, "%s%f", separator, bin);
+            separator = ", ";
+        }
+        fprintf(out, "});\n");
+    }
+    fprintf(out, "}\n\n");
+
+    return errorCount;
+}
+
+static int write_java_histogram_helper(FILE* out, const string& atomName, const string& fieldName,
+                                       const os::statsd::HistogramBinOption& histBinOption,
+                                       const bool staticMethods) {
+    int errorCount = 0;
+
+    // Print method signature.
+    const char* methodPrefix = staticMethods ? "static " : "";
+    fprintf(out, "%*spublic %s%s create%s_%sHistogram() {\n", 4, "", methodPrefix,
+            HISTOGRAM_STEM.c_str(), snake_to_pascal(atomName).c_str(),
+            snake_to_pascal(fieldName).c_str());
+
+    fprintf(out, "%*sreturn %s.create", 8, "", HISTOGRAM_STEM.c_str());
+    if (histBinOption.has_generated_bins()) {
+        const os::statsd::HistogramBinOption::GeneratedBins& genBins =
+                histBinOption.generated_bins();
+        switch (genBins.strategy()) {
+            case os::statsd::HistogramBinOption::GeneratedBins::LINEAR:
+                fprintf(out, "Linear");
+                break;
+            case os::statsd::HistogramBinOption::GeneratedBins::EXPONENTIAL:
+                fprintf(out, "Exponential");
+                break;
+            default:
+                errorCount++;
+        }
+        fprintf(out, "Bins(%ff, %ff, %d);\n", genBins.min(), genBins.max(), genBins.count());
+    } else if (histBinOption.has_explicit_bins()) {
+        const os::statsd::HistogramBinOption::ExplicitBins& explicitBins =
+                histBinOption.explicit_bins();
+        fprintf(out, "ExplicitBins(");
+        const char* separator = "";
+        for (const float bin : explicitBins.bin()) {
+            fprintf(out, "%s%ff", separator, bin);
+            separator = ", ";
+        }
+        fprintf(out, ");\n");
+    }
+    fprintf(out, "%*s}\n\n", 4, "");
+
+    return errorCount;
+}
+
+static int write_src_header(FILE* out, const fs::path& filePath) {
+    ifstream fileStream(filePath);
+    if (!fileStream.is_open()) {
+        fprintf(stderr, "Could not open file: %s", filePath.c_str());
+        return 1;
+    }
+
+    string line;
+    bool atImports = false;
+    while (std::getline(fileStream, line)) {
+        if (line == "// HEADER_BEGIN") {
+            atImports = true;
+        } else if (line == "// HEADER_END") {
+            break;
+        } else if (atImports) {
+            fprintf(out, "%s\n", line.c_str());
+        }
+    }
+    fileStream.close();
+
+    return 0;
+}
+
+static int write_src_body(FILE* out, const fs::path& filePath, int indent,
+                          const std::function<bool(string& firstLine)>& firstLineTransformer) {
+    ifstream fileStream(filePath);
+    if (!fileStream.is_open()) {
+        fprintf(stderr, "Could not open file: %s\n", filePath.c_str());
+        return 1;
+    }
+
+    string line;
+    bool atClassDef = false;
+
+    while (std::getline(fileStream, line)) {
+        if (line == "// BODY_BEGIN") {
+            std::getline(fileStream, line);
+            if (firstLineTransformer && !firstLineTransformer(line)) {
+                fprintf(stderr, "First line transform failed: %s\n", filePath.c_str());
+                return 1;
+            }
+            fprintf(out, "%*s%s\n", indent, "", line.c_str());
+            atClassDef = true;
+        } else if (line == "// BODY_END") {
+            break;
+        } else if (atClassDef) {
+            fprintf(out, "%*s%s\n", indent, "", line.c_str());
+        }
+    }
+    fileStream.close();
+
+    return 0;
+}
+
+static int write_srcs_bodies(FILE* out, const char* path, int indent,
+                             const vector<string>& excludeList,
+                             const std::function<bool(string& firstLine)>& firstLineTransformer) {
+    int errors = 0;
+    const string fullPath = get_data_dir_path(path);
+    for (const fs::path& filePath : fs::directory_iterator(fullPath)) {
+        // Inline source bodies from filePath if it's not in excludeList.
+        if (std::find(excludeList.begin(), excludeList.end(), filePath.stem()) ==
+            excludeList.end()) {
+            errors += write_src_body(out, filePath, indent, firstLineTransformer);
+        }
+    }
+
+    return errors;
+}
+
+static bool make_java_class_static(string& line) {
+    const size_t pos = line.find(' ');
+    if (pos == string::npos) {
+        return false;
+    }
+    line.insert(pos, " static");
+    return true;
+}
+
 void build_non_chained_decl_map(const Atoms& atoms,
                                 std::map<int, AtomDeclSet::const_iterator>* decl_map) {
     for (AtomDeclSet::const_iterator atomIt = atoms.non_chained_decls.begin();
@@ -162,6 +341,25 @@ string make_constant_name(const string& str) {
     return result;
 }
 
+/**
+ * Convert snake_case to PascalCase
+ */
+string snake_to_pascal(const string& snake) {
+    string pascal;
+    bool capitalize = true;
+    for (const char c : snake) {
+        if (c == '_') {
+            capitalize = true;
+        } else if (capitalize) {
+            pascal += std::toupper(c);
+            capitalize = false;
+        } else {
+            pascal += c;
+        }
+    }
+    return pascal;
+}
+
 const char* cpp_type_name(java_type_t type, bool isVendorAtomLogging) {
     switch (type) {
         case JAVA_TYPE_BOOLEAN:
@@ -419,7 +617,7 @@ void write_native_method_header(FILE* out, const string& methodName,
 }
 
 void write_native_header_preamble(FILE* out, const string& cppNamespace, bool includePull,
-                                     bool bootstrap, bool isVendorAtomLogging) {
+                                  bool includeHistogram, bool bootstrap, bool isVendorAtomLogging) {
     // Print prelude
     fprintf(out, "// This file is autogenerated\n");
     fprintf(out, "\n");
@@ -429,10 +627,19 @@ void write_native_header_preamble(FILE* out, const string& cppNamespace, bool in
     fprintf(out, "#include <vector>\n");
     fprintf(out, "#include <map>\n");
     fprintf(out, "#include <set>\n");
+    fprintf(out, "#include <memory>\n");
     if (includePull) {
         fprintf(out, "#include <stats_pull_atom_callback.h>\n");
     }
 
+#ifdef CC_INCLUDE_HDRS_DIR
+    const vector<string> excludeList =
+            includeHistogram ? vector<string>{} : vector<string>{HISTOGRAM_STEM};
+    write_srcs_header(out, CC_INCLUDE_HDRS_DIR, excludeList);
+#else
+    (void)includeHistogram;  // suppress unused parameter error
+#endif
+
     if (isVendorAtomLogging) {
         fprintf(out, "#include <aidl/android/frameworks/stats/VendorAtom.h>\n");
     }
@@ -546,11 +753,13 @@ void write_java_usage(FILE* out, const string& method_name, const string& atom_c
     fprintf(out, ");<br>\n");
 }
 
-int write_java_non_chained_methods(FILE* out, const SignatureInfoMap& signatureInfoMap) {
+int write_java_non_chained_methods(FILE* out, const SignatureInfoMap& signatureInfoMap,
+                                   const bool staticMethods) {
+    const char* methodPrefix = staticMethods ? "static " : "";
     for (auto signatureInfoMapIt = signatureInfoMap.begin();
          signatureInfoMapIt != signatureInfoMap.end(); signatureInfoMapIt++) {
         // Print method signature.
-        fprintf(out, "    public static void write_non_chained(int code");
+        fprintf(out, "    public %svoid write_non_chained(int code", methodPrefix);
         vector<java_type_t> signature = signatureInfoMapIt->first;
         int argIndex = 1;
         for (vector<java_type_t>::const_iterator arg = signature.begin(); arg != signature.end();
@@ -699,5 +908,66 @@ AtomDeclSet get_annotations(int argIndex,
     return fieldNumberToAtomDeclSetIt->second;
 }
 
+bool has_histograms(const AtomDeclSet& decls) {
+    return std::find_if_not(decls.begin(), decls.end(), [](shared_ptr<AtomDecl> decl) {
+               return decl->fieldNameToHistBinOption.empty();
+           }) != decls.end();
+}
+
+void write_native_histogram_helper_declarations(FILE* out, const AtomDeclSet& atomDeclSet) {
+    for (const shared_ptr<AtomDecl>& atomDecl : atomDeclSet) {
+        for (const auto& [fieldName, histBinOption] : atomDecl->fieldNameToHistBinOption) {
+            write_native_histogram_helper_signature(out, atomDecl->name, fieldName);
+            fprintf(out, ";\n");
+        }
+    }
+    fprintf(out, "\n");
+}
+
+int write_native_histogram_helper_definitions(FILE* out, const AtomDeclSet& atomDeclSet) {
+    int errors = 0;
+    for (const shared_ptr<AtomDecl>& atomDecl : atomDeclSet) {
+        for (const auto& [fieldName, histBinOption] : atomDecl->fieldNameToHistBinOption) {
+            errors += write_native_histogram_helper_definition(out, atomDecl->name, fieldName,
+                                                               histBinOption);
+        }
+    }
+    return errors;
+}
+
+int write_srcs_header(FILE* out, const char* path, const vector<string>& excludeList) {
+    int errors = 0;
+    const string fullPath = get_data_dir_path(path);
+    for (const fs::path& filePath : fs::directory_iterator(fullPath)) {
+        // Add headers from filePath if it's not in excludeList.
+        if (std::find(excludeList.begin(), excludeList.end(), filePath.stem()) ==
+            excludeList.end()) {
+            errors += write_src_header(out, filePath);
+        }
+    }
+
+    return errors;
+}
+
+int write_java_srcs_classes(FILE* out, const char* path, const vector<string>& excludeList) {
+    return write_srcs_bodies(out, path, 4 /* indent */, excludeList, make_java_class_static);
+}
+
+int write_cc_srcs_classes(FILE* out, const char* path, const vector<string>& excludeList) {
+    return write_srcs_bodies(out, path, 0 /* indent */, excludeList, nullptr /* nameTransformer */);
+}
+
+int write_java_histogram_helpers(FILE* out, const AtomDeclSet& atomDeclSet,
+                                 const bool staticMethods) {
+    int errors = 0;
+    for (const shared_ptr<AtomDecl>& atomDecl : atomDeclSet) {
+        for (const auto& [fieldName, histBinOption] : atomDecl->fieldNameToHistBinOption) {
+            errors += write_java_histogram_helper(out, atomDecl->name, fieldName, histBinOption,
+                                                  staticMethods);
+        }
+    }
+    return errors;
+}
+
 }  // namespace stats_log_api_gen
 }  // namespace android
diff --git a/stats/stats_log_api_gen/utils.h b/stats/stats_log_api_gen/utils.h
index 1e9ffe47..f6513f5b 100644
--- a/stats/stats_log_api_gen/utils.h
+++ b/stats/stats_log_api_gen/utils.h
@@ -47,6 +47,7 @@ const int JAVA_MODULE_REQUIRES_ATTRIBUTION = 0x02;
 const char ANNOTATION_CONSTANT_NAME_PREFIX[] = "ANNOTATION_ID_";
 const char ANNOTATION_CONSTANT_NAME_VENDOR_PREFIX[] = "AnnotationId.";
 const char ANNOTATION_CONSTANT_NAME_VENDOR_NATIVE_PREFIX[] = "AnnotationId::";
+const string HISTOGRAM_STEM("StatsHistogram");
 
 struct AnnotationStruct {
     string name;
@@ -66,6 +67,8 @@ string get_restriction_category_str(int annotationValue);
 
 string make_constant_name(const string& str);
 
+string snake_to_pascal(const string& snake);
+
 const char* cpp_type_name(java_type_t type, bool isVendorAtomLogging = false);
 
 const char* java_type_name(java_type_t type);
@@ -97,7 +100,8 @@ void write_native_method_header(FILE* out, const string& methodName,
                                 const AtomDecl& attributionDecl, bool isVendorAtomLogging = false);
 
 void write_native_header_preamble(FILE* out, const string& cppNamespace, bool includePull,
-                                  bool bootstrap, bool isVendorAtomLogging = false);
+                                  bool hasHistograms, bool bootstrap,
+                                  bool isVendorAtomLogging = false);
 
 void write_native_header_epilogue(FILE* out, const string& cppNamespace);
 
@@ -112,7 +116,8 @@ int write_java_method_signature(FILE* out, const vector<java_type_t>& signature,
 void write_java_usage(FILE* out, const string& method_name, const string& atom_code_name,
                       const AtomDecl& atom);
 
-int write_java_non_chained_methods(FILE* out, const SignatureInfoMap& signatureInfoMap);
+int write_java_non_chained_methods(FILE* out, const SignatureInfoMap& signatureInfoMap,
+                                   const bool staticMethods);
 
 int write_java_work_source_methods(FILE* out, const SignatureInfoMap& signatureInfoMap);
 
@@ -127,6 +132,21 @@ public:
 int get_max_requires_api_level(int minApiLevel, const AtomDeclSet* atomDeclSet,
                                const vector<java_type_t>& signature);
 
+bool has_histograms(const AtomDeclSet& decls);
+
+void write_native_histogram_helper_declarations(FILE* out, const AtomDeclSet& atomDeclSet);
+
+int write_native_histogram_helper_definitions(FILE* out, const AtomDeclSet& atomDeclSet);
+
+int write_srcs_header(FILE* out, const char* path, const std::vector<std::string>& excludeList);
+
+int write_java_srcs_classes(FILE* out, const char* path,
+                            const std::vector<std::string>& excludeList);
+
+int write_cc_srcs_classes(FILE* out, const char* path, const std::vector<std::string>& excludeList);
+
+int write_java_histogram_helpers(FILE* out, const AtomDeclSet& atomDeclSet,
+                                 const bool staticMethods);
 }  // namespace stats_log_api_gen
 }  // namespace android
 
```

