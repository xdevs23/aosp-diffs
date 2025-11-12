```diff
diff --git a/OWNERS b/OWNERS
index 7d938eb9..e01943f3 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,15 +1,16 @@
 jeffreyhuang@google.com
+klausecker@google.com
 monicamwang@google.com
 muhammadq@google.com
-rayhdez@google.com
 rslawik@google.com
 sharaienko@google.com
 singhtejinder@google.com
-tsaichristine@google.com
+stwu@google.com
+tingsmu@google.com
 yaochen@google.com
 
 # Settings UI
-per-file settings_enums.proto=edgarwang@google.com
+per-file settings_enums.proto=edgarwang@google.com,chiujason@google.com,cipson@google.com
 
 # Adservices
 per-file adservices_enums.proto=binhnguyen@google.com,pdevpura@google.com
diff --git a/stats/Android.bp b/stats/Android.bp
index 259f7e09..68c62dd0 100644
--- a/stats/Android.bp
+++ b/stats/Android.bp
@@ -32,11 +32,11 @@ shared_enum_protos = [
 enum_protos = [
     // go/keep-sorted start
     ":connectivity_service_proto",
-    ":data_stall_event_proto",
-    ":device_policy_proto",
+    ":data_stall_event_enums_proto",
+    ":device_policy_enums_proto",
     ":dns_resolver_proto",
     ":launcher_proto",
-    ":network_stack_proto",
+    ":network_stack_enum_proto",
     ":srcs_bluetooth_leaudio_protos",
     ":srcs_bluetooth_protos",
     ":style_proto",
@@ -44,6 +44,7 @@ enum_protos = [
     ":text_classifier_proto",
     "enums/accessibility/*.proto",
     "enums/accounts/*.proto",
+    "enums/adpf/*.proto",
     "enums/adservices/common/*.proto",
     "enums/adservices/enrollment/*.proto",
     "enums/adservices/fledge/*.proto",
@@ -80,6 +81,8 @@ enum_protos = [
     "enums/pdf/*.proto",
     "enums/performance/*.proto",
     "enums/photopicker/*.proto",
+    "enums/printing/*.proto",
+    "enums/privatespace/*.proto",
     "enums/ranging/*.proto",
     "enums/security/advancedprotection/*.proto",
     "enums/server/*.proto",
@@ -105,6 +108,7 @@ enum_protos = [
     "enums/stats/tls/*.proto",
     "enums/stats/tv/*.proto",
     "enums/stats/wm/*.proto",
+    "enums/statusbar/*.proto",
     "enums/system/**/*.proto",
     "enums/telecomm/*.proto",
     "enums/telephony/*.proto",
@@ -118,6 +122,7 @@ enum_protos = [
     "enums/wear/connectivity/*.proto",
     "enums/wear/media/*.proto",
     "enums/wear/modes/*.proto",
+    "enums/wear/physicalux/*.proto",
     "enums/wear/setupwizard/*.proto",
     "enums/wear/time/*.proto",
     "enums/wifi/*.proto",
@@ -138,6 +143,7 @@ atom_protos = [
     "atoms/appfunctions/*.proto",
     "atoms/appsearch/*.proto",
     "atoms/art/*.proto",
+    "atoms/audioproxy/*.proto",
     "atoms/autofill/*.proto",
     "atoms/automotive/carlauncher/*.proto",
     "atoms/automotive/carpower/*.proto",
@@ -147,6 +153,7 @@ atom_protos = [
     "atoms/automotive/caruilib/*.proto",
     "atoms/automotive/sensitiveapplock/*.proto",
     "atoms/backported_fixes/*.proto",
+    "atoms/battery/*.proto",
     "atoms/bluetooth/*.proto",
     "atoms/broadcasts/*.proto",
     "atoms/camera/*.proto",
@@ -178,6 +185,7 @@ atom_protos = [
     "atoms/kernel/*.proto",
     "atoms/locale/*.proto",
     "atoms/location/*.proto",
+    "atoms/locksettings/*.proto",
     "atoms/media/*.proto",
     "atoms/memory/*.proto",
     "atoms/memorysafety/*.proto",
@@ -192,6 +200,8 @@ atom_protos = [
     "atoms/photopicker/*.proto",
     "atoms/placeholder/*.proto",
     "atoms/power/*.proto",
+    "atoms/printing/*.proto",
+    "atoms/privatespace/*.proto",
     "atoms/providers/mediaprovider/*.proto",
     "atoms/ranging/*.proto",
     "atoms/rkpd/*.proto",
@@ -199,6 +209,7 @@ atom_protos = [
     "atoms/selinux/*.proto",
     "atoms/settings/*.proto",
     "atoms/statsd/*.proto",
+    "atoms/statusbar/*.proto",
     "atoms/sysui/*.proto",
     "atoms/telecomm/*.proto",
     "atoms/telephony/*.proto",
@@ -216,6 +227,7 @@ atom_protos = [
     "atoms/wear/connectivity/*.proto",
     "atoms/wear/media/*.proto",
     "atoms/wear/modes/*.proto",
+    "atoms/wear/physicalux/*.proto",
     "atoms/wear/prototiles/*.proto",
     "atoms/wear/setupwizard/*.proto",
     "atoms/wear/time/*.proto",
@@ -283,6 +295,16 @@ filegroup {
 filegroup {
     name: "libstats_atom_message_protos",
     srcs: [
-        "message/*.proto",
+        "message/**/*.proto",
     ],
 }
+
+rust_protobuf {
+    name: "libframework_service_enums_protos_rs",
+    protos: [
+        "enums/service/enums.proto",
+    ],
+    crate_name: "framework_service_enums_protos_rs",
+    source_stem: "framework_service_enums_protos_rs_source",
+    host_supported: true,
+}
diff --git a/stats/atoms.proto b/stats/atoms.proto
index d5ccb340..6b0d4cd0 100644
--- a/stats/atoms.proto
+++ b/stats/atoms.proto
@@ -37,7 +37,6 @@ import "frameworks/proto_logging/stats/atoms/locale/locale_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/location/location_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/media/media_drm_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/wearsysui/wearsysui_atoms.proto";
-import "frameworks/proto_logging/stats/atoms/providers/mediaprovider/media_provider_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/sysui/sysui_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/usb/usb_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/view/inputmethod/inputmethod_atoms.proto";
@@ -84,8 +83,7 @@ import "frameworks/proto_logging/stats/enums/service/procstats_enum.proto";
 import "frameworks/proto_logging/stats/enums/stats/connectivity/connectivity_service.proto";
 import "frameworks/proto_logging/stats/enums/stats/connectivity/network_stack.proto";
 import "frameworks/proto_logging/stats/enums/stats/connectivity/tethering.proto";
-import "frameworks/proto_logging/stats/enums/stats/dnsresolver/dns_resolver.proto";
-import "frameworks/proto_logging/stats/enums/stats/devicepolicy/device_policy.proto";
+import "frameworks/proto_logging/stats/enums/stats/dnsresolver/dns_resolver_enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/devicepolicy/device_policy_enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/docsui/docsui_enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/accessibility/accessibility_enums.proto";
@@ -112,7 +110,10 @@ import "frameworks/proto_logging/stats/enums/view/enums.proto";
 import "frameworks/proto_logging/stats/enums/wifi/enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/textclassifier/textclassifier_enums.proto";
 import "frameworks/proto_logging/stats/enums/stats/otaupdate/updateengine_enums.proto";
-import "frameworks/proto_logging/stats/message/mediametrics_message.proto";
+import "frameworks/proto_logging/stats/message/connectivity/data_stall_event.proto";
+import "frameworks/proto_logging/stats/message/connectivity/network_stack.proto";
+import "frameworks/proto_logging/stats/message/devicepolicy/device_policy.proto";
+import "frameworks/proto_logging/stats/message/mediametrics/mediametrics_message.proto";
 import "frameworks/proto_logging/stats/atoms/devicelogs/device_logs_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/wearservices/wearservices_atoms.proto";
 import "frameworks/proto_logging/stats/atoms/wear/media/wear_media_atoms.proto";
@@ -196,7 +197,7 @@ message Atom {
                 42 [(module) = "framework", (module) = "statsdtest"];
         IsolatedUidChanged isolated_uid_changed =
                 43 [(module) = "framework", (module) = "statsd", (module) = "statsdtest"];
-        PacketWakeupOccurred packet_wakeup_occurred = 44 [(module) = "framework"];
+        PacketWakeupOccurred packet_wakeup_occurred = 44 [(module) = "framework", deprecated = true];
         WallClockTimeShifted wall_clock_time_shifted = 45 [(module) = "framework"];
         AnomalyDetected anomaly_detected = 46 [(module) = "statsd"];
         AppBreadcrumbReported app_breadcrumb_reported = 47
@@ -209,7 +210,7 @@ message Atom {
         WifiMulticastLockStateChanged wifi_multicast_lock_state_changed = 53 [(module) = "wifi"];
         AppStartMemoryStateCaptured app_start_memory_state_captured = 55 [(module) = "framework"];
         ShutdownSequenceReported shutdown_sequence_reported = 56 [(module) = "framework"];
-        BootSequenceReported boot_sequence_reported = 57;
+        BootSequenceReported boot_sequence_reported = 57 [(module) = "bootstats"];
         OverlayStateChanged overlay_state_changed =
                 59 [(module) = "framework", (module) = "statsdtest"];
         ForegroundServiceStateChanged foreground_service_state_changed
@@ -467,11 +468,13 @@ message Atom {
         MediaProviderIdleMaintenanceFinished media_provider_idle_maintenance_finished =
             237 [(module) = "mediaprovider"];
         RebootEscrowRecoveryReported reboot_escrow_recovery_reported = 238 [(module) = "framework"];
-        BootTimeEventDuration boot_time_event_duration_reported = 239 [(module) = "framework"];
+        BootTimeEventDuration boot_time_event_duration_reported =
+                239 [(module) = "framework", (module) = "bootstats"];
         BootTimeEventElapsedTime boot_time_event_elapsed_time_reported =
-                240 [(module) = "framework"];
-        BootTimeEventUtcTime boot_time_event_utc_time_reported = 241;
-        BootTimeEventErrorCode boot_time_event_error_code_reported = 242 [(module) = "framework"];
+                240 [(module) = "framework", (module) = "bootstats"];
+        BootTimeEventUtcTime boot_time_event_utc_time_reported = 241 [(module) = "bootstats"];
+        BootTimeEventErrorCode boot_time_event_error_code_reported =
+                242 [(module) = "framework", (module) = "bootstats"];
         UserspaceRebootReported userspace_reboot_reported = 243 [(module) = "framework"];
         NotificationReported notification_reported = 244 [(module) = "framework"];
         sysui.NotificationPanelReported notification_panel_reported = 245 [(module) = "sysui"];
@@ -621,7 +624,8 @@ message Atom {
         AppSearchPutDocumentStatsReported app_search_put_document_stats_reported = 348 [(module) = "appsearch"];
         sysui.DeviceControlChanged device_control_changed = 349 [(module) = "sysui"];
         DeviceStateChanged device_state_changed = 350 [(module) = "framework"];
-        input.InputDeviceRegistered inputdevice_registered = 351 [(module) = "framework"];
+        input.InputDeviceRegistered inputdevice_registered =
+            351 [(module) = "framework", (module) = "input"];
         sysui.SmartSpaceCardReported smartspace_card_reported = 352 [(module) = "sysui"];
         AuthPromptAuthenticateInvoked auth_prompt_authenticate_invoked = 353 [(module) = "framework"];
         AuthManagerCanAuthenticateInvoked auth_manager_can_authenticate_invoked = 354 [(module) = "framework"];
@@ -644,7 +648,8 @@ message Atom {
         AppProcessDied app_process_died = 373 [(module) = "framework"];
         NetworkIpReachabilityMonitorReported network_ip_reachability_monitor_reported =
             374 [(module) = "network_stack"];
-        input.SlowInputEventReported slow_input_event_reported = 375 [(module) = "input"];
+        input.SlowInputEventReported slow_input_event_reported =
+            375 [(module) = "input"];
         ANROccurredProcessingStarted anr_occurred_processing_started = 376 [(module) = "framework"];
         AppSearchRemoveStatsReported app_search_remove_stats_reported = 377 [(module) = "appsearch"];
         MediaCodecReported media_codec_reported =
@@ -808,7 +813,7 @@ message Atom {
         VmCpuStatusReported vm_cpu_status_reported = 522 [(module) = "virtualizationservice", deprecated = true];
         VmMemStatusReported vm_mem_status_reported = 523 [(module) = "virtualizationservice", deprecated = true];
         PackageInstallationSessionReported package_installation_session_reported = 524 [(module) = "framework"];
-        DefaultNetworkRematchInfo default_network_rematch_info = 525 [(module) = "connectivity"];
+        DefaultNetworkRematch default_network_rematch = 525 [(module) = "connectivity"];
         NetworkSelectionPerformance network_selection_performance = 526 [(module) = "connectivity"];
         NetworkNsdReported network_nsd_reported = 527 [(module) = "connectivity"];
         BluetoothDisconnectionReasonReported bluetooth_disconnection_reason_reported = 529 [(module) = "bluetooth"];
@@ -877,8 +882,6 @@ message Atom {
         view.inputmethod.ImeRequestFinished ime_request_finished = 581 [(module) = "framework"];
         usb.UsbComplianceWarningsReported usb_compliance_warnings_reported = 582 [(module) = "framework"];
         locale.AppSupportedLocalesChanged app_supported_locales_changed = 583 [(module) = "framework"];
-        providers.mediaprovider.MediaProviderVolumeRecoveryReported
-            media_provider_volume_recovery_reported = 586 [(module) = "mediaprovider"];
         hardware.biometrics.BiometricPropertiesCollected
             biometric_properties_collected = 587 [(module) = "framework"];
         kernel.KernelWakeupAttributed kernel_wakeup_attributed = 588 [(module) = "framework"];
@@ -934,6 +937,7 @@ message Atom {
     extensions 579; // AppSearchSchemaMigrationStatsReported app_search_schema_migration_stats_reported
     extensions 584; // ApplicationGrammaticalInflectionChanged application_grammatical_inflection_changed
     extensions 585; // CredentialManagerApiCalled credential_manager_api_called
+    extensions 586; // MediaProviderVolumeRecoveryReported media_provider_volume_recovery_reported
     extensions 593; // ExpressHistogramSampleReported express_histogram_sample_reported
     extensions 598; // AdServicesBackCompatGetTopicsReported ad_services_back_compat_get_topics_reported
     extensions 599; // AdServicesBackCompatEpochComputationClassifierReported ad_services_back_compat_epoch_computation_classifier_reported
@@ -1181,7 +1185,7 @@ message Atom {
     extensions 847; // PersistAdSelectionResultCalled persist_ad_selection_result_called
     extensions 848; // ServerAuctionKeyFetchCalled server_auction_key_fetch_called
     extensions 849; // ServerAuctionBackgroundKeyFetchScheduled server_auction_background_key_fetch_enabled
-    extensions 850; // VpnConnectionStateChanged vpn_connection_state_changed
+    // reserved 850
     extensions 851; // VpnConnectionReported vpn_connection_reported
     extensions 852; // CarWakeupFromSuspendReported car_wakeup_from_suspend_reported
     extensions 853; // ExcessiveBinderProxyCountReported excessive_binder_proxy_count_reported
@@ -1375,13 +1379,82 @@ message Atom {
     extensions 1046; // AdservicesMeasurementBackgroundJobInfo adservices_measurement_background_job_info
     extensions 1047; // AppSearchVmPayloadStatsReported app_search_vm_payload_stats_reported
     extensions 1048; // ClipboardGetEventReported clipboard_get_event_reported
+    extensions 1049; // PermissionManagerPageInteraction permission_manager_page_interaction
+    extensions 1050; // AppSearchAppOpenEventIndexerStatsReported app_search_app_open_event_indexer_stats_reported
+    extensions 1051; // ThermalHeadroomListenerDataReported thermal_headroom_listener_data_reported
+    extensions 1052; // CpuHeadroomReported cpu_headroom_reported
+    extensions 1053; // GpuHeadroomReported gpu_headroom_reported
+    extensions 1054; // AdvancedProtectionUsbStateChangeErrorReported advanced_protection_usb_state_change_error_reported
+    extensions 1055; // NotificationAssistantEventReported notification_assistant_event_reported
+    extensions 1056; // NotificationAssistantDurationReceived notification_assistant_duration_received
+    extensions 1057; // WifiNetworkValidationReport wifi_network_validation_report
+    extensions 1058; // UnifiedTableEnabledReported unified_table_enabled_reported
+    extensions 1059; // ProdDebugEnabledReported prod_debug_enabled_reported
+    extensions 1060; // SettingsBiometricsOnboarding settings_biometrics_onboarding
+    extensions 1061; // FileAccessAttributesQueryReported file_access_attributes_query_reported
+    extensions 1062; // AdServicesMeasurementReportingOriginsPerEnrollmentCounted adservices_measurement_reporting_origins_per_enrollment_counted
+    extensions 1063; // AdServicesMeasurementReportingOriginsPerEnrllXDestCounted adservices_measurement_reporting_origins_per_enrll_x_dest_counted
+    extensions 1064; // BinderSpamReported binder_spam_reported
+    extensions 1065; // OwnedPhotosRevokedFromAppReported owned_photos_revoked_from_app_reported
+    extensions 1066; //  MediaMetadataExtractionReported media_metadata_extraction_reported
+    extensions 1067; // AutoclickEventReported autoclick_event_reported
+    extensions 1068; // AutoclickEnabledReported autoclick_enabled_reported
+    extensions 1069; // AutoclickSessionDurationReported autoclick_session_duration_reported
+    extensions 1070; // ChannelSoundingTypesSupported channel_sounding_types_supported
+    extensions 1071; // FrameworkPrintJob framework_print_job
+    extensions 1072; // FrameworkPrinterDiscovery framework_printer_discovery
+    extensions 1073; // FrameworkMainPrintUiLaunched framework_main_print_ui_launched
+    extensions 1074; // FrameworkAdvancedOptionsUiLaunched framework_advanced_ui_launched
+    extensions 1075; // BipsPrintJob bips_print_job
+    extensions 1076; // BipsDiscoveredPrinterCapabilities bips_discovered_printer_capabilities
+    extensions 1077; // BipsPrinterDiscovery bips_printer_discovery
+    extensions 1078; // BipsRequestPrinterCapabilitiesStatus bips_request_printer_capabilities_status
+    extensions 1079; // AutoclickSettingsStateReported autoclick_settings_state_reported
+    extensions 1080; // DevicePresenceChanged device_presence_changed
+    extensions 1081; // WearBleMigrationStateChanged wear_ble_migration_state_changed
+    extensions 1082; // AppMediaCodecUsageReported app_media_codec_usage_reported
+    extensions 1083; // AudioProxyConnectionStateChanged audio_proxy_connection_state_changed
+    extensions 1084; // ChannelSoundingRequesterSessionReported channel_sounding_requester_session_reported
+    extensions 1085; // RawBatteryGaugeStatsReported raw_battery_gauge_stats_reported
+    extensions 1086; // Reserved for b/397963390
+    extensions 1087; // DeviceLockKioskAppInstallationFailed device_lock_kiosk_app_installation_failed
+    extensions 1088; // ImplicitUriGrantEventReported implicit_uri_grant_event_reported
+    extensions 1089; // AppRestartOccurred app_restart_occurred
+    extensions 1090; // BinderCallsReported binder_calls_reported
+    extensions 1091; // DeviceLockFcmMessageReceived device_lock_fcm_message_received
+    extensions 1092; // StatusBarChipReported status_bar_chip_reported
+    extensions 1093; // DeviceLockProvisionStateEvent device_lock_provision_state_event
+    extensions 1094; // DeviceLockDeviceStateEvent device_lock_device_state_event
+    extensions 1095; // WearGestureSubscriptionChanged wear_gesture_subscription_changed
+    extensions 1096; // WearGestureReported wear_gesture_reported
+    extensions 1097; // WearGestureDetectionStateChanged wear_gesture_detection_state_changed
+    extensions 1098; // SqliteAppOpEventReported sqlite_app_op_event_reported
+    extensions 1099; // LskfAuthenticationAttempted lskf_authentication_attempted
+    extensions 1100; // PermissionOneTimeSessionEventReported permission_one_time_session_event_reported
+    extensions 1101; // PackageInstallerSessionReported package_installer_session_reported
+    extensions 1102; // CoreNetworkingCriticalBytesEventOccurred core_networking_critical_bytes_event_occurred
+    extensions 1103; // AggregatedAppOpAccessEventReported aggregated_app_op_access_event_reported
+    extensions 1104; // BluetoothPbapClientContactDownloadReported bluetooth_pbap_client_contact_download_reported
+    extensions 1105; // HealthConnectNotification health_connect_notification
+    extensions 1106; // AudioProxyMultichannelGroupJoined audio_proxy_multichannel_group_joined
+    extensions 1107; // AudioProxyMultichannelGroupDisbanded audio_proxy_multichannel_group_disbanded
+    extensions 1108; // AudioProxyMultichannelConnectionErrorReported audio_proxy_multichannel_connection_error_reported
+    extensions 1109; // AudioProxyCloudSettingsRpcRequested audio_proxy_cloud_settings_rpc_requested
+    extensions 1110; // AudioProxySpatialAudioConfigUpdated audio_proxy_spatial_audio_config_updated
+    extensions 1111; // AudioProxySetUpReported audio_proxy_set_up_reported
+    extensions 1112; // MediaProviderOpReported media_provider_op_reported
+    extensions 1113; // FuseOpReported fuse_op_reported
+    extensions 1114; // DeviceStorageStateReported device_storage_state_reported
+    extensions 1115; // DeviceStorageStatePerUidReported device_storage_state_per_uid_reported
+    extensions 1116; // PrivateSpaceAddButtonEvent private_space_add_button_event
+    extensions 1117; // PrivateSpaceMoveContentEvent private_space_move_content_event
+    extensions 1118; // AndroidGraphicsBitmapAllocationSnapshot android_graphics_bitmap_allocation_snapshot
     extensions 9999; // Atom9999 atom_9999
-
     // StatsdStats tracks platform atoms with ids up to 1500.
     // Update StatsdStats::kMaxPushedAtomId when atom ids here approach that value.
 
     // Pulled events will start at field 10000.
-    // Next: 10237
+    // Next: 10246
     oneof pulled {
         WifiBytesTransfer wifi_bytes_transfer = 10000 [(module) = "framework"];
         WifiBytesTransferByFgBg wifi_bytes_transfer_by_fg_bg = 10001 [(module) = "framework"];
@@ -1436,16 +1509,18 @@ message Atom {
         TrainInfo train_info = 10051 [(module) = "statsd"];
         TimeZoneDataInfo time_zone_data_info = 10052 [(module) = "framework"];
         ExternalStorageInfo external_storage_info = 10053 [(module) = "framework"];
-        GpuStatsGlobalInfo gpu_stats_global_info = 10054;
-        GpuStatsAppInfo gpu_stats_app_info = 10055;
+        GpuStatsGlobalInfo gpu_stats_global_info = 10054 [(module) = "gpustats"];
+        GpuStatsAppInfo gpu_stats_app_info = 10055 [(module) = "gpustats"];
         SystemIonHeapSize system_ion_heap_size = 10056 [deprecated = true, (module) = "framework"];
         AppsOnExternalStorageInfo apps_on_external_storage_info = 10057 [(module) = "framework"];
         FaceSettings face_settings = 10058 [(module) = "framework"];
         CoolingDevice cooling_device = 10059 [(module) = "framework"];
         AppOps app_ops = 10060 [(module) = "framework"];
         ProcessSystemIonHeapSize process_system_ion_heap_size = 10061 [(module) = "framework"];
-        SurfaceflingerStatsGlobalInfo surfaceflinger_stats_global_info = 10062;
-        SurfaceflingerStatsLayerInfo surfaceflinger_stats_layer_info = 10063;
+        SurfaceflingerStatsGlobalInfo surfaceflinger_stats_global_info =
+                10062 [(module) = "surfaceflinger"];
+        SurfaceflingerStatsLayerInfo surfaceflinger_stats_layer_info =
+                10063 [(module) = "surfaceflinger"];
         ProcessMemorySnapshot process_memory_snapshot = 10064 [(module) = "framework"];
         VmsClientStats vms_client_stats = 10065 [(module) = "car"];
         NotificationRemoteViews notification_remote_views = 10066 [(module) = "framework"];
@@ -1500,7 +1575,8 @@ message Atom {
         sysui.LauncherLayoutSnapshot launcher_layout_snapshot = 10108
             [(module) = "sysui"];
         GlobalHibernatedApps global_hibernated_apps = 10109 [(module) = "framework"];
-        input.InputEventLatencySketch input_event_latency_sketch = 10110 [(module) = "input"];
+        input.InputEventLatencySketch input_event_latency_sketch =
+            10110 [(module) = "input"];
         BatteryUsageStatsBeforeReset battery_usage_stats_before_reset =
             10111 [(module) = "framework"];
         BatteryUsageStatsSinceReset battery_usage_stats_since_reset =
@@ -1557,7 +1633,7 @@ message Atom {
         PresenceNotifyEvent presence_notify_event = 10144 [(module) = "telephony"];
         GbaEvent gba_event = 10145 [(module) = "telephony"];
         PerSimStatus per_sim_status = 10146 [(module) = "telephony"];
-        GpuWorkPerUid gpu_work_per_uid = 10147;
+        GpuWorkPerUid gpu_work_per_uid = 10147 [(module) = "gpustats"];
         PersistentUriPermissionsAmountPerPackage persistent_uri_permissions_amount_per_package =
             10148 [(module) = "framework"];
         SignedPartitionInfo signed_partition_info = 10149 [(module) = "framework"];
@@ -1649,18 +1725,27 @@ message Atom {
     // 10228 is reserved due to removing the old atom
     extensions 10229; // PressureStallInformation pressure_stall_information
     extensions 10230; // FrameworkWakelockInfo framework_wakelock_info
-    extensions 10231; // NotificationBundlePreferences notification_bundle_preferences
+    extensions 10231; // NotificationAdjustmentPreferences notification_adjustment_preferences
     extensions 10232; // ZramMmStatMmd zram_mm_stat_mmd
     extensions 10233; // ZramBdStatMmd zram_bd_stat_mmd
     extensions 10234; // WidgetMemoryStats
     extensions 10235; // TelecomEventStats telecom_event_stats
     extensions 10236; // AdvancedProtectionStateInfo advanced_protection_state_info
+    extensions 10237; // AdpfSupportInfo adpf_support_info
+    extensions 10238; // ThermalHeadroomListenerInfo thermal_headroom_listener_info
+    extensions 10239; // AndroidHardwareHealthStorage android_hardware_health_storage
+    extensions 10240; // ZramIoStatMmd zram_io_stat_mmd
+    extensions 10241; // Reserved for b/397963390
+    extensions 10242; // CallSequencingStats call_sequencing_stats
+    extensions 10243; // CallSequencingOperationStats call_sequencing_operation_stats
+    extensions 10244; // DeviceLockPotentialBypassSnapshot device_lock_potential_bypass_snapshot
+    extensions 10245; // BatteryLife battery_life
     extensions 99999; // Atom99999 atom_99999
 
     // DO NOT USE field numbers above 100,000 in AOSP.
     // Field numbers 100,000 - 199,999 are reserved for non-AOSP (e.g. OEMs) to use.
     // Field numbers 200,000 and above are reserved for future use; do not use them at all.
-    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 936, 937, 938, 939, 10008, 10036, 10040, 10041, 10228, 21004, 21005;
+    reserved 54, 58, 83, 360 to 363, 492, 597, 801, 850, 936, 937, 938, 939, 10008, 10036, 10040, 10041, 10228, 21004, 21005;
 }
 
 /*
@@ -2136,6 +2221,8 @@ message WifiConnectionResultReported {
     optional int64 l2_connecting_duration_ms = 21;
     // L3 connecting time duration in millis
     optional int64 l3_connecting_duration_ms = 22;
+    // The disconnect reason of previous session
+    optional WifiDisconnectReported.FailureCode last_disconnect_reason = 23;
 }
 
 /**
@@ -2436,6 +2523,8 @@ message WifiSetupFailureCrashReported {
         P2P_FAILURE_HAL = 11;
         // Supplicant error on WifiP2pNative.setupInterface
         P2P_FAILURE_SUPPLICANT = 12;
+        // Subsystem Restart; a crash in the firmware/driver
+        SSR_CRASH = 13;
     }
     // Type of failure
     optional Type type= 1;
@@ -3283,13 +3372,29 @@ message ShutdownSequenceReported {
  *   system/core/bootstat/bootstat.cpp
  */
 message BootSequenceReported {
-    // Reason for bootloader boot. Eg. reboot. See bootstat.cpp for larger list
-    // Default: "<EMPTY>" if not available.
-    optional string bootloader_reason = 1;
+  // Reason for bootloader boot. Eg. reboot. See bootstat.cpp for larger list
+  // Default: "<EMPTY>" if not available.
+  optional string bootloader_reason = 1;
+
+  // Deprecated. Use system_main_reason, system_sub_reason, and
+  // system_detail instead.
+  //
+  // Reason for system boot. Eg. bootloader,reboot,userrequested
+  // Format: <main_reason>,<sub_reason>,<detail>
+  // Default: "<EMPTY>" if not available.
+  optional string system_reason = 2 [deprecated = true];
+
+  // First part of the system reason. E.g. bootloader.
+  // Default: Empty string if not available.
+  optional string system_main_reason = 7;
 
-    // Reason for system boot. Eg. bootloader, reboot,userrequested
-    // Default: "<EMPTY>" if not available.
-    optional string system_reason = 2;
+    // Second part of the system reason. E.g. reboot.
+    // Default: Empty string if not available.
+    optional string system_sub_reason = 8;
+
+    // Third part of the system reason. E.g. userrequested.
+    // Default: Empty string if not available.
+    optional string system_detail = 9;
 
     // End of boot time in ms from unix epoch using system wall clock.
     optional int64 end_time_millis = 3;
@@ -5060,6 +5165,10 @@ message StyleUIChanged {
     optional string shortcut = 30;
     optional string shortcut_slot_id = 31;
     optional int32 lock_effect_id_hash = 32;
+    optional int32 clock_seed_color = 33;
+    optional android.stats.style.CustomizationPickerSrceen customization_picker_screen = 34;
+    optional android.stats.style.AppIconStyle app_icon_style = 35;
+    optional bool use_clock_customization = 36;
 }
 
 /**
@@ -5623,6 +5732,10 @@ message AppStartOccurred {
         NOTIFICATION = 2;
         LOCKSCREEN = 3;
         RECENTS_ANIMATION = 4;
+        DESKTOP_ANIMATION = 5;
+        QSS = 6;
+        TILE = 7;
+        COMPLICATION = 8;
     }
     // The type of the startup source.
     optional SourceType source_type = 16;
@@ -6414,6 +6527,9 @@ message NotificationReported {
     // Whether the notification was promoted and whether it was promotable.
     optional bool is_promoted_ongoing = 30;
     optional bool has_promotable_characteristics = 31;
+
+    // Whether the notification was summarized.
+    optional bool has_summary = 32;
 }
 
 /**
@@ -9396,7 +9512,12 @@ message PackageNotificationPreferences {
     // Which types of bundles (groupings by category) are allowed for this package. Bundle types are
     // a limited set, so this repeated field will never be larger than the total number of bundle
     // types.
-    repeated android.stats.notification.BundleTypes allowed_bundle_types = 8;
+    // DEPRECATED: bundles did not launch with app-specific bundle type permissions, so whether
+    // the adjustment is denied overall is stored instead in denied_adjustments.
+    repeated android.stats.notification.BundleTypes allowed_bundle_types = 8 [deprecated = true];
+    // A list of the types of adjustments (such as notification classification or summarization)
+    // that the user has disabled for this specific package.
+    repeated android.stats.notification.AdjustmentKey denied_adjustments = 9;
 }
 
 /**
@@ -10332,7 +10453,35 @@ message NetworkDnsEventReported {
 
     // Additional pass-through fields opaque to statsd.
     // The DNS resolver Mainline module can add new fields here without requiring an OS update.
-    optional android.stats.dnsresolver.DnsQueryEvents dns_query_events = 8 [(log_mode) = MODE_BYTES];
+    message DnsQueryEvents {
+        message DnsQueryEvent {
+            optional android.stats.dnsresolver.NsRcode rcode = 1;
+
+            optional android.stats.dnsresolver.NsType type = 2;
+
+            optional android.stats.dnsresolver.CacheStatus cache_hit = 3;
+
+            optional android.stats.dnsresolver.IpVersion ip_version = 4;
+
+            optional android.stats.dnsresolver.Protocol protocol = 5;
+
+            // Number of DNS query retry times
+            optional int32 retry_times = 6;
+
+            // Ordinal number of name server.
+            optional int32 dns_server_index = 7;
+
+            // Used only by TCP and DOT. True for new connections.
+            optional bool connected = 8;
+
+            optional int32 latency_micros = 9;
+
+            optional android.stats.dnsresolver.LinuxErrno linux_errno = 10;
+        }
+
+        repeated DnsQueryEvent dns_query_event = 1;
+    }
+    optional DnsQueryEvents dns_query_events = 8 [(log_mode) = MODE_BYTES];
 
     // The sample rate of DNS stats (to statsd) is 1/sampling_rate_denom.
     optional int32 sampling_rate_denom = 9;
@@ -10352,7 +10501,19 @@ message NetworkDnsServerSupportReported {
     optional android.stats.dnsresolver.PrivateDnsModes private_dns_modes = 2;
 
     // Stores the state of all DNS servers for this network
-    optional android.stats.dnsresolver.Servers servers = 3 [(log_mode) = MODE_BYTES];
+    message Servers {
+        message Server {
+            optional android.stats.dnsresolver.Protocol protocol = 1;
+
+            // The order of the dns server in the network
+            optional int32 index = 2;
+
+            // The validation status of the DNS server in the network
+            optional bool validated = 3;
+        }
+        repeated Server server = 1;
+    }
+    optional Servers servers = 3 [(log_mode) = MODE_BYTES];
 }
 
 /**
@@ -13585,7 +13746,7 @@ message RebootEscrowRebootReported {
 /**
  * Logs stats for AppSearch function calls
  *
- * Next tag: 13
+ * Next tag: 14
  */
 message AppSearchCallStatsReported {
     // The sampling interval for this specific type of stats
@@ -13633,12 +13794,15 @@ message AppSearchCallStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 12;
+
+    // The wall-clock timestamp in milliseconds since the previous request.
+    optional int64 time_since_previous_request_millis = 13;
 }
 
 /**
  * Logs detailed stats for putting a single document in AppSearch
  *
- * Next tag: 17
+ * Next tag: 19
  */
 message AppSearchPutDocumentStatsReported {
     // The sampling interval for this specific type of stats
@@ -13696,12 +13860,19 @@ message AppSearchPutDocumentStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 16;
+
+    // Time used to index all metadata terms in the document, which can only be added by
+    // PropertyExistenceIndexingHandler currently.
+    optional int32 metadata_term_index_latency_millis = 17;
+
+    // Time used to index all embeddings in the document.
+    optional int32 embedding_index_latency_millis = 18;
 }
 
 /**
  * Logs detailed stats for AppSearch Initialize
  *
- * Next tag: 22
+ * Next tag: 28
  */
 message AppSearchInitializeStatsReported {
     // The sampling interval for this specific type of stats
@@ -13778,12 +13949,30 @@ message AppSearchInitializeStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 21;
+
+    //Number of consecutive initialization failures that immediately preceded this initialization.
+    optional int32  native_num_previous_init_failures = 22;
+
+    // Restoration cause of integer index.
+    optional int32  native_integer_index_restoration_cause = 23;
+
+    // Restoration cause of qualified id join index.
+    optional int32  native_qualified_id_join_index_restoration_cause = 24;
+
+    // Restoration cause of embedding index.
+    optional int32  native_embedding_index_restoration_cause = 25;
+
+    // ICU data initialization status code
+    optional int32  native_initialize_icu_data_status_code = 26;
+
+    // Number of documents that failed to be reindexed during index restoration.
+    optional int32  native_num_failed_reindexed_documents = 27;
 }
 
 /**
  * Logs detailed stats for querying in AppSearch
  *
- * Next tag: 35
+ * Next tag: 61
  */
 message AppSearchQueryStatsReported {
     // The sampling interval for this specific type of stats
@@ -13824,16 +14013,16 @@ message AppSearchQueryStatsReported {
     // Overall time used for the native function call.
     optional int32 native_latency_millis = 10;
 
-    // Number of terms in the query string.
+    // Number of terms in the query string of parent_search_stats
     optional int32 native_num_terms = 11;
 
-    // Length of the query string.
+    // Length of the query string of parent_search_stats
     optional int32 native_query_length = 12;
 
-    // Number of namespaces filtered.
+    // Number of namespaces filtered of parent_search_stats
     optional int32 native_num_namespaces_filtered = 13;
 
-    // Number of schema types filtered.
+    // Number of schema types filtered of parent_search_stats
     optional int32 native_num_schema_types_filtered = 14;
 
     // The requested number of results in one page.
@@ -13847,18 +14036,18 @@ message AppSearchQueryStatsReported {
     // may be skipped.
     optional bool native_is_first_page = 17;
 
-    // Time used to parse the query, including 2 parts: tokenizing and
+    // Time used to parse the query of parent_search_stats, including 2 parts: tokenizing and
     // transforming tokens into an iterator tree.
     optional int32 native_parse_query_latency_millis = 18;
 
-    // Strategy of scoring and ranking.
+    // Strategy of scoring and ranking of parent_search_stats
     // Needs to be sync with RankingStrategy.Code in google3/third_party/icing/proto/scoring.proto
     optional int32 native_ranking_strategy = 19;
 
-    // Number of documents scored.
+    // Number of documents scored of parent_search_stats
     optional int32 native_num_documents_scored = 20;
 
-    // Time used to score the raw results.
+    // Time used to score the raw results of parent_search_stats.
     optional int32 native_scoring_latency_millis = 21;
 
     // Time used to rank the scored results.
@@ -13905,12 +14094,92 @@ message AppSearchQueryStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 34;
+
+    // Whether it contains numeric query or not.
+    optional bool parent_is_numeric_query = 35;
+
+    // Number of hits fetched by lite index before applying any filters.
+    optional int32 parent_num_fetched_hits_lite_index = 36;
+
+    // Number of hits fetched by main index before applying any filters.
+    optional int32 parent_num_fetched_hits_main_index = 37;
+
+    // Number of hits fetched by integer index before applying any filters.
+    optional int32 parent_num_fetched_hits_integer_index = 38;
+
+    // Time used in Lexer to extract lexer tokens from the query.
+    optional int32 parent_query_processor_lexer_extract_token_latency_ms = 39;
+
+    // Time used in Parser to consume lexer tokens extracted from the query.
+    optional int32 parent_query_processor_parser_consume_query_latency_ms = 40;
+
+    // Time used in QueryVisitor to visit and build (nested) DocHitInfoIterator.
+    optional int32 parent_query_processor_query_visitor_latency_ms = 41;
+
+    // The UTF-8 length of the query string
+    optional int32 child_query_length = 42;
+
+    // Number of terms in the query string.
+    optional int32 child_num_terms = 43;
+
+    // Number of namespaces filtered.
+    optional int32 child_num_namespaces_filtered = 44;
+
+    // Number of schema types filtered.
+    optional int32 child_num_schema_types_filtered = 45;
+
+    // Strategy of scoring and ranking.
+    optional int32 child_ranking_strategy = 46;
+
+    // Number of documents scored.
+    optional int32 child_num_documents_scored = 47;
+
+    // Time used to parse the query, including 2 parts: tokenizing and transforming tokens into an
+    // iterator tree.
+    optional int32 child_parse_query_latency_ms = 48;
+
+    // Time used to score the raw results.
+    optional int32 child_scoring_latency_ms = 49;
+
+    // Whether it contains numeric query or not.
+    optional bool child_is_numeric_query = 50;
+
+    // Number of hits fetched by lite index before applying any filters.
+    optional int32 child_num_fetched_hits_lite_index = 51;
+
+    // Number of hits fetched by main index before applying any filters.
+    optional int32 child_num_fetched_hits_main_index = 52;
+
+    // Number of hits fetched by integer index before applying any filters.
+    optional int32 child_num_fetched_hits_integer_index = 53;
+
+    // Time used in Lexer to extract lexer tokens from the query.
+    optional int32 child_query_processor_lexer_extract_token_latency_ms = 54;
+
+    // Time used in Parser to consume lexer tokens extracted from the query.
+    optional int32 child_query_processor_parser_consume_query_latency_ms = 55;
+
+    // Time used in QueryVisitor to visit and build (nested) DocHitInfoIterator.
+    optional int32 child_query_processor_query_visitor_latency_ms = 56;
+
+    // Byte size of the lite index hit buffer
+    optional int64 lite_index_hit_buffer_byte_size = 57;
+
+    // Byte size of the unsorted tail of the lite index hit buffer.
+    optional int64 lite_index_hit_buffer_unsorted_byte_size = 58;
+
+    // The type of the input page token.
+    optional int32 page_token_type = 59;
+
+    // Number of result states being force-evicted from ResultStateManager due to
+    // budget limit. This doesn't include expired or invalidated states.
+    optional int32 num_result_states_evicted = 60;
 }
 
 /**
  * Logs detailed stats for remove in AppSearch
  *
- * Next tag: 10
+ * Next tag: 17
  */
 message AppSearchRemoveStatsReported {
     // The sampling interval for this specific type of stats
@@ -13950,6 +14219,25 @@ message AppSearchRemoveStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 10;
+
+    // The UTF-8 length of the query string
+    optional int32 query_length = 11;
+
+    // Number of terms in the query string.
+    optional int32 num_terms = 12;
+
+    // Number of namespaces filtered.
+    optional int32 num_namespaces_filtered = 13;
+
+    // Number of schema types filtered.
+    optional int32 num_schema_types_filtered = 14;
+
+    // Time used to parse the query, including 2 parts: tokenizing and
+    // transforming tokens into an iterator tree.
+    optional int32 parse_query_latency_ms = 15;
+
+    // Time used to delete each document.
+    optional int32 document_removal_latency_ms = 16;
 }
 
 /**
@@ -13958,7 +14246,7 @@ message AppSearchRemoveStatsReported {
  * stats pushed from:
  *   frameworks/base/apex/appsearch/service/java/com/android/server/appsearch/AppSearchManagerService.java
  *
- * Next tag: 15
+ * Next tag: 18
  */
 message AppSearchOptimizeStatsReported {
     // The sampling interval for this specific type of stats
@@ -14009,6 +14297,15 @@ message AppSearchOptimizeStatsReported {
     // The bitmask for all enabled features on this device. Must be one or a combination of the
     // types AppSearchEnabledFeatures.
     optional int64 enabled_features = 14;
+
+    // The mode of index restoration if there is any.
+    optional int32 index_restoration_mode = 15;
+
+    // Number of namespaces before the optimization.
+    optional int32 num_original_namespaces = 16;
+
+    //Number of namespaces deleted.
+    optional int32 num_deleted_namespaces = 17;
 }
 
 // Reports information in external/icing/proto/icing/proto/storage.proto#DocumentStorageInfoProto
@@ -15672,6 +15969,7 @@ message AppFreezeChanged {
         UFR_COMPONENT_DISABLED = 29;
         UFR_OOM_ADJ_FOLLOW_UP = 30;
         UFR_OOM_ADJ_RECONFIGURATION = 31;
+        UFR_OOM_ADJ_REASON_SERVICE_BINDER_CALL = 32;
     }
 
     optional UnfreezeReason unfreeze_reason_v2 = 6;
@@ -15964,7 +16262,7 @@ message CellularDataServiceSwitch {
     // Number of switches from rat_from to rat_to.
     optional int32 switch_count = 6;
 
-    // // Whether the subscription is an opportunistic (can change CBRS network when available).
+    // Whether the subscription is an opportunistic (can change CBRS network when available).
     optional bool is_opportunistic = 7;
 }
 
@@ -16153,6 +16451,9 @@ message IncomingSms {
 
     // Whether the message was received over Carrier Roaming NB-Iot NTN network.
     optional bool is_nb_iot_ntn = 19;
+
+    // The length of PDU in bytes
+    optional int32 pdu_length = 20;
 }
 
 /**
@@ -16245,6 +16546,16 @@ message OutgoingSms {
 
     // Whether the message was sent over Carrier Roaming NB-Iot NTN network.
     optional bool is_nb_iot_ntn = 22;
+
+    // The length of PDU in bytes
+    optional int32 pdu_length = 23;
+
+    // The package name of the application sending the sms.
+    // Populated only for sms sent over non-terrestrial networks, empty otherwise.
+    optional string calling_package_name = 24;
+
+    // The application uid.
+    optional int32 app_uid = 25[(is_uid) = true];
 }
 
 /**
@@ -17028,6 +17339,8 @@ message UserLifecycleJourneyReported {
         GRANT_ADMIN = 7; // An admin grant journey
         REVOKE_ADMIN = 8; // An admin revocation journey
         USER_LIFECYCLE = 9; // User journey from creation to deletion
+        DEMOTE_MAIN_USER = 10; // Main user was demoted
+        PROMOTE_MAIN_USER = 11; // An admin user was promoted to main user.
     }
     optional Journey journey = 2;
     // Which user the journey is originating from - could be -1 for certain phases (eg USER_CREATE)
@@ -17340,6 +17653,7 @@ message AudioPowerUsageDataReported {
      * and bluetooth devices.
      */
     enum AudioDevice {
+        UNKNOWN_DEVICE          = 0x0;
         OUTPUT_EARPIECE         = 0x1; // handset
         OUTPUT_SPEAKER          = 0x2; // dual speaker
         OUTPUT_WIRED_HEADSET    = 0x4; // 3.5mm headset
@@ -17391,6 +17705,25 @@ message AudioPowerUsageDataReported {
 
     // Maximum volume (0 ... 1.0)
     optional float maximum_volume = 8;
+
+    // Audio device used based on system/media/audio/include/system/audio-base-utils.h
+    optional int32 device = 9;
+
+    // Audio Stream Type used as defined in audio_stream_type_t
+    // from system/media/audio/include/system/audio-hal-enums.h.
+    optional int32 stream_type = 10;
+
+    // Audio Source used as defined in audio_source_t
+    // from system/media/audio/include/system/audio-hal-enums.h.
+    optional int32 source = 11;
+
+    // Audio Usage used as defined in audio_usage_t
+    // from system/media/audio/include/system/audio-hal-enums.h.
+    optional int32 usage = 12;
+
+    // Content Type used as defined in audio_content_type_t
+    // from system/media/audio/include/system/audio-hal-enums.h.
+    optional int32 content_type = 13;
 }
 
 /**
@@ -22983,6 +23316,9 @@ message CdmAssociationAction {
 
     // Name of the CDM Association Request profiles.
     optional DeviceProfile device_profile = 2;
+
+    // The uid of package that created the association.
+    optional int32 package_uid = 3 [(is_uid) = true];
 }
 
 /**
@@ -23512,6 +23848,9 @@ message IncomingMms {
 
     // Whether the MMS was received over Carrier Roaming NB-Iot NTN network.
     optional bool is_nb_iot_ntn = 14;
+
+    // The length of PDU in bytes
+    optional int32 pdu_length = 15;
 }
 
 /**
@@ -23571,6 +23910,16 @@ message OutgoingMms {
 
     // Whether the MMS was sent over Carrier Roaming NB-Iot NTN network.
     optional bool is_nb_iot_ntn = 15;
+
+    // The length of PDU in bytes
+    optional int32 pdu_length = 16;
+
+    // The package name of the application sending the MMS.
+    // Populated only for MMS sent over non-terrestrial networks, empty otherwise.
+    optional string calling_package_name = 17;
+
+    // The application uid.
+    optional int32 app_uid = 18 [(is_uid) = true];
 }
 
 message PrivacySignalNotificationInteraction {
@@ -24183,8 +24532,22 @@ message ConnectivityStateSample {
 
     // Full list of network details (slice by transport / meteredness / internet+validated)
     optional NetworkList networks = 4 [(android.os.statsd.log_mode) = MODE_BYTES];
+
+    // Information for satellite access.
+    optional SatelliteAccessInfo satellite_access_info = 5
+    [(android.os.statsd.log_mode) = MODE_BYTES];
 }
 
+/**
+ * Pulls information for satellite access.
+ *
+ * Pulled from:
+ *   packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java
+ */
+message SatelliteAccessInfo {
+    // Number of satellite network opt-in uids on the device.
+    optional int32 optin_uid_count = 1;
+}
 
 /**
  * Pulls information for network selection rematch info.
@@ -24199,27 +24562,50 @@ message NetworkSelectionRematchReasonsInfo {
 }
 
 /**
- * Logs rematch information for the default network
+ * Logs rematch event for the default network
  *
  * Logs from:
  *   packages/modules/Connectivity/service/src/com/android/server/ConnectivityService.java
  */
-message DefaultNetworkRematchInfo {
+message DefaultNetworkRematch {
     // The session id comes from each reboot, this is used to correlate the statistics of the
     // networkselect on the same boot
     optional int64 session_id = 1;
 
+    // The reason of network rematch
+    optional android.stats.connectivity.RematchReason rematch_reason = 2;
+
+    optional DefaultNetworkRematchInfoList default_network_rematch_info_list = 3
+    [(android.os.statsd.log_mode) = MODE_BYTES];
+}
+
+message DefaultNetworkRematchInfoList {
+    repeated DefaultNetworkRematchInfo default_network_rematch_info = 1;
+}
+
+message DefaultNetworkRematchInfo {
     // The information of old device default network
-    optional NetworkDescription old_network = 2 [(android.os.statsd.log_mode) = MODE_BYTES];
+    optional NetworkDescription old_network = 1 [(android.os.statsd.log_mode) = MODE_BYTES];
 
     // The information of new device default network
-    optional NetworkDescription new_network = 3 [(android.os.statsd.log_mode) = MODE_BYTES];
-
-    // The reason of network rematch
-    optional android.stats.connectivity.RematchReason rematch_reason = 4;
+    optional NetworkDescription new_network = 2 [(android.os.statsd.log_mode) = MODE_BYTES];
 
     // The time duration the device kept the old network as the default in seconds
-    optional int32 time_duration_on_old_network_sec = 5;
+    optional int32 time_duration_on_old_network_sec = 3;
+
+    // Uid ranges which applied to this event.
+    optional UidRanges uid_ranges = 4 [(android.os.statsd.log_mode) = MODE_BYTES];
+}
+
+message UidRanges {
+    repeated UidRange uid_range = 1;
+}
+
+// Represents a range of UIDs.
+// The range is inclusive, denoted as [begin, end].
+message UidRange {
+    optional int32 begin = 1 [(is_uid) = true];
+    optional int32 end = 2 [(is_uid) = true];
 }
 
 /**
diff --git a/stats/atoms/accessibility/accessibility_extension_atoms.proto b/stats/atoms/accessibility/accessibility_extension_atoms.proto
index 44a3abca..6e6ce6a2 100644
--- a/stats/atoms/accessibility/accessibility_extension_atoms.proto
+++ b/stats/atoms/accessibility/accessibility_extension_atoms.proto
@@ -12,6 +12,18 @@ option java_multiple_files = true;
 extend Atom {
     optional AccessibilityCheckResultReported accessibility_check_result_reported = 910
     [(module) = "accessibility", (restriction_category) = RESTRICTION_DIAGNOSTIC];
+
+    optional AutoclickEventReported autoclick_event_reported = 1067
+    [(module) = "framework"];
+
+    optional AutoclickEnabledReported autoclick_enabled_reported = 1068
+    [(module) = "framework"];
+
+    optional AutoclickSessionDurationReported autoclick_session_duration_reported = 1069
+    [(module) = "framework"];
+
+    optional AutoclickSettingsStateReported autoclick_settings_state_reported = 1079
+    [(module) = "framework"];
 }
 
 /** Logs the result of an AccessibilityCheck. */
@@ -38,3 +50,64 @@ message AccessibilityCheckResultReported {
     // Result ID of the AccessibilityCheckResult.
     optional int32 result_id = 10;
 }
+
+/**
+ * Logs when an autoclick event occurs with information about the click type.
+ * Logged from:
+ *    frameworks/base/services/accessibility/java/com/android/server/accessibility/
+ *    AutoclickController.java
+ * Estimated Logging Rate (for users with autoclick feature enabled):
+ *    Peak: 15 times in 1 min | Avg: ~1000 times per day per user.
+ */
+message AutoclickEventReported {
+    // Type of Autoclick action performed.
+    optional android.accessibility.AutoclickType click_type = 1;
+}
+
+/**
+ * Logs when autoclick feature is enabled.
+ * Logged from:
+ *    frameworks/base/services/accessibility/java/com/android/server/accessibility/
+ *    AutoclickController.java
+ * Estimated Logging Rate:
+ *    Peak: 5 times in 1 min | Avg: 5 times per day per user.
+ */
+message AutoclickEnabledReported {
+    // Whether the feature was enabled or disabled.
+    optional bool enabled = 1;
+}
+
+/**
+ * Logs how long the autoclick feature is used.
+ * Logged from:
+ *    frameworks/base/services/accessibility/java/com/android/server/accessibility/
+ *    AutoclickController.java
+ * Estimated Logging Rate:
+ *    Peak: 2 times in 1 min | Avg: 2 times per day per user.
+ */
+message AutoclickSessionDurationReported {
+    // How long the feature was enabled in seconds.
+    optional int32 session_duration_seconds = 1;
+}
+
+/**
+ * Logs the state of autoclick settings.
+ * Logged from:
+ *    frameworks/base/services/accessibility/java/com/android/server/accessibility/
+ *    AutoclickController.java
+ * Estimated Logging Rate:
+ *    Peak: 10 times in 1 min | Avg: 10 times per day per user.
+ */
+message AutoclickSettingsStateReported {
+    // Delay in milliseconds before autoclick triggers.
+    optional int64 delay_before_click_ms = 1;
+
+    // The cursor area size of autoclick indicator.
+    optional int32 cursor_area_size = 2;
+
+    // Whether minor cursor movements are ignored.
+    optional bool ignore_minor_cursor_movement = 3;
+
+    // Whether autoclick reverts to left click after action.
+    optional bool revert_to_left_click = 4;
+}
diff --git a/stats/atoms/adpf/adpf_atoms.proto b/stats/atoms/adpf/adpf_atoms.proto
index 60cd4433..e8358bc4 100644
--- a/stats/atoms/adpf/adpf_atoms.proto
+++ b/stats/atoms/adpf/adpf_atoms.proto
@@ -3,33 +3,11 @@ syntax = "proto2";
 package android.os.statsd.adpf;
 
 import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/adpf/enums.proto";
 
 option java_package = "com.android.os.adpf";
 option java_multiple_files = true;
 
-enum AdpfSessionTag {
-    // This tag is used to mark uncategorized hint sessions.
-    OTHER = 0;
-    // This tag is used to mark the SurfaceFlinger hint session.
-    SURFACEFLINGER = 1;
-    // This tag is used to mark hint sessions created by HWUI.
-    HWUI = 2;
-    // This tag is used to mark hint sessions created by applications that are
-    // categorized as games.
-    GAME = 3;
-    // This tag is used to mark the hint session is created by the application.
-    // If an applications is categorized as game, then GAME should be used
-    // instead.
-    APP = 4;
-}
-
-enum FmqStatus {
-    OTHER_STATUS = 0;
-    SUPPORTED = 1;
-    UNSUPPORTED = 2;
-    HAL_VERSION_NOT_MET = 3;
-}
-
 /**
  * Logs information related to Android Dynamic Performance Framework (ADPF).
  */
@@ -48,7 +26,18 @@ message PerformanceHintSessionReported {
     optional int32 tid_count = 4;
 
     // Session tag specifying the type of the session.
-    optional AdpfSessionTag session_tag = 5;
+    optional android.os.statsd.adpf.AdpfSessionTag session_tag = 5;
+
+    // True if power efficiency mode is enabled.
+    // Power Efficiency mode tells whether the threads of a session can be
+    // safely scheduled to prefer power efficiency over performance.
+    optional bool is_power_efficient = 6;
+
+    // True if graphics pipeline mode us enabled.
+    // Graphics Pipeline mode tells whether the threads of a session are on critical path for
+    // an application's rendering loop. Depending on the device implementation, session with this
+    // mode enable should have higher resource priority.
+    optional bool is_graphics_pipeline = 7;
 }
 
 message ADPFSystemComponentInfo {
@@ -59,5 +48,5 @@ message ADPFSystemComponentInfo {
     optional bool hwui_hint_enabled = 2;
 
     // True if FMQ is supported and used on the device.
-    optional FmqStatus fmq_supported = 3;
+    optional android.os.statsd.adpf.FmqStatus fmq_supported = 3;
 }
diff --git a/stats/atoms/adpf/adpf_extension_atoms.proto b/stats/atoms/adpf/adpf_extension_atoms.proto
index ef9c27c4..1e8c7793 100644
--- a/stats/atoms/adpf/adpf_extension_atoms.proto
+++ b/stats/atoms/adpf/adpf_extension_atoms.proto
@@ -21,6 +21,7 @@ package android.os.statsd.adpf;
 import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atoms/adpf/adpf_atoms.proto";
+import "frameworks/proto_logging/stats/enums/adpf/enums.proto";
 import "frameworks/proto_logging/stats/enums/os/enums.proto";
 
 option java_package = "com.android.os.adpf";
@@ -32,36 +33,15 @@ extend Atom {
     optional ThermalHeadroomCalled thermal_headroom_called = 773 [(module) = "framework"];
     optional ThermalHeadroomThresholdsCalled thermal_headroom_thresholds_called = 774 [(module) = "framework"];
     optional AdpfHintSessionTidCleanup adpf_hint_session_tid_cleanup = 839 [(module) = "framework"];
+    optional ThermalHeadroomListenerDataReported thermal_headroom_listener_data_reported = 1051 [(module) = "framework"];
+    optional CpuHeadroomReported cpu_headroom_reported = 1052 [(module) = "framework"];
+    optional GpuHeadroomReported gpu_headroom_reported = 1053 [(module) = "framework"];
 
     // Pulled atoms
     optional ThermalHeadroomThresholds thermal_headroom_thresholds = 10201 [(module) = "framework"];
     optional AdpfSessionSnapshot adpf_session_snapshot = 10218 [(module) = "framework"];
-}
-
-enum ThermalApiStatus {
-    UNSPECIFIED_THERMAL_API_FAILURE = 0;
-    SUCCESS = 1;
-    HAL_NOT_READY = 2;
-    FEATURE_NOT_SUPPORTED = 3;
-    INVALID_ARGUMENT = 4;
-    // If the thermal HAL reports no temperature for SKIN type
-    NO_TEMPERATURE = 5;
-    // If the thermal HAL reports no matching threshold for the SKIN temperature
-    NO_TEMPERATURE_THRESHOLD = 6;
-}
-
-enum AdpfSessionUidState {
-    DEFAULT_UID_STATE = 0;
-    FOREGROUND = 1;
-    BACKGROUND = 2;
-}
-
-enum AdpfSessionState {
-    DEFAULT_SESSION_STATE = 0;
-    // This state is used to mark the session is paused.
-    PAUSE = 1;
-    // This state is used to mark the session is resumed.
-    RESUME = 2;
+    optional AdpfSupportInfo adpf_support_info = 10237 [(module) = "framework"];
+    optional ThermalHeadroomListenerInfo thermal_headroom_listener_info = 10238 [(module) = "framework"];
 }
 
 /**
@@ -73,7 +53,7 @@ message ThermalStatusCalled {
     optional int32 uid = 1 [(is_uid) = true];
 
     // API call status.
-    optional ThermalApiStatus api_status = 2;
+    optional android.os.statsd.adpf.ThermalApiStatus api_status = 2;
 
     // Thermal throttling status.
     optional android.os.ThrottlingSeverityEnum status = 3;
@@ -88,13 +68,19 @@ message ThermalHeadroomCalled {
     optional int32 uid = 1 [(is_uid) = true];
 
     // API call status.
-    optional ThermalApiStatus api_status = 2;
+    optional android.os.statsd.adpf.ThermalApiStatus api_status = 2;
 
     // Thermal headroom.
     optional float headroom = 3;
 
-    // Forcast seconds.
+    // Forecast seconds.
     optional int32 forecast_seconds = 4;
+
+    // True if the headroom is from cache.
+    optional bool is_from_cache = 5;
+
+    // True if the headroom is based on skin forecast.
+    optional bool is_hal_skin_forecast_supported = 6;
 }
 
 /**
@@ -106,7 +92,7 @@ message ThermalHeadroomThresholdsCalled {
     optional int32 uid = 1 [(is_uid) = true];
 
     // API call status.
-    optional ThermalApiStatus api_status = 2;
+    optional android.os.statsd.adpf.ThermalApiStatus api_status = 2;
 }
 
 /**
@@ -118,48 +104,273 @@ message ThermalHeadroomThresholds {
     repeated float headroom = 1;
 }
 
+/**
+ * Logs the device information w.r.t. ThermalHAL and statistical data.
+ * Logged from frameworks/base/services/core/java/com/android/server/power/ThermalManagerService.java.
+ */
+message ThermalHeadroomListenerInfo {
+    // The version of thermal HAL.
+    optional int32 thermal_hal_version = 1;
+
+    // The maximum number of listeners that can be registered.
+    optional int32 max_listener_count = 2;
+
+    // True if the device skin forecast API is supported.
+    optional bool is_hal_skin_forecast_supported = 3;
+}
+
+/**
+ * Logs the callback data broadcasting to all registered thermal headroom listeners upon triggered.
+ * Logged from frameworks/base/services/core/java/com/android/server/power/ThermalManagerService.java.
+ */
+message ThermalHeadroomListenerDataReported {
+    enum CallbackType {
+        UNKNOWN_CALLBACK_TYPE = 0;
+        TEMP_CHANGED = 1;
+        THRESHOLD_CHANGED = 2;
+        LISTENER_REGISTRATION = 3;
+    }
+
+    // Which event triggers the callback.
+    optional CallbackType callback_type = 1;
+
+    // UID that invokes the callback.
+    // If it's a device environment change, such as the threshold or the temperature change
+    // of the device, the uid is 0 (i.e. AID_ROOT). If it's a new listener registration,
+    // the uid is the app uid that registers the listener.
+    optional int32 uid = 2 [(is_uid) = true];
+
+    // The data broadcasting to all registered thermal headroom listeners.
+    // The forecast is valid for forecast_seconds, depending on HAL implementation of different
+    // devices.
+    // This depends on the temperature data HAL captures from thermal sensors. This is a binder
+    // blocking call that the actual time depends on vendor implementation.
+    optional float headroom = 3;
+    optional float forecast_headroom = 4;
+    optional int32 forecast_seconds = 5;
+    // An array of headroom thresholds representing each thermal status implemented by HAL.
+    // Each value corresponds to status of
+    // NONE, LIGHT, MODERATE, SEVERE and CRITICAL.
+    // The headroom threshold values range from [0, 1], while NaN indicates no HAL implementation.
+    repeated float headroom_thresholds = 6;
+}
+
 /**
  * Logs the ADPF TID cleanup result.
  * Logged from frameworks/base/services/core/java/com/android/server/power/hint/HintManagerService.java
  */
 message AdpfHintSessionTidCleanup {
+    // Uid of the session, this is app uid.
     optional int32 uid = 1 [(is_uid) = true];
-    // Total duration of cleaning up all sessions of the uid in microseconds
+
+    // Total duration of cleaning up all sessions of the uid in microseconds.
     optional int32 total_duration_us = 2;
-    // Max duration of cleaning up a session in microseconds
+
+    // Max duration of cleaning up a session in microseconds.
     optional int32 max_duration_us = 3;
-    // Total tid count for all sessions of the uid
+
+    // Total tid count for all sessions of the uid.
     optional int32 total_tid_count = 4;
-    // Total invalid tid count for all sessions of the uid
+
+    // Total invalid tid count for all sessions of the uid.
     optional int32 total_invalid_tid_count = 5;
-    // Max invalid tid count per session
+
+    // Max invalid tid count per session.
     optional int32 max_invalid_tid_count = 6;
-    // Count of all session under the same uid
+
+    // Count of all session under the same uid.
     optional int32 session_count = 7;
-    // If the UID is foreground when running cleanup
+
+    // If the UID is foreground when running cleanup.
     optional bool is_uid_foreground = 8;
 }
 
-/*
+/**
+ * Logs the CPU headroom info upon getCpuHeadroom() is called.
+ * Logged from frameworks/base/services/core/java/com/android/server/power/hint/HintManagerService.java
+ */
+message CpuHeadroomReported {
+    enum CpuHeadroomApiStatus {
+        UNKNOWN_STATUS = 0;
+        SUCCESS = 1;
+        INVALID_TID = 2;
+        INSUFFICIENT_USER_MODE_TIME = 3;
+        INCONSISTENT_THREAD_CORE_AFFINITY = 4;
+        HAL_ERROR = 5;
+    }
+
+    // The number of TIDs to be included in the reporting headroom.
+    optional int32 tid_size = 1;
+
+    // The calculation window (in milliseconds) of the headroom.
+    optional int32 calculation_window_millis = 2;
+
+    // The type of the headroom calculation.
+    optional android.os.statsd.adpf.HeadroomCalculationType type = 3;
+
+    // The API call status, including the error cases.
+    optional CpuHeadroomApiStatus status = 4;
+
+    // True if the headroom is from cache.
+    optional bool is_from_cache = 5;
+
+    // The headroom value in ratio,
+    // ranging from [0, 1], where 0 indicates no more cpu resources can be granted.
+    optional float value_ratio = 6;
+}
+
+/**
+ * Logs the GPU headroom info upon getGpuHeadroom() is called
+ * Logged from frameworks/base/services/core/java/com/android/server/power/hint/HintManagerService.java
+ */
+message GpuHeadroomReported {
+    enum GpuHeadroomApiStatus {
+        UNKNOWN_STATUS = 0;
+        SUCCESS = 1;
+        // Reserving 2, 3, 4 for other status to be developed in the future
+        // and to align with CpuHeadRoomApistatus.
+        HAL_ERROR = 5;
+    }
+    // The calculation window (in milliseconds) of the headroom.
+    optional int32 calculation_window_millis = 1;
+
+    // The type of the headroom calculation.
+    optional android.os.statsd.adpf.HeadroomCalculationType type = 2;
+
+    // True if the headroom is from cache.
+    optional bool is_from_cache = 3;
+
+    // The API call status, including the error cases.
+    optional GpuHeadroomApiStatus status = 4;
+
+    // The headroom value in ratio,
+    // ranging from [0, 1], where 0 indicates no more cpu resources can be granted.
+    optional float value_ratio = 5;
+}
+
+/**
  * Logs the ADPF session snapshot upon pulled.
  * Logged from frameworks/base/services/core/java/com/android/server/power/hint/HintManagerService.java
  */
 message AdpfSessionSnapshot {
-    // Uid of the session, this uid is per-app
+    // Uid of the session, this uid is per-app.
     optional int32 uid = 1 [(is_uid) = true];
 
     // Session tag of the snapshot. One uid can generate session with different tags.
     optional AdpfSessionTag session_tag = 2;
 
-    // Maximum number of sessions that concurrently existed
+    // Maximum number of sessions that concurrently existed.
     optional int32 max_concurrent_session = 3;
 
-    // Maximum number of threads created in one session
+    // Maximum number of threads created in one session.
     optional int32 max_tid_count = 4;
 
-    // Power efficiency mode status
+    // Number of power efficient session.
     optional int32 num_power_efficient_session = 5;
 
-    // list of different target durations requested
+    // List of different target durations requested.
     repeated int64 target_duration_ns = 6;
+
+    // Number of graphics pipeline session..
+    optional int32 num_graphics_pipeline_session = 7;
+}
+
+/**
+ * Logs the whole ADPF SupportInfo object.
+ * This object contains essential device information of ADPF-related settings.
+ * Logged from frameworks/base/services/core/java/com/android/server/power/hint/HintManagerService.java
+ */
+message AdpfSupportInfo {
+    // Power HAL interface version.
+    optional int32 power_hal_version = 1;
+
+    // Vendor API level as defined in ro.vendor.api_level.
+    optional int32 vendor_api_level = 2;
+
+    // Hint session support information.
+    // True if hint sessions are supported.
+    optional bool is_hint_session_supported = 3;
+
+    // Bitmask of supported boost types.
+    // The set of "Boost" enum values that are supported by this device,
+    // each bit should correspond to a value of the enum in
+    // hardware/interfaces/power/aidl/android/hardware/power/Boost.aidl
+    optional int64 boosts = 4;
+
+    // Bitmask of supported mode types.
+    // The set of "Mode" enum values that are supported by this device,
+    // each bit should correspond to a value of the enum in
+    // hardware/interfaces/power/aidl/android/hardware/power/Mode.aidl
+    optional int64 modes = 5;
+
+    // Bitmask of supported hints within sessions.
+    // The set of "SessionHint" enum values that are supported by this device,
+    // each bit should correspond to a value of the enum in
+    // hardware/interfaces/power/aidl/android/hardware/power/SessionHint.aidl
+    optional int64 session_hints = 6;
+
+    // Bitmask of supported modes within sessions.
+    // The set of "SessionMode" enum values that are supported by this device,
+    // each bit should correspond to a value of the enum in
+    // hardware/interfaces/power/aidl/android/hardware/power/SessionMode.aidl
+    optional int64 session_modes = 7;
+
+    // Bitmask of supported session tags.
+    // The set of "SessionTag" enum values that are supported by this device,
+    // each bit should correspond to a value of the enum in
+    // hardware/interfaces/power/aidl/android/hardware/power/SessionTag.aidl
+    optional int64 session_tags = 8;
+
+    // Composition data support information.
+    // Whether the sendCompositionData and sendCompositionUpdate in
+    // hardware/interfaces/power/aidl/android/hardware/power/IPower.aidl
+    // are supported on this device.
+    optional bool composition_data_is_supported = 9;
+
+    // Whether to disable sending relevant GPU fence file descriptors along with
+    // timing information when the frame callback happens.
+    optional bool composition_data_disable_gpu_fences = 10;
+
+    // The maximum number of  frame updates to batch before sending.
+    // Setting to a value less than or equal to 1 disables batching entirely.
+    optional int32 composition_data_max_batch_size = 11;
+
+    // Whether to ignore important notifications such as FPS changes and frame
+    // deadline misses, and always send maximum size batches.
+    // By default, the framework will send batches early if these important events happen.
+    optional bool composition_data_always_batch = 12;
+
+    // Headroom support information.
+    // True if CPU headroom is supported.
+    optional bool cpu_headroom_is_supported = 13;
+
+    // True if GPU headroom is supported.
+    optional bool gpu_headroom_is_supported = 14;
+
+    // Minimum polling interval (in milliseconds) for calling getCpuHeadroom in milliseconds
+    // The getCpuHeadroom API may return cached result if called more frequent
+    // than the interval.
+    optional int32 cpu_headroom_min_interval_millis = 15;
+
+    // Minimum polling interval (in milliseconds) for calling getGpuHeadroom in milliseconds
+    // The getGpuHeadroom API may return cached result if called more frequent
+    // than the interval.
+    optional int32 gpu_headroom_min_interval_millis = 16;
+
+    // Minimum time window (in milliseconds) for CPU headroom calculations.
+    // The calculation window is set by the caller of getCpuHeadroom API.
+    optional int32 cpu_headroom_min_calculation_window_millis = 17;
+
+    // Maximum time window (in milliseconds) for CPU headroom calculations.
+    optional int32 cpu_headroom_max_calculation_window_millis = 18;
+
+    // Minimum time window (in milliseconds) for GPU headroom calculations.
+    // The calculation window is set by the caller of getGpuHeadroom API.
+    optional int32 gpu_headroom_min_calculation_window_millis = 19;
+
+    // Maximum time window (in milliseconds) for GPU headroom calculations.
+    optional int32 gpu_headroom_max_calculation_window_millis = 20;
+
+    // Maximum number of TIDs to be included in CPU headroom calculations.
+    optional int32 cpu_headroom_max_tid_count = 21;
 }
diff --git a/stats/atoms/adservices/adservices_extension_atoms.proto b/stats/atoms/adservices/adservices_extension_atoms.proto
index 86b1a832..363397ec 100644
--- a/stats/atoms/adservices/adservices_extension_atoms.proto
+++ b/stats/atoms/adservices/adservices_extension_atoms.proto
@@ -243,6 +243,18 @@ extend Atom {
 
   optional AdservicesMeasurementBackgroundJobInfo adservices_measurement_background_job_info = 1046
   [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional UnifiedTableEnabledReported unified_table_enable_reported = 1058
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional ProdDebugEnabledReported prod_debug_enabled_reported = 1059
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional AdServicesMeasurementReportingOriginsPerEnrollmentCounted adservices_measurement_reporting_origins_per_enrollment_counted = 1062
+  [(module) = "adservices", (truncate_timestamp) = true];
+
+  optional AdServicesMeasurementReportingOriginsPerEnrllXDestCounted adservices_measurement_reporting_origins_per_enrll_x_dest_counted = 1063
+  [(module) = "adservices", (truncate_timestamp) = true];
 }
 
 /**
@@ -2136,6 +2148,30 @@ message UpdateSignalsProcessReported {
 
   // The minimum size of raw protected signals per buyer in bytes.
   optional float min_raw_protected_signals_size_bytes = 10;
+
+  // A list of unique evictors used for an eviction.
+  repeated android.adservices.service.SignalEvictor signal_evictors_used = 11;
+
+  // A list of unique eviction priority values present across updated signals.
+  // Integer values mapped to EvictionPriority. This is a repeated field to
+  // avoid logging the same priority multiple times.
+  repeated int32 updated_signal_eviction_priorities = 12;
+
+  // A list of unique eviction priority values present across evicted signals.
+  // Integer values mapped to EvictionPriority. This is a repeated field to
+  // avoid logging the same priority multiple times.
+  repeated int32 evicted_signal_eviction_priorities = 13;
+
+  // The bucketed size of all evicted signals.
+  optional android.adservices.service.Size per_buyer_evicted_signal_size = 14;
+
+  // The number of unique keys with eviction priority explicitly set.
+  optional int32 updated_signals_with_eviction_priority_count = 15;
+
+  // A JSON can be fetched by requesting a provided URL from the AdTech, and later be used to guide
+  // the signal updates. Per different signal eviction design, the JSON will be parsed differently
+  // relaying on schema version comes with the response.
+  optional int32 signal_update_schema_version = 16;
 }
 
 /** Logs for Topics epoch job setting during scheduling EpochJobService. */
@@ -2405,3 +2441,44 @@ message AdservicesMeasurementBackgroundJobInfo {
   // The default value is STOP_REASON_UNDEFINED.
   optional android.app.job.StopReasonEnum public_stop_reason = 6;
 }
+
+/**
+ * Used for checking if prod debug is enabled in auction server APIs.
+ * Pushed from: packages/modules/AdServices/adservices
+ */
+message ProdDebugEnabledReported {
+  optional bool is_enabled = 1;
+}
+
+/**
+ * Used for checking if unified table is used in on device auction APIs.
+ * Pushed from: packages/modules/AdServices/adservices
+ */
+message UnifiedTableEnabledReported {
+  optional bool is_unified_table_enabled = 1;
+  optional bool is_unified_dao_used = 2;
+}
+
+/**
+* Logs the number of unique reporting origins per enrollment id in the past
+* day when a source is registered.
+* Logged from:
+* packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/stats/StatsdAdServicesLogger.java
+* Estimated Logging Rate:
+*     Avg: 10x per device per day
+*/
+message AdServicesMeasurementReportingOriginsPerEnrollmentCounted {
+ optional int64 unique_reporting_origins_count = 1;
+}
+
+/**
+* Logs the number of unique reporting origins per enrollment id per
+* destination in the past day when a source is registered.
+* Logged from:
+* packages/modules/AdServices/adservices/service-core/java/com/android/adservices/service/stats/StatsdAdServicesLogger.java
+* Estimated Logging Rate:
+*     Avg: 20x per device per day
+*/
+message AdServicesMeasurementReportingOriginsPerEnrllXDestCounted {
+ optional int64 unique_reporting_origins_count = 1;
+}
diff --git a/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto b/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
index 62501466..9d53c651 100644
--- a/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
+++ b/stats/atoms/aiwallpapers/aiwallpapers_extension_atoms.proto
@@ -43,6 +43,8 @@ enum AiWallpapersBackend {
   BACKEND_ARATEA = 1;
   /* local images (for testing) backend */
   BACKEND_LOCAL = 2;
+  /* mythweaver backend */
+  BACKEND_MYTHWEAVER_SERVER = 3;
 }
 
 /**
@@ -78,6 +80,19 @@ enum AiWallpapersPrompt {
   PROMPT_SCAN = 23;
 }
 
+/**
+ * Enum corresponding to the AI model used for image generation.
+ */
+enum AiWallpapersModel {
+  /* unknown model. */
+  MODEL_UNSPECIFIED = 0;
+  /* Imagen model */
+  MODEL_IMAGEN = 1;
+  /* miro model */
+  MODEL_MIRO = 2;
+  /* Juno 3b model*/
+  MODEL_JUNO3B = 3;
+}
 
 /**
  * A record of the fact that a specific button was pressed.
@@ -86,9 +101,14 @@ enum AiWallpapersPrompt {
  *     platform/vendor/unbundled_google/packages/WallpaperEffect/master/AiWallpapers/src/com/google/android/apps/aiwallpapers/utils/
  */
 message AiWallpapersButtonPressed {
+  /* the UI button clicked */
   optional AiWallpapersButton button = 1;
   /* the backend (image generation system) */
   optional AiWallpapersBackend backend = 2;
+  /* the prompt template selected */
+  optional AiWallpapersPrompt prompt = 3;
+  /* the model prompt used */
+  optional AiWallpapersModel model = 4;
 }
 
 /**
diff --git a/stats/atoms/appsearch/appsearch_extension_atoms.proto b/stats/atoms/appsearch/appsearch_extension_atoms.proto
index f3d11c92..2272bf8d 100644
--- a/stats/atoms/appsearch/appsearch_extension_atoms.proto
+++ b/stats/atoms/appsearch/appsearch_extension_atoms.proto
@@ -41,6 +41,9 @@ extend Atom {
   optional AppSearchAppsIndexerStatsReported
           app_search_apps_indexer_stats_reported = 909 [(module) = "appsearch"];
 
+  optional AppSearchAppOpenEventIndexerStatsReported
+          app_search_app_open_event_indexer_stats_reported = 1050 [(module) = "appsearch"];
+
   optional AppSearchVmPayloadStatsReported
           app_search_vm_payload_stats_reported = 1047 [(module) = "appsearch"];
 }
@@ -341,6 +344,35 @@ message AppSearchAppsIndexerStatsReported {
   optional int64 remove_functions_from_appsearch_appsearch_latency_millis = 18;
 }
 
+/**
+ * Reported when AppSearch App Open Event Indexer syncs apps from UsageStatsManager to AppSearch.
+ *
+ * Logged from:
+ *   packages/modules/AppSearch/service/java/com/android/server/appsearch/appsindexer/AppOpenEventIndexerUserInstance.java
+ * Estimated Logging Rate: once per device per day
+ *
+ * Next tag: 9
+ */
+message AppSearchAppOpenEventIndexerStatsReported {
+
+  // Status codes for inserting/updating apps. If everything succeeds, this only contains [0]. If
+  // something fails, this contains all the error codes we got.
+  repeated int32 update_status_codes = 1;
+
+  // Update counts
+  optional int32 number_of_app_open_events_added = 2;
+
+  // Latencies
+  optional int64 total_latency_millis = 3;
+  optional int64 usage_stats_manager_read_latency_millis = 4;
+  optional int64 appsearch_set_schema_latency_millis = 5;
+  optional int64 appsearch_put_latency_millis = 6;
+
+  // Timestamps
+  optional int64 update_start_wallclock_timestamp_millis = 7;
+  optional int64 last_app_update_wallclock_timestamp_millis = 8;
+}
+
 /**
  * Reported when AppSearch VM payload statistics are collected and reported.
  *
diff --git a/stats/atoms/art/art_extension_atoms.proto b/stats/atoms/art/art_extension_atoms.proto
index 0e8d3586..4fe7ad03 100644
--- a/stats/atoms/art/art_extension_atoms.proto
+++ b/stats/atoms/art/art_extension_atoms.proto
@@ -60,7 +60,7 @@ message ArtDatumReported {
     optional ArtGcCollectorType gc = 12;
 
     // The support for userfaultfd and minor fault mode.
-    optional ArtUffdSupport uffd_support = 13;
+    optional ArtUffdSupport uffd_support = 13 [deprecated = true];
 }
 
 // ArtDatumDeltaReported is the same as ArtDatumReported, except for the kind field
@@ -103,7 +103,7 @@ message ArtDatumDeltaReported {
     optional ArtGcCollectorType gc = 12;
 
     // The support for userfaultfd and minor fault mode.
-    optional ArtUffdSupport uffd_support = 13;
+    optional ArtUffdSupport uffd_support = 13 [deprecated = true];
 }
 
 message ArtDex2OatReported {
diff --git a/stats/atoms/audioproxy/audioproxy_extension_atoms.proto b/stats/atoms/audioproxy/audioproxy_extension_atoms.proto
new file mode 100644
index 00000000..6c2d0816
--- /dev/null
+++ b/stats/atoms/audioproxy/audioproxy_extension_atoms.proto
@@ -0,0 +1,217 @@
+syntax = "proto2";
+
+package android.os.statsd.audioproxy;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.audioproxy";
+option java_multiple_files = true;
+
+extend Atom {
+  optional AudioProxyConnectionStateChanged
+      audio_proxy_connection_state_changed = 1083 [(module) = "audioproxy"];
+  optional AudioProxyMultichannelGroupJoined
+      audio_proxy_multichannel_group_joined = 1106 [(module) = "audioproxy"];
+  optional AudioProxyMultichannelGroupDisbanded
+      audio_proxy_multichannel_group_disbanded = 1107 [(module) = "audioproxy"];
+  optional AudioProxyMultichannelConnectionErrorReported
+      audio_proxy_multichannel_connection_error_reported = 1108
+      [(module) = "audioproxy"];
+  optional AudioProxyCloudSettingsRpcRequested
+      audio_proxy_cloud_settings_rpc_requested = 1109 [(module) = "audioproxy"];
+  optional AudioProxySpatialAudioConfigUpdated
+      audio_proxy_spatial_audio_config_updated = 1110 [(module) = "audioproxy"];
+  optional AudioProxySetUpReported audio_proxy_set_up_reported = 1111
+      [(module) = "audioproxy"];
+}
+
+// The source that trigger the target events.
+enum AudioProxyEventSource {
+  UI_SOURCE_UNKNOWN = 0;
+  UI_SOURCE_SYSTEM_MENU = 1;
+  UI_SOURCE_FULLSCREEN = 2;
+  UI_SOURCE_GHA = 3;
+}
+
+/**
+ * Logs connection state changes between AudioProxy and speakers.
+ * Triggered every time a speaker group is connected or disconnected, and when
+ * the Bellflower audio output is enabled or disabled.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/control
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 1-2 per device per day
+ */
+message AudioProxyConnectionStateChanged {
+  // The connection state between ATVs and speakers.
+  enum AudioProxyConnectionState {
+    CONNECTION_STATE_UNKNOWN = 0;
+    CONNECTION_STATE_DISCONNECTED = 1;
+    CONNECTION_STATE_CONNECTED = 2;
+    CONNECTION_STATE_STREAMING = 3;
+  }
+
+  optional AudioProxyConnectionState state = 1;
+
+  // # of speakers in the group. Expecting 1 or 2.
+  optional int32 number_of_speaker = 2;
+
+  // Whether this speaker group connection is triggered by a first-time
+  // Bellflower set-up. If setting to true, expecting |state| to be
+  // CONNECTION_STATE_CONNECTED.
+  optional bool is_first_time_set_up = 3;
+
+  // The event source of the group config updates.
+  optional AudioProxyEventSource source = 4;
+}
+
+/**
+ * Record when ATV joins a multichannel group.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/eureka
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 1-2 per device per day
+ */
+message AudioProxyMultichannelGroupJoined {
+}
+
+/**
+ * Logs stats when the multichannel group the ATV belongs to is disbanded.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/eureka
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 1-2 per device per day
+ */
+message AudioProxyMultichannelGroupDisbanded {
+  // From which source did the disband requests come from.
+  enum AudioProxyDisbandFrom {
+    DISBAND_FROM_UNKNOWN = 0;
+    DISBAND_FROM_USER = 1;
+    DISBAND_FROM_OTHER_DEVICE = 2;
+    DISBAND_FROM_AUDIO_DISBAND = 3;
+    DISBAND_FROM_AUTO = 4;
+    DISBAND_FROM_FDR = 5;
+  }
+
+  // The source of disband requests.
+  optional AudioProxyDisbandFrom disband_from = 1;
+}
+
+/**
+ * Logs stats when a connection error occurs in multichannel group.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/eureka
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~10 times in 1 min | Avg: 0 per device per day
+ */
+message AudioProxyMultichannelConnectionErrorReported {
+  // Whether the connection error is caused by heartbeat timeout.
+  optional bool is_heartbeat_timeout = 1;
+
+  // The flag of the connection error. Expecting zero if |is_hearbeat_timeout|
+  // is true.
+  optional int64 error_flag = 2;
+}
+
+/**
+ * Log stats when a cloud settings RPC is made by AudioProxy_Control.apk.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/control
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 3-5 per device per day
+ */
+message AudioProxyCloudSettingsRpcRequested {
+  // The type of RPC being requested.
+  enum AudioProxyCloudSettingsRpcType {
+    RPC_TYPE_UNKNOWN = 0;
+    RPC_TYPE_GET = 1;
+    RPC_TYPE_UPDATE = 2;
+  }
+
+  // The failure reasons of the RPC call.
+  enum AudioProxyCloudSettingsRpcFailureReason {
+    RPC_FAILURE_REASON_UNKNOWN = 0;
+
+    // The format of the RPC response is incorrect (e.g. having more than one
+    // response entries, missing trait entries, etc.).
+    RPC_FAILURE_REASON_INVALID_RESPONSE = 1;
+
+    // The cloud device ID in the response mismatch with the current device.
+    RPC_FAILURE_REASON_CLOUD_DEVICE_ID_MISMATCH = 2;
+
+    // The trait label in the response mismatch with the request.
+    RPC_FAILURE_REASON_TRAIT_LABEL_MISMATCH = 3;
+
+    // The response itself looks good, but the status code is not OK.
+    RPC_FAILURE_REASON_BAD_TRAIT_RESPONSE = 4;
+
+    // An error occurs when building the RPC request.
+    RPC_FAILURE_REASON_BUILD_REQUEST_ERROR = 5;
+  }
+
+  // The type of RPC being requested.
+  optional AudioProxyCloudSettingsRpcType type = 1;
+
+  // Whether the RPC call succeed without errors.
+  optional bool succeed = 2;
+
+  // The failure reason if the RPC call failed. Expecting zero if |succeed| is
+  // true.
+  optional AudioProxyCloudSettingsRpcFailureReason failure_reason = 3;
+}
+
+/**
+ * Logs stats when ATV receives spatial audio config updates.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/control
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 1-2 per device per day
+ */
+message AudioProxySpatialAudioConfigUpdated {
+  // Whether spatial audio is enabled.
+  optional bool enabled = 1;
+
+  // The distance (cm) of the two speakers. Only meaningful if |enabled| is
+  // true.
+  optional int32 speaker_distance_cm = 2;
+
+  // The distance (cm) between the listener and the middle point of the two
+  // speakers. Only meaningful if |enabled| is true.
+  optional int32 listener_distance_cm = 3;
+}
+
+/**
+ * Logs stats when user set up AudioProxy.
+ *
+ * Logged from:
+ *   vendor/google/services/AudioProxy/control
+ *
+ * Estimated Logging Rate:
+ *   Peak: ~30 times in 1 min | Avg: 1-2 per device per day
+ */
+message AudioProxySetUpReported {
+  // The UI used to set up AudioProxy.
+  optional AudioProxyEventSource source = 1;
+
+  // The total time spent on setting up AudioProxy.
+  optional int64 duration_total = 2;
+
+  // The time spent on device discovery.
+  optional int64 duration_device_discovery = 3;
+
+  // The time spent on device connection.
+  optional int64 duration_device_connection = 4;
+}
diff --git a/stats/atoms/battery/battery_extension_atoms.proto b/stats/atoms/battery/battery_extension_atoms.proto
new file mode 100644
index 00000000..3a77ae26
--- /dev/null
+++ b/stats/atoms/battery/battery_extension_atoms.proto
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
+package android.os.statsd.battery;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+// This file contains all battery related atoms.
+
+extend Atom {
+    optional RawBatteryGaugeStatsReported raw_battery_gauge_stats_reported = 1085 [(module) = "battery"];
+}
+/**
+ * Logged from:
+ * google3/java/com/google/android/wearable/pixel/pdms/features/stateofcharge/SocController.kt
+ * Estimated Logging Rate:
+ * Peak: 1 time per 10 ms | Avg: 1 time per 2 minutes, 720 per device per day
+ * Repeated fields will be capped at 120 elements
+*/
+
+message RawBatteryGaugeStatsReported {
+  // last sampled system clock time in batch
+  repeated int64 system_clock_time_nanos = 1;
+  // Voltage (V)
+  repeated float voltage_volts = 2;
+  // Current (mA)
+  repeated float current_milliamps = 3;
+  }
diff --git a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
index 3684a452..08b9964b 100644
--- a/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
+++ b/stats/atoms/bluetooth/bluetooth_extension_atoms.proto
@@ -76,6 +76,13 @@ extend Atom {
         = 988 [(module) = "bluetooth"];
     optional HearingDeviceActiveEventReported hearing_device_active_event_reported
         = 1021 [(module) = "bluetooth"];
+    optional ChannelSoundingTypesSupported channel_sounding_types_supported
+        = 1070 [(module) = "bluetooth"];
+    optional ChannelSoundingRequesterSessionReported channel_sounding_requester_session_reported
+        = 1084 [(module) = "bluetooth"];
+    optional BluetoothPbapClientContactDownloadReported bluetooth_pbap_client_contact_download_reported
+        = 1104 [(module) = "bluetooth"];
+
 }
 
 /**
@@ -709,8 +716,14 @@ message HearingDeviceActiveEventReported {
   enum DeviceType {
     UNKNOWN_TYPE = 0;
     CLASSIC = 1;
-    ASHA = 2;
-    LE_AUDIO = 3;
+    // Deprecated, use ASHA_ONLY or ASHA_DUAL instead.
+    ASHA = 2 [deprecated = true];
+    // Deprecated, use LE_AUDIO_ONLY or LE_AUDIO_DUAL instead.
+    LE_AUDIO = 3 [deprecated = true];
+    ASHA_ONLY = 4;
+    LE_AUDIO_ONLY = 5;
+    ASHA_DUAL = 6;
+    LE_AUDIO_DUAL = 7;
   }
   enum TimePeriod {
     UNKNOWN_TIME_PERIOD = 0;
@@ -725,3 +738,108 @@ message HearingDeviceActiveEventReported {
   // Remote Device Information
   optional BluetoothRemoteDeviceInformation remote_device_information = 3 [(log_mode) = MODE_BYTES];
 }
+
+/**
+ * Logs the Channel Sounding types Supported by the device.
+ *
+ * Logged from:
+ *     packages/modules/Bluetooth
+ *
+ * Estimated Logging Rate:
+ *     Peak: 1 time in 1 day | Avg: 1 per device per day
+ */
+message ChannelSoundingTypesSupported {
+  // The channel sounding types
+  repeated android.bluetooth.ChannelSoundingType cs_types = 1;
+}
+
+/**
+ * Logs the Channel Sounding measurement session as requester
+ *
+ * Logged from:
+ *     packages/modules/Bluetooth
+ *
+ * Estimated Logging Rate:
+ *     Peak: 100 times in 1 day | Avg: 1 per device per day
+ */
+message ChannelSoundingRequesterSessionReported {
+  // Locally generated id for event matching
+  optional int32 metric_id = 1;
+
+  // Uids of the apps which request the measurement
+  repeated int32 app_uids = 2 [(is_uid) = true];
+
+  // Channel Sounding security levels requested by different apps
+  repeated android.bluetooth.ChannelSoundingSecurityLevel security_levels = 3;
+
+  // Intervals requested by different apps
+  repeated int32 measurement_interval_ms = 4;
+
+  // The reason about why the session is stopped
+  optional android.bluetooth.ChannelSoundingStopReason stop_reason = 5;
+
+  // The channel sounding setup latency
+  optional int32 setup_latency_ms = 6;
+
+  // The duration of measurement session from start to stop
+  optional int32 duration_seconds = 7;
+
+  // If the back to back was detected, the device is used as both requester and responder
+  optional bool back_to_back = 8;
+
+  // The channel sounding type used for this session
+  optional android.bluetooth.ChannelSoundingType cs_type = 9;
+
+  // The minimum number of subevent_len from the procedure_enable_complete command
+  optional int32 min_subevent_len = 10;
+
+  // The count of min_subevent_len, use to estimate the duration of min_subevent_len
+  optional int32 min_subevent_len_count = 11;
+}
+
+/**
+ * Logs BluetoothPbapClient contact downloads.
+ *
+ * Logged from:
+ *     packages/modules/Bluetooth
+ *
+ * Estimated Logging Rate:
+ *     Peak: 100 times in 1 day | Avg: 10 per device per day
+ *     Once per Bluetooth connection.
+ */
+message BluetoothPbapClientContactDownloadReported {
+  // Connecting device information (phone model)
+  optional int32 metrics_id = 1;
+  // BluetoothPbapClient download status
+  optional android.bluetooth.BluetoothPbapClientContactDownloadStatus
+      download_status = 2;
+  // Phonebooks downloaded
+  optional PhonebookDownloads phonebook_downloads = 3
+      [ (log_mode) = MODE_BYTES ];
+}
+
+message PhonebookDownloads {
+  // Phonebooks downloaded
+  repeated PhonebookDownload phonebook_download = 1;
+}
+
+/**
+ * BluetoothPbapClient Phonebook download information.
+ */
+message PhonebookDownload {
+  // Phonebook type
+  optional android.bluetooth.BluetoothPbapClientPhonebookType phonebook_type = 1;
+  // Phonebook download status
+  optional android.bluetooth.BluetoothPbapClientPhonebookDownloadStatus status =
+      2;
+  // Actual number of contacts downloaded
+  optional uint64 actual_contacts = 3;
+  // Expected number of contacts downloaded
+  optional uint64 expected_contacts = 4;
+  // Total time spent downloading contacts
+  optional uint64 total_duration_millis = 5;
+  // Fraction of time spent storing contacts
+  optional uint64 storage_duration_millis = 6;
+  // Number of contacts images
+  optional uint64 contacts_with_images = 7;
+}
diff --git a/stats/atoms/coregraphics/coregraphics_extension_atoms.proto b/stats/atoms/coregraphics/coregraphics_extension_atoms.proto
index 7abc9b0b..68832a6c 100644
--- a/stats/atoms/coregraphics/coregraphics_extension_atoms.proto
+++ b/stats/atoms/coregraphics/coregraphics_extension_atoms.proto
@@ -111,6 +111,10 @@ message SurfaceControlEvent {
     optional int64 time_since_last_event_millis = 2;
     // The previous dataspace of the SurfaceControl's content
     optional int32 previous_dataspace = 3;
+    // Whether lut(s) is applied
+    optional bool previous_use_luts = 4;
+    // The previous requested headroom of the SurfaceControl's content
+    optional float previous_desired_hdr_headroom = 5;
 }
 
 /**
diff --git a/stats/atoms/corenetworking/connectivity/critical_event_extension_atoms.proto b/stats/atoms/corenetworking/connectivity/critical_event_extension_atoms.proto
new file mode 100644
index 00000000..7d438db0
--- /dev/null
+++ b/stats/atoms/corenetworking/connectivity/critical_event_extension_atoms.proto
@@ -0,0 +1,55 @@
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
+package android.os.statsd.corenetworking.connectivity;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/attribution_node.proto";
+import "frameworks/proto_logging/stats/enums/corenetworking/connectivity/enums.proto";
+
+option java_package = "com.android.os.corenetworking.connectivity";
+option java_multiple_files = true;
+
+extend Atom {
+    optional CoreNetworkingCriticalBytesEventOccurred core_networking_critical_bytes_event_occurred =
+        1102 [(module) = "connectivity", (module) = "network_stack",
+            (module) = "resolv", (module) = "network_tethering"];
+}
+
+/**
+ * This message is similar to CoreNetworkingTerribleErrorOccurred. It is used to record
+ * critical bytes events that happen in our core networking codebase. Unlike
+ * CoreNetworkingTerribleErrorOccurred, which only tracks the error type,
+ * this message records the critical event's occurrence and its value.
+ *
+ * Logged from:
+ * packages/modules/Connectivity/
+ * packages/modules/NetworkStack/
+ * packages/modules/DnsResolver/
+ *
+ * Estimated Logging Rate:
+ * Peak: 10 times in 60 mins | Avg: < 5 per device per day
+ */
+message CoreNetworkingCriticalBytesEventOccurred {
+    repeated AttributionNode attribution_node = 1;
+    // Type of critical event.
+    optional android.corenetworking.connectivity.CriticalBytesEventType event_type = 2;
+    // Value associated with the event
+    optional int64 bytes_count = 3;
+}
diff --git a/stats/atoms/corenetworking/platform/vpn_extension_atoms.proto b/stats/atoms/corenetworking/platform/vpn_extension_atoms.proto
index ebc09787..b767f4cf 100644
--- a/stats/atoms/corenetworking/platform/vpn_extension_atoms.proto
+++ b/stats/atoms/corenetworking/platform/vpn_extension_atoms.proto
@@ -26,30 +26,10 @@ import "frameworks/proto_logging/stats/atom_field_options.proto";
 import "frameworks/proto_logging/stats/enums/corenetworking/platform/enums.proto";
 
 extend Atom {
-    // pushed atom
-    optional VpnConnectionStateChanged vpn_connection_state_changed = 850
-        [(module) = "framework"];
-
     // pushed atom
     optional VpnConnectionReported vpn_connection_reported = 851 [(module) = "framework"];
 }
 
-/**
- * Log VPN connection events to develop metrics analyzing the effect of VPN usage on device
- * performance and battery life.
- *
- * Logs from: services/core/java/com/android/server/connectivity/Vpn.java.
- *
- */
-message VpnConnectionStateChanged {
-
-  // The VPN connection state(connected/disconnected)
-  optional android.corenetworking.platform.ConnectionState connection_state = 1 [
-        (state_field_option).exclusive_state = true,
-        (state_field_option).nested = false
-    ];
-}
-
 
 /**
  * Logs the VPN connection stats for analysis performance of VPN
@@ -68,138 +48,21 @@ message VpnConnectionReported {
   // The IP protocol of the VPN server(IPv4/IPv6/IPv4v6)
   optional android.corenetworking.platform.IpType server_ip_protocol = 3;
 
-  // UDP Encapsulation/ESP
-  optional android.corenetworking.platform.EncapType encap_type = 4;
-
-  // Is the VPN a bypassable VPN
-  optional bool bypassability = 5;
-
-  // Is the VPN opt-in to do network validation
-  optional bool validation_required = 6;
-
-  optional android.corenetworking.platform.VpnProfileType vpn_profile_type = 7;
+  optional android.corenetworking.platform.VpnProfileType vpn_profile_type = 4;
 
   // Bitmasked value for allowed algorithms
-  optional int32 allowed_alogithms = 8;
+  optional int32 allowed_algorithms = 5;
 
   // The MTU configuration of the VPN network
-  optional int32 mtu = 9;
-
-  // True if the local networks will be excluded from VPN. This
-  // should only work with bypassable VPNs.
-  optional bool local_route_excluded = 10;
-
-  // Is the VPN a metered VPN
-  optional bool metered = 11;
-
-  // Is the VPN configured with a proxy
-  optional bool proxy_setup = 12;
-
-  // Is the VPN connection a always-on VPN
-  optional bool always_on_vpn = 13;
-
-  // Is the VPN connection a lockdown VPN
-  optional bool lockdown_vpn = 14;
-
-  // The dnses for a VPN network can either come from network side
-  // or use user pre-configured dnses. True if the VPN uses user
-  // preconfigured dnses, false otherwise.
-  optional bool preconfigured_dns = 15;
-
-  // The route for a VPN network can either come from network side
-  // or use user pre-configured routes. True if the VPN uses user
-  // preconfigured routes, false otherwise.
-  optional bool preconfigured_routes = 16;
-
-  // Is the NAT keepalive controllled by the system to send the
-  // keepalive dynamically
-  optional int32 is_auto_keepalive = 17;
-
-  // The duration of connected period in seconds
-  optional int32 connected_period_seconds = 18;
+  optional int32 mtu = 6;
 
   // The list of underlying network type during the VPN connection
-  repeated int32 underlying_network_type = 19;
-
-  // The duration of VPN validated period in seconds
-  optional int32 vpn_validated_period_seconds = 20;
-
-  // Count of the validation attempts
-  optional int32 validation_attempts = 21;
-
-  // Count of the successful validation attempts
-  optional int32 validation_attempts_success = 22;
-
-  // The list of session lost reason during the VPN connection
-  // 0 for success, or other errors for session lost reason
-  repeated android.corenetworking.platform.ErrorCode error_code = 23;
-
-  // The all attempt recovery informations in the VPN connection
-  optional RecoveryInfoPerAttempt recovery_info_per_attempt = 24[(log_mode) = MODE_BYTES];
-
-  // The recovery latency is approxymiate to un-validated period
-  optional int32 recovery_latency = 25;
+  repeated int32 underlying_network_type = 7;
 
-  // Control plane health
-  // The list of each ike attempt informations during the VPN connection
-  optional IkeAttempts ike_attempts = 26[(log_mode) = MODE_BYTES];
+  // The VPN connection state (connected/disconnected)
+  optional bool connected = 8;
 
-  // The list of each network switch info during the VPN connection
-  optional SwitchAttempts switch_attempts = 27[(log_mode) = MODE_BYTES];
-}
-
-/**
- * Log one ike attempt event informations
- */
-message IkeAttemptEvent {
-  // Result of the ike attempt
-  optional bool success = 1;
-
-  // The latency of ike attempt in milliseconds
-  optional int32 latency_milliseconds = 2;
-}
-
-/**
- * Log all ike attempt informations during the VPN connection
- */
-message IkeAttempts {
-   repeated IkeAttemptEvent ike_attempt_event = 1;
-}
-
-/**
- * Log one network switch attempt event informations
- */
-message SwitchAttemptEvent {
-  // Result of the network switch attempt
-  optional bool success = 1;
-
-  // The latency of the network switch attempt in milliseconds
-  optional int32 latency_milliseconds = 2;
-}
-
-/**
- * Log all network switch attempt informations during the VPN connection
- */
-message SwitchAttempts {
-  repeated SwitchAttemptEvent switch_attempt_event = 1;
-}
-
-/**
- * Log the recovery info for the attempt
- */
-message RecoveryInfoForAttempt {
-  // Type of recover action for the attempt
-  optional android.corenetworking.platform.RecoverAction type = 1;
-
-  // Recovery count
-  optional int32 count = 2;
-}
-
-
-/**
- * Log all attempted recovery informations on the VPN connection
- */
-message RecoveryInfoPerAttempt {
-  // The list of recovery info per each attempt in the connection
-  repeated RecoveryInfoForAttempt recovery_info_for_attempt = 1;
+  // The android user id (0, 10, etc.) for the VPN. Different users can configure separate VPN
+  // connections.
+  optional int32 user_id = 9;
 }
diff --git a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
index 94c5c179..2d3f6fd6 100644
--- a/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
+++ b/stats/atoms/desktopmode/desktopmode_extensions_atoms.proto
@@ -211,6 +211,7 @@ message DesktopModeTaskSizeUpdated {
     TOUCHPAD_INPUT_METHOD = 4;
     // Only tiling and maximizing window actions have keyboard shortcuts
     KEYBOARD_INPUT_METHOD = 5;
+    ACCESSIBILITY_INPUT_METHOD = 6;
   }
 
   // How this task was resized
diff --git a/stats/atoms/devicelock/devicelock_extension_atoms.proto b/stats/atoms/devicelock/devicelock_extension_atoms.proto
index 0542b188..14ed3491 100644
--- a/stats/atoms/devicelock/devicelock_extension_atoms.proto
+++ b/stats/atoms/devicelock/devicelock_extension_atoms.proto
@@ -37,6 +37,16 @@ extend Atom {
           [(module) = "devicelock"];
   optional LockUnlockDeviceFailureReported device_lock_lock_unlock_device_failure_reported = 791
           [(module) = "devicelock"];
+  optional DeviceLockKioskAppInstallationFailed device_lock_kiosk_app_installation_failed = 1087
+          [(module) = "devicelock"];
+  optional DeviceLockFcmMessageReceived device_lock_fcm_message_received = 1091
+          [(module) = "devicelock"];
+  optional DeviceLockProvisionStateEvent device_lock_provision_state_event = 1093
+          [(module) = "devicelock"];
+  optional DeviceLockDeviceStateEvent device_lock_device_state_event = 1094
+          [(module) = "devicelock"];
+  optional DeviceLockPotentialBypassSnapshot device_lock_potential_bypass_snapshot = 10244
+          [(module) = "devicelock"];
 }
 
 message DeviceLockCheckInRequestReported {
@@ -117,3 +127,77 @@ message LockUnlockDeviceFailureReported {
   optional bool is_lock = 1;
   optional DeviceState state_post_command = 2;
 }
+
+message DeviceLockKioskAppInstallationFailed {
+  // The version of the devicelock apex package on the device.
+  optional int64 apex_version = 1;
+}
+
+/*
+ * The DeviceLockController received an FCM message from the server.
+ * Logged from: vendor/google/modules/DeviceLockGoogle/DeviceLockControllerGoogle/src/com/android/devicelockcontroller/services/DeviceLockFirebaseMessagingService.java
+ * Estimated Logging Rate:
+ * Peak: 1 time in 4 weeks | Avg: 1 per device in 4 weeks
+ */
+message DeviceLockFcmMessageReceived {
+  // The version of the devicelock apex package on the device.
+  optional int64 apex_version = 1;
+}
+
+/*
+ * Pulled atom that is logged when the device is found to be in a Locked state but lock task mode is not active.
+ * Logged from: packages/modules/DeviceLock/service/java/com/android/server/devicelock/DeviceLockService.java
+ * Estimated Logging Rate:
+ * Only expected to log in a bypass scenario in which case it will be 1 time per day
+ */
+message DeviceLockPotentialBypassSnapshot {
+  // The version of the devicelock apex package on the device.
+  optional int64 apex_version = 1;
+}
+
+ /* Events pertaining to provision state.
+ * Logged from:
+ *      (mostly) packages/modules/DeviceLock/DeviceLockController/src/com/android/devicelockcontroller/provision/
+ * Expected logging rate:
+ *      Peak: 1 time in 3 minutes | Avg: 1 per device per day
+ */
+message DeviceLockProvisionStateEvent {
+  enum Event {
+    EVENT_UNKNOWN = 0;
+    // The client was unable to perform a check-in request.
+    EVENT_UNSUCCESSFUL_CHECKIN_REQUEST = 1;
+    // The kiosk app has successfully changed the device state after provisioning.
+    EVENT_SUCCESSFUL_PROVISIONING = 2;
+    // The device has been reset due to a provisioning failure.
+    EVENT_DEVICE_RESET = 3;
+    // The kiosk app cleared all restrictions and the device was finalized.
+    EVENT_FINALIZATION = 4;
+    // The kiosk app attempted to clear all restrictions but it did not end in a successful finalization.
+    EVENT_FINALIZATION_FAILURE = 5;
+  }
+
+  optional Event event = 1;
+  // The version of the apex package on the device.
+  optional int64 apex_version = 2;
+}
+
+/*
+ * Events pertaining to device state.
+ * Logged from:
+ *      packages/modules/DeviceLock/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
+ * Expected logging rate:
+ *      Peak: 1 time per day | Avg: 1 per device per week
+ */
+message DeviceLockDeviceStateEvent {
+  enum Event {
+    EVENT_UNKNOWN = 0;
+    // The kiosk app successfully locked the device.
+    EVENT_LOCK = 1;
+    // The kiosk app successfully unlocked the device.
+    EVENT_UNLOCK = 2;
+  }
+
+  optional Event event = 1;
+  // The version of the apex package on the device.
+  optional int64 apex_version = 2;
+}
diff --git a/stats/atoms/framework/framework_extension_atoms.proto b/stats/atoms/framework/framework_extension_atoms.proto
index 9e45981a..19f23d89 100644
--- a/stats/atoms/framework/framework_extension_atoms.proto
+++ b/stats/atoms/framework/framework_extension_atoms.proto
@@ -69,14 +69,21 @@ extend Atom {
     optional DeviceStateAutoRotateSettingIssueReported device_state_auto_rotate_setting_issue_reported = 1011 [(module) = "framework"];
     optional ProcessTextActionLaunchedReported process_text_action_launched_reported = 1016 [(module) = "framework"];
     optional IntentRedirectBlocked intent_redirect_blocked = 1037 [(module) = "framework"];
-    optional AndroidGraphicsBitmapAllocated android_graphics_bitmap_allocated =
-            1039 [(module) = "framework"];
     optional WidgetMemoryStats widget_memory_stats = 10234 [(module) = "framework"];
     optional AdvancedProtectionStateChanged advanced_protection_state_changed = 1040 [(module) = "framework"];
     optional AdvancedProtectionSupportDialogDisplayed advanced_protection_support_dialog_displayed = 1041 [(module) = "framework"];
     optional ExtraIntentKeysCollectedOnServer extra_intent_keys_collected_on_server = 1042 [(module) = "framework"];
     optional ClipboardGetEventReported clipboard_get_event_reported = 1048 [(module) = "framework"];
     optional AdvancedProtectionStateInfo advanced_protection_state_info = 10236 [(module) = "framework"];
+    optional AdvancedProtectionUsbStateChangeErrorReported advanced_protection_usb_state_change_error_reported = 1054 [(module) = "framework"];
+    optional BinderSpamReported binder_spam_reported = 1064 [(module) = "framework"];
+    optional DevicePresenceChanged device_presence_changed = 1080 [(module) = "framework"];
+    optional ImplicitUriGrantEventReported implicit_uri_grant_event_reported = 1088 [(module) = "framework"];
+    optional AppRestartOccurred app_restart_occurred = 1089 [(module) = "framework"];
+    optional BinderCallsReported binder_calls_reported = 1090 [(module) = "framework"];
+    optional SqliteAppOpEventReported sqlite_app_op_event_reported = 1098 [(module) = "framework"];
+    optional PermissionOneTimeSessionEventReported permission_one_time_session_event_reported = 1100 [(module) = "framework"];
+    optional AggregatedAppOpAccessEventReported aggregated_app_op_access_event_reported = 1103 [(module) = "framework"];
 }
 
 /**
@@ -124,6 +131,8 @@ message BalAllowed {
         BAL_ALLOW_NON_APP_VISIBLE_WINDOW = 11;
         BAL_ALLOW_TOKEN = 12;
         BAL_ALLOW_BOUND_BY_FOREGROUND = 13;
+        BAL_ALLOW_NOTIFICATION_TOKEN = 14;
+        BAL_ALLOW_WALLPAPER = 15;
         BAL_BLOCKED = 127; // largest int32 serializable as 1 byte
     }
 
@@ -488,6 +497,8 @@ message MediaProjectionTargetChanged {
     TARGET_TYPE_DISPLAY = 1;
     // Capturing one task of an app.
     TARGET_TYPE_APP_TASK = 2;
+    // Capturing via an overlay.
+    TARGET_TYPE_OVERLAY = 3;
   }
 
   // Windowing mode of the captured task, if the user chose to capture
@@ -814,6 +825,15 @@ message PostGCMemorySnapshot {
 
     // Memory sizes in bytes of nonmalloced native allocations registered
     repeated int64  native_allocation_nonmalloced_bytes = 13;
+
+    // java.lang.Runtime.freeMemory() bytes.
+    optional int64 java_free_memory_bytes = 14;
+
+    // java.lang.Runtime.totalMemory() bytes.
+    optional int64 java_total_memory_bytes = 15;
+
+    // java.lang.Runtime.maxMemory() bytes.
+    optional int64 java_max_memory_bytes = 16;
 }
 
 /**
@@ -843,20 +863,6 @@ message DeviceIdleTempAllowlistUpdated {
     optional int32 calling_uid = 7 [(is_uid) = true];
 }
 
-/**
- * Records Bitmap allocations.
- *
- * Logged via Hummingbird for probes at android.graphics.Bitmap constructor.
- *
- * Estimated Logging Rate:
- *   Peak: 100 times in a minute | Avg: O(hundreds) per device per day
- */
-message AndroidGraphicsBitmapAllocated {
-    optional int32 uid = 1 [(is_uid) = true];
-    optional int32 width = 2;
-    optional int32 height = 3;
-}
-
 /**
  * [Pushed Atom] Logs when an AppOp is accessed through noteOp, startOp, finishOp and that access
  * history can be stored in the AppOp discrete access data store.
@@ -960,6 +966,35 @@ message SqliteDiscreteOpEventReported {
   optional int64 storage_bytes = 3 ;
 }
 
+/**
+ * [Pushed Atom] Log AppOps performance results for (unified schema) sqlite implementation.
+ *
+ * Logged from: frameworks/base/services/core/java/com/android/server/appop/AppOpHistoryDbHelper.java
+ */
+message SqliteAppOpEventReported {
+  optional int64 read_time_millis = 1 ;
+  optional int64 write_time_millis = 2 ;
+  optional int64 storage_bytes = 3 ;
+  // Appop are stored in 2 databases, and the data is aggregated based on time interval.
+  enum DatabaseType {
+    DB_UNKNOWN = 0;
+    DB_SHORT_INTERVAL = 1;
+    DB_LONG_INTERVAL = 2;
+  }
+  optional DatabaseType database_type = 4;
+  // What triggered the database write.
+  enum WriteType {
+    WRITE_UNKNOWN = 0;
+    WRITE_CACHE_FULL = 1;
+    WRITE_PERIODIC = 2;
+    WRITE_SHUTDOWN = 3;
+    // During read we flush the cache into database to simplify read queries.
+    WRITE_READ = 4;
+    WRITE_MIGRATION = 5;
+  }
+  optional WriteType write_type = 5;
+}
+
 /**
  * Logs when specific content and file URIs are encountered in several locations. See EventType for
  * more details.
@@ -1327,6 +1362,19 @@ message AdvancedProtectionStateInfo {
     optional int32 hours_since_last_change = 2;
 }
 
+/** Reports failures of enableUsbData signal API calls for the USB data protection feature.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/security/advancedprotection/features/UsbDataAdvancedProtectionHook.java
+ * Estimated Logging Rate:
+ *   Peak: <1 times per device per day. | Avg: <1 time per device per day.
+ */
+message AdvancedProtectionUsbStateChangeErrorReported {
+    // The desired signal state of the API call. If false, then the API call failed to disable
+    // USB data. If true, then the API call failed to enable USB data.
+    optional bool desired_signal_state = 1;
+    optional int32 retries_occurred = 2;
+}
+
 /**
  * Logged by clipboard service when the user pastes clips from the system clipboard.
  * Logged from:
@@ -1377,3 +1425,184 @@ message ClipboardGetEventReported {
      */
     optional int32 time_since_set_in_secs = 5;
 }
+
+/**
+ * Reports that binder spam was detected.
+ * Logged from:
+ *   frameworks/native/libs/binder/IPCThreadState.cpp
+ * Estimated Logging Rate:
+ *   Peak: Every second. | Avg: 2 times per device per day.
+ */
+message BinderSpamReported {
+    // The worksource UID if known, otherwise the calling process UID
+    optional int32 client_uid = 1 [(is_uid) = true];
+    optional int32 server_uid = 2 [(is_uid) = true];
+    optional string aidl_interface = 3;
+    optional string aidl_method = 4; // (or "#<transaction code>" if unknown)
+
+    // New seconds of spam since last report. Intended for SUM aggregation.
+    optional int32 seconds_with_at_least_125_calls = 5;
+    optional int32 seconds_with_at_least_250_calls = 6;
+}
+
+/**
+ * Logged the change in CDM device presence status
+ * Logged from: frameworks/base/services/companion/java/com/android/server/companion/devicepresence
+ */
+message DevicePresenceChanged {
+    enum DeviceProfile {
+        DEVICE_PROFILE_UNKNOWN = 0;
+        DEVICE_PROFILE_UUID = 1;
+        DEVICE_PROFILE_NULL = 2;
+        DEVICE_PROFILE_WATCH = 3;
+        DEVICE_PROFILE_APP_STREAMING = 4;
+        DEVICE_PROFILE_AUTO_PROJECTION = 5;
+        DEVICE_PROFILE_COMPUTER = 6;
+        DEVICE_PROFILE_GLASSES = 7;
+        DEVICE_PROFILE_NEARBY_DEVICE_STREAMING = 8;
+        DEVICE_PROFILE_VIRTUAL_DEVICE = 9;
+        DEVICE_PROFILE_WEARABLE_SENSING = 10;
+    }
+
+    enum DevicePresenceStatus {
+        NOTIFY_UNKNOWN = 0;
+        NOTIFY_BLE_APPEARED = 1;
+        NOTIFY_BLE_DISAPPEARED = 2;
+        NOTIFY_BT_CONNECTED = 3;
+        NOTIFY_BT_DISCONNECTED = 4;
+        NOTIFY_SELF_MANAGED_APPEARED = 5;
+        NOTIFY_SELF_MANAGED_DISAPPEARED = 6;
+    }
+
+    // The companion app's UID.
+    optional int32 uid = 1 [(is_uid) = true];
+    // Name of the Companion Device Manager Association profile.
+    optional DeviceProfile device_profile = 2;
+    optional DevicePresenceStatus device_presence_status = 3;
+}
+
+/**
+ * Logged (once per process) when the first activity is started in the process AND the last exit
+ * info is available.
+ *
+ * Logged from: frameworks/base/services/core/java/com/android/server/wm/ActivityMetricsLogger.java
+ *
+ * Estimated Logging Rate:
+ *   Avg: 50 per device per day
+ *   P95: 150 per device per day
+ */
+message AppRestartOccurred {
+    // The app's uid.
+    optional int32 uid = 1 [(is_uid) = true];
+
+    enum StartType {
+        UNKNOWN = 0;
+
+        // The process was created specifically for the activity.
+        COLD = 1;
+
+        // The process was created for other reason (e.g. to handle a broadcast),
+        // but this activity is the first one to be started in the process.
+        WARM = 2;
+    }
+    optional StartType type = 2;
+
+    optional int64 millis_since_last_exit = 3;
+
+    // Select fields from the ApplicationExitInfo.
+    optional android.app.AppExitReasonCode last_exit_reason = 4;
+    optional android.app.AppExitSubReasonCode last_exit_sub_reason = 5;
+    optional android.app.Importance last_exit_importance = 6;
+}
+
+/**
+ * [Pushed Atom] Logs implicit URI permission grant events.
+ *
+ * Logged from: frameworks/base/core/java/android/content/Intent.java
+ */
+message ImplicitUriGrantEventReported {
+    enum GrantType {
+        GRANT_TYPE_UNKNOWN = 0;
+        GRANTED = 1;
+        RESTRICTED = 2;
+    }
+
+    enum AccessType {
+        ACCESS_TYPE_UNKNOWN = 0;
+        READ = 1;
+        WRITE = 2;
+    }
+
+    enum ActionType {
+        ACTION_TYPE_UNKNOWN = 0;
+        SEND = 1;
+        SEND_MULTIPLE = 2;
+        IMAGE_CAPTURE = 3;
+    }
+
+    // Uid of the package requesting the op
+    optional int32 uid = 1 [(is_uid) = true];
+    optional GrantType grant_type = 2;
+    optional AccessType access_type = 3;
+    optional ActionType action_type = 4;
+}
+
+/**
+ * Reports that binder calls were received.
+ * Logged from:
+ *   frameworks/native/libs/binder/IPCThreadState.cpp
+ * Estimated Logging Rate:
+ *   Peak: 100 times per second. | Avg: every second.
+ */
+message BinderCallsReported {
+    // The worksource UID if known, otherwise the calling process UID
+    optional int32 client_uid = 1 [(is_uid) = true];
+    optional int32 server_uid = 2 [(is_uid) = true];
+    optional string aidl_interface = 3;
+    optional string aidl_method = 4; // (or "#<transaction code>" if unknown)
+
+    // The number of calls received since last report.
+    optional int64 call_count = 5;
+
+    // The total duration for executing the calls since last report.
+    optional int64 call_duration_sum_micros = 6;
+
+    // Duration stats for low-rate spam. These are not necessarily excessive,
+    // so they are part of the general stats rather than spam.
+    // Unlike the fields in BinderSpamReported, these field are only reported
+    // for the AIDL targets for which we collect call stats.
+    optional int32 seconds_with_at_least_10_calls = 7;
+    optional int32 seconds_with_at_least_50_calls = 8;
+}
+
+/**
+ * Reports that one time permission session has completed.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/pm/permission/OneTimePermissionUserManager.java
+ */
+message PermissionOneTimeSessionEventReported {
+    optional int32 uid = 1 [(is_uid) = true];
+    // The permission names that were granted as "only this time" in this session.
+    repeated string permission_names = 2;
+    // The duration of the session in milliseconds.
+    optional int64 duration_millis= 3;
+}
+
+
+/**
+ * Aggregated app ops data per package and attribution tag.
+ * Logged from:
+ *   frameworks/base/services/core/java/com/android/server/appop/AppOpHistoryHelper.java
+ */
+message AggregatedAppOpAccessEventReported {
+    optional string package_name = 1;
+    // The attribution tag from the app, defined in the app's manifest.
+    optional string attribution_tag = 2;
+    optional android.app.AppOpEnum op = 3 [default = APP_OP_NONE];
+    optional int64 foreground_accessed_count = 4;
+    optional int64 background_accessed_count = 5;
+    optional int64 foreground_rejected_count = 6;
+    optional int64 background_rejected_count = 7;
+    optional int64 foreground_duration_millis = 8;
+    optional int64 background_duration_millis = 9;
+}
diff --git a/stats/atoms/hardware/health/battery_extension_atoms.proto b/stats/atoms/hardware/health/battery_extension_atoms.proto
index 4a0edf45..798dc4d4 100644
--- a/stats/atoms/hardware/health/battery_extension_atoms.proto
+++ b/stats/atoms/hardware/health/battery_extension_atoms.proto
@@ -27,6 +27,7 @@ option java_multiple_files = true;
 
 extend Atom {
   optional BatteryHealth battery_health = 10220 [(module) = "framework"];
+  optional BatteryLife battery_life = 10245 [(module) = "framework"];
 }
 
 /*
@@ -58,3 +59,15 @@ message BatteryHealth {
   optional android.hardware.health.BatteryChargingPolicy
       battery_charging_policy = 7;
 }
+
+/*
+ * Pulls total battery life estimate based on current drain rate, as reported
+ * by the android.hardware.health HAL.
+ */
+message BatteryLife {
+  /*
+   * The estimated total battery life at the current drain rate, using the
+   * actual total battery capacity.
+   */
+  optional int32 battery_life_minutes = 1;
+}
diff --git a/stats/atoms/hardware/health/storage_extension_atoms.proto b/stats/atoms/hardware/health/storage_extension_atoms.proto
new file mode 100644
index 00000000..355faf02
--- /dev/null
+++ b/stats/atoms/hardware/health/storage_extension_atoms.proto
@@ -0,0 +1,41 @@
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
+package android.os.statsd.hardware.health;
+
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+
+option java_package = "com.android.os.hardware.health";
+option java_multiple_files = true;
+
+extend Atom {
+  optional StorageHealth storage_health = 10239 [(module) = "framework"];
+}
+
+/*
+ * Storage health information.
+ */
+message StorageHealth {
+  /*
+   * Returns the remaining storage lifetime reported by IVold. This is a
+   * percentage, rounded up as needed when the underlying hardware reports low
+   * precision. On failure, this value equals -1.
+   */
+  optional int32 remaining_lifetime_percent = 1;
+}
diff --git a/stats/atoms/healthfitness/api/api_extension_atoms.proto b/stats/atoms/healthfitness/api/api_extension_atoms.proto
index 6536e87c..26909daa 100644
--- a/stats/atoms/healthfitness/api/api_extension_atoms.proto
+++ b/stats/atoms/healthfitness/api/api_extension_atoms.proto
@@ -231,18 +231,26 @@ message HealthConnectImportInvoked {
  * Avg: 1 per device per day
  */
 message HealthConnectDataBackupInvoked {
-
   // Status of the data backup (started/success/failure)
   optional android.healthfitness.api.DataBackupStatus status = 1;
 
-  // Time taken between the start of the data backup and its conclusion.
-  optional int32 time_to_succeed_or_fail_millis = 2;
+  /**
+   * Time taken between the start of the data backup and its conclusion.
+   * Deprecated as field cannot be populated with data at time of logging.
+   */
+  optional int32 time_to_succeed_or_fail_millis = 2 [deprecated = true];
 
-  // Size of the data being backed up.
-  optional int32 data_size_kb = 3;
+  /**
+   * Size of the data being backed up.
+   * Deprecated as field cannot be populated with data at time of logging.
+   */
+  optional int32 data_size_kb = 3 [deprecated = true];
 
   // Data backup type (full/incremental).
   optional android.healthfitness.api.DataBackupType backup_type = 4;
+
+  // Total number of being records backed up.
+  optional int32 total_record_count = 5;
 }
 
 /**
@@ -281,8 +289,17 @@ message HealthConnectDataRestoreInvoked {
   // Time taken between the start of the data restore and its conclusion.
   optional int32 time_to_succeed_or_fail_millis = 2;
 
-  // Size of the data being restored.
-  optional int32 data_size_kb = 3;
+  /**
+   * Size of the data being restored.
+   * Deprecated as field cannot be populated with data at time of logging.
+   */
+  optional int32 data_size_kb = 3 [deprecated = true];
+
+  // Total number of being records restored.
+  optional int32 total_record_count = 4;
+
+  // Number of successfully restored records.
+  optional int32 successful_record_count = 5;
 }
 
 /**
diff --git a/stats/atoms/healthfitness/ui/ui_extension_atoms.proto b/stats/atoms/healthfitness/ui/ui_extension_atoms.proto
index 5e70b90c..6a99e243 100644
--- a/stats/atoms/healthfitness/ui/ui_extension_atoms.proto
+++ b/stats/atoms/healthfitness/ui/ui_extension_atoms.proto
@@ -32,6 +32,8 @@ extend Atom {
 
     optional HealthConnectAppOpenedReported health_connect_app_opened_reported = 625 [(module) = "healthfitness"];
 
+    optional HealthConnectNotification health_connect_notification = 1105 [(module) = "healthfitness"];
+
 }
 
 message HealthConnectUiImpression {
@@ -48,3 +50,8 @@ message HealthConnectUiInteraction {
 message HealthConnectAppOpenedReported {
     optional android.healthfitness.ui.Source source = 1;
 }
+
+message HealthConnectNotification {
+    optional android.healthfitness.ui.NotificationId notification_id = 1;
+    optional android.healthfitness.ui.NotificationAction notification_action = 2;
+}
diff --git a/stats/atoms/input/input_extension_atoms.proto b/stats/atoms/input/input_extension_atoms.proto
index a769d410..dc2e24ae 100644
--- a/stats/atoms/input/input_extension_atoms.proto
+++ b/stats/atoms/input/input_extension_atoms.proto
@@ -28,10 +28,13 @@ option java_multiple_files = true;
 extend Atom {
     optional KeyboardConfigured keyboard_configured = 682 [(module) = "framework"];
     optional KeyboardSystemsEventReported keyboard_systems_event_reported = 683 [(module) = "framework"];
-    optional InputDeviceUsageReported inputdevice_usage_reported = 686 [(module) = "framework"];
-    optional InputEventLatencyReported input_event_latency_reported = 932 [(module) = "framework"];
+    optional InputDeviceUsageReported inputdevice_usage_reported =
+            686 [(module) = "framework", (module) = "input"];
+    optional InputEventLatencyReported input_event_latency_reported =
+            932 [(module) = "framework", (module) = "input"];
 
-    optional TouchpadUsage touchpad_usage = 10191 [(module) = "framework"];
+    optional TouchpadUsage touchpad_usage =
+            10191 [(module) = "framework", (module) = "input"];
 }
 
 // Keyboard layout configured when the device is connected
diff --git a/stats/atoms/locksettings/locksettings_extension_atoms.proto b/stats/atoms/locksettings/locksettings_extension_atoms.proto
new file mode 100644
index 00000000..15b4e0ea
--- /dev/null
+++ b/stats/atoms/locksettings/locksettings_extension_atoms.proto
@@ -0,0 +1,76 @@
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
+package android.os.statsd.locksettings;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+
+option java_package = "com.android.os.locksettings";
+option java_multiple_files = true;
+
+extend Atom {
+    optional LskfAuthenticationAttempted lskf_authentication_attempted
+        = 1099 [(module) = "framework"];
+}
+
+/**
+ * Logs the result of an attempt to authenticate using LSKF (lock screen
+ * knowledge factor)
+ *
+ * Pushed from:
+ *   frameworks/base/services/core/java/com/android/server/locksettings/SoftwareRateLimiter.java
+ */
+message LskfAuthenticationAttempted {
+    // True if the attempt was successful. False if it was unsuccessful.
+    optional bool success = 1;
+
+    // The number of failed attempts since the last successful attempt (for the
+    // same user), not counting attempts that never reached the real credential
+    // check for a reason such as detection of a duplicate wrong guess,
+    // credential too short, delay still remaining, etc.
+    optional int32 num_failures = 2;
+
+    // The number of the duplicate wrong guesses that have been detected since
+    // the last success or reboot (for the same user). Note that the ability to
+    // detect duplicate wrong guesses may vary from device to device depending
+    // on whether the error codes returned by the hardware rate-limiter clearly
+    // differentiate between wrong guesses and other errors.
+    optional int32 num_duplicate_guesses = 3;
+
+    // The type of lock screen knowledge factor that the user has
+    enum CredentialType {
+        UNKNOWN_TYPE = 0;
+        PATTERN = 1;
+        PASSWORD = 2;
+        PIN = 3;
+        UNIFIED_PROFILE_PASSWORD = 4;
+    }
+    optional CredentialType credential_type = 4;
+
+    // Whether the software rate-limiter is in enforcing mode
+    optional bool software_rate_limiter_enforcing = 5;
+
+    // The type of hardware rate-limiter the lock screen knowledge factor uses
+    enum HardwareRateLimiter {
+      UNSPECIFIED_RATELIMITER = 0;
+      GATEKEEPER = 1;
+      WEAVER = 2;
+    }
+    optional HardwareRateLimiter hardware_rate_limiter = 6;
+}
diff --git a/stats/atoms/media/media_codec_extension_atoms.proto b/stats/atoms/media/media_codec_extension_atoms.proto
index 4247b059..c86eb47d 100644
--- a/stats/atoms/media/media_codec_extension_atoms.proto
+++ b/stats/atoms/media/media_codec_extension_atoms.proto
@@ -35,6 +35,9 @@ extend Atom {
 
   optional MediaCodecRendered media_codec_rendered = 684
         [(module) = "framework", (module) = "media_metrics"];
+
+  optional AppMediaCodecUsageReported app_media_codec_usage_reported = 1082
+        [(module) = "framework", (module) = "media_metrics"];
 }
 
 /**
@@ -288,3 +291,66 @@ message MediaCodecRendered {
     // The histogram bucket limits for judder scores.
     repeated int32 judder_score_histogram_buckets = 32;
 }
+
+/**
+ * MediaResourceManagerService (media.resource_manager) logs this event
+ * when an Application ends (either killed or gracefully ended).
+ * Since this atom is logged when the application terminates and if the application used
+ * any MediaCodecs, the frequency of logging this atom is within the limitations.
+ *
+ * An application can end/terminate gracefully/intentionally or killed.
+ * And the application can be killed due to various reasons, including:
+ *  - low memory conditions
+ *  - app crashes
+ *  - explicit termination by the system
+ *
+ * Logged from:
+ *   frameworks/av/services/mediaresourcemanager/ResourceManagerServiceNew.cpp
+ *
+ * @since 25Q4
+ */
+message AppMediaCodecUsageReported {
+    // This maps with ApplicationExitInfo
+    enum ApplicationTerminationReason {
+        REASON_UNSPECIFIED = 0; // Died due to unknown reason.
+        SELF_EXIT = 1;          // Graceful exit.
+        SIGNALLED = 2;          // Died because of OS signal.
+        LOW_MEMORY = 3;         // Killed by the system low memory killer.
+        CRASH = 4;              // Died because of an unhandled exception in Java code.
+        NATIVE_CRASH = 5;       // Died because of a native code crash.
+        ANR = 6;                // Killed due to being unresponsive (ANR).
+        OTHER = 7;              // Killed by the system for various other reasons.
+    }
+
+    // UID of the Application for which the media codec usage report is posted.
+    optional int32 app_uid = 1 [(is_uid) = true];
+
+    // Application Termination reason.
+    optional ApplicationTerminationReason reason = 2;
+
+    // Applications peak codec usage.
+    optional int32 app_peak_hw_video_decoder_count = 3;
+    optional int32 app_peak_hw_video_encoder_count = 4;
+    optional int32 app_peak_sw_video_decoder_count = 5;
+    optional int32 app_peak_sw_video_encoder_count = 6;
+    optional int32 app_peak_hw_audio_decoder_count = 7;
+    optional int32 app_peak_hw_audio_encoder_count = 8;
+    optional int32 app_peak_sw_audio_decoder_count = 9;
+    optional int32 app_peak_sw_audio_encoder_count = 10;
+    optional int32 app_peak_hw_image_decoder_count = 11;
+    optional int32 app_peak_hw_image_encoder_count = 12;
+    optional int32 app_peak_sw_image_decoder_count = 13;
+    optional int32 app_peak_sw_image_encoder_count = 14;
+
+    // Applications peak pixel count.
+    optional int64 app_peak_pixel_count = 15;
+
+    // Applications peak codec memory usage.
+    optional int64 app_peak_codec_memory_size_in_kb = 16;
+
+    // Total codecs created so far (across all applications)
+    optional int32 total_codecs_created = 17;
+
+    // Total codecs killed so far (because of all the killed applications)
+    optional int32 total_codecs_killed = 18;
+}
diff --git a/stats/atoms/memory/zram_extension_atoms.proto b/stats/atoms/memory/zram_extension_atoms.proto
index 26d1e83f..fd0d0961 100644
--- a/stats/atoms/memory/zram_extension_atoms.proto
+++ b/stats/atoms/memory/zram_extension_atoms.proto
@@ -31,6 +31,7 @@ extend Atom {
 
     optional ZramMmStatMmd zram_mm_stat_mmd = 10232 [(module) = "framework"];
     optional ZramBdStatMmd zram_bd_stat_mmd = 10233 [(module) = "framework"];
+    optional ZramIoStatMmd zram_io_stat_mmd = 10240 [(module) = "framework"];
 }
 
 /**
@@ -68,7 +69,7 @@ message ZramMaintenanceExecuted {
  * Logged from:
  *   * system/memory/mmd
  *
- * Next Tag: 10
+ * Next Tag: 11
  */
 message ZramMmStatMmd {
     // Uncompressed size of data stored in this disk. This excludes
@@ -100,6 +101,9 @@ message ZramMmStatMmd {
     // The number of huge pages since zram set up.
     // Start supporting from v5.15.
     optional int64 huge_pages_since_kb = 9;
+    // The number of huge pages removed since zram set up.
+    // This is calculated from huge_pages_since_kb and huge_pages_kb.
+    optional int64 huge_pages_removed_since_kb = 10;
 }
 
 /**
@@ -119,6 +123,28 @@ message ZramBdStatMmd {
     optional int64 bd_writes_kb = 3;
 }
 
+/**
+ * Zram IO stats from /sys/block/zram0/io_stat
+ *
+ * Logged from:
+ *   * system/memory/mmd
+ *
+ * Next Tag: 5
+ */
+ message ZramIoStatMmd {
+    // The number of failed reads in zram.
+    optional int64 failed_reads = 1;
+    // The number of failed writes in zram.
+    optional int64 failed_writes = 2;
+    // The number of non-page-size-aligned I/O requests in zram.
+    optional int64 invalid_io = 3;
+    // Depending on device usage scenario it may account
+    // a) the number of pages freed because of swap slot free
+    // notifications or b) the number of pages freed because of
+    // REQ_OP_DISCARD requests sent by bio.
+    optional int64 notify_free = 4;
+}
+
 /**
  * Logged when zram setup is executed in mmd.
  *
diff --git a/stats/atoms/notification/notification_extension_atoms.proto b/stats/atoms/notification/notification_extension_atoms.proto
index 87e84e44..6836ef1d 100644
--- a/stats/atoms/notification/notification_extension_atoms.proto
+++ b/stats/atoms/notification/notification_extension_atoms.proto
@@ -26,24 +26,69 @@ option java_package = "com.android.os.notification";
 option java_multiple_files = true;
 
 extend Atom {
-  optional NotificationBundlePreferences notification_bundle_preferences = 10231 [(module) = "framework"];
+  optional NotificationAdjustmentPreferences notification_adjustment_preferences = 10231 [(module) = "framework"];
+  optional NotificationAssistantEventReported notification_assistant_event_reported = 1055 [(module) = "extservices"];
+  optional NotificationAssistantDurationReceived notification_assistant_duration_received = 1056 [(module) = "extservices"];
 }
 
 /**
- * Atom that records a list of a user's notification bundle preferences. Bundles are system-provided
- * groupings of notifications based on notifications being classified as belonging to a particular
- * type (e.g., news). Users can choose to allow or disallow their notifications from being bundled
- * via settings.
+ * Atom that records a user's preferences for assistant-based adjustments to notifications.
+ * The key of the adjustment specifies which kind of adjustment this atom pertains to. These
+ * adjustments may include notification classification or summarization. Users can choose to allow
+ * or disallow specific types of notification adjustments via Settings.
+ *
+ * For notification bundling (classification) specifically, we additionally log a list of a user's
+ * notification bundle preferences. Bundles are system-provided groupings of notifications based on
+ * notifications being classified as belonging to a particular type (e.g., news).
  *
  * Logged from:
  *   frameworks/base/services/core/java/com/android/server/notification/NotificationManagerService.java
+ *
+ * Next id: 6
  */
-message NotificationBundlePreferences {
+message NotificationAdjustmentPreferences {
   // The event_id (as for UiEventReported).
   optional int32 event_id = 1;
-  // Whether bundling is allowed at all. Opting-out of bundling sets to false.
-  optional bool bundles_allowed = 2;
-  // Which types of bundles are allowed. Bundle types are a limited set, so this
+
+  // Whether this type of adjustment is allowed at all. Opting-out of the adjustment sets to false.
+  optional bool adjustment_allowed = 2;
+
+  // For bundles only: which types of bundles are allowed. Bundle types are a limited set, so this
   // repeated field will never be larger than the total number of bundle types.
   repeated android.stats.notification.BundleTypes allowed_bundle_types = 3;
-}
\ No newline at end of file
+
+  // The adjustment key that this set of preferences pertains to.
+  optional android.stats.notification.AdjustmentKey key = 4;
+
+  // The android user ID (0, 1, 10, ...) for which these preferences apply. May be a full user
+  // or a profile user.
+  optional int32 user_id = 5;
+}
+
+/**
+ * Atom that records NotificationAssistant event stats.
+ *
+ * Logged from:
+ *   packages/modules/ExtServices/java/src/android/ext/services/notification/Assistant.java
+ */
+message NotificationAssistantEventReported {
+  enum NotificationAssistantEventType {
+    UNKNOWN = 0;
+    NOTIFICATION_ENQUEUED = 1;
+    TC_FOR_OTP_DETECTION_ENABLED = 2;
+    OTP_CHECKED = 3;
+    OTP_CHECK_SKIPPED_DUE_TO_LOAD = 4;
+    OTP_DETECTED = 5;
+  }
+  optional NotificationAssistantEventType event_type = 1;
+}
+
+/**
+ * Atom that records NotificationAssistant duration stats.
+ *
+ * Logged from:
+ *   packages/modules/ExtServices/java/src/android/ext/services/notification/Assistant.java
+ */
+message NotificationAssistantDurationReceived {
+  optional int64 otp_detection_duration_ms = 1;
+}
diff --git a/stats/atoms/packagemanager/packagemanager_extension_atoms.proto b/stats/atoms/packagemanager/packagemanager_extension_atoms.proto
index 873792b0..16aeae63 100644
--- a/stats/atoms/packagemanager/packagemanager_extension_atoms.proto
+++ b/stats/atoms/packagemanager/packagemanager_extension_atoms.proto
@@ -27,6 +27,8 @@ option java_multiple_files = true;
 extend Atom {
   optional ComponentStateChangedReported component_state_changed_reported = 863
       [(module) = "framework"];
+  optional PackageInstallerSessionReported package_installer_session_reported = 1101
+      [(module) = "framework"];
 }
 
 /**
@@ -70,3 +72,151 @@ message ComponentStateChangedReported {
   // The UID for which the application calls this method.
   optional int32 calling_uid = 6 [(is_uid) = true];
 }
+
+/**
+ * Records data on package installation sessions, tracking from the installer's initiation via PackageInstaller APIs to completion.
+ *
+ * Logged from:
+ *      frameworks/base/services/core/java/com/android/server/pm/PackageInstallerSession.java
+ */
+message PackageInstallerSessionReported {
+    // --- Basic info section ---
+
+    // ID of the session, can be used to correlate with Play logging metrics.
+    optional int32 session_id = 1;
+    // User ID for which the createSession API was called.
+    optional int32 user_id = 2;
+    // UID of the package that creates the installation session.
+    optional int32 installer_uid = 3 [(is_uid) = true];
+    // ID of the child sessions, if this is a parent session, null otherwise.
+    repeated int32 child_session_ids = 4;
+    // ID of the parent session, if this is a child session, -1 otherwise.
+    optional int32 parent_session_id = 5;
+
+    // --- SessionParams section ---
+
+    // The mode of installation, corresponding to the MODE_* in SessionParams.
+    enum Mode {
+        MODE_UNSPECIFIED = 0;
+        MODE_INVALID = 1;
+        MODE_FULL_INSTALL = 2;
+        MODE_INHERIT_EXISTING = 3;
+    }
+    optional Mode mode = 6;
+    // The user action requirement, corresponding to USER_ACTION_* in SessionParams.
+    enum UserActionRequirement {
+        USER_ACTION_UNSPECIFIED = 0;
+        USER_ACTION_REQUIRED = 1;
+        USER_ACTION_NOT_REQUIRED = 2;
+    }
+    optional UserActionRequirement user_action_requirement = 7;
+    // Installation flags as specified in SessionParams.
+    optional int32 install_flags = 8;
+    // Installation location, corresponding to the INSTALL_LOCATION_* in SessionParams.
+    enum InstallLocation {
+        INSTALL_LOCATION_UNSPECIFIED = 0;
+        INSTALL_LOCATION_INTERNAL_ONLY = 1;
+        INSTALL_LOCATION_PREFER_EXTERNAL = 2;
+    }
+    optional InstallLocation install_location = 9;
+    // Installation reason, corresponding to the INSTALL_REASON_* in SessionParams.
+    enum InstallReason {
+        INSTALL_REASON_UNSPECIFIED = 0;
+        INSTALL_REASON_POLICY = 1;
+        INSTALL_REASON_DEVICE_RESTORE = 2;
+        INSTALL_REASON_DEVICE_SETUP = 3;
+        INSTALL_REASON_USER = 4;
+        INSTALL_REASON_ROLLBACK = 5;
+    }
+    optional InstallReason install_reason = 10;
+    // Installation scenario, corresponding to the INSTALL_SCENARIO_* in SessionParams.
+    enum InstallScenario {
+        INSTALL_SCENARIO_UNSPECIFIED = 0;
+        INSTALL_SCENARIO_FAST = 1;
+        INSTALL_SCENARIO_BULK = 2;
+        INSTALL_SCENARIO_BULK_SECONDARY = 3;
+    }
+    optional InstallScenario install_senario = 11;
+    // isStaged as specified in SessionParams.
+    optional bool is_staged = 12;
+    // Required installed version code as specified in SessionParams.
+    optional int64 required_installed_version_code = 13;
+    // Data loader type as specified in SessionParams.
+    enum DataLoaderType {
+        DATA_LOADER_TYPE_UNSPECIFIED = 0;
+        DATA_LOADER_TYPE_STREAMING = 1;
+        DATA_LOADER_TYPE_INCREMENTAL = 2;
+    }
+    optional DataLoaderType data_loader_type = 14;
+    // Rollback data policy as specified in SessionParams.
+    enum RollbackDataPolicy {
+        ROLLBACK_DATA_POLICY_UNSPECIFIED = 0;
+        ROLLBACK_DATA_POLICY_RESTORE = 1;
+        ROLLBACK_DATA_POLICY_WIPE = 3;
+        ROLLBACK_DATA_POLICY_RETAIN = 4;
+    }
+    optional RollbackDataPolicy rollback_data_policy = 15;
+    // Rollback lifetime millis as specified in SessionParams.
+    optional int64 rollback_lifetime_millis = 16;
+    // Rollback impact level as specified in SessionParams.
+    enum RollbackImpactLevel {
+        ROLLBACK_USER_IMPACT_UNSPECIFIED = 0;
+        ROLLBACK_USER_IMPACT_LOW = 1;
+        ROLLBACK_USER_IMPACT_HIGH = 2;
+        ROLLBACK_USER_IMPACT_ONLY_MANUAL = 3;
+    }
+    optional RollbackImpactLevel rollback_impact_level = 17;
+    // Force queryable as specified in SessionParams.
+    optional bool force_queryable_override = 18;
+    // Default application enabled setting as specified in SessionParams.
+    optional bool application_enabled_setting_persistent = 19;
+    // Whether the session is a multi-package session.
+    optional bool is_multi_package = 20;
+    // Whether this session required pre-approval.
+    optional bool is_pre_approval = 21;
+    // Whether the session was for unarchive.
+    optional bool is_unarchive = 22;
+    // Whether auto install dependencies is enabled.
+    optional bool is_auto_install_dependencies_enabled = 23;
+    // Total size of the APKs installed for this package, including the base APK and the splits. 0 if this session is for removing splits.
+    optional int64 apks_size_bytes = 24;
+
+    // --- Result section ---
+
+    // Installation result as defined in PackageInstaller.java
+    enum StatusCode {
+        STATUS_UNSPECIFIED = 0;
+        STATUS_PENDING_STREAMING = 1;
+        STATUS_PENDING_USER_ACTION = 2;
+        STATUS_SUCCESS = 3;
+        STATUS_FAILURE = 4;
+        STATUS_FAILURE_BLOCKED = 5;
+        STATUS_FAILURE_ABORTED = 6;
+        STATUS_FAILURE_INVALID = 7;
+        STATUS_FAILURE_CONFLICT = 8;
+        STATUS_FAILURE_STORAGE = 9;
+        STATUS_FAILURE_INCOMPATIBLE = 10;
+        STATUS_FAILURE_TIMEOUT = 11;
+    }
+    optional StatusCode status_code = 25;
+    // Whether user action was actually required.
+    optional bool user_action_required = 26;
+    // Whether the session was deleted because it expired.
+    optional bool is_expired = 27;
+    
+    // --- Performance section ---
+
+
+    // The duration from session creation to session commit which marks the start of verification and installation. This duration usually reflects the time when the installer writes data, but sometimes the commit might be delayed for various reasons by the installer.
+    optional int64 session_idle_duration_millis = 28;
+    // The duration between when the session was committed and when the session is complete. This duration includes the verification and the installation durations.
+    optional int64 session_commit_duration_millis = 29;
+    // The duration it took to extract native libraries.
+    optional int64 native_libs_extraction_duration_millis = 30;
+    // The duration it took for the session to be verified by package verifier and sufficient verifiers.
+    optional int64 package_verification_duration_millis = 31;
+    // The duration it took to process and install the package in PackageManager internally.
+    optional int64 internal_installation_duration_millis = 32;
+    // The duration between when the session was created to when the session has completed.
+    optional int64 session_lifetime_duration_millis = 33;
+}
diff --git a/stats/atoms/pdf/pdfviewer_extension_atoms.proto b/stats/atoms/pdf/pdfviewer_extension_atoms.proto
index 7ab36396..5e2ed4ae 100644
--- a/stats/atoms/pdf/pdfviewer_extension_atoms.proto
+++ b/stats/atoms/pdf/pdfviewer_extension_atoms.proto
@@ -87,6 +87,10 @@ message PdfApiUsageReported {
   // API Response status
   // Required.
   optional android.pdf.ApiResponseStatus api_response_status = 4;
+
+  // Type of operation (add, remove, update, list)
+  // Optional.
+  optional android.pdf.OperationType operation_type = 5;
 }
 
 /**
diff --git a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
index d937058a..537baf48 100644
--- a/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
+++ b/stats/atoms/permissioncontroller/permissioncontroller_extension_atoms.proto
@@ -46,6 +46,8 @@ extend Atom {
         1034 [(module) = "permissioncontroller"];
     optional CallWithEcmInteractionReported call_with_ecm_interaction_reported =
         1035 [(module) = "permissioncontroller"];
+    optional PermissionManagerPageInteraction permission_manager_page_interaction =
+        1049 [(module) = "permissioncontroller"];
 }
 
 /**
@@ -258,3 +260,29 @@ message CallWithEcmInteractionReported {
     // The call duration, in seconds
     optional int32 duration_secs = 2;
 }
+
+/**
+* Capture user interactions with the permission manager page.
+* Logged from ManageStandardPermissionsFragment.java, and
+* ManageCustomPermissionsFragment.java
+*/
+message PermissionManagerPageInteraction {
+    // id which identifies single session of user interacting with
+    // permission manager page
+    optional int64 session_id = 1;
+
+    enum Action {
+        UNKNOWN = 0;
+        PERMISSION_MANAGER_OPENED = 1;
+        UNUSED_APPS_LEARN_MORE_CLICKED = 2;
+        STANDARD_PERMISSION_GROUP_CLICKED = 3;
+        ADDITIONAL_PERMISSIONS_CLICKED = 4;
+        ADDITIONAL_PERMISSION_GROUP_CLICKED = 5;
+    }
+
+    // The action the user took to interact with the fragment
+    optional Action action = 2;
+    // The permission group the user interacted with, only applies to
+    // STANDARD_PERMISSION_GROUP_CLICKED and ADDITIONAL_PERMISSION_GROUP_CLICKED
+    optional string permission_group_name = 3;
+}
diff --git a/stats/atoms/printing/printing_extension_atoms.proto b/stats/atoms/printing/printing_extension_atoms.proto
new file mode 100644
index 00000000..5fa697ea
--- /dev/null
+++ b/stats/atoms/printing/printing_extension_atoms.proto
@@ -0,0 +1,124 @@
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
+package android.os.statsd.printing;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/attribution_node.proto";
+
+import "frameworks/proto_logging/stats/enums/printing/enums.proto";
+
+extend Atom {
+    optional FrameworkPrintJob framework_print_job = 1071 [(module) =
+    "framework"]; optional FrameworkPrinterDiscovery
+    framework_printer_discovery = 1072 [(module) = "framework"];
+    optional FrameworkMainPrintUiLaunched
+    framework_main_print_ui_launched = 1073 [(module) = "framework"];
+    optional FrameworkAdvancedOptionsUiLaunched
+    framework_advanced_ui_launched = 1074 [(module) = "framework"];
+
+    optional BipsPrintJob bips_print_job = 1075 [(module) =
+    "builtinprintservice"]; optional BipsDiscoveredPrinterCapabilities
+    bips_discovered_printer_capabilities = 1076 [(module) =
+    "builtinprintservice"]; optional BipsPrinterDiscovery
+    bips_printer_discovery = 1077 [(module) = "builtinprintservice"];
+    optional BipsRequestPrinterCapabilitiesStatus
+    bips_request_printer_capabilities_status = 1078 [(module) =
+    "builtinprintservice"];
+}
+
+// Printing Framework Events
+
+// Logged from frameworks/base/packages/PrintSpooler/src/com/android/printspooler/model/PrintSpoolerService.java
+message FrameworkPrintJob {
+  optional FrameworkPrintJobResult final_state = 1;
+  optional FrameworkColorMode color = 2;
+  optional int32 print_service_uid = 3 [(is_uid) = true];
+  optional FrameworkMediaSize size = 4;
+  optional int32 horizontal_dpi = 5;
+  optional int32 vertical_dpi = 6;
+  optional FrameworkOrientation orientation = 7;
+  optional FrameworkDuplexMode duplex_mode = 8;
+  optional FrameworkDocumentType document_type = 9;
+  optional bool saved_pdf = 10;
+  optional int32 page_count = 11;
+}
+
+// Logged from frameworks/base/core/java/android/printservice/PrinterDiscoverySession.java
+message FrameworkPrinterDiscovery {
+  optional int32 print_service_uid = 1 [(is_uid) = true];
+  repeated FrameworkColorMode supported_colors = 2;
+  repeated FrameworkMediaSize supported_sizes = 3;
+  repeated FrameworkDuplexMode supported_duplex_modes = 4;
+}
+
+// Logged from frameworks/base/packages/PrintSpooler/src/com/android/printspooler/ui/PrintActivity.java
+message FrameworkMainPrintUiLaunched {
+  repeated int32 print_service_uids = 1 [(is_uid) = true];
+  optional int32 printer_count = 2;
+}
+
+// Logged from frameworks/base/packages/PrintSpooler/src/com/android/printspooler/ui/PrintActivity.java
+message FrameworkAdvancedOptionsUiLaunched {
+  optional int32 print_service_uid = 1 [(is_uid) = true];
+}
+
+// BIPS Events
+
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/LocalPrintJob.java
+message BipsPrintJob {
+  // Singular IPP string value
+  optional string make_and_model = 1;
+  optional BipsJobOrigin job_origin = 2;
+  optional BipsPrintJobResult result = 3;
+  optional bool borderless = 4;
+  optional FrameworkMediaSize size = 5;
+  optional FrameworkDuplexMode duplex_mode = 6;
+  optional BipsMediaType media_type = 7;
+  optional FrameworkColorMode color = 8;
+  optional bool secure = 9;
+  optional int32 horizontal_dpi = 10;
+  optional int32 vertical_dpi = 11;
+  optional int32 page_count = 12;
+}
+
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/LocalDiscoverySession.java
+message BipsDiscoveredPrinterCapabilities {
+  // Singular IPP string value
+  optional string make_and_model = 1;
+  repeated FrameworkColorMode supported_colors = 2;
+  repeated FrameworkMediaSize supported_sizes = 3;
+  repeated FrameworkDuplexMode supported_duplex_modes = 4;
+  optional bool secure = 5;
+  repeated BipsMediaType media_type = 6;
+}
+
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/LocalDiscoverySession.java
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/discovery/MdnsDiscovery.java
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/p2p/P2pPrinterConnection.java
+message BipsPrinterDiscovery {
+    optional BipsPrinterDiscoveryScheme discovery_scheme = 1;
+    optional bool secure = 2;
+}
+
+// Logged from packages/services/BuiltInPrintService/src/com/android/bips/ipp/GetCapabilitiesTask.java
+message BipsRequestPrinterCapabilitiesStatus {
+    optional BipsRequestCapabilitiesStatus status = 1;
+    optional bool secure = 2;
+}
diff --git a/stats/atoms/privatespace/privatespace_extension_atoms.proto b/stats/atoms/privatespace/privatespace_extension_atoms.proto
new file mode 100644
index 00000000..efb3a487
--- /dev/null
+++ b/stats/atoms/privatespace/privatespace_extension_atoms.proto
@@ -0,0 +1,96 @@
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
+package android.os.statsd.privatespace;
+
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/enums/privatespace/private_space_enums.proto";
+
+option java_package = "com.android.privatespace";
+option java_multiple_files = true;
+
+extend Atom {
+  optional PrivateSpaceAddButtonEvent private_space_add_button_event = 1116
+      [(module) = "privatespace"];
+  optional PrivateSpaceMoveContentEvent private_space_move_content_event = 1117
+      [(module) = "privatespace"];
+}
+
+// Atom for PrivateSpace app shortcut clicks.
+// Logged from packages/apps/PrivateSpace/src/com/android/privatespace/PrivateSpaceActivity.kt
+message PrivateSpaceAddButtonEvent {
+  // User clicked on the PrivateSpace app shortcut displayed after click on add
+  // button in the Private Space container. Use to capture total population that
+  // interacted with the button.
+  optional AddButtonShortcutClick add_button_click = 1;
+}
+
+// Atom for move content session events
+// Logged from various classes under packages/apps/PrivateSpace/src/com/android/privatespace/...
+message PrivateSpaceMoveContentEvent {
+  //  Type of operation selected by the user (move/copy) or cancel/dismiss the
+  //  move content dialog
+  optional OperationType operation_type = 1;
+
+  // Count of total files selected by the user for transfer
+  optional int32 files_selected_count = 2;
+
+  // The overalll result of the transfer
+  optional TransferResult transfer_result = 3;
+
+  // Count of files successfully transferred.
+  optional int32 files_success_count = 4;
+
+  // Count of files that failed to transfer.
+  optional int32 files_failure_count = 5;
+
+  // Total size of files successfully transferred.
+  optional FileSizeBucket total_success_files_size_bucket = 6;
+
+  // Total size of files failed to transfer.
+  optional FileSizeBucket total_failure_files_size_bucket = 7;
+
+  // List of details of failed file transfers. Includes error codes and MIME
+  // types of each file.
+  optional RepeatedFailedFileDetails repeated_failed_file_details = 8
+      [(log_mode) = MODE_BYTES];
+
+  // List of MIME types for successful file transfers.
+  repeated MimeTypeCategory success_file_mime_types = 9;
+
+  // Event of the user interaction with the move content notification (e.g.
+  // click show files)
+  optional NotificationEventType notification_event = 10;
+
+  optional int32 duration_ms = 11;
+
+  // Container for the repeated FailedFileDetails message.
+  message RepeatedFailedFileDetails {
+    repeated FailedFileDetails failed_file_details = 1;
+  }
+
+  // Details of failed file transfers. Includes error codes and MIMEtypes of
+  // each file.
+  message FailedFileDetails {
+    // List of errors for failed file transfers
+    optional TransferErrorCode error_code = 1;
+    // List of MIME types for failed file transfers.
+    optional MimeTypeCategory file_mime_type = 2;
+  }
+}
diff --git a/stats/atoms/providers/mediaprovider/media_provider_atoms.proto b/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
index 61d2069c..f66b955c 100644
--- a/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
+++ b/stats/atoms/providers/mediaprovider/media_provider_atoms.proto
@@ -16,11 +16,26 @@
 
 syntax = "proto2";
 
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/stats/mediaprovider/mediaprovider_enums.proto";
+
 package android.os.statsd.providers.mediaprovider;
 
 option java_package = "com.android.os.providers.mediaprovider";
 option java_multiple_files = true;
 
+extend Atom {
+    optional MediaProviderVolumeRecoveryReported media_provider_volume_recovery_reported = 586 [(module) = "mediaprovider"];
+    optional FileAccessAttributesQueryReported file_access_attributes_query_reported = 1061 [(module) = "mediaprovider"];
+    optional OwnedPhotosRevokedFromAppReported owned_photos_revoked_from_app_reported = 1065 [(module) = "mediaprovider"];
+    optional MediaMetadataExtractionReported media_metadata_extraction_reported = 1066 [(module) = "mediaprovider"];
+    optional MediaProviderOpReported media_provider_op_reported = 1112 [(module) = "mediaprovider"];
+    optional FuseOpReported fuse_op_reported = 1113 [(module) = "mediaprovider"];
+    optional DeviceStorageStateReported device_storage_state_reported = 1114 [(module) = "mediaprovider"];
+    optional DeviceStorageStatePerUidReported device_storage_state_per_uid_reported = 1115 [(module) = "mediaprovider"];
+}
+
 /**
  * Logs when MediaProvider recovers volume data after a DB rollback.
  * Logged from:
@@ -45,7 +60,6 @@ message MediaProviderVolumeRecoveryReported {
     optional int64 total_leveldb_rows = 5;
     // Count of insertion failures
     optional int64 insertionFailures = 6;
-
     enum Status {
         STATUS_UNKNOWN = 0;
         SUCCESS = 1;
@@ -58,3 +72,212 @@ message MediaProviderVolumeRecoveryReported {
     // Status code of volume recovery event
     optional Status status = 7;
 }
+
+/*
+ * Logs when MediaProvider queries for file access attributes for filepath to check if file open is
+ * permitted.
+ * Logged from:
+ *   packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ */
+message FileAccessAttributesQueryReported {
+    // Latency between query fired to SQL and response object received
+    optional int32 sql_query_duration_millis = 1;
+    // Latency between query fired to LevelDb and response object received
+    optional int32 leveldb_query_duration_millis = 2;
+    // Flag to check data consistency between SQL and LevelDb
+    optional bool is_data_consistent = 3;
+}
+
+/*
+ * Logs count of items that have ownership revoked from apps
+ * Logged from:
+ *   packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ * Estimated Logging Rate:
+ *  Peak: 1 time in 1 sec | Avg: <10 in 1 day
+ */
+message OwnedPhotosRevokedFromAppReported {
+    // number of items for which ownership is revoked
+    optional int32 revoked_ownership_item_count = 1;
+
+    // package uid of the package whose ownership is revoked
+    optional int32 package_uid = 2 [(is_uid) = true];
+}
+
+/*
+ * Logs metadata extraction during media scan for different media types.
+ * Logged from:
+ *   packages/providers/MediaProvider/src/com/android/providers/media/scan/ModernMediaScanner.java
+ * Estimated Logging Rate:
+ *  Peak: 1 time in 5 sec | Avg: <10 per device per day
+ */
+message MediaMetadataExtractionReported {
+    // Total number of media files scanned during this session.
+    optional int32 total_files_scanned = 1;
+
+    // Number of files restored from backup
+    optional int32 files_scanned_from_backup = 2;
+
+    // Average time (in nanoseconds) taken to extract metadata across all media types.
+    optional int64 avg_extraction_time_ns = 3;
+
+    // ---- Image metadata extraction stats ---
+
+    // Number of image files whose metadata was extracted using backup data.
+    optional int32 image_extracted_with_backup_count = 4;
+
+    // Average time (in nanoseconds) to extract metadata for images using backup.
+    optional int64 image_extracted_with_backup_avg_time_ns = 5;
+
+    // Number of image files whose metadata was extracted without using backup.
+    optional int32 image_extracted_without_backup_count = 6;
+
+    // Average time (in nanoseconds) to extract metadata for images without backup.
+    optional int64 image_extracted_without_backup_avg_time_ns = 7;
+
+    // --- Video metadata extraction stats ---
+
+    // Number of video files whose metadata was extracted using backup data.
+    optional int32 video_extracted_with_backup_count = 8;
+
+    // Average time (in nanoseconds) to extract metadata for videos using backup.
+    optional int64 video_extracted_with_backup_avg_time_ns = 9;
+
+    // Number of video files whose metadata was extracted without using backup.
+    optional int32 video_extracted_without_backup_count = 10;
+
+    // Average time (in nanoseconds) to extract metadata for videos without backup.
+    optional int64 video_extracted_without_backup_avg_time_ns = 11;
+
+    // --- Audio metadata extraction stats ---
+
+    // Number of audio files whose metadata was extracted using backup data.
+    optional int32 audio_extracted_with_backup_count = 12;
+
+    // Average time (in nanoseconds) to extract metadata for audio using backup.
+    optional int64 audio_extracted_with_backup_avg_time_ns = 13;
+
+    // Number of audio files whose metadata was extracted without using backup.
+    optional int32 audio_extracted_without_backup_count = 14;
+
+    // Average time (in nanoseconds) to extract metadata for audio without backup.
+    optional int64 audio_extracted_without_backup_avg_time_ns = 15;
+
+    // --- Document metadata extraction stats ---
+
+    // Number of document files whose metadata was extracted using backup data.
+    optional int32 document_extracted_with_backup_count = 16;
+
+    // Average time (in nanoseconds) to extract metadata for documents using backup.
+    optional int64 document_extracted_with_backup_avg_time_ns = 17;
+
+    // Number of document files whose metadata was extracted without using backup.
+    optional int32 document_extracted_without_backup_count = 18;
+
+    // Average time (in nanoseconds) to extract metadata for documents without backup.
+    optional int64 document_extracted_without_backup_avg_time_ns = 19;
+}
+
+/**
+ * Logs when MediaProvider APIs are invoked.
+ * Logged from:
+ *     packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ *     packages/providers/MediaProvider/src/com/android/providers/media/AsyncPickerFileOpener.java
+ */
+message MediaProviderOpReported {
+    // MediaProvider operation type
+    optional stats.mediaprovider.MediaProviderOp op_type = 1;
+    // Uri type for which operation metrics are logged
+    optional stats.mediaprovider.Uri uri_type = 2;
+    // Volume type for which operation metrics are logged
+    optional stats.mediaprovider.VolumeType volume = 3;
+    // Calling package uid
+    optional int32 package_uid = 4 [(is_uid) = true];
+    // Time taken to execute operation (in nanoseconds)
+    optional int64 execution_time_nanos = 5;
+}
+
+/**
+ * Logs when MediaProvider APIs are invoked.
+ * Logged from:
+ *     packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ */
+message FuseOpReported {
+    // Native Fuse Operation Type
+    optional stats.mediaprovider.FuseOp op_type = 1;
+    // Volume type for which operation metrics are logged
+    optional stats.mediaprovider.VolumeType volume = 2;
+    // Calling package uid
+    optional int32 package_uid = 3 [(is_uid) = true];
+    // Time taken to execute operation (in nanoseconds)
+    optional int64 execution_time_nanos = 4;
+}
+
+/**
+ * Logs device storage state once every week
+ * Logged from:
+ *     packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ */
+message DeviceStorageStateReported {
+    // Total storage size of media files on the device
+    optional int64 device_storage_size_mb = 1;
+    // Number of files stores in shared storage of the device
+    optional int32 num_files_in_shared_storage = 2;
+    // Number of image files stored in the device
+    optional int32 num_images = 3;
+    // Number of video files stored in the device
+    optional int32 num_videos = 4;
+    // Number of audio files stored in the device
+    optional int32 num_audio = 5;
+    // Number of document files stored in the device
+    optional int32 num_documents = 6;
+    // Number of other media files stored in the device
+    optional int32 num_other_media = 7;
+    // Number of files stored in the default documents directory
+    optional int32 num_in_default_documents = 8;
+    // Number of files stored in the default downloads directory
+    optional int32 num_in_default_downloads = 9;
+    // Number of files stored in the Android/media directory
+    optional int32 num_in_android_media = 10;
+    // Total storage size of files stored in shared storage
+    optional int32 files_shared_storage_size_mb = 11;
+    // Total storage size of image files stored in the device
+    optional int32 images_storage_size_mb = 12;
+    // Total storage size of video files stored in the device
+    optional int32 videos_storage_size_mb = 13;
+    // Total storage size of audio files stored in the device
+    optional int32 audio_storage_size_mb = 14;
+    // Total storage size of documents files stored in the device
+    optional int32 documents_storage_size_mb = 15;
+    // Total storage size of other media files stored in the device
+    optional int32 other_media_storage_size_mb = 16;
+    // Total storage size of default downloads directory
+    optional int32 default_downloads_storage_size_mb = 17;
+    // Total storage size of default documents directory
+    optional int32 default_documents_storage_size_mb = 18;
+    // Total storage size of Android/media directory
+    optional int32 android_media_storage_size_mb = 19;
+}
+
+/**
+ * Logs storage state of each package uid once every week
+ * Logged from:
+ *     packages/providers/MediaProvider/src/com/android/providers/media/MediaProvider.java
+ */
+message DeviceStorageStatePerUidReported {
+    // Package uid for which stats are logged
+    optional int32 package_uid = 1 [(is_uid) = true];
+    // Number of files owned by the package
+    optional int32 num_owned_files = 2;
+    // Total storage size of the package owned files
+    optional int32 owned_files_storage_size_mb = 3;
+    // Number of image files owned by the package
+    optional int32 num_images = 4;
+    // Number of video files owned by the package
+    optional int32 num_videos = 5;
+    // Number of audio files owned by the package
+    optional int32 num_audio = 6;
+    // Number of document files owned by the package
+    optional int32 num_documents = 7;
+    // Number of other media type files owned by the package
+    optional int32 num_other_media = 8;
+}
\ No newline at end of file
diff --git a/stats/atoms/settings/settings_extension_atoms.proto b/stats/atoms/settings/settings_extension_atoms.proto
index cf750d45..8e2067e6 100644
--- a/stats/atoms/settings/settings_extension_atoms.proto
+++ b/stats/atoms/settings/settings_extension_atoms.proto
@@ -28,6 +28,7 @@ option java_multiple_files = true;
 extend Atom {
   optional SettingsSpaReported settings_spa_reported = 622 [(module) = "settings"];
   optional SettingsExtApiReported settings_extapi_reported = 1001 [(module) = "settings"];
+  optional SettingsBiometricsOnboarding settings_biometrics_onboarding = 1060 [(module) = "settings"];
 }
 
 
@@ -92,3 +93,54 @@ message SettingsExtApiReported {
   // Action enum associated with the preference.
   optional android.app.settings.Action action = 6;
 }
+
+/**
+ * Logs when a biometric onboarding flow happens.
+ *
+ * Logged from:
+ *   packages/apps/Settings/
+ *
+ * Keep in sync with packages/apps/Settings/protos/biometrics_onboarding.proto
+ */
+message SettingsBiometricsOnboarding {
+  // Face or fingerprint
+  optional android.app.settings.Modality modality = 1;
+
+  // From SUW/Settings/SafetyCenter...
+  optional android.app.settings.FromSource from_source = 2;
+
+  // The associated user. Eg: 0 for owners, 10+ for others.
+  optional int32 user = 3;
+
+  // The enrolled count during this onboarding flow.
+  optional int32 enrolled_count = 4;
+
+  // Duration of the onboarding flow in millis.
+  optional int64 duration_millis = 5;
+
+  // The capybara status.
+  optional int32 capybara_status = 6;
+
+  // The result code of the onboarding flow
+  optional android.app.settings.OnboardingResult result_code = 7;
+
+  // The error code
+  optional int32 error_code = 8;
+
+  // All screen infos that a user navigates through the onboarding flow.
+  optional RepeatedOnboardingScreenInfo onboarding_screen_info_list = 9 [(log_mode) = MODE_BYTES];
+}
+
+message OnboardingScreenInfo {
+  // The onboarding screen
+  optional android.app.settings.OnboardingScreen onboarding_screen = 1;
+  // The actions that user performs on this screen
+  repeated android.app.settings.OnboardingAction onboarding_actions = 2;
+  // The time in ms that user stays on this screen
+  optional int64 dwell_time_millis = 3;
+}
+
+message RepeatedOnboardingScreenInfo {
+  // The onboarding screen info list
+  repeated OnboardingScreenInfo info_list = 1;
+}
diff --git a/stats/atoms/statsd/statsd_extension_atoms.proto b/stats/atoms/statsd/statsd_extension_atoms.proto
index 8e87844c..1a0c0af2 100644
--- a/stats/atoms/statsd/statsd_extension_atoms.proto
+++ b/stats/atoms/statsd/statsd_extension_atoms.proto
@@ -119,6 +119,7 @@ message StatsSocketLossReported {
 
         // internal error codes are positive
         SOCKET_LOSS_ERROR_QUEUE_OVERFLOW = 1;
+        SOCKET_LOSS_ERROR_LOGGING_RATE_LIMIT_EXCEEDED = 2;
     }
 
     optional int32 uid = 1 [(is_uid) = true];
diff --git a/stats/atoms/statusbar/statusbar_extension_atoms.proto b/stats/atoms/statusbar/statusbar_extension_atoms.proto
new file mode 100644
index 00000000..189d3b68
--- /dev/null
+++ b/stats/atoms/statusbar/statusbar_extension_atoms.proto
@@ -0,0 +1,49 @@
+/*
+* Copyright (C) 2025 The Android Open Source Project
+*
+* Licensed under the Apache License, Version 2.0 (the "License");
+* you may not use this file except in compliance with the License.
+* You may obtain a copy of the License at
+*
+*      http://www.apache.org/licenses/LICENSE-2.0
+*
+* Unless required by applicable law or agreed to in writing, software
+* distributed under the License is distributed on an "AS IS" BASIS,
+* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+* See the License for the specific language governing permissions and
+* limitations under the License.
+*/
+
+syntax = "proto2";
+
+package android.os.statsd.statusbar;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/statusbar/enums.proto";
+
+extend Atom {
+  optional StatusBarChipReported status_bar_chip_reported = 1092 [(module) = "sysui"];
+}
+
+/**
+ * Pushes when a status bar chip is changed in some way (added, removed, tapped).
+ *
+ * Logged from:
+ *   frameworks/base/packages/SystemUI/src/com/android/systemui/statusbar/chips/uievents/StatusBarChipsUiEventLogger.kt
+ *
+ * Estimated Logging Rate:
+ *   Avg: 5 per device per day
+ */
+message StatusBarChipReported {
+  // The event_id (as for UiEventReported)
+  optional int32 event_id = 1;
+  // The type of chip
+  optional android.stats.statusbar.StatusBarChipType chip_type = 2;
+  // The instance ID to track the chip across other events
+  optional int32 instance_id = 3;
+  // How many chips are currently active in the status bar
+  optional int32 total_chips = 4;
+  // The rank that this chip currently has (omitted if this is a removal event)
+  optional int32 chip_rank = 5;
+}
diff --git a/stats/atoms/sysui/sysui_atoms.proto b/stats/atoms/sysui/sysui_atoms.proto
index 45cd7133..d064338a 100644
--- a/stats/atoms/sysui/sysui_atoms.proto
+++ b/stats/atoms/sysui/sysui_atoms.proto
@@ -153,6 +153,53 @@ message ImeTouchReported {
     optional int32 y_coordinate = 2;  // Y coordinate for ACTION_DOWN event.
 }
 
+message LauncherTarget {
+    enum Type {
+        NONE = 0;
+        ITEM_TYPE = 1;
+        CONTROL_TYPE = 2;
+        CONTAINER_TYPE = 3;
+    }
+    enum Item {
+        DEFAULT_ITEM = 0;
+        APP_ICON = 1;
+        SHORTCUT = 2;
+        WIDGET = 3;
+        FOLDER_ICON = 4;
+        DEEPSHORTCUT = 5;
+        SEARCHBOX = 6;
+        EDITTEXT = 7;
+        NOTIFICATION = 8;
+        TASK = 9;
+    }
+    enum Container {
+        DEFAULT_CONTAINER = 0;
+        HOTSEAT = 1;
+        FOLDER = 2;
+        PREDICTION = 3;
+        SEARCHRESULT = 4;
+    }
+    enum Control {
+        DEFAULT_CONTROL = 0;
+        MENU = 1;
+        UNINSTALL = 2;
+        REMOVE = 3;
+    }
+    optional Type type = 1;
+    optional Item item = 2;
+    optional Container container = 3;
+    optional Control control = 4;
+    optional string launch_component = 5;
+    optional int32 page_id = 6;
+    optional int32 grid_x = 7;
+    optional int32 grid_y = 8;
+}
+
+message LauncherExtension {
+    repeated LauncherTarget src_target = 1;
+    repeated LauncherTarget dst_target = 2;
+}
+
 /**
  * Logs when Launcher (HomeScreen) UI has changed or was interacted.
  *
@@ -163,7 +210,7 @@ message LauncherUIChanged {
     optional android.stats.launcher.LauncherAction action = 1 [deprecated = true];
     optional android.stats.launcher.LauncherState src_state = 2;
     optional android.stats.launcher.LauncherState dst_state = 3;
-    optional android.stats.launcher.LauncherExtension extension = 4 [(log_mode) = MODE_BYTES, deprecated = true];
+    optional LauncherExtension extension = 4 [(log_mode) = MODE_BYTES, deprecated = true];
     optional bool is_swipe_up_enabled = 5 [deprecated = true];
 
     // The event id (e.g., app launch, drag and drop, long press)
diff --git a/stats/atoms/telecomm/telecom_extension_atom.proto b/stats/atoms/telecomm/telecom_extension_atom.proto
index 295aba3b..fd7ddc11 100644
--- a/stats/atoms/telecomm/telecom_extension_atom.proto
+++ b/stats/atoms/telecomm/telecom_extension_atom.proto
@@ -32,6 +32,8 @@ extend Atom {
     optional TelecomApiStats telecom_api_stats = 10223 [(module) = "telecom"];
     optional TelecomErrorStats telecom_error_stats = 10224 [(module) = "telecom"];
     optional TelecomEventStats telecom_event_stats = 10235 [(module) = "telecom"];
+    optional CallSequencingStats call_sequencing_stats = 10242 [(module) = "telecom"];
+    optional CallSequencingOperationStats call_sequencing_operation_stats = 10243 [(module) = "telecom"];
 }
 
 /**
@@ -177,3 +179,92 @@ message TelecomEventStats {
     // The number of times this event occurs
     optional int32 count = 4;
 }
+
+/**
+ * Pulled atom to capture general stats of Telecom call sequencing information
+ */
+message CallSequencingStats {
+    // The value should be converted to android.telecom.CallTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallTypeEnum primary_call_type = 1;
+
+    // The value should be converted to android.telecom.CallTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallTypeEnum secondary_call_type = 2;
+
+    // True if the primary call is an emergency call
+    optional bool is_primary_call_emergency = 3;
+
+    // True if the secondary call is an emergency call
+    optional bool is_secondary_call_emergency = 4;
+
+    // True if this event is tracking a secondary call
+    optional bool has_secondary = 5;
+
+    // True if primary and secondary call phone accounts are the same
+    optional bool is_same_phone_account = 6;
+
+    // Average elapsed time between CALL_STATE_ACTIVE to CALL_STATE_DISCONNECTED.
+    optional int32 average_duration_ms = 7;
+
+    // The number of times this stat occurs
+    optional int32 count = 8;
+}
+
+/**
+ * Pulled atom to capture stats of Telecom call sequencing operations
+ */
+message CallSequencingOperationStats {
+    // The value should be converted to android.telecom.CallOperationTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallOperationTypeEnum call_operation = 1;
+
+    // The value should be converted to android.telecom.CallStateEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallStateEnum focus_call_state = 2;
+
+    // The value should be converted to android.telecom.CallStateEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallStateEnum source_call_state = 3;
+
+    // The value should be converted to android.telecom.CallTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallTypeEnum focus_call_type = 4;
+
+    // The value should be converted to android.telecom.CallTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallTypeEnum source_call_type = 5;
+
+    // Carrier name of focus call. This should always be empty/unknown for
+    // the private space calls
+    optional int32 focus_call_carrier_id = 6;
+
+    // Carrier name of the source call. This should always be empty/unknown for
+    // the private space calls or if source call isn’t defined
+    optional int32 source_call_carrier_id = 7;
+
+    // UID of the package to init the call. This should always be -1/unknown for
+    // the private space calls
+    optional int32 focus_call_uid = 8 [(is_uid) = true];
+
+    // UID of the package to init the call. This should always be -1/unknown for
+    // the private space calls or if source call isn’t defined
+    optional int32 source_call_uid = 9 [(is_uid) = true];
+
+    // True if the focus call is an emergency call
+    optional bool is_focus_call_emergency = 10;
+
+    // True if the source call is an emergency call
+    optional bool is_source_call_emergency = 11;
+
+    // The value should be converted to android.telecom.CallOperationResultEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional android.telecom.CallOperationResultEnum operation_result = 12;
+
+    // True if source call (provided that this is present) and focus call
+    // are from same phone accounts
+    optional bool is_same_phone_account = 13;
+
+    // Duration (ms) taken for operation to complete
+    optional int32 operation_duration_ms = 14;
+}
diff --git a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
index 4c023e58..9525af4d 100644
--- a/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
+++ b/stats/atoms/telephony/satellite/satellite_extension_atoms.proto
@@ -148,6 +148,10 @@ message SatelliteController {
   optional int32 count_of_incoming_datagram_type_sms_success = 42;
   // Total count of failed attempts for receiving P2P SMS.
   optional int32 count_of_incoming_datagram_type_sms_fail = 43;
+  // Version of carrier roaming satellite config data.
+  optional int32 carrier_roaming_satellite_config_version = 44;
+  // Max allowed data mode for satellite data.
+  optional int32 max_allowed_data_mode = 45;
 }
 
 /**
@@ -337,6 +341,49 @@ message CarrierRoamingSatelliteSession {
   optional bool is_multi_sim = 20;
   // Whether the service is Carrier Roaming NB-Iot NTN network or not.
   optional bool is_nb_iot_ntn = 21;
+  // Total number of data connections during satellite session
+  optional int32 count_of_data_connections = 22;
+  // last fail causes at the disconnections during satellite session
+  // The value is defined in
+  // frameworks/base/telephony/java/android/telephony/DataFailCause.java
+  repeated int32 last_fail_causes = 23;
+  // Total number of data disconnections during satellite session
+  optional int32 count_of_data_disconnections = 24;
+  // Total number of data stalls during satellite session
+  optional int32 count_of_data_stalls = 25;
+  // Average uplink bandwidth for the satellite session
+  optional int32 average_uplink_bandwidth_kbps = 26;
+  // Average downlink bandwidth for the satellite session
+  optional int32 average_downlink_bandwidth_kbps = 27;
+   // Minimum uplink bandwidth for the satellite session
+  optional int32 min_uplink_bandwidth_kbps = 28;
+  // Maximum uplink bandwidth for the satellite session
+  optional int32 max_uplink_bandwidth_kbps = 29;
+   // Minimum downlink bandwidth for the satellite session
+  optional int32 min_downlink_bandwidth_kbps = 30;
+  // Maximum downlink bandwidth for the satellite session
+  optional int32 max_downlink_bandwidth_kbps = 31;
+  // Active Satellite constrained network Applications package name at Satellite session.
+  // Note: Application active at satellite constrained network only
+  // if PROPERTY_SATELLITE_DATA_OPTIMIZED meta data is set in application
+  // manifest file.
+  // (Ref: frameworks/base/telephony/java/android/telephony/satellite/SatelliteManager.java)
+  // Note: Maximum of Top 5 satellite apps with most data consumed at satellite session 
+  // to be captured
+  repeated string satellite_supported_apps = 32;
+  // Active Satellite constrained network Applications uid at Satellite session.
+  // Note: Application active at satellite constrained network only
+  // if PROPERTY_SATELLITE_DATA_OPTIMIZED meta data is set in application
+  // manifest file.
+  // (Ref: frameworks/base/telephony/java/android/telephony/satellite/SatelliteManager.java)
+  // Note: Maximum of Top 5 satellite apps with most data consumed at satellite session 
+  // to be captured
+  repeated int32 satellite_supported_uids = 33 [(is_uid) = true];
+  // Satellite Data Consumed in Bytes by satellite network Applications
+  // (Ex: Pixel Weather, Accuweather etc) for the satellite session
+  // Note: Maximum of Top 5 satellite apps with most data consumed at satellite session 
+  // to be captured
+  repeated int64 per_app_satellite_data_consumed_bytes = 34;
 }
 
 /**
diff --git a/stats/atoms/threadnetwork/threadnetwork_atoms.proto b/stats/atoms/threadnetwork/threadnetwork_atoms.proto
deleted file mode 100644
index a3dfa944..00000000
--- a/stats/atoms/threadnetwork/threadnetwork_atoms.proto
+++ /dev/null
@@ -1,571 +0,0 @@
-/*
- * Copyright (C) 2023 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-syntax = "proto2";
-
-package android.os.statsd.threadnetwork;
-
-import "frameworks/proto_logging/stats/atom_field_options.proto";
-
-option java_package = "com.android.os.threadnetwork";
-option java_multiple_files = true;
-
-// Thread Telemetry data definition.
-message ThreadnetworkTelemetryDataReported {
-  message WpanStats {
-    optional int32 phy_rx = 1;
-    optional int32 phy_tx = 2;
-    optional int32 mac_unicast_rx = 3;
-    optional int32 mac_unicast_tx = 4;
-    optional int32 mac_broadcast_rx = 5;
-    optional int32 mac_broadcast_tx = 6;
-    optional int32 mac_tx_ack_req = 7;
-    optional int32 mac_tx_no_ack_req = 8;
-    optional int32 mac_tx_acked = 9;
-    optional int32 mac_tx_data = 10;
-    optional int32 mac_tx_data_poll = 11;
-    optional int32 mac_tx_beacon = 12;
-    optional int32 mac_tx_beacon_req = 13;
-    optional int32 mac_tx_other_pkt = 14;
-    optional int32 mac_tx_retry = 15;
-    optional int32 mac_rx_data = 16;
-    optional int32 mac_rx_data_poll = 17;
-    optional int32 mac_rx_beacon = 18;
-    optional int32 mac_rx_beacon_req = 19;
-    optional int32 mac_rx_other_pkt = 20;
-    optional int32 mac_rx_filter_whitelist = 21;
-    optional int32 mac_rx_filter_dest_addr = 22;
-    optional int32 mac_tx_fail_cca = 23;
-    optional int32 mac_rx_fail_decrypt = 24;
-    optional int32 mac_rx_fail_no_frame = 25;
-    optional int32 mac_rx_fail_unknown_neighbor = 26;
-    optional int32 mac_rx_fail_invalid_src_addr = 27;
-    optional int32 mac_rx_fail_fcs = 28;
-    optional int32 mac_rx_fail_other = 29;
-    optional int32 ip_tx_success = 30;
-    optional int32 ip_rx_success = 31;
-    optional int32 ip_tx_failure = 32;
-    optional int32 ip_rx_failure = 33;
-    optional uint32 node_type = 34;
-    optional uint32 channel = 35;
-    optional int32 radio_tx_power = 36;
-    optional float mac_cca_fail_rate = 37;
-  }
-
-  message WpanTopoFull {
-    optional uint32 rloc16 = 1;
-    optional uint32 router_id = 2;
-    optional uint32 leader_router_id = 3;
-    optional uint32 leader_rloc16 = 4; // replaced optional bytes leader_address = 5;
-    optional uint32 leader_weight = 5;
-    optional uint32 leader_local_weight = 6;
-    optional uint32 preferred_router_id = 7;
-    optional uint32 partition_id = 8;
-    optional uint32 child_table_size = 9;
-    optional uint32 neighbor_table_size = 10;
-    optional int32 instant_rssi = 11;
-    optional bool has_extended_pan_id = 12;
-    optional bool is_active_br = 13;
-    optional bool is_active_srp_server = 14;
-    optional uint32 sum_on_link_prefix_changes = 15;
-  }
-
-  enum NodeType {
-    NODE_TYPE_UNSPECIFIED = 0;
-    NODE_TYPE_ROUTER = 1;
-    NODE_TYPE_END = 2;
-    NODE_TYPE_SLEEPY_END = 3;
-    NODE_TYPE_MINIMAL_END = 4;
-
-    NODE_TYPE_OFFLINE = 5;
-    NODE_TYPE_DISABLED = 6;
-    NODE_TYPE_DETACHED = 7;
-
-    NODE_TYPE_NL_LURKER = 0x10;
-    NODE_TYPE_COMMISSIONER = 0x20;
-    NODE_TYPE_LEADER = 0x40;
-  }
-
-  message PacketsAndBytes {
-    optional int64 packet_count = 1;
-    optional int64 byte_count = 2;
-  }
-
-  message Nat64TrafficCounters {
-    optional int64 ipv4_to_ipv6_packets = 1;
-    optional int64 ipv4_to_ipv6_bytes = 2;
-    optional int64 ipv6_to_ipv4_packets = 3;
-    optional int64 ipv6_to_ipv4_bytes = 4;
-  }
-
-  message Nat64ProtocolCounters {
-    optional Nat64TrafficCounters tcp = 1;
-    optional Nat64TrafficCounters udp = 2;
-    optional Nat64TrafficCounters icmp = 3;
-  }
-
-  message Nat64PacketCounters {
-    optional int64 ipv4_to_ipv6_packets = 1;
-    optional int64 ipv6_to_ipv4_packets = 2;
-  }
-
-  message Nat64ErrorCounters {
-    optional Nat64PacketCounters unknown = 1;
-    optional Nat64PacketCounters illegal_packet = 2;
-    optional Nat64PacketCounters unsupported_protocol = 3;
-    optional Nat64PacketCounters no_mapping = 4;
-  }
-
-  message BorderRoutingCounters {
-    // The number of Router Advertisement packets received by otbr-agent on the
-    // infra link
-    optional int64 ra_rx = 1;
-
-    // The number of Router Advertisement packets successfully transmitted by
-    // otbr-agent on the infra link.
-    optional int64 ra_tx_success = 2;
-
-    // The number of Router Advertisement packets failed to transmit by
-    // otbr-agent on the infra link.
-    optional int64 ra_tx_failure = 3;
-
-    // The number of Router Solicitation packets received by otbr-agent on the
-    // infra link
-    optional int64 rs_rx = 4;
-
-    // The number of Router Solicitation packets successfully transmitted by
-    // otbr-agent on the infra link.
-    optional int64 rs_tx_success = 5;
-
-    // The number of Router Solicitation packets failed to transmit by
-    // otbr-agent on the infra link.
-    optional int64 rs_tx_failure = 6;
-
-    // The counters for inbound unicast packets
-    optional PacketsAndBytes inbound_unicast = 7;
-
-    // The counters for inbound multicast packets
-    optional PacketsAndBytes inbound_multicast = 8;
-
-    // The counters for outbound unicast packets
-    optional PacketsAndBytes outbound_unicast = 9;
-
-    // The counters for outbound multicast packets
-    optional PacketsAndBytes outbound_multicast = 10;
-
-    // The inbound and outbound NAT64 traffic through the border router
-    optional Nat64ProtocolCounters nat64_protocol_counters = 11;
-
-    // Error counters for NAT64 translator on the border router
-    optional Nat64ErrorCounters nat64_error_counters = 12;
-  }
-
-  message SrpServerRegistrationInfo {
-    // The number of active hosts/services registered on the SRP server.
-    optional uint32 fresh_count = 1;
-
-    // The number of hosts/services in 'Deleted' state on the SRP server.
-    optional uint32 deleted_count = 2;
-
-    // The sum of lease time in milliseconds of all active hosts/services on the
-    // SRP server.
-    optional uint64 lease_time_total_ms = 3;
-
-    // The sum of key lease time in milliseconds of all active hosts/services on
-    // the SRP server.
-    optional uint64 key_lease_time_total_ms = 4;
-
-    // The sum of remaining lease time in milliseconds of all active
-    // hosts/services on the SRP server.
-    optional uint64 remaining_lease_time_total_ms = 5;
-
-    // The sum of remaining key lease time in milliseconds of all active
-    // hosts/services on the SRP server.
-    optional uint64 remaining_key_lease_time_total_ms = 6;
-  }
-
-  message SrpServerResponseCounters {
-    // The number of successful responses
-    optional uint32 success_count = 1;
-
-    // The number of server failure responses
-    optional uint32 server_failure_count = 2;
-
-    // The number of format error responses
-    optional uint32 format_error_count = 3;
-
-    // The number of 'name exists' responses
-    optional uint32 name_exists_count = 4;
-
-    // The number of refused responses
-    optional uint32 refused_count = 5;
-
-    // The number of other responses
-    optional uint32 other_count = 6;
-  }
-
-  enum SrpServerState {
-    SRP_SERVER_STATE_UNSPECIFIED = 0;
-    SRP_SERVER_STATE_DISABLED = 1;
-    SRP_SERVER_STATE_RUNNING = 2;
-    SRP_SERVER_STATE_STOPPED = 3;
-  }
-
-  // The address mode used by the SRP server
-  enum SrpServerAddressMode {
-    SRP_SERVER_ADDRESS_MODE_UNSPECIFIED = 0;
-    SRP_SERVER_ADDRESS_MODE_UNICAST = 1;
-    SRP_SERVER_ADDRESS_MODE_STATE_ANYCAST = 2;
-  }
-
-  enum UpstreamDnsQueryState {
-    UPSTREAMDNS_QUERY_STATE_UNSPECIFIED = 0;
-    UPSTREAMDNS_QUERY_STATE_ENABLED = 1;
-    UPSTREAMDNS_QUERY_STATE_DISABLED = 2;
-  }
-
-  message SrpServerInfo {
-    // The state of the SRP server
-    optional SrpServerState state = 1;
-
-    // Listening port number
-    optional uint32 port = 2;
-    // The address mode {unicast, anycast} of the SRP server
-    optional SrpServerAddressMode address_mode = 3;
-
-    // The registration information of hosts on the SRP server
-    optional SrpServerRegistrationInfo hosts = 4;
-
-    // The registration information of services on the SRP server
-    optional SrpServerRegistrationInfo services = 5;
-
-    // The counters of response codes sent by the SRP server
-    optional SrpServerResponseCounters response_counters = 6;
-  }
-
-  message DnsServerResponseCounters {
-    // The number of successful responses
-    optional uint32 success_count = 1;
-
-    // The number of server failure responses
-    optional uint32 server_failure_count = 2;
-
-    // The number of format error responses
-    optional uint32 format_error_count = 3;
-
-    // The number of name error responses
-    optional uint32 name_error_count = 4;
-
-    // The number of 'not implemented' responses
-    optional uint32 not_implemented_count = 5;
-
-    // The number of other responses
-    optional uint32 other_count = 6;
-
-    // The number of queries handled by Upstream DNS server.
-    optional uint32 upstream_dns_queries = 7;
-
-    // The number of responses handled by Upstream DNS server.
-    optional uint32 upstream_dns_responses = 8;
-
-    // The number of upstream DNS failures.
-    optional uint32 upstream_dns_failures = 9;
-  }
-
-  message DnsServerInfo {
-    // The counters of response codes sent by the DNS server
-    optional DnsServerResponseCounters response_counters = 1;
-
-    // The number of DNS queries resolved at the local SRP server
-    optional uint32 resolved_by_local_srp_count = 2;
-
-    // The state of upstream DNS query
-    optional UpstreamDnsQueryState upstream_dns_query_state = 3;
-  }
-
-  message MdnsResponseCounters {
-    // The number of successful responses
-    optional uint32 success_count = 1;
-
-    // The number of 'not found' responses
-    optional uint32 not_found_count = 2;
-
-    // The number of 'invalid arg' responses
-    optional uint32 invalid_args_count = 3;
-
-    // The number of 'duplicated' responses
-    optional uint32 duplicated_count = 4;
-
-    // The number of 'not implemented' responses
-    optional uint32 not_implemented_count = 5;
-
-    // The number of unknown error responses
-    optional uint32 unknown_error_count = 6;
-
-    // The number of aborted responses
-    optional uint32 aborted_count = 7;
-
-    // The number of invalid state responses
-    optional uint32 invalid_state_count = 8;
-  }
-
-  message MdnsInfo {
-    // The response counters of host registrations
-    optional MdnsResponseCounters host_registration_responses = 1;
-
-    // The response counters of service registrations
-    optional MdnsResponseCounters service_registration_responses = 2;
-
-    // The response counters of host resolutions
-    optional MdnsResponseCounters host_resolution_responses = 3;
-
-    // The response counters of service resolutions
-    optional MdnsResponseCounters service_resolution_responses = 4;
-
-    // The EMA (Exponential Moving Average) latencies of mDNS operations
-
-    // The EMA latency of host registrations in milliseconds
-    optional uint32 host_registration_ema_latency_ms = 5;
-
-    // The EMA latency of service registrations in milliseconds
-    optional uint32 service_registration_ema_latency_ms = 6;
-
-    // The EMA latency of host resolutions in milliseconds
-    optional uint32 host_resolution_ema_latency_ms = 7;
-
-    // The EMA latency of service resolutions in milliseconds
-    optional uint32 service_resolution_ema_latency_ms = 8;
-  }
-
-  enum Nat64State {
-    NAT64_STATE_UNSPECIFIED = 0;
-    NAT64_STATE_DISABLED = 1;
-    NAT64_STATE_NOT_RUNNING = 2;
-    NAT64_STATE_IDLE = 3;
-    NAT64_STATE_ACTIVE = 4;
-  }
-
-  message BorderRoutingNat64State {
-    optional Nat64State prefix_manager_state = 1;
-    optional Nat64State translator_state = 2;
-  }
-
-  message TrelPacketCounters {
-    // The number of packets successfully transmitted through TREL
-    optional uint64 trel_tx_packets = 1;
-
-    // The number of bytes successfully transmitted through TREL
-    optional uint64 trel_tx_bytes = 2;
-
-    // The number of packet transmission failures through TREL
-    optional uint64 trel_tx_packets_failed = 3;
-
-    // The number of packets successfully received through TREL
-    optional uint64 trel_rx_packets = 4;
-
-    // The number of bytes successfully received through TREL
-    optional uint64 trel_rx_bytes = 5;
-  }
-
-  message TrelInfo {
-    // Whether TREL is enabled.
-    optional bool is_trel_enabled = 1;
-
-    // The number of TREL peers.
-    optional uint32 num_trel_peers = 2;
-
-    // TREL packet counters
-    optional TrelPacketCounters counters = 3;
-  }
-
-  message BorderAgentCounters {
-    // The number of ePSKc activations
-    optional uint32 epskc_activations = 1;
-
-    // The number of ePSKc deactivations due to cleared via API
-    optional uint32 epskc_deactivation_clears = 2;
-
-    // The number of ePSKc deactivations due to timeout
-    optional uint32 epskc_deactivation_timeouts = 3;
-
-    // The number of ePSKc deactivations due to max connection attempts reached
-    optional uint32 epskc_deactivation_max_attempts = 4;
-
-    // The number of ePSKc deactivations due to commissioner disconnected
-    optional uint32 epskc_deactivation_disconnects = 5;
-
-    // The number of ePSKc activation failures caused by invalid border agent
-    // state
-    optional uint32 epskc_invalid_ba_state_errors = 6;
-
-    // The number of ePSKc activation failures caused by invalid argument
-    optional uint32 epskc_invalid_args_errors = 7;
-
-    // The number of ePSKc activation failures caused by failed to start secure
-    // session
-    optional uint32 epskc_start_secure_session_errors = 8;
-
-    // The number of successful secure session establishment with ePSKc
-    optional uint32 epskc_secure_session_successes = 9;
-
-    // The number of failed secure session establishement with ePSKc
-    optional uint32 epskc_secure_session_failures = 10;
-
-    // The number of active commissioner petitioned over secure session
-    // establishment with ePSKc
-    optional uint32 epskc_commissioner_petitions = 11;
-
-    // The number of successful secure session establishment with PSKc
-    optional uint32 pskc_secure_session_successes = 12;
-
-    // The number of failed secure session establishement with PSKc
-    optional uint32 pskc_secure_session_failures = 13;
-
-    // The number of active commissioner petitioned over secure session
-    // establishment with PSKc
-    optional uint32 pskc_commissioner_petitions = 14;
-
-    // The number of MGMT_ACTIVE_GET.req received
-    optional uint32 mgmt_active_get_reqs = 15;
-
-    // The number of MGMT_PENDING_GET.req received
-    optional uint32 mgmt_pending_get_reqs = 16;
-  }
-
-  message BorderAgentInfo {
-    // The border agent counters
-    optional BorderAgentCounters border_agent_counters = 1;
-  }
-
-  message WpanBorderRouter {
-    // Border routing counters
-    optional BorderRoutingCounters border_routing_counters = 1;
-
-    // Information about the SRP server
-    optional SrpServerInfo srp_server = 2;
-
-    // Information about the DNS server
-    optional DnsServerInfo dns_server = 3;
-
-    // Information about the mDNS publisher
-    optional MdnsInfo mdns = 4;
-
-    // Information about the state of components of NAT64
-    optional BorderRoutingNat64State nat64_state = 5;
-
-    // Information about TREL.
-    optional TrelInfo trel_info = 6;
-
-    // Information about the Border Agent
-    optional BorderAgentInfo border_agent_info = 7;
-  }
-
-  message RcpStabilityStatistics {
-    optional uint32 rcp_timeout_count = 1;
-    optional uint32 rcp_reset_count = 2;
-    optional uint32 rcp_restoration_count = 3;
-    optional uint32 spinel_parse_error_count = 4;
-    optional int32 rcp_firmware_update_count = 5;
-    optional uint32 thread_stack_uptime = 6;
-  }
-
-  message RcpInterfaceStatistics {
-    optional uint32 rcp_interface_type = 1;
-    optional uint64 transferred_frames_count = 2;
-    optional uint64 transferred_valid_frames_count = 3;
-    optional uint64 transferred_garbage_frames_count = 4;
-    optional uint64 rx_frames_count = 5;
-    optional uint64 rx_bytes_count = 6;
-    optional uint64 tx_frames_count = 7;
-    optional uint64 tx_bytes_count = 8;
-  }
-
-  message WpanRcp {
-    optional RcpStabilityStatistics rcp_stability_statistics = 1;
-    optional RcpInterfaceStatistics rcp_interface_statistics = 2;
-  }
-
-  message CoexMetrics {
-    optional uint32 count_tx_request = 1;
-    optional uint32 count_tx_grant_immediate = 2;
-    optional uint32 count_tx_grant_wait = 3;
-    optional uint32 count_tx_grant_wait_activated = 4;
-    optional uint32 count_tx_grant_wait_timeout = 5;
-    optional uint32 count_tx_grant_deactivated_during_request = 6;
-    optional uint32 tx_average_request_to_grant_time_us = 7;
-    optional uint32 count_rx_request = 8;
-    optional uint32 count_rx_grant_immediate = 9;
-    optional uint32 count_rx_grant_wait = 10;
-    optional uint32 count_rx_grant_wait_activated = 11;
-    optional uint32 count_rx_grant_wait_timeout = 12;
-    optional uint32 count_rx_grant_deactivated_during_request = 13;
-    optional uint32 count_rx_grant_none = 14;
-    optional uint32 rx_average_request_to_grant_time_us = 15;
-  }
-
-  optional WpanStats wpan_stats = 1 [(log_mode) = MODE_BYTES];
-  optional WpanTopoFull wpan_topo_full = 2 [(log_mode) = MODE_BYTES];
-  optional WpanBorderRouter wpan_border_router = 3 [(log_mode) = MODE_BYTES];
-  optional WpanRcp wpan_rcp = 4 [(log_mode) = MODE_BYTES];
-  optional CoexMetrics coex_metrics = 5 [(log_mode) = MODE_BYTES];
-}
-
-message ThreadnetworkTopoEntryRepeated {
-  message TopoEntry {
-    // 0~15: uint16_t rloc_16
-    // 16~31: uint16_t version Thread version of the neighbor
-    optional uint32 combo_telemetry1 = 1;
-    // 0~7: uint8_t link_quality_in
-    // 8~15: int8_t average_rssi
-    // 16~23: int8_t last_rssi
-    // 24~31: uint8_t network_data_version
-    optional uint32 combo_telemetry2 = 2;
-    optional uint32 age_sec = 3;
-    // Each bit on the flag represents a bool flag
-    // 0: rx_on_when_idle
-    // 1: full_function
-    // 2: secure_data_request
-    // 3: full_network_data
-    // 4: is_child
-    optional uint32 topo_entry_flags = 4;
-    optional uint32 link_frame_counter = 5;
-    optional uint32 mle_frame_counter = 6;
-    optional uint32 timeout_sec = 7;
-    // 0~15: uint16_t frame_error_rate. Frame error rate (0xffff->100%). Requires error tracking feature.
-    // 16~31: uint16_t message_error_rate. (IPv6) msg error rate (0xffff->100%). Requires error tracking feature.
-    optional uint32 combo_telemetry3 = 8;
-  }
-
-  message TopoEntryRepeated {
-    repeated TopoEntry topo_entries = 1;
-  }
-
-  optional TopoEntryRepeated topo_entry_repeated = 1 [(log_mode) = MODE_BYTES];
-}
-
-message ThreadnetworkDeviceInfoReported {
-  // OpenThread host build version.
-  optional string ot_host_version = 1;
-
-  // OpenThread RCP build version.
-  optional string ot_rcp_version = 2;
-
-  // Thread protocol version.
-  optional int32 thread_version = 3;
-
-  // Thread Daemon version.
-  optional string thread_daemon_version = 4;
-}
diff --git a/stats/atoms/threadnetwork/threadnetwork_extension_atoms.proto b/stats/atoms/threadnetwork/threadnetwork_extension_atoms.proto
index ecbbeb29..4eee9982 100644
--- a/stats/atoms/threadnetwork/threadnetwork_extension_atoms.proto
+++ b/stats/atoms/threadnetwork/threadnetwork_extension_atoms.proto
@@ -20,7 +20,6 @@ package android.os.statsd.threadnetwork;
 
 import "frameworks/proto_logging/stats/atoms.proto";
 import "frameworks/proto_logging/stats/atom_field_options.proto";
-import "frameworks/proto_logging/stats/atoms/threadnetwork/threadnetwork_atoms.proto";
 
 option java_package = "com.android.os.threadnetwork";
 option java_multiple_files = true;
@@ -33,3 +32,553 @@ extend Atom {
     optional ThreadnetworkDeviceInfoReported threadnetwork_device_info_reported = 740
     [(module) = "threadnetwork"];
 }
+
+// Thread Telemetry data definition.
+message ThreadnetworkTelemetryDataReported {
+  message WpanStats {
+    optional int32 phy_rx = 1;
+    optional int32 phy_tx = 2;
+    optional int32 mac_unicast_rx = 3;
+    optional int32 mac_unicast_tx = 4;
+    optional int32 mac_broadcast_rx = 5;
+    optional int32 mac_broadcast_tx = 6;
+    optional int32 mac_tx_ack_req = 7;
+    optional int32 mac_tx_no_ack_req = 8;
+    optional int32 mac_tx_acked = 9;
+    optional int32 mac_tx_data = 10;
+    optional int32 mac_tx_data_poll = 11;
+    optional int32 mac_tx_beacon = 12;
+    optional int32 mac_tx_beacon_req = 13;
+    optional int32 mac_tx_other_pkt = 14;
+    optional int32 mac_tx_retry = 15;
+    optional int32 mac_rx_data = 16;
+    optional int32 mac_rx_data_poll = 17;
+    optional int32 mac_rx_beacon = 18;
+    optional int32 mac_rx_beacon_req = 19;
+    optional int32 mac_rx_other_pkt = 20;
+    optional int32 mac_rx_filter_whitelist = 21;
+    optional int32 mac_rx_filter_dest_addr = 22;
+    optional int32 mac_tx_fail_cca = 23;
+    optional int32 mac_rx_fail_decrypt = 24;
+    optional int32 mac_rx_fail_no_frame = 25;
+    optional int32 mac_rx_fail_unknown_neighbor = 26;
+    optional int32 mac_rx_fail_invalid_src_addr = 27;
+    optional int32 mac_rx_fail_fcs = 28;
+    optional int32 mac_rx_fail_other = 29;
+    optional int32 ip_tx_success = 30;
+    optional int32 ip_rx_success = 31;
+    optional int32 ip_tx_failure = 32;
+    optional int32 ip_rx_failure = 33;
+    optional uint32 node_type = 34;
+    optional uint32 channel = 35;
+    optional int32 radio_tx_power = 36;
+    optional float mac_cca_fail_rate = 37;
+  }
+
+  message WpanTopoFull {
+    optional uint32 rloc16 = 1;
+    optional uint32 router_id = 2;
+    optional uint32 leader_router_id = 3;
+    optional uint32 leader_rloc16 = 4; // replaced optional bytes leader_address = 5;
+    optional uint32 leader_weight = 5;
+    optional uint32 leader_local_weight = 6;
+    optional uint32 preferred_router_id = 7;
+    optional uint32 partition_id = 8;
+    optional uint32 child_table_size = 9;
+    optional uint32 neighbor_table_size = 10;
+    optional int32 instant_rssi = 11;
+    optional bool has_extended_pan_id = 12;
+    optional bool is_active_br = 13;
+    optional bool is_active_srp_server = 14;
+    optional uint32 sum_on_link_prefix_changes = 15;
+  }
+
+  enum NodeType {
+    NODE_TYPE_UNSPECIFIED = 0;
+    NODE_TYPE_ROUTER = 1;
+    NODE_TYPE_END = 2;
+    NODE_TYPE_SLEEPY_END = 3;
+    NODE_TYPE_MINIMAL_END = 4;
+
+    NODE_TYPE_OFFLINE = 5;
+    NODE_TYPE_DISABLED = 6;
+    NODE_TYPE_DETACHED = 7;
+
+    NODE_TYPE_NL_LURKER = 0x10;
+    NODE_TYPE_COMMISSIONER = 0x20;
+    NODE_TYPE_LEADER = 0x40;
+  }
+
+  message PacketsAndBytes {
+    optional int64 packet_count = 1;
+    optional int64 byte_count = 2;
+  }
+
+  message Nat64TrafficCounters {
+    optional int64 ipv4_to_ipv6_packets = 1;
+    optional int64 ipv4_to_ipv6_bytes = 2;
+    optional int64 ipv6_to_ipv4_packets = 3;
+    optional int64 ipv6_to_ipv4_bytes = 4;
+  }
+
+  message Nat64ProtocolCounters {
+    optional Nat64TrafficCounters tcp = 1;
+    optional Nat64TrafficCounters udp = 2;
+    optional Nat64TrafficCounters icmp = 3;
+  }
+
+  message Nat64PacketCounters {
+    optional int64 ipv4_to_ipv6_packets = 1;
+    optional int64 ipv6_to_ipv4_packets = 2;
+  }
+
+  message Nat64ErrorCounters {
+    optional Nat64PacketCounters unknown = 1;
+    optional Nat64PacketCounters illegal_packet = 2;
+    optional Nat64PacketCounters unsupported_protocol = 3;
+    optional Nat64PacketCounters no_mapping = 4;
+  }
+
+  message BorderRoutingCounters {
+    // The number of Router Advertisement packets received by otbr-agent on the
+    // infra link
+    optional int64 ra_rx = 1;
+
+    // The number of Router Advertisement packets successfully transmitted by
+    // otbr-agent on the infra link.
+    optional int64 ra_tx_success = 2;
+
+    // The number of Router Advertisement packets failed to transmit by
+    // otbr-agent on the infra link.
+    optional int64 ra_tx_failure = 3;
+
+    // The number of Router Solicitation packets received by otbr-agent on the
+    // infra link
+    optional int64 rs_rx = 4;
+
+    // The number of Router Solicitation packets successfully transmitted by
+    // otbr-agent on the infra link.
+    optional int64 rs_tx_success = 5;
+
+    // The number of Router Solicitation packets failed to transmit by
+    // otbr-agent on the infra link.
+    optional int64 rs_tx_failure = 6;
+
+    // The counters for inbound unicast packets
+    optional PacketsAndBytes inbound_unicast = 7;
+
+    // The counters for inbound multicast packets
+    optional PacketsAndBytes inbound_multicast = 8;
+
+    // The counters for outbound unicast packets
+    optional PacketsAndBytes outbound_unicast = 9;
+
+    // The counters for outbound multicast packets
+    optional PacketsAndBytes outbound_multicast = 10;
+
+    // The inbound and outbound NAT64 traffic through the border router
+    optional Nat64ProtocolCounters nat64_protocol_counters = 11;
+
+    // Error counters for NAT64 translator on the border router
+    optional Nat64ErrorCounters nat64_error_counters = 12;
+  }
+
+  message SrpServerRegistrationInfo {
+    // The number of active hosts/services registered on the SRP server.
+    optional uint32 fresh_count = 1;
+
+    // The number of hosts/services in 'Deleted' state on the SRP server.
+    optional uint32 deleted_count = 2;
+
+    // The sum of lease time in milliseconds of all active hosts/services on the
+    // SRP server.
+    optional uint64 lease_time_total_ms = 3;
+
+    // The sum of key lease time in milliseconds of all active hosts/services on
+    // the SRP server.
+    optional uint64 key_lease_time_total_ms = 4;
+
+    // The sum of remaining lease time in milliseconds of all active
+    // hosts/services on the SRP server.
+    optional uint64 remaining_lease_time_total_ms = 5;
+
+    // The sum of remaining key lease time in milliseconds of all active
+    // hosts/services on the SRP server.
+    optional uint64 remaining_key_lease_time_total_ms = 6;
+  }
+
+  message SrpServerResponseCounters {
+    // The number of successful responses
+    optional uint32 success_count = 1;
+
+    // The number of server failure responses
+    optional uint32 server_failure_count = 2;
+
+    // The number of format error responses
+    optional uint32 format_error_count = 3;
+
+    // The number of 'name exists' responses
+    optional uint32 name_exists_count = 4;
+
+    // The number of refused responses
+    optional uint32 refused_count = 5;
+
+    // The number of other responses
+    optional uint32 other_count = 6;
+  }
+
+  enum SrpServerState {
+    SRP_SERVER_STATE_UNSPECIFIED = 0;
+    SRP_SERVER_STATE_DISABLED = 1;
+    SRP_SERVER_STATE_RUNNING = 2;
+    SRP_SERVER_STATE_STOPPED = 3;
+  }
+
+  // The address mode used by the SRP server
+  enum SrpServerAddressMode {
+    SRP_SERVER_ADDRESS_MODE_UNSPECIFIED = 0;
+    SRP_SERVER_ADDRESS_MODE_UNICAST = 1;
+    SRP_SERVER_ADDRESS_MODE_STATE_ANYCAST = 2;
+  }
+
+  enum UpstreamDnsQueryState {
+    UPSTREAMDNS_QUERY_STATE_UNSPECIFIED = 0;
+    UPSTREAMDNS_QUERY_STATE_ENABLED = 1;
+    UPSTREAMDNS_QUERY_STATE_DISABLED = 2;
+  }
+
+  message SrpServerInfo {
+    // The state of the SRP server
+    optional SrpServerState state = 1;
+
+    // Listening port number
+    optional uint32 port = 2;
+    // The address mode {unicast, anycast} of the SRP server
+    optional SrpServerAddressMode address_mode = 3;
+
+    // The registration information of hosts on the SRP server
+    optional SrpServerRegistrationInfo hosts = 4;
+
+    // The registration information of services on the SRP server
+    optional SrpServerRegistrationInfo services = 5;
+
+    // The counters of response codes sent by the SRP server
+    optional SrpServerResponseCounters response_counters = 6;
+  }
+
+  message DnsServerResponseCounters {
+    // The number of successful responses
+    optional uint32 success_count = 1;
+
+    // The number of server failure responses
+    optional uint32 server_failure_count = 2;
+
+    // The number of format error responses
+    optional uint32 format_error_count = 3;
+
+    // The number of name error responses
+    optional uint32 name_error_count = 4;
+
+    // The number of 'not implemented' responses
+    optional uint32 not_implemented_count = 5;
+
+    // The number of other responses
+    optional uint32 other_count = 6;
+
+    // The number of queries handled by Upstream DNS server.
+    optional uint32 upstream_dns_queries = 7;
+
+    // The number of responses handled by Upstream DNS server.
+    optional uint32 upstream_dns_responses = 8;
+
+    // The number of upstream DNS failures.
+    optional uint32 upstream_dns_failures = 9;
+  }
+
+  message DnsServerInfo {
+    // The counters of response codes sent by the DNS server
+    optional DnsServerResponseCounters response_counters = 1;
+
+    // The number of DNS queries resolved at the local SRP server
+    optional uint32 resolved_by_local_srp_count = 2;
+
+    // The state of upstream DNS query
+    optional UpstreamDnsQueryState upstream_dns_query_state = 3;
+  }
+
+  message MdnsResponseCounters {
+    // The number of successful responses
+    optional uint32 success_count = 1;
+
+    // The number of 'not found' responses
+    optional uint32 not_found_count = 2;
+
+    // The number of 'invalid arg' responses
+    optional uint32 invalid_args_count = 3;
+
+    // The number of 'duplicated' responses
+    optional uint32 duplicated_count = 4;
+
+    // The number of 'not implemented' responses
+    optional uint32 not_implemented_count = 5;
+
+    // The number of unknown error responses
+    optional uint32 unknown_error_count = 6;
+
+    // The number of aborted responses
+    optional uint32 aborted_count = 7;
+
+    // The number of invalid state responses
+    optional uint32 invalid_state_count = 8;
+  }
+
+  message MdnsInfo {
+    // The response counters of host registrations
+    optional MdnsResponseCounters host_registration_responses = 1;
+
+    // The response counters of service registrations
+    optional MdnsResponseCounters service_registration_responses = 2;
+
+    // The response counters of host resolutions
+    optional MdnsResponseCounters host_resolution_responses = 3;
+
+    // The response counters of service resolutions
+    optional MdnsResponseCounters service_resolution_responses = 4;
+
+    // The EMA (Exponential Moving Average) latencies of mDNS operations
+
+    // The EMA latency of host registrations in milliseconds
+    optional uint32 host_registration_ema_latency_ms = 5;
+
+    // The EMA latency of service registrations in milliseconds
+    optional uint32 service_registration_ema_latency_ms = 6;
+
+    // The EMA latency of host resolutions in milliseconds
+    optional uint32 host_resolution_ema_latency_ms = 7;
+
+    // The EMA latency of service resolutions in milliseconds
+    optional uint32 service_resolution_ema_latency_ms = 8;
+  }
+
+  enum Nat64State {
+    NAT64_STATE_UNSPECIFIED = 0;
+    NAT64_STATE_DISABLED = 1;
+    NAT64_STATE_NOT_RUNNING = 2;
+    NAT64_STATE_IDLE = 3;
+    NAT64_STATE_ACTIVE = 4;
+  }
+
+  message BorderRoutingNat64State {
+    optional Nat64State prefix_manager_state = 1;
+    optional Nat64State translator_state = 2;
+  }
+
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
+  message WpanBorderRouter {
+    // Border routing counters
+    optional BorderRoutingCounters border_routing_counters = 1;
+
+    // Information about the SRP server
+    optional SrpServerInfo srp_server = 2;
+
+    // Information about the DNS server
+    optional DnsServerInfo dns_server = 3;
+
+    // Information about the mDNS publisher
+    optional MdnsInfo mdns = 4;
+
+    // Information about the state of components of NAT64
+    optional BorderRoutingNat64State nat64_state = 5;
+
+    // Information about TREL.
+    optional TrelInfo trel_info = 6;
+
+    // Information about the Border Agent
+    optional BorderAgentInfo border_agent_info = 7;
+
+    // Whether multi-AIL is detected.
+    optional bool multi_ail_detected = 8;
+  }
+
+  message RcpStabilityStatistics {
+    optional uint32 rcp_timeout_count = 1;
+    optional uint32 rcp_reset_count = 2;
+    optional uint32 rcp_restoration_count = 3;
+    optional uint32 spinel_parse_error_count = 4;
+    optional int32 rcp_firmware_update_count = 5;
+    optional uint32 thread_stack_uptime = 6;
+  }
+
+  message RcpInterfaceStatistics {
+    optional uint32 rcp_interface_type = 1;
+    optional uint64 transferred_frames_count = 2;
+    optional uint64 transferred_valid_frames_count = 3;
+    optional uint64 transferred_garbage_frames_count = 4;
+    optional uint64 rx_frames_count = 5;
+    optional uint64 rx_bytes_count = 6;
+    optional uint64 tx_frames_count = 7;
+    optional uint64 tx_bytes_count = 8;
+  }
+
+  message WpanRcp {
+    optional RcpStabilityStatistics rcp_stability_statistics = 1;
+    optional RcpInterfaceStatistics rcp_interface_statistics = 2;
+  }
+
+  message CoexMetrics {
+    optional uint32 count_tx_request = 1;
+    optional uint32 count_tx_grant_immediate = 2;
+    optional uint32 count_tx_grant_wait = 3;
+    optional uint32 count_tx_grant_wait_activated = 4;
+    optional uint32 count_tx_grant_wait_timeout = 5;
+    optional uint32 count_tx_grant_deactivated_during_request = 6;
+    optional uint32 tx_average_request_to_grant_time_us = 7;
+    optional uint32 count_rx_request = 8;
+    optional uint32 count_rx_grant_immediate = 9;
+    optional uint32 count_rx_grant_wait = 10;
+    optional uint32 count_rx_grant_wait_activated = 11;
+    optional uint32 count_rx_grant_wait_timeout = 12;
+    optional uint32 count_rx_grant_deactivated_during_request = 13;
+    optional uint32 count_rx_grant_none = 14;
+    optional uint32 rx_average_request_to_grant_time_us = 15;
+  }
+
+  optional WpanStats wpan_stats = 1 [(log_mode) = MODE_BYTES];
+  optional WpanTopoFull wpan_topo_full = 2 [(log_mode) = MODE_BYTES];
+  optional WpanBorderRouter wpan_border_router = 3 [(log_mode) = MODE_BYTES];
+  optional WpanRcp wpan_rcp = 4 [(log_mode) = MODE_BYTES];
+  optional CoexMetrics coex_metrics = 5 [(log_mode) = MODE_BYTES];
+}
+
+message ThreadnetworkTopoEntryRepeated {
+  message TopoEntry {
+    // 0~15: uint16_t rloc_16
+    // 16~31: uint16_t version Thread version of the neighbor
+    optional uint32 combo_telemetry1 = 1;
+    // 0~7: uint8_t link_quality_in
+    // 8~15: int8_t average_rssi
+    // 16~23: int8_t last_rssi
+    // 24~31: uint8_t network_data_version
+    optional uint32 combo_telemetry2 = 2;
+    optional uint32 age_sec = 3;
+    // Each bit on the flag represents a bool flag
+    // 0: rx_on_when_idle
+    // 1: full_function
+    // 2: secure_data_request
+    // 3: full_network_data
+    // 4: is_child
+    optional uint32 topo_entry_flags = 4;
+    optional uint32 link_frame_counter = 5;
+    optional uint32 mle_frame_counter = 6;
+    optional uint32 timeout_sec = 7;
+    // 0~15: uint16_t frame_error_rate. Frame error rate (0xffff->100%). Requires error tracking feature.
+    // 16~31: uint16_t message_error_rate. (IPv6) msg error rate (0xffff->100%). Requires error tracking feature.
+    optional uint32 combo_telemetry3 = 8;
+  }
+
+  message TopoEntryRepeated {
+    repeated TopoEntry topo_entries = 1;
+  }
+
+  optional TopoEntryRepeated topo_entry_repeated = 1 [(log_mode) = MODE_BYTES];
+}
+
+message ThreadnetworkDeviceInfoReported {
+  // OpenThread host build version.
+  optional string ot_host_version = 1;
+
+  // OpenThread RCP build version.
+  optional string ot_rcp_version = 2;
+
+  // Thread protocol version.
+  optional int32 thread_version = 3;
+
+  // Thread Daemon version.
+  optional string thread_daemon_version = 4;
+}
diff --git a/stats/atoms/uprobestats/uprobestats_extension_atoms.proto b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
index b3ffed08..06585ebf 100644
--- a/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
+++ b/stats/atoms/uprobestats/uprobestats_extension_atoms.proto
@@ -28,7 +28,11 @@ extend Atom {
   optional TestUprobeStatsAtomReported test_uprobestats_atom_reported = 915;
   optional SetComponentEnabledSettingReported set_component_enabled_setting_reported = 1018 [(module) = "uprobestats"];
   optional BalProcessControllerAddBoundClientUidReported bal_process_controller_add_bound_client_uid_reported = 1019 [deprecated = true];
-  optional BindServiceLockedWithBalFlagsReported bind_service_locked_with_bal_flags_reported = 1045;
+  optional BindServiceLockedWithBalFlagsReported bind_service_locked_with_bal_flags_reported = 1045 [(module) = "uprobestats"];
+  optional AndroidGraphicsBitmapAllocated android_graphics_bitmap_allocated =
+          1039 [(module) = "uprobestats"];
+  optional AndroidGraphicsBitmapAllocationSnapshot
+      android_graphics_bitmap_allocation_snapshot = 1118 [(module) = "uprobestats"];
 }
 
 /* Test atom, specifically for UprobeStats tests, not logged anywhere */
@@ -135,3 +139,52 @@ message BindServiceLockedWithBalFlagsReported {
     optional int64 flags = 2;
     optional string calling_package_name = 3;
 }
+
+/**
+ * Records Bitmap allocation events.
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
+/**
+ * Records snapshot of Bitmap allocations resident in memory.
+ *
+ * Logged via Hummingbird for probes at android.graphics.Bitmap constructor.
+ *
+ * Estimated Logging Rate:
+ *   Peak: 100 times in a second | Avg: O(hundreds) per device per day
+ */
+message AndroidGraphicsBitmapAllocationSnapshot {
+    optional int32 uid = 1 [(is_uid) = true];
+    optional int32 width = 2;
+    optional int32 height = 3;
+
+    enum PixelStorageType {
+      PIXEL_STORAGE_TYPE_UNSPECIFIED = 0;
+      PIXEL_STORAGE_TYPE_HEAP = 1;
+      PIXEL_STORAGE_TYPE_ASHMEM = 2;
+      PIXEL_STORAGE_TYPE_HARDWARE = 3;
+      PIXEL_STORAGE_TYPE_WRAPPED_PIXEL_REF = 4;
+    };
+
+    optional PixelStorageType pixel_storage_type = 4;
+
+    // Unique identifier for the snapshot, generated randomly on the device
+    // every time a snapshot is taken. Bitmaps in the same snapshot will have
+    // the same snapshot_id.
+    optional int64 snapshot_id = 5;
+    enum SnapshotType {
+        SNAPSHOT_TYPE_UNSPECIFIED = 0;
+        SNAPSHOT_TYPE_RANDOM_SAMPLE = 1;
+        SNAPSHOT_TYPE_MAX_ALLOCATION_SIZE = 2;
+    }
+    optional SnapshotType snapshot_type = 6;
+}
\ No newline at end of file
diff --git a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
index 9f7e6a11..4af32fce 100644
--- a/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
+++ b/stats/atoms/wear/connectivity/wear_connectivity_extension_atoms.proto
@@ -36,6 +36,8 @@ extend Atom {
       [(module) = "wearconnectivity"];
   optional SysproxyServiceStateUpdated sysproxy_service_state_updated = 949
       [(module) = "wearconnectivity"];
+  optional WearBleMigrationStateChanged wear_ble_migration_state_changed = 1081
+      [(module) = 'wearconnectivity'];
 }
 
 /**
@@ -166,3 +168,11 @@ message WearCompanionConnectionState {
 
   optional com.google.android.wearable.connectivity.CompanionConnectionChange connection_change = 2;
 }
+
+/**
+ * Captures updates of the Platform side Wear BLE migrations state.
+ * The sequence of the steps are: STEP_SYSPROXY_PSM_RECEIVED -> STEP_SYSPROXY_TRANSPORT_MIGRATED.
+ */
+message WearBleMigrationStateChanged {
+  optional com.google.android.wearable.connectivity.BleMigrationStep ble_migration_step = 1;
+}
diff --git a/stats/atoms/wear/physicalux/wear_physicalux_extension_atoms.proto b/stats/atoms/wear/physicalux/wear_physicalux_extension_atoms.proto
new file mode 100644
index 00000000..81eee578
--- /dev/null
+++ b/stats/atoms/wear/physicalux/wear_physicalux_extension_atoms.proto
@@ -0,0 +1,76 @@
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
+package android.os.statsd.wear.physicalux;
+
+import "frameworks/proto_logging/stats/atoms.proto";
+import "frameworks/proto_logging/stats/atom_field_options.proto";
+import "frameworks/proto_logging/stats/enums/wear/physicalux/enums.proto";
+
+option java_package = "com.android.os.wear.physicalux";
+option java_multiple_files = true;
+
+extend Atom {
+  optional WearGestureSubscriptionChanged wear_gesture_subscription_changed = 1095 [(module) = "framework"];
+  optional WearGestureReported wear_gesture_reported = 1096 [(module) = "framework"];
+  optional WearGestureDetectionStateChanged wear_gesture_detection_state_changed = 1097 [(module) = "framework"];
+}
+
+// This file contains atom related to Gestures in Wear.
+
+/**
+ * Logged when a client's subscription to gestures changes.
+ *
+ * Logged from:
+ * package: frameworks/opt/wear/src/com/android/clockwork/gesture
+ */
+message WearGestureSubscriptionChanged {
+    // The UID that subscribed to gesture events.
+    optional int32 uid = 1 [(is_uid) = true];
+    // The actions that are subscribed for.
+    // This will be empty when the client unsubscribes.
+    repeated com.google.android.clockwork.physicalux.GestureAction actions = 2;
+}
+
+/**
+ * Logged when a gesture event is reported.
+ *
+ * Logged from:
+ * package: frameworks/opt/wear/src/com/android/clockwork/gesture
+ */
+message WearGestureReported {
+    // The gesture action of the event.
+    optional com.google.android.clockwork.physicalux.GestureAction action = 1;
+    // The raw gesture of the event.
+    optional com.google.android.clockwork.physicalux.Gesture gesture = 2;
+    // The UIDs to whom this event was reported.
+    repeated int32 uids = 3 [(is_uid) = true];
+}
+
+/**
+ * Logged when the state of gesture detection changes.
+ *
+ * Logged from:
+ * package: frameworks/opt/wear/src/com/android/clockwork/gesture
+ */
+message WearGestureDetectionStateChanged {
+    // The new gesture detection state
+    optional com.google.android.clockwork.physicalux.GestureDetectionState state = 1;
+    // The gesture actions with active subscriptions
+    repeated com.google.android.clockwork.physicalux.GestureAction subscribed_actions = 2;
+}
\ No newline at end of file
diff --git a/stats/atoms/wearservices/wearservices_extension_atoms.proto b/stats/atoms/wearservices/wearservices_extension_atoms.proto
index 011851f0..434a6b1c 100644
--- a/stats/atoms/wearservices/wearservices_extension_atoms.proto
+++ b/stats/atoms/wearservices/wearservices_extension_atoms.proto
@@ -419,9 +419,8 @@ message WsBugreportEventReported {
   // It's set to 0 when the event is EVENT_BUGREPORT_REQUESTED or EVENT_BUGREPORT_TRIGGERED.
   optional int32 bugreport_size_kilobytes = 4;
 
-  // Depicts the duration of the bugreport event in seconds.
-  // It's set only for EVENT_BUGREPORT_FINISHED and EVENT_BUGREPORT_RESULT_RECEIVED.
-  optional int32 bugreport_event_duration_seconds = 5;
+  // This field is deprecated in favor of WW duration metric.
+  optional int32 bugreport_event_duration_seconds = 5 [deprecated = true];
 
   // Depics the failure reason in case the bugreport event contains a failure.
   optional android.app.wearservices.BugreportFailureReason failure_reason = 6;
diff --git a/stats/atoms/wifi/wifi_extension_atoms.proto b/stats/atoms/wifi/wifi_extension_atoms.proto
index 28ee34f9..d3ae7f7a 100644
--- a/stats/atoms/wifi/wifi_extension_atoms.proto
+++ b/stats/atoms/wifi/wifi_extension_atoms.proto
@@ -54,6 +54,7 @@ extend Atom {
     optional ScorerPredictionResultReported scorer_prediction_result_reported = 884 [(module) = "wifi"];
     optional WifiSoftApCallbackOnClientsDisconnected wifi_soft_ap_callback_on_clients_disconnected
         = 1010 [(module) = "wifi"];
+    optional WifiNetworkValidationReport wifi_network_validation_report = 1057 [(module) = "wifi"];
 
     // Pull metrics
     optional WifiAwareCapabilities wifi_aware_capabilities = 10190 [(module) = "wifi"];
@@ -422,6 +423,8 @@ message WifiStateChanged {
     optional bool wifi_wake_enabled = 2;
     // If the state change was due to Wi-Fi Wake
     optional bool enabled_by_wifi_wake = 3;
+    // UID of the caller
+    optional int32 uid = 4 [(is_uid) = true];
 }
 
 // Logged when a PNO scan is started.
@@ -852,3 +855,34 @@ message WifiSoftApCallbackOnClientsDisconnected {
     // The uid of the SoftAp creator
     optional int32 uid = 2 [(is_uid) = true];
 }
+
+/**
+* Logs when Wifi receive onValidationStatus callback when network validation completes
+*
+* Estimated Logging Rate:
+*  Peak: 100 times per device per day.
+*  Avg: 20 times per device per day.
+*/
+message WifiNetworkValidationReport {
+    enum ValidationResult{
+        UNKNOWN = 0;
+
+        // Network validation pass
+        VALIDATION_PASSED = 1;
+
+        // Network validation failed
+        VALIDATION_FAILED = 2;
+    }
+
+    // Network validation result.
+    optional ValidationResult validation_result  = 1;
+
+    // Time duration for network validation in milliseconds
+    optional int64 validation_duration_ms = 2;
+
+    // Number of validation attempts
+    optional int32 validation_retry_cnt = 3;
+
+    // Device connect to a captive portal network
+    optional bool captive_portal_detected = 4;
+}
diff --git a/stats/enums/accessibility/enums.proto b/stats/enums/accessibility/enums.proto
index e61491f8..7a2f465d 100644
--- a/stats/enums/accessibility/enums.proto
+++ b/stats/enums/accessibility/enums.proto
@@ -29,3 +29,14 @@ enum AccessibilityCheckResultType {
   ERROR_CHECK_RESULT_TYPE = 1;
   WARNING_CHECK_RESULT_TYPE = 2;
 }
+
+/** The type of autoclick action */
+enum AutoclickType {
+  AUTOCLICK_TYPE_UNKNOWN = 0;
+  AUTOCLICK_TYPE_LEFT_CLICK = 1;
+  AUTOCLICK_TYPE_RIGHT_CLICK = 2;
+  AUTOCLICK_TYPE_DOUBLE_CLICK = 3;
+  AUTOCLICK_TYPE_DRAG = 4;
+  AUTOCLICK_TYPE_SCROLL = 5;
+  AUTOCLICK_TYPE_LONG_PRESS = 6;
+}
diff --git a/stats/enums/adpf/enums.proto b/stats/enums/adpf/enums.proto
new file mode 100644
index 00000000..80652945
--- /dev/null
+++ b/stats/enums/adpf/enums.proto
@@ -0,0 +1,97 @@
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
+package android.os.statsd.adpf;
+
+option java_package = "com.android.os.adpf";
+option java_multiple_files = true;
+
+/**
+ * Enum for CPU/GPU headroom calculation type.
+ */
+enum HeadroomCalculationType {
+    UNKNOWN_CALCULATION_TYPE = 0;
+    MIN = 1;
+    AVERAGE = 2;
+}
+
+/**
+ * Enum for thermal API call status.
+ */
+enum ThermalApiStatus {
+    UNSPECIFIED_THERMAL_API_FAILURE = 0;
+    SUCCESS = 1;
+    HAL_NOT_READY = 2;
+    FEATURE_NOT_SUPPORTED = 3;
+    INVALID_ARGUMENT = 4;
+    // If the thermal HAL reports no temperature for SKIN type
+    NO_TEMPERATURE = 5;
+    // If the thermal HAL reports no matching threshold for the SKIN temperature
+    NO_TEMPERATURE_THRESHOLD = 6;
+}
+
+/**
+ * Enum for ADPF session UID state.
+ */
+enum AdpfSessionUidState {
+    UNKNOWN_UID_STATE = 0;
+    FOREGROUND = 1;
+    BACKGROUND = 2;
+}
+
+/**
+ * Enum for ADPF session state.
+ */
+enum AdpfSessionState {
+    UNKNOWN_SESSION_STATE = 0;
+    // This state is used to mark the session is paused.
+    PAUSE = 1;
+    // This state is used to mark the session is resumed.
+    RESUME = 2;
+}
+
+/**
+ * Enum for ADPF session tag.
+ */
+enum AdpfSessionTag {
+    // This tag is used to mark uncategorized hint sessions.
+    // It's labeled as OTHER in SessionTag.aidl.
+    UNKNOWN_SESSION_TAG = 0;
+    // This tag is used to mark the SurfaceFlinger hint session.
+    SURFACEFLINGER = 1;
+    // This tag is used to mark hint sessions created by HWUI.
+    HWUI = 2;
+    // This tag is used to mark hint sessions created by applications that are
+    // categorized as games.
+    GAME = 3;
+    // This tag is used to mark the hint session is created by the application.
+    // If an applications is categorized as game, then GAME should be used
+    // instead.
+    APP = 4;
+}
+
+/**
+ * Enum for FMQ support status.
+ */
+enum FmqStatus {
+    UNKNOWN_FMQ_STATUS = 0;
+    SUPPORTED = 1;
+    UNSUPPORTED = 2;
+    HAL_VERSION_NOT_MET = 3;
+    OTHER_STATUS = 4;
+}
diff --git a/stats/enums/adservices/common/OWNERS b/stats/enums/adservices/common/OWNERS
index bbf707fd..709ccd77 100644
--- a/stats/enums/adservices/common/OWNERS
+++ b/stats/enums/adservices/common/OWNERS
@@ -1,22 +1,15 @@
 abmehta@google.com
-adarshsridhar@google.com
 adigupt@google.com
 arpanah@google.com
 binhnguyen@google.com
-feifeiji@google.com
-felipeal@google.com
 fumengyao@google.com
 galarragas@google.com
 giladbarkan@google.com
-hanlixy@google.com
 jorgesaldivar@google.com
-karthikmahesh@google.com
 ktjen@google.com
 lmohanan@google.com
 niagra@google.com
 qiaoli@google.com
 shwetachahar@google.com
-tccyp@google.com
 vikassahu@google.com
-yangwangyw@google.com
-zelarabaty@google.com
\ No newline at end of file
+zelarabaty@google.com
diff --git a/stats/enums/adservices/common/adservices_cel_enums.proto b/stats/enums/adservices/common/adservices_cel_enums.proto
index 742f8181..cb15ff0a 100644
--- a/stats/enums/adservices/common/adservices_cel_enums.proto
+++ b/stats/enums/adservices/common/adservices_cel_enums.proto
@@ -132,6 +132,21 @@ enum ErrorCode {
   // Package Deny process failure service disabled.
   PACKAGE_DENY_PROCESS_ERROR_DISABLED = 33;
 
+  // Public or private key is invalid.
+  HPKE_INVALID_KEY = 34;
+
+  // The algorithm chosen is not found by the cryptographic provider.
+  HPKE_ALGORITHM_NOT_FOUND = 35;
+
+  // Underlying HPKE class cannot be located.
+  HPKE_CLASS_NOT_FOUND = 36;
+
+  // Error while encrypting message.
+  HPKE_ENCRYPTION_EXCEPTION = 37;
+
+  // Error while decrypting ciphertext.
+  HPKE_DECRYPTION_EXCEPTION = 38;
+
   // SPE Errors: 901 - 930
   // Get an unavailable job execution start timestamp when calculating the execution latency.
   SPE_UNAVAILABLE_JOB_EXECUTION_START_TIMESTAMP = 901;
@@ -401,6 +416,12 @@ enum ErrorCode {
   // Error occurred when trying to validate the UID of the calling app.
   MEASUREMENT_UID_CHECK_FAILURE = 2023;
 
+  // Error occurred when trying to execute a background job.
+  MEASUREMENT_BACKGROUND_JOB_FAILURE = 2024;
+
+  // Timeout occurred when trying to get instance of an ODP system event manager
+  MEASUREMENT_REGISTRATION_ODP_GET_MANAGER_TIMEOUT = 2025;
+
   // Fledge (PA), PAS errors: 3001 - 4000
   // Exception while PAS unable to find the service.
   PAS_UNABLE_FIND_SERVICES = 3001;
@@ -1308,6 +1329,9 @@ enum ErrorCode {
   // UX Enum is unsupported
   UNSUPPORTED_UX = 4016;
 
+  // Exception when calling setAdsPersonalizationStatus API
+  SET_ADS_PERSONALIZATION_STATUS_ERROR = 4017;
+
   // FederatedCompute errors: 5001-6000
   // Datastore exception while deleting a federated task.
   DELETE_TASK_FAILURE = 5001;
diff --git a/stats/enums/adservices/common/adservices_enums.proto b/stats/enums/adservices/common/adservices_enums.proto
index 95f923ce..ffd44f39 100644
--- a/stats/enums/adservices/common/adservices_enums.proto
+++ b/stats/enums/adservices/common/adservices_enums.proto
@@ -244,6 +244,7 @@ enum Command {
   COMMAND_DEV_SESSION = 9;  // Command to enable or disable adservices developer mode.
   COMMAND_SET_USER_CHOICES = 10;
   COMMAND_SET_MODULE_STATES = 11;
+  COMMAND_SET_ADS_PERSONALIZATION_STATUS = 12;
 
   // Custom audience commands: 101-200
   COMMAND_CUSTOM_AUDIENCE_VIEW = 101;
diff --git a/stats/enums/adservices/fledge/enums.proto b/stats/enums/adservices/fledge/enums.proto
index 486414f7..61429290 100644
--- a/stats/enums/adservices/fledge/enums.proto
+++ b/stats/enums/adservices/fledge/enums.proto
@@ -179,3 +179,10 @@ enum ReportingCallDestination {
   BUYER = 2;
   COMPONENT_SELLER = 3;
 }
+
+/** Enum representing the evictor used in an eviction for updateSignals calls. */
+enum SignalEvictor {
+  UNSPECIFIED_EVICTOR = 0;
+  FIFO_SIGNAL_EVICTOR = 1;
+  PRIORITIZED_FIFO_SIGNAL_EVICTOR = 2;
+}
\ No newline at end of file
diff --git a/stats/enums/app/settings/OWNERS b/stats/enums/app/settings/OWNERS
index dae5079b..a7dac509 100644
--- a/stats/enums/app/settings/OWNERS
+++ b/stats/enums/app/settings/OWNERS
@@ -1,2 +1,4 @@
 noshinmir@google.com
 akaustubh@google.com
+cipson@google.com
+zhibinliu@google.com
\ No newline at end of file
diff --git a/stats/enums/app/settings/settings_enums.proto b/stats/enums/app/settings/settings_enums.proto
index 7edd4d76..b5f7767e 100644
--- a/stats/enums/app/settings/settings_enums.proto
+++ b/stats/enums/app/settings/settings_enums.proto
@@ -2253,6 +2253,224 @@ enum Action {
     // OPEN: SUW Welcome Screen > Set up using another device
     // CATEGORY: SETTINGS
     ACTION_RESTORE_SIMPLE_VIEW_RESULT_IN_SUW = 2040;
+
+    // ACTION: Settings > Sound & vibration > Notification Volume
+    // CATEGORY: SETTINGS
+    ACTION_NOTIFICATION_VOLUME = 2041;
+
+    // ACTION: Settings > Sound & vibration > Alarm Volume
+    // CATEGORY: SETTINGS
+    ACTION_ALARM_VOLUME = 2042;
+
+    // ACTION: Settings > Sound & vibration > Dial pad tones
+    // CATEGORY: SETTINGS
+    ACTION_DIAL_PAD_TONE = 2043;
+
+    // ACTION: Settings > Sound & vibration > Screen locking sound
+    // CATEGORY: SETTINGS
+    ACTION_SCREEN_LOCKING_SOUND = 2044;
+
+    // ACTION: Settings > Sound & vibration > Charging sounds and vibration
+    // CATEGORY: SETTINGS
+    ACTION_CHARGING_SOUND = 2045;
+
+    // ACTION: Settings > Sound & vibration > Tap & click sounds
+    // CATEGORY: SETTINGS
+    ACTION_TOUCH_SOUND = 2046;
+
+    // ACTION: Settings > System > Gestures > Double press power button
+    // CATEGORY: SETTINGS
+    ACTION_DOUBLE_TAP_POWER_ENABLED = 2047;
+
+    // ACTION: Settings > System > Gestures > Double press power button
+    //                                      > Choose actions
+    // CATEGORY: SETTINGS
+    ACTION_DOUBLE_TAP_POWER_BUTTON_BEHAVIOR = 2048;
+
+    // Action: Settings > Connected devices > Pair new device > pair when audio sharing
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SETTINGS_BLUETOOTH_PAIR_IN_AUDIO_SHARING = 2049;
+
+    // Action: Settings > Connected devices > Pair new device > pair blocked when audio sharing
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SETTINGS_BLUETOOTH_PAIR_BLOCKED_IN_AUDIO_SHARING = 2050;
+
+    // Action: Add source to device to share audio
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_AUDIO_SHARING_ADD_SOURCE = 2051;
+
+    // Action: Remove source from device to leave audio sharing
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_AUDIO_SHARING_REMOVE_SOURCE = 2052;
+
+    // Action: Audio sharing supported device connected > Show notification to add source
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SHOW_ADD_SOURCE_NOTIFICATION = 2053;
+
+    // Action: Click cancel button on add source notification
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_CANCEL_ADD_SOURCE_NOTIFICATION = 2054;
+
+    // ACTION: Settings > Battery > Battery banner
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BATTERY_ANOMALY_TIP_SHOW = 2055;
+
+    // ACTION: Settings > Battery > Battery banner
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BATTERY_ANOMALY_TIP_DISMISS = 2056;
+
+    // ACTION: Settings > Battery > Battery banner
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BATTERY_ANOMALY_TIP_VIEW_SETTINGS = 2057;
+
+    // ACTION: Settings > Battery > Battery banner
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_BATTERY_ANOMALY_TIP_UPDATE_OPTIMIZATION_MODE = 2058;
+
+    // ACTION: Settings > Request ignore battery optimization dialog
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZE_FAIL_SHOW = 2059;
+
+    // ACTION: Settings > Request ignore battery optimization dialog
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZE_SHOW = 2060;
+
+    // ACTION: Settings > Request ignore battery optimization dialog
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZE_ALLOW = 2061;
+
+    // ACTION: Settings > Request ignore battery optimization dialog
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZE_DENY = 2062;
+
+    // ACTION: Settings > Request ignore battery optimization dialog
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_REQUEST_IGNORE_BATTERY_OPTIMIZE_DISMISS = 2063;
+
+    // ACTION: Settings > Parental controls > Manage your PIN option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_MANAGE_PIN = 2064;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Update recovery option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_UPDATE_RECOVERY = 2065;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Verify recovery option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_VERIFY_RECOVERY = 2066;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Add recovery option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_ADD_RECOVERY = 2067;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Forgot PIN option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_FORGOT_PIN = 2068;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Change PIN option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_CHANGE_PIN = 2069;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Delete PIN option
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_DELETE_PIN = 2070;
+
+    // ACTION: Settings > Sound & vibration > Docking sounds
+    // CATEGORY: SETTINGS
+    ACTION_DOCKING_SOUND = 2071;
+
+    // ACTION: Settings > Parental controls > Web content filters
+    //                                      > Allow all sites
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_ALLOW_ALL_SITES = 2072;
+
+    // ACTION: Settings > Parental controls > Web content filters
+    //                                      > Block explicit sites
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_BLOCK_EXPLICIT_SITES = 2073;
+
+    // ACTION: Settings > Parental controls > Web content filters
+    //                                      > Search results filter off
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_SEARCH_FILTER_OFF = 2074;
+
+    // ACTION: Settings > Parental controls > Web content filters
+    //                                      > Search results filter on
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_SEARCH_FILTER_ON = 2075;
+
+    // ACTION: Settings > Connected devices
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_OPEN_SETTINGS_CONNECTED_DEVICES = 2076;
+
+    // ACTION: Settings > Connected devices > Device details
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_OPEN_SETTINGS_DEVICE_DETAILS = 2077;
+
+    // Action: Settings > Connected devices > Connection preferences > Audio sharing > Audio stream
+    //         > Join a present source succeeded
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_AUDIO_STREAM_JOIN_PRESENT_SUCCEED = 2078;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Change PIN (or other options)
+    //                                      > on confirm current PIN screen
+    //                                      > click "more options/forgot PIN"
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_FORGOT_PIN_DURING_PIN_INVOCATION = 2079;
+
+    // ACTION: Settings > Parental controls > Manage your PIN
+    //                                      > Forgot PIN
+    //                                      > reset PIN succeeded
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_PIN_RESET_SUCCEED = 2080;
+
+    // ACTION: Settings > Parental controls > Supervision main toggle off
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_MAIN_TOGGLE_OFF = 2081;
+
+    // ACTION: Settings > Parental controls > Supervision main toggle on
+    // CATEGORY: SETTINGS
+    // OS: V
+    ACTION_SUPERVISION_MAIN_TOGGLE_ON = 2082;
 }
 
 /**
@@ -5136,12 +5354,12 @@ enum PageId {
     // OS: V
     DIALOG_START_AUDIO_SHARING = 2049;
 
-    // Open: Settings > Connected devices > Stop audio sharing dialog
+    // Open: Settings > Dialog to stop audio sharing
     // CATEGORY: SETTINGS
     // OS: V
     DIALOG_STOP_AUDIO_SHARING = 2050;
 
-    // Open: Settings > Connected devices > Change device dialog in audio sharing
+    // Open: Settings > Dialog to change device in audio sharing
     // CATEGORY: SETTINGS
     // OS: V
     DIALOG_AUDIO_SHARING_SWITCH_DEVICE = 2051;
@@ -5320,9 +5538,7 @@ enum PageId {
     // OS: V
     DIALOG_AUDIO_SHARING_CONFIRMATION = 2085;
 
-    // OPEN: Settings > Connected devices or
-    //       Settings > Connected devices > Connection preferences > Audio sharing > Toggle on
-    //       > Add device to audio sharing dialog
+    // OPEN: Settings > Dialog to add device to audio sharing
     // CATEGORY: SETTINGS
     // OS: V
     DIALOG_AUDIO_SHARING_ADD_DEVICE = 2086;
@@ -5557,7 +5773,7 @@ enum PageId {
     // DEPRECATED: This was added as page id by mistake, moved to Action.ACTION_WIFI_HOTSPOT
     ACTION_WIFI_HOTSPOT_TOGGLE = 2138 [deprecated = true];
 
-    // Settings -> Supervision
+    // Settings -> Parental controls
     // CATEGORY: SETTINGS
     SUPERVISION_DASHBOARD = 2139;
 
@@ -5656,7 +5872,86 @@ enum PageId {
 
     // OPEN: Settings > Connected devices
     // CATEGORY: SETTINGS
-    SETTINGS_CONNECTED_DEVICES_ENTRYPOINT = 2159;
+    SETTINGS_CONNECTED_DEVICES_ENTRYPOINT = 2159 [deprecated = true];
+
+    // OPEN: Settings -> Accessibility -> Accessibility Scanner
+    // CATEGORY: SETTINGS
+    ACCESSIBILITY_SCANNER = 2160;
+
+    // OPEN: Settings -> Accessibility -> Action Blocks
+    // CATEGORY: SETTINGS
+    ACTION_BLOCKS = 2161;
+
+    // OPEN: Settings -> Accessibility -> Magnifier
+    // CATEGORY: SETTINGS
+    MAGNIFIER = 2162;
+
+    // OPEN: Settings -> Accessibility -> Project Relate
+    // CATEGORY: SETTINGS
+    PROJECT_RELATE = 2163;
+
+    // The dialog will show when turning on Settings > Accessibility > Hearing devices > HAC
+    // CATEGORY: SETTINGS
+    DIALOG_HAC_DISCLAIMER = 2164;
+
+    // Open: Settings > Connected devices > Pair new device
+    //                > Pair an incompatible device for audio sharing
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_AUDIO_SHARING_INCOMPATIBLE_DEVICE = 2165;
+
+    // Open: Settings > Connected devices > Connection preferences > Audio sharing > Start failed
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_AUDIO_SHARING_START_WITH_ERROR = 2166;
+
+    // Open: Settings > Connected devices > Connection preferences > Audio sharing >
+    //                > Dialog to indicate starting sharing is in progress
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_AUDIO_SHARING_IN_PROGRESS = 2167;
+
+    // Open: Settings > Connected devices > Connection preferences > Audio sharing > Toggle on
+    //                > Main dialog to add device to audio sharing when toggle on
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_AUDIO_SHARING_MAIN = 2168;
+
+    // Open: Settings > Handle device connected during audio sharing
+    // CATEGORY: SETTINGS
+    // OS: V
+    AUDIO_SHARING_JOIN_HANDLER = 2169;
+
+    // ACTION: show dialog to request Ignore battery optimize (action intent android.settings.REQUEST_IGNORE_BATTERY_OPTIMIZATIONS)
+    // CATEGORY: SETTINGS
+    // OS: V
+    DIALOG_REQUEST_IGNORE_BATTERY_OPTIMIZE = 2170;
+
+    // Settings > Parental controls > Manage your PIN
+    // CATEGORY: SETTINGS
+    SUPERVISION_MANAGE_PIN_SCREEN = 2171;
+
+    // Open: Settings > System > About phone > EID
+    // CATEGORY: SETTINGS
+    // OS: B
+    DIALOG_EID_INFO = 2172;
+
+    // OPEN: Settings > Battery > Adaptive battery
+    // CATEGORY: SETTINGS
+    // OS: B
+    FUELGAUGE_ADAPTIVE_BATTERY = 2173;
+
+    // Settings > Parental controls > Web content filters
+    // CATEGORY: SETTINGS
+    SUPERVISION_WEB_CONTENT_FILTERS = 2174;
+
+    // OPEN: Settings > Display > HDR brightness
+    // CATEGORY: SETTINGS
+    HDR_BRIGHTNESS_SETTINGS = 2175;
+
+    // OPEN: Settings > Display > Always-on displays
+    // CATEGORY: SETTINGS
+    AMBIENT_DISPLAY_ALWAYS_ON = 2176;
 }
 
 // Battery Saver schedule types.
@@ -5732,3 +6027,60 @@ enum ExtApiResultType {
     RESULT_FAILURE_RESTRICTED = 10;
     RESULT_FAILURE_REQUIRE_USER_CONSENT = 11;
 }
+
+// The biometrics modality
+enum Modality {
+    MODALITY_UNKNOWN = 0;
+    MODALITY_FINGERPRINT = 1;
+    MODALITY_FACE = 2;
+}
+
+// The source that trigger the biometrics onboarding flow
+enum FromSource {
+    FROM_UNKNOWN = 0;
+    FROM_SUW = 1;
+    FROM_SETTINGS = 2;
+    FROM_SAFETY_ISSUE = 3;
+    FROM_FRR_NOTIFICATION = 4;
+}
+
+// The result code of the onboarding flow
+enum OnboardingResult {
+    RESULT_UNKNOWN = 0;
+    RESULT_COMPLETED = 1;
+    RESULT_SKIP = 2;
+    RESULT_TIMEOUT = 3;
+    RESULT_CANCEL = 4;
+}
+
+// Screens during the biometric onboarding flow
+enum OnboardingScreen {
+    SCREEN_UNKNOWN = 0;
+    SCREEN_INTRO = 1;
+    SCREEN_EDUCATION = 2;
+    SCREEN_ENROLLING = 3;
+    SCREEN_CONFIRMATION = 4;
+    SCREEN_CAPYBARA_EDUCATION = 5;
+    SCREEN_CAPYBARA_SCANNER = 6;
+}
+
+// Actions during the biometrics onboarding flow
+enum OnboardingAction {
+    ACTION_ONBOARDING_UNKNOWN = 0;
+    ACTION_NEXT = 1;
+    ACTION_SKIP = 2;
+    ACTION_CANCEL = 3;
+    ACTION_ADD_ANOTHER_FINGERPRINT = 4;
+    ACTION_SETUP_CAPYBARA = 5;
+    ACTION_CAPYBARA_SCAN = 6;
+    ACTION_CAPYBARA_NO_SCAN = 7;
+    ACTION_SETUP_FOR_FACE_A11Y = 8;
+    ACTION_FACE_A11Y_ON = 9;
+    ACTION_FACE_A11Y_OFF = 10;
+    ACTION_FACE_GAZE_ON = 11;
+    ACTION_FACE_GAZE_OFF = 12;
+    ACTION_FACE_SKIP_LOCK_SCREEN_ON = 13;
+    ACTION_FACE_SKIP_LOCK_SCREEN_OFF = 14;
+    ACTION_FACE_ENROLL_TRY_AGAIN = 15;
+    ACTION_FACE_TRY_FAST_ENROLL = 16;
+}
diff --git a/stats/enums/app/wearservices/OWNERS b/stats/enums/app/wearservices/OWNERS
index 3b4b182f..ffea5157 100644
--- a/stats/enums/app/wearservices/OWNERS
+++ b/stats/enums/app/wearservices/OWNERS
@@ -1,4 +1,3 @@
-shijianli@google.com
 krskad@google.com
 xjchen@google.com
 yashasvig@google.com
diff --git a/stats/enums/app/wearservices/wearservices_enums.proto b/stats/enums/app/wearservices/wearservices_enums.proto
index c7e2325d..6e902b68 100644
--- a/stats/enums/app/wearservices/wearservices_enums.proto
+++ b/stats/enums/app/wearservices/wearservices_enums.proto
@@ -580,7 +580,7 @@ enum NotificationFlowComponent {
  * API names are based on:
  * vendor/google_clockwork_partners/packages/WearServices/src/com/google/wear/services/notification/api/NotificationApiImpl.java
  *
- * Next ID: 18
+ * Next ID: 20
  */
 enum NotificationApiName {
   // Unknown value for backward compatibility
@@ -602,8 +602,10 @@ enum NotificationApiName {
 
   NOTIFICATION_API_NAME_GET_NOTIFICATION_COUNT_DATA = 10;
 
+  NOTIFICATION_API_NAME_CANCEL_ALL = 18;
   NOTIFICATION_API_NAME_DISMISS_ALL = 11;
   NOTIFICATION_API_NAME_DISMISS_MULTIPLE_FROM_UI = 12;
+  NOTIFICATION_API_NAME_MARK_ITEMS_READ = 19;
 
   NOTIFICATION_API_NAME_IS_APP_MUTED = 13;
   NOTIFICATION_API_NAME_GET_MUTED_APPS = 14;
diff --git a/stats/enums/app/wearsettings/OWNERS b/stats/enums/app/wearsettings/OWNERS
index b3a1bf4d..7ef64c49 100644
--- a/stats/enums/app/wearsettings/OWNERS
+++ b/stats/enums/app/wearsettings/OWNERS
@@ -5,6 +5,5 @@ mtsmall@google.com
 
 # Core OS Team
 garvitnarang@google.com
-shreerag@google.com
 yeabkal@google.com
 
diff --git a/stats/enums/app/wearsettings/wearsettings_enums.proto b/stats/enums/app/wearsettings/wearsettings_enums.proto
index d2842705..fd3c68f4 100644
--- a/stats/enums/app/wearsettings/wearsettings_enums.proto
+++ b/stats/enums/app/wearsettings/wearsettings_enums.proto
@@ -36,7 +36,7 @@ enum Action {
 }
 
 // IDs for settings UI elements.
-// Next ID: 531
+// Next ID: 532
 enum ItemId {
   // An unknown settings item. This may be set if no preference key is mapped to an enum value or as
   // a catch-all for values not yet added to this proto file.
@@ -104,6 +104,7 @@ enum ItemId {
   AUDIO_BALANCE_LEFT_RIGHT_TEXT = 411;
   BATTERY_SAVER_AUTO_BATTERY_SAVER_ENABLED = 324;
   BATTERY_SAVER_BATTERY_SAVER = 315;
+  BATTERY_SHOW_PERCENTAGE = 531;
   BLUETOOTH_DEVICE_TYPE = 527;
   BLUETOOTH_ENABLED = 135;
   BLUETOOTH_HFP = 136;
diff --git a/stats/enums/app_shared/app_enums.proto b/stats/enums/app_shared/app_enums.proto
index 1bfd8e92..8bd7c668 100644
--- a/stats/enums/app_shared/app_enums.proto
+++ b/stats/enums/app_shared/app_enums.proto
@@ -38,13 +38,8 @@ enum AppTransitionReasonEnum {
 }
 
 // ActivityManager.java PROCESS_STATEs
-// Next tag: 1021
 enum ProcessStateEnum {
-    // Unlike the ActivityManager PROCESS_STATE values, the ordering and numerical values
-    // here are completely fixed and arbitrary. Order is irrelevant.
-    // No attempt need be made to keep them in sync.
-    // The values here must not be modified. Any new process states can be appended to the end.
-
+    PROCESS_STATE_UNSPECIFIED = 0;
     // Process state that is unknown to this proto file (i.e. is not mapped
     // by ActivityManager.processStateAmToProto()). Can only happen if there's a bug in the mapping.
     PROCESS_STATE_UNKNOWN_TO_PROTO = 998;
@@ -133,6 +128,7 @@ enum OomChangeReasonEnum {
     OOM_ADJ_REASON_COMPONENT_DISABLED = 22;
     OOM_ADJ_REASON_FOLLOW_UP = 23;
     OOM_ADJ_REASON_RECONFIGURATION = 24;
+    OOM_ADJ_REASON_SERVICE_BINDER_CALL = 25;
 }
 
 /**
@@ -203,7 +199,7 @@ enum AppExitReasonCode {
      * user clicked the "Force stop" button of the application in the Settings,
      * or swiped away the application from Recents.
      * <p>
-     * Prior to {@link android.os.Build.VERSION_CODES#UPSIDE_DOWN_CAKE}, one of the uses of this 
+     * Prior to {@link android.os.Build.VERSION_CODES#UPSIDE_DOWN_CAKE}, one of the uses of this
      * reason was indicate that an app was killed due to it being updated or any of its component states
      * have changed without {@link android.content.pm.PackageManager#DONT_KILL_APP}
      */
diff --git a/stats/enums/app_shared/app_op_enums.proto b/stats/enums/app_shared/app_op_enums.proto
index 58bad2d0..f725b85b 100644
--- a/stats/enums/app_shared/app_op_enums.proto
+++ b/stats/enums/app_shared/app_op_enums.proto
@@ -187,4 +187,8 @@ enum AppOpEnum {
     APP_OP_HEAD_TRACKING = 160;
     APP_OP_SCENE_UNDERSTANDING_COARSE = 161;
     APP_OP_SCENE_UNDERSTANDING_FINE = 162;
+    APP_OP_POST_PROMOTED_NOTIFICATIONS = 163;
+    APP_OP_SYSTEM_APPLICATION_OVERLAY = 164;
+    APP_OP_READ_CELL_IDENTITY = 165;
+    APP_OP_READ_CELL_INFO = 166;
 }
diff --git a/stats/enums/art/common_enums.proto b/stats/enums/art/common_enums.proto
index fdfd8730..db620039 100644
--- a/stats/enums/art/common_enums.proto
+++ b/stats/enums/art/common_enums.proto
@@ -122,7 +122,8 @@ enum ArtThreadType {
   ART_THREAD_BACKGROUND = 2;
 }
 
-// Indicates support for userfaultfd and minor fault mode.
+// DEPRECATED - Used to indicate support for userfaultfd and minor fault mode.
+// Deprecated in May 2025 as the corresponding filter is no longer needed.
 enum ArtUffdSupport {
   ART_UFFD_SUPPORT_UNKNOWN = 0;
   ART_UFFD_SUPPORT_UFFD_NOT_SUPPORTED = 1;
diff --git a/stats/enums/bluetooth/OWNERS b/stats/enums/bluetooth/OWNERS
index 3098972c..64a6b759 100644
--- a/stats/enums/bluetooth/OWNERS
+++ b/stats/enums/bluetooth/OWNERS
@@ -1,3 +1,2 @@
 girardier@google.com
-ahujapalash@google.com
-rghanti@google.com
\ No newline at end of file
+rghanti@google.com
diff --git a/stats/enums/bluetooth/enums.proto b/stats/enums/bluetooth/enums.proto
index aa9ad08f..aced508f 100644
--- a/stats/enums/bluetooth/enums.proto
+++ b/stats/enums/bluetooth/enums.proto
@@ -813,7 +813,7 @@ enum State {
   SCO_VOICE_RECOGNITION_HEADSET_END = 166;
   SCO_VOICE_RECOGNITION_HEADSET_TIMEOUT = 167;
   AUDIO_PORT_START_STREAM = 168;
-  AUDIO_PORT_STOP_STREAM = 169;
+  AUDIO_PORT_SUSPEND_STREAM = 169;
   AUDIO_PROVIDER_STREAM_STARTED = 170;
 }
 
@@ -860,3 +860,83 @@ enum BtaStatus {
   BTA_STATUS_FAILURE = 2;
   BTA_STATUS_BUSY = 3;
 }
+
+enum ChannelSoundingType {
+  CS_UNSPECIFIED = 0;
+  CS_BT_CORE60 = 1;
+}
+
+enum ChannelSoundingStopReason {
+  REASON_UNSPECIFIED = 0;
+  REASON_LOCAL_APP_REQUEST = 1;
+  REASON_HAL_OPEN_FAILED = 2;
+  REASON_CONFIG_ID_RUN_OUT =3;
+  REASON_LOCAL_CS_STACK_NOT_READY = 4;
+  REASON_LE_DISCONNECT = 5;
+  REASON_VENDOR_SPECIFIC_REPLY_FAILED = 6;
+  REASON_B2B_CONFLICT = 7;
+  REASON_REMOTE_TIMEOUT = 8;
+  REASON_PROCEDURE_ENABLE_COMMAND_STATUS_ERROR = 9;
+  REASON_READ_REMOTE_CAP_COMPLETE_FAILED = 10;
+  REASON_SET_DEFAULT_SETTINGS_COMPLETE_FAILED = 11;
+  REASON_SECURITY_ENABLE_COMPLETE_FAILED = 12;
+  REASON_CREATE_CONFIG_COMPLETE_FAILED = 13;
+  REASON_SECURITY_ENABLE_TIMEOUT = 14;
+  REASON_SET_PROCEDURE_PARAMETERS_COMPLETE_FAILED = 15;
+  REASON_PROCEDURE_ENABLE_COMPLETE_FAILED = 16;
+  REASON_REMOTE_PROCEDURE_DATA_BROKEN = 17;
+  REASON_READ_REMOTE_CAP_COMMAND_STATUS_ERROR = 18;
+  REASON_SECURITY_ENABLE_COMMAND_STATUS_ERROR = 19;
+  REASON_CREATE_CONFIG_COMMAND_STATUS_ERROR = 20;
+  REASON_RAS_REMOTE_NOT_SUPPORT = 21;
+  REASON_RAS_FATAL_ERROR = 22;
+}
+
+// see 10.11.1 of BLUETOOTH CORE SPECIFICATION Version 6.0 | Vol 3, Part C
+enum ChannelSoundingSecurityLevel {
+  LEVEL_UNSPECIFIED = 0;
+  LEVEL_ONE = 1;
+  LEVEL_TWO = 2;
+  LEVEL_THREE = 3;
+  LEVEL_FOUR = 4;
+}
+
+enum BluetoothPbapClientContactDownloadStatus {
+  DOWNLOAD_STATUS_UNSPECIFIED = 0;
+  DOWNLOAD_STATUS_CANCELLED = 1;
+  DOWNLOAD_STATUS_COMPLETED = 2;
+  DOWNLOAD_STATUS_ERROR = 3;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_BAD_REQUEST = 4;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_UNAUTHORIZED = 5;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_FORBIDDEN = 6;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_NOT_FOUND = 7;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_NOT_ACCEPTABLE = 8;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_TIMEOUT = 9;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_PRECON_FAILED = 10;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_INTERNAL_ERROR = 11;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_NOT_IMPLEMENTED = 12;
+  DOWNLOAD_STATUS_ERROR_OBEX_HTTP_UNAVAILABLE = 13;
+}
+
+enum BluetoothPbapClientPhonebookDownloadStatus {
+  STATUS_UNSPECIFIED = 0;
+  STATUS_SUCCESS = 1;                   // Supported and downloaded
+  STATUS_SUCCESS_CACHE_INVALIDATED = 2; // Cached copy was invalidated
+  STATUS_NOT_SUPPORTED = 3;             // Remote device does not support
+  STATUS_SUPPORTED_NOT_REQUESTED = 4;   // Remote device supports but not requested
+  STATUS_CACHED = 5;                    // Contacts were cached
+  STATUS_ERROR = 6;
+}
+
+enum BluetoothPbapClientPhonebookType {
+  PHONEBOOK_UNSPECIFIED = 0;
+  PHONEBOOK_LOCAL = 1;     // Device phonebook
+  PHONEBOOK_FAVORITES = 2; // Contacts marked as favorite
+  PHONEBOOK_MCH = 3;       // Missed calls
+  PHONEBOOK_ICH = 4;       // Incoming calls
+  PHONEBOOK_OCH = 5;       // Outgoing calls
+  PHONEBOOK_SIM = 6;       // SIM stored phonebook
+  PHONEBOOK_SIM_MCH = 7;   // SIM stored missed calls
+  PHONEBOOK_SIM_ICH = 8;   // SIM stored incoming calls
+  PHONEBOOK_SIM_OCH = 9;   // SIM stored outgoing calls
+}
diff --git a/stats/enums/conscrypt/ct/enums.proto b/stats/enums/conscrypt/ct/enums.proto
index 78e7c2ea..24906703 100644
--- a/stats/enums/conscrypt/ct/enums.proto
+++ b/stats/enums/conscrypt/ct/enums.proto
@@ -15,6 +15,7 @@ enum LogListStatus {
 enum LogListCompatibilityVersion {
     COMPAT_VERSION_UNKNOWN = 0;
     COMPAT_VERSION_V1 = 1;
+    COMPAT_VERSION_V2 = 2;
 }
 enum VerificationResult {
     RESULT_UNKNOWN = 0;
@@ -32,4 +33,5 @@ enum VerificationReason {
     REASON_SDK_TARGET_DEFAULT_ENABLED = 2;
     REASON_NSCONFIG_APP_OPT_IN = 3;
     REASON_NSCONFIG_DOMAIN_OPT_IN = 4;
+    REASON_DRY_RUN = 5;
 }
diff --git a/stats/enums/corenetworking/certificatetransparency/enums.proto b/stats/enums/corenetworking/certificatetransparency/enums.proto
index bcedbc3c..54e28f8a 100644
--- a/stats/enums/corenetworking/certificatetransparency/enums.proto
+++ b/stats/enums/corenetworking/certificatetransparency/enums.proto
@@ -4,7 +4,7 @@ package android.os.statsd.corenetworking.certificatetransparency;
 
 option java_package = "com.android.os.corenetworking.certificatetransparency";
 
-// Next ID: 18
+// Next ID: 19
 enum LogListUpdateStatus {
     STATUS_UNKNOWN = 0;
     // Log list was successfully updated.
@@ -41,6 +41,8 @@ enum LogListUpdateStatus {
     FAILURE_PUBLIC_KEY_NOT_ALLOWED = 16;
     // Public key is invalid (e.g. wrong format).
     FAILURE_PUBLIC_KEY_INVALID = 17;
+    // Unable to read the downloaded signature or log list file.
+    FAILURE_UNABLE_TO_READ_FILE = 18;
     // Device is waiting for a Wi-Fi connection to proceed with the download, as
     // it exceeds the size limit for downloads over the mobile network.
     PENDING_WAITING_FOR_WIFI = 11;
diff --git a/stats/enums/corenetworking/connectivity/enums.proto b/stats/enums/corenetworking/connectivity/enums.proto
index 78a880a2..891a743b 100644
--- a/stats/enums/corenetworking/connectivity/enums.proto
+++ b/stats/enums/corenetworking/connectivity/enums.proto
@@ -104,4 +104,34 @@ enum TerribleErrorType {
   // Indicate the error state that tethering was started with a placeholder request (i.e. we
   // couldn't find a pending request for the link layer event).
   TYPE_TETHER_WITH_PLACEHOLDER_REQUEST = 8;
+  // Indicate the error state that the ConnectivityService attempts to clean up
+  // the bypassing private DNS permission for a delegate UID, however, the DNS
+  // resolver doesn't know about this UID and setAllowBypassPrivateDnsOnNetwork API
+  // returns ENOENT.
+  TYPE_DISALLOW_BYPASS_PRIVATE_DNS_FOR_DELEGATE_UID_ENOENT = 9;
+  // Indicate the error state that the ConnectivityService attempts to
+  // set to allow bypassing the VPN permission for a delegate UID, however,
+  // allowBypassVpnOnNetwork API returns a non EEXIST error.
+  TYPE_ALLOW_BYPASS_VPN_FOR_DELEGATE_UID_ERROR = 10;
+  // Indicate the error state that the ConnectivityService attempts to
+  // set to allow bypassing the private DNS permission for a delegate UID,
+  // however, setAllowBypassPrivateDnsOnNetwork API returns a non EEXIST
+  // error.
+  TYPE_ALLOW_BYPASS_PRIVATE_DNS_FOR_DELEGATE_UID_ERROR = 11;
+  // Indicate WiFi tethering was enabled with an interface name that maps to a different type.
+  TYPE_TETHER_WIFI_TYPE_MISMATCH = 12;
+  // Indicate WiFi P2P tethering was enabled with an interface name that maps to a different type.
+  TYPE_TETHER_WIFIP2P_TYPE_MISMATCH = 13;
+}
+
+// Type of critical bytes event.
+enum CriticalBytesEventType {
+  CRITICAL_BYTES_EVENT_TYPE_UNKNOWN = 0;
+
+  /**
+   * Reports tx/rx bytes generated on satellite networks.
+   * Logged when the last satellite network disconnects.
+   */
+  CRITICAL_BYTES_EVENT_TYPE_SATELLITE_COARSE_TX_USAGE = 1;
+  CRITICAL_BYTES_EVENT_TYPE_SATELLITE_COARSE_RX_USAGE = 2;
 }
diff --git a/stats/enums/corenetworking/platform/enums.proto b/stats/enums/corenetworking/platform/enums.proto
index af2a3fdc..42e15c48 100644
--- a/stats/enums/corenetworking/platform/enums.proto
+++ b/stats/enums/corenetworking/platform/enums.proto
@@ -23,21 +23,9 @@ option java_multiple_files = true;
 
 enum IpType {
   IT_UNKNOWN = 0;
-  IT_IPv4 = 1;
-  IT_IPv6 = 2;
-  IT_IPv4v6 = 3;
-}
-
-enum EncapType {
-  ET_UNKNOWN = 0;
-  ET_UDP = 1;
-  ET_ESP = 2;
-}
-
-enum ConnectionState {
-  CS_UNKNOWN = 0;
-  CS_CONNECTED = 1;     // vpn connection is connected
-  CS_DISCONNECTED = 2;   // vpn connection is disconnected
+  IT_IPV4 = 1;
+  IT_IPV6 = 2;
+  IT_IPV4V6 = 3;
 }
 
 enum VpnType {
@@ -49,12 +37,6 @@ enum VpnType {
   TYPE_VPN_OEM = 4;
 }
 
-enum RecoverAction {
-  RA_NONE = 0;
-  RA_MOBIKE = 1;
-  RA_SESSION_RESET = 2;
-}
-
 enum VpnProfileType {
   TYPE_UNKNOWN = 0;
   TYPE_PPTP = 1;
@@ -68,30 +50,3 @@ enum VpnProfileType {
   TYPE_IKEV2_IPSEC_RSA = 9;
   TYPE_IKEV2_FROM_IKE_TUN_CONN_PARAMS = 10;
 }
-
-enum ErrorCode {
-  EC_UNKNOWN = 0;
-  EC_NO_ERROR = 1;
-  // ErrorType in IkeProtocolException.java
-  EC_UNSUPPORTED_CRITICAL_PAYLOAD = 2;
-  EC_INVALID_IKE_SPI = 3;
-  EC_INVALID_MAJOR_VERSION = 4;
-  EC_INVALID_SYNTAX = 5;
-  EC_INVALID_MESSAGE_ID = 6;
-  EC_NO_PROPOSAL_CHOSEN = 7;
-  EC_INVALID_KE_PAYLOAD = 8;
-  EC_AUTHENTICATION_FAILED = 9;
-  EC_SINGLE_PAIR_REQUIRED = 10;
-  EC_NO_ADDITIONAL_SAS = 11;
-  EC_INTERNAL_ADDRESS_FAILURE = 12;
-  EC_FAILED_CP_REQUIRED = 13;
-  EC_TS_UNACCEPTABLE = 14;
-  EC_INVALID_SELECTORS = 15;
-  EC_TEMPORARY_FAILURE = 16;
-  EC_CHILD_SA_NOT_FOUND = 17;
-  // ERROR_CODE_* in VpnManager.java
-  EC_NETWORK_UNKNOWN_HOST = 18;
-  EC_NETWORK_PROTOCOL_TIMEOUT = 19;
-  EC_NETWORK_LOST = 20;
-  EC_NETWORK_IO = 21;
-}
diff --git a/stats/enums/federatedcompute/enums.proto b/stats/enums/federatedcompute/enums.proto
index 04da1d22..29bc07f7 100644
--- a/stats/enums/federatedcompute/enums.proto
+++ b/stats/enums/federatedcompute/enums.proto
@@ -21,7 +21,7 @@ option java_outer_classname = "FederatedComputeProtoEnums";
 option java_multiple_files = true;
 
 // Enum used to track federated computation job stages.
-// Next Tag: 87
+// Next Tag: 89
 enum TrainingEventKind {
   // Undefined value.
   TRAIN_UNDEFINED = 0;
@@ -112,6 +112,8 @@ enum TrainingEventKind {
   TRAIN_DOWNLOAD_TURNED_AWAY_NO_TASK_AVAILABLE = 70;
   TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHORIZED = 71;
   TRAIN_DOWNLOAD_TURNED_AWAY_UNAUTHENTICATED = 72;
+  TRAIN_DOWNLOAD_TURNED_AWAY_CLIENT_VERSION_MISMATCH = 87;
+  TRAIN_DOWNLOAD_TURNED_AWAY_NO_ACTIVE_TASK_EXISTS = 88;
 
   // Client started eligibility eval computation.
   TRAIN_ELIGIBILITY_EVAL_COMPUTATION_STARTED = 19;
diff --git a/stats/enums/healthfitness/ui/enums.proto b/stats/enums/healthfitness/ui/enums.proto
index a3c97b90..2ca24e38 100644
--- a/stats/enums/healthfitness/ui/enums.proto
+++ b/stats/enums/healthfitness/ui/enums.proto
@@ -426,7 +426,42 @@ enum ElementId {
     CANCEL_WRITE_HEALTH_RECORDS_BUTTON = 287;
     // End of PHR
 
-    // Next available: 298;
+    // Start of Connect Apps Onboarding
+    // Home page banners
+    ZERO_APPS_CONNECTED_BANNER = 298;
+    ZERO_APPS_CONNECTED_BANNER_DISMISS_BUTTON = 299;
+    ZERO_APPS_CONNECTED_BANNER_SET_UP_BUTTON = 300;
+
+    ONE_APP_CONNECTED_BANNER = 301;
+    ONE_APP_CONNECTED_BANNER_DISMISS_BUTTON = 302;
+    ONE_APP_CONNECTED_BANNER_SET_UP_BUTTON = 303;
+
+    APP_WITH_ONBOARDING_BUTTON = 304;
+    APP_WITHOUT_ONBOARDING_BUTTON = 305;
+    // Connect first two apps onboarding page
+    CONNECT_FIRST_TWO_APPS_ONBOARDING_SET_UP_LATER_BUTTON = 306;
+
+    // Connect second app onboarding page
+    CONNECT_SECOND_APP_ONBOARDING_SET_UP_LATER_BUTTON = 307;
+    ONBOARDING_CONNECTED_APP_BUTTON = 317;
+
+    // Almost done page
+    ONBOARDING_APP_BUTTON = 308;
+    ONBOARDING_DONE_BUTTON = 309;
+
+    // Fitness app onboarding page
+    FITNESS_APP_ONBOARDING_BACK_BUTTON = 310;
+    FITNESS_APP_ONBOARDING_DONE_BUTTON = 311;
+    FITNESS_APP_ONBOARDING_ALLOW_ALL_BUTTON = 312;
+    FITNESS_APP_ONBOARDING_PERMISSION_BUTTON = 313;
+    FITNESS_APP_ONBOARDING_LEARN_MORE_LINK = 314;
+    FITNESS_APP_ONBOARDING_PRIVACY_POLICY_LINK = 315;
+
+    MORE_ABOUT_HEALTH_CONNECT_BUTTON = 316;
+
+    // End of Connect Apps Onboarding
+
+    // Next available: 318;
 }
 
 enum PageId {
@@ -496,7 +531,13 @@ enum PageId {
     SETTINGS_MANAGE_MEDICAL_APP_PERMISSIONS_PAGE = 54;
     REQUEST_WRITE_MEDICAL_PERMISSION_PAGE = 55;
 
-    // Next available: 56;
+    // Connect Apps Onboarding
+    CONNECT_TWO_APPS_ONBOARDING_PAGE = 56;
+    CONNECT_ONE_APP_ONBOARDING_PAGE = 57;
+    ALMOST_DONE_PAGE = 58;
+    FITNESS_APP_ONBOARDING_PAGE = 59;
+
+    // Next available: 60;
 }
 
 enum Action {
@@ -514,3 +555,18 @@ enum Source {
     SOURCE_QUICK_SETTINGS = 3;
     SOURCE_MAIN_ACTION = 4;
 }
+
+// Unique notification name for each type of notification sent from Health Connect
+enum NotificationId {
+    NOTIFICATION_ID_UNKNOWN = 0;
+    NOTIFICATION_ID_ZERO_APPS_CONNECTED = 1;
+    NOTIFICATION_ID_ONE_APP_CONNECTED = 2;
+}
+
+enum NotificationAction {
+    NOTIFICATION_ACTION_UNKNOWN = 0;
+    NOTIFICATION_ACTION_SENT = 1;
+    NOTIFICATION_ACTION_DISMISSED = 2;
+    NOTIFICATION_ACTION_CLICKED = 3;
+    NOTIFICATION_ACTION_CHANNEL_BLOCKED = 4;
+}
diff --git a/stats/enums/jank/enums.proto b/stats/enums/jank/enums.proto
index f81cd79d..2c6164a1 100644
--- a/stats/enums/jank/enums.proto
+++ b/stats/enums/jank/enums.proto
@@ -144,6 +144,13 @@ enum InteractionType {
     DEFAULT_TASK_TO_TASK_ANIMATION = 128;
     DESKTOP_MODE_MOVE_WINDOW_TO_DISPLAY = 129;
     STATUS_BAR_APP_RETURN_TO_CALL_CHIP = 130;
+    NOTIFICATIONS_ANIMATED_ACTION = 131;
+    LPP_ASSIST_INVOCATION_EFFECT = 132;
+    WEAR_CAROUSEL_SCROLL_JANK = 133;
+    WEAR_CAROUSEL_FLING_JANK = 134;
+    WEAR_CAROUSEL_SWIPE_JANK = 135;
+    WEAR_QSS_TRAY_OPEN = 136;
+    WEAR_NOTIFICATION_TRAY_OPEN = 137;
 
     reserved 2;
     reserved 73 to 78; // For b/281564325.
@@ -208,4 +215,5 @@ enum ActionType {
     ACTION_DESKTOP_MODE_ENTER_APP_HANDLE_DRAG = 34;
     ACTION_DESKTOP_MODE_ENTER_APP_HANDLE_MENU = 35;
     ACTION_DESKTOP_MODE_EXIT_MODE = 36;
+    ACTION_DESKTOP_MODE_EXIT_MODE_ON_LAST_WINDOW_CLOSE = 37;
 }
diff --git a/stats/enums/memory/enums.proto b/stats/enums/memory/enums.proto
index 34a0138c..c28a7d1b 100644
--- a/stats/enums/memory/enums.proto
+++ b/stats/enums/memory/enums.proto
@@ -24,7 +24,7 @@ option java_multiple_files = true;
 /**
  * Result of zram writeback attempt.
  *
- * Next tag: 11
+ * Next tag: 12
  */
 enum ZramWritebackResult {
     WRITEBACK_UNSPECIFIED = 0;
@@ -38,12 +38,13 @@ enum ZramWritebackResult {
     WRITEBACK_INVALID_LIMIT = 8;
     WRITEBACK_ACCESS_WRITEBACK_LIMIT_FAIL = 9;
     WRITEBACK_LOAD_STATS_FAIL = 10;
+    WRITEBACK_TRY_MARK_IDLE_AGAIN = 11;
 }
 
 /**
  * Result of zram recompression attempt.
  *
- * Next tag: 7
+ * Next tag: 8
  */
 enum ZramRecompressionResult {
     RECOMPRESSION_UNSPECIFIED = 0;
@@ -53,6 +54,7 @@ enum ZramRecompressionResult {
     RECOMPRESSION_CALCULATE_IDLE_FAIL = 4;
     RECOMPRESSION_MARK_IDLE_FAIL = 5;
     RECOMPRESSION_TRIGGER_FAIL = 6;
+    RECOMPRESSION_TRY_MARK_IDLE_AGAIN = 7;
 }
 
 /**
diff --git a/stats/enums/notification/enums.proto b/stats/enums/notification/enums.proto
index dba6b2ad..8c122305 100644
--- a/stats/enums/notification/enums.proto
+++ b/stats/enums/notification/enums.proto
@@ -23,7 +23,7 @@ option java_multiple_files = true;
 option java_outer_classname = "NotificationProtoEnums";
 
 /**
- * Enum used in NotificationBundlePreferences.
+ * Enum used in NotificationAdjustmentPreferences.
  * Keep in sync with frameworks/base/core/java/android/service/notification/Adjustment.java#Types
  */
 enum BundleTypes {
@@ -32,4 +32,17 @@ enum BundleTypes {
     TYPE_SOCIAL_MEDIA = 2;
     TYPE_NEWS = 3;
     TYPE_CONTENT_RECOMMENDATION = 4;
-}
\ No newline at end of file
+}
+
+/**
+ * Enum representing the key used for a notification adjustment.
+ *
+ * Meant to be analogous to the strings defined in
+ * frameworks/base/core/java/android/service/notification/Adjustment.java#Keys,
+ * but the enum contains only the adjustment keys that are used in logging.
+ */
+enum AdjustmentKey {
+    KEY_UNKNOWN = 0;
+    KEY_TYPE = 1;
+    KEY_SUMMARIZATION = 2;
+}
diff --git a/stats/enums/pdf/enums.proto b/stats/enums/pdf/enums.proto
index 117fc00d..ad3b1af4 100644
--- a/stats/enums/pdf/enums.proto
+++ b/stats/enums/pdf/enums.proto
@@ -33,6 +33,33 @@ enum ApiType {
   API_TYPE_UNKNOWN = 0;
   // PDF Text selected
   API_TYPE_SELECT_CONTENT = 1;
+  // PDF Text page object
+  API_TYPE_TEXT_PAGE_OBJECT = 2;
+  // PDF Image page object
+  API_TYPE_IMAGE_PAGE_OBJECT = 3;
+  // PDF Path page object
+  API_TYPE_PATH_PAGE_OBJECT = 4;
+  // PDF free text annotation
+  API_TYPE_FREE_TEXT_ANNOTATION = 5;
+  // PDF highlight annotation
+  API_TYPE_HIGHLIGHT_ANNOTATION = 6;
+  // PDF stamp annotation
+  API_TYPE_STAMP_ANNOTATION = 7;
+}
+
+// Type of operation (add, remove, update, list)
+enum OperationType {
+  OPERATION_TYPE_UNKNOWN = 0;
+  // Add operation
+  OPERATION_TYPE_ADD = 1;
+  // Remove operation
+  OPERATION_TYPE_REMOVE = 2;
+  // Update operation
+  OPERATION_TYPE_UPDATE = 3;
+  // List operation
+  OPERATION_TYPE_LIST = 4;
+  // Get top page object at pos
+  OPERATION_TYPE_GET_TOP_PAGE_OBJECT_AT_POS = 5;
 }
 
 enum PdfLinearizedType {
diff --git a/stats/enums/printing/enums.proto b/stats/enums/printing/enums.proto
new file mode 100644
index 00000000..e28216ab
--- /dev/null
+++ b/stats/enums/printing/enums.proto
@@ -0,0 +1,211 @@
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
+package android.os.statsd.printing;
+
+option java_outer_classname = "PrintingProtoEnums";
+option java_multiple_files = true;
+
+enum FrameworkPrintJobResult {
+  FrameworkPrintJobResult_UNSPECIFIED = 0;
+  FrameworkPrintJobResult_COMPLETED = 1;
+  FrameworkPrintJobResult_CANCELLED = 2;
+  FrameworkPrintJobResult_FAILED = 3;
+}
+
+enum FrameworkColorMode {
+  FrameworkColorMode_UNSPECIFIED = 0;
+  FrameworkColorMode_MONOCRHOME = 1;
+  FrameworkColorMode_COLOR = 2;
+}
+
+enum FrameworkMediaSize {
+  FrameworkMediaSize_UNSPECIFIED = 0;
+  FrameworkMediaSize_UNKNOWN_PORTRAIT = 1;
+  FrameworkMediaSize_UNKNOWN_LANDSCAPE = 2;
+  FrameworkMediaSize_ISO_A0 = 3;
+  FrameworkMediaSize_ISO_A1 = 4;
+  FrameworkMediaSize_ISO_A2 = 5;
+  FrameworkMediaSize_ISO_A3 = 6;
+  FrameworkMediaSize_ISO_A4 = 7;
+  FrameworkMediaSize_ISO_A5 = 8;
+  FrameworkMediaSize_ISO_A6 = 9;
+  FrameworkMediaSize_ISO_A7 = 10;
+  FrameworkMediaSize_ISO_A8 = 11;
+  FrameworkMediaSize_ISO_A9 = 12;
+  FrameworkMediaSize_ISO_A10 = 13;
+  FrameworkMediaSize_ISO_B0 = 14;
+  FrameworkMediaSize_ISO_B1 = 15;
+  FrameworkMediaSize_ISO_B2 = 16;
+  FrameworkMediaSize_ISO_B3 = 17;
+  FrameworkMediaSize_ISO_B4 = 18;
+  FrameworkMediaSize_ISO_B5 = 19;
+  FrameworkMediaSize_ISO_B6 = 20;
+  FrameworkMediaSize_ISO_B7 = 21;
+  FrameworkMediaSize_ISO_B8 = 22;
+  FrameworkMediaSize_ISO_B9 = 23;
+  FrameworkMediaSize_ISO_B10 = 24;
+  FrameworkMediaSize_ISO_C0 = 25;
+  FrameworkMediaSize_ISO_C1 = 26;
+  FrameworkMediaSize_ISO_C2 = 27;
+  FrameworkMediaSize_ISO_C3 = 28;
+  FrameworkMediaSize_ISO_C4 = 29;
+  FrameworkMediaSize_ISO_C5 = 30;
+  FrameworkMediaSize_ISO_C6 = 31;
+  FrameworkMediaSize_ISO_C7 = 32;
+  FrameworkMediaSize_ISO_C8 = 33;
+  FrameworkMediaSize_ISO_C9 = 34;
+  FrameworkMediaSize_ISO_C10 = 35;
+  FrameworkMediaSize_NA_LETTER = 36;
+  FrameworkMediaSize_NA_GOVT_LETTER = 37;
+  FrameworkMediaSize_NA_LEGAL = 38;
+  FrameworkMediaSize_NA_JUNIOR_LEGAL = 39;
+  FrameworkMediaSize_NA_LEDGER = 40;
+  FrameworkMediaSize_NA_TABLOID = 41;
+  FrameworkMediaSize_NA_INDEX_3X5 = 42;
+  FrameworkMediaSize_NA_INDEX_4X6 = 43;
+  FrameworkMediaSize_NA_INDEX_5X8 = 44;
+  FrameworkMediaSize_NA_MONARCH = 45;
+  FrameworkMediaSize_NA_QUARTO = 46;
+  FrameworkMediaSize_NA_FOOLSCAP = 47;
+  FrameworkMediaSize_ANSI_C = 48;
+  FrameworkMediaSize_ANSI_D = 49;
+  FrameworkMediaSize_ANSI_E = 50;
+  FrameworkMediaSize_ANSI_F = 51;
+  FrameworkMediaSize_NA_ARCH_A = 52;
+  FrameworkMediaSize_NA_ARCH_B = 53;
+  FrameworkMediaSize_NA_ARCH_C = 54;
+  FrameworkMediaSize_NA_ARCH_D = 55;
+  FrameworkMediaSize_NA_ARCH_E = 56;
+  FrameworkMediaSize_NA_ARCH_E1 = 57;
+  FrameworkMediaSize_NA_SUPER_B = 58;
+  FrameworkMediaSize_ROC_8K = 59;
+  FrameworkMediaSize_ROC_16K = 60;
+  FrameworkMediaSize_PRC_1 = 61;
+  FrameworkMediaSize_PRC_2 = 62;
+  FrameworkMediaSize_PRC_3 = 63;
+  FrameworkMediaSize_PRC_4 = 64;
+  FrameworkMediaSize_PRC_5 = 65;
+  FrameworkMediaSize_PRC_6 = 66;
+  FrameworkMediaSize_PRC_7 = 67;
+  FrameworkMediaSize_PRC_8 = 68;
+  FrameworkMediaSize_PRC_9 = 69;
+  FrameworkMediaSize_PRC_10 = 70;
+  FrameworkMediaSize_PRC_16K = 71;
+  FrameworkMediaSize_OM_PA_KAI = 72;
+  FrameworkMediaSize_OM_DAI_PA_KAI = 73;
+  FrameworkMediaSize_OM_JUURO_KU_KAI = 74;
+  FrameworkMediaSize_JIS_B10 = 75;
+  FrameworkMediaSize_JIS_B9 = 76;
+  FrameworkMediaSize_JIS_B8 = 77;
+  FrameworkMediaSize_JIS_B7 = 78;
+  FrameworkMediaSize_JIS_B6 = 79;
+  FrameworkMediaSize_JIS_B5 = 80;
+  FrameworkMediaSize_JIS_B4 = 81;
+  FrameworkMediaSize_JIS_B3 = 82;
+  FrameworkMediaSize_JIS_B2 = 83;
+  FrameworkMediaSize_JIS_B1 = 84;
+  FrameworkMediaSize_JIS_B0 = 85;
+  FrameworkMediaSize_JIS_EXEC = 86;
+  FrameworkMediaSize_JPN_CHOU4 = 87;
+  FrameworkMediaSize_JPN_CHOU3 = 88;
+  FrameworkMediaSize_JPN_CHOU2 = 89;
+  FrameworkMediaSize_JPN_HAGAKI = 90;
+  FrameworkMediaSize_JPN_OUFUKU = 91;
+  FrameworkMediaSize_JPN_KAHU = 92;
+  FrameworkMediaSize_JPN_KAKU2 = 93;
+  FrameworkMediaSize_JPN_YOU4 = 94;
+  FrameworkMediaSize_JPN_OE_PHOTO_L = 95;
+}
+
+enum FrameworkDuplexMode {
+  FrameworkDuplexMode_UNSPECIFIED = 0;
+  FrameworkDuplexMode_NONE = 1;
+  FrameworkDuplexMode_LONG_EDGE = 2;
+  FrameworkDuplexMode_SHORT_EDGE = 3;
+}
+
+enum FrameworkOrientation {
+  FrameworkOrientation_UNSPECIFIED = 0;
+  FrameworkOrientation_PORTRAIT = 1;
+  FrameworkOrientation_LANDSCAPE = 2;
+}
+
+enum FrameworkDocumentType {
+  FrameworkDocumentType_UNSPECIFIED = 1;
+  FrameworkDocumentType_DOCUMENT = 2;
+  FrameworkDocumentType_PHOTO = 3;
+}
+
+
+// BIPS Enums
+enum BipsJobOrigin {
+  BipsJobOrigin_UNSPECIFIED = 0;
+  BipsJobOrigin_DIRECT_PRINT = 1;
+  BipsJobOrigin_SHARED_IMAGE = 2;
+  BipsJobOrigin_SHARED_PDF = 3;
+}
+
+enum BipsPrintJobResult {
+  BipsPrintJobResult_UNSPECIFIED = 0;
+  BipsPrintJobResult_COMPLETED = 1;
+  BipsPrintJobResult_CANCELLED = 2;
+  BipsPrintJobResult_FAILED_CORRUPT = 3;
+  BipsPrintJobResult_FAILED_CERTIFICATE = 4;
+  BipsPrintJobResult_FAILED_UNKNOWN = 5;
+}
+
+enum BipsMediaType {
+  BipsMediaType_UNSPECIFIED = 0;
+  BipsMediaType_MEDIA_PLAIN = 1;
+  BipsMediaType_MEDIA_SPECIAL = 2;
+  BipsMediaType_MEDIA_PHOTO = 3;
+  BipsMediaType_MEDIA_TRANSPARENCY = 4;
+  BipsMediaType_MEDIA_IRON_ON = 5;
+  BipsMediaType_MEDIA_IRON_ON_MIRROR = 6;
+  BipsMediaType_MEDIA_ADVANCED_PHOTO = 7;
+  BipsMediaType_MEDIA_FAST_TRANSPARENCY = 8;
+  BipsMediaType_MEDIA_BROCHURE_GLOSSY = 9;
+  BipsMediaType_MEDIA_BROCHURE_MATTE = 10;
+  BipsMediaType_MEDIA_PHOTO_GLOSSY = 11;
+  BipsMediaType_MEDIA_PHOTO_MATTE = 12;
+  BipsMediaType_MEDIA_PREMIUM_PHOTO = 13;
+  BipsMediaType_MEDIA_OTHER_PHOTO = 14;
+  BipsMediaType_MEDIA_PRINTABLE_CD = 15;
+  BipsMediaType_MEDIA_PREMIUM_PRESENTATION = 16;
+
+  // New types above this line
+  BipsMediaType_MEDIA_AUTO = 99;
+  BipsMediaType_MEDIA_UNKNOWN = 100;
+}
+
+enum BipsPrinterDiscoveryScheme {
+  BipsPrinterDiscoveryScheme_UNSPECIFIED = 0;
+  BipsPrinterDiscoveryScheme_MDNS = 1;
+  BipsPrinterDiscoveryScheme_MANUAL = 2;
+  BipsPrinterDiscoveryScheme_P2P = 3;
+}
+
+enum BipsRequestCapabilitiesStatus {
+  BipsRequestCapabilitiesStatus_UNSPECIFIED = 0;
+  BipsRequestCapabilitiesStatus_OK = 1;
+  BipsRequestCapabilitiesStatus_ERROR = 2;
+  BipsRequestCapabilitiesStatus_CANCELLED = 3;
+  BipsRequestCapabilitiesStatus_CORRUPT = 4;
+  BipsRequestCapabilitiesStatus_BAD_CERTIFICATE = 5;
+}
diff --git a/stats/enums/privatespace/OWNERS b/stats/enums/privatespace/OWNERS
new file mode 100644
index 00000000..2520f2f2
--- /dev/null
+++ b/stats/enums/privatespace/OWNERS
@@ -0,0 +1 @@
+file:platform/packages/apps/PrivateSpace:/OWNERS
diff --git a/stats/enums/privatespace/private_space_enums.proto b/stats/enums/privatespace/private_space_enums.proto
new file mode 100644
index 00000000..20b81cfb
--- /dev/null
+++ b/stats/enums/privatespace/private_space_enums.proto
@@ -0,0 +1,116 @@
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
+package android.os.statsd.privatespace;
+
+option java_outer_classname = "PrivateSpaceProtoEnums";
+option java_multiple_files = true;
+
+// Result of the move content transfer.
+enum TransferResult {
+  TRANSFER_RESULT_UNKNOWN = 0;
+  // All files successfully transferred
+  TRANSFER_RESULT_SUCCESS = 1;
+  // The whole transfer failed, no files transferred.
+  TRANSFER_RESULT_FAILURE = 2;
+  // Transfer started but not all files successfully transferred.
+  // Look into individual files' errors.
+  TTRANSFER_RESULT_PARTIAL_SUCCESS = 3;
+}
+
+// Types of the operation chosen with the dialog
+enum OperationType {
+  OPERATION_UNKNOWN = 0;
+  // move button clicked
+  OPERATION_MOVE = 1;
+  // copy button clicked
+  OPERATION_COPY = 2;
+  // cancel button clicked
+  OPERATION_CANCEL_BY_USER = 3;
+  // dialog dismissed
+  OPERATION_DIALOG_DISMISSED = 4;
+}
+
+// Errors for the file transfer operation
+enum TransferErrorCode {
+  TRANSFER_ERROR_UNKNOWN = 0;
+
+  // Errors that fail the whole transfer, all files expected to have the same
+  // error.
+  TRANSFER_ERROR_ANOTHER_TRANSFER_IN_PROGRESS = 1;
+  TRANSFER_ERROR_ABOVE_FILE_SIZE_LIMITS = 2;
+  TRANSFER_ERROR_TOO_MANY_FILES_SELECTED = 3;
+  TRANSFER_ERROR_ABOVE_AVAILABLE_DEVICE_STORAGE = 4;
+  TRANSFER_ERROR_NOT_ENOUGH_SPACE = 5;
+
+  // Errors while transferring a single file
+  TRANSFER_ERROR_CALCULATE_FILE_SIZE = 101;
+  TRANSFER_ERROR_GET_METADATA = 102;
+  TRANSFER_ERROR_CREATE_NEW_MEDIA_ENTRY = 103;
+  TRANSFER_ERROR_GET_FILE_NAME = 104;
+  TRANSFER_ERROR_QUERY_URI = 105;
+  TRANSFER_ERROR_OPEN_OUTPUT_STREAM = 106;
+  TRANSFER_ERROR_OPEN_INPUT_STREAM = 107;
+  TRANSFER_ERROR_COPY_FILE = 108;
+  TRANSFER_ERROR_REMOVE_ORIGINAL_FILE = 109;
+  // TODO add errors for ioexception and other common exceptions?
+}
+
+// Buckets for the file sizes.
+// 0-1KB, 1-10KB, 10-100KB, 100-500KB, 500KB-1MB, 1MB-10MB, 10MB-100MB,
+// 100MB-500MB, 500MB-1GB, 1GB-2GB, >2GB
+enum FileSizeBucket {
+  FILE_SIZE_UNKNOWN = 0;
+  FILE_SIZE_0_TO_1_KB = 1;
+  FILE_SIZE_1_TO_10_KB = 2;
+  FILE_SIZE_10_TO_100_KB = 3;
+  FILE_SIZE_100_TO_500_KB = 4;
+  FILE_SIZE_500_KB_TO_1_MB = 5;
+  FILE_SIZE_1_TO_10_MB = 6;
+  FILE_SIZE_10_TO_100_MB = 7;
+  FILE_SIZE_100_TO_500_MB = 8;
+  FILE_SIZE_500_MB_TO_1_GB = 9;
+  FILE_SIZE_1_TO_2_GB = 10;
+  FILE_SIZE_MORE_THAN_2_GB = 11;
+}
+
+// MIME types categories.
+enum MimeTypeCategory {
+  MIME_TYPE_CATEGORY_UNKNOWN = 0;
+  MIME_TYPE_CATEGORY_IMAGE = 1;
+  MIME_TYPE_CATEGORY_VIDEO = 2;
+  MIME_TYPE_CATEGORY_AUDIO = 3;
+  MIME_TYPE_CATEGORY_APPLICATION = 4;
+  MIME_TYPE_CATEGORY_PDF = 5;
+  MIME_TYPE_CATEGORY_TEXT = 6;
+  MIME_TYPE_CATEGORY_GENERIC_OCTET_STREAM = 7;
+  MIME_TYPE_CATEGORY_OTHERS = 8;
+}
+
+// Types of user interaction with the move content notification.
+enum NotificationEventType {
+  NOTIFICATION_EVENT_TYPE_UNKNOWN = 0;
+  NOTIFICATION_EVENT_TYPE_SHOW_FILES_CLICK = 1;
+}
+
+// Shortcut types
+enum AddButtonShortcutClick {
+  ADD_BUTTON_CLICK_UNKNOWN = 0;
+  ADD_BUTTON_CLICK_OPEN_MARKET_APP_SHORTCUT = 1;
+  ADD_BUTTON_CLICK_MOVE_FILES_SHORTCUT = 2;
+}
\ No newline at end of file
diff --git a/stats/enums/server/connectivity/Android.bp b/stats/enums/server/connectivity/Android.bp
index ae41484d..8e2f4523 100644
--- a/stats/enums/server/connectivity/Android.bp
+++ b/stats/enums/server/connectivity/Android.bp
@@ -16,22 +16,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-java_library_static {
-    name: "datastallprotosnano",
-    proto: {
-        type: "nano",
-    },
-    srcs: [
-        "data_stall_event.proto",
-    ],
-    sdk_version: "system_current",
-    // this is part of updatable modules(NetworkStack) which targets 29(Q)
-    min_sdk_version: "29",
-}
-
-
 filegroup {
-    name: "data_stall_event_proto",
+    name: "data_stall_event_enums_proto",
     srcs: [
         "data_stall_event.proto",
     ],
diff --git a/stats/enums/server/connectivity/data_stall_event.proto b/stats/enums/server/connectivity/data_stall_event.proto
index 787074ba..0d5270e7 100644
--- a/stats/enums/server/connectivity/data_stall_event.proto
+++ b/stats/enums/server/connectivity/data_stall_event.proto
@@ -60,32 +60,3 @@ enum RadioTech {
   RADIO_TECHNOLOGY_NR = 20;
 }
 
-// Cellular specific information.
-message CellularData {
-    // Indicate the radio technology at the time of data stall suspected.
-    optional RadioTech rat_type = 1;
-    // True if device is in roaming network at the time of data stall suspected.
-    optional bool is_roaming = 2;
-    // Registered network MccMnc when data stall happen
-    optional string network_mccmnc = 3;
-    // Indicate the SIM card carrier.
-    optional string sim_mccmnc = 4;
-    // Signal strength level at the time of data stall suspected.
-    optional int32 signal_strength = 5;
-}
-
-// Wifi specific information.
-message WifiData {
-    // Signal strength at the time of data stall suspected.
-    // RSSI range is between -55 to -110.
-    optional int32 signal_strength = 1;
-    // AP band.
-    optional ApBand wifi_band = 2;
-}
-
-message DnsEvent {
-    // The dns return code.
-    repeated int32 dns_return_code = 1;
-    // Indicate the timestamp of the dns event.
-    repeated int64 dns_time = 2;
-}
diff --git a/stats/enums/stats/connectivity/Android.bp b/stats/enums/stats/connectivity/Android.bp
index 83c470e8..89a53cf5 100644
--- a/stats/enums/stats/connectivity/Android.bp
+++ b/stats/enums/stats/connectivity/Android.bp
@@ -16,17 +16,6 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-java_library_static {
-    name: "networkstackprotos",
-    proto: {
-        type: "lite",
-    },
-    srcs: [
-        "network_stack.proto",
-    ],
-    sdk_version: "system_29",
-}
-
 java_library_static {
     name: "tetheringprotos",
     proto: {
@@ -65,7 +54,7 @@ filegroup {
 }
 
 filegroup {
-    name: "network_stack_proto",
+    name: "network_stack_enum_proto",
     srcs: [
         "network_stack.proto",
     ],
diff --git a/stats/enums/stats/connectivity/network_stack.proto b/stats/enums/stats/connectivity/network_stack.proto
index 98a09f2b..f83c7521 100644
--- a/stats/enums/stats/connectivity/network_stack.proto
+++ b/stats/enums/stats/connectivity/network_stack.proto
@@ -18,7 +18,6 @@ syntax = "proto2";
 
 package android.stats.connectivity;
 option java_multiple_files = true;
-option java_outer_classname = "NetworkStackProto";
 
 enum Ipv6ProvisioningMode {
     IPV6_PROV_MODE_UNKNOWN = 0;
@@ -195,6 +194,7 @@ enum NetworkQuirkEvent {
     QE_APF_GENERATE_FILTER_EXCEPTION = 4;
     QE_DHCP6_HEURISTIC_TRIGGERED = 5;
     QE_DHCP6_PD_PROVISIONED = 6;
+    QE_DHCP6_PFLAG_TRIGGERED = 7;
 }
 
 enum IpType {
@@ -313,9 +313,11 @@ enum CounterName {
    CN_DROPPED_IPV6_MLD_V1_GENERAL_QUERY_REPLIED = 64;
    CN_DROPPED_IPV6_MLD_V2_GENERAL_QUERY_REPLIED = 65;
    CN_DROPPED_MDNS_REPLIED = 66;
-}
-
-message NetworkStackEventData {
-
+   CN_PASSED_ALLOCATE_FAILURE = 67;
+   CN_PASSED_TRANSMIT_FAILURE = 68;
+   CN_CORRUPT_DNS_PACKET = 69;
+   CN_EXCEPTIONS = 70;
+   CN_PASSED_RA = 71;
+   CN_DROPPED_NON_UNICAST_TDLS = 72;
 }
 
diff --git a/stats/enums/stats/devicepolicy/Android.bp b/stats/enums/stats/devicepolicy/Android.bp
index ed05c018..8dea9be6 100644
--- a/stats/enums/stats/devicepolicy/Android.bp
+++ b/stats/enums/stats/devicepolicy/Android.bp
@@ -16,28 +16,8 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-java_library_static {
-    name: "devicepolicyprotosnano",
-    proto: {
-        type: "nano",
-    },
-    srcs: [
-        "*.proto",
-    ],
-    java_version: "1.8",
-    target: {
-        android: {
-            jarjar_rules: "jarjar-rules.txt",
-        },
-        host: {
-            static_libs: ["libprotobuf-java-nano"],
-        }
-    },
-    sdk_version: "core_platform",
-}
-
 filegroup {
-    name: "device_policy_proto",
+    name: "device_policy_enums_proto",
     srcs: [
         "*.proto",
     ],
diff --git a/stats/enums/stats/dnsresolver/Android.bp b/stats/enums/stats/dnsresolver/Android.bp
index 3bf5bfeb..dbbed464 100644
--- a/stats/enums/stats/dnsresolver/Android.bp
+++ b/stats/enums/stats/dnsresolver/Android.bp
@@ -16,20 +16,9 @@ package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-java_library_static {
-    name: "dnsresolverprotosnano",
-    proto: {
-        type: "nano",
-    },
-    srcs: [
-        "dns_resolver.proto",
-    ],
-    sdk_version: "system_current",
-}
-
 filegroup {
     name: "dns_resolver_proto",
     srcs: [
-        "dns_resolver.proto",
+        "dns_resolver_enums.proto",
     ],
 }
diff --git a/stats/enums/stats/dnsresolver/dns_resolver.proto b/stats/enums/stats/dnsresolver/dns_resolver_enums.proto
similarity index 93%
rename from stats/enums/stats/dnsresolver/dns_resolver.proto
rename to stats/enums/stats/dnsresolver/dns_resolver_enums.proto
index b859ee96..5c9e5294 100644
--- a/stats/enums/stats/dnsresolver/dns_resolver.proto
+++ b/stats/enums/stats/dnsresolver/dns_resolver_enums.proto
@@ -349,35 +349,6 @@ enum LinuxErrno {
     SYS_EHWPOISON = 133;
 }
 
-message DnsQueryEvent {
-    optional android.stats.dnsresolver.NsRcode rcode = 1;
-
-    optional android.stats.dnsresolver.NsType type = 2;
-
-    optional android.stats.dnsresolver.CacheStatus cache_hit = 3;
-
-    optional android.stats.dnsresolver.IpVersion ip_version = 4;
-
-    optional android.stats.dnsresolver.Protocol protocol = 5;
-
-    // Number of DNS query retry times
-    optional int32 retry_times = 6;
-
-    // Ordinal number of name server.
-    optional int32 dns_server_index = 7;
-
-    // Used only by TCP and DOT. True for new connections.
-    optional bool connected = 8;
-
-    optional int32 latency_micros = 9;
-
-    optional android.stats.dnsresolver.LinuxErrno linux_errno = 10;
-}
-
-message DnsQueryEvents {
-    repeated DnsQueryEvent dns_query_event = 1;
-}
-
 enum HandshakeResult {
     HR_UNKNOWN = 0;
     HR_SUCCESS = 1;
@@ -393,16 +364,3 @@ enum HandshakeCause {
     HC_RETRY_AFTER_ERROR = 3;
 }
 
-message Servers {
-    repeated Server server = 1;
-}
-
-message Server {
-    optional android.stats.dnsresolver.Protocol protocol = 1;
-
-    // The order of the dns server in the network
-    optional int32 index = 2;
-
-    // The validation status of the DNS server in the network
-    optional bool validated = 3;
-}
diff --git a/stats/enums/stats/launcher/launcher.proto b/stats/enums/stats/launcher/launcher.proto
index fc177d57..515fbbd7 100644
--- a/stats/enums/stats/launcher/launcher.proto
+++ b/stats/enums/stats/launcher/launcher.proto
@@ -40,49 +40,3 @@ enum LauncherState {
     UNCHANGED = 5;
 }
 
-message LauncherTarget {
-    enum Type {
-        NONE = 0;
-        ITEM_TYPE = 1;
-        CONTROL_TYPE = 2;
-        CONTAINER_TYPE = 3;
-    }
-    enum Item {
-        DEFAULT_ITEM = 0;
-        APP_ICON = 1;
-        SHORTCUT = 2;
-        WIDGET = 3;
-        FOLDER_ICON = 4;
-        DEEPSHORTCUT = 5;
-        SEARCHBOX = 6;
-        EDITTEXT = 7;
-        NOTIFICATION = 8;
-        TASK = 9;
-    }
-    enum Container {
-        DEFAULT_CONTAINER = 0;
-        HOTSEAT = 1;
-        FOLDER = 2;
-        PREDICTION = 3;
-        SEARCHRESULT = 4;
-    }
-    enum Control {
-        DEFAULT_CONTROL = 0;
-        MENU = 1;
-        UNINSTALL = 2;
-        REMOVE = 3;
-    }
-    optional Type type = 1;
-    optional Item item = 2;
-    optional Container container = 3;
-    optional Control control = 4;
-    optional string launch_component = 5;
-    optional int32 page_id = 6;
-    optional int32 grid_x = 7;
-    optional int32 grid_y = 8;
-}
-
-message LauncherExtension {
-    repeated LauncherTarget src_target = 1;
-    repeated LauncherTarget dst_target = 2;
-}
diff --git a/stats/enums/stats/mediaprovider/mediaprovider_enums.proto b/stats/enums/stats/mediaprovider/mediaprovider_enums.proto
index 138782bf..3c3cb008 100644
--- a/stats/enums/stats/mediaprovider/mediaprovider_enums.proto
+++ b/stats/enums/stats/mediaprovider/mediaprovider_enums.proto
@@ -28,3 +28,77 @@ enum VolumeType {
     // Volume is non-primary external storage
     EXTERNAL_OTHER = 3;
 }
+
+enum Uri {
+    URI_UNSPECIFIED = 0;
+    URI_MEDIA = 1;
+    URI_MEDIA_PICKER = 2;
+    URI_MEDIA_REDACTED = 3;
+    URI_MEDIA_DOCUMENT = 4;
+}
+
+enum FuseOp {
+    FUSE_OP_UNSPECIFIED = 0;
+    UNLINK = 1;
+    OPENDIR = 2;
+    ACCESS = 3;
+    RENAME = 4;
+    OPEN = 5;
+    READ = 6;
+    READDIR = 7;
+    CREATE = 8;
+    GETATTR = 9;
+    SETATTR = 10;
+    MKDIR = 11;
+    RMDIR = 12;
+    LOOKUP = 13;
+    LOOKUP_POSTFILTER = 14;
+    INIT = 15;
+    DESTROY = 16;
+    FORGET = 17;
+    CANONICAL_PATH = 18;
+    MKNOD =  19;
+    FLUSH = 20;
+    RELEASE = 21;
+    FSYNC = 22;
+    READDIR_POSTFILTER = 23;
+    RELEASEDIR = 24;
+    FSYNCDIR = 25;
+    STATFS = 26;
+    WRITE_BUF = 27;
+    FALLOCATE = 28;
+    FORGET_MULTI = 29;
+}
+
+enum MediaProviderOp {
+    MEDIA_PROVIDER_OP_UNSPECIFIED = 0;
+    ON_CREATE = 1;
+    BULK_INSERT = 2;
+    INSERT = 3;
+    DELETE = 4;
+    UPDATE = 5;
+    OPEN_FILE = 6;
+    OPEN_TYPED_ASSET_FILE = 7;
+    OPEN_FILE_ASYNC = 8;
+    OPEN_ASSET_FILE_ASYNC = 9;
+    APPLY_BATCH = 10;
+    ATTACH_VOLUME = 11;
+    DETACH_VOLUME = 12;
+
+    // MediaStore Call APIs
+    RESOLVE_PLAYLIST_MEMBERS_CALL = 20;
+    GET_VERSION_CALL = 21;
+    GET_GENERATION_CALL = 22;
+    GET_DOCUMENT_URI_CALL = 23;
+    GET_MEDIA_URI_CALL = 24;
+    GET_REDACTED_MEDIA_URI_CALL = 25;
+    GET_REDACTED_MEDIA_URI_LIST_CALL = 26;
+    CREATE_WRITE_REQUEST_CALL = 27;
+    CREATE_FAVORITE_REQUEST_CALL = 28;
+    CREATE_TRASH_REQUEST_CALL = 29;
+    CREATE_DELETE_REQUEST_CALL = 30;
+    MARK_MEDIA_AS_FAVORITE = 31;
+    PICKER_TRANSCODE_CALL = 32;
+    SYNC_PROVIDERS_CALL = 33;
+    BULK_UPDATE_OEM_METADATA_CALL = 34;
+}
diff --git a/stats/enums/stats/style/style_enums.proto b/stats/enums/stats/style/style_enums.proto
index f91599f4..896e828c 100644
--- a/stats/enums/stats/style/style_enums.proto
+++ b/stats/enums/stats/style/style_enums.proto
@@ -60,6 +60,11 @@ enum Action {
     SHORTCUT_APPLIED = 38;
     DARK_THEME_APPLIED = 39;
     RESET_APPLIED = 40;
+    SHAPE_APPLIED = 41;
+    ENTER_SCREEN = 42;
+    CURATED_PHOTOS_FETCH_START = 43;
+    CURATED_PHOTOS_FETCH_END = 44;
+    CURATED_PHOTOS_RENDER_COMPLETE = 45;
 }
 
 enum LocationPreference {
@@ -105,6 +110,7 @@ enum SetWallpaperEntryPoint {
     SET_WALLPAPER_ENTRY_POINT_ROTATION_WALLPAPER = 4;
     SET_WALLPAPER_ENTRY_POINT_RESET = 5;
     SET_WALLPAPER_ENTRY_POINT_RESTORE = 6;
+    SET_WALLPAPER_ENTRY_POINT_WALLPAPER_PREVIEW_SUGGESTED_PHOTOS = 7;
 }
 
 enum WallpaperDestination {
@@ -126,3 +132,17 @@ enum ClockSize {
     CLOCK_SIZE_DYNAMIC = 1;
     CLOCK_SIZE_SMALL = 2;
 }
+
+enum CustomizationPickerSrceen {
+    SCREEN_UNSPECIFIED = 0;
+    SCREEN_COLORS = 1;
+    SCREEN_ICONS = 2;
+    SCREEN_LAYOUT = 3;
+    SCREEN_CLOCK = 4;
+    SCREEN_SHORTCUTS = 5;
+}
+
+enum AppIconStyle {
+    APP_ICON_STYLE_UNSPECIFIED = 0;
+    APP_ICON_STYLE_THEMED = 1;
+}
diff --git a/stats/enums/statusbar/enums.proto b/stats/enums/statusbar/enums.proto
new file mode 100644
index 00000000..b74b9127
--- /dev/null
+++ b/stats/enums/statusbar/enums.proto
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
+
+syntax = "proto2";
+
+package android.stats.statusbar;
+
+option java_package = "com.android.os.statusbar";
+option java_multiple_files = true;
+option java_outer_classname = "StatusBarProtoEnums";
+
+/**
+ * Enum used with StatusBarChipReported.
+ */
+enum StatusBarChipType {
+    STATUS_BAR_CHIP_TYPE_UNKNOWN = 0;
+    // The chip is for sharing screen or audio to another app
+    SCREEN_SHARE = 1;
+    // The chip is for system screen recording
+    SCREEN_RECORD = 2;
+    // The chip is for casting screen or audio to a different device
+    SCREEN_CAST = 3;
+    // The chip is for a call notification
+    CALL = 4;
+    // The chip is for a promoted notification
+    PROMOTED_NOTIFICATION = 5;
+}
diff --git a/stats/enums/telecomm/enums.proto b/stats/enums/telecomm/enums.proto
index 1fc9247b..2412627c 100644
--- a/stats/enums/telecomm/enums.proto
+++ b/stats/enums/telecomm/enums.proto
@@ -355,6 +355,12 @@ enum ApiNameEnum {
     API_SILENCE_RINGER = 57;
     API_START_CONFERENCE = 58;
     API_UNREGISTER_PHONE_ACCOUNT = 59;
+    // API usage enum for method:
+    // TelecomManager#getCallConnectedIndicatorPreference
+    API_GET_CALL_CONNECTED_INDICATOR_PREF = 60;
+    // API usage enum for method:
+    // TelecomManager#setCallConnectedIndicatorPreference
+    API_SET_CALL_CONNECTED_INDICATOR_PREF = 61;
 }
 
 /**
@@ -454,3 +460,37 @@ enum EventCauseEnum {
     CALL_TRANSACTION_CALL_NOT_PERMITTED_AT_PRESENT_TIME = 1005;
     CALL_TRANSACTION_CODE_OPERATION_TIMED_OUT = 1006;
 }
+
+/**
+ * Indicating the operation being performed on the call. This includes
+ * answer, hold, unhold, disconnect, and reject.
+ */
+enum CallOperationTypeEnum {
+    CALL_OPERATION_UNKNOWN = 0;
+    CALL_OPERATION_ANSWER = 1;
+    CALL_OPERATION_HOLD = 2;
+    CALL_OPERATION_UNHOLD = 3;
+    CALL_OPERATION_DISCONNECT = 4;
+    CALL_OPERATION_REJECT = 5;
+}
+
+/**
+ * Indicating the result of the call operation being performed. This can either succeed, fail due
+ * to an external issue, or timeout.
+ */
+enum CallOperationResultEnum {
+    CALL_OPERATION_RESULT_UNKNOWN = 0;
+    CALL_OPERATION_RESULT_SUCCESS = 1;
+    CALL_OPERATION_RESULT_ERROR = 2;
+    CALL_OPERATION_RESULT_TIMEOUT = 3;
+}
+
+/**
+ * Indicating the type of the call - managed, self-managed, transactional, or unknown.
+ */
+enum CallTypeEnum {
+    UNKNOWN_CALL_TYPE = 0;
+    MANAGED_CALL_TYPE = 1;
+    SELF_MANAGED_CALL_TYPE = 2;
+    TRANSACTIONAL_CALL_TYPE = 3;
+}
diff --git a/stats/enums/telephony/enums.proto b/stats/enums/telephony/enums.proto
index e52bbd50..d06e0a05 100644
--- a/stats/enums/telephony/enums.proto
+++ b/stats/enums/telephony/enums.proto
@@ -325,6 +325,7 @@ enum DataDeactivateReasonEnum {
     DEACTIVATE_REASON_PREFERRED_DATA_SWITCHED = 34;
     DEACTIVATE_REASON_DATA_LIMIT_REACHED = 35;
     DEACTIVATE_REASON_DATA_NETWORK_TRANSPORT_NOT_ALLOWED = 36;
+    DEACTIVATE_REASON_DEVICE_SHUT_DOWN = 37;
 }
 
 // IP type of the data call
@@ -578,6 +579,7 @@ enum SmsSendErrorEnum {
     SMS_SEND_ERROR_RIL_NO_NETWORK_FOUND = 135;
     SMS_SEND_ERROR_RIL_DEVICE_IN_USE = 136;
     SMS_SEND_ERROR_RIL_ABORTED = 137;
+    SMS_SEND_ERROR_FAIL_AFTER_MAX_RETRY = 138;
 }
 
 /**
diff --git a/stats/enums/view/inputmethod/enums.proto b/stats/enums/view/inputmethod/enums.proto
index 580bfb94..f036a9c8 100644
--- a/stats/enums/view/inputmethod/enums.proto
+++ b/stats/enums/view/inputmethod/enums.proto
@@ -74,8 +74,8 @@ enum SoftInputShowHideReasonEnum {
     REASON_DISPLAY_CONFIGURATION_CHANGED = 47;
     REASON_DISPLAY_INSETS_CHANGED = 48;
     REASON_DISPLAY_CONTROLS_CHANGED = 49;
-    REASON_UNBIND_CURRENT_METHOD = 50;
-    REASON_HIDE_SOFT_INPUT_ON_ANIMATION_STATE_CHANGED = 51;
+    REASON_UNBIND_CURRENT_METHOD = 50 [deprecated = true];
+    REASON_HIDE_SOFT_INPUT_ON_ANIMATION_STATE_CHANGED = 51 [deprecated = true];
     REASON_HIDE_SOFT_INPUT_REQUEST_HIDE_WITH_CONTROL = 52;
     REASON_SHOW_SOFT_INPUT_IME_TOGGLE_SOFT_INPUT = 53;
     REASON_SHOW_SOFT_INPUT_IMM_DEPRECATION = 54;
@@ -84,6 +84,7 @@ enum SoftInputShowHideReasonEnum {
     REASON_HIDE_INPUT_TARGET_CHANGED = 57;
     REASON_HIDE_WINDOW_LOST_FOCUS = 58;
     REASON_IME_REQUESTED_CHANGED_LISTENER = 59;
+    REASON_HIDE_FOR_BUBBLES_WHEN_LOCKED = 60;
 }
 
 // The type of the IME request, used by android/view/inputmethod/ImeTracker.java.
@@ -172,13 +173,13 @@ enum ImeRequestPhaseEnum {
     // Requested applying the IME visibility in the insets source consumer.
     PHASE_IME_APPLY_VISIBILITY_INSETS_CONSUMER = 16 [deprecated = true];
     // Applied the IME visibility.
-    PHASE_SERVER_APPLY_IME_VISIBILITY = 17;
+    PHASE_SERVER_APPLY_IME_VISIBILITY = 17 [deprecated = true];
     // Started the show IME runner.
-    PHASE_WM_SHOW_IME_RUNNER = 18;
+    PHASE_WM_SHOW_IME_RUNNER = 18 [deprecated = true];
     // Ready to show IME.
     PHASE_WM_SHOW_IME_READY = 19;
     // The Window Manager has a connection to the IME insets control target.
-    PHASE_WM_HAS_IME_INSETS_CONTROL_TARGET = 20;
+    PHASE_WM_HAS_IME_INSETS_CONTROL_TARGET = 20 [deprecated = true];
     // Reached the window insets control target's show insets method.
     PHASE_WM_WINDOW_INSETS_CONTROL_TARGET_SHOW_INSETS = 21;
     // Reached the window insets control target's hide insets method.
@@ -208,13 +209,13 @@ enum ImeRequestPhaseEnum {
     // Checked that the IME is controllable.
     PHASE_CLIENT_DISABLED_USER_ANIMATION = 34 [deprecated = true];
     // Collecting insets source controls.
-    PHASE_CLIENT_COLLECT_SOURCE_CONTROLS = 35;
+    PHASE_CLIENT_COLLECT_SOURCE_CONTROLS = 35 [deprecated = true];
     // Reached the insets source consumer's show request method.
-    PHASE_CLIENT_INSETS_CONSUMER_REQUEST_SHOW = 36;
+    PHASE_CLIENT_INSETS_CONSUMER_REQUEST_SHOW = 36 [deprecated = true];
     // Reached input method manager's request IME show method.
-    PHASE_CLIENT_REQUEST_IME_SHOW = 37;
+    PHASE_CLIENT_REQUEST_IME_SHOW = 37 [deprecated = true];
     // Reached the insets source consumer's notify hidden method.
-    PHASE_CLIENT_INSETS_CONSUMER_NOTIFY_HIDDEN = 38;
+    PHASE_CLIENT_INSETS_CONSUMER_NOTIFY_HIDDEN = 38 [deprecated = true];
     // Queued the IME window insets show animation.
     PHASE_CLIENT_ANIMATION_RUNNING = 39;
     // Cancelled the IME window insets show animation.
@@ -222,7 +223,7 @@ enum ImeRequestPhaseEnum {
     // Finished the IME window insets show animation.
     PHASE_CLIENT_ANIMATION_FINISHED_SHOW = 41;
     // Finished the IME window insets hide animation.
-    PHASE_CLIENT_ANIMATION_FINISHED_HIDE = 42;
+    PHASE_CLIENT_ANIMATION_FINISHED_HIDE = 42 [deprecated = true];
     // Aborted the request to show the IME post layout.
     PHASE_WM_ABORT_SHOW_IME_POST_LAYOUT = 43;
     // Reached the IME's showWindow method.
@@ -297,5 +298,7 @@ enum ImeRequestPhaseEnum {
     PHASE_SERVER_IME_INVOKER = 77;
     // Reached the IME client invoker on the server.
     PHASE_SERVER_CLIENT_INVOKER = 78;
+    // The server will dispatch the show request to the IME, but this is already visible.
+    PHASE_SERVER_ALREADY_VISIBLE = 79;
 }
 
diff --git a/stats/enums/wear/connectivity/enums.proto b/stats/enums/wear/connectivity/enums.proto
index 36fb699a..05d270e6 100644
--- a/stats/enums/wear/connectivity/enums.proto
+++ b/stats/enums/wear/connectivity/enums.proto
@@ -289,3 +289,9 @@ enum CompanionConnectionChange {
     CONNECTED = 1;
     DISCONNECTED = 2;
 }
+
+enum BleMigrationStep {
+    STEP_UNKNOWN = 0;
+    STEP_SYSPROXY_PSM_RECEIVED = 1;
+    STEP_SYSPROXY_TRANSPORT_MIGRATED = 2;
+}
diff --git a/stats/enums/wear/modes/enums.proto b/stats/enums/wear/modes/enums.proto
index 152be6c7..8eb97399 100644
--- a/stats/enums/wear/modes/enums.proto
+++ b/stats/enums/wear/modes/enums.proto
@@ -36,6 +36,7 @@ enum ModeId {
   TOUCH_LOCK_MODE = 6;
   SCHOOL_MODE = 7;
   OFF_BODY = 8;
+  DOWNTIME_MODE = 9;
 }
 
 // Indicates Network state as being on or off
diff --git a/stats/enums/wear/physicalux/enums.proto b/stats/enums/wear/physicalux/enums.proto
new file mode 100644
index 00000000..82333139
--- /dev/null
+++ b/stats/enums/wear/physicalux/enums.proto
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
+
+syntax = "proto2";
+
+package com.google.android.clockwork.physicalux;
+
+// Gesture Actions
+enum GestureAction {
+  ACTION_UNSPECIFIED = 0;
+  ACTION_PRIMARY = 1;
+  ACTION_DISMISS = 2;
+}
+
+// Raw Gestures
+enum Gesture {
+  GESTURE_UNSPECIFIED = 0;
+  GESTURE_DOUBLE_PINCH = 1;
+  GESTURE_WRIST_TURN = 2;
+}
+
+// State of gesture detection
+enum GestureDetectionState {
+  STATE_UNSPECIFIED = 0;
+  STATE_ACTIVE = 1;
+  STATE_INACTIVE = 2;
+}
\ No newline at end of file
diff --git a/stats/express/catalog/bluetooth.cfg b/stats/express/catalog/bluetooth.cfg
deleted file mode 100644
index 7f9f763b..00000000
--- a/stats/express/catalog/bluetooth.cfg
+++ /dev/null
@@ -1,166 +0,0 @@
-express_metric {
-    id: "bluetooth.value_close_profile_proxy_adapter_mismatch"
-    type: COUNTER_WITH_UID
-    display_name: "Calls of closeProfileProxy on a proxy from a different BluetoothAdapter"
-    description:
-        "Counting how many calls to BluetoothAdapter.closeProfileProxy where made with"
-        "a BluetoothProfile opened with getProfileProxy on a different BluetoothAdapter"
-        "instance."
-    owner_email: "licorne@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_cvsd_codec_usage_over_hfp"
-    type: COUNTER
-    display_name: "HFP codec usage -- CVSD"
-    description: "Counter on how many times CVSD codec is used for HFP."
-    owner_email: "wescande@google.com"
-    owner_email: "rotkiewicz@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_msbc_codec_usage_over_hfp"
-    type: COUNTER
-    display_name: "HFP codec usage -- mSbc"
-    description: "Counter on how many times mSbc codec is used for HFP."
-    owner_email: "wescande@google.com"
-    owner_email: "rotkiewicz@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_aptx_codec_usage_over_hfp"
-    type: COUNTER
-    display_name: "HFP codec usage -- AptX"
-    description: "Counter on how many times AptX codec is used for HFP."
-    owner_email: "wescande@google.com"
-    owner_email: "rotkiewicz@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_lc3_codec_usage_over_hfp"
-    type: COUNTER
-    display_name: "HFP codec usage -- LC3"
-    description: "Counter on how many times LC3 codec is used for HFP."
-    owner_email: "wescande@google.com"
-    owner_email: "rotkiewicz@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_sbc_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- SBC"
-    description: "Counter on how many times SBC is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_aac_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- AAC"
-    description: "Counter on how many times AAC is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_aptx_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- AptX"
-    description: "Counter on how many times AptX is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_aptx_hd_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- AptX HD"
-    description: "Counter on how many times Aptx HD is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_ldac_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- LDAC"
-    description: "Counter on how many times LDAC is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_opus_codec_usage_over_a2dp"
-    type: COUNTER
-    display_name: "A2DP codec usage -- Opus"
-    description: "Counter on how many times Opus is used for A2DP."
-    owner_email: "henrichataing@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_auto_on_supported"
-    type: COUNTER
-    display_name: "Auto on -- support"
-    description: "How many times the Bluetooth start with AutoOnFeature supported"
-    owner_email: "wescande@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_auto_on_triggered"
-    type: COUNTER
-    display_name: "Auto on -- trigger"
-    description: "How many times the Bluetooth restart because of AutoOnFeature"
-    owner_email: "wescande@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_auto_on_disabled"
-    type: COUNTER
-    display_name: "Auto on -- disabled"
-    description: "How many times the user manually disable the AutoOnFeature"
-    owner_email: "wescande@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_auto_on_enabled"
-    type: COUNTER
-    display_name: "Auto on -- enabled"
-    description: "How many times the user manually enable the AutoOnFeature"
-    owner_email: "wescande@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_kill_from_binder_thread"
-    type: COUNTER
-    display_name: "Kill from binder thread"
-    description: "How many times Bluetooth could not be turned OFF and needed to be kill from the binder thread"
-    owner_email: "wescande@google.com"
-    unit: UNIT_COUNT
-}
-
-express_metric {
-    id: "bluetooth.value_shutdown_latency"
-    type: HISTOGRAM
-    display_name: "Bluetooth app shutdown time"
-    description: "Latency to shutdown entirely the Bluetooth app"
-    owner_email: "wescande@google.com"
-    unit: UNIT_TIME_MILLIS
-    histogram_options: {
-        uniform_bins: {
-            count: 50
-            min: 0
-            max: 3000
-        }
-    }
-}
diff --git a/stats/atoms/threadnetwork/Android.bp b/stats/message/connectivity/Android.bp
similarity index 55%
rename from stats/atoms/threadnetwork/Android.bp
rename to stats/message/connectivity/Android.bp
index 7062e679..d2152168 100644
--- a/stats/atoms/threadnetwork/Android.bp
+++ b/stats/message/connectivity/Android.bp
@@ -1,5 +1,4 @@
-//
-// Copyright (C) 2023 The Android Open Source Project
+// Copyright (C) 2025 The Android Open Source Project
 //
 // Licensed under the Apache License, Version 2.0 (the "License");
 // you may not use this file except in compliance with the License.
@@ -12,28 +11,33 @@
 // WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 // See the License for the specific language governing permissions and
 // limitations under the License.
-//
 
 package {
     default_applicable_licenses: ["Android-Apache-2.0"],
 }
 
-cc_library_static {
-    name: "ot-daemon-atom-cc-proto-lite",
+java_library_static {
+    name: "networkstackprotos",
     proto: {
         type: "lite",
-        // Need to be able to see the .pb.h files that are generated
-        export_proto_headers: true,
-        include_dirs: [
-            "external/protobuf/src",
-            "frameworks/proto_logging/stats",
-        ],
     },
     srcs: [
-        "threadnetwork_atoms.proto",
-        ":libstats_atom_options_protos",
-        ":libprotobuf-internal-descriptor-proto",
+        ":network_stack_enum_proto",
+        "network_stack.proto",
+    ],
+    sdk_version: "system_29",
+}
+
+java_library_static {
+    name: "datastallprotosnano",
+    proto: {
+        type: "nano",
+    },
+    srcs: [
+        ":data_stall_event_enums_proto",
+        "data_stall_event.proto",
     ],
-    min_sdk_version: "30",
-    apex_available: [ "com.android.tethering" ],
+    sdk_version: "system_current",
+    // this is part of updatable modules(NetworkStack) which targets 29(Q)
+    min_sdk_version: "29",
 }
diff --git a/stats/message/connectivity/data_stall_event.proto b/stats/message/connectivity/data_stall_event.proto
new file mode 100644
index 00000000..058721f4
--- /dev/null
+++ b/stats/message/connectivity/data_stall_event.proto
@@ -0,0 +1,52 @@
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
+package com.android.server.connectivity;
+option java_multiple_files = true;
+
+import "frameworks/proto_logging/stats/enums/server/connectivity/data_stall_event.proto";
+
+// Cellular specific information.
+message CellularData {
+    // Indicate the radio technology at the time of data stall suspected.
+    optional RadioTech rat_type = 1;
+    // True if device is in roaming network at the time of data stall suspected.
+    optional bool is_roaming = 2;
+    // Registered network MccMnc when data stall happen
+    optional string network_mccmnc = 3;
+    // Indicate the SIM card carrier.
+    optional string sim_mccmnc = 4;
+    // Signal strength level at the time of data stall suspected.
+    optional int32 signal_strength = 5;
+}
+
+// Wifi specific information.
+message WifiData {
+    // Signal strength at the time of data stall suspected.
+    // RSSI range is between -55 to -110.
+    optional int32 signal_strength = 1;
+    // AP band.
+    optional ApBand wifi_band = 2;
+}
+
+message DnsEvent {
+    // The dns return code.
+    repeated int32 dns_return_code = 1;
+    // Indicate the timestamp of the dns event.
+    repeated int64 dns_time = 2;
+}
diff --git a/stats/message/connectivity/network_stack.proto b/stats/message/connectivity/network_stack.proto
new file mode 100644
index 00000000..5af6acf6
--- /dev/null
+++ b/stats/message/connectivity/network_stack.proto
@@ -0,0 +1,25 @@
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
+package android.stats.connectivity;
+option java_multiple_files = true;
+option java_outer_classname = "NetworkStackProto";
+
+message NetworkStackEventData {
+
+}
diff --git a/stats/message/devicepolicy/Android.bp b/stats/message/devicepolicy/Android.bp
new file mode 100644
index 00000000..34db6c55
--- /dev/null
+++ b/stats/message/devicepolicy/Android.bp
@@ -0,0 +1,38 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+    name: "devicepolicyprotosnano",
+    proto: {
+        type: "nano",
+    },
+    srcs: [
+        ":device_policy_enums_proto",
+        "*.proto",
+    ],
+    java_version: "1.8",
+    target: {
+        android: {
+            jarjar_rules: "jarjar-rules.txt",
+        },
+        host: {
+            static_libs: ["libprotobuf-java-nano"],
+        },
+    },
+    sdk_version: "core_platform",
+}
diff --git a/stats/enums/stats/devicepolicy/device_policy.proto b/stats/message/devicepolicy/device_policy.proto
similarity index 93%
rename from stats/enums/stats/devicepolicy/device_policy.proto
rename to stats/message/devicepolicy/device_policy.proto
index af30cf3f..c736d0e8 100644
--- a/stats/enums/stats/devicepolicy/device_policy.proto
+++ b/stats/message/devicepolicy/device_policy.proto
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2018 The Android Open Source Project
+ * Copyright (C) 2025 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
diff --git a/stats/enums/stats/devicepolicy/jarjar-rules.txt b/stats/message/devicepolicy/jarjar-rules.txt
similarity index 100%
rename from stats/enums/stats/devicepolicy/jarjar-rules.txt
rename to stats/message/devicepolicy/jarjar-rules.txt
diff --git a/stats/message/mediametrics_message.proto b/stats/message/mediametrics/mediametrics_message.proto
similarity index 100%
rename from stats/message/mediametrics_message.proto
rename to stats/message/mediametrics/mediametrics_message.proto
diff --git a/stats/stats_log_api_gen/Android.bp b/stats/stats_log_api_gen/Android.bp
index c278d1c2..34b25424 100644
--- a/stats/stats_log_api_gen/Android.bp
+++ b/stats/stats_log_api_gen/Android.bp
@@ -245,6 +245,44 @@ cc_library_static {
     ],
 }
 
+rust_test_host {
+    name: "test_api_gen_vendor_rust",
+    crate_name: "test_api_gen_vendor_rust",
+    crate_root: "test_api_gen_vendor.rs",
+    edition: "2021",
+    rustlibs: [
+        "android.frameworks.stats-V2-rust",
+        "libtest_vendor_atoms_rust",
+        "libmatches",
+    ],
+}
+
+genrule {
+    name: "test_vendor_atoms.rs",
+    tools: ["stats-log-api-gen"],
+    cmd: "$(location stats-log-api-gen) --rust $(out)" +
+        " --vendor-proto frameworks/proto_logging/stats/stats_log_api_gen/test_vendor_atoms.proto",
+    out: [
+        "test_vendor_atoms.rs",
+    ],
+    srcs: [
+        "test_vendor_atoms.proto",
+        ":libprotobuf-internal-descriptor-proto",
+        ":libstats_atom_options_protos",
+    ],
+}
+
+rust_library {
+    name: "libtest_vendor_atoms_rust",
+    crate_name: "test_vendor_atoms",
+    srcs: [":test_vendor_atoms.rs"],
+    edition: "2021",
+    rustlibs: [
+        "android.frameworks.stats-V2-rust",
+    ],
+    host_supported: true,
+}
+
 // ==========================================================
 // Native library
 // ==========================================================
@@ -333,6 +371,7 @@ rust_library {
     apex_available: [
         "//apex_available:platform",
         "com.android.resolv",
+        "com.android.uprobestats",
         "com.android.virt",
     ],
     min_sdk_version: "29",
diff --git a/stats/stats_log_api_gen/java_writer.cpp b/stats/stats_log_api_gen/java_writer.cpp
index add72a62..2308a3c0 100644
--- a/stats/stats_log_api_gen/java_writer.cpp
+++ b/stats/stats_log_api_gen/java_writer.cpp
@@ -387,7 +387,8 @@ int write_stats_log_java(FILE* out, const Atoms& atoms, const AtomDecl& attribut
     fprintf(out, " * @hide\n");
     fprintf(out, " */\n");
 
-    fprintf(out, "public class %s {\n", javaClass.c_str());
+    const char* finalPrefix = staticMethods ? "final " : "";
+    fprintf(out, "public %sclass %s {\n", finalPrefix, javaClass.c_str());
 
     write_java_atom_codes(out, atoms);
     write_java_enum_values(out, atoms);
diff --git a/stats/stats_log_api_gen/main.cpp b/stats/stats_log_api_gen/main.cpp
index 55a735b0..db15a80f 100644
--- a/stats/stats_log_api_gen/main.cpp
+++ b/stats/stats_log_api_gen/main.cpp
@@ -36,11 +36,13 @@ static void print_usage() {
     fprintf(stderr, "  --help               this message\n");
     fprintf(stderr, "  --java FILENAME      the java file to output\n");
     fprintf(stderr, "  --rust FILENAME      the rust file to output\n");
-    fprintf(stderr, "  --rustHeader FILENAME the rust file to output for write helpers\n");
+    fprintf(stderr,
+            "  --rustHeader FILENAME the rust file to output for write helpers. "
+            "Not needed/supported for --vendor-proto\n");
     fprintf(stderr,
             "  --rustHeaderCrate NAME        header crate to be used while "
             "generating the code. Note: this should be the same as the crate_name "
-            "created by rust_library for the header \n");
+            "created by rust_library for the header. Not needed for --vendor-proto\n");
     fprintf(stderr, "  --module NAME        optional, module name to generate outputs for\n");
     fprintf(stderr,
             "  --namespace COMMA,SEP,NAMESPACE   required for cpp/header with "
@@ -372,8 +374,8 @@ static int run(int argc, char const* const* argv) {
                 return 1;
             }
 
-            errorCount = android::stats_log_api_gen::write_stats_log_java_vendor(out, atoms,
-                    javaClass, javaPackage, javaStaticMethods);
+            errorCount = android::stats_log_api_gen::write_stats_log_java_vendor(
+                    out, atoms, javaClass, javaPackage, javaStaticMethods);
 #endif
         }
 
@@ -382,8 +384,8 @@ static int run(int argc, char const* const* argv) {
 
     // Write the main .rs file
     if (!rustFilename.empty()) {
-        if (rustHeaderCrate.empty()) {
-            fprintf(stderr, "rustHeaderCrate flag is either not passed or is empty");
+        if (rustHeaderCrate.empty() && vendorProto.empty()) {
+            fprintf(stderr, "rustHeaderCrate flag is either not passed or is empty\n");
             return 1;
         }
 
@@ -393,14 +395,24 @@ static int run(int argc, char const* const* argv) {
             return 1;
         }
 
-        errorCount += android::stats_log_api_gen::write_stats_log_rust(
-                out, atoms, attributionDecl, minApiLevel, rustHeaderCrate.c_str());
+        if (vendorProto.empty()) {
+            errorCount += android::stats_log_api_gen::write_stats_log_rust(
+                    out, atoms, attributionDecl, minApiLevel, rustHeaderCrate.c_str());
+        } else {
+            errorCount += android::stats_log_api_gen::write_stats_log_rust_vendor(out, atoms,
+                                                                                  attributionDecl);
+        }
 
         fclose(out);
     }
 
     // Write the header .rs file
     if (!rustHeaderFilename.empty()) {
+        if (!vendorProto.empty()) {
+            fprintf(stderr, "rustHeaderFilename is not needed for vendor proto\n");
+            return 1;
+        }
+
         if (rustHeaderCrate.empty()) {
             fprintf(stderr, "rustHeaderCrate flag is either not passed or is empty");
             return 1;
diff --git a/stats/stats_log_api_gen/rust_writer.cpp b/stats/stats_log_api_gen/rust_writer.cpp
index b21d4a12..5afc6383 100644
--- a/stats/stats_log_api_gen/rust_writer.cpp
+++ b/stats/stats_log_api_gen/rust_writer.cpp
@@ -21,6 +21,7 @@
 #include <algorithm>
 #include <cctype>
 #include <map>
+#include <ranges>
 
 #include "Collation.h"
 #include "utils.h"
@@ -405,6 +406,193 @@ static int write_rust_stats_write_method(FILE* out, const shared_ptr<AtomDecl>&
     return 0;
 }
 
+static bool needs_lifetime(const shared_ptr<AtomDecl>& atomDecl) {
+    for (const AtomField& atomField : atomDecl->fields) {
+        const java_type_t& type = atomField.javaType;
+        if (type == JAVA_TYPE_ATTRIBUTION_CHAIN || type == JAVA_TYPE_STRING ||
+            type == JAVA_TYPE_BYTE_ARRAY) {
+            return true;
+        }
+    }
+    return false;
+}
+
+// Ported from write_native_annotations_vendor_for_field() in native_writer_vendor.cpp.
+static void write_rust_vendor_annotations(
+        FILE* out, const map<AnnotationId, AnnotationStruct>& annotationIdConstants,
+        const AnnotationSet& annotationSet, const string& fieldName, const char* indent,
+        const char* begin, const char* end, const char* empty) {
+    bool isEmpty = true;
+
+    int resetState = -1;
+    int defaultState = -1;
+
+    for (const shared_ptr<Annotation>& annotation : annotationSet) {
+        const AnnotationStruct& annotationConstant =
+                annotationIdConstants.at(annotation->annotationId);
+
+        if (ANNOTATION_ID_TRIGGER_STATE_RESET == annotation->annotationId) {
+            resetState = annotation->value.intValue;
+        } else if (ANNOTATION_ID_DEFAULT_STATE == annotation->annotationId) {
+            defaultState = annotation->value.intValue;
+        } else {
+            if (isEmpty) {
+                isEmpty = false;
+                fprintf(out, "%s\n", begin);
+            }
+            switch (annotation->type) {
+                case ANNOTATION_TYPE_INT:
+                    fprintf(out,
+                            "%s    Some(Annotation { annotationId: AnnotationId::%s, "
+                            "value: AnnotationValue::IntValue(%d) }),\n",
+                            indent, annotationConstant.name.c_str(), annotation->value.intValue);
+                    break;
+                case ANNOTATION_TYPE_BOOL:
+                    fprintf(out,
+                            "%s    Some(Annotation { annotationId: AnnotationId::%s, "
+                            "value: AnnotationValue::BoolValue(%s) }),\n",
+                            indent, annotationConstant.name.c_str(),
+                            annotation->value.boolValue ? "true" : "false");
+                    break;
+                default:
+                    break;
+            }
+        }
+    }
+
+    if (defaultState != -1 && resetState != -1) {
+        if (isEmpty) {
+            isEmpty = false;
+            fprintf(out, "%s\n", begin);
+        }
+        const AnnotationStruct& annotationConstant =
+                annotationIdConstants.at(ANNOTATION_ID_TRIGGER_STATE_RESET);
+        fprintf(out,
+                "%s    if self.%s as i32 == %d { Some(Annotation { annotationId: AnnotationId::%s, "
+                "value: AnnotationValue::IntValue(%d) }) } else { None },\n",
+                indent, get_variable_name(fieldName).c_str(), resetState,
+                annotationConstant.name.c_str(), defaultState);
+    }
+
+    if (isEmpty) {
+        fprintf(out, "%s,\n", empty);
+    } else {
+        fprintf(out, "%s%s,\n", indent, end);
+    }
+}
+
+static int write_rust_vendor_atom_method(FILE* out, const shared_ptr<AtomDecl>& atomDecl) {
+    const bool lifetime = needs_lifetime(atomDecl);
+
+    fprintf(out, "    impl %s%s {\n", make_camel_case_name(atomDecl->name).c_str(),
+            lifetime ? "<'_>" : "");
+
+    fprintf(out, "        pub const CODE: i32 = %d;\n", atomDecl->code);
+    fprintf(out, "\n");
+
+    fprintf(out, "        pub fn to_vendor_atom(&self) -> VendorAtom {\n");
+    fprintf(out, "            VendorAtom {\n");
+    fprintf(out, "                atomId: Self::CODE,\n");
+    fprintf(out, "                reverseDomainName: self.%s.to_string(),\n",
+            get_variable_name(atomDecl->fields.at(0).name).c_str());
+    fprintf(out, "                values: vec![\n");
+    for (const AtomField& field : atomDecl->fields | std::ranges::views::drop(1)) {
+        fprintf(out, "                    VendorAtomValue::");
+        switch (field.javaType) {
+            case JAVA_TYPE_BOOLEAN:
+                fprintf(out, "BoolValue(self.%s),\n", get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_INT:
+                fprintf(out, "IntValue(self.%s),\n", get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_ENUM:
+                fprintf(out, "IntValue(self.%s as i32),\n", get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_FLOAT:
+                fprintf(out, "FloatValue(self.%s),\n", get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_LONG:
+                fprintf(out, "LongValue(self.%s),\n", get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_STRING:
+                fprintf(out, "StringValue(self.%s.to_string()),\n",
+                        get_variable_name(field.name).c_str());
+                break;
+            case JAVA_TYPE_BYTE_ARRAY:
+                fprintf(out, "ByteArrayValue(Some(self.%s.to_vec())),\n",
+                        get_variable_name(field.name).c_str());
+                break;
+            default:
+                // Unsupported types: OBJECT, DOUBLE
+                fprintf(stderr, "Encountered unsupported type: %d.", field.javaType);
+                return 1;
+        }
+    }
+    fprintf(out, "                ],\n");
+
+    const auto ANNOTATION_ID_CONSTANTS = get_annotation_id_constants("");
+    {
+        bool hasValuesAnnotations = false;
+        for (const auto& [argIndex, annotations] : atomDecl->fieldNumberToAnnotations) {
+            if (argIndex == ATOM_ID_FIELD_NUMBER) {
+                continue;
+            }
+            const int valueIndex = argIndex - 2;
+
+            if (!hasValuesAnnotations) {
+                hasValuesAnnotations = true;
+                fprintf(out, "                valuesAnnotations: Some(vec![\n");
+            }
+            fprintf(out, "                    Some(AnnotationSet {\n");
+            fprintf(out, "                        valueIndex: %d,\n", valueIndex);
+            fprintf(out, "                        annotations: ");
+            write_rust_vendor_annotations(out, ANNOTATION_ID_CONSTANTS,
+                                          /*annotationSet=*/annotations,
+                                          /*fieldName=*/atomDecl->fields.at(argIndex - 1).name,
+                                          /*indent=*/"                        ",
+                                          /*begin=*/"[",
+                                          /*end*/ "].into_iter().flatten().collect()",
+                                          /*empty=*/"Vec::new()");
+            fprintf(out, "                    }),\n");
+        }
+        if (hasValuesAnnotations) {
+            fprintf(out, "                ]),\n");
+        } else {
+            fprintf(out, "                valuesAnnotations: None,\n");
+        }
+    }
+    {
+        fprintf(out, "                atomAnnotations: ");
+        if (auto atomAnnotations = atomDecl->fieldNumberToAnnotations.find(ATOM_ID_FIELD_NUMBER);
+            atomAnnotations != atomDecl->fieldNumberToAnnotations.end()) {
+            write_rust_vendor_annotations(
+                    out, ANNOTATION_ID_CONSTANTS,
+                    /*annotationSet=*/atomAnnotations->second,
+                    /*fieldName=*/"<ATOM_ANNOTATIONS>",
+                    /*indent*/ "                ",
+                    /*begin=*/"Some([",
+                    /*end=*/"].into_iter().filter(Option::is_some).collect())",
+                    /*empty=*/"None");
+        } else {
+            fprintf(out, "None,\n");
+        }
+    }
+
+    fprintf(out, "            }\n");
+    fprintf(out, "        }\n");
+    fprintf(out, "    }\n");
+    fprintf(out, "\n");
+
+    fprintf(out, "    impl From<%s%s> for VendorAtom {\n",
+            make_camel_case_name(atomDecl->name).c_str(), lifetime ? "<'_>" : "");
+    fprintf(out, "        fn from(value: %s) -> VendorAtom {\n",
+            make_camel_case_name(atomDecl->name).c_str());
+    fprintf(out, "            value.to_vendor_atom()\n");
+    fprintf(out, "        }\n");
+    fprintf(out, "    }\n");
+    return 0;
+}
+
 static void write_rust_stats_write_non_chained_method(FILE* out,
                                                       const shared_ptr<AtomDecl>& atomDecl,
                                                       const AtomDecl& attributionDecl,
@@ -437,20 +625,8 @@ static void write_rust_stats_write_non_chained_method(FILE* out,
     fprintf(out, "    }\n\n");
 }
 
-static bool needs_lifetime(const shared_ptr<AtomDecl>& atomDecl) {
-    for (const AtomField& atomField : atomDecl->fields) {
-        const java_type_t& type = atomField.javaType;
-        if (type == JAVA_TYPE_ATTRIBUTION_CHAIN || type == JAVA_TYPE_STRING ||
-            type == JAVA_TYPE_BYTE_ARRAY) {
-            return true;
-        }
-    }
-    return false;
-}
-
 static void write_rust_struct(FILE* out, const shared_ptr<AtomDecl>& atomDecl,
-                              const AtomDecl& attributionDecl, const char* headerCrate) {
-    // Write the struct.
+                              const AtomDecl& attributionDecl) {
     const bool lifetime = needs_lifetime(atomDecl);
     if (lifetime) {
         fprintf(out, "    pub struct %s<'a> {\n", make_camel_case_name(atomDecl->name).c_str());
@@ -474,8 +650,11 @@ static void write_rust_struct(FILE* out, const shared_ptr<AtomDecl>& atomDecl,
         }
     }
     fprintf(out, "    }\n");
+}
 
-    // Write the impl
+static void write_rust_impl(FILE* out, const shared_ptr<AtomDecl>& atomDecl,
+                            const AtomDecl& attributionDecl, const char* headerCrate) {
+    const bool lifetime = needs_lifetime(atomDecl);
     const bool isPush = atomDecl->atomType == ATOM_TYPE_PUSHED;
     if (isPush) {
         if (lifetime) {
@@ -524,7 +703,8 @@ static void write_rust_struct(FILE* out, const shared_ptr<AtomDecl>& atomDecl,
 static int write_rust_stats_write_atoms(FILE* out, const AtomDeclSet& atomDeclSet,
                                         const AtomDecl& attributionDecl,
                                         const AtomDeclSet& nonChainedAtomDeclSet,
-                                        const int minApiLevel, const char* headerCrate) {
+                                        const int minApiLevel, const char* headerCrate,
+                                        bool isVendor) {
     for (const auto& atomDecl : atomDeclSet) {
         // TODO(b/216543320): support repeated fields in Rust
         if (std::find_if(atomDecl->fields.begin(), atomDecl->fields.end(),
@@ -534,21 +714,44 @@ static int write_rust_stats_write_atoms(FILE* out, const AtomDeclSet& atomDeclSe
             continue;
         }
         fprintf(out, "pub mod %s {\n", atomDecl->name.c_str());
-        fprintf(out, "    use statspull_bindgen::*;\n");
-        fprintf(out, "    #[allow(unused)]\n");
-        fprintf(out, "    use std::convert::TryInto;\n");
+        if (isVendor) {
+            const char* AIDL_STATS = "android_frameworks_stats::aidl::android::frameworks::stats";
+            fprintf(out,
+
+                    R"(    use %1$s::Annotation::Annotation;
+    use %1$s::AnnotationId::AnnotationId;
+    use %1$s::AnnotationSet::AnnotationSet;
+    use %1$s::AnnotationValue::AnnotationValue;
+    use %1$s::VendorAtom::VendorAtom;
+    use %1$s::VendorAtomValue::VendorAtomValue;
+)",
+                    AIDL_STATS);
+        } else {
+            fprintf(out, "    use statspull_bindgen::*;\n");
+            fprintf(out, "    #[allow(unused)]\n");
+            fprintf(out, "    use std::convert::TryInto;\n");
+        }
         fprintf(out, "\n");
         write_rust_atom_constant_values(out, atomDecl);
-        write_rust_struct(out, atomDecl, attributionDecl, headerCrate);
-        const int ret = write_rust_stats_write_method(out, atomDecl, attributionDecl, minApiLevel,
-                                                      headerCrate);
-        if (ret != 0) {
-            return ret;
-        }
-        auto nonChained = nonChainedAtomDeclSet.find(atomDecl);
-        if (nonChained != nonChainedAtomDeclSet.end()) {
-            write_rust_stats_write_non_chained_method(out, *nonChained, attributionDecl,
-                                                      headerCrate);
+        write_rust_struct(out, atomDecl, attributionDecl);
+        if (isVendor) {
+            const int ret = write_rust_vendor_atom_method(out, atomDecl);
+            if (ret != 0) {
+                return ret;
+            }
+        } else {
+            write_rust_impl(out, atomDecl, attributionDecl, headerCrate);
+            const int ret = write_rust_stats_write_method(out, atomDecl, attributionDecl,
+                                                          minApiLevel, headerCrate);
+            if (ret != 0) {
+                return ret;
+            }
+            auto nonChained = nonChainedAtomDeclSet.find(atomDecl);
+            if (nonChained != nonChainedAtomDeclSet.end()) {
+                (void)write_rust_stats_write_non_chained_method;
+                write_rust_stats_write_non_chained_method(out, *nonChained, attributionDecl,
+                                                          headerCrate);
+            }
         }
         fprintf(out, "}\n");
     }
@@ -599,8 +802,24 @@ int write_stats_log_rust(FILE* out, const Atoms& atoms, const AtomDecl& attribut
 
     write_rust_annotation_constants(out);
 
-    const int errorCount = write_rust_stats_write_atoms(
-            out, atoms.decls, attributionDecl, atoms.non_chained_decls, minApiLevel, headerCrate);
+    const int errorCount =
+            write_rust_stats_write_atoms(out, atoms.decls, attributionDecl, atoms.non_chained_decls,
+                                         minApiLevel, headerCrate, /*isVendor=*/false);
+
+    return errorCount;
+}
+
+int write_stats_log_rust_vendor(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl) {
+    // Print prelude
+    fprintf(out, "// This file is autogenerated.\n");
+    fprintf(out, "\n");
+    fprintf(out, "#![allow(missing_docs)]\n");
+    fprintf(out, "#![allow(unused_imports)]\n");
+    fprintf(out, "#![allow(non_snake_case)]\n");
+
+    const int errorCount = write_rust_stats_write_atoms(out, atoms.decls, attributionDecl,
+                                                        atoms.non_chained_decls, /*minApiLevel=*/0,
+                                                        /*headerCrate=*/nullptr, /*isVendor=*/true);
 
     return errorCount;
 }
diff --git a/stats/stats_log_api_gen/rust_writer.h b/stats/stats_log_api_gen/rust_writer.h
index 70c2f3e3..f5fb4073 100644
--- a/stats/stats_log_api_gen/rust_writer.h
+++ b/stats/stats_log_api_gen/rust_writer.h
@@ -26,6 +26,8 @@ namespace stats_log_api_gen {
 int write_stats_log_rust(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                          const int minApiLevel, const char* rustHeaderCrate);
 
+int write_stats_log_rust_vendor(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl);
+
 void write_stats_log_rust_header(FILE* out, const Atoms& atoms, const AtomDecl& attributionDecl,
                                  const char* rustHeaderCrate);
 
diff --git a/stats/stats_log_api_gen/test_api_gen_vendor.cpp b/stats/stats_log_api_gen/test_api_gen_vendor.cpp
index 0dc5c3ca..87d2a7ac 100644
--- a/stats/stats_log_api_gen/test_api_gen_vendor.cpp
+++ b/stats/stats_log_api_gen/test_api_gen_vendor.cpp
@@ -273,8 +273,8 @@ TEST(ApiGenVendorAtomTest, buildAtomWithTruncateTimestampTest) {
     EXPECT_EQ(atom2.atomAnnotations.value()[0]->annotationId, AnnotationId::TRUNCATE_TIMESTAMP);
     EXPECT_TRUE(atom2.atomAnnotations.value()[0]->value.get<AnnotationValue::boolValue>());
 
-    VendorAtom atom3 = func(TRUNCATE_TIMESTAMP_ATOM2, kTestStringValue, kTestIntValue);
-    EXPECT_EQ(atom3.atomId, TRUNCATE_TIMESTAMP_ATOM2);
+    VendorAtom atom3 = func(TRUNCATE_TIMESTAMP_ATOM3, kTestStringValue, kTestIntValue);
+    EXPECT_EQ(atom3.atomId, TRUNCATE_TIMESTAMP_ATOM3);
     EXPECT_EQ(atom3.reverseDomainName, kTestStringValue);
     EXPECT_EQ(atom3.values.size(), static_cast<size_t>(1));
     EXPECT_EQ(atom3.values[0].get<VendorAtomValue::intValue>(), kTestIntValue);
diff --git a/stats/stats_log_api_gen/test_api_gen_vendor.rs b/stats/stats_log_api_gen/test_api_gen_vendor.rs
new file mode 100644
index 00000000..7b8d1e0c
--- /dev/null
+++ b/stats/stats_log_api_gen/test_api_gen_vendor.rs
@@ -0,0 +1,464 @@
+// Copyright (C) 2025 The Android Open Source Project
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
+use android_frameworks_stats::aidl::android::frameworks::stats::AnnotationId::AnnotationId;
+use android_frameworks_stats::aidl::android::frameworks::stats::AnnotationValue::AnnotationValue;
+use android_frameworks_stats::aidl::android::frameworks::stats::VendorAtomValue::VendorAtomValue;
+use matches::assert_matches;
+
+const TEST_INT_VALUE: i32 = 100;
+const TEST_UID_VALUE: i32 = 1000;
+const TEST_PID_VALUE: i32 = 3000;
+const TEST_LONG_VALUE: i64 = i64::MAX - (TEST_INT_VALUE as i64);
+const TEST_FLOAT_VALUE: f32 = TEST_INT_VALUE as f32 / TEST_LONG_VALUE as f32;
+const TEST_BOOL_VALUE: bool = true;
+const TEST_STRING_VALUE: &str = "test_string";
+const TEST_STRING_VALUE2: &str = "test_string2";
+
+trait VendorAtomValueExt {
+    fn unwrap_int_value(&self) -> i32;
+    fn unwrap_long_value(&self) -> i64;
+    fn unwrap_float_value(&self) -> f32;
+    fn unwrap_bool_value(&self) -> bool;
+    fn unwrap_byte_array_value(&self) -> &[u8];
+}
+
+impl VendorAtomValueExt for VendorAtomValue {
+    fn unwrap_int_value(&self) -> i32 {
+        match self {
+            VendorAtomValue::IntValue(x) => *x,
+            _ => panic!("not an IntValue"),
+        }
+    }
+    fn unwrap_long_value(&self) -> i64 {
+        match self {
+            VendorAtomValue::LongValue(x) => *x,
+            _ => panic!("not a LongValue"),
+        }
+    }
+    fn unwrap_float_value(&self) -> f32 {
+        match self {
+            VendorAtomValue::FloatValue(x) => *x,
+            _ => panic!("not a FloatValue"),
+        }
+    }
+    fn unwrap_bool_value(&self) -> bool {
+        match self {
+            VendorAtomValue::BoolValue(x) => *x,
+            _ => panic!("not a BoolValue"),
+        }
+    }
+    fn unwrap_byte_array_value(&self) -> &[u8] {
+        match self {
+            VendorAtomValue::ByteArrayValue(Some(x)) => x,
+            VendorAtomValue::ByteArrayValue(None) => panic!("ByteArrayValue is None"),
+            _ => panic!("not a ByteArrayValue"),
+        }
+    }
+}
+
+/// Tests native auto generated code for specific vendor atom contains proper ids
+#[test]
+fn atom_id_constants_test() {
+    assert_eq!(test_vendor_atoms::vendorAtom1::Vendoratom1::CODE, 105501);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Vendoratom2::CODE, 105502);
+    // TODO(b/216543320): support repeated fields in Rust
+    // assert_eq!(test_vendor_atoms::vendorAtom4::Vendoratom4::CODE, 105504);
+}
+
+/// Tests native auto generated code for specific vendor atom contains proper enums
+#[test]
+fn atom_enum_test() {
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield1::TypeUnknown as i32, 0);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield1::Type1 as i32, 1);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield1::Type2 as i32, 2);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield1::Type3 as i32, 3);
+
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield3::AnotherTypeUnknown as i32, 0);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield3::AnotherType1 as i32, 1);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield3::AnotherType2 as i32, 2);
+    assert_eq!(test_vendor_atoms::vendorAtom1::Enumfield3::AnotherType3 as i32, 3);
+
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield1::TypeUnknown as i32, 0);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield1::Type1 as i32, 1);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield1::Type2 as i32, 2);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield1::Type3 as i32, 3);
+
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield3::AnotherTypeUnknown as i32, 0);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield3::AnotherType1 as i32, 1);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield3::AnotherType2 as i32, 2);
+    assert_eq!(test_vendor_atoms::vendorAtom2::Enumfield3::AnotherType3 as i32, 3);
+
+    // TODO(b/216543320): support repeated fields in Rust
+    // assert_eq!(test_vendor_atoms::vendorAtom4::Enumfield1::TypeUnknown as i32, 0);
+    // assert_eq!(test_vendor_atoms::vendorAtom4::Enumfield1::Type1 as i32, 1);
+}
+
+#[test]
+fn build_vendor_atom1_api_test() {
+    use test_vendor_atoms::vendorAtom1;
+
+    let atom = vendorAtom1::Vendoratom1 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        enum_field1: vendorAtom1::Enumfield1::Type1,
+        enum_field2: vendorAtom1::Enumfield2::Type2,
+        int_value32: TEST_INT_VALUE,
+        int_value64: TEST_LONG_VALUE,
+        float_value: TEST_FLOAT_VALUE,
+        bool_value: TEST_BOOL_VALUE,
+        enum_field3: vendorAtom1::Enumfield3::AnotherType2,
+        enum_field4: vendorAtom1::Enumfield4::AnotherType3,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, vendorAtom1::Vendoratom1::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 8);
+    assert_eq!(atom.values[0].unwrap_int_value(), vendorAtom1::Enumfield1::Type1 as _);
+    assert_eq!(atom.values[1].unwrap_int_value(), vendorAtom1::Enumfield1::Type2 as _);
+    assert_eq!(atom.values[2].unwrap_int_value(), TEST_INT_VALUE);
+    assert_eq!(atom.values[3].unwrap_long_value(), TEST_LONG_VALUE);
+    assert_eq!(atom.values[4].unwrap_float_value(), TEST_FLOAT_VALUE);
+    assert_eq!(atom.values[5].unwrap_bool_value(), TEST_BOOL_VALUE);
+    assert_eq!(atom.values[6].unwrap_int_value(), vendorAtom1::Enumfield3::AnotherType2 as _);
+    assert_eq!(atom.values[7].unwrap_int_value(), vendorAtom1::Enumfield4::AnotherType3 as _);
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_vendor_atom3_api_test() {
+    use test_vendor_atoms::vendorAtom3;
+
+    let atom = vendorAtom3::Vendoratom3 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        int_field: TEST_INT_VALUE,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, vendorAtom3::Vendoratom3::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 1);
+    assert_eq!(atom.values[0].unwrap_int_value(), TEST_INT_VALUE);
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_vendor_atom4_api_test() {
+    // TODO(b/216543320): support repeated fields in Rust
+    // vendorAtom4 depends on repeated fields
+}
+
+#[test]
+fn build_vendor_atom5_api_test() {
+    use test_vendor_atoms::vendorAtom5;
+
+    // The C++ buildVendorAtom5ApiTest test uses a serialized TestNestedMessage.
+    // Here we use raw bytes without protobuf.
+    let nested_data = TEST_STRING_VALUE2.as_bytes();
+    let atom = vendorAtom5::Vendoratom5 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        float_field: TEST_FLOAT_VALUE,
+        int_field: TEST_INT_VALUE,
+        long_field: TEST_LONG_VALUE,
+        nested_message_field: nested_data,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, vendorAtom5::Vendoratom5::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 4);
+    assert_eq!(atom.values[0].unwrap_float_value(), TEST_FLOAT_VALUE);
+    assert_eq!(atom.values[1].unwrap_int_value(), TEST_INT_VALUE);
+    assert_eq!(atom.values[2].unwrap_long_value(), TEST_LONG_VALUE);
+    assert_eq!(atom.values[3].unwrap_byte_array_value(), nested_data);
+    assert!(atom.valuesAnnotations.is_none()); // C++ checks atomAnnotations, Rust generated code puts annotations in valuesAnnotations
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_atom_with_truncate_timestamp_test() {
+    use test_vendor_atoms::{
+        truncateTimestampAtom1, truncateTimestampAtom2, truncateTimestampAtom3,
+    };
+
+    let atom1 = truncateTimestampAtom1::Truncatetimestampatom1 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        state: truncateTimestampAtom1::State::TestState1,
+    }
+    .to_vendor_atom();
+    assert_eq!(atom1.atomId, truncateTimestampAtom1::Truncatetimestampatom1::CODE);
+    assert_eq!(atom1.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom1.values.len(), 1);
+    assert_eq!(atom1.values[0].unwrap_int_value(), truncateTimestampAtom1::State::TestState1 as _);
+    assert!(atom1.atomAnnotations.is_some());
+    assert_eq!(atom1.atomAnnotations.as_ref().unwrap().len(), 1);
+    assert!(atom1.atomAnnotations.as_ref().unwrap()[0].is_some());
+    assert_eq!(
+        atom1.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotationId,
+        AnnotationId::TRUNCATE_TIMESTAMP
+    );
+    assert_matches!(
+        atom1.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().value,
+        AnnotationValue::BoolValue(true)
+    );
+
+    let atom2 = truncateTimestampAtom2::Truncatetimestampatom2 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        state: truncateTimestampAtom2::State::TestState2,
+    }
+    .to_vendor_atom();
+    assert_eq!(atom2.atomId, truncateTimestampAtom2::Truncatetimestampatom2::CODE);
+    assert_eq!(atom2.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom2.values.len(), 1);
+    assert_eq!(atom2.values[0].unwrap_int_value(), truncateTimestampAtom2::State::TestState2 as _);
+    assert!(atom2.atomAnnotations.is_some());
+    assert_eq!(atom2.atomAnnotations.as_ref().unwrap().len(), 1);
+    assert!(atom2.atomAnnotations.as_ref().unwrap()[0].is_some());
+    assert_eq!(
+        atom2.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotationId,
+        AnnotationId::TRUNCATE_TIMESTAMP
+    );
+    assert_matches!(
+        atom2.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().value,
+        AnnotationValue::BoolValue(true)
+    );
+
+    let atom3 = truncateTimestampAtom3::Truncatetimestampatom3 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        int_value: TEST_INT_VALUE,
+    }
+    .to_vendor_atom();
+    assert_eq!(atom3.atomId, truncateTimestampAtom3::Truncatetimestampatom3::CODE);
+    assert_eq!(atom3.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom3.values.len(), 1);
+    assert_eq!(atom3.values[0].unwrap_int_value(), TEST_INT_VALUE);
+    assert!(atom3.atomAnnotations.is_some());
+    assert_eq!(atom3.atomAnnotations.as_ref().unwrap().len(), 1);
+    assert!(atom3.atomAnnotations.as_ref().unwrap()[0].is_some());
+    assert_eq!(
+        atom3.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotationId,
+        AnnotationId::TRUNCATE_TIMESTAMP
+    );
+    assert_matches!(
+        atom3.atomAnnotations.as_ref().unwrap()[0].as_ref().unwrap().value,
+        AnnotationValue::BoolValue(true)
+    );
+}
+
+#[test]
+fn build_atom_with_exclusive_state_annotation_test() {
+    use test_vendor_atoms::stateAtom3;
+
+    let atom = stateAtom3::Stateatom3 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        state: stateAtom3::State::TestState3,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, stateAtom3::Stateatom3::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 1);
+    assert_eq!(atom.values[0].unwrap_int_value(), stateAtom3::State::TestState3 as _);
+    assert!(atom.valuesAnnotations.is_some());
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap().len(), 1);
+    assert!(atom.valuesAnnotations.as_ref().unwrap()[0].is_some());
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().valueIndex, 0);
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations.len(), 1);
+    assert_eq!(
+        atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations[0].annotationId,
+        AnnotationId::EXCLUSIVE_STATE
+    );
+    assert_matches!(
+        atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations[0].value,
+        AnnotationValue::BoolValue(true)
+    );
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_atom_with_exclusive_state_and_primary_field_annotation_test() {
+    use test_vendor_atoms::stateAtom1;
+
+    let atom = stateAtom1::Stateatom1 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        uid: TEST_UID_VALUE,
+        state: stateAtom1::State::TestState3,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, stateAtom1::Stateatom1::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 2);
+    assert_eq!(atom.values[0].unwrap_int_value(), TEST_UID_VALUE);
+    assert_eq!(atom.values[1].unwrap_int_value(), stateAtom1::State::TestState3 as _);
+    assert!(atom.valuesAnnotations.is_some());
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap().len(), 2);
+    assert!(atom.valuesAnnotations.as_ref().unwrap()[0].is_some());
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().valueIndex, 0);
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations.len(), 1);
+    assert_eq!(
+        atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations[0].annotationId,
+        AnnotationId::PRIMARY_FIELD
+    );
+    assert_matches!(
+        atom.valuesAnnotations.as_ref().unwrap()[0].as_ref().unwrap().annotations[0].value,
+        AnnotationValue::BoolValue(true)
+    );
+    assert!(atom.valuesAnnotations.as_ref().unwrap()[1].is_some());
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[1].as_ref().unwrap().valueIndex, 1);
+    assert_eq!(atom.valuesAnnotations.as_ref().unwrap()[1].as_ref().unwrap().annotations.len(), 1);
+    assert_eq!(
+        atom.valuesAnnotations.as_ref().unwrap()[1].as_ref().unwrap().annotations[0].annotationId,
+        AnnotationId::EXCLUSIVE_STATE
+    );
+    assert_matches!(
+        atom.valuesAnnotations.as_ref().unwrap()[1].as_ref().unwrap().annotations[0].value,
+        AnnotationValue::BoolValue(true)
+    );
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_atom_with_exclusive_state_and_two_primary_field_annotation_test() {
+    use test_vendor_atoms::stateAtom2;
+
+    let atom = stateAtom2::Stateatom2 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        uid: TEST_UID_VALUE,
+        pid: TEST_PID_VALUE,
+        state: stateAtom2::State::TestState2,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, stateAtom2::Stateatom2::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 3);
+    assert_eq!(atom.values[0].unwrap_int_value(), TEST_UID_VALUE);
+    assert_eq!(atom.values[1].unwrap_int_value(), TEST_PID_VALUE);
+    assert_eq!(atom.values[2].unwrap_int_value(), stateAtom2::State::TestState2 as _);
+
+    assert!(atom.valuesAnnotations.is_some());
+    let annotations = atom.valuesAnnotations.as_ref().unwrap();
+    assert_eq!(annotations.len(), 3);
+
+    assert!(annotations[0].is_some());
+    let annotation_set0 = annotations[0].as_ref().unwrap();
+    assert_eq!(annotation_set0.valueIndex, 0);
+    assert_eq!(annotation_set0.annotations.len(), 1);
+    assert_eq!(annotation_set0.annotations[0].annotationId, AnnotationId::PRIMARY_FIELD);
+    assert_matches!(annotation_set0.annotations[0].value, AnnotationValue::BoolValue(true));
+
+    assert!(annotations[1].is_some());
+    let annotation_set1 = annotations[1].as_ref().unwrap();
+    assert_eq!(annotation_set1.valueIndex, 1);
+    assert_eq!(annotation_set1.annotations.len(), 1);
+    assert_eq!(annotation_set1.annotations[0].annotationId, AnnotationId::PRIMARY_FIELD);
+    assert_matches!(annotation_set1.annotations[0].value, AnnotationValue::BoolValue(true));
+
+    assert!(annotations[2].is_some());
+    let annotation_set2 = annotations[2].as_ref().unwrap();
+    assert_eq!(annotation_set2.valueIndex, 2);
+    assert_eq!(annotation_set2.annotations.len(), 1);
+    assert_eq!(annotation_set2.annotations[0].annotationId, AnnotationId::EXCLUSIVE_STATE);
+    assert_matches!(annotation_set2.annotations[0].value, AnnotationValue::BoolValue(true));
+
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_atom_with_multiple_annotations_per_value_test() {
+    use test_vendor_atoms::stateAtom4;
+
+    let atom = stateAtom4::Stateatom4 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        state: stateAtom4::State::On,
+        some_flag: TEST_BOOL_VALUE,
+    }
+    .to_vendor_atom();
+
+    assert_eq!(atom.atomId, stateAtom4::Stateatom4::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 2);
+    assert_eq!(atom.values[0].unwrap_int_value(), stateAtom4::State::On as _);
+    assert_eq!(atom.values[1].unwrap_bool_value(), TEST_BOOL_VALUE);
+
+    assert!(atom.valuesAnnotations.is_some());
+    let annotations = atom.valuesAnnotations.as_ref().unwrap();
+    assert_eq!(annotations.len(), 2);
+
+    assert!(annotations[0].is_some());
+    let annotation_set0 = annotations[0].as_ref().unwrap();
+    assert_eq!(annotation_set0.valueIndex, 0);
+    assert_eq!(annotation_set0.annotations.len(), 2);
+    assert_eq!(annotation_set0.annotations[0].annotationId, AnnotationId::EXCLUSIVE_STATE);
+    assert_matches!(annotation_set0.annotations[0].value, AnnotationValue::BoolValue(true));
+    assert_eq!(annotation_set0.annotations[1].annotationId, AnnotationId::STATE_NESTED);
+    assert_matches!(annotation_set0.annotations[1].value, AnnotationValue::BoolValue(true));
+
+    assert!(annotations[1].is_some());
+    let annotation_set1 = annotations[1].as_ref().unwrap();
+    assert_eq!(annotation_set1.valueIndex, 1);
+    assert_eq!(annotation_set1.annotations.len(), 1);
+    assert_eq!(annotation_set1.annotations[0].annotationId, AnnotationId::PRIMARY_FIELD);
+    assert_matches!(annotation_set1.annotations[0].value, AnnotationValue::BoolValue(true));
+
+    assert!(atom.atomAnnotations.is_none());
+}
+
+#[test]
+fn build_atom_with_trigger_reset_annotation_test() {
+    use test_vendor_atoms::stateAtom4;
+
+    let atom = stateAtom4::Stateatom4 {
+        reverse_domain_name: TEST_STRING_VALUE,
+        state: stateAtom4::State::Reset,
+        some_flag: TEST_BOOL_VALUE,
+    }
+    .to_vendor_atom();
+
+    const DEFAULT_STATE_VALUE: i32 = stateAtom4::State::Off as i32;
+
+    assert_eq!(atom.atomId, stateAtom4::Stateatom4::CODE);
+    assert_eq!(atom.reverseDomainName, TEST_STRING_VALUE);
+    assert_eq!(atom.values.len(), 2);
+    assert_eq!(atom.values[0].unwrap_int_value(), stateAtom4::State::Reset as _);
+    assert_eq!(atom.values[1].unwrap_bool_value(), TEST_BOOL_VALUE);
+
+    assert!(atom.valuesAnnotations.is_some());
+    let annotations = atom.valuesAnnotations.as_ref().unwrap();
+    assert_eq!(annotations.len(), 2);
+
+    assert!(annotations[0].is_some());
+    let annotation_set0 = annotations[0].as_ref().unwrap();
+    assert_eq!(annotation_set0.valueIndex, 0);
+    assert_eq!(annotation_set0.annotations.len(), 3);
+    assert_eq!(annotation_set0.annotations[0].annotationId, AnnotationId::EXCLUSIVE_STATE);
+    assert_matches!(annotation_set0.annotations[0].value, AnnotationValue::BoolValue(true));
+    assert_eq!(annotation_set0.annotations[1].annotationId, AnnotationId::STATE_NESTED);
+    assert_matches!(annotation_set0.annotations[1].value, AnnotationValue::BoolValue(true));
+    assert_eq!(annotation_set0.annotations[2].annotationId, AnnotationId::TRIGGER_STATE_RESET);
+    assert_matches!(
+        annotation_set0.annotations[2].value,
+        AnnotationValue::IntValue(DEFAULT_STATE_VALUE)
+    );
+
+    assert!(annotations[1].is_some());
+    let annotation_set1 = annotations[1].as_ref().unwrap();
+    assert_eq!(annotation_set1.valueIndex, 1);
+    assert_eq!(annotation_set1.annotations.len(), 1);
+    assert_eq!(annotation_set1.annotations[0].annotationId, AnnotationId::PRIMARY_FIELD);
+    assert_matches!(annotation_set1.annotations[0].value, AnnotationValue::BoolValue(true));
+
+    assert!(atom.atomAnnotations.is_none());
+}
diff --git a/stats/stats_log_api_gen/utils.h b/stats/stats_log_api_gen/utils.h
index f6513f5b..c43cecfa 100644
--- a/stats/stats_log_api_gen/utils.h
+++ b/stats/stats_log_api_gen/utils.h
@@ -53,7 +53,7 @@ struct AnnotationStruct {
     string name;
     int minApiLevel;
     AnnotationStruct(string name, int minApiLevel)
-        : name(std::move(name)), minApiLevel(minApiLevel){};
+        : name(std::move(name)), minApiLevel(minApiLevel) {};
 };
 
 void build_non_chained_decl_map(const Atoms& atoms,
```

