```diff
diff --git a/DeviceLockController/Android.bp b/DeviceLockController/Android.bp
index 1dd536a7..b7dd6966 100644
--- a/DeviceLockController/Android.bp
+++ b/DeviceLockController/Android.bp
@@ -101,7 +101,7 @@ java_library {
     ],
     libs: [
         "devicelockcontroller-proto-lite",
-        "framework-connectivity",
+        "framework-connectivity.stubs.module_lib",
     ],
     visibility: [
         "//packages/modules/DeviceLock:__subpackages__",
@@ -117,7 +117,7 @@ java_test_helper_library {
         ":statslog-devicelock-java-gen",
     ],
     libs: [
-        "framework-statsd",
+        "framework-statsd.stubs.module_lib",
         "modules-utils-expresslog",
     ],
     static_libs: [
@@ -144,11 +144,11 @@ android_library {
     libs: [
         "framework-annotations-lib",
         "framework-devicelock.impl",
-        "org.apache.http.legacy",
-        "framework-statsd",
+        "org.apache.http.legacy.stubs.system",
+        "framework-statsd.stubs.module_lib",
         "modules-utils-expresslog",
         "devicelockcontroller-proto-lite",
-        "framework-connectivity",
+        "framework-connectivity.stubs.module_lib",
     ],
     static_libs: [
         "androidx.annotation_annotation",
diff --git a/DeviceLockController/proto/checkin_service.proto b/DeviceLockController/proto/checkin_service.proto
index 377e29cb..f1f1a3a7 100644
--- a/DeviceLockController/proto/checkin_service.proto
+++ b/DeviceLockController/proto/checkin_service.proto
@@ -46,6 +46,10 @@ service DeviceLockCheckinService {
   // provisioning.
   rpc ReportDeviceProvisionState(ReportDeviceProvisionStateRequest)
       returns (ReportDeviceProvisionStateResponse) {}
+
+  // Updates FCM token for a device.
+  rpc UpdateFcmToken(UpdateFcmTokenRequest)
+      returns (UpdateFcmTokenResponse) {}
 }
 
 // Request to retrieve the check-in status of the device.
@@ -252,3 +256,33 @@ message ReportDeviceProvisionStateResponse {
   // CLIENT_PROVISION_STATE_DISMISSIBLE_UI
   optional uint32 days_left_until_reset = 2;
 }
+
+// Request to update FCM token for a device.
+message UpdateFcmTokenRequest {
+  // The device identifiers associated with the device provided by the Device
+  // Lock Android client.
+  repeated ClientDeviceIdentifier client_device_identifiers = 1;
+
+  // The Firebase Cloud Messaging (FCM) registration token associated with the
+  // device provided by the Device Lock Android client. The token is only used
+  // for GMS devices.
+  optional string fcm_registration_token = 2;
+}
+
+// Response to a request to update FCM token for a device.
+message UpdateFcmTokenResponse {
+  // The result of the update.
+  optional UpdateFcmTokenResult result = 1;
+}
+
+// The results of FCM token update.
+enum UpdateFcmTokenResult {
+  // Unspecified result.
+  UPDATE_FCM_TOKEN_RESULT_UNSPECIFIED = 0;
+
+  // Update to FCM token was successful.
+  UPDATE_FCM_TOKEN_RESULT_SUCCESS = 1;
+
+  // Update to FCM token was unsuccessful.
+  UPDATE_FCM_TOKEN_RESULT_FAILURE = 2;
+}
diff --git a/DeviceLockController/res/values-bs/strings.xml b/DeviceLockController/res/values-bs/strings.xml
index 8dadd3e3..ca85fcc3 100644
--- a/DeviceLockController/res/values-bs/strings.xml
+++ b/DeviceLockController/res/values-bs/strings.xml
@@ -123,7 +123,7 @@
     <string name="provision_notification_channel_name" msgid="6123500714047647805">"Pružanje usluge"</string>
     <string name="device_reset_in_days_notification_title" msgid="920859483535317727">"{count,plural, =1{Uređaj će se vratiti na zadano za 1 dan}one{Uređaj će se vratiti na zadano za # dan}few{Uređaj će se vratiti na zadano za # dana}other{Uređaj će se vratiti na zadano za # dana}}"</string>
     <string name="device_reset_timer_notification_title" msgid="301978346002711614">"Uređaj će se vratiti na zadano za <xliff:g id="TIMER">%s</xliff:g>"</string>
-    <string name="device_reset_notification_content" msgid="7642367488663440437">"Izbrisat će se svi podaci s uređaja. Za pomoć prilikom prijave uređaja kontaktirajte <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
+    <string name="device_reset_notification_content" msgid="7642367488663440437">"Izbrisat će se svi podaci uređaja. Za pomoć prilikom prijave uređaja kontaktirajte <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
     <string name="provisioning_failed" msgid="5350252817004028300">"Pružanje usluge finansiranja nije uspjelo"</string>
     <string name="click_to_contact_financier" msgid="5932768971588112528">"Za pomoć prilikom prijave uređaja <xliff:g id="SUPPORT_LINK_START">&lt;a href=%2$s&gt;</xliff:g>kontaktirajte pružaoca usluge <xliff:g id="PROVIDER_NAME">%1$s</xliff:g><xliff:g id="SUPPORT_LINK_END">&lt;/a&gt;</xliff:g>."</string>
     <string name="exit" msgid="645084771882733921">"Izađi"</string>
diff --git a/DeviceLockController/res/values-en-rCA/strings.xml b/DeviceLockController/res/values-en-rCA/strings.xml
new file mode 100644
index 00000000..5dfa4244
--- /dev/null
+++ b/DeviceLockController/res/values-en-rCA/strings.xml
@@ -0,0 +1,131 @@
+<?xml version="1.0" encoding="UTF-8"?>
+<!-- 
+  Copyright (c) 2022, The Android Open Source Project
+
+  Licensed under the Apache License, Version 2.0 (the "License");
+  you may not use this file except in compliance with the License.
+  You may obtain a copy of the License at
+
+      http://www.apache.org/licenses/LICENSE-2.0
+
+  Unless required by applicable law or agreed to in writing, software
+  distributed under the License is distributed on an "AS IS" BASIS,
+  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
+  See the License for the specific language governing permissions and
+  limitations under the License.
+ -->
+
+<resources xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
+    <string name="app_name" msgid="5655878067457216814">"DeviceLockController"</string>
+    <string name="next_button" msgid="1856423430963548653">"Next"</string>
+    <string name="reset_button" msgid="4649354411129240809">"Reset"</string>
+    <string name="setup_more_button" msgid="4456370972302510109">"More"</string>
+    <string name="setup_info_title_text" msgid="299562193092219293">"How <xliff:g id="CREDITOR_APP">%1$s</xliff:g> can manage this device"</string>
+    <string name="setup_failed_title_text" msgid="9045111389981992536">"Can\'t install <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app"</string>
+    <string name="setup_failed_reset_device_text" msgid="178419033440060908">"Resetting device to try again."</string>
+    <string name="setup_failed_reset_device_timer_text" msgid="5270970227714985986">"{count,plural, =1{Reset this device, then try setting it up again. It\'ll reset automatically in 1 second.}other{Reset this device, then try setting it up again. It\'ll reset automatically in # seconds.}}"</string>
+    <string name="setup_progress_title_text" msgid="2388779167610656852">"Installing <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app<xliff:g id="ELLIPSIS">…</xliff:g>"</string>
+    <string name="setup_finish_title_text" msgid="2810842695806992743">"Opening <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app<xliff:g id="ELLIPSIS">…</xliff:g>"</string>
+    <string name="setup_error_title_text" msgid="1123742279081942535">"Can\'t open <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app"</string>
+    <string name="try_again" msgid="5964839819170927721">"Try again"</string>
+    <string name="reset_phone" msgid="1161657350311160627">"Reset phone"</string>
+    <string name="control_section_title" msgid="2213476068991045785">"What can <xliff:g id="CREDITOR_APP">%1$s</xliff:g> do?"</string>
+    <string name="control_lock_device_text" msgid="8253302484073757764">"Restrict this device if you don\'t make a payment"</string>
+    <string name="control_download_text" msgid="8514650561843088172">"Download, install, and update the <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app"</string>
+    <string name="control_disable_debug_text" msgid="8112443250013094442">"Turn off debugging features"</string>
+    <string name="locked_section_title" msgid="2748725389334076510">"What works if this device is locked?"</string>
+    <string name="locked_emergency_text" msgid="3509216445555779286">"Emergency calling services"</string>
+    <string name="locked_phone_usage_text" msgid="1913605870324552847">"Incoming and some outgoing calls"</string>
+    <string name="locked_settings_usage_text" msgid="8336476063187737700">"Settings"</string>
+    <string name="locked_backup_and_restore_text" msgid="104616318625243429">"&lt;a href=https://support.google.com/android/answer/2819582&gt;Backing up and restoring&lt;/a&gt; your data"</string>
+    <string name="exposure_section_title" msgid="2329122144337528752">"What\'s visible to <xliff:g id="CREDITOR_APP">%1$s</xliff:g>?"</string>
+    <string name="exposure_install_text" msgid="2631074166447765453">"When the <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app is installed or uninstalled"</string>
+    <string name="exposure_lock_unlock_text" msgid="6827412845847260579">"Any lock or unlock requests from <xliff:g id="CREDITOR_APP">%1$s</xliff:g>"</string>
+    <string name="exposure_disable_dlc_text" msgid="2898692398106736423">"If the <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app isn\'t available"</string>
+    <string name="open_source_licenses" msgid="6464389386262455443">"Open-source licenses"</string>
+    <string name="footer_notice_content_description" msgid="2160540400079419440">"The management capabilities in the financed device section of Security settings don\'t apply to this device."</string>
+    <string name="device_provided_by_provider" msgid="290593329676291991">"This device is provided by <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
+    <string name="download_kiosk_app" msgid="1845089944897502656">"The Kiosk app will be downloaded and installed automatically"</string>
+    <string name="install_kiosk_app_secondary_user" msgid="49911908012320834">"The Kiosk app will be installed for this user"</string>
+    <string name="restrict_device_if_missing_payment" msgid="8883980285859496904">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> can restrict the device if you miss a payment. For details, view the <xliff:g id="TERMS_AND_CONDITIONS_LINK_START">&lt;a href=%2$s&gt;</xliff:g>Terms &amp; Conditions<xliff:g id="TERMS_AND_CONDITIONS_LINK_END">&lt;/a&gt;</xliff:g>."</string>
+    <string name="restrict_device_if_dont_make_payment" msgid="1619095674945507015">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> can restrict this device if you don\'t make the necessary payments. For details, view the <xliff:g id="TERMS_AND_CONDITIONS_LINK_START">&lt;a href=%2$s&gt;</xliff:g>Terms &amp; Conditions<xliff:g id="TERMS_AND_CONDITIONS_LINK_END">&lt;/a&gt;</xliff:g>."</string>
+    <string name="contact_provider_for_help" msgid="3872028089834808884">"For help, <xliff:g id="SUPPORT_LINK_START">&lt;a href=%2$s&gt;</xliff:g>contact <xliff:g id="PROVIDER_NAME">%1$s</xliff:g><xliff:g id="SUPPORT_LINK_END">&lt;/a&gt;</xliff:g>."</string>
+    <string name="previous" msgid="5241891780917802570">"Previous"</string>
+    <string name="next" msgid="8248291863254324326">"Next"</string>
+    <string name="start" msgid="2842214844667658537">"Start"</string>
+    <string name="ok" msgid="3568398726528719749">"OK"</string>
+    <string name="done" msgid="4507782734740410307">"Done"</string>
+    <string name="do_it_in_one_hour" msgid="2727777340568739453">"Do it in 1 hour"</string>
+    <string name="header_icon_content_description" msgid="6069602031334473195">"Info"</string>
+    <string name="provision_info_item_icon_content_description" msgid="2306298178610632507">"Provision info"</string>
+    <string name="enroll_your_device_header" msgid="2226305405591945098">"Enroll your device"</string>
+    <string name="enroll_your_device_financing_subheader" msgid="8810608106273097451">"You can now enroll your device in <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s finance program"</string>
+    <string name="enroll_your_device_subsidy_subheader" msgid="8598730780370624995">"You can now enroll your device in <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s subsidy program"</string>
+    <string name="subsidy_program_header" msgid="2321508488856303554">"You\'re on <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s subsidy program"</string>
+    <string name="device_enrollment_header_text" msgid="5283341102404741658">"Device enrollment"</string>
+    <string name="device_financing_enrollment_body_text" msgid="5506086383249511498">"Your device will be enrolled in <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s finance program within 30 days"</string>
+    <string name="device_subsidy_enrollment_body_text" msgid="3971584929178719388">"Your device will be enrolled in <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s subsidy program within 30 days"</string>
+    <string name="device_enrollment_notification_body_text" msgid="8755080244956655854">"Enrollment will resume at <xliff:g id="TIME">%1$s</xliff:g>. You can continue using your device."</string>
+    <string name="continue_using_device" msgid="5816570734692191190">"You can continue using your device"</string>
+    <string name="device_paid" msgid="6606280698381856804">"You paid for your device"</string>
+    <string name="device_removed_from_subsidy_program" msgid="1243434945619071051">"Device removed from <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> subsidy program"</string>
+    <string name="device_removed_from_finance_program" msgid="825548999540107578">"Your device has been removed from <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>\'s finance program"</string>
+    <string name="restrictions_lifted" msgid="5785586265984319396">"All restrictions on your device have been lifted"</string>
+    <string name="uninstall_kiosk_app" msgid="3459557395024053988">"You can uninstall the Kiosk app from your device"</string>
+    <string name="getting_device_ready" msgid="2829009584599871699">"Getting your device ready…"</string>
+    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"This may take a few minutes"</string>
+    <string name="installing_kiosk_app" msgid="324208168205545860">"Installing <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app…"</string>
+    <string name="opening_kiosk_app" msgid="2021888641430165654">"Opening <xliff:g id="CREDITOR_APP">%1$s</xliff:g> app…"</string>
+    <string name="settings_banner_title" msgid="527041021011279252">"Device provided by <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
+    <string name="settings_banner_body" msgid="5814902066260202824">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> can change settings on this device"</string>
+    <string name="settings_banner_button" msgid="1831020849782670907">"Learn more"</string>
+    <string name="settings_screen_title" msgid="721470080648091035">"Financed device info"</string>
+    <string name="settings_intro_device_financing" msgid="2548476558131048133">"<xliff:g id="PROVIDER_NAME_0">%1$s</xliff:g> can change settings and install the Kiosk app on the device.\n\nIf you miss a payment, <xliff:g id="PROVIDER_NAME_1">%1$s</xliff:g> can restrict your device.\n\nTo learn more, contact <xliff:g id="PROVIDER_NAME_2">%1$s</xliff:g>."</string>
+    <string name="settings_intro_device_subsidy" msgid="4274945644204818702">"<xliff:g id="PROVIDER_NAME_0">%1$s</xliff:g> can change settings and install the Kiosk app on the device.\n\n<xliff:g id="PROVIDER_NAME_1">%1$s</xliff:g> may also restrict this device if you miss a payment or stop using <xliff:g id="PROVIDER_NAME_2">%1$s</xliff:g>’s SIM.\n\nTo learn more, contact <xliff:g id="PROVIDER_NAME_3">%1$s</xliff:g>."</string>
+    <string name="settings_intro_preference_key" msgid="6610461073400554162">"settings_intro_preference_key"</string>
+    <string name="settings_restrictions_category" msgid="5746868117342406677">"Until you’ve paid for your device, you can’t:"</string>
+    <string name="settings_restrictions_category_preference_key" msgid="88318147152676512">"settings_restrictions_category_preference_key"</string>
+    <string name="settings_install_apps" msgid="3634279771448183713">"Install apps from outside the Play Store"</string>
+    <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
+    <string name="settings_safe_mode" msgid="3035228015586375153">"Reboot your device into safe mode"</string>
+    <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"Use developer options"</string>
+    <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
+    <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"If something goes wrong with your device, <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> can:"</string>
+    <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
+    <string name="settings_IMEI" msgid="697965824361262506">"Access your IMEI number"</string>
+    <string name="settings_IMEI_preference_key" msgid="608809590948249412">"settings_IMEI_preference_key"</string>
+    <string name="settings_factory_reset" msgid="418045189048067625">"Factory reset your device"</string>
+    <string name="settings_factory_reset_preference_key" msgid="2168528486393635382">"settings_factory_reset_preference_key"</string>
+    <string name="settings_locked_mode_category" msgid="6307525048618331737">"If your device is restricted, you can only use it to:"</string>
+    <string name="settings_locked_mode_category_preference_key" msgid="7202573929427220258">"settings_locked_mode_category_preference_key"</string>
+    <string name="settings_emergency_calls" msgid="2460996367176786040">"Make calls to emergency numbers"</string>
+    <string name="settings_emergency_calls_preference_key" msgid="737598609727181316">"settings_emergency_calls_preference_key"</string>
+    <string name="settings_system_info" msgid="1352629332624774940">"View system info like date, time, network status, and battery"</string>
+    <string name="settings_system_info_preference_key" msgid="8607675914059202598">"settings_system_info_preference_key"</string>
+    <string name="settings_turn_on_off_device" msgid="5414836621603462439">"Turn your device on or off"</string>
+    <string name="settings_turn_on_off_device_preference_key" msgid="5981163790552677734">"settings_turn_on_off_device_preference_key"</string>
+    <string name="settings_notifications" msgid="63348993899505034">"View notifications and text messages"</string>
+    <string name="settings_notifications_preference_key" msgid="4527872342061056462">"settings_notifications_preference_key"</string>
+    <string name="settings_allowlisted_apps" msgid="5531810497056091097">"Access apps that are allowed by <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
+    <string name="settings_allowlisted_apps_preference_key" msgid="8662705531235468080">"settings_allowlisted_apps_preference_key"</string>
+    <string name="settings_fully_paid_category" msgid="2459776591689824433">"Once you pay the full amount:"</string>
+    <string name="settings_fully_paid_category_preference_key" msgid="1759690898170600559">"settings_fully_paid_category_preference_key"</string>
+    <string name="settings_restrictions_removed" msgid="1398080654904863221">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> can’t restrict your device or change device settings"</string>
+    <string name="settings_restrictions_removed_preference_key" msgid="7741933477145197391">"settings_restrictions_removed_preference_key"</string>
+    <string name="settings_uninstall_kiosk_app" msgid="2611134364295637875">"You can uninstall the <xliff:g id="KIOSK_APP">%1$s</xliff:g> app"</string>
+    <string name="settings_uninstall_kiosk_app_preference_key" msgid="5578103644009268125">"settings_uninstall_kiosk_app_preference_key"</string>
+    <string name="settings_support_category" msgid="7210906871924935770">"To get help:"</string>
+    <string name="settings_support_category_preference_key" msgid="1818953199283261021">"settings_support_category_preference_key"</string>
+    <string name="settings_contact_provider" msgid="2481819956474692039">"<xliff:g id="SUPPORT_LINK_START">&lt;a href=%2$s&gt;</xliff:g>Contact <xliff:g id="PROVIDER_NAME">%1$s</xliff:g><xliff:g id="SUPPORT_LINK_END">&lt;/a&gt;</xliff:g>"</string>
+    <string name="settings_contact_provider_preference_key" msgid="2703619536229342624">"settings_contact_provider_preference_key"</string>
+    <string name="provision_notification_channel_name" msgid="6123500714047647805">"Provision"</string>
+    <string name="device_reset_in_days_notification_title" msgid="920859483535317727">"{count,plural, =1{Device will reset in 1 day}other{Device will reset in # days}}"</string>
+    <string name="device_reset_timer_notification_title" msgid="301978346002711614">"Device will reset in <xliff:g id="TIMER">%s</xliff:g>"</string>
+    <string name="device_reset_notification_content" msgid="7642367488663440437">"All device data will be deleted. For help enrolling your device, contact <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
+    <string name="provisioning_failed" msgid="5350252817004028300">"Financing provisioning has failed"</string>
+    <string name="click_to_contact_financier" msgid="5932768971588112528">"For help enrolling your device, <xliff:g id="SUPPORT_LINK_START">&lt;a href=%2$s&gt;</xliff:g>contact <xliff:g id="PROVIDER_NAME">%1$s</xliff:g><xliff:g id="SUPPORT_LINK_END">&lt;/a&gt;</xliff:g>."</string>
+    <string name="exit" msgid="645084771882733921">"Exit"</string>
+    <string name="retry" msgid="7497287909193345356">"Retry"</string>
+</resources>
diff --git a/DeviceLockController/res/values-es-rUS/strings.xml b/DeviceLockController/res/values-es-rUS/strings.xml
index 136a4b00..9e04b70d 100644
--- a/DeviceLockController/res/values-es-rUS/strings.xml
+++ b/DeviceLockController/res/values-es-rUS/strings.xml
@@ -21,7 +21,7 @@
     <string name="next_button" msgid="1856423430963548653">"Siguiente"</string>
     <string name="reset_button" msgid="4649354411129240809">"Restablecer"</string>
     <string name="setup_more_button" msgid="4456370972302510109">"Más"</string>
-    <string name="setup_info_title_text" msgid="299562193092219293">"Cómo administra este dispositivo <xliff:g id="CREDITOR_APP">%1$s</xliff:g>"</string>
+    <string name="setup_info_title_text" msgid="299562193092219293">"Cómo <xliff:g id="CREDITOR_APP">%1$s</xliff:g> administra este dispositivo"</string>
     <string name="setup_failed_title_text" msgid="9045111389981992536">"No se puede instalar la app de <xliff:g id="CREDITOR_APP">%1$s</xliff:g>"</string>
     <string name="setup_failed_reset_device_text" msgid="178419033440060908">"Restableciendo el dispositivo para volver a intentarlo."</string>
     <string name="setup_failed_reset_device_timer_text" msgid="5270970227714985986">"{count,plural, =1{Restablece este dispositivo y vuelve a configurarlo. Se restablecerá automáticamente en 1 segundo.}other{Restablece este dispositivo y vuelve a configurarlo. Se restablecerá automáticamente en # segundos.}}"</string>
@@ -45,7 +45,7 @@
     <string name="exposure_disable_dlc_text" msgid="2898692398106736423">"Si la app de <xliff:g id="CREDITOR_APP">%1$s</xliff:g> no está disponible"</string>
     <string name="open_source_licenses" msgid="6464389386262455443">"Licencias de código abierto"</string>
     <string name="footer_notice_content_description" msgid="2160540400079419440">"Las funciones de administración de la sección de la Configuración de seguridad del dispositivo financiado no se aplican a este dispositivo."</string>
-    <string name="device_provided_by_provider" msgid="290593329676291991">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> proporciona este dispositivo"</string>
+    <string name="device_provided_by_provider" msgid="290593329676291991">"Este dispositivo lo proporciona <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
     <string name="download_kiosk_app" msgid="1845089944897502656">"Se descargará e instalará la aplicación de Kiosco automáticamente."</string>
     <string name="install_kiosk_app_secondary_user" msgid="49911908012320834">"Se instalará la aplicación de Kiosco para este usuario"</string>
     <string name="restrict_device_if_missing_payment" msgid="8883980285859496904">"<xliff:g id="PROVIDER_NAME">%1$s</xliff:g> puede restringir el dispositivo si no realizas un pago. Para obtener más información, consulta los <xliff:g id="TERMS_AND_CONDITIONS_LINK_START">&lt;a href=%2$s&gt;</xliff:g>Términos y Condiciones<xliff:g id="TERMS_AND_CONDITIONS_LINK_END">&lt;/a&gt;</xliff:g>."</string>
diff --git a/DeviceLockController/res/values-hi/strings.xml b/DeviceLockController/res/values-hi/strings.xml
index 708f8833..fe2cbe64 100644
--- a/DeviceLockController/res/values-hi/strings.xml
+++ b/DeviceLockController/res/values-hi/strings.xml
@@ -90,7 +90,7 @@
     <string name="settings_install_apps_preference_key" msgid="27542314345238427">"settings_install_apps_preference_key"</string>
     <string name="settings_safe_mode" msgid="3035228015586375153">"अपने डिवाइस को सुरक्षित मोड में फिर से चालू करें"</string>
     <string name="settings_safe_mode_preference_key" msgid="2106617747358027424">"settings_safe_mode_preference_key"</string>
-    <string name="settings_developer_options" msgid="880701002025216672">"डेवलपर के लिए सेटिंग और टूल का यूज़ करें"</string>
+    <string name="settings_developer_options" msgid="880701002025216672">"डेवलपर के लिए सेटिंग और टूल का इस्तेमाल करें"</string>
     <string name="settings_developer_options_preference_key" msgid="6807036808722582954">"settings_developer_options_preference_key"</string>
     <string name="settings_credit_provider_capabilities_category" msgid="1274440595211820868">"डिवाइस में गड़बड़ी होने पर <xliff:g id="PROVIDER_NAME">%1$s</xliff:g> यह कर सकता है:"</string>
     <string name="settings_credit_provider_capabilities_category_preference_key" msgid="4571685720898641262">"settings_credit_provider_capabilities_category_preference_key"</string>
diff --git a/DeviceLockController/res/values-iw/strings.xml b/DeviceLockController/res/values-iw/strings.xml
index 4e8aaaaa..21f75abf 100644
--- a/DeviceLockController/res/values-iw/strings.xml
+++ b/DeviceLockController/res/values-iw/strings.xml
@@ -74,7 +74,7 @@
     <string name="restrictions_lifted" msgid="5785586265984319396">"כל ההגבלות על המכשיר הוסרו"</string>
     <string name="uninstall_kiosk_app" msgid="3459557395024053988">"אפשר להסיר את אפליקציית \"קיוסק\" מהמכשיר"</string>
     <string name="getting_device_ready" msgid="2829009584599871699">"המכשיר בתהליך הגדרה…"</string>
-    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"הפעולה עשויה להימשך מספר דקות"</string>
+    <string name="this_may_take_a_few_minutes" msgid="2482876246874429351">"זה יכול לקחת כמה דקות"</string>
     <string name="installing_kiosk_app" msgid="324208168205545860">"אפליקציית <xliff:g id="CREDITOR_APP">%1$s</xliff:g> מותקנת…"</string>
     <string name="opening_kiosk_app" msgid="2021888641430165654">"האפליקציה <xliff:g id="CREDITOR_APP">%1$s</xliff:g> נפתחת…"</string>
     <string name="settings_banner_title" msgid="527041021011279252">"המכשיר סופק על ידי <xliff:g id="PROVIDER_NAME">%1$s</xliff:g>"</string>
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
index 82125122..7b999314 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/DeviceLockControllerService.java
@@ -17,7 +17,6 @@
 package com.android.devicelockcontroller;
 
 import android.app.Service;
-import android.app.admin.DevicePolicyManager;
 import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.devicelock.ParcelableException;
@@ -43,9 +42,6 @@ import com.google.common.util.concurrent.Futures;
 import com.google.common.util.concurrent.ListenableFuture;
 import com.google.common.util.concurrent.MoreExecutors;
 
-import java.util.List;
-import java.util.Objects;
-
 /**
  * Device Lock Controller Service. This is hosted in an APK and is bound
  * by the Device Lock System Service.
@@ -127,10 +123,6 @@ public final class DeviceLockControllerService extends Service {
 
                 @Override
                 public void onUserUnlocked(RemoteCallback remoteCallback) {
-                    DevicePolicyManager dpm = getSystemService(DevicePolicyManager.class);
-                    Objects.requireNonNull(dpm).setUserControlDisabledPackages(
-                            /* admin= */ null,
-                            List.of(getPackageName()));
                     Futures.addCallback(mPolicyController.onUserUnlocked(),
                             remoteCallbackWrapper(remoteCallback),
                             MoreExecutors.directExecutor());
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
index 2c2bc6be..1c674717 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/debug/DeviceCheckInClientDebug.java
@@ -25,6 +25,7 @@ import android.os.SystemClock;
 import android.util.ArraySet;
 
 import androidx.annotation.Keep;
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
 import com.android.devicelockcontroller.common.DeviceId;
@@ -38,6 +39,7 @@ import com.android.devicelockcontroller.provision.grpc.IsDeviceInApprovedCountry
 import com.android.devicelockcontroller.provision.grpc.PauseDeviceProvisioningGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.ProvisioningConfiguration;
 import com.android.devicelockcontroller.provision.grpc.ReportDeviceProvisionStateGrpcResponse;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
 import com.android.devicelockcontroller.util.LogUtil;
 import com.android.devicelockcontroller.util.ThreadAsserts;
 
@@ -247,4 +249,16 @@ public final class DeviceCheckInClientDebug extends DeviceCheckInClient {
             }
         };
     }
+
+    @Override
+    public UpdateFcmTokenGrpcResponse updateFcmToken(ArraySet<DeviceId> deviceIds,
+            @NonNull String fcmRegistrationToken) {
+        ThreadAsserts.assertWorkerThread("updateFcmToken");
+        return new UpdateFcmTokenGrpcResponse() {
+            @Override
+            public int getFcmTokenResult() {
+                return FcmTokenResult.RESULT_SUCCESS;
+            }
+        };
+    }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
index fa91477c..de3c6318 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImpl.java
@@ -134,14 +134,14 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
     DevicePolicyControllerImpl(Context context,
             DevicePolicyManager devicePolicyManager,
             UserManager userManager,
-            UserRestrictionsPolicyHandler userRestrictionsPolicyHandler,
-            AppOpsPolicyHandler appOpsPolicyHandler,
-            LockTaskModePolicyHandler lockTaskModePolicyHandler,
-            PackagePolicyHandler packagePolicyHandler,
-            RolePolicyHandler rolePolicyHandler,
-            KioskKeepAlivePolicyHandler kioskKeepAlivePolicyHandler,
-            ControllerKeepAlivePolicyHandler controllerKeepAlivePolicyHandler,
-            NotificationsPolicyHandler notificationsPolicyHandler,
+            PolicyHandler userRestrictionsPolicyHandler,
+            PolicyHandler appOpsPolicyHandler,
+            PolicyHandler lockTaskModePolicyHandler,
+            PolicyHandler packagePolicyHandler,
+            PolicyHandler rolePolicyHandler,
+            PolicyHandler kioskKeepAlivePolicyHandler,
+            PolicyHandler controllerKeepAlivePolicyHandler,
+            PolicyHandler notificationsPolicyHandler,
             ProvisionStateController provisionStateController,
             Executor bgExecutor) {
         mContext = context;
@@ -258,9 +258,6 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
             @ProvisionState int provisionState, @DeviceState int deviceState) {
         LogUtil.i(TAG, "Enforcing policies for provision state " + provisionState
                 + " and device state " + deviceState);
-        if (provisionState == UNPROVISIONED) {
-            return Futures.immediateFuture(resolveLockTaskType(provisionState, deviceState));
-        }
         List<ListenableFuture<Boolean>> futures = new ArrayList<>();
         if (deviceState == CLEARED) {
             // If device is cleared, then ignore provision state and add cleared policies
@@ -292,6 +289,9 @@ public final class DevicePolicyControllerImpl implements DevicePolicyController
             for (int i = 0, policyLen = mPolicyList.size(); i < policyLen; i++) {
                 PolicyHandler policy = mPolicyList.get(i);
                 switch (provisionState) {
+                    case UNPROVISIONED:
+                        futures.add(policy.onUnprovisioned());
+                        break;
                     case PROVISION_IN_PROGRESS:
                         futures.add(policy.onProvisionInProgress());
                         break;
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
index 6c623a2e..82b9f8f3 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/DeviceStateControllerImpl.java
@@ -25,6 +25,9 @@ import static com.android.devicelockcontroller.policy.ProvisionStateController.P
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.UNPROVISIONED;
 
+import androidx.annotation.VisibleForTesting;
+
+import com.android.devicelock.flags.Flags;
 import com.android.devicelockcontroller.storage.GlobalParametersClient;
 
 import com.google.common.util.concurrent.Futures;
@@ -42,7 +45,8 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
     // Used to exercising APIs under CTS without actually applying any policies.
     // This is not persistent across controller restarts, but should be good enough for the
     // intended purpose.
-    private volatile @DeviceState int mPseudoDeviceState;
+    @VisibleForTesting
+    volatile @DeviceState int mPseudoDeviceState;
 
     public DeviceStateControllerImpl(DevicePolicyController policyController,
             ProvisionStateController provisionStateController, Executor executor) {
@@ -92,6 +96,13 @@ public final class DeviceStateControllerImpl implements DeviceStateController {
                         mPseudoDeviceState = deviceState;
                         // Do not apply any policies
                         return Futures.immediateVoidFuture();
+                    } else if (Flags.clearDeviceRestrictions()
+                            && (provisionState == UNPROVISIONED && deviceState == CLEARED)) {
+                        // During normal operation, we should not get clear requests in
+                        // the UNPROVISIONED state. Used for CTS compliance.
+                        mPseudoDeviceState = deviceState;
+                        // Do not apply any policies
+                        return Futures.immediateVoidFuture();
                     } else {
                         throw new RuntimeException(
                                 "User has not been provisioned! Current state " + provisionState);
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
index af36d97d..935f686e 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/FinalizationControllerImpl.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.policy;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState.FINALIZED;
 import static com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState.FINALIZED_UNREPORTED;
 import static com.android.devicelockcontroller.policy.FinalizationControllerImpl.FinalizationState.UNFINALIZED;
@@ -33,7 +28,6 @@ import android.app.AlarmManager;
 import android.content.ComponentName;
 import android.content.Context;
 import android.content.pm.PackageManager;
-import android.net.NetworkRequest;
 import android.os.OutcomeReceiver;
 
 import androidx.annotation.NonNull;
@@ -244,14 +238,8 @@ public final class FinalizationControllerImpl implements FinalizationController
     private void requestWorkToReportFinalized() {
         WorkManager workManager =
                 WorkManager.getInstance(mContext);
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
         Constraints constraints = new Constraints.Builder()
-                .setRequiredNetworkRequest(request, NetworkType.CONNECTED)
+                .setRequiredNetworkType(NetworkType.CONNECTED)
                 .build();
         OneTimeWorkRequest work =
                 new OneTimeWorkRequest.Builder(mReportDeviceFinalizedWorkerClass)
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandler.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandler.java
index 71553e58..19bc77db 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandler.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandler.java
@@ -99,6 +99,16 @@ public final class KioskKeepAlivePolicyHandler implements PolicyHandler {
                 });
     }
 
+    @Override
+    public ListenableFuture<Boolean> onLocked() {
+        return getEnableKioskKeepAliveFuture();
+    }
+
+    @Override
+    public ListenableFuture<Boolean> onUnlocked() {
+        return getDisableKioskKeepAliveFuture();
+    }
+
     @Override
     public ListenableFuture<Boolean> onProvisioned() {
         return getEnableKioskKeepAliveFuture();
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/LockTaskModePolicyHandler.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/LockTaskModePolicyHandler.java
index c0c4a108..1fc3cd4f 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/LockTaskModePolicyHandler.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/LockTaskModePolicyHandler.java
@@ -178,17 +178,19 @@ final class LockTaskModePolicyHandler implements PolicyHandler {
             if (mUserManager.isUserUnlocked()) {
                 WorkManager.getInstance(mContext).cancelUniqueWork(START_LOCK_TASK_MODE_WORK_NAME);
             }
-
             // Device Policy Engine treats lock task features and packages as one policy and
             // therefore we need to set both lock task features (to LOCK_TASK_FEATURE_NONE) and
             // lock task packages (to an empty string array).
-            mDpm.setLockTaskFeatures(null /* admin */, DevicePolicyManager.LOCK_TASK_FEATURE_NONE);
+
             // This is a hacky workaround to stop the lock task mode by enforcing that no apps
             // can be in lock task mode
             // TODO(b/288886570): Fix this in the framework so we don't have to do this workaround
             mDpm.setLockTaskPackages(null /* admin */, new String[]{""});
             // This will remove the DLC policy and allow other admins to enforce their policy
             mDpm.setLockTaskPackages(null /* admin */, new String[0]);
+            // Set lock task features (to LOCK_TASK_FEATURE_NONE) after removing the DLC policy
+            // in order to prevent keyguard from being disabled while lock task is still active.
+            mDpm.setLockTaskFeatures(null /* admin */, DevicePolicyManager.LOCK_TASK_FEATURE_NONE);
             mDpm.clearPackagePersistentPreferredActivities(null /* admin */,
                     mContext.getPackageName());
             ComponentName lockedHomeActivity =
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/PackagePolicyHandler.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/PackagePolicyHandler.java
index 97db153f..6ffd6009 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/PackagePolicyHandler.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/PackagePolicyHandler.java
@@ -43,6 +43,11 @@ final class PackagePolicyHandler implements PolicyHandler {
         mBgExecutor = bgExecutor;
     }
 
+    @Override
+    public ListenableFuture<Boolean> onUnprovisioned() {
+        return enablePackageProtection(/* enableForKiosk= */ false);
+    }
+
     @Override
     public ListenableFuture<Boolean> onProvisioned() {
         return enablePackageProtection(/* enableForKiosk= */ true);
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/PolicyHandler.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/PolicyHandler.java
index 15ce64b5..b2e6f8e7 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/PolicyHandler.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/PolicyHandler.java
@@ -24,6 +24,10 @@ import com.google.common.util.concurrent.ListenableFuture;
  */
 interface PolicyHandler {
 
+    default ListenableFuture<Boolean> onUnprovisioned() {
+        return Futures.immediateFuture(true);
+    }
+
     default ListenableFuture<Boolean> onProvisioned() {
         return Futures.immediateFuture(true);
     }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
index 52487210..d30dd78c 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/policy/ProvisionHelperImpl.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.policy;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static androidx.work.WorkInfo.State.CANCELLED;
 import static androidx.work.WorkInfo.State.FAILED;
 import static androidx.work.WorkInfo.State.SUCCEEDED;
@@ -37,7 +32,6 @@ import android.content.SharedPreferences;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager.NameNotFoundException;
 import android.database.sqlite.SQLiteException;
-import android.net.NetworkRequest;
 import android.os.Build;
 import android.os.Handler;
 import android.os.Looper;
@@ -367,15 +361,9 @@ public final class ProvisionHelperImpl implements ProvisionHelper {
 
     @NonNull
     private static OneTimeWorkRequest getIsDeviceInApprovedCountryWork() {
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
         return new OneTimeWorkRequest.Builder(IsDeviceInApprovedCountryWorker.class)
-                .setConstraints(new Constraints.Builder().setRequiredNetworkRequest(
-                        request, NetworkType.CONNECTED).build())
+                .setConstraints(new Constraints.Builder().setRequiredNetworkType(
+                        NetworkType.CONNECTED).build())
                 // Set the request as expedited and use a short retry backoff time since the
                 // user is in the setup flow while we check if the device is in an approved country
                 .setExpedited(OutOfQuotaPolicy.RUN_AS_NON_EXPEDITED_WORK_REQUEST)
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
index ab8ff20f..e58f4e08 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/DeviceCheckInClient.java
@@ -23,6 +23,7 @@ import android.os.Build;
 import android.os.UserHandle;
 import android.util.ArraySet;
 
+import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 import androidx.annotation.WorkerThread;
 
@@ -187,6 +188,19 @@ public abstract class DeviceCheckInClient {
             @DeviceProvisionState int lastReceivedProvisionState,
             boolean isSuccessful, @ProvisionFailureReason int failureReason);
 
+    /**
+     * Update FCM registration token on device lock backend server for the given device identifiers.
+     *
+     * @param deviceIds            A set of all device unique identifiers, this could include IMEIs,
+     *                             MEIDs, etc.
+     * @param fcmRegistrationToken The fcm registration token
+     * @return A class that encapsulate the response from the backend server.
+     */
+    @WorkerThread
+    public abstract UpdateFcmTokenGrpcResponse updateFcmToken(
+            ArraySet<DeviceId> deviceIds,
+            @NonNull String fcmRegistrationToken);
+
     /**
      * Called when this device check in client is no longer in use and should clean up its
      * resources.
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/UpdateFcmTokenGrpcResponse.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/UpdateFcmTokenGrpcResponse.java
new file mode 100644
index 00000000..a713fc87
--- /dev/null
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/UpdateFcmTokenGrpcResponse.java
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
+
+package com.android.devicelockcontroller.provision.grpc;
+
+import androidx.annotation.IntDef;
+import androidx.annotation.NonNull;
+
+import io.grpc.Status;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+
+/**
+ * An abstract class that is used to encapsulate the response for updating the FCM registration
+ * token.
+ */
+public abstract class UpdateFcmTokenGrpcResponse extends GrpcResponse {
+    /** Definitions for FCM token results. */
+    @Retention(RetentionPolicy.SOURCE)
+    @IntDef(
+            value = {
+                    FcmTokenResult.RESULT_UNSPECIFIED,
+                    FcmTokenResult.RESULT_SUCCESS,
+                    FcmTokenResult.RESULT_FAILURE
+            }
+    )
+    public @interface FcmTokenResult {
+        /** Result unspecified */
+        int RESULT_UNSPECIFIED = 0;
+        /** FCM registration token successfully updated */
+        int RESULT_SUCCESS = 1;
+        /** FCM registration token falied to update */
+        int RESULT_FAILURE = 2;
+    }
+
+    public UpdateFcmTokenGrpcResponse() {
+        mStatus = null;
+    }
+
+    public UpdateFcmTokenGrpcResponse(@NonNull Status status) {
+        super(status);
+    }
+
+    /**
+     * Get result of updating FCM registration token.
+     *
+     * @return one of {@link FcmTokenResult}
+     */
+    @FcmTokenResult
+    public abstract int getFcmTokenResult();
+}
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
index eedf8b30..767c0f9b 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckInClientImpl.java
@@ -54,11 +54,13 @@ import com.android.devicelockcontroller.proto.IsDeviceInApprovedCountryRequest;
 import com.android.devicelockcontroller.proto.PauseDeviceProvisioningReason;
 import com.android.devicelockcontroller.proto.PauseDeviceProvisioningRequest;
 import com.android.devicelockcontroller.proto.ReportDeviceProvisionStateRequest;
+import com.android.devicelockcontroller.proto.UpdateFcmTokenRequest;
 import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
 import com.android.devicelockcontroller.provision.grpc.GetDeviceCheckInStatusGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.IsDeviceInApprovedCountryGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.PauseDeviceProvisioningGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.ReportDeviceProvisionStateGrpcResponse;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
 import com.android.devicelockcontroller.util.LogUtil;
 import com.android.devicelockcontroller.util.ThreadAsserts;
 
@@ -201,7 +203,6 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
             @Nullable String fcmRegistrationToken,
             @NonNull DeviceLockCheckinServiceBlockingStub stub) {
         try {
-            // TODO(339313833): Make a separate grpc call for passing in the token
             return new GetDeviceCheckInStatusGrpcResponseWrapper(
                     stub.withDeadlineAfter(GRPC_DEADLINE_MS, TimeUnit.MILLISECONDS)
                             .getDeviceCheckinStatus(createGetDeviceCheckinStatusRequest(
@@ -315,6 +316,40 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
         }
     }
 
+    @Override
+    public UpdateFcmTokenGrpcResponse updateFcmToken(ArraySet<DeviceId> deviceIds,
+            @NonNull String fcmRegistrationToken) {
+        ThreadAsserts.assertWorkerThread("getDeviceCheckInStatus");
+        UpdateFcmTokenGrpcResponse response =
+                updateFcmToken(deviceIds, fcmRegistrationToken, mDefaultBlockingStub);
+        if (response.hasRecoverableError()) {
+            DeviceLockCheckinServiceBlockingStub stub;
+            synchronized (this) {
+                if (mNonVpnBlockingStub == null) {
+                    return response;
+                }
+                stub = mNonVpnBlockingStub;
+            }
+            LogUtil.d(TAG, "Non-VPN network fallback detected. Re-attempt fcm token update.");
+            return updateFcmToken(deviceIds, fcmRegistrationToken, stub);
+        }
+        return response;
+    }
+
+    private UpdateFcmTokenGrpcResponse updateFcmToken(
+            ArraySet<DeviceId> deviceIds,
+            @NonNull String fcmRegistrationToken,
+            @NonNull DeviceLockCheckinServiceBlockingStub stub) {
+        try {
+            return new UpdateFcmTokenGrpcResponseWrapper(
+                    stub.withDeadlineAfter(GRPC_DEADLINE_MS, TimeUnit.MILLISECONDS)
+                            .updateFcmToken(createUpdateFcmTokenRequest(
+                                    deviceIds, fcmRegistrationToken)));
+        } catch (StatusRuntimeException e) {
+            return new UpdateFcmTokenGrpcResponseWrapper(e.getStatus());
+        }
+    }
+
     @Override
     public void cleanUp() {
         super.cleanUp();
@@ -356,24 +391,10 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
             @Nullable String fcmRegistrationToken) {
         GetDeviceCheckinStatusRequest.Builder builder = GetDeviceCheckinStatusRequest.newBuilder();
         for (DeviceId deviceId : deviceIds) {
-            DeviceIdentifierType type;
-            switch (deviceId.getType()) {
-                case DeviceIdType.DEVICE_ID_TYPE_UNSPECIFIED:
-                    type = DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_UNSPECIFIED;
-                    break;
-                case DeviceIdType.DEVICE_ID_TYPE_IMEI:
-                    type = DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_IMEI;
-                    break;
-                case DeviceIdType.DEVICE_ID_TYPE_MEID:
-                    type = DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_MEID;
-                    break;
-                default:
-                    throw new IllegalStateException(
-                            "Unexpected DeviceId type: " + deviceId.getType());
-            }
             builder.addClientDeviceIdentifiers(
                     ClientDeviceIdentifier.newBuilder()
-                            .setDeviceIdentifierType(type)
+                            .setDeviceIdentifierType(
+                                    convertToProtoDeviceIdType(deviceId.getType()))
                             .setDeviceIdentifier(deviceId.getId()));
         }
         builder.setCarrierMccmnc(carrierInfo);
@@ -386,6 +407,19 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
         return builder.build();
     }
 
+    private static DeviceIdentifierType convertToProtoDeviceIdType(@DeviceIdType int deviceIdType) {
+        return switch (deviceIdType) {
+            case DeviceIdType.DEVICE_ID_TYPE_UNSPECIFIED ->
+                    DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_UNSPECIFIED;
+            case DeviceIdType.DEVICE_ID_TYPE_IMEI ->
+                    DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_IMEI;
+            case DeviceIdType.DEVICE_ID_TYPE_MEID ->
+                    DeviceIdentifierType.DEVICE_IDENTIFIER_TYPE_MEID;
+            default -> throw new IllegalStateException(
+                    "Unexpected DeviceId type: " + deviceIdType);
+        };
+    }
+
     private static IsDeviceInApprovedCountryRequest createIsDeviceInApprovedCountryRequest(
             String carrierInfo, String registeredId) {
         return IsDeviceInApprovedCountryRequest.newBuilder()
@@ -469,4 +503,18 @@ public final class DeviceCheckInClientImpl extends DeviceCheckInClient {
         }
         return builder.build();
     }
+
+    private static UpdateFcmTokenRequest createUpdateFcmTokenRequest(ArraySet<DeviceId> deviceIds,
+            @NonNull String fcmRegistrationToken) {
+        UpdateFcmTokenRequest.Builder builder = UpdateFcmTokenRequest.newBuilder();
+        for (DeviceId deviceId : deviceIds) {
+            builder.addClientDeviceIdentifiers(
+                    ClientDeviceIdentifier.newBuilder()
+                            .setDeviceIdentifierType(
+                                    convertToProtoDeviceIdType(deviceId.getType()))
+                            .setDeviceIdentifier(deviceId.getId()));
+        }
+        builder.setFcmRegistrationToken(fcmRegistrationToken);
+        return builder.build();
+    }
 }
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/UpdateFcmTokenGrpcResponseWrapper.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/UpdateFcmTokenGrpcResponseWrapper.java
new file mode 100644
index 00000000..6f8e90e0
--- /dev/null
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/grpc/impl/UpdateFcmTokenGrpcResponseWrapper.java
@@ -0,0 +1,53 @@
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
+package com.android.devicelockcontroller.provision.grpc.impl;
+
+import com.android.devicelockcontroller.proto.UpdateFcmTokenResponse;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
+
+import io.grpc.Status;
+
+/**
+ * A wrapper class for {@link UpdateFcmTokenGrpcResponse}.
+ */
+public final class UpdateFcmTokenGrpcResponseWrapper extends UpdateFcmTokenGrpcResponse {
+    private UpdateFcmTokenResponse mResponse;
+
+    public UpdateFcmTokenGrpcResponseWrapper(Status status) {
+        super(status);
+    }
+
+    public UpdateFcmTokenGrpcResponseWrapper(UpdateFcmTokenResponse response) {
+        super();
+        mResponse = response;
+    }
+
+    @Override
+    @FcmTokenResult
+    public int getFcmTokenResult() {
+        if (mResponse == null) {
+            return FcmTokenResult.RESULT_UNSPECIFIED;
+        }
+        return switch (mResponse.getResult()) {
+            case UPDATE_FCM_TOKEN_RESULT_UNSPECIFIED -> FcmTokenResult.RESULT_UNSPECIFIED;
+            case UPDATE_FCM_TOKEN_RESULT_SUCCESS -> FcmTokenResult.RESULT_SUCCESS;
+            case UPDATE_FCM_TOKEN_RESULT_FAILURE -> FcmTokenResult.RESULT_FAILURE;
+            default -> throw new IllegalStateException(
+                    "Unexpected update FCM result: " + mResponse.getResult());
+        };
+    }
+}
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/PauseProvisioningWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/PauseProvisioningWorker.java
index dc38af07..7303450a 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/PauseProvisioningWorker.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/PauseProvisioningWorker.java
@@ -16,16 +16,10 @@
 
 package com.android.devicelockcontroller.provision.worker;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.common.DeviceLockConstants.REASON_UNSPECIFIED;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.USER_DEFERRED_DEVICE_PROVISIONING;
 
 import android.content.Context;
-import android.net.NetworkRequest;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
@@ -70,14 +64,8 @@ public final class PauseProvisioningWorker extends AbstractCheckInWorker {
         Data inputData = new Data.Builder()
                 .putInt(KEY_PAUSE_DEVICE_PROVISIONING_REASON, USER_DEFERRED_DEVICE_PROVISIONING)
                 .build();
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
         Constraints constraints = new Constraints.Builder()
-                .setRequiredNetworkRequest(request, NetworkType.CONNECTED)
+                .setRequiredNetworkType(NetworkType.CONNECTED)
                 .build();
         OneTimeWorkRequest work =
                 new OneTimeWorkRequest.Builder(PauseProvisioningWorker.class)
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
index 886d4b2c..8d48e623 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/provision/worker/ReportDeviceProvisionStateWorker.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.provision.worker;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_DISMISSIBLE_UI;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_FACTORY_RESET;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_PERSISTENT_UI;
@@ -30,7 +25,6 @@ import static com.android.devicelockcontroller.common.DeviceLockConstants.Device
 import static com.android.devicelockcontroller.common.DeviceLockConstants.ProvisionFailureReason.DEADLINE_PASSED;
 
 import android.content.Context;
-import android.net.NetworkRequest;
 
 import androidx.annotation.NonNull;
 import androidx.annotation.VisibleForTesting;
@@ -110,14 +104,8 @@ public final class ReportDeviceProvisionStateWorker extends AbstractCheckInWorke
     }
 
     private static void enqueueReportWork(Data inputData, WorkManager workManager) {
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
         Constraints constraints = new Constraints.Builder()
-                .setRequiredNetworkRequest(request, NetworkType.CONNECTED)
+                .setRequiredNetworkType(NetworkType.CONNECTED)
                 .build();
         OneTimeWorkRequest work =
                 new OneTimeWorkRequest.Builder(ReportDeviceProvisionStateWorker.class)
diff --git a/DeviceLockController/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImpl.java b/DeviceLockController/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImpl.java
index 878a3bff..adfd5cdd 100644
--- a/DeviceLockController/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImpl.java
+++ b/DeviceLockController/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImpl.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.schedule;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.WorkManagerExceptionHandler.AlarmReason;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.MANDATORY_PROVISION_DEVICE_RESET_COUNTDOWN_MINUTE;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.NON_MANDATORY_PROVISION_DEVICE_RESET_COUNTDOWN_MINUTE;
@@ -35,7 +30,6 @@ import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
 import android.content.SharedPreferences;
-import android.net.NetworkRequest;
 import android.os.Build;
 import android.os.SystemClock;
 
@@ -487,16 +481,10 @@ public final class DeviceLockControllerSchedulerImpl implements DeviceLockContro
     }
 
     private Operation enqueueCheckInWorkRequest(boolean isExpedited, Duration delay) {
-        NetworkRequest request = new NetworkRequest.Builder()
-                .addCapability(NET_CAPABILITY_NOT_RESTRICTED)
-                .addCapability(NET_CAPABILITY_TRUSTED)
-                .addCapability(NET_CAPABILITY_INTERNET)
-                .addCapability(NET_CAPABILITY_NOT_VPN)
-                .build();
         OneTimeWorkRequest.Builder builder =
                 new OneTimeWorkRequest.Builder(DeviceCheckInWorker.class)
                         .setConstraints(
-                                new Constraints.Builder().setRequiredNetworkRequest(request,
+                                new Constraints.Builder().setRequiredNetworkType(
                                         NetworkType.CONNECTED).build())
                         .setInitialDelay(delay)
                         .setBackoffCriteria(BackoffPolicy.EXPONENTIAL, BACKOFF_DELAY);
diff --git a/DeviceLockController/tests/android_test/Android.bp b/DeviceLockController/tests/android_test/Android.bp
index 45c0ebcc..de6d6a25 100644
--- a/DeviceLockController/tests/android_test/Android.bp
+++ b/DeviceLockController/tests/android_test/Android.bp
@@ -34,6 +34,6 @@ android_test {
     libs: [
         "android.test.runner.stubs",
         "android.test.base.stubs",
-        "framework-statsd",
+        "framework-statsd.stubs.module_lib",
     ],
 }
diff --git a/DeviceLockController/tests/robolectric/Android.bp b/DeviceLockController/tests/robolectric/Android.bp
index 70ecd334..161fd64f 100644
--- a/DeviceLockController/tests/robolectric/Android.bp
+++ b/DeviceLockController/tests/robolectric/Android.bp
@@ -18,6 +18,7 @@ package {
 
 android_robolectric_test {
     name: "DeviceLockControllerRoboTests",
+    team: "trendy_team_android_go",
     instrumentation_for: "DeviceLockController",
     upstream: true,
     java_resource_dirs: [
@@ -32,9 +33,11 @@ android_robolectric_test {
         "guava-android-testlib",
         "grpc-java-lite",
         "grpc-java-testing",
+        "flag-junit",
     ],
     libs: [
         "androidx.work_work-testing",
+        "devicelock-aconfig-flags-lib",
     ],
     test_suites: ["general-tests"],
 
diff --git a/DeviceLockController/tests/robolectric/AndroidTest.xml b/DeviceLockController/tests/robolectric/AndroidTest.xml
index a0510d52..62bab5f3 100644
--- a/DeviceLockController/tests/robolectric/AndroidTest.xml
+++ b/DeviceLockController/tests/robolectric/AndroidTest.xml
@@ -17,7 +17,7 @@
     <option name="test-suite-tag" value="robolectric" />
     <option name="test-suite-tag" value="robolectric-tests" />
 
-    <option name="java-folder" value="prebuilts/jdk/jdk17/linux-x86/" />
+    <option name="java-folder" value="prebuilts/jdk/jdk21/linux-x86/" />
     <option name="exclude-paths" value="java" />
     <option name="use-robolectric-resources" value="true" />
 
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplEnforcementTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplEnforcementTest.java
new file mode 100644
index 00000000..1ca8ce48
--- /dev/null
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplEnforcementTest.java
@@ -0,0 +1,422 @@
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
+package com.android.devicelockcontroller.policy;
+
+import static com.android.devicelockcontroller.policy.DeviceStateController.DeviceState.UNDEFINED;
+
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.verifyNoInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
+import static org.mockito.Mockito.when;
+
+import android.app.admin.DevicePolicyManager;
+import android.os.UserManager;
+
+import androidx.test.core.app.ApplicationProvider;
+
+import com.android.devicelockcontroller.TestDeviceLockControllerApplication;
+import com.android.devicelockcontroller.storage.GlobalParametersClient;
+
+import com.google.common.util.concurrent.Futures;
+
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+import org.mockito.junit.MockitoJUnit;
+import org.mockito.junit.MockitoRule;
+import org.robolectric.RobolectricTestRunner;
+
+import java.util.concurrent.ExecutionException;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
+
+@RunWith(RobolectricTestRunner.class)
+public final class DevicePolicyControllerImplEnforcementTest {
+    @Rule
+    public MockitoRule mMockitoRule = MockitoJUnit.rule();
+
+    @Mock
+    private ProvisionStateController mMockProvisionStateController;
+    @Mock
+    private DevicePolicyManager mMockDpm;
+    @Mock
+    private UserManager mMockUserManager;
+    @Mock
+    private PolicyHandler mMockUserRestrictionsPolicyHandler;
+    @Mock
+    private PolicyHandler mMockAppOpsPolicyHandler;
+    @Mock
+    private PolicyHandler mMockLockTaskModePolicyHandler;
+    @Mock
+    private PolicyHandler mMockPackagePolicyHandler;
+    @Mock
+    private PolicyHandler mMockRolePolicyHandler;
+    @Mock
+    private PolicyHandler mMockKioskKeepAlivePolicyHandler;
+    @Mock
+    private PolicyHandler mMockControllerKeepAlivePolicyHandler;
+    @Mock
+    private PolicyHandler mMockNotificationsPolicyHandler;
+
+    private DevicePolicyController mDevicePolicyController;
+    private TestDeviceLockControllerApplication mTestApp;
+
+    private void setupPolicyHandler(PolicyHandler policyHandler) {
+        when(policyHandler.onUnprovisioned()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onProvisioned()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onProvisionInProgress()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onProvisionPaused()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onProvisionFailed()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onLocked()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onUnlocked()).thenReturn(Futures.immediateFuture(true));
+        when(policyHandler.onCleared()).thenReturn(Futures.immediateFuture(true));
+    }
+
+    @Before
+    public void setUp() {
+        mTestApp = ApplicationProvider.getApplicationContext();
+        ExecutorService bgExecutor = Executors.newSingleThreadExecutor();
+
+        setupPolicyHandler(mMockUserRestrictionsPolicyHandler);
+        setupPolicyHandler(mMockAppOpsPolicyHandler);
+        setupPolicyHandler(mMockLockTaskModePolicyHandler);
+        setupPolicyHandler(mMockPackagePolicyHandler);
+        setupPolicyHandler(mMockRolePolicyHandler);
+        setupPolicyHandler(mMockKioskKeepAlivePolicyHandler);
+        setupPolicyHandler(mMockControllerKeepAlivePolicyHandler);
+        setupPolicyHandler(mMockNotificationsPolicyHandler);
+
+        mDevicePolicyController =
+                new DevicePolicyControllerImpl(mTestApp,
+                        mMockDpm,
+                        mMockUserManager,
+                        mMockUserRestrictionsPolicyHandler,
+                        mMockAppOpsPolicyHandler,
+                        mMockLockTaskModePolicyHandler,
+                        mMockPackagePolicyHandler,
+                        mMockRolePolicyHandler,
+                        mMockKioskKeepAlivePolicyHandler,
+                        mMockControllerKeepAlivePolicyHandler,
+                        mMockNotificationsPolicyHandler,
+                        mMockProvisionStateController,
+                        bgExecutor);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withProvisionStateUnprovisioned_shouldCallOnUnprovisioned()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.UNPROVISIONED));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onUnprovisioned();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withProvisionStateProgress_shouldCallOnProvisionInProgress()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_IN_PROGRESS));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onProvisionInProgress();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withProvisionStateKioskProvisioned_shouldCallOnProvisioned()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.KIOSK_PROVISIONED));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onProvisioned();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withProvisionStatePaused_shouldCallOnProvisionPaused()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_PAUSED));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onProvisionPaused();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withProvisionStateFailed_shouldCallOnProvisionFailed()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_FAILED));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onProvisionFailed();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_provisionSucceeded_deviceUnlocked_shouldCallOnUnlocked()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED));
+        GlobalParametersClient.getInstance().setDeviceState(
+                DeviceStateController.DeviceState.UNLOCKED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onUnlocked();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_provisionSucceeded_deviceLocked_shouldCallOnLocked()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED));
+        GlobalParametersClient.getInstance().setDeviceState(
+                DeviceStateController.DeviceState.LOCKED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onLocked();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_provisionSucceeded_deviceStateUndefined_shouldDoNothing()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.PROVISION_SUCCEEDED));
+        GlobalParametersClient.getInstance().setDeviceState(UNDEFINED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verifyNoInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verifyNoInteractions(mMockAppOpsPolicyHandler);
+
+        verifyNoInteractions(mMockLockTaskModePolicyHandler);
+
+        verifyNoInteractions(mMockPackagePolicyHandler);
+
+        verifyNoInteractions(mMockRolePolicyHandler);
+
+        verifyNoInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verifyNoInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verifyNoInteractions(mMockNotificationsPolicyHandler);
+    }
+
+    @Test
+    public void enforceCurrentPolicies_withDeviceStateCleared_shouldCallOnCleared()
+            throws ExecutionException, InterruptedException {
+        // Provision state can be anything.
+        when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
+                ProvisionStateController.ProvisionState.UNPROVISIONED));
+        GlobalParametersClient.getInstance().setDeviceState(
+                DeviceStateController.DeviceState.CLEARED).get();
+
+        mDevicePolicyController.enforceCurrentPolicies().get();
+
+        verify(mMockUserRestrictionsPolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockUserRestrictionsPolicyHandler);
+
+        verify(mMockAppOpsPolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockAppOpsPolicyHandler);
+
+        verify(mMockLockTaskModePolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockLockTaskModePolicyHandler);
+
+        verify(mMockPackagePolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockPackagePolicyHandler);
+
+        verify(mMockRolePolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockRolePolicyHandler);
+
+        verify(mMockKioskKeepAlivePolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockKioskKeepAlivePolicyHandler);
+
+        verify(mMockControllerKeepAlivePolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockControllerKeepAlivePolicyHandler);
+
+        verify(mMockNotificationsPolicyHandler).onCleared();
+        verifyNoMoreInteractions(mMockNotificationsPolicyHandler);
+    }
+}
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
index 938a4b45..ad2b2eab 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DevicePolicyControllerImplTest.java
@@ -287,6 +287,7 @@ public final class DevicePolicyControllerImplTest {
             throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
         when(mMockUserManager.isUserUnlocked()).thenReturn(true);
@@ -303,6 +304,7 @@ public final class DevicePolicyControllerImplTest {
             throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnDisableKioskKeepAlive();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
         when(mMockUserManager.isUserUnlocked()).thenReturn(true);
@@ -361,6 +363,7 @@ public final class DevicePolicyControllerImplTest {
             throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
         when(mMockUserManager.isUserUnlocked()).thenReturn(true);
@@ -546,6 +549,7 @@ public final class DevicePolicyControllerImplTest {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
         setExpectationsOnDisableControllerKeepAlive();
+        setExpectationsOnEnableKioskKeepAlive();
         GlobalParametersClient.getInstance().setDeviceState(LOCKED).get();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
@@ -562,6 +566,7 @@ public final class DevicePolicyControllerImplTest {
             throws ExecutionException, InterruptedException {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         GlobalParametersClient.getInstance().setDeviceState(LOCKED).get();
         installKioskAppWithLockScreenIntentFilter();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
@@ -582,6 +587,7 @@ public final class DevicePolicyControllerImplTest {
             throws ExecutionException, InterruptedException {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         GlobalParametersClient.getInstance().setDeviceState(LOCKED).get();
         installKioskAppWithoutCategoryHomeIntentFilter();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
@@ -601,6 +607,7 @@ public final class DevicePolicyControllerImplTest {
             throws ExecutionException, InterruptedException {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnDisableKioskKeepAlive();
         GlobalParametersClient.getInstance().setDeviceState(UNLOCKED).get();
         installKioskAppWithoutCategoryHomeIntentFilter();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
@@ -917,6 +924,7 @@ public final class DevicePolicyControllerImplTest {
     public void onUserUnlocked_withLockedDeviceState_shouldMakeExpectedCalls() throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         when(mMockProvisionStateController.onUserUnlocked()).thenReturn(
                 Futures.immediateVoidFuture());
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
@@ -934,6 +942,7 @@ public final class DevicePolicyControllerImplTest {
     public void onUserUnlocked_withUnlockedDeviceState_shouldMakeExpectedCalls() throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnDisableKioskKeepAlive();
         when(mMockProvisionStateController.onUserUnlocked()).thenReturn(
                 Futures.immediateVoidFuture());
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
@@ -1065,6 +1074,7 @@ public final class DevicePolicyControllerImplTest {
     public void onAppCrashed_withLockedDeviceState_shouldMakeExpectedCalls() throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnEnableKioskKeepAlive();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
         when(mMockUserManager.isUserUnlocked()).thenReturn(true);
@@ -1081,6 +1091,7 @@ public final class DevicePolicyControllerImplTest {
             throws Exception {
         setupSetupParameters();
         setupAppOpsPolicyHandlerExpectations();
+        setExpectationsOnDisableKioskKeepAlive();
         when(mMockProvisionStateController.getState()).thenReturn(Futures.immediateFuture(
                 ProvisionState.PROVISION_SUCCEEDED));
         when(mMockUserManager.isUserUnlocked()).thenReturn(true);
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
index 458b8433..4983640f 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/DeviceStateControllerImplTest.java
@@ -22,6 +22,10 @@ import static org.junit.Assert.assertThrows;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.Mockito.when;
 
+import android.platform.test.annotations.EnableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
+
+import com.android.devicelock.flags.Flags;
 import com.android.devicelockcontroller.policy.DeviceStateController.DeviceState;
 import com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionEvent;
 import com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState;
@@ -48,6 +52,9 @@ public final class DeviceStateControllerImplTest {
     @Rule
     public MockitoRule mMockitoRule = MockitoJUnit.rule();
 
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
     @Mock
     private DevicePolicyController mMockDevicePolicyController;
 
@@ -74,6 +81,9 @@ public final class DeviceStateControllerImplTest {
         // Should not have changed the real device state
         assertThat(GlobalParametersClient.getInstance().getDeviceState().get()).isEqualTo(
                 DeviceState.UNDEFINED);
+
+        assertThat(((DeviceStateControllerImpl) mDeviceStateController).mPseudoDeviceState)
+                .isEqualTo(DeviceState.LOCKED);
     }
 
     @Test
@@ -193,6 +203,9 @@ public final class DeviceStateControllerImplTest {
         // Should not have changed the real device state
         assertThat(GlobalParametersClient.getInstance().getDeviceState().get()).isEqualTo(
                 DeviceState.UNDEFINED);
+
+        assertThat(((DeviceStateControllerImpl) mDeviceStateController).mPseudoDeviceState)
+                .isEqualTo(DeviceState.UNLOCKED);
     }
 
     @Test
@@ -369,6 +382,24 @@ public final class DeviceStateControllerImplTest {
                 DeviceState.CLEARED);
     }
 
+    @Test
+    @EnableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
+    public void clearDevice_withUnprovisionedState_shouldNotThrowException()
+            throws ExecutionException, InterruptedException {
+        when(mMockProvisionStateController.getState()).thenReturn(
+                Futures.immediateFuture(ProvisionState.UNPROVISIONED));
+
+        // Clearing the device state should not throw an exception.
+        mDeviceStateController.clearDevice().get();
+
+        // Should not have changed the real device state
+        assertThat(GlobalParametersClient.getInstance().getDeviceState().get()).isEqualTo(
+                DeviceState.UNDEFINED);
+
+        assertThat(((DeviceStateControllerImpl) mDeviceStateController).mPseudoDeviceState)
+                .isEqualTo(DeviceState.CLEARED);
+    }
+
     @Test
     public void getDeviceState_shouldReturnResultFromGlobalParametersClient()
             throws ExecutionException, InterruptedException {
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandlerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandlerTest.java
index 65858c41..2e057c7d 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandlerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/KioskKeepAlivePolicyHandlerTest.java
@@ -127,15 +127,43 @@ public final class KioskKeepAlivePolicyHandlerTest {
     }
 
     @Test
-    public void onLocked_shouldDoNothing() throws ExecutionException, InterruptedException {
+    public void onLocked_enablesKioskKeepalive()
+            throws ExecutionException, InterruptedException {
+        setExpectationsOnEnableKioskKeepalive(/* isSuccess =*/ true);
         assertThat(mHandler.onLocked().get()).isTrue();
-        verifyNoInteractions(mSystemDeviceLockManager);
+        verify(mSystemDeviceLockManager).enableKioskKeepalive(eq(TEST_KIOSK_PACKAGE),
+                any(Executor.class), any());
+        verify(mSystemDeviceLockManager, never()).disableKioskKeepalive(any(Executor.class), any());
+    }
+
+    @Test
+    public void onLocked_onFailure_stillReturnsTrue()
+            throws ExecutionException, InterruptedException {
+        setExpectationsOnEnableKioskKeepalive(/* isSuccess =*/ false);
+        assertThat(mHandler.onLocked().get()).isTrue();
+        verify(mSystemDeviceLockManager).enableKioskKeepalive(eq(TEST_KIOSK_PACKAGE),
+                any(Executor.class), any());
+        verify(mSystemDeviceLockManager, never()).disableKioskKeepalive(any(Executor.class), any());
     }
 
     @Test
-    public void onUnlocked_shouldDoNothing() throws ExecutionException, InterruptedException {
+    public void onUnlocked_disablesKioskKeepalive()
+            throws ExecutionException, InterruptedException {
+        setExpectationsOnDisableKioskKeepalive(/* isSuccess =*/ true);
         assertThat(mHandler.onUnlocked().get()).isTrue();
-        verifyNoInteractions(mSystemDeviceLockManager);
+        verify(mSystemDeviceLockManager).disableKioskKeepalive(any(Executor.class), any());
+        verify(mSystemDeviceLockManager, never()).enableKioskKeepalive(eq(TEST_KIOSK_PACKAGE),
+                any(Executor.class), any());
+    }
+
+    @Test
+    public void onUnlocked_onFailure_stillReturnsTrue()
+            throws ExecutionException, InterruptedException {
+        setExpectationsOnDisableKioskKeepalive(/* isSuccess =*/ false);
+        assertThat(mHandler.onUnlocked().get()).isTrue();
+        verify(mSystemDeviceLockManager).disableKioskKeepalive(any(Executor.class), any());
+        verify(mSystemDeviceLockManager, never()).enableKioskKeepalive(eq(TEST_KIOSK_PACKAGE),
+                any(Executor.class), any());
     }
 
     private void setExpectationsOnEnableKioskKeepalive(boolean isSuccess) {
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/PackagePolicyHandlerTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/PackagePolicyHandlerTest.java
index 71faa7bb..a9dcd095 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/PackagePolicyHandlerTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/policy/PackagePolicyHandlerTest.java
@@ -76,6 +76,20 @@ public final class PackagePolicyHandlerTest {
                 Executors.newSingleThreadExecutor());
     }
 
+    @Test
+    public void onUnprovisioned_shouldSetUserControlDisabledPackagesForController()
+            throws ExecutionException, InterruptedException {
+
+        assertThat(mHandler.onUnprovisioned().get()).isTrue();
+
+        verify(mMockDpm).setUserControlDisabledPackages(eq(null),
+                mUserControlDisabledPackages.capture());
+        List<String> userControlDisabledPackages = mUserControlDisabledPackages.getValue();
+
+        assertThat(userControlDisabledPackages).hasSize(1);
+        assertThat(userControlDisabledPackages).contains(mContext.getPackageName());
+    }
+
     @Test
     public void onProvisioned_withKioskPackageSet_shouldHaveExpectedMethodCalls()
             throws ExecutionException, InterruptedException {
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
index 6ed66dba..d3d3c01a 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/provision/grpc/impl/DeviceCheckinClientImplTest.java
@@ -41,11 +41,14 @@ import com.android.devicelockcontroller.proto.PauseDeviceProvisioningRequest;
 import com.android.devicelockcontroller.proto.PauseDeviceProvisioningResponse;
 import com.android.devicelockcontroller.proto.ReportDeviceProvisionStateRequest;
 import com.android.devicelockcontroller.proto.ReportDeviceProvisionStateResponse;
+import com.android.devicelockcontroller.proto.UpdateFcmTokenRequest;
+import com.android.devicelockcontroller.proto.UpdateFcmTokenResponse;
 import com.android.devicelockcontroller.provision.grpc.DeviceCheckInClient;
 import com.android.devicelockcontroller.provision.grpc.GetDeviceCheckInStatusGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.IsDeviceInApprovedCountryGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.PauseDeviceProvisioningGrpcResponse;
 import com.android.devicelockcontroller.provision.grpc.ReportDeviceProvisionStateGrpcResponse;
+import com.android.devicelockcontroller.provision.grpc.UpdateFcmTokenGrpcResponse;
 
 import io.grpc.CallOptions;
 import io.grpc.Channel;
@@ -709,6 +712,127 @@ public final  class DeviceCheckinClientImplTest {
         assertThat(response.get().hasRecoverableError()).isTrue();
     }
 
+    @Test
+    public void updateFcmToken_succeeds() throws Exception {
+        // GIVEN the service succeeds through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeSucceedingService())
+                .build()
+                .start());
+
+        // WHEN we update FCM token
+        AtomicReference<UpdateFcmTokenGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor.submit(() -> response.set(
+                mDeviceCheckInClientImpl.updateFcmToken(
+                        new ArraySet<>(), TEST_FCM_TOKEN))).get();
+
+        // THEN the response is successful
+        assertThat(response.get().isSuccessful()).isTrue();
+        assertThat(mReceivedFcmToken).isEqualTo(TEST_FCM_TOKEN);
+    }
+
+    @Test
+    public void updateFcmToken_noDefaultConnectivity_fallsBackToNonVpn()
+            throws Exception {
+        // GIVEN a non-VPN network is connected with connectivity
+        Set<ConnectivityManager.NetworkCallback> networkCallbacks =
+                mShadowConnectivityManager.getNetworkCallbacks();
+        for (ConnectivityManager.NetworkCallback callback : networkCallbacks) {
+            NetworkCapabilities capabilities =
+                    Shadows.shadowOf(new NetworkCapabilities()).addCapability(
+                            NET_CAPABILITY_VALIDATED);
+            callback.onCapabilitiesChanged(mNonVpnNetwork, capabilities);
+        }
+
+        // GIVEN the service fails through the default network and succeeds through the non-VPN
+        // network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeFailingService())
+                .build()
+                .start());
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mNonVpnServerName)
+                .directExecutor()
+                .addService(makeSucceedingService())
+                .build()
+                .start());
+
+        // WHEN we update FCM token
+        AtomicReference<UpdateFcmTokenGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor.submit(() -> response.set(
+                mDeviceCheckInClientImpl.updateFcmToken(
+                        new ArraySet<>(), TEST_FCM_TOKEN))).get();
+
+        // THEN the response is successful
+        assertThat(response.get().isSuccessful()).isTrue();
+        assertThat(mReceivedFcmToken).isEqualTo(TEST_FCM_TOKEN);
+    }
+
+    @Test
+    public void updateFcmToken_noConnectivityOrNonVpnNetwork_isNotSuccessful()
+            throws Exception {
+        // GIVEN non-VPN network connects and then loses connectivity
+        Set<ConnectivityManager.NetworkCallback> networkCallbacks =
+                mShadowConnectivityManager.getNetworkCallbacks();
+        for (ConnectivityManager.NetworkCallback callback : networkCallbacks) {
+            callback.onUnavailable();
+        }
+
+        // GIVEN the service fails through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeFailingService())
+                .build()
+                .start());
+
+        // WHEN we update FCM token
+        AtomicReference<UpdateFcmTokenGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor.submit(() -> response.set(
+                mDeviceCheckInClientImpl.updateFcmToken(
+                        new ArraySet<>(), TEST_FCM_TOKEN))).get();
+
+        // THEN the response is unsuccessful
+        assertThat(response.get().isSuccessful()).isFalse();
+    }
+
+    @Test
+    public void updateFcmToken_lostNonVpnConnection_isNotSuccessful()
+            throws Exception {
+        // GIVEN no connectable non-VPN networks
+        Set<ConnectivityManager.NetworkCallback> networkCallbacks =
+                mShadowConnectivityManager.getNetworkCallbacks();
+        for (ConnectivityManager.NetworkCallback callback : networkCallbacks) {
+            NetworkCapabilities capabilities =
+                    Shadows.shadowOf(new NetworkCapabilities()).addCapability(
+                            NET_CAPABILITY_VALIDATED);
+            callback.onCapabilitiesChanged(mNonVpnNetwork, capabilities);
+            callback.onLost(mNonVpnNetwork);
+        }
+
+        // GIVEN the service fails through the default network
+        mGrpcCleanup.register(InProcessServerBuilder
+                .forName(mDefaultNetworkServerName)
+                .directExecutor()
+                .addService(makeFailingService())
+                .build()
+                .start());
+
+        // WHEN we update FCM token
+        AtomicReference<UpdateFcmTokenGrpcResponse> response = new AtomicReference<>();
+        mBgExecutor.submit(() -> response.set(
+                mDeviceCheckInClientImpl.updateFcmToken(
+                        new ArraySet<>(), TEST_FCM_TOKEN))).get();
+
+        // THEN the response is unsuccessful
+        assertThat(response.get().isSuccessful()).isFalse();
+        assertThat(response.get().hasRecoverableError()).isTrue();
+    }
+
     @Test
     public void cleanUp_unregistersNetworkCallback() {
         // WHEN we call clean up
@@ -784,6 +908,17 @@ public final  class DeviceCheckinClientImplTest {
                 responseObserver.onNext(response);
                 responseObserver.onCompleted();
             }
+
+            @Override
+            public void updateFcmToken(UpdateFcmTokenRequest req,
+                    StreamObserver<UpdateFcmTokenResponse> responseObserver) {
+                mReceivedFcmToken = req.getFcmRegistrationToken();
+                UpdateFcmTokenResponse response = UpdateFcmTokenResponse
+                        .newBuilder()
+                        .build();
+                responseObserver.onNext(response);
+                responseObserver.onCompleted();
+            }
         };
     }
 
@@ -816,6 +951,13 @@ public final  class DeviceCheckinClientImplTest {
                 responseObserver.onError(new StatusRuntimeException(Status.DEADLINE_EXCEEDED));
                 responseObserver.onCompleted();
             }
+
+            @Override
+            public void updateFcmToken(UpdateFcmTokenRequest req,
+                    StreamObserver<UpdateFcmTokenResponse> responseObserver) {
+                responseObserver.onError(new StatusRuntimeException(Status.DEADLINE_EXCEEDED));
+                responseObserver.onCompleted();
+            }
         };
     }
 }
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/NextProvisionFailedStepReceiverTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/NextProvisionFailedStepReceiverTest.java
index d6ea9774..14c918ae 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/NextProvisionFailedStepReceiverTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/receivers/NextProvisionFailedStepReceiverTest.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.receivers;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_DISMISSIBLE_UI;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_PERSISTENT_UI;
 import static com.android.devicelockcontroller.common.DeviceLockConstants.DeviceProvisionState.PROVISION_STATE_RETRY;
@@ -33,12 +28,12 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.robolectric.annotation.LooperMode.Mode.LEGACY;
 
 import android.content.Intent;
-import android.net.NetworkRequest;
 import android.os.Handler;
 import android.os.HandlerThread;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.work.Configuration;
+import androidx.work.NetworkType;
 import androidx.work.WorkInfo;
 import androidx.work.WorkManager;
 import androidx.work.testing.SynchronousExecutor;
@@ -157,11 +152,8 @@ public class NextProvisionFailedStepReceiverTest {
                 REPORT_PROVISION_STATE_WORK_NAME).get();
         assertThat(actualWorks.size()).isEqualTo(1);
         WorkInfo actualWorkInfo = actualWorks.get(0);
-        NetworkRequest networkRequest = actualWorkInfo.getConstraints().getRequiredNetworkRequest();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_INTERNET)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_VPN)).isTrue();
+        assertThat(actualWorkInfo.getConstraints().getRequiredNetworkType()).isEqualTo(
+                NetworkType.CONNECTED);
     }
 
     private static void verifyReportProvisionStateWorkNotScheduled(WorkManager workManager)
diff --git a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImplTest.java b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImplTest.java
index 5ac605ae..849d0161 100644
--- a/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImplTest.java
+++ b/DeviceLockController/tests/robolectric/src/com/android/devicelockcontroller/schedule/DeviceLockControllerSchedulerImplTest.java
@@ -16,11 +16,6 @@
 
 package com.android.devicelockcontroller.schedule;
 
-import static android.net.NetworkCapabilities.NET_CAPABILITY_INTERNET;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_RESTRICTED;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_NOT_VPN;
-import static android.net.NetworkCapabilities.NET_CAPABILITY_TRUSTED;
-
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.PROVISION_PAUSED;
 import static com.android.devicelockcontroller.policy.ProvisionStateController.ProvisionState.UNPROVISIONED;
 import static com.android.devicelockcontroller.schedule.DeviceLockControllerSchedulerImpl.DEVICE_CHECK_IN_WORK_NAME;
@@ -29,12 +24,12 @@ import static com.google.common.truth.Truth.assertThat;
 
 import android.app.AlarmManager;
 import android.app.PendingIntent;
-import android.net.NetworkRequest;
 import android.os.SystemClock;
 
 import androidx.test.core.app.ApplicationProvider;
 import androidx.work.Configuration;
 import androidx.work.ExistingWorkPolicy;
+import androidx.work.NetworkType;
 import androidx.work.OneTimeWorkRequest;
 import androidx.work.WorkInfo;
 import androidx.work.WorkManager;
@@ -257,11 +252,8 @@ public final class DeviceLockControllerSchedulerImplTest {
                 DEVICE_CHECK_IN_WORK_NAME));
         assertThat(actualWorks.size()).isEqualTo(1);
         WorkInfo actualWorkInfo = actualWorks.get(0);
-        NetworkRequest networkRequest = actualWorkInfo.getConstraints().getRequiredNetworkRequest();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_INTERNET)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_VPN)).isTrue();
+        assertThat(actualWorkInfo.getConstraints().getRequiredNetworkType()).isEqualTo(
+                NetworkType.CONNECTED);
         assertThat(actualWorkInfo.getInitialDelayMillis()).isEqualTo(0);
     }
 
@@ -280,11 +272,8 @@ public final class DeviceLockControllerSchedulerImplTest {
                 DEVICE_CHECK_IN_WORK_NAME));
         assertThat(actualWorks.size()).isEqualTo(1);
         WorkInfo actualWorkInfo = actualWorks.get(0);
-        NetworkRequest networkRequest = actualWorkInfo.getConstraints().getRequiredNetworkRequest();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_INTERNET)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_VPN)).isTrue();
+        assertThat(actualWorkInfo.getConstraints().getRequiredNetworkType()).isEqualTo(
+                NetworkType.CONNECTED);
         assertThat(actualWorkInfo.getInitialDelayMillis()).isEqualTo(
                 TEST_RETRY_CHECK_IN_DELAY.toMillis());
 
@@ -318,11 +307,8 @@ public final class DeviceLockControllerSchedulerImplTest {
                 DEVICE_CHECK_IN_WORK_NAME));
         assertThat(actualWorks.size()).isEqualTo(1);
         WorkInfo actualWorkInfo = actualWorks.get(0);
-        NetworkRequest networkRequest = actualWorkInfo.getConstraints().getRequiredNetworkRequest();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_INTERNET)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_VPN)).isTrue();
+        assertThat(actualWorkInfo.getConstraints().getRequiredNetworkType()).isEqualTo(
+                NetworkType.CONNECTED);
 
         long expectedDelay = TEST_NEXT_CHECK_IN_TIME_MILLIS - TEST_CURRENT_TIME_MILLIS;
         assertThat(actualWorkInfo.getInitialDelayMillis()).isEqualTo(expectedDelay);
@@ -390,11 +376,8 @@ public final class DeviceLockControllerSchedulerImplTest {
                 DEVICE_CHECK_IN_WORK_NAME));
         assertThat(actualWorks.size()).isEqualTo(1);
         WorkInfo actualWorkInfo = actualWorks.get(0);
-        NetworkRequest networkRequest = actualWorkInfo.getConstraints().getRequiredNetworkRequest();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_RESTRICTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_TRUSTED)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_INTERNET)).isTrue();
-        assertThat(networkRequest.hasCapability(NET_CAPABILITY_NOT_VPN)).isTrue();
+        assertThat(actualWorkInfo.getConstraints().getRequiredNetworkType()).isEqualTo(
+                NetworkType.CONNECTED);
 
         long expectedDelay = TEST_NEXT_CHECK_IN_TIME_MILLIS - TEST_CURRENT_TIME_MILLIS;
         assertThat(actualWorkInfo.getInitialDelayMillis()).isEqualTo(expectedDelay);
diff --git a/apex/Android.bp b/apex/Android.bp
index 48251a49..10343775 100644
--- a/apex/Android.bp
+++ b/apex/Android.bp
@@ -59,6 +59,7 @@ bootclasspath_fragment {
         // result in a build failure due to inconsistent flags.
         package_prefixes: [
             "android.devicelock",
+            "com.android.devicelock.flags",
         ],
     },
 }
diff --git a/flags/Android.bp b/flags/Android.bp
new file mode 100644
index 00000000..ad63d9d3
--- /dev/null
+++ b/flags/Android.bp
@@ -0,0 +1,54 @@
+//
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
+//
+
+package {
+    default_applicable_licenses: ["Android-Apache-2.0"],
+}
+
+aconfig_declarations {
+    name: "devicelock-aconfig-flags",
+    package: "com.android.devicelock.flags",
+    container: "com.android.devicelock",
+    exportable: true,
+    srcs: ["flags.aconfig"],
+}
+
+java_aconfig_library {
+    name: "devicelock-aconfig-flags-lib",
+    aconfig_declarations: "devicelock-aconfig-flags",
+    min_sdk_version: "UpsideDownCake",
+    apex_available: [
+        "com.android.devicelock",
+    ],
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    visibility: [
+        "//packages/modules/DeviceLock:__subpackages__",
+    ],
+}
+
+java_aconfig_library {
+    name: "devicelock-exported-aconfig-flags-lib",
+    aconfig_declarations: "devicelock-aconfig-flags",
+    min_sdk_version: "UpsideDownCake",
+    mode: "exported",
+    apex_available: [
+        "com.android.devicelock",
+    ],
+    defaults: ["framework-minus-apex-aconfig-java-defaults"],
+    visibility: [
+        "//packages/modules/DeviceLock:__subpackages__",
+    ],
+}
diff --git a/flags/flags.aconfig b/flags/flags.aconfig
new file mode 100644
index 00000000..45b97f1b
--- /dev/null
+++ b/flags/flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.devicelock.flags"
+container: "com.android.devicelock"
+
+flag {
+    name: "clear_device_restrictions"
+    is_exported: true
+    namespace: "devicelock"
+    description: "Flag for API to clear device restrictions"
+    bug: "349177010"
+}
diff --git a/framework/Android.bp b/framework/Android.bp
index 30cc6e48..b7c6a7df 100644
--- a/framework/Android.bp
+++ b/framework/Android.bp
@@ -42,7 +42,10 @@ java_sdk_library {
     name: "framework-devicelock",
     srcs: [":framework-devicelock-sources"],
     defaults: ["framework-module-defaults"],
-    permitted_packages: ["android.devicelock"],
+    permitted_packages: [
+        "android.devicelock",
+        "com.android.devicelock.flags",
+    ],
     impl_library_visibility: ["//packages/modules/DeviceLock:__subpackages__"],
     apex_available: [
         "com.android.devicelock",
@@ -50,4 +53,5 @@ java_sdk_library {
     sdk_version: "module_current",
     min_sdk_version: "UpsideDownCake",
     libs: ["framework-annotations-lib"],
+    static_libs: ["devicelock-aconfig-flags-lib"],
 }
diff --git a/framework/api/current.txt b/framework/api/current.txt
index 61b599b9..3ff70e34 100644
--- a/framework/api/current.txt
+++ b/framework/api/current.txt
@@ -9,6 +9,7 @@ package android.devicelock {
   }
 
   public final class DeviceLockManager {
+    method @FlaggedApi("com.android.devicelock.flags.clear_device_restrictions") @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void clearDeviceRestrictions(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Void,java.lang.Exception>);
     method @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void getDeviceId(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<android.devicelock.DeviceId,java.lang.Exception>);
     method public void getKioskApps(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.util.Map<java.lang.Integer,java.lang.String>,java.lang.Exception>);
     method @RequiresPermission(android.Manifest.permission.MANAGE_DEVICE_LOCK_STATE) public void isDeviceLocked(@NonNull java.util.concurrent.Executor, @NonNull android.os.OutcomeReceiver<java.lang.Boolean,java.lang.Exception>);
diff --git a/framework/java/android/devicelock/DeviceLockManager.java b/framework/java/android/devicelock/DeviceLockManager.java
index 0d6aa6de..46aa33fc 100644
--- a/framework/java/android/devicelock/DeviceLockManager.java
+++ b/framework/java/android/devicelock/DeviceLockManager.java
@@ -16,8 +16,11 @@
 
 package android.devicelock;
 
+import static com.android.devicelock.flags.Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS;
+
 import android.Manifest.permission;
 import android.annotation.CallbackExecutor;
+import android.annotation.FlaggedApi;
 import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.RequiresFeature;
@@ -101,10 +104,10 @@ public final class DeviceLockManager {
 
         try {
             mService.lockDevice(
-                    new ILockUnlockDeviceCallback.Stub() {
+                    new IVoidResultCallback.Stub() {
                         @Override
-                        public void onDeviceLockedUnlocked() {
-                            executor.execute(() -> callback.onResult(null));
+                        public void onSuccess() {
+                            executor.execute(() -> callback.onResult(/* result= */ null));
                         }
 
                         @Override
@@ -131,10 +134,10 @@ public final class DeviceLockManager {
 
         try {
             mService.unlockDevice(
-                    new ILockUnlockDeviceCallback.Stub() {
+                    new IVoidResultCallback.Stub() {
                         @Override
-                        public void onDeviceLockedUnlocked() {
-                            executor.execute(() -> callback.onResult(null));
+                        public void onSuccess() {
+                            executor.execute(() -> callback.onResult(/* result= */ null));
                         }
 
                         @Override
@@ -178,6 +181,65 @@ public final class DeviceLockManager {
         }
     }
 
+    /**
+     * Clear device restrictions.
+     *
+     * <p>After a device determines that it's part of a program (e.g. financing) by checking in with
+     * the device lock backend, it will go though a provisioning flow and install a kiosk app.
+     *
+     * <p>At this point, the device is "restricted" and the creditor kiosk app is able to lock
+     * the device. For example, a creditor kiosk app in a financing use case may lock the device
+     * (using {@link #lockDevice}) if payments are missed and unlock (using {@link #unlockDevice})
+     * once they are resumed.
+     *
+     * <p>The Device Lock solution will also put in place some additional restrictions when a device
+     * is enrolled in the program, namely:
+     *
+     * <ul>
+     *     <li>Disable debugging features
+     *     ({@link android.os.UserManager#DISALLOW_DEBUGGING_FEATURES})
+     *     <li>Disable installing from unknown sources
+     *     ({@link android.os.UserManager#DISALLOW_INSTALL_UNKNOWN_SOURCES},
+     *     when configured in the backend)
+     *     <li>Disable outgoing calls
+     *     ({@link android.os.UserManager#DISALLOW_OUTGOING_CALLS},
+     *     when configured in the backend and the device is locked)
+     * </ul>
+     *
+     * <p>Once the program is completed (e.g. the device has been fully paid off), the kiosk app
+     * can use the {@link #clearDeviceRestrictions} API to lift the above restrictions.
+     *
+     * <p>At this point, the kiosk app has relinquished its ability to lock the device.
+     *
+     * @param executor the {@link Executor} on which to invoke the callback.
+     * @param callback this returns either success or an exception.
+     */
+    @RequiresPermission(permission.MANAGE_DEVICE_LOCK_STATE)
+    @FlaggedApi(FLAG_CLEAR_DEVICE_RESTRICTIONS)
+    public void clearDeviceRestrictions(@NonNull @CallbackExecutor Executor executor,
+            @NonNull OutcomeReceiver<Void, Exception> callback) {
+        Objects.requireNonNull(executor);
+        Objects.requireNonNull(callback);
+
+        try {
+            mService.clearDeviceRestrictions(
+                    new IVoidResultCallback.Stub() {
+                        @Override
+                        public void onSuccess() {
+                            executor.execute(() -> callback.onResult(/* result= */ null));
+                        }
+
+                        @Override
+                        public void onError(ParcelableException parcelableException) {
+                            callback.onError(parcelableException.getException());
+                        }
+                    }
+            );
+        } catch (RemoteException e) {
+            executor.execute(() -> callback.onError(new RuntimeException(e)));
+        }
+    }
+
     /**
      * Get the device id.
      *
diff --git a/framework/java/android/devicelock/IDeviceLockService.aidl b/framework/java/android/devicelock/IDeviceLockService.aidl
index 0e19fb9f..90fb272b 100644
--- a/framework/java/android/devicelock/IDeviceLockService.aidl
+++ b/framework/java/android/devicelock/IDeviceLockService.aidl
@@ -19,7 +19,7 @@ package android.devicelock;
 import android.devicelock.IGetKioskAppsCallback;
 import android.devicelock.IGetDeviceIdCallback;
 import android.devicelock.IIsDeviceLockedCallback;
-import android.devicelock.ILockUnlockDeviceCallback;
+import android.devicelock.IVoidResultCallback;
 
 import android.os.RemoteCallback;
 
@@ -31,18 +31,23 @@ oneway interface IDeviceLockService {
     /**
      * Asynchronously lock the device.
      */
-    void lockDevice(in ILockUnlockDeviceCallback callback);
+    void lockDevice(in IVoidResultCallback callback);
 
     /**
      * Asynchronously unlock the device.
      */
-    void unlockDevice(in ILockUnlockDeviceCallback callback);
+    void unlockDevice(in IVoidResultCallback callback);
 
     /**
      * Asynchronously retrieve the device lock status.
      */
     void isDeviceLocked(in IIsDeviceLockedCallback callback);
 
+    /**
+     * Asynchronously clear the device restrictions.
+     */
+    void clearDeviceRestrictions(in IVoidResultCallback callback);
+
     /**
      * Asynchronously retrieve the device identifier.
      */
diff --git a/framework/java/android/devicelock/ILockUnlockDeviceCallback.aidl b/framework/java/android/devicelock/IVoidResultCallback.aidl
similarity index 85%
rename from framework/java/android/devicelock/ILockUnlockDeviceCallback.aidl
rename to framework/java/android/devicelock/IVoidResultCallback.aidl
index 6664ecb0..036b3e97 100644
--- a/framework/java/android/devicelock/ILockUnlockDeviceCallback.aidl
+++ b/framework/java/android/devicelock/IVoidResultCallback.aidl
@@ -19,11 +19,11 @@ package android.devicelock;
 import android.devicelock.ParcelableException;
 
 /**
-  * Callback for a lockDevice()/unlockDevice() request.
+  * Generic callback for requests not returning a value.
   * {@hide}
   */
-oneway interface ILockUnlockDeviceCallback {
-    void onDeviceLockedUnlocked();
+oneway interface IVoidResultCallback {
+    void onSuccess();
 
     void onError(in ParcelableException parcelableException);
 }
diff --git a/framework/java/android/devicelock/ParcelableException.java b/framework/java/android/devicelock/ParcelableException.java
index 750138c7..1d787b32 100644
--- a/framework/java/android/devicelock/ParcelableException.java
+++ b/framework/java/android/devicelock/ParcelableException.java
@@ -30,10 +30,6 @@ public final class ParcelableException extends Exception implements Parcelable {
         super(t);
     }
 
-    public ParcelableException(String message) {
-        super(message);
-    }
-
     private static Exception readFromParcel(Parcel in) {
         final String name = in.readString();
         final String msg = in.readString();
diff --git a/service/Android.bp b/service/Android.bp
index 93a2705f..a7d81653 100644
--- a/service/Android.bp
+++ b/service/Android.bp
@@ -33,8 +33,8 @@ java_library {
     min_sdk_version: "UpsideDownCake",
     libs: [
         "framework-devicelock.impl",
-        "framework-permission",
-        "framework-permission-s",
+        "framework-permission.stubs.module_lib",
+        "framework-permission-s.stubs.module_lib",
     ],
     static_libs: [
         "devicelockcontroller-interface",
diff --git a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
index e0783efb..3e5d618b 100644
--- a/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
+++ b/service/java/com/android/server/devicelock/DeviceLockControllerConnectorStub.java
@@ -19,6 +19,7 @@ package com.android.server.devicelock;
 import android.annotation.IntDef;
 import android.os.OutcomeReceiver;
 
+import com.android.devicelock.flags.Flags;
 import com.android.internal.annotations.GuardedBy;
 
 import java.lang.annotation.ElementType;
@@ -144,6 +145,10 @@ public class DeviceLockControllerConnectorStub implements DeviceLockControllerCo
 
     @GuardedBy("this")
     private boolean setExceptionIfDeviceIsCleared(OutcomeReceiver<?, Exception> callback) {
+        if (Flags.clearDeviceRestrictions()) {
+            return false;
+        }
+
         if (mPseudoState == DevicePseudoState.CLEARED) {
             setException(callback, "Device has been cleared!");
 
diff --git a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
index 36f53d50..ee384dff 100644
--- a/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
+++ b/service/java/com/android/server/devicelock/DeviceLockServiceImpl.java
@@ -51,7 +51,7 @@ import android.devicelock.IDeviceLockService;
 import android.devicelock.IGetDeviceIdCallback;
 import android.devicelock.IGetKioskAppsCallback;
 import android.devicelock.IIsDeviceLockedCallback;
-import android.devicelock.ILockUnlockDeviceCallback;
+import android.devicelock.IVoidResultCallback;
 import android.devicelock.ParcelableException;
 import android.net.NetworkPolicyManager;
 import android.net.Uri;
@@ -460,11 +460,11 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
                 == PERMISSION_GRANTED;
     }
 
-    private void reportDeviceLockedUnlocked(@NonNull ILockUnlockDeviceCallback callback,
+    private void reportDeviceLockedUnlocked(@NonNull IVoidResultCallback callback,
             @Nullable Exception exception) {
         try {
             if (exception == null) {
-                callback.onDeviceLockedUnlocked();
+                callback.onSuccess();
             } else {
                 callback.onError(getParcelableException(exception));
             }
@@ -474,7 +474,7 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     }
 
     private OutcomeReceiver<Void, Exception> getLockUnlockOutcomeReceiver(
-            @NonNull ILockUnlockDeviceCallback callback, @NonNull String successMessage) {
+            @NonNull IVoidResultCallback callback, @NonNull String successMessage) {
         return new OutcomeReceiver<>() {
             @Override
             public void onResult(Void ignored) {
@@ -496,7 +496,7 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     }
 
     @Override
-    public void lockDevice(@NonNull ILockUnlockDeviceCallback callback) {
+    public void lockDevice(@NonNull IVoidResultCallback callback) {
         if (!checkCallerPermission()) {
             try {
                 callback.onError(new ParcelableException(new SecurityException()));
@@ -511,7 +511,7 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     }
 
     @Override
-    public void unlockDevice(@NonNull ILockUnlockDeviceCallback callback) {
+    public void unlockDevice(@NonNull IVoidResultCallback callback) {
         if (!checkCallerPermission()) {
             try {
                 callback.onError(new ParcelableException(new SecurityException()));
@@ -525,6 +525,45 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
                 getLockUnlockOutcomeReceiver(callback, "Device unlocked"));
     }
 
+    @Override
+    public void clearDeviceRestrictions(@NonNull IVoidResultCallback callback) {
+        if (!checkCallerPermission()) {
+            try {
+                callback.onError(new ParcelableException(new SecurityException()));
+            } catch (RemoteException e) {
+                Slog.e(TAG, "clearDeviceRestrictions() - Unable to send error to the callback", e);
+            }
+            return;
+        }
+
+        final UserHandle userHandle = Binder.getCallingUserHandle();
+
+        getDeviceLockControllerConnector(userHandle).clearDeviceRestrictions(
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(Void ignored) {
+                        Slog.i(TAG, "Device cleared ");
+
+                        try {
+                            callback.onSuccess();
+                        } catch (RemoteException e) {
+                            Slog.e(TAG, "Unable to send result to the callback", e);
+                        }
+                    }
+
+                    @Override
+                    public void onError(Exception ex) {
+                        Slog.e(TAG, "Exception clearing device: ", ex);
+
+                        try {
+                            callback.onError(getParcelableException(ex));
+                        } catch (RemoteException e) {
+                            Slog.e(TAG, "Unable to send error to the callback", e);
+                        }
+                    }
+                });
+    }
+
     @Override
     public void isDeviceLocked(@NonNull IIsDeviceLockedCallback callback) {
         if (!checkCallerPermission()) {
@@ -573,7 +612,8 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     void getDeviceId(@NonNull IGetDeviceIdCallback callback, int deviceIdTypeBitmap) {
         try {
             if (deviceIdTypeBitmap < 0 || deviceIdTypeBitmap >= (1 << (LAST_DEVICE_ID_TYPE + 1))) {
-                callback.onError(new ParcelableException("Invalid device type"));
+                Exception exception = new Exception("Invalid device type");
+                callback.onError(new ParcelableException(exception));
                 return;
             }
         } catch (RemoteException e) {
@@ -620,7 +660,8 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
                     //
                     // TODO(b/270392813): Send the device ID back to the callback with
                     //  UNSPECIFIED device ID type.
-                    callback.onError(new ParcelableException("Unable to get device id"));
+                    Exception exception = new Exception("Unable to get device id");
+                    callback.onError(new ParcelableException(exception));
                 } catch (RemoteException e) {
                     Slog.e(TAG, "getDeviceId() - Unable to send result to the callback", e);
                 }
@@ -985,21 +1026,37 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
 
     @Override
     public void enableKioskKeepalive(String packageName, @NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         enableKeepalive(true /* forKiosk */, packageName, remoteCallback);
     }
 
     @Override
     public void disableKioskKeepalive(@NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         disableKeepalive(true /* forKiosk */, remoteCallback);
     }
 
     @Override
     public void enableControllerKeepalive(@NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         enableKeepalive(false /* forKiosk */, mServiceInfo.packageName, remoteCallback);
     }
 
     @Override
     public void disableControllerKeepalive(@NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         disableKeepalive(false /* forKiosk */, remoteCallback);
     }
 
@@ -1069,6 +1126,10 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
 
     @Override
     public void setDeviceFinalized(boolean finalized, @NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         mPersistentStore.scheduleWrite(finalized);
         UserHandle user = getCallingUserHandle();
         if (canDlcBeDisabledForFinalizedUser(user)) {
@@ -1084,6 +1145,10 @@ final class DeviceLockServiceImpl extends IDeviceLockService.Stub {
     @Override
     public void setPostNotificationsSystemFixed(boolean systemFixed,
             @NonNull RemoteCallback remoteCallback) {
+        if (!checkDeviceLockControllerPermission(remoteCallback)) {
+            return;
+        }
+
         final UserHandle userHandle = Binder.getCallingUserHandle();
         final PackageManager packageManager = mContext.getPackageManager();
         final int permissionFlags = PackageManager.FLAG_PERMISSION_SYSTEM_FIXED;
diff --git a/tests/cts/Android.bp b/tests/cts/Android.bp
index 5ab4c42a..9892101f 100644
--- a/tests/cts/Android.bp
+++ b/tests/cts/Android.bp
@@ -30,6 +30,7 @@ android_test {
         "truth",
         "androidx.test.core",
         "compatibility-device-util-axt",
+        "devicelock-exported-aconfig-flags-lib",
     ],
     test_suites: [
         "general-tests",
diff --git a/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java b/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
index d6bbb08e..f3c12b71 100644
--- a/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
+++ b/tests/cts/src/com/android/cts/devicelock/DeviceLockManagerTest.java
@@ -26,6 +26,9 @@ import android.devicelock.DeviceLockManager;
 import android.os.Build;
 import android.os.OutcomeReceiver;
 import android.os.UserHandle;
+import android.platform.test.annotations.RequiresFlagsEnabled;
+import android.platform.test.flag.junit.CheckFlagsRule;
+import android.platform.test.flag.junit.DeviceFlagsValueProvider;
 import android.util.ArrayMap;
 
 import androidx.concurrent.futures.CallbackToFutureAdapter;
@@ -34,9 +37,11 @@ import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.compatibility.common.util.ApiTest;
 import com.android.compatibility.common.util.SystemUtil;
+import com.android.devicelock.flags.Flags;
 
 import com.google.common.util.concurrent.ListenableFuture;
 
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
@@ -61,6 +66,9 @@ public final class DeviceLockManagerTest {
     private final DeviceLockManager mDeviceLockManager =
             mContext.getSystemService(DeviceLockManager.class);
 
+    @Rule
+    public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
+
     private static final int TIMEOUT = 1;
 
     private void addFinancedDeviceKioskRole() {
@@ -181,6 +189,26 @@ public final class DeviceLockManagerTest {
                 });
     }
 
+    private ListenableFuture<Void> getClearDeviceRestrictionsFuture() {
+        return CallbackToFutureAdapter.getFuture(
+                completer -> {
+                    mDeviceLockManager.clearDeviceRestrictions(mExecutorService,
+                            new OutcomeReceiver<>() {
+                                @Override
+                                public void onResult(Void result) {
+                                    completer.set(null);
+                                }
+
+                                @Override
+                                public void onError(Exception error) {
+                                    completer.setException(error);
+                                }
+                            });
+                    // Used only for debugging.
+                    return "clearDeviceRestrictions operation";
+                });
+    }
+
     @Test
     @ApiTest(apis = {"android.devicelock.DeviceLockManager#lockDevice"})
     public void lockDevicePermissionCheck() {
@@ -207,6 +235,20 @@ public final class DeviceLockManagerTest {
                 .isInstanceOf(SecurityException.class);
     }
 
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#clearDeviceRestrictions"})
+    public void clearDeviceRestrictionsPermissionCheck() {
+        ListenableFuture<Void> clearDeviceRestrictionsFuture = getClearDeviceRestrictionsFuture();
+
+        Exception clearDeviceRestrictionsResponseException =
+                assertThrows(
+                        ExecutionException.class,
+                        () -> clearDeviceRestrictionsFuture.get(TIMEOUT, TimeUnit.SECONDS));
+        assertThat(clearDeviceRestrictionsResponseException).hasCauseThat()
+                .isInstanceOf(SecurityException.class);
+    }
+
     @Test
     @ApiTest(apis = {"android.devicelock.DeviceLockManager#isDeviceLocked"})
     public void isDeviceLockedPermissionCheck() {
@@ -304,4 +346,19 @@ public final class DeviceLockManagerTest {
         Map<Integer, String> kioskAppsMap = getKioskAppsFuture().get(TIMEOUT, TimeUnit.SECONDS);
         assertThat(kioskAppsMap).isEmpty();
     }
+
+    @Test
+    @RequiresFlagsEnabled(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
+    @ApiTest(apis = {"android.devicelock.DeviceLockManager#clearDeviceRestrictions"})
+    public void clearDeviceRestrictionsShouldSucceed()
+            throws ExecutionException, InterruptedException, TimeoutException {
+        try {
+            addFinancedDeviceKioskRole();
+
+            // Clearing device restrictions should not throw an exception.
+            getClearDeviceRestrictionsFuture().get(TIMEOUT, TimeUnit.SECONDS);
+        } finally {
+            removeFinancedDeviceKioskRole();
+        }
+    }
 }
diff --git a/tests/unittests/Android.bp b/tests/unittests/Android.bp
index fdadbabd..9c44d906 100644
--- a/tests/unittests/Android.bp
+++ b/tests/unittests/Android.bp
@@ -23,6 +23,7 @@ android_app {
 
 android_robolectric_test {
     name: "DeviceLockUnitTests",
+    team: "trendy_team_android_go",
     srcs: [
         "src/**/*.java",
         ":framework-devicelock-sources",
@@ -30,8 +31,10 @@ android_robolectric_test {
     java_resource_dirs: ["config"],
     static_libs: [
         "service-devicelock",
+        "devicelock-aconfig-flags-lib",
         "androidx.test.core",
         "androidx.test.runner",
+        "flag-junit",
         "mockito-robolectric-prebuilt",
         "truth",
     ],
diff --git a/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java b/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
index 8a82b74e..402f8152 100644
--- a/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
+++ b/tests/unittests/src/com/android/server/devicelock/DeviceLockControllerConnectorStubTest.java
@@ -21,12 +21,17 @@ import static com.google.common.truth.Truth.assertThat;
 import static org.junit.Assert.assertThrows;
 
 import android.os.OutcomeReceiver;
+import android.platform.test.annotations.DisableFlags;
+import android.platform.test.flag.junit.SetFlagsRule;
 
 import androidx.concurrent.futures.CallbackToFutureAdapter;
 
+import com.android.devicelock.flags.Flags;
+
 import com.google.common.util.concurrent.ListenableFuture;
 
 import org.junit.Before;
+import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.robolectric.RobolectricTestRunner;
@@ -43,6 +48,9 @@ public final class DeviceLockControllerConnectorStubTest {
     private DeviceLockControllerConnectorStub mDeviceLockControllerConnectorStub;
     private static final int TIMEOUT_SEC = 5;
 
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
     @Before
     public void setup() throws Exception {
         mDeviceLockControllerConnectorStub = new DeviceLockControllerConnectorStub();
@@ -78,6 +86,7 @@ public final class DeviceLockControllerConnectorStubTest {
     }
 
     @Test
+    @DisableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
     public void lockDevice_withClearedState_shouldThrowException()
             throws ExecutionException, InterruptedException, TimeoutException {
         // Given the device state is CLEARED
@@ -119,6 +128,7 @@ public final class DeviceLockControllerConnectorStubTest {
     }
 
     @Test
+    @DisableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
     public void unlockDevice_withClearedState_shouldThrowException()
             throws ExecutionException, InterruptedException, TimeoutException {
         // Given the device state is CLEARED
@@ -160,6 +170,7 @@ public final class DeviceLockControllerConnectorStubTest {
     }
 
     @Test
+    @DisableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
     public void clearDeviceRestrictions_withClearedState_shouldThrowException()
             throws ExecutionException, InterruptedException, TimeoutException {
         // Given the device state is CLEARED
@@ -202,6 +213,7 @@ public final class DeviceLockControllerConnectorStubTest {
     }
 
     @Test
+    @DisableFlags(Flags.FLAG_CLEAR_DEVICE_RESTRICTIONS)
     public void isDeviceLocked_withClearedState_shouldThrownException()
             throws ExecutionException, InterruptedException, TimeoutException {
         // Given the device state is CLEARED
diff --git a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
index f452a18c..48ebeafc 100644
--- a/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
+++ b/tests/unittests/src/com/android/server/devicelock/DeviceLockServiceImplTest.java
@@ -398,6 +398,78 @@ public final class DeviceLockServiceImplTest {
                 .isEqualTo(COMPONENT_ENABLED_STATE_DISABLED);
     }
 
+    @Test
+    public void enableKioskKeepalive_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.enableKioskKeepalive(mContext.getPackageName(), new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
+    @Test
+    public void disableKioskKeepalive_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.disableKioskKeepalive(new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
+    @Test
+    public void enableControllerKeepalive_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.enableControllerKeepalive(new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
+    @Test
+    public void disableControllerKeepalive_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.disableControllerKeepalive(new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
+    @Test
+    public void setDeviceFinalized_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.setDeviceFinalized(true, new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
+    @Test
+    public void setPostNotificationsSystemFixed_withoutPermission_shouldFail() throws Exception {
+        mShadowApplication.denyPermissions(MANAGE_DEVICE_LOCK_SERVICE_FROM_CONTROLLER);
+
+        AtomicBoolean succeeded = new AtomicBoolean(true);
+        mService.setPostNotificationsSystemFixed(true, new RemoteCallback(result ->
+                succeeded.set(result.getBoolean(KEY_REMOTE_CALLBACK_RESULT))));
+        waitUntilBgExecutorIdle();
+
+        assertThat(succeeded.get()).isFalse();
+    }
+
     /**
      * Make the resolve info for the DLC package.
      */
diff --git a/tests/unittests/src/com/android/server/devicelock/ParcelableExceptionTest.java b/tests/unittests/src/com/android/server/devicelock/ParcelableExceptionTest.java
new file mode 100644
index 00000000..4a3e3108
--- /dev/null
+++ b/tests/unittests/src/com/android/server/devicelock/ParcelableExceptionTest.java
@@ -0,0 +1,63 @@
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
+package com.android.server.devicelock;
+
+import static com.google.common.truth.Truth.assertThat;
+
+import android.devicelock.ParcelableException;
+import android.os.Parcel;
+
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.robolectric.RobolectricTestRunner;
+
+/**
+ * Tests for {@link android.devicelock.ParcelableException}.
+ */
+@RunWith(RobolectricTestRunner.class)
+public final class ParcelableExceptionTest {
+    private static final String EXCEPTION_MESSAGE = "TEST_EXCEPTION_MESSAGE";
+
+    @Test
+    public void parcelableExceptionShouldReturnOriginalException() {
+        Exception exception = new Exception(EXCEPTION_MESSAGE);
+        ParcelableException parcelableException = new ParcelableException(exception);
+
+        Exception cause = parcelableException.getException();
+
+        assertThat(cause).isNotNull();
+        assertThat(cause.getMessage()).isEqualTo(EXCEPTION_MESSAGE);
+    }
+
+    @Test
+    public void parcelableExceptionShouldParcelAndUnparcel() {
+        Parcel parcel = Parcel.obtain();
+        try {
+            Exception exception = new Exception(EXCEPTION_MESSAGE);
+            ParcelableException inParcelable = new ParcelableException(exception);
+            parcel.writeParcelable(inParcelable, 0);
+            parcel.setDataPosition(0);
+            ParcelableException outParcelable = parcel.readParcelable(
+                    ParcelableException.class.getClassLoader(), ParcelableException.class);
+            assertThat(outParcelable).isNotNull();
+            assertThat(inParcelable.getException().getMessage())
+                    .isEqualTo(outParcelable.getException().getMessage());
+        } finally {
+            parcel.recycle();
+        }
+    }
+}
```

