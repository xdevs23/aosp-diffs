```diff
diff --git a/Android.bp b/Android.bp
index 0d1c81ddd..65e4402f0 100644
--- a/Android.bp
+++ b/Android.bp
@@ -31,6 +31,7 @@ android_library {
         "androidx.annotation_annotation",
         "androidx.core_core",
         "telecom_flags_core_java_lib",
+        "modules-utils-handlerexecutor",
     ],
     resource_dirs: ["res"],
     proto: {
diff --git a/flags/Android.bp b/flags/Android.bp
index 501eba40c..54b14437d 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -44,6 +44,7 @@ aconfig_declarations {
         "telecom_bluetoothdevicemanager_flags.aconfig",
         "telecom_non_critical_security_flags.aconfig",
         "telecom_headless_system_user_mode.aconfig",
+        "telecom_session_flags.aconfig",
         "telecom_metrics_flags.aconfig",
     ],
 }
diff --git a/flags/telecom_anomaly_report_flags.aconfig b/flags/telecom_anomaly_report_flags.aconfig
index b060ed0eb..5d42b867c 100644
--- a/flags/telecom_anomaly_report_flags.aconfig
+++ b/flags/telecom_anomaly_report_flags.aconfig
@@ -16,3 +16,14 @@ flag {
   description: "If a self-managed call is stuck in certain states, disconnect it"
   bug: "360298368"
 }
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "dont_timeout_destroyed_calls"
+  namespace: "telecom"
+  description: "When create connection timeout is hit, if call is already destroyed, skip anomaly"
+  bug: "381684580"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_api_flags.aconfig b/flags/telecom_api_flags.aconfig
index 75efdfae3..2dfd878a4 100644
--- a/flags/telecom_api_flags.aconfig
+++ b/flags/telecom_api_flags.aconfig
@@ -73,3 +73,12 @@ flag {
   description: "Formalizes the getLastKnownCellIdentity API that Telecom reliees on as a system api"
   bug: "327454165"
 }
+
+# OWNER=grantmenke TARGET=25Q2
+flag {
+  name: "allow_system_apps_resolve_voip_calls"
+  is_exported: true
+  namespace: "telecom"
+  description: "Allow system apps such as accessibility to accept and end VOIP calls."
+  bug: "353579043"
+}
diff --git a/flags/telecom_bluetoothdevicemanager_flags.aconfig b/flags/telecom_bluetoothdevicemanager_flags.aconfig
index 4c91491cc..5dd5831dd 100644
--- a/flags/telecom_bluetoothdevicemanager_flags.aconfig
+++ b/flags/telecom_bluetoothdevicemanager_flags.aconfig
@@ -8,3 +8,13 @@ flag {
   description: "Fix for Log.wtf in the BinderProxy"
   bug: "333417369"
 }
+# OWNER=huiwang TARGET=25Q1
+flag {
+  name: "keep_bluetooth_devices_cache_updated"
+  namespace: "telecom"
+  description: "Fix the devices cache issue of BluetoothDeviceManager"
+  bug: "380320985"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_callaudioroutestatemachine_flags.aconfig b/flags/telecom_callaudioroutestatemachine_flags.aconfig
index 33bccba22..a60c0f13b 100644
--- a/flags/telecom_callaudioroutestatemachine_flags.aconfig
+++ b/flags/telecom_callaudioroutestatemachine_flags.aconfig
@@ -17,6 +17,14 @@ flag {
   bug: "306395598"
 }
 
+# OWNER=pmadapurmath TARGET=25Q1
+flag {
+  name: "resolve_active_bt_routing_and_bt_timing_issue"
+  namespace: "telecom"
+  description: "Resolve the active BT device routing and flaky timing issues noted in BT routing."
+  bug: "372029371"
+}
+
 # OWNER=tgunn TARGET=24Q3
 flag {
   name: "ensure_audio_mode_updates_on_foreground_call_change"
@@ -99,3 +107,25 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+# OWNER=pmadapurmath TARGET=25Q1
+flag {
+  name: "new_audio_path_speaker_broadcast_and_unfocused_routing"
+  namespace: "telecom"
+  description: "Replace the speaker broadcasts with the communication device changed listener and resolve baseline routing issues when a call ends."
+  bug: "353419513"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=pmadapurmath TARGET=25Q2
+flag {
+  name: "fix_user_request_baseline_route_video_call"
+  namespace: "telecom"
+  description: "Ensure that audio is routed out of speaker in a video call when we receive USER_SWITCH_BASELINE_ROUTE."
+  bug: "374037591"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_headless_system_user_mode.aconfig b/flags/telecom_headless_system_user_mode.aconfig
index f79873354..4135794ae 100644
--- a/flags/telecom_headless_system_user_mode.aconfig
+++ b/flags/telecom_headless_system_user_mode.aconfig
@@ -11,4 +11,28 @@ flag {
     metadata {
         purpose: PURPOSE_BUGFIX
       }
+}
+
+# OWNER=grantmenke TARGET=25Q1
+flag {
+    name: "telecom_main_user_in_block_check"
+    is_exported: true
+    namespace: "telecom"
+    description: "Support HSUM mode by using the main user when checking if a number is blocked."
+    bug: "369062239"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+      }
+}
+
+# OWNER=grantmenke TARGET=25Q2
+flag {
+    name: "telecom_app_label_proxy_hsum_aware"
+    is_exported: true
+    namespace: "telecom"
+    description: "Support HSUM mode by ensuring AppLableProxy is multiuser aware."
+    bug: "321817633"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+      }
 }
\ No newline at end of file
diff --git a/flags/telecom_non_critical_security_flags.aconfig b/flags/telecom_non_critical_security_flags.aconfig
index 37929a85e..e492073d5 100644
--- a/flags/telecom_non_critical_security_flags.aconfig
+++ b/flags/telecom_non_critical_security_flags.aconfig
@@ -7,4 +7,15 @@ flag {
   namespace: "telecom"
   description: "When set, Telecom will unregister accounts if the service is not resolvable"
   bug: "281061708"
+}
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "enforce_transactional_exclusivity"
+  namespace: "telecom"
+  description: "When set, ensure that transactional accounts cannot also be call capable"
+  bug: "376936125"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
 }
\ No newline at end of file
diff --git a/flags/telecom_resolve_hidden_dependencies.aconfig b/flags/telecom_resolve_hidden_dependencies.aconfig
index a120b85b6..e5bb1fb3e 100644
--- a/flags/telecom_resolve_hidden_dependencies.aconfig
+++ b/flags/telecom_resolve_hidden_dependencies.aconfig
@@ -16,4 +16,5 @@ flag {
     description: "Fixed read only flag used for setting up BlockedNumbersManager to be retrieved via context"
     bug: "325049252"
     is_fixed_read_only: true
+    is_exported: true
 }
diff --git a/flags/telecom_ringer_flag_declarations.aconfig b/flags/telecom_ringer_flag_declarations.aconfig
index 6517e0f62..f954b09a2 100644
--- a/flags/telecom_ringer_flag_declarations.aconfig
+++ b/flags/telecom_ringer_flag_declarations.aconfig
@@ -15,4 +15,16 @@ flag {
   namespace: "telecom"
   description: "Gates whether to ensure that when a user is in their car, they are able to hear ringing for an incoming call."
   bug: "348708398"
+}
+
+
+# OWNER=tjstuart TARGET=25Q1
+flag {
+  name: "get_ringer_mode_anom_report"
+  namespace: "telecom"
+  description: "getRingerMode & getRingerModeInternal should return the same val when dnd is off"
+  bug: "307389562"
+    metadata {
+      purpose: PURPOSE_BUGFIX
+    }
 }
\ No newline at end of file
diff --git a/flags/telecom_session_flags.aconfig b/flags/telecom_session_flags.aconfig
new file mode 100644
index 000000000..5b8075ce4
--- /dev/null
+++ b/flags/telecom_session_flags.aconfig
@@ -0,0 +1,13 @@
+package: "com.android.server.telecom.flags"
+container: "system"
+
+# OWNER=breadley TARGET=25Q1
+flag {
+  name: "end_session_improvements"
+  namespace: "telecom"
+  description: "Ensure that ending a session doesnt cause a stack overflow"
+  bug: "370349160"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
\ No newline at end of file
diff --git a/proto/pulled_atoms.proto b/proto/pulled_atoms.proto
index 7360b6a0a..6c9af46b5 100644
--- a/proto/pulled_atoms.proto
+++ b/proto/pulled_atoms.proto
@@ -101,13 +101,13 @@ message TelecomApiStats {
  * From frameworks/proto_logging/stats/atoms/telecomm/telecom_extension_atom.proto
  */
 message TelecomErrorStats {
-    // The value should be converted to android.telecom.SubmoduleNameEnum
+    // The value should be converted to android.telecom.SubmoduleEnum
     // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
-    optional int32 submodule_name = 1;
+    optional int32 submodule = 1;
 
-    // The value should be converted to android.telecom.ErrorNameEnum
+    // The value should be converted to android.telecom.ErrorEnum
     // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
-    optional int32 error_name = 2;
+    optional int32 error = 2;
 
     // The number of times this error occurs
     optional int32 count = 3;
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index d2ac13aa7..ba75d0cb5 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -100,7 +100,7 @@
     <string name="notification_channel_background_calls" msgid="7785659903711350506">"Pozivi u pozadini"</string>
     <string name="notification_channel_disconnected_calls" msgid="8228636543997645757">"Prekinuti pozivi"</string>
     <string name="notification_channel_in_call_service_crash" msgid="7313237519166984267">"Padovi aplikacija za telefon"</string>
-    <string name="notification_channel_call_streaming" msgid="5100510699787538991">"Prijenos poziva"</string>
+    <string name="notification_channel_call_streaming" msgid="5100510699787538991">"Prenos poziva"</string>
     <string name="alert_outgoing_call" msgid="5319895109298927431">"Upućivanje ovog poziva će prekinuti poziv: <xliff:g id="OTHER_APP">%1$s</xliff:g>"</string>
     <string name="alert_redirect_outgoing_call_or_not" msgid="665409645789521636">"Odaberite kako želite uputiti ovaj poziv"</string>
     <string name="alert_place_outgoing_call_with_redirection" msgid="5221065030959024121">"Preusmjeri poziv pomoću aplikacije <xliff:g id="OTHER_APP">%1$s</xliff:g>"</string>
@@ -131,7 +131,7 @@
     <string name="callendpoint_name_speaker" msgid="1971760468695323189">"Zvučnik"</string>
     <string name="callendpoint_name_streaming" msgid="2337595450408275576">"Vanjski"</string>
     <string name="callendpoint_name_unknown" msgid="2199074708477193852">"Nepoznato"</string>
-    <string name="call_streaming_notification_body" msgid="502216105683378263">"Prijenos zvuka na drugom uređaju"</string>
+    <string name="call_streaming_notification_body" msgid="502216105683378263">"Prenos zvuka na drugom uređaju"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Prekini vezu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Prebaci ovdje"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index 886ccdfea..da7fef862 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -54,13 +54,13 @@
     <string name="no_vm_number_msg" msgid="1339245731058529388">"ಸಿಮ್‌ ಕಾರ್ಡ್‌ನಲ್ಲಿ ಯಾವುದೇ ಧ್ವನಿಮೇಲ್‌ ಸಂಖ್ಯೆಯನ್ನು ಸಂಗ್ರಹಿಸಿಲ್ಲ."</string>
     <string name="add_vm_number_str" msgid="5179510133063168998">"ಸಂಖ್ಯೆಯನ್ನು ಸೇರಿಸಿ"</string>
     <string name="change_default_dialer_dialog_title" msgid="5861469279421508060">"<xliff:g id="NEW_APP">%s</xliff:g> ಅನ್ನು ನಿಮ್ಮ ಡಿಫಾಲ್ಟ್ ಫೋನ್ ಆ್ಯಪ್ ಆಗಿ ಮಾಡಬೇಕೆ?"</string>
-    <string name="change_default_dialer_dialog_affirmative" msgid="8604665314757739550">"ಡಿಫಾಲ್ಟ್ ಹೊಂದಿಸಿ"</string>
+    <string name="change_default_dialer_dialog_affirmative" msgid="8604665314757739550">"ಡಿಫಾಲ್ಟ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="change_default_dialer_dialog_negative" msgid="8648669840052697821">"ರದ್ದುಮಾಡಿ"</string>
     <string name="change_default_dialer_warning_message" msgid="8461963987376916114">"<xliff:g id="NEW_APP">%s</xliff:g> ಗೆ ನಿಮ್ಮ ಕರೆಗಳ ಎಲ್ಲಾ ಅಂಶಗಳನ್ನು ನಿಯಂತ್ರಿಸಲು ಮತ್ತು ಕರೆಗಳನ್ನು ಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತದೆ. ನೀವು ವಿಶ್ವಾಸವಿರಿಸಿರುವಂತಹ ಆ್ಯಪ್‌ಗಳನ್ನು ಮಾತ್ರ ನಿಮ್ಮ ಡಿಫಾಲ್ಟ್ ಆ್ಯಪ್‌ ಆಗಿ ಹೊಂದಿಸಬೇಕು."</string>
     <string name="change_default_call_screening_dialog_title" msgid="5365787219927262408">"<xliff:g id="NEW_APP">%s</xliff:g> ನಿಮ್ಮ ಡೀಫಾಲ್ಟ್ ಕರೆ ಸ್ಕ್ರೀನಿಂಗ್ ಆ್ಯಪ್‌ ಆಗಿ ಮಾಡಬೇಕೇ?"</string>
     <string name="change_default_call_screening_warning_message_for_disable_old_app" msgid="2039830033533243164">"<xliff:g id="OLD_APP">%s</xliff:g> ಇನ್ನು ಮುಂದೆ ಕರೆಗಳನ್ನು ಸ್ಕ್ರೀನ್‌ ಮಾಡಲು ಸಾಧ್ಯವಾಗುವುದಿಲ್ಲ."</string>
     <string name="change_default_call_screening_warning_message" msgid="9020537562292754269">"<xliff:g id="NEW_APP">%s</xliff:g> ಗೆ ನಿಮ್ಮ ಸಂಪರ್ಕಗಳಲ್ಲಿ ಇಲ್ಲದ ಕರೆದಾರರ ಬಗ್ಗೆ ಮಾಹಿತಿಯನ್ನು ನೋಡಲು ಮತ್ತು ಈ ಕರೆಗಳನ್ನು ಬ್ಲಾಕ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತದೆ. ನೀವು ವಿಶ್ವಾಸವಿರಿಸಿರುವಂತಹ ಆ್ಯಪ್‌ಗಳನ್ನು ಮಾತ್ರ ನಿಮ್ಮ ಡೀಫಾಲ್ಟ್ ಕರೆ ಸ್ಕ್ರೀನಿಂಗ್ ಆ್ಯಪ್‌ ಆಗಿ ಹೊಂದಿಸಬೇಕು."</string>
-    <string name="change_default_call_screening_dialog_affirmative" msgid="7162433828280058647">"ಡೀಫಾಲ್ಟ್ ಹೊಂದಿಸಿ"</string>
+    <string name="change_default_call_screening_dialog_affirmative" msgid="7162433828280058647">"ಡೀಫಾಲ್ಟ್ ಸೆಟ್ ಮಾಡಿ"</string>
     <string name="change_default_call_screening_dialog_negative" msgid="1839266125623106342">"ರದ್ದುಮಾಡಿ"</string>
     <string name="blocked_numbers" msgid="8322134197039865180">"ನಿರ್ಬಂಧಿಸಲಾದ ಸಂಖ್ಯೆಗಳು"</string>
     <string name="blocked_numbers_msg" msgid="2797422132329662697">"ನಿರ್ಬಂಧಿಸಲಾದ ಸಂಖ್ಯೆಗಳಿಂದ ಕರೆಗಳು ಅಥವಾ ಪಠ್ಯ ಸಂದೇಶಗಳನ್ನು ನೀವು ಸ್ವೀಕರಿಸುವುದಿಲ್ಲ."</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index d8fc473bf..4aeceef5d 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -72,7 +72,7 @@
     <string name="block_button" msgid="485080149164258770">"रोक्नुहोस्"</string>
     <string name="non_primary_user" msgid="315564589279622098">"यन्त्रको मालिकले रोकिएका नम्बरहरूलाई हेर्न र व्यवस्थापन गर्न सक्छ।"</string>
     <string name="delete_icon_description" msgid="5335959254954774373">"अनब्लक गर्नुहोस्"</string>
-    <string name="blocked_numbers_butter_bar_title" msgid="582982373755950791">"रोक लगाउने काम अस्थायी रूपमा निष्क्रिय छ"</string>
+    <string name="blocked_numbers_butter_bar_title" msgid="582982373755950791">"रोक लगाउने काम अस्थायी रूपमा अफ छ"</string>
     <string name="blocked_numbers_butter_bar_body" msgid="1261213114919301485">"तपाईँले आपत्‌कालीन नम्बरमा डायल गरेपछि वा टेक्स्ट म्यासेज पठाएपछि आपत्‌कालीन सेवाहरूले तपाईँलाई सम्पर्क गर्न सकून् भन्ने कुरा सुनिश्चित गर्न कलमाथिको अवरोध निष्क्रिय गरिन्छ।"</string>
     <string name="blocked_numbers_butter_bar_button" msgid="2704456308072489793">"अब पुन:-अन गर्नुहोस्"</string>
     <string name="blocked_numbers_number_blocked_message" msgid="4314736791180919167">"<xliff:g id="BLOCKED_NUMBER">%1$s</xliff:g> माथि रोक लगाइयो"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 831f26045..96ee0e800 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -109,7 +109,7 @@
     <string name="phone_settings_call_blocking_txt" msgid="7311523114822507178">"ਕਾਲ ਬਲਾਕ ਕਰਨਾ"</string>
     <string name="phone_settings_number_not_in_contact_txt" msgid="2602249106007265757">"ਨੰਬਰ ਜੋ ਤੁਹਾਡੇ ਸੰਪਰਕਾਂ ਵਿੱਚ ਨਹੀਂ ਹਨ"</string>
     <string name="phone_settings_number_not_in_contact_summary_txt" msgid="963327038085718969">"ਉਹ ਨੰਬਰ ਬਲਾਕ ਕਰੋ ਜੋ ਤੁਹਾਡੇ ਸੰਪਰਕਾਂ ਵਿੱਚ ਨਹੀਂ ਹਨ"</string>
-    <string name="phone_settings_private_num_txt" msgid="6339272760338475619">"ਨਿੱਜੀ"</string>
+    <string name="phone_settings_private_num_txt" msgid="6339272760338475619">"ਪ੍ਰਾਈਵੇਟ"</string>
     <string name="phone_settings_private_num_summary_txt" msgid="6755758240544021037">"ਉਹ ਕਾਲਰ ਬਲਾਕ ਕਰੋ ਜਿਨ੍ਹਾਂ ਦਾ ਨੰਬਰ ਨਹੀਂ ਦਿਖਾਈ ਦਿੰਦਾ ਹੈ"</string>
     <string name="phone_settings_payphone_txt" msgid="5003987966052543965">"ਜਨਤਕ ਫ਼ੋਨ"</string>
     <string name="phone_settings_payphone_summary_txt" msgid="3936631076065563665">"ਜਨਤਕ ਫ਼ੋਨਾਂ ਵਾਲੀਆਂ ਕਾਲਾਂ ਬਲਾਕ ਕਰੋ"</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index 1e8b027fb..e302ea69c 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -50,8 +50,8 @@
     <string name="outgoing_call_not_allowed_no_permission" msgid="8590468836581488679">"Este aplicativo não pode fazer chamadas sem a permissão do smartphone."</string>
     <string name="outgoing_call_error_no_phone_number_supplied" msgid="7665135102566099778">"Para realizar uma chamada, digite um número válido."</string>
     <string name="duplicate_video_call_not_allowed" msgid="5754746140185781159">"No momento, não é possível adicionar a chamada."</string>
-    <string name="no_vm_number" msgid="2179959110602180844">"Número correio de voz ausente"</string>
-    <string name="no_vm_number_msg" msgid="1339245731058529388">"Não há um número correio de voz armazenado no chip."</string>
+    <string name="no_vm_number" msgid="2179959110602180844">"Número do correio de voz ausente"</string>
+    <string name="no_vm_number_msg" msgid="1339245731058529388">"Não há um número do correio de voz armazenado no chip."</string>
     <string name="add_vm_number_str" msgid="5179510133063168998">"Adicionar número"</string>
     <string name="change_default_dialer_dialog_title" msgid="5861469279421508060">"Usar o <xliff:g id="NEW_APP">%s</xliff:g> como seu app de telefone padrão?"</string>
     <string name="change_default_dialer_dialog_affirmative" msgid="8604665314757739550">"Definir padrão"</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 876b0497a..7d8045a8b 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -126,7 +126,7 @@
     <string name="cancel" msgid="6733466216239934756">"Anulo"</string>
     <string name="back" msgid="6915955601805550206">"Pas"</string>
     <string name="callendpoint_name_earpiece" msgid="7047285080319678594">"Receptori"</string>
-    <string name="callendpoint_name_bluetooth" msgid="210210953208913172">"Bluetooth"</string>
+    <string name="callendpoint_name_bluetooth" msgid="210210953208913172">"Bluetooth-i"</string>
     <string name="callendpoint_name_wiredheadset" msgid="6860787176412079742">"Kufje me tel"</string>
     <string name="callendpoint_name_speaker" msgid="1971760468695323189">"Altoparlant"</string>
     <string name="callendpoint_name_streaming" msgid="2337595450408275576">"E jashtme"</string>
diff --git a/src/com/android/server/telecom/AppLabelProxy.java b/src/com/android/server/telecom/AppLabelProxy.java
index 7c00f283c..c4d83dd76 100644
--- a/src/com/android/server/telecom/AppLabelProxy.java
+++ b/src/com/android/server/telecom/AppLabelProxy.java
@@ -16,8 +16,11 @@
 
 package com.android.server.telecom;
 
+import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
+import com.android.server.telecom.flags.FeatureFlags;
+import android.os.UserHandle;
 import android.telecom.Log;
 
 /**
@@ -30,15 +33,34 @@ public interface AppLabelProxy {
     class Util {
         /**
          * Default impl of getAppLabel.
-         * @param pm PackageManager instance
+         * @param context Context instance that is not necessarily associated with the correct user.
+         * @param userHandle UserHandle instance of the user that is associated with the app.
          * @param packageName package name to look up.
          */
-        public static CharSequence getAppLabel(PackageManager pm, String packageName) {
+        public static CharSequence getAppLabel(Context context, UserHandle userHandle,
+                String packageName, FeatureFlags featureFlags) {
             try {
-                ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
-                CharSequence result = pm.getApplicationLabel(info);
-                Log.i(LOG_TAG, "package %s: name is %s", packageName, result);
-                return result;
+                if (featureFlags.telecomAppLabelProxyHsumAware()){
+                    Context userContext = context.createContextAsUser(userHandle, 0 /* flags */);
+                    PackageManager userPackageManager = userContext.getPackageManager();
+                    if (userPackageManager == null) {
+                        Log.w(LOG_TAG, "Could not determine app label since PackageManager is "
+                                + "null. Package name is %s", packageName);
+                        return null;
+                    }
+                    ApplicationInfo info = userPackageManager.getApplicationInfo(packageName, 0);
+                    CharSequence result = userPackageManager.getApplicationLabel(info);
+                    Log.i(LOG_TAG, "package %s: name is %s for user = %s", packageName, result,
+                            userHandle.toString());
+                    return result;
+                } else {
+                    // Legacy code path:
+                    PackageManager pm = context.getPackageManager();
+                    ApplicationInfo info = pm.getApplicationInfo(packageName, 0);
+                    CharSequence result = pm.getApplicationLabel(info);
+                    Log.i(LOG_TAG, "package %s: name is %s", packageName, result);
+                    return result;
+                }
             } catch (PackageManager.NameNotFoundException nnfe) {
                 Log.w(LOG_TAG, "Could not determine app label. Package name is %s", packageName);
             }
@@ -47,5 +69,5 @@ public interface AppLabelProxy {
         }
     }
 
-    CharSequence getAppLabel(String packageName);
+    CharSequence getAppLabel(String packageName, UserHandle userHandle);
 }
diff --git a/src/com/android/server/telecom/AudioRoute.java b/src/com/android/server/telecom/AudioRoute.java
index d469a4364..d3ed77d21 100644
--- a/src/com/android/server/telecom/AudioRoute.java
+++ b/src/com/android/server/telecom/AudioRoute.java
@@ -318,15 +318,16 @@ public class AudioRoute {
     // sending SPEAKER_OFF, or disconnecting SCO).
     void onOrigRouteAsPendingRoute(boolean active, PendingAudioRoute pendingAudioRoute,
             AudioManager audioManager, BluetoothRouteManager bluetoothRouteManager) {
-        Log.i(this, "onOrigRouteAsPendingRoute: active (%b), type (%d)", active, mAudioRouteType);
+        Log.i(this, "onOrigRouteAsPendingRoute: active (%b), type (%s)", active,
+                DEVICE_TYPE_STRINGS.get(mAudioRouteType));
         if (active) {
-            if (mAudioRouteType == TYPE_SPEAKER) {
-                pendingAudioRoute.addMessage(SPEAKER_OFF, null);
-            }
             int result = clearCommunicationDevice(pendingAudioRoute, bluetoothRouteManager,
                     audioManager);
-            // Only send BT_AUDIO_DISCONNECTED for SCO if disconnect was successful.
-            if (mAudioRouteType == TYPE_BLUETOOTH_SCO && result == BluetoothStatusCodes.SUCCESS) {
+            if (mAudioRouteType == TYPE_SPEAKER) {
+                pendingAudioRoute.addMessage(SPEAKER_OFF, null);
+            } else if (mAudioRouteType == TYPE_BLUETOOTH_SCO
+                    && result == BluetoothStatusCodes.SUCCESS) {
+                // Only send BT_AUDIO_DISCONNECTED for SCO if disconnect was successful.
                 pendingAudioRoute.addMessage(BT_AUDIO_DISCONNECTED, mBluetoothAddress);
             }
         }
@@ -407,8 +408,26 @@ public class AudioRoute {
         }
 
         if (result == BluetoothStatusCodes.SUCCESS) {
+            if (pendingAudioRoute.getFeatureFlags().resolveActiveBtRoutingAndBtTimingIssue()) {
+                maybeClearConnectedPendingMessages(pendingAudioRoute);
+            }
             pendingAudioRoute.setCommunicationDeviceType(AudioRoute.TYPE_INVALID);
         }
         return result;
     }
+
+    private void maybeClearConnectedPendingMessages(PendingAudioRoute pendingAudioRoute) {
+        // If we're still waiting on BT_AUDIO_CONNECTED/SPEAKER_ON but have routed out of it
+        // since and disconnected the device, then remove that message so we aren't waiting for
+        // it in the message queue.
+        if (mAudioRouteType == TYPE_BLUETOOTH_SCO) {
+            Log.i(this, "clearCommunicationDevice: Clearing pending "
+                    + "BT_AUDIO_CONNECTED messages.");
+            pendingAudioRoute.clearPendingMessage(
+                    new Pair<>(BT_AUDIO_CONNECTED, mBluetoothAddress));
+        } else if (mAudioRouteType == TYPE_SPEAKER) {
+            Log.i(this, "clearCommunicationDevice: Clearing pending SPEAKER_ON messages.");
+            pendingAudioRoute.clearPendingMessage(new Pair<>(SPEAKER_ON, null));
+        }
+    }
 }
diff --git a/src/com/android/server/telecom/CachedVideoStateChange.java b/src/com/android/server/telecom/CachedVideoStateChange.java
index cefb92bcb..8aa6d402a 100644
--- a/src/com/android/server/telecom/CachedVideoStateChange.java
+++ b/src/com/android/server/telecom/CachedVideoStateChange.java
@@ -16,7 +16,8 @@
 
 package com.android.server.telecom;
 
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToString;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToString;
 
 import android.telecom.Log;
 
diff --git a/src/com/android/server/telecom/Call.java b/src/com/android/server/telecom/Call.java
index c3916414d..df31e02fd 100644
--- a/src/com/android/server/telecom/Call.java
+++ b/src/com/android/server/telecom/Call.java
@@ -21,8 +21,10 @@ import static android.telephony.TelephonyManager.EVENT_DISPLAY_EMERGENCY_MESSAGE
 
 import static com.android.server.telecom.CachedCallback.TYPE_QUEUE;
 import static com.android.server.telecom.CachedCallback.TYPE_STATE;
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToString;
-import static com.android.server.telecom.voip.VideoStateTranslation.VideoProfileStateToTransactionalVideoState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToString;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .VideoProfileStateToTransactionalVideoState;
 
 import android.annotation.NonNull;
 import android.annotation.Nullable;
@@ -78,9 +80,9 @@ import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.stats.CallFailureCause;
 import com.android.server.telecom.stats.CallStateChangedAtomWriter;
 import com.android.server.telecom.ui.ToastFactory;
-import com.android.server.telecom.voip.TransactionManager;
-import com.android.server.telecom.voip.VerifyCallStateChangeTransaction;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.VerifyCallStateChangeTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.io.IOException;
 import java.text.SimpleDateFormat;
@@ -3185,7 +3187,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         tm.addTransaction(new VerifyCallStateChangeTransaction(mCallsManager.getLock(),
                 this, targetCallState), new OutcomeReceiver<>() {
             @Override
-            public void onResult(VoipCallTransactionResult result) {
+            public void onResult(CallTransactionResult result) {
                 Log.i(this, "awaitCallStateChangeAndMaybeDisconnectCall: %s: onResult:"
                         + " due to CallException=[%s]", callingMethod, result);
             }
diff --git a/src/com/android/server/telecom/CallAnomalyWatchdog.java b/src/com/android/server/telecom/CallAnomalyWatchdog.java
index 384110c3e..c331b2975 100644
--- a/src/com/android/server/telecom/CallAnomalyWatchdog.java
+++ b/src/com/android/server/telecom/CallAnomalyWatchdog.java
@@ -153,7 +153,8 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
     public static final UUID WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_UUID =
             UUID.fromString("3fbecd12-059d-4fd3-87b7-6c3079891c23");
     public static final String WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_MSG =
-            "Telecom CallAnomalyWatchdog caught stuck VoIP call in a starting state";
+            "A VoIP call was flagged due to exceeding a one-minute threshold in the DIALING or "
+                    + "RINGING state";
 
 
     @VisibleForTesting
diff --git a/src/com/android/server/telecom/CallAudioManager.java b/src/com/android/server/telecom/CallAudioManager.java
index 8c2f63152..d156c0c07 100644
--- a/src/com/android/server/telecom/CallAudioManager.java
+++ b/src/com/android/server/telecom/CallAudioManager.java
@@ -1101,6 +1101,9 @@ public class CallAudioManager extends CallsManagerListenerBase {
                     call.getId());
             disconnectedToneFuture.complete(null);
         }
+        // Make sure we schedule the unbinding of the BT ICS once the disconnected tone future has
+        // been completed.
+        mCallsManager.getInCallController().maybeScheduleBtUnbind(call);
     }
 
     @VisibleForTesting
diff --git a/src/com/android/server/telecom/CallAudioModeStateMachine.java b/src/com/android/server/telecom/CallAudioModeStateMachine.java
index fb196f2e6..e149bdd9b 100644
--- a/src/com/android/server/telecom/CallAudioModeStateMachine.java
+++ b/src/com/android/server/telecom/CallAudioModeStateMachine.java
@@ -17,7 +17,6 @@
 package com.android.server.telecom;
 
 import android.media.AudioAttributes;
-import android.media.AudioFocusRequest;
 import android.media.AudioManager;
 import android.os.Looper;
 import android.os.Message;
@@ -47,22 +46,6 @@ public class CallAudioModeStateMachine extends StateMachine {
         }
     }
 
-    private static final AudioAttributes RING_AUDIO_ATTRIBUTES = new AudioAttributes.Builder()
-            .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
-            .setLegacyStreamType(AudioManager.STREAM_RING)
-            .build();
-    public static final AudioFocusRequest RING_AUDIO_FOCUS_REQUEST = new AudioFocusRequest
-            .Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
-            .setAudioAttributes(RING_AUDIO_ATTRIBUTES).build();
-
-    private static final AudioAttributes CALL_AUDIO_ATTRIBUTES = new AudioAttributes.Builder()
-            .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
-            .setLegacyStreamType(AudioManager.STREAM_VOICE_CALL)
-            .build();
-    public static final AudioFocusRequest CALL_AUDIO_FOCUS_REQUEST = new AudioFocusRequest
-            .Builder(AudioManager.AUDIOFOCUS_GAIN_TRANSIENT)
-            .setAudioAttributes(CALL_AUDIO_ATTRIBUTES).build();
-
     public static class MessageArgs {
         public boolean hasActiveOrDialingCalls;
         public boolean hasRingingCalls;
@@ -232,8 +215,6 @@ public class CallAudioModeStateMachine extends StateMachine {
     public static final String STREAMING_STATE_NAME = StreamingFocusState.class.getSimpleName();
     public static final String COMMS_STATE_NAME = VoipCallFocusState.class.getSimpleName();
 
-    private AudioFocusRequest mCurrentAudioFocusRequest = null;
-
     private class BaseState extends State {
         @Override
         public boolean processMessage(Message msg) {
@@ -348,18 +329,9 @@ public class CallAudioModeStateMachine extends StateMachine {
                             + args.toString());
                     return HANDLED;
                 case AUDIO_OPERATIONS_COMPLETE:
-                    if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                        if (mCurrentAudioFocusRequest != null) {
-                            Log.i(this, "AudioOperationsComplete: "
-                                    + "AudioManager#abandonAudioFocusRequest(); now unfocused");
-                            mAudioManager.abandonAudioFocusRequest(mCurrentAudioFocusRequest);
-                            mCurrentAudioFocusRequest = null;
-                        } else {
-                            Log.i(this, "AudioOperationsComplete: already unfocused");
-                        }
-                    } else {
-                        mAudioManager.abandonAudioFocusForCall();
-                    }
+                    Log.i(this, "AudioOperationsComplete: "
+                            + "AudioManager#abandonAudioFocusRequest(); now unfocused");
+                    mAudioManager.abandonAudioFocusForCall();
                     // Clear requested communication device after the call ends.
                     if (mFeatureFlags.clearCommunicationDeviceAfterAudioOpsComplete()) {
                         mCommunicationDeviceTracker.clearCommunicationDevice(
@@ -438,14 +410,7 @@ public class CallAudioModeStateMachine extends StateMachine {
                 case AUDIO_OPERATIONS_COMPLETE:
                     Log.i(LOG_TAG, "AudioManager#abandonAudioFocusRequest: now "
                             + "AUDIO_PROCESSING");
-                    if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                        if (mCurrentAudioFocusRequest != null) {
-                            mAudioManager.abandonAudioFocusRequest(mCurrentAudioFocusRequest);
-                            mCurrentAudioFocusRequest = null;
-                        }
-                    } else {
-                        mAudioManager.abandonAudioFocusForCall();
-                    }
+                    mAudioManager.abandonAudioFocusForCall();
                     return HANDLED;
                 default:
                     // The forced focus switch commands are handled by BaseState.
@@ -468,14 +433,10 @@ public class CallAudioModeStateMachine extends StateMachine {
             }
 
             if (mCallAudioManager.startRinging()) {
-                if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                    mCurrentAudioFocusRequest = RING_AUDIO_FOCUS_REQUEST;
-                    Log.i(this, "tryStartRinging: AudioManager#requestAudioFocus(RING)");
-                    mAudioManager.requestAudioFocus(RING_AUDIO_FOCUS_REQUEST);
-                } else {
-                    mAudioManager.requestAudioFocusForCall(
-                            AudioManager.STREAM_RING, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
-                }
+                Log.i(this, "tryStartRinging: AudioManager#requestAudioFocus(RING)");
+                mAudioManager.requestAudioFocusForCall(
+                        AudioManager.STREAM_RING, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
+
                 // Do not set MODE_RINGTONE if we were previously in the CALL_SCREENING mode --
                 // this trips up the audio system.
                 if (mAudioManager.getMode() != AudioManager.MODE_CALL_SCREENING) {
@@ -570,14 +531,9 @@ public class CallAudioModeStateMachine extends StateMachine {
         public void enter() {
             Log.i(LOG_TAG, "Audio focus entering SIM CALL state");
             mLocalLog.log("Enter SIM_CALL");
-            if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
-                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
-                mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
-            } else {
-                mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
-                        AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
-            }
+            Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
+            mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
+                AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             Log.i(this, "enter: AudioManager#setMode(MODE_IN_CALL)");
             mAudioManager.setMode(AudioManager.MODE_IN_CALL);
             mLocalLog.log("Mode MODE_IN_CALL");
@@ -660,14 +616,9 @@ public class CallAudioModeStateMachine extends StateMachine {
         public void enter() {
             Log.i(LOG_TAG, "Audio focus entering VOIP CALL state");
             mLocalLog.log("Enter VOIP_CALL");
-            if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
-                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
-                mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
-            } else {
-                mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
-                        AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
-            }
+            Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
+            mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
+                    AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             Log.i(this, "enter: AudioManager#setMode(MODE_IN_COMMUNICATION)");
             mAudioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);
             mLocalLog.log("Mode MODE_IN_COMMUNICATION");
@@ -823,14 +774,9 @@ public class CallAudioModeStateMachine extends StateMachine {
         public void enter() {
             Log.i(LOG_TAG, "Audio focus entering TONE/HOLDING state");
             mLocalLog.log("Enter TONE/HOLDING");
-            if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
-                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
-                mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
-            } else {
-                mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
-                        AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
-            }
+            Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
+            mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
+                    AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             Log.i(this, "enter: AudioManager#setMode(%d)", mMostRecentMode);
             mAudioManager.setMode(mMostRecentMode);
             mLocalLog.log("Mode " + mMostRecentMode);
diff --git a/src/com/android/server/telecom/CallAudioRouteController.java b/src/com/android/server/telecom/CallAudioRouteController.java
index e27535a8a..6b7bbf0a4 100644
--- a/src/com/android/server/telecom/CallAudioRouteController.java
+++ b/src/com/android/server/telecom/CallAudioRouteController.java
@@ -17,6 +17,7 @@
 package com.android.server.telecom;
 
 import static com.android.server.telecom.AudioRoute.BT_AUDIO_ROUTE_TYPES;
+import static com.android.server.telecom.AudioRoute.DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE;
 import static com.android.server.telecom.AudioRoute.TYPE_INVALID;
 import static com.android.server.telecom.AudioRoute.TYPE_SPEAKER;
 
@@ -52,9 +53,11 @@ import com.android.internal.os.SomeArgs;
 import com.android.internal.util.IndentingPrintWriter;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.ErrorStats;
 import com.android.server.telecom.metrics.TelecomMetricsController;
 
 import java.util.ArrayList;
+import java.util.Collections;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
@@ -62,6 +65,8 @@ import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
+import java.util.concurrent.ExecutorService;
+import java.util.concurrent.Executors;
 
 public class CallAudioRouteController implements CallAudioRouteAdapter {
     private static final AudioRoute DUMMY_ROUTE = new AudioRoute(TYPE_INVALID, null, null);
@@ -106,6 +111,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private PendingAudioRoute mPendingAudioRoute;
     private AudioRoute.Factory mAudioRouteFactory;
     private StatusBarNotifier mStatusBarNotifier;
+    private AudioManager.OnCommunicationDeviceChangedListener mCommunicationDeviceListener;
+    private ExecutorService mCommunicationDeviceChangedExecutor;
     private FeatureFlags mFeatureFlags;
     private int mFocusType;
     private int mCallSupportedRouteMask = -1;
@@ -199,10 +206,12 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         handlerThread.start();
 
         // Register broadcast receivers
-        IntentFilter speakerChangedFilter = new IntentFilter(
-                AudioManager.ACTION_SPEAKERPHONE_STATE_CHANGED);
-        speakerChangedFilter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
-        context.registerReceiver(mSpeakerPhoneChangeReceiver, speakerChangedFilter);
+        if (!mFeatureFlags.newAudioPathSpeakerBroadcastAndUnfocusedRouting()) {
+            IntentFilter speakerChangedFilter = new IntentFilter(
+                    AudioManager.ACTION_SPEAKERPHONE_STATE_CHANGED);
+            speakerChangedFilter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
+            context.registerReceiver(mSpeakerPhoneChangeReceiver, speakerChangedFilter);
+        }
 
         IntentFilter micMuteChangedFilter = new IntentFilter(
                 AudioManager.ACTION_MICROPHONE_MUTE_CHANGED);
@@ -213,6 +222,27 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         muteChangedFilter.setPriority(IntentFilter.SYSTEM_HIGH_PRIORITY);
         context.registerReceiver(mMuteChangeReceiver, muteChangedFilter);
 
+        // Register AudioManager#onCommunicationDeviceChangedListener listener to receive updates
+        // to communication device (via AudioManager#setCommunicationDevice). This is a replacement
+        // to using broadcasts in the hopes of improving performance.
+        mCommunicationDeviceChangedExecutor = Executors.newSingleThreadExecutor();
+        mCommunicationDeviceListener = new AudioManager.OnCommunicationDeviceChangedListener() {
+            @Override
+            public void onCommunicationDeviceChanged(AudioDeviceInfo device) {
+                @AudioRoute.AudioRouteType int audioType = device != null
+                        ? DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(device.getType())
+                        : TYPE_INVALID;
+                Log.i(this, "onCommunicationDeviceChanged: %d", audioType);
+                if (device != null && device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
+                    if (mCurrentRoute.getType() != TYPE_SPEAKER) {
+                        sendMessageWithSessionInfo(SPEAKER_ON);
+                    }
+                } else {
+                    sendMessageWithSessionInfo(SPEAKER_OFF);
+                }
+            }
+        };
+
         // Create handler
         mHandler = new Handler(handlerThread.getLooper()) {
             @Override
@@ -277,12 +307,12 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                             break;
                         case SWITCH_BASELINE_ROUTE:
                             address = (String) ((SomeArgs) msg.obj).arg2;
-                            handleSwitchBaselineRoute(msg.arg1 == INCLUDE_BLUETOOTH_IN_BASELINE,
-                                    address);
+                            handleSwitchBaselineRoute(false,
+                                    msg.arg1 == INCLUDE_BLUETOOTH_IN_BASELINE, address);
                             break;
                         case USER_SWITCH_BASELINE_ROUTE:
-                            handleSwitchBaselineRoute(msg.arg1 == INCLUDE_BLUETOOTH_IN_BASELINE,
-                                    null);
+                            handleSwitchBaselineRoute(true,
+                                    msg.arg1 == INCLUDE_BLUETOOTH_IN_BASELINE, null);
                             break;
                         case SPEAKER_ON:
                             handleSpeakerOn();
@@ -342,7 +372,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     public void initialize() {
         mAvailableRoutes = new HashSet<>();
         mCallSupportedRoutes = new HashSet<>();
-        mBluetoothRoutes = new LinkedHashMap<>();
+        mBluetoothRoutes = Collections.synchronizedMap(new LinkedHashMap<>());
         mActiveDeviceCache = new HashMap<>();
         mActiveDeviceCache.put(AudioRoute.TYPE_BLUETOOTH_SCO, null);
         mActiveDeviceCache.put(AudioRoute.TYPE_BLUETOOTH_HA, null);
@@ -410,6 +440,11 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mIsActive = false;
         mCallAudioState = new CallAudioState(mIsMute, ROUTE_MAP.get(mCurrentRoute.getType()),
                 supportMask, null, new HashSet<>());
+        if (mFeatureFlags.newAudioPathSpeakerBroadcastAndUnfocusedRouting()) {
+            mAudioManager.addOnCommunicationDeviceChangedListener(
+                    mCommunicationDeviceChangedExecutor,
+                    mCommunicationDeviceListener);
+        }
     }
 
     @Override
@@ -512,6 +547,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         if (destRoute == null || (!destRoute.equals(mStreamingRoute)
                 && !getCallSupportedRoutes().contains(destRoute))) {
             Log.i(this, "Ignore routing to unavailable route: %s", destRoute);
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_AUDIO,
+                        ErrorStats.ERROR_AUDIO_ROUTE_UNAVAILABLE);
+            }
             return;
         }
         if (mIsPending) {
@@ -522,7 +561,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                             + "%s(active=%b)",
                     mPendingAudioRoute.getDestRoute(), mIsActive, destRoute, active);
             // Ensure we don't keep waiting for SPEAKER_ON if dest route gets overridden.
-            if (active && mPendingAudioRoute.getDestRoute().getType() == TYPE_SPEAKER) {
+            if (!mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue() && active
+                    && mPendingAudioRoute.getDestRoute().getType() == TYPE_SPEAKER) {
                 mPendingAudioRoute.clearPendingMessage(new Pair<>(SPEAKER_ON, null));
             }
             // override pending route while keep waiting for still pending messages for the
@@ -558,6 +598,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             wiredHeadsetRoute = mAudioRouteFactory.create(AudioRoute.TYPE_WIRED, null,
                     mAudioManager);
         } catch (IllegalArgumentException e) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_AUDIO,
+                        ErrorStats.ERROR_EXTERNAL_EXCEPTION);
+            }
             Log.e(this, e, "Can't find available audio device info for route type:"
                     + AudioRoute.DEVICE_TYPE_STRINGS.get(AudioRoute.TYPE_WIRED));
         }
@@ -597,6 +641,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         try {
             dockRoute = mAudioRouteFactory.create(AudioRoute.TYPE_DOCK, null, mAudioManager);
         } catch (IllegalArgumentException e) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_AUDIO,
+                        ErrorStats.ERROR_EXTERNAL_EXCEPTION);
+            }
             Log.e(this, e, "Can't find available audio device info for route type:"
                     + AudioRoute.DEVICE_TYPE_STRINGS.get(AudioRoute.TYPE_WIRED));
         }
@@ -770,10 +818,30 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      * Message being handled: BT_ACTIVE_DEVICE_GONE
      */
     private void handleBtActiveDeviceGone(@AudioRoute.AudioRouteType int type) {
-        if ((mIsPending && mPendingAudioRoute.getDestRoute().getType() == type)
-                || (!mIsPending && mCurrentRoute.getType() == type)) {
-            // Fallback to an available route
-            routeTo(mIsActive, getBaseRoute(true, null));
+        // Determine what the active device for the BT audio type was so that we can exclude this
+        // device from being used when calculating the base route.
+        String previouslyActiveDeviceAddress = mFeatureFlags
+                .resolveActiveBtRoutingAndBtTimingIssue()
+                ? mActiveDeviceCache.get(type)
+                : null;
+        // It's possible that the dest route hasn't been set yet when the controller is first
+        // initialized.
+        boolean pendingRouteNeedsUpdate = mPendingAudioRoute.getDestRoute() != null
+                && mPendingAudioRoute.getDestRoute().getType() == type;
+        boolean currentRouteNeedsUpdate = mCurrentRoute.getType() == type;
+        if (mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()) {
+            if (pendingRouteNeedsUpdate) {
+                pendingRouteNeedsUpdate = mPendingAudioRoute.getDestRoute().getBluetoothAddress()
+                        .equals(previouslyActiveDeviceAddress);
+            }
+            if (currentRouteNeedsUpdate) {
+                currentRouteNeedsUpdate = mCurrentRoute.getBluetoothAddress()
+                        .equals(previouslyActiveDeviceAddress);
+            }
+        }
+        if ((mIsPending && pendingRouteNeedsUpdate) || (!mIsPending && currentRouteNeedsUpdate)) {
+            // Fallback to an available route excluding the previously active device.
+            routeTo(mIsActive, getBaseRoute(true, previouslyActiveDeviceAddress));
         }
     }
 
@@ -789,6 +857,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                             mCallsManager.getCurrentUserHandle().getIdentifier(),
                             mContext.getAttributionTag());
                 } catch (RemoteException e) {
+                    if (mFeatureFlags.telecomMetricsSupport()) {
+                        mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_AUDIO,
+                                ErrorStats.ERROR_EXTERNAL_EXCEPTION);
+                    }
                     Log.e(this, e, "Remote exception while toggling mute.");
                     return;
                 }
@@ -802,19 +874,22 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mFocusType = focus;
         switch (focus) {
             case NO_FOCUS -> {
-                if (mIsActive) {
-                    // Notify the CallAudioModeStateMachine that audio operations are complete so
-                    // that we can relinquish audio focus.
-                    mCallAudioManager.notifyAudioOperationsComplete();
-
-                    // Reset mute state after call ends.
-                    handleMuteChanged(false);
-                    // Route back to inactive route.
-                    routeTo(false, mCurrentRoute);
-                    // Clear pending messages
-                    mPendingAudioRoute.clearPendingMessages();
-                    clearRingingBluetoothAddress();
-                }
+                // Notify the CallAudioModeStateMachine that audio operations are complete so
+                // that we can relinquish audio focus.
+                mCallAudioManager.notifyAudioOperationsComplete();
+                // Reset mute state after call ends. This should remain unaffected if audio routing
+                // never went active.
+                handleMuteChanged(false);
+                // Ensure we reset call audio state at the end of the call (i.e. if we're on
+                // speaker, route back to earpiece). If we're on BT, remain on BT if it's still
+                // connected.
+                AudioRoute route = mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()
+                        ? calculateBaselineRoute(false, true, null)
+                        : mCurrentRoute;
+                routeTo(false, route);
+                // Clear pending messages
+                mPendingAudioRoute.clearPendingMessages();
+                clearRingingBluetoothAddress();
             }
             case ACTIVE_FOCUS -> {
                 // Route to active baseline route (we may need to change audio route in the case
@@ -903,12 +978,16 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      * @return {@link AudioRoute} of the BT device.
      */
     private AudioRoute getArbitraryBluetoothDevice() {
-        if (mActiveBluetoothDevice != null) {
-            return getBluetoothRoute(mActiveBluetoothDevice.first, mActiveBluetoothDevice.second);
-        } else if (!mBluetoothRoutes.isEmpty()) {
-            return mBluetoothRoutes.keySet().stream().toList().get(mBluetoothRoutes.size() - 1);
+        synchronized (mLock) {
+            if (mActiveBluetoothDevice != null) {
+                return getBluetoothRoute(
+                    mActiveBluetoothDevice.first, mActiveBluetoothDevice.second);
+            } else if (!mBluetoothRoutes.isEmpty()) {
+                return mBluetoothRoutes.keySet().stream().toList()
+                    .get(mBluetoothRoutes.size() - 1);
+            }
+            return null;
         }
-        return null;
     }
 
     private void handleSwitchHeadset() {
@@ -929,8 +1008,42 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
     }
 
-    private void handleSwitchBaselineRoute(boolean includeBluetooth, String btAddressToExclude) {
-        routeTo(mIsActive, calculateBaselineRoute(includeBluetooth, btAddressToExclude));
+    private void handleSwitchBaselineRoute(boolean isExplicitUserRequest, boolean includeBluetooth,
+            String btAddressToExclude) {
+        Log.i(this, "handleSwitchBaselineRoute: includeBluetooth: %b, "
+                + "btAddressToExclude: %s", includeBluetooth, btAddressToExclude);
+        boolean areExcludedBtAndDestBtSame = btAddressToExclude != null
+                && mPendingAudioRoute.getDestRoute() != null
+                && Objects.equals(btAddressToExclude, mPendingAudioRoute.getDestRoute()
+                .getBluetoothAddress());
+        Pair<Integer, String> btDevicePendingMsg =
+                new Pair<>(BT_AUDIO_CONNECTED, btAddressToExclude);
+
+        // If SCO is once again connected or there's a pending message for BT_AUDIO_CONNECTED, then
+        // we know that the device has reconnected or is in the middle of connecting. Ignore routing
+        // out of this BT device.
+        boolean isExcludedDeviceConnectingOrConnected = areExcludedBtAndDestBtSame
+                && (mIsScoAudioConnected || mPendingAudioRoute.getPendingMessages()
+                .contains(btDevicePendingMsg));
+        // Check if the pending audio route or current route is already different from the route
+        // including the BT device that should be excluded from route selection.
+        boolean isCurrentOrDestRouteDifferent = btAddressToExclude != null
+                && ((mIsPending && !btAddressToExclude.equals(mPendingAudioRoute.getDestRoute()
+                .getBluetoothAddress())) || (!mIsPending && !btAddressToExclude.equals(
+                        mCurrentRoute.getBluetoothAddress())));
+        if (mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()) {
+            if (isExcludedDeviceConnectingOrConnected) {
+                Log.i(this, "BT device with address (%s) is currently connecting/connected. "
+                        + "Ignoring route switch.", btAddressToExclude);
+                return;
+            } else if (isCurrentOrDestRouteDifferent) {
+                Log.i(this, "Current or pending audio route isn't routed to device with address "
+                        + "(%s). Ignoring route switch.", btAddressToExclude);
+                return;
+            }
+        }
+        routeTo(mIsActive, calculateBaselineRoute(isExplicitUserRequest, includeBluetooth,
+                btAddressToExclude));
     }
 
     private void handleSpeakerOn() {
@@ -941,7 +1054,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             mStatusBarNotifier.notifySpeakerphone(mCallsManager.hasAnyCalls());
         } else {
             if (mSpeakerDockRoute != null && getCallSupportedRoutes().contains(mSpeakerDockRoute)
-                    && mSpeakerDockRoute.getType() == AudioRoute.TYPE_SPEAKER) {
+                    && mSpeakerDockRoute.getType() == AudioRoute.TYPE_SPEAKER
+                    && mCurrentRoute.getType() != AudioRoute.TYPE_SPEAKER) {
                 routeTo(mIsActive, mSpeakerDockRoute);
                 // Since the route switching triggered by this message, we need to manually send it
                 // again so that we won't stuck in the pending route
@@ -1014,7 +1128,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     BluetoothDevice deviceToAdd = mBluetoothRoutes.get(route);
                     // Only include the lead device for LE audio (otherwise, the routes will show
                     // two separate devices in the UI).
-                    if (route.getType() == AudioRoute.TYPE_BLUETOOTH_LE
+                    if (deviceToAdd != null && route.getType() == AudioRoute.TYPE_BLUETOOTH_LE
                             && getLeAudioService() != null) {
                         int groupId = getLeAudioService().getGroupId(deviceToAdd);
                         if (groupId != BluetoothLeAudio.GROUP_ID_INVALID) {
@@ -1112,7 +1226,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
 
         // Get corresponding audio route
-        @AudioRoute.AudioRouteType int type = AudioRoute.DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(
+        @AudioRoute.AudioRouteType int type = DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(
                 deviceAttr.getType());
         if (BT_AUDIO_ROUTE_TYPES.contains(type)) {
             return getBluetoothRoute(type, deviceAttr.getAddress());
@@ -1140,13 +1254,18 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         return mAudioManager.getPreferredDeviceForStrategy(strategy);
     }
 
-    private AudioRoute getPreferredAudioRouteFromDefault(boolean includeBluetooth,
-            String btAddressToExclude) {
-        boolean skipEarpiece;
+    private AudioRoute getPreferredAudioRouteFromDefault(boolean isExplicitUserRequest,
+            boolean includeBluetooth, String btAddressToExclude) {
+        boolean skipEarpiece = false;
         Call foregroundCall = mCallAudioManager.getForegroundCall();
-        synchronized (mTelecomLock) {
-            skipEarpiece = foregroundCall != null
-                    && VideoProfile.isVideo(foregroundCall.getVideoState());
+        if (!mFeatureFlags.fixUserRequestBaselineRouteVideoCall()) {
+            isExplicitUserRequest = false;
+        }
+        if (!isExplicitUserRequest) {
+            synchronized (mTelecomLock) {
+                skipEarpiece = foregroundCall != null
+                        && VideoProfile.isVideo(foregroundCall.getVideoState());
+            }
         }
         // Route to earpiece, wired, or speaker route if there are not bluetooth routes or if there
         // are only wearables available.
@@ -1246,7 +1365,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         Log.i(this, "getBaseRoute: preferred audio route is %s", destRoute);
         if (destRoute == null || (destRoute.getBluetoothAddress() != null && (!includeBluetooth
                 || destRoute.getBluetoothAddress().equals(btAddressToExclude)))) {
-            destRoute = getPreferredAudioRouteFromDefault(includeBluetooth, btAddressToExclude);
+            destRoute = getPreferredAudioRouteFromDefault(false, includeBluetooth, btAddressToExclude);
         }
         if (destRoute != null && !getCallSupportedRoutes().contains(destRoute)) {
             destRoute = null;
@@ -1255,8 +1374,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         return destRoute;
     }
 
-    private AudioRoute calculateBaselineRoute(boolean includeBluetooth, String btAddressToExclude) {
-        AudioRoute destRoute = getPreferredAudioRouteFromDefault(
+    private AudioRoute calculateBaselineRoute(boolean isExplicitUserRequest,
+            boolean includeBluetooth, String btAddressToExclude) {
+        AudioRoute destRoute = getPreferredAudioRouteFromDefault(isExplicitUserRequest,
                 includeBluetooth, btAddressToExclude);
         if (destRoute != null && !getCallSupportedRoutes().contains(destRoute)) {
             destRoute = null;
@@ -1322,7 +1442,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             return getMostRecentlyActiveBtRoute(btAddressToExclude);
         }
 
-        List<AudioRoute> bluetoothRoutes = mBluetoothRoutes.keySet().stream().toList();
+        List<AudioRoute> bluetoothRoutes = getAvailableBluetoothDevicesForRouting();
         // Traverse the routes from the most recently active recorded devices first.
         AudioRoute nonWatchDeviceRoute = null;
         for (int i = bluetoothRoutes.size() - 1; i >= 0; i--) {
@@ -1334,14 +1454,20 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 continue;
             }
             // Check if the most recently active device is a watch device.
-            if (i == (bluetoothRoutes.size() - 1) && device.equals(mCallAudioState
-                    .getActiveBluetoothDevice()) && mBluetoothRouteManager.isWatch(device)) {
+            boolean isActiveDevice;
+            synchronized (mLock) {
+                isActiveDevice = mActiveBluetoothDevice != null
+                    && device.getAddress().equals(mActiveBluetoothDevice.second);
+            }
+            if (i == (bluetoothRoutes.size() - 1) && mBluetoothRouteManager.isWatch(device)
+                    && (device.equals(mCallAudioState.getActiveBluetoothDevice())
+                    || isActiveDevice)) {
                 Log.i(this, "getActiveWatchOrNonWatchDeviceRoute: Routing to active watch - %s",
                         bluetoothRoutes.get(0));
                 return bluetoothRoutes.get(0);
             }
             // Record the first occurrence of a non-watch device route if found.
-            if (!mBluetoothRouteManager.isWatch(device) && nonWatchDeviceRoute == null) {
+            if (!mBluetoothRouteManager.isWatch(device)) {
                 nonWatchDeviceRoute = route;
                 break;
             }
@@ -1351,6 +1477,22 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         return nonWatchDeviceRoute;
     }
 
+    private List<AudioRoute> getAvailableBluetoothDevicesForRouting() {
+        List<AudioRoute> bluetoothRoutes = new ArrayList<>(mBluetoothRoutes.keySet());
+        if (!mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()) {
+            return bluetoothRoutes;
+        }
+        // Consider the active device (BT_ACTIVE_DEVICE_PRESENT) if it exists first.
+        AudioRoute activeDeviceRoute = getArbitraryBluetoothDevice();
+        if (activeDeviceRoute != null && (bluetoothRoutes.isEmpty()
+                || !bluetoothRoutes.get(bluetoothRoutes.size() - 1).equals(activeDeviceRoute))) {
+            Log.i(this, "getActiveWatchOrNonWatchDeviceRoute: active BT device (%s) present."
+                    + "Considering this device for selection first.", activeDeviceRoute);
+            bluetoothRoutes.add(activeDeviceRoute);
+        }
+        return bluetoothRoutes;
+    }
+
     /**
      * Returns the most actively reported bluetooth route excluding the passed in route.
      */
@@ -1430,22 +1572,32 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      *                           address of the device.
      */
     public void updateActiveBluetoothDevice(Pair<Integer, String> device) {
-        mActiveDeviceCache.put(device.first, device.second);
-        // Update most recently active device if address isn't null (meaning some device is active).
-        if (device.second != null) {
-            mActiveBluetoothDevice = device;
-        } else {
-            // If a device was removed, check to ensure that no other device is still considered
-            // active.
-            boolean hasActiveDevice = false;
-            for (String address : mActiveDeviceCache.values()) {
-                if (address != null) {
-                    hasActiveDevice = true;
-                    break;
+        synchronized (mLock) {
+            mActiveDeviceCache.put(device.first, device.second);
+            // Update most recently active device if address isn't null (meaning
+            // some device is active).
+            if (device.second != null) {
+                mActiveBluetoothDevice = device;
+            } else {
+                // If a device was removed, check to ensure that no other device is
+                //still considered active.
+                boolean hasActiveDevice = false;
+                List<Map.Entry<Integer, String>> activeBtDevices =
+                        new ArrayList<>(mActiveDeviceCache.entrySet());
+                for (Map.Entry<Integer, String> activeDevice : activeBtDevices) {
+                    Integer btAudioType = activeDevice.getKey();
+                    String address = activeDevice.getValue();
+                    if (address != null) {
+                        hasActiveDevice = true;
+                        if (mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()) {
+                            mActiveBluetoothDevice = new Pair<>(btAudioType, address);
+                        }
+                        break;
+                    }
+                }
+                if (!hasActiveDevice) {
+                    mActiveBluetoothDevice = null;
                 }
-            }
-            if (!hasActiveDevice) {
-                mActiveBluetoothDevice = null;
             }
         }
     }
diff --git a/src/com/android/server/telecom/CallStreamingController.java b/src/com/android/server/telecom/CallStreamingController.java
index efd458e86..d14a55367 100644
--- a/src/com/android/server/telecom/CallStreamingController.java
+++ b/src/com/android/server/telecom/CallStreamingController.java
@@ -39,10 +39,10 @@ import android.telecom.StreamingCall;
 import android.telecom.Log;
 
 import com.android.internal.telecom.ICallStreamingService;
-import com.android.server.telecom.voip.ParallelTransaction;
-import com.android.server.telecom.voip.SerialTransaction;
-import com.android.server.telecom.voip.VoipCallTransaction;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
+import com.android.server.telecom.callsequencing.voip.ParallelTransaction;
+import com.android.server.telecom.callsequencing.voip.SerialTransaction;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.ArrayList;
 import java.util.List;
@@ -112,7 +112,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
     }
 
-    public static class QueryCallStreamingTransaction extends VoipCallTransaction {
+    public static class QueryCallStreamingTransaction extends CallTransaction {
         private final CallsManager mCallsManager;
 
         public QueryCallStreamingTransaction(CallsManager callsManager) {
@@ -121,24 +121,24 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
 
         @Override
-        public CompletableFuture<VoipCallTransactionResult> processTransaction(Void v) {
+        public CompletableFuture<CallTransactionResult> processTransaction(Void v) {
             Log.i(this, "processTransaction");
-            CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+            CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
             if (mCallsManager.getCallStreamingController().isStreaming()) {
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         "STREAMING_FAILED_ALREADY_STREAMING"));
             } else {
-                future.complete(new VoipCallTransactionResult(
-                        VoipCallTransactionResult.RESULT_SUCCEED, null));
+                future.complete(new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED, null));
             }
 
             return future;
         }
     }
 
-    public static class AudioInterceptionTransaction extends VoipCallTransaction {
+    public static class AudioInterceptionTransaction extends CallTransaction {
         private Call mCall;
         private boolean mEnterInterception;
 
@@ -150,16 +150,16 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
 
         @Override
-        public CompletableFuture<VoipCallTransactionResult> processTransaction(Void v) {
+        public CompletableFuture<CallTransactionResult> processTransaction(Void v) {
             Log.i(this, "processTransaction");
-            CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+            CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
             if (mEnterInterception) {
                 mCall.startStreaming();
             } else {
                 mCall.stopStreaming();
             }
-            future.complete(new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED,
+            future.complete(new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                     null));
             return future;
         }
@@ -170,7 +170,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         return new StreamingServiceTransaction(context, wrapper, call);
     }
 
-    public class StreamingServiceTransaction extends VoipCallTransaction {
+    public class StreamingServiceTransaction extends CallTransaction {
         public static final String MESSAGE = "STREAMING_FAILED_NO_SENDER";
         private final TransactionalServiceWrapper mWrapper;
         private final Context mContext;
@@ -188,14 +188,14 @@ public class CallStreamingController extends CallsManagerListenerBase {
 
         @SuppressLint("LongLogTag")
         @Override
-        public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+        public CompletionStage<CallTransactionResult> processTransaction(Void v) {
             Log.i(this, "processTransaction");
-            CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+            CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
             RoleManager roleManager = mContext.getSystemService(RoleManager.class);
             PackageManager packageManager = mContext.getPackageManager();
             if (roleManager == null || packageManager == null) {
                 Log.w(this, "processTransaction: Can't find system service");
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         MESSAGE));
                 return future;
@@ -205,7 +205,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
                     RoleManager.ROLE_SYSTEM_CALL_STREAMING, mUserHandle);
             if (holders.isEmpty()) {
                 Log.w(this, "processTransaction: Can't find streaming app");
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         MESSAGE));
                 return future;
@@ -217,7 +217,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
                     PackageManager.GET_META_DATA, mUserHandle);
             if (infos.isEmpty()) {
                 Log.w(this, "processTransaction: Can't find streaming service");
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         MESSAGE));
                 return future;
@@ -229,7 +229,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
                     Manifest.permission.BIND_CALL_STREAMING_SERVICE)) {
                 Log.w(this, "Must require BIND_CALL_STREAMING_SERVICE: " +
                         serviceInfo.packageName);
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         MESSAGE));
                 return future;
@@ -242,7 +242,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
                     | Context.BIND_FOREGROUND_SERVICE
                     | Context.BIND_SCHEDULE_LIKE_TOP_APP, mUserHandle)) {
                 Log.w(this, "Can't bind to streaming service");
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         "STREAMING_FAILED_SENDER_BINDING_ERROR"));
             }
@@ -254,19 +254,19 @@ public class CallStreamingController extends CallsManagerListenerBase {
         return new UnbindStreamingServiceTransaction();
     }
 
-    public class UnbindStreamingServiceTransaction extends VoipCallTransaction {
+    public class UnbindStreamingServiceTransaction extends CallTransaction {
         public UnbindStreamingServiceTransaction() {
             super(mTelecomLock);
         }
 
         @SuppressLint("LongLogTag")
         @Override
-        public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+        public CompletionStage<CallTransactionResult> processTransaction(Void v) {
             Log.i(this, "processTransaction (unbindStreaming");
-            CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+            CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
             resetController();
-            future.complete(new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED,
+            future.complete(new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                     null));
             return future;
         }
@@ -275,7 +275,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
     public class StartStreamingTransaction extends SerialTransaction {
         private Call mCall;
 
-        public StartStreamingTransaction(List<VoipCallTransaction> subTransactions, Call call,
+        public StartStreamingTransaction(List<CallTransaction> subTransactions, Call call,
                 TelecomSystem.SyncRoot lock) {
             super(subTransactions, lock);
             mCall = call;
@@ -287,7 +287,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
     }
 
-    public VoipCallTransaction getStartStreamingTransaction(CallsManager callsManager,
+    public CallTransaction getStartStreamingTransaction(CallsManager callsManager,
             TransactionalServiceWrapper wrapper, Call call, TelecomSystem.SyncRoot lock) {
         // start streaming transaction flow:
         //     1. make sure there's no ongoing streaming call --> bind to EXO
@@ -296,7 +296,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         // If bind to EXO failed, add transaction for stop the streaming
 
         // create list for multiple transactions
-        List<VoipCallTransaction> transactions = new ArrayList<>();
+        List<CallTransaction> transactions = new ArrayList<>();
         transactions.add(new QueryCallStreamingTransaction(callsManager));
         transactions.add(new AudioInterceptionTransaction(call, true, lock));
         transactions.add(getCallStreamingServiceTransaction(
@@ -304,10 +304,10 @@ public class CallStreamingController extends CallsManagerListenerBase {
         return new StartStreamingTransaction(transactions, call, lock);
     }
 
-    public VoipCallTransaction getStopStreamingTransaction(Call call, TelecomSystem.SyncRoot lock) {
+    public CallTransaction getStopStreamingTransaction(Call call, TelecomSystem.SyncRoot lock) {
         // TODO: implement this
         // Stop streaming transaction flow:
-        List<VoipCallTransaction> transactions = new ArrayList<>();
+        List<CallTransaction> transactions = new ArrayList<>();
 
         // 1. unbind to call streaming service
         transactions.add(getUnbindStreamingServiceTransaction());
@@ -352,7 +352,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
                 mTransactionalServiceWrapper.getTransactionManager().addTransaction(transaction,
                         new OutcomeReceiver<>() {
                             @Override
-                            public void onResult(VoipCallTransactionResult result) {
+                            public void onResult(CallTransactionResult result) {
                                 // ignore
                             }
 
@@ -366,7 +366,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
     }
 
-    private class CallStreamingStateChangeTransaction extends VoipCallTransaction {
+    private class CallStreamingStateChangeTransaction extends CallTransaction {
         @StreamingCall.StreamingCallState int mState;
 
         public CallStreamingStateChangeTransaction(@StreamingCall.StreamingCallState int state) {
@@ -375,14 +375,14 @@ public class CallStreamingController extends CallsManagerListenerBase {
         }
 
         @Override
-        public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
-            CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        public CompletionStage<CallTransactionResult> processTransaction(Void v) {
+            CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
             try {
                 mService.onCallStreamingStateChanged(mState);
-                future.complete(new VoipCallTransactionResult(
-                        VoipCallTransactionResult.RESULT_SUCCEED, null));
+                future.complete(new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED, null));
             } catch (RemoteException e) {
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         "Exception when request "
                         + "setting state to streaming app."));
@@ -395,10 +395,10 @@ public class CallStreamingController extends CallsManagerListenerBase {
             ServiceConnection {
         private Call mCall;
         private TransactionalServiceWrapper mWrapper;
-        private CompletableFuture<VoipCallTransactionResult> mFuture;
+        private CompletableFuture<CallTransactionResult> mFuture;
 
         public CallStreamingServiceConnection(Call call, TransactionalServiceWrapper wrapper,
-                CompletableFuture<VoipCallTransactionResult> future) {
+                CompletableFuture<CallTransactionResult> future) {
             mCall = call;
             mWrapper = wrapper;
             mFuture = future;
@@ -409,11 +409,11 @@ public class CallStreamingController extends CallsManagerListenerBase {
             try {
                 Log.i(this, "onServiceConnected: " + name);
                 onConnectedInternal(mCall, mWrapper, service);
-                mFuture.complete(new VoipCallTransactionResult(
-                        VoipCallTransactionResult.RESULT_SUCCEED, null));
+                mFuture.complete(new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED, null));
             } catch (RemoteException e) {
                 resetController();
-                mFuture.complete(new VoipCallTransactionResult(
+                mFuture.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         StreamingServiceTransaction.MESSAGE));
             }
@@ -437,7 +437,7 @@ public class CallStreamingController extends CallsManagerListenerBase {
         private void clearBinding() {
             resetController();
             if (!mFuture.isDone()) {
-                mFuture.complete(new VoipCallTransactionResult(
+                mFuture.complete(new CallTransactionResult(
                         CallException.CODE_ERROR_UNKNOWN /* TODO:: define error b/335703584 */,
                         "STREAMING_FAILED_SENDER_BINDING_ERROR"));
             } else {
diff --git a/src/com/android/server/telecom/CallsManager.java b/src/com/android/server/telecom/CallsManager.java
index 028d8c1c9..22b28b5da 100644
--- a/src/com/android/server/telecom/CallsManager.java
+++ b/src/com/android/server/telecom/CallsManager.java
@@ -131,9 +131,12 @@ import com.android.server.telecom.callfiltering.DndCallFilter;
 import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
 import com.android.server.telecom.callfiltering.IncomingCallFilterGraphProvider;
 import com.android.server.telecom.callredirection.CallRedirectionProcessor;
+import com.android.server.telecom.callsequencing.CallSequencingController;
 import com.android.server.telecom.components.ErrorDialogActivity;
 import com.android.server.telecom.components.TelecomBroadcastReceiver;
+import com.android.server.telecom.callsequencing.CallsManagerCallSequencingAdapter;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.ErrorStats;
 import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.stats.CallFailureCause;
 import com.android.server.telecom.ui.AudioProcessingNotification;
@@ -143,8 +146,8 @@ import com.android.server.telecom.ui.ConfirmCallDialogActivity;
 import com.android.server.telecom.ui.DisconnectedCallNotifier;
 import com.android.server.telecom.ui.IncomingCallNotifier;
 import com.android.server.telecom.ui.ToastFactory;
-import com.android.server.telecom.voip.VoipCallMonitor;
-import com.android.server.telecom.voip.TransactionManager;
+import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import java.util.ArrayList;
 import java.util.Arrays;
@@ -490,6 +493,7 @@ public class CallsManager extends Call.ListenerBase
     private final UserManager mUserManager;
     private final CallStreamingNotification mCallStreamingNotification;
     private final BlockedNumbersManager mBlockedNumbersManager;
+    private final CallsManagerCallSequencingAdapter mCallSequencingAdapter;
     private final FeatureFlags mFeatureFlags;
     private final com.android.internal.telephony.flags.FeatureFlags mTelephonyFeatureFlags;
 
@@ -530,6 +534,8 @@ public class CallsManager extends Call.ListenerBase
     private AnomalyReporterAdapter mAnomalyReporter = new AnomalyReporterAdapterImpl();
 
     private final MmiUtils mMmiUtils = new MmiUtils();
+
+    private TelecomMetricsController mMetricsController;
     /**
      * Listener to PhoneAccountRegistrar events.
      */
@@ -697,7 +703,7 @@ public class CallsManager extends Call.ListenerBase
                 ringtoneFactory, systemVibrator,
                 new Ringer.VibrationEffectProxy(), mInCallController,
                 mContext.getSystemService(NotificationManager.class),
-                accessibilityManagerAdapter, featureFlags);
+                accessibilityManagerAdapter, featureFlags, mAnomalyReporter);
         if (featureFlags.telecomResolveHiddenDependencies()) {
             // This is now deprecated
             mCallRecordingTonePlayer = null;
@@ -733,9 +739,13 @@ public class CallsManager extends Call.ListenerBase
         mCallStreamingNotification = callStreamingNotification;
         mFeatureFlags = featureFlags;
         mTelephonyFeatureFlags = telephonyFlags;
+        mMetricsController = metricsController;
         mBlockedNumbersManager = mFeatureFlags.telecomMainlineBlockedNumbersManager()
                 ? mContext.getSystemService(BlockedNumbersManager.class)
                 : null;
+        mCallSequencingAdapter = new CallsManagerCallSequencingAdapter(this,
+                new CallSequencingController(this, mFeatureFlags.enableCallSequencing()),
+                mFeatureFlags.enableCallSequencing());
 
         if (mFeatureFlags.useImprovedListenerOrder()) {
             mListeners.add(mInCallController);
@@ -929,8 +939,8 @@ public class CallsManager extends Call.ListenerBase
         String defaultDialerPackageName = telecomManager.getDefaultDialerPackage(userHandle);
         String userChosenPackageName = getRoleManagerAdapter().
                 getDefaultCallScreeningApp(userHandle);
-        AppLabelProxy appLabelProxy = packageName -> AppLabelProxy.Util.getAppLabel(
-                mContext.getPackageManager(), packageName);
+        AppLabelProxy appLabelProxy = (packageName, user) -> AppLabelProxy.Util.getAppLabel(
+                mContext, user, packageName, mFeatureFlags);
         ParcelableCallUtils.Converter converter = new ParcelableCallUtils.Converter();
 
         IncomingCallFilterGraph graph = mIncomingCallFilterGraphProvider.createGraph(incomingCall,
@@ -938,7 +948,7 @@ public class CallsManager extends Call.ListenerBase
         DirectToVoicemailFilter voicemailFilter = new DirectToVoicemailFilter(incomingCall,
                 mCallerInfoLookupHelper);
         BlockCheckerFilter blockCheckerFilter = new BlockCheckerFilter(mContext, incomingCall,
-                mCallerInfoLookupHelper, new BlockCheckerAdapter(mFeatureFlags));
+                mCallerInfoLookupHelper, new BlockCheckerAdapter(mFeatureFlags), mFeatureFlags);
         DndCallFilter dndCallFilter = new DndCallFilter(incomingCall, getRinger());
         CallScreeningServiceFilter carrierCallScreeningServiceFilter =
                 new CallScreeningServiceFilter(incomingCall, carrierPackageName,
@@ -2029,10 +2039,18 @@ public class CallsManager extends Call.ListenerBase
                     if (exception != null){
                         Log.e(TAG, exception, "Error retrieving list of potential phone accounts.");
                         if (finalCall.isEmergencyCall()) {
+                            if (mFeatureFlags.telecomMetricsSupport()) {
+                                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                                        ErrorStats.ERROR_RETRIEVING_ACCOUNT_EMERGENCY);
+                            }
                             mAnomalyReporter.reportAnomaly(
                                     EXCEPTION_RETRIEVING_PHONE_ACCOUNTS_EMERGENCY_ERROR_UUID,
                                     EXCEPTION_RETRIEVING_PHONE_ACCOUNTS_EMERGENCY_ERROR_MSG);
                         } else {
+                            if (mFeatureFlags.telecomMetricsSupport()) {
+                                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                                        ErrorStats.ERROR_RETRIEVING_ACCOUNT);
+                            }
                             mAnomalyReporter.reportAnomaly(
                                     EXCEPTION_RETRIEVING_PHONE_ACCOUNTS_ERROR_UUID,
                                     EXCEPTION_RETRIEVING_PHONE_ACCOUNTS_ERROR_MSG);
@@ -2071,21 +2089,18 @@ public class CallsManager extends Call.ListenerBase
 
 
         // This future checks the status of existing calls and attempts to make room for the
-        // outgoing call. The future returned by the inner method will usually be pre-completed --
-        // we only pause here if user interaction is required to disconnect a self-managed call.
-        // It runs after the account handle is set, independently of the phone account suggestion
-        // future.
-        CompletableFuture<Call> makeRoomForCall = setAccountHandle.thenComposeAsync(
+        // outgoing call.
+        CompletableFuture<Boolean> makeRoomForCall = setAccountHandle.thenComposeAsync(
                 potentialPhoneAccounts -> {
                     Log.i(CallsManager.this, "make room for outgoing call stage");
                     if (mMmiUtils.isPotentialInCallMMICode(handle) && !isSelfManaged) {
-                        return CompletableFuture.completedFuture(finalCall);
+                        return CompletableFuture.completedFuture(true);
                     }
                     // If a call is being reused, then it has already passed the
                     // makeRoomForOutgoingCall check once and will fail the second time due to the
                     // call transitioning into the CONNECTING state.
                     if (isReusedCall) {
-                        return CompletableFuture.completedFuture(finalCall);
+                        return CompletableFuture.completedFuture(true);
                     } else {
                         Call reusableCall = reuseOutgoingCall(handle);
                         if (reusableCall != null) {
@@ -2112,48 +2127,75 @@ public class CallsManager extends Call.ListenerBase
                                     finalCall.getTargetPhoneAccount(), finalCall);
                         }
                         finalCall.setStartFailCause(CallFailureCause.IN_EMERGENCY_CALL);
-                        return CompletableFuture.completedFuture(null);
+                        return CompletableFuture.completedFuture(false);
                     }
 
-                    // If we can not supportany more active calls, our options are to move a call
+                    // If we can not support any more active calls, our options are to move a call
                     // to hold, disconnect a call, or cancel this call altogether.
-                    boolean isRoomForCall = finalCall.isEmergencyCall() ?
-                            makeRoomForOutgoingEmergencyCall(finalCall) :
-                            makeRoomForOutgoingCall(finalCall);
-                    if (!isRoomForCall) {
-                        Call foregroundCall = getForegroundCall();
-                        Log.d(CallsManager.this, "No more room for outgoing call %s ", finalCall);
-                        if (foregroundCall.isSelfManaged()) {
-                            // If the ongoing call is a self-managed call, then prompt the user to
-                            // ask if they'd like to disconnect their ongoing call and place the
-                            // outgoing call.
-                            Log.i(CallsManager.this, "Prompting user to disconnect "
-                                    + "self-managed call");
-                            finalCall.setOriginalCallIntent(originalIntent);
-                            CompletableFuture<Call> completionFuture = new CompletableFuture<>();
-                            startCallConfirmation(finalCall, completionFuture);
-                            return completionFuture;
-                        } else {
-                            // If the ongoing call is a managed call, we will prevent the outgoing
-                            // call from dialing.
-                            if (isConference) {
-                                notifyCreateConferenceFailed(finalCall.getTargetPhoneAccount(),
-                                    finalCall);
-                            } else {
-                                notifyCreateConnectionFailed(
-                                        finalCall.getTargetPhoneAccount(), finalCall);
-                            }
+                    CompletableFuture<Boolean> isRoomForCallFuture =
+                            mCallSequencingAdapter.makeRoomForOutgoingCall(
+                                    finalCall.isEmergencyCall(), finalCall);
+                    isRoomForCallFuture.exceptionally((throwable -> {
+                        if (throwable != null) {
+                            Log.w(CallsManager.this,
+                                    "Exception thrown in makeRoomForOutgoing*Call, "
+                                            + "returning false. Ex:" + throwable);
                         }
-                        Log.i(CallsManager.this, "Aborting call since there's no room");
+                        return false;
+                    }));
+                    return isRoomForCallFuture;
+        }, new LoggedHandlerExecutor(outgoingCallHandler, "CM.dSMCP", mLock));
+
+        // The future returned by the inner method will usually be pre-completed --
+        // we only pause here if user interaction is required to disconnect a self-managed call.
+        // It runs after the account handle is set, independently of the phone account suggestion
+        // future.
+        CompletableFuture<Call> makeRoomResultHandler = makeRoomForCall
+                .thenComposeAsync((isRoom) -> {
+                    // If we have an ongoing emergency call, we would have already notified
+                    // connection failure for the new call being placed. Catch this so we don't
+                    // resend it again.
+                    boolean hasOngoingEmergencyCall = !finalCall.isEmergencyCall()
+                            && isInEmergencyCall();
+                    if (isRoom) {
+                        return CompletableFuture.completedFuture(finalCall);
+                    } else if (hasOngoingEmergencyCall) {
                         return CompletableFuture.completedFuture(null);
                     }
-                    return CompletableFuture.completedFuture(finalCall);
-        }, new LoggedHandlerExecutor(outgoingCallHandler, "CM.dSMCP", mLock));
+                    Call foregroundCall = getForegroundCall();
+                    Log.d(CallsManager.this, "No more room for outgoing call %s ",
+                            finalCall);
+                    if (foregroundCall.isSelfManaged()) {
+                        // If the ongoing call is a self-managed call, then prompt the
+                        // user to ask if they'd like to disconnect their ongoing call
+                        // and place the outgoing call.
+                        Log.i(CallsManager.this, "Prompting user to disconnect "
+                                + "self-managed call");
+                        finalCall.setOriginalCallIntent(originalIntent);
+                        CompletableFuture<Call> completionFuture =
+                                new CompletableFuture<>();
+                        startCallConfirmation(finalCall, completionFuture);
+                        return completionFuture;
+                    } else {
+                        // If the ongoing call is a managed call, we will prevent the
+                        // outgoing call from dialing.
+                        if (isConference) {
+                            notifyCreateConferenceFailed(
+                                    finalCall.getTargetPhoneAccount(),
+                                    finalCall);
+                        } else {
+                            notifyCreateConnectionFailed(
+                                    finalCall.getTargetPhoneAccount(), finalCall);
+                        }
+                    }
+                    Log.i(CallsManager.this,  "Aborting call since there's no room");
+                    return CompletableFuture.completedFuture(null);
+                }, new LoggedHandlerExecutor(outgoingCallHandler, "CM.mROC", mLock));
 
         // The outgoing call can be placed, go forward. This future glues together the results of
         // the account suggestion stage and the make room for call stage.
         CompletableFuture<Pair<Call, List<PhoneAccountSuggestion>>> preSelectStage =
-                makeRoomForCall.thenCombine(suggestionFuture, Pair::create);
+                makeRoomResultHandler.thenCombine(suggestionFuture, Pair::create);
         mLatestPreAccountSelectionFuture = preSelectStage;
 
         // This future takes the list of suggested accounts and the call and determines if more
@@ -2194,6 +2236,11 @@ public class CallsManager extends Call.ListenerBase
                                 showErrorMessage(R.string.cant_call_due_to_no_supported_service);
                                 mListeners.forEach(l -> l.onCreateConnectionFailed(callToPlace));
                                 if (callToPlace.isEmergencyCall()) {
+                                    if (mFeatureFlags.telecomMetricsSupport()) {
+                                        mMetricsController.getErrorStats().log(
+                                                ErrorStats.SUB_CALL_MANAGER,
+                                                ErrorStats.ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT);
+                                    }
                                     mAnomalyReporter.reportAnomaly(
                                             EMERGENCY_CALL_ABORTED_NO_PHONE_ACCOUNTS_ERROR_UUID,
                                             EMERGENCY_CALL_ABORTED_NO_PHONE_ACCOUNTS_ERROR_MSG);
@@ -2219,6 +2266,11 @@ public class CallsManager extends Call.ListenerBase
                                         PackageManager.FEATURE_TELEPHONY_SUBSCRIPTION)) {
                                     if (SubscriptionManager.getDefaultVoiceSubscriptionId() !=
                                             SubscriptionManager.INVALID_SUBSCRIPTION_ID) {
+                                        if (mFeatureFlags.telecomMetricsSupport()) {
+                                            mMetricsController.getErrorStats().log(
+                                                    ErrorStats.SUB_CALL_MANAGER,
+                                                    ErrorStats.ERROR_DEFAULT_MO_ACCOUNT_MISMATCH);
+                                        }
                                         mAnomalyReporter.reportAnomaly(
                                                 TELEPHONY_HAS_DEFAULT_BUT_TELECOM_DOES_NOT_UUID,
                                                 TELEPHONY_HAS_DEFAULT_BUT_TELECOM_DOES_NOT_MSG);
@@ -2540,8 +2592,8 @@ public class CallsManager extends Call.ListenerBase
                 theCall,
                 new AppLabelProxy() {
                     @Override
-                    public CharSequence getAppLabel(String packageName) {
-                        return Util.getAppLabel(mContext.getPackageManager(), packageName);
+                    public CharSequence getAppLabel(String packageName, UserHandle userHandle) {
+                        return Util.getAppLabel(mContext, userHandle, packageName, mFeatureFlags);
                     }
                 }).process();
         future.thenApply( v -> {
@@ -3033,6 +3085,10 @@ public class CallsManager extends Call.ListenerBase
                     // If an exceptions is thrown while creating the connection, prompt the user to
                     // generate a bugreport and force disconnect.
                     Log.e(TAG, exception, "Exception thrown while establishing connection.");
+                    if (mFeatureFlags.telecomMetricsSupport()) {
+                        mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                                ErrorStats.ERROR_ESTABLISHING_CONNECTION);
+                    }
                     mAnomalyReporter.reportAnomaly(
                             EXCEPTION_WHILE_ESTABLISHING_CONNECTION_ERROR_UUID,
                             EXCEPTION_WHILE_ESTABLISHING_CONNECTION_ERROR_MSG);
@@ -3076,7 +3132,22 @@ public class CallsManager extends Call.ListenerBase
     public void answerCall(Call call, int videoState) {
         if (!mCalls.contains(call)) {
             Log.i(this, "Request to answer a non-existent call %s", call);
-        } else if (call.isTransactionalCall()) {
+        }
+        mCallSequencingAdapter.answerCall(call, videoState);
+    }
+
+    /**
+     * CS: Hold any existing calls, request focus, and then set the call state to answered state.
+     * <p>
+     * T: Call TransactionalServiceWrapper, which then generates transactions to hold calls
+     * {@link #transactionHoldPotentialActiveCallForNewCall} and then move the active call focus
+     * {@link #requestNewCallFocusAndVerify} and notify the remote VOIP app of the call state
+     * moving to active.
+     * <p>
+     * Note: This is only used when {@link FeatureFlags#enableCallSequencing()} is false.
+     */
+    public void answerCallOld(Call call, int videoState) {
+        if (call.isTransactionalCall()) {
             // InCallAdapter is requesting to answer the given transactioanl call. Must get an ack
             // from the client via a transaction before answering.
             call.answer(videoState);
@@ -3143,7 +3214,7 @@ public class CallsManager extends Call.ListenerBase
         }
 
         CharSequence requestingAppName = AppLabelProxy.Util.getAppLabel(
-                mContext.getPackageManager(), requestingPackageName);
+                mContext, call.getAssociatedUser(), requestingPackageName, mFeatureFlags);
         if (requestingAppName == null) {
             requestingAppName = requestingPackageName;
         }
@@ -3410,10 +3481,10 @@ public class CallsManager extends Call.ListenerBase
     public void holdCall(Call call) {
         if (!mCalls.contains(call)) {
             Log.w(this, "Unknown call (%s) asked to be put on hold", call);
-        } else {
-            Log.d(this, "Putting call on hold: (%s)", call);
-            call.hold();
+            return;
         }
+        Log.d(this, "Putting call on hold: (%s)", call);
+        mCallSequencingAdapter.holdCall(call);
     }
 
     /**
@@ -3425,44 +3496,57 @@ public class CallsManager extends Call.ListenerBase
     public void unholdCall(Call call) {
         if (!mCalls.contains(call)) {
             Log.w(this, "Unknown call (%s) asked to be removed from hold", call);
-        } else {
-            if (getOutgoingCall() != null) {
-                Log.w(this, "There is an outgoing call, so it is unable to unhold this call %s",
-                        call);
-                return;
-            }
-            Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
-            String activeCallId = null;
-            if (activeCall != null && !activeCall.isLocallyDisconnecting()) {
-                activeCallId = activeCall.getId();
-                if (canHold(activeCall)) {
-                    activeCall.hold("Swap to " + call.getId());
-                    Log.addEvent(activeCall, LogUtils.Events.SWAP, "To " + call.getId());
-                    Log.addEvent(call, LogUtils.Events.SWAP, "From " + activeCall.getId());
-                } else {
-                    // This call does not support hold. If it is from a different connection
-                    // service or connection manager, then disconnect it, otherwise invoke
-                    // call.hold() and allow the connection service or connection manager to handle
-                    // the situation.
-                    if (!areFromSameSource(activeCall, call)) {
-                        if (!activeCall.isEmergencyCall()) {
-                            activeCall.disconnect("Swap to " + call.getId());
-                        } else {
-                            Log.w(this, "unholdCall: % is an emergency call, aborting swap to %s",
-                                    activeCall.getId(), call.getId());
-                            // Don't unhold the call as requested; we don't want to drop an
-                            // emergency call.
-                            return;
-                        }
+            return;
+        }
+        if (getOutgoingCall() != null) {
+            Log.w(this, "There is an outgoing call, so it is unable to unhold this call %s",
+                    call);
+            return;
+        }
+        mCallSequencingAdapter.unholdCall(call);
+    }
+
+    /**
+     * Instructs telecom to hold any ongoing active calls and bring this call to the active state.
+     * <p>
+     * Note: This is only used when {@link FeatureFlags#enableCallSequencing()} is false.
+     */
+    public void unholdCallOld(Call call) {
+        Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
+        String activeCallId = null;
+        if (activeCall != null && !activeCall.isLocallyDisconnecting()) {
+            activeCallId = activeCall.getId();
+            if (canHold(activeCall)) {
+                activeCall.hold("Swap to " + call.getId());
+                Log.addEvent(activeCall, LogUtils.Events.SWAP, "To " + call.getId());
+                Log.addEvent(call, LogUtils.Events.SWAP, "From " + activeCall.getId());
+            } else {
+                // This call does not support hold. If it is from a different connection
+                // service or connection manager, then disconnect it, otherwise invoke
+                // call.hold() and allow the connection service or connection manager to handle
+                // the situation.
+                if (!areFromSameSource(activeCall, call)) {
+                    if (!activeCall.isEmergencyCall()) {
+                        activeCall.disconnect("Swap to " + call.getId());
                     } else {
-                        activeCall.hold("Swap to " + call.getId());
+                        Log.w(this, "unholdCall: % is an emergency call, aborting swap to %s",
+                                activeCall.getId(), call.getId());
+                        // Don't unhold the call as requested; we don't want to drop an
+                        // emergency call.
+                        return;
                     }
+                } else {
+                    activeCall.hold("Swap to " + call.getId());
                 }
             }
-            mConnectionSvrFocusMgr.requestFocus(
-                    call,
-                    new RequestCallback(new ActionUnHoldCall(call, activeCallId)));
         }
+        requestActionUnholdCall(call, activeCallId);
+    }
+
+    public void requestActionUnholdCall(Call call, String activeCallId) {
+        mConnectionSvrFocusMgr.requestFocus(
+                call,
+                new RequestCallback(new ActionUnHoldCall(call, activeCallId)));
     }
 
     @Override
@@ -3831,6 +3915,11 @@ public class CallsManager extends Call.ListenerBase
         maybeMoveToSpeakerPhone(call);
     }
 
+    void requestFocusActionAnswerCall(Call call, int videoState) {
+        mConnectionSvrFocusMgr.requestFocus(call, new CallsManager.RequestCallback(
+                new CallsManager.ActionAnswerCall(call, videoState)));
+    }
+
     /**
      * Returns true if the active call is held.
      */
@@ -3972,6 +4061,12 @@ public class CallsManager extends Call.ListenerBase
         return supportsHold(activeCall) && areFromSameSource(activeCall, call);
     }
 
+    /**
+     * CS: Mark a call as active. If the call is self-mangaed, we will also hold any active call
+     * before moving the self-managed call to active.
+     * <p>
+     * Note: Only used when {@link FeatureFlags#enableCallSequencing()} is false.
+     */
     @VisibleForTesting
     public void markCallAsActive(Call call) {
         Log.i(this, "markCallAsActive, isSelfManaged: " + call.isSelfManaged());
@@ -4006,6 +4101,11 @@ public class CallsManager extends Call.ListenerBase
         }
     }
 
+    /**
+     * Mark a call as on hold after the hold operation has already completed.
+     * <p>
+     * Note: only used when {@link FeatureFlags#enableCallSequencing()} is false.
+     */
     public void markCallAsOnHold(Call call) {
         setCallState(call, CallState.ON_HOLD, "on-hold set explicitly");
     }
@@ -4160,6 +4260,10 @@ public class CallsManager extends Call.ListenerBase
                     }, new LoggedHandlerExecutor(mHandler, "CM.pR", mLock))
                     .exceptionally((throwable) -> {
                         Log.e(TAG, throwable, "Error while executing call removal");
+                        if (mFeatureFlags.telecomMetricsSupport()) {
+                            mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                                    ErrorStats.ERROR_REMOVING_CALL);
+                        }
                         mAnomalyReporter.reportAnomaly(CALL_REMOVAL_EXECUTION_ERROR_UUID,
                                 CALL_REMOVAL_EXECUTION_ERROR_MSG);
                         return null;
@@ -4177,12 +4281,24 @@ public class CallsManager extends Call.ListenerBase
     private void doRemoval(Call call) {
         call.maybeCleanupHandover();
         removeCall(call);
+        boolean isLocallyDisconnecting = mLocallyDisconnectingCalls.contains(call);
+        mLocallyDisconnectingCalls.remove(call);
+        mCallSequencingAdapter.unholdCallForRemoval(call, isLocallyDisconnecting);
+    }
+
+    /**
+     * Move the held call to foreground in the event that there is a held call and the disconnected
+     * call was disconnected locally or the held call has no way to auto-unhold because it does not
+     * support hold capability.
+     * <p>
+     * Note: This is only used when {@link FeatureFlags#enableCallSequencing()} is set to false.
+     */
+    public void maybeMoveHeldCallToForeground(Call removedCall, boolean isLocallyDisconnecting) {
         Call foregroundCall = mCallAudioManager.getPossiblyHeldForegroundCall();
-        if (mLocallyDisconnectingCalls.contains(call)) {
-            boolean isDisconnectingChildCall = call.isDisconnectingChildCall();
-            Log.v(this, "performRemoval: isDisconnectingChildCall = "
-                    + isDisconnectingChildCall + "call -> %s", call);
-            mLocallyDisconnectingCalls.remove(call);
+        if (isLocallyDisconnecting) {
+            boolean isDisconnectingChildCall = removedCall.isDisconnectingChildCall();
+            Log.v(this, "maybeMoveHeldCallToForeground: isDisconnectingChildCall = "
+                    + isDisconnectingChildCall + "call -> %s", removedCall);
             // Auto-unhold the foreground call due to a locally disconnected call, except if the
             // call which was disconnected is a member of a conference (don't want to auto
             // un-hold the conference if we remove a member of the conference).
@@ -4191,7 +4307,8 @@ public class CallsManager extends Call.ListenerBase
             // implementations, especially if one is managed and the other is a VoIP CS.
             if (!isDisconnectingChildCall && foregroundCall != null
                     && foregroundCall.getState() == CallState.ON_HOLD
-                    && areFromSameSource(foregroundCall, call)) {
+                    && areFromSameSource(foregroundCall, removedCall)) {
+
                 foregroundCall.unhold();
             }
         } else if (foregroundCall != null &&
@@ -4201,8 +4318,8 @@ public class CallsManager extends Call.ListenerBase
             // The new foreground call is on hold, however the carrier does not display the hold
             // button in the UI.  Therefore, we need to auto unhold the held call since the user
             // has no means of unholding it themselves.
-            Log.i(this, "performRemoval: Auto-unholding held foreground call (call doesn't "
-                    + "support hold)");
+            Log.i(this, "maybeMoveHeldCallToForeground: Auto-unholding held foreground call (call "
+                    + "doesn't support hold)");
             foregroundCall.unhold();
         }
     }
@@ -4309,12 +4426,14 @@ public class CallsManager extends Call.ListenerBase
                         return true;
                     }
                 } else {
+                    Log.addEvent(ringingCall, LogUtils.Events.INFO,
+                            "media btn short press - answer call.");
                     answerCall(ringingCall, VideoProfile.STATE_AUDIO_ONLY);
                     return true;
                 }
             } else if (HeadsetMediaButton.LONG_PRESS == type) {
                 if (ringingCall != null) {
-                    Log.addEvent(getForegroundCall(),
+                    Log.addEvent(ringingCall,
                             LogUtils.Events.INFO, "media btn long press - reject");
                     ringingCall.reject(false, null);
                 } else {
@@ -4335,6 +4454,7 @@ public class CallsManager extends Call.ListenerBase
                 return true;
             }
         }
+        Log.i(this, "onMediaButton: type=%d; no active calls", type);
         return false;
     }
 
@@ -4426,6 +4546,10 @@ public class CallsManager extends Call.ListenerBase
         return getFirstCallWithState(null, states);
     }
 
+    public Call getFirstCallWithLiveState() {
+        return getFirstCallWithState(null, LIVE_CALL_STATES);
+    }
+
     @VisibleForTesting
     public PhoneNumberUtilsAdapter getPhoneNumberUtilsAdapter() {
         return mPhoneNumberUtilsAdapter;
@@ -5007,7 +5131,7 @@ public class CallsManager extends Call.ListenerBase
         return (int) callsStream.count();
     }
 
-    private boolean hasMaximumLiveCalls(Call exceptCall) {
+    public boolean hasMaximumLiveCalls(Call exceptCall) {
         return MAXIMUM_LIVE_CALLS <= getNumCallsWithState(CALL_FILTER_ALL,
                 exceptCall, null /* phoneAccountHandle*/, LIVE_CALL_STATES);
     }
@@ -5151,6 +5275,14 @@ public class CallsManager extends Call.ListenerBase
                 && incomingCall.getHandoverSourceCall() == null;
     }
 
+    /**
+     * Make room for a pending outgoing emergency {@link Call}.
+     * <p>
+     * Note: This method is only applicable when {@link FeatureFlags#enableCallSequencing()}
+     * is false.
+     * @param call The new pending outgoing call.
+     * @return true if room was made, false if no room could be made.
+     */
     @VisibleForTesting
     public boolean makeRoomForOutgoingEmergencyCall(Call emergencyCall) {
         // Always disconnect any ringing/incoming calls when an emergency call is placed to minimize
@@ -5227,6 +5359,10 @@ public class CallsManager extends Call.ListenerBase
 
         // If the live call is stuck in a connecting state, prompt the user to generate a bugreport.
         if (liveCall.getState() == CallState.CONNECTING) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                        ErrorStats.ERROR_STUCK_CONNECTING_EMERGENCY);
+            }
             mAnomalyReporter.reportAnomaly(LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_UUID,
                     LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_MSG);
         }
@@ -5313,6 +5449,14 @@ public class CallsManager extends Call.ListenerBase
         return false;
     }
 
+    /**
+     * Make room for a pending outgoing {@link Call}.
+     * <p>
+     * Note: This method is only applicable when {@link FeatureFlags#enableCallSequencing()}
+     * is false.
+     * @param call The new pending outgoing call.
+     * @return true if room was made, false if no room could be made.
+     */
     @VisibleForTesting
     public boolean makeRoomForOutgoingCall(Call call) {
         // Already room!
@@ -5343,6 +5487,10 @@ public class CallsManager extends Call.ListenerBase
         if (liveCall.getState() == CallState.CONNECTING
                 && ((mClockProxy.elapsedRealtime() - liveCall.getCreationElapsedRealtimeMillis())
                 > mTimeoutsAdapter.getNonVoipCallTransitoryStateTimeoutMillis())) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                        ErrorStats.ERROR_STUCK_CONNECTING);
+            }
             mAnomalyReporter.reportAnomaly(LIVE_CALL_STUCK_CONNECTING_ERROR_UUID,
                     LIVE_CALL_STUCK_CONNECTING_ERROR_MSG);
             liveCall.disconnect("Force disconnect CONNECTING call.");
@@ -6472,7 +6620,7 @@ public class CallsManager extends Call.ListenerBase
                 call.can(Connection.CAPABILITY_HOLD)) && call.getState() != CallState.DIALING;
     }
 
-    private boolean supportsHold(Call call) {
+    public boolean supportsHold(Call call) {
         return call.can(Connection.CAPABILITY_SUPPORT_HOLD);
     }
 
diff --git a/src/com/android/server/telecom/ConnectionServiceWrapper.java b/src/com/android/server/telecom/ConnectionServiceWrapper.java
index 14c8f6278..260c2383f 100644
--- a/src/com/android/server/telecom/ConnectionServiceWrapper.java
+++ b/src/com/android/server/telecom/ConnectionServiceWrapper.java
@@ -130,11 +130,7 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                 synchronized (mLock) {
                     logIncoming("handleCreateConnectionComplete %s", callId);
                     Call call = mCallIdMapper.getCall(callId);
-                    if (call != null && mScheduledFutureMap.containsKey(call)) {
-                        ScheduledFuture<?> existingTimeout = mScheduledFutureMap.get(call);
-                        existingTimeout.cancel(false /* cancelIfRunning */);
-                        mScheduledFutureMap.remove(call);
-                    }
+                    maybeRemoveCleanupFuture(call);
                     // Check status hints image for cross user access
                     if (connection.getStatusHints() != null) {
                         Icon icon = connection.getStatusHints().getIcon();
@@ -174,11 +170,7 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                 synchronized (mLock) {
                     logIncoming("handleCreateConferenceComplete %s", callId);
                     Call call = mCallIdMapper.getCall(callId);
-                    if (call != null && mScheduledFutureMap.containsKey(call)) {
-                        ScheduledFuture<?> existingTimeout = mScheduledFutureMap.get(call);
-                        existingTimeout.cancel(false /* cancelIfRunning */);
-                        mScheduledFutureMap.remove(call);
-                    }
+                    maybeRemoveCleanupFuture(call);
                     // Check status hints image for cross user access
                     if (conference.getStatusHints() != null) {
                         Icon icon = conference.getStatusHints().getIcon();
@@ -1678,6 +1670,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                             Log.getExternalSession(TELECOM_ABBREVIATION));
                 } catch (RemoteException e) {
                     Log.e(this, e, "Failure to createConference -- %s", getComponentName());
+                    if (mFlags.dontTimeoutDestroyedCalls()) {
+                        maybeRemoveCleanupFuture(call);
+                    }
                     mPendingResponses.remove(callId).handleCreateConferenceFailure(
                             new DisconnectCause(DisconnectCause.ERROR, e.toString()));
                 }
@@ -1708,6 +1703,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                     Log.i(ConnectionServiceWrapper.this, "Call not present"
                             + " in call id mapper, maybe it was aborted before the bind"
                             + " completed successfully?");
+                    if (mFlags.dontTimeoutDestroyedCalls()) {
+                        maybeRemoveCleanupFuture(call);
+                    }
                     response.handleCreateConnectionFailure(
                             new DisconnectCause(DisconnectCause.CANCELED));
                     return;
@@ -1793,6 +1791,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                 mScheduledFutureMap.put(call, future);
                 try {
                     if (mFlags.cswServiceInterfaceIsNull() && mServiceInterface == null) {
+                        if (mFlags.dontTimeoutDestroyedCalls()) {
+                            maybeRemoveCleanupFuture(call);
+                        }
                         mPendingResponses.remove(callId).handleCreateConnectionFailure(
                                 new DisconnectCause(DisconnectCause.ERROR,
                                         "CSW#oCC ServiceInterface is null"));
@@ -1807,6 +1808,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                     }
                 } catch (RemoteException e) {
                     Log.e(this, e, "Failure to createConnection -- %s", getComponentName());
+                    if (mFlags.dontTimeoutDestroyedCalls()) {
+                        maybeRemoveCleanupFuture(call);
+                    }
                     mPendingResponses.remove(callId).handleCreateConnectionFailure(
                             new DisconnectCause(DisconnectCause.ERROR, e.toString()));
                 }
@@ -2286,6 +2290,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         if (response != null) {
             response.handleCreateConnectionFailure(disconnectCause);
         }
+        if (mFlags.dontTimeoutDestroyedCalls()) {
+            maybeRemoveCleanupFuture(mCallIdMapper.getCall(callId));
+        }
 
         mCallIdMapper.removeCall(callId);
     }
@@ -2295,6 +2302,9 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         if (response != null) {
             response.handleCreateConnectionFailure(disconnectCause);
         }
+        if (mFlags.dontTimeoutDestroyedCalls()) {
+            maybeRemoveCleanupFuture(call);
+        }
 
         mCallIdMapper.removeCall(call);
     }
@@ -2754,4 +2764,20 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
     public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter){
         mAnomalyReporter = mAnomalyReporterAdapter;
     }
+
+    /**
+     * Given a call, unschedule and cancel the cleanup future.
+     * @param call the call.
+     */
+    private void maybeRemoveCleanupFuture(Call call) {
+        if (call == null) {
+            return;
+        }
+        ScheduledFuture<?> future = mScheduledFutureMap.remove(call);
+        if (future == null) {
+            return;
+        }
+        future.cancel(false /* interrupt */);
+
+    }
 }
diff --git a/src/com/android/server/telecom/DefaultDialerCache.java b/src/com/android/server/telecom/DefaultDialerCache.java
index 44b426a53..98289ede9 100644
--- a/src/com/android/server/telecom/DefaultDialerCache.java
+++ b/src/com/android/server/telecom/DefaultDialerCache.java
@@ -31,76 +31,58 @@ import android.os.UserHandle;
 import android.provider.Settings;
 import android.telecom.DefaultDialerManager;
 import android.telecom.Log;
-import android.util.SparseArray;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.IndentingPrintWriter;
 
 import java.util.Objects;
+import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.Executor;
 import java.util.function.IntConsumer;
 
 public class DefaultDialerCache {
-    public interface DefaultDialerManagerAdapter {
-        String getDefaultDialerApplication(Context context);
-        String getDefaultDialerApplication(Context context, int userId);
-        boolean setDefaultDialerApplication(Context context, String packageName, int userId);
-    }
-
-    static class DefaultDialerManagerAdapterImpl implements DefaultDialerManagerAdapter {
-        @Override
-        public String getDefaultDialerApplication(Context context) {
-            return DefaultDialerManager.getDefaultDialerApplication(context);
-        }
-
-        @Override
-        public String getDefaultDialerApplication(Context context, int userId) {
-            return DefaultDialerManager.getDefaultDialerApplication(context, userId);
-        }
-
-        @Override
-        public boolean setDefaultDialerApplication(Context context, String packageName,
-                int userId) {
-            return DefaultDialerManager.setDefaultDialerApplication(context, packageName, userId);
-        }
-    }
-
     private static final String LOG_TAG = "DefaultDialerCache";
+    @VisibleForTesting
+    public final Handler mHandler = new Handler(Looper.getMainLooper());
+    private final Context mContext;
+    private final DefaultDialerManagerAdapter mDefaultDialerManagerAdapter;
+    private final ComponentName mSystemDialerComponentName;
+    private final RoleManagerAdapter mRoleManagerAdapter;
+    private final ConcurrentHashMap<Integer, String> mCurrentDefaultDialerPerUser =
+            new ConcurrentHashMap<>();
     private final BroadcastReceiver mReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
-            Log.startSession("DDC.oR");
-            try {
-                String packageName;
-                if (Intent.ACTION_PACKAGE_CHANGED.equals(intent.getAction())) {
-                    packageName = null;
-                } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())
-                        && !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
-                    packageName = intent.getData().getSchemeSpecificPart();
-                } else if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
-                    packageName = null;
-                } else if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
-                    packageName = null;
-                } else {
-                    return;
-                }
+            mHandler.post(() -> {
+                Log.startSession("DDC.oR");
+                try {
+                    String packageName;
+                    if (Intent.ACTION_PACKAGE_CHANGED.equals(intent.getAction())) {
+                        packageName = null;
+                    } else if (Intent.ACTION_PACKAGE_REMOVED.equals(intent.getAction())
+                            && !intent.getBooleanExtra(Intent.EXTRA_REPLACING, false)) {
+                        packageName = intent.getData().getSchemeSpecificPart();
+                    } else if (Intent.ACTION_PACKAGE_ADDED.equals(intent.getAction())) {
+                        packageName = null;
+                    } else if (Intent.ACTION_BOOT_COMPLETED.equals(intent.getAction())) {
+                        packageName = null;
+                    } else {
+                        return;
+                    }
 
-                synchronized (mLock) {
                     refreshCachesForUsersWithPackage(packageName);
+                } finally {
+                    Log.endSession();
                 }
-
-            } finally {
-                Log.endSession();
-            }
+            });
         }
     };
-
     private final BroadcastReceiver mUserRemovedReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
             if (Intent.ACTION_USER_REMOVED.equals(intent.getAction())) {
                 int removedUser = intent.getIntExtra(Intent.EXTRA_USER_HANDLE,
-                    UserHandle.USER_NULL);
+                        UserHandle.USER_NULL);
                 if (removedUser == UserHandle.USER_NULL) {
                     Log.w(LOG_TAG, "Expected EXTRA_USER_HANDLE with ACTION_USER_REMOVED");
                 } else {
@@ -110,8 +92,6 @@ public class DefaultDialerCache {
             }
         }
     };
-
-    private final Handler mHandler = new Handler(Looper.getMainLooper());
     private final ContentObserver mDefaultDialerObserver = new ContentObserver(mHandler) {
         @Override
         public void onChange(boolean selfChange) {
@@ -119,9 +99,7 @@ public class DefaultDialerCache {
             try {
                 // We don't get the user ID of the user that changed here, so we'll have to
                 // refresh all of the users.
-                synchronized (mLock) {
-                    refreshCachesForUsersWithPackage(null);
-                }
+                refreshCachesForUsersWithPackage(null);
             } finally {
                 Log.endSession();
             }
@@ -132,29 +110,21 @@ public class DefaultDialerCache {
             return true;
         }
     };
-
-    private final Context mContext;
-    private final DefaultDialerManagerAdapter mDefaultDialerManagerAdapter;
-    private final TelecomSystem.SyncRoot mLock;
-    private final ComponentName mSystemDialerComponentName;
-    private final RoleManagerAdapter mRoleManagerAdapter;
-    private SparseArray<String> mCurrentDefaultDialerPerUser = new SparseArray<>();
     private ComponentName mOverrideSystemDialerComponentName;
 
     public DefaultDialerCache(Context context,
-                              DefaultDialerManagerAdapter defaultDialerManagerAdapter,
-                              RoleManagerAdapter roleManagerAdapter,
-                              TelecomSystem.SyncRoot lock) {
+            DefaultDialerManagerAdapter defaultDialerManagerAdapter,
+            RoleManagerAdapter roleManagerAdapter,
+            TelecomSystem.SyncRoot lock) {
         mContext = context;
         mDefaultDialerManagerAdapter = defaultDialerManagerAdapter;
         mRoleManagerAdapter = roleManagerAdapter;
-        mLock = lock;
+
         Resources resources = mContext.getResources();
         mSystemDialerComponentName = new ComponentName(resources.getString(
                 com.android.internal.R.string.config_defaultDialer),
                 resources.getString(R.string.incall_default_class));
 
-
         IntentFilter packageIntentFilter = new IntentFilter();
         packageIntentFilter.addAction(Intent.ACTION_PACKAGE_CHANGED);
         packageIntentFilter.addAction(Intent.ACTION_PACKAGE_REMOVED);
@@ -195,7 +165,7 @@ public class DefaultDialerCache {
         //
         //synchronized (mLock) {
         //    String defaultDialer = mCurrentDefaultDialerPerUser.get(userId);
-        //    if (defaultDialer != null) {
+        //    if (!TextUtils.isEmpty(defaultDialer)) {
         //        return defaultDialer;
         //    }
         //}
@@ -241,11 +211,9 @@ public class DefaultDialerCache {
     public boolean setDefaultDialer(String packageName, int userId) {
         boolean isChanged = mDefaultDialerManagerAdapter.setDefaultDialerApplication(
                 mContext, packageName, userId);
-        if(isChanged) {
-            synchronized (mLock) {
-                // Update the cache synchronously so that there is no delay in cache update.
-                mCurrentDefaultDialerPerUser.put(userId, packageName);
-            }
+        if (isChanged) {
+            // Update the cache synchronously so that there is no delay in cache update.
+            mCurrentDefaultDialerPerUser.put(userId, packageName == null ? "" : packageName);
         }
         return isChanged;
     }
@@ -253,47 +221,39 @@ public class DefaultDialerCache {
     private String refreshCacheForUser(int userId) {
         String currentDefaultDialer =
                 mRoleManagerAdapter.getDefaultDialerApp(userId);
-        synchronized (mLock) {
-            mCurrentDefaultDialerPerUser.put(userId, currentDefaultDialer);
-        }
+        mCurrentDefaultDialerPerUser.put(userId, currentDefaultDialer == null ? "" :
+                currentDefaultDialer);
         return currentDefaultDialer;
     }
 
     /**
      * Refreshes the cache for users that currently have packageName as their cached default dialer.
      * If packageName is null, refresh all caches.
+     *
      * @param packageName Name of the affected package.
      */
     private void refreshCachesForUsersWithPackage(String packageName) {
-        for (int i = 0; i < mCurrentDefaultDialerPerUser.size(); i++) {
-            int userId = mCurrentDefaultDialerPerUser.keyAt(i);
-            if (packageName == null ||
-                    Objects.equals(packageName, mCurrentDefaultDialerPerUser.get(userId))) {
+        mCurrentDefaultDialerPerUser.forEach((userId, currentName) -> {
+            if (packageName == null || Objects.equals(packageName, currentName)) {
                 String newDefaultDialer = refreshCacheForUser(userId);
                 Log.v(LOG_TAG, "Refreshing default dialer for user %d: now %s",
                         userId, newDefaultDialer);
             }
-        }
+        });
     }
 
     public void dumpCache(IndentingPrintWriter pw) {
-        synchronized (mLock) {
-            for (int i = 0; i < mCurrentDefaultDialerPerUser.size(); i++) {
-                pw.printf("User %d: %s\n", mCurrentDefaultDialerPerUser.keyAt(i),
-                        mCurrentDefaultDialerPerUser.valueAt(i));
-            }
-        }
+        mCurrentDefaultDialerPerUser.forEach((k, v) -> pw.printf("User %d: %s\n", k, v));
     }
 
     private void removeUserFromCache(int userId) {
-        synchronized (mLock) {
-            mCurrentDefaultDialerPerUser.remove(userId);
-        }
+        mCurrentDefaultDialerPerUser.remove(userId);
     }
 
     /**
      * registerContentObserver is really hard to mock out, so here is a getter method for the
      * content observer for testing instead.
+     *
      * @return The content observer
      */
     @VisibleForTesting
@@ -304,4 +264,30 @@ public class DefaultDialerCache {
     public RoleManagerAdapter getRoleManagerAdapter() {
         return mRoleManagerAdapter;
     }
-}
\ No newline at end of file
+
+    public interface DefaultDialerManagerAdapter {
+        String getDefaultDialerApplication(Context context);
+
+        String getDefaultDialerApplication(Context context, int userId);
+
+        boolean setDefaultDialerApplication(Context context, String packageName, int userId);
+    }
+
+    static class DefaultDialerManagerAdapterImpl implements DefaultDialerManagerAdapter {
+        @Override
+        public String getDefaultDialerApplication(Context context) {
+            return DefaultDialerManager.getDefaultDialerApplication(context);
+        }
+
+        @Override
+        public String getDefaultDialerApplication(Context context, int userId) {
+            return DefaultDialerManager.getDefaultDialerApplication(context, userId);
+        }
+
+        @Override
+        public boolean setDefaultDialerApplication(Context context, String packageName,
+                int userId) {
+            return DefaultDialerManager.setDefaultDialerApplication(context, packageName, userId);
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/HeadsetMediaButton.java b/src/com/android/server/telecom/HeadsetMediaButton.java
index 7458f546b..afc82aebd 100644
--- a/src/com/android/server/telecom/HeadsetMediaButton.java
+++ b/src/com/android/server/telecom/HeadsetMediaButton.java
@@ -103,7 +103,7 @@ public class HeadsetMediaButton extends CallsManagerListenerBase {
                 if ((event != null) && ((event.getKeyCode() == KeyEvent.KEYCODE_HEADSETHOOK) ||
                         (event.getKeyCode() == KeyEvent.KEYCODE_MEDIA_PLAY_PAUSE))) {
                     synchronized (mLock) {
-                        Log.v(this, "SessionCallback: HEADSETHOOK/MEDIA_PLAY_PAUSE");
+                        Log.i(this, "onMediaButton: event=%s", event);
                         boolean consumed = handleCallMediaButton(event);
                         Log.v(this, "==> handleCallMediaButton(): consumed = %b.", consumed);
                         return consumed;
diff --git a/src/com/android/server/telecom/InCallController.java b/src/com/android/server/telecom/InCallController.java
index 529bc79f1..3f8f57995 100644
--- a/src/com/android/server/telecom/InCallController.java
+++ b/src/com/android/server/telecom/InCallController.java
@@ -305,7 +305,7 @@ public class InCallController extends CallsManagerListenerBase implements
 
         //this is really used for cases where the userhandle for a call
         //does not match what we want to use for bindAsUser
-        private final UserHandle mUserHandleToUseForBinding;
+        private UserHandle mUserHandleToUseForBinding;
 
         public InCallServiceBindingConnection(InCallServiceInfo info) {
             mInCallServiceInfo = info;
@@ -388,6 +388,8 @@ public class InCallController extends CallsManagerListenerBase implements
                                     + "INTERACT_ACROSS_USERS permission");
                 }
             }
+            // Used for referencing what user we used to bind to the given ICS.
+            mUserHandleToUseForBinding = userToBind;
             Log.i(this, "using user id: %s for binding. User from Call is: %s", userToBind,
                     userFromCall);
             if (!mContext.bindServiceAsUser(intent, mServiceConnection,
@@ -1230,7 +1232,7 @@ public class InCallController extends CallsManagerListenerBase implements
             mCombinedInCallServiceMap = new ArrayMap<>();
 
     private final CallIdMapper mCallIdMapper = new CallIdMapper(Call::getId);
-    private final Collection<Call> mPendingEndToneCall = new ArraySet<>();
+    private final Collection<Call> mBtIcsCallTracker = new ArraySet<>();
 
     private final Context mContext;
     private final AppOpsManager mAppOpsManager;
@@ -1246,7 +1248,7 @@ public class InCallController extends CallsManagerListenerBase implements
             mInCallServiceConnections = new ArrayMap<>();
     private final Map<UserHandle, NonUIInCallServiceConnectionCollection>
             mNonUIInCallServiceConnections = new ArrayMap<>();
-    private final Map<UserHandle, InCallServiceConnection> mBTInCallServiceConnections =
+    private final Map<UserHandle, InCallServiceBindingConnection> mBTInCallServiceConnections =
             new ArrayMap<>();
     private final ClockProxy mClockProxy;
     private final IBinder mToken = new Binder();
@@ -1421,6 +1423,7 @@ public class InCallController extends CallsManagerListenerBase implements
                 bindingToBtRequired = true;
                 bindToBTService(call, null);
             }
+
             if (!isBoundAndConnectedToServices(userFromCall)) {
                 Log.i(this, "onCallAdded: %s; not bound or connected to other ICS.", call);
                 // We are not bound, or we're not connected.
@@ -1565,36 +1568,82 @@ public class InCallController extends CallsManagerListenerBase implements
                                 + "disconnected tone future");
                         mDisconnectedToneBtFutures.get(call.getId()).complete(null);
                     }
-                    mPendingEndToneCall.remove(call);
-                    if (!mPendingEndToneCall.isEmpty()) {
-                        return;
-                    }
-                    UserHandle userHandle = getUserFromCall(call);
-                    if (mBTInCallServiceConnections.containsKey(userHandle)) {
-                        Log.i(this, "onDisconnectedTonePlaying: Schedule unbind BT service");
-                        final InCallServiceConnection connection =
-                                mBTInCallServiceConnections.get(userHandle);
-
-                        // Similar to in onCallRemoved when we unbind from the other ICS, we need to
-                        // delay unbinding from the BT ICS because we need to give the ICS a
-                        // moment to finish the onCallRemoved signal it got just prior.
-                        mHandler.postDelayed(new Runnable("ICC.oDCTP", mLock) {
-                            @Override
-                            public void loggedRun() {
-                                Log.i(this, "onDisconnectedTonePlaying: unbinding");
-                                connection.disconnect();
-                            }
-                        }.prepare(), mTimeoutsAdapter.getCallRemoveUnbindInCallServicesDelay(
-                                mContext.getContentResolver()));
+                    // Schedule unbinding of BT ICS.
+                    maybeScheduleBtUnbind(call);
+                }
+            }
+        }
+    }
 
-                        mBTInCallServiceConnections.remove(userHandle);
-                    }
-                    // Ensure that BT ICS instance is cleaned up
-                    if (mBTInCallServices.remove(userHandle) != null) {
-                        updateCombinedInCallServiceMap(userHandle);
+    public void maybeScheduleBtUnbind(Call call) {
+        mBtIcsCallTracker.remove(call);
+        // Track the current calls that are being tracked by the BT ICS and determine the
+        // associated users of those calls as well as the users which have been used to bind to the
+        // ICS.
+        Set<UserHandle> usersFromOngoingCalls = new ArraySet<>();
+        Set<UserHandle> usersCurrentlyBound = new ArraySet<>();
+        for (Call pendingCall : mBtIcsCallTracker) {
+            UserHandle userFromPendingCall = getUserFromCall(pendingCall);
+            final InCallServiceBindingConnection pendingCallConnection =
+                    mBTInCallServiceConnections.get(userFromPendingCall);
+            usersFromOngoingCalls.add(userFromPendingCall);
+            if (pendingCallConnection != null) {
+                usersCurrentlyBound.add(pendingCallConnection.mUserHandleToUseForBinding);
+            }
+        }
+
+        UserHandle userHandle = getUserFromCall(call);
+        // Refrain from unbinding ICS and clearing the ICS mapping if there's an ongoing call under
+        // the same associated user. Make sure we keep the internal mappings so that they aren't
+        // cleared until that call is disconnected. Note here that if the associated users are the
+        // same, the user used for the binding will also be the same.
+        if (usersFromOngoingCalls.contains(userHandle)) {
+            Log.i(this, "scheduleBtUnbind: Refraining from unbinding BT service due to an ongoing "
+                    + "call detected under the same user (%s).", userHandle);
+            return;
+        }
+
+        if (mBTInCallServiceConnections.containsKey(userHandle)) {
+            Log.i(this, "scheduleBtUnbind: Schedule unbind BT service");
+            final InCallServiceBindingConnection connection =
+                    mBTInCallServiceConnections.get(userHandle);
+            // The user that was used for binding may be different than the user from call
+            // (associated user), which is what we use to reference the BT ICS bindings. For
+            // example, consider the work profile scenario where the BT ICS is only available under
+            // User 0: in this case, the user to bind to will be User 0 whereas we store the
+            // references to this connection and BT ICS under the work user. This logic ensures
+            // that we prevent unbinding the BT ICS if there is a personal (associatedUser: 0) call
+            // + work call (associatedUser: 10) and one of them gets disconnected.
+            if (usersCurrentlyBound.contains(connection.mUserHandleToUseForBinding)) {
+                Log.i(this, "scheduleBtUnbind: Refraining from unbinding BT service to an "
+                        + "ongoing call detected which is bound to the same user (%s).",
+                        connection.mUserHandleToUseForBinding);
+            } else {
+                // Similar to in onCallRemoved when we unbind from the other ICS, we need to
+                // delay unbinding from the BT ICS because we need to give the ICS a
+                // moment to finish the onCallRemoved signal it got just prior.
+                mHandler.postDelayed(new Runnable("ICC.sBU", mLock) {
+                    @Override
+                    public void loggedRun() {
+                        Log.i(this, "onDisconnectedTonePlaying: unbinding from BT ICS.");
+                        // Prevent unbinding in the case that this is run while another call
+                        // has been placed/received. Otherwise, we will early unbind from
+                        // the BT ICS and not be able to properly relay call state updates.
+                        if (!mBTInCallServiceConnections.containsKey(userHandle)) {
+                            connection.disconnect();
+                        } else {
+                            Log.i(this, "onDisconnectedTonePlaying: Refraining from "
+                                    + "unbinding BT ICS. Another call is ongoing.");
+                        }
                     }
-                }
+                }.prepare(), mTimeoutsAdapter.getCallRemoveUnbindInCallServicesDelay(
+                        mContext.getContentResolver()));
             }
+            mBTInCallServiceConnections.remove(userHandle);
+        }
+        // Ensure that BT ICS instance is cleaned up
+        if (mBTInCallServices.remove(userHandle) != null) {
+            updateCombinedInCallServiceMap(userHandle);
         }
     }
 
@@ -1873,7 +1922,6 @@ public class InCallController extends CallsManagerListenerBase implements
         }
     }
 
-    @VisibleForTesting
     public void bringToForeground(boolean showDialpad, UserHandle callingUser) {
         KeyguardManager keyguardManager = mContext.getSystemService(KeyguardManager.class);
         boolean isLockscreenRestricted = keyguardManager != null
@@ -2778,7 +2826,9 @@ public class InCallController extends CallsManagerListenerBase implements
                                     "updateCall: (deferred) Sending call disconnected update "
                                             + "to BT ICS.");
                             updateCallToIcs(inCallService, info, parcelableCall, componentName);
-                            mDisconnectedToneBtFutures.remove(call.getId());
+                            synchronized (mLock) {
+                                mDisconnectedToneBtFutures.remove(call.getId());
+                            }
                         });
                         mDisconnectedToneBtFutures.put(call.getId(), disconnectedToneFuture);
                     } else {
@@ -2832,7 +2882,7 @@ public class InCallController extends CallsManagerListenerBase implements
             mCallIdMapper.addCall(call);
             call.addListener(mCallListener);
             if (mFeatureFlags.separatelyBindToBtIncallService()) {
-                mPendingEndToneCall.add(call);
+                mBtIcsCallTracker.add(call);
             }
         }
 
diff --git a/src/com/android/server/telecom/PendingAudioRoute.java b/src/com/android/server/telecom/PendingAudioRoute.java
index ffde9640c..d21ac5635 100644
--- a/src/com/android/server/telecom/PendingAudioRoute.java
+++ b/src/com/android/server/telecom/PendingAudioRoute.java
@@ -130,6 +130,10 @@ public class PendingAudioRoute {
         mPendingMessages.remove(message);
     }
 
+    public Set<Pair<Integer, String>> getPendingMessages() {
+        return mPendingMessages;
+    }
+
     public boolean isActive() {
         return mActive;
     }
@@ -146,4 +150,8 @@ public class PendingAudioRoute {
     public void overrideDestRoute(AudioRoute route) {
         mDestRoute = route;
     }
+
+    public FeatureFlags getFeatureFlags() {
+        return mFeatureFlags;
+    }
 }
diff --git a/src/com/android/server/telecom/PhoneAccountRegistrar.java b/src/com/android/server/telecom/PhoneAccountRegistrar.java
index f0423c3b7..1a1af925f 100644
--- a/src/com/android/server/telecom/PhoneAccountRegistrar.java
+++ b/src/com/android/server/telecom/PhoneAccountRegistrar.java
@@ -1284,12 +1284,15 @@ public class PhoneAccountRegistrar {
         boolean isNewAccount;
 
         // add self-managed capability for transactional accounts that are missing it
-        if (hasTransactionalCallCapabilities(account) &&
-                !account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
+        if (hasTransactionalCallCapabilities(account)
+                && !account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
             account = account.toBuilder()
                     .setCapabilities(account.getCapabilities()
                             | PhoneAccount.CAPABILITY_SELF_MANAGED)
                     .build();
+            // Note: below we will automatically remove CAPABILITY_CONNECTION_MANAGER,
+            // CAPABILITY_CALL_PROVIDER, and CAPABILITY_SIM_SUBSCRIPTION if this magically becomes
+            // a self-managed phone account here.
         }
 
         PhoneAccount oldAccount = getPhoneAccountUnchecked(account.getAccountHandle());
@@ -1310,6 +1313,12 @@ public class PhoneAccountRegistrar {
         if (account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
             // Turn off bits we don't want to be able to set (TelecomServiceImpl protects against
             // this but we'll also prevent it from happening here, just to be safe).
+            if ((account.getCapabilities() & (PhoneAccount.CAPABILITY_CALL_PROVIDER
+                    | PhoneAccount.CAPABILITY_CONNECTION_MANAGER
+                    | PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION)) > 0) {
+                Log.w(this, "addOrReplacePhoneAccount: attempt to register a "
+                        + "VoIP phone account with call provider/cm/sim sub capabilities.");
+            }
             int newCapabilities = account.getCapabilities() &
                     ~(PhoneAccount.CAPABILITY_CALL_PROVIDER |
                         PhoneAccount.CAPABILITY_CONNECTION_MANAGER |
@@ -1317,7 +1326,10 @@ public class PhoneAccountRegistrar {
 
             // Ensure name is correct.
             CharSequence newLabel = mAppLabelProxy.getAppLabel(
-                    account.getAccountHandle().getComponentName().getPackageName());
+                    account.getAccountHandle().getComponentName().getPackageName(),
+                    UserUtil.getAssociatedUserForCall(
+                            mTelecomFeatureFlags.associatedUserRefactorForWorkProfile(),
+                            this, UserHandle.CURRENT, account.getAccountHandle()));
 
             account = account.toBuilder()
                     .setLabel(newLabel)
diff --git a/src/com/android/server/telecom/Ringer.java b/src/com/android/server/telecom/Ringer.java
index c309dd5fc..bfaadf0df 100644
--- a/src/com/android/server/telecom/Ringer.java
+++ b/src/com/android/server/telecom/Ringer.java
@@ -59,6 +59,7 @@ import java.io.InputStream;
 import java.io.InputStreamReader;
 import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
+import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutionException;
@@ -176,6 +177,11 @@ public class Ringer {
 
     private static VolumeShaper.Configuration mVolumeShaperConfig;
 
+    public static final UUID GET_RINGER_MODE_ANOMALY_UUID =
+            UUID.fromString("eb10505b-4d7b-4fab-b4a1-a18186799065");
+    public static final String GET_RINGER_MODE_ANOMALY_MSG = "AM#GetRingerMode() and"
+            + " AM#GetRingerModeInternal() are returning diff values when DoNotDisturb is OFF!";
+
     /**
      * Used to keep ordering of unanswered incoming calls. There can easily exist multiple incoming
      * calls and explicit ordering is useful for maintaining the proper state of the ringer.
@@ -191,6 +197,8 @@ public class Ringer {
     private final boolean mIsHapticPlaybackSupportedByDevice;
     private final FeatureFlags mFlags;
     private final boolean mRingtoneVibrationSupported;
+    private final AnomalyReporterAdapter mAnomalyReporter;
+
     /**
      * For unit testing purposes only; when set, {@link #startRinging(Call, boolean)} will complete
      * the future provided by the test using {@link #setBlockOnRingingFuture(CompletableFuture)}.
@@ -237,7 +245,8 @@ public class Ringer {
             InCallController inCallController,
             NotificationManager notificationManager,
             AccessibilityManagerAdapter accessibilityManagerAdapter,
-            FeatureFlags featureFlags) {
+            FeatureFlags featureFlags,
+            AnomalyReporterAdapter anomalyReporter) {
 
         mLock = new Object();
         mSystemSettingsUtil = systemSettingsUtil;
@@ -252,6 +261,7 @@ public class Ringer {
         mVibrationEffectProxy = vibrationEffectProxy;
         mNotificationManager = notificationManager;
         mAccessibilityManagerAdapter = accessibilityManagerAdapter;
+        mAnomalyReporter = anomalyReporter;
 
         mDefaultVibrationEffect =
                 loadDefaultRingVibrationEffect(
@@ -358,6 +368,12 @@ public class Ringer {
 
             mVolumeShaperConfig = null;
 
+            String vibratorAttrs = String.format("hasVibrator=%b, userRequestsVibrate=%b, "
+                            + "ringerMode=%d, isVibratorEnabled=%b",
+                    mVibrator.hasVibrator(),
+                    mSystemSettingsUtil.isRingVibrationEnabled(mContext),
+                    mAudioManager.getRingerMode(), isVibratorEnabled);
+
             if (attributes.isRingerAudible()) {
                 mRingingCall = foregroundCall;
                 Log.addEvent(foregroundCall, LogUtils.Events.START_RINGER);
@@ -399,11 +415,12 @@ public class Ringer {
                     // If ringer is not audible for this call, then the phone is in "Vibrate" mode.
                     // Use haptic-only ringtone or do not play anything.
                     isHapticOnly = true;
-                    if (DEBUG_RINGER) {
-                        Log.i(this, "Set ringtone as haptic only: " + isHapticOnly);
-                    }
+                    Log.i(this, "Set ringtone as haptic only: " + isHapticOnly);
                 } else {
+                    Log.i(this, "ringer & haptics are off, user missed alerts for call");
                     foregroundCall.setUserMissed(USER_MISSED_NO_VIBRATE);
+                    Log.addEvent(foregroundCall, LogUtils.Events.SKIP_VIBRATION,
+                            vibratorAttrs);
                     return attributes.shouldAcquireAudioFocus(); // ringer not audible
                 }
             }
@@ -429,18 +446,14 @@ public class Ringer {
                 ringtoneInfoSupplier = () -> mRingtoneFactory.getRingtone(
                         foregroundCall, null, false);
             }
-
+            Log.i(this, "isRingtoneInfoSupplierNull=[%b]", ringtoneInfoSupplier == null);
             // If vibration will be done, reserve the vibrator.
             boolean vibratorReserved = isVibratorEnabled && attributes.shouldRingForContact()
                 && tryReserveVibration(foregroundCall);
             if (!vibratorReserved) {
                 foregroundCall.setUserMissed(USER_MISSED_NO_VIBRATE);
                 Log.addEvent(foregroundCall, LogUtils.Events.SKIP_VIBRATION,
-                        "hasVibrator=%b, userRequestsVibrate=%b, ringerMode=%d, "
-                                + "isVibratorEnabled=%b",
-                        mVibrator.hasVibrator(),
-                        mSystemSettingsUtil.isRingVibrationEnabled(mContext),
-                        mAudioManager.getRingerMode(), isVibratorEnabled);
+                        vibratorAttrs);
             }
 
             // The vibration logic depends on the loaded ringtone, but we need to defer the ringtone
@@ -556,6 +569,11 @@ public class Ringer {
                 mIsVibrating = true;
                 mVibrator.vibrate(effect, VIBRATION_ATTRIBUTES);
                 Log.i(this, "start vibration.");
+            } else {
+                Log.i(this, "vibrateIfNeeded: skip; isVibrating=%b, fgCallId=%s, vibratingCall=%s",
+                        mIsVibrating,
+                        (foregroundCall == null ? "null" : foregroundCall.getId()),
+                        (mVibratingCall == null ? "null" : mVibratingCall.getId()));
             }
             // else stopped already: this isn't started unless a reservation was made.
         }
@@ -697,12 +715,43 @@ public class Ringer {
         // AudioManager#getRingerModeInternal which only useful for volume controllers
         boolean zenModeOn = mNotificationManager != null
                 && mNotificationManager.getZenMode() != ZEN_MODE_OFF;
+        maybeGenAnomReportForGetRingerMode(zenModeOn, audioManager);
         return mVibrator.hasVibrator()
                 && mSystemSettingsUtil.isRingVibrationEnabled(context)
                 && (audioManager.getRingerMode() != AudioManager.RINGER_MODE_SILENT
                 || (zenModeOn && shouldRingForContact));
     }
 
+    /**
+     * There are 3 settings for haptics:
+     * - AudioManager.RINGER_MODE_SILENT
+     * - AudioManager.RINGER_MODE_VIBRATE
+     * - AudioManager.RINGER_MODE_NORMAL
+     * If the user does not have {@link AudioManager#RINGER_MODE_SILENT} set, the user should
+     * have haptic feeback
+     *
+     * Note: If DND/ZEN_MODE is on, {@link AudioManager#getRingerMode()} will return
+     * {@link AudioManager#RINGER_MODE_SILENT}, regardless of the user setting. Therefore,
+     * getRingerModeInternal is the source of truth instead of {@link AudioManager#getRingerMode()}.
+     * However, if DND/ZEN_MOD is off, the APIs should return the same value.  Generate an anomaly
+     * report if they diverge.
+     */
+    private void maybeGenAnomReportForGetRingerMode(boolean isZenModeOn, AudioManager am) {
+        if (!mFlags.getRingerModeAnomReport()) {
+            return;
+        }
+        if (!isZenModeOn) {
+            int ringerMode = am.getRingerMode();
+            int ringerModeInternal = am.getRingerModeInternal();
+            if (ringerMode != ringerModeInternal) {
+                Log.i(this, "getRingerMode=[%d], getRingerModeInternal=[%d]",
+                        ringerMode, ringerModeInternal);
+                mAnomalyReporter.reportAnomaly(GET_RINGER_MODE_ANOMALY_UUID,
+                        GET_RINGER_MODE_ANOMALY_MSG);
+            }
+        }
+    }
+
     private RingerAttributes getRingerAttributes(Call call, boolean isHfpDeviceAttached) {
         mAudioManager = mContext.getSystemService(AudioManager.class);
         RingerAttributes.Builder builder = new RingerAttributes.Builder();
diff --git a/src/com/android/server/telecom/RoleManagerAdapterImpl.java b/src/com/android/server/telecom/RoleManagerAdapterImpl.java
index ded4d9c40..55326e84a 100644
--- a/src/com/android/server/telecom/RoleManagerAdapterImpl.java
+++ b/src/com/android/server/telecom/RoleManagerAdapterImpl.java
@@ -204,8 +204,8 @@ public class RoleManagerAdapterImpl implements RoleManagerAdapter {
             pw.print("(override ");
             pw.print(mOverrideDefaultCallRedirectionApp);
             pw.print(") ");
-            pw.print(getRoleManagerCallRedirectionApp(Binder.getCallingUserHandle()));
         }
+        pw.print(getRoleManagerCallRedirectionApp(Binder.getCallingUserHandle()));
         pw.println();
 
         pw.print("DefaultCallScreeningApp: ");
@@ -213,19 +213,19 @@ public class RoleManagerAdapterImpl implements RoleManagerAdapter {
             pw.print("(override ");
             pw.print(mOverrideDefaultCallScreeningApp);
             pw.print(") ");
-            pw.print(getRoleManagerCallScreeningApp(Binder.getCallingUserHandle()));
         }
+        pw.print(getRoleManagerCallScreeningApp(Binder.getCallingUserHandle()));
         pw.println();
 
         pw.print("DefaultCallCompanionApps: ");
-        if (mOverrideCallCompanionApps != null) {
+        if (!mOverrideCallCompanionApps.isEmpty()) {
             pw.print("(override ");
             pw.print(mOverrideCallCompanionApps.stream().collect(Collectors.joining(", ")));
             pw.print(") ");
-            List<String> appsInRole = getRoleManagerCallCompanionApps();
-            if (appsInRole != null) {
-                pw.print(appsInRole.stream().collect(Collectors.joining(", ")));
-            }
+        }
+        List<String> appsInRole = getRoleManagerCallCompanionApps();
+        if (!appsInRole.isEmpty()) {
+            pw.print(appsInRole.stream().collect(Collectors.joining(", ")));
         }
         pw.println();
     }
diff --git a/src/com/android/server/telecom/TelecomServiceImpl.java b/src/com/android/server/telecom/TelecomServiceImpl.java
index b8141bf95..e19f1bd26 100644
--- a/src/com/android/server/telecom/TelecomServiceImpl.java
+++ b/src/com/android/server/telecom/TelecomServiceImpl.java
@@ -52,12 +52,12 @@ import android.net.Uri;
 import android.os.Binder;
 import android.os.Build;
 import android.os.Bundle;
+import android.os.Handler;
+import android.os.Looper;
 import android.os.OutcomeReceiver;
 import android.os.ParcelFileDescriptor;
 import android.os.Process;
 import android.os.RemoteException;
-import android.os.ResultReceiver;
-import android.os.ShellCallback;
 import android.os.UserHandle;
 import android.provider.BlockedNumberContract;
 import android.provider.BlockedNumbersManager;
@@ -68,6 +68,7 @@ import android.telecom.DisconnectCause;
 import android.telecom.Log;
 import android.telecom.PhoneAccount;
 import android.telecom.PhoneAccountHandle;
+import android.telecom.StatusHints;
 import android.telecom.TelecomAnalytics;
 import android.telecom.TelecomManager;
 import android.telecom.VideoProfile;
@@ -77,22 +78,22 @@ import android.text.TextUtils;
 import android.util.EventLog;
 
 import androidx.annotation.NonNull;
-import androidx.annotation.Nullable;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.telecom.ICallControl;
 import com.android.internal.telecom.ICallEventCallback;
 import com.android.internal.telecom.ITelecomService;
 import com.android.internal.util.IndentingPrintWriter;
-import com.android.modules.utils.BasicShellCommandHandler;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.ApiStats;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.settings.BlockedNumbersActivity;
-import com.android.server.telecom.voip.IncomingCallTransaction;
-import com.android.server.telecom.voip.OutgoingCallTransaction;
-import com.android.server.telecom.voip.TransactionManager;
-import com.android.server.telecom.voip.VoipCallTransaction;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
+import com.android.server.telecom.callsequencing.voip.IncomingCallTransaction;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.io.FileDescriptor;
 import java.io.PrintWriter;
@@ -112,45 +113,6 @@ import java.util.UUID;
  */
 public class TelecomServiceImpl {
 
-    public interface SubscriptionManagerAdapter {
-        int getDefaultVoiceSubId();
-    }
-
-    static class SubscriptionManagerAdapterImpl implements SubscriptionManagerAdapter {
-        @Override
-        public int getDefaultVoiceSubId() {
-            return SubscriptionManager.getDefaultVoiceSubscriptionId();
-        }
-    }
-
-    public interface SettingsSecureAdapter {
-        void putStringForUser(ContentResolver resolver, String name, String value, int userHandle);
-
-        String getStringForUser(ContentResolver resolver, String name, int userHandle);
-    }
-
-    static class SettingsSecureAdapterImpl implements SettingsSecureAdapter {
-        @Override
-        public void putStringForUser(ContentResolver resolver, String name, String value,
-            int userHandle) {
-            Settings.Secure.putStringForUser(resolver, name, value, userHandle);
-        }
-
-        @Override
-        public String getStringForUser(ContentResolver resolver, String name, int userHandle) {
-            return Settings.Secure.getStringForUser(resolver, name, userHandle);
-        }
-    }
-
-    private static final String TAG = "TelecomServiceImpl";
-    private static final String TIME_LINE_ARG = "timeline";
-    private static final int DEFAULT_VIDEO_STATE = -1;
-    private static final String PERMISSION_HANDLE_CALL_INTENT =
-            "android.permission.HANDLE_CALL_INTENT";
-    private static final String ADD_CALL_ERR_MSG = "Call could not be created or found. "
-            + "Retry operation.";
-    private AnomalyReporterAdapter mAnomalyReporter = new AnomalyReporterAdapterImpl();
-
     /**
      * Anomaly Report UUIDs and corresponding error descriptions specific to TelecomServiceImpl.
      */
@@ -182,17 +144,39 @@ public class TelecomServiceImpl {
             UUID.fromString("4edf6c8d-1e43-4c94-b0fc-a40c8d80cfe8");
     public static final String PLACE_CALL_SECURITY_EXCEPTION_ERROR_MSG =
             "Security exception thrown while placing an outgoing call.";
-
-    @VisibleForTesting
-    public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter){
-        mAnomalyReporter = mAnomalyReporterAdapter;
-    }
-
+    private static final String TAG = "TelecomServiceImpl";
+    private static final String TIME_LINE_ARG = "timeline";
+    private static final int DEFAULT_VIDEO_STATE = -1;
+    private static final String PERMISSION_HANDLE_CALL_INTENT =
+            "android.permission.HANDLE_CALL_INTENT";
+    private static final String ADD_CALL_ERR_MSG = "Call could not be created or found. "
+            + "Retry operation.";
+    private final PhoneAccountRegistrar mPhoneAccountRegistrar;
+    private final CallIntentProcessor.Adapter mCallIntentProcessorAdapter;
+    private final UserCallIntentProcessorFactory mUserCallIntentProcessorFactory;
+    private final DefaultDialerCache mDefaultDialerCache;
+    private final SubscriptionManagerAdapter mSubscriptionManagerAdapter;
+    private final SettingsSecureAdapter mSettingsSecureAdapter;
+    private final TelecomSystem.SyncRoot mLock;
+    private final TransactionalServiceRepository mTransactionalServiceRepository;
+    private final BlockedNumbersManager mBlockedNumbersManager;
+    private final FeatureFlags mFeatureFlags;
+    private final com.android.internal.telephony.flags.FeatureFlags mTelephonyFeatureFlags;
+    private final TelecomMetricsController mMetricsController;
+    private final String mSystemUiPackageName;
+    private AnomalyReporterAdapter mAnomalyReporter = new AnomalyReporterAdapterImpl();
+    private final Context mContext;
+    private final AppOpsManager mAppOpsManager;
+    private final PackageManager mPackageManager;
+    private final CallsManager mCallsManager;
+    private TransactionManager mTransactionManager;
     private final ITelecomService.Stub mBinderImpl = new ITelecomService.Stub() {
 
         @Override
         public void addCall(CallAttributes callAttributes, ICallEventCallback callEventCallback,
                 String callId, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ADDCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aC", Log.getPackageAbbreviation(callingPackage));
                 Log.i(TAG, "addCall: id=[%s], attributes=[%s]", callId, callAttributes);
@@ -205,12 +189,14 @@ public class TelecomServiceImpl {
                 enforcePhoneAccountIsRegisteredEnabled(handle, handle.getUserHandle());
                 enforceCallingPackage(callingPackage, "addCall");
 
+                event.setResult(ApiStats.RESULT_EXCEPTION);
+
                 // add extras about info used for FGS delegation
                 Bundle extras = new Bundle();
                 extras.putInt(CallAttributes.CALLER_UID_KEY, Binder.getCallingUid());
                 extras.putInt(CallAttributes.CALLER_PID_KEY, Binder.getCallingPid());
 
-                VoipCallTransaction transaction = null;
+                CallTransaction transaction = null;
                 // create transaction based on the call direction
                 switch (callAttributes.getDirection()) {
                     case DIRECTION_OUTGOING:
@@ -230,7 +216,7 @@ public class TelecomServiceImpl {
 
                 mTransactionManager.addTransaction(transaction, new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
                         Log.d(TAG, "addCall: onResult");
                         Call call = result.getCall();
 
@@ -268,7 +254,9 @@ public class TelecomServiceImpl {
                         onAddCallControl(callId, callEventCallback, null, exception);
                     }
                 });
+                event.setResult(ApiStats.RESULT_NORMAL);
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -292,12 +280,17 @@ public class TelecomServiceImpl {
         @Override
         public PhoneAccountHandle getDefaultOutgoingPhoneAccount(String uriScheme,
                 String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETDEFAULTOUTGOINGPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gDOPA", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
                     PhoneAccountHandle phoneAccountHandle = null;
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+
+                    event.setResult(ApiStats.RESULT_EXCEPTION);
                     try {
                         phoneAccountHandle = mPhoneAccountRegistrar
                                 .getOutgoingPhoneAccountForScheme(uriScheme, callingUserHandle);
@@ -307,6 +300,8 @@ public class TelecomServiceImpl {
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
+
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     if (isCallerSimCallManager(phoneAccountHandle)
                             || canReadPhoneState(
                             callingPackage,
@@ -317,12 +312,16 @@ public class TelecomServiceImpl {
                     return null;
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
         @Override
         public PhoneAccountHandle getUserSelectedOutgoingPhoneAccount(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.gUSOPA", Log.getPackageAbbreviation(callingPackage));
@@ -330,6 +329,7 @@ public class TelecomServiceImpl {
                         throw new SecurityException("Only the default dialer, or caller with "
                                 + "READ_PRIVILEGED_PHONE_STATE can call this method.");
                     }
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     return mPhoneAccountRegistrar.getUserSelectedOutgoingPhoneAccount(
                             callingUserHandle);
@@ -337,6 +337,7 @@ public class TelecomServiceImpl {
                     Log.e(this, e, "getUserSelectedOutgoingPhoneAccount");
                     throw e;
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -344,6 +345,9 @@ public class TelecomServiceImpl {
 
         @Override
         public void setUserSelectedOutgoingPhoneAccount(PhoneAccountHandle accountHandle) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_SETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.sUSOPA");
                 synchronized (mLock) {
@@ -353,6 +357,7 @@ public class TelecomServiceImpl {
                     try {
                         mPhoneAccountRegistrar.setUserSelectedOutgoingPhoneAccount(
                                 accountHandle, callingUserHandle);
+                        event.setResult(ApiStats.RESULT_NORMAL);
                     } catch (Exception e) {
                         Log.e(this, e, "setUserSelectedOutgoingPhoneAccount");
                         mAnomalyReporter.reportAnomaly(SET_USER_PHONE_ACCOUNT_ERROR_UUID,
@@ -363,6 +368,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -371,6 +377,9 @@ public class TelecomServiceImpl {
         public ParceledListSlice<PhoneAccountHandle> getCallCapablePhoneAccounts(
                 boolean includeDisabledAccounts, String callingPackage,
                 String callingFeatureId, boolean acrossProfiles) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETCALLCAPABLEPHONEACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gCCPA", Log.getPackageAbbreviation(callingPackage));
 
@@ -400,13 +409,13 @@ public class TelecomServiceImpl {
                         "getCallCapablePhoneAccounts")) {
                     return ParceledListSlice.emptyList();
                 }
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
-                    boolean crossUserAccess = mTelephonyFeatureFlags.workProfileApiSplit()
-                            && !acrossProfiles ? false
-                            : (mTelephonyFeatureFlags.workProfileApiSplit()
-                                    ? hasInAppCrossProfilePermission()
-                                    : hasInAppCrossUserPermission());
+                    boolean crossUserAccess = (!mTelephonyFeatureFlags.workProfileApiSplit()
+                            || acrossProfiles) && (mTelephonyFeatureFlags.workProfileApiSplit()
+                            ? hasInAppCrossProfilePermission()
+                            : hasInAppCrossUserPermission());
                     long token = Binder.clearCallingIdentity();
                     try {
                         return new ParceledListSlice<>(
@@ -414,6 +423,7 @@ public class TelecomServiceImpl {
                                         includeDisabledAccounts, callingUserHandle,
                                         crossUserAccess));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getCallCapablePhoneAccounts");
                         mAnomalyReporter.reportAnomaly(GET_CALL_CAPABLE_ACCOUNTS_ERROR_UUID,
                                 GET_CALL_CAPABLE_ACCOUNTS_ERROR_MSG);
@@ -423,6 +433,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -430,6 +441,9 @@ public class TelecomServiceImpl {
         @Override
         public ParceledListSlice<PhoneAccountHandle> getSelfManagedPhoneAccounts(
                 String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETSELFMANAGEDPHONEACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gSMPA", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId,
@@ -439,10 +453,12 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(mPhoneAccountRegistrar
                                 .getSelfManagedPhoneAccounts(callingUserHandle));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getSelfManagedPhoneAccounts");
                         throw e;
                     } finally {
@@ -450,6 +466,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -457,6 +474,9 @@ public class TelecomServiceImpl {
         @Override
         public ParceledListSlice<PhoneAccountHandle> getOwnSelfManagedPhoneAccounts(
                 String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETOWNSELFMANAGEDPHONEACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gOSMPA", Log.getPackageAbbreviation(callingPackage));
                 try {
@@ -472,11 +492,13 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(mPhoneAccountRegistrar
                                 .getSelfManagedPhoneAccountsForPackage(callingPackage,
                                         callingUserHandle));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e,
                                 "getSelfManagedPhoneAccountsForPackage");
                         throw e;
@@ -485,6 +507,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -492,6 +515,9 @@ public class TelecomServiceImpl {
         @Override
         public ParceledListSlice<PhoneAccountHandle> getPhoneAccountsSupportingScheme(
                 String uriScheme, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETPHONEACCOUNTSSUPPORTINGSCHEME,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gPASS", Log.getPackageAbbreviation(callingPackage));
                 try {
@@ -506,11 +532,13 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(mPhoneAccountRegistrar
-                            .getCallCapablePhoneAccounts(uriScheme, false,
-                                    callingUserHandle, false));
+                                .getCallCapablePhoneAccounts(uriScheme, false,
+                                        callingUserHandle, false));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getPhoneAccountsSupportingScheme %s", uriScheme);
                         throw e;
                     } finally {
@@ -518,6 +546,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -526,42 +555,53 @@ public class TelecomServiceImpl {
         public ParceledListSlice<PhoneAccountHandle> getPhoneAccountsForPackage(
                 String packageName) {
             //TODO: Deprecate this in S
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETPHONEACCOUNTSFORPACKAGE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
-                enforceCallingPackage(packageName, "getPhoneAccountsForPackage");
-            } catch (SecurityException se1) {
-                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
-                        "getPhoneAccountsForPackage: invalid calling package");
-                throw se1;
-            }
-
-            try {
-                enforcePermission(READ_PRIVILEGED_PHONE_STATE);
-            } catch (SecurityException se2) {
-                EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
-                        "getPhoneAccountsForPackage: no permission");
-                throw se2;
-            }
+                try {
+                    enforceCallingPackage(packageName, "getPhoneAccountsForPackage");
+                } catch (SecurityException se1) {
+                    EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                            "getPhoneAccountsForPackage: invalid calling package");
+                    throw se1;
+                }
 
-            synchronized (mLock) {
-                final UserHandle callingUserHandle = Binder.getCallingUserHandle();
-                long token = Binder.clearCallingIdentity();
                 try {
-                    Log.startSession("TSI.gPAFP");
-                    return new ParceledListSlice<>(mPhoneAccountRegistrar
-                            .getAllPhoneAccountHandlesForPackage(callingUserHandle, packageName));
-                } catch (Exception e) {
-                    Log.e(this, e, "getPhoneAccountsForPackage %s", packageName);
-                    throw e;
-                } finally {
-                    Binder.restoreCallingIdentity(token);
-                    Log.endSession();
+                    enforcePermission(READ_PRIVILEGED_PHONE_STATE);
+                } catch (SecurityException se2) {
+                    EventLog.writeEvent(0x534e4554, "153995334", Binder.getCallingUid(),
+                            "getPhoneAccountsForPackage: no permission");
+                    throw se2;
+                }
+
+                synchronized (mLock) {
+                    final UserHandle callingUserHandle = Binder.getCallingUserHandle();
+                    long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
+                    try {
+                        Log.startSession("TSI.gPAFP");
+                        return new ParceledListSlice<>(mPhoneAccountRegistrar
+                                .getAllPhoneAccountHandlesForPackage(
+                                        callingUserHandle, packageName));
+                    } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
+                        Log.e(this, e, "getPhoneAccountsForPackage %s", packageName);
+                        throw e;
+                    } finally {
+                        Binder.restoreCallingIdentity(token);
+                        Log.endSession();
+                    }
                 }
+            } finally {
+                logEvent(event);
             }
         }
 
         @Override
         public PhoneAccount getPhoneAccount(PhoneAccountHandle accountHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gPA", Log.getPackageAbbreviation(callingPackage));
                 try {
@@ -588,6 +628,7 @@ public class TelecomServiceImpl {
                     Set<String> permissions = computePermissionsForBoundPackage(
                             Set.of(MODIFY_PHONE_STATE), null);
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         // In ideal case, we should not resolve the handle across profiles. But
                         // given the fact that profile's call is handled by its parent user's
@@ -598,6 +639,7 @@ public class TelecomServiceImpl {
                                         /* acrossProfiles */ true);
                         return maybeCleansePhoneAccount(account, permissions);
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getPhoneAccount %s", accountHandle);
                         mAnomalyReporter.reportAnomaly(GET_PHONE_ACCOUNT_ERROR_UUID,
                                 GET_PHONE_ACCOUNT_ERROR_MSG);
@@ -607,6 +649,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -614,6 +657,8 @@ public class TelecomServiceImpl {
         @Override
         public ParceledListSlice<PhoneAccount> getRegisteredPhoneAccounts(String callingPackage,
                 String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETREGISTEREDPHONEACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gRPA", Log.getPackageAbbreviation(callingPackage));
                 try {
@@ -635,6 +680,7 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(
                                 mPhoneAccountRegistrar.getPhoneAccounts(
@@ -647,6 +693,7 @@ public class TelecomServiceImpl {
                                         hasCrossUserAccess /* crossUserAccess */,
                                         false /* includeAll */));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getRegisteredPhoneAccounts");
                         throw e;
                     } finally {
@@ -654,14 +701,18 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
         @Override
         public int getAllPhoneAccountsCount() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETALLPHONEACCOUNTSCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gAPAC");
+                event.setCallerUid(Binder.getCallingUid());
                 try {
                     enforceModifyPermission(
                             "getAllPhoneAccountsCount requires MODIFY_PHONE_STATE permission.");
@@ -672,22 +723,27 @@ public class TelecomServiceImpl {
                 }
 
                 synchronized (mLock) {
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         // This list is pre-filtered for the calling user.
                         return getAllPhoneAccounts().getList().size();
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getAllPhoneAccountsCount");
                         throw e;
 
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
         @Override
         public ParceledListSlice<PhoneAccount> getAllPhoneAccounts() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETALLPHONEACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.gAPA");
@@ -702,16 +758,19 @@ public class TelecomServiceImpl {
 
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(mPhoneAccountRegistrar
                                 .getAllPhoneAccounts(callingUserHandle, false));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getAllPhoneAccounts");
                         throw e;
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -719,6 +778,8 @@ public class TelecomServiceImpl {
 
         @Override
         public ParceledListSlice<PhoneAccountHandle> getAllPhoneAccountHandles() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETALLPHONEACCOUNTHANDLES,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gAPAH");
 
@@ -735,11 +796,13 @@ public class TelecomServiceImpl {
                     final UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     boolean crossUserAccess = hasInAppCrossUserPermission();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return new ParceledListSlice<>(mPhoneAccountRegistrar
                                 .getAllPhoneAccountHandles(callingUserHandle,
                                         crossUserAccess));
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getAllPhoneAccountsHandles");
                         throw e;
                     } finally {
@@ -747,12 +810,15 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
         @Override
         public PhoneAccountHandle getSimCallManager(int subId, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETSIMCALLMANAGER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.gSCM", Log.getPackageAbbreviation(callingPackage));
@@ -763,6 +829,7 @@ public class TelecomServiceImpl {
                         if (user != ActivityManager.getCurrentUser()) {
                             enforceCrossUserPermission(callingUid);
                         }
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         return mPhoneAccountRegistrar.getSimCallManager(subId, UserHandle.of(user));
                     } finally {
                         Binder.restoreCallingIdentity(token);
@@ -773,6 +840,7 @@ public class TelecomServiceImpl {
                             GET_SIM_MANAGER_ERROR_MSG);
                     throw e;
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -780,6 +848,8 @@ public class TelecomServiceImpl {
 
         @Override
         public PhoneAccountHandle getSimCallManagerForUser(int user, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETSIMCALLMANAGERFORUSER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.gSCMFU", Log.getPackageAbbreviation(callingPackage));
@@ -788,6 +858,7 @@ public class TelecomServiceImpl {
                         enforceCrossUserPermission(callingUid);
                     }
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mPhoneAccountRegistrar.getSimCallManager(UserHandle.of(user));
                     } finally {
@@ -799,6 +870,7 @@ public class TelecomServiceImpl {
                             GET_SIM_MANAGER_FOR_USER_ERROR_MSG);
                     throw e;
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -806,22 +878,27 @@ public class TelecomServiceImpl {
 
         @Override
         public void registerPhoneAccount(PhoneAccount account, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_REGISTERPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.rPA", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
                     try {
                         enforcePhoneAccountModificationForPackage(
                                 account.getAccountHandle().getComponentName().getPackageName());
-                        if (account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
+                        if (account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)
+                                || (mFeatureFlags.enforceTransactionalExclusivity()
+                                && account.hasCapabilities(
+                                PhoneAccount.CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS))) {
                             enforceRegisterSelfManaged();
                             if (account.hasCapabilities(PhoneAccount.CAPABILITY_CALL_PROVIDER) ||
                                     account.hasCapabilities(
                                             PhoneAccount.CAPABILITY_CONNECTION_MANAGER) ||
                                     account.hasCapabilities(
                                             PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION)) {
-                                throw new SecurityException("Self-managed ConnectionServices " +
-                                        "cannot also be call capable, connection managers, or " +
-                                        "SIM accounts.");
+                                throw new SecurityException("Self-managed ConnectionServices "
+                                        + "cannot also be call capable, connection managers, or "
+                                        + "SIM accounts.");
                             }
 
                             // For self-managed CS, the phone account registrar will override the
@@ -878,6 +955,7 @@ public class TelecomServiceImpl {
                         }
 
                         final long token = Binder.clearCallingIdentity();
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         try {
                             Log.i(this, "registerPhoneAccount: account=%s",
                                     account);
@@ -893,6 +971,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -900,6 +979,8 @@ public class TelecomServiceImpl {
         @Override
         public void unregisterPhoneAccount(PhoneAccountHandle accountHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_UNREGISTERPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.uPA", Log.getPackageAbbreviation(callingPackage));
@@ -907,6 +988,7 @@ public class TelecomServiceImpl {
                             accountHandle.getComponentName().getPackageName());
                     enforceUserHandleMatchesCaller(accountHandle);
                     final long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         mPhoneAccountRegistrar.unregisterPhoneAccount(accountHandle);
                     } finally {
@@ -916,6 +998,7 @@ public class TelecomServiceImpl {
                     Log.e(this, e, "unregisterPhoneAccount %s", accountHandle);
                     throw e;
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -923,16 +1006,20 @@ public class TelecomServiceImpl {
 
         @Override
         public void clearAccounts(String packageName) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_CLEARACCOUNTS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             synchronized (mLock) {
                 try {
                     Log.startSession("TSI.cA");
                     enforcePhoneAccountModificationForPackage(packageName);
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     mPhoneAccountRegistrar
                             .clearAccounts(packageName, Binder.getCallingUserHandle());
                 } catch (Exception e) {
                     Log.e(this, e, "clearAccounts %s", packageName);
                     throw e;
                 } finally {
+                    logEvent(event);
                     Log.endSession();
                 }
             }
@@ -944,6 +1031,8 @@ public class TelecomServiceImpl {
         @Override
         public boolean isVoiceMailNumber(PhoneAccountHandle accountHandle, String number,
                 String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISVOICEMAILNUMBER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iVMN", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
@@ -957,9 +1046,11 @@ public class TelecomServiceImpl {
                         return false;
                     }
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mPhoneAccountRegistrar.isVoiceMailNumber(accountHandle, number);
                     } catch (Exception e) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.e(this, e, "getSubscriptionIdForPhoneAccount");
                         throw e;
                     } finally {
@@ -967,6 +1058,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -977,6 +1069,8 @@ public class TelecomServiceImpl {
         @Override
         public String getVoiceMailNumber(PhoneAccountHandle accountHandle, String callingPackage,
                 String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETVOICEMAILNUMBER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gVMN", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "getVoiceMailNumber")) {
@@ -997,8 +1091,10 @@ public class TelecomServiceImpl {
                                     .getSubscriptionIdForPhoneAccount(accountHandle);
                         }
                     }
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     return getTelephonyManager(subId).getVoiceMailNumber();
                 } catch (UnsupportedOperationException ignored) {
+                    event.setResult(ApiStats.RESULT_EXCEPTION);
                     Log.w(this, "getVoiceMailNumber: no Telephony");
                     return null;
                 } catch (Exception e) {
@@ -1006,6 +1102,7 @@ public class TelecomServiceImpl {
                     throw e;
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1016,6 +1113,8 @@ public class TelecomServiceImpl {
         @Override
         public String getLine1Number(PhoneAccountHandle accountHandle, String callingPackage,
                 String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETLINE1NUMBER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("getL1N", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneNumbers(callingPackage, callingFeatureId, "getLine1Number")) {
@@ -1036,8 +1135,10 @@ public class TelecomServiceImpl {
                         subId = mPhoneAccountRegistrar.getSubscriptionIdForPhoneAccount(
                                 accountHandle);
                     }
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     return getTelephonyManager(subId).getLine1Number();
                 } catch (UnsupportedOperationException ignored) {
+                    event.setResult(ApiStats.RESULT_EXCEPTION);
                     Log.w(this, "getLine1Number: no telephony");
                     return null;
                 } catch (Exception e) {
@@ -1047,6 +1148,7 @@ public class TelecomServiceImpl {
                     Binder.restoreCallingIdentity(token);
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1056,6 +1158,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public void silenceRinger(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_SILENCERINGER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.sR", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
@@ -1063,17 +1167,20 @@ public class TelecomServiceImpl {
                     UserHandle callingUserHandle = Binder.getCallingUserHandle();
                     boolean crossUserAccess = hasInAppCrossUserPermission();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_EXCEPTION);
                     try {
                         Log.i(this, "Silence Ringer requested by %s", callingPackage);
                         Set<UserHandle> userHandles = mCallsManager.getCallAudioManager().
                                 silenceRingers(mContext, callingUserHandle,
                                         crossUserAccess);
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         mCallsManager.getInCallController().silenceRinger(userHandles);
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1085,10 +1192,13 @@ public class TelecomServiceImpl {
          */
         @Override
         public ComponentName getDefaultPhoneApp() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETDEFAULTPHONEAPP,
+                    Binder.getCallingUid(), ApiStats.RESULT_NORMAL);
             try {
                 Log.startSession("TSI.gDPA");
                 return mDefaultDialerCache.getDialtactsSystemDialerComponent();
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1101,6 +1211,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public String getDefaultDialerPackage(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETDEFAULTDIALERPACKAGE,
+                    Binder.getCallingUid(), ApiStats.RESULT_NORMAL);
             try {
                 Log.startSession("TSI.gDDP", Log.getPackageAbbreviation(callingPackage));
                 int callerUserId = UserHandle.getCallingUserId();
@@ -1112,6 +1224,7 @@ public class TelecomServiceImpl {
                     Binder.restoreCallingIdentity(token);
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1125,18 +1238,23 @@ public class TelecomServiceImpl {
          */
         @Override
         public String getDefaultDialerPackageForUser(int userId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_GETDEFAULTDIALERPACKAGEFORUSER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gDDPU");
                 mContext.enforceCallingOrSelfPermission(READ_PRIVILEGED_PHONE_STATE,
                         "READ_PRIVILEGED_PHONE_STATE permission required.");
 
                 final long token = Binder.clearCallingIdentity();
+                event.setResult(ApiStats.RESULT_NORMAL);
                 try {
                     return mDefaultDialerCache.getDefaultDialerApplication(userId);
                 } finally {
                     Binder.restoreCallingIdentity(token);
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1146,10 +1264,13 @@ public class TelecomServiceImpl {
          */
         @Override
         public String getSystemDialerPackage(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETSYSTEMDIALERPACKAGE,
+                    Binder.getCallingUid(), ApiStats.RESULT_NORMAL);
             try {
                 Log.startSession("TSI.gSDP", Log.getPackageAbbreviation(callingPackage));
                 return mDefaultDialerCache.getSystemDialerApplication();
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1177,17 +1298,20 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean isInCall(String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISINCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iIC", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "isInCall")) {
                     return false;
                 }
-
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.hasOngoingCalls(Binder.getCallingUserHandle(),
                             hasInAppCrossUserPermission());
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1197,9 +1321,13 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean hasManageOngoingCallsPermission(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_HASMANAGEONGOINGCALLSPERMISSION,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.hMOCP", Log.getPackageAbbreviation(callingPackage));
                 enforceCallingPackage(callingPackage, "hasManageOngoingCallsPermission");
+                event.setResult(ApiStats.RESULT_NORMAL);
                 return PermissionChecker.checkPermissionForDataDeliveryFromDataSource(
                         mContext, Manifest.permission.MANAGE_ONGOING_CALLS,
                         Binder.getCallingPid(),
@@ -1209,6 +1337,7 @@ public class TelecomServiceImpl {
                         "Checking whether the caller has MANAGE_ONGOING_CALLS permission")
                         == PermissionChecker.PERMISSION_GRANTED;
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1218,18 +1347,21 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean isInManagedCall(String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISINMANAGEDCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iIMC", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "isInManagedCall")) {
                     throw new SecurityException("Only the default dialer or caller with " +
                             "READ_PHONE_STATE permission can use this method.");
                 }
-
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.hasOngoingManagedCalls(Binder.getCallingUserHandle(),
                             hasInAppCrossUserPermission());
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1239,6 +1371,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean isRinging(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISRINGING,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iR");
                 if (!isPrivilegedDialerCalling(callingPackage)) {
@@ -1251,6 +1385,7 @@ public class TelecomServiceImpl {
                     }
                 }
 
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     // Note: We are explicitly checking the calls telecom is tracking rather than
                     // relying on mCallsManager#getCallState(). Since getCallState() relies on the
@@ -1260,6 +1395,7 @@ public class TelecomServiceImpl {
                     return mCallsManager.hasRingingOrSimulatedRingingCall();
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1272,6 +1408,8 @@ public class TelecomServiceImpl {
         @Deprecated
         @Override
         public int getCallState() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETCALLSTATE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.getCallState(DEPRECATED)");
                 if (CompatChanges.isChangeEnabled(
@@ -1282,6 +1420,7 @@ public class TelecomServiceImpl {
                     throw new SecurityException("This method can only be used for applications "
                             + "targeting API version 30 or less.");
                 }
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.getCallState();
                 }
@@ -1295,12 +1434,14 @@ public class TelecomServiceImpl {
          */
         @Override
         public int getCallStateUsingPackage(String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETCALLSTATEUSINGPACKAGE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.getCallStateUsingPackage");
 
                 // ensure the callingPackage is not spoofed
                 // skip check for privileged UIDs and throw SE if package does not match records
-                if (!isPrivilegedUid(callingPackage)
+                if (!isPrivilegedUid()
                         && !callingUidMatchesPackageManagerRecords(callingPackage)) {
                     EventLog.writeEvent(0x534e4554, "236813210", Binder.getCallingUid(),
                             "getCallStateUsingPackage");
@@ -1323,25 +1464,46 @@ public class TelecomServiceImpl {
                                 + " for API version 31+");
                     }
                 }
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.getCallState();
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
-        private boolean isPrivilegedUid(String callingPackage) {
+        private boolean isPrivilegedUid() {
             int callingUid = Binder.getCallingUid();
-            boolean isPrivileged = false;
-            switch (callingUid) {
-                case Process.ROOT_UID:
-                case Process.SYSTEM_UID:
-                case Process.SHELL_UID:
-                    isPrivileged = true;
-                    break;
+            return mFeatureFlags.allowSystemAppsResolveVoipCalls()
+                    ? (UserHandle.isSameApp(callingUid, Process.ROOT_UID)
+                            || UserHandle.isSameApp(callingUid, Process.SYSTEM_UID)
+                            || UserHandle.isSameApp(callingUid, Process.SHELL_UID))
+                    : (callingUid == Process.ROOT_UID
+                            || callingUid == Process.SYSTEM_UID
+                            || callingUid == Process.SHELL_UID);
+        }
+
+        private boolean isSysUiUid() {
+            int callingUid = Binder.getCallingUid();
+            int systemUiUid;
+            if (mPackageManager != null && mSystemUiPackageName != null) {
+                try {
+                    systemUiUid = mPackageManager.getPackageUid(mSystemUiPackageName, 0);
+                    Log.i(TAG, "isSysUiUid: callingUid = " + callingUid + "; systemUiUid = "
+                            + systemUiUid);
+                    return UserHandle.isSameApp(callingUid, systemUiUid);
+                } catch (PackageManager.NameNotFoundException e) {
+                    Log.w(TAG, "isSysUiUid: caught PackageManager NameNotFoundException = " + e);
+                    return false;
+                }
+            } else {
+                Log.w(TAG, "isSysUiUid: caught null check and returned false; "
+                        + "mPackageManager = " + mPackageManager + "; mSystemUiPackageName = "
+                        + mSystemUiPackageName);
             }
-            return isPrivileged;
+            return false;
         }
 
         /**
@@ -1349,21 +1511,32 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean endCall(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ENDCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.eC", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
                     if (!enforceAnswerCallPermission(callingPackage, Binder.getCallingUid())) {
                         throw new SecurityException("requires ANSWER_PHONE_CALLS permission");
                     }
-
+                    // Legacy behavior is to ignore whether the invocation is from a system app:
+                    boolean isCallerPrivileged = false;
+                    if (mFeatureFlags.allowSystemAppsResolveVoipCalls()) {
+                        isCallerPrivileged = isPrivilegedUid() || isSysUiUid();
+                        Log.i(TAG, "endCall: Binder.getCallingUid = [" +
+                                Binder.getCallingUid() + "] isCallerPrivileged = " +
+                                isCallerPrivileged);
+                    }
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
-                        return endCallInternal(callingPackage);
+                        return endCallInternal(callingPackage, isCallerPrivileged);
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1373,19 +1546,31 @@ public class TelecomServiceImpl {
          */
         @Override
         public void acceptRingingCall(String packageName) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ACCEPTRINGINGCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aRC", Log.getPackageAbbreviation(packageName));
                 synchronized (mLock) {
                     if (!enforceAnswerCallPermission(packageName, Binder.getCallingUid())) return;
-
+                    // Legacy behavior is to ignore whether the invocation is from a system app:
+                    boolean isCallerPrivileged = false;
+                    if (mFeatureFlags.allowSystemAppsResolveVoipCalls()) {
+                        isCallerPrivileged = isPrivilegedUid() || isSysUiUid();
+                        Log.i(TAG, "acceptRingingCall: Binder.getCallingUid = [" +
+                                Binder.getCallingUid() + "] isCallerPrivileged = " +
+                                isCallerPrivileged);
+                    }
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
-                        acceptRingingCallInternal(DEFAULT_VIDEO_STATE, packageName);
+                        acceptRingingCallInternal(DEFAULT_VIDEO_STATE, packageName,
+                                isCallerPrivileged);
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1395,19 +1580,31 @@ public class TelecomServiceImpl {
          */
         @Override
         public void acceptRingingCallWithVideoState(String packageName, int videoState) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_ACCEPTRINGINGCALLWITHVIDEOSTATE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aRCWVS", Log.getPackageAbbreviation(packageName));
                 synchronized (mLock) {
                     if (!enforceAnswerCallPermission(packageName, Binder.getCallingUid())) return;
-
+                    // Legacy behavior is to ignore whether the invocation is from a system app:
+                    boolean isCallerPrivileged = false;
+                    if (mFeatureFlags.allowSystemAppsResolveVoipCalls()) {
+                        isCallerPrivileged = isPrivilegedUid() || isSysUiUid();
+                        Log.i(TAG, "acceptRingingCallWithVideoState: Binder.getCallingUid = "
+                                + "[" + Binder.getCallingUid() + "] isCallerPrivileged = " +
+                                isCallerPrivileged);
+                    }
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
-                        acceptRingingCallInternal(videoState, packageName);
+                        acceptRingingCallInternal(videoState, packageName, isCallerPrivileged);
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1418,6 +1615,8 @@ public class TelecomServiceImpl {
         @Override
         public void showInCallScreen(boolean showDialpad, String callingPackage,
                 String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_SHOWINCALLSCREEN,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.sICS", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "showInCallScreen")) {
@@ -1425,16 +1624,18 @@ public class TelecomServiceImpl {
                 }
 
                 synchronized (mLock) {
-
                     UserHandle callingUser = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
-                        mCallsManager.getInCallController().bringToForeground(showDialpad, callingUser);
+                        mCallsManager.getInCallController().bringToForeground(
+                                showDialpad, callingUser);
                     } finally {
                         Binder.restoreCallingIdentity(token);
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1444,12 +1645,16 @@ public class TelecomServiceImpl {
          */
         @Override
         public void cancelMissedCallsNotification(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_CANCELMISSEDCALLSNOTIFICATION,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.cMCN", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
                     enforcePermissionOrPrivilegedDialer(MODIFY_PHONE_STATE, callingPackage);
                     UserHandle userHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         mCallsManager.getMissedCallNotifier().clearMissedCalls(userHandle);
                     } finally {
@@ -1457,6 +1662,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1466,6 +1672,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean handlePinMmi(String dialString, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_HANDLEPINMMI,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.hPM", Log.getPackageAbbreviation(callingPackage));
                 enforcePermissionOrPrivilegedDialer(MODIFY_PHONE_STATE, callingPackage);
@@ -1473,6 +1681,7 @@ public class TelecomServiceImpl {
                 // Switch identity so that TelephonyManager checks Telecom's permissions
                 // instead.
                 long token = Binder.clearCallingIdentity();
+                event.setResult(ApiStats.RESULT_NORMAL);
                 boolean retval = false;
                 try {
                     retval = getTelephonyManager(
@@ -1484,6 +1693,7 @@ public class TelecomServiceImpl {
 
                 return retval;
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1494,9 +1704,11 @@ public class TelecomServiceImpl {
         @Override
         public boolean handlePinMmiForPhoneAccount(PhoneAccountHandle accountHandle,
                 String dialString, String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_HANDLEPINMMIFORPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.hPMFPA", Log.getPackageAbbreviation(callingPackage));
-
                 enforcePermissionOrPrivilegedDialer(MODIFY_PHONE_STATE, callingPackage);
                 UserHandle callingUserHandle = Binder.getCallingUserHandle();
                 synchronized (mLock) {
@@ -1511,6 +1723,7 @@ public class TelecomServiceImpl {
                 // Switch identity so that TelephonyManager checks Telecom's permissions
                 // instead.
                 long token = Binder.clearCallingIdentity();
+                event.setResult(ApiStats.RESULT_NORMAL);
                 boolean retval = false;
                 int subId;
                 try {
@@ -1522,6 +1735,7 @@ public class TelecomServiceImpl {
                         retval = getTelephonyManager(subId)
                                 .handlePinMmiForSubscriber(subId, dialString);
                     } catch (UnsupportedOperationException uoe) {
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.w(this, "handlePinMmiForPhoneAccount: no telephony");
                         retval = false;
                     }
@@ -1530,6 +1744,7 @@ public class TelecomServiceImpl {
                 }
                 return retval;
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1540,6 +1755,8 @@ public class TelecomServiceImpl {
         @Override
         public Uri getAdnUriForPhoneAccount(PhoneAccountHandle accountHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETADNURIFORPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aAUFPA", Log.getPackageAbbreviation(callingPackage));
                 enforcePermissionOrPrivilegedDialer(MODIFY_PHONE_STATE, callingPackage);
@@ -1554,6 +1771,7 @@ public class TelecomServiceImpl {
                 // Switch identity so that TelephonyManager checks Telecom's permissions
                 // instead.
                 long token = Binder.clearCallingIdentity();
+                event.setResult(ApiStats.RESULT_NORMAL);
                 String retval = "content://icc/adn/";
                 try {
                     long subId = mPhoneAccountRegistrar
@@ -1565,6 +1783,7 @@ public class TelecomServiceImpl {
 
                 return Uri.parse(retval);
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1574,6 +1793,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean isTtySupported(String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISTTYSUPPORTED,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iTS", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "isTtySupported")) {
@@ -1581,10 +1802,12 @@ public class TelecomServiceImpl {
                             "READ_PRIVILEGED_PHONE_STATE or READ_PHONE_STATE can call this api");
                 }
 
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.isTtySupported();
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1594,16 +1817,20 @@ public class TelecomServiceImpl {
          */
         @Override
         public int getCurrentTtyMode(String callingPackage, String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_GETCURRENTTTYMODE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.gCTM", Log.getPackageAbbreviation(callingPackage));
                 if (!canReadPhoneState(callingPackage, callingFeatureId, "getCurrentTtyMode")) {
                     return TelecomManager.TTY_MODE_OFF;
                 }
 
+                event.setResult(ApiStats.RESULT_NORMAL);
                 synchronized (mLock) {
                     return mCallsManager.getCurrentTtyMode();
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1614,6 +1841,8 @@ public class TelecomServiceImpl {
         @Override
         public void addNewIncomingCall(PhoneAccountHandle phoneAccountHandle, Bundle extras,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ADDNEWINCOMINGCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aNIC", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
@@ -1647,6 +1876,7 @@ public class TelecomServiceImpl {
                             }
                         }
                         long token = Binder.clearCallingIdentity();
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         try {
                             Intent intent = new Intent(TelecomManager.ACTION_INCOMING_CALL);
                             intent.putExtra(TelecomManager.EXTRA_PHONE_ACCOUNT_HANDLE,
@@ -1685,11 +1915,14 @@ public class TelecomServiceImpl {
                             Binder.restoreCallingIdentity(token);
                         }
                     } else {
+                        // Invalid parameters are considered as an exception
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.w(this, "Null phoneAccountHandle. Ignoring request to add new" +
                                 " incoming call");
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1700,6 +1933,8 @@ public class TelecomServiceImpl {
         @Override
         public void addNewIncomingConference(PhoneAccountHandle phoneAccountHandle, Bundle extras,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ADDNEWINCOMINGCONFERENCE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aNIC", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
@@ -1727,6 +1962,7 @@ public class TelecomServiceImpl {
                             }
                         }
                         long token = Binder.clearCallingIdentity();
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         try {
                             mCallsManager.processIncomingConference(
                                     phoneAccountHandle, extras);
@@ -1734,22 +1970,26 @@ public class TelecomServiceImpl {
                             Binder.restoreCallingIdentity(token);
                         }
                     } else {
+                        // Invalid parameters are considered as an exception
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.w(this, "Null phoneAccountHandle. Ignoring request to add new" +
                                 " incoming conference");
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
-
         /**
          * @see android.telecom.TelecomManager#acceptHandover
          */
         @Override
         public void acceptHandover(Uri srcAddr, int videoState, PhoneAccountHandle destAcct,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ACCEPTHANDOVER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aHO", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
@@ -1779,17 +2019,22 @@ public class TelecomServiceImpl {
                         }
 
                         long token = Binder.clearCallingIdentity();
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         try {
                             mCallsManager.acceptHandover(srcAddr, videoState, destAcct);
+                            event.setResult(ApiStats.RESULT_NORMAL);
                         } finally {
                             Binder.restoreCallingIdentity(token);
                         }
                     } else {
+                        // Invalid parameters are considered as an exception
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.w(this, "Null phoneAccountHandle. Ignoring request " +
                                 "to handover the call");
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1799,6 +2044,8 @@ public class TelecomServiceImpl {
          */
         @Override
         public void addNewUnknownCall(PhoneAccountHandle phoneAccountHandle, Bundle extras) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ADDNEWUNKNOWNCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aNUC");
                 try {
@@ -1822,7 +2069,7 @@ public class TelecomServiceImpl {
                         enforcePhoneAccountIsRegisteredEnabled(phoneAccountHandle,
                                 Binder.getCallingUserHandle());
                         long token = Binder.clearCallingIdentity();
-
+                        event.setResult(ApiStats.RESULT_NORMAL);
                         try {
                             Intent intent = new Intent(TelecomManager.ACTION_NEW_UNKNOWN_CALL);
                             if (extras != null) {
@@ -1838,12 +2085,15 @@ public class TelecomServiceImpl {
                             Binder.restoreCallingIdentity(token);
                         }
                     } else {
+                        // Invalid parameters are considered as an exception
+                        event.setResult(ApiStats.RESULT_EXCEPTION);
                         Log.i(this,
                                 "Null phoneAccountHandle or not initiated by Telephony. " +
                                         "Ignoring request to add new unknown call.");
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1854,6 +2104,8 @@ public class TelecomServiceImpl {
         @Override
         public void startConference(List<Uri> participants, Bundle extras,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_STARTCONFERENCE,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.sC", Log.getPackageAbbreviation(callingPackage));
                 if (!canCallPhone(callingPackage, "startConference")) {
@@ -1863,6 +2115,7 @@ public class TelecomServiceImpl {
                 // Binder is clearing the identity, so we need to keep the store the handle
                 UserHandle currentUserHandle = Binder.getCallingUserHandle();
                 long token = Binder.clearCallingIdentity();
+                event.setResult(ApiStats.RESULT_NORMAL);
                 try {
                     mCallsManager.startConference(participants, extras, callingPackage,
                             currentUserHandle);
@@ -1870,6 +2123,7 @@ public class TelecomServiceImpl {
                     Binder.restoreCallingIdentity(token);
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1880,6 +2134,8 @@ public class TelecomServiceImpl {
         @Override
         public void placeCall(Uri handle, Bundle extras, String callingPackage,
                 String callingFeatureId) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_PLACECALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.pC", Log.getPackageAbbreviation(callingPackage));
                 enforceCallingPackage(callingPackage, "placeCall");
@@ -1955,6 +2211,7 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     final UserHandle userHandle = Binder.getCallingUserHandle();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         final Intent intent = new Intent(hasCallPrivilegedPermission ?
                                 Intent.ACTION_CALL_PRIVILEGED : Intent.ACTION_CALL, handle);
@@ -1972,6 +2229,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -1981,11 +2239,14 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean enablePhoneAccount(PhoneAccountHandle accountHandle, boolean isEnabled) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ENABLEPHONEACCOUNT,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.ePA");
                 enforceModifyPermission();
                 synchronized (mLock) {
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         // enable/disable phone account
                         return mPhoneAccountRegistrar.enablePhoneAccount(accountHandle, isEnabled);
@@ -1994,12 +2255,15 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
         @Override
         public boolean setDefaultDialer(String packageName) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_SETDEFAULTDIALER,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.sDD");
                 enforcePermission(MODIFY_PHONE_STATE);
@@ -2007,6 +2271,7 @@ public class TelecomServiceImpl {
                 synchronized (mLock) {
                     int callerUserId = UserHandle.getCallingUserId();
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mDefaultDialerCache.setDefaultDialer(packageName,
                                 callerUserId);
@@ -2015,6 +2280,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -2047,11 +2313,15 @@ public class TelecomServiceImpl {
 
         @Override
         public TelecomAnalytics dumpCallAnalytics() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_DUMPCALLANALYTICS,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.dCA");
                 enforcePermission(DUMP);
+                event.setResult(ApiStats.RESULT_NORMAL);
                 return Analytics.dumpToParcelableAnalytics();
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -2066,6 +2336,8 @@ public class TelecomServiceImpl {
          */
         @Override
         protected void dump(FileDescriptor fd, final PrintWriter writer, String[] args) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_DUMP,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             if (mContext.checkCallingOrSelfPermission(
                     android.Manifest.permission.DUMP)
                     != PackageManager.PERMISSION_GRANTED) {
@@ -2075,6 +2347,8 @@ public class TelecomServiceImpl {
                 return;
             }
 
+            event.setResult(ApiStats.RESULT_NORMAL);
+            logEvent(event);
 
             if (args != null && args.length > 0 && Analytics.ANALYTICS_DUMPSYS_ARG.equals(
                     args[0])) {
@@ -2154,7 +2428,7 @@ public class TelecomServiceImpl {
                 }
 
                 for (Method m : methods) {
-                    String flagEnabled = (Boolean) m.invoke(mFeatureFlags) ? "[✅]": "[❌]";
+                    String flagEnabled = (Boolean) m.invoke(mFeatureFlags) ? "[✅]" : "[❌]";
                     String methodName = m.getName();
                     String camelCaseName = methodName.replaceAll("([a-z])([A-Z]+)", "$1_$2")
                             .toLowerCase(Locale.US);
@@ -2171,17 +2445,23 @@ public class TelecomServiceImpl {
          */
         @Override
         public Intent createManageBlockedNumbersIntent(String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_CREATEMANAGEBLOCKEDNUMBERSINTENT,
+                    Binder.getCallingUid(), ApiStats.RESULT_NORMAL);
             try {
                 Log.startSession("TSI.cMBNI", Log.getPackageAbbreviation(callingPackage));
                 return BlockedNumbersActivity.getIntentForStartingActivity();
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
 
-
         @Override
         public Intent createLaunchEmergencyDialerIntent(String number) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(
+                    ApiStats.API_CREATELAUNCHEMERGENCYDIALERINTENT,
+                    Binder.getCallingUid(), ApiStats.RESULT_NORMAL);
             String packageName = mContext.getApplicationContext().getString(
                     com.android.internal.R.string.config_emergency_dialer_package);
             Intent intent = new Intent(Intent.ACTION_DIAL_EMERGENCY)
@@ -2194,6 +2474,7 @@ public class TelecomServiceImpl {
             if (!TextUtils.isEmpty(number) && TextUtils.isDigitsOnly(number)) {
                 intent.setData(Uri.parse("tel:" + number));
             }
+            logEvent(event);
             return intent;
         }
 
@@ -2203,6 +2484,8 @@ public class TelecomServiceImpl {
         @Override
         public boolean isIncomingCallPermitted(PhoneAccountHandle phoneAccountHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISINCOMINGCALLPERMITTED,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             Log.startSession("TSI.iICP", Log.getPackageAbbreviation(callingPackage));
             try {
                 enforceCallingPackage(callingPackage, "isIncomingCallPermitted");
@@ -2211,6 +2494,7 @@ public class TelecomServiceImpl {
                 enforceUserHandleMatchesCaller(phoneAccountHandle);
                 synchronized (mLock) {
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mCallsManager.isIncomingCallPermitted(phoneAccountHandle);
                     } finally {
@@ -2218,6 +2502,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -2228,6 +2513,8 @@ public class TelecomServiceImpl {
         @Override
         public boolean isOutgoingCallPermitted(PhoneAccountHandle phoneAccountHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISOUTGOINGCALLPERMITTED,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             Log.startSession("TSI.iOCP", Log.getPackageAbbreviation(callingPackage));
             try {
                 enforceCallingPackage(callingPackage, "isOutgoingCallPermitted");
@@ -2236,6 +2523,7 @@ public class TelecomServiceImpl {
                 enforceUserHandleMatchesCaller(phoneAccountHandle);
                 synchronized (mLock) {
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mCallsManager.isOutgoingCallPermitted(phoneAccountHandle);
                     } finally {
@@ -2243,6 +2531,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -2296,11 +2585,14 @@ public class TelecomServiceImpl {
          */
         @Override
         public boolean isInEmergencyCall() {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISINEMERGENCYCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.iIEC");
                 enforceModifyPermission();
                 synchronized (mLock) {
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         boolean isInEmergencyCall = mCallsManager.isInEmergencyCall();
                         Log.i(this, "isInEmergencyCall: %b", isInEmergencyCall);
@@ -2310,6 +2602,7 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
@@ -2383,7 +2676,7 @@ public class TelecomServiceImpl {
             }
         }
 
-        private boolean isDisconnectingOrDisconnected(Call call){
+        private boolean isDisconnectingOrDisconnected(Call call) {
             return call.getState() == CallState.DISCONNECTED
                     || call.getState() == CallState.DISCONNECTING;
         }
@@ -2631,6 +2924,8 @@ public class TelecomServiceImpl {
         @Override
         public boolean isInSelfManagedCall(String packageName, UserHandle userHandle,
                 String callingPackage) {
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ISINSELFMANAGEDCALL,
+                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
             try {
                 mContext.enforceCallingOrSelfPermission(READ_PRIVILEGED_PHONE_STATE,
                         "READ_PRIVILEGED_PHONE_STATE required.");
@@ -2643,6 +2938,7 @@ public class TelecomServiceImpl {
                 Log.startSession("TSI.iISMC", Log.getPackageAbbreviation(callingPackage));
                 synchronized (mLock) {
                     long token = Binder.clearCallingIdentity();
+                    event.setResult(ApiStats.RESULT_NORMAL);
                     try {
                         return mCallsManager.isInSelfManagedCall(
                                 packageName, userHandle);
@@ -2651,81 +2947,11 @@ public class TelecomServiceImpl {
                     }
                 }
             } finally {
+                logEvent(event);
                 Log.endSession();
             }
         }
     };
-
-    private boolean enforceCallStreamingPermission(String packageName, PhoneAccountHandle handle,
-            int uid) {
-        // TODO: implement this permission check (make sure the calling package is the d2di package)
-        PhoneAccount account = mPhoneAccountRegistrar.getPhoneAccount(handle,
-                UserHandle.getUserHandleForUid(uid));
-        if (account == null
-                || !account.hasCapabilities(PhoneAccount.CAPABILITY_SUPPORTS_CALL_STREAMING)) {
-            throw new SecurityException(
-                    "The phone account handle in requesting can't support call streaming: "
-                            + handle);
-        }
-        return true;
-    }
-
-    /**
-     * @return whether to return early without doing the action/throwing
-     * @throws SecurityException same as {@link Context#enforceCallingOrSelfPermission}
-     */
-    private boolean enforceAnswerCallPermission(String packageName, int uid) {
-        try {
-            enforceModifyPermission();
-        } catch (SecurityException e) {
-            final String permission = Manifest.permission.ANSWER_PHONE_CALLS;
-            enforcePermission(permission);
-
-            final int opCode = AppOpsManager.permissionToOpCode(permission);
-            if (opCode != AppOpsManager.OP_NONE
-                    && mAppOpsManager.checkOp(opCode, uid, packageName)
-                        != AppOpsManager.MODE_ALLOWED) {
-                return false;
-            }
-        }
-        return true;
-    }
-
-    /**
-     * @return {@code true} if the app has the handover permission and has received runtime
-     * permission to perform that operation, {@code false}.
-     * @throws SecurityException same as {@link Context#enforceCallingOrSelfPermission}
-     */
-    private boolean enforceAcceptHandoverPermission(String packageName, int uid) {
-        mContext.enforceCallingOrSelfPermission(Manifest.permission.ACCEPT_HANDOVER,
-                "App requires ACCEPT_HANDOVER permission to accept handovers.");
-
-        final int opCode = AppOpsManager.permissionToOpCode(Manifest.permission.ACCEPT_HANDOVER);
-        if (opCode != AppOpsManager.OP_ACCEPT_HANDOVER || (
-                mAppOpsManager.checkOp(opCode, uid, packageName)
-                        != AppOpsManager.MODE_ALLOWED)) {
-            return false;
-        }
-        return true;
-    }
-
-    private Context mContext;
-    private AppOpsManager mAppOpsManager;
-    private PackageManager mPackageManager;
-    private CallsManager mCallsManager;
-    private final PhoneAccountRegistrar mPhoneAccountRegistrar;
-    private final CallIntentProcessor.Adapter mCallIntentProcessorAdapter;
-    private final UserCallIntentProcessorFactory mUserCallIntentProcessorFactory;
-    private final DefaultDialerCache mDefaultDialerCache;
-    private final SubscriptionManagerAdapter mSubscriptionManagerAdapter;
-    private final SettingsSecureAdapter mSettingsSecureAdapter;
-    private final TelecomSystem.SyncRoot mLock;
-    private TransactionManager mTransactionManager;
-    private final TransactionalServiceRepository mTransactionalServiceRepository;
-    private final BlockedNumbersManager mBlockedNumbersManager;
-    private final FeatureFlags mFeatureFlags;
-    private final com.android.internal.telephony.flags.FeatureFlags mTelephonyFeatureFlags;
-
     public TelecomServiceImpl(
             Context context,
             CallsManager callsManager,
@@ -2737,9 +2963,10 @@ public class TelecomServiceImpl {
             SettingsSecureAdapter settingsSecureAdapter,
             FeatureFlags featureFlags,
             com.android.internal.telephony.flags.FeatureFlags telephonyFeatureFlags,
-            TelecomSystem.SyncRoot lock) {
+            TelecomSystem.SyncRoot lock, TelecomMetricsController metricsController,
+            String sysUiPackageName) {
         mContext = context;
-        mAppOpsManager = (AppOpsManager) mContext.getSystemService(Context.APP_OPS_SERVICE);
+        mAppOpsManager = mContext.getSystemService(AppOpsManager.class);
 
         mPackageManager = mContext.getPackageManager();
 
@@ -2758,6 +2985,8 @@ public class TelecomServiceImpl {
         mCallIntentProcessorAdapter = callIntentProcessorAdapter;
         mSubscriptionManagerAdapter = subscriptionManagerAdapter;
         mSettingsSecureAdapter = settingsSecureAdapter;
+        mMetricsController = metricsController;
+        mSystemUiPackageName = sysUiPackageName;
 
         mDefaultDialerCache.observeDefaultDialerApplication(mContext.getMainExecutor(), userId -> {
             String defaultDialer = mDefaultDialerCache.getDefaultDialerApplication(userId);
@@ -2772,14 +3001,68 @@ public class TelecomServiceImpl {
         });
 
         mTransactionManager = TransactionManager.getInstance();
-        mTransactionalServiceRepository = new TransactionalServiceRepository();
+        mTransactionalServiceRepository = new TransactionalServiceRepository(mFeatureFlags);
         mBlockedNumbersManager = mFeatureFlags.telecomMainlineBlockedNumbersManager()
                 ? mContext.getSystemService(BlockedNumbersManager.class)
                 : null;
     }
 
     @VisibleForTesting
-    public void setTransactionManager(TransactionManager transactionManager){
+    public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter) {
+        mAnomalyReporter = mAnomalyReporterAdapter;
+    }
+
+    private boolean enforceCallStreamingPermission(String packageName, PhoneAccountHandle handle,
+            int uid) {
+        // TODO: implement this permission check (make sure the calling package is the d2di package)
+        PhoneAccount account = mPhoneAccountRegistrar.getPhoneAccount(handle,
+                UserHandle.getUserHandleForUid(uid));
+        if (account == null
+                || !account.hasCapabilities(PhoneAccount.CAPABILITY_SUPPORTS_CALL_STREAMING)) {
+            throw new SecurityException(
+                    "The phone account handle in requesting can't support call streaming: "
+                            + handle);
+        }
+        return true;
+    }
+
+    /**
+     * @return whether to return early without doing the action/throwing
+     * @throws SecurityException same as {@link Context#enforceCallingOrSelfPermission}
+     */
+    private boolean enforceAnswerCallPermission(String packageName, int uid) {
+        try {
+            enforceModifyPermission();
+        } catch (SecurityException e) {
+            final String permission = Manifest.permission.ANSWER_PHONE_CALLS;
+            enforcePermission(permission);
+
+            final int opCode = AppOpsManager.permissionToOpCode(permission);
+            if (opCode != AppOpsManager.OP_NONE
+                    && mAppOpsManager.checkOp(opCode, uid, packageName)
+                    != AppOpsManager.MODE_ALLOWED) {
+                return false;
+            }
+        }
+        return true;
+    }
+
+    /**
+     * @return {@code true} if the app has the handover permission and has received runtime
+     * permission to perform that operation, {@code false}.
+     * @throws SecurityException same as {@link Context#enforceCallingOrSelfPermission}
+     */
+    private boolean enforceAcceptHandoverPermission(String packageName, int uid) {
+        mContext.enforceCallingOrSelfPermission(Manifest.permission.ACCEPT_HANDOVER,
+                "App requires ACCEPT_HANDOVER permission to accept handovers.");
+
+        final int opCode = AppOpsManager.permissionToOpCode(Manifest.permission.ACCEPT_HANDOVER);
+        return opCode == AppOpsManager.OP_ACCEPT_HANDOVER
+                && (mAppOpsManager.checkOp(opCode, uid, packageName) == AppOpsManager.MODE_ALLOWED);
+    }
+
+    @VisibleForTesting
+    public void setTransactionManager(TransactionManager transactionManager) {
         mTransactionManager = transactionManager;
     }
 
@@ -2787,10 +3070,6 @@ public class TelecomServiceImpl {
         return mBinderImpl;
     }
 
-    //
-    // Supporting methods for the ITelecomService interface implementation.
-    //
-
     private boolean isPhoneAccountHandleVisibleToCallingUser(
             PhoneAccountHandle phoneAccountUserHandle, UserHandle callingUser) {
         synchronized (mLock) {
@@ -2822,13 +3101,14 @@ public class TelecomServiceImpl {
         return false;
     }
 
-    private void acceptRingingCallInternal(int videoState, String packageName) {
+    private void acceptRingingCallInternal(int videoState, String packageName,
+            boolean isCallerPrivileged) {
         Call call = mCallsManager.getFirstCallWithState(CallState.RINGING,
                 CallState.SIMULATED_RINGING);
         if (call != null) {
-            if (call.isSelfManaged()) {
+            if (call.isSelfManaged() && !isCallerPrivileged) {
                 Log.addEvent(call, LogUtils.Events.REQUEST_ACCEPT,
-                        "self-mgd accept ignored from " + packageName);
+                        "self-mgd accept ignored from non-privileged app " + packageName);
                 return;
             }
 
@@ -2839,7 +3119,11 @@ public class TelecomServiceImpl {
         }
     }
 
-    private boolean endCallInternal(String callingPackage) {
+    //
+    // Supporting methods for the ITelecomService interface implementation.
+    //
+
+    private boolean endCallInternal(String callingPackage, boolean isCallerPrivileged) {
         // Always operate on the foreground call if one exists, otherwise get the first call in
         // priority order by call-state.
         Call call = mCallsManager.getForegroundCall();
@@ -2859,9 +3143,10 @@ public class TelecomServiceImpl {
                 return false;
             }
 
-            if (call.isSelfManaged()) {
+            if (call.isSelfManaged() && !isCallerPrivileged) {
                 Log.addEvent(call, LogUtils.Events.REQUEST_DISCONNECT,
-                        "self-mgd disconnect ignored from " + callingPackage);
+                        "self-mgd disconnect ignored from non-privileged app " +
+                                callingPackage);
                 return false;
             }
 
@@ -2880,14 +3165,14 @@ public class TelecomServiceImpl {
     // Enforce that the PhoneAccountHandle being passed in is both registered to the current user
     // and enabled.
     private void enforcePhoneAccountIsRegisteredEnabled(PhoneAccountHandle phoneAccountHandle,
-                                                        UserHandle callingUserHandle) {
+            UserHandle callingUserHandle) {
         PhoneAccount phoneAccount = mPhoneAccountRegistrar.getPhoneAccount(phoneAccountHandle,
                 callingUserHandle);
-        if(phoneAccount == null) {
+        if (phoneAccount == null) {
             EventLog.writeEvent(0x534e4554, "26864502", Binder.getCallingUid(), "R");
             throw new SecurityException("This PhoneAccountHandle is not registered for this user!");
         }
-        if(!phoneAccount.isEnabled()) {
+        if (!phoneAccount.isEnabled()) {
             EventLog.writeEvent(0x534e4554, "26864502", Binder.getCallingUid(), "E");
             throw new SecurityException("This PhoneAccountHandle is not enabled for this user!");
         }
@@ -2959,7 +3244,7 @@ public class TelecomServiceImpl {
     /**
      * helper method that compares the binder_uid to what the packageManager_uid reports for the
      * passed in packageName.
-     *
+     * <p>
      * returns true if the binder_uid matches the packageManager_uid records
      */
     private boolean callingUidMatchesPackageManagerRecords(String packageName) {
@@ -2967,13 +3252,12 @@ public class TelecomServiceImpl {
         int callingUid = Binder.getCallingUid();
         PackageManager pm;
         long token = Binder.clearCallingIdentity();
-        try{
+        try {
             pm = mContext.createContextAsUser(
                     UserHandle.getUserHandleForUid(callingUid), 0).getPackageManager();
-        }
-        catch (Exception e){
+        } catch (Exception e) {
             Log.i(this, "callingUidMatchesPackageManagerRecords:"
-                            + " createContextAsUser hit exception=[%s]", e.toString());
+                    + " createContextAsUser hit exception=[%s]", e.toString());
             return false;
         } finally {
             Binder.restoreCallingIdentity(token);
@@ -2988,7 +3272,7 @@ public class TelecomServiceImpl {
 
         if (packageUid != callingUid) {
             Log.i(this, "callingUidMatchesPackageManagerRecords: uid mismatch found for"
-                            + "packageName=[%s]. packageManager reports packageUid=[%d] but "
+                    + "packageName=[%s]. packageManager reports packageUid=[%d] but "
                     + "binder reports callingUid=[%d]", packageName, packageUid, callingUid);
         }
 
@@ -3079,7 +3363,7 @@ public class TelecomServiceImpl {
         boolean permissionsOk =
                 isCallerSimCallManagerForAnySim(account.getAccountHandle())
                         || mContext.checkCallingOrSelfPermission(REGISTER_SIM_SUBSCRIPTION)
-                                == PackageManager.PERMISSION_GRANTED;
+                        == PackageManager.PERMISSION_GRANTED;
         if (!prerequisiteCapabilitiesOk || !permissionsOk) {
             throw new SecurityException(
                     "Only SIM subscriptions and connection managers are allowed to declare "
@@ -3091,7 +3375,7 @@ public class TelecomServiceImpl {
     private void enforceRegisterSkipCallFiltering() {
         if (!isCallerSystemApp()) {
             throw new SecurityException(
-                "EXTRA_SKIP_CALL_FILTERING is only available to system apps.");
+                    "EXTRA_SKIP_CALL_FILTERING is only available to system apps.");
         }
     }
 
@@ -3261,9 +3545,9 @@ public class TelecomServiceImpl {
 
     private boolean isSelfManagedConnectionService(PhoneAccountHandle phoneAccountHandle) {
         if (phoneAccountHandle != null) {
-                PhoneAccount phoneAccount = mPhoneAccountRegistrar.getPhoneAccountUnchecked(
-                        phoneAccountHandle);
-                return phoneAccount != null && phoneAccount.isSelfManaged();
+            PhoneAccount phoneAccount = mPhoneAccountRegistrar.getPhoneAccountUnchecked(
+                    phoneAccountHandle);
+            return phoneAccount != null && phoneAccount.isSelfManaged();
         }
         return false;
     }
@@ -3365,10 +3649,11 @@ public class TelecomServiceImpl {
         // Note: Important to clear the calling identity since the code below calls into RoleManager
         // to check who holds the dialer role, and that requires MANAGE_ROLE_HOLDERS permission
         // which is a system permission.
+        int callingUserId = Binder.getCallingUserHandle().getIdentifier();
         long token = Binder.clearCallingIdentity();
         try {
             return mDefaultDialerCache.isDefaultOrSystemDialer(
-                    callingPackage, Binder.getCallingUserHandle().getIdentifier());
+                    callingPackage, callingUserId);
         } finally {
             Binder.restoreCallingIdentity(token);
         }
@@ -3399,7 +3684,7 @@ public class TelecomServiceImpl {
     }
 
     private void broadcastCallScreeningAppChangedIntent(String componentName,
-        boolean isDefault) {
+            boolean isDefault) {
         if (TextUtils.isEmpty(componentName)) {
             return;
         }
@@ -3408,11 +3693,11 @@ public class TelecomServiceImpl {
 
         if (broadcastComponentName != null) {
             Intent intent = new Intent(TelecomManager
-                .ACTION_DEFAULT_CALL_SCREENING_APP_CHANGED);
+                    .ACTION_DEFAULT_CALL_SCREENING_APP_CHANGED);
             intent.putExtra(TelecomManager
-                .EXTRA_IS_DEFAULT_CALL_SCREENING_APP, isDefault);
+                    .EXTRA_IS_DEFAULT_CALL_SCREENING_APP, isDefault);
             intent.putExtra(TelecomManager
-                .EXTRA_DEFAULT_CALL_SCREENING_APP_COMPONENT_NAME, componentName);
+                    .EXTRA_DEFAULT_CALL_SCREENING_APP_COMPONENT_NAME, componentName);
             intent.setPackage(broadcastComponentName.getPackageName());
             mContext.sendBroadcast(intent);
         }
@@ -3423,15 +3708,13 @@ public class TelecomServiceImpl {
         // incompatible types.
         if (icon != null && (icon.getType() == Icon.TYPE_URI
                 || icon.getType() == Icon.TYPE_URI_ADAPTIVE_BITMAP)) {
-            String encodedUser = icon.getUri().getEncodedUserInfo();
-            // If there is no encoded user, the URI is calling into the calling user space
-            if (encodedUser != null) {
-                int userId = Integer.parseInt(encodedUser);
-                if (userId != UserHandle.getUserId(Binder.getCallingUid())) {
-                    // If we are transcending the profile boundary, throw an error.
-                    throw new IllegalArgumentException("Attempting to register a phone account with"
-                            + " an image icon belonging to another user.");
-                }
+            int callingUserId = UserHandle.getCallingUserId();
+            int requestingUserId = StatusHints.getUserIdFromAuthority(
+                    icon.getUri().getAuthority(), callingUserId);
+            if(callingUserId != requestingUserId) {
+                // If we are transcending the profile boundary, throw an error.
+                throw new IllegalArgumentException("Attempting to register a phone account with"
+                        + " an image icon belonging to another user.");
             }
         }
     }
@@ -3451,4 +3734,40 @@ public class TelecomServiceImpl {
             }
         }
     }
+
+    private void logEvent(ApiStats.ApiEvent event) {
+        if (mFeatureFlags.telecomMetricsSupport()) {
+            mMetricsController.getApiStats().log(event);
+        }
+    }
+
+    public interface SubscriptionManagerAdapter {
+        int getDefaultVoiceSubId();
+    }
+
+    public interface SettingsSecureAdapter {
+        void putStringForUser(ContentResolver resolver, String name, String value, int userHandle);
+
+        String getStringForUser(ContentResolver resolver, String name, int userHandle);
+    }
+
+    static class SubscriptionManagerAdapterImpl implements SubscriptionManagerAdapter {
+        @Override
+        public int getDefaultVoiceSubId() {
+            return SubscriptionManager.getDefaultVoiceSubscriptionId();
+        }
+    }
+
+    static class SettingsSecureAdapterImpl implements SettingsSecureAdapter {
+        @Override
+        public void putStringForUser(ContentResolver resolver, String name, String value,
+                int userHandle) {
+            Settings.Secure.putStringForUser(resolver, name, value, userHandle);
+        }
+
+        @Override
+        public String getStringForUser(ContentResolver resolver, String name, int userHandle) {
+            return Settings.Secure.getStringForUser(resolver, name, userHandle);
+        }
+    }
 }
diff --git a/src/com/android/server/telecom/TelecomSystem.java b/src/com/android/server/telecom/TelecomSystem.java
index fd1053ff5..702088509 100644
--- a/src/com/android/server/telecom/TelecomSystem.java
+++ b/src/com/android/server/telecom/TelecomSystem.java
@@ -55,7 +55,7 @@ import com.android.server.telecom.ui.DisconnectedCallNotifier;
 import com.android.server.telecom.ui.IncomingCallNotifier;
 import com.android.server.telecom.ui.MissedCallNotifierImpl.MissedCallNotifierImplFactory;
 import com.android.server.telecom.ui.ToastFactory;
-import com.android.server.telecom.voip.TransactionManager;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import java.io.FileNotFoundException;
 import java.io.InputStream;
@@ -224,6 +224,7 @@ public class TelecomSystem {
             RoleManagerAdapter roleManagerAdapter,
             ContactsAsyncHelper.Factory contactsAsyncHelperFactory,
             DeviceIdleControllerAdapter deviceIdleControllerAdapter,
+            String sysUiPackageName,
             Ringer.AccessibilityManagerAdapter accessibilityManagerAdapter,
             Executor asyncTaskExecutor,
             Executor asyncCallAudioTaskExecutor,
@@ -245,8 +246,8 @@ public class TelecomSystem {
         // Wrap this in a try block to ensure session cleanup occurs in the case of error.
         try {
             mPhoneAccountRegistrar = new PhoneAccountRegistrar(mContext, mLock, defaultDialerCache,
-                    packageName -> AppLabelProxy.Util.getAppLabel(
-                            mContext.getPackageManager(), packageName), null, mFeatureFlags);
+                    (packageName, userHandle) -> AppLabelProxy.Util.getAppLabel(mContext,
+                            userHandle, packageName, mFeatureFlags), null, mFeatureFlags);
 
             mContactsAsyncHelper = contactsAsyncHelperFactory.create(
                     new ContactsAsyncHelper.ContentResolverAdapter() {
@@ -386,8 +387,8 @@ public class TelecomSystem {
 
             CallStreamingNotification callStreamingNotification =
                     new CallStreamingNotification(mContext,
-                            packageName -> AppLabelProxy.Util.getAppLabel(
-                                    mContext.getPackageManager(), packageName), asyncTaskExecutor);
+                            (packageName, userHandle) -> AppLabelProxy.Util.getAppLabel(mContext,
+                                    userHandle, packageName, mFeatureFlags), asyncTaskExecutor);
 
             mCallsManager = new CallsManager(
                     mContext,
@@ -502,7 +503,9 @@ public class TelecomSystem {
                     new TelecomServiceImpl.SettingsSecureAdapterImpl(),
                     featureFlags,
                     null,
-                    mLock);
+                    mLock,
+                    metricsController,
+                    sysUiPackageName);
         } finally {
             Log.endSession();
         }
diff --git a/src/com/android/server/telecom/Timeouts.java b/src/com/android/server/telecom/Timeouts.java
index 0ed71df80..ee1825009 100644
--- a/src/com/android/server/telecom/Timeouts.java
+++ b/src/com/android/server/telecom/Timeouts.java
@@ -447,12 +447,12 @@ public final class Timeouts {
 
     /**
      * Returns the duration of time a VoIP call can be in an intermediate state before Telecom will
-     * try to clean up the call.
+     * try to clean up the call.  The default is 2 minutes.
      * @return the state timeout in millis.
      */
     public static long getVoipCallIntermediateStateTimeoutMillis() {
         return DeviceConfig.getLong(DeviceConfig.NAMESPACE_TELEPHONY,
-                INTERMEDIATE_STATE_VOIP_NORMAL_TIMEOUT_MILLIS, 60000L);
+                INTERMEDIATE_STATE_VOIP_NORMAL_TIMEOUT_MILLIS, 120000L);
     }
 
     /**
diff --git a/src/com/android/server/telecom/TransactionalServiceRepository.java b/src/com/android/server/telecom/TransactionalServiceRepository.java
index 793840e06..5ae459e21 100644
--- a/src/com/android/server/telecom/TransactionalServiceRepository.java
+++ b/src/com/android/server/telecom/TransactionalServiceRepository.java
@@ -20,6 +20,8 @@ import android.telecom.Log;
 import android.telecom.PhoneAccountHandle;
 
 import com.android.internal.telecom.ICallEventCallback;
+import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import java.util.HashMap;
 import java.util.Map;
@@ -32,8 +34,10 @@ public class TransactionalServiceRepository {
     private static final String TAG = TransactionalServiceRepository.class.getSimpleName();
     private static final Map<PhoneAccountHandle, TransactionalServiceWrapper> mServiceLookupTable =
             new HashMap<>();
+    private final FeatureFlags mFlags;
 
-    public TransactionalServiceRepository() {
+    public TransactionalServiceRepository(FeatureFlags flags) {
+        mFlags = flags;
     }
 
     public TransactionalServiceWrapper addNewCallForTransactionalServiceWrapper
@@ -45,7 +49,8 @@ public class TransactionalServiceRepository {
         if (!hasExistingServiceWrapper(phoneAccountHandle)) {
             Log.d(TAG, "creating a new TSW; handle=[%s]", phoneAccountHandle);
             service = new TransactionalServiceWrapper(callEventCallback,
-                    callsManager, phoneAccountHandle, call, this);
+                    callsManager, phoneAccountHandle, call, this,
+                    TransactionManager.getInstance(), mFlags.enableCallSequencing());
         } else {
             Log.d(TAG, "add a new call to an existing TSW; handle=[%s]", phoneAccountHandle);
             service = getTransactionalServiceWrapper(phoneAccountHandle);
diff --git a/src/com/android/server/telecom/TransactionalServiceWrapper.java b/src/com/android/server/telecom/TransactionalServiceWrapper.java
index b73de2345..cf5ef41c6 100644
--- a/src/com/android/server/telecom/TransactionalServiceWrapper.java
+++ b/src/com/android/server/telecom/TransactionalServiceWrapper.java
@@ -39,23 +39,18 @@ import androidx.annotation.VisibleForTesting;
 
 import com.android.internal.telecom.ICallControl;
 import com.android.internal.telecom.ICallEventCallback;
-import com.android.server.telecom.voip.CallEventCallbackAckTransaction;
-import com.android.server.telecom.voip.EndpointChangeTransaction;
-import com.android.server.telecom.voip.HoldCallTransaction;
-import com.android.server.telecom.voip.EndCallTransaction;
-import com.android.server.telecom.voip.MaybeHoldCallForNewCallTransaction;
-import com.android.server.telecom.voip.RequestNewActiveCallTransaction;
-import com.android.server.telecom.voip.SerialTransaction;
-import com.android.server.telecom.voip.SetMuteStateTransaction;
-import com.android.server.telecom.voip.RequestVideoStateTransaction;
-import com.android.server.telecom.voip.TransactionManager;
-import com.android.server.telecom.voip.VoipCallTransaction;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
-
-import java.util.ArrayList;
-import java.util.List;
+import com.android.server.telecom.callsequencing.TransactionalCallSequencingAdapter;
+import com.android.server.telecom.callsequencing.voip.CallEventCallbackAckTransaction;
+import com.android.server.telecom.callsequencing.voip.EndpointChangeTransaction;
+import com.android.server.telecom.callsequencing.voip.SetMuteStateTransaction;
+import com.android.server.telecom.callsequencing.voip.RequestVideoStateTransaction;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+
 import java.util.Locale;
 import java.util.Set;
+import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ConcurrentHashMap;
 
 /**
@@ -73,6 +68,8 @@ public class TransactionalServiceWrapper implements
     public static final String DISCONNECT = "Disconnect";
     public static final String START_STREAMING = "StartStreaming";
     public static final String REQUEST_VIDEO_STATE = "RequestVideoState";
+    public static final String SET_MUTE_STATE = "SetMuteState";
+    public static final String CALL_ENDPOINT_CHANGE = "CallEndpointChange";
 
     // CallEventCallback : Telecom --> Client (ex. voip app)
     public static final String ON_SET_ACTIVE = "onSetActive";
@@ -80,6 +77,7 @@ public class TransactionalServiceWrapper implements
     public static final String ON_ANSWER = "onAnswer";
     public static final String ON_DISCONNECT = "onDisconnect";
     public static final String ON_STREAMING_STARTED = "onStreamingStarted";
+    public static final String STOP_STREAMING = "stopStreaming";
 
     private final CallsManager mCallsManager;
     private final ICallEventCallback mICallEventCallback;
@@ -93,6 +91,7 @@ public class TransactionalServiceWrapper implements
     // needs to be non-final for testing
     private TransactionManager mTransactionManager;
     private CallStreamingController mStreamingController;
+    private final TransactionalCallSequencingAdapter mCallSequencingAdapter;
 
 
     // Each TransactionalServiceWrapper should have their own Binder.DeathRecipient to clean up
@@ -108,26 +107,24 @@ public class TransactionalServiceWrapper implements
 
     public TransactionalServiceWrapper(ICallEventCallback callEventCallback,
             CallsManager callsManager, PhoneAccountHandle phoneAccountHandle, Call call,
-            TransactionalServiceRepository repo) {
+            TransactionalServiceRepository repo, TransactionManager transactionManager,
+            boolean isCallSequencingEnabled) {
         // passed args
         mICallEventCallback = callEventCallback;
         mCallsManager = callsManager;
         mPhoneAccountHandle = phoneAccountHandle;
         mTrackedCalls.put(call.getId(), call); // service is now tracking its first call
         mRepository = repo;
+        mTransactionManager = transactionManager;
         // init instance vars
         mPackageName = phoneAccountHandle.getComponentName().getPackageName();
-        mTransactionManager = TransactionManager.getInstance();
         mStreamingController = mCallsManager.getCallStreamingController();
         mLock = mCallsManager.getLock();
+        mCallSequencingAdapter = new TransactionalCallSequencingAdapter(mTransactionManager,
+                mCallsManager, isCallSequencingEnabled);
         setDeathRecipient(callEventCallback);
     }
 
-    @VisibleForTesting
-    public void setTransactionManager(TransactionManager transactionManager) {
-        mTransactionManager = transactionManager;
-    }
-
     public TransactionManager getTransactionManager() {
         return mTransactionManager;
     }
@@ -170,11 +167,7 @@ public class TransactionalServiceWrapper implements
     }
 
     private void cleanupTransactionalServiceWrapper() {
-        for (Call call : mTrackedCalls.values()) {
-            mCallsManager.markCallAsDisconnected(call,
-                    new DisconnectCause(DisconnectCause.ERROR, "process died"));
-            mCallsManager.removeCall(call); // This will clear mTrackedCalls && ClientTWS
-        }
+        mCallSequencingAdapter.cleanup(mTrackedCalls.values());
     }
 
     /***
@@ -184,8 +177,7 @@ public class TransactionalServiceWrapper implements
      */
     private final ICallControl mICallControl = new ICallControl.Stub() {
         @Override
-        public void setActive(String callId, android.os.ResultReceiver callback)
-                throws RemoteException {
+        public void setActive(String callId, android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.sA");
@@ -197,8 +189,8 @@ public class TransactionalServiceWrapper implements
         }
 
         @Override
-        public void answer(int videoState, String callId, android.os.ResultReceiver callback)
-                throws RemoteException {
+
+        public void answer(int videoState, String callId, android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.a");
@@ -210,8 +202,7 @@ public class TransactionalServiceWrapper implements
         }
 
         @Override
-        public void setInactive(String callId, android.os.ResultReceiver callback)
-                throws RemoteException {
+        public void setInactive(String callId, android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.sI");
@@ -224,8 +215,7 @@ public class TransactionalServiceWrapper implements
 
         @Override
         public void disconnect(String callId, DisconnectCause disconnectCause,
-                android.os.ResultReceiver callback)
-                throws RemoteException {
+                android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.d");
@@ -237,12 +227,11 @@ public class TransactionalServiceWrapper implements
         }
 
         @Override
-        public void setMuteState(boolean isMuted, android.os.ResultReceiver callback)
-                throws RemoteException {
+        public void setMuteState(boolean isMuted, android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.sMS");
-                addTransactionsToManager(
+                addTransactionsToManager(SET_MUTE_STATE,
                         new SetMuteStateTransaction(mCallsManager, isMuted), callback);
             } finally {
                 Binder.restoreCallingIdentity(token);
@@ -251,8 +240,7 @@ public class TransactionalServiceWrapper implements
         }
 
         @Override
-        public void startCallStreaming(String callId, android.os.ResultReceiver callback)
-                throws RemoteException {
+        public void startCallStreaming(String callId, android.os.ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.sCS");
@@ -264,8 +252,7 @@ public class TransactionalServiceWrapper implements
         }
 
         @Override
-        public void requestVideoState(int videoState, String callId, ResultReceiver callback)
-                throws RemoteException {
+        public void requestVideoState(int videoState, String callId, ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.rVS");
@@ -283,27 +270,29 @@ public class TransactionalServiceWrapper implements
             if (call != null) {
                 switch (action) {
                     case SET_ACTIVE:
-                        handleCallControlNewCallFocusTransactions(call, SET_ACTIVE,
-                                false /* isAnswer */, 0/*VideoState (ignored)*/, callback);
+                        mCallSequencingAdapter.setActive(call,
+                                getCompleteReceiver(action, callback));
                         break;
                     case ANSWER:
-                        handleCallControlNewCallFocusTransactions(call, ANSWER,
-                                true /* isAnswer */, (int) objects[0] /*VideoState*/, callback);
+                        mCallSequencingAdapter.setAnswered(call, (int) objects[0] /*VideoState*/,
+                                getCompleteReceiver(action, callback));
                         break;
                     case DISCONNECT:
-                        addTransactionsToManager(new EndCallTransaction(mCallsManager,
-                                (DisconnectCause) objects[0], call), callback);
+                        DisconnectCause dc = (DisconnectCause) objects[0];
+                        mCallSequencingAdapter.setDisconnected(call, dc,
+                                getCompleteReceiver(action, callback));
                         break;
                     case SET_INACTIVE:
-                        addTransactionsToManager(
-                                new HoldCallTransaction(mCallsManager, call), callback);
+                        mCallSequencingAdapter.setInactive(call,
+                                getCompleteReceiver(action,callback));
                         break;
                     case START_STREAMING:
-                        addTransactionsToManager(mStreamingController.getStartStreamingTransaction(mCallsManager,
-                                TransactionalServiceWrapper.this, call, mLock), callback);
+                        addTransactionsToManager(action,
+                                mStreamingController.getStartStreamingTransaction(mCallsManager,
+                                TransactionalServiceWrapper.this, call, mLock),  callback);
                         break;
                     case REQUEST_VIDEO_STATE:
-                        addTransactionsToManager(
+                        addTransactionsToManager(action,
                                 new RequestVideoStateTransaction(mCallsManager, call,
                                         (int) objects[0]), callback);
                         break;
@@ -321,40 +310,13 @@ public class TransactionalServiceWrapper implements
             }
         }
 
-        // The client is request their VoIP call state go ACTIVE/ANSWERED.
-        // This request is originating from the VoIP application.
-        private void handleCallControlNewCallFocusTransactions(Call call, String action,
-                boolean isAnswer, int potentiallyNewVideoState, ResultReceiver callback) {
-            mTransactionManager.addTransaction(
-                    createSetActiveTransactions(call, true /* isCallControlRequest */),
-                    new OutcomeReceiver<>() {
-                        @Override
-                        public void onResult(VoipCallTransactionResult result) {
-                            Log.i(TAG, String.format(Locale.US,
-                                    "%s: onResult: callId=[%s]", action, call.getId()));
-                            if (isAnswer) {
-                                call.setVideoState(potentiallyNewVideoState);
-                            }
-                            callback.send(TELECOM_TRANSACTION_SUCCESS, new Bundle());
-                        }
-
-                        @Override
-                        public void onError(CallException exception) {
-                            Bundle extras = new Bundle();
-                            extras.putParcelable(TRANSACTION_EXCEPTION_KEY, exception);
-                            callback.send(exception == null ? CallException.CODE_ERROR_UNKNOWN :
-                                    exception.getCode(), extras);
-                        }
-                    });
-        }
-
         @Override
         public void requestCallEndpointChange(CallEndpoint endpoint, ResultReceiver callback) {
             long token = Binder.clearCallingIdentity();
             try {
                 Log.startSession("TSW.rCEC");
-                addTransactionsToManager(new EndpointChangeTransaction(endpoint, mCallsManager),
-                        callback);
+                addTransactionsToManager(CALL_ENDPOINT_CHANGE,
+                        new EndpointChangeTransaction(endpoint, mCallsManager), callback);
             } finally {
                 Binder.restoreCallingIdentity(token);
                 Log.endSession();
@@ -384,26 +346,31 @@ public class TransactionalServiceWrapper implements
         }
     };
 
-    private void addTransactionsToManager(VoipCallTransaction transaction,
+    private void addTransactionsToManager(String action, CallTransaction transaction,
             ResultReceiver callback) {
         Log.d(TAG, "addTransactionsToManager");
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(transaction, getCompleteReceiver(action, callback));
+    }
 
-        mTransactionManager.addTransaction(transaction, new OutcomeReceiver<>() {
+    private OutcomeReceiver<CallTransactionResult, CallException> getCompleteReceiver(
+            String action, ResultReceiver callback) {
+        return new OutcomeReceiver<>() {
             @Override
-            public void onResult(VoipCallTransactionResult result) {
-                Log.d(TAG, "addTransactionsToManager: onResult:");
+            public void onResult(CallTransactionResult result) {
+                Log.d(TAG, "completeReceiver: onResult[" + action + "]:" + result);
                 callback.send(TELECOM_TRANSACTION_SUCCESS, new Bundle());
             }
 
             @Override
             public void onError(CallException exception) {
-                Log.d(TAG, "addTransactionsToManager: onError");
+                Log.d(TAG, "completeReceiver: onError[" + action + "]" + exception);
                 Bundle extras = new Bundle();
                 extras.putParcelable(TRANSACTION_EXCEPTION_KEY, exception);
                 callback.send(exception == null ? CallException.CODE_ERROR_UNKNOWN :
                         exception.getCode(), extras);
             }
-        });
+        };
     }
 
     public ICallControl getICallControl() {
@@ -416,89 +383,53 @@ public class TransactionalServiceWrapper implements
      **********************************************************************************************
      */
 
-    public void onSetActive(Call call) {
+    public CompletableFuture<Boolean> onSetActive(Call call) {
+        CallTransaction callTransaction = new CallEventCallbackAckTransaction(
+                mICallEventCallback, ON_SET_ACTIVE, call.getId(), mLock);
+        CompletableFuture<Boolean> onSetActiveFuture;
         try {
             Log.startSession("TSW.oSA");
             Log.d(TAG, String.format(Locale.US, "onSetActive: callId=[%s]", call.getId()));
-            handleCallEventCallbackNewFocus(call, ON_SET_ACTIVE, false /*isAnswerRequest*/,
-                    0 /*VideoState*/);
+            onSetActiveFuture = mCallSequencingAdapter.onSetActive(call,
+                    callTransaction, result ->
+                            Log.i(TAG, String.format(Locale.US,
+                                    "%s: onResult: callId=[%s], result=[%s]", ON_SET_ACTIVE,
+                                    call.getId(), result)));
         } finally {
             Log.endSession();
         }
+        return onSetActiveFuture;
     }
 
     public void onAnswer(Call call, int videoState) {
         try {
             Log.startSession("TSW.oA");
             Log.d(TAG, String.format(Locale.US, "onAnswer: callId=[%s]", call.getId()));
-            handleCallEventCallbackNewFocus(call, ON_ANSWER, true /*isAnswerRequest*/,
-                    videoState /*VideoState*/);
+            mCallSequencingAdapter.onSetAnswered(call, videoState,
+                    new CallEventCallbackAckTransaction(mICallEventCallback,
+                            ON_ANSWER, call.getId(), videoState, mLock),
+                    result -> Log.i(TAG, String.format(Locale.US,
+                            "%s: onResult: callId=[%s], result=[%s]",
+                            ON_ANSWER, call.getId(), result)));
         } finally {
             Log.endSession();
         }
     }
 
-    // handle a CallEventCallback to set a call ACTIVE/ANSWERED. Must get ack from client since the
-    // request has come from another source (ex. Android Auto is requesting a call to go active)
-    private void handleCallEventCallbackNewFocus(Call call, String action, boolean isAnswerRequest,
-            int potentiallyNewVideoState) {
-        // save CallsManager state before sending client state changes
-        Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
-        boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
-
-        SerialTransaction serialTransactions = createSetActiveTransactions(call,
-                false /* isCallControlRequest */);
-        // 3. get ack from client (that the requested call can go active)
-        if (isAnswerRequest) {
-            serialTransactions.appendTransaction(
-                    new CallEventCallbackAckTransaction(mICallEventCallback,
-                            action, call.getId(), potentiallyNewVideoState, mLock));
-        } else {
-            serialTransactions.appendTransaction(
-                    new CallEventCallbackAckTransaction(mICallEventCallback,
-                            action, call.getId(), mLock));
-        }
-
-        // do CallsManager workload before asking client and
-        //   reset CallsManager state if client does NOT ack
-        mTransactionManager.addTransaction(serialTransactions,
-                new OutcomeReceiver<>() {
-                    @Override
-                    public void onResult(VoipCallTransactionResult result) {
-                        Log.i(TAG, String.format(Locale.US,
-                                "%s: onResult: callId=[%s]", action, call.getId()));
-                        if (isAnswerRequest) {
-                            call.setVideoState(potentiallyNewVideoState);
-                        }
-                    }
-
-                    @Override
-                    public void onError(CallException exception) {
-                        if (isAnswerRequest) {
-                            // This also sends the signal to untrack from TSW and the client_TSW
-                            removeCallFromCallsManager(call,
-                                    new DisconnectCause(DisconnectCause.REJECTED,
-                                            "client rejected to answer the call;"
-                                                    + " force disconnecting"));
-                        } else {
-                            mCallsManager.markCallAsOnHold(call);
-                        }
-                        maybeResetForegroundCall(foregroundCallBeforeSwap, wasActive);
-                    }
-                });
-    }
-
-
-    public void onSetInactive(Call call) {
+    public CompletableFuture<Boolean> onSetInactive(Call call) {
+        CallTransaction callTransaction = new CallEventCallbackAckTransaction(
+                mICallEventCallback, ON_SET_INACTIVE, call.getId(), mLock);
+        CompletableFuture<Boolean> onSetInactiveFuture;
         try {
             Log.startSession("TSW.oSI");
             Log.i(TAG, String.format(Locale.US, "onSetInactive: callId=[%s]", call.getId()));
-            mTransactionManager.addTransaction(
-                    new CallEventCallbackAckTransaction(mICallEventCallback,
-                            ON_SET_INACTIVE, call.getId(), mLock), new OutcomeReceiver<>() {
+            onSetInactiveFuture = mCallSequencingAdapter.onSetInactive(call,
+                    callTransaction, new OutcomeReceiver<>() {
                         @Override
-                        public void onResult(VoipCallTransactionResult result) {
-                            mCallsManager.markCallAsOnHold(call);
+                        public void onResult(CallTransactionResult result) {
+                            Log.i(TAG, String.format(Locale.US, "onSetInactive: callId=[%s]"
+                                            + ", result=[%s]",
+                                    call.getId(), result));
                         }
 
                         @Override
@@ -510,30 +441,26 @@ public class TransactionalServiceWrapper implements
         } finally {
             Log.endSession();
         }
+        return onSetInactiveFuture;
     }
 
-    public void onDisconnect(Call call, DisconnectCause cause) {
+    public CompletableFuture<Boolean> onDisconnect(Call call,
+            DisconnectCause cause) {
+        CallTransaction callTransaction = new CallEventCallbackAckTransaction(
+                mICallEventCallback, ON_DISCONNECT, call.getId(), cause, mLock);
+        CompletableFuture<Boolean> onDisconnectFuture;
         try {
             Log.startSession("TSW.oD");
             Log.d(TAG, String.format(Locale.US, "onDisconnect: callId=[%s]", call.getId()));
-
-            mTransactionManager.addTransaction(
-                    new CallEventCallbackAckTransaction(mICallEventCallback, ON_DISCONNECT,
-                            call.getId(), cause, mLock), new OutcomeReceiver<>() {
-                        @Override
-                        public void onResult(VoipCallTransactionResult result) {
-                            removeCallFromCallsManager(call, cause);
-                        }
-
-                        @Override
-                        public void onError(CallException exception) {
-                            removeCallFromCallsManager(call, cause);
-                        }
-                    }
-            );
+            onDisconnectFuture = mCallSequencingAdapter.onSetDisconnected(call, cause,
+                    callTransaction,
+                    result -> Log.i(TAG, String.format(Locale.US,
+                            "%s: onResult: callId=[%s], result=[%s]",
+                            ON_DISCONNECT, call.getId(), result)));
         } finally {
             Log.endSession();
         }
+        return onDisconnectFuture;
     }
 
     public void onCallStreamingStarted(Call call) {
@@ -546,7 +473,7 @@ public class TransactionalServiceWrapper implements
                     new CallEventCallbackAckTransaction(mICallEventCallback, ON_STREAMING_STARTED,
                             call.getId(), mLock), new OutcomeReceiver<>() {
                         @Override
-                        public void onResult(VoipCallTransactionResult result) {
+                        public void onResult(CallTransactionResult result) {
                         }
 
                         @Override
@@ -641,35 +568,6 @@ public class TransactionalServiceWrapper implements
      **                                Helpers                                                  **
      **********************************************************************************************
      */
-    private void maybeResetForegroundCall(Call foregroundCallBeforeSwap, boolean wasActive) {
-        if (foregroundCallBeforeSwap == null) {
-            return;
-        }
-        if (wasActive && !foregroundCallBeforeSwap.isActive()) {
-            mCallsManager.markCallAsActive(foregroundCallBeforeSwap);
-        }
-    }
-
-    private void removeCallFromCallsManager(Call call, DisconnectCause cause) {
-        if (cause.getCode() != DisconnectCause.REJECTED) {
-            mCallsManager.markCallAsDisconnected(call, cause);
-        }
-        mCallsManager.removeCall(call);
-    }
-
-    private SerialTransaction createSetActiveTransactions(Call call, boolean isCallControlRequest) {
-        // create list for multiple transactions
-        List<VoipCallTransaction> transactions = new ArrayList<>();
-
-        // potentially hold the current active call in order to set a new call (active/answered)
-        transactions.add(
-                new MaybeHoldCallForNewCallTransaction(mCallsManager, call, isCallControlRequest));
-        // And request a new focus call update
-        transactions.add(new RequestNewActiveCallTransaction(mCallsManager, call));
-
-        return new SerialTransaction(transactions, mLock);
-    }
-
     private void setDeathRecipient(ICallEventCallback callEventCallback) {
         try {
             callEventCallback.asBinder().linkToDeath(mAppDeathListener, 0);
@@ -720,9 +618,10 @@ public class TransactionalServiceWrapper implements
     public void stopCallStreaming(Call call) {
         Log.i(this, "stopCallStreaming; callid=%s", call.getId());
         if (call != null && call.isStreaming()) {
-            VoipCallTransaction stopStreamingTransaction = mStreamingController
+            CallTransaction stopStreamingTransaction = mStreamingController
                     .getStopStreamingTransaction(call, mLock);
-            addTransactionsToManager(stopStreamingTransaction, new ResultReceiver(null));
+            addTransactionsToManager(STOP_STREAMING, stopStreamingTransaction,
+                    new ResultReceiver(null));
         }
     }
 }
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
index 0f27dad17..f4d6041da 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
@@ -308,19 +308,19 @@ public class BluetoothDeviceManager {
         mFeatureFlags = featureFlags;
         if (bluetoothAdapter != null) {
             mBluetoothAdapter = bluetoothAdapter;
-            if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
-                mBluetoothHeadsetFuture = new CompletableFuture<>();
-            }
             bluetoothAdapter.getProfileProxy(context, mBluetoothProfileServiceListener,
                     BluetoothProfile.HEADSET);
             bluetoothAdapter.getProfileProxy(context, mBluetoothProfileServiceListener,
                     BluetoothProfile.HEARING_AID);
             bluetoothAdapter.getProfileProxy(context, mBluetoothProfileServiceListener,
                     BluetoothProfile.LE_AUDIO);
-            mAudioManager = context.getSystemService(AudioManager.class);
-            mExecutor = context.getMainExecutor();
-            mCommunicationDeviceTracker = communicationDeviceTracker;
         }
+        if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+            mBluetoothHeadsetFuture = new CompletableFuture<>();
+        }
+        mAudioManager = context.getSystemService(AudioManager.class);
+        mExecutor = context.getMainExecutor();
+        mCommunicationDeviceTracker = communicationDeviceTracker;
     }
 
     public void setBluetoothRouteManager(BluetoothRouteManager brm) {
@@ -519,7 +519,10 @@ public class BluetoothDeviceManager {
                 Log.i(this, "onDeviceConnected: Adding device with address: %s and devicetype=%s",
                         device, getDeviceTypeString(deviceType));
                 targetDeviceMap.put(device.getAddress(), device);
-                mBluetoothRouteManager.onDeviceAdded(device.getAddress());
+                if (!mFeatureFlags.keepBluetoothDevicesCacheUpdated()
+                        || !mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+                    mBluetoothRouteManager.onDeviceAdded(device.getAddress());
+                }
             }
         }
     }
@@ -551,7 +554,10 @@ public class BluetoothDeviceManager {
                 Log.i(this, "onDeviceDisconnected: Removing device with address: %s, devicetype=%s",
                         device, getDeviceTypeString(deviceType));
                 targetDeviceMap.remove(device.getAddress());
-                mBluetoothRouteManager.onDeviceLost(device.getAddress());
+                if (!mFeatureFlags.keepBluetoothDevicesCacheUpdated()
+                        || !mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+                    mBluetoothRouteManager.onDeviceLost(device.getAddress());
+                }
             }
         }
     }
@@ -759,7 +765,7 @@ public class BluetoothDeviceManager {
             Log.w(this, "setCommunicationDeviceForAddress: Device %s not found.", address);
             return false;
         }
-        if (mAudioManager.getCommunicationDevice().equals(deviceInfo)) {
+        if (deviceInfo.equals(mAudioManager.getCommunicationDevice())) {
             Log.i(this, "setCommunicationDeviceForAddress: Device %s already active.", address);
             return true;
         }
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
index cd52889d2..1cea5317e 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
@@ -211,6 +211,9 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
             if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_DEVICE_ADDED,
                         audioRouteType, device);
+                if (mFeatureFlags.keepBluetoothDevicesCacheUpdated()) {
+                    mBluetoothDeviceManager.onDeviceConnected(device, deviceType);
+                }
             } else {
                 mBluetoothDeviceManager.onDeviceConnected(device, deviceType);
             }
@@ -219,6 +222,9 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
             if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_DEVICE_REMOVED,
                         audioRouteType, device);
+                if (mFeatureFlags.keepBluetoothDevicesCacheUpdated()) {
+                    mBluetoothDeviceManager.onDeviceDisconnected(device, deviceType);
+                }
             } else {
                 mBluetoothDeviceManager.onDeviceDisconnected(device, deviceType);
             }
@@ -252,10 +258,12 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
             CallAudioRouteController audioRouteController = (CallAudioRouteController)
                     mCallAudioRouteAdapter;
             if (device == null) {
+                // Update the active device cache immediately.
                 audioRouteController.updateActiveBluetoothDevice(new Pair(audioRouteType, null));
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_GONE,
                         audioRouteType);
             } else {
+                // Update the active device cache immediately.
                 audioRouteController.updateActiveBluetoothDevice(
                         new Pair(audioRouteType, device.getAddress()));
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
@@ -265,11 +273,17 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                     if (!mBluetoothDeviceManager.setCommunicationDeviceForAddress(
                             device.getAddress())) {
                         Log.i(this, "handleActiveDeviceChanged: Failed to set "
-                                + "communication device for %s. Sending PENDING_ROUTE_FAILED to "
-                                + "pending audio route.", device);
-                        mCallAudioRouteAdapter.getPendingAudioRoute()
-                                .onMessageReceived(new Pair<>(PENDING_ROUTE_FAILED,
-                                        device.getAddress()), device.getAddress());
+                                + "communication device for %s.", device);
+                        if (!mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()) {
+                            Log.i(this, "Sending PENDING_ROUTE_FAILED "
+                                    + "to pending audio route.");
+                            mCallAudioRouteAdapter.getPendingAudioRoute()
+                                    .onMessageReceived(new Pair<>(PENDING_ROUTE_FAILED,
+                                            device.getAddress()), device.getAddress());
+                        } else {
+                            Log.i(this, "Refrain from sending PENDING_ROUTE_FAILED"
+                                    + " to pending audio route.");
+                        }
                     } else {
                         // Track the currently set communication device.
                         int routeType = deviceType == BluetoothDeviceManager.DEVICE_TYPE_LE_AUDIO
diff --git a/src/com/android/server/telecom/callfiltering/BlockCheckerFilter.java b/src/com/android/server/telecom/callfiltering/BlockCheckerFilter.java
index 5beb5f003..7e3837dd3 100644
--- a/src/com/android/server/telecom/callfiltering/BlockCheckerFilter.java
+++ b/src/com/android/server/telecom/callfiltering/BlockCheckerFilter.java
@@ -21,6 +21,7 @@ import android.net.Uri;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.os.UserManager;
 import android.provider.BlockedNumberContract;
 import android.provider.CallLog;
 import android.telecom.CallerInfo;
@@ -29,6 +30,7 @@ import android.telecom.TelecomManager;
 
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallerInfoLookupHelper;
+import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.LogUtils;
 import com.android.server.telecom.LoggedHandlerExecutor;
 import com.android.server.telecom.settings.BlockedNumbersUtil;
@@ -45,6 +47,7 @@ public class BlockCheckerFilter extends CallFilter {
     private boolean mContactExists;
     private HandlerThread mHandlerThread;
     private Handler mHandler;
+    private FeatureFlags mFeatureFlags;
 
     public static final long CALLER_INFO_QUERY_TIMEOUT = 5000;
 
@@ -105,7 +108,7 @@ public class BlockCheckerFilter extends CallFilter {
 
     public BlockCheckerFilter(Context context, Call call,
             CallerInfoLookupHelper callerInfoLookupHelper,
-            BlockCheckerAdapter blockCheckerAdapter) {
+            BlockCheckerAdapter blockCheckerAdapter, FeatureFlags featureFlags) {
         mCall = call;
         mContext = context;
         mCallerInfoLookupHelper = callerInfoLookupHelper;
@@ -114,6 +117,7 @@ public class BlockCheckerFilter extends CallFilter {
         mHandlerThread = new HandlerThread(TAG);
         mHandlerThread.start();
         mHandler = new Handler(mHandlerThread.getLooper());
+        mFeatureFlags = featureFlags;
     }
 
     @Override
@@ -121,7 +125,13 @@ public class BlockCheckerFilter extends CallFilter {
         Log.addEvent(mCall, LogUtils.Events.BLOCK_CHECK_INITIATED);
         CompletableFuture<CallFilteringResult> resultFuture = new CompletableFuture<>();
         Bundle extras = new Bundle();
-        if (BlockedNumbersUtil.isEnhancedCallBlockingEnabledByPlatform(mContext)) {
+        final Context userContext;
+        if (mFeatureFlags.telecomMainUserInBlockCheck()) {
+            userContext = mContext.createContextAsUser(mCall.getAssociatedUser(), 0);
+        } else {
+            userContext = mContext;
+        }
+        if (BlockedNumbersUtil.isEnhancedCallBlockingEnabledByPlatform(userContext)) {
             int presentation = mCall.getHandlePresentation();
             extras.putInt(BlockedNumberContract.EXTRA_CALL_PRESENTATION, presentation);
             if (presentation == TelecomManager.PRESENTATION_ALLOWED) {
@@ -132,7 +142,7 @@ public class BlockCheckerFilter extends CallFilter {
                                 if (info != null && info.contactExists) {
                                     mContactExists = true;
                                 }
-                                getBlockStatus(resultFuture);
+                                getBlockStatus(resultFuture, userContext);
                             }
 
                             @Override
@@ -141,22 +151,22 @@ public class BlockCheckerFilter extends CallFilter {
                             }
                         });
             } else {
-                getBlockStatus(resultFuture);
+                getBlockStatus(resultFuture, userContext);
             }
         } else {
-            getBlockStatus(resultFuture);
+            getBlockStatus(resultFuture, userContext);
         }
         return resultFuture;
     }
 
     private void getBlockStatus(
-            CompletableFuture<CallFilteringResult> resultFuture) {
+            CompletableFuture<CallFilteringResult> resultFuture, Context userContext) {
         // Set presentation and if contact exists. Used in determining if the system should block
         // the passed in number. Use default values as they would be returned if the keys didn't
         // exist in the extras to maintain existing behavior.
         int presentation;
         boolean isNumberInContacts;
-        if (BlockedNumbersUtil.isEnhancedCallBlockingEnabledByPlatform(mContext)) {
+        if (BlockedNumbersUtil.isEnhancedCallBlockingEnabledByPlatform(userContext)) {
             presentation = mCall.getHandlePresentation();
         } else {
             presentation = 0;
@@ -173,7 +183,7 @@ public class BlockCheckerFilter extends CallFilter {
                 mCall.getHandle().getSchemeSpecificPart();
 
         CompletableFuture.supplyAsync(
-                () -> mBlockCheckerAdapter.getBlockStatus(mContext, number,
+                () -> mBlockCheckerAdapter.getBlockStatus(userContext, number,
                         presentation, isNumberInContacts),
                 new LoggedHandlerExecutor(mHandler, "BCF.gBS", null))
                 .thenApplyAsync((x) -> completeResult(resultFuture, x),
diff --git a/src/com/android/server/telecom/callfiltering/CallScreeningServiceFilter.java b/src/com/android/server/telecom/callfiltering/CallScreeningServiceFilter.java
index f07c0aa42..efac87d1a 100644
--- a/src/com/android/server/telecom/callfiltering/CallScreeningServiceFilter.java
+++ b/src/com/android/server/telecom/callfiltering/CallScreeningServiceFilter.java
@@ -269,7 +269,8 @@ public class CallScreeningServiceFilter extends CallFilter {
         mContext = context;
         mPackageManager = mContext.getPackageManager();
         mCallsManager = callsManager;
-        mAppName = appLabelProxy.getAppLabel(mPackageName);
+        mAppName = appLabelProxy.getAppLabel(mPackageName,
+                mCall.getAssociatedUser());
         mParcelableCallUtilsConverter = parcelableCallUtilsConverter;
     }
 
diff --git a/src/com/android/server/telecom/callsequencing/CallSequencingController.java b/src/com/android/server/telecom/callsequencing/CallSequencingController.java
new file mode 100644
index 000000000..2f0ae4554
--- /dev/null
+++ b/src/com/android/server/telecom/callsequencing/CallSequencingController.java
@@ -0,0 +1,82 @@
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
+package com.android.server.telecom.callsequencing;
+
+import android.os.Handler;
+import android.os.HandlerThread;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallsManager;
+
+import java.util.concurrent.CompletableFuture;
+
+/**
+ * Controls the sequencing between calls when moving between the user ACTIVE (RINGING/ACTIVE) and
+ * user INACTIVE (INCOMING/HOLD/DISCONNECTED) states.
+ */
+public class CallSequencingController {
+//    private final CallsManager mCallsManager;
+    private final TransactionManager mTransactionManager;
+//    private final Handler mHandler;
+//    private boolean mCallSequencingEnabled;
+
+    public CallSequencingController(CallsManager callsManager, boolean callSequencingEnabled) {
+//        mCallsManager = callsManager;
+        mTransactionManager = TransactionManager.getInstance();
+        HandlerThread handlerThread = new HandlerThread(this.toString());
+        handlerThread.start();
+//        mHandler = new Handler(handlerThread.getLooper());
+//        mCallSequencingEnabled = callSequencingEnabled;
+    }
+
+    public void answerCall(Call incomingCall, int videoState) {
+        // Todo: call sequencing logic (stubbed)
+    }
+
+//    private CompletableFuture<Boolean> holdActiveCallForNewCallWithSequencing(Call call) {
+//        // Todo: call sequencing logic (stubbed)
+//        return null;
+//    }
+
+    public void unholdCall(Call call) {
+        // Todo: call sequencing logic (stubbed)
+    }
+
+    public CompletableFuture<Boolean> makeRoomForOutgoingCall(boolean isEmergency, Call call) {
+        // Todo: call sequencing logic (stubbed)
+        return CompletableFuture.completedFuture(true);
+//        return isEmergency ? makeRoomForOutgoingEmergencyCall(call) : makeRoomForOutgoingCall(call);
+    }
+
+//    private CompletableFuture<Boolean> makeRoomForOutgoingEmergencyCall(Call emergencyCall) {
+//        // Todo: call sequencing logic (stubbed)
+//        return CompletableFuture.completedFuture(true);
+//    }
+
+//    private CompletableFuture<Boolean> makeRoomForOutgoingCall(Call call) {
+//        // Todo: call sequencing logic (stubbed)
+//        return CompletableFuture.completedFuture(true);
+//    }
+
+//    private void resetProcessingCallSequencing() {
+//        mTransactionManager.setProcessingCallSequencing(false);
+//    }
+
+    public CompletableFuture<Boolean> disconnectCall() {
+        return CompletableFuture.completedFuture(true);
+    }
+}
diff --git a/src/com/android/server/telecom/voip/VoipCallTransaction.java b/src/com/android/server/telecom/callsequencing/CallTransaction.java
similarity index 85%
rename from src/com/android/server/telecom/voip/VoipCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/CallTransaction.java
index a589a6de0..8d7da7cd8 100644
--- a/src/com/android/server/telecom/voip/VoipCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/CallTransaction.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2022 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing;
 
 import android.os.Handler;
 import android.os.HandlerThread;
@@ -34,7 +34,7 @@ import java.util.concurrent.TimeUnit;
 import java.util.concurrent.atomic.AtomicBoolean;
 import java.util.function.Function;
 
-public class VoipCallTransaction {
+public class CallTransaction {
     //TODO: add log events
     private static final long DEFAULT_TRANSACTION_TIMEOUT_MS = 5000L;
 
@@ -52,7 +52,7 @@ public class VoipCallTransaction {
         private long mFinishedTimeNs = -1L;
         // If finished, did this transaction finish because it timed out?
         private boolean mIsTimedOut = false;
-        private VoipCallTransactionResult  mTransactionResult = null;
+        private CallTransactionResult  mTransactionResult = null;
 
         public Stats() {
             addedTimeStamp = LocalDateTime.now();
@@ -70,7 +70,7 @@ public class VoipCallTransaction {
         /**
          * Mark the transaction as completed and record the time.
          */
-        public void markComplete(boolean isTimedOut, VoipCallTransactionResult result) {
+        public void markComplete(boolean isTimedOut, CallTransactionResult result) {
             if (mFinishedTimeNs > -1) return;
             mFinishedTimeNs = System.nanoTime();
             mIsTimedOut = isTimedOut;
@@ -124,7 +124,7 @@ public class VoipCallTransaction {
          * @return the result if the transaction completed, null if it timed out or hasn't completed
          * yet.
          */
-        public VoipCallTransactionResult getTransactionResult() {
+        public CallTransactionResult getTransactionResult() {
             return mTransactionResult;
         }
     }
@@ -134,13 +134,13 @@ public class VoipCallTransaction {
     private final HandlerThread mHandlerThread;
     protected final Handler mHandler;
     protected TransactionManager.TransactionCompleteListener mCompleteListener;
-    protected final List<VoipCallTransaction> mSubTransactions;
+    protected final List<CallTransaction> mSubTransactions;
     protected final TelecomSystem.SyncRoot mLock;
     protected final long mTransactionTimeoutMs;
     protected final Stats mStats;
 
-    public VoipCallTransaction(
-            List<VoipCallTransaction> subTransactions, TelecomSystem.SyncRoot lock,
+    public CallTransaction(
+            List<CallTransaction> subTransactions, TelecomSystem.SyncRoot lock,
             long timeoutMs) {
         mSubTransactions = subTransactions;
         mHandlerThread = new HandlerThread(this.toString());
@@ -151,15 +151,15 @@ public class VoipCallTransaction {
         mStats = Flags.enableCallSequencing() ? new Stats() : null;
     }
 
-    public VoipCallTransaction(List<VoipCallTransaction> subTransactions,
+    public CallTransaction(List<CallTransaction> subTransactions,
             TelecomSystem.SyncRoot lock) {
         this(subTransactions, lock, DEFAULT_TRANSACTION_TIMEOUT_MS);
     }
-    public VoipCallTransaction(TelecomSystem.SyncRoot lock, long timeoutMs) {
+    public CallTransaction(TelecomSystem.SyncRoot lock, long timeoutMs) {
         this(null /* mSubTransactions */, lock, timeoutMs);
     }
 
-    public VoipCallTransaction(TelecomSystem.SyncRoot lock) {
+    public CallTransaction(TelecomSystem.SyncRoot lock) {
         this(null /* mSubTransactions */, lock);
     }
 
@@ -178,7 +178,7 @@ public class VoipCallTransaction {
     }
 
     /**
-     * By default, this processes this transaction. For VoipCallTransactions with sub-transactions,
+     * By default, this processes this transaction. For CallTransaction with sub-transactions,
      * this implementation should be overwritten to handle also processing sub-transactions.
      */
     protected void processTransactions() {
@@ -187,7 +187,7 @@ public class VoipCallTransaction {
 
     /**
      * This method is called when the transaction has finished either successfully or exceptionally.
-     * VoipCallTransactions that are extending this class should override this method to clean up
+     * CallTransaction that are extending this class should override this method to clean up
      * any leftover state.
      */
     protected void finishTransaction() {
@@ -199,7 +199,7 @@ public class VoipCallTransaction {
                 mTransactionName + "@" + hashCode() + ".sT", mLock);
         CompletableFuture<Void> future = CompletableFuture.completedFuture(null);
         future.thenComposeAsync(this::processTransaction, executor)
-                .thenApplyAsync((Function<VoipCallTransactionResult, Void>) result -> {
+                .thenApplyAsync((Function<CallTransactionResult, Void>) result -> {
                     notifyListenersOfResult(result);
                     return null;
                 }, executor)
@@ -208,14 +208,14 @@ public class VoipCallTransaction {
                     // Instead, propagate the failure to the other transactions immediately!
                     String errorMessage = throwable != null ? throwable.getMessage() :
                             "encountered an exception while processing " + mTransactionName;
-                    notifyListenersOfResult(new VoipCallTransactionResult(
+                    notifyListenersOfResult(new CallTransactionResult(
                             CallException.CODE_ERROR_UNKNOWN, errorMessage));
                     Log.e(this, throwable, "Error while executing transaction.");
                     return null;
                 }));
     }
 
-    protected void notifyListenersOfResult(VoipCallTransactionResult result){
+    protected void notifyListenersOfResult(CallTransactionResult result){
         mCompleted.set(true);
         finish(result);
         if (mCompleteListener != null) {
@@ -223,9 +223,9 @@ public class VoipCallTransaction {
         }
     }
 
-    protected CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    protected CompletionStage<CallTransactionResult> processTransaction(Void v) {
         return CompletableFuture.completedFuture(
-                new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED, null));
+                new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED, null));
     }
 
     public final void setCompleteListener(TransactionManager.TransactionCompleteListener listener) {
@@ -248,11 +248,11 @@ public class VoipCallTransaction {
         return mHandler;
     }
 
-    public final void finish(VoipCallTransactionResult result) {
+    public final void finish(CallTransactionResult result) {
         finish(false, result);
     }
 
-    private void finish(boolean isTimedOut, VoipCallTransactionResult result) {
+    private void finish(boolean isTimedOut, CallTransactionResult result) {
         if (mStats != null) mStats.markComplete(isTimedOut, result);
         finishTransaction();
         // finish all sub transactions
diff --git a/src/com/android/server/telecom/voip/VoipCallTransactionResult.java b/src/com/android/server/telecom/callsequencing/CallTransactionResult.java
similarity index 66%
rename from src/com/android/server/telecom/voip/VoipCallTransactionResult.java
rename to src/com/android/server/telecom/callsequencing/CallTransactionResult.java
index 50871f212..8b5f5bf97 100644
--- a/src/com/android/server/telecom/voip/VoipCallTransactionResult.java
+++ b/src/com/android/server/telecom/callsequencing/CallTransactionResult.java
@@ -1,5 +1,5 @@
 /*
- * Copyright (C) 2022 The Android Open Source Project
+ * Copyright (C) 2024 The Android Open Source Project
  *
  * Licensed under the Apache License, Version 2.0 (the "License");
  * you may not use this file except in compliance with the License.
@@ -14,33 +14,38 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing;
 
 import com.android.server.telecom.Call;
 
 import java.util.Objects;
 
-public class VoipCallTransactionResult {
+public class CallTransactionResult {
     public static final int RESULT_SUCCEED = 0;
+    private static final String VOIP_TRANSACTION_TAG = "VoipCallTransactionResult";
+    private static final String PSTN_TRANSACTION_TAG = "PstnTransactionResult";
 
-    // NOTE: if the VoipCallTransactionResult should not use the RESULT_SUCCEED to represent a
+    // NOTE: if the CallTransactionResult should not use the RESULT_SUCCEED to represent a
     // successful transaction, use an error code defined in the
     // {@link android.telecom.CallException} class
 
     private final int mResult;
     private final String mMessage;
     private final Call mCall;
+    private final String mCallType;
 
-    public VoipCallTransactionResult(int result, String message) {
+    public CallTransactionResult(int result, String message) {
         mResult = result;
         mMessage = message;
         mCall = null;
+        mCallType = "";
     }
 
-    public VoipCallTransactionResult(int result, Call call, String message) {
+    public CallTransactionResult(int result, Call call, String message, boolean isVoip) {
         mResult = result;
         mCall = call;
         mMessage = message;
+        mCallType = isVoip ? VOIP_TRANSACTION_TAG : PSTN_TRANSACTION_TAG;
     }
 
     public int getResult() {
@@ -58,8 +63,8 @@ public class VoipCallTransactionResult {
     @Override
     public boolean equals(Object o) {
         if (this == o) return true;
-        if (!(o instanceof VoipCallTransactionResult)) return false;
-        VoipCallTransactionResult that = (VoipCallTransactionResult) o;
+        if (!(o instanceof CallTransactionResult)) return false;
+        CallTransactionResult that = (CallTransactionResult) o;
         return mResult == that.mResult && Objects.equals(mMessage, that.mMessage);
     }
 
@@ -71,7 +76,9 @@ public class VoipCallTransactionResult {
     @Override
     public String toString() {
         return new StringBuilder().
-                append("{ VoipCallTransactionResult: [mResult: ").
+                append("{ ").
+                append(mCallType).
+                append(": [mResult: ").
                 append(mResult).
                 append("], [mCall: ").
                 append((mCall != null) ? mCall : "null").
diff --git a/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java b/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java
new file mode 100644
index 000000000..8410c5451
--- /dev/null
+++ b/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java
@@ -0,0 +1,88 @@
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
+package com.android.server.telecom.callsequencing;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallsManager;
+
+import java.util.concurrent.CompletableFuture;
+
+/**
+ * Abstraction layer for CallsManager to perform call sequencing operations through CallsManager
+ * or CallSequencingController, which is controlled by {@link FeatureFlags#enableCallSequencing()}.
+ */
+public class CallsManagerCallSequencingAdapter {
+
+    private final CallsManager mCallsManager;
+    private final CallSequencingController mSequencingController;
+    private final boolean mIsCallSequencingEnabled;
+
+    public CallsManagerCallSequencingAdapter(CallsManager callsManager,
+            CallSequencingController sequencingController,
+            boolean isCallSequencingEnabled) {
+        mCallsManager = callsManager;
+        mSequencingController = sequencingController;
+        mIsCallSequencingEnabled = isCallSequencingEnabled;
+    }
+
+    public void answerCall(Call incomingCall, int videoState) {
+        if (mIsCallSequencingEnabled && !incomingCall.isTransactionalCall()) {
+            mSequencingController.answerCall(incomingCall, videoState);
+        } else {
+            mCallsManager.answerCallOld(incomingCall, videoState);
+        }
+    }
+
+    public void unholdCall(Call call) {
+        if (mIsCallSequencingEnabled) {
+            mSequencingController.unholdCall(call);
+        } else {
+            mCallsManager.unholdCallOld(call);
+        }
+    }
+
+    public void holdCall(Call call) {
+        // Sequencing already taken care of for CSW/TSW in Call class.
+        call.hold();
+    }
+
+    public void unholdCallForRemoval(Call removedCall,
+            boolean isLocallyDisconnecting) {
+        // Todo: confirm verification of disconnect logic
+        // Sequencing already taken care of for CSW/TSW in Call class.
+        mCallsManager.maybeMoveHeldCallToForeground(removedCall, isLocallyDisconnecting);
+    }
+
+    public CompletableFuture<Boolean> makeRoomForOutgoingCall(boolean isEmergency, Call call) {
+        if (mIsCallSequencingEnabled) {
+            return mSequencingController.makeRoomForOutgoingCall(isEmergency, call);
+        } else {
+            return isEmergency
+                    ? CompletableFuture.completedFuture(
+                            makeRoomForOutgoingEmergencyCallFlagOff(call))
+                    : CompletableFuture.completedFuture(makeRoomForOutgoingCallFlagOff(call));
+        }
+    }
+
+    private boolean makeRoomForOutgoingCallFlagOff(Call call) {
+        return mCallsManager.makeRoomForOutgoingCall(call);
+    }
+
+    private boolean makeRoomForOutgoingEmergencyCallFlagOff(Call call) {
+        return mCallsManager.makeRoomForOutgoingEmergencyCall(call);
+    }
+}
diff --git a/src/com/android/server/telecom/voip/TransactionManager.java b/src/com/android/server/telecom/callsequencing/TransactionManager.java
similarity index 76%
rename from src/com/android/server/telecom/voip/TransactionManager.java
rename to src/com/android/server/telecom/callsequencing/TransactionManager.java
index 0086d0790..a3b3828ab 100644
--- a/src/com/android/server/telecom/voip/TransactionManager.java
+++ b/src/com/android/server/telecom/callsequencing/TransactionManager.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing;
 
 import static android.telecom.CallException.CODE_OPERATION_TIMED_OUT;
 
@@ -32,18 +32,20 @@ import java.util.Deque;
 import java.util.List;
 import java.util.Locale;
 import java.util.Queue;
+import java.util.concurrent.CompletableFuture;
 
 public class TransactionManager {
-    private static final String TAG = "VoipCallTransactionManager";
+    private static final String TAG = "CallTransactionManager";
     private static final int TRANSACTION_HISTORY_SIZE = 20;
     private static TransactionManager INSTANCE = null;
     private static final Object sLock = new Object();
-    private final Queue<VoipCallTransaction> mTransactions;
-    private final Deque<VoipCallTransaction> mCompletedTransactions;
-    private VoipCallTransaction mCurrentTransaction;
+    private final Queue<CallTransaction> mTransactions;
+    private final Deque<CallTransaction> mCompletedTransactions;
+    private CallTransaction mCurrentTransaction;
+    private boolean mProcessingCallSequencing;
 
     public interface TransactionCompleteListener {
-        void onTransactionCompleted(VoipCallTransactionResult result, String transactionName);
+        void onTransactionCompleted(CallTransactionResult result, String transactionName);
         void onTransactionTimeout(String transactionName);
     }
 
@@ -70,28 +72,32 @@ public class TransactionManager {
         return new TransactionManager();
     }
 
-    public void addTransaction(VoipCallTransaction transaction,
-            OutcomeReceiver<VoipCallTransactionResult, CallException> receiver) {
+    public CompletableFuture<Boolean> addTransaction(CallTransaction transaction,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        CompletableFuture<Boolean> transactionCompleteFuture = new CompletableFuture<>();
         synchronized (sLock) {
             mTransactions.add(transaction);
         }
         transaction.setCompleteListener(new TransactionCompleteListener() {
             @Override
-            public void onTransactionCompleted(VoipCallTransactionResult result,
+            public void onTransactionCompleted(CallTransactionResult result,
                     String transactionName) {
                 Log.i(TAG, String.format("transaction %s completed: with result=[%d]",
                         transactionName, result.getResult()));
                 try {
                     if (result.getResult() == TelecomManager.TELECOM_TRANSACTION_SUCCESS) {
                         receiver.onResult(result);
+                        transactionCompleteFuture.complete(true);
                     } else {
                         receiver.onError(
                                 new CallException(result.getMessage(),
                                         result.getResult()));
+                        transactionCompleteFuture.complete(false);
                     }
                 } catch (Exception e) {
                     Log.e(TAG, String.format("onTransactionCompleted: Notifying transaction result"
                             + " %s resulted in an Exception.", result), e);
+                    transactionCompleteFuture.complete(false);
                 }
                 finishTransaction();
             }
@@ -102,15 +108,18 @@ public class TransactionManager {
                 try {
                     receiver.onError(new CallException(transactionName + " timeout",
                             CODE_OPERATION_TIMED_OUT));
+                    transactionCompleteFuture.complete(false);
                 } catch (Exception e) {
                     Log.e(TAG, String.format("onTransactionTimeout: Notifying transaction "
                             + " %s resulted in an Exception.", transactionName), e);
+                    transactionCompleteFuture.complete(false);
                 }
                 finishTransaction();
             }
         });
 
         startTransactions();
+        return transactionCompleteFuture;
     }
 
     private void startTransactions() {
@@ -141,17 +150,17 @@ public class TransactionManager {
 
     @VisibleForTesting
     public void clear() {
-        List<VoipCallTransaction> pendingTransactions;
+        List<CallTransaction> pendingTransactions;
         synchronized (sLock) {
             pendingTransactions = new ArrayList<>(mTransactions);
         }
-        for (VoipCallTransaction t : pendingTransactions) {
-            t.finish(new VoipCallTransactionResult(CallException.CODE_ERROR_UNKNOWN
+        for (CallTransaction t : pendingTransactions) {
+            t.finish(new CallTransactionResult(CallException.CODE_ERROR_UNKNOWN
                     /* TODO:: define error b/335703584 */, "clear called"));
         }
     }
 
-    private void addTransactionToHistory(VoipCallTransaction t) {
+    private void addTransactionToHistory(CallTransaction t) {
         if (!Flags.enableCallSequencing()) return;
 
         mCompletedTransactions.add(t);
@@ -160,6 +169,14 @@ public class TransactionManager {
         }
     }
 
+    public void setProcessingCallSequencing(boolean processingCallSequencing) {
+        mProcessingCallSequencing = processingCallSequencing;
+    }
+
+    public boolean isProcessingCallSequencing() {
+        return mProcessingCallSequencing;
+    }
+
     /**
      * Called when the dumpsys is created for telecom to capture the current state.
      */
@@ -171,7 +188,7 @@ public class TransactionManager {
         synchronized (sLock) {
             pw.println("Pending Transactions:");
             pw.increaseIndent();
-            for (VoipCallTransaction t : mTransactions) {
+            for (CallTransaction t : mTransactions) {
                 printPendingTransactionStats(t, pw);
             }
             pw.decreaseIndent();
@@ -185,7 +202,7 @@ public class TransactionManager {
 
             pw.println("Completed Transactions:");
             pw.increaseIndent();
-            for (VoipCallTransaction t : mCompletedTransactions) {
+            for (CallTransaction t : mCompletedTransactions) {
                 printCompleteTransactionStats(t, pw);
             }
             pw.decreaseIndent();
@@ -193,12 +210,12 @@ public class TransactionManager {
     }
 
     /**
-     * Recursively print the pending {@link VoipCallTransaction} stats for logging purposes.
+     * Recursively print the pending {@link CallTransaction} stats for logging purposes.
      * @param t The transaction that stats should be printed for
      * @param pw The IndentingPrintWriter to print the result to
      */
-    private void printPendingTransactionStats(VoipCallTransaction t, IndentingPrintWriter pw) {
-        VoipCallTransaction.Stats s = t.getStats();
+    private void printPendingTransactionStats(CallTransaction t, IndentingPrintWriter pw) {
+        CallTransaction.Stats s = t.getStats();
         if (s == null) {
             pw.println(String.format(Locale.getDefault(), "%s: <NO STATS>", t.mTransactionName));
             return;
@@ -215,7 +232,7 @@ public class TransactionManager {
             return;
         }
         pw.increaseIndent();
-        for (VoipCallTransaction subTransaction : t.mSubTransactions) {
+        for (CallTransaction subTransaction : t.mSubTransactions) {
             printPendingTransactionStats(subTransaction, pw);
         }
         pw.decreaseIndent();
@@ -226,8 +243,8 @@ public class TransactionManager {
      * @param t The transaction that stats should be printed for
      * @param pw The IndentingPrintWriter to print the result to
      */
-    private void printCompleteTransactionStats(VoipCallTransaction t, IndentingPrintWriter pw) {
-        VoipCallTransaction.Stats s = t.getStats();
+    private void printCompleteTransactionStats(CallTransaction t, IndentingPrintWriter pw) {
+        CallTransaction.Stats s = t.getStats();
         if (s == null) {
             pw.println(String.format(Locale.getDefault(), "%s: <NO STATS>", t.mTransactionName));
             return;
@@ -242,16 +259,16 @@ public class TransactionManager {
             return;
         }
         pw.increaseIndent();
-        for (VoipCallTransaction subTransaction : t.mSubTransactions) {
+        for (CallTransaction subTransaction : t.mSubTransactions) {
             printCompleteTransactionStats(subTransaction, pw);
         }
         pw.decreaseIndent();
     }
 
-    private String parseTransactionResult(VoipCallTransaction.Stats s) {
+    private String parseTransactionResult(CallTransaction.Stats s) {
         if (s.isTimedOut()) return "TIMED OUT";
         if (s.getTransactionResult() == null) return "PENDING";
-        if (s.getTransactionResult().getResult() == VoipCallTransactionResult.RESULT_SUCCEED) {
+        if (s.getTransactionResult().getResult() == CallTransactionResult.RESULT_SUCCEED) {
             return "SUCCESS";
         }
         return s.getTransactionResult().toString();
diff --git a/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java b/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java
new file mode 100644
index 000000000..7c8bbe407
--- /dev/null
+++ b/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java
@@ -0,0 +1,304 @@
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
+package com.android.server.telecom.callsequencing;
+
+import android.os.OutcomeReceiver;
+import android.telecom.CallException;
+import android.telecom.DisconnectCause;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.voip.EndCallTransaction;
+import com.android.server.telecom.callsequencing.voip.HoldCallTransaction;
+import com.android.server.telecom.callsequencing.voip.MaybeHoldCallForNewCallTransaction;
+import com.android.server.telecom.callsequencing.voip.RequestNewActiveCallTransaction;
+import com.android.server.telecom.callsequencing.voip.SerialTransaction;
+
+import java.util.ArrayList;
+import java.util.Collection;
+import java.util.List;
+import java.util.concurrent.CompletableFuture;
+
+/**
+ * Helper adapter class used to centralized code that will be affected by toggling the
+ * {@link Flags#enableCallSequencing()} flag.
+ */
+public class TransactionalCallSequencingAdapter {
+    private final TransactionManager mTransactionManager;
+    private final CallsManager mCallsManager;
+//    private final boolean mIsCallSequencingEnabled;
+
+    public TransactionalCallSequencingAdapter(TransactionManager transactionManager,
+            CallsManager callsManager, boolean isCallSequencingEnabled) {
+        mTransactionManager = transactionManager;
+        mCallsManager = callsManager;
+        // TODO implement call sequencing changes
+//        mIsCallSequencingEnabled = isCallSequencingEnabled;
+    }
+
+    /**
+     * Client -> Server request to set a call active
+     */
+    public void setActive(Call call,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        setActiveFlagOff(call, receiver);
+    }
+
+    /**
+     * Client -> Server request to answer a call
+     */
+    public void setAnswered(Call call, int newVideoState,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        setAnsweredFlagOff(call, newVideoState, receiver);
+    }
+
+    /**
+     * Client -> Server request to set a call to disconnected
+     */
+    public void setDisconnected(Call call, DisconnectCause dc,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        setDisconnectedFlagOff(call, dc, receiver);
+    }
+
+    /**
+     * Client -> Server request to set a call to inactive
+     */
+    public void setInactive(Call call,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        setInactiveFlagOff(call, receiver);
+    }
+
+    /**
+     * Server -> Client command to set the call active, which if it fails, will try to reset the
+     * state to what it was before the call was set to active.
+     */
+    public CompletableFuture<Boolean> onSetActive(Call call,
+            CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        return onSetActiveFlagOff(call, clientCbT, receiver);
+    }
+
+    /**
+     * Server -> Client command to answer an incoming call, which if it fails, will trigger the
+     * disconnect of the call and then reset the state of the other call back to what it was before.
+     */
+    public void onSetAnswered(Call call, int videoState, CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        onSetAnsweredFlagOff(call, videoState, clientCbT, receiver);
+    }
+
+    /**
+     * Server -> Client command to set the call as inactive
+     */
+    public CompletableFuture<Boolean> onSetInactive(Call call,
+            CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        return onSetInactiveFlagOff(call, clientCbT, receiver);
+    }
+
+    /**
+     * Server -> Client command to disconnect the call
+     */
+    public CompletableFuture<Boolean> onSetDisconnected(Call call,
+            DisconnectCause dc, CallTransaction clientCbT, OutcomeReceiver<CallTransactionResult,
+            CallException> receiver) {
+        return onSetDisconnectedFlagOff(call, dc, clientCbT, receiver);
+    }
+
+    /**
+     * Clean up the calls that have been passed in from CallsManager
+     */
+    public void cleanup(Collection<Call> calls) {
+        cleanupFlagOff(calls);
+    }
+
+    private void setActiveFlagOff(Call call,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(createSetActiveTransactions(call,
+                true /* callControlRequest */), receiver);
+    }
+
+    private void setAnsweredFlagOff(Call call, int newVideoState,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(createSetActiveTransactions(call,
+                                true /* callControlRequest */),
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(CallTransactionResult callTransactionResult) {
+                        call.setVideoState(newVideoState);
+                        receiver.onResult(callTransactionResult);
+                    }
+
+                    @Override
+                    public void onError(CallException error) {
+                        receiver.onError(error);
+                    }
+                });
+    }
+
+    private void setDisconnectedFlagOff(Call call, DisconnectCause dc,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(new EndCallTransaction(mCallsManager,
+                        dc, call), receiver);
+    }
+
+    private void setInactiveFlagOff(Call call,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(new HoldCallTransaction(mCallsManager,call), receiver);
+    }
+
+    private CompletableFuture<Boolean> onSetActiveFlagOff(Call call,
+            CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        // save CallsManager state before sending client state changes
+        Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
+        boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
+        SerialTransaction serialTransactions = createSetActiveTransactions(call,
+                false /* callControlRequest */);
+        serialTransactions.appendTransaction(clientCbT);
+        // do CallsManager workload before asking client and
+        //   reset CallsManager state if client does NOT ack
+        return mTransactionManager.addTransaction(
+                serialTransactions,
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(CallTransactionResult result) {
+                        receiver.onResult(result);
+                    }
+
+                    @Override
+                    public void onError(CallException exception) {
+                        mCallsManager.markCallAsOnHold(call);
+                        maybeResetForegroundCall(foregroundCallBeforeSwap, wasActive);
+                        receiver.onError(exception);
+                    }
+                });
+    }
+
+    private void onSetAnsweredFlagOff(Call call, int videoState, CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        // save CallsManager state before sending client state changes
+        Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
+        boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
+        SerialTransaction serialTransactions = createSetActiveTransactions(call,
+                false /* callControlRequest */);
+        serialTransactions.appendTransaction(clientCbT);
+        // do CallsManager workload before asking client and
+        //   reset CallsManager state if client does NOT ack
+        CompletableFuture<Boolean> transactionResult = mTransactionManager
+                .addTransaction(serialTransactions,
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(CallTransactionResult result) {
+                        call.setVideoState(videoState);
+                        receiver.onResult(result);
+                    }
+
+                    @Override
+                    public void onError(CallException exception) {
+                        // This also sends the signal to untrack from TSW and the client_TSW
+                        removeCallFromCallsManager(call,
+                                new DisconnectCause(DisconnectCause.REJECTED,
+                                        "client rejected to answer the call;"
+                                                + " force disconnecting"));
+                        maybeResetForegroundCall(foregroundCallBeforeSwap, wasActive);
+                        receiver.onError(exception);
+                    }
+                });
+    }
+
+    private CompletableFuture<Boolean> onSetInactiveFlagOff(Call call,
+            CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        return mTransactionManager.addTransaction(clientCbT,
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(CallTransactionResult callTransactionResult) {
+                        mCallsManager.markCallAsOnHold(call);
+                        receiver.onResult(callTransactionResult);
+                    }
+
+                    @Override
+                    public void onError(CallException error) {
+                        receiver.onError(error);
+                    }
+                });
+    }
+
+    /**
+     * Server -> Client command to disconnect the call
+     */
+    private CompletableFuture<Boolean> onSetDisconnectedFlagOff(Call call,
+            DisconnectCause dc, CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        return mTransactionManager.addTransaction(clientCbT,
+                new OutcomeReceiver<>() {
+                    @Override
+                    public void onResult(CallTransactionResult result) {
+                        removeCallFromCallsManager(call, dc);
+                        receiver.onResult(result);
+                    }
+
+                    @Override
+                    public void onError(CallException exception) {
+                        removeCallFromCallsManager(call, dc);
+                        receiver.onError(exception);
+                    }
+                }
+        );
+    }
+
+    private SerialTransaction createSetActiveTransactions(Call call, boolean isCallControlRequest) {
+        // create list for multiple transactions
+        List<CallTransaction> transactions = new ArrayList<>();
+
+        // potentially hold the current active call in order to set a new call (active/answered)
+        transactions.add(new MaybeHoldCallForNewCallTransaction(mCallsManager, call,
+                isCallControlRequest));
+        // And request a new focus call update
+        transactions.add(new RequestNewActiveCallTransaction(mCallsManager, call));
+
+        return new SerialTransaction(transactions, mCallsManager.getLock());
+    }
+
+    private void removeCallFromCallsManager(Call call, DisconnectCause cause) {
+        if (cause.getCode() != DisconnectCause.REJECTED) {
+            mCallsManager.markCallAsDisconnected(call, cause);
+        }
+        mCallsManager.removeCall(call);
+    }
+
+    private void maybeResetForegroundCall(Call foregroundCallBeforeSwap, boolean wasActive) {
+        if (foregroundCallBeforeSwap == null) {
+            return;
+        }
+        if (wasActive && !foregroundCallBeforeSwap.isActive()) {
+            mCallsManager.markCallAsActive(foregroundCallBeforeSwap);
+        }
+    }
+    private void cleanupFlagOff(Collection<Call> calls) {
+        for (Call call : calls) {
+            mCallsManager.markCallAsDisconnected(call,
+                    new DisconnectCause(DisconnectCause.ERROR, "process died"));
+            mCallsManager.removeCall(call); // This will clear mTrackedCalls && ClientTWS
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/voip/VerifyCallStateChangeTransaction.java b/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
similarity index 69%
rename from src/com/android/server/telecom/voip/VerifyCallStateChangeTransaction.java
rename to src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
index 5de4b1d24..82b32fbe3 100644
--- a/src/com/android/server/telecom/voip/VerifyCallStateChangeTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.Call;
@@ -22,8 +22,11 @@ import com.android.server.telecom.TelecomSystem;
 
 import android.telecom.Log;
 
+import java.util.Set;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
+import java.util.stream.Collectors;
+import java.util.stream.IntStream;
 
 /**
  * VerifyCallStateChangeTransaction is a transaction that verifies a CallState change and has
@@ -31,21 +34,22 @@ import java.util.concurrent.CompletionStage;
  * <p>
  * Note: This transaction has a timeout of 2 seconds.
  */
-public class VerifyCallStateChangeTransaction extends VoipCallTransaction {
+public class VerifyCallStateChangeTransaction extends CallTransaction {
     private static final String TAG = VerifyCallStateChangeTransaction.class.getSimpleName();
     private static final long CALL_STATE_TIMEOUT_MILLISECONDS = 2000L;
     private final Call mCall;
-    private final int mTargetCallState;
-    private final CompletableFuture<VoipCallTransactionResult> mTransactionResult =
+    private final Set<Integer> mTargetCallStates;
+    private final CompletableFuture<CallTransactionResult> mTransactionResult =
             new CompletableFuture<>();
 
     private final Call.CallStateListener mCallStateListenerImpl = new Call.CallStateListener() {
         @Override
         public void onCallStateChanged(int newCallState) {
-            Log.d(TAG, "newState=[%d], expectedState=[%d]", newCallState, mTargetCallState);
-            if (newCallState == mTargetCallState) {
-                mTransactionResult.complete(new VoipCallTransactionResult(
-                        VoipCallTransactionResult.RESULT_SUCCEED, TAG));
+            Log.d(TAG, "newState=[%d], possible expected state(s)=[%s]", newCallState,
+                    mTargetCallStates);
+            if (mTargetCallStates.contains(newCallState)) {
+                mTransactionResult.complete(new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED, TAG));
             }
             // NOTE:: keep listening to the call state until the timeout is reached. It's possible
             // another call state is reached in between...
@@ -53,19 +57,19 @@ public class VerifyCallStateChangeTransaction extends VoipCallTransaction {
     };
 
     public VerifyCallStateChangeTransaction(TelecomSystem.SyncRoot lock,  Call call,
-            int targetCallState) {
+            int... targetCallStates) {
         super(lock, CALL_STATE_TIMEOUT_MILLISECONDS);
         mCall = call;
-        mTargetCallState = targetCallState;
+        mTargetCallStates = IntStream.of(targetCallStates).boxed().collect(Collectors.toSet());;
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction:");
         // It's possible the Call is already in the expected call state
         if (isNewCallStateTargetCallState()) {
-            mTransactionResult.complete(new VoipCallTransactionResult(
-                    VoipCallTransactionResult.RESULT_SUCCEED, TAG));
+            mTransactionResult.complete(new CallTransactionResult(
+                    CallTransactionResult.RESULT_SUCCEED, TAG));
             return mTransactionResult;
         }
         mCall.addCallStateListener(mCallStateListenerImpl);
@@ -78,11 +82,11 @@ public class VerifyCallStateChangeTransaction extends VoipCallTransaction {
     }
 
     private boolean isNewCallStateTargetCallState() {
-        return mCall.getState() == mTargetCallState;
+        return mTargetCallStates.contains(mCall.getState());
     }
 
     @VisibleForTesting
-    public CompletableFuture<VoipCallTransactionResult> getTransactionResult() {
+    public CompletableFuture<CallTransactionResult> getTransactionResult() {
         return mTransactionResult;
     }
 
diff --git a/src/com/android/server/telecom/voip/CallEventCallbackAckTransaction.java b/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
similarity index 91%
rename from src/com/android/server/telecom/voip/CallEventCallbackAckTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
index 9e140a74f..802ea7e46 100644
--- a/src/com/android/server/telecom/voip/CallEventCallbackAckTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import static android.telecom.TelecomManager.TELECOM_TRANSACTION_SUCCESS;
 import static android.telecom.CallException.CODE_OPERATION_TIMED_OUT;
@@ -29,6 +29,8 @@ import android.util.Log;
 import com.android.internal.telecom.ICallEventCallback;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.TransactionalServiceWrapper;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
@@ -39,7 +41,7 @@ import java.util.concurrent.TimeUnit;
  * SRP: using the ICallEventCallback binder, reach out to the client for the pending call event and
  * get an acknowledgement that the call event can be completed.
  */
-public class CallEventCallbackAckTransaction extends VoipCallTransaction {
+public class CallEventCallbackAckTransaction extends CallTransaction {
     private static final String TAG = CallEventCallbackAckTransaction.class.getSimpleName();
     private final ICallEventCallback mICallEventCallback;
     private final String mAction;
@@ -48,7 +50,7 @@ public class CallEventCallbackAckTransaction extends VoipCallTransaction {
     private int mVideoState = CallAttributes.AUDIO_CALL;
     private DisconnectCause mDisconnectCause = null;
 
-    private final VoipCallTransactionResult TRANSACTION_FAILED = new VoipCallTransactionResult(
+    private final CallTransactionResult TRANSACTION_FAILED = new CallTransactionResult(
             CODE_OPERATION_TIMED_OUT, "failed to complete the operation before timeout");
 
     private static class AckResultReceiver extends ResultReceiver {
@@ -96,7 +98,7 @@ public class CallEventCallbackAckTransaction extends VoipCallTransaction {
 
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
         CountDownLatch latch = new CountDownLatch(1);
         ResultReceiver receiver = new AckResultReceiver(latch);
@@ -134,7 +136,7 @@ public class CallEventCallbackAckTransaction extends VoipCallTransaction {
             } else {
                 // success
                 return CompletableFuture.completedFuture(
-                        new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED,
+                        new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                                 "success"));
             }
         } catch (InterruptedException ie) {
diff --git a/src/com/android/server/telecom/voip/EndCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/EndCallTransaction.java
similarity index 83%
rename from src/com/android/server/telecom/voip/EndCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/EndCallTransaction.java
index 0cb74581f..b4c92fe79 100644
--- a/src/com/android/server/telecom/voip/EndCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/EndCallTransaction.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.telecom.DisconnectCause;
 import android.util.Log;
@@ -22,6 +22,8 @@ import android.util.Log;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
@@ -29,7 +31,7 @@ import java.util.concurrent.CompletionStage;
 /**
  * This transaction should only be created for a CallControl action.
  */
-public class EndCallTransaction extends VoipCallTransaction {
+public class EndCallTransaction extends CallTransaction {
     private static final String TAG = EndCallTransaction.class.getSimpleName();
     private final CallsManager mCallsManager;
     private final Call mCall;
@@ -43,7 +45,7 @@ public class EndCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         int code = mCause.getCode();
         Log.d(TAG, String.format("processTransaction: mCode=[%d], mCall=[%s]", code, mCall));
 
@@ -56,7 +58,7 @@ public class EndCallTransaction extends VoipCallTransaction {
         mCallsManager.markCallAsRemoved(mCall);
 
         return CompletableFuture.completedFuture(
-                new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED,
+                new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                         "EndCallTransaction: RESULT_SUCCEED"));
     }
 }
diff --git a/src/com/android/server/telecom/voip/EndpointChangeTransaction.java b/src/com/android/server/telecom/callsequencing/voip/EndpointChangeTransaction.java
similarity index 75%
rename from src/com/android/server/telecom/voip/EndpointChangeTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/EndpointChangeTransaction.java
index 6841fcf9c..46678da34 100644
--- a/src/com/android/server/telecom/voip/EndpointChangeTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/EndpointChangeTransaction.java
@@ -14,7 +14,7 @@
  * See the License for the specific language governing permissions and
  * limitations under the License.
  */
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.os.Bundle;
 import android.os.ResultReceiver;
@@ -23,11 +23,13 @@ import android.telecom.CallException;
 import android.util.Log;
 
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
-public class EndpointChangeTransaction extends VoipCallTransaction {
+public class EndpointChangeTransaction extends CallTransaction {
     private static final String TAG = EndpointChangeTransaction.class.getSimpleName();
     private final CallEndpoint mCallEndpoint;
     private final CallsManager mCallsManager;
@@ -39,19 +41,19 @@ public class EndpointChangeTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.i(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
         mCallsManager.requestCallEndpointChange(mCallEndpoint, new ResultReceiver(null) {
             @Override
             protected void onReceiveResult(int resultCode, Bundle resultData) {
                 Log.i(TAG, "processTransaction: code=" + resultCode);
                 if (resultCode == CallEndpoint.ENDPOINT_OPERATION_SUCCESS) {
-                    future.complete(new VoipCallTransactionResult(
-                            VoipCallTransactionResult.RESULT_SUCCEED, null));
+                    future.complete(new CallTransactionResult(
+                            CallTransactionResult.RESULT_SUCCEED, null));
                 } else {
                     // TODO:: define errors in CallException class. b/335703584
-                    future.complete(new VoipCallTransactionResult(
+                    future.complete(new CallTransactionResult(
                             CallException.CODE_ERROR_UNKNOWN, null));
                 }
             }
diff --git a/src/com/android/server/telecom/voip/HoldCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/HoldCallTransaction.java
similarity index 72%
rename from src/com/android/server/telecom/voip/HoldCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/HoldCallTransaction.java
index 6c4e8b7cd..2fa7ff7b6 100644
--- a/src/com/android/server/telecom/voip/HoldCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/HoldCallTransaction.java
@@ -14,18 +14,20 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.telecom.CallException;
 import android.util.Log;
 
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
-public class HoldCallTransaction extends VoipCallTransaction {
+public class HoldCallTransaction extends CallTransaction {
 
     private static final String TAG = HoldCallTransaction.class.getSimpleName();
     private final CallsManager mCallsManager;
@@ -38,17 +40,17 @@ public class HoldCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
         if (mCallsManager.canHold(mCall)) {
             mCallsManager.markCallAsOnHold(mCall);
-            future.complete(new VoipCallTransactionResult(
-                    VoipCallTransactionResult.RESULT_SUCCEED, null));
+            future.complete(new CallTransactionResult(
+                    CallTransactionResult.RESULT_SUCCEED, null));
         } else {
             Log.d(TAG, "processTransaction: onError");
-            future.complete(new VoipCallTransactionResult(
+            future.complete(new CallTransactionResult(
                     CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL, "cannot hold call"));
         }
         return future;
diff --git a/src/com/android/server/telecom/voip/IncomingCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/IncomingCallTransaction.java
similarity index 85%
rename from src/com/android/server/telecom/voip/IncomingCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/IncomingCallTransaction.java
index ed0c7d669..31ce30351 100644
--- a/src/com/android/server/telecom/voip/IncomingCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/IncomingCallTransaction.java
@@ -14,12 +14,13 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import static android.telecom.CallAttributes.CALL_CAPABILITIES_KEY;
 import static android.telecom.CallAttributes.DISPLAY_NAME_KEY;
 
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToVideoProfileState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToVideoProfileState;
 
 import android.os.Bundle;
 import android.telecom.CallAttributes;
@@ -30,12 +31,14 @@ import android.util.Log;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
-public class IncomingCallTransaction extends VoipCallTransaction {
+public class IncomingCallTransaction extends CallTransaction {
 
     private static final String TAG = IncomingCallTransaction.class.getSimpleName();
     private final String mCallId;
@@ -64,7 +67,7 @@ public class IncomingCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
 
         if (mCallsManager.isIncomingCallPermitted(mCallAttributes.getPhoneAccountHandle())) {
@@ -75,13 +78,13 @@ public class IncomingCallTransaction extends VoipCallTransaction {
                     generateExtras(mCallAttributes), false);
 
             return CompletableFuture.completedFuture(
-                    new VoipCallTransactionResult(
-                            VoipCallTransactionResult.RESULT_SUCCEED, call, "success"));
+                    new CallTransactionResult(
+                            CallTransactionResult.RESULT_SUCCEED, call, "success", true));
         } else {
             Log.d(TAG, "processTransaction: incoming call is not permitted at this time");
 
             return CompletableFuture.completedFuture(
-                    new VoipCallTransactionResult(
+                    new CallTransactionResult(
                             CallException.CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
                             "incoming call not permitted at the current time"));
         }
diff --git a/src/com/android/server/telecom/voip/MaybeHoldCallForNewCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
similarity index 74%
rename from src/com/android/server/telecom/voip/MaybeHoldCallForNewCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
index 3bed088c1..32062b566 100644
--- a/src/com/android/server/telecom/voip/MaybeHoldCallForNewCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.os.OutcomeReceiver;
 import android.telecom.CallException;
@@ -22,15 +22,17 @@ import android.util.Log;
 
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
 /**
- * This VoipCallTransaction is responsible for holding any active call in favor of a new call
+ * This VOIP CallTransaction is responsible for holding any active call in favor of a new call
  * request. If the active call cannot be held or disconnected, the transaction will fail.
  */
-public class MaybeHoldCallForNewCallTransaction extends VoipCallTransaction {
+public class MaybeHoldCallForNewCallTransaction extends CallTransaction {
 
     private static final String TAG = MaybeHoldCallForNewCallTransaction.class.getSimpleName();
     private final CallsManager mCallsManager;
@@ -46,23 +48,23 @@ public class MaybeHoldCallForNewCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
         mCallsManager.transactionHoldPotentialActiveCallForNewCall(mCall, mIsCallControlRequest,
                 new OutcomeReceiver<>() {
             @Override
             public void onResult(Boolean result) {
                 Log.d(TAG, "processTransaction: onResult");
-                future.complete(new VoipCallTransactionResult(
-                        VoipCallTransactionResult.RESULT_SUCCEED, null));
+                future.complete(new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED, null));
             }
 
             @Override
             public void onError(CallException exception) {
                 Log.d(TAG, "processTransaction: onError");
-                future.complete(new VoipCallTransactionResult(
+                future.complete(new CallTransactionResult(
                        exception.getCode(), exception.getMessage()));
             }
         });
diff --git a/src/com/android/server/telecom/voip/OutgoingCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
similarity index 87%
rename from src/com/android/server/telecom/voip/OutgoingCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
index 68ffecfed..572de55d8 100644
--- a/src/com/android/server/telecom/voip/OutgoingCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
@@ -14,14 +14,15 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import static android.Manifest.permission.CALL_PRIVILEGED;
 import static android.telecom.CallAttributes.CALL_CAPABILITIES_KEY;
 import static android.telecom.CallAttributes.DISPLAY_NAME_KEY;
 import static android.telecom.CallException.CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME;
 
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToVideoProfileState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToVideoProfileState;
 
 import android.content.Context;
 import android.content.Intent;
@@ -35,12 +36,14 @@ import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.LoggedHandlerExecutor;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
-public class OutgoingCallTransaction extends VoipCallTransaction {
+public class OutgoingCallTransaction extends CallTransaction {
 
     private static final String TAG = OutgoingCallTransaction.class.getSimpleName();
     private final String mCallId;
@@ -73,7 +76,7 @@ public class OutgoingCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
 
         final boolean hasCallPrivilegedPermission = mContext.checkCallingPermission(
@@ -95,11 +98,11 @@ public class OutgoingCallTransaction extends VoipCallTransaction {
 
             if (callFuture == null) {
                 return CompletableFuture.completedFuture(
-                        new VoipCallTransactionResult(
+                        new CallTransactionResult(
                                 CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
                                 "incoming call not permitted at the current time"));
             }
-            CompletionStage<VoipCallTransactionResult> result = callFuture.thenComposeAsync(
+            CompletionStage<CallTransactionResult> result = callFuture.thenComposeAsync(
                     (call) -> {
 
                         Log.d(TAG, "processTransaction: completing future");
@@ -107,7 +110,7 @@ public class OutgoingCallTransaction extends VoipCallTransaction {
                         if (call == null) {
                             Log.d(TAG, "processTransaction: call is null");
                             return CompletableFuture.completedFuture(
-                                    new VoipCallTransactionResult(
+                                    new CallTransactionResult(
                                             CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
                                             "call could not be created at this time"));
                         } else {
@@ -121,16 +124,16 @@ public class OutgoingCallTransaction extends VoipCallTransaction {
                         }
 
                         return CompletableFuture.completedFuture(
-                                new VoipCallTransactionResult(
-                                        VoipCallTransactionResult.RESULT_SUCCEED,
-                                        call, null));
+                                new CallTransactionResult(
+                                        CallTransactionResult.RESULT_SUCCEED,
+                                        call, null, true));
                     }
                     , new LoggedHandlerExecutor(mHandler, "OCT.pT", null));
 
             return result;
         } else {
             return CompletableFuture.completedFuture(
-                    new VoipCallTransactionResult(
+                    new CallTransactionResult(
                             CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
                             "incoming call not permitted at the current time"));
 
diff --git a/src/com/android/server/telecom/voip/ParallelTransaction.java b/src/com/android/server/telecom/callsequencing/voip/ParallelTransaction.java
similarity index 80%
rename from src/com/android/server/telecom/voip/ParallelTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/ParallelTransaction.java
index e235ead17..77e93f95f 100644
--- a/src/com/android/server/telecom/voip/ParallelTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/ParallelTransaction.java
@@ -14,22 +14,25 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.telecom.CallException;
 
 import com.android.server.telecom.LoggedHandlerExecutor;
 import com.android.server.telecom.TelecomSystem;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import java.util.List;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.atomic.AtomicInteger;
 
 /**
- * A VoipCallTransaction implementation that its sub transactions will be executed in parallel
+ * A CallTransaction implementation that its sub transactions will be executed in parallel
  */
-public class ParallelTransaction extends VoipCallTransaction {
-    public ParallelTransaction(List<VoipCallTransaction> subTransactions,
+public class ParallelTransaction extends CallTransaction {
+    public ParallelTransaction(List<CallTransaction> subTransactions,
             TelecomSystem.SyncRoot lock) {
         super(subTransactions, lock);
     }
@@ -45,9 +48,9 @@ public class ParallelTransaction extends VoipCallTransaction {
                     private final AtomicInteger mCount = new AtomicInteger(mSubTransactions.size());
 
                     @Override
-                    public void onTransactionCompleted(VoipCallTransactionResult result,
+                    public void onTransactionCompleted(CallTransactionResult result,
                             String transactionName) {
-                        if (result.getResult() != VoipCallTransactionResult.RESULT_SUCCEED) {
+                        if (result.getResult() != CallTransactionResult.RESULT_SUCCEED) {
                             CompletableFuture.completedFuture(null).thenApplyAsync(
                                     (x) -> {
                                         finish(result);
@@ -68,8 +71,8 @@ public class ParallelTransaction extends VoipCallTransaction {
                     public void onTransactionTimeout(String transactionName) {
                         CompletableFuture.completedFuture(null).thenApplyAsync(
                                 (x) -> {
-                                    VoipCallTransactionResult mainResult =
-                                            new VoipCallTransactionResult(
+                                    CallTransactionResult mainResult =
+                                            new CallTransactionResult(
                                                     CallException.CODE_OPERATION_TIMED_OUT,
                                             String.format("sub transaction %s timed out",
                                                     transactionName));
@@ -82,7 +85,7 @@ public class ParallelTransaction extends VoipCallTransaction {
                                                 + ".oTT", mLock));
                     }
                 };
-        for (VoipCallTransaction transaction : mSubTransactions) {
+        for (CallTransaction transaction : mSubTransactions) {
             transaction.setCompleteListener(subTransactionListener);
             transaction.start();
         }
diff --git a/src/com/android/server/telecom/voip/RequestNewActiveCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/RequestNewActiveCallTransaction.java
similarity index 83%
rename from src/com/android/server/telecom/voip/RequestNewActiveCallTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/RequestNewActiveCallTransaction.java
index e3aed8e7f..8e6e3540f 100644
--- a/src/com/android/server/telecom/voip/RequestNewActiveCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/RequestNewActiveCallTransaction.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.os.OutcomeReceiver;
 import android.telecom.CallException;
@@ -24,6 +24,8 @@ import com.android.server.telecom.Call;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.ConnectionServiceFocusManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 import com.android.server.telecom.flags.Flags;
 
 import java.util.concurrent.CompletableFuture;
@@ -42,7 +44,7 @@ import java.util.concurrent.CompletionStage;
  * - MaybeHoldCallForNewCallTransaction was performed before this so any potential active calls
  * should be held now.
  */
-public class RequestNewActiveCallTransaction extends VoipCallTransaction {
+public class RequestNewActiveCallTransaction extends CallTransaction {
 
     private static final String TAG = RequestNewActiveCallTransaction.class.getSimpleName();
     private final CallsManager mCallsManager;
@@ -55,14 +57,14 @@ public class RequestNewActiveCallTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
         int currentCallState = mCall.getState();
 
         // certain calls cannot go active/answered (ex. disconnect calls, etc.)
         if (!canBecomeNewCallFocus(currentCallState)) {
-            future.complete(new VoipCallTransactionResult(
+            future.complete(new CallTransactionResult(
                     CallException.CODE_CALL_CANNOT_BE_SET_TO_ACTIVE,
                     "CallState cannot be set to active or answered due to current call"
                             + " state being in invalid state"));
@@ -71,7 +73,7 @@ public class RequestNewActiveCallTransaction extends VoipCallTransaction {
 
         if (!Flags.transactionalHoldDisconnectsUnholdable() &&
                 mCallsManager.getActiveCall() != null) {
-            future.complete(new VoipCallTransactionResult(
+            future.complete(new CallTransactionResult(
                     CallException.CODE_CALL_CANNOT_BE_SET_TO_ACTIVE,
                     "Already an active call. Request hold on current active call."));
             return future;
@@ -81,14 +83,14 @@ public class RequestNewActiveCallTransaction extends VoipCallTransaction {
                     @Override
                     public void onResult(Boolean result) {
                         Log.d(TAG, "processTransaction: onResult");
-                        future.complete(new VoipCallTransactionResult(
-                                VoipCallTransactionResult.RESULT_SUCCEED, null));
+                        future.complete(new CallTransactionResult(
+                                CallTransactionResult.RESULT_SUCCEED, null));
                     }
 
                     @Override
                     public void onError(CallException exception) {
                         Log.d(TAG, "processTransaction: onError");
-                        future.complete(new VoipCallTransactionResult(
+                        future.complete(new CallTransactionResult(
                                 exception.getCode(), exception.getMessage()));
                     }
                 });
diff --git a/src/com/android/server/telecom/voip/RequestVideoStateTransaction.java b/src/com/android/server/telecom/callsequencing/voip/RequestVideoStateTransaction.java
similarity index 73%
rename from src/com/android/server/telecom/voip/RequestVideoStateTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/RequestVideoStateTransaction.java
index c1bc3432b..6fb183694 100644
--- a/src/com/android/server/telecom/voip/RequestVideoStateTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/RequestVideoStateTransaction.java
@@ -14,9 +14,10 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToVideoProfileState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToVideoProfileState;
 
 import android.telecom.CallException;
 import android.telecom.VideoProfile;
@@ -24,11 +25,13 @@ import android.util.Log;
 
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.Call;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
 
-public class RequestVideoStateTransaction extends VoipCallTransaction {
+public class RequestVideoStateTransaction extends CallTransaction {
 
     private static final String TAG = RequestVideoStateTransaction.class.getSimpleName();
     private final Call mCall;
@@ -42,19 +45,19 @@ public class RequestVideoStateTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
         if (isRequestingVideoTransmission(mVideoProfileState) &&
                 !mCall.isVideoCallingSupportedByPhoneAccount()) {
-            future.complete(new VoipCallTransactionResult(
+            future.complete(new CallTransactionResult(
                     CallException.CODE_ERROR_UNKNOWN /*TODO:: define error code. b/335703584 */,
                     "Video calling is not supported by the target account"));
         } else {
             mCall.setVideoState(mVideoProfileState);
-            future.complete(new VoipCallTransactionResult(
-                    VoipCallTransactionResult.RESULT_SUCCEED,
+            future.complete(new CallTransactionResult(
+                    CallTransactionResult.RESULT_SUCCEED,
                     "The Video State was changed successfully"));
         }
         return future;
diff --git a/src/com/android/server/telecom/voip/SerialTransaction.java b/src/com/android/server/telecom/callsequencing/voip/SerialTransaction.java
similarity index 79%
rename from src/com/android/server/telecom/voip/SerialTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/SerialTransaction.java
index 748f28500..d5d75d086 100644
--- a/src/com/android/server/telecom/voip/SerialTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/SerialTransaction.java
@@ -14,27 +14,30 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.telecom.CallException;
 
 import com.android.server.telecom.LoggedHandlerExecutor;
 import com.android.server.telecom.TelecomSystem;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import java.util.List;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.atomic.AtomicInteger;
 
 /**
- * A VoipCallTransaction implementation that its sub transactions will be executed in serial
+ * A CallTransaction implementation that its sub transactions will be executed in serial
  */
-public class SerialTransaction extends VoipCallTransaction {
-    public SerialTransaction(List<VoipCallTransaction> subTransactions,
+public class SerialTransaction extends CallTransaction {
+    public SerialTransaction(List<CallTransaction> subTransactions,
             TelecomSystem.SyncRoot lock) {
         super(subTransactions, lock);
     }
 
-    public void appendTransaction(VoipCallTransaction transaction){
+    public void appendTransaction(CallTransaction transaction){
         mSubTransactions.add(transaction);
     }
 
@@ -49,9 +52,9 @@ public class SerialTransaction extends VoipCallTransaction {
                     private final AtomicInteger mTransactionIndex = new AtomicInteger(0);
 
                     @Override
-                    public void onTransactionCompleted(VoipCallTransactionResult result,
+                    public void onTransactionCompleted(CallTransactionResult result,
                             String transactionName) {
-                        if (result.getResult() != VoipCallTransactionResult.RESULT_SUCCEED) {
+                        if (result.getResult() != CallTransactionResult.RESULT_SUCCEED) {
                             handleTransactionFailure();
                             CompletableFuture.completedFuture(null).thenApplyAsync(
                                     (x) -> {
@@ -65,7 +68,7 @@ public class SerialTransaction extends VoipCallTransaction {
                         } else {
                             int currTransactionIndex = mTransactionIndex.incrementAndGet();
                             if (currTransactionIndex < mSubTransactions.size()) {
-                                VoipCallTransaction transaction = mSubTransactions.get(
+                                CallTransaction transaction = mSubTransactions.get(
                                         currTransactionIndex);
                                 transaction.setCompleteListener(this);
                                 transaction.start();
@@ -80,8 +83,8 @@ public class SerialTransaction extends VoipCallTransaction {
                         handleTransactionFailure();
                         CompletableFuture.completedFuture(null).thenApplyAsync(
                                 (x) -> {
-                                    VoipCallTransactionResult mainResult =
-                                            new VoipCallTransactionResult(
+                                    CallTransactionResult mainResult =
+                                            new CallTransactionResult(
                                                     CallException.CODE_OPERATION_TIMED_OUT,
                                             String.format("sub transaction %s timed out",
                                                     transactionName));
@@ -94,7 +97,7 @@ public class SerialTransaction extends VoipCallTransaction {
                                                 + ".oTT", mLock));
                     }
                 };
-        VoipCallTransaction transaction = mSubTransactions.get(0);
+        CallTransaction transaction = mSubTransactions.get(0);
         transaction.setCompleteListener(subTransactionListener);
         transaction.start();
 
diff --git a/src/com/android/server/telecom/voip/SetMuteStateTransaction.java b/src/com/android/server/telecom/callsequencing/voip/SetMuteStateTransaction.java
similarity index 74%
rename from src/com/android/server/telecom/voip/SetMuteStateTransaction.java
rename to src/com/android/server/telecom/callsequencing/voip/SetMuteStateTransaction.java
index d9f73294e..14f8945e5 100644
--- a/src/com/android/server/telecom/voip/SetMuteStateTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/SetMuteStateTransaction.java
@@ -14,11 +14,13 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.util.Log;
 
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.CompletionStage;
@@ -27,7 +29,7 @@ import java.util.concurrent.CompletionStage;
  * This transaction should be used to change the global mute state for transactional
  * calls. There is currently no way for this transaction to fail.
  */
-public class SetMuteStateTransaction extends VoipCallTransaction {
+public class SetMuteStateTransaction extends CallTransaction {
 
     private static final String TAG = SetMuteStateTransaction.class.getSimpleName();
     private final CallsManager mCallsManager;
@@ -40,14 +42,14 @@ public class SetMuteStateTransaction extends VoipCallTransaction {
     }
 
     @Override
-    public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
         Log.d(TAG, "processTransaction");
-        CompletableFuture<VoipCallTransactionResult> future = new CompletableFuture<>();
+        CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
         mCallsManager.mute(mIsMuted);
 
-        future.complete(new VoipCallTransactionResult(
-                VoipCallTransactionResult.RESULT_SUCCEED,
+        future.complete(new CallTransactionResult(
+                CallTransactionResult.RESULT_SUCCEED,
                 "The Mute State was changed successfully"));
 
         return future;
diff --git a/src/com/android/server/telecom/voip/VideoStateTranslation.java b/src/com/android/server/telecom/callsequencing/voip/VideoStateTranslation.java
similarity index 96%
rename from src/com/android/server/telecom/voip/VideoStateTranslation.java
rename to src/com/android/server/telecom/callsequencing/voip/VideoStateTranslation.java
index 3812d15c0..4610f964a 100644
--- a/src/com/android/server/telecom/voip/VideoStateTranslation.java
+++ b/src/com/android/server/telecom/callsequencing/voip/VideoStateTranslation.java
@@ -14,17 +14,12 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import android.telecom.CallAttributes;
 import android.telecom.Log;
 import android.telecom.VideoProfile;
 
-import com.android.server.telecom.AnomalyReporterAdapter;
-import com.android.server.telecom.AnomalyReporterAdapterImpl;
-
-import java.util.UUID;
-
 /**
  * This remapping class is needed because {@link VideoProfile} has more fine grain levels of video
  * states as apposed to Transactional video states (defined in  {@link CallAttributes.CallType}.
diff --git a/src/com/android/server/telecom/voip/VoipCallMonitor.java b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
similarity index 99%
rename from src/com/android/server/telecom/voip/VoipCallMonitor.java
rename to src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
index 8f6ad514f..1d1a1a6df 100644
--- a/src/com/android/server/telecom/voip/VoipCallMonitor.java
+++ b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
@@ -14,7 +14,7 @@
  * limitations under the License.
  */
 
-package com.android.server.telecom.voip;
+package com.android.server.telecom.callsequencing.voip;
 
 import static android.app.ForegroundServiceDelegationOptions.DELEGATION_SERVICE_PHONE_CALL;
 import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
diff --git a/src/com/android/server/telecom/components/TelecomService.java b/src/com/android/server/telecom/components/TelecomService.java
index 2d8c78ead..4db3e1450 100644
--- a/src/com/android/server/telecom/components/TelecomService.java
+++ b/src/com/android/server/telecom/components/TelecomService.java
@@ -81,10 +81,11 @@ public class TelecomService extends Service implements TelecomSystem.Component {
         Log.d(this, "onBind");
         return new ITelecomLoader.Stub() {
             @Override
-            public ITelecomService createTelecomService(IInternalServiceRetriever retriever) {
+            public ITelecomService createTelecomService(IInternalServiceRetriever retriever,
+                    String sysUiPackageName) {
                 InternalServiceRetrieverAdapter adapter =
                         new InternalServiceRetrieverAdapter(retriever);
-                initializeTelecomSystem(TelecomService.this, adapter);
+                initializeTelecomSystem(TelecomService.this, adapter, sysUiPackageName);
                 synchronized (getTelecomSystem().getLock()) {
                     return getTelecomSystem().getTelecomServiceImpl().getBinder();
                 }
@@ -103,7 +104,7 @@ public class TelecomService extends Service implements TelecomSystem.Component {
      * @param context
      */
     static void initializeTelecomSystem(Context context,
-            InternalServiceRetrieverAdapter internalServiceRetriever) {
+            InternalServiceRetrieverAdapter internalServiceRetriever, String sysUiPackageName) {
         if (TelecomSystem.getInstance() == null) {
             FeatureFlags featureFlags = new FeatureFlagsImpl();
             NotificationChannelManager notificationChannelManager =
@@ -204,6 +205,7 @@ public class TelecomService extends Service implements TelecomSystem.Component {
                                     (RoleManager) context.getSystemService(Context.ROLE_SERVICE)),
                             new ContactsAsyncHelper.Factory(),
                             internalServiceRetriever.getDeviceIdleController(),
+                            sysUiPackageName,
                             new Ringer.AccessibilityManagerAdapter() {
                                 @Override
                                 public boolean startFlashNotificationSequence(
diff --git a/src/com/android/server/telecom/metrics/ApiStats.java b/src/com/android/server/telecom/metrics/ApiStats.java
index b37569f0d..4b23e47d9 100644
--- a/src/com/android/server/telecom/metrics/ApiStats.java
+++ b/src/com/android/server/telecom/metrics/ApiStats.java
@@ -18,10 +18,12 @@ package com.android.server.telecom.metrics;
 
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
 
+import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.app.StatsManager;
 import android.content.Context;
 import android.os.Looper;
+import android.telecom.Log;
 import android.util.StatsEvent;
 
 import androidx.annotation.VisibleForTesting;
@@ -29,6 +31,8 @@ import androidx.annotation.VisibleForTesting;
 import com.android.server.telecom.TelecomStatsLog;
 import com.android.server.telecom.nano.PulledAtomsClass;
 
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
@@ -36,9 +40,134 @@ import java.util.Map;
 import java.util.Objects;
 
 public class ApiStats extends TelecomPulledAtom {
-
+    public static final int API_UNSPECIFIC = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_UNSPECIFIED;
+    public static final int API_ACCEPTHANDOVER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ACCEPT_HANDOVER;
+    public static final int API_ACCEPTRINGINGCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ACCEPT_RINGING_CALL;
+    public static final int API_ACCEPTRINGINGCALLWITHVIDEOSTATE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ACCEPT_RINGING_CALL_WITH_VIDEO_STATE;
+    public static final int API_ADDCALL = TelecomStatsLog.TELECOM_API_STATS__API_NAME__API_ADD_CALL;
+    public static final int API_ADDNEWINCOMINGCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ADD_NEW_INCOMING_CALL;
+    public static final int API_ADDNEWINCOMINGCONFERENCE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ADD_NEW_INCOMING_CONFERENCE;
+    public static final int API_ADDNEWUNKNOWNCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ADD_NEW_UNKNOWN_CALL;
+    public static final int API_CANCELMISSEDCALLSNOTIFICATION = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_CANCEL_MISSED_CALLS_NOTIFICATION;
+    public static final int API_CLEARACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_CLEAR_ACCOUNTS;
+    public static final int API_CREATELAUNCHEMERGENCYDIALERINTENT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_CREATE_LAUNCH_EMERGENCY_DIALER_INTENT;
+    public static final int API_CREATEMANAGEBLOCKEDNUMBERSINTENT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_CREATE_MANAGE_BLOCKED_NUMBERS_INTENT;
+    public static final int API_DUMP = TelecomStatsLog.TELECOM_API_STATS__API_NAME__API_DUMP;
+    public static final int API_DUMPCALLANALYTICS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_DUMP_CALL_ANALYTICS;
+    public static final int API_ENABLEPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_ENABLE_PHONE_ACCOUNT;
+    public static final int API_ENDCALL = TelecomStatsLog.TELECOM_API_STATS__API_NAME__API_END_CALL;
+    public static final int API_GETADNURIFORPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_ADN_URI_FOR_PHONE_ACCOUNT;
+    public static final int API_GETALLPHONEACCOUNTHANDLES = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_ALL_PHONE_ACCOUNT_HANDLES;
+    public static final int API_GETALLPHONEACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_ALL_PHONE_ACCOUNTS;
+    public static final int API_GETALLPHONEACCOUNTSCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_ALL_PHONE_ACCOUNTS_COUNT;
+    public static final int API_GETCALLCAPABLEPHONEACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_CALL_CAPABLE_PHONE_ACCOUNTS;
+    public static final int API_GETCALLSTATE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_CALL_STATE;
+    public static final int API_GETCALLSTATEUSINGPACKAGE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_CALL_STATE_USING_PACKAGE;
+    public static final int API_GETCURRENTTTYMODE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_CURRENT_TTY_MODE;
+    public static final int API_GETDEFAULTDIALERPACKAGE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_DEFAULT_DIALER_PACKAGE;
+    public static final int API_GETDEFAULTDIALERPACKAGEFORUSER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_DEFAULT_DIALER_PACKAGE_FOR_USER;
+    public static final int API_GETDEFAULTOUTGOINGPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_DEFAULT_OUTGOING_PHONE_ACCOUNT;
+    public static final int API_GETDEFAULTPHONEAPP = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_DEFAULT_PHONE_APP;
+    public static final int API_GETLINE1NUMBER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_LINE1_NUMBER;
+    public static final int API_GETOWNSELFMANAGEDPHONEACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_OWN_SELF_MANAGED_PHONE_ACCOUNTS;
+    public static final int API_GETPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_PHONE_ACCOUNT;
+    public static final int API_GETPHONEACCOUNTSFORPACKAGE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_PHONE_ACCOUNTS_FOR_PACKAGE;
+    public static final int API_GETPHONEACCOUNTSSUPPORTINGSCHEME = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_PHONE_ACCOUNTS_SUPPORTING_SCHEME;
+    public static final int API_GETREGISTEREDPHONEACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_REGISTERED_PHONE_ACCOUNTS;
+    public static final int API_GETSELFMANAGEDPHONEACCOUNTS = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_SELF_MANAGED_PHONE_ACCOUNTS;
+    public static final int API_GETSIMCALLMANAGER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_SIM_CALL_MANAGER;
+    public static final int API_GETSIMCALLMANAGERFORUSER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_SIM_CALL_MANAGER_FOR_USER;
+    public static final int API_GETSYSTEMDIALERPACKAGE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_SYSTEM_DIALER_PACKAGE;
+    public static final int API_GETUSERSELECTEDOUTGOINGPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT;
+    public static final int API_GETVOICEMAILNUMBER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_GET_VOICE_MAIL_NUMBER;
+    public static final int API_HANDLEPINMMI = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_HANDLE_PIN_MMI;
+    public static final int API_HANDLEPINMMIFORPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_HANDLE_PIN_MMI_FOR_PHONE_ACCOUNT;
+    public static final int API_HASMANAGEONGOINGCALLSPERMISSION = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_HAS_MANAGE_ONGOING_CALLS_PERMISSION;
+    public static final int API_ISINCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_IN_CALL;
+    public static final int API_ISINCOMINGCALLPERMITTED = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_IN_EMERGENCY_CALL;
+    public static final int API_ISINEMERGENCYCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_IN_MANAGED_CALL;
+    public static final int API_ISINMANAGEDCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_IN_SELF_MANAGED_CALL;
+    public static final int API_ISINSELFMANAGEDCALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_INCOMING_CALL_PERMITTED;
+    public static final int API_ISOUTGOINGCALLPERMITTED = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_OUTGOING_CALL_PERMITTED;
+    public static final int API_ISRINGING = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_RINGING;
+    public static final int API_ISTTYSUPPORTED = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_TTY_SUPPORTED;
+    public static final int API_ISVOICEMAILNUMBER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_IS_VOICE_MAIL_NUMBER;
+    public static final int API_PLACECALL = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_PLACE_CALL;
+    public static final int API_REGISTERPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_REGISTER_PHONE_ACCOUNT;
+    public static final int API_SETDEFAULTDIALER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_SET_DEFAULT_DIALER;
+    public static final int API_SETUSERSELECTEDOUTGOINGPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_SET_USER_SELECTED_OUTGOING_PHONE_ACCOUNT;
+    public static final int API_SHOWINCALLSCREEN = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_SHOW_IN_CALL_SCREEN;
+    public static final int API_SILENCERINGER = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_SILENCE_RINGER;
+    public static final int API_STARTCONFERENCE = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_START_CONFERENCE;
+    public static final int API_UNREGISTERPHONEACCOUNT = TelecomStatsLog
+            .TELECOM_API_STATS__API_NAME__API_UNREGISTER_PHONE_ACCOUNT;
+    public static final int RESULT_UNKNOWN = TelecomStatsLog
+            .TELECOM_API_STATS__API_RESULT__RESULT_UNKNOWN;
+    public static final int RESULT_NORMAL = TelecomStatsLog
+            .TELECOM_API_STATS__API_RESULT__RESULT_SUCCESS;
+    public static final int RESULT_PERMISSION = TelecomStatsLog
+            .TELECOM_API_STATS__API_RESULT__RESULT_PERMISSION;
+    public static final int RESULT_EXCEPTION = TelecomStatsLog
+            .TELECOM_API_STATS__API_RESULT__RESULT_EXCEPTION;
+    private static final String TAG = ApiStats.class.getSimpleName();
     private static final String FILE_NAME = "api_stats";
-    private Map<ApiStatsKey, Integer> mApiStatsMap;
+    private Map<ApiEvent, Integer> mApiStatsMap;
 
     public ApiStats(@NonNull Context context, @NonNull Looper looper) {
         super(context, looper);
@@ -62,6 +191,8 @@ public class ApiStats extends TelecomPulledAtom {
             Arrays.stream(mPulledAtoms.telecomApiStats).forEach(v -> data.add(
                     TelecomStatsLog.buildStatsEvent(getTag(),
                             v.getApiName(), v.getUid(), v.getApiResult(), v.getCount())));
+            mApiStatsMap.clear();
+            onAggregate();
             return StatsManager.PULL_SUCCESS;
         } else {
             return StatsManager.PULL_SKIP;
@@ -73,7 +204,7 @@ public class ApiStats extends TelecomPulledAtom {
         if (mPulledAtoms.telecomApiStats != null) {
             mApiStatsMap = new HashMap<>();
             for (PulledAtomsClass.TelecomApiStats v : mPulledAtoms.telecomApiStats) {
-                mApiStatsMap.put(new ApiStatsKey(v.getApiName(), v.getUid(), v.getApiResult()),
+                mApiStatsMap.put(new ApiEvent(v.getApiName(), v.getUid(), v.getApiResult()),
                         v.getCount());
             }
             mLastPulledTimestamps = mPulledAtoms.getTelecomApiStatsPullTimestampMillis();
@@ -83,6 +214,7 @@ public class ApiStats extends TelecomPulledAtom {
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     @Override
     public synchronized void onAggregate() {
+        Log.d(TAG, "onAggregate: %s", mApiStatsMap);
         clearAtoms();
         if (mApiStatsMap.isEmpty()) {
             return;
@@ -93,7 +225,7 @@ public class ApiStats extends TelecomPulledAtom {
         int[] index = new int[1];
         mApiStatsMap.forEach((k, v) -> {
             mPulledAtoms.telecomApiStats[index[0]] = new PulledAtomsClass.TelecomApiStats();
-            mPulledAtoms.telecomApiStats[index[0]].setApiName(k.mApiId);
+            mPulledAtoms.telecomApiStats[index[0]].setApiName(k.mId);
             mPulledAtoms.telecomApiStats[index[0]].setUid(k.mCallerUid);
             mPulledAtoms.telecomApiStats[index[0]].setApiResult(k.mResult);
             mPulledAtoms.telecomApiStats[index[0]].setCount(v);
@@ -102,46 +234,131 @@ public class ApiStats extends TelecomPulledAtom {
         save(DELAY_FOR_PERSISTENT_MILLIS);
     }
 
-    public void log(int apiId, int callerUid, int result) {
+    public void log(@NonNull ApiEvent event) {
         post(() -> {
-            ApiStatsKey key = new ApiStatsKey(apiId, callerUid, result);
-            mApiStatsMap.put(key, mApiStatsMap.getOrDefault(key, 0) + 1);
+            mApiStatsMap.put(event, mApiStatsMap.getOrDefault(event, 0) + 1);
             onAggregate();
         });
     }
 
-    static class ApiStatsKey {
+    @IntDef(prefix = "API", value = {
+            API_UNSPECIFIC,
+            API_ACCEPTHANDOVER,
+            API_ACCEPTRINGINGCALL,
+            API_ACCEPTRINGINGCALLWITHVIDEOSTATE,
+            API_ADDCALL,
+            API_ADDNEWINCOMINGCALL,
+            API_ADDNEWINCOMINGCONFERENCE,
+            API_ADDNEWUNKNOWNCALL,
+            API_CANCELMISSEDCALLSNOTIFICATION,
+            API_CLEARACCOUNTS,
+            API_CREATELAUNCHEMERGENCYDIALERINTENT,
+            API_CREATEMANAGEBLOCKEDNUMBERSINTENT,
+            API_DUMP,
+            API_DUMPCALLANALYTICS,
+            API_ENABLEPHONEACCOUNT,
+            API_ENDCALL,
+            API_GETADNURIFORPHONEACCOUNT,
+            API_GETALLPHONEACCOUNTHANDLES,
+            API_GETALLPHONEACCOUNTS,
+            API_GETALLPHONEACCOUNTSCOUNT,
+            API_GETCALLCAPABLEPHONEACCOUNTS,
+            API_GETCALLSTATE,
+            API_GETCALLSTATEUSINGPACKAGE,
+            API_GETCURRENTTTYMODE,
+            API_GETDEFAULTDIALERPACKAGE,
+            API_GETDEFAULTDIALERPACKAGEFORUSER,
+            API_GETDEFAULTOUTGOINGPHONEACCOUNT,
+            API_GETDEFAULTPHONEAPP,
+            API_GETLINE1NUMBER,
+            API_GETOWNSELFMANAGEDPHONEACCOUNTS,
+            API_GETPHONEACCOUNT,
+            API_GETPHONEACCOUNTSFORPACKAGE,
+            API_GETPHONEACCOUNTSSUPPORTINGSCHEME,
+            API_GETREGISTEREDPHONEACCOUNTS,
+            API_GETSELFMANAGEDPHONEACCOUNTS,
+            API_GETSIMCALLMANAGER,
+            API_GETSIMCALLMANAGERFORUSER,
+            API_GETSYSTEMDIALERPACKAGE,
+            API_GETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+            API_GETVOICEMAILNUMBER,
+            API_HANDLEPINMMI,
+            API_HANDLEPINMMIFORPHONEACCOUNT,
+            API_HASMANAGEONGOINGCALLSPERMISSION,
+            API_ISINCALL,
+            API_ISINCOMINGCALLPERMITTED,
+            API_ISINEMERGENCYCALL,
+            API_ISINMANAGEDCALL,
+            API_ISINSELFMANAGEDCALL,
+            API_ISOUTGOINGCALLPERMITTED,
+            API_ISRINGING,
+            API_ISTTYSUPPORTED,
+            API_ISVOICEMAILNUMBER,
+            API_PLACECALL,
+            API_REGISTERPHONEACCOUNT,
+            API_SETDEFAULTDIALER,
+            API_SETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+            API_SHOWINCALLSCREEN,
+            API_SILENCERINGER,
+            API_STARTCONFERENCE,
+            API_UNREGISTERPHONEACCOUNT,
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface ApiId {
+    }
+
+    @IntDef(prefix = "RESULT", value = {
+            RESULT_UNKNOWN,
+            RESULT_NORMAL,
+            RESULT_PERMISSION,
+            RESULT_EXCEPTION,
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface ResultId {
+    }
+
+    public static class ApiEvent {
 
-        int mApiId;
+        @ApiId
+        int mId;
         int mCallerUid;
+        @ResultId
         int mResult;
 
-        ApiStatsKey(int apiId, int callerUid, int result) {
-            mApiId = apiId;
+        public ApiEvent(@ApiId int id, int callerUid, @ResultId int result) {
+            mId = id;
             mCallerUid = callerUid;
             mResult = result;
         }
 
+        public void setCallerUid(int uid) {
+            this.mCallerUid = uid;
+        }
+
+        public void setResult(@ResultId int result) {
+            this.mResult = result;
+        }
+
         @Override
         public boolean equals(Object other) {
             if (this == other) {
                 return true;
             }
-            if (other == null || !(other instanceof ApiStatsKey obj)) {
+            if (!(other instanceof ApiEvent obj)) {
                 return false;
             }
-            return this.mApiId == obj.mApiId && this.mCallerUid == obj.mCallerUid
+            return this.mId == obj.mId && this.mCallerUid == obj.mCallerUid
                     && this.mResult == obj.mResult;
         }
 
         @Override
         public int hashCode() {
-            return Objects.hash(mApiId, mCallerUid, mResult);
+            return Objects.hash(mId, mCallerUid, mResult);
         }
 
         @Override
         public String toString() {
-            return "[ApiStatsKey: mApiId=" + mApiId + ", mCallerUid=" + mCallerUid
+            return "[ApiEvent: mApiId=" + mId + ", mCallerUid=" + mCallerUid
                     + ", mResult=" + mResult + "]";
         }
     }
diff --git a/src/com/android/server/telecom/metrics/AudioRouteStats.java b/src/com/android/server/telecom/metrics/AudioRouteStats.java
index 21624f1fa..4611b2220 100644
--- a/src/com/android/server/telecom/metrics/AudioRouteStats.java
+++ b/src/com/android/server/telecom/metrics/AudioRouteStats.java
@@ -99,6 +99,8 @@ public class AudioRouteStats extends TelecomPulledAtom {
                     TelecomStatsLog.buildStatsEvent(getTag(),
                             v.getCallAudioRouteSource(), v.getCallAudioRouteDest(),
                             v.getSuccess(), v.getRevert(), v.getCount(), v.getAverageLatencyMs())));
+            mAudioRouteStatsMap.clear();
+            onAggregate();
             return StatsManager.PULL_SUCCESS;
         } else {
             return StatsManager.PULL_SKIP;
diff --git a/src/com/android/server/telecom/metrics/CallStats.java b/src/com/android/server/telecom/metrics/CallStats.java
index 39b0e6d77..8bdeffbca 100644
--- a/src/com/android/server/telecom/metrics/CallStats.java
+++ b/src/com/android/server/telecom/metrics/CallStats.java
@@ -81,6 +81,8 @@ public class CallStats extends TelecomPulledAtom {
                             v.getCallDirection(), v.getExternalCall(), v.getEmergencyCall(),
                             v.getMultipleAudioAvailable(), v.getAccountType(), v.getUid(),
                             v.getCount(), v.getAverageDurationMs())));
+            mCallStatsMap.clear();
+            onAggregate();
             return StatsManager.PULL_SUCCESS;
         } else {
             return StatsManager.PULL_SKIP;
@@ -129,7 +131,7 @@ public class CallStats extends TelecomPulledAtom {
     }
 
     public void log(int direction, boolean isExternal, boolean isEmergency,
-                    boolean isMultipleAudioAvailable, int accountType, int uid, int duration) {
+            boolean isMultipleAudioAvailable, int accountType, int uid, int duration) {
         post(() -> {
             CallStatsKey key = new CallStatsKey(direction, isExternal, isEmergency,
                     isMultipleAudioAvailable, accountType, uid);
@@ -158,13 +160,23 @@ public class CallStats extends TelecomPulledAtom {
                     : (call.isOutgoing() ? CALL_STATS__CALL_DIRECTION__DIR_OUTGOING
                     : CALL_STATS__CALL_DIRECTION__DIR_UNKNOWN);
             final int accountType = getAccountType(call.getPhoneAccountFromHandle());
-            final int uid = call.getAssociatedUser().getIdentifier();
+            int uid = call.getCallingPackageIdentity().mCallingPackageUid;
+            try {
+                uid = mContext.getPackageManager().getApplicationInfo(
+                        call.getTargetPhoneAccount().getComponentName().getPackageName(), 0).uid;
+            } catch (Exception e) {
+                Log.i(TAG, "failed to get the uid for " + e);
+            }
+
             log(direction, call.isExternalCall(), call.isEmergencyCall(), hasMultipleAudioDevices,
                     accountType, uid, duration);
         });
     }
 
     private int getAccountType(PhoneAccount account) {
+        if (account == null) {
+            return CALL_STATS__ACCOUNT_TYPE__ACCOUNT_UNKNOWN;
+        }
         if (account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
             return account.hasCapabilities(
                     PhoneAccount.CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS)
@@ -202,7 +214,7 @@ public class CallStats extends TelecomPulledAtom {
         final int mUid;
 
         CallStatsKey(int direction, boolean isExternal, boolean isEmergency,
-                     boolean isMultipleAudioAvailable, int accountType, int uid) {
+                boolean isMultipleAudioAvailable, int accountType, int uid) {
             mDirection = direction;
             mIsExternal = isExternal;
             mIsEmergency = isEmergency;
diff --git a/src/com/android/server/telecom/metrics/ErrorStats.java b/src/com/android/server/telecom/metrics/ErrorStats.java
index e4d0a51ca..f334710f6 100644
--- a/src/com/android/server/telecom/metrics/ErrorStats.java
+++ b/src/com/android/server/telecom/metrics/ErrorStats.java
@@ -18,10 +18,12 @@ package com.android.server.telecom.metrics;
 
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
 
+import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.app.StatsManager;
 import android.content.Context;
 import android.os.Looper;
+import android.telecom.Log;
 import android.util.StatsEvent;
 
 import androidx.annotation.VisibleForTesting;
@@ -29,6 +31,8 @@ import androidx.annotation.VisibleForTesting;
 import com.android.server.telecom.TelecomStatsLog;
 import com.android.server.telecom.nano.PulledAtomsClass;
 
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
@@ -36,9 +40,83 @@ import java.util.Map;
 import java.util.Objects;
 
 public class ErrorStats extends TelecomPulledAtom {
-
+    public static final int SUB_UNKNOWN = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_UNKNOWN;
+    public static final int SUB_CALL_AUDIO = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_CALL_AUDIO;
+    public static final int SUB_CALL_LOGS = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_CALL_LOGS;
+    public static final int SUB_CALL_MANAGER = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_CALL_MANAGER;
+    public static final int SUB_CONNECTION_SERVICE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_CONNECTION_SERVICE;
+    public static final int SUB_EMERGENCY_CALL = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_EMERGENCY_CALL;
+    public static final int SUB_IN_CALL_SERVICE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_IN_CALL_SERVICE;
+    public static final int SUB_MISC = TelecomStatsLog.TELECOM_ERROR_STATS__SUBMODULE__SUB_MISC;
+    public static final int SUB_PHONE_ACCOUNT = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_PHONE_ACCOUNT;
+    public static final int SUB_SYSTEM_SERVICE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_SYSTEM_SERVICE;
+    public static final int SUB_TELEPHONY = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_TELEPHONY;
+    public static final int SUB_UI = TelecomStatsLog.TELECOM_ERROR_STATS__SUBMODULE__SUB_UI;
+    public static final int SUB_VOIP_CALL = TelecomStatsLog
+            .TELECOM_ERROR_STATS__SUBMODULE__SUB_VOIP_CALL;
+    public static final int ERROR_UNKNOWN = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_UNKNOWN;
+    public static final int ERROR_EXTERNAL_EXCEPTION = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_EXTERNAL_EXCEPTION;
+    public static final int ERROR_INTERNAL_EXCEPTION = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_INTERNAL_EXCEPTION;
+    public static final int ERROR_AUDIO_ROUTE_RETRY_REJECTED = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_AUDIO_ROUTE_RETRY_REJECTED;
+    public static final int ERROR_BT_GET_SERVICE_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_BT_GET_SERVICE_FAILURE;
+    public static final int ERROR_BT_REGISTER_CALLBACK_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_BT_REGISTER_CALLBACK_FAILURE;
+    public static final int ERROR_AUDIO_ROUTE_UNAVAILABLE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_AUDIO_ROUTE_UNAVAILABLE;
+    public static final int ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE;
+    public static final int ERROR_NOTIFY_CALL_STREAM_START_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_NOTIFY_CALL_STREAM_START_FAILURE;
+    public static final int ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE;
+    public static final int ERROR_NOTIFY_CALL_STREAM_STOP_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_NOTIFY_CALL_STREAM_STOP_FAILURE;
+    public static final int ERROR_RTT_STREAM_CLOSE_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_RTT_STREAM_CLOSE_FAILURE;
+    public static final int ERROR_RTT_STREAM_CREATE_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_RTT_STREAM_CREATE_FAILURE;
+    public static final int ERROR_SET_MUTED_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_SET_MUTED_FAILURE;
+    public static final int ERROR_VIDEO_PROVIDER_SET_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_VIDEO_PROVIDER_SET_FAILURE;
+    public static final int ERROR_WIRED_HEADSET_NOT_AVAILABLE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_WIRED_HEADSET_NOT_AVAILABLE;
+    public static final int ERROR_LOG_CALL_FAILURE = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_LOG_CALL_FAILURE;
+    public static final int ERROR_RETRIEVING_ACCOUNT_EMERGENCY = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_RETRIEVING_ACCOUNT_EMERGENCY;
+    public static final int ERROR_RETRIEVING_ACCOUNT = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_RETRIEVING_ACCOUNT;
+    public static final int ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT;
+    public static final int ERROR_DEFAULT_MO_ACCOUNT_MISMATCH = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_DEFAULT_MO_ACCOUNT_MISMATCH;
+    public static final int ERROR_ESTABLISHING_CONNECTION = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_ESTABLISHING_CONNECTION;
+    public static final int ERROR_REMOVING_CALL = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_REMOVING_CALL;
+    public static final int ERROR_STUCK_CONNECTING_EMERGENCY = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_STUCK_CONNECTING_EMERGENCY;
+    public static final int ERROR_STUCK_CONNECTING = TelecomStatsLog
+            .TELECOM_ERROR_STATS__ERROR__ERROR_STUCK_CONNECTING;
+    private static final String TAG = ErrorStats.class.getSimpleName();
     private static final String FILE_NAME = "error_stats";
-    private Map<ErrorStatsKey, Integer> mErrorStatsMap;
+    private Map<ErrorEvent, Integer> mErrorStatsMap;
 
     public ErrorStats(@NonNull Context context, @NonNull Looper looper) {
         super(context, looper);
@@ -61,7 +139,9 @@ public class ErrorStats extends TelecomPulledAtom {
         if (mPulledAtoms.telecomErrorStats.length != 0) {
             Arrays.stream(mPulledAtoms.telecomErrorStats).forEach(v -> data.add(
                     TelecomStatsLog.buildStatsEvent(getTag(),
-                            v.getSubmoduleName(), v.getErrorName(), v.getCount())));
+                            v.getSubmodule(), v.getError(), v.getCount())));
+            mErrorStatsMap.clear();
+            onAggregate();
             return StatsManager.PULL_SUCCESS;
         } else {
             return StatsManager.PULL_SKIP;
@@ -73,7 +153,7 @@ public class ErrorStats extends TelecomPulledAtom {
         if (mPulledAtoms.telecomErrorStats != null) {
             mErrorStatsMap = new HashMap<>();
             for (PulledAtomsClass.TelecomErrorStats v : mPulledAtoms.telecomErrorStats) {
-                mErrorStatsMap.put(new ErrorStatsKey(v.getSubmoduleName(), v.getErrorName()),
+                mErrorStatsMap.put(new ErrorEvent(v.getSubmodule(), v.getError()),
                         v.getCount());
             }
             mLastPulledTimestamps = mPulledAtoms.getTelecomErrorStatsPullTimestampMillis();
@@ -83,6 +163,7 @@ public class ErrorStats extends TelecomPulledAtom {
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     @Override
     public synchronized void onAggregate() {
+        Log.d(TAG, "onAggregate: %s", mErrorStatsMap);
         clearAtoms();
         if (mErrorStatsMap.isEmpty()) {
             return;
@@ -93,28 +174,78 @@ public class ErrorStats extends TelecomPulledAtom {
         int[] index = new int[1];
         mErrorStatsMap.forEach((k, v) -> {
             mPulledAtoms.telecomErrorStats[index[0]] = new PulledAtomsClass.TelecomErrorStats();
-            mPulledAtoms.telecomErrorStats[index[0]].setSubmoduleName(k.mModuleId);
-            mPulledAtoms.telecomErrorStats[index[0]].setErrorName(k.mErrorId);
+            mPulledAtoms.telecomErrorStats[index[0]].setSubmodule(k.mModuleId);
+            mPulledAtoms.telecomErrorStats[index[0]].setError(k.mErrorId);
             mPulledAtoms.telecomErrorStats[index[0]].setCount(v);
             index[0]++;
         });
         save(DELAY_FOR_PERSISTENT_MILLIS);
     }
 
-    public void log(int moduleId, int errorId) {
+    public void log(@SubModuleId int moduleId, @ErrorId int errorId) {
         post(() -> {
-            ErrorStatsKey key = new ErrorStatsKey(moduleId, errorId);
+            ErrorEvent key = new ErrorEvent(moduleId, errorId);
             mErrorStatsMap.put(key, mErrorStatsMap.getOrDefault(key, 0) + 1);
             onAggregate();
         });
     }
 
-    static class ErrorStatsKey {
+    @IntDef(prefix = "SUB", value = {
+            SUB_UNKNOWN,
+            SUB_CALL_AUDIO,
+            SUB_CALL_LOGS,
+            SUB_CALL_MANAGER,
+            SUB_CONNECTION_SERVICE,
+            SUB_EMERGENCY_CALL,
+            SUB_IN_CALL_SERVICE,
+            SUB_MISC,
+            SUB_PHONE_ACCOUNT,
+            SUB_SYSTEM_SERVICE,
+            SUB_TELEPHONY,
+            SUB_UI,
+            SUB_VOIP_CALL,
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface SubModuleId {
+    }
+
+    @IntDef(prefix = "ERROR", value = {
+            ERROR_UNKNOWN,
+            ERROR_EXTERNAL_EXCEPTION,
+            ERROR_INTERNAL_EXCEPTION,
+            ERROR_AUDIO_ROUTE_RETRY_REJECTED,
+            ERROR_BT_GET_SERVICE_FAILURE,
+            ERROR_BT_REGISTER_CALLBACK_FAILURE,
+            ERROR_AUDIO_ROUTE_UNAVAILABLE,
+            ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE,
+            ERROR_NOTIFY_CALL_STREAM_START_FAILURE,
+            ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE,
+            ERROR_NOTIFY_CALL_STREAM_STOP_FAILURE,
+            ERROR_RTT_STREAM_CLOSE_FAILURE,
+            ERROR_RTT_STREAM_CREATE_FAILURE,
+            ERROR_SET_MUTED_FAILURE,
+            ERROR_VIDEO_PROVIDER_SET_FAILURE,
+            ERROR_WIRED_HEADSET_NOT_AVAILABLE,
+            ERROR_LOG_CALL_FAILURE,
+            ERROR_RETRIEVING_ACCOUNT_EMERGENCY,
+            ERROR_RETRIEVING_ACCOUNT,
+            ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT,
+            ERROR_DEFAULT_MO_ACCOUNT_MISMATCH,
+            ERROR_ESTABLISHING_CONNECTION,
+            ERROR_REMOVING_CALL,
+            ERROR_STUCK_CONNECTING_EMERGENCY,
+            ERROR_STUCK_CONNECTING,
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface ErrorId {
+    }
+
+    static class ErrorEvent {
 
-        final int mModuleId;
-        final int mErrorId;
+        final @SubModuleId int mModuleId;
+        final @ErrorId int mErrorId;
 
-        ErrorStatsKey(int moduleId, int errorId) {
+        ErrorEvent(@SubModuleId int moduleId, @ErrorId int errorId) {
             mModuleId = moduleId;
             mErrorId = errorId;
         }
@@ -124,7 +255,7 @@ public class ErrorStats extends TelecomPulledAtom {
             if (this == other) {
                 return true;
             }
-            if (!(other instanceof ErrorStatsKey obj)) {
+            if (!(other instanceof ErrorEvent obj)) {
                 return false;
             }
             return this.mModuleId == obj.mModuleId && this.mErrorId == obj.mErrorId;
@@ -137,7 +268,7 @@ public class ErrorStats extends TelecomPulledAtom {
 
         @Override
         public String toString() {
-            return "[ErrorStatsKey: mModuleId=" + mModuleId + ", mErrorId=" + mErrorId + "]";
+            return "[ErrorEvent: mModuleId=" + mModuleId + ", mErrorId=" + mErrorId + "]";
         }
     }
 }
diff --git a/src/com/android/server/telecom/metrics/TelecomMetricsController.java b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
index 8903b0259..df735c044 100644
--- a/src/com/android/server/telecom/metrics/TelecomMetricsController.java
+++ b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
@@ -30,6 +30,8 @@ import android.util.StatsEvent;
 
 import androidx.annotation.VisibleForTesting;
 
+import com.android.modules.utils.HandlerExecutor;
+
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
@@ -51,7 +53,7 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
 
     @NonNull
     public static TelecomMetricsController make(@NonNull Context context) {
-        Log.i(TAG, "TMC.iN1");
+        Log.i(TAG, "TMC.m1");
         HandlerThread handlerThread = new HandlerThread(TAG);
         handlerThread.start();
         return make(context, handlerThread);
@@ -61,7 +63,7 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     @NonNull
     public static TelecomMetricsController make(@NonNull Context context,
                                                 @NonNull HandlerThread handlerThread) {
-        Log.i(TAG, "TMC.iN2");
+        Log.i(TAG, "TMC.m2");
         Objects.requireNonNull(context);
         Objects.requireNonNull(handlerThread);
         return new TelecomMetricsController(context, handlerThread);
@@ -122,10 +124,23 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
 
     @VisibleForTesting
     public void registerAtom(int tag, TelecomPulledAtom atom) {
-        mStats.put(tag, atom);
+        final StatsManager statsManager = mContext.getSystemService(StatsManager.class);
+        if (statsManager != null) {
+            statsManager.setPullAtomCallback(tag, null, new HandlerExecutor(atom), this);
+            mStats.put(tag, atom);
+        } else {
+            Log.w(TAG, "Unable to register the pulled atom as StatsManager is null");
+        }
     }
 
     public void destroy() {
+        final StatsManager statsManager = mContext.getSystemService(StatsManager.class);
+        if (statsManager != null) {
+            mStats.forEach((tag, stat) -> statsManager.clearPullAtomCallback(tag));
+        } else {
+            Log.w(TAG, "Unable to clear pulled atoms as StatsManager is null");
+        }
+
         mStats.clear();
         mHandlerThread.quitSafely();
     }
diff --git a/src/com/android/server/telecom/metrics/TelecomPulledAtom.java b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
index d6eb039a4..161eaa8a4 100644
--- a/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
+++ b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
@@ -44,7 +44,7 @@ public abstract class TelecomPulledAtom extends Handler {
     private static final String TAG = TelecomPulledAtom.class.getSimpleName();
     private static final long MIN_PULL_INTERVAL_MILLIS = 23L * 60 * 60 * 1000;
     private static final int EVENT_SAVE = 1;
-    private final Context mContext;
+    protected final Context mContext;
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     public PulledAtoms mPulledAtoms;
     protected long mLastPulledTimestamps;
diff --git a/src/com/android/server/telecom/ui/CallStreamingNotification.java b/src/com/android/server/telecom/ui/CallStreamingNotification.java
index 8414047a2..06da5e32b 100644
--- a/src/com/android/server/telecom/ui/CallStreamingNotification.java
+++ b/src/com/android/server/telecom/ui/CallStreamingNotification.java
@@ -192,7 +192,7 @@ public class CallStreamingNotification extends CallsManagerListenerBase implemen
         // Use the caller name for the label if available, default to app name if none.
         if (TextUtils.isEmpty(callerName)) {
             // App did not provide a caller name, so default to app's name.
-            callerName = mAppLabelProxy.getAppLabel(appPackageName).toString();
+            callerName = mAppLabelProxy.getAppLabel(appPackageName, userHandle).toString();
         }
 
         // Action to hangup; this can use the default hangup action from the call style
diff --git a/testapps/transactionalVoipApp/res/values-bs/strings.xml b/testapps/transactionalVoipApp/res/values-bs/strings.xml
index 24ffba2d3..f417043b3 100644
--- a/testapps/transactionalVoipApp/res/values-bs/strings.xml
+++ b/testapps/transactionalVoipApp/res/values-bs/strings.xml
@@ -31,7 +31,7 @@
     <string name="request_earpiece_endpoint" msgid="6649571985089296573">"Slušalica"</string>
     <string name="request_speaker_endpoint" msgid="1033259535289845405">"Zvučnik"</string>
     <string name="request_bluetooth_endpoint" msgid="5933254250623451836">"Bluetooth"</string>
-    <string name="start_stream" msgid="3567634786280097431">"pokreni prijenos"</string>
+    <string name="start_stream" msgid="3567634786280097431">"pokreni prenos"</string>
     <string name="crash_app" msgid="2548690390730057704">"izbaci izuzetak"</string>
     <string name="update_notification" msgid="8677916482672588779">"ažuriraj obavještenje u stil poziva u toku"</string>
 </resources>
diff --git a/testapps/transactionalVoipApp/res/values-in/strings.xml b/testapps/transactionalVoipApp/res/values-in/strings.xml
index 935f03617..ba41376e6 100644
--- a/testapps/transactionalVoipApp/res/values-in/strings.xml
+++ b/testapps/transactionalVoipApp/res/values-in/strings.xml
@@ -27,7 +27,7 @@
     <string name="set_call_active" msgid="3365404393507589899">"setelAktif"</string>
     <string name="answer" msgid="5423590397665409939">"jawab"</string>
     <string name="set_call_inactive" msgid="7106775211368705195">"setelNonaktif"</string>
-    <string name="disconnect_call" msgid="1349412380315371385">"putuskan koneksi"</string>
+    <string name="disconnect_call" msgid="1349412380315371385">"berhenti hubungkan"</string>
     <string name="request_earpiece_endpoint" msgid="6649571985089296573">"Earpiece"</string>
     <string name="request_speaker_endpoint" msgid="1033259535289845405">"Speaker"</string>
     <string name="request_bluetooth_endpoint" msgid="5933254250623451836">"Bluetooth"</string>
diff --git a/testapps/transactionalVoipApp/res/values-sq/strings.xml b/testapps/transactionalVoipApp/res/values-sq/strings.xml
index ddaba66bd..28164735c 100644
--- a/testapps/transactionalVoipApp/res/values-sq/strings.xml
+++ b/testapps/transactionalVoipApp/res/values-sq/strings.xml
@@ -30,7 +30,7 @@
     <string name="disconnect_call" msgid="1349412380315371385">"shkëput"</string>
     <string name="request_earpiece_endpoint" msgid="6649571985089296573">"Receptori"</string>
     <string name="request_speaker_endpoint" msgid="1033259535289845405">"Altoparlanti"</string>
-    <string name="request_bluetooth_endpoint" msgid="5933254250623451836">"Bluetooth"</string>
+    <string name="request_bluetooth_endpoint" msgid="5933254250623451836">"Bluetooth-i"</string>
     <string name="start_stream" msgid="3567634786280097431">"nis transmetimin"</string>
     <string name="crash_app" msgid="2548690390730057704">"gjenero një përjashtim"</string>
     <string name="update_notification" msgid="8677916482672588779">"përditëso njoftimin me stilin e telefonatës në vazhdim"</string>
diff --git a/tests/src/com/android/server/telecom/tests/BlockCheckerFilterTest.java b/tests/src/com/android/server/telecom/tests/BlockCheckerFilterTest.java
index e76989c18..a706f4bba 100644
--- a/tests/src/com/android/server/telecom/tests/BlockCheckerFilterTest.java
+++ b/tests/src/com/android/server/telecom/tests/BlockCheckerFilterTest.java
@@ -88,7 +88,7 @@ public class BlockCheckerFilterTest extends TelecomTestCase {
         super.setUp();
         when(mCall.getHandle()).thenReturn(TEST_HANDLE);
         mFilter = new BlockCheckerFilter(mContext, mCall, mCallerInfoLookupHelper,
-                mBlockCheckerAdapter);
+                mBlockCheckerAdapter, mFeatureFlags);
     }
 
     @SmallTest
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioModeStateMachineTest.java b/tests/src/com/android/server/telecom/tests/CallAudioModeStateMachineTest.java
index 4513c65b7..9414e16e8 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioModeStateMachineTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioModeStateMachineTest.java
@@ -16,15 +16,10 @@
 
 package com.android.server.telecom.tests;
 
-import static com.android.server.telecom.CallAudioModeStateMachine.CALL_AUDIO_FOCUS_REQUEST;
-import static com.android.server.telecom.CallAudioModeStateMachine.RING_AUDIO_FOCUS_REQUEST;
-
 import static org.junit.Assert.assertEquals;
-import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.ArgumentMatchers.nullable;
-import static org.mockito.Mockito.atLeast;
 import static org.mockito.Mockito.clearInvocations;
 import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.times;
@@ -49,7 +44,6 @@ import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
-import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 
 @RunWith(JUnit4.class)
@@ -329,33 +323,6 @@ public class CallAudioModeStateMachineTest extends TelecomTestCase {
         verify(mCallAudioManager, times(2)).startRinging();
     }
 
-    @SmallTest
-    @Test
-    public void testAudioFocusRequestWithResolveHiddenDependencies() {
-        CallAudioModeStateMachine sm = new CallAudioModeStateMachine(mSystemStateHelper,
-                mAudioManager, mTestThread.getLooper(), mFeatureFlags, mCommunicationDeviceTracker);
-        when(mFeatureFlags.telecomResolveHiddenDependencies()).thenReturn(true);
-        ArgumentCaptor<AudioFocusRequest> captor = ArgumentCaptor.forClass(AudioFocusRequest.class);
-        sm.setCallAudioManager(mCallAudioManager);
-
-        resetMocks();
-        when(mCallAudioManager.startRinging()).thenReturn(true);
-        when(mCallAudioManager.isRingtonePlaying()).thenReturn(false);
-
-        sm.sendMessage(CallAudioModeStateMachine.ENTER_RING_FOCUS_FOR_TESTING);
-        waitForHandlerAction(sm.getHandler(), TEST_TIMEOUT);
-        verify(mAudioManager).requestAudioFocus(captor.capture());
-        assertTrue(areAudioFocusRequestsMatch(captor.getValue(), RING_AUDIO_FOCUS_REQUEST));
-
-        sm.sendMessage(CallAudioModeStateMachine.ENTER_CALL_FOCUS_FOR_TESTING);
-        waitForHandlerAction(sm.getHandler(), TEST_TIMEOUT);
-        verify(mAudioManager, atLeast(1)).requestAudioFocus(captor.capture());
-        AudioFocusRequest request = captor.getValue();
-        assertTrue(areAudioFocusRequestsMatch(request, CALL_AUDIO_FOCUS_REQUEST));
-
-        sm.sendMessage(CallAudioModeStateMachine.ABANDON_FOCUS_FOR_TESTING);
-    }
-
     private void resetMocks() {
         clearInvocations(mCallAudioManager, mAudioManager);
     }
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
index ade2a2285..809abb4b2 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
@@ -20,6 +20,7 @@ import static com.android.server.telecom.CallAudioRouteAdapter.ACTIVE_FOCUS;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_ACTIVE_DEVICE_GONE;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_ACTIVE_DEVICE_PRESENT;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_AUDIO_CONNECTED;
+import static com.android.server.telecom.CallAudioRouteAdapter.BT_AUDIO_DISCONNECTED;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_DEVICE_ADDED;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_DEVICE_REMOVED;
 import static com.android.server.telecom.CallAudioRouteAdapter.CONNECT_DOCK;
@@ -36,10 +37,13 @@ import static com.android.server.telecom.CallAudioRouteAdapter.STREAMING_FORCE_D
 import static com.android.server.telecom.CallAudioRouteAdapter.STREAMING_FORCE_ENABLED;
 import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_BASELINE_ROUTE;
 import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_FOCUS;
+import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_BASELINE_ROUTE;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_BLUETOOTH;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_EARPIECE;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_HEADSET;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_SPEAKER;
+import static com.android.server.telecom.CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
@@ -70,6 +74,7 @@ import android.media.audiopolicy.AudioProductStrategy;
 import android.os.UserHandle;
 import android.telecom.CallAudioState;
 import android.telecom.VideoProfile;
+import android.util.Pair;
 
 import androidx.test.filters.SmallTest;
 
@@ -189,6 +194,9 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         when(mCall.getSupportedAudioRoutes()).thenReturn(CallAudioState.ROUTE_ALL);
         when(mFeatureFlags.ignoreAutoRouteToWatchDevice()).thenReturn(false);
         when(mFeatureFlags.useRefactoredAudioRouteSwitching()).thenReturn(true);
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(false);
+        when(mFeatureFlags.newAudioPathSpeakerBroadcastAndUnfocusedRouting()).thenReturn(false);
+        when(mFeatureFlags.fixUserRequestBaselineRouteVideoCall()).thenReturn(false);
     }
 
     @After
@@ -908,6 +916,279 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
     }
 
+    @SmallTest
+    @Test
+    public void testMimicVoiceDialWithBt() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        mController.initialize();
+        mController.setActive(true);
+
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                BLUETOOTH_DEVICE_1);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        // Mimic behavior of controller processing BT_AUDIO_DISCONNECTED
+        mController.sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                INCLUDE_BLUETOOTH_IN_BASELINE, BLUETOOTH_DEVICE_1.getAddress());
+        // Process BT_AUDIO_CONNECTED from connecting to BT device in active focus request.
+        mController.setIsScoAudioConnected(true);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0, BLUETOOTH_DEVICE_1);
+        // Verify SCO not disconnected and route stays on connected BT device.
+        verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT).times(0)).disconnectSco();
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    @SmallTest
+    @Test
+    public void testTransactionalCallBtConnectingAndSwitchCallEndpoint() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        mController.initialize();
+        mController.setActive(true);
+
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                BLUETOOTH_DEVICE_1);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, BT_ADDRESS_1);
+        // Omit sending BT_AUDIO_CONNECTED to mimic scenario where BT is still connecting and user
+        // switches to speaker.
+        mController.sendMessageWithSessionInfo(USER_SWITCH_SPEAKER);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                BLUETOOTH_DEVICE_1);
+
+        // Verify SCO disconnected
+        verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT)).disconnectSco();
+        // Verify audio properly routes into speaker.
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    @Test
+    @SmallTest
+    public void testBluetoothRouteToActiveDevice() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        // Connect first BT device.
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        // Connect another BT device.
+        String scoDeviceAddress = "00:00:00:00:00:03";
+        BluetoothDevice scoDevice =
+                BluetoothRouteManagerTest.makeBluetoothDevice(scoDeviceAddress);
+        BLUETOOTH_DEVICES.add(scoDevice);
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                scoDevice);
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDeviceAddress);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                BLUETOOTH_DEVICE_1);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0,
+                scoDevice);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, scoDevice, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Mimic behavior when inactive headset is used to answer the call (i.e. tap headset). In
+        // this case, the inactive BT device will become the active device (reported to us from BT
+        // stack to controller via BT_ACTIVE_DEVICE_PRESENT).
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, BLUETOOTH_DEVICE_1.getAddress());
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                scoDevice);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0,
+                BLUETOOTH_DEVICE_1);
+        // Verify audio routed to BLUETOOTH_DEVICE_1
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Now switch call to active focus so that base route can be recalculated.
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        // Verify that audio is still routed into BLUETOOTH_DEVICE_1 and not the 2nd BT device.
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Clean up BLUETOOTH_DEVICES for subsequent tests.
+        BLUETOOTH_DEVICES.remove(scoDevice);
+    }
+
+    @Test
+    @SmallTest
+    public void verifyRouteReinitializedAfterCallEnd() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        mController.initialize();
+        mController.setActive(true);
+
+        // Switch to speaker
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Verify that call audio route is reinitialized to default (in this case, earpiece) when
+        // call audio focus is lost.
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS, 0);
+        mController.sendMessageWithSessionInfo(SPEAKER_OFF);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    @Test
+    @SmallTest
+    public void testUserSwitchBaselineRouteVideoCall() {
+        when(mFeatureFlags.fixUserRequestBaselineRouteVideoCall()).thenReturn(true);
+        mController.initialize();
+        mController.setActive(true);
+        // Set capabilities for video call.
+        when(mCall.getVideoState()).thenReturn(VideoProfile.STATE_BIDIRECTIONAL);
+
+        // Turn on speaker
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // USER_SWITCH_BASELINE_ROUTE (explicit user request). Verify that audio is routed back to
+        // earpiece.
+        mController.sendMessageWithSessionInfo(USER_SWITCH_BASELINE_ROUTE,
+                CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE);
+        mController.sendMessageWithSessionInfo(SPEAKER_OFF);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // SWITCH_BASELINE_ROUTE. Verify that audio is routed to speaker for non-user requests.
+        mController.sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    @Test
+    @SmallTest
+    public void testRouteToWatchWhenCallAnsweredOnWatch_MultipleBtDevices() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        // Connect first BT device.
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        // Connect another BT device.
+        String scoDeviceAddress = "00:00:00:00:00:03";
+        BluetoothDevice watchDevice =
+                BluetoothRouteManagerTest.makeBluetoothDevice(scoDeviceAddress);
+        when(mBluetoothRouteManager.isWatch(eq(watchDevice))).thenReturn(true);
+        BLUETOOTH_DEVICES.add(watchDevice);
+
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                watchDevice);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
+                | CallAudioState.ROUTE_BLUETOOTH, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Signal that watch is now the active device. This is done in BluetoothStateReceiver and
+        // then BT_ACTIVE_DEVICE_PRESENT will be sent to the controller to be processed.
+        mController.updateActiveBluetoothDevice(
+                new Pair<>(AudioRoute.TYPE_BLUETOOTH_SCO, watchDevice.getAddress()));
+        // Emulate scenario with call answered on watch. Ensure at this point that audio was routed
+        // into watch
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED,
+                0, watchDevice);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED,
+                0, BLUETOOTH_DEVICE_1);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
+                        | CallAudioState.ROUTE_BLUETOOTH, watchDevice, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Hardcode signal from BT stack signaling to Telecom that watch is now the active device.
+        // This should just be a no-op since audio was already routed when processing active focus.
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDeviceAddress);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Mimic behavior of controller processing BT_AUDIO_DISCONNECTED for BLUETOOTH_DEVICE_1 and
+        // verify that audio remains routed to the watch and not routed to earpiece (this should
+        // be taking into account what the BT active device is as reported to us by the BT stack).
+        mController.sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                INCLUDE_BLUETOOTH_IN_BASELINE, BLUETOOTH_DEVICE_1.getAddress());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        BLUETOOTH_DEVICES.remove(watchDevice);
+    }
+
+
+    @Test
+    @SmallTest
+    public void testAbandonCallAudioFocusAfterCallEnd() {
+        // Make sure in-band ringing is disabled so that route never becomes active
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
+
+        mController.initialize();
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                BLUETOOTH_DEVICE_1);
+
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, BT_ADDRESS_1);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        assertFalse(mController.isActive());
+
+        // Verify route never went active due to in-band ringing being disabled.
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
+        assertFalse(mController.isActive());
+
+        // Emulate scenario of rejecting an incoming call so that call focus is lost and verify
+        // that we abandon the call audio focus that was gained from when the call went to
+        // ringing state.
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS, 0);
+        // Ensure we tell the CallAudioManager that audio operations are done so that we can ensure
+        // audio focus is relinquished.
+        verify(mCallAudioManager, timeout(TEST_TIMEOUT)).notifyAudioOperationsComplete();
+    }
+
     private void verifyConnectBluetoothDevice(int audioType) {
         mController.initialize();
         mController.setActive(true);
diff --git a/tests/src/com/android/server/telecom/tests/CallScreeningServiceFilterTest.java b/tests/src/com/android/server/telecom/tests/CallScreeningServiceFilterTest.java
index d1427dbde..d97263d08 100644
--- a/tests/src/com/android/server/telecom/tests/CallScreeningServiceFilterTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallScreeningServiceFilterTest.java
@@ -17,6 +17,7 @@
 package com.android.server.telecom.tests;
 
 import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
@@ -136,7 +137,7 @@ public class CallScreeningServiceFilterTest extends TelecomTestCase {
         when(mContext.getSystemService(TelecomManager.class))
                 .thenReturn(mTelecomManager);
         when(mTelecomManager.getSystemDialerPackage()).thenReturn(PKG_NAME);
-        when(mAppLabelProxy.getAppLabel(PKG_NAME)).thenReturn(APP_NAME);
+        when(mAppLabelProxy.getAppLabel(PKG_NAME, PA_HANDLE.getUserHandle())).thenReturn(APP_NAME);
         when(mParcelableCallUtilsConverter.toParcelableCall(
                 eq(mCall), anyBoolean(), eq(mPhoneAccountRegistrar))).thenReturn(null);
         when(mContext.bindServiceAsUser(nullable(Intent.class), nullable(ServiceConnection.class),
diff --git a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
index fc6a095d0..79fd3d501 100644
--- a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
@@ -142,7 +142,7 @@ import com.android.server.telecom.ui.AudioProcessingNotification;
 import com.android.server.telecom.ui.CallStreamingNotification;
 import com.android.server.telecom.ui.DisconnectedCallNotifier;
 import com.android.server.telecom.ui.ToastFactory;
-import com.android.server.telecom.voip.TransactionManager;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import com.google.common.base.Objects;
 
@@ -3329,10 +3329,10 @@ public class CallsManagerTest extends TelecomTestCase {
         Bundle extras = mock(Bundle.class);
         when(call.getIntentExtras()).thenReturn(extras);
 
-        final int attachmentDisabledMask = ~0
-                ^ CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_LOCATION
-                ^ CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_SUBJECT
-                ^ CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_PRIORITY;
+        final int attachmentDisabledMask = ~(
+                CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_LOCATION |
+                CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_SUBJECT |
+                CallScreeningService.CallResponse.CALL_COMPOSER_ATTACHMENT_PRIORITY);
         CallScreeningService.ParcelableCallResponse response =
                 mock(CallScreeningService.ParcelableCallResponse.class);
         when(response.getCallComposerAttachmentsToShow()).thenReturn(attachmentDisabledMask);
diff --git a/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java b/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
index 25f94c63e..1432834b0 100644
--- a/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
+++ b/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
@@ -32,6 +32,7 @@ import android.annotation.Nullable;
 import android.annotation.RequiresPermission;
 import android.app.AppOpsManager;
 import android.app.NotificationManager;
+import android.app.StatsManager;
 import android.app.StatusBarManager;
 import android.app.UiModeManager;
 import android.app.role.RoleManager;
@@ -258,6 +259,8 @@ public class ComponentContextFixture implements TestFixture<Context> {
                     return mAccessibilityManager;
                 case Context.BLOCKED_NUMBERS_SERVICE:
                     return mBlockedNumbersManager;
+                case Context.STATS_MANAGER_SERVICE:
+                    return mStatsManager;
                 default:
                     return null;
             }
@@ -301,6 +304,10 @@ public class ComponentContextFixture implements TestFixture<Context> {
                 return Context.TELECOM_SERVICE;
             } else if (svcClass == BlockedNumbersManager.class) {
                 return Context.BLOCKED_NUMBERS_SERVICE;
+            } else if (svcClass == AppOpsManager.class) {
+                return Context.APP_OPS_SERVICE;
+            } else if (svcClass == StatsManager.class) {
+                return Context.STATS_MANAGER_SERVICE;
             }
             throw new UnsupportedOperationException(svcClass.getName());
         }
@@ -642,6 +649,7 @@ public class ComponentContextFixture implements TestFixture<Context> {
     private final PermissionInfo mPermissionInfo = mock(PermissionInfo.class);
     private final SensorPrivacyManager mSensorPrivacyManager = mock(SensorPrivacyManager.class);
     private final List<BroadcastReceiver> mBroadcastReceivers = new ArrayList<>();
+    private final StatsManager mStatsManager = mock(StatsManager.class);
 
     private TelecomManager mTelecomManager = mock(TelecomManager.class);
     private BlockedNumbersManager mBlockedNumbersManager = mock(BlockedNumbersManager.class);
diff --git a/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java b/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
index 18f2eb080..3da9284d3 100644
--- a/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
+++ b/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
@@ -56,14 +56,17 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
     private static final int USER0 = 0;
     private static final int USER1 = 1;
     private static final int USER2 = 2;
+    private static final int DELAY_TOLERANCE = 100;
 
     private DefaultDialerCache mDefaultDialerCache;
     private ContentObserver mDefaultDialerSettingObserver;
     private BroadcastReceiver mPackageChangeReceiver;
     private BroadcastReceiver mUserRemovedReceiver;
 
-    @Mock private DefaultDialerCache.DefaultDialerManagerAdapter mMockDefaultDialerManager;
-    @Mock private RoleManagerAdapter mRoleManagerAdapter;
+    @Mock
+    private DefaultDialerCache.DefaultDialerManagerAdapter mMockDefaultDialerManager;
+    @Mock
+    private RoleManagerAdapter mRoleManagerAdapter;
 
     @Override
     @Before
@@ -76,18 +79,19 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
 
         mDefaultDialerCache = new DefaultDialerCache(
                 mContext, mMockDefaultDialerManager, mRoleManagerAdapter,
-                new TelecomSystem.SyncRoot() { });
+                new TelecomSystem.SyncRoot() {
+                });
 
         verify(mContext, times(2)).registerReceiverAsUser(
-            packageReceiverCaptor.capture(), eq(UserHandle.ALL), any(IntentFilter.class),
+                packageReceiverCaptor.capture(), eq(UserHandle.ALL), any(IntentFilter.class),
                 isNull(String.class), isNull(Handler.class));
         // Receive the first receiver that was captured, the package change receiver.
         mPackageChangeReceiver = packageReceiverCaptor.getAllValues().get(0);
 
         ArgumentCaptor<BroadcastReceiver> userRemovedReceiverCaptor =
-            ArgumentCaptor.forClass(BroadcastReceiver.class);
+                ArgumentCaptor.forClass(BroadcastReceiver.class);
         verify(mContext).registerReceiver(
-            userRemovedReceiverCaptor.capture(), any(IntentFilter.class));
+                userRemovedReceiverCaptor.capture(), any(IntentFilter.class));
         mUserRemovedReceiver = userRemovedReceiverCaptor.getAllValues().get(0);
 
         mDefaultDialerSettingObserver = mDefaultDialerCache.getContentObserver();
@@ -140,7 +144,10 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
         Intent packageChangeIntent = new Intent(Intent.ACTION_PACKAGE_CHANGED,
                 Uri.fromParts("package", DIALER1, null));
         when(mRoleManagerAdapter.getDefaultDialerApp(eq(USER0))).thenReturn(DIALER2);
+
         mPackageChangeReceiver.onReceive(mContext, packageChangeIntent);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
+
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER1));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER2));
@@ -158,6 +165,8 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
         Intent packageChangeIntent = new Intent(Intent.ACTION_PACKAGE_CHANGED,
                 Uri.fromParts("package", "red.orange.blue", null));
         mPackageChangeReceiver.onReceive(mContext, packageChangeIntent);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
+
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER1));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER2));
@@ -192,6 +201,8 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
         packageChangeIntent.putExtra(Intent.EXTRA_REPLACING, false);
 
         mPackageChangeReceiver.onReceive(mContext, packageChangeIntent);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
+
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(1)).getDefaultDialerApp(eq(USER1));
         verify(mRoleManagerAdapter, times(1)).getDefaultDialerApp(eq(USER2));
@@ -208,6 +219,8 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
                 Uri.fromParts("package", "ppp.qqq.zzz", null));
 
         mPackageChangeReceiver.onReceive(mContext, packageChangeIntent);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
+
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER1));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER2));
@@ -225,6 +238,8 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
         packageChangeIntent.putExtra(Intent.EXTRA_REPLACING, true);
 
         mPackageChangeReceiver.onReceive(mContext, packageChangeIntent);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
+
         verify(mRoleManagerAdapter, times(1)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(1)).getDefaultDialerApp(eq(USER1));
         verify(mRoleManagerAdapter, times(1)).getDefaultDialerApp(eq(USER2));
@@ -240,7 +255,9 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
         when(mRoleManagerAdapter.getDefaultDialerApp(eq(USER0))).thenReturn(DIALER2);
         when(mRoleManagerAdapter.getDefaultDialerApp(eq(USER1))).thenReturn(DIALER2);
         when(mRoleManagerAdapter.getDefaultDialerApp(eq(USER2))).thenReturn(DIALER2);
+
         mDefaultDialerSettingObserver.onChange(false);
+        waitForHandlerAction(mDefaultDialerCache.mHandler, DELAY_TOLERANCE);
 
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER0));
         verify(mRoleManagerAdapter, times(2)).getDefaultDialerApp(eq(USER2));
diff --git a/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java b/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
index 45b4ed130..a480a7b5c 100644
--- a/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
+++ b/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
@@ -113,7 +113,8 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
     private final String PACKAGE_1 = "PACKAGE_1";
     private final String PACKAGE_2 = "PACKAGE_2";
     private final String COMPONENT_NAME = "com.android.server.telecom.tests.MockConnectionService";
-    private final UserHandle USER_HANDLE_10 = new UserHandle(10);
+    private final UserHandle USER_HANDLE_10 = UserHandle.of(10);
+    private final UserHandle USER_HANDLE_1000 = UserHandle.of(1000);
     private final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() { };
     private PhoneAccountRegistrar mRegistrar;
     @Mock private SubscriptionManager mSubscriptionManager;
@@ -135,11 +136,12 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
                 .delete();
         when(mDefaultDialerCache.getDefaultDialerApplication(anyInt()))
                 .thenReturn("com.android.dialer");
-        when(mAppLabelProxy.getAppLabel(anyString()))
+        when(mAppLabelProxy.getAppLabel(anyString(), any()))
                 .thenReturn(TEST_LABEL);
         mRegistrar = new PhoneAccountRegistrar(
                 mComponentContextFixture.getTestDouble().getApplicationContext(), mLock, FILE_NAME,
                 mDefaultDialerCache, mAppLabelProxy, mTelephonyFeatureFlags, mFeatureFlags);
+        mRegistrar.setCurrentUserHandle(UserHandle.SYSTEM);
         when(mFeatureFlags.onlyUpdateTelephonyOnValidSubIds()).thenReturn(false);
         when(mFeatureFlags.unregisterUnresolvableAccounts()).thenReturn(true);
         when(mTelephonyFeatureFlags.workProfileApiSplit()).thenReturn(false);
@@ -1306,8 +1308,7 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
                 Mockito.mock(IConnectionService.class));
         UserManager userManager = mContext.getSystemService(UserManager.class);
 
-        List<UserHandle> users = Arrays.asList(new UserHandle(0),
-                new UserHandle(1000));
+        List<UserHandle> users = Arrays.asList(UserHandle.SYSTEM, USER_HANDLE_1000);
 
         PhoneAccount pa1 = new PhoneAccount.Builder(
                 new PhoneAccountHandle(new ComponentName(PACKAGE_1, COMPONENT_NAME), "1234",
@@ -1606,7 +1607,7 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
                 .setCapabilities(PhoneAccount.CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS);
 
         // WHEN
-        when(mAppLabelProxy.getAppLabel(anyString())).thenReturn(invalidLabel);
+        when(mAppLabelProxy.getAppLabel(anyString(), any())).thenReturn(invalidLabel);
 
         // THEN
         try {
diff --git a/tests/src/com/android/server/telecom/tests/RingerTest.java b/tests/src/com/android/server/telecom/tests/RingerTest.java
index c4d967823..46916fd48 100644
--- a/tests/src/com/android/server/telecom/tests/RingerTest.java
+++ b/tests/src/com/android/server/telecom/tests/RingerTest.java
@@ -66,6 +66,7 @@ import android.util.Pair;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.AsyncRingtonePlayer;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallState;
@@ -123,6 +124,7 @@ public class RingerTest extends TelecomTestCase {
     @Mock NotificationManager mockNotificationManager;
     @Mock Ringer.AccessibilityManagerAdapter mockAccessibilityManagerAdapter;
     @Mock private FeatureFlags mFeatureFlags;
+    @Mock private AnomalyReporterAdapter mAnomalyReporterAdapter;
 
     @Spy Ringer.VibrationEffectProxy spyVibrationEffectProxy;
 
@@ -178,7 +180,7 @@ public class RingerTest extends TelecomTestCase {
         mRingerUnderTest = new Ringer(mockPlayerFactory, mContext, mockSystemSettingsUtil,
                 asyncRingtonePlayer, mockRingtoneFactory, mockVibrator, spyVibrationEffectProxy,
                 mockInCallController, mockNotificationManager, mockAccessibilityManagerAdapter,
-                mFeatureFlags);
+                mFeatureFlags, mAnomalyReporterAdapter);
         // This future is used to wait for AsyncRingtonePlayer to finish its part.
         mRingerUnderTest.setBlockOnRingingFuture(mRingCompletionFuture);
     }
diff --git a/tests/src/com/android/server/telecom/tests/SessionManagerTest.java b/tests/src/com/android/server/telecom/tests/SessionManagerTest.java
index 3e82eac4c..631d52290 100644
--- a/tests/src/com/android/server/telecom/tests/SessionManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/SessionManagerTest.java
@@ -21,10 +21,14 @@ import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNotNull;
 import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.fail;
 
+import android.telecom.Log;
 import android.telecom.Logging.Session;
 import android.telecom.Logging.SessionManager;
 
+import com.android.server.telecom.flags.Flags;
+
 import androidx.test.filters.SmallTest;
 
 import org.junit.After;
@@ -57,13 +61,11 @@ public class SessionManagerTest extends TelecomTestCase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        mTestSessionManager = new SessionManager();
+        mTestSessionManager = new SessionManager(null);
         mTestSessionManager.registerSessionListener(((sessionName, timeMs) -> {
             mfullSessionCompleteTime = timeMs;
             mFullSessionMethodName = sessionName;
         }));
-        // Remove automatic stale session cleanup for testing
-        mTestSessionManager.mCleanStaleSessions = null;
     }
 
     @Override
@@ -411,4 +413,33 @@ public class SessionManagerTest extends TelecomTestCase {
         assertTrue(mTestSessionManager.mSessionMapper.isEmpty());
         assertNull(sessionRef.get());
     }
+
+    /**
+     * If Telecom gets into a situation where there are MANY sub-sessions created in a deep tree,
+     * ensure that cleanup still happens properly.
+     */
+    @SmallTest
+    @Test
+    public void testManySubsessionCleanupStress() {
+        // This test will mostly likely fail with recursion due to stack overflow
+        if (!Flags.endSessionImprovements()) return;
+        Log.setIsExtendedLoggingEnabled(false);
+        mTestSessionManager.mCurrentThreadId = () -> TEST_PARENT_THREAD_ID;
+        mTestSessionManager.startSession(TEST_PARENT_NAME, null);
+        Session parentSession = mTestSessionManager.mSessionMapper.get(TEST_PARENT_THREAD_ID);
+        Session subsession;
+        try {
+            for (int i = 0; i < 10000; i++) {
+                subsession = mTestSessionManager.createSubsession();
+                mTestSessionManager.endSession();
+                mTestSessionManager.continueSession(subsession, TEST_CHILD_NAME + i);
+            }
+            mTestSessionManager.endSession();
+        } catch (Exception e) {
+            fail("Exception: " + e);
+        }
+        assertTrue(mTestSessionManager.mSessionMapper.isEmpty());
+        assertTrue(parentSession.isSessionCompleted());
+        assertTrue(parentSession.getChildSessions().isEmpty());
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/SessionTest.java b/tests/src/com/android/server/telecom/tests/SessionTest.java
index 5378596cd..4cddc89d0 100644
--- a/tests/src/com/android/server/telecom/tests/SessionTest.java
+++ b/tests/src/com/android/server/telecom/tests/SessionTest.java
@@ -269,6 +269,6 @@ public class SessionTest extends TelecomTestCase {
     }
 
     private Session createTestSession(String name, String methodName) {
-        return new Session(name, methodName, 0, false, null);
+        return new Session(name, methodName, 0, false, false ,null);
     }
 }
diff --git a/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
index e2ab8d6ac..4d494f343 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
@@ -21,8 +21,11 @@ import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
 import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyObject;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
 import android.app.StatsManager;
@@ -119,18 +122,27 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
     }
 
     @Test
-    public void testRegisterAtomIsSameInstance() {
+    public void testRegisterAtom() {
+        StatsManager statsManager = mContext.getSystemService(StatsManager.class);
         ApiStats stats = mock(ApiStats.class);
 
         mTelecomMetricsController.registerAtom(TELECOM_API_STATS, stats);
 
+        verify(statsManager, times(1)).setPullAtomCallback(eq(TELECOM_API_STATS), anyObject(),
+                anyObject(), eq(mTelecomMetricsController));
         assertThat(mTelecomMetricsController.getStats().get(TELECOM_API_STATS))
                 .isSameInstanceAs(stats);
     }
 
     @Test
     public void testDestroy() {
+        StatsManager statsManager = mContext.getSystemService(StatsManager.class);
         mTelecomMetricsController.destroy();
+
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(CALL_AUDIO_ROUTE_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(CALL_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_API_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_ERROR_STATS));
         assertThat(mTelecomMetricsController.getStats()).isEmpty();
     }
 
diff --git a/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
index bc8aeac8e..d3c7859e4 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
@@ -37,10 +37,13 @@ import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 
 import android.app.StatsManager;
+import android.content.ComponentName;
 import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
 import android.os.Looper;
-import android.os.UserHandle;
 import android.telecom.PhoneAccount;
+import android.telecom.PhoneAccountHandle;
 import android.util.StatsEvent;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
@@ -66,7 +69,10 @@ import java.io.File;
 import java.io.FileOutputStream;
 import java.io.IOException;
 import java.util.ArrayList;
+import java.util.HashMap;
 import java.util.List;
+import java.util.Map;
+import java.util.Random;
 
 @RunWith(AndroidJUnit4.class)
 public class TelecomPulledAtomTest extends TelecomTestCase {
@@ -201,12 +207,14 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         createTestFileForApiStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
         ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
         final List<StatsEvent> data = new ArrayList<>();
+        int sizePulled = apiStats.mPulledAtoms.telecomApiStats.length;
 
         int result = apiStats.pull(data);
 
         assertEquals(StatsManager.PULL_SUCCESS, result);
         verify(apiStats).onPull(eq(data));
-        assertEquals(data.size(), apiStats.mPulledAtoms.telecomApiStats.length);
+        assertEquals(data.size(), sizePulled);
+        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 0);
     }
 
     @Test
@@ -227,12 +235,14 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         createTestFileForAudioRouteStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
         AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
         final List<StatsEvent> data = new ArrayList<>();
+        int sizePulled = audioRouteStats.mPulledAtoms.callAudioRouteStats.length;
 
         int result = audioRouteStats.pull(data);
 
         assertEquals(StatsManager.PULL_SUCCESS, result);
         verify(audioRouteStats).onPull(eq(data));
-        assertEquals(data.size(), audioRouteStats.mPulledAtoms.callAudioRouteStats.length);
+        assertEquals(data.size(), sizePulled);
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 0);
     }
 
     @Test
@@ -253,12 +263,14 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         createTestFileForCallStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
         CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
         final List<StatsEvent> data = new ArrayList<>();
+        int sizePulled = callStats.mPulledAtoms.callStats.length;
 
         int result = callStats.pull(data);
 
         assertEquals(StatsManager.PULL_SUCCESS, result);
         verify(callStats).onPull(eq(data));
-        assertEquals(data.size(), callStats.mPulledAtoms.callStats.length);
+        assertEquals(data.size(), sizePulled);
+        assertEquals(callStats.mPulledAtoms.callStats.length, 0);
     }
 
     @Test
@@ -279,35 +291,119 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         createTestFileForErrorStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
         ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
         final List<StatsEvent> data = new ArrayList<>();
+        int sizePulled = errorStats.mPulledAtoms.telecomErrorStats.length;
 
         int result = errorStats.pull(data);
 
         assertEquals(StatsManager.PULL_SUCCESS, result);
         verify(errorStats).onPull(eq(data));
-        assertEquals(data.size(), errorStats.mPulledAtoms.telecomErrorStats.length);
+        assertEquals(data.size(), sizePulled);
+        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 0);
     }
 
     @Test
-    public void testApiStatsLog() throws Exception {
+    public void testApiStatsLogCount() throws Exception {
         ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        ApiStats.ApiEvent event = new ApiStats.ApiEvent(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
 
-        apiStats.log(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
-        waitForHandlerAction(apiStats, TEST_TIMEOUT);
+        for (int i = 0; i < 10; i++) {
+            apiStats.log(event);
+            waitForHandlerAction(apiStats, TEST_TIMEOUT);
 
-        verify(apiStats, times(1)).onAggregate();
-        verify(apiStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
-        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 1);
-        verifyMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats[0], VALUE_API_ID,
-                VALUE_UID, VALUE_API_RESULT, 1);
-
-        apiStats.log(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
-        waitForHandlerAction(apiStats, TEST_TIMEOUT);
+            verify(apiStats, times(i + 1)).onAggregate();
+            verify(apiStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 1);
+            verifyMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats[0], VALUE_API_ID,
+                    VALUE_UID, VALUE_API_RESULT, i + 1);
+        }
+    }
 
-        verify(apiStats, times(2)).onAggregate();
-        verify(apiStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
-        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 1);
-        verifyMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats[0], VALUE_API_ID,
-                VALUE_UID, VALUE_API_RESULT, 2);
+    @Test
+    public void testApiStatsLogEvent() throws Exception {
+        final int[] apis = {
+                ApiStats.API_UNSPECIFIC,
+                ApiStats.API_ACCEPTHANDOVER,
+                ApiStats.API_ACCEPTRINGINGCALL,
+                ApiStats.API_ACCEPTRINGINGCALLWITHVIDEOSTATE,
+                ApiStats.API_ADDCALL,
+                ApiStats.API_ADDNEWINCOMINGCALL,
+                ApiStats.API_ADDNEWINCOMINGCONFERENCE,
+                ApiStats.API_ADDNEWUNKNOWNCALL,
+                ApiStats.API_CANCELMISSEDCALLSNOTIFICATION,
+                ApiStats.API_CLEARACCOUNTS,
+                ApiStats.API_CREATELAUNCHEMERGENCYDIALERINTENT,
+                ApiStats.API_CREATEMANAGEBLOCKEDNUMBERSINTENT,
+                ApiStats.API_DUMP,
+                ApiStats.API_DUMPCALLANALYTICS,
+                ApiStats.API_ENABLEPHONEACCOUNT,
+                ApiStats.API_ENDCALL,
+                ApiStats.API_GETADNURIFORPHONEACCOUNT,
+                ApiStats.API_GETALLPHONEACCOUNTHANDLES,
+                ApiStats.API_GETALLPHONEACCOUNTS,
+                ApiStats.API_GETALLPHONEACCOUNTSCOUNT,
+                ApiStats.API_GETCALLCAPABLEPHONEACCOUNTS,
+                ApiStats.API_GETCALLSTATE,
+                ApiStats.API_GETCALLSTATEUSINGPACKAGE,
+                ApiStats.API_GETCURRENTTTYMODE,
+                ApiStats.API_GETDEFAULTDIALERPACKAGE,
+                ApiStats.API_GETDEFAULTDIALERPACKAGEFORUSER,
+                ApiStats.API_GETDEFAULTOUTGOINGPHONEACCOUNT,
+                ApiStats.API_GETDEFAULTPHONEAPP,
+                ApiStats.API_GETLINE1NUMBER,
+                ApiStats.API_GETOWNSELFMANAGEDPHONEACCOUNTS,
+                ApiStats.API_GETPHONEACCOUNT,
+                ApiStats.API_GETPHONEACCOUNTSFORPACKAGE,
+                ApiStats.API_GETPHONEACCOUNTSSUPPORTINGSCHEME,
+                ApiStats.API_GETREGISTEREDPHONEACCOUNTS,
+                ApiStats.API_GETSELFMANAGEDPHONEACCOUNTS,
+                ApiStats.API_GETSIMCALLMANAGER,
+                ApiStats.API_GETSIMCALLMANAGERFORUSER,
+                ApiStats.API_GETSYSTEMDIALERPACKAGE,
+                ApiStats.API_GETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+                ApiStats.API_GETVOICEMAILNUMBER,
+                ApiStats.API_HANDLEPINMMI,
+                ApiStats.API_HANDLEPINMMIFORPHONEACCOUNT,
+                ApiStats.API_HASMANAGEONGOINGCALLSPERMISSION,
+                ApiStats.API_ISINCALL,
+                ApiStats.API_ISINCOMINGCALLPERMITTED,
+                ApiStats.API_ISINEMERGENCYCALL,
+                ApiStats.API_ISINMANAGEDCALL,
+                ApiStats.API_ISINSELFMANAGEDCALL,
+                ApiStats.API_ISOUTGOINGCALLPERMITTED,
+                ApiStats.API_ISRINGING,
+                ApiStats.API_ISTTYSUPPORTED,
+                ApiStats.API_ISVOICEMAILNUMBER,
+                ApiStats.API_PLACECALL,
+                ApiStats.API_REGISTERPHONEACCOUNT,
+                ApiStats.API_SETDEFAULTDIALER,
+                ApiStats.API_SETUSERSELECTEDOUTGOINGPHONEACCOUNT,
+                ApiStats.API_SHOWINCALLSCREEN,
+                ApiStats.API_SILENCERINGER,
+                ApiStats.API_STARTCONFERENCE,
+                ApiStats.API_UNREGISTERPHONEACCOUNT,
+        };
+        final int[] results = {ApiStats.RESULT_UNKNOWN, ApiStats.RESULT_NORMAL,
+                ApiStats.RESULT_EXCEPTION, ApiStats.RESULT_PERMISSION};
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        Random rand = new Random();
+        Map<ApiStats.ApiEvent, Integer> eventMap = new HashMap<>();
+
+        for (int i = 0; i < 10; i++) {
+            int api = apis[rand.nextInt(apis.length)];
+            int uid = rand.nextInt(65535);
+            int result = results[rand.nextInt(results.length)];
+            ApiStats.ApiEvent event = new ApiStats.ApiEvent(api, uid, result);
+            eventMap.put(event, eventMap.getOrDefault(event, 0) + 1);
+
+            apiStats.log(event);
+            waitForHandlerAction(apiStats, TEST_TIMEOUT);
+
+            verify(apiStats, times(i + 1)).onAggregate();
+            verify(apiStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, eventMap.size());
+            assertTrue(hasMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats,
+                    api, uid, result, eventMap.get(event)));
+        }
     }
 
     @Test
@@ -570,8 +666,19 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testCallStatsOnStartThenEnd() throws Exception {
         int duration = 1000;
-        UserHandle uh = UserHandle.of(UserHandle.USER_SYSTEM);
+        int fakeUid = 10010;
         PhoneAccount account = mock(PhoneAccount.class);
+        Call.CallingPackageIdentity callingPackage = new Call.CallingPackageIdentity();
+        PackageManager pm = mock(PackageManager.class);
+        ApplicationInfo ai = new ApplicationInfo();
+        ai.uid = fakeUid;
+        doReturn(ai).when(pm).getApplicationInfo(any(), anyInt());
+        doReturn(pm).when(mSpyContext).getPackageManager();
+        Context fakeContext = spy(mContext);
+        doReturn("").when(fakeContext).getPackageName();
+        ComponentName cn = new ComponentName(fakeContext, this.getClass());
+        PhoneAccountHandle handle = mock(PhoneAccountHandle.class);
+        doReturn(cn).when(handle).getComponentName();
         Call call = mock(Call.class);
         doReturn(true).when(call).isIncoming();
         doReturn(account).when(call).getPhoneAccountFromHandle();
@@ -579,7 +686,8 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_CALL_PROVIDER));
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
-        doReturn(uh).when(call).getAssociatedUser();
+        doReturn(callingPackage).when(call).getCallingPackageIdentity();
+        doReturn(handle).when(call).getTargetPhoneAccount();
         CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
 
         callStats.onCallStart(call);
@@ -590,14 +698,25 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
         verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
                 eq(false), eq(false), eq(false), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
-                eq(UserHandle.USER_SYSTEM), eq(duration));
+                eq(fakeUid), eq(duration));
     }
 
     @Test
     public void testCallStatsOnMultipleAudioDevices() throws Exception {
         int duration = 1000;
-        UserHandle uh = UserHandle.of(UserHandle.USER_SYSTEM);
+        int fakeUid = 10010;
         PhoneAccount account = mock(PhoneAccount.class);
+        Call.CallingPackageIdentity callingPackage = new Call.CallingPackageIdentity();
+        PackageManager pm = mock(PackageManager.class);
+        ApplicationInfo ai = new ApplicationInfo();
+        ai.uid = fakeUid;
+        doReturn(ai).when(pm).getApplicationInfo(any(), anyInt());
+        doReturn(pm).when(mSpyContext).getPackageManager();
+        Context fakeContext = spy(mContext);
+        doReturn("").when(fakeContext).getPackageName();
+        ComponentName cn = new ComponentName(fakeContext, this.getClass());
+        PhoneAccountHandle handle = mock(PhoneAccountHandle.class);
+        doReturn(cn).when(handle).getComponentName();
         Call call = mock(Call.class);
         doReturn(true).when(call).isIncoming();
         doReturn(account).when(call).getPhoneAccountFromHandle();
@@ -605,7 +724,8 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_CALL_PROVIDER));
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
-        doReturn(uh).when(call).getAssociatedUser();
+        doReturn(callingPackage).when(call).getCallingPackageIdentity();
+        doReturn(handle).when(call).getTargetPhoneAccount();
         CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
 
         callStats.onCallStart(call);
@@ -619,30 +739,88 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
         verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
                 eq(false), eq(false), eq(true), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
-                eq(UserHandle.USER_SYSTEM), eq(duration));
+                eq(fakeUid), eq(duration));
     }
 
     @Test
-    public void testErrorStatsLog() throws Exception {
+    public void testErrorStatsLogCount() throws Exception {
         ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        for (int i = 0; i < 10; i++) {
+            errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
+            waitForHandlerAction(errorStats, TEST_TIMEOUT);
+
+            verify(errorStats, times(i + 1)).onAggregate();
+            verify(errorStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 1);
+            verifyMessageForErrorStats(errorStats.mPulledAtoms.telecomErrorStats[0],
+                    VALUE_MODULE_ID,
+                    VALUE_ERROR_ID, i + 1);
+        }
+    }
 
-        errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
-        waitForHandlerAction(errorStats, TEST_TIMEOUT);
-
-        verify(errorStats, times(1)).onAggregate();
-        verify(errorStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
-        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 1);
-        verifyMessageForErrorStats(errorStats.mPulledAtoms.telecomErrorStats[0], VALUE_MODULE_ID,
-                VALUE_ERROR_ID, 1);
-
-        errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
-        waitForHandlerAction(errorStats, TEST_TIMEOUT);
-
-        verify(errorStats, times(2)).onAggregate();
-        verify(errorStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
-        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 1);
-        verifyMessageForErrorStats(errorStats.mPulledAtoms.telecomErrorStats[0], VALUE_MODULE_ID,
-                VALUE_ERROR_ID, 2);
+    @Test
+    public void testErrorStatsLogEvent() throws Exception {
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        int[] modules = {
+                ErrorStats.SUB_UNKNOWN,
+                ErrorStats.SUB_CALL_AUDIO,
+                ErrorStats.SUB_CALL_LOGS,
+                ErrorStats.SUB_CALL_MANAGER,
+                ErrorStats.SUB_CONNECTION_SERVICE,
+                ErrorStats.SUB_EMERGENCY_CALL,
+                ErrorStats.SUB_IN_CALL_SERVICE,
+                ErrorStats.SUB_MISC,
+                ErrorStats.SUB_PHONE_ACCOUNT,
+                ErrorStats.SUB_SYSTEM_SERVICE,
+                ErrorStats.SUB_TELEPHONY,
+                ErrorStats.SUB_UI,
+                ErrorStats.SUB_VOIP_CALL,
+        };
+        int[] errors = {
+                ErrorStats.ERROR_UNKNOWN,
+                ErrorStats.ERROR_EXTERNAL_EXCEPTION,
+                ErrorStats.ERROR_INTERNAL_EXCEPTION,
+                ErrorStats.ERROR_AUDIO_ROUTE_RETRY_REJECTED,
+                ErrorStats.ERROR_BT_GET_SERVICE_FAILURE,
+                ErrorStats.ERROR_BT_REGISTER_CALLBACK_FAILURE,
+                ErrorStats.ERROR_AUDIO_ROUTE_UNAVAILABLE,
+                ErrorStats.ERROR_EMERGENCY_NUMBER_DETERMINED_FAILURE,
+                ErrorStats.ERROR_NOTIFY_CALL_STREAM_START_FAILURE,
+                ErrorStats.ERROR_NOTIFY_CALL_STREAM_STATE_CHANGED_FAILURE,
+                ErrorStats.ERROR_NOTIFY_CALL_STREAM_STOP_FAILURE,
+                ErrorStats.ERROR_RTT_STREAM_CLOSE_FAILURE,
+                ErrorStats.ERROR_RTT_STREAM_CREATE_FAILURE,
+                ErrorStats.ERROR_SET_MUTED_FAILURE,
+                ErrorStats.ERROR_VIDEO_PROVIDER_SET_FAILURE,
+                ErrorStats.ERROR_WIRED_HEADSET_NOT_AVAILABLE,
+                ErrorStats.ERROR_LOG_CALL_FAILURE,
+                ErrorStats.ERROR_RETRIEVING_ACCOUNT_EMERGENCY,
+                ErrorStats.ERROR_RETRIEVING_ACCOUNT,
+                ErrorStats.ERROR_EMERGENCY_CALL_ABORTED_NO_ACCOUNT,
+                ErrorStats.ERROR_DEFAULT_MO_ACCOUNT_MISMATCH,
+                ErrorStats.ERROR_ESTABLISHING_CONNECTION,
+                ErrorStats.ERROR_REMOVING_CALL,
+                ErrorStats.ERROR_STUCK_CONNECTING_EMERGENCY,
+                ErrorStats.ERROR_STUCK_CONNECTING,
+        };
+        Random rand = new Random();
+        Map<Long, Integer> eventMap = new HashMap<>();
+
+        for (int i = 0; i < 10; i++) {
+            int module = modules[rand.nextInt(modules.length)];
+            int error = errors[rand.nextInt(errors.length)];
+            long key = (long) module << 32 | error;
+            eventMap.put(key, eventMap.getOrDefault(key, 0) + 1);
+
+            errorStats.log(module, error);
+            waitForHandlerAction(errorStats, DELAY_TOLERANCE);
+
+            verify(errorStats, times(i + 1)).onAggregate();
+            verify(errorStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, eventMap.size());
+            assertTrue(hasMessageForErrorStats(
+                    errorStats.mPulledAtoms.telecomErrorStats, module, error, eventMap.get(key)));
+        }
     }
 
     private void createTestFileForApiStats(long timestamps) throws IOException {
@@ -664,7 +842,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     }
 
     private void verifyTestDataForApiStats(final PulledAtomsClass.PulledAtoms atom,
-                                           long timestamps) {
+            long timestamps) {
         assertNotNull(atom);
         assertEquals(atom.getTelecomApiStatsPullTimestampMillis(), timestamps);
         assertNotNull(atom.telecomApiStats);
@@ -677,13 +855,24 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     }
 
     private void verifyMessageForApiStats(final PulledAtomsClass.TelecomApiStats msg, int apiId,
-                                          int uid, int result, int count) {
+            int uid, int result, int count) {
         assertEquals(msg.getApiName(), apiId);
         assertEquals(msg.getUid(), uid);
         assertEquals(msg.getApiResult(), result);
         assertEquals(msg.getCount(), count);
     }
 
+    private boolean hasMessageForApiStats(final PulledAtomsClass.TelecomApiStats[] msgs, int apiId,
+            int uid, int result, int count) {
+        for (PulledAtomsClass.TelecomApiStats msg : msgs) {
+            if (msg.getApiName() == apiId && msg.getUid() == uid && msg.getApiResult() == result
+                    && msg.getCount() == count) {
+                return true;
+            }
+        }
+        return false;
+    }
+
     private void createTestFileForAudioRouteStats(long timestamps) throws IOException {
         PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
         atom.callAudioRouteStats =
@@ -704,7 +893,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     }
 
     private void verifyTestDataForAudioRouteStats(final PulledAtomsClass.PulledAtoms atom,
-                                                  long timestamps) {
+            long timestamps) {
         assertNotNull(atom);
         assertEquals(atom.getCallAudioRouteStatsPullTimestampMillis(), timestamps);
         assertNotNull(atom.callAudioRouteStats);
@@ -750,7 +939,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     }
 
     private void verifyTestDataForCallStats(final PulledAtomsClass.PulledAtoms atom,
-                                            long timestamps) {
+            long timestamps) {
         assertNotNull(atom);
         assertEquals(atom.getCallStatsPullTimestampMillis(), timestamps);
         assertNotNull(atom.callStats);
@@ -782,8 +971,8 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
                 new PulledAtomsClass.TelecomErrorStats[VALUE_ATOM_COUNT];
         for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
             atom.telecomErrorStats[i] = new PulledAtomsClass.TelecomErrorStats();
-            atom.telecomErrorStats[i].setSubmoduleName(VALUE_MODULE_ID);
-            atom.telecomErrorStats[i].setErrorName(VALUE_ERROR_ID);
+            atom.telecomErrorStats[i].setSubmodule(VALUE_MODULE_ID);
+            atom.telecomErrorStats[i].setError(VALUE_ERROR_ID);
             atom.telecomErrorStats[i].setCount(VALUE_ERROR_COUNT);
         }
         atom.setTelecomErrorStatsPullTimestampMillis(timestamps);
@@ -807,8 +996,19 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
     private void verifyMessageForErrorStats(final PulledAtomsClass.TelecomErrorStats msg,
             int moduleId, int errorId, int count) {
-        assertEquals(msg.getSubmoduleName(), moduleId);
-        assertEquals(msg.getErrorName(), errorId);
+        assertEquals(msg.getSubmodule(), moduleId);
+        assertEquals(msg.getError(), errorId);
         assertEquals(msg.getCount(), count);
     }
+
+    private boolean hasMessageForErrorStats(final PulledAtomsClass.TelecomErrorStats[] msgs,
+            int moduleId, int errorId, int count) {
+        for (PulledAtomsClass.TelecomErrorStats msg : msgs) {
+            if (msg.getSubmodule() == moduleId && msg.getError() == errorId
+                    && msg.getCount() == count) {
+                return true;
+            }
+        }
+        return false;
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java b/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
index dc5f3256e..96bf05ad8 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
@@ -96,9 +96,10 @@ import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.components.UserCallIntentProcessor;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
-import com.android.server.telecom.voip.IncomingCallTransaction;
-import com.android.server.telecom.voip.OutgoingCallTransaction;
-import com.android.server.telecom.voip.TransactionManager;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+import com.android.server.telecom.callsequencing.voip.IncomingCallTransaction;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import org.junit.After;
 import org.junit.Before;
@@ -204,9 +205,11 @@ public class TelecomServiceImplTest extends TelecomTestCase {
     @Mock private com.android.internal.telephony.flags.FeatureFlags mTelephonyFeatureFlags;
 
     @Mock private InCallController mInCallController;
+    @Mock private TelecomMetricsController mMockTelecomMetricsController;
 
     private final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() { };
 
+    private static final String SYSTEM_UI_PACKAGE = "com.android.systemui";
     private static final String DEFAULT_DIALER_PACKAGE = "com.google.android.dialer";
     private static final UserHandle USER_HANDLE_16 = new UserHandle(16);
     private static final UserHandle USER_HANDLE_17 = new UserHandle(17);
@@ -257,7 +260,9 @@ public class TelecomServiceImplTest extends TelecomTestCase {
                 mSettingsSecureAdapter,
                 mFeatureFlags,
                 mTelephonyFeatureFlags,
-                mLock);
+                mLock,
+                mMockTelecomMetricsController,
+                SYSTEM_UI_PACKAGE);
         telecomServiceImpl.setTransactionManager(mTransactionManager);
         telecomServiceImpl.setAnomalyReporterAdapter(mAnomalyReporterAdapter);
         mTSIBinder = telecomServiceImpl.getBinder();
@@ -1090,6 +1095,20 @@ public class TelecomServiceImplTest extends TelecomTestCase {
         // This should fail; security exception will be thrown.
         registerPhoneAccountTestHelper(phoneAccount, false);
 
+        icon = Icon.createWithContentUri(
+                new Uri.Builder().scheme("content")
+                        .encodedAuthority("10%40media")
+                        .path("external/images/media/${mediaId.text}".trim())
+                        .build());
+        phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
+        // This should fail; security exception will be thrown
+        registerPhoneAccountTestHelper(phoneAccount, false);
+
+        icon = Icon.createWithContentUri( Uri.parse("content://10%40play.ground"));
+        phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
+        // This should fail; security exception will be thrown
+        registerPhoneAccountTestHelper(phoneAccount, false);
+
         icon = Icon.createWithContentUri("content://0@media/external/images/media/");
         phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
         // This should succeed.
@@ -2304,7 +2323,8 @@ public class TelecomServiceImplTest extends TelecomTestCase {
     }
 
     /**
-     * Ensure self-managed calls cannot be ended using {@link TelecomManager#endCall()}.
+     * Ensure self-managed calls cannot be ended using {@link TelecomManager#endCall()} when the
+     * caller of this method is not considered privileged.
      * @throws Exception
      */
     @SmallTest
@@ -2321,7 +2341,8 @@ public class TelecomServiceImplTest extends TelecomTestCase {
 
     /**
      * Ensure self-managed calls cannot be answered using {@link TelecomManager#acceptRingingCall()}
-     * or {@link TelecomManager#acceptRingingCall(int)}.
+     * or {@link TelecomManager#acceptRingingCall(int)} when the caller of these methods is not
+     * considered privileged.
      * @throws Exception
      */
     @SmallTest
@@ -2336,6 +2357,53 @@ public class TelecomServiceImplTest extends TelecomTestCase {
         verify(mFakeCallsManager, never()).answerCall(eq(call), anyInt());
     }
 
+    /**
+     * Ensure self-managed calls can be answered using {@link TelecomManager#acceptRingingCall()}
+     * or {@link TelecomManager#acceptRingingCall(int)} if the caller of these methods is
+     * privileged.
+     * @throws Exception
+     */
+    @SmallTest
+    @Test
+    public void testCanAnswerSelfManagedCallIfPrivileged() throws Exception {
+        when(mFeatureFlags.allowSystemAppsResolveVoipCalls()).thenReturn(true);
+        // Configure the test so that the caller of acceptRingingCall is considered privileged:
+        when(mPackageManager.getPackageUid(SYSTEM_UI_PACKAGE, 0))
+                .thenReturn(Binder.getCallingUid());
+
+        // Ensure that the call is successfully accepted:
+        Call call = mock(Call.class);
+        when(call.isSelfManaged()).thenReturn(true);
+        when(call.getState()).thenReturn(CallState.ACTIVE);
+        when(mFakeCallsManager.getFirstCallWithState(any()))
+                .thenReturn(call);
+        mTSIBinder.acceptRingingCall(TEST_PACKAGE);
+        verify(mFakeCallsManager).answerCall(eq(call), anyInt());
+    }
+
+    /**
+     * Ensure self-managed calls can be ended using {@link TelecomManager#endCall()} when the
+     * caller of these methods is privileged.
+     * @throws Exception
+     */
+    @SmallTest
+    @Test
+    public void testCanEndSelfManagedCallIfPrivileged() throws Exception {
+        when(mFeatureFlags.allowSystemAppsResolveVoipCalls()).thenReturn(true);
+        // Configure the test so that the caller of endCall is considered privileged:
+        when(mPackageManager.getPackageUid(SYSTEM_UI_PACKAGE, 0))
+                .thenReturn(Binder.getCallingUid());
+        // Set up the call:
+        Call call = mock(Call.class);
+        when(call.isSelfManaged()).thenReturn(true);
+        when(call.getState()).thenReturn(CallState.ACTIVE);
+        when(mFakeCallsManager.getFirstCallWithState(any()))
+                .thenReturn(call);
+        // Ensure that the call is successfully ended:
+        assertTrue(mTSIBinder.endCall(TEST_PACKAGE));
+        verify(mFakeCallsManager).disconnectCall(eq(call));
+    }
+
     @SmallTest
     @Test
     public void testGetAdnUriForPhoneAccount() throws Exception {
diff --git a/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java b/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
index 4463d65b2..1e6501103 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
@@ -224,6 +224,7 @@ public class TelecomSystemTest extends TelecomTestCase{
     @Mock
     com.android.internal.telephony.flags.FeatureFlags mTelephonyFlags;
 
+    private static final String SYSTEM_UI_PACKAGE = "com.android.systemui";
     final ComponentName mInCallServiceComponentNameX =
             new ComponentName(
                     "incall-service-package-X",
@@ -580,7 +581,8 @@ public class TelecomSystemTest extends TelecomTestCase{
                             ContactsAsyncHelper.ContentResolverAdapter adapter) {
                         return new ContactsAsyncHelper(adapter, mHandlerThread.getLooper());
                     }
-                }, mDeviceIdleControllerAdapter, mAccessibilityManagerAdapter,
+                }, mDeviceIdleControllerAdapter, SYSTEM_UI_PACKAGE,
+                mAccessibilityManagerAdapter,
                 Runnable::run,
                 Runnable::run,
                 mBlockedNumbersAdapter,
diff --git a/tests/src/com/android/server/telecom/tests/TelecomTestCase.java b/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
index e8389a06d..5b5c3ed7e 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
@@ -51,8 +51,8 @@ public abstract class TelecomTestCase {
 
         mComponentContextFixture = new ComponentContextFixture(mFeatureFlags);
         mContext = mComponentContextFixture.getTestDouble().getApplicationContext();
-        Log.setSessionContext(mComponentContextFixture.getTestDouble().getApplicationContext());
-        Log.getSessionManager().mCleanStaleSessions = null;
+        Log.setSessionManager(mComponentContextFixture.getTestDouble().getApplicationContext(),
+                null);
     }
 
     public void tearDown() throws Exception {
diff --git a/tests/src/com/android/server/telecom/tests/TransactionTests.java b/tests/src/com/android/server/telecom/tests/TransactionTests.java
index 58764744b..78c22109d 100644
--- a/tests/src/com/android/server/telecom/tests/TransactionTests.java
+++ b/tests/src/com/android/server/telecom/tests/TransactionTests.java
@@ -16,24 +16,25 @@
 
 package com.android.server.telecom.tests;
 
-import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToVideoProfileState;
-import static com.android.server.telecom.voip.VideoStateTranslation.VideoProfileStateToTransactionalVideoState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .TransactionalVideoStateToVideoProfileState;
+import static com.android.server.telecom.callsequencing.voip.VideoStateTranslation
+        .VideoProfileStateToTransactionalVideoState;
 
+import static org.junit.Assert.assertEquals;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.ArgumentMatchers.nullable;
 import static org.mockito.Mockito.atLeastOnce;
+import static org.mockito.Mockito.doAnswer;
+import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.isA;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
-import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.isA;
-import static org.junit.Assert.assertEquals;
-import static org.mockito.ArgumentMatchers.nullable;
-import static org.mockito.Mockito.doAnswer;
-import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.when;
 
 import android.content.ComponentName;
@@ -59,30 +60,26 @@ import com.android.server.telecom.CallerInfoLookupHelper;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.ClockProxy;
 import com.android.server.telecom.ConnectionServiceWrapper;
-import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.PhoneNumberUtilsAdapter;
 import com.android.server.telecom.TelecomSystem;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.VerifyCallStateChangeTransaction;
+import com.android.server.telecom.callsequencing.voip.EndCallTransaction;
+import com.android.server.telecom.callsequencing.voip.HoldCallTransaction;
+import com.android.server.telecom.callsequencing.voip.IncomingCallTransaction;
+import com.android.server.telecom.callsequencing.voip.MaybeHoldCallForNewCallTransaction;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
+import com.android.server.telecom.callsequencing.voip.RequestNewActiveCallTransaction;
 import com.android.server.telecom.ui.ToastFactory;
-import com.android.server.telecom.voip.EndCallTransaction;
-import com.android.server.telecom.voip.HoldCallTransaction;
-import com.android.server.telecom.voip.IncomingCallTransaction;
-import com.android.server.telecom.voip.OutgoingCallTransaction;
-import com.android.server.telecom.voip.MaybeHoldCallForNewCallTransaction;
-import com.android.server.telecom.voip.RequestNewActiveCallTransaction;
-import com.android.server.telecom.voip.TransactionManager;
-import com.android.server.telecom.voip.VerifyCallStateChangeTransaction;
-import com.android.server.telecom.voip.VideoStateTranslation;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
 
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
-
 import org.mockito.Mock;
 import org.mockito.Mockito;
 import org.mockito.MockitoAnnotations;
 
-import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ExecutionException;
 import java.util.concurrent.TimeUnit;
 import java.util.concurrent.TimeoutException;
@@ -421,7 +418,7 @@ public class TransactionTests extends TelecomTestCase {
 
         // THEN
         verify(mMockCall1, times(1)).addCallStateListener(t.getCallStateListenerImpl());
-        assertEquals(VoipCallTransactionResult.RESULT_SUCCEED,
+        assertEquals(CallTransactionResult.RESULT_SUCCEED,
                 t.getTransactionResult().get(2, TimeUnit.SECONDS).getResult());
         verify(mMockCall1, atLeastOnce()).removeCallStateListener(any());
     }
diff --git a/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java b/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
index fa5f2a295..fea613583 100644
--- a/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
+++ b/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
@@ -39,10 +39,10 @@ import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.TransactionalServiceRepository;
 import com.android.server.telecom.TransactionalServiceWrapper;
-import com.android.server.telecom.voip.EndCallTransaction;
-import com.android.server.telecom.voip.HoldCallTransaction;
-import com.android.server.telecom.voip.SerialTransaction;
-import com.android.server.telecom.voip.TransactionManager;
+import com.android.server.telecom.callsequencing.voip.EndCallTransaction;
+import com.android.server.telecom.callsequencing.voip.HoldCallTransaction;
+import com.android.server.telecom.callsequencing.voip.SerialTransaction;
+import com.android.server.telecom.callsequencing.TransactionManager;
 
 import org.junit.After;
 import org.junit.Before;
@@ -83,9 +83,8 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
         Mockito.when(mCallsManager.getLock()).thenReturn(mLock);
         Mockito.when(mCallEventCallback.asBinder()).thenReturn(mIBinder);
         mTransactionalServiceWrapper = new TransactionalServiceWrapper(mCallEventCallback,
-                mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository);
-
-        mTransactionalServiceWrapper.setTransactionManager(mTransactionManager);
+                mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
+                false /*call sequencing*/);
     }
 
     @Override
@@ -98,7 +97,8 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
     public void testTransactionalServiceWrapperStartState() throws Exception {
         TransactionalServiceWrapper service =
                 new TransactionalServiceWrapper(mCallEventCallback,
-                        mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository);
+                        mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
+                        false /*call sequencing*/);
 
         assertEquals(SERVICE_HANDLE, service.getPhoneAccountHandle());
         assertEquals(1, service.getNumberOfTrackedCalls());
@@ -108,7 +108,8 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
     public void testTransactionalServiceWrapperCallCount() throws Exception {
         TransactionalServiceWrapper service =
                 new TransactionalServiceWrapper(mCallEventCallback,
-                        mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository);
+                        mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
+                        false /*call sequencing*/);
 
         assertEquals(1, service.getNumberOfTrackedCalls());
         service.trackCall(mMockCall2);
diff --git a/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java b/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
index 7f7399c67..bf68f8c43 100644
--- a/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
+++ b/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
@@ -49,7 +49,7 @@ import androidx.test.filters.SmallTest;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.TelecomSystem;
-import com.android.server.telecom.voip.VoipCallMonitor;
+import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
 
 import org.junit.Before;
 import org.junit.Test;
diff --git a/tests/src/com/android/server/telecom/tests/VoipCallTransactionTest.java b/tests/src/com/android/server/telecom/tests/VoipCallTransactionTest.java
index c5be13019..c479aac15 100644
--- a/tests/src/com/android/server/telecom/tests/VoipCallTransactionTest.java
+++ b/tests/src/com/android/server/telecom/tests/VoipCallTransactionTest.java
@@ -25,11 +25,11 @@ import android.telecom.CallException;
 import androidx.test.filters.SmallTest;
 
 import com.android.server.telecom.TelecomSystem;
-import com.android.server.telecom.voip.ParallelTransaction;
-import com.android.server.telecom.voip.SerialTransaction;
-import com.android.server.telecom.voip.TransactionManager;
-import com.android.server.telecom.voip.VoipCallTransaction;
-import com.android.server.telecom.voip.VoipCallTransactionResult;
+import com.android.server.telecom.callsequencing.voip.ParallelTransaction;
+import com.android.server.telecom.callsequencing.voip.SerialTransaction;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
 
 import org.junit.After;
 import org.junit.Before;
@@ -51,7 +51,7 @@ public class VoipCallTransactionTest extends TelecomTestCase {
     private TransactionManager mTransactionManager;
     private static final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() { };
 
-    private class TestVoipCallTransaction extends VoipCallTransaction {
+    private class TestVoipCallTransaction extends CallTransaction {
         public static final int SUCCESS = 0;
         public static final int FAILED = 1;
         public static final int TIMEOUT = 2;
@@ -70,27 +70,27 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         }
 
         @Override
-        public CompletionStage<VoipCallTransactionResult> processTransaction(Void v) {
+        public CompletionStage<CallTransactionResult> processTransaction(Void v) {
             if (mType == EXCEPTION) {
                 mLog.append(mName).append(" exception;\n");
                 throw new IllegalStateException("TEST EXCEPTION");
             }
-            CompletableFuture<VoipCallTransactionResult> resultFuture = new CompletableFuture<>();
+            CompletableFuture<CallTransactionResult> resultFuture = new CompletableFuture<>();
             mHandler.postDelayed(() -> {
                 if (mType == SUCCESS) {
                     mLog.append(mName).append(" success;\n");
                     resultFuture.complete(
-                            new VoipCallTransactionResult(VoipCallTransactionResult.RESULT_SUCCEED,
+                            new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                                     null));
                 } else if (mType == FAILED) {
                     mLog.append(mName).append(" failed;\n");
                     resultFuture.complete(
-                            new VoipCallTransactionResult(CallException.CODE_ERROR_UNKNOWN,
+                            new CallTransactionResult(CallException.CODE_ERROR_UNKNOWN,
                                     null));
                 } else {
                     mLog.append(mName).append(" timeout;\n");
                     resultFuture.complete(
-                            new VoipCallTransactionResult(CallException.CODE_ERROR_UNKNOWN,
+                            new CallTransactionResult(CallException.CODE_ERROR_UNKNOWN,
                                     "timeout"));
                 }
             }, mSleepTime);
@@ -122,7 +122,7 @@ public class VoipCallTransactionTest extends TelecomTestCase {
     @Test
     public void testSerialTransactionSuccess()
             throws ExecutionException, InterruptedException, TimeoutException {
-        List<VoipCallTransaction> subTransactions = new ArrayList<>();
+        List<CallTransaction> subTransactions = new ArrayList<>();
         TestVoipCallTransaction t1 = new TestVoipCallTransaction("t1", 1000L,
                 TestVoipCallTransaction.SUCCESS);
         TestVoipCallTransaction t2 = new TestVoipCallTransaction("t2", 1000L,
@@ -132,13 +132,13 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         subTransactions.add(t1);
         subTransactions.add(t2);
         subTransactions.add(t3);
-        CompletableFuture<VoipCallTransactionResult> resultFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        CompletableFuture<CallTransactionResult> resultFuture = new CompletableFuture<>();
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 resultFuture::complete;
         String expectedLog = "t1 success;\nt2 success;\nt3 success;\n";
         mTransactionManager.addTransaction(new SerialTransaction(subTransactions, mLock),
                 outcomeReceiver);
-        assertEquals(VoipCallTransactionResult.RESULT_SUCCEED,
+        assertEquals(CallTransactionResult.RESULT_SUCCEED,
                 resultFuture.get(5000L, TimeUnit.MILLISECONDS).getResult());
         assertEquals(expectedLog, mLog.toString());
         verifyTransactionsFinished(t1, t2, t3);
@@ -148,7 +148,7 @@ public class VoipCallTransactionTest extends TelecomTestCase {
     @Test
     public void testSerialTransactionFailed()
             throws ExecutionException, InterruptedException, TimeoutException {
-        List<VoipCallTransaction> subTransactions = new ArrayList<>();
+        List<CallTransaction> subTransactions = new ArrayList<>();
         TestVoipCallTransaction t1 = new TestVoipCallTransaction("t1", 1000L,
                 TestVoipCallTransaction.SUCCESS);
         TestVoipCallTransaction t2 = new TestVoipCallTransaction("t2", 1000L,
@@ -159,10 +159,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         subTransactions.add(t2);
         subTransactions.add(t3);
         CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
-                new OutcomeReceiver<VoipCallTransactionResult, CallException>() {
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
+                new OutcomeReceiver<CallTransactionResult, CallException>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
 
                     }
 
@@ -183,7 +183,7 @@ public class VoipCallTransactionTest extends TelecomTestCase {
     @Test
     public void testParallelTransactionSuccess()
             throws ExecutionException, InterruptedException, TimeoutException {
-        List<VoipCallTransaction> subTransactions = new ArrayList<>();
+        List<CallTransaction> subTransactions = new ArrayList<>();
         TestVoipCallTransaction t1 = new TestVoipCallTransaction("t1", 1000L,
                 TestVoipCallTransaction.SUCCESS);
         TestVoipCallTransaction t2 = new TestVoipCallTransaction("t2", 500L,
@@ -193,12 +193,12 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         subTransactions.add(t1);
         subTransactions.add(t2);
         subTransactions.add(t3);
-        CompletableFuture<VoipCallTransactionResult> resultFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        CompletableFuture<CallTransactionResult> resultFuture = new CompletableFuture<>();
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 resultFuture::complete;
         mTransactionManager.addTransaction(new ParallelTransaction(subTransactions, mLock),
                 outcomeReceiver);
-        assertEquals(VoipCallTransactionResult.RESULT_SUCCEED,
+        assertEquals(CallTransactionResult.RESULT_SUCCEED,
                 resultFuture.get(5000L, TimeUnit.MILLISECONDS).getResult());
         String log = mLog.toString();
         assertTrue(log.contains("t1 success;\n"));
@@ -211,7 +211,7 @@ public class VoipCallTransactionTest extends TelecomTestCase {
     @Test
     public void testParallelTransactionFailed()
             throws ExecutionException, InterruptedException, TimeoutException {
-        List<VoipCallTransaction> subTransactions = new ArrayList<>();
+        List<CallTransaction> subTransactions = new ArrayList<>();
         TestVoipCallTransaction t1 = new TestVoipCallTransaction("t1", 1000L,
                 TestVoipCallTransaction.SUCCESS);
         TestVoipCallTransaction t2 = new TestVoipCallTransaction("t2", 500L,
@@ -222,10 +222,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         subTransactions.add(t2);
         subTransactions.add(t3);
         CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 new OutcomeReceiver<>() {
             @Override
-            public void onResult(VoipCallTransactionResult result) {
+            public void onResult(CallTransactionResult result) {
 
             }
 
@@ -248,10 +248,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         TestVoipCallTransaction t = new TestVoipCallTransaction("t", 10000L,
                 TestVoipCallTransaction.SUCCESS);
         CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
 
                     }
 
@@ -275,10 +275,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         TestVoipCallTransaction t2 = new TestVoipCallTransaction("t2", 1000L,
                 TestVoipCallTransaction.SUCCESS);
         CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeExceptionReceiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeExceptionReceiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
                     }
 
                     @Override
@@ -291,12 +291,12 @@ public class VoipCallTransactionTest extends TelecomTestCase {
         exceptionFuture.get(7000L, TimeUnit.MILLISECONDS);
         assertTrue(mLog.toString().contains("t1 exception;\n"));
         // Verify an exception in a processing a previous transaction does not stall the next one.
-        CompletableFuture<VoipCallTransactionResult> resultFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        CompletableFuture<CallTransactionResult> resultFuture = new CompletableFuture<>();
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 resultFuture::complete;
         mTransactionManager.addTransaction(t2, outcomeReceiver);
         String expectedLog = "t1 exception;\nt2 success;\n";
-        assertEquals(VoipCallTransactionResult.RESULT_SUCCEED,
+        assertEquals(CallTransactionResult.RESULT_SUCCEED,
                 resultFuture.get(5000L, TimeUnit.MILLISECONDS).getResult());
         assertEquals(expectedLog, mLog.toString());
         verifyTransactionsFinished(t1, t2);
@@ -317,10 +317,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
                 TestVoipCallTransaction.EXCEPTION);
         // verify the TransactionManager informs the client of the failed transaction
         CompletableFuture<String> exceptionFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeExceptionReceiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeExceptionReceiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
                     }
 
                     @Override
@@ -346,10 +346,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
                 TestVoipCallTransaction.SUCCESS);
         TestVoipCallTransaction t3 = new TestVoipCallTransaction("t3", 1000L,
                 TestVoipCallTransaction.SUCCESS);
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeExceptionReceiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeExceptionReceiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
                         throw new IllegalStateException("RESULT EXCEPTION");
                     }
 
@@ -358,10 +358,10 @@ public class VoipCallTransactionTest extends TelecomTestCase {
                     }
                 };
         mTransactionManager.addTransaction(t1, outcomeExceptionReceiver);
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeException2Receiver =
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeException2Receiver =
                 new OutcomeReceiver<>() {
                     @Override
-                    public void onResult(VoipCallTransactionResult result) {
+                    public void onResult(CallTransactionResult result) {
                     }
 
                     @Override
@@ -371,12 +371,12 @@ public class VoipCallTransactionTest extends TelecomTestCase {
                 };
         mTransactionManager.addTransaction(t2, outcomeException2Receiver);
         // Verify an exception in a previous transaction result does not stall the next one.
-        CompletableFuture<VoipCallTransactionResult> resultFuture = new CompletableFuture<>();
-        OutcomeReceiver<VoipCallTransactionResult, CallException> outcomeReceiver =
+        CompletableFuture<CallTransactionResult> resultFuture = new CompletableFuture<>();
+        OutcomeReceiver<CallTransactionResult, CallException> outcomeReceiver =
                 resultFuture::complete;
         mTransactionManager.addTransaction(t3, outcomeReceiver);
         String expectedLog = "t1 success;\nt2 success;\nt3 success;\n";
-        assertEquals(VoipCallTransactionResult.RESULT_SUCCEED,
+        assertEquals(CallTransactionResult.RESULT_SUCCEED,
                 resultFuture.get(5000L, TimeUnit.MILLISECONDS).getResult());
         assertEquals(expectedLog, mLog.toString());
         verifyTransactionsFinished(t1, t2, t3);
```

