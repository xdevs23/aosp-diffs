```diff
diff --git a/TEST_MAPPING b/TEST_MAPPING
index 09ebfe255..13553436c 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -47,11 +47,9 @@
           "exclude-annotation": "androidx.test.filters.FlakyTest"
         }
       ]
-    }
-  ],
-  "presubmit-large": [
+    },
     {
-      "name": "CtsTelecomTestCases",
+      "name": "CtsTelecomCujTestCases",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.FlakyTest"
@@ -59,9 +57,9 @@
       ]
     }
   ],
-  "postsubmit": [
+  "presubmit-large": [
     {
-      "name": "CtsTelecomCujTestCases",
+      "name": "CtsTelecomTestCases",
       "options": [
         {
           "exclude-annotation": "androidx.test.filters.FlakyTest"
diff --git a/flags/Android.bp b/flags/Android.bp
index 54b14437d..6f9caae6d 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -46,5 +46,6 @@ aconfig_declarations {
         "telecom_headless_system_user_mode.aconfig",
         "telecom_session_flags.aconfig",
         "telecom_metrics_flags.aconfig",
+        "telecom_voip_flags.aconfig",
     ],
 }
diff --git a/flags/telecom_anomaly_report_flags.aconfig b/flags/telecom_anomaly_report_flags.aconfig
index 5d42b867c..bc248c80e 100644
--- a/flags/telecom_anomaly_report_flags.aconfig
+++ b/flags/telecom_anomaly_report_flags.aconfig
@@ -27,3 +27,11 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+# OWNER=tjstuart TARGET=25Q2
+flag {
+  name: "enable_call_exception_anom_reports"
+  namespace: "telecom"
+  description: "When a new CallException is created, generate an anomaly report for metrics"
+  bug: "308932906"
+}
diff --git a/flags/telecom_bluetoothdevicemanager_flags.aconfig b/flags/telecom_bluetoothdevicemanager_flags.aconfig
index 5dd5831dd..1c8bd0c10 100644
--- a/flags/telecom_bluetoothdevicemanager_flags.aconfig
+++ b/flags/telecom_bluetoothdevicemanager_flags.aconfig
@@ -18,3 +18,13 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+# OWNER=grantmenke TARGET=25Q2
+flag {
+  name: "skip_baseline_switch_when_route_not_bluetooth"
+  namespace: "telecom"
+  description: "Only switch back to baseline if the call audio is currently routed to bluetooth"
+  bug: "333417369"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
\ No newline at end of file
diff --git a/flags/telecom_call_flags.aconfig b/flags/telecom_call_flags.aconfig
index 634d7a383..0000f3292 100644
--- a/flags/telecom_call_flags.aconfig
+++ b/flags/telecom_call_flags.aconfig
@@ -65,4 +65,23 @@ flag {
   metadata {
       purpose: PURPOSE_BUGFIX
     }
-}
\ No newline at end of file
+}
+
+# OWNER=breadley TARGET=25Q2
+flag {
+  name: "enable_respond_via_sms_manager_async"
+  namespace: "telecom"
+  description: "Move RespondViaSmsManager to async thread"
+  bug: "328013578"
+  metadata {
+      purpose: PURPOSE_BUGFIX
+    }
+}
+
+# OWNER=pmadapurmath TARGET=25Q4
+flag {
+  name: "call_sequencing_call_resume_failed"
+  namespace: "telecom"
+  description: "Connection event received when a call resume fails"
+  bug: "390116261"
+}
diff --git a/flags/telecom_callaudioroutestatemachine_flags.aconfig b/flags/telecom_callaudioroutestatemachine_flags.aconfig
index a60c0f13b..c0edf7f4b 100644
--- a/flags/telecom_callaudioroutestatemachine_flags.aconfig
+++ b/flags/telecom_callaudioroutestatemachine_flags.aconfig
@@ -89,6 +89,17 @@ flag {
   bug: "315865533"
 }
 
+# OWNER=tgunn TARGET=24Q3
+flag {
+  name: "dont_use_communication_device_tracker"
+  namespace: "telecom"
+  description: "Do not use the communication device tracker with useRefactoredAudioRouteSwitching."
+  bug: "346472575"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
 # OWNER=pmadapurmath TARGET=24Q3
 flag {
   name: "resolve_switching_bt_devices_computation"
@@ -129,3 +140,69 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "only_clear_communication_device_on_inactive"
+  namespace: "telecom"
+  description: "Only clear the communication device when transitioning to an inactive route."
+  bug: "376781369"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "check_device_type_on_route_change"
+  namespace: "telecom"
+  description: "When comparing devices on route change, also consider device type."
+  bug: "388509460"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "bus_device_is_a_speaker"
+  namespace: "telecom"
+  description: "Treat TYPE_BUS devices like TYPE_SPEAKER"
+  bug: "395647782"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=pmadapurmath TARGET=25Q3
+flag {
+  name: "update_preferred_audio_device_logic"
+  namespace: "telecom"
+  description: "Change the use of preferred device for strategy to only use it at the start of the call and include relevant syncing with AudioManager#getCommunicationDevice"
+  bug: "377345692"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=pmadapurmath TARGET=25Q3
+flag {
+  name: "call_audio_routing_performance_improvemenent"
+  namespace: "telecom"
+  description: "Change the handler to use the main looper to improve performance with processing messages from the message queue"
+  bug: "383466267"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
+
+# OWNER=pmadapurmath TARGET=25Q3
+flag {
+  name: "maybe_default_speaker_after_unhold"
+  namespace: "telecom"
+  description: "If the call audio route was on speaker and the call is held/unheld, ensure that we route back to speaker."
+  bug: "406898224"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_calls_manager_flags.aconfig b/flags/telecom_calls_manager_flags.aconfig
index f46e84429..6b8b772b7 100644
--- a/flags/telecom_calls_manager_flags.aconfig
+++ b/flags/telecom_calls_manager_flags.aconfig
@@ -35,3 +35,14 @@ flag {
     purpose: PURPOSE_BUGFIX
   }
 }
+
+# OWNER=tgunn TARGET=25Q2
+flag {
+  name: "enable_call_audio_watchdog"
+  namespace: "telecom"
+  description: "Enables tracking of audio resources for voip calls to aid in diagnostics."
+  bug: "384570270"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_voip_flags.aconfig b/flags/telecom_voip_flags.aconfig
new file mode 100644
index 000000000..67635e9f3
--- /dev/null
+++ b/flags/telecom_voip_flags.aconfig
@@ -0,0 +1,13 @@
+package: "com.android.server.telecom.flags"
+container: "system"
+
+# OWNER=tjstuart TARGET=25Q2
+flag {
+  name: "voip_call_monitor_refactor"
+  namespace: "telecom"
+  description: "VoipCallMonitor reworked to handle multi calling scenarios for the same app"
+  bug: "381129034"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
\ No newline at end of file
diff --git a/proguard.flags b/proguard.flags
index 7c71a157b..9d326ff78 100644
--- a/proguard.flags
+++ b/proguard.flags
@@ -1,7 +1,9 @@
--verbose
--keep @com.android.internal.annotations.VisibleForTesting class *
+# TODO(b/373579455): Evaluate if <init> needs to be kept.
+-keep @com.android.internal.annotations.VisibleForTesting class * {
+  void <init>();
+}
 -keep public class * extends android.widget.ListView {
-    public *;
+  public *;
 }
 -keep class com.android.server.telecom.TelecomSystem {
   *;
diff --git a/proto/pulled_atoms.proto b/proto/pulled_atoms.proto
index 6c9af46b5..a72e847d9 100644
--- a/proto/pulled_atoms.proto
+++ b/proto/pulled_atoms.proto
@@ -14,6 +14,8 @@ message PulledAtoms {
   optional int64 telecom_api_stats_pull_timestamp_millis = 6;
   repeated TelecomErrorStats telecom_error_stats = 7;
   optional int64 telecom_error_stats_pull_timestamp_millis = 8;
+  repeated TelecomEventStats telecom_event_stats = 9;
+  optional int64 telecom_event_stats_pull_timestamp_millis = 10;
 }
 
 /**
@@ -48,6 +50,18 @@ message CallStats {
 
     // Average elapsed time between CALL_STATE_ACTIVE to CALL_STATE_DISCONNECTED.
     optional int32 average_duration_ms = 8;
+
+    // The disconnect cause of the call. Eg. ERROR, LOCAL, REMOTE, etc.
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 disconnect_cause = 9;
+
+    // The type of simultaneous call type. Eg. SINGLE, DUAL_SAME_ACCOUNT,
+    // DUAL_DIFF_ACCOUNT, etc.
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 simultaneous_type = 10;
+
+    // True if it is a video call
+    optional bool video_call = 11;
 }
 
 /**
@@ -112,3 +126,22 @@ message TelecomErrorStats {
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
+    optional int32 event = 1;
+
+    // UID of the caller. This is always -1/unknown for the private space.
+    optional int32 uid = 2;
+
+    // The cause related to the event
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 event_cause = 3;
+
+    // The number of times this event occurs
+    optional int32 count = 4;
+}
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 71564e874..0ab86e222 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -30,7 +30,7 @@
     <string name="notification_disconnectedCall_body" msgid="600491714584417536">"Die oproep na <xliff:g id="CALLER">%s</xliff:g> is ontkoppel as gevolg van \'n noodoproep wat gemaak word."</string>
     <string name="notification_disconnectedCall_generic_body" msgid="5282765206349184853">"Jou oproep is ontkoppel as gevolg van \'n noodoproep wat gemaak word."</string>
     <string name="notification_audioProcessing_title" msgid="1619035039880584575">"Agtergrondoproep"</string>
-    <string name="notification_audioProcessing_body" msgid="8811420157964118913">"<xliff:g id="AUDIO_PROCESSING_APP_NAME">%s</xliff:g> verwerk ’n oproep in die agtergrond. Hierdie program kan dalk toegang tot oudio kry en dit oor die oproep speel."</string>
+    <string name="notification_audioProcessing_body" msgid="8811420157964118913">"<xliff:g id="AUDIO_PROCESSING_APP_NAME">%s</xliff:g> verwerk ’n oproep in die agtergrond. Hierdie app kan dalk toegang tot oudio kry en dit oor die oproep speel."</string>
     <string name="notification_incallservice_not_responding_title" msgid="5347557574288598548">"<xliff:g id="IN_CALL_SERVICE_APP_NAME">%s</xliff:g> het opgehou reageer"</string>
     <string name="notification_incallservice_not_responding_body" msgid="9209308270131968623">"Jou oproep het die foonprogram gebruik wat saam met jou toestel gekom het"</string>
     <string name="accessibility_call_muted" msgid="2968461092554300779">"Oproep stilgemaak."</string>
@@ -47,16 +47,16 @@
     <string name="respond_via_sms_failure_format" msgid="5198680980054596391">"Kon nie boodskap aan <xliff:g id="PHONE_NUMBER">%s</xliff:g> stuur nie."</string>
     <string name="enable_account_preference_title" msgid="6949224486748457976">"Oproeprekeninge"</string>
     <string name="outgoing_call_not_allowed_user_restriction" msgid="3424338207838851646">"Net noodoproepe word toegelaat."</string>
-    <string name="outgoing_call_not_allowed_no_permission" msgid="8590468836581488679">"Hierdie program kan nie uitgaande oproepe maak sonder die foon se toestemming nie."</string>
+    <string name="outgoing_call_not_allowed_no_permission" msgid="8590468836581488679">"Hierdie app kan nie uitgaande oproepe maak sonder die foon se toestemming nie."</string>
     <string name="outgoing_call_error_no_phone_number_supplied" msgid="7665135102566099778">"Voer \'n geldige nommer in om \'n oproep te maak."</string>
     <string name="duplicate_video_call_not_allowed" msgid="5754746140185781159">"Oproep kan nie op die oomblik bygevoeg word nie."</string>
     <string name="no_vm_number" msgid="2179959110602180844">"Vermiste stemboodskapnommer"</string>
     <string name="no_vm_number_msg" msgid="1339245731058529388">"Geen stemboodskapnommer is op die SIM-kaart gestoor nie."</string>
     <string name="add_vm_number_str" msgid="5179510133063168998">"Voeg nommer by"</string>
-    <string name="change_default_dialer_dialog_title" msgid="5861469279421508060">"Maak <xliff:g id="NEW_APP">%s</xliff:g> jou verstek-Foon-program?"</string>
+    <string name="change_default_dialer_dialog_title" msgid="5861469279421508060">"Maak <xliff:g id="NEW_APP">%s</xliff:g> jou verstek-Foon-app?"</string>
     <string name="change_default_dialer_dialog_affirmative" msgid="8604665314757739550">"Stel verstek"</string>
     <string name="change_default_dialer_dialog_negative" msgid="8648669840052697821">"Kanselleer"</string>
-    <string name="change_default_dialer_warning_message" msgid="8461963987376916114">"<xliff:g id="NEW_APP">%s</xliff:g> sal oproepe kan maak en alle aspekte daarvan beheer. Net programme wat jy vertrou, moet as die verstek-Foon-program gestel word."</string>
+    <string name="change_default_dialer_warning_message" msgid="8461963987376916114">"<xliff:g id="NEW_APP">%s</xliff:g> sal oproepe kan maak en alle aspekte daarvan beheer. Net apps wat jy vertrou, moet as die verstek-Foon-app gestel word."</string>
     <string name="change_default_call_screening_dialog_title" msgid="5365787219927262408">"Maak <xliff:g id="NEW_APP">%s</xliff:g> jou verstek-oproepsiftingsprogram?"</string>
     <string name="change_default_call_screening_warning_message_for_disable_old_app" msgid="2039830033533243164">"<xliff:g id="OLD_APP">%s</xliff:g> sal nie meer oproepe kan sif nie."</string>
     <string name="change_default_call_screening_warning_message" msgid="9020537562292754269">"<xliff:g id="NEW_APP">%s</xliff:g> sal inligting oor bellers kan sien wat nie in jou kontakte is nie en hulle sal hierdie oproepe kan blokkeer. Net programme wat jy vertrou, moet as die verstek-oproepsiftingsprogram gestel word."</string>
@@ -93,7 +93,7 @@
     <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Kan nie oproep maak nie. Gaan jou toestel se verbinding na."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Oproep kan nie gemaak word nie weens jou <xliff:g id="OTHER_CALL">%1$s</xliff:g>-oproep."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Oproep kan nie gemaak word nie weens jou <xliff:g id="OTHER_CALL">%1$s</xliff:g>-oproepe."</string>
-    <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Oproep kan nie gemaak word nie weens \'n oproep in \'n ander program."</string>
+    <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Oproep kan nie gemaak word nie weens \'n oproep in \'n ander app."</string>
     <string name="notification_channel_incoming_call" msgid="5245550964701715662">"Inkomende oproepe"</string>
     <string name="notification_channel_missed_call" msgid="7168893015283909012">"Gemiste oproepe"</string>
     <string name="notification_channel_call_blocking" msgid="2028807677868598710">"Oproepblokkering"</string>
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Stroom oudio na ander toestel"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Beëindig oproep"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Skakel hier oor"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Kan nie ’n oproep maak nie omdat daar reeds ’n ander oproep is wat verbind. Wag dat die oproep beantwoord word of beëindig die oproep voordat ’n ander oproep gemaak word."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Kan nie ’n oproep maak nie omdat daar reeds twee oproepe aan die gang is. Beëindig een van die oproepe of voeg dit saam in ’n konferensie voordat ’n nuwe oproep gemaak word."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Kan nie ’n oproep maak nie omdat daar reeds twee oproepe aan die gang is. Beëindig een van die oproepe voordat ’n nuwe oproep gemaak word."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Kan nie ’n oproep maak nie omdat daar ’n oproep is wat nie aangehou kan word nie. Beëindig die oproep voordat ’n nuwe oproep gemaak word."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Kan nie ’n oproep maak nie, aangesien daar ’n onbeantwoorde inkomende oproep is. Beantwoord of weier die inkomende oproep voordat jy ’n nuwe oproep plaas."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Hierdie MMI-kode is nie beskikbaar vir oproepe tussen verskeie rekeninge nie."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-kodes kan nie tydens ’n noodoproep geskakel word nie."</string>
 </resources>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index dafbe6e7b..e42985986 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ኦዲዮን ወደ ሌላ መሣሪያ በመልቀቅ ላይ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ዝጋ"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"እዚህ ቀይር"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ቀድሞውኑ ሌላ ጥሪ እየተገናኘ ስለሆነ ጥሪ ማድረግ አይቻልም። ሌላ ጥሪ ከማድረግዎ በፊት ጥሪ እስኪመለስ ወይም ግንኙነቱ እስኪቋረጥ ድረስ ይጠብቁ።"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ቀድሞውኑ ሁለት ጥሪዎች በሂደት ላይ ስለሆኑ ጥሪ ማድረግ አልተቻለም። አዲስ ጥሪ ከማድረግዎ በፊት ከጥሪዎቹ ላይ የአንዱን ግንኙነት ያቋርጡ ወይም ወደ ጉባዔ ያዋህዷቸው።"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ቀድሞውኑ ሁለት ጥሪዎች በሂደት ላይ ስለሆኑ ጥሪ ማድረግ አልተቻለም። አዲስ ጥሪ ከማድረግዎ በፊት ከጥሪዎቹ የአንዱን ግንኙነት ያቋርጡ።"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ይቆይ ሊደረግ የማይችል ጥሪ በመኖሩ ጥሪ ማድረግ አልተቻለም። አዲስ ጥሪ ከማድረግዎ በፊት የጥሪውን ግንኙነት ያቋርጡ።"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ያልተመለሰ ገቢ ጥሪ ስላለ ጥሪ ማድረግ አይቻልም። አዲስ ጥሪ ከማድረግዎ በፊት ገቢ ጥሪን ይመልሱ ወይም ይዝጉ።"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ይህ MMI ኮድ በርካታ መለያዎች ላይ ላሉ ጥሪዎች አይገኝም።"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI ኮዶች በአደጋ ጥሪ ወቅት መደወል አይችሉም።"</string>
 </resources>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 9eb3a35c1..dcc5cd2b3 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"بث الصوت على جهاز آخر"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"قطع الاتصال"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"الانتقال إلى هنا"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"لا يمكن إجراء مكالمة لأنّ هناك مكالمة أخرى تجري حاليًا. يُرجى الانتظار حتى يتم الرد على المكالمة أو إنهائها قبل إجراء مكالمة أخرى."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"لا يمكن إجراء مكالمة لأنّ هناك مكالمتين جاريتين حاليًا. يمكنك إنهاء إحدى المكالمتين أو دمجهما في مكالمة جماعية قبل إجراء مكالمة جديدة."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"لا يمكن إجراء مكالمة لأنّ هناك مكالمتين جاريتين حاليًا. يُرجى إنهاء إحدى المكالمتين قبل إجراء مكالمة جديدة."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"أنت في مكالمة غير قابلة للتعليق، لذا لا يمكن إجراء مكالمة أخرى. يُرجى إنهاء المكالمة الحالية لإجراء مكالمة جديدة."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"لا يمكن إجراء مكالمة لأن هناك مكالمة واردة لم يتم الرد عليها. يُرجى الرد على المكالمة الواردة أو رفضها قبل إجراء مكالمة جديدة."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"‏لا يتوفّر رمز MMI هذا للمكالمات على مستوى حسابات متعددة."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"‏لا يمكن الاتصال برموز MMI أثناء إجراء مكالمة طوارئ."</string>
 </resources>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 668f5e55d..9d20cd2c6 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"অন্য এটা ডিভাইচলৈ অডিঅ’ ষ্ট্ৰীম কৰি থকা হৈছে"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"কলটো কাটি দিয়ক"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ইয়াত সলনি কৰক"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"কল কৰিব নোৱাৰি কাৰণ অন্য এটা কল সংযোগ কৰি থকা হৈছে। অন্য এটা কল কৰাৰ আগতে সেই কলটোৰ উত্তৰ দিয়ালৈ বা সংযোগ বিচ্ছিন্ন হোৱালৈ অপেক্ষা কৰক।"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"কল কৰিব নোৱাৰি, কাৰণ ইতিমধ্যে দুটা কল চলি আছে। এটা নতুন কল কৰাৰ আগতে সেই দুটা কলৰ এটাৰ সংযোগ বিচ্ছিন্ন কৰক অথবা কল দুটা একত্ৰিত কৰি এটা কনফাৰেন্স কললৈ সলনি কৰক।"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"কল কৰিব নোৱাৰি কাৰণ ইতিমধ্যে দুটা কল চলি আছে। এটা নতুন কল কৰাৰ আগতে সেই দুটা কলৰ এটাৰ সংযোগ বিচ্ছিন্ন কৰক।"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"হ’ল্ডত ৰাখিব নোৱাৰা কল এটা চলি থকাৰ বাবে কল কৰিব নোৱাৰি। এটা নতুন কল কৰাৰ আগেয়ে কলটোৰ সংযোগ বিচ্ছিন্ন কৰক।"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"কল কৰিব নোৱাৰি, কাৰণ এটা অন্তৰ্গামী কল প্ৰগতিত আছে যাৰ উত্তৰ দিয়া হোৱা নাই। এটা নতুন কল কৰাৰ আগেয়ে অন্তৰ্গামী কলটোৰ উত্তৰ দিয়ক বা সেইটো প্ৰত্যাখ্যান কৰক।"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"একাধিক একাউণ্টৰ মাজত কল কৰাৰ বাবে এই MMI ক’ডটো উপলব্ধ নহয়।"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"জৰুৰীকালীন কলৰ সময়ত MMI ক’ড ডায়েল কৰিব নোৱাৰি।"</string>
 </resources>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index c9751591a..c679b0277 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audio digər cihaza ötürülür"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Zəngi sonlandırın"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Buraya keçin"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Artıq başqa zəng qoşulduğu üçün zəng etmək mümkün deyil. Başqa zəng etməzdən əvvəl zəngin cavablandırılmasını gözləyin və ya onu dayandırın."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Davam edən iki zəng olduğuna görə zəng etmək mümkün deyil. Yeni zəng etməzdən əvvəl zənglərin birini dayandırın və ya onları konfransa birləşdirin."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Davam edən iki zəng olduğuna görə zəng etmək mümkün deyil. Yeni zəng etməzdən əvvəl zənglərin birini dayandırın."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Canlı zəngi dayandırmaq mümkün olmadığına görə yeni zəng etmək olmur. Yeni zəng etməzdən əvvəl digər zəngi dayandırın."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Cavabsız gələn zəng olduğuna görə zəng etmək mümkün deyil. Yeni zəngə başlamazdan əvvəl gələn zəngə cavab verin və ya rədd edin."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Bu MMI kodu birdən çox hesab üzrə zənglər üçün əlçatan deyil."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Təcili zəng zamanı MMI kodlarını yığmaq olmur."</string>
 </resources>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index 3709c251c..dd7ac7329 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Zvuk se strimuje na drugi uređaj"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Prekini vezu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Prebaci ovde"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Ne možete da pozovete jer se već uspostavlja veza sa drugim pozivom. Sačekajte da neko odgovori na poziv ili ga prekinite pre upućivanja drugog poziva."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Ne možete da pozovete jer su dva poziva već u toku. Prekinite jedan od njih ili ih objedinite u konferenciju pre upućivanja novog poziva."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Ne možete da pozovete jer su dva poziva već u toku. Prekinite jedan od poziva pre upućivanja novog poziva."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Ne možete da uputite poziv jer je u toku poziv koji ne može da se stavi na čekanje. Prekinite taj poziv pre upućivanja novog poziva."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Ne možete da pozovete jer imate dolazni poziv na koji niste odgovorili. Primite ga ili odbijte pre upućivanja novog poziva."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ovaj MMI kôd nije dostupan za pozive na više naloga."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Biranje MMI kodova noje moguće tokom hitnog poziva."</string>
 </resources>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index c3c6e2f4f..118151450 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Перадача аўдыя плынню на іншую прыладу"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Завяршыць выклік"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Пераключыцца"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Немагчыма зрабіць выклік, бо падключаецца іншы выклік. Пачакайце адказу ці адключэння, перш чым зрабіць новы выклік."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Немагчыма зрабіць новы выклік, бо ўжо выконваюцца два іншыя. Каб зрабіць новы выклік, завяршыце адзін з бягучых ці аб’яднайце іх у канферэнц-выклік."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Немагчыма зрабіць новы выклік, бо ўжо выконваюцца два іншыя. Завяршыце адзін з выклікаў, перш чым зрабіць новы."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Немагчыма зрабіць выклік, бо ўжо выконваецца выклік, які нельга пераключыць у рэжым утрымання. Перш чым зрабіць новы выклік, завяршыце актыўны."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Нельга зрабіць выклік, паколькі ёсць уваходны выклік без адказу. Адкажыце на ўваходны выклік або адхіліце яго, каб зрабіць новы."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Гэты код MMI недаступны для выклікаў паміж некалькімі ўліковымі запісамі."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Коды MMI нельга набраць падчас экстраннага выкліку."</string>
 </resources>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index 116c88408..4f2ea3ffe 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Звукът се предава поточно към друго устройство"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Затваряне"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Превключете тук"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Не може да се извърши обаждане, тъй като вече се установява връзка в друго обаждане. Изчакайте да му бъде отговорено или го прекъснете, преди да започнете друго обаждане."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Не може да се извърши обаждане, тъй като вече се провеждат две обаждания. Прекъснете едно от тях или ги обединете в конферентен разговор, преди да започнете ново."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Не може да се извърши обаждане, тъй като вече се провеждат две обаждания. Прекъснете едно от тях, преди да започнете ново."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Не може да се извърши обаждане, тъй като има обаждане, което не може да бъде поставено на изчакване. Прекъснете обаждането, преди да извършите ново."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Не може да се извърши обаждане, тъй като има неотговорено входящо обаждане. Отговорете му или го отхвърлете, преди да извършите ново обаждане."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Този MMI код не е налице, докато се провежда обаждане в друг профил."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"По време на спешно обаждане не могат да се набират MMI кодове."</string>
 </resources>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 4f4fea6fc..a1fbd12bf 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"অন্য ডিভাইসে অডিও স্ট্রিম করা হচ্ছে"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"কল কেটে দিন"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"এখানে পাল্টান"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"অন্য একটি কল কানেক্ট করা হচ্ছে বলে কল করা যাচ্ছে না। আরেকটি কল করার আগে, কলটির উত্তর না দেওয়া পর্যন্ত অপেক্ষা করুন অথবা এটি ডিসকানেক্ট করুন।"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"দুটি কল চলছে, তাই আরেকটি কল করা যাচ্ছে না। নতুন কল করার আগে যেকোনও একটি কল ডিসকানেক্ট করুন অথবা দুটিকে একসাথে একটি কনফারেন্সে মার্জ করুন।"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"দুটি কল চলছে, তাই আরেকটি কল করা যাচ্ছে না। নতুন কল করার আগে যেকোনও একটি কল ডিসকানেক্ট করুন।"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"হোল্ড করা যাবে না এমন কল রয়েছে তাই আরেকটি কল করা যাচ্ছে না। নতুন কল করার আগে কলটি ডিসকানেক্ট করুন।"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"উত্তর দেওয়া হয়নি এমন একটি ইনকামিং কল রয়েছে, তাই কল করা যাচ্ছে না। নতুন কল করার আগে ইনকামিং কলটির উত্তর দিন বা সেটি বাতিল করুন।"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"একাধিক অ্যাকাউন্ট জুড়ে কলের জন্য এই MMI কোড উপলভ্য নেই।"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"জরুরি কলের সময় MMI কোড ডায়াল করা যাবে না।"</string>
 </resources>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index ba75d0cb5..c3f643d4c 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Prenos zvuka na drugom uređaju"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Prekini vezu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Prebaci ovdje"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nije moguće uputiti poziv jer se već uspostavlja drugi poziv. Pričekajte odgovor na poziv ili prekid veze prije upućivanja drugog poziva."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nije moguće uputiti poziv jer su već dva poziva u toku. Prekinite jedan od tih poziva ili ih spojite u konferencijski poziv prije upućivanja novog poziva."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nije moguće uputiti poziv jer su već dva poziva u toku. Prekinite jedan od tih poziva prije upućivanja novog."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nije moguće uputiti poziv zbog poziva koji se ne može staviti na čekanje. Prekinite taj poziv prije upućivanja novog poziva."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nije moguće uputiti poziv zbog neodgovorenog dolaznog poziva. Odgovorite ili odbijte dolazni poziv prije upućivanja novog poziva."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"MMI kôd nije dostupan za pozive na više računa."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI kodovi se ne mogu birati tokom hitnog poziva."</string>
 </resources>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 579344939..1bd052391 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"S\'està reproduint àudio en continu en un altre dispositiu"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Penja"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Canvia aquí"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"No es pot fer la trucada perquè ja se n\'està connectant una altra. Espera que la trucada es respongui o desconnecta-la abans de fer-ne una altra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"No es pot fer la trucada perquè ja n\'hi ha dues en curs. Desconnecta\'n una o combina-les en una conferència abans de fer-ne més de noves."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"No es pot fer la trucada perquè ja n\'hi ha dues en curs. Desconnecta\'n una abans de fer-ne més de noves."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"No es pot fer la trucada perquè n\'hi ha una que no es pot posar en espera. Desconnecta-la abans de fer-ne més de noves."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"No es pot fer la trucada perquè hi ha una trucada entrant sense resposta. Respon-hi o rebutja-la abans de fer més trucades."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Aquest codi MMI no es pot utilitzar per fer trucades amb diversos comptes."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"No es poden marcar codis MMI durant una trucada d\'emergència."</string>
 </resources>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 06193081a..27f38cc51 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streamování zvuku do druhého zařízení"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Zavěsit"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Přepnout sem"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Hovor nelze zahájit, protože právě dochází ke spojení jiného hovoru. Než zahájíte nový hovor vyčkejte, dokud druhá strana stávající hovor nepřijme nebo sami zavěste."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Hovor nelze zahájit, protože už probíhají jiné dva hovory. Než zahájíte nový hovor, jeden ze stávajících zavěste nebo je slučte do konference."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Hovor nelze zahájit, protože už probíhají jiné dva hovory. Než zahájíte nový hovor, jeden ze stávajících zavěste."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nemůžete uskutečnit hovor, protože už probíhá hovor, který nelze podržet. Než zahájíte nový hovor, odpojte ten předchozí."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nemůžete uskutečnit hovor, protože máte nepřijatý příchozí hovor. Nejdřív ho tedy přijměte nebo odmítněte."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Tento kód MMI není k dispozici pro hovory ve více účtech."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Při tísňovém volání nelze vytáčet kódy MMI."</string>
 </resources>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 0eb69ff43..7aa6bf5a9 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streamer lyd til en anden enhed"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Læg på"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Skift hertil"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Der kan ikke foretages et opkald, fordi der allerede er et andet opkald i gang. Vent, indtil opkaldet besvares, eller afslut det, før du foretager et nyt opkald."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Der kan ikke foretages et opkald, fordi der allerede er to igangværende opkald. Afslut et af opkaldene, eller flet dem til et telefonmøde, før du foretager et nyt opkald."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Der kan ikke foretages et opkald, fordi der allerede er to igangværende opkald. Afslut et af opkaldene, før du foretager et nyt."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Opkaldet kan ikke foretages, fordi der er et opkald i gang, som ikke kan sættes på hold. Afslut opkaldet, før du foretager et nyt."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Der kan ikke foretages et opkald, fordi et indgående opkald ringer. Besvar eller afvis det indgående opkald, før du foretager et nyt opkald."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Denne MMI-kode er ikke tilgængelig for opkald på tværs af flere konti."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-koder kan ikke ringe under et nødopkald."</string>
 </resources>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index 665124abc..6af8a8a6d 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audio auf einem anderen Gerät streamen"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Anruf beenden"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Auf dieses Gerät wechseln"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Anruf nicht möglich, weil bereits ein anderer Anruf verbunden wird. Warte, bis der Anruf angenommen wird, oder lege auf, bevor du einen neuen Anruf startest."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Anruf nicht möglich, weil bereits zwei Anrufe aktiv sind. Beende einen der Anrufe oder führe beide Anrufe in einer Telefonkonferenz zusammen, bevor du einen neuen Anruf startest."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Anruf nicht möglich, weil bereits zwei Anrufe aktiv sind. Beende einen der Anrufe, bevor du einen neuen startest."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Anruf nicht möglich, da ein Anruf nicht gehalten werden kann. Beende den Anruf, bevor du einen neuen Anruf startest."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Anruf nicht möglich, da ein nicht angenommener eingehender Anruf vorhanden ist. Nimm den eingehenden Anruf an oder lehne ihn ab, bevor du einen neuen Anruf startest."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Dieser MMI-Code ist nicht für Anrufe mit mehreren Konten verfügbar."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-Codes können während eines Notrufs nicht gewählt werden."</string>
 </resources>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index ba504d7d3..c21c8a6a5 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Ροή ήχου σε άλλη συσκευή"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Απόρριψη"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Εναλλαγή εδώ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Δεν είναι δυνατή η πραγματοποίηση κλήσης, επειδή γίνεται ήδη η σύνδεση άλλης κλήσης. Περιμένετε να απαντηθεί η κλήση ή τερματίστε τη σύνδεση πριν πραγματοποιήσετε άλλη κλήση."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Δεν είναι δυνατή η πραγματοποίηση κλήσης, επειδή υπάρχουν ήδη δύο κλήσεις σε εξέλιξη. Τερματίστε μία από τις κλήσεις ή συγχωνεύστε τις σε μια διάσκεψη, προτού πραγματοποιήσετε νέα κλήση."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Δεν είναι δυνατή η πραγματοποίηση κλήσης, επειδή υπάρχουν ήδη δύο κλήσεις σε εξέλιξη. Αποσυνδέστε μία από τις κλήσεις πριν πραγματοποιήσετε νέα κλήση."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Δεν είναι δυνατή η πραγματοποίηση κλήσης, επειδή υπάρχει κλήση που δεν μπορεί να τεθεί σε αναμονή. Τερματίστε την κλήση πριν πραγματοποιήσετε νέα κλήση."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Δεν είναι δυνατή η πραγματοποίηση κλήσης, επειδή υπάρχει αναπάντητη εισερχόμενη κλήση. Απαντήστε ή απορρίψτε την εισερχόμενη κλήση, προτού πραγματοποιήσετε μια νέα κλήση."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Αυτός ο κωδικός MMI δεν είναι διαθέσιμος για κλήσεις σε πολλούς λογαριασμούς."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Δεν είναι δυνατή η κλήση κωδικών MMI κατά τη διάρκεια μιας κλήσης έκτακτης ανάγκης."</string>
 </resources>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 1ce62df44..ad1c0e3ba 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio to other device"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Hang up"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Switch here"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Cannot place a call as there is already another call connecting. Wait for the call to be answered or disconnect it before placing another call."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls or merge them into a conference prior to placing a new call."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls prior to placing a new call."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Cannot place a call as there is an unholdable call. Disconnect the call prior to placing a new call."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Cannot place a call as there is an unanswered incoming call. Answer or reject the incoming call prior to placing a new call."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"This MMI code is not available for calls across multiple accounts."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI codes cannot be dialled during an emergency call."</string>
 </resources>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index 8ae9c0a99..ceb8258d4 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio to other device"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Hang up"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Switch here"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Cannot place a call as there is already another call connecting. Wait for the call to be answered or disconnect it before placing another call."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls or merge them into a conference prior to placing a new call."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls prior to placing a new call."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Cannot place a call as there is an unholdable call. Disconnect the call prior to placing a new call."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Cannot place a call as there is an unanswered incoming call. Answer or reject the incoming call prior to placing a new call."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"This MMI code is not available for calls across multiple accounts."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI codes cannot be dialed during an emergency call."</string>
 </resources>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 1ce62df44..ad1c0e3ba 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio to other device"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Hang up"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Switch here"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Cannot place a call as there is already another call connecting. Wait for the call to be answered or disconnect it before placing another call."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls or merge them into a conference prior to placing a new call."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls prior to placing a new call."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Cannot place a call as there is an unholdable call. Disconnect the call prior to placing a new call."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Cannot place a call as there is an unanswered incoming call. Answer or reject the incoming call prior to placing a new call."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"This MMI code is not available for calls across multiple accounts."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI codes cannot be dialled during an emergency call."</string>
 </resources>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 1ce62df44..ad1c0e3ba 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio to other device"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Hang up"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Switch here"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Cannot place a call as there is already another call connecting. Wait for the call to be answered or disconnect it before placing another call."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls or merge them into a conference prior to placing a new call."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Cannot place a call as there are already two calls in progress. Disconnect one of the calls prior to placing a new call."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Cannot place a call as there is an unholdable call. Disconnect the call prior to placing a new call."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Cannot place a call as there is an unanswered incoming call. Answer or reject the incoming call prior to placing a new call."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"This MMI code is not available for calls across multiple accounts."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI codes cannot be dialled during an emergency call."</string>
 </resources>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index 668a696a7..66db65b68 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Transmitiendo el audio a otro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Colgar"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Cambiar aquí"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"No puedes realizar la llamada porque hay otra en curso. Espera a que se responda la llamada en curso o finalízala antes de realizar otra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"No puedes realizar la llamada porque hay otras dos en curso. Finaliza una de ellas o combínalas en una conferencia antes de iniciar una nueva."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"No puedes realizar la llamada porque hay otras dos en curso. Finaliza una de ellas antes de realizar una nueva."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"No puedes realizar la llamada porque hay otra que no se puede mantener en espera. Finalízala antes de iniciar una nueva."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"No puedes realizar la llamada porque hay una llamada entrante que aún no contestas. Contéstala o recházala antes de realizar una nueva."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Este código MMI no está disponible para llamadas en varias cuentas."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"No se pueden marcar códigos MMI durante las llamadas de emergencia."</string>
 </resources>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 96163b32f..193491366 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Transmitiendo audio a otro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Colgar"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Cambiar aquí"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"No se puede hacer una llamada porque ya hay otra conectándose. Espera a que se responda a la llamada o cuelga antes de hacer otra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"No se puede llamar porque ya hay dos llamadas en curso. Interrumpe una de ellas o combínalas en una conferencia antes de hacer otra llamada."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"No se puede llamar porque ya hay dos llamadas en curso. Interrumpe una de las llamadas antes de hacer otra."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"No se puede hacer una llamada porque ya hay otra que no se puede poner en espera. Interrumpe la llamada antes de hacer otra."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"No se puede llamar porque hay una llamada entrante sin responder. Contéstala o recházala antes de hacer otra llamada."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Este código MMI no está disponible para hacer llamadas con varias cuentas."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"No se pueden marcar códigos MMI durante las llamadas de emergencia."</string>
 </resources>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index 6fd55929b..ba5be48c8 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Heli voogesitamine teise seadmesse"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Lõpeta kõne"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Vaheta siia"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Kõnet ei saa teha, kuna teist kõnet juba ühendatakse. Oodake, kuni kõnele vastatakse või katkestage kõne enne uue tegemist."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Kõnet ei saa teha, kuna kaks kõnet on juba pooleli. Enne uue kõne tegemist katkestage üks kõnedest või liitke need konverentskõneks."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Kõnet ei saa teha, kuna kaks kõnet on juba pooleli. Enne uue kõne tegemist katkestage üks kõnedest."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Uut kõnet ei saa teha, kuna pooleliolevat kõnet ei saa ootele panna. Enne uue kõne tegemist katkestage pooleliolev kõne."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Kõnet ei saa teha, kuna teil on vastamata sissetulev kõne. Enne uue kõne tegemist vastake sissetulevale kõnele või keelduge sellest."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"See MMI-kood pole saadaval mitmel kontol toimuvate kõnede jaoks."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-koode ei saa hädaabikõne ajal valida."</string>
 </resources>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index 3efbc0720..6f362e86c 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audioa beste gailu batera igortzen ari da"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Amaitu deia"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Aldatu hona"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Ezin da egin deia, beste dei bat konektatzen ari delako. Itxaron deiari erantzun arte edo deskonekta ezazu beste bat egin aurretik."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Ezin da egin deia, dagoeneko 2 dei daudelako abian. Beste dei bat egin aurretik, eten deietako bat edo bateratu deiak konferentzia-dei bakarrean."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Ezin da egin deia, dagoeneko 2 dei daudelako abian. Beste dei bat egin aurretik, eten deietako bat."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Ezin da egin deia, zain utzi ezin den dei bat abian delako. Deskonektatu dei hori beste dei bat egin ahal izateko."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Ezin da egin deia, oraindik erantzun ez diozun dei bat jasotzen ari zarelako. Beste dei bat egin aurretik, erantzun deiari edo bazter ezazu."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"MMI kode hau ezin da erabili kontu baten baino gehiagoren bidez deiak egiteko."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI kodeak ezin dira markatu larrialdi-deietan."</string>
 </resources>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 6bd2ff67e..3bb8889f9 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"درحال جاری‌سازی صدا به دستگاه دیگر"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"قطع تماس"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"انتقال در اینجا انجام شود"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"نمی‌توانید تماسی برقرار کنید چون تماس دیگری ازقبل درحال متصل شدن است. قبل‌از برقراری تماس دیگری، صبر کنید تا تماس پاسخ داده شود یا اتصال آن را قطع کنید."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"نمی‌توانید تماسی برقرار کنید، زیرا هم‌اکنون دو تماس دیگر درحال انجام است. قبل‌از برقراری تماس جدید، یکی از تماس‌ها را قطع کنید یا آن‌ها را به‌صورت کنفرانسی ادغام کنید."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"نمی‌توانید تماسی برقرار کنید چون دو تماس دیگر ازقبل درحال انجام است. قبل‌از برقراری تماس جدید، یکی از تماس‌ها را قطع کنید."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"نمی‌توانید تماسی برقرار کنید زیرا هم‌اکنون تماسی بدون قابلیت انتظار درحال انجام است. قبل‌از برقراری تماس جدید، تماس را قطع کنید."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"نمی‌توانید تماسی برقرار کنید، چون تماس ورودی بی‌پاسخی درحال انجام است. قبل‌از برقراری تماس جدید، به تماس ورودی پاسخ دهید یا آن را رد کنید."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"‏این کد MMI برای تماس در چندین حساب دردسترس نیست."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"‏امکان شماره‌گیری کدهای MMI حین تماس اضطراری وجود ندارد"</string>
 </resources>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 0d5fdbbb7..9681dceb6 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audiota striimataan toiselle laitteelle"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Lopeta puhelu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Vaihda puhelimeen"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Puhelua ei voi soittaa, koska toista puhelua soitetaan. Odota, että puheluun vastataan, tai katkaise puhelu ennen uuden soittamista."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Puhelua ei voi soittaa, koska kaksi puhelua on jo käynnissä. Katkaise toinen puheluista tai yhdistä ne puhelinneuvotteluksi ennen uuden puhelun soittamista."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Puhelua ei voi soittaa, koska kaksi puhelua on jo käynnissä. Katkaise toinen puheluista ennen uuden puhelun soittamista."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Puhelua ei voi soittaa, koska puhelua ei voi asettaa pitoon. Katkaise puhelu ennen uuden puhelun soittamista."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Puhelua ei voi soittaa, koska saapuvaan puheluun ei ole vielä vastattu. Vastaa saapuvaan puheluun tai hylkää se, ennen kuin soitat uuden puhelun."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"MMI-koodi ei ole käytettävissä useilla tileillä käytävissä puheluissa."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-koodeja ei voi käyttää hätäpuhelun aikana."</string>
 </resources>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index cfd153b94..ac82985dc 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Diffusion audio en continu vers un autre appareil en cours…"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Raccrocher"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Revenir à cet appareil"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Impossible de passer un appel parce qu\'un autre appel est déjà en cours de connexion. Attendez que quelqu\'un réponde à l\'appel ou déconnectez-le avant de passer un autre appel."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Impossible de passer un appel parce que deux appels sont déjà en cours. Déconnectez-en un ou fusionnez-les en conférence téléphonique avant de passer un nouvel appel."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Impossible de passer un appel parce que deux appels sont déjà en cours. Déconnectez-en un avant de passer un nouvel appel."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Impossible de passer un appel parce qu\'un appel impossible à mettre en attente est en cours. Débranchez l\'appel avant de passer un nouvel appel."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Impossible de passer un appel parce qu\'un appel entrant attend une réponse. Répondez à cet appel ou refusez-le avant de passer un nouvel appel."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ce code IHM n\'est pas disponible pour les appels utilisant plusieurs comptes."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Impossible de composer un code IHM pendant un appel d\'urgence."</string>
 </resources>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index 9dbca8f5a..2db30ae75 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming de l\'audio sur un autre appareil"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Raccrocher"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Passer ici"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Impossible de passer un appel, car un autre appel est en cours de connexion. Attendez que l\'appel aboutisse ou mettez-y fin avant de passer un autre appel."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Impossible de passer un appel, car deux appels sont déjà en cours. Mettez fin à l\'un des appels ou fusionnez-les afin de créer une conférence avant de passer un nouvel appel."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Impossible de passer un appel, car deux appels sont déjà en cours. Mettez fin à l\'un des appels avant de passer un nouvel appel."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Impossible de passer un appel, car un appel est en cours et ne peut pas être mis en attente. Mettez fin à l\'appel avant de passer un nouvel appel."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Impossible de passer un appel lorsqu\'un appel entrant attend une réponse. Répondez à cet appel ou refusez-le avant de passer un nouvel appel."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ce code IHM n\'est pas disponible pour les appels sur plusieurs comptes."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Impossible de composer des codes IHM pendant un appel d\'urgence."</string>
 </resources>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index f8eb32cbb..cf144a868 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Emitindo audio noutro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Colgar"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Volver aquí"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Non se pode facer ningunha chamada porque hai outra que se está conectando. Agarda a que se conteste a chamada ou desconéctaa antes de facer outra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Non se pode facer ningunha chamada porque xa hai dúas en curso. Para poder facer unha nova, desconecta unha desas dúas ou combínaas nunha conferencia."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Non se pode facer ningunha chamada porque xa hai dúas en curso. Desconecta unha delas antes de facer outra."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Non se pode facer ningunha chamada porque hai unha que non é posible poñer en espera. Desconéctaa para poder facer unha nova."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Non podes chamar porque te están chamando nestes momentos. Para poder facer unha chamada, primeiro tes que responder á outra ou rexeitala."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Este código MMI non está dispoñible para chamadas en varias contas."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Non se poden marcar códigos MMI durante as chamadas de emerxencia."</string>
 </resources>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index dd04bcf84..3503a6a6c 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ઑડિયોને અન્ય ડિવાઇસ પર સ્ટ્રીમ કરી રહ્યાં છીએ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"સમાપ્ત કરો"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"અહીં સ્વિચ કરો"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"પહેલેથી બીજો કોઈ કૉલ કનેક્ટ થઈ રહ્યો હોવાથી કૉલ કરી શકાતો નથી. કૉલનો જવાબ મળે ત્યાં સુધી રાહ જુઓ અથવા બીજો કૉલ કરતા પહેલાં તેને ડિસ્કનેક્ટ કરો."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"કૉલ કરી શકાતો નથી, કારણ કે બે કૉલ પહેલેથી ચાલુ છે. કોઈ નવો કૉલ કરતા પહેલાં તેમાંના એક કૉલને ડિસ્કનેક્ટ કરો અથવા તેમને કોઈ કૉન્ફરન્સમાં મર્જ કરો."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"કૉલ કરી શકાતો નથી, કારણ કે બે કૉલ પહેલેથી ચાલુ છે. કોઈ નવો કૉલ કરતા પહેલાં તેમાંના એક કૉલને ડિસ્કનેક્ટ કરો."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"કૉલ કરી શકાતો નથી, કારણ કે હોલ્ડ ન કરી શકાય તેવો કોઈ કૉલ ચાલુ છે. કોઈ નવો કૉલ કરતા પહેલાં કૉલને ડિસ્કનેક્ટ કરો."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"કૉલ કરી શકાતો નથી કારણ કે ઇનકમિંગ કૉલનો જવાબ આપવામાં આવી રહ્યો નથી. નવો કૉલ કરતા પહેલાં ઇનકમિંગ કૉલનો જવાબ આપો અથવા તેને નકારો."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"આ MMI કોડનો ઉપયોગ એકથી વધુ એકાઉન્ટ પર ચાલી રહેલા કૉલ માટે ઉપલબ્ધ નથી."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ઇમર્જન્સી કૉલ દરમિયાન MMI કોડ ડાયલ કરી શકાતા નથી."</string>
 </resources>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index 683a5ab8e..338519f0b 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ऑडियो को दूसरे डिवाइस पर स्ट्रीम किया जा रहा है"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"कॉल खत्म करें"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"यहां स्विच करें"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"कॉल नहीं किया जा सकता, क्योंकि पहले से ही एक अन्य कॉल कनेक्ट किया जा रहा है. कॉल का जवाब मिलने का इंतज़ार करें या नया कॉल करने से पहले, मौजूदा कॉल को डिसकनेक्ट करें."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"कॉल नहीं किया जा सकता, क्योंकि पहले से ही दो कॉल जारी हैं. नया कॉल करने से पहले, उनमें से किसी एक कॉल को डिसकनेक्ट करें या उन्हें कॉन्फ़्रेंस कॉल में मर्ज करें."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"कॉल नहीं किया जा सकता, क्योंकि पहले से ही दो कॉल जारी हैं. नया कॉल करने से पहले, उनमें से किसी एक कॉल को डिसकनेक्ट करें."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"कॉल नहीं किया जा सकता, क्योंकि पहले से चल रहे कॉल को होल्ड नहीं किया जा सकता. नया कॉल करने से पहले, मौजूदा कॉल को डिसकनेक्ट करें."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"कॉल नहीं किया जा सकता, क्योंकि एक इनकमिंग कॉल का जवाब नहीं दिया जा रहा है. नया कॉल करने से पहले इनकमिंग कॉल का जवाब दें या उसे अस्वीकार करें."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"किसी दूसरे खाते पर चल रहे कॉल के दौरान, इस एमएमआई कोड का इस्तेमाल नहीं किया जा सकता."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"आपातकालीन कॉल के दौरान, MMI कोड डायल नहीं किए जा सकते."</string>
 </resources>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index b664e5c29..383dc4662 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming zvuka na drugi uređaj"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Prekini vezu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Promijeni ovdje"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Poziv se ne može uputiti jer se već uspostavlja drugi poziv. Pričekajte odgovor na poziv ili prekidanje veze prije upućivanja novog poziva."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Poziv se ne može uputiti jer već su dva poziva u tijeku. Prije upućivanja novog poziva prekinite jedan od ta dva poziva ili ih spojite u konferencijski poziv."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Poziv se ne može uputiti jer već su dva poziva u tijeku. Prekinite jedan od tih poziva prije upućivanja novog."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Poziv se ne može uputiti jer je u tijeku poziv koji se ne može zadržati. Prekinite taj poziv prije upućivanja novog."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Poziv se ne može uputiti jer je aktivan neodgovoreni dolazni poziv. Odgovorite ili odbijte dolazni poziv prije upućivanja novog poziva."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Taj MMI kôd nije dostupan za pozive na više računa."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI kodovi ne mogu se birati tijekom hitnog poziva."</string>
 </resources>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 0a0c37787..828ae2bcc 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Hang átvitele másik eszközre"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Hívás befejezése"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Váltás itt"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nem kezdeményezhet hívást, mert már folyamatban van egy másik hívás. Várja meg, amíg a hívást felveszik, vagy szakítsa meg a hívást, mielőtt új hívást indítana."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nem kezdeményezhet hívást, mert már két hívás van folyamatban. Mielőtt új hívást indítana, tegye le az egyiket, vagy egyesítse őket egy konferenciahívásban."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nem kezdeményezhet hívást, mert már két hívás van folyamatban. Mielőtt új hívást indítana, szakítsa meg az egyik hívást."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nem kezdeményezhet hívást, mert folyamatban van egy nem tartható hívás. Mielőtt új hívást indítana, szakítsa meg a hívást."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nem kezdeményezhet hívást, mert folyamatban van egy megválaszolatlan bejövő hívás. Mielőtt új hívást indítana, vegye fel vagy utasítsa el a bejövő hívást."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ez az MMI-kód nem áll rendelkezésre hívásokhoz több fiók használata esetén."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Segélyhívás közben nem lehet MMI-kódot tárcsázni."</string>
 </resources>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 7f877c590..b336905ee 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Աուդիոյի հեռարձակում այլ սարքում"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Ավարտել զանգը"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Անցնել այստեղ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Հնարավոր չէ զանգել, քանի որ մեկ այլ զանգ է կատարվում։ Սպասեք, մինչև բաժանորդը պատասխանի, կամ ավարտեք զանգը նախքան նորը կատարելը։"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Հնարավոր չէ զանգել, քանի որ արդեն երկու ընթացիկ զանգ կա։ Նախքան նոր զանգ կատարելը ավարտեք զանգերից մեկը կամ միավորեք դրանք մեկ խմբային զանգում։"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Հնարավոր չէ զանգել, քանի որ արդեն երկու ընթացիկ զանգ կա։ Նախքան նոր զանգ կատարելը ավարտեք զանգերից մեկը։"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Հնարավոր չէ զանգել, քանի որ ընթացիկ զանգը չի կարելի սպասման մեջ դնել։ Նախքան նոր զանգ կատարելը պատասխանեք ավարտեք այս զանգը։"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Հնարավոր չէ զանգել, քանի որ անպատասխան մուտքային զանգ կա։ Նախքան նոր զանգ կատարելը պատասխանեք մուտքային զանգին կամ մերժեք այն։"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Այս MMI կոդը հասանելի չէ մի քանի հաշիվների օգտագործմամբ զանգերի համար։"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Շտապ կանչի ընթացքում MMI կոդերի հավաքումը հնարավոր չէ։"</string>
 </resources>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 34c0c6693..331d2bec5 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio ke perangkat lain"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Akhiri"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Beralih ke sini"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Tidak dapat melakukan panggilan karena ada panggilan lain yang sedang terhubung. Tunggu hingga panggilan dijawab atau putuskan panggilan sebelum melakukan panggilan lain."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Tidak dapat melakukan panggilan karena ada dua panggilan yang sedang berlangsung. Putuskan salah satu panggilan atau gabungkan keduanya menjadi satu konferensi sebelum melakukan panggilan baru."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Tidak dapat melakukan panggilan karena ada dua panggilan yang sedang berlangsung. Putuskan salah satu panggilan sebelum melakukan panggilan baru."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Tidak dapat melakukan panggilan karena ada panggilan yang tidak dapat ditahan. Putuskan panggilan sebelum melakukan panggilan baru."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Tidak dapat melakukan panggilan karena ada panggilan masuk yang belum terjawab. Jawab atau tolak panggilan masuk sebelum melakukan panggilan baru."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Kode MMI ini tidak tersedia untuk panggilan di beberapa akun."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Kode MMI tidak dapat di-dial selama panggilan darurat."</string>
 </resources>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index c2fcf8f22..c389052f4 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streymir hljóði í annað tæki"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Leggja á"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Skipta hingað"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Ekki er hægt að hringja símtal þar sem annað símtal er þegar að tengjast. Bíddu eftir að símtalinu sé svarað eða slíttu því áður en þú hringir annað símtal."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Ekki er hægt að hringja símtal vegna þess að þegar eru tvö símtöl í gangi. Slíttu öðru símtalinu eða sameinaðu þau í símafund áður en þú hringir nýtt símtal."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Ekki er hægt að hringja símtal þar sem það eru þegar tvö símtöl í gangi. Slíttu öðru símtalinu áður en þú hringir nýtt símtal."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Ekki er hægt að hringja símtal vegna símtals sem ekki er hægt að setja í bið. Slíttu símtalinu áður en þú hringir nýtt símtal."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Ekki er hægt að hringja símtal, þar sem ósvarað símtal er að berast. Svaraðu eða hafnaðu símtalinu áður en þú hringir nýtt símtal."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Þessi MMI-kóði er ekki í boði ef hringt er í marga reikninga."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Ekki er hægt að hringja MMI-kóða í neyðarsímtali."</string>
 </resources>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 42cb0c8d3..85715742c 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio all\'altro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Riaggancia"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Passa qui"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Impossibile effettuare una chiamata perché è già in corso un\'altra chiamata. Attendi che qualcuno risponda alla chiamata o disconnetti prima di effettuarne un\'altra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Impossibile effettuare una chiamata perché due chiamate sono già in corso. Unisci le chiamate in una conferenza o scollegane una prima di effettuare una nuova chiamata."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Impossibile effettuare una chiamata perché due chiamate sono già in corso. Termina una delle chiamate prima di effettuarne una nuova."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Impossibile effettuare una chiamata perché è presente una chiamata non bloccabile. Termina la chiamata prima di effettuarne una nuova."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Impossibile effettuare una chiamata perché è presente una chiamata in arrivo senza risposta. Rispondi o rifiuta la chiamata in arrivo prima di effettuare una nuova chiamata."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Questo codice MMI non è disponibile per le chiamate su più account."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Impossibile comporre codici MMI durante una chiamata di emergenza."</string>
 </resources>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 98c53470b..b31b68d2f 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"הקול מושמע במכשיר אחר"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ניתוק"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"העברת השיחה בחזרה לטלפון"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"אי אפשר להתקשר לשני מספרים בו-זמנית. כדי להתחיל שיחה חדשה, צריך לחכות למענה בשיחה הראשונה או לנתק."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"אי אפשר להתקשר כי כבר יש שתי שיחות פעילות. כדי להתחיל שיחה חדשה, צריך לנתק את אחת מהשיחות או למזג אותן וליצור שיחת ועידה."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"אי אפשר להתקשר כי כבר יש שתי שיחות פעילות. כדי להתחיל שיחה חדשה, צריך לנתק את אחת מהשיחות."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"אי אפשר להתקשר כי כבר יש שיחה פעילה ואי אפשר להעביר אותה להמתנה. צריך לנתק את השיחה ורק אז לנסות להתקשר למספר אחר."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"אי אפשר להתקשר כי יש שיחה נכנסת אחרת. צריך לענות לשיחה או לדחות אותה ורק אז לנסות להתקשר למספר אחר."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"‏אי אפשר להשתמש בקוד ה-MMI הזה לשיחות במספר חשבונות."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"‏אי אפשר להתקשר לקודי MMI בזמן שיחת חירום."</string>
 </resources>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 2df673616..c03db2b80 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"他のデバイスに音声をストリーミングしています"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"通話を終了"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"このデバイスに切り替える"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"接続中の通話がすでにあるため、新しく通話を発信することはできません。既存の通話が応答されるのを待つか、その通話を終了してから新しい通話を発信してください。"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"進行中の通話がすでに 2 件あるため、新しく通話を発信することはできません。進行中の通話のどちらかを終了するか、2 件の通話を統合してグループ通話にすると、新しく通話を発信できるようになります。"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"進行中の通話がすでに 2 件あるため、新しく通話を発信することはできません。進行中の通話のどちらかを終了すると、新しく通話を発信できるようになります。"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"保留できない通話があるため、新しく通話を発信できません。通話を終了すると、新しく通話を発信できるようになります。"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"通話を着信中のため、新しく通話を発信することはできません。着信中の通話に応答するか、通話を拒否すると、新しく通話を発信できるようになります。"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"この MMI コードは、複数のアカウントにまたがる通話には使用できません。"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"緊急通報中は MMI コードをダイヤルできません。"</string>
 </resources>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index f2a3e90bb..ad841f3de 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"მიმდინარეობს აუდიოს სტრიმინგი სხვა მოწყობილობაზე"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"გათიშვა"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"გადართვა"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ზარის განხორციელება შეუძლებელია, რადგან უკვე მიმდინარეობს სხვა ზარის დაკავშირება. დაელოდეთ, რომ ზარს უპასუხონ ან გათიშეთ, სანამ სხვა ზარს განახორციელებთ."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ზარის განხორციელება შეუძლებელია, რადგან უკვე ორი ზარი მიმდინარეობს. ახალი ზარის განსახორციელებლად გათიშეთ ერთ-ერთი ზარი ან გააერთიანეთ ისინი კონფერენციად."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ზარის განხორციელება შეუძლებელია, რადგან უკვე ორი ზარი მიმდინარეობს. ახალი ზარის განსახორციელებლად გათიშეთ ერთ-ერთი ზარი."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ზარის განხორციელება ვერ ხერხდება, რადგან მიმდინარეობს ზარი, რომლის მოცდის რეჟიმში გადაყვანაც შეუძლებელია. ახალი ზარის განსახორციელებლად გათიშეთ აღნიშნული ზარი."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ზარის განხორციელება შეუძლებელია, რადგან გაქვთ უპასუხო შემომავალი ზარი. უპასუხეთ ან უარყავით შემომავალი ზარი ახალი ზარის განხორციელებამდე."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ეს MMI კოდი ხელმისაწვდომი არ არის სხვადასხვა ანგარიშზე ზარების განხორცილებისას."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI კოდების აკრეფა შეუძლებელია გადაუდებელი ზარის განხორციელებისას."</string>
 </resources>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 22ac1fc82..af0026631 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Аудионы басқа құрылғыға трансляциялау"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Қоңырауды аяқтау"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Осы жерде ауысу"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Қоңырау шалу мүмкін емес, себебі басқа қоңырау жүріп жатыр. Жаңа қоңырау шалмас бұрын, ағымдағы қоңырауға жауапты күтіңіз немесе оны тоқтатыңыз."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Қоңырау шалу мүмкін емес, себебі онсыз да екі қоңырау жүріп жатыр. Жаңа қоңырау шалмас бұрын, қоңыраулардың бірін тоқтатыңыз немесе оларды бір конференцияға біріктіріңіз."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Қоңырау шалу мүмкін емес, себебі онсыз да екі қоңырау жүріп жатыр. Жаңа қоңырау шалмас бұрын, қоңыраулардың бірін тоқтатыңыз."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Қоңырау шалу мүмкін емес, себебі жүріп жатқан қоңырау кідіртілмейді. Жаңадан қоңырау шалу үшін жүріп жатқан қоңырауды тоқтатыңыз."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Қоңырау шалу мүмкін емес, себебі жауап бермеген кіріс қоңырау бар. Жаңа қоңырау шалу үшін кіріс қоңырауға жауап беріңіз немесе оны қабылдамаңыз."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Бұл MMI кодын бірнеше аккаунттағы қоңыраулар үшін пайдалану мүмкін емес."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Құтқару қызметіне қоңырау шалу кезінде MMI кодтары терілмейді."</string>
 </resources>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 41b02f307..578fff152 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"កំពុង​ផ្សាយ​សំឡេង​ទៅឧបករណ៍​ផ្សេងទៀត"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"បញ្ចប់​ការហៅ​ទូរសព្ទ"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ប្ដូរនៅទីនេះ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"មិនអាច​ធ្វើ​ការហៅ​ទូរសព្ទ​បានទេ ដោយសារ​កំពុងភ្ជាប់​ការហៅ​ទូរសព្ទ​ផ្សេងទៀត​ស្រាប់ហើយ។ សូម​រង់ចាំ​ឱ្យគេ​ទទួល​ទូរសព្ទនោះ ឬ​ផ្ដាច់វាសិន មុនពេល​ធ្វើការហៅ​ទូរសព្ទ​ផ្សេងទៀត។"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"មិន​អាច​ធ្វើ​ការហៅ​ទូរសព្ទ​បាន​ទេ ដោយសារ​មាន​ការហៅ​ទូរសព្ទ​ពីរ​កំពុង​ដំណើរការ​រួច​ហើយ។ ផ្ដាច់​ការហៅ​ទូរសព្ទ​មួយ ឬ​ដាក់​ការហៅ​ទូរសព្ទ​ទាំងនេះ​ចូល​គ្នា​ជា​ការហៅជាក្រុម មុន​នឹង​ធ្វើ​ការហៅ​ទូរសព្ទ​ថ្មី។"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"មិនអាច​ធ្វើ​ការហៅ​ទូរសព្ទ​បានទេ ដោយសារ​មាន​ការហៅ​ទូរសព្ទ​ពីរ​កំពុង​ដំណើរការ​ស្រាប់​ហើយ។ សូមផ្ដាច់​ការហៅ​ទូរសព្ទ​មួយសិន មុនពេល​ធ្វើការហៅ​ទូរសព្ទថ្មី។"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"មិនអាច​ធ្វើការហៅ​ទូរសព្ទ​បានទេ ដោយសារ​មានការហៅ​ទូរសព្ទ​ដែលមិនអាច​ដាក់ឱ្យ​រង់ចាំបាន។ សូមផ្ដាច់​ការហៅ​ទូរសព្ទ​នោះសិន មុនពេល​ធ្វើការហៅ​ទូរសព្ទថ្មី។"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"មិន​អាច​ធ្វើ​ការហៅ​ទូរសព្ទ​បាន​ទេ ដោយសារ​មាន​ការហៅ​ចូល​មួយ​ដែល​មិន​បាន​ឆ្លើយតប។ ឆ្លើយតប ឬ​ច្រានចោល​ការហៅ​ចូល មុន​ពេល​ធ្វើ​ការហៅ​ទូរសព្ទ​ថ្មី។"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"មិនអាចប្រើលេខកូដ MMI នេះសម្រាប់ការហៅទូរសព្ទនៅលើ​គណនី​ច្រើនបានទេ។"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"មិនអាច​ចុចលេខ​កូដ MMI ក្នុង​អំឡុងពេល​ហៅ​ទៅលេខ​សង្គ្រោះ​បន្ទាន់​បានទេ។"</string>
 </resources>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index da7fef862..40319b3cc 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ಇತರ ಸಾಧನಕ್ಕೆ ಆಡಿಯೊವನ್ನು ಸ್ಟ್ರೀಮ್ ಮಾಡಲಾಗುತ್ತಿದೆ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ಹ್ಯಾಂಗ್ ಅಪ್"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ಇಲ್ಲಿಗೆ ಬದಲಾಯಿಸಿ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ಈಗಾಗಲೇ ಇನ್ನೊಂದು ಕರೆ ಕನೆಕ್ಟ್ ಆಗುತ್ತಿರುವ ಕಾರಣ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ಕರೆಗೆ ಉತ್ತರಿಸುವವರೆಗೆ ಕಾಯಿರಿ ಅಥವಾ ಇನ್ನೊಂದು ಕರೆ ಮಾಡುವ ಮುನ್ನ ಅದನ್ನು ಡಿಸ್‌ಕನೆಕ್ಟ್ ಮಾಡಿ."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ಈಗಾಗಲೇ ಎರಡು ಕರೆಗಳು ಪ್ರಗತಿಯಲ್ಲಿರುವ ಕಾರಣ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ಒಂದು ಕರೆಯನ್ನು ಡಿಸ್‌ಕನೆಕ್ಟ್ ಮಾಡಿ ಅಥವಾ ಹೊಸ ಕರೆಯನ್ನು ಮಾಡುವ ಮೊದಲು ಎರಡು ಕರೆಗಳನ್ನು ಒಂದೇ ಕಾನ್ಫರೆನ್ಸ್‌ನಲ್ಲಿ ವಿಲೀನಗೊಳಿಸಿ."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ಈಗಾಗಲೇ ಎರಡು ಕರೆಗಳು ಪ್ರಗತಿಯಲ್ಲಿರುವ ಕಾರಣ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ಹೊಸ ಕರೆಯನ್ನು ಮಾಡುವ ಮೊದಲು ಒಂದು ಕರೆಯನ್ನು ಡಿಸ್‌ಕನೆಕ್ಟ್ ಮಾಡಿ."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ಈಗಾಗಲೇ ಪ್ರಗತಿಯಲ್ಲಿರುವ ಕರೆಯನ್ನು ಹೋಲ್ಡ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲದ ಕಾರಣ, ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ಹೊಸ ಕರೆಯನ್ನು ಮಾಡುವ ಮೊದಲು ಕರೆಯನ್ನು ಡಿಸ್‌ಕನೆಕ್ಟ್ ಮಾಡಿ."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ಉತ್ತರಿಸದ ಒಳಬರುವ ಕರೆ ಬರುತ್ತಿರುವುದರಿಂದ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಾಗುವುದಿಲ್ಲ. ಹೊಸ ಕರೆಯನ್ನು ಮಾಡುವ ಮೊದಲು ಕರೆಗೆ ಉತ್ತರ ನೀಡಿ ಅಥವಾ ತಿರಸ್ಕರಿಸಿ."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ಬಹು ಖಾತೆಗಳಾದ್ಯಂತ ಕರೆಗಳಿಗೆ ಈ MMI ಕೋಡ್ ಲಭ್ಯವಿರುವುದಿಲ್ಲ."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ತುರ್ತು ಕರೆಯ ಸಮಯದಲ್ಲಿ MMI ಕೋಡ್‌ಗಳನ್ನು ಡಯಲ್ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ."</string>
 </resources>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index f0b95fd06..bd19dc271 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"다른 기기로 오디오 스트리밍"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"전화 끊기"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"현재 기기로 전환"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"이미 다른 통화가 연결 중이므로 전화를 걸 수 없습니다. 전화를 받거나 통화를 종료한 후 다른 전화를 걸 수 있습니다."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"이미 진행 중인 두 건의 통화가 있으므로 전화를 걸 수 없습니다. 통화 중 하나를 연결 해제하거나 두 통화를 다자간 통화로 병합한 후 새로운 전화를 걸 수 있습니다."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"이미 진행 중인 두 건의 통화가 있으므로 전화를 걸 수 없습니다. 통화 중 하나를 연결 해제한 후 새로운 전화를 걸 수 있습니다."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"대기할 수 없는 통화가 있으므로 전화를 걸 수 없습니다. 새로 전화를 걸기 전에 통화를 종료하세요."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"받지 않은 수신 전화가 있으므로 전화를 걸 수 없습니다. 새로 전화를 걸기 전에 수신 전화를 받거나 거절하세요."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"이 MMI 코드는 여러 계정 간에 통화에 사용할 수 없습니다."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"긴급 전화 중에는 MMI 코드로 전화를 걸 수 없습니다."</string>
 </resources>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index ad19dd767..c1bf92160 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Аудио башка түзмөккө берилүүдө"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Чалууну бүтүрүү"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Бул жерге которулуу"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Чалынып жатат, андыктан чалууга болбойт. Бул чалуудан кийин жаңы чалууну аткарыңыз."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Чалуу аткарылбайт, анткени эки чалуу аткарылууда. Бир чалууну өчүрүңүз же аларды конференцияга бириктириңиз."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Эки чалуу аткарылууда, андыктан чалууга болбойт. Жаңы чалуу аткаруудан мурун учурдагы чалуулардын бирин бүтүрүңүз."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Чалуу мүмкүн эмес, анткени кармалбаган чалуу бар. Жаңы чалуудан мурда учурдагыны бүтүрүңүз."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Чалуу аткарылбайт, анткени кирүүчү чалууга жооп берилген жок. Жаңы чалуу аткаруудан мурун кирүүчү чалууга жооп бериңиз же четке кагыңыз."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Бул MMI коду бир нече аккаунт аркылуу чалуулар үчүн жеткиликсиз."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Шашылыш чалуу учурунда MMI коддорун терүүгө болбойт."</string>
 </resources>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index 8e439359d..288614f6e 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ສະຕຣີມສຽງໄປໃສ່ອຸປະກອນອື່ນ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ວາງສາຍ"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ສະຫຼັບບ່ອນນີ້"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກມີສາຍອື່ນເຊື່ອມຕໍ່ຢູ່ແລ້ວ. ລໍຖ້າໃຫ້ຄົນຮັບສາຍ ຫຼື ຕັດການເຊື່ອມຕໍ່ກ່ອນໂທອອກອີກຄັ້ງ."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ບໍ່ສາມາດໂທໄດ້ເນື່ອງຈາກມີສອງສາຍກຳລັງໂທຢູ່. ກະລຸນາຕັດການເຊື່ອມຕໍ່ສາຍໃດໜຶ່ງອອກ ຫຼື ຮວມສາຍເປັນການປະຊຸມທາງໂທລະສັບກ່ອນໂທໃໝ່."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກມີສອງສາຍທີ່ພວມດຳເນີນຢູ່. ຕັດການເຊື່ອມຕໍ່ສາຍໃດໜຶ່ງກ່ອນທີ່ຈະໂທໃໝ່."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ບໍ່ສາມາດໂທໄດ້ເນື່ອງຈາກມີການໂທທີ່ບໍ່ສາມາດຖືສາຍຄ້າງໄວ້ໄດ້. ຕັດການເຊື່ອມຕໍ່ສາຍກ່ອນໂທໃໝ່."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກມີສາຍໂທເຂົ້າທີ່ຍັງບໍ່ໄດ້ຮັບຢູ່. ກະລຸນາຮັບສາຍ ຫຼື ວາງສາຍທີ່ກຳລັງໂທເຂົ້າມາກ່ອນຈະໂທໃໝ່."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ລະຫັດ MMI ນີ້ແມ່ນໃຊ້ບໍ່ໄດ້ສໍາລັບການໂທດ້ວຍຫຼາຍບັນຊີ."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ບໍ່ສາມາດກົດລະຫັດ MMI ໄດ້ໃນລະຫວ່າງການໂທ​ສຸກ​ເສີນໄດ້."</string>
 </resources>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 04f4c96c4..da31d3647 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Srautinis garso perdavimas į kitą įrenginį"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Baigti skambutį"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Perjungti čia"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Negalite skambinti, nes jau sujungiamas kitas skambutis. Prieš pradėdami kitą skambutį palaukite, kol bus atsiliepta, arba nutraukite skambutį."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Negalite skambinti, nes jau dalyvaujate dviejuose skambučiuose. Prieš pradėdami naują skambutį užbaikite vieną iš skambučių arba sujunkite juos į konferenciją."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Negalite skambinti, nes jau dalyvaujate dviejuose skambučiuose. Prieš pradėdami naują skambutį užbaikite vieną iš skambučių"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Negalite skambinti, nes yra skambutis, kurio negalima sulaikyti. Prieš pradėdami naują skambutį nutraukite esamą."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Negalite skambinti, nes yra neatsakytas gaunamasis skambutis. Atsiliepkite arba atmeskite gaunamąjį skambutį prieš pradėdami naują."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Šis MMI kodas nepasiekiamas skambučiuose keliose paskyrose."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI kodų negalima rinkti per skambutį pagalbos numeriu."</string>
 </resources>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index ee807da0b..24ad8a08b 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Notiek audio straumēšana uz citu ierīci."</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Beigt zvanu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Pārslēgties šeit"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nevar veikt zvanu, jo pašlaik jau tiek veikts cits zvans. Pirms jauna zvana veikšanas uzgaidiet, līdz tiek atbildēts uz pašreizējo zvanu, vai pārtrauciet pašreizējo zvanu."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nevar veikt zvanu, jo pašlaik jau notiek divi zvani. Pirms jauna zvana veikšanas pārtrauciet vienu no pašreizējiem zvaniem vai apvienojiet tos konferences zvanā."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nevar veikt zvanu, jo pašlaik jau notiek divi zvani. Pirms jauna zvana veikšanas pārtrauciet vienu no pašreizējiem zvaniem."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nevar veikt zvanu, jo pašlaik notiek zvans, ko nevar pārtraukt. Pirms jauna zvana veikšanas pārtrauciet pašreizējo zvanu."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nevar veikt zvanu, jo ir neatbildēts ienākošais zvans. Pirms jauna zvana veikšanas atbildiet uz ienākošo zvanu vai noraidiet to."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Šis MMI kods nav pieejams zvaniem vairākos kontos."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI kodus nevar ievadīt ārkārtas izsaukuma laikā."</string>
 </resources>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 0f6e41fe9..dca758bf7 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Звукот се стримува на друг уред"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Спушти"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Префрли овде"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Не може да се воспостави повик бидејќи веќе се поврзува друг повик. Почекајте да се одговори на повикот или прекинете го пред да воспоставите друг повик."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Не може да се воспостави повик бидејќи веќе се во тек два повика. Исклучете го едниот од повиците или спојте ги во конференциски повик пред да воспоставите нов повик."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Не може да се воспостави повик бидејќи веќе има два повика во тек. Прекинете еден од повиците пред да воспоставите нов повик."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Не може да се воспостави повик бидејќи има повик што не може да се стави на чекање. Исклучете го повикот пред да воспоставите нов повик."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Не може да се воспостави повик затоа што има неодговорен дојдовен повик. Одговорете или одбијте го дојдовниот повик пред воспоставувањето на новиот повик."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"MMI-кодов не е достапен за повици на повеќе сметки."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"MMI-кодовите не може да се бираат за време на итен повик."</string>
 </resources>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index 1301b4432..fd6f31399 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ഓഡിയോ മറ്റൊരു ഉപകരണത്തിലേക്ക് സ്‌ട്രീം ചെയ്യുന്നു"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"മാറ്റി വയ്‌ക്കുക"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ഇവിടേക്ക് മാറുക"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"മറ്റൊരു കോൾ നിലവിൽ കണക്റ്റ് ചെയ്യുന്നതിനാൽ ഇനിയൊരു കോൾ കൂടി ചെയ്യാനാകില്ല. കോളിന് മറുപടി നൽകുന്നത് വരെ കാത്തിരിക്കുക അല്ലെങ്കിൽ മറ്റൊരു കോൾ ചെയ്യുന്നതിന് മുമ്പ് ഇത് വിച്‌ഛേദിക്കുക."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"രണ്ട് കോളുകൾ നിലവിൽ പുരോഗമിക്കുന്നതിനാൽ, ഇനിയൊരു കോൾ കൂടി ചെയ്യാനാകില്ല. പുതിയൊരു കോൾ ചെയ്യുന്നതിന് മുമ്പ്, കോളുകളിലൊരെണ്ണം വിച്ഛേദിക്കുകയോ അവ കോൺഫറൻസ് കോളായി ലയിപ്പിക്കുകയോ ചെയ്യുക."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"രണ്ട് കോളുകൾ നിലവിൽ പുരോഗമിക്കുന്നതിനാൽ, ഇനിയൊരു കോൾ കൂടി ചെയ്യാനാകില്ല. പുതിയൊരു കോൾ ചെയ്യുന്നതിന് മുമ്പ് കോളുകളിലൊന്ന് വിച്ഛേദിക്കുക."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ഹോൾഡ് ചെയ്യാനാകാത്ത കോൾ പുരോഗമിക്കുന്നതിനാൽ ഇനിയൊരു കോൾ കൂടി ചെയ്യാനാകില്ല. പുതിയൊരു കോൾ ചെയ്യുന്നതിന് മുമ്പ് കോൾ വിച്ഛേദിക്കുക."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"മറുപടി ലഭിക്കാത്ത ഒരു ഇൻ‌കമിംഗ് കോൾ ഉള്ളതിനാൽ, പുതിയൊരു കോൾ ചെയ്യാനാവില്ല. പുതിയ കോൾ ചെയ്യുന്നതിന് മുമ്പ് ഇൻകമിംഗ് കോളിന് മറുപടി നൽകുകയോ നിരസിക്കുകയോ ചെയ്യുക."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ഒന്നിലധികം അക്കൗണ്ടുകളിലുടനീളം കോളുകൾക്ക് ഈ MMI കോഡ് ലഭ്യമല്ല."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"എമർജൻസി കോളിനിടെ MMI കോഡുകൾ ഡയൽ ചെയ്യാനാകില്ല."</string>
 </resources>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 0b26e7e29..e116f9912 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Бусад төхөөрөмж рүү аудио дамжуулж байна"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Таслах"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Ийшээ сэлгэх"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Аль хэдийн өөр дуудлага холбогдож байгаа тул дуудлага хийх боломжгүй. Өөр нэг дуудлага хийхээсээ өмнө тухайн дуудлагыг авах, салгахыг хүлээнэ үү."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Аль хэдийн хоёр дуудлага хийж байгаа тул дуудлага хийх боломжгүй байна. Шинэ дуудлага хийхээсээ өмнө аль нэг дуудлагыг салгах эсвэл тэдгээрийг хурал болгож нэгтгэнэ үү."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Аль хэдийн хоёр дуудлага хийж байгаа тул дуудлага хийх боломжгүй. Шинэ дуудлага хийхээсээ өмнө аль нэг дуудлагыг салгана уу."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Хүлээлгэх боломжгүй дуудлага байгаа тул дуудлага хийх боломжгүй. Шинэ дуудлага хийхээсээ өмнө тухайн дуудлагыг салгана уу."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Хариулаагүй ирсэн дуудлага байгаа тул дуудлага хийх боломжгүй. Шинэ дуудлага хийхээсээ өмнө ирсэн дуудлагад хариулах эсвэл тасална уу."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Энэ MMI код нь олон бүртгэл дээрх дуудлагад боломжгүй."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Яаралтай дуудлагын үеэр MMI кодыг оруулах боломжгүй."</string>
 </resources>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index eca7b4de0..232b8f43c 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ऑडिओ हा दुसऱ्या डिव्हाइसवर स्ट्रीम करत आहे"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"बंद करा"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"येथे स्विच करा"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"आधीच दुसरा कॉल कनेक्ट केलेला असल्यामुळे कॉल करू शकत नाही. कॉलला उत्तर दिले जाण्याची प्रतीक्षा करा किंवा दुसरा कॉल करण्यापूर्वी सद्य कॉल डिस्कनेक्ट करा."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"आधीच दोन कॉल सुरू असल्यामुळे कॉल करू शकत नाही. नवीन कॉल करण्यापूर्वी त्यांपैकी एक कॉल डिस्कनेक्ट करा किंवा त्यांना कॉन्फरन्समध्ये मर्ज करा."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"आधीच दोन कॉल सुरू असल्यामुळे कॉल करू शकत नाही. नवीन कॉल करण्यापूर्वी त्यांपैकी एक कॉल डिस्कनेक्ट करा."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"होल्डवर न ठेवता येणारा कॉल असल्यामुळे, कॉल करू शकत नाही. नवीन कॉल करण्यापूर्वी, कॉल डिस्कनेक्ट करा."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"इनकमिंग कॉलला उत्तर दिले जात नसल्यामुळे कॉल करू शकत नाही. नवीन कॉल करण्याआधी येणार्‍या कॉलला उत्तर द्या किंवा त्याला नकार द्या."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"हा MMI कोड एकाहून अधिक खात्यांवरील कॉलसाठी उपलब्ध नाही."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"आणीबाणीच्या कॉल दरम्यान MMI कोड डायल केले जाऊ शकत नाहीत."</string>
 </resources>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index ebfffd04c..20f2fde07 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Penstriman audio pada peranti lain"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Tamatkan panggilan"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Tukar di sini"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Tidak dapat membuat panggilan kerana terdapat panggilan lain yang sedang disambungkan. Tunggu sehingga panggilan dijawab atau putuskan sambungan sebelum membuat panggilan lain."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Tidak dapat membuat panggilan kerana sudah terdapat dua panggilan yang sedang berlangsung. Putuskan satu daripada panggilan itu atau gabungkan panggilan tersebut menjadi persidangan sebelum membuat panggilan baharu."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Tidak dapat membuat panggilan kerana sudah terdapat dua panggilan yang sedang berlangsung. Putuskan satu daripada panggilan sebelum ini untuk membuat panggilan baharu."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Tidak dapat membuat panggilan kerana terdapat panggilan yang sedang menunggu. Putuskan panggilan sebelum membuat panggilan baharu."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Tidak dapat membuat panggilan kerana terdapat panggilan masuk yang tidak dijawab. Jawab atau tolak panggilan masuk itu sebelum membuat panggilan baharu."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Kod MMI ini tidak tersedia untuk panggilan merentas berbilang akaun."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Kod MMI tidak boleh didail semasa panggilan kecemasan."</string>
 </resources>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index e7f0fd439..59fd1da41 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"အသံကို အခြားစက်တွင် တိုက်ရိုက်လွှင့်နေသည်"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ဖုန်းချရန်"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ဤနေရာသို့ လွှဲပြောင်းရန်"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ခေါ်ဆိုမှုနောက်တစ်ခုကို ချိတ်ဆက်နေသဖြင့် ဖုန်းထပ်ခေါ်၍မရပါ။ ခေါ်ဆိုမှုကို ဖြေကြားရန် စောင့်ပါ (သို့) နောက်တစ်ခု မခေါ်မီ ယခင်ခေါ်ဆိုမှုကို ဖုန်းချပါ။"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ခေါ်ဆိုမှုနှစ်ခုကို ပြုလုပ်နေသဖြင့် ဖုန်းထပ်ခေါ်၍မရပါ။ ခေါ်ဆိုမှုအသစ် မပြုလုပ်မီ ၎င်းတို့အနက် တစ်ခုကို ဖုန်းချပါ (သို့) အစည်းအဝေးအဖြစ် ပေါင်းစည်းပါ။"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ခေါ်ဆိုမှုနှစ်ခုကို ပြုလုပ်နေသဖြင့် ဖုန်းထပ်ခေါ်၍မရပါ။ ခေါ်ဆိုမှုအသစ် မပြုလုပ်မီ ၎င်းတို့အနက် တစ်ခုကို ဖုန်းချပါ။"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ဆိုင်းငံ့၍မရသော ခေါ်ဆိုမှုရှိနေသဖြင့် ဖုန်းထပ်ခေါ်၍မရပါ။ ခေါ်ဆိုမှုအသစ် မပြုလုပ်မီ ဤခေါ်ဆိုမှုကို ဖုန်းချပါ။"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"မဖြေကြားရသေးသော အဝင်ခေါ်ဆိုမှု ရှိနေသဖြင့် ဖုန်းခေါ်၍ မရနိုင်ပါ။ အသစ်မခေါ်ဆိုမီ ဖုန်းကိုင်ပါ (သို့) ငြင်းပယ်ပါ။"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ဤ MMI ကုဒ်ကို အကောင့်အများအပြား၌ ခေါ်ဆိုမှုများအတွက် မရနိုင်ပါ။"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"အရေးပေါ်ဖုန်းခေါ်နေစဉ်အတွင်း MMI ကုဒ်များကို ခေါ်၍မရနိုင်ပါ။"</string>
 </resources>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 66e6ffc72..4299d10e2 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Strømmer lyden til en annen enhet"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Legg på"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Flytt hit"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Kan ikke ringe fordi det allerede pågår et annet anrop. Vent til anropet blir besvart, eller avslutt det før du ringer på nytt."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Du kan ikke ringe fordi to andre anrop allerede pågår. Koble fra ett av anropene eller slå dem sammen i en konferansesamtale, før du ringer på nytt."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Du kan ikke ringe fordi to andre anrop allerede pågår. Koble fra ett av anropene før du ringer på nytt."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Kan ikke ringe fordi det pågår en samtale som ikke kan settes på vent. Avslutt samtalen før du ringer på nytt."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Du kan ikke ringe, fordi du har et innkommende anrop. Svar på eller avvis anropet før du prøver å ringe igjen."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Denne MMI-koden kan ikke brukes til anrop på flere kontoer samtidig."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Det er ikke mulig å taste MMI-koder under nødanrop."</string>
 </resources>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index 4aeceef5d..336adc72b 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"अर्को डिभाइसमा अडियो स्ट्रिम गरिँदै छ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"कल काट्नुहोस्"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"यहाँ गई बदल्नुहोस्"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"अर्को कल कनेक्ट भइरहेको हुनाले नयाँ कल गर्न सकिँदैन। यो कल नउठाइन्जेल पर्खनुहोस् वा नयाँ कल गर्नुअघि यसलाई डिस्कनेक्ट गर्नुहोस्।"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"दुई वटा कल चलिरहेका हुनाले नयाँ कल गर्न सकिँदैन। नयाँ कल गर्नुअघि दुईमध्ये एउटा कल डिस्कनेक्ट गर्नुहोस् वा तिनलाई मर्ज गरी कन्फ्रेन्स कल बनाउनुहोस्।"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"दुई वटा कल चलिरहेका हुनाले नयाँ कल गर्न सकिँदैन। नयाँ कल गर्नुअघि दुईमध्ये एउटा कल डिस्कनेक्ट गर्नुहोस्।"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"होल्ड गर्न नमिल्ने कल चलिरहेको हुनाले नयाँ कल गर्न सकिँदैन। नयाँ कल गर्नुअघि यो कल डिस्कनेक्ट गर्नुहोस्।"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"अहिले आइरहेको कल नउठाइएको हुनाले नयाँ कल गर्न सकिँदैन। नयाँ कल गर्नुअघि उक्त कल उठाउनुहोस् वा काट्नुहोस्।"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"अर्को खातामार्फत कल चलिरहेका बेला यो MMI कोड प्रयोग गर्न मिल्दैन।"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"आपत्कालीन कल चलिरहेका बेला MMI कोड डायल गर्न मिल्दैन।"</string>
 </resources>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index e395ef1d0..bcf94aa52 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audio streamen naar ander apparaat"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Ophangen"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Hiernaartoe schakelen"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Kan gesprek niet plaatsen omdat er al een ander gesprek bezig is. Wacht tot het gesprek wordt beantwoord of verbreek de verbinding voordat je een ander gesprek start."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Kan gesprek niet plaatsen omdat er al 2 actieve gesprekken zijn. Verbreek de verbinding in een van de gesprekken of voeg ze samen tot een conferencecall voordat je een nieuw gesprek plaatst."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Kan gesprek niet plaatsen omdat er al 2 actieve gesprekken zijn. Verbreek de verbinding van een van de gesprekken voordat je een nieuw gesprek plaatst."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Kan gesprek niet plaatsen omdat je het live gesprek niet in de wacht kunt zetten. Verbreek de verbinding van het live gesprek voordat je een nieuw gesprek plaatst."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Kan niet bellen omdat er een niet-beantwoord inkomend gesprek is. Beantwoord of weiger het inkomende gesprek voordat je opnieuw belt."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Deze MMI-code is niet beschikbaar voor gesprekken met meerdere accounts."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Je kunt geen MMI-code kiezen tijdens een noodoproep."</string>
 </resources>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 535583ae8..6081da88e 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ଅନ୍ୟ ଡିଭାଇସରେ ଅଡିଓ ଷ୍ଟ୍ରିମ କରାଯାଉଛି"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"କଲ ସମାପ୍ତ କରନ୍ତୁ"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ଏଠାରେ ସୁଇଚ କରନ୍ତୁ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ପୂର୍ବରୁ ଆଉ ଏକ କଲ୍ କନେକ୍ଟ ହୋଇଥିବା ଯୋଗୁଁ କଲ କରାଯାଇପାରିବ ନାହିଁ। କଲର ଉତ୍ତର ପାଇବା ପର୍ଯ୍ୟନ୍ତ ଅପେକ୍ଷା କରନ୍ତୁ କିମ୍ବା ଅନ୍ୟ ଏକ କଲ କରିବା ପୂର୍ବରୁ ଏହାକୁ ଡିସକନେକ୍ଟ କରନ୍ତୁ।"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ପୂର୍ବରୁ ଦୁଇଟି କଲ ଚାଲୁ ଥିବା ଯୋଗୁଁ ଆଉ ଏକ କଲ କରାଯାଇପାରିବ ନାହିଁ। ଏକ ନୂଆ କଲ କରିବା ପୂର୍ବରୁ ଗୋଟିଏ କଲକୁ ଡିସକନେଜ୍ଟ କରନ୍ତୁ କିମ୍ବା ସେଗୁଡ଼ିକୁ ଏକ କନଫରେନ୍ସ କଲରେ ମର୍ଜ କରନ୍ତୁ।"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ପୂର୍ବରୁ ଦୁଇଟି କଲ ଚାଲିଛି ତେଣୁ କଲ କରାଯାଇପାରିବ ନାହିଁ। ନୂଆ କଲ କରିବା ପୂର୍ବରୁ ଗୋଟିଏ କଲ ଡିସକନେକ୍ଟ କରନ୍ତୁ।"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ହୋଲ୍ଡ କରିହେଉନଥିବା ଏକ କଲ ଚାଲୁ ଥିବା ଯୋଗୁଁ ଆଉ ଏକ କଲ କରାଯାଇପାରିବ ନାହିଁ। ଏକ ନୂଆ କଲ କରିବା ପୂର୍ବରୁ କଲକୁ ଡିସକନେକ୍ଟ କରନ୍ତୁ।"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ଗୋଟିଏ ଉତ୍ତର ଦିଆଯାଇନଥିବା ଇନକମିଂ କଲ ଥିବା ଯୋଗୁଁ ଅନ୍ୟ ଏକ କଲ କରିପାରିବେ ନାହିଁ। ଏକ ନୂଆ କଲ କରିବା ପୂର୍ବରୁ ଇନକମିଂ କଲଟିର ଉତ୍ତର ଦିଅନ୍ତୁ କିମ୍ବା ଏହାକୁ ଅଗ୍ରାହ୍ୟ କରନ୍ତୁ।"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ଏକାଧିକ ଆକାଉଣ୍ଟରେ କଲଗୁଡ଼ିକ ପାଇଁ ଏହି MMI କୋଡ ଉପଲବ୍ଧ ନାହିଁ।"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ଏକ ଜରୁରୀକାଳୀନ କଲ ସମୟରେ MMI କୋଡଗୁଡ଼ିକ ଡାଏଲ କରାଯାଇପାରିବ ନାହିଁ।"</string>
 </resources>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index 96ee0e800..2a2226419 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ਆਡੀਓ ਨੂੰ ਕਿਸੇ ਹੋਰ ਡੀਵਾਈਸ \'ਤੇ ਸਟ੍ਰੀਮ ਕੀਤਾ ਜਾ ਰਿਹਾ ਹੈ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ਕਾਲ ਸਮਾਪਤ ਕਰੋ"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ਇੱਥੇ ਸਵਿੱਚ ਕਰੋ"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਪਹਿਲਾਂ ਹੀ ਕੋਈ ਹੋਰ ਕਾਲ ਕਨੈਕਟ ਹੋ ਰਹੀ ਹੈ। ਕੋਈ ਹੋਰ ਕਾਲ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਕਾਲ ਦੇ ਜਵਾਬ ਦੀ ਉਡੀਕ ਕਰੋ ਜਾਂ ਉਸਨੂੰ ਡਿਸਕਨੈਕਟ ਕਰੋ।"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਪਹਿਲਾਂ ਤੋਂ ਦੋ ਕਾਲਾਂ ਚੱਲ ਰਹੀਆਂ ਹਨ। ਨਵੀਂ ਕਾਲ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਕਿਸੇ ਇੱਕ ਕਾਲ ਨੂੰ ਡਿਸਕਨੈਕਟ ਕਰੋ ਜਾਂ ਦੋਨਾਂ ਕਾਲਾਂ ਨੂੰ ਮਿਲਾ ਕੇ ਕਾਨਫਰੰਸ ਕਾਲ ਵਿੱਚ ਬਦਲੋ।"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਪਹਿਲਾਂ ਤੋਂ ਦੋ ਕਾਲਾਂ ਚੱਲ ਰਹੀਆਂ ਹਨ। ਨਵੀਂ ਕਾਲ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਕਿਸੇ ਇੱਕ ਕਾਲ ਨੂੰ ਡਿਸਕਨੈਕਟ ਕਰੋ।"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਪਹਿਲਾਂ ਤੋਂ ਇੱਕ ਕਾਲ ਚੱਲ ਰਹੀ ਹੈ, ਜਿਸਨੂੰ ਹੋਲਡ \'ਤੇ ਨਹੀਂ ਰੱਖਿਆ ਜਾ ਸਕਦਾ। ਨਵੀਂ ਕਾਲ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਕਾਲ ਨੂੰ ਡਿਸਕਨੈਕਟ ਕਰੋ।"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਇੱਕ ਜਵਾਬ ਨਾ ਦਿੱਤੀ ਗਈ ਇਨਕਮਿੰਗ ਕਾਲ ਪਹਿਲਾਂ ਤੋਂ ਹੀ ਆ ਰਹੀ ਹੈ। ਨਵੀਂ ਕਾਲ ਕਰਨ ਤੋਂ ਪਹਿਲਾਂ ਇਨਕਮਿੰਗ ਕਾਲ ਦਾ ਜਵਾਬ ਦਿਓ ਜਾਂ ਅਸਵੀਕਾਰ ਕਰੋ।"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ਇਹ MMI ਕੋਡ ਇੱਕ ਤੋਂ ਵੱਧ ਖਾਤਿਆਂ ਵਿੱਚ ਕਾਲਾਂ ਲਈ ਉਪਲਬਧ ਨਹੀਂ ਹੈ।"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ਐਮਰਜੈਂਸੀ ਕਾਲ ਦੌਰਾਨ MMI ਕੋਡ ਡਾਇਲ ਨਹੀਂ ਕੀਤੇ ਜਾ ਸਕਦੇ।"</string>
 </resources>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index 23776f56a..e5b73b1d8 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Strumieniowanie dźwięku na inne urządzenie"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Rozłącz"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Przełącz tutaj"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nie można nawiązać połączenia, ponieważ trwa już inne połączenie. Zanim nawiążesz nowe połączenie, poczekaj na odpowiedź lub zakończ trwające połączenie."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nie można nawiązać połączenia, ponieważ trwają już 2 inne połączenia. Aby nawiązać nowe połączenie, zakończ jedno z nich lub scal je w połączenie konferencyjne."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nie można nawiązać połączenia, ponieważ trwają już 2 połączenia. Aby nawiązać nowe połączenie, zakończ jedno z nich."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nie można nawiązać połączenia, ponieważ trwa połączenie, którego nie można wstrzymać. Aby nawiązać nowe połączenie, zakończ to połączenie."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nie można nawiązać połączenia, ponieważ masz nieodebrane połączenie przychodzące. Odbierz je lub odrzuć przed nawiązaniem nowego."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ten kod MMI nie jest dostępny w przypadku połączeń na więcej niż 1 koncie."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Nie można wybierać kodów MMI podczas połączenia alarmowego."</string>
 </resources>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 122615af4..5c8777252 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"A fazer stream de áudio para outro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Desligar"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Mudar aqui"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Não pode fazer uma chamada porque já existe outra chamada em curso. Aguarde que a chamada seja atendida ou desligue-a antes de iniciar outra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Não pode fazer uma chamada porque já existem 2 chamadas em curso. Desligue uma das chamadas ou una-as numa conferência antes de iniciar uma nova."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Não pode fazer uma chamada porque já existem 2 chamadas em curso. Desligue uma das chamadas antes de iniciar uma nova."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Não pode fazer uma chamada porque tem uma chamada que não pode ser colocada em espera. Termine essa chamada antes de fazer uma nova chamada."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Não pode fazer uma chamada porque há uma chamada recebida não atendida. Atenda ou rejeite a chamada recebida antes de fazer uma nova chamada."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Este código MMI não está disponível para chamadas em várias contas."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Não é possível marcar códigos MMI durante uma chamada de emergência."</string>
 </resources>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index e302ea69c..dcaf3cc3c 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Fazendo streaming de áudio para outro dispositivo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Desligar"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Mudar para este dispositivo"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Não é possível ligar porque há outra chamada sendo feita. Aguarde a chamada ser atendida ou encerre a ligação antes de fazer outra."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Não é possível ligar porque há duas chamadas em andamento. Encerre uma delas ou mescle-as em uma videoconferência antes de fazer outra."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Não é possível ligar porque há duas chamadas em andamento. Encerre uma das ligações antes de fazer outra."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Não é possível ligar porque há uma chamada que não pode ficar em espera. Encerre essa ligação antes de fazer outra."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Não é possível ligar porque há uma ligação recebida que não foi atendida. Atenda ou rejeite essa chamada antes de fazer outra."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Este código MMI não está disponível para chamadas em várias contas."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Não é possível discar códigos MMI durante uma chamada de emergência."</string>
 </resources>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index fe5ad9367..16cc3cb24 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streaming audio pe alt dispozitiv"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Încheie apelul"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Treci la alt cont aici"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nu se poate iniția un apel când există deja un alt apel în curs de conectare. Așteaptă să se răspundă la apel sau deconectează apelul înainte de a iniția altul."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nu se poate iniția un apel când există deja două apeluri în desfășurare. Deconectează unul dintre ele sau îmbină-le într-o conferință înainte de a iniția un apel nou."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nu se poate iniția un apel când există deja două apeluri în desfășurare. Deconectează unul dintre apeluri înainte de a iniția un apel nou."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nu se poate iniția un apel când există un apel care nu poate fi pus în așteptare. Închide apelul înainte de a iniția un apel nou."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nu se poate iniția un apel când primești un apel la care nu ai răspuns. Răspunde sau respinge apelul primit înainte de a iniția un apel nou."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Acest cod MMI nu este disponibil pentru apelurile din mai multe conturi."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Codurile MMI nu pot fi formate în timpul unui apel de urgență."</string>
 </resources>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index cc69d40b8..1e807d5b4 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Потоковая передача аудио на другое устройство"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Завершить"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Переключиться"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Невозможно позвонить, поскольку уже устанавливается соединение для другого звонка. Дождитесь ответа или сбросьте вызов."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Невозможно позвонить, поскольку ещё не завершены два текущих вызова. Сбросьте один из вызовов или объедините их в конференцию."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Невозможно позвонить, поскольку ещё не завершены два текущих вызова. Сбросьте один из них."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Невозможно позвонить, поскольку нельзя поставить текущий вызов на удержание. Сбросьте вызов, чтобы начать новый."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Невозможно позвонить, поскольку вы не ответили на входящий вызов. Примите или отклоните текущий звонок."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Этот код MMI недоступен для вызовов с использованием нескольких аккаунтов."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Коды MMI нельзя использовать во время экстренных вызовов."</string>
 </resources>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 2ea058f0a..423c21ac8 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"වෙනත් උපාංගයකට ශ්‍රව්‍ය ප්‍රවාහ කිරීම"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"විසන්ධි කරන්න"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"මෙතැනට මාරු වෙන්න"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"තවත් ඇමතුමක් සම්බන්ධ වෙමින් පවතින බැවින් ඇමතුමක් ලබා ගත නොහැක. ඇමතුමට පිළිතුරු ලැබෙන තෙක් රැඳී සිටින්න නැතහොත් තවත් ඇමතුමක් ගැනීමට පෙර එය විසන්ධි කරන්න."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"දැනටමත් ඇමතුම් දෙකක් කෙරෙමින් පවතින නිසා ඇමතුමක් ගැනීමට නොහැක. නව ඇමතුමක් ගැනීමට පෙරාතුව ඇමතුම්වලින් එකක් විසන්ධි කරන්න නැතහොත් ඒවා සම්මන්ත්‍රණයකට ඒකාබද්ධ කරන්න."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"දැනටමත් ඇමතුම් දෙකක් ක්‍රියාත්මක වෙමින් පවතින බැවින් ඇමතුමක් ලබා ගත නොහැක. නව ඇමතුමක් ලබා ගැනීමට පෙර එක් ඇමතුමක් විසන්ධි කරන්න."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"රඳවා ගත නොහැකි ඇමතුමක් ඇති බැවින් ඇමතුමක් ලබා ගත නොහැක. නව ඇමතුමක් ලබා ගැනීමට පෙර ඇමතුම විසන්ධි කරන්න."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"පිළිතුරු නොලැබෙන ඇමතුමක් ඇති බැවින් ඇමතුමක් ලබා ගත නොහැක. නව ඇමතුමක් ලබා ගැනීමට පෙර ලැබෙන ඇමතුමට පිළිතුරු දෙන්න හෝ ප්‍රතික්ෂේප කරන්න."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"මෙම MMI කේතය බහු ගිණුම් හරහා ඇමතුම් සඳහා ලබා ගත නොහැක."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"හදිසි ඇමතුමක දී MMI කේත ඇමතිය නොහැක."</string>
 </resources>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index fc7108af3..fe20409fa 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streamovanie zvuku do iného zariadenia"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Zložiť"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Prepnúť sem"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Hovor sa nedá uskutočniť, pretože sa už pripája iný hovor. Pred uskutočnením ďalšieho hovoru počkajte na prijatie aktuálneho hovoru alebo ho ukončite."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Hovor sa nedá uskutočniť, pretože už prebiehajú dva hovory. Odpojte jeden hovor alebo ich zlúčte do konferencie a až potom uskutočnite nový hovor."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Hovor sa nedá uskutočniť, pretože už prebiehajú dva hovory. Pred uskutočnením nového hovoru ukončite jeden z prebiehajúcich hovorov."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Hovor sa nedá uskutočniť, pretože prebieha hovor, ktorý sa nedá podržať. Pred uskutočnením nového hovoru najprv ukončite ten prebiehajúci."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Hovor sa nedá uskutočniť, pretože máte neprijatý prichádzajúci hovor. Prijmite alebo odmietnite prichádzajúci hovor a až potom uskutočnite nový hovor."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Tento kód MMI nie je k dispozícii pre hovory v rámci viacerých účtov."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Kódy MMI nemožno vytočiť počas tiesňového volania."</string>
 </resources>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 7ee0b0b88..5b6b41871 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Pretočno predvajanje zvoka v drugo napravo"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Prekini klic"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Preklopi sem"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Klica ni mogoče opraviti, ker že poteka vzpostavljanje drugega klica. Preden začnete nov klic, počakajte, da bo klic sprejet, ali ga prekinite."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Klica ni mogoče opraviti, ker potekata že dva klica. Preden začnete nov klic, prekinite enega od klicev ali ju združite v konferenčni klic."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Klica ni mogoče opraviti, ker potekata že dva klica. Preden začnete nov klic, prekinite enega od klicev."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Klica ni mogoče opraviti, ker že imate klic, ki ga ni mogoče zadržati. Preden opravite nov klic, prekinite omenjeni klic."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Klica ni mogoče opraviti, ker imate dohodni klic, na katerega še niste odgovorili. Preden začnete nov klic, sprejmite ali zavrnite dohodni klic."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ta koda MMI ni na voljo za klice v več računih."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Med klicem v sili ni mogoče vnesti kod MMI."</string>
 </resources>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 7d8045a8b..fb53968a7 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Po transmetohet audioja te një pajisje tjetër"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Mbyll"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Ndërro këtu"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Nuk mund të kryhet një telefonatë sepse po lidhet tashmë një telefonatë tjetër. Prit derisa telefonata të marrë përgjigje ose shkëpute atë para se të kryesh një telefonatë tjetër."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Nuk mund të kryhet një telefonatë sepse janë tashmë dy telefonata në vazhdim. Shkëput një nga telefonatat ose shkriji ato në një konferencë para se të kryesh një telefonatë të re."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Nuk mund të kryhet një telefonatë sepse janë tashmë dy telefonata në vazhdim. Shkëput një nga telefonatat para se të kryesh një telefonatë të re."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Nuk mund të kryhet një telefonatë pasi është në telefonatë që nuk mund të vendoset në pritje. Shkëput telefonatën para se të kryesh një telefonatë të re."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Nuk mund të kryhet një telefonatë sepse është një telefonatë hyrëse që nuk ka marrë përgjigje. Përgjigju ose refuzoje telefonatën hyrëse para se të kryesh një telefonatë të re."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Ky kod MMI nuk ofrohet për telefonatat në disa llogari."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Kodet MMI nuk mund të formohen gjatë një telefonate urgjence."</string>
 </resources>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 148cb14d1..26855ac2d 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Звук се стримује на други уређај"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Прекини везу"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Пребаци овде"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Не можете да позовете јер се већ успоставља веза са другим позивом. Сачекајте да неко одговори на позив или га прекините пре упућивања другог позива."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Не можете да позовете јер су два позива већ у току. Прекините један од њих или их обједините у конференцију пре упућивања новог позива."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Не можете да позовете јер су два позива већ у току. Прекините један од позива пре упућивања новог позива."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Не можете да упутите позив јер је у току позив који не може да се стави на чекање. Прекините тај позив пре упућивања новог позива."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Не можете да позовете јер имате долазни позив на који нисте одговорили. Примите га или одбијте пре упућивања новог позива."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Овај MMI кôд није доступан за позиве на више налога."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Бирање MMI кодова ноје могуће током хитног позива."</string>
 </resources>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index d4a930cd3..b86e26063 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Streama ljud till en annan enhet"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Lägg på"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Koppla hit"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Det går inte att ringa eftersom ett annat samtal redan kopplas. Vänta tills samtalet besvaras eller koppla bort det innan du ringer ett nytt samtal."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Det går inte att ringa eftersom det redan finns två pågående samtal. Koppla bort ett eller slå ihop dem till en konferens innan du ringer ett nytt samtal."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Det går inte att ringa eftersom det redan finns två pågående samtal. Koppla bort ett av samtalen innan du ringer ett nytt samtal."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Det går inte att ringa eftersom det finns ett samtal som inte kan sättas i vänteläge. Koppla bort samtalet innan du ringer ett nytt samtal."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Det går inte att ringa eftersom det finns ett obesvarat inkommande samtal. Svara eller avvisa det innan du ringer ett nytt samtal."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Den här MMI-koden är inte tillgänglig för samtal på flera konton."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Det går inte att ange MMI-koder under ett nödsamtal."</string>
 </resources>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index ac0518dfe..85760fed7 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Inatiririsha sauti kwenye kifaa kingine"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Kata simu"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Badili hapa"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Imeshindwa kupiga simu kwa sababu tayari kuna simu nyingine inayounganisha. Subiri simu ijibiwe au uitenganishe kabla ya kupiga simu nyingine."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Imeshindwa kupiga simu kwa sababu tayari kuna simu mbili zinazoendelea. Kata mojawapo ya simu hizo au uziunganishe ili ziwe simu ya mkutano kabla ya kupiga simu mpya."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Imeshindwa kupiga simu kwa sababu tayari kuna simu mbili zinazoendelea. Kata mojawapo ya simu hizo kabla ya kupiga simu mpya."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Imeshindwa kupiga simu kwa sababu kuna simu isiyoweza kusubirishwa. Kata simu kabla ya kupiga simu mpya."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Haiwezi kupiga simu kwa sababu kuna simu unayopigiwa ambayo hujajibu. Jibu au ukatae simu hiyo unayopigiwa kabla ya kupiga simu mpya."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Msimbo huu wa MMI haupatikani katika simu kwenye akaunti nyingi."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Huwezi kupiga misimbo ya MMI wakati wa simu ya dharura."</string>
 </resources>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 57c70f4bb..aca2738e1 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"வேறு சாதனத்திற்கு ஆடியோவை ஸ்ட்ரீம் செய்கிறது"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"அழைப்பைத் துண்டி"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"இங்கே மாற்று"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ஏற்கெனவே ஒரு அழைப்பு இணைக்கப்படுவதால் அழைப்பை மேற்கொள்ள முடியவில்லை. அதற்குப் பதிலளிக்கப்படும் வரை காத்திருங்கள் அல்லது அதைத் துண்டித்துவிட்டு அடுத்த அழைப்பை மேற்கொள்ளுங்கள்."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ஏற்கெனவே இரண்டு அழைப்புகள் செயலில் இருப்பதால் புதிய அழைப்பை மேற்கொள்ள முடியவில்லை. புதிதாக ஒரு அழைப்பை மேற்கொள்வதற்கு முன்னர் செயலில் உள்ள அழைப்புகளில் ஏதேனும் ஒன்றைத் துண்டிக்கவும் அல்லது அவற்றை இணைத்து குழு அழைப்பாக மாற்றவும்."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ஏற்கெனவே இரண்டு அழைப்புகள் செயலில் இருப்பதால் புதிய அழைப்பை மேற்கொள்ள முடியவில்லை. புதிதாக ஒரு அழைப்பை மேற்கொள்வதற்கு முன்னர் செயலில் உள்ள அழைப்புகளில் ஏதேனும் ஒன்றைத் துண்டிக்கவும்."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"ஹோல்டு செய்ய முடியாத ஓர் அழைப்பு ஏற்கெனவே செயலில் இருப்பதால் அழைப்பை மேற்கொள்ள முடியவில்லை. செயலில் உள்ள அழைப்பைத் துண்டித்து புதிய அழைப்பை மேற்கொள்ளவும்."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"உள்வரும் அழைப்பிற்கு இன்னும் பதிலளிக்காததால் இந்த அழைப்பைச் செய்ய முடியாது. புதிதாக ஓர் அழைப்பைச் செய்யும் முன்னர் உள்வரும் அழைப்பிற்குப் பதிலளிக்கவும் அல்லது நிராகரிக்கவும்."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"பல கணக்குகளில் மேற்கொள்ளப்படும் அழைப்புகளுக்கு இந்த MMI குறியீட்டைப் பயன்படுத்த முடியாது."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"அவசர அழைப்பின்போது MMI குறியீடுகளை டயல் செய்ய முடியாது."</string>
 </resources>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 22f4b8a4d..6e6776407 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"ఆడియోను ఇతర పరికరానికి స్ట్రీమింగ్ చేయండి"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"ముగించండి"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"ఇక్కడకు స్విచ్ అవ్వండి"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"ఇప్పటికే వేరే కాల్ కనెక్ట్ అయి ఉన్నందున కాల్ చేయడం సాధ్యపడదు. కాల్‌కు సమాధానమిచ్చేంత వరకు వేచి ఉండండి లేదా వేరొక కాల్‌ను చేయడానికి ముందు దీన్ని డిస్‌కనెక్ట్ చేయండి."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"ఇప్పటికే రెండు కాల్స్ జరుగుతున్నందున కాల్ చేయడం సాధ్యపడదు. ఆ కాల్స్‌లో ఒకదానిని డిస్‌కనెక్ట్ చేయండి లేదా అవి రెండింటినీ విలీనం చేసి ఒక కాన్ఫరెన్స్ కాల్‌గా మార్చి, తర్వాత కొత్త కాల్ చేయండి."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"ఇప్పటికే రెండు కాల్స్ ప్రోగ్రెస్‌లో ఉన్నందున కాల్ చేయడం సాధ్యం కాదు. కొత్త కాల్ చేయడానికంటే ముందుగా రెండు కాల్స్‌లో ఒకదాన్ని డిస్‌కనెక్ట్ చేయండి."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"హోల్డ్‌లో పెట్టడం సాధ్యం కాని కాల్ జరుగుతున్నందున కాల్ చేయడం సాధ్యం కాదు. కొత్త కాల్ చేయడానికంటే ముందుగా ప్రస్తుత కాల్‌ను డిస్‌కనెక్ట్ చేయండి."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ఇన్‌కమింగ్ కాల్ వస్తున్నంతసేపు వేరొక కాల్ చేయడం సాధ్యపడదు. కొత్త కాల్ చేయడానికి ముందుగా ఇన్‌కమింగ్ కాల్‌కు సమాధానమివ్వండి లేదా కాల్‌ను నిరాకరించండి."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"ఈ MMI కోడ్ పలు ఖాతాలలో కాల్స్ కోసం అందుబాటులో లేదు."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ఎమర్జెన్సీ కాల్ సమయంలో MMI కోడ్‌లను డయల్ చేయడం సాధ్యం కాదు."</string>
 </resources>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index e3a20b129..a0a7fddae 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"กำลังสตรีมเสียงไปยังอุปกรณ์อื่นๆ"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"วางสาย"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"เปลี่ยนที่นี่"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"โทรออกไม่ได้เนื่องจากมีสายอื่นกำลังเชื่อมต่ออยู่ โปรดรอให้สายได้รับการตอบรับหรือยกเลิกการเชื่อมต่อก่อนโทรออกใหม่"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"โทรออกไม่ได้เนื่องจากมีการโทร 2 สายที่กำลังดำเนินอยู่ โปรดยกเลิกการเชื่อมต่อสายใดสายหนึ่งหรือรวมเป็นการประชุมสายก่อนโทรออกใหม่"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"โทรออกไม่ได้เนื่องจากมีการโทร 2 สายที่กำลังดำเนินอยู่ โปรดยกเลิกการเชื่อมต่อ 1 สายก่อนโทรออกใหม่"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"โทรออกไม่ได้เนื่องจากมีการโทรที่ไม่สามารถพักสายได้ โปรดยกเลิกการเชื่อมต่อสายดังกล่าวก่อนโทรออกใหม่"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"โทรออกไม่ได้เนื่องจากมีสายเรียกเข้าที่ยังไม่ได้รับ โปรดรับหรือปฏิเสธสายเรียกเข้าก่อนจึงค่อยโทรออกใหม่"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"รหัส MMI นี้ใช้ไม่ได้กับการโทรผ่านหลายบัญชี"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"ไม่สามารถโทรออกด้วยโค้ด MMI ระหว่างการโทรฉุกเฉิน"</string>
 </resources>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 001a19ae1..f7e32d572 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Naka-stream ang audio sa ibang device"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Mag-hang up"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Lumipat dito"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Hindi puwedeng tumawag dahil may isa pang kumokonektang tawag. Hintaying sagutin ang tawag o idiskonekta ito bago gumawa ng isa pang pagtawag."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Hindi puwedeng tumawag dahil mayroon nang dalawang tawag na kasalukuyang nagaganap. Idiskonekta ang isa sa mga tawag o i-merge ang mga ito sa isang conference bago gumawa ng bagong pagtawag."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Hindi puwedeng tumawag dahil mayroon nang dalawang tawag na kasalukuyang nagaganap Idiskonekta ang isa sa mga tawag bago gumawa ng bagong pagtawag."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Hindi puwedeng tumawag dahil may tawag na hindi puwedeng i-hold. Idiskonekta ang tawag bago gumawa ng bagong pagtawag."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Hindi puwedeng tumawag dahil mayroong hindi nasagot na papasok na tawag. Sagutin o tanggihan ang papasok na tawag bago gumawa ng bagong pagtawag."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Hindi available ang MMI code na ito para sa mga tawag sa magkakaibang account."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Hindi puwedeng mag-dial ng mga MMI code habang may emergency na tawag."</string>
 </resources>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 1924d922f..36feb7c6c 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Ses başka bir cihaza aktarılıyor"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Görüşmeyi bitir"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Buraya dön"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Bağlanmaya çalışılan başka bir arama olduğu için arama yapılamıyor. Yeni bir arama yapmadan önce aramanın cevaplanmasını bekleyin veya aramayı sonlandırın."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Devam eden iki arama olduğu için arama yapılamıyor. Yeni bir arama yapmadan önce aramalardan birini sonlandırın veya iki aramayı bir konferans aramasında birleştirin."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Devam eden iki arama olduğu için arama yapılamıyor. Yeni bir arama yapmadan önce aramalardan birini sonlandırın."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Bekletilemeyen bir arama devam ettiğinden arama yapılamıyor. Yeni bir arama yapmadan önce mevcut aramayı sonlandırın."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Gelen arama olduğu için arama yapılamıyor. Yeni bir arama yapmadan önce gelen aramayı cevaplayın veya reddedin."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Bu MMI kodu, birden fazla hesaptan arama yapılırken kullanılamaz."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Acil durum aramalarında MMI kodları kullanılamaz."</string>
 </resources>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index 2d4f5bc46..7fc3fa817 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Аудіо транслюється на інший пристрій"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Завершити"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Перевести сюди"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Неможливо зателефонувати, оскільки здійснюється інший виклик. Зачекайте, поки абонент вам відповість, або скасуйте наявний виклик, перш ніж починати інший."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Неможливо зателефонувати, оскільки тривають уже два виклики. Припиніть один із них або об’єднайте їх у конференцію, перш ніж здійснити новий."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Неможливо зателефонувати, оскільки тривають уже два виклики. Припиніть один із них, перш ніж здійснити новий."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Неможливо зателефонувати, оскільки поточний виклик не можна поставити на утримання. Припиніть виклик, перш ніж здійснити новий."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Неможливо зателефонувати. Прийміть або відхиліть вхідний дзвінок, перш ніж здійснювати новий."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Цей код MMI недоступний для дзвінків із використанням кількох облікових записів."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Не можна набирати коди MMI під час екстреного виклику."</string>
 </resources>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index b09f244b6..a08729338 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"دوسرے آلے پر آڈیو کی سلسلہ بندی کی جا رہی ہے"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"منقطع کریں"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"یہاں سوئچ کریں"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"کال نہیں کر سکتا کیونکہ پہلے سے ہی ایک اور کال منسلک ہو رہی ہے۔ کال کا جواب آنے کا انتظار کریں یا دوسری کال کرنے سے پہلے اسے غیر منسلک کریں۔"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"پہلے سے دو کالز کے پیش رفت میں ہونے کی وجہ سے کال نہیں کی جا سکتی۔ نئی کال کرنے کیلئے پہلے ان میں سے ایک کو غیر منسلک کریں یا انہیں کانفرنس میں ضم کریں۔"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"کال نہیں کر سکتا کیونکہ پہلے سے ہی دو کالز جاری ہیں۔ نئی کال کرنے سے پہلے کالز میں سے ایک کو غیر منسلک کریں۔"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"کال نہیں کر سکتے کیونکہ پہلے سے جاری کال کو ہولڈ نہیں کیا جا سکتا۔ نئی کال کرنے سے پہلے موجودہ کال کو غیر منسلک کریں۔"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"ایک جواب نہ ملنے والی اِن کمنگ کال کی وجہ سے کال نہیں کی جا سکتی۔ نئی کال کرنے کے لیے پہلے اِن کمنگ کال کا جواب دیں یا مسترد کریں۔"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"‏یہ MMI کوڈ متعدد اکاؤنٹس پر کالز کے لیے دستیاب نہیں ہے۔"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"‏‫MMI کوڈز ایمرجنسی کال کے دوران ڈائل نہیں کیے جا سکتے۔"</string>
 </resources>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index ff049035b..585a8690c 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Audio translatsiyani boshqa qurilmaga olish"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Tugatish"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Shu yerga olish"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Telefon qilish imkonsiz, chunki ayni paytda boshqa chaqiruv ulanmoqda. Telefon qilishdan oldin chaqiruvga javob berilishi yoki aloqa uzilishini kuting."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Telefon qilish imkonsiz, chunki ayni paytda ikkita chaqiruv davom etmoqda. Telefon qilish uchun chaqiruvlardan birini yakunlang yoki ularni konferens-aloqaga birlashtiring."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Telefon qilish imkonsiz, chunki ayni paytda ikkita chaqiruv davom etmoqda. Telefon qilish uchun avval mavjud bittasini uzing."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Chaqirish imkonsiz, chunki joriy chaqiruv pauza qilinmaydi. Yangisini boshlash uchun chaqiruvni bekor qiling."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Telefon qilish imkonsiz. Telefon qilish uchun avval kiruvchi chaqiruvni qabul qiling yoki rad eting."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Bu MMI kodi bir nechta hisobdagi chaqiruvlarda ishlamaydi."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Favqulodda chaqiruv paytida MMI kodlarini terish imkonsiz."</string>
 </resources>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 142026c31..224cba699 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Đang truyền trực tuyến âm thanh tới thiết bị khác"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Kết thúc"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Chuyển qua thiết bị này"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Không thể thực hiện cuộc gọi vì có một cuộc gọi khác đang kết nối. Hãy chờ đến khi cuộc gọi được trả lời hoặc ngắt kết nối trước khi thực hiện cuộc gọi khác."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Không thể thực hiện cuộc gọi vì đã có 2 cuộc gọi đang diễn ra. Hãy ngắt kết nối 1 trong các cuộc gọi hoặc gộp thành 1 cuộc gọi kiểu hội nghị truyền hình trước khi thực hiện cuộc gọi mới."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Không thể thực hiện cuộc gọi vì đã có 2 cuộc gọi đang diễn ra. Hãy ngắt kết nối 1 trong các cuộc gọi đó trước khi thực hiện cuộc gọi mới."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Không thể thực hiện cuộc gọi vì có một cuộc gọi không thể tạm ngưng. Hãy ngắt kết nối với cuộc gọi đó trước khi thực hiện cuộc gọi mới."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Bạn không thể gọi vì chưa trả lời cuộc gọi đến. Hãy trả lời hoặc từ chối cuộc gọi đến trước khi thực hiện cuộc gọi mới."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Mã MMI này không dùng được cho các cuộc gọi trên nhiều tài khoản."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Không thể quay số mã MMI trong khi thực hiện cuộc gọi khẩn cấp."</string>
 </resources>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 7cb8a7a13..48c76e551 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"将音频流式传输到其他设备"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"挂断"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"在此处切换"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"目前正在连接其他通话，因此无法拨打电话。请等待通话接听或挂断，然后再拨打其他电话。"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"由于已有两个正在进行的通话，因此无法拨打电话。请挂断其中一个通话或将两个通话合并到同一个会议中，然后才能拨打新电话。"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"由于已有两个正在进行的通话，因此无法拨打电话。请先挂断其中一个通话，然后再拨打新电话。"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"由于有无法暂停的通话，因此不能拨打电话。请先断开通话，然后再拨打新电话。"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"由于有未接来电，因此无法拨打电话。请先接听或拒绝来电，然后才能拨打新电话。"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"此 MMI 码无法用于跨多个账号的通话。"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"在紧急呼叫期间，无法拨打 MMI 码。"</string>
 </resources>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 213255a19..6388a828a 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"正在串流音訊至其他裝置"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"結束通話"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"在這裡切換"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"目前有另一個通話連接中，因此無法撥打電話。請等候對方接聽，或先掛斷，然後再撥打電話。"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"目前已有兩個通話正在進行，因此無法撥打電話。請先結束其中一個通話，或將兩個通話合併為一個會議，然後再撥打電話。"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"目前已有兩個通話正在進行，因此無法撥打電話。請先結束其中一個通話，然後再撥打電話。"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"目前有一個無法保留的通話，因此無法撥打電話。請先結束通話，然後再撥打電話。"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"你尚未接聽目前的來電，因此無法撥打電話。請先接聽或拒絕來電，然後再撥打電話。"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"在透過多個帳戶進行通話時，無法使用 MMI 碼。"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"進行緊急電話時無法撥打 MMI 碼"</string>
 </resources>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index 287f62713..38976126d 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"正在將音訊串流到其他裝置"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"掛斷"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"切換到這部裝置"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"目前正在撥打其他電話，因此無法撥號。請等待通話接通或掛斷，再撥打電話。"</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"目前有兩個進行中的通話，因此無法撥號。請掛斷其中一個通話，或將通話合併成會議，再撥打電話。"</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"目前有兩個進行中的通話，因此無法撥號。請先掛斷其中一個通話，再撥打電話。"</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"目前有無法保留的通話，因此無法撥號。請先掛斷通話，再撥打電話。"</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"有人打電話給你，因此你目前無法撥打電話。你必須先接聽或拒接來電，才能撥打電話。"</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"這個 MMI 代碼無法用於透過多個帳戶進行通話。"</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"進行緊急電話時無法撥打 MMI 碼。"</string>
 </resources>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index 8d0437d80..e1e73473a 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -134,4 +134,11 @@
     <string name="call_streaming_notification_body" msgid="502216105683378263">"Sakaza umsindo kwenye idivayisi"</string>
     <string name="call_streaming_notification_action_hang_up" msgid="7017663335289063827">"Beka phansi"</string>
     <string name="call_streaming_notification_action_switch_here" msgid="3524180754186221228">"Shintsha lapha"</string>
+    <string name="callFailed_outgoing_already_present" msgid="411484560432884251">"Awukwazi ukwenza ikholi njengoba sekuvele kukhona enye ikholi exhunyiwe. Linda ukuthi ikholi iphendulwe noma inqamuke ngaphambi kokwenza enye ikholi."</string>
+    <string name="callFailed_too_many_calls_include_merge" msgid="2234495082825519920">"Awukwazi ukwenza ikholi njengoba kunamakholi amabili aqhubekayo kakade. Nqamula eyodwa yamakholi noma wahlanganisele enkomfeni ngaphambi kokwenza ikholi entsha."</string>
+    <string name="callFailed_too_many_calls_exclude_merge" msgid="8616011288480453495">"Awukwazi ukwenza ikholi njengoba sekunamakholi amabili aqhubekayo. Nqamula eyodwa yamakholi ngaphambi kokwenza ikholi entsha."</string>
+    <string name="callFailed_unholdable_call" msgid="7580834131274566524">"Ayikwazi ukwenza ikholi njengoba kukhona ikholi engabanjwa. Nqamula ikholi ngaphambi kokwenza ikholi entsha."</string>
+    <string name="callFailed_already_ringing" msgid="7931232733958098270">"Ayikwazi ukubeka ikholi njengoba kunekholi engenayo engaphenduliwe. Phendula noma nqaba ikholi engenayo ngaphambi kokubeka ikholi entsha."</string>
+    <string name="callFailed_reject_mmi" msgid="5219280796733595167">"Le khodi ye-MMI ayitholakali ngamakholi kuma-akhawunti amaningi."</string>
+    <string name="emergencyCall_reject_mmi" msgid="5056319534549705785">"Amakhodi e-MMI awakwazi ukushayelwa ngesikhathi socingo oluphuthumayo."</string>
 </resources>
diff --git a/res/values/strings.xml b/res/values/strings.xml
index aefd2e6f9..adbedfb57 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -417,4 +417,25 @@
          Call streaming is a feature where a user can see and interact with a call from another
          device like a tablet while the call takes place on their phone. -->
     <string name="call_streaming_notification_action_switch_here">Switch here</string>
+    <!-- In-call screen: error message shown when the user attempts to place a call, but calling has
+         been disabled using a debug property. -->
+    <string name="callFailed_outgoing_already_present">Cannot place a call as there is already another call connecting. Wait for the call to be answered or disconnect it before placing another call.</string>
+    <!-- In-call screen: error message shown when the user attempts to place a call, but calling has
+         been disabled using a debug property. -->
+    <string name="callFailed_too_many_calls_include_merge">Cannot place a call as there are already two calls in progress. Disconnect one of the calls or merge them into a conference prior to placing a new call.</string>
+    <!-- In-call screen: error message shown when the user attempts to place a call, but calling has
+             been disabled using a debug property. -->
+    <string name="callFailed_too_many_calls_exclude_merge">Cannot place a call as there are already two calls in progress. Disconnect one of the calls prior to placing a new call.</string>
+    <!-- In-call screen: error message shown when the user attempts to place a call, but the live
+         call cannot be held. -->
+    <string name="callFailed_unholdable_call">Cannot place a call as there is an unholdable call. Disconnect the call prior to placing a new call.</string>
+    <!-- In-call screen: error message shown when the user has attempted to place a new outgoing
+         call while there is already a call in ringing state. -->
+    <string name="callFailed_already_ringing">Cannot place a call as there is an unanswered incoming call. Answer or reject the incoming call prior to placing a new call.</string>
+    <!-- In-call screen: error message shown when the user attempts to dial an MMI code, but there
+         is an ongoing call on a different phone account. -->
+    <string name="callFailed_reject_mmi">This MMI code is not available for calls across multiple accounts.</string>
+    <!-- In-call screen: error message shown when the user attempts to dial an MMI code during an
+         ongoing emergency call. -->
+    <string name="emergencyCall_reject_mmi">MMI codes cannot be dialed during an emergency call.</string>
 </resources>
diff --git a/src/com/android/server/telecom/AsyncRingtonePlayer.java b/src/com/android/server/telecom/AsyncRingtonePlayer.java
index 3b5e3424c..7cb05cd1c 100644
--- a/src/com/android/server/telecom/AsyncRingtonePlayer.java
+++ b/src/com/android/server/telecom/AsyncRingtonePlayer.java
@@ -23,6 +23,7 @@ import android.media.VolumeShaper;
 import android.net.Uri;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.os.Looper;
 import android.os.Message;
 import android.telecom.Log;
 import android.telecom.Logging.Session;
@@ -184,6 +185,13 @@ public class AsyncRingtonePlayer {
         }
     }
 
+    public @NonNull Looper getLooper() {
+        if (mHandler == null) {
+            mHandler = getNewHandler();
+        }
+        return mHandler.getLooper();
+    }
+
     /**
      * Creates a new ringtone Handler running in its own thread.
      */
diff --git a/src/com/android/server/telecom/AudioRoute.java b/src/com/android/server/telecom/AudioRoute.java
index d3ed77d21..661f1db2d 100644
--- a/src/com/android/server/telecom/AudioRoute.java
+++ b/src/com/android/server/telecom/AudioRoute.java
@@ -24,9 +24,11 @@ import static com.android.server.telecom.CallAudioRouteAdapter.SPEAKER_ON;
 
 import android.annotation.IntDef;
 import android.bluetooth.BluetoothDevice;
+import android.bluetooth.BluetoothHeadset;
 import android.bluetooth.BluetoothStatusCodes;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
+import android.sysprop.BluetoothProperties;
 import android.telecom.Log;
 import android.util.Pair;
 
@@ -138,6 +140,7 @@ public class AudioRoute {
     private String mBluetoothAddress;
     private AudioDeviceInfo mInfo;
     private boolean mIsDestRouteForWatch;
+    private boolean mIsScoManagedByAudio;
     public static final Set<Integer> BT_AUDIO_DEVICE_INFO_TYPES = Set.of(
             AudioDeviceInfo.TYPE_BLE_HEADSET,
             AudioDeviceInfo.TYPE_BLE_SPEAKER,
@@ -253,26 +256,26 @@ public class AudioRoute {
     // Invoked when entered pending route whose dest route is this route
     void onDestRouteAsPendingRoute(boolean active, PendingAudioRoute pendingAudioRoute,
             BluetoothDevice device, AudioManager audioManager,
-            BluetoothRouteManager bluetoothRouteManager, boolean isScoAudioConnected) {
-        Log.i(this, "onDestRouteAsPendingRoute: active (%b), type (%s)", active,
-                DEVICE_TYPE_STRINGS.get(mAudioRouteType));
+            BluetoothRouteManager bluetoothRouteManager, boolean isScoAlreadyConnected) {
+        Log.i(this, "onDestRouteAsPendingRoute: active (%b), type (%s), isScoAlreadyConnected(%s)",
+                active, DEVICE_TYPE_STRINGS.get(mAudioRouteType), isScoAlreadyConnected);
         if (pendingAudioRoute.isActive() && !active) {
             clearCommunicationDevice(pendingAudioRoute, bluetoothRouteManager, audioManager);
         } else if (active) {
             // Handle BT routing case.
             if (BT_AUDIO_ROUTE_TYPES.contains(mAudioRouteType)) {
+                // Check if the communication device was set for the device, even if
+                // BluetoothHeadset#connectAudio reports that the SCO connection wasn't
+                // successfully established.
                 boolean connectedBtAudio = connectBtAudio(pendingAudioRoute, device,
-                        audioManager, bluetoothRouteManager);
+                        audioManager, bluetoothRouteManager, isScoAlreadyConnected);
                 // Special handling for SCO case.
-                if (mAudioRouteType == TYPE_BLUETOOTH_SCO) {
+                if (!mIsScoManagedByAudio && mAudioRouteType == TYPE_BLUETOOTH_SCO) {
                     // Set whether the dest route is for the watch
                     mIsDestRouteForWatch = bluetoothRouteManager.isWatch(device);
-                    // Check if the communication device was set for the device, even if
-                    // BluetoothHeadset#connectAudio reports that the SCO connection wasn't
-                    // successfully established.
-                    if (connectedBtAudio || isScoAudioConnected) {
+                    if (connectedBtAudio || isScoAlreadyConnected) {
                         pendingAudioRoute.setCommunicationDeviceType(mAudioRouteType);
-                        if (!isScoAudioConnected) {
+                        if (!isScoAlreadyConnected) {
                             pendingAudioRoute.addMessage(BT_AUDIO_CONNECTED, mBluetoothAddress);
                         }
                     } else {
@@ -281,7 +284,8 @@ public class AudioRoute {
                     }
                     return;
                 }
-            } else if (mAudioRouteType == TYPE_SPEAKER) {
+            } else if (mAudioRouteType == TYPE_SPEAKER && !this.equals(
+                    pendingAudioRoute.getOrigRoute())) {
                 pendingAudioRoute.addMessage(SPEAKER_ON, null);
             }
 
@@ -290,17 +294,32 @@ public class AudioRoute {
             for (AudioDeviceInfo deviceInfo : devices) {
                 // It's possible for the AudioDeviceInfo to be updated for the BT device so adjust
                 // mInfo accordingly.
+                // Note: we need to check the device type as well since a dual mode (LE and HFP) BT
+                // device can change type during a call if the user toggles LE for the device.
+                boolean isSameDeviceType =
+                        !pendingAudioRoute.getFeatureFlags().checkDeviceTypeOnRouteChange() ||
+                                (pendingAudioRoute.getFeatureFlags().checkDeviceTypeOnRouteChange()
+                                        && mAudioRouteType
+                                        == DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(
+                                        deviceInfo.getType()));
                 if (BT_AUDIO_ROUTE_TYPES.contains(mAudioRouteType) && mBluetoothAddress
-                        .equals(deviceInfo.getAddress())) {
+                        .equals(deviceInfo.getAddress())
+                        && isSameDeviceType) {
                     mInfo = deviceInfo;
                 }
                 if (deviceInfo.equals(mInfo)) {
                     result = audioManager.setCommunicationDevice(mInfo);
                     if (result) {
                         pendingAudioRoute.setCommunicationDeviceType(mAudioRouteType);
+                        if (mAudioRouteType == TYPE_BLUETOOTH_SCO
+                                && !isScoAlreadyConnected
+                                && mIsScoManagedByAudio) {
+                            pendingAudioRoute.addMessage(BT_AUDIO_CONNECTED, mBluetoothAddress);
+                        }
                     }
                     Log.i(this, "onDestRouteAsPendingRoute: route=%s, "
-                            + "AudioManager#setCommunicationDevice()=%b", this, result);
+                            + "AudioManager#setCommunicationDevice(%s)=%b", this,
+                            audioDeviceTypeToString(mInfo.getType()), result);
                     break;
                 }
             }
@@ -314,13 +333,21 @@ public class AudioRoute {
         }
     }
 
-    // Takes care of cleaning up original audio route (i.e. clearCommunicationDevice,
-    // sending SPEAKER_OFF, or disconnecting SCO).
-    void onOrigRouteAsPendingRoute(boolean active, PendingAudioRoute pendingAudioRoute,
-            AudioManager audioManager, BluetoothRouteManager bluetoothRouteManager) {
-        Log.i(this, "onOrigRouteAsPendingRoute: active (%b), type (%s)", active,
-                DEVICE_TYPE_STRINGS.get(mAudioRouteType));
-        if (active) {
+    /**
+     * Takes care of cleaning up original audio route (i.e. clearCommunicationDevice,
+     * sending SPEAKER_OFF, or disconnecting SCO).
+     * @param wasActive Was the origin route active or not.
+     * @param pendingAudioRoute The pending audio route change we're performing.
+     * @param audioManager Good 'ol audio manager.
+     * @param bluetoothRouteManager The BT route manager.
+     */
+    void onOrigRouteAsPendingRoute(boolean wasActive, PendingAudioRoute pendingAudioRoute,
+            AudioManager audioManager, BluetoothRouteManager bluetoothRouteManager,
+            boolean isScoAlreadyConnected) {
+        Log.i(this, "onOrigRouteAsPendingRoute: wasActive (%b), type (%s), pending(%s),"
+                + "isScoAlreadyConnected(%s)", wasActive, DEVICE_TYPE_STRINGS.get(mAudioRouteType),
+                pendingAudioRoute, isScoAlreadyConnected);
+        if (wasActive && !isScoAlreadyConnected) {
             int result = clearCommunicationDevice(pendingAudioRoute, bluetoothRouteManager,
                     audioManager);
             if (mAudioRouteType == TYPE_SPEAKER) {
@@ -338,6 +365,9 @@ public class AudioRoute {
         mAudioRouteType = type;
         mBluetoothAddress = bluetoothAddress;
         mInfo = info;
+        // Indication that SCO is managed by audio (i.e. supports setCommunicationDevice).
+        mIsScoManagedByAudio = android.media.audio.Flags.scoManagedByAudio()
+                && BluetoothProperties.isScoManagedByAudioEnabled().orElse(false);
     }
 
     @Override
@@ -368,11 +398,12 @@ public class AudioRoute {
     }
 
     private boolean connectBtAudio(PendingAudioRoute pendingAudioRoute, BluetoothDevice device,
-            AudioManager audioManager, BluetoothRouteManager bluetoothRouteManager) {
+            AudioManager audioManager, BluetoothRouteManager bluetoothRouteManager,
+            boolean isScoAlreadyConnected) {
         // Ensure that if another BT device was set, it is disconnected before connecting
         // the new one.
         AudioRoute currentRoute = pendingAudioRoute.getOrigRoute();
-        if (currentRoute.getBluetoothAddress() != null &&
+        if (!isScoAlreadyConnected && currentRoute.getBluetoothAddress() != null &&
                 !currentRoute.getBluetoothAddress().equals(device.getAddress())) {
             clearCommunicationDevice(pendingAudioRoute, bluetoothRouteManager, audioManager);
         }
@@ -381,7 +412,7 @@ public class AudioRoute {
         boolean success = false;
         if (device != null) {
             success = bluetoothRouteManager.getDeviceManager()
-                    .connectAudio(device, mAudioRouteType);
+                    .connectAudio(device, mAudioRouteType, mIsScoManagedByAudio);
         }
 
         Log.i(this, "connectBtAudio: routeToConnectTo = %s, successful = %b",
@@ -389,6 +420,20 @@ public class AudioRoute {
         return success;
     }
 
+    /**
+     * Clears the communication device; this takes into account the fact that SCO devices require
+     * us to call {@link BluetoothHeadset#disconnectAudio()} rather than
+     * {@link AudioManager#clearCommunicationDevice()}.
+     * As a general rule, if we are transitioning from an active route to another active route, we
+     * do NOT need to call {@link AudioManager#clearCommunicationDevice()}, but if the device is a
+     * legacy SCO device we WILL need to call {@link BluetoothHeadset#disconnectAudio()}.  We rely
+     * on the {@link PendingAudioRoute#isActive()} indicator to tell us if the destination route
+     * is going to be active or not.
+     * @param pendingAudioRoute The pending audio route transition we're implementing.
+     * @param bluetoothRouteManager The BT route manager.
+     * @param audioManager The audio manager.
+     * @return -1 if nothing was done, or the result code from the BT SCO disconnect.
+     */
     int clearCommunicationDevice(PendingAudioRoute pendingAudioRoute,
             BluetoothRouteManager bluetoothRouteManager, AudioManager audioManager) {
         // Try to see if there's a previously set device for communication that should be cleared.
@@ -398,11 +443,20 @@ public class AudioRoute {
         }
 
         int result = BluetoothStatusCodes.SUCCESS;
-        if (pendingAudioRoute.getCommunicationDeviceType() == TYPE_BLUETOOTH_SCO) {
-            Log.i(this, "clearCommunicationDevice: Disconnecting SCO device.");
+        boolean shouldDisconnectSco = !mIsScoManagedByAudio
+                && pendingAudioRoute.getCommunicationDeviceType() == TYPE_BLUETOOTH_SCO;
+        if (shouldDisconnectSco) {
+            Log.i(this, "Disconnecting SCO device via BluetoothHeadset.");
             result = bluetoothRouteManager.getDeviceManager().disconnectSco();
-        } else {
-            Log.i(this, "clearCommunicationDevice: AudioManager#clearCommunicationDevice, type=%s",
+        }
+        // Only clear communication device if the destination route will be inactive; route to
+        // route transitions do not require clearing the communication device.
+        boolean onlyClearCommunicationDeviceOnInactive =
+                pendingAudioRoute.getFeatureFlags().onlyClearCommunicationDeviceOnInactive();
+        if ((!onlyClearCommunicationDeviceOnInactive && !shouldDisconnectSco)
+                || !pendingAudioRoute.isActive()) {
+            Log.i(this,
+                    "clearCommunicationDevice: AudioManager#clearCommunicationDevice, type=%s",
                     DEVICE_TYPE_STRINGS.get(pendingAudioRoute.getCommunicationDeviceType()));
             audioManager.clearCommunicationDevice();
         }
@@ -430,4 +484,23 @@ public class AudioRoute {
             pendingAudioRoute.clearPendingMessage(new Pair<>(SPEAKER_ON, null));
         }
     }
+
+    /**
+     * Get a human readable (for logs) version of an an audio device type.
+     * @param type the device type
+     * @return the human readable string
+     */
+    private static String audioDeviceTypeToString(int type) {
+        return switch (type) {
+            case AudioDeviceInfo.TYPE_BUILTIN_EARPIECE -> "earpiece";
+            case AudioDeviceInfo.TYPE_BUILTIN_SPEAKER -> "speaker";
+            case AudioDeviceInfo.TYPE_BUS -> "bus(auto speaker)";
+            case AudioDeviceInfo.TYPE_BLUETOOTH_SCO -> "bt sco";
+            case AudioDeviceInfo.TYPE_BLE_HEADSET -> "bt le";
+            case AudioDeviceInfo.TYPE_HEARING_AID -> "bt hearing aid";
+            case AudioDeviceInfo.TYPE_USB_HEADSET -> "usb headset";
+            case AudioDeviceInfo.TYPE_WIRED_HEADSET -> "wired headset";
+            default -> Integer.toString(type);
+        };
+    }
 }
diff --git a/src/com/android/server/telecom/Call.java b/src/com/android/server/telecom/Call.java
index df31e02fd..a54a3b6d6 100644
--- a/src/com/android/server/telecom/Call.java
+++ b/src/com/android/server/telecom/Call.java
@@ -80,6 +80,7 @@ import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.stats.CallFailureCause;
 import com.android.server.telecom.stats.CallStateChangedAtomWriter;
 import com.android.server.telecom.ui.ToastFactory;
+import com.android.server.telecom.callsequencing.CallTransaction;
 import com.android.server.telecom.callsequencing.TransactionManager;
 import com.android.server.telecom.callsequencing.VerifyCallStateChangeTransaction;
 import com.android.server.telecom.callsequencing.CallTransactionResult;
@@ -130,6 +131,20 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
 
     private static final char NO_DTMF_TONE = '\0';
 
+    /**
+     * The following simultaneous call types will be set on each call on creation and may be updated
+     * according to priority level. CALL_DIRECTION_DUAL_DIFF_ACCOUNT holds the highest priority.
+     * So if for example, a call is created with CALL_DIRECTION_DUAL_SAME_ACCOUNT, it can be
+     * upgraded to CALL_DIRECTION_DUAL_DIFF_ACCOUNT if another call is added with a different phone
+     * account.
+     */
+    public static final int CALL_SIMULTANEOUS_UNKNOWN = 0;
+    // Only used if simultaneous calling is not available
+    public static final int CALL_SIMULTANEOUS_DISABLED_SAME_ACCOUNT = 1;
+    // Only used if simultaneous calling is not available
+    public static final int CALL_SIMULTANEOUS_DISABLED_DIFF_ACCOUNT = 2;
+    public static final int CALL_DIRECTION_DUAL_SAME_ACCOUNT = 3;
+    public static final int CALL_DIRECTION_DUAL_DIFF_ACCOUNT = 4;
 
     /**
      * Listener for CallState changes which can be leveraged by a Transaction.
@@ -190,6 +205,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         default void onHoldToneRequested(Call call) {};
         default void onCallHoldFailed(Call call) {};
         default void onCallSwitchFailed(Call call) {};
+        default void onCallResumeFailed(Call call) {};
         default void onConnectionEvent(Call call, String event, Bundle extras) {};
         default void onCallStreamingStateChanged(Call call, boolean isStreaming) {}
         default void onExternalCallChanged(Call call, boolean isExternalCall) {};
@@ -280,6 +296,8 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         @Override
         public void onCallSwitchFailed(Call call) {}
         @Override
+        public void onCallResumeFailed(Call call) {}
+        @Override
         public void onConnectionEvent(Call call, String event, Bundle extras) {}
         @Override
         public void onCallStreamingStateChanged(Call call, boolean isStreaming) {}
@@ -500,6 +518,16 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      */
     private DisconnectCause mOverrideDisconnectCause = new DisconnectCause(DisconnectCause.UNKNOWN);
 
+    /**
+     * Simultaneous type of the call.
+     */
+    private int mSimultaneousType = CALL_SIMULTANEOUS_UNKNOWN;
+
+    /**
+     * Indicate whether the call has the video
+     */
+    boolean mHasVideoCall;
+
     private Bundle mIntentExtras = new Bundle();
 
     /**
@@ -619,6 +647,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
 
     private boolean mIsTransactionalCall = false;
     private CallingPackageIdentity mCallingPackageIdentity = new CallingPackageIdentity();
+    private boolean mSkipAutoUnhold = false;
 
     /**
      * CallingPackageIdentity is responsible for storing properties about the calling package that
@@ -1882,7 +1911,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         return mTargetPhoneAccountHandle;
     }
 
-    @VisibleForTesting
     public PhoneAccountHandle getTargetPhoneAccount() {
         return mTargetPhoneAccountHandle;
     }
@@ -2642,7 +2670,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
             return;
         }
         mCreateConnectionProcessor = new CreateConnectionProcessor(this, mRepository, this,
-                phoneAccountRegistrar, mContext, mFlags, new Timeouts.Adapter());
+                phoneAccountRegistrar, mCallsManager, mContext, mFlags, new Timeouts.Adapter());
         mCreateConnectionProcessor.process();
     }
 
@@ -2832,20 +2860,20 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
     }
 
     @VisibleForTesting
-    public void disconnect() {
-        disconnect(0);
+    public CompletableFuture<Boolean> disconnect() {
+        return disconnect(0);
     }
 
-    public void disconnect(String reason) {
-        disconnect(0, reason);
+    public CompletableFuture<Boolean> disconnect(String reason) {
+        return disconnect(0, reason);
     }
 
     /**
      * Attempts to disconnect the call through the connection service.
      */
     @VisibleForTesting
-    public void disconnect(long disconnectionTimeout) {
-        disconnect(disconnectionTimeout, "internal" /** reason */);
+    public CompletableFuture<Boolean> disconnect(long disconnectionTimeout) {
+        return disconnect(disconnectionTimeout, "internal" /* reason */);
     }
 
     /**
@@ -2855,16 +2883,24 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      *               as TelecomManager.
      */
     @VisibleForTesting
-    public void disconnect(long disconnectionTimeout, String reason) {
+    public CompletableFuture<Boolean> disconnect(long disconnectionTimeout,
+            String reason) {
         Log.addEvent(this, LogUtils.Events.REQUEST_DISCONNECT, reason);
 
         // Track that the call is now locally disconnecting.
         setLocallyDisconnecting(true);
         maybeSetCallAsDisconnectingChild();
 
+        CompletableFuture<Boolean> disconnectFutureHandler =
+                CompletableFuture.completedFuture(false);
         if (mState == CallState.NEW || mState == CallState.SELECT_PHONE_ACCOUNT ||
                 mState == CallState.CONNECTING) {
             Log.i(this, "disconnect: Aborting call %s", getId());
+            if (mFlags.enableCallSequencing()) {
+                disconnectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                        false /* shouldDisconnectUponTimeout */, "disconnect",
+                        CallState.DISCONNECTED, CallState.ABORTED);
+            }
             abort(disconnectionTimeout);
         } else if (mState != CallState.ABORTED && mState != CallState.DISCONNECTED) {
             if (mState == CallState.AUDIO_PROCESSING && !hasGoneActiveBefore()) {
@@ -2876,7 +2912,8 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 setOverrideDisconnectCauseCode(new DisconnectCause(DisconnectCause.MISSED));
             }
             if (mTransactionalService != null) {
-                mTransactionalService.onDisconnect(this, getDisconnectCause());
+                disconnectFutureHandler = mTransactionalService.onDisconnect(this,
+                        getDisconnectCause());
                 Log.i(this, "Send Disconnect to transactional service for call");
             } else if (mConnectionService == null) {
                 Log.e(this, new Exception(), "disconnect() request on a call without a"
@@ -2887,9 +2924,15 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 // confirms that the call was actually disconnected. Only then is the
                 // association between call and connection service severed, see
                 // {@link CallsManager#markCallAsDisconnected}.
+                if (mFlags.enableCallSequencing()) {
+                    disconnectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "disconnect",
+                            CallState.DISCONNECTED);
+                }
                 mConnectionService.disconnect(this);
             }
         }
+        return disconnectFutureHandler;
     }
 
     void abort(long disconnectionTimeout) {
@@ -2932,29 +2975,35 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      * @param videoState The video state in which to answer the call.
      */
     @VisibleForTesting
-    public void answer(int videoState) {
+    public CompletableFuture<Boolean> answer(int videoState) {
+        CompletableFuture<Boolean> answerCallFuture = CompletableFuture.completedFuture(false);
         // Check to verify that the call is still in the ringing state. A call can change states
         // between the time the user hits 'answer' and Telecom receives the command.
         if (isRinging("answer")) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_ACCEPT);
             if (!isVideoCallingSupportedByPhoneAccount() && VideoProfile.isVideo(videoState)) {
                 // Video calling is not supported, yet the InCallService is attempting to answer as
                 // video.  We will simply answer as audio-only.
                 videoState = VideoProfile.STATE_AUDIO_ONLY;
             }
             // At this point, we are asking the connection service to answer but we don't assume
-            // that it will work. Instead, we wait until confirmation from the connectino service
+            // that it will work. Instead, we wait until confirmation from the connection service
             // that the call is in a non-STATE_RINGING state before changing the UI. See
             // {@link ConnectionServiceAdapter#setActive} and other set* methods.
             if (mConnectionService != null) {
+                if (mFlags.enableCallSequencing()) {
+                    answerCallFuture = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "answer", CallState.ACTIVE);
+                }
                 mConnectionService.answer(this, videoState);
             } else if (mTransactionalService != null) {
-                mTransactionalService.onAnswer(this, videoState);
+                return mTransactionalService.onAnswer(this, videoState);
             } else {
                 Log.e(this, new NullPointerException(),
                         "answer call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_ACCEPT);
         }
+        return answerCallFuture;
     }
 
     /**
@@ -3034,74 +3083,101 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      *               if the reject is initiated from an API such as TelecomManager.
      */
     @VisibleForTesting
-    public void reject(boolean rejectWithMessage, String textMessage, String reason) {
+    public CompletableFuture<Boolean> reject(boolean rejectWithMessage,
+            String textMessage, String reason) {
+        CompletableFuture<Boolean> rejectFutureHandler = CompletableFuture.completedFuture(false);
         if (mState == CallState.SIMULATED_RINGING) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, reason);
             // This handles the case where the user manually rejects a call that's in simulated
             // ringing. Since the call is already active on the connectionservice side, we want to
             // hangup, not reject.
             setOverrideDisconnectCauseCode(new DisconnectCause(DisconnectCause.REJECTED));
             if (mTransactionalService != null) {
-                mTransactionalService.onDisconnect(this,
+                return mTransactionalService.onDisconnect(this,
                         new DisconnectCause(DisconnectCause.REJECTED));
             } else if (mConnectionService != null) {
+                if (mFlags.enableCallSequencing()) {
+                    rejectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "reject",
+                            CallState.DISCONNECTED);
+                }
                 mConnectionService.disconnect(this);
+                return rejectFutureHandler;
             } else {
                 Log.e(this, new NullPointerException(),
                         "reject call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, reason);
         } else if (isRinging("reject") || isAnswered("reject")) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, reason);
             // Ensure video state history tracks video state at time of rejection.
             mVideoStateHistory |= mVideoState;
 
             if (mTransactionalService != null) {
-                mTransactionalService.onDisconnect(this,
+                return mTransactionalService.onDisconnect(this,
                         new DisconnectCause(DisconnectCause.REJECTED));
             } else if (mConnectionService != null) {
+                if (mFlags.enableCallSequencing()) {
+                    rejectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "reject",
+                            CallState.DISCONNECTED);
+                }
                 mConnectionService.reject(this, rejectWithMessage, textMessage);
+                return rejectFutureHandler;
             } else {
                 Log.e(this, new NullPointerException(),
                         "reject call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, reason);
         }
+        return rejectFutureHandler;
     }
 
     /**
      * Reject this Telecom call with the user-indicated reason.
      * @param rejectReason The user-indicated reason fore rejecting the call.
      */
-    public void reject(@android.telecom.Call.RejectReason int rejectReason) {
+    public CompletableFuture<Boolean> reject(@android.telecom.Call.RejectReason int rejectReason) {
+        CompletableFuture<Boolean> rejectFutureHandler = CompletableFuture.completedFuture(false);
         if (mState == CallState.SIMULATED_RINGING) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT);
             // This handles the case where the user manually rejects a call that's in simulated
             // ringing. Since the call is already active on the connectionservice side, we want to
             // hangup, not reject.
             // Since its simulated reason we can't pass along the reject reason.
             setOverrideDisconnectCauseCode(new DisconnectCause(DisconnectCause.REJECTED));
             if (mTransactionalService != null) {
-                mTransactionalService.onDisconnect(this,
+                return mTransactionalService.onDisconnect(this,
                         new DisconnectCause(DisconnectCause.REJECTED));
             } else if (mConnectionService != null) {
+                if (mFlags.enableCallSequencing()) {
+                    rejectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "reject",
+                            CallState.DISCONNECTED);
+                }
                 mConnectionService.disconnect(this);
             } else {
                 Log.e(this, new NullPointerException(),
                         "reject call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT);
         } else if (isRinging("reject") || isAnswered("reject")) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, rejectReason);
             // Ensure video state history tracks video state at time of rejection.
             mVideoStateHistory |= mVideoState;
             if (mTransactionalService != null) {
-                mTransactionalService.onDisconnect(this,
+                return mTransactionalService.onDisconnect(this,
                         new DisconnectCause(DisconnectCause.REJECTED));
             } else if (mConnectionService != null) {
+                if (mFlags.enableCallSequencing()) {
+                    rejectFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "reject",
+                            CallState.DISCONNECTED);
+                }
                 mConnectionService.rejectWithReason(this, rejectReason);
             } else {
                 Log.e(this, new NullPointerException(),
                         "reject call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_REJECT, rejectReason);
         }
+        return rejectFutureHandler;
     }
 
     /**
@@ -3151,41 +3227,57 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      * Puts the call on hold if it is currently active.
      */
     @VisibleForTesting
-    public void hold() {
-        hold(null /* reason */);
+    public CompletableFuture<Boolean> hold() {
+        return hold(null /* reason */);
     }
 
     /**
      * This method requests the ConnectionService or TransactionalService hosting the call to put
      * the call on hold
      */
-    public void hold(String reason) {
+    public CompletableFuture<Boolean> hold(String reason) {
+        CompletableFuture<Boolean> holdFutureHandler = CompletableFuture.completedFuture(false);
         if (mState == CallState.ACTIVE) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_HOLD, reason);
             if (mTransactionalService != null) {
-                mTransactionalService.onSetInactive(this);
+                return mTransactionalService.onSetInactive(this);
             } else if (mConnectionService != null) {
-                if (mFlags.transactionalCsVerifier()) {
-                    awaitCallStateChangeAndMaybeDisconnectCall(CallState.ON_HOLD, isSelfManaged(),
-                            "hold");
+                if (mFlags.transactionalCsVerifier() || mFlags.enableCallSequencing()) {
+                    holdFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(isSelfManaged(),
+                            "hold", CallState.ON_HOLD, CallState.DISCONNECTED).thenCompose(
+                                    (result) -> {
+                                        // Explicitly handle self-managed hold failures where we
+                                        // explicitly disconnect the call and treat it as a
+                                        // completed transaction.
+                                        if (!result && isSelfManaged()) {
+                                            Log.i(this, "hold: Completing transaction "
+                                                    + "after disconnecting held call.");
+                                            return CompletableFuture.completedFuture(true);
+                                        }
+                                        return CompletableFuture.completedFuture(result);
+                                    });;
                 }
                 mConnectionService.hold(this);
+                return holdFutureHandler;
             } else {
                 Log.e(this, new NullPointerException(),
                         "hold call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_HOLD, reason);
         }
+        return holdFutureHandler;
     }
 
     /**
      * helper that can be used for any callback that requests a call state change and wants to
      * verify the change
      */
-    public void awaitCallStateChangeAndMaybeDisconnectCall(int targetCallState,
-            boolean shouldDisconnectUponTimeout, String callingMethod) {
+    public CompletableFuture<Boolean> awaitCallStateChangeAndMaybeDisconnectCall(
+            boolean shouldDisconnectUponTimeout, String callingMethod, int... targetCallStates) {
         TransactionManager tm = TransactionManager.getInstance();
-        tm.addTransaction(new VerifyCallStateChangeTransaction(mCallsManager.getLock(),
-                this, targetCallState), new OutcomeReceiver<>() {
+        CallTransaction callTransaction = new VerifyCallStateChangeTransaction(
+                mCallsManager.getLock(), this, targetCallStates);
+        return tm.addTransaction(callTransaction,
+                new OutcomeReceiver<>() {
             @Override
             public void onResult(CallTransactionResult result) {
                 Log.i(this, "awaitCallStateChangeAndMaybeDisconnectCall: %s: onResult:"
@@ -3210,22 +3302,29 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      * Releases the call from hold if it is currently active.
      */
     @VisibleForTesting
-    public void unhold() {
-        unhold(null /* reason */);
+    public CompletableFuture<Boolean> unhold() {
+        return unhold(null /* reason */);
     }
 
-    public void unhold(String reason) {
+    public CompletableFuture<Boolean> unhold(String reason) {
+        CompletableFuture<Boolean> unholdFutureHandler = CompletableFuture.completedFuture(false);
         if (mState == CallState.ON_HOLD) {
+            Log.addEvent(this, LogUtils.Events.REQUEST_UNHOLD, reason);
             if (mTransactionalService != null){
-                mTransactionalService.onSetActive(this);
+                return mTransactionalService.onSetActive(this);
             } else if (mConnectionService != null){
+                if (mFlags.enableCallSequencing()) {
+                    unholdFutureHandler = awaitCallStateChangeAndMaybeDisconnectCall(
+                            false /* shouldDisconnectUponTimeout */, "unhold", CallState.ACTIVE);
+                }
                 mConnectionService.unhold(this);
+                return unholdFutureHandler;
             } else {
                 Log.e(this, new NullPointerException(),
                         "unhold call failed due to null CS callId=%s", getId());
             }
-            Log.addEvent(this, LogUtils.Events.REQUEST_UNHOLD, reason);
         }
+        return unholdFutureHandler;
     }
 
     /** Checks if this is a live call or not. */
@@ -3325,6 +3424,13 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
             }
         }
 
+        if (extras.containsKey(Connection.EXTRA_ANSWERING_DROPS_FG_CALL)) {
+            CharSequence appName =
+                    extras.getCharSequence(Connection.EXTRA_ANSWERING_DROPS_FG_CALL_APP_NAME);
+            Log.addEvent(this, LogUtils.Events.ANSWER_DROPS_FG,
+                    "Answering will drop FG call from %s", appName);
+        }
+
         // The remote connection service API can track the phone account which was originally
         // requested to create a connection via the remote connection service API; we store that so
         // we have some visibility into how a call was actually placed.
@@ -4230,6 +4336,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         }
 
         if (VideoProfile.isVideo(videoState)) {
+            mHasVideoCall = true;
             mAnalytics.setCallIsVideo(true);
         }
     }
@@ -4441,6 +4548,10 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
             for (Listener l : mListeners) {
                 l.onCallSwitchFailed(this);
             }
+        } else if (Connection.EVENT_CALL_RESUME_FAILED.equals(event)) {
+            for (Listener l : mListeners) {
+                l.onCallResumeFailed(this);
+            }
         } else if (Connection.EVENT_DEVICE_TO_DEVICE_MESSAGE.equals(event)
                 && extras != null && extras.containsKey(
                 Connection.EXTRA_DEVICE_TO_DEVICE_MESSAGE_TYPE)
@@ -4993,4 +5104,33 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
             }
         }
     }
+
+    public void setSimultaneousType(int simultaneousType) {
+        mSimultaneousType = simultaneousType;
+    }
+
+    public int getSimultaneousType() {
+        return mSimultaneousType;
+    }
+
+    public boolean hasVideoCall() {
+        return mHasVideoCall;
+    }
+
+    /**
+     * Used only for call sequencing for cases when we may end up auto-unholding the held call while
+     * processing an outgoing (emergency) call. We want to refrain from unholding the held call so
+     * that we don't end up with two active calls. Once the outgoing call is disconnected (either
+     * from a successful disconnect by the user or a failed call), the auto-unhold logic will be
+     * triggered again and successfully unhold the held call at that point. Note, that this only
+     * applies to non-holdable phone accounts (i.e. Verizon). Refer to
+     * {@link CallsManagerCallSequencingAdapter#maybeMoveHeldCallToForeground} for details.
+     */
+    public void setSkipAutoUnhold(boolean result) {
+        mSkipAutoUnhold = result;
+    }
+
+    public boolean getSkipAutoUnhold() {
+        return mSkipAutoUnhold;
+    }
 }
diff --git a/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java b/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
index 8d5f9fd77..7bd4dca57 100644
--- a/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
+++ b/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
@@ -144,7 +144,8 @@ public class CallAudioCommunicationDeviceTracker {
         boolean handleLeAudioDeviceSwitch = btDevice != null
                 && !btDevice.getAddress().equals(mBtAudioDevice);
         if ((audioDeviceType == mAudioDeviceType
-                || isUsbHeadsetType(audioDeviceType, mAudioDeviceType))
+                || isUsbHeadsetType(audioDeviceType, mAudioDeviceType)
+                || isSpeakerType(audioDeviceType, mAudioDeviceType))
                 && !handleLeAudioDeviceSwitch) {
             Log.i(this, "Communication device is already set for this audio type");
             return false;
@@ -161,7 +162,8 @@ public class CallAudioCommunicationDeviceTracker {
             Log.i(this, "Available device type: " + device.getType());
             // Ensure that we do not select the same BT LE audio device for communication.
             if ((audioDeviceType == device.getType()
-                    || isUsbHeadsetType(audioDeviceType, device.getType()))
+                    || isUsbHeadsetType(audioDeviceType, device.getType())
+                    || isSpeakerType(audioDeviceType, device.getType()))
                     && !device.getAddress().equals(mBtAudioDevice)) {
                 activeDevice = device;
                 break;
@@ -234,13 +236,15 @@ public class CallAudioCommunicationDeviceTracker {
                 audioDeviceType, isBtDevice);
 
         if (audioDeviceType != mAudioDeviceType
-                && !isUsbHeadsetType(audioDeviceType, mAudioDeviceType)) {
-            Log.i(this, "Unable to clear communication device of type(s), %s. "
-                            + "Device does not correspond to the locally requested device type.",
+                && !isUsbHeadsetType(audioDeviceType, mAudioDeviceType)
+                && !isSpeakerType(audioDeviceType, mAudioDeviceType)) {
+            Log.i(this, "Unable to clear communication device of type(s) %s. "
+                            + "Device does not correspond to the locally requested device type %s.",
                     audioDeviceType == AudioDeviceInfo.TYPE_WIRED_HEADSET
                             ? Arrays.asList(AudioDeviceInfo.TYPE_WIRED_HEADSET,
                             AudioDeviceInfo.TYPE_USB_HEADSET)
-                            : audioDeviceType
+                            : audioDeviceType,
+                    mAudioDeviceType
             );
             return;
         }
@@ -251,6 +255,7 @@ public class CallAudioCommunicationDeviceTracker {
         }
 
         // Clear device and reset locally saved device type.
+        Log.i(this, "clearCommunicationDevice: AudioManager#clearCommunicationDevice()");
         mAudioManager.clearCommunicationDevice();
         mAudioDeviceType = sAUDIO_DEVICE_TYPE_INVALID;
 
@@ -266,4 +271,11 @@ public class CallAudioCommunicationDeviceTracker {
         return audioDeviceType == AudioDeviceInfo.TYPE_WIRED_HEADSET
                 && sourceType == AudioDeviceInfo.TYPE_USB_HEADSET;
     }
+
+    private boolean isSpeakerType(@AudioDeviceInfo.AudioDeviceType int audioDeviceType,
+        @AudioDeviceInfo.AudioDeviceType int sourceType) {
+        if (!Flags.busDeviceIsASpeaker()) return false;
+        return audioDeviceType == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER
+                && sourceType == AudioDeviceInfo.TYPE_BUS;
+    }
 }
diff --git a/src/com/android/server/telecom/CallAudioModeStateMachine.java b/src/com/android/server/telecom/CallAudioModeStateMachine.java
index e149bdd9b..d1fd56434 100644
--- a/src/com/android/server/telecom/CallAudioModeStateMachine.java
+++ b/src/com/android/server/telecom/CallAudioModeStateMachine.java
@@ -334,9 +334,15 @@ public class CallAudioModeStateMachine extends StateMachine {
                     mAudioManager.abandonAudioFocusForCall();
                     // Clear requested communication device after the call ends.
                     if (mFeatureFlags.clearCommunicationDeviceAfterAudioOpsComplete()) {
-                        mCommunicationDeviceTracker.clearCommunicationDevice(
-                                mCommunicationDeviceTracker
-                                        .getCurrentLocallyRequestedCommunicationDevice());
+                        // Oh flags!  If we're using the refactored audio route switching, we should
+                        // not be using the communication device tracker; that is exclusively for
+                        // the old code path.
+                        if (!mFeatureFlags.dontUseCommunicationDeviceTracker()
+                                || !mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+                            mCommunicationDeviceTracker.clearCommunicationDevice(
+                                    mCommunicationDeviceTracker
+                                            .getCurrentLocallyRequestedCommunicationDevice());
+                        }
                     }
                     return HANDLED;
                 default:
diff --git a/src/com/android/server/telecom/CallAudioRouteController.java b/src/com/android/server/telecom/CallAudioRouteController.java
index 6b7bbf0a4..727b9ce43 100644
--- a/src/com/android/server/telecom/CallAudioRouteController.java
+++ b/src/com/android/server/telecom/CallAudioRouteController.java
@@ -37,6 +37,7 @@ import android.media.IAudioService;
 import android.media.audiopolicy.AudioProductStrategy;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.os.Looper;
 import android.os.Message;
 import android.os.RemoteException;
 import android.telecom.CallAudioState;
@@ -65,6 +66,7 @@ import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
+import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
 
@@ -116,10 +118,14 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private FeatureFlags mFeatureFlags;
     private int mFocusType;
     private int mCallSupportedRouteMask = -1;
-    private boolean mIsScoAudioConnected;
+    private BluetoothDevice mScoAudioConnectedDevice;
     private boolean mAvailableRoutesUpdated;
+    private boolean mUsePreferredDeviceStrategy;
+    private AudioDeviceInfo mCurrentCommunicationDevice;
     private final Object mLock = new Object();
     private final TelecomSystem.SyncRoot mTelecomLock;
+    private CountDownLatch mAudioOperationsCompleteLatch;
+    private CountDownLatch mAudioActiveCompleteLatch;
     private final BroadcastReceiver mSpeakerPhoneChangeReceiver = new BroadcastReceiver() {
         @Override
         public void onReceive(Context context, Intent intent) {
@@ -127,7 +133,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             try {
                 if (AudioManager.ACTION_SPEAKERPHONE_STATE_CHANGED.equals(intent.getAction())) {
                     if (mAudioManager != null) {
-                        AudioDeviceInfo info = mAudioManager.getCommunicationDevice();
+                        AudioDeviceInfo info = mFeatureFlags.updatePreferredAudioDeviceLogic()
+                                ? getCurrentCommunicationDevice()
+                                : mAudioManager.getCommunicationDevice();
                         if ((info != null) &&
                                 (info.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER)) {
                             if (mCurrentRoute.getType() != AudioRoute.TYPE_SPEAKER) {
@@ -180,6 +188,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private boolean mIsMute;
     private boolean mIsPending;
     private boolean mIsActive;
+    private boolean mWasOnSpeaker;
     private final TelecomMetricsController mMetricsController;
 
     public CallAudioRouteController(
@@ -200,10 +209,16 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mFeatureFlags = featureFlags;
         mMetricsController = metricsController;
         mFocusType = NO_FOCUS;
-        mIsScoAudioConnected = false;
+        mScoAudioConnectedDevice = null;
+        mUsePreferredDeviceStrategy = true;
+        mWasOnSpeaker = false;
+        setCurrentCommunicationDevice(null);
+
         mTelecomLock = callsManager.getLock();
         HandlerThread handlerThread = new HandlerThread(this.getClass().getSimpleName());
-        handlerThread.start();
+        if (!mFeatureFlags.callAudioRoutingPerformanceImprovemenent()) {
+            handlerThread.start();
+        }
 
         // Register broadcast receivers
         if (!mFeatureFlags.newAudioPathSpeakerBroadcastAndUnfocusedRouting()) {
@@ -229,11 +244,11 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mCommunicationDeviceListener = new AudioManager.OnCommunicationDeviceChangedListener() {
             @Override
             public void onCommunicationDeviceChanged(AudioDeviceInfo device) {
-                @AudioRoute.AudioRouteType int audioType = device != null
-                        ? DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(device.getType())
-                        : TYPE_INVALID;
-                Log.i(this, "onCommunicationDeviceChanged: %d", audioType);
-                if (device != null && device.getType() == AudioDeviceInfo.TYPE_BUILTIN_SPEAKER) {
+                @AudioRoute.AudioRouteType int audioType = getAudioType(device);
+                setCurrentCommunicationDevice(device);
+                Log.i(this, "onCommunicationDeviceChanged: device (%s), audioType (%d)",
+                        device, audioType);
+                if (audioType == TYPE_SPEAKER) {
                     if (mCurrentRoute.getType() != TYPE_SPEAKER) {
                         sendMessageWithSessionInfo(SPEAKER_ON);
                     }
@@ -243,8 +258,11 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             }
         };
 
+        Looper looper = mFeatureFlags.callAudioRoutingPerformanceImprovemenent()
+                ? Looper.getMainLooper()
+                : handlerThread.getLooper();
         // Create handler
-        mHandler = new Handler(handlerThread.getLooper()) {
+        mHandler = new Handler(looper) {
             @Override
             public void handleMessage(@NonNull Message msg) {
                 synchronized (this) {
@@ -290,16 +308,16 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                             break;
                         case SWITCH_EARPIECE:
                         case USER_SWITCH_EARPIECE:
-                            handleSwitchEarpiece();
+                            handleSwitchEarpiece(msg.what == USER_SWITCH_EARPIECE);
                             break;
                         case SWITCH_BLUETOOTH:
                         case USER_SWITCH_BLUETOOTH:
                             address = (String) ((SomeArgs) msg.obj).arg2;
-                            handleSwitchBluetooth(address);
+                            handleSwitchBluetooth(address, msg.what == USER_SWITCH_BLUETOOTH);
                             break;
                         case SWITCH_HEADSET:
                         case USER_SWITCH_HEADSET:
-                            handleSwitchHeadset();
+                            handleSwitchHeadset(msg.what == USER_SWITCH_HEADSET);
                             break;
                         case SWITCH_SPEAKER:
                         case USER_SWITCH_SPEAKER:
@@ -343,6 +361,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                         case MUTE_EXTERNALLY_CHANGED:
                             handleMuteChanged(mAudioManager.isMicrophoneMute());
                             break;
+                        case TOGGLE_MUTE:
+                            handleMuteChanged(!mIsMute);
+                            break;
                         case SWITCH_FOCUS:
                             focus = msg.arg1;
                             handleEndTone = (int) ((SomeArgs) msg.obj).arg2;
@@ -437,6 +458,12 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         } else {
             mCurrentRoute = DUMMY_ROUTE;
         }
+        // Audio ops will only ever be completed if there's a call placed and it gains
+        // ACTIVE/RINGING focus, hence why the initial value is 0.
+        mAudioOperationsCompleteLatch = new CountDownLatch(0);
+        // This latch will be count down when ACTIVE/RINGING focus is gained. This is determined
+        // when the routing goes active.
+        mAudioActiveCompleteLatch = new CountDownLatch(1);
         mIsActive = false;
         mCallAudioState = new CallAudioState(mIsMute, ROUTE_MAP.get(mCurrentRoute.getType()),
                 supportMask, null, new HashSet<>());
@@ -543,7 +570,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         return mIsPending;
     }
 
-    private void routeTo(boolean active, AudioRoute destRoute) {
+    private void routeTo(boolean isDestRouteActive, AudioRoute destRoute) {
         if (destRoute == null || (!destRoute.equals(mStreamingRoute)
                 && !getCallSupportedRoutes().contains(destRoute))) {
             Log.i(this, "Ignore routing to unavailable route: %s", destRoute);
@@ -553,39 +580,54 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             }
             return;
         }
+        // If another BT device connects during RINGING_FOCUS, in-band ringing will be disabled by
+        // default. In this case, we should adjust the active routing value so that we don't try
+        // to connect to the BT device as it will fail.
+        isDestRouteActive = maybeAdjustActiveRouting(destRoute, isDestRouteActive);
+        // It's possible that there are multiple HFP devices connected and if we receive SCO audio
+        // connected for the destination route's BT device, then we shouldn't disconnect SCO when
+        // clearing the communication device for the original route if it was also a HFP device.
+        // This does not apply to the route deactivation scenario.
+        boolean isScoDeviceAlreadyConnected = mScoAudioConnectedDevice != null && isDestRouteActive
+                && Objects.equals(mScoAudioConnectedDevice, mBluetoothRoutes.get(destRoute));
         if (mIsPending) {
-            if (destRoute.equals(mPendingAudioRoute.getDestRoute()) && (mIsActive == active)) {
+            if (destRoute.equals(mPendingAudioRoute.getDestRoute())
+                    && (mIsActive == isDestRouteActive)) {
                 return;
             }
             Log.i(this, "Override current pending route destination from %s(active=%b) to "
                             + "%s(active=%b)",
-                    mPendingAudioRoute.getDestRoute(), mIsActive, destRoute, active);
+                    mPendingAudioRoute.getDestRoute(), mIsActive, destRoute, isDestRouteActive);
             // Ensure we don't keep waiting for SPEAKER_ON if dest route gets overridden.
-            if (!mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue() && active
+            if (!mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue() && isDestRouteActive
                     && mPendingAudioRoute.getDestRoute().getType() == TYPE_SPEAKER) {
                 mPendingAudioRoute.clearPendingMessage(new Pair<>(SPEAKER_ON, null));
             }
             // override pending route while keep waiting for still pending messages for the
             // previous pending route
-            mPendingAudioRoute.setOrigRoute(mIsActive, mPendingAudioRoute.getDestRoute());
+            mPendingAudioRoute.setOrigRoute(mIsActive /* origin */,
+                    mPendingAudioRoute.getDestRoute(), isDestRouteActive /* dest */,
+                    isScoDeviceAlreadyConnected);
         } else {
-            if (mCurrentRoute.equals(destRoute) && (mIsActive == active)) {
+            if (mCurrentRoute.equals(destRoute) && (mIsActive == isDestRouteActive)) {
                 return;
             }
             Log.i(this, "Enter pending route, orig%s(active=%b), dest%s(active=%b)", mCurrentRoute,
-                    mIsActive, destRoute, active);
+                    mIsActive, destRoute, isDestRouteActive);
             // route to pending route
             if (getCallSupportedRoutes().contains(mCurrentRoute)) {
-                mPendingAudioRoute.setOrigRoute(mIsActive, mCurrentRoute);
+                mPendingAudioRoute.setOrigRoute(mIsActive /* origin */, mCurrentRoute,
+                        isDestRouteActive /* dest */, isScoDeviceAlreadyConnected);
             } else {
                 // Avoid waiting for pending messages for an unavailable route
-                mPendingAudioRoute.setOrigRoute(mIsActive, DUMMY_ROUTE);
+                mPendingAudioRoute.setOrigRoute(mIsActive /* origin */, DUMMY_ROUTE,
+                        isDestRouteActive /* dest */, isScoDeviceAlreadyConnected);
             }
             mIsPending = true;
         }
-        mPendingAudioRoute.setDestRoute(active, destRoute, mBluetoothRoutes.get(destRoute),
-                mIsScoAudioConnected);
-        mIsActive = active;
+        mPendingAudioRoute.setDestRoute(isDestRouteActive, destRoute,
+                mBluetoothRoutes.get(destRoute), isScoDeviceAlreadyConnected);
+        mIsActive = isDestRouteActive;
         mPendingAudioRoute.evaluatePendingState();
         if (mFeatureFlags.telecomMetricsSupport()) {
             mMetricsController.getAudioRouteStats().onRouteEnter(mPendingAudioRoute);
@@ -623,16 +665,37 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             updateAvailableRoutes(wiredHeadsetRoute, false);
             mEarpieceWiredRoute = null;
         }
-        AudioRoute earpieceRoute = mTypeRoutes.get(AudioRoute.TYPE_EARPIECE);
+        AudioRoute earpieceRoute = null;
+        try {
+            earpieceRoute = mTypeRoutes.get(AudioRoute.TYPE_EARPIECE) == null
+                ? mAudioRouteFactory.create(AudioRoute.TYPE_EARPIECE, null,
+                    mAudioManager)
+                : mTypeRoutes.get(AudioRoute.TYPE_EARPIECE);
+        } catch (IllegalArgumentException e) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_AUDIO,
+                        ErrorStats.ERROR_EXTERNAL_EXCEPTION);
+            }
+            Log.e(this, e, "Can't find available audio device info for route type:"
+                    + AudioRoute.DEVICE_TYPE_STRINGS.get(AudioRoute.TYPE_EARPIECE));
+        }
         if (earpieceRoute != null) {
             updateAvailableRoutes(earpieceRoute, true);
             mEarpieceWiredRoute = earpieceRoute;
+            // In the case that the route was never created, ensure that we update the map.
+            mTypeRoutes.putIfAbsent(AudioRoute.TYPE_EARPIECE, mEarpieceWiredRoute);
         }
         onAvailableRoutesChanged();
 
         // Route to expected state
         if (mCurrentRoute.equals(wiredHeadsetRoute)) {
-            routeTo(mIsActive, getBaseRoute(true, null));
+            // Preserve speaker routing if it was the last audio routing path when the wired headset
+            // disconnects. Ignore this special cased routing when the route isn't active
+            // (in other words, when we're not in a call).
+            AudioRoute route = mWasOnSpeaker && mIsActive && mSpeakerDockRoute != null
+                    && mSpeakerDockRoute.getType() == AudioRoute.TYPE_SPEAKER
+                    ? mSpeakerDockRoute : getBaseRoute(true, null);
+            routeTo(mIsActive, route);
         }
     }
 
@@ -797,13 +860,15 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private void handleBtActiveDevicePresent(@AudioRoute.AudioRouteType int type,
             String deviceAddress) {
         AudioRoute bluetoothRoute = getBluetoothRoute(type, deviceAddress);
-        if (bluetoothRoute != null) {
+        boolean isBtDeviceCurrentActive = Objects.equals(bluetoothRoute,
+                getArbitraryBluetoothDevice());
+        if (bluetoothRoute != null && isBtDeviceCurrentActive) {
             Log.i(this, "request to route to bluetooth route: %s (active=%b)", bluetoothRoute,
                     mIsActive);
             routeTo(mIsActive, bluetoothRoute);
         } else {
-            Log.i(this, "request to route to unavailable bluetooth route - type (%s), address (%s)",
-                    type, deviceAddress);
+            Log.i(this, "request to route to unavailable bluetooth route or the route isn't the "
+                    + "currently active device - type (%s), address (%s)", type, deviceAddress);
         }
     }
 
@@ -840,6 +905,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             }
         }
         if ((mIsPending && pendingRouteNeedsUpdate) || (!mIsPending && currentRouteNeedsUpdate)) {
+            maybeDisableWasOnSpeaker(true);
             // Fallback to an available route excluding the previously active device.
             routeTo(mIsActive, getBaseRoute(true, previouslyActiveDeviceAddress));
         }
@@ -874,6 +940,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mFocusType = focus;
         switch (focus) {
             case NO_FOCUS -> {
+                mWasOnSpeaker = false;
                 // Notify the CallAudioModeStateMachine that audio operations are complete so
                 // that we can relinquish audio focus.
                 mCallAudioManager.notifyAudioOperationsComplete();
@@ -890,6 +957,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 // Clear pending messages
                 mPendingAudioRoute.clearPendingMessages();
                 clearRingingBluetoothAddress();
+                mUsePreferredDeviceStrategy = true;
             }
             case ACTIVE_FOCUS -> {
                 // Route to active baseline route (we may need to change audio route in the case
@@ -907,6 +975,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                                     mCurrentRoute.getBluetoothAddress())
                             ? mCurrentRoute
                             : getBaseRoute(true, null);
+                    // Once we have processed active focus once during the call, we can ignore using
+                    // the preferred device strategy.
+                    mUsePreferredDeviceStrategy = false;
                     routeTo(true, audioRoute);
                     clearRingingBluetoothAddress();
                 }
@@ -917,7 +988,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     BluetoothDevice device = mBluetoothRoutes.get(route);
                     // Check if in-band ringtone is enabled for the device; if it isn't, move to
                     // inactive route.
-                    if (device != null && !mBluetoothRouteManager.isInbandRingEnabled(device)) {
+                    if (device != null && !mBluetoothRouteManager
+                            .isInbandRingEnabled(route.getType(), device)) {
                         routeTo(false, route);
                     } else {
                         routeTo(true, route);
@@ -925,7 +997,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 } else {
                     // Route is already active.
                     BluetoothDevice device = mBluetoothRoutes.get(mCurrentRoute);
-                    if (device != null && !mBluetoothRouteManager.isInbandRingEnabled(device)) {
+                    if (device != null && !mBluetoothRouteManager
+                            .isInbandRingEnabled(mCurrentRoute.getType(), device)) {
                         routeTo(false, mCurrentRoute);
                     }
                 }
@@ -933,16 +1006,17 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
     }
 
-    public void handleSwitchEarpiece() {
+    public void handleSwitchEarpiece(boolean isUserRequest) {
         AudioRoute earpieceRoute = mTypeRoutes.get(AudioRoute.TYPE_EARPIECE);
         if (earpieceRoute != null && getCallSupportedRoutes().contains(earpieceRoute)) {
+            maybeDisableWasOnSpeaker(isUserRequest);
             routeTo(mIsActive, earpieceRoute);
         } else {
             Log.i(this, "ignore switch earpiece request");
         }
     }
 
-    private void handleSwitchBluetooth(String address) {
+    private void handleSwitchBluetooth(String address, boolean isUserRequest) {
         Log.i(this, "handle switch to bluetooth with address %s", address);
         AudioRoute bluetoothRoute = null;
         BluetoothDevice bluetoothDevice = null;
@@ -960,9 +1034,11 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
 
         if (bluetoothRoute != null && bluetoothDevice != null) {
+            maybeDisableWasOnSpeaker(isUserRequest);
             if (mFocusType == RINGING_FOCUS) {
-                routeTo(mBluetoothRouteManager.isInbandRingEnabled(bluetoothDevice) && mIsActive,
-                        bluetoothRoute);
+                routeTo(mBluetoothRouteManager
+                                .isInbandRingEnabled(bluetoothRoute.getType(), bluetoothDevice)
+                                && mIsActive, bluetoothRoute);
                 mBluetoothAddressForRinging = bluetoothDevice.getAddress();
             } else {
                 routeTo(mIsActive, bluetoothRoute);
@@ -990,9 +1066,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
     }
 
-    private void handleSwitchHeadset() {
+    private void handleSwitchHeadset(boolean isUserRequest) {
         AudioRoute headsetRoute = mTypeRoutes.get(AudioRoute.TYPE_WIRED);
         if (headsetRoute != null && getCallSupportedRoutes().contains(headsetRoute)) {
+            maybeDisableWasOnSpeaker(isUserRequest);
             routeTo(mIsActive, headsetRoute);
         } else {
             Log.i(this, "ignore switch headset request");
@@ -1012,10 +1089,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             String btAddressToExclude) {
         Log.i(this, "handleSwitchBaselineRoute: includeBluetooth: %b, "
                 + "btAddressToExclude: %s", includeBluetooth, btAddressToExclude);
+        AudioRoute pendingDestRoute = mPendingAudioRoute.getDestRoute();
         boolean areExcludedBtAndDestBtSame = btAddressToExclude != null
-                && mPendingAudioRoute.getDestRoute() != null
-                && Objects.equals(btAddressToExclude, mPendingAudioRoute.getDestRoute()
-                .getBluetoothAddress());
+                && pendingDestRoute != null
+                && Objects.equals(btAddressToExclude, pendingDestRoute.getBluetoothAddress());
         Pair<Integer, String> btDevicePendingMsg =
                 new Pair<>(BT_AUDIO_CONNECTED, btAddressToExclude);
 
@@ -1023,8 +1100,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         // we know that the device has reconnected or is in the middle of connecting. Ignore routing
         // out of this BT device.
         boolean isExcludedDeviceConnectingOrConnected = areExcludedBtAndDestBtSame
-                && (mIsScoAudioConnected || mPendingAudioRoute.getPendingMessages()
-                .contains(btDevicePendingMsg));
+                && (Objects.equals(mBluetoothRoutes.get(pendingDestRoute), mScoAudioConnectedDevice)
+                || mPendingAudioRoute.getPendingMessages().contains(btDevicePendingMsg));
         // Check if the pending audio route or current route is already different from the route
         // including the BT device that should be excluded from route selection.
         boolean isCurrentOrDestRouteDifferent = btAddressToExclude != null
@@ -1042,6 +1119,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 return;
             }
         }
+        maybeDisableWasOnSpeaker(isExplicitUserRequest);
         routeTo(mIsActive, calculateBaselineRoute(isExplicitUserRequest, includeBluetooth,
                 btAddressToExclude));
     }
@@ -1095,6 +1173,26 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             mIsPending = false;
             mPendingAudioRoute.clearPendingMessages();
             onCurrentRouteChanged();
+            if (mIsActive) {
+                // Only set mWasOnSpeaker if the routing was active. We don't want to consider this
+                // selection outside of a call.
+                if (mCurrentRoute.getType() == TYPE_SPEAKER) {
+                    mWasOnSpeaker = true;
+                }
+                // Reinitialize the audio ops complete latch since the routing went active. We
+                // should always expect operations to complete after this point.
+                if (mAudioOperationsCompleteLatch.getCount() == 0) {
+                    mAudioOperationsCompleteLatch = new CountDownLatch(1);
+                }
+                mAudioActiveCompleteLatch.countDown();
+            } else {
+                // Reinitialize the active routing latch when audio ops are complete so that it can
+                // once again be processed when a new call is placed/received.
+                if (mAudioActiveCompleteLatch.getCount() == 0) {
+                    mAudioActiveCompleteLatch = new CountDownLatch(1);
+                }
+                mAudioOperationsCompleteLatch.countDown();
+            }
             if (mFeatureFlags.telecomMetricsSupport()) {
                 mMetricsController.getAudioRouteStats().onRouteExit(mPendingAudioRoute, true);
             }
@@ -1228,6 +1326,22 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         // Get corresponding audio route
         @AudioRoute.AudioRouteType int type = DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(
                 deviceAttr.getType());
+        AudioDeviceInfo currentCommunicationDevice = null;
+        if (mFeatureFlags.updatePreferredAudioDeviceLogic()) {
+            currentCommunicationDevice = getCurrentCommunicationDevice();
+        }
+        // We will default to TYPE_INVALID if the currentCommunicationDevice is null or the type
+        // cannot be resolved from the given audio device info.
+        int communicationDeviceAudioType = getAudioType(currentCommunicationDevice);
+        // Sync the preferred device strategy with the current communication device if there's a
+        // valid audio device output set as the preferred device strategy. This will address timing
+        // issues between updates made to the preferred device strategy. From the audio fwk
+        // standpoint, updates to the communication device take precedent to changes in the
+        // preferred device strategy so the former should be used as the source of truth.
+        if (type != TYPE_INVALID && communicationDeviceAudioType != TYPE_INVALID
+                && communicationDeviceAudioType != type) {
+            type = communicationDeviceAudioType;
+        }
         if (BT_AUDIO_ROUTE_TYPES.contains(type)) {
             return getBluetoothRoute(type, deviceAttr.getAddress());
         } else {
@@ -1285,11 +1399,14 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     ? mEarpieceWiredRoute
                     : mSpeakerDockRoute;
             // Ensure that we default to speaker route if we're in a video call, but disregard it if
-            // a wired headset is plugged in.
-            if (skipEarpiece && defaultRoute != null
+            // a wired headset is plugged in. Also consider the case when we're holding/unholding a
+            // call. If the route was on speaker mode, ensure that we preserve the route selection.
+            boolean shouldDefaultSpeaker = mFeatureFlags.maybeDefaultSpeakerAfterUnhold()
+                    && mWasOnSpeaker;
+            if ((skipEarpiece || shouldDefaultSpeaker) && defaultRoute != null
                     && defaultRoute.getType() == AudioRoute.TYPE_EARPIECE) {
                 Log.i(this, "getPreferredAudioRouteFromDefault: Audio routing defaulting to "
-                        + "speaker route for video call.");
+                        + "speaker route for (video) call.");
                 defaultRoute = mSpeakerDockRoute;
             }
             return defaultRoute;
@@ -1361,6 +1478,11 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     }
 
     public AudioRoute getBaseRoute(boolean includeBluetooth, String btAddressToExclude) {
+        // Catch-all case for all invocations to this method where we shouldn't be using
+        // getPreferredAudioRouteFromStrategy
+        if (mFeatureFlags.updatePreferredAudioDeviceLogic() && !mUsePreferredDeviceStrategy) {
+            return calculateBaselineRoute(false, includeBluetooth, btAddressToExclude);
+        }
         AudioRoute destRoute = getPreferredAudioRouteFromStrategy();
         Log.i(this, "getBaseRoute: preferred audio route is %s", destRoute);
         if (destRoute == null || (destRoute.getBluetoothAddress() != null && (!includeBluetooth
@@ -1514,15 +1636,16 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
 
     private boolean isLeAudioNonLeadDeviceOrServiceUnavailable(@AudioRoute.AudioRouteType int type,
             BluetoothDevice device) {
+        BluetoothLeAudio leAudioService = getLeAudioService();
         if (type != AudioRoute.TYPE_BLUETOOTH_LE) {
             return false;
-        } else if (getLeAudioService() == null) {
+        } else if (leAudioService == null) {
             return true;
         }
 
-        int groupId = getLeAudioService().getGroupId(device);
+        int groupId = leAudioService.getGroupId(device);
         if (groupId != BluetoothLeAudio.GROUP_ID_INVALID) {
-            BluetoothDevice leadDevice = getLeAudioService().getConnectedGroupLeadDevice(groupId);
+            BluetoothDevice leadDevice = leAudioService.getConnectedGroupLeadDevice(groupId);
             Log.i(this, "Lead device for device (%s) is %s.", device, leadDevice);
             return leadDevice == null || !device.getAddress().equals(leadDevice.getAddress());
         }
@@ -1551,8 +1674,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mIsPending = isPending;
     }
 
-    public void setIsScoAudioConnected(boolean value) {
-        mIsScoAudioConnected = value;
+    @VisibleForTesting
+    public void setScoAudioConnectedDevice(BluetoothDevice device) {
+        mScoAudioConnectedDevice = device;
     }
 
     private void clearRingingBluetoothAddress() {
@@ -1626,4 +1750,70 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE,
                 btAddressToExclude);
     }
+
+    public CountDownLatch getAudioOperationsCompleteLatch() {
+        return mAudioOperationsCompleteLatch;
+    }
+
+    public CountDownLatch getAudioActiveCompleteLatch() {
+        return mAudioActiveCompleteLatch;
+    }
+
+    private @AudioRoute.AudioRouteType int getAudioType(AudioDeviceInfo device) {
+        return device != null
+                ? DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.getOrDefault(
+                device.getType(), TYPE_INVALID)
+                : TYPE_INVALID;
+    }
+
+    @VisibleForTesting
+    public boolean getUsePreferredDeviceStrategy() {
+        return mUsePreferredDeviceStrategy;
+    }
+
+    @VisibleForTesting
+    public void setCurrentCommunicationDevice(AudioDeviceInfo device) {
+        synchronized (mLock) {
+            mCurrentCommunicationDevice = device;
+        }
+    }
+
+    public AudioDeviceInfo getCurrentCommunicationDevice() {
+        synchronized (mLock) {
+            return mCurrentCommunicationDevice;
+        }
+    }
+
+    private void maybeDisableWasOnSpeaker(boolean isUserRequest) {
+        if (isUserRequest) {
+            mWasOnSpeaker = false;
+        }
+    }
+
+    /*
+     * Adjusts routing to go inactive if we're active in the case that we're processing
+     * RINGING_FOCUS and another BT headset is connected which causes in-band ringing to get
+     * disabled. If we stay in active routing, Telecom will send requests to connect to these BT
+     * devices while the call is ringing and each of these requests will fail at the BT stack side.
+     * By default, in-band ringtone is disabled when more than one BT device is paired. Instead,
+     * ringtone is played using the headset's default ringtone.
+     */
+    private boolean maybeAdjustActiveRouting(AudioRoute destRoute, boolean isDestRouteActive) {
+        BluetoothDevice device = mBluetoothRoutes.get(destRoute);
+        // If routing is active and in-band ringing is disabled while the call is ringing, move to
+        // inactive routing.
+        if (isDestRouteActive && mFocusType == RINGING_FOCUS && device != null
+                && !mBluetoothRouteManager.isInbandRingEnabled(destRoute.getType(), device)) {
+            return false;
+        }
+        else if (!isDestRouteActive && mFocusType == RINGING_FOCUS && (device == null
+                || mBluetoothRouteManager.isInbandRingEnabled(destRoute.getType(), device))) {
+            // If the routing is inactive while the call is ringing and we re-evaluate this to find
+            // that we're routing to a non-BT device or a BT device that does support in-band
+            // ringing, then re-enable active routing (i.e. second HFP headset is disconnected
+            // while call is ringing).
+            return true;
+        }
+        return isDestRouteActive;
+    }
 }
diff --git a/src/com/android/server/telecom/CallAudioWatchdog.java b/src/com/android/server/telecom/CallAudioWatchdog.java
new file mode 100644
index 000000000..4ca237a3b
--- /dev/null
+++ b/src/com/android/server/telecom/CallAudioWatchdog.java
@@ -0,0 +1,705 @@
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
+ * limitations under the License
+ */
+
+package com.android.server.telecom;
+
+import static android.media.AudioPlaybackConfiguration.PLAYER_STATE_STARTED;
+
+import android.annotation.IntDef;
+import android.media.AudioAttributes;
+import android.media.AudioManager;
+import android.media.AudioManager.AudioPlaybackCallback;
+import android.media.AudioPlaybackConfiguration;
+import android.media.AudioRecord;
+import android.media.AudioRecordingConfiguration;
+import android.media.AudioTrack;
+import android.media.MediaRecorder;
+import android.os.Handler;
+import android.os.Process;
+import android.telecom.Log;
+import android.telecom.Logging.EventManager;
+import android.telecom.PhoneAccountHandle;
+import android.util.ArrayMap;
+import android.util.ArraySet;
+import android.util.LocalLog;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.internal.util.IndentingPrintWriter;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.text.SimpleDateFormat;
+import java.util.Collection;
+import java.util.Collections;
+import java.util.Date;
+import java.util.Iterator;
+import java.util.List;
+import java.util.Map;
+import java.util.Set;
+
+/**
+ * Monitors {@link AudioRecord}, {@link AudioTrack}, and {@link AudioManager#getMode()} to determine
+ * the reliability of audio operations for a call.  Augments the Telecom dumpsys with Telecom calls
+ * with information about calls.
+ */
+public class CallAudioWatchdog extends CallsManagerListenerBase {
+    /**
+     * Bit flag set on a {@link CommunicationSession#sessionAttr} to indicate that the session has
+     * audio recording resources.
+     */
+    public static final int SESSION_ATTR_HAS_AUDIO_RECORD = 1 << 0;
+
+    /**
+     * Bit flag set on a {@link CommunicationSession#sessionAttr} to indicate that the session has
+     * audio playback resources.
+     */
+    public static final int SESSION_ATTR_HAS_AUDIO_PLAYBACK = 1 << 1;
+
+    /**
+     * Bit flag set on a {@link CommunicationSession#sessionAttr} to indicate that the uid for the
+     * session has a phone account allocated.  This helps us track cases where an app is telecom
+     * capable but chooses not to use the telecom integration.
+     */
+    public static final int SESSION_ATTR_HAS_PHONE_ACCOUNT = 1 << 2;
+
+    @IntDef(prefix = { "SESSION_ATTR_" },
+            value = {SESSION_ATTR_HAS_AUDIO_RECORD, SESSION_ATTR_HAS_AUDIO_PLAYBACK,
+                    SESSION_ATTR_HAS_PHONE_ACCOUNT},
+            flag = true)
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface SessionAttribute {}
+
+    /**
+     * Proxy for operations related to phone accounts.
+     */
+    public interface PhoneAccountRegistrarProxy {
+        /**
+         * Determines if a specified {@code uid} has an associated phone account registered.
+         * @param uid the uid.
+         * @return {@code true} if there is a phone account registered, {@code false} otherwise
+         */
+        boolean hasPhoneAccountForUid(int uid);
+
+        /**
+         * Given a {@link PhoneAccountHandle} determines the uid for the app owning the account.
+         * @param handle The phone account; the phone account handle's package and userhandle are
+         *               ultimately used to find the associated uid.
+         * @return the uid for the phone account.
+         */
+        int getUidForPhoneAccountHandle(PhoneAccountHandle handle);
+    }
+
+    /**
+     * Keyed on uid, tracks a communication session and whether there are audio record and playback
+     * resources for that session.
+     */
+    public class CommunicationSession {
+        private int uid;
+        @SessionAttribute
+        private int sessionAttr;
+        private ArrayMap<Integer, Set<Integer>> audioResourcesByType = new ArrayMap<>();
+        private EventManager.Loggable telecomCall;
+        private long sessionStartMillis;
+        private long sessionStartClockMillis;
+
+        /**
+         * @return {@code true} if audio record or playback is held for the session, {@code false}
+         * otherwise.
+         */
+        public boolean hasMediaResources() {
+            return (getSessionAttr()
+                    & (SESSION_ATTR_HAS_AUDIO_RECORD | SESSION_ATTR_HAS_AUDIO_PLAYBACK)) != 0;
+        }
+
+        /**
+         * Sets a bit enabled for the session.
+         * @param bit the bit
+         */
+        public void setBit(@SessionAttribute int bit) {
+            setSessionAttr(getSessionAttr() | bit);
+        }
+
+        /**
+         * Clears the specified bit for the session.
+         * @param bit the bit
+         */
+        public void clearBit(@SessionAttribute int bit) {
+            setSessionAttr(getSessionAttr() & ~bit);
+        }
+
+        /**
+         * Determines if a bit is set in the given bitmask.
+         * @param mask the bitmask.
+         * @param bit The bit
+         * @return {@code true} if set, {@code false} otherwise.
+         */
+        public static boolean isBitSet(@SessionAttribute int mask, @SessionAttribute int bit) {
+            return (mask & bit) == bit;
+        }
+
+        /**
+         * Determines if a bit is set for the current session.
+         * @param bit The bit
+         * @return {@code true} if set, {@code false} otherwise.
+         */
+        public boolean isBitSet(@SessionAttribute int bit) {
+            return isBitSet(getSessionAttr(), bit);
+        }
+
+        /**
+         * Generate a string representing the session attributes bitmask, suitable for logging.
+         * @param attr The session attributes.
+         * @return String of bits!
+         */
+        public static String sessionAttrToString(@SessionAttribute int attr) {
+            return (isBitSet(attr, SESSION_ATTR_HAS_PHONE_ACCOUNT) ? "phac, " : "") +
+                    (isBitSet(attr, SESSION_ATTR_HAS_AUDIO_PLAYBACK) ? "ap, " : "") +
+                    (isBitSet(attr, SESSION_ATTR_HAS_AUDIO_RECORD) ? "ar, " : "");
+        }
+
+        @Override
+        public String toString() {
+            return "CommSess{" +
+                    "uid=" + getUid() +
+                    ", created=" + SimpleDateFormat.getDateTimeInstance().format(
+                    new Date(getSessionStartClockMillis())) +
+                    ", attr=" + sessionAttrToString(getSessionAttr()) +
+                    ", callId=" + (getTelecomCall() != null ? getTelecomCall().getId() : "none") +
+                    ", duration=" + (mClockProxy.elapsedRealtime() - getSessionStartMillis())/1000 +
+                    '}';
+        }
+
+        /**
+         * The uid for the session.
+         */
+        public int getUid() {
+            return uid;
+        }
+
+        public void setUid(int uid) {
+            this.uid = uid;
+        }
+
+        /**
+         * The attributes for the session.
+         */
+        public int getSessionAttr() {
+            return sessionAttr;
+        }
+
+        public void setSessionAttr(int sessionAttr) {
+            this.sessionAttr = sessionAttr;
+        }
+
+        /**
+         * ArrayMap, keyed by {@link #SESSION_ATTR_HAS_AUDIO_PLAYBACK} and
+         * {@link #SESSION_ATTR_HAS_AUDIO_RECORD}. For each, contains a set of the
+         * {@link AudioManager} ids associated with active playback and recording sessions for a
+         * uid.
+         *
+         * {@link AudioPlaybackConfiguration#getPlayerInterfaceId()} is used for audio playback;
+         * per docs, this is an identifier unique for the lifetime of the player.
+         *
+         * {@link AudioRecordingConfiguration#getClientAudioSessionId()} is used for audio record
+         * tracking; this is unique similar to the audio playback config.
+         */
+        public ArrayMap<Integer, Set<Integer>> getAudioResourcesByType() {
+            return audioResourcesByType;
+        }
+
+        public void setAudioResourcesByType(
+                ArrayMap<Integer, Set<Integer>> audioResourcesByType) {
+            this.audioResourcesByType = audioResourcesByType;
+        }
+
+        /**
+         * The Telecom call this session is associated with; set if the call takes place during a
+         * telecom call.
+         */
+        public EventManager.Loggable getTelecomCall() {
+            return telecomCall;
+        }
+
+        public void setTelecomCall(EventManager.Loggable telecomCall) {
+            this.telecomCall = telecomCall;
+        }
+
+        /**
+         * The time in {@link android.os.SystemClock#elapsedRealtime()} timebase when the session
+         * started.  Used only to determine duration.
+         */
+        public long getSessionStartMillis() {
+            return sessionStartMillis;
+        }
+
+        public void setSessionStartMillis(long sessionStartMillis) {
+            this.sessionStartMillis = sessionStartMillis;
+        }
+
+        /**
+         * The time in {@link System#currentTimeMillis()} timebase when the session started; used
+         * to indicate the wall block time when the session started.
+         */
+        public long getSessionStartClockMillis() {
+            return sessionStartClockMillis;
+        }
+
+        public void setSessionStartClockMillis(long sessionStartClockMillis) {
+            this.sessionStartClockMillis = sessionStartClockMillis;
+        }
+    }
+
+    /**
+     * Listener for AudioManager audio playback changes.  Finds audio playback tagged for voice
+     * communication.  Updates the {@link #mCommunicationSessions} based on this data to track if
+     * audio playback it taking place.
+     *
+     * Note: {@link AudioPlaybackCallback} reports information about audio playback for an app; if
+     * an app releases audio playback resources, the list of audio playback configurations no longer
+     * includes a {@link AudioPlaybackConfiguration} for that specific audio playback session.  This
+     * API semantic is why the code below is a bit confusing; in the listener we need to track all
+     * the ids we've seen and then correlate that back to what we knew about it from the last
+     * callback.
+     *
+     * An app may have MULTIPLE {@link AudioPlaybackConfiguration} for voip use-cases and switch
+     * between them for a single call -- this was observed in live app testing.
+     */
+    public class WatchdogAudioPlaybackCallback extends AudioPlaybackCallback {
+        @Override
+        public void onPlaybackConfigChanged(List<AudioPlaybackConfiguration> configs) {
+            Map<Integer,Set<Integer>> sessionIdentifiersByUid = new ArrayMap<>();
+            for (AudioPlaybackConfiguration config : configs) {
+                Log.d(this, "onPlaybackConfigChanged: config=%s", config);
+                // only track USAGE_VOICE_COMMUNICATION as this is for VOIP calls.
+                if (config.getAudioAttributes() != null
+                        && config.getAudioAttributes().getUsage()
+                        == AudioAttributes.USAGE_VOICE_COMMUNICATION) {
+
+                    // Skip if the client's pid is same as myself
+                    if (config.getClientPid() == Process.myPid()) {
+                        continue;
+                    }
+
+                    // If an audio session is idle, we don't count it as playing.  It must be in a
+                    // started state.
+                    boolean isPlaying = config.getPlayerState() == PLAYER_STATE_STARTED;
+
+                    maybeTrackAudioPlayback(config.getClientUid(), config.getPlayerInterfaceId(),
+                            isPlaying);
+                    if (isPlaying) {
+                        // Track the list of player id active for each uid; we use it later for
+                        // cleanup of stale sessions.
+                        putOrDefault(sessionIdentifiersByUid,config.getClientUid(),
+                                new ArraySet<>()).add(config.getPlayerInterfaceId());
+                    }
+                }
+            }
+
+            // The listener will drop uid/playerInterfaceIds no longer active, so we need to go back
+            // and see if any sessions need to be removed now.
+            cleanupAttributeForSessions(SESSION_ATTR_HAS_AUDIO_PLAYBACK,
+                    sessionIdentifiersByUid);
+        }
+    }
+
+    /**
+     * Similar to {@link WatchdogAudioPlaybackCallback}, tracks audio recording an app performs.
+     * This code is handling the onRecordingConfigChanged event from the AudioManager. The event
+     * is fired when the list of active recording configurations changes. In this case, the code
+     * is only interested in recording configurations that are using the VOICE_COMMUNICATION
+     * audio source. For these configurations, the code tracks the session identifiers and
+     * potentially adds them to the SESSION_ATTR_HAS_AUDIO_RECORD attribute. The code also cleans
+     * up the attribute for any sessions that are no longer active.
+     * The same caveat/note applies here; a single app can have many audio recording sessions that
+     * the app swaps between during a call.
+     */
+    public class WatchdogAudioRecordCallback extends AudioManager.AudioRecordingCallback {
+        @Override
+        public void onRecordingConfigChanged(List<AudioRecordingConfiguration> configs) {
+            List<AudioRecordingConfiguration> theConfigs =
+                    mAudioManager.getActiveRecordingConfigurations();
+            Map<Integer,Set<Integer>> sessionIdentifiersByUid = new ArrayMap<>();
+            for (AudioRecordingConfiguration config : theConfigs) {
+                if (config.getClientAudioSource()
+                        == MediaRecorder.AudioSource.VOICE_COMMUNICATION) {
+
+                    putOrDefault(sessionIdentifiersByUid, config.getClientUid(),
+                            new ArraySet<>()).add(config.getClientAudioSessionId());
+                    maybeTrackAudioRecord(config.getClientUid(), config.getClientAudioSessionId(),
+                            true);
+                }
+            }
+            // The listener stops reporting audio sessions that go away, so we need to clean up the
+            // session potentially.
+            cleanupAttributeForSessions(
+                    SESSION_ATTR_HAS_AUDIO_RECORD,
+                    sessionIdentifiersByUid);
+        }
+    }
+
+    // Proxies to make testing possible-ish.
+    private final ClockProxy mClockProxy;
+    private final PhoneAccountRegistrarProxy mPhoneAccountRegistrarProxy;
+
+    private final WatchdogAudioPlaybackCallback mWatchdogAudioPlayback =
+            new WatchdogAudioPlaybackCallback();
+    private final WatchdogAudioRecordCallback
+            mWatchdogAudioRecordCallack = new WatchdogAudioRecordCallback();
+    private final AudioManager mAudioManager;
+    private final Handler mHandler;
+
+    // Guards access to mCommunicationSessions.
+    private final Object mCommunicationSessionsLock = new Object();
+
+    /**
+     * Key - UID of communication app.
+     * Value - an instance of {@link CommunicationSession} tracking data for that uid.
+     */
+    private final Map<Integer, CommunicationSession> mCommunicationSessions = new ArrayMap<>();
+
+    // Local logs for tracking non-telecom calls.
+    private final LocalLog mLocalLog = new LocalLog(30);
+
+    private final TelecomMetricsController mMetricsController;
+
+    public CallAudioWatchdog(AudioManager audioManager,
+            PhoneAccountRegistrarProxy phoneAccountRegistrarProxy, ClockProxy clockProxy,
+            Handler handler, TelecomMetricsController metricsController) {
+        mPhoneAccountRegistrarProxy = phoneAccountRegistrarProxy;
+        mClockProxy = clockProxy;
+        mAudioManager = audioManager;
+        mHandler = handler;
+        mAudioManager.registerAudioPlaybackCallback(mWatchdogAudioPlayback, mHandler);
+        mAudioManager.registerAudioRecordingCallback(mWatchdogAudioRecordCallack, mHandler);
+        mMetricsController = metricsController;
+    }
+
+    /**
+     * Tracks Telecom adding a call; we use this to associate a uid's sessions with a call.
+     * Note: this is not 100% accurate if there are multiple calls -- we just associate with the
+     * first call and leave it at that.  It's not possible to know which audio sessions belong to
+     * which Telecom calls.
+     * @param call the Telecom call being added.
+     */
+    @Override
+    public void onCallAdded(Call call) {
+        // Only track for voip calls.
+        if (call.isSelfManaged() || call.isTransactionalCall()) {
+            maybeTrackTelecomCall(call);
+        }
+    }
+
+    @Override
+    public void onCallRemoved(Call call) {
+        // Only track for voip calls.
+        if (call.isSelfManaged() || call.isTransactionalCall()) {
+            maybeRemoveCall(call);
+        }
+    }
+
+    @VisibleForTesting
+    public WatchdogAudioPlaybackCallback getWatchdogAudioPlayback() {
+        return mWatchdogAudioPlayback;
+    }
+
+    @VisibleForTesting
+    public WatchdogAudioRecordCallback getWatchdogAudioRecordCallack() {
+        return mWatchdogAudioRecordCallack;
+    }
+
+    @VisibleForTesting
+    public Map<Integer, CommunicationSession> getCommunicationSessions() {
+        return mCommunicationSessions;
+    }
+
+    /**
+     * Include info on audio stuff in the telecom dumpsys.
+     * @param pw
+     */
+    void dump(IndentingPrintWriter pw) {
+        pw.println("CallAudioWatchdog:");
+        pw.increaseIndent();
+        pw.println("Active Sessions:");
+        pw.increaseIndent();
+        Collection<CommunicationSession> sessions;
+        synchronized (mCommunicationSessionsLock) {
+            sessions = mCommunicationSessions.values();
+        }
+        sessions.forEach(pw::println);
+        pw.decreaseIndent();
+        pw.println("Audio sessions Sessions:");
+        pw.increaseIndent();
+        mLocalLog.dump(pw);
+        pw.decreaseIndent();
+        pw.decreaseIndent();
+    }
+
+    /**
+     * Tracks audio playback for a uid.
+     * @param uid the uid of the app having audio back change.
+     * @param playerInterfaceId From {@link AudioPlaybackConfiguration#getPlayerInterfaceId()} (see
+     * {@link CommunicationSession#audioResourcesByType} for keying info).
+     * @param isPlaying {@code true} if audio is starting for the client.
+     */
+    private void maybeTrackAudioPlayback(int uid, int playerInterfaceId, boolean isPlaying) {
+        CommunicationSession session;
+        synchronized (mCommunicationSessionsLock) {
+            if (!isPlaying) {
+                // A session can start in an idle state and never go active; in this case we will
+                // not proactively add a new session; we'll just get one if it's already there.
+                // When the session goes active we can add it then.
+                session = getSession(uid);
+            } else {
+                // The playback is active, so we need to get or add a new communication session.
+                session = getOrAddSession(uid);
+            }
+        }
+        if (session == null) {
+            return;
+        }
+
+        // First track individual player interface id playing status.
+        if (isPlaying) {
+            putOrDefault(session.getAudioResourcesByType(), SESSION_ATTR_HAS_AUDIO_PLAYBACK,
+                    new ArraySet<>()).add(playerInterfaceId);
+        } else {
+            putOrDefault(session.getAudioResourcesByType(), SESSION_ATTR_HAS_AUDIO_PLAYBACK,
+                    new ArraySet<>()).remove(playerInterfaceId);
+        }
+
+        // Keep the bitmask up to date so that we have quicker access to the audio playback state.
+        int originalAttrs = session.getSessionAttr();
+        // If there are active audio playback clients, then the session has playback.
+        if (!session.getAudioResourcesByType().get(SESSION_ATTR_HAS_AUDIO_PLAYBACK).isEmpty()) {
+            session.setBit(SESSION_ATTR_HAS_AUDIO_PLAYBACK);
+        } else {
+            session.clearBit(SESSION_ATTR_HAS_AUDIO_PLAYBACK);
+        }
+
+        // If there was a change, log to a call if set.
+        if (originalAttrs != session.getSessionAttr() && session.getTelecomCall() != null) {
+            Log.addEvent(session.getTelecomCall(), LogUtils.Events.AUDIO_ATTR,
+                    CommunicationSession.sessionAttrToString(originalAttrs)
+                            + " -> " + CommunicationSession.sessionAttrToString(
+                            session.getSessionAttr()));
+        }
+        Log.d(this, "maybeTrackAudioPlayback: %s", session);
+    }
+
+    /**
+     * Similar to {@link #maybeTrackAudioPlayback(int, int, boolean)}, except tracks audio records
+     * for an app.
+     * @param uid the app uid.
+     * @param recordSessionID The recording session (per
+     * @param isRecording {@code true} if recording, {@code false} otherwise.
+     */
+    private void maybeTrackAudioRecord(int uid, int recordSessionID, boolean isRecording) {
+        synchronized (mCommunicationSessionsLock) {
+            CommunicationSession session = getOrAddSession(uid);
+
+            // First track individual recording status.
+            if (isRecording) {
+                putOrDefault(session.getAudioResourcesByType(), SESSION_ATTR_HAS_AUDIO_RECORD,
+                        new ArraySet<>()).add(recordSessionID);
+            } else {
+                putOrDefault(session.getAudioResourcesByType(), SESSION_ATTR_HAS_AUDIO_RECORD,
+                        new ArraySet<>()).remove(recordSessionID);
+            }
+
+            int originalAttrs = session.getSessionAttr();
+            if (!session.getAudioResourcesByType().get(SESSION_ATTR_HAS_AUDIO_RECORD).isEmpty()) {
+                session.setBit(SESSION_ATTR_HAS_AUDIO_RECORD);
+            } else {
+                session.clearBit(SESSION_ATTR_HAS_AUDIO_RECORD);
+            }
+
+            if (originalAttrs != session.getSessionAttr() && session.getTelecomCall() != null) {
+                Log.addEvent(session.getTelecomCall(), LogUtils.Events.AUDIO_ATTR,
+                        CommunicationSession.sessionAttrToString(originalAttrs)
+                        + " -> " + CommunicationSession.sessionAttrToString(
+                                session.getSessionAttr()));
+            }
+
+            Log.d(this, "maybeTrackAudioRecord: %s", session);
+        }
+    }
+
+    /**
+     * Given a new Telecom call, start a new session or annotate an existing one with this call.
+     * Helps to associated resources with a telecom call.
+     * @param call the call!
+     */
+    private void maybeTrackTelecomCall(Call call) {
+        int uid = mPhoneAccountRegistrarProxy.getUidForPhoneAccountHandle(
+                call.getTargetPhoneAccount());
+        CommunicationSession session;
+        synchronized (mCommunicationSessionsLock) {
+            session = getOrAddSession(uid);
+        }
+        session.setTelecomCall(call);
+        Log.d(this, "maybeTrackTelecomCall: %s", session);
+        Log.addEvent(session.getTelecomCall(), LogUtils.Events.AUDIO_ATTR,
+                CommunicationSession.sessionAttrToString(session.getSessionAttr()));
+    }
+
+    /**
+     * Given a telecom call, cleanup the session if there are no audio resources remaining for that
+     * session.
+     * @param call The call.
+     */
+    private void maybeRemoveCall(Call call) {
+        int uid = mPhoneAccountRegistrarProxy.getUidForPhoneAccountHandle(
+                call.getTargetPhoneAccount());
+        CommunicationSession session;
+        synchronized (mCommunicationSessionsLock) {
+            session = getSession(uid);
+            if (session == null) {
+                return;
+            }
+            if (!session.hasMediaResources()) {
+                mLocalLog.log(session.toString());
+                maybeLogMetrics(session);
+                mCommunicationSessions.remove(uid);
+            }
+        }
+    }
+
+    /**
+     * Returns an existing session for a uid, or {@code null} if none exists.
+     * @param uid the uid,
+     * @return The session found, or {@code null}.
+     */
+    private CommunicationSession getSession(int uid) {
+        return mCommunicationSessions.get(uid);
+    }
+
+    /**
+     * Locates an existing session for the specified uid or creates a new one.
+     * @param uid the uid
+     * @return The session.
+     */
+    private CommunicationSession getOrAddSession(int uid) {
+        CommunicationSession session = mCommunicationSessions.get(uid);
+        if (session != null) {
+            Log.i(this, "getOrAddSession: uid=%d, ex, %s", uid, session);
+            return session;
+        } else {
+            CommunicationSession newSession = new CommunicationSession();
+            newSession.setSessionStartMillis(mClockProxy.elapsedRealtime());
+            newSession.setSessionStartClockMillis(mClockProxy.currentTimeMillis());
+            newSession.setUid(uid);
+            if (mPhoneAccountRegistrarProxy.hasPhoneAccountForUid(uid)) {
+                newSession.setBit(SESSION_ATTR_HAS_PHONE_ACCOUNT);
+            }
+            mCommunicationSessions.put(uid, newSession);
+            Log.i(this, "getOrAddSession: uid=%d, new, %s", uid, newSession);
+            return newSession;
+        }
+    }
+
+    /**
+     * This method is used to cleanup any playback or recording sessions that may have went away
+     * after the {@link AudioPlaybackConfiguration} or {@link AudioRecordingConfiguration} updates.
+     *
+     * {@link CommunicationSession#audioResourcesByType} is keyed by
+     * {@link #SESSION_ATTR_HAS_AUDIO_RECORD} and {@link #SESSION_ATTR_HAS_AUDIO_PLAYBACK} and
+     * contains a list of each of the record or playback sessions we've been tracking.
+     *
+     * @param bit the type of resources to cleanup.
+     * @param sessionsByUid A map, keyed on uid of the set of play or record ids that were provided
+     *                      in the most recent {@link AudioPlaybackConfiguration} or
+     *                      {@link AudioRecordingConfiguration} update.
+     */
+    private void cleanupAttributeForSessions(int bit, Map<Integer, Set<Integer>> sessionsByUid) {
+        synchronized (mCommunicationSessionsLock) {
+            // Use an iterator so we can do in-place removal.
+            Iterator<Map.Entry<Integer, CommunicationSession>> iterator =
+                    mCommunicationSessions.entrySet().iterator();
+
+            // Lets loop through all the uids we're tracking and see that they still have an audio
+            // resource of type {@code bit} in {@code sessionsByUid}.
+            while (iterator.hasNext()) {
+                Map.Entry<Integer, CommunicationSession> next = iterator.next();
+                int existingUid = next.getKey();
+                CommunicationSession session = next.getValue();
+
+                // Get the set of sessions for this type, or emptyset if none present.
+                Set<Integer> sessionsForThisUid = sessionsByUid.getOrDefault(existingUid,
+                        Collections.emptySet());
+
+                // Update the known sessions of this resource type in the CommunicationSession.
+                Set<Integer> trackedSessions = putOrDefault(session.getAudioResourcesByType(), bit,
+                        new ArraySet<>());
+                trackedSessions.clear();
+                trackedSessions.addAll(sessionsForThisUid);
+
+                // Set or unset the bit in the bitmask for quicker access.
+                if (!trackedSessions.isEmpty()) {
+                    session.setBit(bit);
+                } else {
+                    session.clearBit(bit);
+                }
+
+                // If audio resources are no longer held for a uid, then we'll clean up its
+                // media session.
+                if (!session.hasMediaResources() && session.getTelecomCall() == null) {
+                    Log.i(this, "cleanupAttributeForSessions: removing session %s", session);
+                    mLocalLog.log(session.toString());
+                    maybeLogMetrics(session);
+                    iterator.remove();
+                }
+            }
+        }
+    }
+
+    /**
+     * Generic method to put a key value to a map and set to a default it not found, in both cases
+     * returning the value.
+     *
+     * This is a concession due to the fact that {@link Map#putIfAbsent(Object, Object)} returns
+     * null if the default is set. 🙄
+     *
+     * @param map The map.
+     * @param key The key to find.
+     * @param theDefault The default value for the key to use and return if nothing found.
+     * @return The existing key value or the default after adding.
+     * @param <K> The map key
+     * @param <V> The map value
+     */
+    private <K,V> V putOrDefault(Map<K,V> map, K key, V theDefault) {
+        if (map.containsKey(key)) {
+            return map.get(key);
+        }
+
+        map.put(key, theDefault);
+        return theDefault;
+    }
+
+    /**
+     * If this call has no associated Telecom {@link Call} and metrics are enabled, log this as a
+     * non-telecom call.
+     * @param session the session to log.
+     */
+    private void maybeLogMetrics(CommunicationSession session) {
+        if (mMetricsController != null && session.getTelecomCall() == null) {
+            mMetricsController.getCallStats().onNonTelecomCallEnd(
+                    session.isBitSet(SESSION_ATTR_HAS_PHONE_ACCOUNT),
+                    session.getUid(),
+                    mClockProxy.elapsedRealtime() - session.getSessionStartMillis());
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/CallsManager.java b/src/com/android/server/telecom/CallsManager.java
index 22b28b5da..f959c5272 100644
--- a/src/com/android/server/telecom/CallsManager.java
+++ b/src/com/android/server/telecom/CallsManager.java
@@ -27,6 +27,8 @@ import static android.provider.CallLog.Calls.USER_MISSED_NEVER_RANG;
 import static android.provider.CallLog.Calls.USER_MISSED_NOT_RUNNING;
 import static android.provider.CallLog.Calls.USER_MISSED_NO_ANSWER;
 import static android.provider.CallLog.Calls.USER_MISSED_SHORT_RING;
+import static android.telecom.CallAttributes.DIRECTION_INCOMING;
+import static android.telecom.CallAttributes.DIRECTION_OUTGOING;
 import static android.telecom.TelecomManager.ACTION_POST_CALL;
 import static android.telecom.TelecomManager.DURATION_LONG;
 import static android.telecom.TelecomManager.DURATION_MEDIUM;
@@ -40,6 +42,7 @@ import static android.telecom.TelecomManager.SHORT_CALL_TIME_MS;
 import static android.telecom.TelecomManager.VERY_SHORT_CALL_TIME_MS;
 
 import android.Manifest;
+import android.annotation.IntDef;
 import android.annotation.NonNull;
 import android.annotation.Nullable;
 import android.app.ActivityManager;
@@ -54,6 +57,7 @@ import android.content.DialogInterface;
 import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.pm.PackageManager;
+import android.content.pm.PackageManager.NameNotFoundException;
 import android.content.pm.PackageManager.ResolveInfoFlags;
 import android.content.pm.ResolveInfo;
 import android.content.pm.UserInfo;
@@ -132,6 +136,8 @@ import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
 import com.android.server.telecom.callfiltering.IncomingCallFilterGraphProvider;
 import com.android.server.telecom.callredirection.CallRedirectionProcessor;
 import com.android.server.telecom.callsequencing.CallSequencingController;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.voip.IncomingCallTransaction;
 import com.android.server.telecom.components.ErrorDialogActivity;
 import com.android.server.telecom.components.TelecomBroadcastReceiver;
 import com.android.server.telecom.callsequencing.CallsManagerCallSequencingAdapter;
@@ -148,7 +154,10 @@ import com.android.server.telecom.ui.IncomingCallNotifier;
 import com.android.server.telecom.ui.ToastFactory;
 import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
 import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.voip.VoipCallMonitorLegacy;
 
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
 import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.Collection;
@@ -183,6 +192,23 @@ import java.util.stream.Stream;
  */
 public class CallsManager extends Call.ListenerBase
         implements VideoProviderProxy.Listener, CallFilterResultCallback, CurrentUserProxy {
+    /**
+     * The origin of the request is not known.
+     */
+    public static final int REQUEST_ORIGIN_UNKNOWN = -1;
+
+    /**
+     * The request originated from a Telecom-provided disambiguation.
+     */
+    public static final int REQUEST_ORIGIN_TELECOM_DISAMBIGUATION = 1;
+
+    /**
+     * @hide
+     */
+    @IntDef(prefix = { "REQUEST_ORIGIN_" },
+            value = {REQUEST_ORIGIN_UNKNOWN, REQUEST_ORIGIN_TELECOM_DISAMBIGUATION})
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface RequestOrigin {}
 
     // TODO: Consider renaming this CallsManagerPlugin.
     @VisibleForTesting
@@ -272,7 +298,7 @@ public class CallsManager extends Call.ListenerBase
      * {@link #getNumCallsWithState(int, Call, PhoneAccountHandle, int...)} to indicate both managed
      * and self-managed calls should be included.
      */
-    private static final int CALL_FILTER_ALL = 3;
+    public static final int CALL_FILTER_ALL = 3;
 
     private static final String PERMISSION_PROCESS_PHONE_ACCOUNT_REGISTRATION =
             "android.permission.PROCESS_PHONE_ACCOUNT_REGISTRATION";
@@ -323,8 +349,12 @@ public class CallsManager extends Call.ListenerBase
             UUID.fromString("0a86157c-50ca-11ee-be56-0242ac120002");
     public static final String TELEPHONY_HAS_DEFAULT_BUT_TELECOM_DOES_NOT_MSG =
             "Telephony has a default MO acct but Telecom prompted user for MO";
+    public static final UUID CANNOT_HOLD_CURRENT_ACTIVE_CALL_ERROR_UUID =
+            UUID.fromString("1b6a9b88-5049-4ffa-a52a-134d7c3a40e6");
+    public static final UUID FAILED_TO_SWITCH_FOCUS_ERROR_UUID =
+            UUID.fromString("a1b2c3d4-e5f6-7890-1234-567890abcdef");
 
-    private static final int[] OUTGOING_CALL_STATES =
+    public static final int[] OUTGOING_CALL_STATES =
             {CallState.CONNECTING, CallState.SELECT_PHONE_ACCOUNT, CallState.DIALING,
                     CallState.PULLING};
 
@@ -369,6 +399,7 @@ public class CallsManager extends Call.ListenerBase
                 Analytics.THIRD_PARTY_PHONE);
     }
 
+    private static final long WAIT_FOR_AUDIO_UPDATE_TIMEOUT = 4000L;
     /**
      * The main call repository. Keeps an instance of all live calls. New incoming and outgoing
      * calls are added to the map and removed when the calls move to the disconnected state.
@@ -421,7 +452,10 @@ public class CallsManager extends Call.ListenerBase
             new ConcurrentHashMap<>();
 
     private CompletableFuture<Call> mPendingCallConfirm;
-    private CompletableFuture<Pair<Call, PhoneAccountHandle>> mPendingAccountSelection;
+    // Map the call's id to the corresponding pending account selection future associated with the
+    // call.
+    private final Map<String, CompletableFuture<Pair<Call, PhoneAccountHandle>>>
+            mPendingAccountSelection;
 
     // Instance variables for testing -- we keep the latest copy of the outgoing call futures
     // here so that we can wait on them in tests
@@ -480,9 +514,13 @@ public class CallsManager extends Call.ListenerBase
     private final ConnectionServiceFocusManager mConnectionSvrFocusMgr;
     /* Handler tied to thread in which CallManager was initialized. */
     private final Handler mHandler = new Handler(Looper.getMainLooper());
+    private final HandlerThread mHandlerThread = new HandlerThread("telecomAudioCallbacks",
+            android.os.Process.THREAD_PRIORITY_BACKGROUND);
+    private final Handler mAudioCallbackHandler;
     private final EmergencyCallHelper mEmergencyCallHelper;
     private final RoleManagerAdapter mRoleManagerAdapter;
     private final VoipCallMonitor mVoipCallMonitor;
+    private final VoipCallMonitorLegacy mVoipCallMonitorLegacy;
     private final CallEndpointController mCallEndpointController;
     private final CallAnomalyWatchdog mCallAnomalyWatchdog;
 
@@ -493,11 +531,13 @@ public class CallsManager extends Call.ListenerBase
     private final UserManager mUserManager;
     private final CallStreamingNotification mCallStreamingNotification;
     private final BlockedNumbersManager mBlockedNumbersManager;
-    private final CallsManagerCallSequencingAdapter mCallSequencingAdapter;
+    private CallsManagerCallSequencingAdapter mCallSequencingAdapter;
     private final FeatureFlags mFeatureFlags;
     private final com.android.internal.telephony.flags.FeatureFlags mTelephonyFeatureFlags;
 
     private final IncomingCallFilterGraphProvider mIncomingCallFilterGraphProvider;
+    private final CallAudioWatchdog mCallAudioWatchDog;
+    private final CallAudioRouteAdapter mCallAudioRouteAdapter;
 
     private final ConnectionServiceFocusManager.CallsManagerRequester mRequester =
             new ConnectionServiceFocusManager.CallsManagerRequester() {
@@ -644,15 +684,43 @@ public class CallsManager extends Call.ListenerBase
         mCallerInfoLookupHelper = callerInfoLookupHelper;
         mEmergencyCallDiagnosticLogger = emergencyCallDiagnosticLogger;
         mIncomingCallFilterGraphProvider = incomingCallFilterGraphProvider;
+        if (featureFlags.enableCallAudioWatchdog()) {
+            mHandlerThread.start();
+            mAudioCallbackHandler = new Handler(mHandlerThread.getLooper());
+            mCallAudioWatchDog = new CallAudioWatchdog(
+                    mContext.getSystemService(AudioManager.class),
+                    new CallAudioWatchdog.PhoneAccountRegistrarProxy() {
+                        @Override
+                        public boolean hasPhoneAccountForUid(int uid) {
+                            return mPhoneAccountRegistrar.hasPhoneAccountForUid(uid);
+                        }
+
+                        @Override
+                        public int getUidForPhoneAccountHandle(PhoneAccountHandle handle) {
+                            Context userContext = mContext.createContextAsUser(
+                                    handle.getUserHandle(),
+                                    0 /*flags */);
+                            try {
+                                return userContext.getPackageManager().getPackageUid(
+                                        handle.getComponentName().getPackageName(), 0 /* flags */);
+                            } catch (NameNotFoundException nfe) {
+                                return -1;
+                            }
+                        }
+                    }, clockProxy, mAudioCallbackHandler,
+                    featureFlags.telecomMetricsSupport() ? metricsController : null);
+        } else {
+            mAudioCallbackHandler = null;
+            mCallAudioWatchDog = null;
+        }
 
         mDtmfLocalTonePlayer =
                 new DtmfLocalTonePlayer(new DtmfLocalTonePlayer.ToneGeneratorProxy());
-        CallAudioRouteAdapter callAudioRouteAdapter;
         // TODO: add another flag check when
         // bluetoothDeviceManager.getBluetoothHeadset().isScoManagedByAudio()
         // available and return true
         if (!featureFlags.useRefactoredAudioRouteSwitching()) {
-            callAudioRouteAdapter = callAudioRouteStateMachineFactory.create(
+            mCallAudioRouteAdapter = callAudioRouteStateMachineFactory.create(
                     context,
                     this,
                     bluetoothManager,
@@ -665,17 +733,17 @@ public class CallsManager extends Call.ListenerBase
                     featureFlags
             );
         } else {
-            callAudioRouteAdapter = new CallAudioRouteController(context, this, audioServiceFactory,
-                    new AudioRoute.Factory(), wiredHeadsetManager, mBluetoothRouteManager,
-                    statusBarNotifier, featureFlags, metricsController);
+            mCallAudioRouteAdapter = new CallAudioRouteController(context, this,
+                    audioServiceFactory, new AudioRoute.Factory(), wiredHeadsetManager,
+                    mBluetoothRouteManager, statusBarNotifier, featureFlags, metricsController);
         }
-        callAudioRouteAdapter.initialize();
-        bluetoothStateReceiver.setCallAudioRouteAdapter(callAudioRouteAdapter);
-        bluetoothDeviceManager.setCallAudioRouteAdapter(callAudioRouteAdapter);
+        mCallAudioRouteAdapter.initialize();
+        bluetoothStateReceiver.setCallAudioRouteAdapter(mCallAudioRouteAdapter);
+        bluetoothDeviceManager.setCallAudioRouteAdapter(mCallAudioRouteAdapter);
 
         CallAudioRoutePeripheralAdapter callAudioRoutePeripheralAdapter =
                 new CallAudioRoutePeripheralAdapter(
-                        callAudioRouteAdapter,
+                        mCallAudioRouteAdapter,
                         bluetoothManager,
                         wiredHeadsetManager,
                         mDockManager,
@@ -688,7 +756,8 @@ public class CallsManager extends Call.ListenerBase
                                         audioManager.generateAudioSessionId()));
         InCallTonePlayer.Factory playerFactory = new InCallTonePlayer.Factory(
                 callAudioRoutePeripheralAdapter, lock, toneGeneratorFactory, mediaPlayerFactory,
-                () -> audioManager.getStreamVolume(AudioManager.STREAM_RING) > 0, featureFlags);
+                () -> audioManager.getStreamVolume(AudioManager.STREAM_RING) > 0, featureFlags,
+                Looper.getMainLooper());
 
         SystemSettingsUtil systemSettingsUtil = new SystemSettingsUtil();
         RingtoneFactory ringtoneFactory = new RingtoneFactory(this, context, featureFlags);
@@ -711,7 +780,7 @@ public class CallsManager extends Call.ListenerBase
             mCallRecordingTonePlayer = new CallRecordingTonePlayer(mContext, audioManager,
                     mTimeoutsAdapter, mLock);
         }
-        mCallAudioManager = new CallAudioManager(callAudioRouteAdapter,
+        mCallAudioManager = new CallAudioManager(mCallAudioRouteAdapter,
                 this, callAudioModeStateMachineFactory.create(systemStateHelper,
                 (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE),
                 featureFlags, communicationDeviceTracker),
@@ -732,20 +801,30 @@ public class CallsManager extends Call.ListenerBase
         mClockProxy = clockProxy;
         mToastFactory = toastFactory;
         mRoleManagerAdapter = roleManagerAdapter;
-        mVoipCallMonitor = new VoipCallMonitor(mContext, mLock);
         mTransactionManager = transactionManager;
         mBlockedNumbersAdapter = blockedNumbersAdapter;
         mCallStreamingController = new CallStreamingController(mContext, mLock);
         mCallStreamingNotification = callStreamingNotification;
         mFeatureFlags = featureFlags;
+        if (mFeatureFlags.voipCallMonitorRefactor()) {
+            mVoipCallMonitor = new VoipCallMonitor(
+                    mContext,
+                    new Handler(Looper.getMainLooper()),
+                    mLock);
+            mVoipCallMonitorLegacy = null;
+        } else {
+            mVoipCallMonitor = null;
+            mVoipCallMonitorLegacy = new VoipCallMonitorLegacy(mContext, mLock);
+        }
         mTelephonyFeatureFlags = telephonyFlags;
         mMetricsController = metricsController;
         mBlockedNumbersManager = mFeatureFlags.telecomMainlineBlockedNumbersManager()
                 ? mContext.getSystemService(BlockedNumbersManager.class)
                 : null;
-        mCallSequencingAdapter = new CallsManagerCallSequencingAdapter(this,
-                new CallSequencingController(this, mFeatureFlags.enableCallSequencing()),
-                mFeatureFlags.enableCallSequencing());
+        mCallSequencingAdapter = new CallsManagerCallSequencingAdapter(this, mContext,
+                new CallSequencingController(this, mContext, mClockProxy,
+                        mAnomalyReporter, mTimeoutsAdapter, mMetricsController, mMmiUtils,
+                        mFeatureFlags), mCallAudioManager, mFeatureFlags);
 
         if (mFeatureFlags.useImprovedListenerOrder()) {
             mListeners.add(mInCallController);
@@ -773,10 +852,18 @@ public class CallsManager extends Call.ListenerBase
 
         // this needs to be after the mCallAudioManager
         mListeners.add(mPhoneStateBroadcaster);
-        mListeners.add(mVoipCallMonitor);
         mListeners.add(mCallStreamingNotification);
+        if (featureFlags.enableCallAudioWatchdog()) {
+            mListeners.add(mCallAudioWatchDog);
+        }
 
-        mVoipCallMonitor.startMonitor();
+        if (mFeatureFlags.voipCallMonitorRefactor()) {
+            mVoipCallMonitor.registerNotificationListener();
+            mListeners.add(mVoipCallMonitor);
+        } else {
+            mVoipCallMonitorLegacy.startMonitor();
+            mListeners.add(mVoipCallMonitorLegacy);
+        }
 
         // There is no USER_SWITCHED broadcast for user 0, handle it here explicitly.
         final UserManager userManager = mContext.getSystemService(UserManager.class);
@@ -795,6 +882,7 @@ public class CallsManager extends Call.ListenerBase
         mCallAnomalyWatchdog = callAnomalyWatchdog;
         mAsyncTaskExecutor = asyncTaskExecutor;
         mUserManager = mContext.getSystemService(UserManager.class);
+        mPendingAccountSelection = new HashMap<>();
     }
 
     public void setIncomingCallNotifier(IncomingCallNotifier incomingCallNotifier) {
@@ -1409,6 +1497,14 @@ public class CallsManager extends Call.ListenerBase
         markAllAnsweredCallAsRinging(call, "switch");
     }
 
+    @Override
+    public void onCallResumeFailed(Call call) {
+        Call heldCall = getFirstCallWithState(call, true /* skipSelfManaged */, CallState.ON_HOLD);
+        if (heldCall != null) {
+            mCallSequencingAdapter.handleCallResumeFailed(call, heldCall);
+        }
+    }
+
     private void markAllAnsweredCallAsRinging(Call call, String actionName) {
         // Normally, we don't care whether a call hold or switch has failed.
         // However, if a call was held or switched in order to answer an incoming call, that
@@ -1591,6 +1687,7 @@ public class CallsManager extends Call.ListenerBase
             call.setAssociatedUser(associatedUser);
         }
 
+        Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
         if (phoneAccount != null) {
             Bundle phoneAccountExtras = phoneAccount.getExtras();
             if (call.isSelfManaged()) {
@@ -1599,23 +1696,8 @@ public class CallsManager extends Call.ListenerBase
                 call.setVisibleToInCallService(phoneAccountExtras == null
                         || phoneAccountExtras.getBoolean(
                         PhoneAccount.EXTRA_ADD_SELF_MANAGED_CALLS_TO_INCALLSERVICE, true));
-            } else {
-                // Incoming call is managed, the active call is self-managed and can't be held.
-                // We need to set extras on it to indicate whether answering will cause a
-                // active self-managed call to drop.
-                Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
-                if (activeCall != null && !canHold(activeCall) && activeCall.isSelfManaged()) {
-                    Bundle dropCallExtras = new Bundle();
-                    dropCallExtras.putBoolean(Connection.EXTRA_ANSWERING_DROPS_FG_CALL, true);
-
-                    // Include the name of the app which will drop the call.
-                    CharSequence droppedApp = activeCall.getTargetPhoneAccountLabel();
-                    dropCallExtras.putCharSequence(
-                            Connection.EXTRA_ANSWERING_DROPS_FG_CALL_APP_NAME, droppedApp);
-                    Log.i(this, "Incoming managed call will drop %s call.", droppedApp);
-                    call.putConnectionServiceExtras(dropCallExtras);
-                }
             }
+            mCallSequencingAdapter.maybeAddAnsweringCallDropsFg(activeCall, call);
 
             if (phoneAccountExtras != null
                     && phoneAccountExtras.getBoolean(
@@ -1626,6 +1708,7 @@ public class CallsManager extends Call.ListenerBase
             }
         }
 
+
         boolean isRttSettingOn = isRttSettingOn(phoneAccountHandle);
         if (isRttSettingOn ||
                 extras.getBoolean(TelecomManager.EXTRA_START_CALL_WITH_RTT, false)) {
@@ -1765,6 +1848,24 @@ public class CallsManager extends Call.ListenerBase
             } else {
                 notifyCreateConnectionFailed(phoneAccountHandle, call);
             }
+        } else if (mFeatureFlags.enableCallSequencing() && (hasMaximumManagedRingingCalls(call)
+                || hasMaximumManagedDialingCalls(call))) {
+            // Fail incoming call if there's already a ringing or dialing call present.
+            boolean maxRinging = hasMaximumManagedRingingCalls(call);
+            if (maxRinging) {
+                call.setMissedReason(AUTO_MISSED_MAXIMUM_RINGING);
+                call.setStartFailCause(CallFailureCause.MAX_RINGING_CALLS);
+            } else {
+                call.setMissedReason(AUTO_MISSED_MAXIMUM_DIALING);
+            }
+            call.getAnalytics().setMissedReason(call.getMissedReason());
+            mCallLogManager.logCall(call, Calls.MISSED_TYPE,
+                    true /*showNotificationForMissedCall*/, null /*CallFilteringResult*/);
+            if (isConference) {
+                notifyCreateConferenceFailed(phoneAccountHandle, call);
+            } else {
+                notifyCreateConnectionFailed(phoneAccountHandle, call);
+            }
         } else if (call.isTransactionalCall()) {
             // transactional calls should skip Call#startCreateConnection below
             // as that is meant for Call objects with a ConnectionServiceWrapper
@@ -1779,6 +1880,25 @@ public class CallsManager extends Call.ListenerBase
         return call;
     }
 
+    public void maybeAddAnsweringCallDropsFgOld(Call activeCall, Call incomingCall) {
+        // Incoming call is managed, the active call is self-managed and can't be held.
+        // We need to set extras on it to indicate whether answering will cause a
+        // active self-managed call to drop.
+        // Only runs if call sequencing is enabled.
+        if (!incomingCall.isSelfManaged() && activeCall != null && !canHold(activeCall)
+                && activeCall.isSelfManaged()) {
+            Bundle dropCallExtras = new Bundle();
+            dropCallExtras.putBoolean(Connection.EXTRA_ANSWERING_DROPS_FG_CALL, true);
+
+            // Include the name of the app which will drop the call.
+            CharSequence droppedApp = activeCall.getTargetPhoneAccountLabel();
+            dropCallExtras.putCharSequence(
+                    Connection.EXTRA_ANSWERING_DROPS_FG_CALL_APP_NAME, droppedApp);
+            Log.i(this, "Incoming managed call will drop %s call.", droppedApp);
+            incomingCall.putConnectionServiceExtras(dropCallExtras);
+        }
+    }
+
     void addNewUnknownCall(PhoneAccountHandle phoneAccountHandle, Bundle extras) {
         Uri handle = extras.getParcelable(TelecomManager.EXTRA_UNKNOWN_CALL_HANDLE);
         Log.i(this, "addNewUnknownCall with handle: %s", Log.pii(handle));
@@ -1874,6 +1994,37 @@ public class CallsManager extends Call.ListenerBase
                 originalIntent, callingPackage, false);
     }
 
+    /**
+     * Creates a transaction representing either the outgoing or incoming transactional call.
+     * @param callId The call id associated with the call.
+     * @param callAttributes The call attributes associated with the call.
+     * @param extras The extras that are associated with the call.
+     * @param callingPackage The calling package representing where the request was invoked from.
+     * @return The {@link CompletableFuture<CallTransaction>} that encompasses the request to
+     *         place/receive the transactional call.
+     */
+    public CompletableFuture<CallTransaction> createTransactionalCall(String callId,
+            CallAttributes callAttributes, Bundle extras, String callingPackage) {
+        CompletableFuture<CallTransaction> transaction;
+        // create transaction based on the call direction
+        switch (callAttributes.getDirection()) {
+            case DIRECTION_OUTGOING:
+                transaction = mCallSequencingAdapter.createTransactionalOutgoingCall(callId,
+                        callAttributes, extras, callingPackage);
+                break;
+            case DIRECTION_INCOMING:
+                transaction = CompletableFuture.completedFuture(new IncomingCallTransaction(
+                        callId, callAttributes, this, extras, mFeatureFlags));
+                break;
+            default:
+                throw new IllegalArgumentException(String.format("Invalid Call Direction. "
+                                + "Was [%d] but should be within [%d,%d]",
+                        callAttributes.getDirection(), DIRECTION_INCOMING,
+                        DIRECTION_OUTGOING));
+        }
+        return transaction;
+    }
+
     private String generateNextCallId(Bundle extras) {
         if (extras != null && extras.containsKey(TelecomManager.TRANSACTION_CALL_ID_KEY)) {
             return extras.getString(TelecomManager.TRANSACTION_CALL_ID_KEY);
@@ -2094,7 +2245,18 @@ public class CallsManager extends Call.ListenerBase
                 potentialPhoneAccounts -> {
                     Log.i(CallsManager.this, "make room for outgoing call stage");
                     if (mMmiUtils.isPotentialInCallMMICode(handle) && !isSelfManaged) {
-                        return CompletableFuture.completedFuture(true);
+                        // We will allow the MMI code if call sequencing is not enabled or there
+                        // are only calls on the same phone account.
+                        boolean shouldAllowMmiCode = mCallSequencingAdapter
+                                .shouldAllowMmiCode(finalCall);
+                        if (shouldAllowMmiCode) {
+                            return CompletableFuture.completedFuture(true);
+                        } else {
+                            // Reject the in-call MMI code.
+                            Log.i(this, "Rejecting the in-call MMI code because there is an "
+                                    + "ongoing call on a different phone account.");
+                            return CompletableFuture.completedFuture(false);
+                        }
                     }
                     // If a call is being reused, then it has already passed the
                     // makeRoomForOutgoingCall check once and will fail the second time due to the
@@ -2127,6 +2289,10 @@ public class CallsManager extends Call.ListenerBase
                                     finalCall.getTargetPhoneAccount(), finalCall);
                         }
                         finalCall.setStartFailCause(CallFailureCause.IN_EMERGENCY_CALL);
+                        // Show an error message when dialing a MMI code during an emergency call.
+                        if (mMmiUtils.isPotentialMMICode(handle)) {
+                            showErrorMessage(R.string.emergencyCall_reject_mmi);
+                        }
                         return CompletableFuture.completedFuture(false);
                     }
 
@@ -2294,11 +2460,12 @@ public class CallsManager extends Call.ListenerBase
                                     android.telecom.Call.EXTRA_SUGGESTED_PHONE_ACCOUNTS,
                                     accountSuggestions);
                             // Set a future in place so that we can proceed once the dialer replies.
-                            mPendingAccountSelection = new CompletableFuture<>();
+                            mPendingAccountSelection.put(callToPlace.getId(),
+                                    new CompletableFuture<>());
                             callToPlace.setIntentExtras(newExtras);
 
                             addCall(callToPlace);
-                            return mPendingAccountSelection;
+                            return mPendingAccountSelection.get(callToPlace.getId());
                         }, new LoggedHandlerExecutor(outgoingCallHandler, "CM.dSPA", mLock));
 
         // Potentially perform call identification for dialed TEL scheme numbers.
@@ -3120,6 +3287,18 @@ public class CallsManager extends Call.ListenerBase
         call.conferenceWith(otherCall);
     }
 
+    /**
+     * Similar to {@link #answerCall(Call, int, int)}, instructs Telecom to answer the specified
+     * call.  This prototype assumes that the origin of the request is
+     * {@link #REQUEST_ORIGIN_UNKNOWN} for the time being.  In most cases this is likely a user
+     * request to answer a call, but could be internal to Telecom.
+     * @param call The call to answer.
+     * @param videoState The video state in which to answer the call.
+     */
+    public void answerCall(Call call, int videoState) {
+        answerCall(call, videoState, REQUEST_ORIGIN_UNKNOWN);
+    }
+
     /**
      * Instructs Telecom to answer the specified call. Intended to be invoked by the in-call
      * app through {@link InCallAdapter} after Telecom notifies it of an incoming call followed by
@@ -3127,26 +3306,27 @@ public class CallsManager extends Call.ListenerBase
      *
      * @param call The call to answer.
      * @param videoState The video state in which to answer the call.
+     * @param requestOrigin The origin of the request being made.
      */
     @VisibleForTesting
-    public void answerCall(Call call, int videoState) {
+    public void answerCall(Call call, int videoState, @RequestOrigin int requestOrigin) {
         if (!mCalls.contains(call)) {
             Log.i(this, "Request to answer a non-existent call %s", call);
         }
-        mCallSequencingAdapter.answerCall(call, videoState);
+        mCallSequencingAdapter.answerCall(call, videoState, requestOrigin);
     }
 
     /**
      * CS: Hold any existing calls, request focus, and then set the call state to answered state.
      * <p>
      * T: Call TransactionalServiceWrapper, which then generates transactions to hold calls
-     * {@link #transactionHoldPotentialActiveCallForNewCall} and then move the active call focus
-     * {@link #requestNewCallFocusAndVerify} and notify the remote VOIP app of the call state
-     * moving to active.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall} and
+     * then move the active call focus {@link #requestNewCallFocusAndVerify} and notify the remote
+     * VOIP app of the call state moving to active.
      * <p>
      * Note: This is only used when {@link FeatureFlags#enableCallSequencing()} is false.
      */
-    public void answerCallOld(Call call, int videoState) {
+    public void answerCallOld(Call call, int videoState, @RequestOrigin int requestOrigin) {
         if (call.isTransactionalCall()) {
             // InCallAdapter is requesting to answer the given transactioanl call. Must get an ack
             // from the client via a transaction before answering.
@@ -3430,34 +3610,43 @@ public class CallsManager extends Call.ListenerBase
             Log.w(this, "Unknown call (%s) asked to disconnect", call);
         } else {
             mLocallyDisconnectingCalls.add(call);
-            int previousState = call.getState();
-            call.disconnect();
-            for (CallsManagerListener listener : mListeners) {
-                listener.onCallStateChanged(call, previousState, call.getState());
-            }
-            // Cancel any of the outgoing call futures if they're still around.
-            if (mPendingCallConfirm != null && !mPendingCallConfirm.isDone()) {
-                mPendingCallConfirm.complete(null);
-                mPendingCallConfirm = null;
-            }
-            if (mPendingAccountSelection != null && !mPendingAccountSelection.isDone()) {
-                mPendingAccountSelection.complete(null);
-                mPendingAccountSelection = null;
-            }
+            mCallSequencingAdapter.disconnectCall(call);
         }
     }
 
     /**
-     * Instructs Telecom to disconnect all calls.
+     * Disconnects the provided call. This is only used when
+     * {@link FeatureFlags#enableCallSequencing()} is false.
+     * @param call The call to disconnect.
+     * @param previousState The previous call state before the call is disconnected.
      */
-    void disconnectAllCalls() {
-        Log.v(this, "disconnectAllCalls");
-
-        for (Call call : mCalls) {
-            disconnectCall(call);
+    public void disconnectCallOld(Call call, int previousState) {
+        call.disconnect();
+        for (CallsManagerListener listener : mListeners) {
+            listener.onCallStateChanged(call, previousState, call.getState());
         }
+        processDisconnectCallAndCleanup(call, previousState);
     }
 
+    /**
+     * Helper to process the call state change upon disconnecting the provided call and performs
+     * local cleanup to clear the outgoing call futures, if they exist.
+     * @param call The call to disconnect.
+     * @param previousState The previous call state before the call is disconnected.
+     */
+    public void processDisconnectCallAndCleanup(Call call, int previousState) {
+        // Cancel any of the outgoing call futures if they're still around.
+        if (mPendingCallConfirm != null && !mPendingCallConfirm.isDone()) {
+            mPendingCallConfirm.complete(null);
+            mPendingCallConfirm = null;
+        }
+        String callId = call.getId();
+        if (mPendingAccountSelection.containsKey(callId)
+                && !mPendingAccountSelection.get(callId).isDone()) {
+            mPendingAccountSelection.get(callId).complete(null);
+        }
+        mPendingAccountSelection.remove(callId);
+    }
     /**
      * Disconnects calls for any other {@link PhoneAccountHandle} but the one specified.
      * Note: As a protective measure, will NEVER disconnect an emergency call.  Although that
@@ -3549,6 +3738,16 @@ public class CallsManager extends Call.ListenerBase
                 new RequestCallback(new ActionUnHoldCall(call, activeCallId)));
     }
 
+    public void requestActionSetActiveCall(Call call, String tag) {
+        mConnectionSvrFocusMgr.requestFocus(call,
+                new RequestCallback(new ActionSetCallState(call, CallState.ACTIVE, tag)));
+    }
+
+    public void requestFocusActionAnswerCall(Call call, int videoState) {
+        mConnectionSvrFocusMgr.requestFocus(call, new CallsManager.RequestCallback(
+                new ActionAnswerCall(call, videoState)));
+    }
+
     @Override
     public void onExtrasRemoved(Call c, int source, List<String> keys) {
         if (source != Call.SOURCE_CONNECTION_SERVICE) {
@@ -3823,7 +4022,7 @@ public class CallsManager extends Call.ListenerBase
         return isRttModeSettingOn && !shouldIgnoreRttModeSetting;
     }
 
-    private PersistableBundle getCarrierConfigForPhoneAccount(PhoneAccountHandle handle) {
+    public PersistableBundle getCarrierConfigForPhoneAccount(PhoneAccountHandle handle) {
         int subscriptionId = mPhoneAccountRegistrar.getSubscriptionIdForPhoneAccount(handle);
         CarrierConfigManager carrierConfigManager =
                 mContext.getSystemService(CarrierConfigManager.class);
@@ -3841,9 +4040,10 @@ public class CallsManager extends Call.ListenerBase
                         .setUserSelectedOutgoingPhoneAccount(account, call.getAssociatedUser());
             }
 
-            if (mPendingAccountSelection != null) {
-                mPendingAccountSelection.complete(Pair.create(call, account));
-                mPendingAccountSelection = null;
+            String callId = call.getId();
+            if (mPendingAccountSelection.containsKey(callId)) {
+                mPendingAccountSelection.get(callId).complete(Pair.create(call, account));
+                mPendingAccountSelection.remove(callId);
             }
         }
     }
@@ -3915,15 +4115,10 @@ public class CallsManager extends Call.ListenerBase
         maybeMoveToSpeakerPhone(call);
     }
 
-    void requestFocusActionAnswerCall(Call call, int videoState) {
-        mConnectionSvrFocusMgr.requestFocus(call, new CallsManager.RequestCallback(
-                new CallsManager.ActionAnswerCall(call, videoState)));
-    }
-
     /**
      * Returns true if the active call is held.
      */
-    boolean holdActiveCallForNewCall(Call call) {
+    public boolean holdActiveCallForNewCall(Call call) {
         Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
         Log.i(this, "holdActiveCallForNewCall, newCall: %s, activeCall: %s", call.getId(),
                 (activeCall == null ? "<none>" : activeCall.getId()));
@@ -3981,79 +4176,74 @@ public class CallsManager extends Call.ListenerBase
     }
 
     /**
-     * attempt to hold or swap the current active call in favor of a new call request. The
-     * OutcomeReceiver will return onResult if the current active call is held or disconnected.
-     * Otherwise, the OutcomeReceiver will fail.
+     * Attempt to hold or swap the current active call in favor of a new call request. The old code
+     * path where {@link FeatureFlags#transactionalHoldDisconnectsUnholdable} is enabled but
+     * {@link FeatureFlags#enableCallSequencing()} is disabled.
      */
-    public void transactionHoldPotentialActiveCallForNewCall(Call newCall,
-            boolean isCallControlRequest, OutcomeReceiver<Boolean, CallException> callback) {
-        String mTag = "transactionHoldPotentialActiveCallForNewCall: ";
-        Call activeCall = (Call) mConnectionSvrFocusMgr.getCurrentFocusCall();
-        Log.i(this, mTag + "newCall=[%s], activeCall=[%s]", newCall, activeCall);
-
-        if (activeCall == null || activeCall == newCall) {
-            Log.i(this, mTag + "no need to hold activeCall");
+    public void transactionHoldPotentialActiveCallForNewCallOld(Call newCall,
+            Call activeCall, OutcomeReceiver<Boolean, CallException> callback) {
+        if (holdActiveCallForNewCall(newCall)) {
+            // Transactional clients do not call setHold but the request was sent to set the
+            // call as inactive and it has already been acked by this point.
+            markCallAsOnHold(activeCall);
             callback.onResult(true);
-            return;
-        }
-
-        if (mFeatureFlags.transactionalHoldDisconnectsUnholdable()) {
-            // prevent bad actors from disconnecting the activeCall. Instead, clients will need to
-            // notify the user that they need to disconnect the ongoing call before making the
-            // new call ACTIVE.
-            if (isCallControlRequest && !canHoldOrSwapActiveCall(activeCall, newCall)) {
-                Log.i(this, mTag + "CallControlRequest exit");
-                callback.onError(new CallException("activeCall is NOT holdable or swappable, please"
-                        + " request the user disconnect the call.",
-                        CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
-                return;
-            }
-
-            if (holdActiveCallForNewCall(newCall)) {
-                // Transactional clients do not call setHold but the request was sent to set the
-                // call as inactive and it has already been acked by this point.
-                markCallAsOnHold(activeCall);
+        } else {
+            // It's possible that holdActiveCallForNewCall disconnected the activeCall.
+            // Therefore, the activeCalls state should be checked before failing.
+            if (activeCall.isLocallyDisconnecting()) {
                 callback.onResult(true);
             } else {
-                // It's possible that holdActiveCallForNewCall disconnected the activeCall.
-                // Therefore, the activeCalls state should be checked before failing.
-                if (activeCall.isLocallyDisconnecting()) {
-                    callback.onResult(true);
-                } else {
-                    Log.i(this, mTag + "active call could not be held or disconnected");
-                    callback.onError(
-                            new CallException("activeCall could not be held or disconnected",
-                                    CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+                String msg = "active call could not be held or disconnected";
+                Log.i(this, "transactionHoldPotentialActiveCallForNewCallOld: " + msg);
+                callback.onError(
+                        new CallException(msg,
+                                CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+                if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                    mAnomalyReporter.reportAnomaly(CANNOT_HOLD_CURRENT_ACTIVE_CALL_ERROR_UUID, msg);
                 }
             }
-        } else {
-            // before attempting CallsManager#holdActiveCallForNewCall(Call), check if it'll fail
-            // early
-            if (!canHold(activeCall) &&
-                    !(supportsHold(activeCall) && areFromSameSource(activeCall, newCall))) {
-                Log.i(this, "transactionHoldPotentialActiveCallForNewCall: "
-                        + "conditions show the call cannot be held.");
-                callback.onError(new CallException("call does not support hold",
-                        CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
-                return;
-            }
+        }
+    }
 
-            // attempt to hold the active call
-            if (!holdActiveCallForNewCall(newCall)) {
-                Log.i(this, "transactionHoldPotentialActiveCallForNewCall: "
-                        + "attempted to hold call but failed.");
-                callback.onError(new CallException("cannot hold active call failed",
-                        CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
-                return;
+    /**
+     * The transactional unflagged (original) code path to hold or swap the active call in favor of
+     * a new call request. Refer to
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall}.
+     */
+    public void transactionHoldPotentialActiveCallForNewCallUnflagged(Call activeCall, Call newCall,
+            OutcomeReceiver<Boolean, CallException> callback) {
+        // before attempting CallsManager#holdActiveCallForNewCall(Call), check if it'll fail
+        // early
+        if (!canHold(activeCall) &&
+                !(supportsHold(activeCall) && areFromSameSource(activeCall, newCall))) {
+            String msg = "call does not support hold";
+            Log.i(this, "transactionHoldPotentialActiveCallForNewCall: " + msg);
+            callback.onError(new CallException(msg,
+                    CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+            if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                mAnomalyReporter.reportAnomaly(CANNOT_HOLD_CURRENT_ACTIVE_CALL_ERROR_UUID, msg);
             }
+            return;
+        }
 
-            // officially mark the activeCall as held
-            markCallAsOnHold(activeCall);
-            callback.onResult(true);
+        // attempt to hold the active call
+        if (!holdActiveCallForNewCall(newCall)) {
+            String msg = "cannot hold active call failed";
+            Log.i(this, "transactionHoldPotentialActiveCallForNewCall: " + msg);
+            callback.onError(new CallException(msg,
+                    CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+            if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                mAnomalyReporter.reportAnomaly(CANNOT_HOLD_CURRENT_ACTIVE_CALL_ERROR_UUID, msg);
+            }
+            return;
         }
+
+        // officially mark the activeCall as held
+        markCallAsOnHold(activeCall);
+        callback.onResult(true);
     }
 
-    private boolean canHoldOrSwapActiveCall(Call activeCall, Call newCall) {
+    public boolean canHoldOrSwapActiveCall(Call activeCall, Call newCall) {
         return canHold(activeCall) || sameSourceHoldCase(activeCall, newCall);
     }
 
@@ -4064,8 +4254,6 @@ public class CallsManager extends Call.ListenerBase
     /**
      * CS: Mark a call as active. If the call is self-mangaed, we will also hold any active call
      * before moving the self-managed call to active.
-     * <p>
-     * Note: Only used when {@link FeatureFlags#enableCallSequencing()} is false.
      */
     @VisibleForTesting
     public void markCallAsActive(Call call) {
@@ -4075,13 +4263,7 @@ public class CallsManager extends Call.ListenerBase
             // to active directly. We should hold or disconnect the current active call based on the
             // holdability, and request the call focus for the self-managed call before the state
             // change.
-            holdActiveCallForNewCall(call);
-            mConnectionSvrFocusMgr.requestFocus(
-                    call,
-                    new RequestCallback(new ActionSetCallState(
-                            call,
-                            CallState.ACTIVE,
-                            "active set explicitly for self-managed")));
+            mCallSequencingAdapter.markCallAsActiveSelfManagedCall(call);
         } else {
             if (mPendingAudioProcessingCall == call) {
                 if (mCalls.contains(call)) {
@@ -4103,8 +4285,6 @@ public class CallsManager extends Call.ListenerBase
 
     /**
      * Mark a call as on hold after the hold operation has already completed.
-     * <p>
-     * Note: only used when {@link FeatureFlags#enableCallSequencing()} is false.
      */
     public void markCallAsOnHold(Call call) {
         setCallState(call, CallState.ON_HOLD, "on-hold set explicitly");
@@ -4283,45 +4463,7 @@ public class CallsManager extends Call.ListenerBase
         removeCall(call);
         boolean isLocallyDisconnecting = mLocallyDisconnectingCalls.contains(call);
         mLocallyDisconnectingCalls.remove(call);
-        mCallSequencingAdapter.unholdCallForRemoval(call, isLocallyDisconnecting);
-    }
-
-    /**
-     * Move the held call to foreground in the event that there is a held call and the disconnected
-     * call was disconnected locally or the held call has no way to auto-unhold because it does not
-     * support hold capability.
-     * <p>
-     * Note: This is only used when {@link FeatureFlags#enableCallSequencing()} is set to false.
-     */
-    public void maybeMoveHeldCallToForeground(Call removedCall, boolean isLocallyDisconnecting) {
-        Call foregroundCall = mCallAudioManager.getPossiblyHeldForegroundCall();
-        if (isLocallyDisconnecting) {
-            boolean isDisconnectingChildCall = removedCall.isDisconnectingChildCall();
-            Log.v(this, "maybeMoveHeldCallToForeground: isDisconnectingChildCall = "
-                    + isDisconnectingChildCall + "call -> %s", removedCall);
-            // Auto-unhold the foreground call due to a locally disconnected call, except if the
-            // call which was disconnected is a member of a conference (don't want to auto
-            // un-hold the conference if we remove a member of the conference).
-            // Also, ensure that the call we're removing is from the same ConnectionService as
-            // the one we're removing.  We don't want to auto-unhold between ConnectionService
-            // implementations, especially if one is managed and the other is a VoIP CS.
-            if (!isDisconnectingChildCall && foregroundCall != null
-                    && foregroundCall.getState() == CallState.ON_HOLD
-                    && areFromSameSource(foregroundCall, removedCall)) {
-
-                foregroundCall.unhold();
-            }
-        } else if (foregroundCall != null &&
-                !foregroundCall.can(Connection.CAPABILITY_SUPPORT_HOLD) &&
-                foregroundCall.getState() == CallState.ON_HOLD) {
-
-            // The new foreground call is on hold, however the carrier does not display the hold
-            // button in the UI.  Therefore, we need to auto unhold the held call since the user
-            // has no means of unholding it themselves.
-            Log.i(this, "maybeMoveHeldCallToForeground: Auto-unholding held foreground call (call "
-                    + "doesn't support hold)");
-            foregroundCall.unhold();
-        }
+        mCallSequencingAdapter.maybeMoveHeldCallToForeground(call, isLocallyDisconnecting);
     }
 
     /**
@@ -4395,11 +4537,16 @@ public class CallsManager extends Call.ListenerBase
         return getFirstCallWithState(CallState.RINGING, CallState.ANSWERED) != null;
     }
 
-    boolean hasRingingOrSimulatedRingingCall() {
+    public boolean hasRingingOrSimulatedRingingCall() {
         return getFirstCallWithState(
                 CallState.SIMULATED_RINGING, CallState.RINGING, CallState.ANSWERED) != null;
     }
 
+    public boolean hasManagedRingingOrSimulatedRingingCall() {
+        return getFirstCallWithState(null /* callToSkip */, true /* skipSelfManaged */,
+                CallState.SIMULATED_RINGING, CallState.RINGING, CallState.ANSWERED) != null;
+    }
+
     @VisibleForTesting
     public boolean onMediaButton(int type) {
         if (hasAnyCalls()) {
@@ -4543,11 +4690,11 @@ public class CallsManager extends Call.ListenerBase
 
     @VisibleForTesting
     public Call getFirstCallWithState(int... states) {
-        return getFirstCallWithState(null, states);
+        return getFirstCallWithState(null, false /* skipSelfManaged */, states);
     }
 
     public Call getFirstCallWithLiveState() {
-        return getFirstCallWithState(null, LIVE_CALL_STATES);
+        return getFirstCallWithState(null, false /* skipSelfManaged */, LIVE_CALL_STATES);
     }
 
     @VisibleForTesting
@@ -4572,7 +4719,7 @@ public class CallsManager extends Call.ListenerBase
      *
      * @param callToSkip Call that this method should skip while searching
      */
-    Call getFirstCallWithState(Call callToSkip, int... states) {
+    Call getFirstCallWithState(Call callToSkip, boolean skipSelfManaged, int... states) {
         for (int currentState : states) {
             // check the foreground first
             Call foregroundCall = getForegroundCall();
@@ -4594,6 +4741,10 @@ public class CallsManager extends Call.ListenerBase
                     continue;
                 }
 
+                if (skipSelfManaged && call.isSelfManaged()) {
+                    continue;
+                }
+
                 if (currentState == call.getState()) {
                     return call;
                 }
@@ -4754,6 +4905,9 @@ public class CallsManager extends Call.ListenerBase
         Log.i(this, "addCall(%s)", call);
         call.addListener(this);
         mCalls.add(call);
+        // Reprocess the simultaneous call types for all the tracked calls after having added a new
+        // call.
+        mCallSequencingAdapter.processSimultaneousCallTypes(mCalls);
         mSelfManagedCallsBeingSetup.remove(call);
 
         // Specifies the time telecom finished routing the call. This is used by the dialer for
@@ -5043,14 +5197,40 @@ public class CallsManager extends Call.ListenerBase
      *                   ({@link #CALL_FILTER_ALL}).
      * @param excludeCall Where {@code non-null}, this call is excluded from the count.
      * @param phoneAccountHandle Where {@code non-null}, calls for this {@link PhoneAccountHandle}
-     *                           are excluded from the count.
+     *                           are included in the count.
      * @param states The list of {@link CallState}s to include in the count.
      * @return Count of calls matching criteria.
      */
     @VisibleForTesting
     public int getNumCallsWithState(final int callFilter, Call excludeCall,
                                     PhoneAccountHandle phoneAccountHandle, int... states) {
+        Stream<Call> callsStream = getCallsWithState(callFilter, excludeCall, states);
 
+        // If a phone account handle was specified, only consider calls for that phone account.
+        if (phoneAccountHandle != null) {
+            callsStream = callsStream.filter(
+                    call -> phoneAccountHandle.equals(call.getTargetPhoneAccount()));
+        }
+
+        return (int) callsStream.count();
+    }
+
+    @VisibleForTesting
+    public int getNumCallsWithStateWithoutHandle(final int callFilter, Call excludeCall,
+            PhoneAccountHandle phoneAccountHandle, int... states) {
+        Stream<Call> callsStream = getCallsWithState(callFilter, excludeCall, states);
+
+        // If a phone account handle was specified, only consider calls not associated with that
+        // phone account.
+        if (phoneAccountHandle != null) {
+            callsStream = callsStream.filter(
+                    call -> !phoneAccountHandle.equals(call.getTargetPhoneAccount()));
+        }
+
+        return (int) callsStream.count();
+    }
+
+    private Stream<Call> getCallsWithState(final int callFilter, Call excludeCall, int... states) {
         Set<Integer> desiredStates = IntStream.of(states).boxed().collect(Collectors.toSet());
 
         Stream<Call> callsStream = mCalls.stream()
@@ -5068,15 +5248,8 @@ public class CallsManager extends Call.ListenerBase
             callsStream = callsStream.filter(call -> call != excludeCall);
         }
 
-        // If a phone account handle was specified, only consider calls for that phone account.
-        if (phoneAccountHandle != null) {
-            callsStream = callsStream.filter(
-                    call -> phoneAccountHandle.equals(call.getTargetPhoneAccount()));
-        }
-
-        return (int) callsStream.count();
+        return callsStream;
     }
-
     /**
      * Determines the number of calls (visible to the calling user) matching the specified criteria.
      * This is an overloaded method which is being used in a security patch to fix up the call
@@ -5093,7 +5266,7 @@ public class CallsManager extends Call.ListenerBase
      *                    {@link UserHandle}.
      * @param hasCrossUserAccess indicates if calling user has the INTERACT_ACROSS_USERS permission.
      * @param phoneAccountHandle Where {@code non-null}, calls for this {@link PhoneAccountHandle}
-     *                           are excluded from the count.
+     *                           are included in the count.
      * @param states The list of {@link CallState}s to include in the count.
      * @return Count of calls matching criteria.
      */
@@ -5147,7 +5320,7 @@ public class CallsManager extends Call.ListenerBase
                 exceptCall, phoneAccountHandle, ANY_CALL_STATE);
     }
 
-    private boolean hasMaximumManagedHoldingCalls(Call exceptCall) {
+    public boolean hasMaximumManagedHoldingCalls(Call exceptCall) {
         return MAXIMUM_HOLD_CALLS <= getNumCallsWithState(false /* isSelfManaged */, exceptCall,
                 null /* phoneAccountHandle */, CallState.ON_HOLD);
     }
@@ -5163,7 +5336,7 @@ public class CallsManager extends Call.ListenerBase
                 phoneAccountHandle, CallState.RINGING, CallState.ANSWERED);
     }
 
-    private boolean hasMaximumOutgoingCalls(Call exceptCall) {
+    public boolean hasMaximumOutgoingCalls(Call exceptCall) {
         return MAXIMUM_LIVE_CALLS <= getNumCallsWithState(CALL_FILTER_ALL,
                 exceptCall, null /* phoneAccountHandle */, OUTGOING_CALL_STATES);
     }
@@ -5280,7 +5453,7 @@ public class CallsManager extends Call.ListenerBase
      * <p>
      * Note: This method is only applicable when {@link FeatureFlags#enableCallSequencing()}
      * is false.
-     * @param call The new pending outgoing call.
+     * @param emergencyCall The new pending outgoing call.
      * @return true if room was made, false if no room could be made.
      */
     @VisibleForTesting
@@ -5580,7 +5753,7 @@ public class CallsManager extends Call.ListenerBase
      * @param parentCall The parent call.
      * @return The first non-null phone account handle of the children, or {@code null} if none.
      */
-    private PhoneAccountHandle getFirstChildPhoneAccount(Call parentCall) {
+    public PhoneAccountHandle getFirstChildPhoneAccount(Call parentCall) {
         for (Call childCall : parentCall.getChildCalls()) {
             PhoneAccountHandle childPhoneAccount = childCall.getTargetPhoneAccount();
             if (childPhoneAccount != null) {
@@ -6156,6 +6329,10 @@ public class CallsManager extends Call.ListenerBase
             mConnectionSvrFocusMgr.dump(pw);
             pw.decreaseIndent();
         }
+
+        if (mCallAudioWatchDog != null) {
+            mCallAudioWatchDog.dump(pw);
+        }
     }
 
     /**
@@ -6662,7 +6839,13 @@ public class CallsManager extends Call.ListenerBase
         public void performAction() {
             synchronized (mLock) {
                 Log.d(this, "perform unhold call for %s", mCall);
-                mCall.unhold("held " + mPreviouslyHeldCallId);
+                CompletableFuture<Boolean> unholdFuture =
+                        mCall.unhold("held " + mPreviouslyHeldCallId);
+                mCallSequencingAdapter.maybeLogFutureResultTransaction(unholdFuture,
+                        "performAction", "AUC.pA", "performAction: unhold call transaction "
+                                + "succeeded. Call state is active.",
+                        "performAction: unhold call transaction failed. Call state did not "
+                                + "move to active in designated time.");
             }
         }
     }
@@ -6684,10 +6867,11 @@ public class CallsManager extends Call.ListenerBase
                     listener.onIncomingCallAnswered(mCall);
                 }
 
+                CompletableFuture<Boolean> answerCallFuture = null;
                 // We do not update the UI until we get confirmation of the answer() through
                 // {@link #markCallAsActive}.
                 if (mCall.getState() == CallState.RINGING) {
-                    mCall.answer(mVideoState);
+                    answerCallFuture = mCall.answer(mVideoState);
                     setCallState(mCall, CallState.ANSWERED, "answered");
                 } else if (mCall.getState() == CallState.SIMULATED_RINGING) {
                     // If the call's in simulated ringing, we don't have to wait for the CS --
@@ -6698,12 +6882,17 @@ public class CallsManager extends Call.ListenerBase
                     // In certain circumstances, the connection service can lose track of a request
                     // to answer a call. Therefore, if the user presses answer again, still send it
                     // on down, but log a warning in the process and don't change the call state.
-                    mCall.answer(mVideoState);
+                    answerCallFuture = mCall.answer(mVideoState);
                     Log.w(this, "Duplicate answer request for call %s", mCall.getId());
                 }
                 if (isSpeakerphoneAutoEnabledForVideoCalls(mVideoState)) {
                     mCall.setStartWithSpeakerphoneOn(true);
                 }
+                mCallSequencingAdapter.maybeLogFutureResultTransaction(answerCallFuture,
+                        "performAction", "AAC.pA", "performAction: answer call transaction "
+                                + "succeeded. Call state is active.",
+                        "performAction: answer call transaction failed. Call state did not "
+                                + "move to active in designated time.");
             }
         }
     }
@@ -6789,8 +6978,12 @@ public class CallsManager extends Call.ListenerBase
                 if (mTargetCallFocus.getState() != mPreviousCallState) {
                     mTargetCallFocus.setState(mPreviousCallState, "resetting call state");
                 }
-                mCallback.onError(new CallException("failed to switch focus to requested call",
+                String msg = "failed to switch focus to requested call";
+                mCallback.onError(new CallException(msg,
                         CallException.CODE_CALL_CANNOT_BE_SET_TO_ACTIVE));
+                if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                    mAnomalyReporter.reportAnomaly(FAILED_TO_SWITCH_FOCUS_ERROR_UUID, msg);
+                }
                 return;
             }
             // at this point, we know the FocusManager is able to update successfully
@@ -7017,4 +7210,39 @@ public class CallsManager extends Call.ListenerBase
     public void addCallBeingSetup(Call call) {
         mSelfManagedCallsBeingSetup.add(call);
     }
+
+    @VisibleForTesting
+    public CallsManagerCallSequencingAdapter getCallSequencingAdapter() {
+        return mCallSequencingAdapter;
+    }
+
+    @VisibleForTesting
+    public void setCallSequencingAdapter(CallsManagerCallSequencingAdapter adapter) {
+        mCallSequencingAdapter = adapter;
+    }
+
+    public void waitForAudioToUpdate(boolean expectActive) {
+        Log.i(this, "waitForAudioToUpdate");
+        if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+            try {
+                CallAudioRouteController audioRouteController =
+                        (CallAudioRouteController) mCallAudioRouteAdapter;
+                if (expectActive) {
+                    audioRouteController.getAudioActiveCompleteLatch().await(
+                            WAIT_FOR_AUDIO_UPDATE_TIMEOUT, TimeUnit.MILLISECONDS);
+                } else {
+                    audioRouteController.getAudioOperationsCompleteLatch().await(
+                            WAIT_FOR_AUDIO_UPDATE_TIMEOUT, TimeUnit.MILLISECONDS);
+                }
+            } catch (InterruptedException e) {
+                Log.w(this, e.toString());
+            }
+        }
+    }
+
+    @VisibleForTesting
+    public Map<String, CompletableFuture<Pair<Call, PhoneAccountHandle>>>
+    getPendingAccountSelection() {
+        return mPendingAccountSelection;
+    }
 }
diff --git a/src/com/android/server/telecom/ConnectionServiceWrapper.java b/src/com/android/server/telecom/ConnectionServiceWrapper.java
index 915d3ea71..7a95cc850 100644
--- a/src/com/android/server/telecom/ConnectionServiceWrapper.java
+++ b/src/com/android/server/telecom/ConnectionServiceWrapper.java
@@ -96,7 +96,8 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         ConnectionServiceFocusManager.ConnectionServiceFocus, CallSourceService {
 
     /**
-     * Anomaly Report UUIDs and corresponding error descriptions specific to CallsManager.
+     * Anomaly Report UUIDs and corresponding error descriptions specific to
+     * ConnectionServiceWrapper.
      */
     public static final UUID CREATE_CONNECTION_TIMEOUT_ERROR_UUID =
             UUID.fromString("54b7203d-a79f-4cbd-b639-85cd93a39cbb");
@@ -106,6 +107,15 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
             UUID.fromString("caafe5ea-2472-4c61-b2d8-acb9d47e13dd");
     public static final String CREATE_CONFERENCE_TIMEOUT_ERROR_MSG =
             "Timeout expired before Telecom conference was created.";
+    public static final UUID NULL_SCHEDULED_EXECUTOR_ERROR_UUID =
+            UUID.fromString("af6b293b-239f-4ccf-bf3a-db212594e29d");
+    public static final String NULL_SCHEDULED_EXECUTOR_ERROR_MSG =
+            "Scheduled executor is null when creating connection/conference.";
+    public static final UUID EXECUTOR_REJECTED_EXECUTION_ERROR_UUID =
+            UUID.fromString("649b348c-9d3f-451e-bae9-d9920e7b422c");
+
+    public static final String EXECUTOR_REJECTED_EXECUTION_ERROR_MSG =
+            "Scheduled executor caused a Rejected Execution Exception when creating connection.";
 
     private static final String TELECOM_ABBREVIATION = "cast";
     private static final long SERVICE_BINDING_TIMEOUT = 15000L;
@@ -1667,9 +1677,15 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                     } catch (RejectedExecutionException e) {
                         Log.e(this, e, "createConference: mScheduledExecutor was "
                                 + "already shutdown");
+                        mAnomalyReporter.reportAnomaly(
+                                EXECUTOR_REJECTED_EXECUTION_ERROR_UUID,
+                                EXECUTOR_REJECTED_EXECUTION_ERROR_MSG);
                     }
                 } else {
                     Log.w(this, "createConference: Scheduled executor is null or shutdown");
+                    mAnomalyReporter.reportAnomaly(
+                        NULL_SCHEDULED_EXECUTOR_ERROR_UUID,
+                        NULL_SCHEDULED_EXECUTOR_ERROR_MSG);
                 }
                 try {
                     mServiceInterface.createConference(
@@ -1806,9 +1822,15 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                     } catch (RejectedExecutionException e) {
                         Log.e(this, e, "createConnection: mScheduledExecutor was "
                                 + "already shutdown");
+                        mAnomalyReporter.reportAnomaly(
+                                EXECUTOR_REJECTED_EXECUTION_ERROR_UUID,
+                                EXECUTOR_REJECTED_EXECUTION_ERROR_MSG);
                     }
                 } else {
                     Log.w(this, "createConnection: Scheduled executor is null or shutdown");
+                    mAnomalyReporter.reportAnomaly(
+                        NULL_SCHEDULED_EXECUTOR_ERROR_UUID,
+                        NULL_SCHEDULED_EXECUTOR_ERROR_MSG);
                 }
                 try {
                     if (mFlags.cswServiceInterfaceIsNull() && mServiceInterface == null) {
diff --git a/src/com/android/server/telecom/CreateConnectionProcessor.java b/src/com/android/server/telecom/CreateConnectionProcessor.java
index a2c742d43..c2b5da10b 100644
--- a/src/com/android/server/telecom/CreateConnectionProcessor.java
+++ b/src/com/android/server/telecom/CreateConnectionProcessor.java
@@ -37,12 +37,13 @@ import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.ArrayList;
 import java.util.Collection;
-import java.util.Collections;
-import java.util.Comparator;
+import java.util.HashMap;
 import java.util.HashSet;
 import java.util.Iterator;
 import java.util.List;
+import java.util.Map;
 import java.util.Objects;
+import java.util.Set;
 import java.util.stream.Collectors;
 
 /**
@@ -127,6 +128,21 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
         }
     };
 
+    /**
+     * Call states which should be prioritized when sorting phone accounts. The ordering is
+     * intentional and should NOT be modified. Other call states will not have any priority.
+     */
+    private static final int[] PRIORITY_CALL_STATES = new int []
+            {CallState.ACTIVE, CallState.ON_HOLD, CallState.DIALING, CallState.RINGING};
+    private static final int DEFAULT_CALL_STATE_PRIORITY = PRIORITY_CALL_STATES.length;
+    private static final Map<Integer, Integer> mCallStatePriorityMap = new HashMap<>();
+    static {
+        for (int i = 0; i < PRIORITY_CALL_STATES.length; i++) {
+            mCallStatePriorityMap.put(PRIORITY_CALL_STATES[i], i);
+        }
+    }
+
+
     private ITelephonyManagerAdapter mTelephonyAdapter = new ITelephonyManagerAdapterImpl();
 
     private final Call mCall;
@@ -136,6 +152,7 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
     private CreateConnectionResponse mCallResponse;
     private DisconnectCause mLastErrorDisconnectCause;
     private final PhoneAccountRegistrar mPhoneAccountRegistrar;
+    private final CallsManager mCallsManager;
     private final Context mContext;
     private final FeatureFlags mFlags;
     private final Timeouts.Adapter mTimeoutsAdapter;
@@ -148,6 +165,7 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
             ConnectionServiceRepository repository,
             CreateConnectionResponse response,
             PhoneAccountRegistrar phoneAccountRegistrar,
+            CallsManager callsManager,
             Context context,
             FeatureFlags featureFlags,
             Timeouts.Adapter timeoutsAdapter) {
@@ -156,6 +174,7 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
         mRepository = repository;
         mCallResponse = response;
         mPhoneAccountRegistrar = phoneAccountRegistrar;
+        mCallsManager = callsManager;
         mContext = context;
         mConnectionAttempt = 0;
         mFlags = featureFlags;
@@ -693,6 +712,23 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
                 return retval;
             }
 
+            // Sort accounts by ongoing call states
+            Set<Integer> callStatesAccount1 = mCallsManager.getCalls().stream()
+                    .filter(c -> Objects.equals(account1.getAccountHandle(),
+                            c.getTargetPhoneAccount()))
+                    .map(Call::getState).collect(Collectors.toSet());
+            Set<Integer> callStatesAccount2 = mCallsManager.getCalls().stream()
+                    .filter(c -> Objects.equals(account2.getAccountHandle(),
+                            c.getTargetPhoneAccount()))
+                    .map(Call::getState).collect(Collectors.toSet());
+            int account1Priority = computeCallStatePriority(callStatesAccount1);
+            int account2Priority = computeCallStatePriority(callStatesAccount2);
+            Log.d(this, "account1: %s, call state priority: %s", account1, account1Priority);
+            Log.d(this, "account2: %s, call state priority: %s", account2, account2Priority);
+            if (account1Priority != account2Priority) {
+                return account1Priority < account2Priority ? -1 : 1;
+            }
+
             // Prefer the user's choice if all PhoneAccounts are associated with valid logical
             // slots.
             if (userPreferredAccount != null) {
@@ -731,6 +767,25 @@ public class CreateConnectionProcessor implements CreateConnectionResponse {
         });
     }
 
+    /**
+     * Computes the call state priority based on the passed in call states associated with the
+     * calls present on the phone account. The lower the value, the higher the priority (i.e.
+     * ACTIVE (0) < HOLDING (1) < DIALING (2) < RINGING (3) equates to ACTIVE holding the highest
+     * priority).
+     */
+    private int computeCallStatePriority(Set<Integer> callStates) {
+        int priority = DEFAULT_CALL_STATE_PRIORITY;
+        for (int state: callStates) {
+            if (priority == mCallStatePriorityMap.get(CallState.ACTIVE)) {
+                return priority;
+            } else if (mCallStatePriorityMap.containsKey(state)
+                    && priority > mCallStatePriorityMap.get(state)) {
+                priority = mCallStatePriorityMap.get(state);
+            }
+        }
+        return priority;
+    }
+
     private static String nullToEmpty(String str) {
         return str == null ? "" : str;
     }
diff --git a/src/com/android/server/telecom/CreateConnectionTimeout.java b/src/com/android/server/telecom/CreateConnectionTimeout.java
index 3046ca4fb..2889e1353 100644
--- a/src/com/android/server/telecom/CreateConnectionTimeout.java
+++ b/src/com/android/server/telecom/CreateConnectionTimeout.java
@@ -16,8 +16,6 @@
 
 package com.android.server.telecom;
 
-import static com.android.internal.telephony.flags.Flags.carrierEnabledSatelliteFlag;
-
 import android.content.Context;
 import android.os.Handler;
 import android.os.Looper;
@@ -117,11 +115,6 @@ public final class CreateConnectionTimeout extends Runnable {
 
     @Override
     public void loggedRun() {
-        if (!carrierEnabledSatelliteFlag()) {
-            timeoutCallIfNeeded();
-            return;
-        }
-
         PhoneAccountHandle connectionManager =
                 mPhoneAccountRegistrar.getSimCallManagerFromCall(mCall);
         if (connectionManager != null) {
diff --git a/src/com/android/server/telecom/InCallController.java b/src/com/android/server/telecom/InCallController.java
index 3f8f57995..6cfa4fdea 100644
--- a/src/com/android/server/telecom/InCallController.java
+++ b/src/com/android/server/telecom/InCallController.java
@@ -44,6 +44,7 @@ import android.os.Handler;
 import android.os.IBinder;
 import android.os.Looper;
 import android.os.PackageTagsList;
+import android.os.Parcel;
 import android.os.RemoteException;
 import android.os.UserHandle;
 import android.os.UserManager;
@@ -1723,7 +1724,8 @@ public class InCallController extends CallsManagerListenerBase implements
 
                     try {
                         inCallService.updateCall(
-                                sanitizeParcelableCallForService(info, parcelableCall));
+                                copyIfLocal(sanitizeParcelableCallForService(info, parcelableCall),
+                                        inCallService));
                     } catch (RemoteException ignored) {
                     }
                 }
@@ -2854,7 +2856,8 @@ public class InCallController extends CallsManagerListenerBase implements
             ParcelableCall parcelableCall, ComponentName componentName) {
         try {
             inCallService.updateCall(
-                    sanitizeParcelableCallForService(info, parcelableCall));
+                    copyIfLocal(sanitizeParcelableCallForService(info, parcelableCall),
+                            inCallService));
         } catch (RemoteException exception) {
             Log.w(this, "Call status update did not send to: "
                     + componentName + " successfully with error " + exception);
@@ -3435,4 +3438,43 @@ public class InCallController extends CallsManagerListenerBase implements
         }
         return false;
     }
+
+    /**
+     * Given a {@link ParcelableCall} and a {@link IInCallService}, determines if the ICS binder is
+     * local or remote.  If the binder is remote, we just return the parcelable call instance
+     * already constructed.
+     * If the binder if local, as will be the case for
+     * {@code EnhancedConfirmationCallTrackerService} (or any other ICS in the system server, the
+     * underlying Binder implementation is NOT going to parcel and unparcel the
+     * {@link ParcelableCall} instance automatically.  This means that the parcelable call instance
+     * is passed by reference and that the ICS in the system server could potentially try to access
+     * internals in the {@link ParcelableCall} in an unsafe manner.  As a workaround, we will
+     * manually parcel and unparcel the {@link ParcelableCall} instance so that they get a fresh
+     * copy that they can use safely.
+     *
+     * @param parcelableCall The ParcelableCall instance we want to maybe copy.
+     * @param remote the binder the call is going out over.
+     * @return either the original {@link ParcelableCall} or a deep copy of it if the destination
+     * binder is local.
+     */
+    private ParcelableCall copyIfLocal(ParcelableCall parcelableCall, IInCallService remote) {
+        // We care more about parceling than local (though they should be the same); so, use
+        // queryLocalInterface since that's what Binder uses to decide if it needs to parcel.
+        if (remote.asBinder().queryLocalInterface(IInCallService.Stub.DESCRIPTOR) == null) {
+            // No local interface, so binder itself will parcel and thus we don't need to.
+            return parcelableCall;
+        }
+        // Binder won't be parceling; however, the remotes assume they have their own native
+        // objects (and don't know if caller is local or not), so we need to make a COPY here so
+        // that the remote can clean it up without clearing the original transaction.
+        // Since there's no direct `copy` for Transaction, we have to parcel/unparcel instead.
+        final Parcel p = Parcel.obtain();
+        try {
+            parcelableCall.writeToParcel(p, 0);
+            p.setDataPosition(0);
+            return ParcelableCall.CREATOR.createFromParcel(p);
+        } finally {
+            p.recycle();
+        }
+    }
 }
diff --git a/src/com/android/server/telecom/InCallTonePlayer.java b/src/com/android/server/telecom/InCallTonePlayer.java
index b7edeb512..2bc1e3918 100644
--- a/src/com/android/server/telecom/InCallTonePlayer.java
+++ b/src/com/android/server/telecom/InCallTonePlayer.java
@@ -56,17 +56,19 @@ public class InCallTonePlayer extends Thread {
         private final MediaPlayerFactory mMediaPlayerFactory;
         private final AudioManagerAdapter mAudioManagerAdapter;
         private final FeatureFlags mFeatureFlags;
+        private final Looper mLooper;
 
         public Factory(CallAudioRoutePeripheralAdapter callAudioRoutePeripheralAdapter,
                 TelecomSystem.SyncRoot lock, ToneGeneratorFactory toneGeneratorFactory,
                 MediaPlayerFactory mediaPlayerFactory, AudioManagerAdapter audioManagerAdapter,
-                FeatureFlags flags) {
+                FeatureFlags flags, Looper looper) {
             mCallAudioRoutePeripheralAdapter = callAudioRoutePeripheralAdapter;
             mLock = lock;
             mToneGeneratorFactory = toneGeneratorFactory;
             mMediaPlayerFactory = mediaPlayerFactory;
             mAudioManagerAdapter = audioManagerAdapter;
             mFeatureFlags = flags;
+            mLooper = looper;
         }
 
         public void setCallAudioManager(CallAudioManager callAudioManager) {
@@ -76,7 +78,7 @@ public class InCallTonePlayer extends Thread {
         public InCallTonePlayer createPlayer(Call call, int tone) {
             return new InCallTonePlayer(call, tone, mCallAudioManager,
                     mCallAudioRoutePeripheralAdapter, mLock, mToneGeneratorFactory,
-                    mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags);
+                    mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags, mLooper);
         }
     }
 
@@ -199,7 +201,7 @@ public class InCallTonePlayer extends Thread {
     private final CallAudioManager mCallAudioManager;
     private final CallAudioRoutePeripheralAdapter mCallAudioRoutePeripheralAdapter;
 
-    private final Handler mMainThreadHandler = new Handler(Looper.getMainLooper());
+    private final Handler mMainThreadHandler;
 
     /** The ID of the tone to play. */
     private final int mToneId;
@@ -242,7 +244,8 @@ public class InCallTonePlayer extends Thread {
             ToneGeneratorFactory toneGeneratorFactory,
             MediaPlayerFactory mediaPlayerFactor,
             AudioManagerAdapter audioManagerAdapter,
-            FeatureFlags flags) {
+            FeatureFlags flags,
+            Looper looper) {
         mCall = call;
         mState = STATE_OFF;
         mToneId = toneId;
@@ -253,6 +256,7 @@ public class InCallTonePlayer extends Thread {
         mMediaPlayerFactory = mediaPlayerFactor;
         mAudioManagerAdapter = audioManagerAdapter;
         mFeatureFlags = flags;
+        mMainThreadHandler = new Handler(looper);
     }
 
     /** {@inheritDoc} */
diff --git a/src/com/android/server/telecom/LogUtils.java b/src/com/android/server/telecom/LogUtils.java
index d98ebfe6b..d927f8f45 100644
--- a/src/com/android/server/telecom/LogUtils.java
+++ b/src/com/android/server/telecom/LogUtils.java
@@ -226,10 +226,14 @@ public class LogUtils {
         public static final String FLASH_NOTIFICATION_START = "FLASH_NOTIFICATION_START";
         public static final String FLASH_NOTIFICATION_STOP = "FLASH_NOTIFICATION_STOP";
         public static final String GAINED_FGS_DELEGATION = "GAINED_FGS_DELEGATION";
+        public static final String ALREADY_HAS_FGS_DELEGATION = "ALREADY_HAS_FGS_DELEGATION";
+        public static final String MAINTAINING_FGS_DELEGATION = "MAINTAINING_FGS_DELEGATION";
         public static final String GAIN_FGS_DELEGATION_FAILED = "GAIN_FGS_DELEGATION_FAILED";
         public static final String LOST_FGS_DELEGATION = "LOST_FGS_DELEGATION";
         public static final String START_STREAMING = "START_STREAMING";
         public static final String STOP_STREAMING = "STOP_STREAMING";
+        public static final String AUDIO_ATTR = "AUDIO_ATTR";
+        public static final String ANSWER_DROPS_FG = "ANSWER_DROPS_FG";
 
         public static class Timings {
             public static final String ACCEPT_TIMING = "accept";
diff --git a/src/com/android/server/telecom/ParcelableCallUtils.java b/src/com/android/server/telecom/ParcelableCallUtils.java
index 3573de82e..5764a9c1b 100644
--- a/src/com/android/server/telecom/ParcelableCallUtils.java
+++ b/src/com/android/server/telecom/ParcelableCallUtils.java
@@ -263,6 +263,7 @@ public class ParcelableCallUtils {
                 .setContactDisplayName(call.getName())
                 .setActiveChildCallId(activeChildCallId)
                 .setContactPhotoUri(contactPhotoUri)
+                .setAssociatedUser(call.getAssociatedUser())
                 .createParcelableCall();
     }
 
diff --git a/src/com/android/server/telecom/PendingAudioRoute.java b/src/com/android/server/telecom/PendingAudioRoute.java
index d21ac5635..37c70ad1d 100644
--- a/src/com/android/server/telecom/PendingAudioRoute.java
+++ b/src/com/android/server/telecom/PendingAudioRoute.java
@@ -70,8 +70,24 @@ public class PendingAudioRoute {
         mCommunicationDeviceType = AudioRoute.TYPE_INVALID;
     }
 
-    void setOrigRoute(boolean active, AudioRoute origRoute) {
-        origRoute.onOrigRouteAsPendingRoute(active, this, mAudioManager, mBluetoothRouteManager);
+    /**
+     * Sets the originating route information, and begins the process of transitioning OUT of the
+     * originating route.
+     * Note: We also pass in whether the destination route is going to be active.  This is so that
+     * {@link AudioRoute#onOrigRouteAsPendingRoute(boolean, PendingAudioRoute, AudioManager,
+     * BluetoothRouteManager)} knows whether or not the destination route will be active or not and
+     * can determine whether or not it needs to call {@link AudioManager#clearCommunicationDevice()}
+     * or not.  To optimize audio performance we only need to clear the communication device if the
+     * end result is going to be that we are in an inactive state.
+     * @param isOriginActive Whether the origin is active.
+     * @param origRoute The origin.
+     * @param isDestActive Whether the destination will be active.
+     */
+    void setOrigRoute(boolean isOriginActive, AudioRoute origRoute, boolean isDestActive,
+            boolean isScoAlreadyConnected) {
+        mActive = isDestActive;
+        origRoute.onOrigRouteAsPendingRoute(isOriginActive, this, mAudioManager,
+                mBluetoothRouteManager, isScoAlreadyConnected);
         mOrigRoute = origRoute;
     }
 
@@ -80,9 +96,9 @@ public class PendingAudioRoute {
     }
 
     void setDestRoute(boolean active, AudioRoute destRoute, BluetoothDevice device,
-            boolean isScoAudioConnected) {
+            boolean isScoAlreadyConnected) {
         destRoute.onDestRouteAsPendingRoute(active, this, device,
-                mAudioManager, mBluetoothRouteManager, isScoAudioConnected);
+                mAudioManager, mBluetoothRouteManager, isScoAlreadyConnected);
         mActive = active;
         mDestRoute = destRoute;
     }
@@ -134,6 +150,10 @@ public class PendingAudioRoute {
         return mPendingMessages;
     }
 
+    /**
+     * Whether the destination {@link #getDestRoute()} will be active or not.
+     * @return {@code true} if destination will be active, {@code false} otherwise.
+     */
     public boolean isActive() {
         return mActive;
     }
@@ -154,4 +174,14 @@ public class PendingAudioRoute {
     public FeatureFlags getFeatureFlags() {
         return mFeatureFlags;
     }
+
+    @Override
+    public String toString() {
+        return "PendingAudioRoute{" +
+                ", mOrigRoute=" + mOrigRoute +
+                ", mDestRoute=" + mDestRoute +
+                ", mActive=" + mActive +
+                ", mCommunicationDeviceType=" + mCommunicationDeviceType +
+                '}';
+    }
 }
diff --git a/src/com/android/server/telecom/PhoneAccountRegistrar.java b/src/com/android/server/telecom/PhoneAccountRegistrar.java
index 1a1af925f..c59cf2c11 100644
--- a/src/com/android/server/telecom/PhoneAccountRegistrar.java
+++ b/src/com/android/server/telecom/PhoneAccountRegistrar.java
@@ -79,6 +79,7 @@ import java.lang.Integer;
 import java.lang.SecurityException;
 import java.lang.String;
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.Collections;
 import java.util.Comparator;
 import java.util.HashMap;
@@ -180,7 +181,7 @@ public class PhoneAccountRegistrar {
     private final TelecomSystem.SyncRoot mLock;
     private State mState;
     private UserHandle mCurrentUserHandle;
-    private String mTestPhoneAccountPackageNameFilter;
+    private final Set<String> mTestPhoneAccountPackageNameFilters;
     private interface PhoneAccountRegistrarWriteLock {}
     private final PhoneAccountRegistrarWriteLock mWriteLock =
             new PhoneAccountRegistrarWriteLock() {};
@@ -214,6 +215,7 @@ public class PhoneAccountRegistrar {
         mAppLabelProxy = appLabelProxy;
         mCurrentUserHandle = Process.myUserHandle();
         mTelecomFeatureFlags = telecomFeatureFlags;
+        mTestPhoneAccountPackageNameFilters = new HashSet<>();
 
         if (telephonyFeatureFlags != null) {
             mTelephonyFeatureFlags = telephonyFeatureFlags;
@@ -606,23 +608,33 @@ public class PhoneAccountRegistrar {
      * {@link PhoneAccount}s with the same package name.
      */
     public void setTestPhoneAccountPackageNameFilter(String packageNameFilter) {
-        mTestPhoneAccountPackageNameFilter = packageNameFilter;
-        Log.i(this, "filter set for PhoneAccounts, packageName=" + packageNameFilter);
+        mTestPhoneAccountPackageNameFilters.clear();
+        if (packageNameFilter == null) {
+            return;
+        }
+        String [] pkgNamesFilter = packageNameFilter.split(",");
+        mTestPhoneAccountPackageNameFilters.addAll(Arrays.asList(pkgNamesFilter));
+        StringBuilder pkgNames = new StringBuilder();
+        for (int i = 0; i < pkgNamesFilter.length; i++) {
+            pkgNames.append(pkgNamesFilter[i])
+                    .append(i != pkgNamesFilter.length - 1 ? ", " : ".");
+        }
+        Log.i(this, "filter set for PhoneAccounts, packageNames: %s", pkgNames.toString());
     }
 
     /**
      * Filter the given {@link List<PhoneAccount>} and keep only {@link PhoneAccount}s that have the
-     * #mTestPhoneAccountPackageNameFilter.
+     * #mTestPhoneAccountPackageNameFilters.
      * @param accounts List of {@link PhoneAccount}s to filter.
      * @return new list of filtered {@link PhoneAccount}s.
      */
     public List<PhoneAccount> filterRestrictedPhoneAccounts(List<PhoneAccount> accounts) {
-        if (TextUtils.isEmpty(mTestPhoneAccountPackageNameFilter)) {
+        if (mTestPhoneAccountPackageNameFilters.isEmpty()) {
             return new ArrayList<>(accounts);
         }
-        // Remove all PhoneAccounts that do not have the same package name as the filter.
-        return accounts.stream().filter(account -> mTestPhoneAccountPackageNameFilter.equals(
-                account.getAccountHandle().getComponentName().getPackageName()))
+        // Remove all PhoneAccounts that do not have the same package name (prefix) as the filter.
+        return accounts.stream().filter(account -> mTestPhoneAccountPackageNameFilters
+                .contains(account.getAccountHandle().getComponentName().getPackageName()))
                 .collect(Collectors.toList());
     }
 
@@ -1976,7 +1988,7 @@ public class PhoneAccountRegistrar {
             }
             pw.decreaseIndent();
             pw.increaseIndent();
-            pw.println("test emergency PhoneAccount filter: " + mTestPhoneAccountPackageNameFilter);
+            pw.println("test emergency PhoneAccount filter: " + mTestPhoneAccountPackageNameFilters);
             pw.decreaseIndent();
         }
     }
@@ -2940,4 +2952,24 @@ public class PhoneAccountRegistrar {
             return null;
         }
     };
+
+    /**
+     * Determines if an app specified by a uid has a phone account for that uid.
+     * @param uid the uid to check
+     * @return {@code true} if there is a phone account for that UID, {@code false} otherwise.
+     */
+    public boolean hasPhoneAccountForUid(int uid) {
+        String[] packageNames = mContext.getPackageManager().getPackagesForUid(uid);
+        if (packageNames == null || packageNames.length == 0) {
+            return false;
+        }
+        UserHandle userHandle = UserHandle.getUserHandleForUid(uid);
+        return mState.accounts.stream()
+                .anyMatch(p -> {
+                    PhoneAccountHandle handle = p.getAccountHandle();
+                    return handle.getUserHandle().equals(userHandle)
+                            && Arrays.stream(packageNames).anyMatch( s -> s.equals(
+                                    handle.getComponentName().getPackageName()));
+                });
+    }
 }
diff --git a/src/com/android/server/telecom/RespondViaSmsManager.java b/src/com/android/server/telecom/RespondViaSmsManager.java
index 2dcd093ce..bff33133e 100644
--- a/src/com/android/server/telecom/RespondViaSmsManager.java
+++ b/src/com/android/server/telecom/RespondViaSmsManager.java
@@ -25,8 +25,10 @@ import android.content.Intent;
 import android.content.IntentFilter;
 import android.content.SharedPreferences;
 import android.content.res.Resources;
+import android.os.Looper;
 import android.telecom.Connection;
 import android.telecom.Log;
+import android.telecom.Logging.Session;
 import android.telephony.PhoneNumberUtils;
 import android.telephony.SmsManager;
 import android.telephony.SubscriptionManager;
@@ -36,9 +38,13 @@ import android.text.SpannableString;
 import android.text.TextUtils;
 import android.widget.Toast;
 
+import com.android.server.telecom.flags.FeatureFlags;
+
 import java.text.Bidi;
 import java.util.ArrayList;
 import java.util.List;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.Executor;
 
 /**
  * Helper class to manage the "Respond via Message" feature for incoming calls.
@@ -74,10 +80,15 @@ public class RespondViaSmsManager extends CallsManagerListenerBase {
 
     private final CallsManager mCallsManager;
     private final TelecomSystem.SyncRoot mLock;
+    private final Executor mAsyncExecutor;
+    private final FeatureFlags mFeatureFlags;
 
-    public RespondViaSmsManager(CallsManager callsManager, TelecomSystem.SyncRoot lock) {
+    public RespondViaSmsManager(CallsManager callsManager, TelecomSystem.SyncRoot lock,
+        Executor asyncExecutor, FeatureFlags featureFlags) {
         mCallsManager = callsManager;
         mLock = lock;
+        mAsyncExecutor = asyncExecutor;
+        mFeatureFlags = featureFlags;
     }
 
     /**
@@ -93,49 +104,75 @@ public class RespondViaSmsManager extends CallsManagerListenerBase {
      */
     public void loadCannedTextMessages(final CallsManager.Response<Void, List<String>> response,
             final Context context) {
-        new Thread() {
-            @Override
-            public void run() {
-                Log.d(RespondViaSmsManager.this, "loadCannedResponses() starting");
-
-                // This function guarantees that QuickResponses will be in our
-                // SharedPreferences with the proper values considering there may be
-                // old QuickResponses in Telephony pre L.
-                QuickResponseUtils.maybeMigrateLegacyQuickResponses(context);
-
-                final SharedPreferences prefs = context.getSharedPreferences(
-                        QuickResponseUtils.SHARED_PREFERENCES_NAME,
-                        Context.MODE_PRIVATE | Context.MODE_MULTI_PROCESS);
-                final Resources res = context.getResources();
-
-                final ArrayList<String> textMessages = new ArrayList<>(
-                        QuickResponseUtils.NUM_CANNED_RESPONSES);
-
-                // Where the user has changed a quick response back to the same text as the
-                // original text, clear the shared pref.  This ensures we always load the resource
-                // in the current active language.
-                QuickResponseUtils.maybeResetQuickResponses(context, prefs);
-
-                // Note the default values here must agree with the corresponding
-                // android:defaultValue attributes in respond_via_sms_settings.xml.
-                textMessages.add(0, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_1,
-                        res.getString(R.string.respond_via_sms_canned_response_1)));
-                textMessages.add(1, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_2,
-                        res.getString(R.string.respond_via_sms_canned_response_2)));
-                textMessages.add(2, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_3,
-                        res.getString(R.string.respond_via_sms_canned_response_3)));
-                textMessages.add(3, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_4,
-                        res.getString(R.string.respond_via_sms_canned_response_4)));
-
-                Log.d(RespondViaSmsManager.this,
-                        "loadCannedResponses() completed, found responses: %s",
-                        textMessages.toString());
-
-                synchronized (mLock) {
-                    response.onResult(null, textMessages);
+        if (mFeatureFlags.enableRespondViaSmsManagerAsync()) {
+            CompletableFuture<List<String>> cannedTextMessages = new CompletableFuture<>();
+            Session s = Log.createSubsession();
+            mAsyncExecutor.execute(() -> {
+                try {
+                    Log.continueSession(s, "RVSM.lCTM.e");
+                    cannedTextMessages.complete(loadCannedTextMessages(context));
+                } finally {
+                    Log.endSession();
                 }
-            }
-        }.start();
+            });
+            cannedTextMessages.whenCompleteAsync((result, exception) -> {
+                    if (exception != null) {
+                        Log.e(RespondViaSmsManager.class.getSimpleName(), exception,
+                                "loadCannedTextMessages failed");
+                        response.onError(null, -1, exception.toString());
+                    } else {
+                        response.onResult(null, result);
+                    }
+                }, new LoggedHandlerExecutor(context.getMainThreadHandler(), "RVSM.lCTM.c", mLock));
+
+        } else {
+          new Thread() {
+                @Override
+                public void run() {
+                    List<String> textMessages = loadCannedTextMessages(context);
+                    synchronized (mLock) {
+                        response.onResult(null, textMessages);
+                    }
+                }
+            }.start();
+        }
+    }
+
+    private List<String> loadCannedTextMessages(final Context context) {
+        Log.d(RespondViaSmsManager.this, "loadCannedTextMessages() starting");
+        // This function guarantees that QuickResponses will be in our
+        // SharedPreferences with the proper values considering there may be
+        // old QuickResponses in Telephony pre L.
+        QuickResponseUtils.maybeMigrateLegacyQuickResponses(context);
+
+        final SharedPreferences prefs = context.getSharedPreferences(
+                QuickResponseUtils.SHARED_PREFERENCES_NAME,
+                Context.MODE_PRIVATE | Context.MODE_MULTI_PROCESS);
+        final Resources res = context.getResources();
+
+        final ArrayList<String> textMessages = new ArrayList<>(
+                QuickResponseUtils.NUM_CANNED_RESPONSES);
+
+        // Where the user has changed a quick response back to the same text as the
+        // original text, clear the shared pref.  This ensures we always load the resource
+        // in the current active language.
+        QuickResponseUtils.maybeResetQuickResponses(context, prefs);
+
+        // Note the default values here must agree with the corresponding
+        // android:defaultValue attributes in respond_via_sms_settings.xml.
+        textMessages.add(0, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_1,
+                res.getString(R.string.respond_via_sms_canned_response_1)));
+        textMessages.add(1, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_2,
+                res.getString(R.string.respond_via_sms_canned_response_2)));
+        textMessages.add(2, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_3,
+                res.getString(R.string.respond_via_sms_canned_response_3)));
+        textMessages.add(3, prefs.getString(QuickResponseUtils.KEY_CANNED_RESPONSE_PREF_4,
+                res.getString(R.string.respond_via_sms_canned_response_4)));
+
+        Log.d(RespondViaSmsManager.this,
+                "loadCannedResponses() completed, found responses: %s",
+                textMessages.toString());
+        return textMessages;
     }
 
     @Override
@@ -199,7 +236,23 @@ public class RespondViaSmsManager extends CallsManagerListenerBase {
                     subId);
             return;
         }
+        if(mFeatureFlags.enableRespondViaSmsManagerAsync()) {
+            Session s = Log.createSubsession();
+            mAsyncExecutor.execute(() -> {
+                try {
+                    Log.continueSession(s, "RVSM.rCWM.e");
+                    sendTextMessage(context, phoneNumber, textMessage, subId, contactName);
+                } finally {
+                    Log.endSession();
+                }
+            });
+        } else {
+            sendTextMessage(context, phoneNumber, textMessage, subId, contactName);
+        }
+    }
 
+    private void sendTextMessage(Context context, String phoneNumber, String textMessage,
+            int subId, String contactName) {
         SmsManager smsManager = SmsManager.getSmsManagerForSubscriptionId(subId);
         try {
             ArrayList<String> messageParts = smsManager.divideMessage(textMessage);
diff --git a/src/com/android/server/telecom/Ringer.java b/src/com/android/server/telecom/Ringer.java
index bfaadf0df..5904689c8 100644
--- a/src/com/android/server/telecom/Ringer.java
+++ b/src/com/android/server/telecom/Ringer.java
@@ -31,6 +31,7 @@ import android.content.res.Resources;
 import android.media.AudioAttributes;
 import android.media.AudioManager;
 import android.media.Ringtone;
+import android.media.RingtoneManager;
 import android.media.Utils;
 import android.media.VolumeShaper;
 import android.media.audio.Flags;
@@ -304,6 +305,8 @@ public class Ringer {
                 return false;
             }
 
+            mAttributesLatch = new CountDownLatch(1);
+
             // Use completable future to establish a timeout, not intent to make these work outside
             // the main thread asynchronously
             // TODO: moving these RingerAttributes calculation out of Telecom lock to avoid blocking
@@ -313,7 +316,6 @@ public class Ringer {
 
             RingerAttributes attributes = null;
             try {
-                mAttributesLatch = new CountDownLatch(1);
                 attributes = ringerAttributesFuture.get(
                         RINGER_ATTRIBUTES_TIMEOUT, TimeUnit.MILLISECONDS);
             } catch (ExecutionException | InterruptedException | TimeoutException e) {
@@ -431,6 +433,11 @@ public class Ringer {
                     && isVibratorEnabled) {
                 Log.i(this, "Muted haptic channels since audio coupled ramping ringer is disabled");
                 hapticChannelsMuted = true;
+                if (useCustomVibration(foregroundCall)) {
+                    Log.i(this,
+                            "Not muted haptic channel for customization when apply ramping ringer");
+                    hapticChannelsMuted = false;
+                }
             } else if (hapticChannelsMuted) {
                 Log.i(this,
                         "Muted haptic channels isVibratorEnabled=%s, hapticPlaybackSupported=%s",
@@ -442,7 +449,7 @@ public class Ringer {
             if (!isHapticOnly) {
                 ringtoneInfoSupplier = () -> mRingtoneFactory.getRingtone(
                         foregroundCall, mVolumeShaperConfig, finalHapticChannelsMuted);
-            } else if (Flags.enableRingtoneHapticsCustomization() && mRingtoneVibrationSupported) {
+            } else if (useCustomVibration(foregroundCall)) {
                 ringtoneInfoSupplier = () -> mRingtoneFactory.getRingtone(
                         foregroundCall, null, false);
             }
@@ -521,6 +528,21 @@ public class Ringer {
         }
     }
 
+    private boolean useCustomVibration(@NonNull Call foregroundCall) {
+        return Flags.enableRingtoneHapticsCustomization() && mRingtoneVibrationSupported
+                && hasExplicitVibration(foregroundCall);
+    }
+
+    private boolean hasExplicitVibration(@NonNull Call foregroundCall) {
+        final Uri ringtoneUri = foregroundCall.getRingtone();
+        if (ringtoneUri != null) {
+            // TODO(b/399265235) : Avoid this hidden API access for mainline
+            return Utils.hasVibration(ringtoneUri);
+        }
+        return Utils.hasVibration(RingtoneManager.getActualDefaultRingtoneUri(
+                mContext, RingtoneManager.TYPE_RINGTONE));
+    }
+
     /**
      * Try to reserve the vibrator for this call, returning false if it's already committed.
      * The vibration will be started by AsyncRingtonePlayer to ensure timing is aligned with the
@@ -831,7 +853,9 @@ public class Ringer {
             call.setUserMissed(USER_MISSED_DND_MODE);
         }
 
-        mAttributesLatch.countDown();
+        if (mAttributesLatch != null) {
+            mAttributesLatch.countDown();
+        }
         return builder.setEndEarly(endEarly)
                 .setLetDialerHandleRinging(letDialerHandleRinging)
                 .setAcquireAudioFocus(shouldAcquireAudioFocus)
diff --git a/src/com/android/server/telecom/TelecomBroadcastIntentProcessor.java b/src/com/android/server/telecom/TelecomBroadcastIntentProcessor.java
index 523b8418e..2efc79c6c 100644
--- a/src/com/android/server/telecom/TelecomBroadcastIntentProcessor.java
+++ b/src/com/android/server/telecom/TelecomBroadcastIntentProcessor.java
@@ -184,7 +184,8 @@ public final class TelecomBroadcastIntentProcessor {
                 // Answer the current ringing call.
                 Call incomingCall = mCallsManager.getIncomingCallNotifier().getIncomingCall();
                 if (incomingCall != null) {
-                    mCallsManager.answerCall(incomingCall, incomingCall.getVideoState());
+                    mCallsManager.answerCall(incomingCall, incomingCall.getVideoState(),
+                            CallsManager.REQUEST_ORIGIN_TELECOM_DISAMBIGUATION);
                 }
             } finally {
                 Log.endSession();
diff --git a/src/com/android/server/telecom/TelecomServiceImpl.java b/src/com/android/server/telecom/TelecomServiceImpl.java
index e19f1bd26..e84d7a518 100644
--- a/src/com/android/server/telecom/TelecomServiceImpl.java
+++ b/src/com/android/server/telecom/TelecomServiceImpl.java
@@ -27,8 +27,6 @@ import static android.Manifest.permission.READ_PRIVILEGED_PHONE_STATE;
 import static android.Manifest.permission.READ_SMS;
 import static android.Manifest.permission.REGISTER_SIM_SUBSCRIPTION;
 import static android.Manifest.permission.WRITE_SECURE_SETTINGS;
-import static android.telecom.CallAttributes.DIRECTION_INCOMING;
-import static android.telecom.CallAttributes.DIRECTION_OUTGOING;
 import static android.telecom.CallException.CODE_ERROR_UNKNOWN;
 import static android.telecom.TelecomManager.TELECOM_TRANSACTION_SUCCESS;
 
@@ -52,8 +50,6 @@ import android.net.Uri;
 import android.os.Binder;
 import android.os.Build;
 import android.os.Bundle;
-import android.os.Handler;
-import android.os.Looper;
 import android.os.OutcomeReceiver;
 import android.os.ParcelFileDescriptor;
 import android.os.Process;
@@ -84,13 +80,14 @@ import com.android.internal.telecom.ICallControl;
 import com.android.internal.telecom.ICallEventCallback;
 import com.android.internal.telecom.ITelecomService;
 import com.android.internal.util.IndentingPrintWriter;
+import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.metrics.ApiStats;
+import com.android.server.telecom.metrics.EventStats;
+import com.android.server.telecom.metrics.EventStats.CriticalEvent;
 import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.settings.BlockedNumbersActivity;
-import com.android.server.telecom.callsequencing.voip.IncomingCallTransaction;
-import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
 import com.android.server.telecom.callsequencing.TransactionManager;
 import com.android.server.telecom.callsequencing.CallTransaction;
 import com.android.server.telecom.callsequencing.CallTransactionResult;
@@ -105,6 +102,7 @@ import java.util.Locale;
 import java.util.Objects;
 import java.util.Set;
 import java.util.UUID;
+import java.util.concurrent.CompletableFuture;
 
 // TODO: Needed for move to system service: import com.android.internal.R;
 
@@ -144,6 +142,13 @@ public class TelecomServiceImpl {
             UUID.fromString("4edf6c8d-1e43-4c94-b0fc-a40c8d80cfe8");
     public static final String PLACE_CALL_SECURITY_EXCEPTION_ERROR_MSG =
             "Security exception thrown while placing an outgoing call.";
+    public static final UUID CALL_IS_NULL_OR_ID_MISMATCH_UUID =
+            UUID.fromString("b11f3251-474c-4f90-96d6-a256aebc3c19");
+    public static final String CALL_IS_NULL_OR_ID_MISMATCH_MSG =
+            "call is null or id mismatch";
+    public static final UUID ADD_CALL_ON_ERROR_UUID =
+            UUID.fromString("f8e7d6c5-b4a3-9210-8765-432109abcdef");
+
     private static final String TAG = "TelecomServiceImpl";
     private static final String TIME_LINE_ARG = "timeline";
     private static final int DEFAULT_VIDEO_STATE = -1;
@@ -172,11 +177,30 @@ public class TelecomServiceImpl {
     private TransactionManager mTransactionManager;
     private final ITelecomService.Stub mBinderImpl = new ITelecomService.Stub() {
 
+        @Override
+        public boolean hasForegroundServiceDelegation(
+                PhoneAccountHandle handle,
+                String packageName) {
+            enforceCallingPackage(packageName, "hasForegroundServiceDelegation");
+            long token = Binder.clearCallingIdentity();
+            try {
+                VoipCallMonitor vcm = mCallsManager.getVoipCallMonitor();
+                if (vcm != null) {
+                    return vcm.hasForegroundServiceDelegation(handle);
+                }
+                return false;
+            } finally {
+                Binder.restoreCallingIdentity(token);
+            }
+        }
+
         @Override
         public void addCall(CallAttributes callAttributes, ICallEventCallback callEventCallback,
                 String callId, String callingPackage) {
+            int uid = Binder.getCallingUid();
+            int pid = Binder.getCallingPid();
             ApiStats.ApiEvent event = new ApiStats.ApiEvent(ApiStats.API_ADDCALL,
-                    Binder.getCallingUid(), ApiStats.RESULT_PERMISSION);
+                    uid, ApiStats.RESULT_PERMISSION);
             try {
                 Log.startSession("TSI.aC", Log.getPackageAbbreviation(callingPackage));
                 Log.i(TAG, "addCall: id=[%s], attributes=[%s]", callId, callAttributes);
@@ -193,68 +217,88 @@ public class TelecomServiceImpl {
 
                 // add extras about info used for FGS delegation
                 Bundle extras = new Bundle();
-                extras.putInt(CallAttributes.CALLER_UID_KEY, Binder.getCallingUid());
-                extras.putInt(CallAttributes.CALLER_PID_KEY, Binder.getCallingPid());
-
-                CallTransaction transaction = null;
-                // create transaction based on the call direction
-                switch (callAttributes.getDirection()) {
-                    case DIRECTION_OUTGOING:
-                        transaction = new OutgoingCallTransaction(callId, mContext, callAttributes,
-                                mCallsManager, extras, mFeatureFlags);
-                        break;
-                    case DIRECTION_INCOMING:
-                        transaction = new IncomingCallTransaction(callId, callAttributes,
-                                mCallsManager, extras, mFeatureFlags);
-                        break;
-                    default:
-                        throw new IllegalArgumentException(String.format("Invalid Call Direction. "
-                                        + "Was [%d] but should be within [%d,%d]",
-                                callAttributes.getDirection(), DIRECTION_INCOMING,
-                                DIRECTION_OUTGOING));
-                }
-
-                mTransactionManager.addTransaction(transaction, new OutcomeReceiver<>() {
-                    @Override
-                    public void onResult(CallTransactionResult result) {
-                        Log.d(TAG, "addCall: onResult");
-                        Call call = result.getCall();
-
-                        if (call == null || !call.getId().equals(callId)) {
-                            Log.i(TAG, "addCall: onResult: call is null or id mismatch");
-                            onAddCallControl(callId, callEventCallback, null,
-                                    new CallException(ADD_CALL_ERR_MSG, CODE_ERROR_UNKNOWN));
-                            return;
-                        }
+                extras.putInt(CallAttributes.CALLER_UID_KEY, uid);
+                extras.putInt(CallAttributes.CALLER_PID_KEY, pid);
 
-                        TransactionalServiceWrapper serviceWrapper =
-                                mTransactionalServiceRepository
-                                        .addNewCallForTransactionalServiceWrapper(handle,
-                                                callEventCallback, mCallsManager, call);
 
-                        call.setTransactionServiceWrapper(serviceWrapper);
+                CompletableFuture<CallTransaction> transactionFuture;
+                long token = Binder.clearCallingIdentity();
+                try {
+                    transactionFuture = mCallsManager.createTransactionalCall(callId,
+                            callAttributes, extras, callingPackage);
+                } finally {
+                    Binder.restoreCallingIdentity(token);
+                }
 
-                        if (mFeatureFlags.transactionalVideoState()) {
-                            call.setTransactionalCallSupportsVideoCalling(callAttributes);
-                        }
-                        ICallControl clientCallControl = serviceWrapper.getICallControl();
+                transactionFuture.thenCompose((transaction) -> {
+                    if (transaction != null) {
+                        mTransactionManager.addTransaction(transaction, new OutcomeReceiver<>() {
+                            @Override
+                            public void onResult(CallTransactionResult result) {
+                                Log.d(TAG, "addCall: onResult");
+                                Call call = result.getCall();
+                                if (mFeatureFlags.telecomMetricsSupport()) {
+                                    mMetricsController.getEventStats().log(new CriticalEvent(
+                                            EventStats.ID_ADD_CALL, uid,
+                                            EventStats.CAUSE_CALL_TRANSACTION_SUCCESS));
+                                }
 
-                        if (clientCallControl == null) {
-                            throw new IllegalStateException("TransactionalServiceWrapper"
-                                    + "#ICallControl is null.");
-                        }
+                                if (call == null || !call.getId().equals(callId)) {
+                                    Log.i(TAG, "addCall: onResult: call is null or id mismatch");
+                                    onAddCallControl(callId, callEventCallback, null,
+                                            new CallException(ADD_CALL_ERR_MSG,
+                                                    CODE_ERROR_UNKNOWN));
+                                    if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                                        mAnomalyReporter.reportAnomaly(
+                                                CALL_IS_NULL_OR_ID_MISMATCH_UUID,
+                                                CALL_IS_NULL_OR_ID_MISMATCH_MSG);
+                                    }
+                                    return;
+                                }
 
-                        // finally, send objects back to the client
-                        onAddCallControl(callId, callEventCallback, clientCallControl, null);
-                    }
+                                TransactionalServiceWrapper serviceWrapper =
+                                        mTransactionalServiceRepository
+                                                .addNewCallForTransactionalServiceWrapper(handle,
+                                                        callEventCallback, mCallsManager, call);
+
+                                call.setTransactionServiceWrapper(serviceWrapper);
+
+                                if (mFeatureFlags.transactionalVideoState()) {
+                                    call.setTransactionalCallSupportsVideoCalling(callAttributes);
+                                }
+                                ICallControl clientCallControl = serviceWrapper.getICallControl();
 
-                    @Override
-                    public void onError(@NonNull CallException exception) {
-                        Log.d(TAG, "addCall: onError: e=[%s]", exception.toString());
-                        onAddCallControl(callId, callEventCallback, null, exception);
+                                if (clientCallControl == null) {
+                                    throw new IllegalStateException("TransactionalServiceWrapper"
+                                            + "#ICallControl is null.");
+                                }
+
+                                // finally, send objects back to the client
+                                onAddCallControl(callId, callEventCallback, clientCallControl,
+                                        null);
+                            }
+
+                            @Override
+                            public void onError(@NonNull CallException exception) {
+                                Log.d(TAG, "addCall: onError: e=[%s]", exception.toString());
+                                onAddCallControl(callId, callEventCallback, null, exception);
+                                if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                                    mAnomalyReporter.reportAnomaly(
+                                            ADD_CALL_ON_ERROR_UUID,
+                                            exception.getMessage());
+                                }
+                                if (mFeatureFlags.telecomMetricsSupport()) {
+                                    mMetricsController.getEventStats().log(new CriticalEvent(
+                                            EventStats.ID_ADD_CALL, uid,
+                                            EventStats.CAUSE_CALL_TRANSACTION_BASE
+                                                    + exception.getCode()));
+                                }
+                            }
+                        });
                     }
+                    event.setResult(ApiStats.RESULT_NORMAL);
+                    return CompletableFuture.completedFuture(transaction);
                 });
-                event.setResult(ApiStats.RESULT_NORMAL);
             } finally {
                 logEvent(event);
                 Log.endSession();
@@ -1477,26 +1521,36 @@ public class TelecomServiceImpl {
         private boolean isPrivilegedUid() {
             int callingUid = Binder.getCallingUid();
             return mFeatureFlags.allowSystemAppsResolveVoipCalls()
-                    ? (UserHandle.isSameApp(callingUid, Process.ROOT_UID)
-                            || UserHandle.isSameApp(callingUid, Process.SYSTEM_UID)
-                            || UserHandle.isSameApp(callingUid, Process.SHELL_UID))
+                    ? (isSameApp(callingUid, Process.ROOT_UID)
+                            || isSameApp(callingUid, Process.SYSTEM_UID)
+                            || isSameApp(callingUid, Process.SHELL_UID))
                     : (callingUid == Process.ROOT_UID
                             || callingUid == Process.SYSTEM_UID
                             || callingUid == Process.SHELL_UID);
         }
 
+        private boolean isSameApp(int uid1, int uid2) {
+            return UserHandle.getAppId(uid1) == UserHandle.getAppId(uid2);
+        }
+
         private boolean isSysUiUid() {
             int callingUid = Binder.getCallingUid();
             int systemUiUid;
             if (mPackageManager != null && mSystemUiPackageName != null) {
+                long whosCalling = Binder.clearCallingIdentity();
                 try {
-                    systemUiUid = mPackageManager.getPackageUid(mSystemUiPackageName, 0);
-                    Log.i(TAG, "isSysUiUid: callingUid = " + callingUid + "; systemUiUid = "
-                            + systemUiUid);
-                    return UserHandle.isSameApp(callingUid, systemUiUid);
-                } catch (PackageManager.NameNotFoundException e) {
-                    Log.w(TAG, "isSysUiUid: caught PackageManager NameNotFoundException = " + e);
-                    return false;
+                    try {
+                        systemUiUid = mPackageManager.getPackageUid(mSystemUiPackageName, 0);
+                        Log.i(TAG, "isSysUiUid: callingUid = " + callingUid + "; systemUiUid = "
+                                + systemUiUid);
+                        return isSameApp(callingUid, systemUiUid);
+                    } catch (PackageManager.NameNotFoundException e) {
+                        Log.w(TAG,
+                                "isSysUiUid: caught PackageManager NameNotFoundException = " + e);
+                        return false;
+                    }
+                } finally {
+                    Binder.restoreCallingIdentity(whosCalling);
                 }
             } else {
                 Log.w(TAG, "isSysUiUid: caught null check and returned false; "
@@ -2912,6 +2966,17 @@ public class TelecomServiceImpl {
             }
         }
 
+        @Override
+        public void setMetricsTestMode(boolean enabled) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.setTestMode(enabled);
+            }
+        }
+
+        @Override
+        public void waitForAudioToUpdate(boolean expectActive) {
+            mCallsManager.waitForAudioToUpdate(expectActive);
+        }
         /**
          * Determines whether there are any ongoing {@link PhoneAccount#CAPABILITY_SELF_MANAGED}
          * calls for a given {@code packageName} and {@code userHandle}.
@@ -3001,7 +3066,10 @@ public class TelecomServiceImpl {
         });
 
         mTransactionManager = TransactionManager.getInstance();
-        mTransactionalServiceRepository = new TransactionalServiceRepository(mFeatureFlags);
+        mTransactionManager.setFeatureFlag(mFeatureFlags);
+        mTransactionManager.setAnomalyReporter(mAnomalyReporter);
+        mTransactionalServiceRepository = new TransactionalServiceRepository(mFeatureFlags,
+                mAnomalyReporter);
         mBlockedNumbersManager = mFeatureFlags.telecomMainlineBlockedNumbersManager()
                 ? mContext.getSystemService(BlockedNumbersManager.class)
                 : null;
@@ -3255,6 +3323,16 @@ public class TelecomServiceImpl {
         try {
             pm = mContext.createContextAsUser(
                     UserHandle.getUserHandleForUid(callingUid), 0).getPackageManager();
+
+            // This has to happen inside the scope of the `clearCallingIdentity` block
+            // otherwise the caller may fail to call `TelecomManager#endCall`.
+            if (pm != null) {
+                try {
+                    packageUid = pm.getPackageUid(packageName, 0);
+                } catch (PackageManager.NameNotFoundException e) {
+                    // packageUid is -1.
+                }
+            }
         } catch (Exception e) {
             Log.i(this, "callingUidMatchesPackageManagerRecords:"
                     + " createContextAsUser hit exception=[%s]", e.toString());
@@ -3262,13 +3340,6 @@ public class TelecomServiceImpl {
         } finally {
             Binder.restoreCallingIdentity(token);
         }
-        if (pm != null) {
-            try {
-                packageUid = pm.getPackageUid(packageName, 0);
-            } catch (PackageManager.NameNotFoundException e) {
-                // packageUid is -1.
-            }
-        }
 
         if (packageUid != callingUid) {
             Log.i(this, "callingUidMatchesPackageManagerRecords: uid mismatch found for"
diff --git a/src/com/android/server/telecom/TelecomShellCommand.java b/src/com/android/server/telecom/TelecomShellCommand.java
index 11ceb26b6..2e955a929 100644
--- a/src/com/android/server/telecom/TelecomShellCommand.java
+++ b/src/com/android/server/telecom/TelecomShellCommand.java
@@ -67,6 +67,10 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
     private static final String COMMAND_RESET_CAR_MODE = "reset-car-mode";
     private static final String COMMAND_IS_NON_IN_CALL_SERVICE_BOUND =
             "is-non-ui-in-call-service-bound";
+    private static final String COMMAND_WAIT_FOR_AUDIO_OPS_COMPLETION =
+            "wait-for-audio-ops-complete";
+    private static final String COMMAND_WAIT_FOR_AUDIO_ACTIVE_COMPLETION =
+            "wait-for-audio-active";
 
     /**
      * Change the system dialer package name if a package name was specified,
@@ -83,6 +87,8 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
     private static final String COMMAND_GET_MAX_PHONES = "get-max-phones";
     private static final String COMMAND_SET_TEST_EMERGENCY_PHONE_ACCOUNT_PACKAGE_FILTER =
             "set-test-emergency-phone-account-package-filter";
+    private static final String COMMAND_SET_METRICS_TEST_ENABLED = "set-metrics-test-enabled";
+    private static final String COMMAND_SET_METRICS_TEST_DISABLED = "set-metrics-test-disabled";
     /**
      * Command used to emit a distinct "mark" in the logs.
      */
@@ -184,6 +190,18 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
                 case COMMAND_LOG_MARK:
                     runLogMark();
                     break;
+                case COMMAND_SET_METRICS_TEST_ENABLED:
+                    mTelecomService.setMetricsTestMode(true);
+                    break;
+                case COMMAND_SET_METRICS_TEST_DISABLED:
+                    mTelecomService.setMetricsTestMode(false);
+                    break;
+                case COMMAND_WAIT_FOR_AUDIO_OPS_COMPLETION:
+                    mTelecomService.waitForAudioToUpdate(false);
+                    break;
+                case COMMAND_WAIT_FOR_AUDIO_ACTIVE_COMPLETION:
+                    mTelecomService.waitForAudioToUpdate(true);
+                    break;
                 default:
                     return handleDefaultCommands(command);
             }
@@ -262,6 +280,8 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
                 + "testers to indicate where in the logs various test steps take place.\n"
                 + "telecom is-non-ui-in-call-service-bound <PACKAGE>: queries a particular "
                 + "non-ui-InCallService in InCallController to determine if it is bound \n"
+                + "telecom set-metrics-test-enabled: Enable the metrics test mode.\n"
+                + "telecom set-metrics-test-disabled: Disable the metrics test mode.\n"
         );
     }
     private void runSetPhoneAccountEnabled(boolean enabled) throws RemoteException {
diff --git a/src/com/android/server/telecom/TelecomSystem.java b/src/com/android/server/telecom/TelecomSystem.java
index 702088509..50a0a7f03 100644
--- a/src/com/android/server/telecom/TelecomSystem.java
+++ b/src/com/android/server/telecom/TelecomSystem.java
@@ -28,6 +28,7 @@ import android.content.pm.ResolveInfo;
 import android.net.Uri;
 import android.os.BugreportManager;
 import android.os.DropBoxManager;
+import android.os.Looper;
 import android.os.UserHandle;
 import android.telecom.Log;
 import android.telecom.PhoneAccountHandle;
@@ -48,6 +49,7 @@ import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
 import com.android.server.telecom.components.UserCallIntentProcessor;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.EventStats;
 import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.ui.AudioProcessingNotification;
 import com.android.server.telecom.ui.CallStreamingNotification;
@@ -230,7 +232,8 @@ public class TelecomSystem {
             Executor asyncCallAudioTaskExecutor,
             BlockedNumbersAdapter blockedNumbersAdapter,
             FeatureFlags featureFlags,
-            com.android.internal.telephony.flags.FeatureFlags telephonyFlags) {
+            com.android.internal.telephony.flags.FeatureFlags telephonyFlags,
+            Looper looper) {
         mContext = context.getApplicationContext();
         mFeatureFlags = featureFlags;
         LogUtils.initLogging(mContext);
@@ -264,7 +267,7 @@ public class TelecomSystem {
                     communicationDeviceTracker, featureFlags);
             BluetoothRouteManager bluetoothRouteManager = new BluetoothRouteManager(mContext, mLock,
                     bluetoothDeviceManager, new Timeouts.Adapter(),
-                    communicationDeviceTracker, featureFlags);
+                    communicationDeviceTracker, featureFlags, looper);
             BluetoothStateReceiver bluetoothStateReceiver = new BluetoothStateReceiver(
                     bluetoothDeviceManager, bluetoothRouteManager,
                     communicationDeviceTracker, featureFlags);
@@ -459,7 +462,8 @@ public class TelecomSystem {
             });
             mCallsManager.setIncomingCallNotifier(mIncomingCallNotifier);
 
-            mRespondViaSmsManager = new RespondViaSmsManager(mCallsManager, mLock);
+            mRespondViaSmsManager = new RespondViaSmsManager(mCallsManager, mLock,
+                asyncTaskExecutor, featureFlags);
             mCallsManager.setRespondViaSmsManager(mRespondViaSmsManager);
 
             mContext.registerReceiverAsUser(mUserSwitchedReceiver, UserHandle.ALL,
diff --git a/src/com/android/server/telecom/TransactionalServiceRepository.java b/src/com/android/server/telecom/TransactionalServiceRepository.java
index 5ae459e21..954307a7c 100644
--- a/src/com/android/server/telecom/TransactionalServiceRepository.java
+++ b/src/com/android/server/telecom/TransactionalServiceRepository.java
@@ -35,9 +35,13 @@ public class TransactionalServiceRepository {
     private static final Map<PhoneAccountHandle, TransactionalServiceWrapper> mServiceLookupTable =
             new HashMap<>();
     private final FeatureFlags mFlags;
+    private final AnomalyReporterAdapter mAnomalyReporter;
 
-    public TransactionalServiceRepository(FeatureFlags flags) {
+    public TransactionalServiceRepository(
+            FeatureFlags flags,
+            AnomalyReporterAdapter anomalyReporter) {
         mFlags = flags;
+        mAnomalyReporter = anomalyReporter;
     }
 
     public TransactionalServiceWrapper addNewCallForTransactionalServiceWrapper
@@ -50,7 +54,8 @@ public class TransactionalServiceRepository {
             Log.d(TAG, "creating a new TSW; handle=[%s]", phoneAccountHandle);
             service = new TransactionalServiceWrapper(callEventCallback,
                     callsManager, phoneAccountHandle, call, this,
-                    TransactionManager.getInstance(), mFlags.enableCallSequencing());
+                    TransactionManager.getInstance(), mFlags.enableCallSequencing(),
+                    mFlags, mAnomalyReporter);
         } else {
             Log.d(TAG, "add a new call to an existing TSW; handle=[%s]", phoneAccountHandle);
             service = getTransactionalServiceWrapper(phoneAccountHandle);
diff --git a/src/com/android/server/telecom/TransactionalServiceWrapper.java b/src/com/android/server/telecom/TransactionalServiceWrapper.java
index cf5ef41c6..cc0d54771 100644
--- a/src/com/android/server/telecom/TransactionalServiceWrapper.java
+++ b/src/com/android/server/telecom/TransactionalServiceWrapper.java
@@ -47,9 +47,11 @@ import com.android.server.telecom.callsequencing.voip.RequestVideoStateTransacti
 import com.android.server.telecom.callsequencing.TransactionManager;
 import com.android.server.telecom.callsequencing.CallTransaction;
 import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.Locale;
 import java.util.Set;
+import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ConcurrentHashMap;
 
@@ -92,7 +94,12 @@ public class TransactionalServiceWrapper implements
     private TransactionManager mTransactionManager;
     private CallStreamingController mStreamingController;
     private final TransactionalCallSequencingAdapter mCallSequencingAdapter;
-
+    private final FeatureFlags mFeatureFlags;
+    private final AnomalyReporterAdapter mAnomalyReporter;
+    public static final UUID CALL_IS_NO_LONGER_BEING_TRACKED_ERROR_UUID =
+            UUID.fromString("8187cd59-97a7-4e9f-a772-638dda4b69bb");
+    public static final String CALL_IS_NO_LONGER_BEING_TRACKED_ERROR_MSG =
+            "A call update was attempted for a call no longer being tracked";
 
     // Each TransactionalServiceWrapper should have their own Binder.DeathRecipient to clean up
     // any calls in the event the application crashes or is force stopped.
@@ -108,7 +115,8 @@ public class TransactionalServiceWrapper implements
     public TransactionalServiceWrapper(ICallEventCallback callEventCallback,
             CallsManager callsManager, PhoneAccountHandle phoneAccountHandle, Call call,
             TransactionalServiceRepository repo, TransactionManager transactionManager,
-            boolean isCallSequencingEnabled) {
+            boolean isCallSequencingEnabled, FeatureFlags featureFlags,
+            AnomalyReporterAdapter anomalyReporterAdapter) {
         // passed args
         mICallEventCallback = callEventCallback;
         mCallsManager = callsManager;
@@ -123,6 +131,8 @@ public class TransactionalServiceWrapper implements
         mCallSequencingAdapter = new TransactionalCallSequencingAdapter(mTransactionManager,
                 mCallsManager, isCallSequencingEnabled);
         setDeathRecipient(callEventCallback);
+        mFeatureFlags = featureFlags;
+        mAnomalyReporter = anomalyReporterAdapter;
     }
 
     public TransactionManager getTransactionManager() {
@@ -307,6 +317,11 @@ public class TransactionalServiceWrapper implements
                                 + " via TelecomManager#addCall", action, callId),
                                 CODE_CALL_IS_NOT_BEING_TRACKED));
                 callback.send(CODE_CALL_IS_NOT_BEING_TRACKED, exceptionBundle);
+                if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                    mAnomalyReporter.reportAnomaly(
+                            CALL_IS_NO_LONGER_BEING_TRACKED_ERROR_UUID,
+                            CALL_IS_NO_LONGER_BEING_TRACKED_ERROR_MSG);
+                }
             }
         }
 
@@ -401,11 +416,12 @@ public class TransactionalServiceWrapper implements
         return onSetActiveFuture;
     }
 
-    public void onAnswer(Call call, int videoState) {
+    public CompletableFuture<Boolean> onAnswer(Call call, int videoState) {
+        CompletableFuture<Boolean> onAnswerFuture;
         try {
             Log.startSession("TSW.oA");
             Log.d(TAG, String.format(Locale.US, "onAnswer: callId=[%s]", call.getId()));
-            mCallSequencingAdapter.onSetAnswered(call, videoState,
+            onAnswerFuture = mCallSequencingAdapter.onSetAnswered(call, videoState,
                     new CallEventCallbackAckTransaction(mICallEventCallback,
                             ON_ANSWER, call.getId(), videoState, mLock),
                     result -> Log.i(TAG, String.format(Locale.US,
@@ -414,6 +430,7 @@ public class TransactionalServiceWrapper implements
         } finally {
             Log.endSession();
         }
+        return onAnswerFuture;
     }
 
     public CompletableFuture<Boolean> onSetInactive(Call call) {
diff --git a/src/com/android/server/telecom/UserUtil.java b/src/com/android/server/telecom/UserUtil.java
index 57906d496..8c124c8a3 100644
--- a/src/com/android/server/telecom/UserUtil.java
+++ b/src/com/android/server/telecom/UserUtil.java
@@ -35,15 +35,28 @@ public final class UserUtil {
     private UserUtil() {
     }
 
+    private static final String LOG_TAG = "UserUtil";
+
     private static UserInfo getUserInfoFromUserHandle(Context context, UserHandle userHandle) {
         UserManager userManager = context.getSystemService(UserManager.class);
         return userManager.getUserInfo(userHandle.getIdentifier());
     }
 
+    private static UserManager getUserManagerFromUserHandle(Context context,
+            UserHandle userHandle) {
+        UserManager userManager = null;
+        try {
+            userManager = context.createContextAsUser(userHandle, 0)
+                    .getSystemService(UserManager.class);
+        } catch (IllegalStateException e) {
+            Log.e(LOG_TAG, e, "Error while creating context as user = " + userHandle);
+        }
+        return userManager;
+    }
+
     public static boolean isManagedProfile(Context context, UserHandle userHandle,
             FeatureFlags featureFlags) {
-        UserManager userManager = context.createContextAsUser(userHandle, 0)
-                .getSystemService(UserManager.class);
+        UserManager userManager = getUserManagerFromUserHandle(context, userHandle);
         UserInfo userInfo = getUserInfoFromUserHandle(context, userHandle);
         return featureFlags.telecomResolveHiddenDependencies()
                 ? userManager != null && userManager.isManagedProfile()
@@ -51,15 +64,13 @@ public final class UserUtil {
     }
 
     public static boolean isPrivateProfile(UserHandle userHandle, Context context) {
-        UserManager um = context.createContextAsUser(userHandle, 0).getSystemService(
-                UserManager.class);
+        UserManager um = getUserManagerFromUserHandle(context, userHandle);
         return um != null && um.isPrivateProfile();
     }
 
     public static boolean isProfile(Context context, UserHandle userHandle,
             FeatureFlags featureFlags) {
-        UserManager userManager = context.createContextAsUser(userHandle, 0)
-                .getSystemService(UserManager.class);
+        UserManager userManager = getUserManagerFromUserHandle(context, userHandle);
         UserInfo userInfo = getUserInfoFromUserHandle(context, userHandle);
         return featureFlags.telecomResolveHiddenDependencies()
                 ? userManager != null && userManager.isProfile()
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
index f4d6041da..eda8c64d3 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
@@ -34,6 +34,7 @@ import android.content.Context;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.os.Bundle;
+import android.telecom.CallAudioState;
 import android.telecom.Log;
 import android.util.ArraySet;
 import android.util.LocalLog;
@@ -166,6 +167,12 @@ public class BluetoothDeviceManager {
                             mLocalLog.log(logString);
                             return;
                         }
+                        if (mBluetoothLeAudioService == null) {
+                            logString += ", but leAudio service is unavailable";
+                            Log.i(BluetoothDeviceManager.this, logString);
+                            mLocalLog.log(logString);
+                            return;
+                        }
                         try {
                             mLeAudioCallbackRegistered = true;
                             mBluetoothLeAudioService.registerCallback(
@@ -233,21 +240,25 @@ public class BluetoothDeviceManager {
                 }
            };
 
-    private void handleAudioRefactoringServiceDisconnected(int profile) {
+    @VisibleForTesting
+    public void handleAudioRefactoringServiceDisconnected(int profile) {
         CallAudioRouteController controller = (CallAudioRouteController)
                 mCallAudioRouteAdapter;
         Map<AudioRoute, BluetoothDevice> btRoutes = controller
                 .getBluetoothRoutes();
         List<Pair<AudioRoute, BluetoothDevice>> btRoutesToRemove =
                 new ArrayList<>();
-        for (AudioRoute route: btRoutes.keySet()) {
-            if (route.getType() != PROFILE_TO_AUDIO_ROUTE_MAP.get(profile)) {
-                continue;
+        // Prevent concurrent modification exception by just iterating
+        //through keys instead of simultaneously removing them. Ensure that
+        // we synchronize on the map while we traverse via an Iterator.
+        synchronized (btRoutes) {
+            for (AudioRoute route: btRoutes.keySet()) {
+                if (route.getType() != PROFILE_TO_AUDIO_ROUTE_MAP.get(profile)) {
+                    continue;
+                }
+                BluetoothDevice device = btRoutes.get(route);
+                btRoutesToRemove.add(new Pair<>(route, device));
             }
-            BluetoothDevice device = btRoutes.get(route);
-            // Prevent concurrent modification exception by just iterating through keys instead of
-            // simultaneously removing them.
-            btRoutesToRemove.add(new Pair<>(route, device));
         }
 
         for (Pair<AudioRoute, BluetoothDevice> routeToRemove:
@@ -257,8 +268,23 @@ public class BluetoothDeviceManager {
             mCallAudioRouteAdapter.sendMessageWithSessionInfo(
                     BT_DEVICE_REMOVED, route.getType(), device);
         }
-        mCallAudioRouteAdapter.sendMessageWithSessionInfo(
-                SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE, (String) null);
+
+        if (mFeatureFlags.skipBaselineSwitchWhenRouteNotBluetooth()) {
+            CallAudioState currentAudioState = controller.getCurrentCallAudioState();
+            int currentRoute = currentAudioState.getRoute();
+            if (currentRoute == CallAudioState.ROUTE_BLUETOOTH) {
+                Log.d(this, "handleAudioRefactoringServiceDisconnected: call audio "
+                        + "is currently routed to BT so switching back to baseline");
+                mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                        SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE, (String) null);
+            } else {
+                Log.d(this, "handleAudioRefactoringServiceDisconnected: call audio "
+                        + "is not currently routed to BT so skipping switch to baseline");
+            }
+        } else {
+            mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                    SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE, (String) null);
+        }
     }
 
     private final LinkedHashMap<String, BluetoothDevice> mHfpDevicesByAddress =
@@ -579,7 +605,8 @@ public class BluetoothDeviceManager {
             Log.w(this, "disconnectSco: Trying to disconnect audio but no headset service exists.");
         } else {
             result = mBluetoothHeadset.disconnectAudio();
-            Log.i(this, "disconnectSco: BluetoothHeadset#disconnectAudio()=%b", result);
+            Log.i(this, "disconnectSco: BluetoothHeadset#disconnectAudio()=%s",
+                    btCodeToString(result));
         }
         return result;
     }
@@ -825,6 +852,7 @@ public class BluetoothDeviceManager {
         if (callProfile == BluetoothProfile.LE_AUDIO) {
             if (mBluetoothAdapter.setActiveDevice(
                     device, BluetoothAdapter.ACTIVE_DEVICE_ALL)) {
+                Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=true", address);
                 /* ACTION_ACTIVE_DEVICE_CHANGED intent will trigger setting communication device.
                  * Only after receiving ACTION_ACTIVE_DEVICE_CHANGED it is known that device that
                  * will be audio switched to is available to be choose as communication device */
@@ -836,9 +864,11 @@ public class BluetoothDeviceManager {
                 }
                 return true;
             }
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=false", address);
             return false;
         } else if (callProfile == BluetoothProfile.HEARING_AID) {
             if (mBluetoothAdapter.setActiveDevice(device, BluetoothAdapter.ACTIVE_DEVICE_ALL)) {
+                Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=true", address);
                 /* ACTION_ACTIVE_DEVICE_CHANGED intent will trigger setting communication device.
                  * Only after receiving ACTION_ACTIVE_DEVICE_CHANGED it is known that device that
                  * will be audio switched to is available to be choose as communication device */
@@ -850,19 +880,20 @@ public class BluetoothDeviceManager {
                 }
                 return true;
             }
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=false", address);
             return false;
         } else if (callProfile == BluetoothProfile.HEADSET) {
             boolean success = mBluetoothAdapter.setActiveDevice(device,
                 BluetoothAdapter.ACTIVE_DEVICE_PHONE_CALL);
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=%b", address, success);
             if (!success) {
                 Log.w(this, "connectAudio: Couldn't set active device to %s", address);
                 return false;
             }
-            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)", address);
             if (getBluetoothHeadset() != null) {
                 int scoConnectionRequest = mBluetoothHeadset.connectAudio();
-                Log.i(this, "connectAudio: BluetoothHeadset#connectAudio()=%d",
-                        scoConnectionRequest);
+                Log.i(this, "connectAudio: BluetoothHeadset#connectAudio()=%s",
+                        btCodeToString(scoConnectionRequest));
                 return scoConnectionRequest == BluetoothStatusCodes.SUCCESS ||
                         scoConnectionRequest
                                 == BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_CONNECTED;
@@ -883,7 +914,8 @@ public class BluetoothDeviceManager {
      * @param type {@link AudioRoute.AudioRouteType} associated with the device.
      * @return {@code true} if device was successfully connected, {@code false} otherwise.
      */
-    public boolean connectAudio(BluetoothDevice device, @AudioRoute.AudioRouteType int type) {
+    public boolean connectAudio(BluetoothDevice device, @AudioRoute.AudioRouteType int type,
+            boolean isScoManagedByAudio) {
         String address = device.getAddress();
         int callProfile = BluetoothProfile.LE_AUDIO;
         if (type == TYPE_BLUETOOTH_SCO) {
@@ -901,19 +933,23 @@ public class BluetoothDeviceManager {
         }
 
         if (callProfile == BluetoothProfile.LE_AUDIO
-                || callProfile == BluetoothProfile.HEARING_AID) {
-            return mBluetoothAdapter.setActiveDevice(device, BluetoothAdapter.ACTIVE_DEVICE_ALL);
+                || callProfile == BluetoothProfile.HEARING_AID || isScoManagedByAudio) {
+            boolean success = mBluetoothAdapter.setActiveDevice(device,
+                    BluetoothAdapter.ACTIVE_DEVICE_ALL);
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=%b", address, success);
+            return success;
         } else if (callProfile == BluetoothProfile.HEADSET) {
             boolean success = mBluetoothAdapter.setActiveDevice(device,
                     BluetoothAdapter.ACTIVE_DEVICE_PHONE_CALL);
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)=%b", address, success);
             if (!success) {
                 Log.w(this, "connectAudio: Couldn't set active device to %s", address);
                 return false;
             }
             if (getBluetoothHeadset() != null) {
                 int scoConnectionRequest = mBluetoothHeadset.connectAudio();
-                Log.i(this, "connectaudio: BluetoothHeadset#connectAudio()=%d",
-                        scoConnectionRequest);
+                Log.i(this, "connectAudio: BluetoothHeadset#connectAudio()=%s",
+                        btCodeToString(scoConnectionRequest));
                 return scoConnectionRequest == BluetoothStatusCodes.SUCCESS ||
                         scoConnectionRequest
                                 == BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_CONNECTED;
@@ -956,6 +992,34 @@ public class BluetoothDeviceManager {
         return isInbandRingEnabled(activeDevice);
     }
 
+    /**
+     * Check if inband ringing is enabled for the specified BT device.
+     * This is intended for use by {@link CallAudioRouteController}.
+     * @param audioRouteType The BT device type.
+     * @param bluetoothDevice The BT device.
+     * @return {@code true} if inband ringing is enabled, {@code false} otherwise.
+     */
+    public boolean isInbandRingEnabled(@AudioRoute.AudioRouteType int audioRouteType,
+            BluetoothDevice bluetoothDevice) {
+        if (audioRouteType == AudioRoute.TYPE_BLUETOOTH_LE) {
+            if (mBluetoothLeAudioService == null) {
+                Log.i(this, "isInbandRingingEnabled: no leaudio service available.");
+                return false;
+            }
+            int groupId = mBluetoothLeAudioService.getGroupId(bluetoothDevice);
+            return mBluetoothLeAudioService.isInbandRingtoneEnabled(groupId);
+        } else {
+            if (getBluetoothHeadset() == null) {
+                Log.i(this, "isInbandRingingEnabled: no headset service available.");
+                return false;
+            }
+            boolean isEnabled = mBluetoothHeadset.isInbandRingingEnabled();
+            Log.i(this, "isInbandRingEnabled: device: %s, isEnabled: %b", bluetoothDevice,
+                    isEnabled);
+            return isEnabled;
+        }
+    }
+
     public boolean isInbandRingEnabled(BluetoothDevice bluetoothDevice) {
         if (mBluetoothRouteManager.isCachedLeAudioDevice(bluetoothDevice)) {
             if (mBluetoothLeAudioService == null) {
@@ -983,4 +1047,33 @@ public class BluetoothDeviceManager {
     public void dump(IndentingPrintWriter pw) {
         mLocalLog.dump(pw);
     }
+
+    private String btCodeToString(int code) {
+        switch (code) {
+            case BluetoothStatusCodes.SUCCESS:
+                return "SUCCESS";
+            case BluetoothStatusCodes.ERROR_UNKNOWN:
+                return "ERROR_UNKNOWN";
+            case BluetoothStatusCodes.ERROR_PROFILE_SERVICE_NOT_BOUND:
+                return "ERROR_PROFILE_SERVICE_NOT_BOUND";
+            case BluetoothStatusCodes.ERROR_TIMEOUT:
+                return "ERROR_TIMEOUT";
+            case BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_CONNECTED:
+                return "ERROR_AUDIO_DEVICE_ALREADY_CONNECTED";
+            case BluetoothStatusCodes.ERROR_NO_ACTIVE_DEVICES:
+                return "ERROR_NO_ACTIVE_DEVICES";
+            case BluetoothStatusCodes.ERROR_NOT_ACTIVE_DEVICE:
+                return "ERROR_NOT_ACTIVE_DEVICE";
+            case BluetoothStatusCodes.ERROR_AUDIO_ROUTE_BLOCKED:
+                return "ERROR_AUDIO_ROUTE_BLOCKED";
+            case BluetoothStatusCodes.ERROR_CALL_ACTIVE:
+                return "ERROR_CALL_ACTIVE";
+            case BluetoothStatusCodes.ERROR_PROFILE_NOT_CONNECTED:
+                return "ERROR_PROFILE_NOT_CONNECTED";
+            case BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_DISCONNECTED:
+                return "BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_DISCONNECTED";
+            default:
+                return Integer.toString(code);
+        }
+    }
 }
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothRouteManager.java b/src/com/android/server/telecom/bluetooth/BluetoothRouteManager.java
index 5a440417e..93dbed6b9 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothRouteManager.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothRouteManager.java
@@ -26,6 +26,7 @@ import android.bluetooth.BluetoothLeAudio;
 import android.content.Context;
 import android.media.AudioDeviceInfo;
 import android.os.Message;
+import android.os.Looper;
 import android.telecom.Log;
 import android.telecom.Logging.Session;
 import android.util.Pair;
@@ -36,6 +37,7 @@ import com.android.internal.os.SomeArgs;
 import com.android.internal.util.IState;
 import com.android.internal.util.State;
 import com.android.internal.util.StateMachine;
+import com.android.server.telecom.AudioRoute;
 import com.android.server.telecom.CallAudioCommunicationDeviceTracker;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
@@ -607,8 +609,8 @@ public class BluetoothRouteManager extends StateMachine {
     public BluetoothRouteManager(Context context, TelecomSystem.SyncRoot lock,
             BluetoothDeviceManager deviceManager, Timeouts.Adapter timeoutsAdapter,
             CallAudioCommunicationDeviceTracker communicationDeviceTracker,
-            FeatureFlags featureFlags) {
-        super(BluetoothRouteManager.class.getSimpleName());
+            FeatureFlags featureFlags, Looper looper) {
+        super(BluetoothRouteManager.class.getSimpleName(), looper);
         mContext = context;
         mLock = lock;
         mDeviceManager = deviceManager;
@@ -1179,6 +1181,11 @@ public class BluetoothRouteManager extends StateMachine {
         return mDeviceManager.isInbandRingEnabled(bluetoothDevice);
     }
 
+    public boolean isInbandRingEnabled(@AudioRoute.AudioRouteType int audioRouteType,
+            BluetoothDevice bluetoothDevice) {
+        return mDeviceManager.isInbandRingEnabled(audioRouteType, bluetoothDevice);
+    }
+
     private boolean addDevice(String address) {
         if (mAudioConnectingStates.containsKey(address)) {
             Log.i(this, "Attempting to add device %s twice.", address);
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
index 1cea5317e..0478fdc73 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
@@ -40,6 +40,7 @@ import android.content.Intent;
 import android.content.IntentFilter;
 import android.media.AudioDeviceInfo;
 import android.os.Bundle;
+import android.sysprop.BluetoothProperties;
 import android.telecom.Log;
 import android.telecom.Logging.Session;
 import android.util.Pair;
@@ -50,7 +51,8 @@ import com.android.server.telecom.CallAudioCommunicationDeviceTracker;
 import com.android.server.telecom.CallAudioRouteAdapter;
 import com.android.server.telecom.CallAudioRouteController;
 import com.android.server.telecom.flags.FeatureFlags;
-import com.android.server.telecom.flags.Flags;
+
+import java.util.Objects;
 
 public class BluetoothStateReceiver extends BroadcastReceiver {
     private static final String LOG_TAG = BluetoothStateReceiver.class.getSimpleName();
@@ -74,6 +76,7 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
     private final BluetoothDeviceManager mBluetoothDeviceManager;
     private CallAudioCommunicationDeviceTracker mCommunicationDeviceTracker;
     private FeatureFlags mFeatureFlags;
+    private boolean mIsScoManagedByAudio;
     private CallAudioRouteAdapter mCallAudioRouteAdapter;
 
     public void onReceive(Context context, Intent intent) {
@@ -123,16 +126,17 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                 if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                     CallAudioRouteController audioRouteController =
                             (CallAudioRouteController) mCallAudioRouteAdapter;
-                    audioRouteController.setIsScoAudioConnected(true);
-                    if (audioRouteController.isPending()) {
+                    audioRouteController.setScoAudioConnectedDevice(device);
+                    AudioRoute btRoute = audioRouteController.getBluetoothRoute(
+                            AudioRoute.TYPE_BLUETOOTH_SCO, device.getAddress());
+                    if (audioRouteController.isPending() && Objects.equals(audioRouteController
+                            .getPendingAudioRoute().getDestRoute(), btRoute)) {
                         mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0,
                                 device);
                     } else {
                         // It's possible that the initial BT connection fails but BT_AUDIO_CONNECTED
                         // is sent later, indicating that SCO audio is on. We should route
                         // appropriately in order for the UI to reflect this state.
-                        AudioRoute btRoute = audioRouteController.getBluetoothRoute(
-                                AudioRoute.TYPE_BLUETOOTH_SCO, device.getAddress());
                         if (btRoute != null) {
                             audioRouteController.getPendingAudioRoute().overrideDestRoute(btRoute);
                             audioRouteController.overrideIsPending(true);
@@ -154,7 +158,7 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                 if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                     CallAudioRouteController audioRouteController =
                             (CallAudioRouteController) mCallAudioRouteAdapter;
-                    audioRouteController.setIsScoAudioConnected(false);
+                    audioRouteController.setScoAudioConnectedDevice(null);
                     if (audioRouteController.isPending()) {
                         mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
                                 device);
@@ -269,7 +273,12 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
                         audioRouteType, device.getAddress());
                 if (deviceType == BluetoothDeviceManager.DEVICE_TYPE_HEARING_AID
-                        || deviceType == BluetoothDeviceManager.DEVICE_TYPE_LE_AUDIO) {
+                        || deviceType == BluetoothDeviceManager.DEVICE_TYPE_LE_AUDIO
+                        || mIsScoManagedByAudio) {
+                    if (!mIsInCall) {
+                        Log.i(LOG_TAG, "Ignoring audio on since we're not in a call");
+                        return;
+                    }
                     if (!mBluetoothDeviceManager.setCommunicationDeviceForAddress(
                             device.getAddress())) {
                         Log.i(this, "handleActiveDeviceChanged: Failed to set "
@@ -286,11 +295,12 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                         }
                     } else {
                         // Track the currently set communication device.
-                        int routeType = deviceType == BluetoothDeviceManager.DEVICE_TYPE_LE_AUDIO
-                                ? AudioRoute.TYPE_BLUETOOTH_LE
-                                : AudioRoute.TYPE_BLUETOOTH_HA;
                         mCallAudioRouteAdapter.getPendingAudioRoute()
-                                .setCommunicationDeviceType(routeType);
+                                .setCommunicationDeviceType(audioRouteType);
+                        if (audioRouteType == AudioRoute.TYPE_BLUETOOTH_SCO) {
+                            mCallAudioRouteAdapter.getPendingAudioRoute()
+                                    .addMessage(BT_AUDIO_CONNECTED, device.getAddress());
+                        }
                     }
                 }
             }
@@ -379,6 +389,9 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
         mBluetoothRouteManager = routeManager;
         mCommunicationDeviceTracker = communicationDeviceTracker;
         mFeatureFlags = featureFlags;
+        // Indication that SCO is managed by audio (i.e. supports setCommunicationDevice).
+        mIsScoManagedByAudio = android.media.audio.Flags.scoManagedByAudio()
+                && BluetoothProperties.isScoManagedByAudioEnabled().orElse(false);
     }
 
     public void setIsInCall(boolean isInCall) {
diff --git a/src/com/android/server/telecom/callsequencing/CallSequencingController.java b/src/com/android/server/telecom/callsequencing/CallSequencingController.java
index 2f0ae4554..29be3d039 100644
--- a/src/com/android/server/telecom/callsequencing/CallSequencingController.java
+++ b/src/com/android/server/telecom/callsequencing/CallSequencingController.java
@@ -16,67 +16,1201 @@
 
 package com.android.server.telecom.callsequencing;
 
+import static android.Manifest.permission.CALL_PRIVILEGED;
+
+import static com.android.server.telecom.CallsManager.CALL_FILTER_ALL;
+import static com.android.server.telecom.CallsManager.LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_MSG;
+import static com.android.server.telecom.CallsManager.LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_UUID;
+import static com.android.server.telecom.CallsManager.LIVE_CALL_STUCK_CONNECTING_ERROR_MSG;
+import static com.android.server.telecom.CallsManager.LIVE_CALL_STUCK_CONNECTING_ERROR_UUID;
+import static com.android.server.telecom.CallsManager.ONGOING_CALL_STATES;
+import static com.android.server.telecom.CallsManager.OUTGOING_CALL_STATES;
+import static com.android.server.telecom.UserUtil.showErrorDialogForRestrictedOutgoingCall;
+
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.net.Uri;
+import android.os.Bundle;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.os.OutcomeReceiver;
+import android.telecom.CallAttributes;
+import android.telecom.CallException;
+import android.telecom.Connection;
+import android.telecom.DisconnectCause;
+import android.telecom.Log;
+import android.telecom.PhoneAccount;
+import android.telecom.PhoneAccountHandle;
+import android.telephony.AnomalyReporter;
+import android.telephony.CarrierConfigManager;
+import android.util.Pair;
 
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.Call;
+import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.ClockProxy;
+import com.android.server.telecom.LogUtils;
+import com.android.server.telecom.LoggedHandlerExecutor;
+import com.android.server.telecom.MmiUtils;
+import com.android.server.telecom.R;
+import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransactionSequencing;
+import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.ErrorStats;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+import com.android.server.telecom.stats.CallFailureCause;
 
+import java.util.HashSet;
+import java.util.List;
+import java.util.Objects;
+import java.util.Set;
+import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 
 /**
  * Controls the sequencing between calls when moving between the user ACTIVE (RINGING/ACTIVE) and
- * user INACTIVE (INCOMING/HOLD/DISCONNECTED) states.
+ * user INACTIVE (INCOMING/HOLD/DISCONNECTED) states. This controller is gated by the
+ * {@link FeatureFlags#enableCallSequencing()} flag. Call state changes are verified on a
+ * transactional basis where each operation is verified step by step for cross-phone account calls
+ * or just for the focus call in the case of processing calls on the same phone account.
  */
 public class CallSequencingController {
-//    private final CallsManager mCallsManager;
-    private final TransactionManager mTransactionManager;
-//    private final Handler mHandler;
-//    private boolean mCallSequencingEnabled;
-
-    public CallSequencingController(CallsManager callsManager, boolean callSequencingEnabled) {
-//        mCallsManager = callsManager;
-        mTransactionManager = TransactionManager.getInstance();
+    private final CallsManager mCallsManager;
+    private final ClockProxy mClockProxy;
+    private final AnomalyReporterAdapter mAnomalyReporter;
+    private final Timeouts.Adapter mTimeoutsAdapter;
+    private final TelecomMetricsController mMetricsController;
+    private final Handler mHandler;
+    private final Context mContext;
+    private final MmiUtils mMmiUtils;
+    private final FeatureFlags mFeatureFlags;
+    private static String TAG = CallSequencingController.class.getSimpleName();
+    public static final UUID SEQUENCING_CANNOT_HOLD_ACTIVE_CALL_UUID =
+            UUID.fromString("ea094d77-6ea9-4e40-891e-14bff5d485d7");
+    public static final String SEQUENCING_CANNOT_HOLD_ACTIVE_CALL_MSG =
+            "Cannot hold active call";
+
+    public CallSequencingController(CallsManager callsManager, Context context,
+            ClockProxy clockProxy, AnomalyReporterAdapter anomalyReporter,
+            Timeouts.Adapter timeoutsAdapter, TelecomMetricsController metricsController,
+            MmiUtils mmiUtils, FeatureFlags featureFlags) {
+        mCallsManager = callsManager;
+        mClockProxy = clockProxy;
+        mAnomalyReporter = anomalyReporter;
+        mMetricsController = metricsController;
+        mTimeoutsAdapter = timeoutsAdapter;
         HandlerThread handlerThread = new HandlerThread(this.toString());
         handlerThread.start();
-//        mHandler = new Handler(handlerThread.getLooper());
-//        mCallSequencingEnabled = callSequencingEnabled;
+        mHandler = new Handler(handlerThread.getLooper());
+        mMmiUtils = mmiUtils;
+        mFeatureFlags = featureFlags;
+        mContext = context;
+    }
+
+    /**
+     * Creates the outgoing call transaction given that call sequencing is enabled. Two separate
+     * transactions are being tracked here; one is if room needs to be made for the outgoing call
+     * and another to verify that the new call was placed. We need to ensure that the transaction
+     * to make room for the outgoing call is processed beforehand (i.e. see
+     * {@link OutgoingCallTransaction}.
+     * @param callAttributes The call attributes associated with the call.
+     * @param extras The extras that are associated with the call.
+     * @param callingPackage The calling package representing where the request was invoked from.
+     * @return The {@link CompletableFuture<CallTransaction>} that encompasses the request to
+     *         place/receive the transactional call.
+     */
+    public CompletableFuture<CallTransaction> createTransactionalOutgoingCall(String callId,
+            CallAttributes callAttributes, Bundle extras, String callingPackage) {
+        PhoneAccountHandle requestedAccountHandle = callAttributes.getPhoneAccountHandle();
+        Uri address = callAttributes.getAddress();
+        if (mCallsManager.isOutgoingCallPermitted(requestedAccountHandle)) {
+            Log.d(this, "createTransactionalOutgoingCall: outgoing call permitted");
+            final boolean hasCallPrivilegedPermission = mContext.checkCallingPermission(
+                    CALL_PRIVILEGED) == PackageManager.PERMISSION_GRANTED;
+
+            final Intent intent = new Intent(hasCallPrivilegedPermission ?
+                    Intent.ACTION_CALL_PRIVILEGED : Intent.ACTION_CALL, address);
+            Bundle updatedExtras = OutgoingCallTransaction.generateExtras(callId, extras,
+                    callAttributes, mFeatureFlags);
+            // Note that this may start a potential transaction to make room for the outgoing call
+            // so we want to ensure that transaction is queued up first and then create another
+            // transaction to complete the call future.
+            CompletableFuture<Call> callFuture = mCallsManager.startOutgoingCall(address,
+                    requestedAccountHandle, updatedExtras, requestedAccountHandle.getUserHandle(),
+                    intent, callingPackage);
+            // The second transaction is represented below which will contain the result of whether
+            // the new outgoing call was placed or not. To simplify the logic, we will wait on the
+            // result of the outgoing call future before adding the transaction so that we can wait
+            // for the make room future to complete first.
+            if (callFuture == null) {
+                Log.d(this, "createTransactionalOutgoingCall: Outgoing call not permitted at the "
+                        + "current time.");
+                return CompletableFuture.completedFuture(new OutgoingCallTransactionSequencing(
+                        mCallsManager, null, true /* callNotPermitted */, mFeatureFlags));
+            }
+            return callFuture.thenComposeAsync((call) -> CompletableFuture.completedFuture(
+                    new OutgoingCallTransactionSequencing(mCallsManager, callFuture,
+                            false /* callNotPermitted */, mFeatureFlags)),
+                    new LoggedHandlerExecutor(mHandler, "CSC.aC", mCallsManager.getLock()));
+        } else {
+            Log.d(this, "createTransactionalOutgoingCall: outgoing call not permitted at the "
+                    + "current time.");
+            return CompletableFuture.completedFuture(new OutgoingCallTransactionSequencing(
+                    mCallsManager, null, true /* callNotPermitted */, mFeatureFlags));
+        }
     }
 
-    public void answerCall(Call incomingCall, int videoState) {
-        // Todo: call sequencing logic (stubbed)
+    /**
+     * Processes the answer call request from the app and verifies the call state changes with
+     * sequencing provided that the calls that are being manipulated are across phone accounts.
+     * @param incomingCall The incoming call to be answered.
+     * @param videoState The video state configuration for the provided call.
+     * @param requestOrigin The origin of the request to answer the call; this can impact sequencing
+     *                      decisions as requests that Telecom makes can override rules we have set
+     *                      for actions which originate from outside.
+     */
+    public void answerCall(Call incomingCall, int videoState,
+            @CallsManager.RequestOrigin int requestOrigin) {
+        Log.i(this, "answerCall: Beginning call sequencing transaction for answering "
+                + "incoming call.");
+        holdActiveCallForNewCallWithSequencing(incomingCall, requestOrigin)
+                .thenComposeAsync((result) -> {
+                if (result) {
+                    mCallsManager.requestFocusActionAnswerCall(incomingCall, videoState);
+                } else {
+                    Log.i(this, "answerCall: Hold active call transaction failed. Aborting "
+                            + "request to answer the incoming call.");
+                }
+                return CompletableFuture.completedFuture(result);
+            }, new LoggedHandlerExecutor(mHandler, "CSC.aC",
+                mCallsManager.getLock()));
     }
 
-//    private CompletableFuture<Boolean> holdActiveCallForNewCallWithSequencing(Call call) {
-//        // Todo: call sequencing logic (stubbed)
-//        return null;
-//    }
+    /**
+     * Handles the case of setting a self-managed call active with call sequencing support.
+     * @param call The self-managed call that's waiting to go active.
+     */
+    public void handleSetSelfManagedCallActive(Call call) {
+        holdActiveCallForNewCallWithSequencing(call, CallsManager.REQUEST_ORIGIN_UNKNOWN)
+                .thenComposeAsync((result) -> {
+                if (result) {
+                    Log.i(this, "markCallAsActive: requesting focus for self managed call "
+                            + "before setting active.");
+                    mCallsManager.requestActionSetActiveCall(call,
+                            "active set explicitly for self-managed");
+                } else {
+                    Log.i(this, "markCallAsActive: Unable to hold active call. "
+                            + "Aborting transaction to set self managed call active.");
+                }
+                return CompletableFuture.completedFuture(result);
+            }, new LoggedHandlerExecutor(mHandler,
+                "CM.mCAA", mCallsManager.getLock()));
+    }
+
+    /**
+     * This applies to transactional calls which request to hold the active call with call
+     * sequencing support. The resulting future is an indication of whether the hold request
+     * succeeded which is then used to create additional transactions to request call focus for the
+     * new call.
+     * @param newCall The new transactional call that's waiting to go active.
+     * @param callback The callback used to report the result of holding the active call and if
+     *                 the new call can go active.
+     * @return The {@code CompletableFuture} indicating the result of holding the active call
+     *         (if applicable).
+     */
+    public void transactionHoldPotentialActiveCallForNewCallSequencing(
+            Call newCall, OutcomeReceiver<Boolean, CallException> callback) {
+        holdActiveCallForNewCallWithSequencing(newCall, CallsManager.REQUEST_ORIGIN_UNKNOWN)
+                .thenComposeAsync((result) -> {
+                    if (result) {
+                        // Either we were able to hold the active call or the active call was
+                        // disconnected in favor of the new call.
+                        callback.onResult(true);
+                    } else {
+                        Log.i(this, "transactionHoldPotentialActiveCallForNewCallSequencing: "
+                                + "active call could not be held or disconnected");
+                        callback.onError(
+                                new CallException("activeCall could not be held or disconnected",
+                                CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+                        if (mFeatureFlags.enableCallExceptionAnomReports()) {
+                            mAnomalyReporter.reportAnomaly(
+                                    SEQUENCING_CANNOT_HOLD_ACTIVE_CALL_UUID,
+                                    SEQUENCING_CANNOT_HOLD_ACTIVE_CALL_MSG
+                            );
+                        }
+                    }
+                    return CompletableFuture.completedFuture(result);
+                }, new LoggedHandlerExecutor(mHandler, "CM.mCAA", mCallsManager.getLock()));
+    }
 
+    /**
+     * Attempts to hold the active call so that the provided call can go active. This is done via
+     * call sequencing and the resulting future is an indication of whether that request
+     * has succeeded.
+     *
+     * @param call The call that's waiting to go active.
+     * @return The {@link CompletableFuture} indicating the result of whether the
+     * active call was able to be held (if applicable).
+     */
+    @VisibleForTesting
+    public CompletableFuture<Boolean> holdActiveCallForNewCallWithSequencing(
+            Call call, int requestOrigin) {
+        Call activeCall = (Call) mCallsManager.getConnectionServiceFocusManager()
+                .getCurrentFocusCall();
+        Log.i(this, "holdActiveCallForNewCallWithSequencing, newCall: %s, "
+                        + "activeCall: %s", call.getId(),
+                (activeCall == null ? "<none>" : activeCall.getId()));
+        if (activeCall != null && activeCall != call) {
+            boolean isSequencingRequiredActiveAndCall = !arePhoneAccountsSame(call, activeCall);
+            if (mCallsManager.canHold(activeCall)) {
+                CompletableFuture<Boolean> holdFuture = activeCall.hold("swap to " + call.getId());
+                return isSequencingRequiredActiveAndCall
+                        ? holdFuture
+                        : CompletableFuture.completedFuture(true);
+            } else if (mCallsManager.supportsHold(activeCall)) {
+                // Handle the case where active call supports hold but can't currently be held.
+                // In this case, we'll look for the currently held call to disconnect prior to
+                // holding the active call.
+                // E.g.
+                // Call A - Held   (Supports hold, can't hold)
+                // Call B - Active (Supports hold, can't hold)
+                // Call C - Incoming
+                // Here we need to disconnect A prior to holding B so that C can be answered.
+                // This case is driven by telephony requirements ultimately.
+                //
+                // These cases can further be broken down at the phone account level:
+                // E.g. All cases not outlined below...
+                // (1)                              (2)
+                // Call A (Held) - PA1              Call A (Held) - PA1
+                // Call B (Active) - PA2            Call B (Active) - PA2
+                // Call C (Incoming) - PA1          Call C (Incoming) - PA2
+                // We should ensure that only operations across phone accounts require sequencing.
+                // Otherwise, we can send the requests up til the focus call state in question.
+                Call heldCall = mCallsManager.getFirstCallWithState(CallState.ON_HOLD);
+                CompletableFuture<Boolean> disconnectFutureHandler = null;
+
+                boolean isSequencingRequiredHeldAndActive = false;
+                if (heldCall != null) {
+                    // If the calls are from the same source or the incoming call isn't a VOIP call
+                    // and the held call is a carrier call, then disconnect the held call. The
+                    // idea is that if we have a held carrier call and the incoming call is a
+                    // VOIP call, we don't want to force the carrier call to auto-disconnect).
+                    // Note: If the origin of this request was from the Telecom call incoming call
+                    // disambiguation notification, we will allow the request to continue.
+                    if (isManagedCall(heldCall) && isVoipCall(call) && requestOrigin
+                            != CallsManager.REQUEST_ORIGIN_TELECOM_DISAMBIGUATION) {
+                        // Otherwise, fail the transaction.
+                        Log.w(this, "holdActiveCallForNewCallWithSequencing: ignoring request to "
+                                + "disconnect carrier call %s for voip call %s.", activeCall,
+                                heldCall);
+                        return CompletableFuture.completedFuture(false);
+                    } else {
+                        isSequencingRequiredHeldAndActive = !arePhoneAccountsSame(
+                                heldCall, activeCall);
+                        disconnectFutureHandler = heldCall.disconnect();
+                        Log.i(this, "holdActiveCallForNewCallWithSequencing: "
+                                        + "Disconnect held call %s before holding active call %s.",
+                                heldCall.getId(), activeCall.getId());
+                    }
+                }
+                Log.i(this, "holdActiveCallForNewCallWithSequencing: Holding active "
+                        + "%s before making %s active.", activeCall.getId(), call.getId());
+
+                CompletableFuture<Boolean> holdFutureHandler;
+                if (isSequencingRequiredHeldAndActive && disconnectFutureHandler != null) {
+                    holdFutureHandler = disconnectFutureHandler
+                            .thenComposeAsync((result) -> {
+                                if (result) {
+                                    return activeCall.hold().thenCompose((holdSuccess) -> {
+                                        if (holdSuccess) {
+                                            // Increase hold count only if hold succeeds.
+                                            call.increaseHeldByThisCallCount();
+                                        }
+                                        return CompletableFuture.completedFuture(holdSuccess);
+                                    });
+                                }
+                                return CompletableFuture.completedFuture(false);
+                            }, new LoggedHandlerExecutor(mHandler,
+                                    "CSC.hACFNCWS", mCallsManager.getLock()));
+                } else {
+                    holdFutureHandler = activeCall.hold();
+                    call.increaseHeldByThisCallCount();
+                }
+                // Next transaction will be performed on the call passed in and the last transaction
+                // was performed on the active call so ensure that the caller has this information
+                // to determine if sequencing is required.
+                return isSequencingRequiredActiveAndCall
+                        ? holdFutureHandler
+                        : CompletableFuture.completedFuture(true);
+            } else {
+                // This call does not support hold. If it is from a different connection
+                // service or connection manager, then disconnect it, otherwise allow the connection
+                // service or connection manager to figure out the right states.
+                Log.i(this, "holdActiveCallForNewCallWithSequencing: evaluating disconnecting %s "
+                        + "so that %s can be made active.", activeCall.getId(), call.getId());
+                if (!activeCall.isEmergencyCall()) {
+                    // We don't want to allow VOIP apps to disconnect carrier calls. We are
+                    // purposely completing the future with false so that the call isn't
+                    // answered.
+                    if (isSequencingRequiredActiveAndCall && isVoipCall(call)
+                            && isManagedCall(activeCall)) {
+                        Log.w(this, "holdActiveCallForNewCallWithSequencing: ignore "
+                                + "disconnecting carrier call for making VOIP call active");
+                        return CompletableFuture.completedFuture(false);
+                    } else {
+                        if (isSequencingRequiredActiveAndCall) {
+                            // Disconnect all calls with the same phone account as the active call
+                            // as they do would not support holding.
+                            Log.i(this, "Disconnecting non-holdable calls from account (%s).",
+                                    activeCall.getTargetPhoneAccount());
+                            return disconnectAllCallsWithPhoneAccount(
+                                    activeCall.getTargetPhoneAccount(), false /* excludeAccount */);
+                        } else {
+                            // Disconnect calls on other phone accounts and allow CS to handle
+                            // holding/disconnecting calls from the same CS.
+                            Log.i(this, "holdActiveCallForNewCallWithSequencing: "
+                                    + "disconnecting calls on other phone accounts and allowing "
+                                    + "ConnectionService to determine how to handle this case.");
+                            return disconnectAllCallsWithPhoneAccount(
+                                    activeCall.getTargetPhoneAccount(), true /* excludeAccount */);
+                        }
+                    }
+                } else {
+                    // It's not possible to hold the active call, and it's an emergency call so
+                    // we will silently reject the incoming call instead of answering it.
+                    Log.w(this, "holdActiveCallForNewCallWithSequencing: rejecting incoming "
+                            + "call %s as the active call is an emergency call and "
+                            + "it cannot be held.", call.getId());
+                    call.reject(false /* rejectWithMessage */, "" /* message */,
+                            "active emergency call can't be held");
+                    return CompletableFuture.completedFuture(false);
+                }
+            }
+        }
+        return CompletableFuture.completedFuture(true);
+    }
+
+    /**
+     * Processes the unhold call request sent by the app with call sequencing support.
+     * @param call The call to be unheld.
+     */
     public void unholdCall(Call call) {
-        // Todo: call sequencing logic (stubbed)
+        // Cases: set active call on hold and then set this call to active
+        // Calls could be made on different phone accounts, in which case, we need to verify state
+        // change for each call.
+        CompletableFuture<Boolean> unholdCallFutureHandler = null;
+        Call activeCall = (Call) mCallsManager.getConnectionServiceFocusManager()
+                .getCurrentFocusCall();
+        String activeCallId = null;
+        boolean isSequencingRequiredActiveAndCall = false;
+        if (activeCall != null && !activeCall.isLocallyDisconnecting()) {
+            activeCallId = activeCall.getId();
+            // Determine whether the calls are placed on different phone accounts.
+            isSequencingRequiredActiveAndCall = !arePhoneAccountsSame(activeCall, call);
+            boolean canSwapCalls = canSwap(activeCall, call);
+
+            // If the active + held call are from different phone accounts, ensure that the call
+            // sequencing states are verified at each step.
+            if (canSwapCalls) {
+                unholdCallFutureHandler = activeCall.hold("Swap to " + call.getId());
+                Log.addEvent(activeCall, LogUtils.Events.SWAP, "To " + call.getId());
+                Log.addEvent(call, LogUtils.Events.SWAP, "From " + activeCallId);
+            } else {
+                if (isSequencingRequiredActiveAndCall) {
+                    // If hold isn't supported and the active and held call are on
+                    // different phone accounts where the held call is self-managed and active call
+                    // is managed, abort the transaction. Otherwise, disconnect the call. We also
+                    // don't want to drop an emergency call.
+                    if (!activeCall.isEmergencyCall()) {
+                        Log.w(this, "unholdCall: Unable to hold the active call (%s),"
+                                        + " aborting swap to %s", activeCallId, call.getId(),
+                                call.getId());
+                        showErrorDialogForCannotHoldCall(call, false);
+                    } else {
+                        Log.w(this, "unholdCall: %s is an emergency call, aborting swap to %s",
+                                activeCallId, call.getId());
+                    }
+                    return;
+                } else {
+                    activeCall.hold("Swap to " + call.getId());
+                }
+            }
+        }
+
+        // Verify call state was changed to ACTIVE state
+        if (isSequencingRequiredActiveAndCall && unholdCallFutureHandler != null) {
+            String fixedActiveCallId = activeCallId;
+            // Only attempt to unhold call if previous request to hold/disconnect call (on different
+            // phone account) succeeded.
+            unholdCallFutureHandler.thenComposeAsync((result) -> {
+                if (result) {
+                    Log.i(this, "unholdCall: Request to hold active call transaction succeeded.");
+                    mCallsManager.requestActionUnholdCall(call, fixedActiveCallId);
+                } else {
+                    Log.i(this, "unholdCall: Request to hold active call transaction failed. "
+                            + "Aborting unhold transaction.");
+                }
+                return CompletableFuture.completedFuture(result);
+            }, new LoggedHandlerExecutor(mHandler, "CSC.uC",
+                    mCallsManager.getLock()));
+        } else {
+            // Otherwise, we should verify call unhold succeeded for focus call.
+            mCallsManager.requestActionUnholdCall(call, activeCallId);
+        }
     }
 
     public CompletableFuture<Boolean> makeRoomForOutgoingCall(boolean isEmergency, Call call) {
-        // Todo: call sequencing logic (stubbed)
-        return CompletableFuture.completedFuture(true);
-//        return isEmergency ? makeRoomForOutgoingEmergencyCall(call) : makeRoomForOutgoingCall(call);
+        return isEmergency
+                ? makeRoomForOutgoingEmergencyCall(call)
+                : makeRoomForOutgoingCall(call);
     }
 
-//    private CompletableFuture<Boolean> makeRoomForOutgoingEmergencyCall(Call emergencyCall) {
-//        // Todo: call sequencing logic (stubbed)
-//        return CompletableFuture.completedFuture(true);
-//    }
+    /**
+     * This function tries to make room for the new emergency outgoing call via call sequencing.
+     * The resulting future is an indication of whether room was able to be made for the emergency
+     * call if needed.
+     * @param emergencyCall The outgoing emergency call to be placed.
+     * @return The {@code CompletableFuture} indicating the result of whether room was able to be
+     *         made for the emergency call.
+     */
+    private CompletableFuture<Boolean> makeRoomForOutgoingEmergencyCall(Call emergencyCall) {
+        // Disconnect all self-managed + transactional calls + calls that don't support holding for
+        // emergency. We will never use these accounts for emergency calling. For the single sim
+        // case (like Verizon), we should support the existing behavior of disconnecting the active
+        // call; refrain from disconnecting the held call in this case if it exists.
+        Pair<Set<Call>, CompletableFuture<Boolean>> disconnectCallsForEmergencyPair =
+                disconnectCallsForEmergencyCall(emergencyCall);
+        // The list of calls that were disconnected
+        Set<Call> disconnectedCalls = disconnectCallsForEmergencyPair.first;
+        // The future encompassing the result of the disconnect transaction(s). Because of the
+        // bulk transaction, we will always opt to perform sequencing on this future. Note that this
+        // future will always be completed with true if no disconnects occurred.
+        CompletableFuture<Boolean> transactionFuture = disconnectCallsForEmergencyPair.second;
 
-//    private CompletableFuture<Boolean> makeRoomForOutgoingCall(Call call) {
-//        // Todo: call sequencing logic (stubbed)
-//        return CompletableFuture.completedFuture(true);
-//    }
+        Call ringingCall;
+        if (mCallsManager.hasRingingOrSimulatedRingingCall() && !disconnectedCalls
+                .contains(mCallsManager.getRingingOrSimulatedRingingCall())) {
+            // Always disconnect any ringing/incoming calls when an emergency call is placed to
+            // minimize distraction. This does not affect live call count.
+            ringingCall = mCallsManager.getRingingOrSimulatedRingingCall();
+            ringingCall.getAnalytics().setCallIsAdditional(true);
+            ringingCall.getAnalytics().setCallIsInterrupted(true);
+            if (ringingCall.getState() == CallState.SIMULATED_RINGING) {
+                if (!ringingCall.hasGoneActiveBefore()) {
+                    // If this is an incoming call that is currently in SIMULATED_RINGING only
+                    // after a call screen, disconnect to make room and mark as missed, since
+                    // the user didn't get a chance to accept/reject.
+                    transactionFuture = transactionFuture.thenComposeAsync((result) ->
+                                    ringingCall.disconnect("emergency call dialed during simulated "
+                                            + "ringing after screen."),
+                            new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC",
+                                    mCallsManager.getLock()));
+                } else {
+                    // If this is a simulated ringing call after being active and put in
+                    // AUDIO_PROCESSING state again, disconnect normally.
+                    transactionFuture = transactionFuture.thenComposeAsync((result) ->
+                                    ringingCall.reject(false, null,
+                                            "emergency call dialed during simulated ringing."),
+                            new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC",
+                                    mCallsManager.getLock()));
+                }
+            } else { // normal incoming ringing call.
+                // Hang up the ringing call to make room for the emergency call and mark as missed,
+                // since the user did not reject.
+                ringingCall.setOverrideDisconnectCauseCode(
+                        new DisconnectCause(DisconnectCause.MISSED));
+                transactionFuture = transactionFuture.thenComposeAsync((result) ->
+                                ringingCall.reject(false, null,
+                                        "emergency call dialed during ringing."),
+                        new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC",
+                                mCallsManager.getLock()));
+            }
+            disconnectedCalls.add(ringingCall);
+        } else {
+            ringingCall = null;
+        }
 
-//    private void resetProcessingCallSequencing() {
-//        mTransactionManager.setProcessingCallSequencing(false);
-//    }
+        // There is already room!
+        if (!mCallsManager.hasMaximumLiveCalls(emergencyCall)) {
+            return transactionFuture;
+        }
 
-    public CompletableFuture<Boolean> disconnectCall() {
-        return CompletableFuture.completedFuture(true);
+        Call liveCall = mCallsManager.getFirstCallWithLiveState();
+        Log.i(this, "makeRoomForOutgoingEmergencyCall: call = " + emergencyCall
+                + " livecall = " + liveCall);
+
+        // Don't need to proceed further if we already disconnected the live call or if the live
+        // call is the emergency call being placed (not likely).
+        if (emergencyCall == liveCall || disconnectedCalls.contains(liveCall)) {
+            return transactionFuture;
+        }
+
+        // After having rejected any potential ringing call as well as calls that aren't supported
+        // during emergency calls (refer to disconnectCallsForEmergencyCall logic), we can
+        // re-evaluate whether we still have multiple phone accounts in use in order to disconnect
+        // non-holdable calls:
+        // If (yes) - disconnect call the non-holdable calls (this would be just the active call)
+        // If (no)  - skip the disconnect and instead let the logic be handled explicitly for the
+        //            single sim behavior.
+        boolean areMultiplePhoneAccountsActive = areMultiplePhoneAccountsActive(disconnectedCalls);
+        if (areMultiplePhoneAccountsActive && !liveCall.can(Connection.CAPABILITY_SUPPORT_HOLD)) {
+            // After disconnecting, we should be able to place the ECC now (we either have no calls
+            // or a held call after this point).
+            String disconnectReason = "disconnecting non-holdable call to make room "
+                    + "for emergency call";
+            emergencyCall.getAnalytics().setCallIsAdditional(true);
+            liveCall.getAnalytics().setCallIsInterrupted(true);
+            return disconnectOngoingCallForEmergencyCall(transactionFuture, liveCall,
+                    disconnectReason);
+        }
+
+        // If we already disconnected the outgoing call, then don't perform any additional ops on
+        // it.
+        if (mCallsManager.hasMaximumOutgoingCalls(emergencyCall) && !disconnectedCalls
+                .contains(mCallsManager.getFirstCallWithState(OUTGOING_CALL_STATES))) {
+            Call outgoingCall = mCallsManager.getFirstCallWithState(OUTGOING_CALL_STATES);
+            String disconnectReason = null;
+            if (!outgoingCall.isEmergencyCall()) {
+                emergencyCall.getAnalytics().setCallIsAdditional(true);
+                outgoingCall.getAnalytics().setCallIsInterrupted(true);
+                disconnectReason = "Disconnecting dialing call in favor of new dialing"
+                        + " emergency call.";
+            }
+            if (outgoingCall.getState() == CallState.SELECT_PHONE_ACCOUNT) {
+                // Correctness check: if there is an orphaned emergency call in the
+                // {@link CallState#SELECT_PHONE_ACCOUNT} state, just disconnect it since the user
+                // has explicitly started a new call.
+                emergencyCall.getAnalytics().setCallIsAdditional(true);
+                outgoingCall.getAnalytics().setCallIsInterrupted(true);
+                disconnectReason = "Disconnecting call in SELECT_PHONE_ACCOUNT in favor"
+                        + " of new outgoing call.";
+            }
+            if (disconnectReason != null) {
+                // Skip auto-unhold for when the outgoing call is disconnected. Consider a scenario
+                // where we have a held non-holdable call (VZW) and the dialing call (also VZW). If
+                // we auto unhold the VZW while placing the emergency call, then we may end up with
+                // two active calls. The auto-unholding logic really only applies for the
+                // non-holdable phone account.
+                outgoingCall.setSkipAutoUnhold(true);
+                boolean isSequencingRequiredRingingAndOutgoing = ringingCall == null
+                        || !arePhoneAccountsSame(ringingCall, outgoingCall);
+                return disconnectOngoingCallForEmergencyCall(transactionFuture, outgoingCall,
+                        disconnectReason);
+            }
+            //  If the user tries to make two outgoing calls to different emergency call numbers,
+            //  we will try to connect the first outgoing call and reject the second.
+            emergencyCall.setStartFailCause(CallFailureCause.IN_EMERGENCY_CALL);
+            return CompletableFuture.completedFuture(false);
+        }
+
+        if (liveCall.getState() == CallState.AUDIO_PROCESSING) {
+            emergencyCall.getAnalytics().setCallIsAdditional(true);
+            liveCall.getAnalytics().setCallIsInterrupted(true);
+            // Skip auto-unhold for when the live call is disconnected. Consider a scenario where
+            // we have a held non-holdable call (VZW) and the live call (also VZW) is stuck in
+            // audio processing. If we auto unhold the VZW while placing the emergency call, then we
+            // may end up with two active calls. The auto-unholding logic really only applies for
+            // the non-holdable phone account.
+            liveCall.setSkipAutoUnhold(true);
+            final String disconnectReason = "disconnecting audio processing call for emergency";
+            return disconnectOngoingCallForEmergencyCall(transactionFuture, liveCall,
+                    disconnectReason);
+        }
+
+        // If the live call is stuck in a connecting state, prompt the user to generate a bugreport.
+        if (liveCall.getState() == CallState.CONNECTING) {
+            AnomalyReporter.reportAnomaly(LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_UUID,
+                    LIVE_CALL_STUCK_CONNECTING_EMERGENCY_ERROR_MSG);
+        }
+
+        // If we have the max number of held managed calls and we're placing an emergency call,
+        // we'll disconnect the active call if it cannot be held. If we have a self-managed call
+        // that can't be held, then we should disconnect the call in favor of the emergency call.
+        // This will only happen for the single sim scenario to support backwards compatibility.
+        // For dual sim, we should try disconnecting the held call and hold the active call. Also
+        // note that in a scenario where we don't have any held calls and the live call can't be
+        // held (only applies for single sim case), we should try holding the active call (and
+        // disconnect on fail) before placing the ECC (i.e. Verizon swap case). The latter is being
+        // handled further down in this method.
+        Call heldCall = mCallsManager.getFirstCallWithState(CallState.ON_HOLD);
+        if (mCallsManager.hasMaximumManagedHoldingCalls(emergencyCall)
+                && !disconnectedCalls.contains(heldCall)) {
+            final String disconnectReason = "disconnecting to make room for emergency call "
+                    + emergencyCall.getId();
+            emergencyCall.getAnalytics().setCallIsAdditional(true);
+            // Single sim case
+            if (!areMultiplePhoneAccountsActive) {
+                liveCall.getAnalytics().setCallIsInterrupted(true);
+                // Skip auto-unhold for when the live call is disconnected. Consider a scenario
+                // where we have a held non-holdable call (VZW) and an active call (also VZW). If
+                // we auto unhold the VZW while placing the emergency call, then we may end up with
+                // two active calls. The auto-unholding logic really only applies for the
+                // non-holdable phone account.
+                liveCall.setSkipAutoUnhold(true);
+                // Disconnect the active call instead of the holding call because it is historically
+                // easier to do, rather than disconnecting a held call and holding the active call.
+                disconnectOngoingCallForEmergencyCall(transactionFuture, liveCall,
+                        disconnectReason);
+                // Don't wait on the live call disconnect future result above since we're handling
+                // the same phone account case. It's possible that disconnect may time out in the
+                // case that two calls are being merged while the disconnect for the live call is
+                // sent.
+                return transactionFuture;
+            } else if (heldCall != null) { // Dual sim case
+                // Note at this point, we should always have a held call then that should
+                // be disconnected (over the active call) but still enforce with a null check and
+                // ensure we haven't disconnected it already.
+                heldCall.getAnalytics().setCallIsInterrupted(true);
+                // Disconnect the held call.
+                transactionFuture = disconnectOngoingCallForEmergencyCall(transactionFuture,
+                        heldCall, disconnectReason);
+            }
+        }
+
+        // TODO: Remove once b/23035408 has been corrected.
+        // If the live call is a conference, it will not have a target phone account set.  This
+        // means the check to see if the live call has the same target phone account as the new
+        // call will not cause us to bail early.  As a result, we'll end up holding the
+        // ongoing conference call.  However, the ConnectionService is already doing that.  This
+        // has caused problems with some carriers.  As a workaround until b/23035408 is
+        // corrected, we will try and get the target phone account for one of the conference's
+        // children and use that instead.
+        PhoneAccountHandle liveCallPhoneAccount = liveCall.getTargetPhoneAccount();
+        if (liveCallPhoneAccount == null && liveCall.isConference() &&
+                !liveCall.getChildCalls().isEmpty()) {
+            liveCallPhoneAccount = mCallsManager.getFirstChildPhoneAccount(liveCall);
+            Log.i(this, "makeRoomForOutgoingEmergencyCall: using child call PhoneAccount = " +
+                    liveCallPhoneAccount);
+        }
+
+        // We may not know which PhoneAccount the emergency call will be placed on yet, but if
+        // the liveCall PhoneAccount does not support placing emergency calls, then we know it
+        // will not be that one and we do not want multiple PhoneAccounts active during an
+        // emergency call if possible. Disconnect the active call in favor of the emergency call
+        // instead of trying to hold.
+        if (liveCallPhoneAccount != null) {
+            PhoneAccount pa = mCallsManager.getPhoneAccountRegistrar().getPhoneAccountUnchecked(
+                    liveCallPhoneAccount);
+            if((pa.getCapabilities() & PhoneAccount.CAPABILITY_PLACE_EMERGENCY_CALLS) == 0) {
+                liveCall.setOverrideDisconnectCauseCode(new DisconnectCause(
+                        DisconnectCause.LOCAL, DisconnectCause.REASON_EMERGENCY_CALL_PLACED));
+                final String disconnectReason = "outgoing call does not support emergency calls, "
+                        + "disconnecting.";
+                return disconnectOngoingCallForEmergencyCall(transactionFuture, liveCall,
+                        disconnectReason);
+            }
+        }
+
+        // At this point, if we still have an active call, then it supports holding for emergency
+        // and is a managed call. It may not support holding but we will still try to hold anyway
+        // (i.e. swap for Verizon). Note that there will only be one call at this stage which is
+        // the active call so that means that we will attempt to place the emergency call on the
+        // same phone account unless it's not using a Telephony phone account (Fi wifi call), in
+        // which case, we would want to verify holding happened. For cases like backup calling, the
+        // shared data call will be over Telephony as well as the emergency call, so the shared
+        // data call would get disconnected by the CS.
+
+        // We want to verify if the live call was placed via the connection manager. Don't use
+        // the manipulated liveCallPhoneAccount since the delegate would pull directly from the
+        // target phone account.
+        boolean isLiveUsingConnectionManager = !Objects.equals(liveCall.getTargetPhoneAccount(),
+                liveCall.getDelegatePhoneAccountHandle());
+        return maybeHoldLiveCallForEmergency(transactionFuture, liveCall,
+                emergencyCall, isLiveUsingConnectionManager);
+    }
+
+    /**
+     * This function tries to make room for the new outgoing call via call sequencing. The
+     * resulting future is an indication of whether room was able to be made for the call if
+     * needed.
+     * @param call The outgoing call to make room for.
+     * @return The {@code CompletableFuture} indicating the result of whether room was able to be
+     *         made for the outgoing call.
+     */
+    private CompletableFuture<Boolean> makeRoomForOutgoingCall(Call call) {
+        // For the purely managed CS cases, check if there's a ringing call, in which case we will
+        // disallow the outgoing call.
+        if (isManagedCall(call) && mCallsManager.hasManagedRingingOrSimulatedRingingCall()) {
+            showErrorDialogForOutgoingDuringRingingCall(call);
+            return CompletableFuture.completedFuture(false);
+        }
+        // Already room!
+        if (!mCallsManager.hasMaximumLiveCalls(call)) {
+            return CompletableFuture.completedFuture(true);
+        }
+
+        // NOTE: If the amount of live calls changes beyond 1, this logic will probably
+        // have to change.
+        Call liveCall = mCallsManager.getFirstCallWithLiveState();
+        Log.i(this, "makeRoomForOutgoingCall call = " + call + " livecall = " +
+                liveCall);
+
+        if (call == liveCall) {
+            // If the call is already the foreground call, then we are golden.
+            // This can happen after the user selects an account in the SELECT_PHONE_ACCOUNT
+            // state since the call was already populated into the list.
+            return CompletableFuture.completedFuture(true);
+        }
+
+        // If the live call is stuck in a connecting state for longer than the transitory timeout,
+        // then we should disconnect it in favor of the new outgoing call and prompt the user to
+        // generate a bugreport.
+        // TODO: In the future we should let the CallAnomalyWatchDog do this disconnection of the
+        // live call stuck in the connecting state.  Unfortunately that code will get tripped up by
+        // calls that have a longer than expected new outgoing call broadcast response time.  This
+        // mitigation is intended to catch calls stuck in a CONNECTING state for a long time that
+        // block outgoing calls.  However, if the user dials two calls in quick succession it will
+        // result in both calls getting disconnected, which is not optimal.
+        if (liveCall.getState() == CallState.CONNECTING
+                && ((mClockProxy.elapsedRealtime() - liveCall.getCreationElapsedRealtimeMillis())
+                > mTimeoutsAdapter.getNonVoipCallTransitoryStateTimeoutMillis())) {
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getErrorStats().log(ErrorStats.SUB_CALL_MANAGER,
+                        ErrorStats.ERROR_STUCK_CONNECTING);
+            }
+            mAnomalyReporter.reportAnomaly(LIVE_CALL_STUCK_CONNECTING_ERROR_UUID,
+                    LIVE_CALL_STUCK_CONNECTING_ERROR_MSG);
+            // Skip auto-unhold for when the live call is disconnected. Consider a scenario where
+            // we have a held non-holdable call (VZW) and the live call (also VZW) is stuck in
+            // connecting. If we auto unhold the VZW while placing the emergency call, then we may
+            // end up with two active calls. The auto-unholding logic really only applies for
+            // the non-holdable phone account.
+            liveCall.setSkipAutoUnhold(true);
+            return liveCall.disconnect("Force disconnect CONNECTING call.");
+        }
+
+        if (mCallsManager.hasMaximumOutgoingCalls(call)) {
+            Call outgoingCall = mCallsManager.getFirstCallWithState(OUTGOING_CALL_STATES);
+            if (outgoingCall.getState() == CallState.SELECT_PHONE_ACCOUNT) {
+                // If there is an orphaned call in the {@link CallState#SELECT_PHONE_ACCOUNT}
+                // state, just disconnect it since the user has explicitly started a new call.
+                call.getAnalytics().setCallIsAdditional(true);
+                outgoingCall.getAnalytics().setCallIsInterrupted(true);
+                // Skip auto-unhold for when the outgoing call is disconnected. Consider a scenario
+                // where we have a held non-holdable call (VZW) and a dialing call (also VZW). If we
+                // auto unhold the VZW while placing the emergency call, then we may end up with
+                // two active calls. The auto-unholding logic really only applies for the
+                // non-holdable phone account.
+                outgoingCall.setSkipAutoUnhold(true);
+                return outgoingCall.disconnect(
+                        "Disconnecting call in SELECT_PHONE_ACCOUNT in favor of new "
+                                + "outgoing call.");
+            }
+            showErrorDialogForMaxOutgoingCallOutgoingPresent(call);
+            return CompletableFuture.completedFuture(false);
+        }
+
+        // If we detect a MMI code, allow it to go through since we are not treating it as an actual
+        // call.
+        if (mMmiUtils.isPotentialMMICode(call.getHandle())) {
+            Log.i(this, "makeRoomForOutgoingCall: Detected mmi code. Allowing to go through.");
+            return CompletableFuture.completedFuture(true);
+        }
+
+        // Early check to see if we already have a held call + live call. It's possible if a device
+        // switches to DSDS with two ongoing calls for the phone account to be null in which case,
+        // based on the logic below, we would've completed the future with true and reported a
+        // different failure cause. Now, we perform this early check to ensure the right max
+        // outgoing call restriction error is displayed instead.
+        if (mCallsManager.hasMaximumManagedHoldingCalls(call) && !mCallsManager.canHold(liveCall)) {
+            Call heldCall = mCallsManager.getFirstCallWithState(CallState.ON_HOLD);
+            showErrorDialogForMaxOutgoingCallTooManyCalls(call,
+                    arePhoneAccountsSame(heldCall, liveCall));
+            return CompletableFuture.completedFuture(false);
+        }
+
+        // Self-Managed + Transactional calls require Telecom to manage calls in the same
+        // PhoneAccount, whereas managed calls require the ConnectionService to manage calls in the
+        // same PhoneAccount for legacy reasons (Telephony).
+        if (arePhoneAccountsSame(call, liveCall) && isManagedCall(call)) {
+            Log.i(this, "makeRoomForOutgoingCall: allowing managed CS to handle "
+                    + "calls from the same self-managed account");
+            return CompletableFuture.completedFuture(true);
+        } else if (call.getTargetPhoneAccount() == null) {
+            Log.i(this, "makeRoomForOutgoingCall: no PA specified, allowing");
+            // Without a phone account, we can't say reliably that the call will fail.
+            // If the user chooses the same phone account as the live call, then it's
+            // still possible that the call can be made (like with CDMA calls not supporting
+            // hold but they still support adding a call by going immediately into conference
+            // mode). Return true here and we'll run this code again after user chooses an
+            // account.
+            return CompletableFuture.completedFuture(true);
+        }
+
+        // Try to hold the live call before attempting the new outgoing call.
+        if (mCallsManager.canHold(liveCall)) {
+            Log.i(this, "makeRoomForOutgoingCall: holding live call.");
+            call.getAnalytics().setCallIsAdditional(true);
+            liveCall.getAnalytics().setCallIsInterrupted(true);
+            return liveCall.hold("calling " + call.getId());
+        }
+
+        // The live call cannot be held so we're out of luck here.  There's no room.
+        showErrorDialogForCannotHoldCall(call, true);
+        return CompletableFuture.completedFuture(false);
+    }
+
+    /**
+     * Processes the request from the app to disconnect a call. This is done via call sequencing
+     * so that Telecom properly cleans up the call locally provided that the call has been
+     * properly disconnected on the connection side.
+     * @param call The call to disconnect.
+     * @param previousState The previous state of the call before disconnecting.
+     */
+    public void disconnectCall(Call call, int previousState) {
+        CompletableFuture<Boolean> disconnectFuture = call.disconnect();
+        disconnectFuture.thenComposeAsync((result) -> {
+            if (result) {
+                Log.i(this, "disconnectCall: Disconnect call transaction succeeded. "
+                        + "Processing associated cleanup.");
+                mCallsManager.processDisconnectCallAndCleanup(call, previousState);
+            } else {
+                Log.i(this, "disconnectCall: Disconnect call transaction failed. "
+                        + "Aborting associated cleanup.");
+            }
+            return CompletableFuture.completedFuture(false);
+        }, new LoggedHandlerExecutor(mHandler, "CSC.dC",
+                mCallsManager.getLock()));
+    }
+
+    /* HELPERS */
+
+    /* makeRoomForOutgoingEmergencyCall helpers */
+
+    /**
+     * Tries to hold the live call before placing the emergency call. If the hold fails, then we
+     * will instead disconnect the call. This only applies for when the emergency call and live call
+     * are from the same phone account or there's only one ongoing call, in which case, we should
+     * place the emergency call on the ongoing call's phone account.
+     *
+     * Note: This only applies when the live call and emergency call are from the same phone
+     * account.
+     */
+    private CompletableFuture<Boolean> maybeHoldLiveCallForEmergency(
+            CompletableFuture<Boolean> transactionFuture,
+            Call liveCall, Call emergencyCall, boolean isLiveUsingConnectionManager) {
+        emergencyCall.getAnalytics().setCallIsAdditional(true);
+        liveCall.getAnalytics().setCallIsInterrupted(true);
+        final String holdReason = "calling " + emergencyCall.getId();
+        CompletableFuture<Boolean> holdResultFuture;
+        holdResultFuture = transactionFuture.thenComposeAsync((result) -> {
+            if (result) {
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Previous transaction "
+                        + "succeeded. Attempting to hold live call.");
+            } else { // Log the failure but proceed with hold transaction.
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Previous transaction "
+                        + "failed. Still attempting to hold live call.");
+            }
+            Log.i(this, "makeRoomForOutgoingEmergencyCall: Attempt to hold live call. "
+                    + "Verifying hold: %b", isLiveUsingConnectionManager);
+            return liveCall.hold(holdReason);
+        }, new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC", mCallsManager.getLock()));
+
+        // If the live call was placed using a connection manager, we should verify that holding
+        // happened before placing the emergency call. We should disconnect the call if hold fails.
+        // Otherwise, let Telephony handle additional sequencing that may be required.
+        if (!isLiveUsingConnectionManager) {
+            return transactionFuture;
+        }
+
+        // Otherwise, verify hold succeeded and if it didn't, then hangup the call.
+        return holdResultFuture.thenComposeAsync((result) -> {
+            if (!result) {
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Attempt to hold live call "
+                        + "failed. Disconnecting live call in favor of emergency call.");
+                return liveCall.disconnect("Disconnecting live call which failed to be held");
+            } else {
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Attempt to hold live call "
+                        + "transaction succeeded.");
+                emergencyCall.increaseHeldByThisCallCount();
+                return CompletableFuture.completedFuture(true);
+            }
+        }, new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC", mCallsManager.getLock()));
+    }
+
+    /**
+     * Disconnects all VOIP (SM + Transactional) as well as those that don't support placing
+     * emergency calls before placing an emergency call.
+     *
+     * Note: If a call can't be held, it will be active to begin with.
+     * @return The list of calls to be disconnected alongside the future keeping track of the
+     *         disconnect transaction.
+     */
+    private Pair<Set<Call>, CompletableFuture<Boolean>> disconnectCallsForEmergencyCall(
+            Call emergencyCall) {
+        Set<Call> callsDisconnected = new HashSet<>();
+        Call previousCall = null;
+        Call ringingCall = mCallsManager.getRingingOrSimulatedRingingCall();
+        CompletableFuture<Boolean> disconnectFuture = CompletableFuture.completedFuture(true);
+        for (Call call: mCallsManager.getCalls()) {
+            if (skipDisconnectForEmergencyCall(call, ringingCall)) {
+                continue;
+            }
+            emergencyCall.getAnalytics().setCallIsAdditional(true);
+            call.getAnalytics().setCallIsInterrupted(true);
+            call.setOverrideDisconnectCauseCode(new DisconnectCause(
+                    DisconnectCause.LOCAL, DisconnectCause.REASON_EMERGENCY_CALL_PLACED));
+
+            Call finalPreviousCall = previousCall;
+            disconnectFuture = disconnectFuture.thenComposeAsync((result) -> {
+                if (!result) {
+                    // Log the failure if it happens but proceed with the disconnects.
+                    Log.i(this, "Call (%s) failed to be disconnected",
+                            finalPreviousCall);
+                }
+                return call.disconnect("Disconnecting call with phone account that does not "
+                        + "support emergency call");
+            }, new LoggedHandlerExecutor(mHandler, "CSC.dAVC",
+                    mCallsManager.getLock()));
+            previousCall = call;
+            callsDisconnected.add(call);
+        }
+        return new Pair<>(callsDisconnected, disconnectFuture);
+    }
+
+    private boolean skipDisconnectForEmergencyCall(Call call, Call ringingCall) {
+        // Conditions for checking if call doesn't need to be disconnected immediately.
+        boolean isVoip = isVoipCall(call);
+        boolean callSupportsHoldingEmergencyCall = shouldHoldForEmergencyCall(
+                call.getTargetPhoneAccount());
+
+        // Skip the ringing call; we'll handle the disconnect explicitly later. Also, if we have
+        // a conference call, only disconnect the host call.
+        if (call.equals(ringingCall) || call.getParentCall() != null) {
+            return true;
+        }
+
+        // If the call is managed and supports holding for emergency calls, don't disconnect the
+        // call.
+        if (!isVoip && callSupportsHoldingEmergencyCall) {
+            return true;
+        }
+        // Otherwise, we will disconnect the call because it doesn't meet one of the conditions
+        // above.
+        Log.i(this, "Disconnecting call (%s). isManaged: %b, call "
+                + "supports holding emergency call: %b", call.getId(), !isVoip,
+                callSupportsHoldingEmergencyCall);
+        return false;
+    }
+
+    /**
+     * Waiting on the passed future completion when sequencing is required, this will try to the
+     * disconnect the call passed in.
+     */
+    private CompletableFuture<Boolean> disconnectOngoingCallForEmergencyCall(
+            CompletableFuture<Boolean> transactionFuture, Call callToDisconnect,
+            String disconnectReason) {
+        return transactionFuture.thenComposeAsync((result) -> {
+            if (result) {
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Request to disconnect "
+                        + "previous call succeeded. Attempting to disconnect ongoing call"
+                        + " %s.", callToDisconnect);
+            } else {
+                Log.i(this, "makeRoomForOutgoingEmergencyCall: Request to disconnect "
+                        + "previous call failed. Still attempting to disconnect ongoing call"
+                        + " %s.", callToDisconnect);
+            }
+            return callToDisconnect.disconnect(disconnectReason);
+        }, new LoggedHandlerExecutor(mHandler, "CSC.mRFOEC", mCallsManager.getLock()));
+    }
+
+    /**
+     * Determines if DSDA is being used (i.e. calls present on more than one phone account).
+     * @param callsToExclude The list of calls to exclude (these will be calls that have been
+     *                       disconnected but may still be being tracked by CallsManager depending
+     *                       on timing).
+     */
+    private boolean areMultiplePhoneAccountsActive(Set<Call> callsToExclude) {
+        for (Call excludedCall: callsToExclude) {
+            Log.i(this, "Calls to exclude: %s", excludedCall);
+        }
+        List<Call> calls = mCallsManager.getCalls().stream()
+                .filter(c -> !callsToExclude.contains(c)).toList();
+        PhoneAccountHandle handle1 = null;
+        if (!calls.isEmpty()) {
+            // Find the first handle different from the one retrieved from the first call in
+            // the list.
+            for(int i = 0; i < calls.size(); i++) {
+                if (handle1 == null && calls.get(i).getTargetPhoneAccount() != null) {
+                    handle1 = calls.getFirst().getTargetPhoneAccount();
+                }
+                if (handle1 != null && calls.get(i).getTargetPhoneAccount() != null
+                        && !handle1.equals(calls.get(i).getTargetPhoneAccount())) {
+                    return true;
+                }
+            }
+        }
+        return false;
+    }
+
+    /**
+     * Checks the carrier config to see if the carrier supports holding emergency calls.
+     * @param handle The {@code PhoneAccountHandle} to check
+     * @return {@code true} if the carrier supports holding emergency calls, {@code} false
+     *         otherwise.
+     */
+    private boolean shouldHoldForEmergencyCall(PhoneAccountHandle handle) {
+        return mCallsManager.getCarrierConfigForPhoneAccount(handle).getBoolean(
+                CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, true);
+    }
+
+    @VisibleForTesting
+    public boolean arePhoneAccountsSame(Call call1, Call call2) {
+        if (call1 == null || call2 == null) {
+            return false;
+        }
+        return Objects.equals(call1.getTargetPhoneAccount(), call2.getTargetPhoneAccount());
+    }
+
+    /**
+     * Checks to see if two calls can be swapped. This is granted that the call to be unheld is
+     * already ON_HOLD and the active call supports holding. Note that in HoldTracker, there can
+     * only be one top call that is holdable (if there are two, the calls are not holdable) and only
+     * that connection would have the CAPABILITY_HOLD present. For swapping logic, we should take
+     * this into account and request to hold regardless.
+     */
+    @VisibleForTesting
+    private boolean canSwap(Call callToBeHeld, Call callToUnhold) {
+        return callToBeHeld.can(Connection.CAPABILITY_SUPPORT_HOLD)
+                && callToBeHeld.getState() != CallState.DIALING
+                && callToUnhold.getState() == CallState.ON_HOLD;
+    }
+
+    private CompletableFuture<Boolean> disconnectAllCallsWithPhoneAccount(
+            PhoneAccountHandle handle, boolean excludeAccount) {
+        CompletableFuture<Boolean> disconnectFuture = CompletableFuture.completedFuture(true);
+        // Filter out the corresponding phone account and ensure that we don't consider conference
+        // participants as part of the bulk disconnect (we'll just disconnect the host directly).
+        List<Call> calls = mCallsManager.getCalls().stream()
+                .filter(c -> excludeAccount != c.getTargetPhoneAccount().equals(handle)
+                        && c.getParentCall() == null).toList();
+        for (Call call: calls) {
+            // Wait for all disconnects before we accept the new call.
+            disconnectFuture = disconnectFuture.thenComposeAsync((result) -> {
+                if (!result) {
+                    Log.i(this, "disconnectAllCallsWithPhoneAccount: "
+                            + "Failed to disconnect %s.", call);
+                }
+                return call.disconnect("Call " + call + " disconnected "
+                        + "in favor of new call.");
+            }, new LoggedHandlerExecutor(mHandler, "CSC.dACWPA", mCallsManager.getLock()));
+        }
+        return disconnectFuture;
+    }
+
+    /**
+     * Generic helper to log the result of the {@link CompletableFuture} containing the transactions
+     * that are being processed in the context of call sequencing.
+     * @param future The {@link CompletableFuture} encompassing the transaction that's being
+     *               computed.
+     * @param methodName The method name to describe the type of transaction being processed.
+     * @param sessionName The session name to identify the log.
+     * @param successMsg The message to be logged if the transaction succeeds.
+     * @param failureMsg The message to be logged if the transaction fails.
+     */
+    public void logFutureResultTransaction(CompletableFuture<Boolean> future, String methodName,
+            String sessionName, String successMsg, String failureMsg) {
+        future.thenApplyAsync((result) -> {
+            String msg = methodName + ": " + (result ? successMsg : failureMsg);
+            Log.i(this, msg);
+            return CompletableFuture.completedFuture(result);
+        }, new LoggedHandlerExecutor(mHandler, sessionName, mCallsManager.getLock()));
+    }
+
+    public boolean hasMmiCodeRestriction(Call call) {
+        if (mCallsManager.getNumCallsWithStateWithoutHandle(
+                CALL_FILTER_ALL, call, call.getTargetPhoneAccount(), ONGOING_CALL_STATES) > 0) {
+            // Set disconnect cause so that error will be printed out when call is disconnected.
+            CharSequence msg = mContext.getText(R.string.callFailed_reject_mmi);
+            call.setOverrideDisconnectCauseCode(new DisconnectCause(DisconnectCause.ERROR, msg, msg,
+                    "Rejected MMI code due to an ongoing call on another phone account."));
+            return true;
+        }
+        return false;
+    }
+
+    public void maybeAddAnsweringCallDropsFg(Call activeCall, Call incomingCall) {
+        // Don't set the extra when we have an incoming self-managed call that would potentially
+        // disconnect the active managed call.
+        if (activeCall == null || (isVoipCall(incomingCall) && isManagedCall(activeCall))) {
+            return;
+        }
+        // Check if the active call doesn't support hold. If it doesn't we should indicate to the
+        // user via the EXTRA_ANSWERING_DROPS_FG_CALL extra that the call would be dropped by
+        // answering the incoming call.
+        if (!mCallsManager.supportsHold(activeCall)) {
+            CharSequence droppedApp = activeCall.getTargetPhoneAccountLabel();
+            Bundle dropCallExtras = new Bundle();
+            dropCallExtras.putBoolean(Connection.EXTRA_ANSWERING_DROPS_FG_CALL, true);
+
+            // Include the name of the app which will drop the call.
+            dropCallExtras.putCharSequence(
+                    Connection.EXTRA_ANSWERING_DROPS_FG_CALL_APP_NAME, droppedApp);
+            Log.i(this, "Incoming call will drop %s call.", droppedApp);
+            incomingCall.putConnectionServiceExtras(dropCallExtras);
+        }
+    }
+
+    private void showErrorDialogForMaxOutgoingCallOutgoingPresent(Call call) {
+        int resourceId = R.string.callFailed_outgoing_already_present;
+        String reason = " there is already another call connecting. Wait for the "
+                + "call to be answered or disconnect before placing another call.";
+        showErrorDialogForFailedCall(call, CallFailureCause.MAX_OUTGOING_CALLS, resourceId, reason);
+    }
+
+    private void showErrorDialogForMaxOutgoingCallTooManyCalls(
+            Call call, boolean arePhoneAccountsSame) {
+        int resourceId = arePhoneAccountsSame
+                ? R.string.callFailed_too_many_calls_include_merge
+                : R.string.callFailed_too_many_calls_exclude_merge;
+        String reason = " there are two calls already in progress. Disconnect one "
+                + "of the calls or merge the calls (if possible).";
+        showErrorDialogForFailedCall(call, CallFailureCause.MAX_OUTGOING_CALLS, resourceId, reason);
+    }
+
+    private void showErrorDialogForOutgoingDuringRingingCall(Call call) {
+        int resourceId = R.string.callFailed_already_ringing;
+        String reason = " can't place outgoing call with an unanswered incoming call.";
+        showErrorDialogForFailedCall(call, null, resourceId, reason);
+    }
+
+    private void showErrorDialogForCannotHoldCall(Call call, boolean setCallFailure) {
+        CallFailureCause cause = null;
+        if (setCallFailure) {
+            cause = CallFailureCause.CANNOT_HOLD_CALL;
+        }
+        int resourceId = R.string.callFailed_unholdable_call;
+        String reason = " unable to hold live call. Disconnect the unholdable call.";
+        showErrorDialogForFailedCall(call, cause, resourceId, reason);
+    }
+
+    private void showErrorDialogForFailedCall(Call call, CallFailureCause cause, int resourceId,
+            String reason) {
+        if (cause != null) {
+            call.setStartFailCause(cause);
+        }
+        showErrorDialogForRestrictedOutgoingCall(mContext, resourceId, TAG, reason);
+    }
+
+    public Handler getHandler() {
+        return mHandler;
+    }
+
+    private boolean isVoipCall(Call call) {
+        if (call == null) {
+            return false;
+        }
+        return call.isSelfManaged() || call.isTransactionalCall();
+    }
+
+    private boolean isManagedCall(Call call) {
+        if (call == null) {
+            return false;
+        }
+        return !call.isSelfManaged() && !call.isTransactionalCall() && !call.isExternalCall();
     }
 }
diff --git a/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java b/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java
index 8410c5451..b2cfcabb1 100644
--- a/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java
+++ b/src/com/android/server/telecom/callsequencing/CallsManagerCallSequencingAdapter.java
@@ -16,9 +16,27 @@
 
 package com.android.server.telecom.callsequencing;
 
+import android.content.Context;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.OutcomeReceiver;
+import android.telecom.CallAttributes;
+import android.telecom.CallException;
+import android.telecom.Connection;
+import android.telecom.Log;
+import android.telecom.PhoneAccountHandle;
+
 import com.android.server.telecom.Call;
+import com.android.server.telecom.CallAudioManager;
+import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransaction;
+import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.R;
 
+import java.util.Collection;
+import java.util.HashSet;
+import java.util.Set;
 import java.util.concurrent.CompletableFuture;
 
 /**
@@ -28,25 +46,46 @@ import java.util.concurrent.CompletableFuture;
 public class CallsManagerCallSequencingAdapter {
 
     private final CallsManager mCallsManager;
+    private final Context mContext;
     private final CallSequencingController mSequencingController;
+    private final CallAudioManager mCallAudioManager;
+    private final Handler mHandler;
+    private final FeatureFlags mFeatureFlags;
     private final boolean mIsCallSequencingEnabled;
 
-    public CallsManagerCallSequencingAdapter(CallsManager callsManager,
-            CallSequencingController sequencingController,
-            boolean isCallSequencingEnabled) {
+    public CallsManagerCallSequencingAdapter(CallsManager callsManager, Context context,
+            CallSequencingController sequencingController, CallAudioManager callAudioManager,
+            FeatureFlags featureFlags) {
         mCallsManager = callsManager;
+        mContext = context;
         mSequencingController = sequencingController;
-        mIsCallSequencingEnabled = isCallSequencingEnabled;
+        mCallAudioManager = callAudioManager;
+        mHandler = sequencingController.getHandler();
+        mFeatureFlags = featureFlags;
+        mIsCallSequencingEnabled = featureFlags.enableCallSequencing();
     }
 
-    public void answerCall(Call incomingCall, int videoState) {
+    /**
+     * Conditionally try to answer the call depending on whether call sequencing
+     * (mIsCallSequencingEnabled) is enabled.
+     * @param incomingCall The incoming call that should be answered.
+     * @param videoState The video state configuration associated with the call.
+     * @param requestOrigin The origin of the request.
+     */
+    public void answerCall(Call incomingCall, int videoState,
+            @CallsManager.RequestOrigin int requestOrigin) {
         if (mIsCallSequencingEnabled && !incomingCall.isTransactionalCall()) {
-            mSequencingController.answerCall(incomingCall, videoState);
+            mSequencingController.answerCall(incomingCall, videoState, requestOrigin);
         } else {
-            mCallsManager.answerCallOld(incomingCall, videoState);
+            mCallsManager.answerCallOld(incomingCall, videoState, requestOrigin);
         }
     }
 
+    /**
+     * Conditionally attempt to unhold the provided call depending on whether call sequencing
+     * (mIsCallSequencingEnabled) is enabled.
+     * @param call The call to unhold.
+     */
     public void unholdCall(Call call) {
         if (mIsCallSequencingEnabled) {
             mSequencingController.unholdCall(call);
@@ -55,34 +94,293 @@ public class CallsManagerCallSequencingAdapter {
         }
     }
 
+    /**
+     * Conditionally attempt to hold the provided call depending on whether call sequencing
+     * (mIsCallSequencingEnabled) is enabled.
+     * @param call The call to hold.
+     */
     public void holdCall(Call call) {
         // Sequencing already taken care of for CSW/TSW in Call class.
-        call.hold();
+        CompletableFuture<Boolean> holdFuture = call.hold();
+        maybeLogFutureResultTransaction(holdFuture, "holdCall", "CMCSA.hC",
+                "hold call transaction succeeded.", "hold call transaction failed.");
     }
 
-    public void unholdCallForRemoval(Call removedCall,
-            boolean isLocallyDisconnecting) {
-        // Todo: confirm verification of disconnect logic
-        // Sequencing already taken care of for CSW/TSW in Call class.
-        mCallsManager.maybeMoveHeldCallToForeground(removedCall, isLocallyDisconnecting);
+    /**
+     * Conditionally disconnect the provided call depending on whether call sequencing
+     * (mIsCallSequencingEnabled) is enabled. The sequencing functionality ensures that we wait for
+     * the call to be disconnected as signalled by CSW/TSW as to ensure that subsequent call
+     * operations don't overlap with this one.
+     * @param call The call to disconnect.
+     */
+    public void disconnectCall(Call call) {
+        int previousState = call.getState();
+        if (mIsCallSequencingEnabled) {
+            mSequencingController.disconnectCall(call, previousState);
+        } else {
+            mCallsManager.disconnectCallOld(call, previousState);
+        }
     }
 
+    /**
+     * Conditionally make room for the outgoing call depending on whether call sequencing
+     * (mIsCallSequencingEnabled) is enabled.
+     * @param isEmergency Indicator of whether the call is an emergency call.
+     * @param call The call to potentially make room for.
+     * @return {@link CompletableFuture} which will contain the result of the transaction if room
+     *         was able to made for the call.
+     */
     public CompletableFuture<Boolean> makeRoomForOutgoingCall(boolean isEmergency, Call call) {
         if (mIsCallSequencingEnabled) {
             return mSequencingController.makeRoomForOutgoingCall(isEmergency, call);
         } else {
             return isEmergency
                     ? CompletableFuture.completedFuture(
-                            makeRoomForOutgoingEmergencyCallFlagOff(call))
-                    : CompletableFuture.completedFuture(makeRoomForOutgoingCallFlagOff(call));
+                            mCallsManager.makeRoomForOutgoingEmergencyCall(call))
+                    : CompletableFuture.completedFuture(
+                            mCallsManager.makeRoomForOutgoingCall(call));
+        }
+    }
+
+    /**
+     * Attempts to mark the self-managed call as active by first holding the active call and then
+     * requesting call focus for the self-managed call.
+     * @param call The self-managed call to set active
+     */
+    public void markCallAsActiveSelfManagedCall(Call call) {
+        if (mIsCallSequencingEnabled) {
+            mSequencingController.handleSetSelfManagedCallActive(call);
+        } else {
+            mCallsManager.holdActiveCallForNewCall(call);
+            mCallsManager.requestActionSetActiveCall(call,
+                    "active set explicitly for self-managed");
+        }
+    }
+
+    /**
+     * Helps create the transaction representing the outgoing transactional call. For outgoing
+     * calls, there can be more than one transaction that will need to complete when
+     * mIsCallSequencingEnabled is true. Otherwise, rely on the old behavior of creating an
+     * {@link OutgoingCallTransaction}.
+     * @param callAttributes The call attributes associated with the call.
+     * @param extras The extras that are associated with the call.
+     * @param callingPackage The calling package representing where the request was invoked from.
+     * @return The {@link CompletableFuture<CallTransaction>} that encompasses the request to
+     *         place/receive the transactional call.
+     */
+    public CompletableFuture<CallTransaction> createTransactionalOutgoingCall(String callId,
+            CallAttributes callAttributes, Bundle extras, String callingPackage) {
+        return mIsCallSequencingEnabled
+                ? mSequencingController.createTransactionalOutgoingCall(callId,
+                callAttributes, extras, callingPackage)
+                : CompletableFuture.completedFuture(new OutgoingCallTransaction(callId,
+                        mCallsManager.getContext(), callAttributes, mCallsManager, extras,
+                        mFeatureFlags));
+    }
+
+    /**
+     * attempt to hold or swap the current active call in favor of a new call request. The
+     * OutcomeReceiver will return onResult if the current active call is held or disconnected.
+     * Otherwise, the OutcomeReceiver will fail.
+     * @param newCall The new (transactional) call that's waiting to go active.
+     * @param isCallControlRequest Indication of whether this is a call control request.
+     * @param callback The callback to report the result of the aforementioned hold
+     *      transaction.
+     */
+    public void transactionHoldPotentialActiveCallForNewCall(Call newCall,
+            boolean isCallControlRequest, OutcomeReceiver<Boolean, CallException> callback) {
+        String mTag = "transactionHoldPotentialActiveCallForNewCall: ";
+        Call activeCall = (Call) mCallsManager.getConnectionServiceFocusManager()
+                .getCurrentFocusCall();
+        Log.i(this, mTag + "newCall=[%s], activeCall=[%s]", newCall, activeCall);
+
+        if (activeCall == null || activeCall == newCall) {
+            Log.i(this, mTag + "no need to hold activeCall");
+            callback.onResult(true);
+            return;
+        }
+
+        if (mFeatureFlags.transactionalHoldDisconnectsUnholdable()) {
+            // prevent bad actors from disconnecting the activeCall. Instead, clients will need to
+            // notify the user that they need to disconnect the ongoing call before making the
+            // new call ACTIVE.
+            if (isCallControlRequest
+                    && !mCallsManager.canHoldOrSwapActiveCall(activeCall, newCall)) {
+                Log.i(this, mTag + "CallControlRequest exit");
+                callback.onError(new CallException("activeCall is NOT holdable or swappable, please"
+                        + " request the user disconnect the call.",
+                        CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL));
+                return;
+            }
+
+            if (mIsCallSequencingEnabled) {
+                mSequencingController.transactionHoldPotentialActiveCallForNewCallSequencing(
+                        newCall, callback);
+            } else {
+                // The code path without sequencing but where transactionalHoldDisconnectsUnholdable
+                // flag is enabled.
+                mCallsManager.transactionHoldPotentialActiveCallForNewCallOld(newCall,
+                        activeCall, callback);
+            }
+        } else {
+            // The unflagged path (aka original code with no flags).
+            mCallsManager.transactionHoldPotentialActiveCallForNewCallUnflagged(activeCall,
+                    newCall, callback);
+        }
+    }
+
+    /**
+     * Attempts to move the held call to the foreground in cases where we need to auto-unhold the
+     * call.
+     */
+    public void maybeMoveHeldCallToForeground(Call removedCall, boolean isLocallyDisconnecting) {
+        CompletableFuture<Boolean> unholdForegroundCallFuture = null;
+        Call foregroundCall = mCallAudioManager.getPossiblyHeldForegroundCall();
+        // There are some cases (non-holdable calls) where we may want to skip auto-unholding when
+        // we're processing a new outgoing call and waiting for it to go active. Skip the
+        // auto-unholding in this case so that we don't end up with two active calls. If the new
+        // call fails, we will auto-unhold on that removed call. This is only set in
+        // CallSequencingController because the legacy code doesn't wait for disconnects to occur
+        // in order to place an outgoing (emergency) call, so we don't see this issue.
+        if (removedCall.getSkipAutoUnhold()) {
+            return;
+        }
+
+        if (isLocallyDisconnecting) {
+            boolean isDisconnectingChildCall = removedCall.isDisconnectingChildCall();
+            Log.v(this, "maybeMoveHeldCallToForeground: isDisconnectingChildCall = "
+                    + isDisconnectingChildCall + "call -> %s", removedCall);
+            // Auto-unhold the foreground call due to a locally disconnected call, except if the
+            // call which was disconnected is a member of a conference (don't want to auto
+            // un-hold the conference if we remove a member of the conference).
+            // Also, ensure that the call we're removing is from the same ConnectionService as
+            // the one we're removing.  We don't want to auto-unhold between ConnectionService
+            // implementations, especially if one is managed and the other is a VoIP CS.
+            if (!isDisconnectingChildCall && foregroundCall != null
+                    && foregroundCall.getState() == CallState.ON_HOLD
+                    && CallsManager.areFromSameSource(foregroundCall, removedCall)) {
+                unholdForegroundCallFuture = foregroundCall.unhold();
+            }
+        } else if (foregroundCall != null &&
+                !foregroundCall.can(Connection.CAPABILITY_SUPPORT_HOLD) &&
+                foregroundCall.getState() == CallState.ON_HOLD) {
+
+            // The new foreground call is on hold, however the carrier does not display the hold
+            // button in the UI.  Therefore, we need to auto unhold the held call since the user
+            // has no means of unholding it themselves.
+            Log.i(this, "maybeMoveHeldCallToForeground: Auto-unholding held foreground call (call "
+                    + "doesn't support hold)");
+            unholdForegroundCallFuture = foregroundCall.unhold();
         }
+        maybeLogFutureResultTransaction(unholdForegroundCallFuture,
+                "maybeMoveHeldCallToForeground", "CM.mMHCTF",
+                "Successfully unheld the foreground call.",
+                "Failed to unhold the foreground call.");
     }
 
-    private boolean makeRoomForOutgoingCallFlagOff(Call call) {
-        return mCallsManager.makeRoomForOutgoingCall(call);
+    /**
+     * Generic helper to log the result of the {@link CompletableFuture} containing the transactions
+     * that are being processed in the context of call sequencing.
+     * @param future The {@link CompletableFuture} encompassing the transaction that's being
+     *               computed.
+     * @param methodName The method name to describe the type of transaction being processed.
+     * @param sessionName The session name to identify the log.
+     * @param successMsg The message to be logged if the transaction succeeds.
+     * @param failureMsg The message to be logged if the transaction fails.
+     */
+    public void maybeLogFutureResultTransaction(CompletableFuture<Boolean> future,
+            String methodName, String sessionName, String successMsg, String failureMsg) {
+        if (mIsCallSequencingEnabled && future != null) {
+            mSequencingController.logFutureResultTransaction(future, methodName, sessionName,
+                    successMsg, failureMsg);
+        }
+    }
+
+    /**
+     * Determines if we need to add the {@link Connection#EXTRA_ANSWERING_DROPS_FG_CALL} extra to
+     * the incoming connection. This is set if the ongoing calls don't support hold.
+     */
+    public void maybeAddAnsweringCallDropsFg(Call activeCall, Call incomingCall) {
+        if (mIsCallSequencingEnabled) {
+            mSequencingController.maybeAddAnsweringCallDropsFg(activeCall, incomingCall);
+        } else {
+            mCallsManager.maybeAddAnsweringCallDropsFgOld(activeCall, incomingCall);
+        }
+    }
+
+    /**
+     * Tries to see if there are any ongoing calls on another phone account when an MMI code is
+     * detected to determine whether it should be allowed. For DSDA purposes, we will not allow any
+     * MMI codes when there's a call on a different phone account.
+     * @param call The call to ignore and the associated phone account to exclude when getting the
+     *             total call count.
+     * @return {@code true} if the MMI code should be allowed, {@code false} otherwise.
+     */
+    public boolean shouldAllowMmiCode(Call call) {
+        return !mIsCallSequencingEnabled || !mSequencingController.hasMmiCodeRestriction(call);
+    }
+
+    /**
+     * Processes the simultaneous call type for the ongoing calls that are being tracked in
+     * {@link CallsManager}. The current call's simultaneous call type will be overridden only if
+     * it's current type priority is lower than the one being set.
+     * @param calls The list of the currently tracked calls.
+     */
+    public void processSimultaneousCallTypes(Collection<Call> calls) {
+        // Metrics should only be tracked when call sequencing flag is enabled.
+        if (!mIsCallSequencingEnabled) {
+            return;
+        }
+        // Device should have simultaneous calling supported.
+        boolean isSimultaneousCallingSupported = mCallsManager.isDsdaCallingPossible();
+        int type;
+        // Go through the available calls' phone accounts to determine how many different ones
+        // are being used.
+        Set<PhoneAccountHandle> handles = new HashSet<>();
+        for (Call call : calls) {
+            if (call.getTargetPhoneAccount() != null) {
+                handles.add(call.getTargetPhoneAccount());
+            }
+            // No need to proceed further given that we already know there is more than 1 phone
+            // account being used.
+            if (handles.size() > 1) {
+                break;
+            }
+        }
+        type = handles.size() > 1
+                ? (isSimultaneousCallingSupported ? Call.CALL_DIRECTION_DUAL_DIFF_ACCOUNT
+                        : Call.CALL_SIMULTANEOUS_DISABLED_DIFF_ACCOUNT)
+                : (isSimultaneousCallingSupported ? Call.CALL_DIRECTION_DUAL_SAME_ACCOUNT
+                        : Call.CALL_SIMULTANEOUS_DISABLED_SAME_ACCOUNT);
+
+        Log.i(this, "processSimultaneousCallTypes: the calculated simultaneous call type for "
+                + "the tracked calls is [%d]", type);
+        calls.forEach(c -> {
+            // If the current call's simultaneous call type priority is lower than the one being
+            // set, then let the override occur. Otherwise, ignore it.
+            if (c.getSimultaneousType() < type) {
+                Log.i(this, "processSimultaneousCallTypes: overriding simultaneous call type for "
+                        + "call (%s). Previous value: %d", c.getId(), c.getSimultaneousType());
+                c.setSimultaneousType(type);
+            }
+        });
+    }
+
+    /**
+     * Upon a call resume failure, we will auto-unhold the foreground call that was held. Note that
+     * this should only apply for calls across phone accounts as the ImsPhoneCallTracker handles
+     * this for a single phone.
+     * @param callResumeFailed The call that failed to resume.
+     * @param callToUnhold The fg call that was held.
+     */
+    public void handleCallResumeFailed(Call callResumeFailed, Call callToUnhold) {
+        if (mIsCallSequencingEnabled && !mSequencingController.arePhoneAccountsSame(
+                callResumeFailed, callToUnhold)) {
+            unholdCall(callToUnhold);
+        }
     }
 
-    private boolean makeRoomForOutgoingEmergencyCallFlagOff(Call call) {
-        return mCallsManager.makeRoomForOutgoingEmergencyCall(call);
+    public Handler getHandler() {
+        return mHandler;
     }
 }
diff --git a/src/com/android/server/telecom/callsequencing/TransactionManager.java b/src/com/android/server/telecom/callsequencing/TransactionManager.java
index a3b3828ab..98d54daa3 100644
--- a/src/com/android/server/telecom/callsequencing/TransactionManager.java
+++ b/src/com/android/server/telecom/callsequencing/TransactionManager.java
@@ -25,6 +25,8 @@ import android.util.IndentingPrintWriter;
 import android.util.Log;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.telecom.AnomalyReporterAdapter;
+import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.flags.Flags;
 import java.util.ArrayDeque;
 import java.util.ArrayList;
@@ -32,6 +34,7 @@ import java.util.Deque;
 import java.util.List;
 import java.util.Locale;
 import java.util.Queue;
+import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 
 public class TransactionManager {
@@ -43,6 +46,12 @@ public class TransactionManager {
     private final Deque<CallTransaction> mCompletedTransactions;
     private CallTransaction mCurrentTransaction;
     private boolean mProcessingCallSequencing;
+    private AnomalyReporterAdapter mAnomalyReporter;
+    private FeatureFlags mFeatureFlags;
+    public static final UUID TRANSACTION_MANAGER_TIMEOUT_UUID =
+            UUID.fromString("9ccce52e-6694-4357-9e5e-516a9531b062");
+    public static final String TRANSACTION_MANAGER_TIMEOUT_MSG =
+            "TransactionManager hit a timeout while processing a transaction";
 
     public interface TransactionCompleteListener {
         void onTransactionCompleted(CallTransactionResult result, String transactionName);
@@ -67,6 +76,14 @@ public class TransactionManager {
         return INSTANCE;
     }
 
+    public void setFeatureFlag(FeatureFlags flag){
+       mFeatureFlags = flag;
+    }
+
+    public void setAnomalyReporter(AnomalyReporterAdapter callAnomalyReporter){
+        mAnomalyReporter = callAnomalyReporter;
+    }
+
     @VisibleForTesting
     public static TransactionManager getTestInstance() {
         return new TransactionManager();
@@ -109,6 +126,12 @@ public class TransactionManager {
                     receiver.onError(new CallException(transactionName + " timeout",
                             CODE_OPERATION_TIMED_OUT));
                     transactionCompleteFuture.complete(false);
+                    if (mFeatureFlags != null && mAnomalyReporter != null &&
+                            mFeatureFlags.enableCallExceptionAnomReports()) {
+                        mAnomalyReporter.reportAnomaly(
+                                TRANSACTION_MANAGER_TIMEOUT_UUID,
+                                TRANSACTION_MANAGER_TIMEOUT_MSG);
+                    }
                 } catch (Exception e) {
                     Log.e(TAG, String.format("onTransactionTimeout: Notifying transaction "
                             + " %s resulted in an Exception.", transactionName), e);
@@ -169,14 +192,6 @@ public class TransactionManager {
         }
     }
 
-    public void setProcessingCallSequencing(boolean processingCallSequencing) {
-        mProcessingCallSequencing = processingCallSequencing;
-    }
-
-    public boolean isProcessingCallSequencing() {
-        return mProcessingCallSequencing;
-    }
-
     /**
      * Called when the dumpsys is created for telecom to capture the current state.
      */
diff --git a/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java b/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java
index 7c8bbe407..37bc065cc 100644
--- a/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java
+++ b/src/com/android/server/telecom/callsequencing/TransactionalCallSequencingAdapter.java
@@ -40,14 +40,13 @@ import java.util.concurrent.CompletableFuture;
 public class TransactionalCallSequencingAdapter {
     private final TransactionManager mTransactionManager;
     private final CallsManager mCallsManager;
-//    private final boolean mIsCallSequencingEnabled;
+    private final boolean mIsCallSequencingEnabled;
 
     public TransactionalCallSequencingAdapter(TransactionManager transactionManager,
             CallsManager callsManager, boolean isCallSequencingEnabled) {
         mTransactionManager = transactionManager;
         mCallsManager = callsManager;
-        // TODO implement call sequencing changes
-//        mIsCallSequencingEnabled = isCallSequencingEnabled;
+        mIsCallSequencingEnabled = isCallSequencingEnabled;
     }
 
     /**
@@ -55,7 +54,13 @@ public class TransactionalCallSequencingAdapter {
      */
     public void setActive(Call call,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        setActiveFlagOff(call, receiver);
+        if (mIsCallSequencingEnabled) {
+            createSetActiveTransactionSequencing(call, true /* callControlRequest */, null,
+                    receiver, receiver);
+        } else {
+            mTransactionManager.addTransaction(createSetActiveTransactions(call,
+                    true /* callControlRequest */), receiver);
+        }
     }
 
     /**
@@ -63,7 +68,18 @@ public class TransactionalCallSequencingAdapter {
      */
     public void setAnswered(Call call, int newVideoState,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        setAnsweredFlagOff(call, newVideoState, receiver);
+        boolean isCallControlRequest = true;
+        OutcomeReceiver<CallTransactionResult, CallException> receiverForTransaction =
+                getSetAnswerReceiver(call, null /* foregroundCallBeforeSwap */,
+                        false /* wasForegroundActive */, newVideoState, receiver,
+                        isCallControlRequest);
+        if (mIsCallSequencingEnabled) {
+            createSetActiveTransactionSequencing(call, isCallControlRequest, null,
+                    receiver, receiverForTransaction /* receiverForTransaction */);
+        } else {
+            mTransactionManager.addTransaction(createSetActiveTransactions(call,
+                    isCallControlRequest), receiverForTransaction);
+        }
     }
 
     /**
@@ -71,7 +87,8 @@ public class TransactionalCallSequencingAdapter {
      */
     public void setDisconnected(Call call, DisconnectCause dc,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        setDisconnectedFlagOff(call, dc, receiver);
+        mTransactionManager.addTransaction(
+                new EndCallTransaction(mCallsManager, dc, call), receiver);
     }
 
     /**
@@ -79,7 +96,7 @@ public class TransactionalCallSequencingAdapter {
      */
     public void setInactive(Call call,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        setInactiveFlagOff(call, receiver);
+        mTransactionManager.addTransaction(new HoldCallTransaction(mCallsManager,call), receiver);
     }
 
     /**
@@ -89,143 +106,58 @@ public class TransactionalCallSequencingAdapter {
     public CompletableFuture<Boolean> onSetActive(Call call,
             CallTransaction clientCbT,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        return onSetActiveFlagOff(call, clientCbT, receiver);
+        // save CallsManager state before sending client state changes
+        Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
+        boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
+        OutcomeReceiver<CallTransactionResult, CallException> receiverForTransaction =
+                getOnSetActiveReceiver(call, foregroundCallBeforeSwap, wasActive, receiver);
+
+        if (mIsCallSequencingEnabled) {
+            return createSetActiveTransactionSequencing(call, false /* callControlRequest */,
+                    clientCbT, receiver, receiverForTransaction);
+        } else {
+            SerialTransaction serialTransactions = createSetActiveTransactions(call,
+                    false /* callControlRequest */);
+            serialTransactions.appendTransaction(clientCbT);
+            // do CallsManager workload before asking client and
+            //   reset CallsManager state if client does NOT ack
+            return mTransactionManager.addTransaction(
+                    serialTransactions, receiverForTransaction);
+        }
     }
 
     /**
      * Server -> Client command to answer an incoming call, which if it fails, will trigger the
      * disconnect of the call and then reset the state of the other call back to what it was before.
      */
-    public void onSetAnswered(Call call, int videoState, CallTransaction clientCbT,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        onSetAnsweredFlagOff(call, videoState, clientCbT, receiver);
-    }
-
-    /**
-     * Server -> Client command to set the call as inactive
-     */
-    public CompletableFuture<Boolean> onSetInactive(Call call,
-            CallTransaction clientCbT,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        return onSetInactiveFlagOff(call, clientCbT, receiver);
-    }
-
-    /**
-     * Server -> Client command to disconnect the call
-     */
-    public CompletableFuture<Boolean> onSetDisconnected(Call call,
-            DisconnectCause dc, CallTransaction clientCbT, OutcomeReceiver<CallTransactionResult,
+    public CompletableFuture<Boolean> onSetAnswered(Call call, int videoState,
+            CallTransaction clientCbT, OutcomeReceiver<CallTransactionResult,
             CallException> receiver) {
-        return onSetDisconnectedFlagOff(call, dc, clientCbT, receiver);
-    }
-
-    /**
-     * Clean up the calls that have been passed in from CallsManager
-     */
-    public void cleanup(Collection<Call> calls) {
-        cleanupFlagOff(calls);
-    }
-
-    private void setActiveFlagOff(Call call,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        CompletableFuture<Boolean> transactionResult = mTransactionManager
-                .addTransaction(createSetActiveTransactions(call,
-                true /* callControlRequest */), receiver);
-    }
-
-    private void setAnsweredFlagOff(Call call, int newVideoState,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        CompletableFuture<Boolean> transactionResult = mTransactionManager
-                .addTransaction(createSetActiveTransactions(call,
-                                true /* callControlRequest */),
-                new OutcomeReceiver<>() {
-                    @Override
-                    public void onResult(CallTransactionResult callTransactionResult) {
-                        call.setVideoState(newVideoState);
-                        receiver.onResult(callTransactionResult);
-                    }
-
-                    @Override
-                    public void onError(CallException error) {
-                        receiver.onError(error);
-                    }
-                });
-    }
-
-    private void setDisconnectedFlagOff(Call call, DisconnectCause dc,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        CompletableFuture<Boolean> transactionResult = mTransactionManager
-                .addTransaction(new EndCallTransaction(mCallsManager,
-                        dc, call), receiver);
-    }
-
-    private void setInactiveFlagOff(Call call,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        CompletableFuture<Boolean> transactionResult = mTransactionManager
-                .addTransaction(new HoldCallTransaction(mCallsManager,call), receiver);
-    }
-
-    private CompletableFuture<Boolean> onSetActiveFlagOff(Call call,
-            CallTransaction clientCbT,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        boolean isCallControlRequest = false;
         // save CallsManager state before sending client state changes
         Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
         boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
-        SerialTransaction serialTransactions = createSetActiveTransactions(call,
-                false /* callControlRequest */);
-        serialTransactions.appendTransaction(clientCbT);
-        // do CallsManager workload before asking client and
-        //   reset CallsManager state if client does NOT ack
-        return mTransactionManager.addTransaction(
-                serialTransactions,
-                new OutcomeReceiver<>() {
-                    @Override
-                    public void onResult(CallTransactionResult result) {
-                        receiver.onResult(result);
-                    }
-
-                    @Override
-                    public void onError(CallException exception) {
-                        mCallsManager.markCallAsOnHold(call);
-                        maybeResetForegroundCall(foregroundCallBeforeSwap, wasActive);
-                        receiver.onError(exception);
-                    }
-                });
-    }
-
-    private void onSetAnsweredFlagOff(Call call, int videoState, CallTransaction clientCbT,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
-        // save CallsManager state before sending client state changes
-        Call foregroundCallBeforeSwap = mCallsManager.getForegroundCall();
-        boolean wasActive = foregroundCallBeforeSwap != null && foregroundCallBeforeSwap.isActive();
-        SerialTransaction serialTransactions = createSetActiveTransactions(call,
-                false /* callControlRequest */);
-        serialTransactions.appendTransaction(clientCbT);
-        // do CallsManager workload before asking client and
-        //   reset CallsManager state if client does NOT ack
-        CompletableFuture<Boolean> transactionResult = mTransactionManager
-                .addTransaction(serialTransactions,
-                new OutcomeReceiver<>() {
-                    @Override
-                    public void onResult(CallTransactionResult result) {
-                        call.setVideoState(videoState);
-                        receiver.onResult(result);
-                    }
-
-                    @Override
-                    public void onError(CallException exception) {
-                        // This also sends the signal to untrack from TSW and the client_TSW
-                        removeCallFromCallsManager(call,
-                                new DisconnectCause(DisconnectCause.REJECTED,
-                                        "client rejected to answer the call;"
-                                                + " force disconnecting"));
-                        maybeResetForegroundCall(foregroundCallBeforeSwap, wasActive);
-                        receiver.onError(exception);
-                    }
-                });
+        OutcomeReceiver<CallTransactionResult, CallException> receiverForTransaction =
+                getSetAnswerReceiver(call, foregroundCallBeforeSwap, wasActive,
+                        videoState, receiver, isCallControlRequest);
+
+        if (mIsCallSequencingEnabled) {
+            return createSetActiveTransactionSequencing(call, false /* callControlRequest */,
+                    clientCbT, receiver, receiverForTransaction);
+        } else {
+            SerialTransaction serialTransactions = createSetActiveTransactions(call,
+                    isCallControlRequest);
+            serialTransactions.appendTransaction(clientCbT);
+            // do CallsManager workload before asking client and
+            //   reset CallsManager state if client does NOT ack
+            return mTransactionManager.addTransaction(serialTransactions, receiverForTransaction);
+        }
     }
 
-    private CompletableFuture<Boolean> onSetInactiveFlagOff(Call call,
+    /**
+     * Server -> Client command to set the call as inactive
+     */
+    public CompletableFuture<Boolean> onSetInactive(Call call,
             CallTransaction clientCbT,
             OutcomeReceiver<CallTransactionResult, CallException> receiver) {
         return mTransactionManager.addTransaction(clientCbT,
@@ -246,9 +178,9 @@ public class TransactionalCallSequencingAdapter {
     /**
      * Server -> Client command to disconnect the call
      */
-    private CompletableFuture<Boolean> onSetDisconnectedFlagOff(Call call,
-            DisconnectCause dc, CallTransaction clientCbT,
-            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+    public CompletableFuture<Boolean> onSetDisconnected(Call call,
+            DisconnectCause dc, CallTransaction clientCbT, OutcomeReceiver<CallTransactionResult,
+            CallException> receiver) {
         return mTransactionManager.addTransaction(clientCbT,
                 new OutcomeReceiver<>() {
                     @Override
@@ -262,8 +194,14 @@ public class TransactionalCallSequencingAdapter {
                         removeCallFromCallsManager(call, dc);
                         receiver.onError(exception);
                     }
-                }
-        );
+                });
+    }
+
+    /**
+     * Clean up the calls that have been passed in from CallsManager
+     */
+    public void cleanup(Collection<Call> calls) {
+        cleanupFlagOff(calls);
     }
 
     private SerialTransaction createSetActiveTransactions(Call call, boolean isCallControlRequest) {
@@ -279,10 +217,50 @@ public class TransactionalCallSequencingAdapter {
         return new SerialTransaction(transactions, mCallsManager.getLock());
     }
 
+    /**
+     * This code path is invoked when mIsCallSequencingEnabled is true. We will first try to hold
+     * the active call before adding the transactions to request call focus for the new call as well
+     * as verify the client ack for the transaction (if applicable). If the hold transaction
+     * succeeds, we will continue processing the rest of the transactions via a SerialTransaction.
+     */
+    private CompletableFuture<Boolean> createSetActiveTransactionSequencing(
+            Call call, boolean isCallControlRequest, CallTransaction clientCbT,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver,
+            OutcomeReceiver<CallTransactionResult, CallException> receiverForTransaction) {
+        final CompletableFuture<Boolean>[] createSetActiveFuture =
+                new CompletableFuture[]{new CompletableFuture<>()};
+        OutcomeReceiver<Boolean, CallException> maybePerformHoldCallback = new OutcomeReceiver<>() {
+            @Override
+            public void onResult(Boolean result) {
+                // Transaction not yet completed. Still need to request focus for active call and
+                // process client callback transaction if applicable.
+                // create list for multiple transactions
+                List<CallTransaction> transactions = new ArrayList<>();
+                // And request a new focus call update
+                transactions.add(new RequestNewActiveCallTransaction(mCallsManager, call));
+                if (clientCbT != null){
+                    transactions.add(clientCbT);
+                }
+                SerialTransaction serialTransactions = new SerialTransaction(
+                        transactions, mCallsManager.getLock());
+                createSetActiveFuture[0] = mTransactionManager.addTransaction(serialTransactions,
+                        receiverForTransaction);
+            }
+
+            @Override
+            public void onError(CallException exception) {
+                createSetActiveFuture[0] = CompletableFuture.completedFuture(false);
+                receiver.onError(exception);
+            }
+        };
+
+        mCallsManager.getCallSequencingAdapter().transactionHoldPotentialActiveCallForNewCall(call,
+                isCallControlRequest, maybePerformHoldCallback);
+        return createSetActiveFuture[0];
+    }
+
     private void removeCallFromCallsManager(Call call, DisconnectCause cause) {
-        if (cause.getCode() != DisconnectCause.REJECTED) {
-            mCallsManager.markCallAsDisconnected(call, cause);
-        }
+        mCallsManager.markCallAsDisconnected(call, cause);
         mCallsManager.removeCall(call);
     }
 
@@ -301,4 +279,49 @@ public class TransactionalCallSequencingAdapter {
             mCallsManager.removeCall(call); // This will clear mTrackedCalls && ClientTWS
         }
     }
+
+    private OutcomeReceiver<CallTransactionResult, CallException> getOnSetActiveReceiver(
+            Call call, Call foregroundCallBeforeSwap, boolean wasForegroundActive,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver) {
+        return new OutcomeReceiver<>() {
+            @Override
+            public void onResult(CallTransactionResult result) {
+                receiver.onResult(result);
+            }
+
+            @Override
+            public void onError(CallException exception) {
+                mCallsManager.markCallAsOnHold(call);
+                maybeResetForegroundCall(foregroundCallBeforeSwap, wasForegroundActive);
+                receiver.onError(exception);
+            }
+        };
+    }
+
+    private OutcomeReceiver<CallTransactionResult, CallException> getSetAnswerReceiver(
+            Call call, Call foregroundCallBeforeSwap, boolean wasForegroundActive, int videoState,
+            OutcomeReceiver<CallTransactionResult, CallException> receiver,
+            boolean isCallControlRequest) {
+        return new OutcomeReceiver<>() {
+            @Override
+            public void onResult(CallTransactionResult result) {
+                call.setVideoState(videoState);
+                receiver.onResult(result);
+            }
+
+            @Override
+            public void onError(CallException exception) {
+                if (!isCallControlRequest) {
+                    // This also sends the signal to untrack from TSW and the
+                    // client_TSW
+                    removeCallFromCallsManager(call,
+                            new DisconnectCause(DisconnectCause.REJECTED,
+                                    "client rejected to answer the call;"
+                                            + " force disconnecting"));
+                    maybeResetForegroundCall(foregroundCallBeforeSwap, wasForegroundActive);
+                }
+                receiver.onError(exception);
+            }
+        };
+    }
 }
diff --git a/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java b/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
index 82b32fbe3..b7e4f0494 100644
--- a/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/VerifyCallStateChangeTransaction.java
@@ -18,8 +18,10 @@ package com.android.server.telecom.callsequencing;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.Call;
+import com.android.server.telecom.CallState;
 import com.android.server.telecom.TelecomSystem;
 
+import android.telecom.CallException;
 import android.telecom.Log;
 
 import java.util.Set;
@@ -36,7 +38,7 @@ import java.util.stream.IntStream;
  */
 public class VerifyCallStateChangeTransaction extends CallTransaction {
     private static final String TAG = VerifyCallStateChangeTransaction.class.getSimpleName();
-    private static final long CALL_STATE_TIMEOUT_MILLISECONDS = 2000L;
+    private static final long CALL_STATE_TIMEOUT_MILLISECONDS = 5000L;
     private final Call mCall;
     private final Set<Integer> mTargetCallStates;
     private final CompletableFuture<CallTransactionResult> mTransactionResult =
@@ -56,6 +58,26 @@ public class VerifyCallStateChangeTransaction extends CallTransaction {
         }
     };
 
+    private final Call.ListenerBase mCallListenerImpl = new Call.ListenerBase() {
+        @Override
+        public void onCallHoldFailed(Call call) {
+            if (call.equals(mCall) && mTargetCallStates.contains(CallState.ON_HOLD)) {
+                // Fail the transaction if a call hold failure is received.
+                mTransactionResult.complete(new CallTransactionResult(
+                        CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL, "error holding call"));
+            }
+        }
+        @Override
+        public void onCallResumeFailed(Call call) {
+            if (call.equals(mCall) && mTargetCallStates.contains(CallState.ACTIVE)) {
+                // Fail the transaction if a call resume failure is received (this means that the
+                // current call could not be unheld).
+                mTransactionResult.complete(new CallTransactionResult(
+                        CallException.CODE_CALL_CANNOT_BE_SET_TO_ACTIVE, "error unholding call"));
+            }
+        }
+    };
+
     public VerifyCallStateChangeTransaction(TelecomSystem.SyncRoot lock,  Call call,
             int... targetCallStates) {
         super(lock, CALL_STATE_TIMEOUT_MILLISECONDS);
@@ -73,12 +95,14 @@ public class VerifyCallStateChangeTransaction extends CallTransaction {
             return mTransactionResult;
         }
         mCall.addCallStateListener(mCallStateListenerImpl);
+        mCall.addListener(mCallListenerImpl);
         return mTransactionResult;
     }
 
     @Override
     public void finishTransaction() {
         mCall.removeCallStateListener(mCallStateListenerImpl);
+        mCall.removeListener(mCallListenerImpl);
     }
 
     private boolean isNewCallStateTargetCallState() {
diff --git a/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java b/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
index 802ea7e46..ae10deea2 100644
--- a/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/CallEventCallbackAckTransaction.java
@@ -54,17 +54,17 @@ public class CallEventCallbackAckTransaction extends CallTransaction {
             CODE_OPERATION_TIMED_OUT, "failed to complete the operation before timeout");
 
     private static class AckResultReceiver extends ResultReceiver {
-        CountDownLatch mCountDownLatch;
+        CompletableFuture<Boolean> mCompletableFuture;
 
-        public AckResultReceiver(CountDownLatch latch) {
+        public AckResultReceiver(CompletableFuture<Boolean> future) {
             super(null);
-            mCountDownLatch = latch;
+            mCompletableFuture = future;
         }
 
         @Override
         protected void onReceiveResult(int resultCode, Bundle resultData) {
             if (resultCode == TELECOM_TRANSACTION_SUCCESS) {
-                mCountDownLatch.countDown();
+                mCompletableFuture.complete(true);
             }
         }
     }
@@ -99,9 +99,10 @@ public class CallEventCallbackAckTransaction extends CallTransaction {
 
     @Override
     public CompletionStage<CallTransactionResult> processTransaction(Void v) {
-        Log.d(TAG, "processTransaction");
-        CountDownLatch latch = new CountDownLatch(1);
-        ResultReceiver receiver = new AckResultReceiver(latch);
+        Log.d(TAG, "processTransaction: action [" + mAction + "]");
+        CompletableFuture<Boolean> future = new CompletableFuture<Boolean>()
+                .completeOnTimeout(false, mTransactionTimeoutMs, TimeUnit.MILLISECONDS);
+        ResultReceiver receiver = new AckResultReceiver(future);
 
         try {
             switch (mAction) {
@@ -125,9 +126,7 @@ public class CallEventCallbackAckTransaction extends CallTransaction {
             return CompletableFuture.completedFuture(TRANSACTION_FAILED);
         }
 
-        try {
-            // wait for the client to ack that CallEventCallback
-            boolean success = latch.await(mTransactionTimeoutMs, TimeUnit.MILLISECONDS);
+        return future.thenCompose((success) -> {
             if (!success) {
                 // client send onError and failed to complete transaction
                 Log.i(TAG, String.format("CallEventCallbackAckTransaction:"
@@ -139,8 +138,6 @@ public class CallEventCallbackAckTransaction extends CallTransaction {
                         new CallTransactionResult(CallTransactionResult.RESULT_SUCCEED,
                                 "success"));
             }
-        } catch (InterruptedException ie) {
-            return CompletableFuture.completedFuture(TRANSACTION_FAILED);
-        }
+        });
     }
 }
diff --git a/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
index 32062b566..cb839dc52 100644
--- a/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/MaybeHoldCallForNewCallTransaction.java
@@ -52,8 +52,8 @@ public class MaybeHoldCallForNewCallTransaction extends CallTransaction {
         Log.d(TAG, "processTransaction");
         CompletableFuture<CallTransactionResult> future = new CompletableFuture<>();
 
-        mCallsManager.transactionHoldPotentialActiveCallForNewCall(mCall, mIsCallControlRequest,
-                new OutcomeReceiver<>() {
+        mCallsManager.getCallSequencingAdapter().transactionHoldPotentialActiveCallForNewCall(
+                mCall, mIsCallControlRequest, new OutcomeReceiver<>() {
             @Override
             public void onResult(Boolean result) {
                 Log.d(TAG, "processTransaction: onResult");
diff --git a/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
index 572de55d8..b22157918 100644
--- a/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
+++ b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransaction.java
@@ -91,7 +91,7 @@ public class OutgoingCallTransaction extends CallTransaction {
             CompletableFuture<Call> callFuture =
                     mCallsManager.startOutgoingCall(mCallAttributes.getAddress(),
                             mCallAttributes.getPhoneAccountHandle(),
-                            generateExtras(mCallAttributes),
+                            generateExtras(mCallId, mExtras, mCallAttributes, mFeatureFlags),
                             mCallAttributes.getPhoneAccountHandle().getUserHandle(),
                             intent,
                             mCallingPackage);
@@ -102,35 +102,11 @@ public class OutgoingCallTransaction extends CallTransaction {
                                 CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
                                 "incoming call not permitted at the current time"));
             }
-            CompletionStage<CallTransactionResult> result = callFuture.thenComposeAsync(
-                    (call) -> {
-
-                        Log.d(TAG, "processTransaction: completing future");
-
-                        if (call == null) {
-                            Log.d(TAG, "processTransaction: call is null");
-                            return CompletableFuture.completedFuture(
-                                    new CallTransactionResult(
-                                            CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
-                                            "call could not be created at this time"));
-                        } else {
-                            Log.d(TAG, "processTransaction: call done. id=" + call.getId());
-                        }
-
-                        if (mFeatureFlags.disconnectSelfManagedStuckStartupCalls()) {
-                            // set to dialing so the CallAnomalyWatchdog gives the VoIP calls 1
-                            // minute to timeout rather than 5 seconds.
-                            mCallsManager.markCallAsDialing(call);
-                        }
-
-                        return CompletableFuture.completedFuture(
-                                new CallTransactionResult(
-                                        CallTransactionResult.RESULT_SUCCEED,
-                                        call, null, true));
-                    }
-                    , new LoggedHandlerExecutor(mHandler, "OCT.pT", null));
 
-            return result;
+            return callFuture.thenComposeAsync(
+                    (call) -> processOutgoingCallTransactionHelper(call, TAG,
+                            mCallsManager, mFeatureFlags)
+                    , new LoggedHandlerExecutor(mHandler, "OCT.pT", null));
         } else {
             return CompletableFuture.completedFuture(
                     new CallTransactionResult(
@@ -141,20 +117,47 @@ public class OutgoingCallTransaction extends CallTransaction {
     }
 
     @VisibleForTesting
-    public Bundle generateExtras(CallAttributes callAttributes) {
-        mExtras.setDefusable(true);
-        mExtras.putString(TelecomManager.TRANSACTION_CALL_ID_KEY, mCallId);
-        mExtras.putInt(CALL_CAPABILITIES_KEY, callAttributes.getCallCapabilities());
-        if (mFeatureFlags.transactionalVideoState()) {
+    public static Bundle generateExtras(String callId, Bundle extras,
+            CallAttributes callAttributes, FeatureFlags featureFlags) {
+        extras.setDefusable(true);
+        extras.putString(TelecomManager.TRANSACTION_CALL_ID_KEY, callId);
+        extras.putInt(CALL_CAPABILITIES_KEY, callAttributes.getCallCapabilities());
+        if (featureFlags.transactionalVideoState()) {
             // Transactional calls need to remap the CallAttributes video state to the existing
             // VideoProfile for consistency.
-            mExtras.putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE,
+            extras.putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE,
                     TransactionalVideoStateToVideoProfileState(callAttributes.getCallType()));
         } else {
-            mExtras.putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE,
+            extras.putInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE,
                     callAttributes.getCallType());
         }
-        mExtras.putCharSequence(DISPLAY_NAME_KEY, callAttributes.getDisplayName());
-        return mExtras;
+        extras.putCharSequence(DISPLAY_NAME_KEY, callAttributes.getDisplayName());
+        return extras;
+    }
+
+    public static CompletableFuture<CallTransactionResult> processOutgoingCallTransactionHelper(
+            Call call, String tag, CallsManager callsManager, FeatureFlags featureFlags) {
+        Log.d(tag, "processTransaction: completing future");
+
+        if (call == null) {
+            Log.d(tag, "processTransaction: call is null");
+            return CompletableFuture.completedFuture(
+                    new CallTransactionResult(
+                            CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
+                            "call could not be created at this time"));
+        } else {
+            Log.d(tag, "processTransaction: call done. id=" + call.getId());
+        }
+
+        if (featureFlags.disconnectSelfManagedStuckStartupCalls()) {
+            // set to dialing so the CallAnomalyWatchdog gives the VoIP calls 1
+            // minute to timeout rather than 5 seconds.
+            callsManager.markCallAsDialing(call);
+        }
+
+        return CompletableFuture.completedFuture(
+                new CallTransactionResult(
+                        CallTransactionResult.RESULT_SUCCEED,
+                        call, null, true));
     }
 }
diff --git a/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransactionSequencing.java b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransactionSequencing.java
new file mode 100644
index 000000000..af6af343f
--- /dev/null
+++ b/src/com/android/server/telecom/callsequencing/voip/OutgoingCallTransactionSequencing.java
@@ -0,0 +1,72 @@
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
+package com.android.server.telecom.callsequencing.voip;
+
+import static android.telecom.CallException.CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME;
+
+import android.util.Log;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.LoggedHandlerExecutor;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.flags.FeatureFlags;
+
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.CompletionStage;
+
+public class OutgoingCallTransactionSequencing extends CallTransaction {
+
+    private static final String TAG = OutgoingCallTransactionSequencing.class.getSimpleName();
+    private final CompletableFuture<Call> mCallFuture;
+    private final CallsManager mCallsManager;
+    private final boolean mCallNotPermitted;
+    private FeatureFlags mFeatureFlags;
+
+    public OutgoingCallTransactionSequencing(CallsManager callsManager,
+            CompletableFuture<Call> callFuture, boolean callNotPermitted,
+            FeatureFlags featureFlags) {
+        super(callsManager.getLock());
+        mCallsManager = callsManager;
+        mCallFuture = callFuture;
+        mCallNotPermitted = callNotPermitted;
+        mFeatureFlags = featureFlags;
+    }
+
+    @Override
+    public CompletionStage<CallTransactionResult> processTransaction(Void v) {
+        Log.d(TAG, "processTransaction");
+        if (mCallNotPermitted) {
+            return CompletableFuture.completedFuture(
+                    new CallTransactionResult(
+                            CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
+                            "outgoing call not permitted at the current time"));
+        }
+
+        return mCallFuture.thenComposeAsync(
+                (call) -> OutgoingCallTransaction.processOutgoingCallTransactionHelper(call, TAG,
+                        mCallsManager, mFeatureFlags)
+                , new LoggedHandlerExecutor(mHandler, "OCT.pT", null));
+    }
+
+    @VisibleForTesting
+    public boolean getCallNotPermitted() {
+        return mCallNotPermitted;
+    }
+}
diff --git a/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
index 1d1a1a6df..8c74510db 100644
--- a/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
+++ b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitor.java
@@ -30,10 +30,8 @@ import android.content.ComponentName;
 import android.content.Context;
 import android.content.ServiceConnection;
 import android.os.Handler;
-import android.os.HandlerThread;
 import android.os.IBinder;
 import android.os.RemoteException;
-import android.os.UserHandle;
 import android.service.notification.NotificationListenerService;
 import android.service.notification.StatusBarNotification;
 import android.telecom.Log;
@@ -42,319 +40,371 @@ import android.telecom.PhoneAccountHandle;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.LocalServices;
 import com.android.server.telecom.Call;
-
 import com.android.server.telecom.CallsManagerListenerBase;
 import com.android.server.telecom.LogUtils;
-import com.android.server.telecom.LoggedHandlerExecutor;
 import com.android.server.telecom.TelecomSystem;
 
 import java.util.ArrayList;
-import java.util.HashMap;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.Set;
-import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ConcurrentHashMap;
+import java.util.concurrent.ConcurrentLinkedQueue;
 
 public class VoipCallMonitor extends CallsManagerListenerBase {
-
-    private final List<Call> mNotificationPendingCalls;
-    // Same notification may be passed as different object in onNotificationPosted and
-    // onNotificationRemoved. Use its string as key to cache ongoing notifications.
-    private final Map<NotificationInfo, Call> mNotificationInfoToCallMap;
-    private final Map<PhoneAccountHandle, Set<Call>> mAccountHandleToCallMap;
+    public static final long NOTIFICATION_NOT_POSTED_IN_TIME_TIMEOUT = 5000L;
+    public static final long NOTIFICATION_REMOVED_BUT_CALL_IS_STILL_ONGOING_TIMEOUT = 5000L;
+    private static final String TAG = VoipCallMonitor.class.getSimpleName();
+    private static final String DElIMITER = "#";
+    // This list caches calls that are added to the VoipCallMonitor and need an accompanying
+    // Call-Style Notification!
+    private final ConcurrentLinkedQueue<Call> mNewCallsMissingCallStyleNotification;
+    private final ConcurrentHashMap<String, Call> mNotificationIdToCall;
+    private final ConcurrentHashMap<PhoneAccountHandle, Set<Call>> mAccountHandleToCallMap;
+    private final ConcurrentHashMap<PhoneAccountHandle, ServiceConnection> mServices;
     private ActivityManagerInternal mActivityManagerInternal;
-    private final Map<PhoneAccountHandle, ServiceConnection> mServices;
-    private NotificationListenerService mNotificationListener;
-    private final Object mLock = new Object();
-    private final HandlerThread mHandlerThread;
-    private final Handler mHandler;
+    private final NotificationListenerService mNotificationListener;
+    private final Handler mHandlerForClass;
     private final Context mContext;
-    private List<NotificationInfo> mCachedNotifications;
-    private TelecomSystem.SyncRoot mSyncRoot;
+    private final TelecomSystem.SyncRoot mSyncRoot;
 
-    public VoipCallMonitor(Context context, TelecomSystem.SyncRoot lock) {
+    public VoipCallMonitor(Context context, Handler handler, TelecomSystem.SyncRoot lock) {
         mSyncRoot = lock;
         mContext = context;
-        mHandlerThread = new HandlerThread(this.getClass().getSimpleName());
-        mHandlerThread.start();
-        mHandler = new Handler(mHandlerThread.getLooper());
-        mNotificationPendingCalls = new ArrayList<>();
-        mCachedNotifications = new ArrayList<>();
-        mNotificationInfoToCallMap = new HashMap<>();
-        mServices = new HashMap<>();
-        mAccountHandleToCallMap = new HashMap<>();
+        mHandlerForClass = handler;
+        mNewCallsMissingCallStyleNotification = new ConcurrentLinkedQueue<>();
+        mNotificationIdToCall = new ConcurrentHashMap<>();
+        mServices = new ConcurrentHashMap<>();
+        mAccountHandleToCallMap = new ConcurrentHashMap<>();
         mActivityManagerInternal = LocalServices.getService(ActivityManagerInternal.class);
-
         mNotificationListener = new NotificationListenerService() {
             @Override
             public void onNotificationPosted(StatusBarNotification sbn) {
-                synchronized (mLock) {
-                    if (sbn.getNotification().isStyle(Notification.CallStyle.class)) {
-                        NotificationInfo info = new NotificationInfo(sbn.getPackageName(),
-                                sbn.getUser());
-                        boolean sbnMatched = false;
-                        for (Call call : mNotificationPendingCalls) {
-                            if (info.matchesCall(call)) {
-                                Log.i(this, "onNotificationPosted: found a pending "
-                                                + "callId=[%s] for the call notification w/ "
-                                                + "id=[%s]",
-                                        call.getId(), sbn.getId());
-                                mNotificationPendingCalls.remove(call);
-                                mNotificationInfoToCallMap.put(info, call);
-                                sbnMatched = true;
-                                break;
-                            }
-                        }
-                        if (!sbnMatched &&
-                                !mCachedNotifications.contains(info) /* don't re-add if update */) {
-                            Log.i(this, "onNotificationPosted: could not find a"
-                                            + "call for the call notification w/ id=[%s]",
-                                    sbn.getId());
-                            // notification may post before we started to monitor the call, cache
-                            // this notification and try to match it later with new added call.
-                            mCachedNotifications.add(info);
+                if (isCallStyleNotification(sbn)) {
+                    Log.i(TAG, "onNotificationPosted: sbn=[%s]", sbn);
+                    // Case 1: Call added to this class (via onCallAdded) BEFORE Call-Style
+                    //         Notification is posted by the app (only supported scenario)
+                    Call newCallNoLongerAwaitingNotification = null;
+                    for (Call call : mNewCallsMissingCallStyleNotification) {
+                        if (isNotificationForCall(sbn, call)) {
+                            Log.i(TAG, "onNotificationPosted: found a pending "
+                                    + "call=[%s] for sbn.id=[%s]", call, sbn.getId());
+                            mNotificationIdToCall.put(
+                                    getNotificationIdToCallKey(sbn),
+                                    call);
+                            newCallNoLongerAwaitingNotification = call;
+                            break;
                         }
                     }
+                    // Case 2: Call-Style Notification was posted BEFORE the Call was added
+                    // --> Currently do not support this
+                    // Case 3: Call-Style Notification was updated (ex. incoming -> ongoing)
+                    // --> do nothing
+                    if (newCallNoLongerAwaitingNotification == null) {
+                        Log.i(TAG, "onNotificationPosted: could not find a call for the"
+                                + " sbn.id=[%s]. This could mean the notification posted"
+                                + " BEFORE the call is added (error) or it's an update from"
+                                + " incoming to ongoing (ok).", sbn.getId());
+                    } else {
+                        // --> remove the newly added call from
+                        // mNewCallsMissingCallStyleNotification so FGS is not revoked when the
+                        // timeout is hit in VoipCallMonitor#startMonitoringNotification(...). The
+                        // timeout ensures the voip app posts a call-style notification within
+                        // 5 seconds!
+                        mNewCallsMissingCallStyleNotification
+                                .remove(newCallNoLongerAwaitingNotification);
+                    }
                 }
             }
 
             @Override
             public void onNotificationRemoved(StatusBarNotification sbn) {
-                synchronized (mLock) {
-                    NotificationInfo info = new NotificationInfo(sbn.getPackageName(),
-                            sbn.getUser());
-                    mCachedNotifications.remove(info);
-                    if (mNotificationInfoToCallMap.isEmpty()) {
-                        return;
+                if (!isCallStyleNotification(sbn)) {
+                    return;
+                }
+                Log.i(TAG, "onNotificationRemoved: Call-Style notification=[%s] removed", sbn);
+                Call call = getCallFromStatusBarNotificationId(sbn);
+                if (call != null) {
+                    if (!isCallDisconnected(call)) {
+                        mHandlerForClass.postDelayed(() -> {
+                            if (isCallStillBeingTracked(call)) {
+                                Log.w(TAG,
+                                        "onNotificationRemoved: notification has been removed for"
+                                                + " more than 5 seconds but call still ongoing "
+                                                + "c=[%s]", call);
+                                // TODO:: stopFGSDelegation(call, handle) when b/383403913 is fixed
+                            }
+                        }, NOTIFICATION_REMOVED_BUT_CALL_IS_STILL_ONGOING_TIMEOUT);
                     }
-                    Call call = mNotificationInfoToCallMap.getOrDefault(info, null);
-                    if (call != null) {
-                        // TODO: fix potential bug for multiple calls of same voip app.
-                        mNotificationInfoToCallMap.remove(info, call);
-                        stopFGSDelegation(call);
+                    mNotificationIdToCall.remove(getNotificationIdToCallKey(sbn));
+                }
+            }
+
+            // TODO:: b/383403913 fix gap in matching notifications
+            private boolean isNotificationForCall(StatusBarNotification sbn, Call call) {
+                PhoneAccountHandle callHandle = getTargetPhoneAccount(call);
+                if (callHandle == null) {
+                    return false;
+                }
+                String callPackageName = VoipCallMonitor.this.getPackageName(call);
+                return Objects.equals(sbn.getUser(), callHandle.getUserHandle()) &&
+                        Objects.equals(sbn.getPackageName(), callPackageName);
+            }
+
+            private Call getCallFromStatusBarNotificationId(StatusBarNotification sbn) {
+                if (mNotificationIdToCall.size() == 0) {
+                    return null;
+                }
+                String targetKey = getNotificationIdToCallKey(sbn);
+                for (Map.Entry<String, Call> entry : mNotificationIdToCall.entrySet()) {
+                    if (targetKey.equals(entry.getKey())) {
+                        return entry.getValue();
                     }
                 }
+                return null;
+            }
+
+            private String getNotificationIdToCallKey(StatusBarNotification sbn) {
+                return sbn.getPackageName() + DElIMITER + sbn.getId();
+            }
+
+            private boolean isCallStyleNotification(StatusBarNotification sbn) {
+                return sbn.getNotification().isStyle(Notification.CallStyle.class);
+            }
+
+            private boolean isCallStillBeingTracked(Call call) {
+                PhoneAccountHandle handle = getTargetPhoneAccount(call);
+                if (call == null || handle == null) {
+                    return false;
+                }
+                return mAccountHandleToCallMap
+                        .computeIfAbsent(handle, k -> new HashSet<>())
+                        .contains(call);
             }
         };
 
     }
 
-    public void startMonitor() {
+    public void registerNotificationListener() {
         try {
             mNotificationListener.registerAsSystemService(mContext,
                     new ComponentName(this.getClass().getPackageName(),
                             this.getClass().getCanonicalName()), ActivityManager.getCurrentUser());
         } catch (RemoteException e) {
-            Log.e(this, e, "Cannot register notification listener");
+            Log.e(TAG, e, "Cannot register notification listener");
         }
     }
 
-    public void stopMonitor() {
+    public void unregisterNotificationListener() {
         try {
             mNotificationListener.unregisterAsSystemService();
         } catch (RemoteException e) {
-            Log.e(this, e, "Cannot unregister notification listener");
+            Log.e(TAG, e, "Cannot unregister notification listener");
         }
     }
 
     @Override
     public void onCallAdded(Call call) {
-        if (!call.isTransactionalCall()) {
+        PhoneAccountHandle handle = getTargetPhoneAccount(call);
+        if (!isTransactional(call) || handle == null) {
             return;
         }
-
-        synchronized (mLock) {
-            PhoneAccountHandle phoneAccountHandle = call.getTargetPhoneAccount();
-            Set<Call> callList = mAccountHandleToCallMap.computeIfAbsent(phoneAccountHandle,
-                    k -> new HashSet<>());
-            callList.add(call);
-            CompletableFuture.completedFuture(null).thenComposeAsync(
-                    (x) -> {
-                        startFGSDelegation(call.getCallingPackageIdentity().mCallingPackagePid,
-                                call.getCallingPackageIdentity().mCallingPackageUid, call);
-                        return null;
-                    }, new LoggedHandlerExecutor(mHandler, "VCM.oCA", mSyncRoot));
-        }
+        int callingPid = getCallingPackagePid(call);
+        int callingUid = getCallingPackageUid(call);
+        mAccountHandleToCallMap
+                .computeIfAbsent(handle, k -> new HashSet<>())
+                .add(call);
+        maybeStartFGSDelegation(callingPid, callingUid, handle, call);
     }
 
     @Override
     public void onCallRemoved(Call call) {
-        if (!call.isTransactionalCall()) {
+        PhoneAccountHandle handle = getTargetPhoneAccount(call);
+        if (!isTransactional(call) || handle == null) {
             return;
         }
-
-        synchronized (mLock) {
-            stopMonitorWorks(call);
-            PhoneAccountHandle phoneAccountHandle = call.getTargetPhoneAccount();
-            Set<Call> callList = mAccountHandleToCallMap.computeIfAbsent(phoneAccountHandle,
-                    k -> new HashSet<>());
-            callList.remove(call);
-
-            if (callList.isEmpty()) {
-                stopFGSDelegation(call);
-            }
+        Set<Call> ongoingCalls = mAccountHandleToCallMap
+                .computeIfAbsent(handle, k -> new HashSet<>());
+        ongoingCalls.remove(call);
+        Log.d(TAG, "onCallRemoved: callList.size=[%d]", ongoingCalls.size());
+        if (ongoingCalls.isEmpty()) {
+            stopFGSDelegation(call, handle);
+        } else {
+            Log.addEvent(call, LogUtils.Events.MAINTAINING_FGS_DELEGATION);
         }
     }
 
-    private void startFGSDelegation(int pid, int uid, Call call) {
-        Log.i(this, "startFGSDelegation for call %s", call.getId());
+    private void maybeStartFGSDelegation(int pid, int uid, PhoneAccountHandle handle, Call call) {
+        Log.i(TAG, "maybeStartFGSDelegation for call=[%s]", call);
         if (mActivityManagerInternal != null) {
-            PhoneAccountHandle handle = call.getTargetPhoneAccount();
+            if (mServices.containsKey(handle)) {
+                Log.addEvent(call, LogUtils.Events.ALREADY_HAS_FGS_DELEGATION);
+                startMonitoringNotification(call, handle);
+                return;
+            }
             ForegroundServiceDelegationOptions options = new ForegroundServiceDelegationOptions(pid,
                     uid, handle.getComponentName().getPackageName(), null /* clientAppThread */,
                     false /* isSticky */, String.valueOf(handle.hashCode()),
                     FOREGROUND_SERVICE_TYPE_PHONE_CALL |
-                    FOREGROUND_SERVICE_TYPE_MICROPHONE |
-                    FOREGROUND_SERVICE_TYPE_CAMERA |
-                    FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE /* foregroundServiceTypes */,
+                            FOREGROUND_SERVICE_TYPE_MICROPHONE |
+                            FOREGROUND_SERVICE_TYPE_CAMERA |
+                            FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE /* foregroundServiceTypes */,
                     DELEGATION_SERVICE_PHONE_CALL /* delegationService */);
             ServiceConnection fgsConnection = new ServiceConnection() {
                 @Override
                 public void onServiceConnected(ComponentName name, IBinder service) {
+                    Log.addEvent(call, LogUtils.Events.GAINED_FGS_DELEGATION);
                     mServices.put(handle, this);
-                    startMonitorWorks(call);
+                    startMonitoringNotification(call, handle);
                 }
 
                 @Override
                 public void onServiceDisconnected(ComponentName name) {
+                    Log.addEvent(call, LogUtils.Events.LOST_FGS_DELEGATION);
                     mServices.remove(handle);
                 }
             };
             try {
                 if (mActivityManagerInternal
                         .startForegroundServiceDelegate(options, fgsConnection)) {
-                    Log.addEvent(call, LogUtils.Events.GAINED_FGS_DELEGATION);
+                    Log.i(TAG, "maybeStartFGSDelegation: startForegroundServiceDelegate success");
                 } else {
                     Log.addEvent(call, LogUtils.Events.GAIN_FGS_DELEGATION_FAILED);
                 }
             } catch (Exception e) {
-                Log.i(this, "startForegroundServiceDelegate failed due to: " + e);
+                Log.i(TAG, "startForegroundServiceDelegate failed due to: " + e);
             }
         }
     }
 
     @VisibleForTesting
-    public void stopFGSDelegation(Call call) {
-        synchronized (mLock) {
-            Log.i(this, "stopFGSDelegation of call %s", call);
-            PhoneAccountHandle handle = call.getTargetPhoneAccount();
-            Set<Call> calls = mAccountHandleToCallMap.get(handle);
-
-            // Every call for the package that is losing foreground service delegation should be
-            // removed from tracking maps/contains in this class
-            if (calls != null) {
-                for (Call c : calls) {
-                    stopMonitorWorks(c); // remove the call from tacking in this class
-                }
-            }
+    public void stopFGSDelegation(Call call, PhoneAccountHandle handle) {
+        Log.i(TAG, "stopFGSDelegation of call=[%s]", call);
+        if (handle == null) {
+            return;
+        }
 
-            mAccountHandleToCallMap.remove(handle);
+        // In the event this class is waiting for any new calls to post a notification, cleanup
+        List<Call> toRemove = new ArrayList<>();
+        for (Call callAwaitingNotification : mNewCallsMissingCallStyleNotification) {
+            if (handle.equals(callAwaitingNotification.getTargetPhoneAccount())) {
+                Log.d(TAG, "stopFGSDelegation: removing call from notification tracking c=[%s]",
+                        callAwaitingNotification);
+                toRemove.add(callAwaitingNotification);
+            }
+        }
+        mNewCallsMissingCallStyleNotification.removeAll(toRemove);
 
-            if (mActivityManagerInternal != null) {
-                ServiceConnection fgsConnection = mServices.get(handle);
-                if (fgsConnection != null) {
-                    mActivityManagerInternal.stopForegroundServiceDelegate(fgsConnection);
-                    Log.addEvent(call, LogUtils.Events.LOST_FGS_DELEGATION);
-                }
+        if (mActivityManagerInternal != null) {
+            ServiceConnection fgsConnection = mServices.get(handle);
+            if (fgsConnection != null) {
+                Log.i(TAG, "stopFGSDelegation: requesting stopForegroundServiceDelegate");
+                mActivityManagerInternal.stopForegroundServiceDelegate(fgsConnection);
             }
         }
+        mAccountHandleToCallMap.remove(handle);
     }
 
-    private void startMonitorWorks(Call call) {
-        startMonitorNotification(call);
+    private void startMonitoringNotification(Call call, PhoneAccountHandle handle) {
+        String packageName = getPackageName(call);
+        String callId = getCallId(call);
+        // Wait 5 seconds for a CallStyle notification to be posted for the call.
+        // If the Call-Style Notification is not posted, FGS delegation needs to be revoked!
+        Log.i(TAG, "startMonitoringNotification: starting timeout for call.id=[%s]", callId);
+        mNewCallsMissingCallStyleNotification.add(call);
+        // If no notification is posted, stop foreground service delegation!
+        mHandlerForClass.postDelayed(() -> {
+            if (mNewCallsMissingCallStyleNotification.contains(call)) {
+                Log.i(TAG, "startMonitoringNotification: A Call-Style-Notification"
+                        + " for voip-call=[%s] hasn't posted in time,"
+                        + " stopping delegation for app=[%s].", call, packageName);
+                stopFGSDelegation(call, handle);
+            } else {
+                Log.i(TAG, "startMonitoringNotification: found a call-style"
+                        + " notification for call.id[%s] at timeout", callId);
+            }
+        }, NOTIFICATION_NOT_POSTED_IN_TIME_TIMEOUT);
     }
 
-    private void stopMonitorWorks(Call call) {
-        stopMonitorNotification(call);
-    }
+    /**
+     * Helpers
+     */
 
-    private void startMonitorNotification(Call call) {
-        synchronized (mLock) {
-            boolean sbnMatched = false;
-            for (NotificationInfo info : mCachedNotifications) {
-                if (info.matchesCall(call)) {
-                    Log.i(this, "startMonitorNotification: found a cached call "
-                            + "notification for call=[%s]", call);
-                    mCachedNotifications.remove(info);
-                    mNotificationInfoToCallMap.put(info, call);
-                    sbnMatched = true;
-                    break;
-                }
-            }
-            if (!sbnMatched) {
-                // Only continue to
-                Log.i(this, "startMonitorNotification: could not find a call"
-                        + " notification for the call=[%s];", call);
-                mNotificationPendingCalls.add(call);
-                CompletableFuture<Void> future = new CompletableFuture<>();
-                mHandler.postDelayed(() -> future.complete(null), 5000L);
-                future.thenComposeAsync(
-                        (x) -> {
-                            if (mNotificationPendingCalls.contains(call)) {
-                                Log.i(this, "Notification for voip-call %s haven't "
-                                        + "posted in time, stop delegation.", call.getId());
-                                stopFGSDelegation(call);
-                                mNotificationPendingCalls.remove(call);
-                                return null;
-                            }
-                            return null;
-                        }, new LoggedHandlerExecutor(mHandler, "VCM.sMN", mSyncRoot));
+    private PhoneAccountHandle getTargetPhoneAccount(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
+                return null;
+            } else {
+                return call.getTargetPhoneAccount();
             }
         }
     }
 
-    private void stopMonitorNotification(Call call) {
-        mNotificationPendingCalls.remove(call);
+    private int getCallingPackageUid(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
+                return -1;
+            } else {
+                return call.getCallingPackageIdentity().mCallingPackageUid;
+            }
+        }
     }
 
-    @VisibleForTesting
-    public void setActivityManagerInternal(ActivityManagerInternal ami) {
-        mActivityManagerInternal = ami;
+    private int getCallingPackagePid(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
+                return -1;
+            } else {
+                return call.getCallingPackageIdentity().mCallingPackagePid;
+            }
+        }
     }
 
-    private static class NotificationInfo extends Object {
-        private String mPackageName;
-        private UserHandle mUserHandle;
-
-        NotificationInfo(String packageName, UserHandle userHandle) {
-            mPackageName = packageName;
-            mUserHandle = userHandle;
+    private String getCallId(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
+                return "";
+            } else {
+                return call.getId();
+            }
         }
+    }
 
-        boolean matchesCall(Call call) {
-            PhoneAccountHandle accountHandle = call.getTargetPhoneAccount();
-            return mPackageName != null && mPackageName.equals(
-                    accountHandle.getComponentName().getPackageName())
-                    && mUserHandle != null && mUserHandle.equals(accountHandle.getUserHandle());
+    private boolean isCallDisconnected(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
+                return true;
+            } else {
+                return call.isDisconnected();
+            }
         }
+    }
 
-        @Override
-        public boolean equals(Object obj) {
-            if (!(obj instanceof NotificationInfo)) {
+    private boolean isTransactional(Call call) {
+        synchronized (mSyncRoot) {
+            if (call == null) {
                 return false;
+            } else {
+                return call.isTransactionalCall();
             }
-            NotificationInfo that = (NotificationInfo) obj;
-            return Objects.equals(this.mPackageName, that.mPackageName)
-                    && Objects.equals(this.mUserHandle, that.mUserHandle);
         }
+    }
 
-        @Override
-        public int hashCode() {
-            return Objects.hash(mPackageName, mUserHandle);
+    private String getPackageName(Call call) {
+        String pn = "";
+        try {
+            pn = getTargetPhoneAccount(call).getComponentName().getPackageName();
+        } catch (Exception e) {
+            // fall through
         }
+        return pn;
+    }
 
-        @Override
-        public String toString() {
-            StringBuilder sb = new StringBuilder();
-            sb.append("{ NotificationInfo: [mPackageName: ")
-                    .append(mPackageName)
-                    .append("], [mUserHandle=")
-                    .append(mUserHandle)
-                    .append("]  }");
-            return sb.toString();
-        }
+    @VisibleForTesting
+    public void setActivityManagerInternal(ActivityManagerInternal ami) {
+        mActivityManagerInternal = ami;
     }
 
     @VisibleForTesting
@@ -367,8 +417,19 @@ public class VoipCallMonitor extends CallsManagerListenerBase {
         mNotificationListener.onNotificationRemoved(statusBarNotification);
     }
 
+    public boolean hasForegroundServiceDelegation(PhoneAccountHandle handle) {
+        boolean hasFgs = mServices.containsKey(handle);
+        Log.i(TAG, "hasForegroundServiceDelegation: handle=[%s], hasFgs=[%b]", handle, hasFgs);
+        return hasFgs;
+    }
+
+    @VisibleForTesting
+    public ConcurrentHashMap<PhoneAccountHandle, Set<Call>> getAccountToCallsMapping() {
+        return mAccountHandleToCallMap;
+    }
+
     @VisibleForTesting
-    public Set<Call> getCallsForHandle(PhoneAccountHandle handle){
-        return mAccountHandleToCallMap.get(handle);
+    public  ConcurrentLinkedQueue<Call> getNewCallsMissingCallStyleNotificationQueue(){
+        return mNewCallsMissingCallStyleNotification;
     }
 }
diff --git a/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitorLegacy.java b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitorLegacy.java
new file mode 100644
index 000000000..78f5d525f
--- /dev/null
+++ b/src/com/android/server/telecom/callsequencing/voip/VoipCallMonitorLegacy.java
@@ -0,0 +1,373 @@
+/*
+ * Copyright (C) 2022 The Android Open Source Project
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
+package com.android.server.telecom.callsequencing.voip;
+
+import static android.app.ForegroundServiceDelegationOptions.DELEGATION_SERVICE_PHONE_CALL;
+import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CAMERA;
+import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE;
+import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL;
+
+import android.app.ActivityManager;
+import android.app.ActivityManagerInternal;
+import android.app.ForegroundServiceDelegationOptions;
+import android.app.Notification;
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.ServiceConnection;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.IBinder;
+import android.os.RemoteException;
+import android.os.UserHandle;
+import android.service.notification.NotificationListenerService;
+import android.service.notification.StatusBarNotification;
+import android.telecom.Log;
+import android.telecom.PhoneAccountHandle;
+
+import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.LocalServices;
+import com.android.server.telecom.Call;
+
+import com.android.server.telecom.CallsManagerListenerBase;
+import com.android.server.telecom.LogUtils;
+import com.android.server.telecom.LoggedHandlerExecutor;
+import com.android.server.telecom.TelecomSystem;
+
+import java.util.ArrayList;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+import java.util.Set;
+import java.util.concurrent.CompletableFuture;
+
+public class VoipCallMonitorLegacy extends CallsManagerListenerBase {
+
+    private final List<Call> mNotificationPendingCalls;
+    // Same notification may be passed as different object in onNotificationPosted and
+    // onNotificationRemoved. Use its string as key to cache ongoing notifications.
+    private final Map<NotificationInfo, Call> mNotificationInfoToCallMap;
+    private final Map<PhoneAccountHandle, Set<Call>> mAccountHandleToCallMap;
+    private ActivityManagerInternal mActivityManagerInternal;
+    private final Map<PhoneAccountHandle, ServiceConnection> mServices;
+    private NotificationListenerService mNotificationListener;
+    private final Object mLock = new Object();
+    private final HandlerThread mHandlerThread;
+    private final Handler mHandler;
+    private final Context mContext;
+    private List<NotificationInfo> mCachedNotifications;
+    private TelecomSystem.SyncRoot mSyncRoot;
+
+    public VoipCallMonitorLegacy(Context context, TelecomSystem.SyncRoot lock) {
+        mSyncRoot = lock;
+        mContext = context;
+        mHandlerThread = new HandlerThread(this.getClass().getSimpleName());
+        mHandlerThread.start();
+        mHandler = new Handler(mHandlerThread.getLooper());
+        mNotificationPendingCalls = new ArrayList<>();
+        mCachedNotifications = new ArrayList<>();
+        mNotificationInfoToCallMap = new HashMap<>();
+        mServices = new HashMap<>();
+        mAccountHandleToCallMap = new HashMap<>();
+        mActivityManagerInternal = LocalServices.getService(ActivityManagerInternal.class);
+
+        mNotificationListener = new NotificationListenerService() {
+            @Override
+            public void onNotificationPosted(StatusBarNotification sbn) {
+                synchronized (mLock) {
+                    if (sbn.getNotification().isStyle(Notification.CallStyle.class)) {
+                        NotificationInfo info = new NotificationInfo(sbn.getPackageName(),
+                                sbn.getUser());
+                        boolean sbnMatched = false;
+                        for (Call call : mNotificationPendingCalls) {
+                            if (info.matchesCall(call)) {
+                                Log.i(this, "onNotificationPosted: found a pending "
+                                                + "callId=[%s] for the call notification w/ "
+                                                + "id=[%s]",
+                                        call.getId(), sbn.getId());
+                                mNotificationPendingCalls.remove(call);
+                                mNotificationInfoToCallMap.put(info, call);
+                                sbnMatched = true;
+                                break;
+                            }
+                        }
+                        if (!sbnMatched &&
+                                !mCachedNotifications.contains(info) /* don't re-add if update */) {
+                            Log.i(this, "onNotificationPosted: could not find a"
+                                            + "call for the call notification w/ id=[%s]",
+                                    sbn.getId());
+                            // notification may post before we started to monitor the call, cache
+                            // this notification and try to match it later with new added call.
+                            mCachedNotifications.add(info);
+                        }
+                    }
+                }
+            }
+
+            @Override
+            public void onNotificationRemoved(StatusBarNotification sbn) {
+                synchronized (mLock) {
+                    NotificationInfo info = new NotificationInfo(sbn.getPackageName(),
+                            sbn.getUser());
+                    mCachedNotifications.remove(info);
+                    if (mNotificationInfoToCallMap.isEmpty()) {
+                        return;
+                    }
+                    Call call = mNotificationInfoToCallMap.getOrDefault(info, null);
+                    if (call != null) {
+                        mNotificationInfoToCallMap.remove(info, call);
+                        CompletableFuture<Void> future = new CompletableFuture<>();
+                        mHandler.postDelayed(() -> future.complete(null), 5000L);
+                        stopFGSDelegation(call);
+                    }
+                }
+            }
+        };
+
+    }
+
+    public void startMonitor() {
+        try {
+            mNotificationListener.registerAsSystemService(mContext,
+                    new ComponentName(this.getClass().getPackageName(),
+                            this.getClass().getCanonicalName()), ActivityManager.getCurrentUser());
+        } catch (RemoteException e) {
+            Log.e(this, e, "Cannot register notification listener");
+        }
+    }
+
+    public void stopMonitor() {
+        try {
+            mNotificationListener.unregisterAsSystemService();
+        } catch (RemoteException e) {
+            Log.e(this, e, "Cannot unregister notification listener");
+        }
+    }
+
+    @Override
+    public void onCallAdded(Call call) {
+        if (!call.isTransactionalCall()) {
+            return;
+        }
+
+        synchronized (mLock) {
+            PhoneAccountHandle phoneAccountHandle = call.getTargetPhoneAccount();
+            Set<Call> callList = mAccountHandleToCallMap.computeIfAbsent(phoneAccountHandle,
+                    k -> new HashSet<>());
+            callList.add(call);
+            CompletableFuture.completedFuture(null).thenComposeAsync(
+                    (x) -> {
+                        startFGSDelegation(call.getCallingPackageIdentity().mCallingPackagePid,
+                                call.getCallingPackageIdentity().mCallingPackageUid, call);
+                        return null;
+                    }, new LoggedHandlerExecutor(mHandler, "VCM.oCA", mSyncRoot));
+        }
+    }
+
+    @Override
+    public void onCallRemoved(Call call) {
+        if (!call.isTransactionalCall()) {
+            return;
+        }
+        synchronized (mLock) {
+            stopMonitorWorks(call);
+            PhoneAccountHandle phoneAccountHandle = call.getTargetPhoneAccount();
+            Set<Call> callList = mAccountHandleToCallMap.computeIfAbsent(phoneAccountHandle,
+                    k -> new HashSet<>());
+            callList.remove(call);
+            if (callList.isEmpty()) {
+                stopFGSDelegation(call);
+            }
+        }
+    }
+
+    private void startFGSDelegation(int pid, int uid, Call call) {
+        Log.i(this, "startFGSDelegation for call %s", call.getId());
+        if (mActivityManagerInternal != null) {
+            PhoneAccountHandle handle = call.getTargetPhoneAccount();
+            ForegroundServiceDelegationOptions options = new ForegroundServiceDelegationOptions(pid,
+                    uid, handle.getComponentName().getPackageName(), null /* clientAppThread */,
+                    false /* isSticky */, String.valueOf(handle.hashCode()),
+                    FOREGROUND_SERVICE_TYPE_PHONE_CALL |
+                    FOREGROUND_SERVICE_TYPE_MICROPHONE |
+                    FOREGROUND_SERVICE_TYPE_CAMERA |
+                    FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE /* foregroundServiceTypes */,
+                    DELEGATION_SERVICE_PHONE_CALL /* delegationService */);
+            ServiceConnection fgsConnection = new ServiceConnection() {
+                @Override
+                public void onServiceConnected(ComponentName name, IBinder service) {
+                    mServices.put(handle, this);
+                    startMonitorWorks(call);
+                }
+
+                @Override
+                public void onServiceDisconnected(ComponentName name) {
+                    mServices.remove(handle);
+                }
+            };
+            try {
+                if (mActivityManagerInternal
+                        .startForegroundServiceDelegate(options, fgsConnection)) {
+                    Log.addEvent(call, LogUtils.Events.GAINED_FGS_DELEGATION);
+                } else {
+                    Log.addEvent(call, LogUtils.Events.GAIN_FGS_DELEGATION_FAILED);
+                }
+            } catch (Exception e) {
+                Log.i(this, "startForegroundServiceDelegate failed due to: " + e);
+            }
+        }
+    }
+
+    @VisibleForTesting
+    public void stopFGSDelegation(Call call) {
+        synchronized (mLock) {
+            Log.i(this, "stopFGSDelegation of call %s", call);
+            PhoneAccountHandle handle = call.getTargetPhoneAccount();
+            Set<Call> calls = mAccountHandleToCallMap.get(handle);
+
+            // Every call for the package that is losing foreground service delegation should be
+            // removed from tracking maps/contains in this class
+            if (calls != null) {
+                for (Call c : calls) {
+                    stopMonitorWorks(c); // remove the call from tacking in this class
+                }
+            }
+
+            mAccountHandleToCallMap.remove(handle);
+
+            if (mActivityManagerInternal != null) {
+                ServiceConnection fgsConnection = mServices.get(handle);
+                if (fgsConnection != null) {
+                    mActivityManagerInternal.stopForegroundServiceDelegate(fgsConnection);
+                    Log.addEvent(call, LogUtils.Events.LOST_FGS_DELEGATION);
+                }
+            }
+        }
+    }
+
+    private void startMonitorWorks(Call call) {
+        startMonitorNotification(call);
+    }
+
+    private void stopMonitorWorks(Call call) {
+        stopMonitorNotification(call);
+    }
+
+    private void startMonitorNotification(Call call) {
+        synchronized (mLock) {
+            boolean sbnMatched = false;
+            for (NotificationInfo info : mCachedNotifications) {
+                if (info.matchesCall(call)) {
+                    Log.i(this, "startMonitorNotification: found a cached call "
+                            + "notification for call=[%s]", call);
+                    mCachedNotifications.remove(info);
+                    mNotificationInfoToCallMap.put(info, call);
+                    sbnMatched = true;
+                    break;
+                }
+            }
+            if (!sbnMatched) {
+                // Only continue to
+                Log.i(this, "startMonitorNotification: could not find a call"
+                        + " notification for the call=[%s];", call);
+                mNotificationPendingCalls.add(call);
+                CompletableFuture<Void> future = new CompletableFuture<>();
+                mHandler.postDelayed(() -> future.complete(null), 5000L);
+                future.thenComposeAsync(
+                        (x) -> {
+                            if (mNotificationPendingCalls.contains(call)) {
+                                Log.i(this, "Notification for voip-call %s haven't "
+                                        + "posted in time, stop delegation.", call.getId());
+                                stopFGSDelegation(call);
+                                mNotificationPendingCalls.remove(call);
+                                return null;
+                            }
+                            return null;
+                        }, new LoggedHandlerExecutor(mHandler, "VCM.sMN", mSyncRoot));
+            }
+        }
+    }
+
+    private void stopMonitorNotification(Call call) {
+        mNotificationPendingCalls.remove(call);
+    }
+
+    @VisibleForTesting
+    public void setActivityManagerInternal(ActivityManagerInternal ami) {
+        mActivityManagerInternal = ami;
+    }
+
+    private static class NotificationInfo extends Object {
+        private String mPackageName;
+        private UserHandle mUserHandle;
+
+        NotificationInfo(String packageName, UserHandle userHandle) {
+            mPackageName = packageName;
+            mUserHandle = userHandle;
+        }
+
+        boolean matchesCall(Call call) {
+            PhoneAccountHandle accountHandle = call.getTargetPhoneAccount();
+            return mPackageName != null && mPackageName.equals(
+                    accountHandle.getComponentName().getPackageName())
+                    && mUserHandle != null && mUserHandle.equals(accountHandle.getUserHandle());
+        }
+
+        @Override
+        public boolean equals(Object obj) {
+            if (!(obj instanceof NotificationInfo)) {
+                return false;
+            }
+            NotificationInfo that = (NotificationInfo) obj;
+            return Objects.equals(this.mPackageName, that.mPackageName)
+                    && Objects.equals(this.mUserHandle, that.mUserHandle);
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mPackageName, mUserHandle);
+        }
+
+        @Override
+        public String toString() {
+            StringBuilder sb = new StringBuilder();
+            sb.append("{ NotificationInfo: [mPackageName: ")
+                    .append(mPackageName)
+                    .append("], [mUserHandle=")
+                    .append(mUserHandle)
+                    .append("]  }");
+            return sb.toString();
+        }
+    }
+
+    @VisibleForTesting
+    public void postNotification(StatusBarNotification statusBarNotification) {
+        mNotificationListener.onNotificationPosted(statusBarNotification);
+    }
+
+    @VisibleForTesting
+    public void removeNotification(StatusBarNotification statusBarNotification) {
+        mNotificationListener.onNotificationRemoved(statusBarNotification);
+    }
+
+    @VisibleForTesting
+    public Set<Call> getCallsForHandle(PhoneAccountHandle handle){
+        return mAccountHandleToCallMap.get(handle);
+    }
+}
diff --git a/src/com/android/server/telecom/components/TelecomService.java b/src/com/android/server/telecom/components/TelecomService.java
index 4db3e1450..2fbdf8b78 100644
--- a/src/com/android/server/telecom/components/TelecomService.java
+++ b/src/com/android/server/telecom/components/TelecomService.java
@@ -22,6 +22,7 @@ import android.content.Context;
 import android.content.Intent;
 import android.media.IAudioService;
 import android.media.ToneGenerator;
+import android.os.HandlerThread;
 import android.os.IBinder;
 import android.os.PowerManager;
 import android.os.ServiceManager;
@@ -111,6 +112,9 @@ public class TelecomService extends Service implements TelecomSystem.Component {
                     new NotificationChannelManager();
             notificationChannelManager.createChannels(context);
 
+            HandlerThread handlerThread = new HandlerThread("TelecomSystem");
+            handlerThread.start();
+
             TelecomSystem.setInstance(
                     new TelecomSystem(
                             context,
@@ -242,7 +246,8 @@ public class TelecomService extends Service implements TelecomSystem.Component {
                                 }
                             },
                             featureFlags,
-                            new com.android.internal.telephony.flags.FeatureFlagsImpl()));
+                            new com.android.internal.telephony.flags.FeatureFlagsImpl(),
+                            handlerThread.getLooper()));
         }
     }
 
diff --git a/src/com/android/server/telecom/metrics/ApiStats.java b/src/com/android/server/telecom/metrics/ApiStats.java
index 4b23e47d9..d962276c0 100644
--- a/src/com/android/server/telecom/metrics/ApiStats.java
+++ b/src/com/android/server/telecom/metrics/ApiStats.java
@@ -169,8 +169,8 @@ public class ApiStats extends TelecomPulledAtom {
     private static final String FILE_NAME = "api_stats";
     private Map<ApiEvent, Integer> mApiStatsMap;
 
-    public ApiStats(@NonNull Context context, @NonNull Looper looper) {
-        super(context, looper);
+    public ApiStats(@NonNull Context context, @NonNull Looper looper, boolean isTestMode) {
+        super(context, looper, isTestMode);
     }
 
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
diff --git a/src/com/android/server/telecom/metrics/AudioRouteStats.java b/src/com/android/server/telecom/metrics/AudioRouteStats.java
index 4611b2220..a79fdeaef 100644
--- a/src/com/android/server/telecom/metrics/AudioRouteStats.java
+++ b/src/com/android/server/telecom/metrics/AudioRouteStats.java
@@ -76,8 +76,8 @@ public class AudioRouteStats extends TelecomPulledAtom {
     private Pair<AudioRouteStatsKey, long[]> mCur;
     private boolean mIsOngoing;
 
-    public AudioRouteStats(@NonNull Context context, @NonNull Looper looper) {
-        super(context, looper);
+    public AudioRouteStats(@NonNull Context context, @NonNull Looper looper, boolean isTestMode) {
+        super(context, looper, isTestMode);
     }
 
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
diff --git a/src/com/android/server/telecom/metrics/CallStats.java b/src/com/android/server/telecom/metrics/CallStats.java
index 8bdeffbca..41de0d1a2 100644
--- a/src/com/android/server/telecom/metrics/CallStats.java
+++ b/src/com/android/server/telecom/metrics/CallStats.java
@@ -22,6 +22,8 @@ import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYP
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_UNKNOWN;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_VOIP_API;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_NON_TELECOM_VOIP;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_NON_TELECOM_VOIP_WITH_TELECOM_SUPPORT;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_INCOMING;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_OUTGOING;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_UNKNOWN;
@@ -40,6 +42,7 @@ import com.android.server.telecom.Call;
 import com.android.server.telecom.TelecomStatsLog;
 import com.android.server.telecom.nano.PulledAtomsClass;
 
+import java.util.ArrayList;
 import java.util.Arrays;
 import java.util.HashMap;
 import java.util.HashSet;
@@ -57,8 +60,8 @@ public class CallStats extends TelecomPulledAtom {
     private Map<CallStatsKey, CallStatsData> mCallStatsMap;
     private boolean mHasMultipleAudioDevices;
 
-    public CallStats(@NonNull Context context, @NonNull Looper looper) {
-        super(context, looper);
+    public CallStats(@NonNull Context context, @NonNull Looper looper, boolean isTestMode) {
+        super(context, looper, isTestMode);
     }
 
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
@@ -80,7 +83,8 @@ public class CallStats extends TelecomPulledAtom {
                     TelecomStatsLog.buildStatsEvent(getTag(),
                             v.getCallDirection(), v.getExternalCall(), v.getEmergencyCall(),
                             v.getMultipleAudioAvailable(), v.getAccountType(), v.getUid(),
-                            v.getCount(), v.getAverageDurationMs())));
+                            v.getCount(), v.getAverageDurationMs(), v.getDisconnectCause(),
+                            v.getSimultaneousType(), v.getVideoCall())));
             mCallStatsMap.clear();
             onAggregate();
             return StatsManager.PULL_SUCCESS;
@@ -95,10 +99,12 @@ public class CallStats extends TelecomPulledAtom {
             mCallStatsMap = new HashMap<>();
             for (PulledAtomsClass.CallStats v : mPulledAtoms.callStats) {
                 mCallStatsMap.put(new CallStatsKey(v.getCallDirection(),
-                                v.getExternalCall(), v.getEmergencyCall(),
-                                v.getMultipleAudioAvailable(),
-                                v.getAccountType(), v.getUid()),
-                        new CallStatsData(v.getCount(), v.getAverageDurationMs()));
+                        v.getExternalCall(), v.getEmergencyCall(),
+                        v.getMultipleAudioAvailable(), v.getAccountType(),
+                        v.getUid(), v.getDisconnectCause(), v.getSimultaneousType(),
+                        v.getVideoCall()),
+                        new CallStatsData(
+                                v.getCount(), v.getAverageDurationMs()));
             }
             mLastPulledTimestamps = mPulledAtoms.getCallStatsPullTimestampMillis();
         }
@@ -123,6 +129,9 @@ public class CallStats extends TelecomPulledAtom {
             mPulledAtoms.callStats[index[0]].setMultipleAudioAvailable(k.mIsMultipleAudioAvailable);
             mPulledAtoms.callStats[index[0]].setAccountType(k.mAccountType);
             mPulledAtoms.callStats[index[0]].setUid(k.mUid);
+            mPulledAtoms.callStats[index[0]].setDisconnectCause(k.mCause);
+            mPulledAtoms.callStats[index[0]].setSimultaneousType(k.mSimultaneousType);
+            mPulledAtoms.callStats[index[0]].setVideoCall(k.mHasVideoCall);
             mPulledAtoms.callStats[index[0]].setCount(v.mCount);
             mPulledAtoms.callStats[index[0]].setAverageDurationMs(v.mAverageDuration);
             index[0]++;
@@ -131,10 +140,18 @@ public class CallStats extends TelecomPulledAtom {
     }
 
     public void log(int direction, boolean isExternal, boolean isEmergency,
-            boolean isMultipleAudioAvailable, int accountType, int uid, int duration) {
+        boolean isMultipleAudioAvailable, int accountType, int uid, int duration) {
+        log(direction, isExternal, isEmergency, isMultipleAudioAvailable, accountType, uid,
+                0, 0, false, duration);
+    }
+
+    public void log(int direction, boolean isExternal, boolean isEmergency,
+            boolean isMultipleAudioAvailable, int accountType, int uid,
+            int disconnectCause, int simultaneousType, boolean hasVideoCall, int duration) {
         post(() -> {
             CallStatsKey key = new CallStatsKey(direction, isExternal, isEmergency,
-                    isMultipleAudioAvailable, accountType, uid);
+                    isMultipleAudioAvailable, accountType, uid, disconnectCause, simultaneousType,
+                    hasVideoCall);
             CallStatsData data = mCallStatsMap.computeIfAbsent(key, k -> new CallStatsData(0, 0));
             data.add(duration);
             onAggregate();
@@ -169,10 +186,33 @@ public class CallStats extends TelecomPulledAtom {
             }
 
             log(direction, call.isExternalCall(), call.isEmergencyCall(), hasMultipleAudioDevices,
-                    accountType, uid, duration);
+                    accountType, uid, call.getDisconnectCause().getCode(),
+                    call.getSimultaneousType(), call.hasVideoCall(), duration);
         });
     }
 
+    /**
+     * Used for logging non-telecom calls that have no associated {@link Call}.  This is inferred
+     * from the {@link com.android.server.telecom.CallAudioWatchdog}.
+     *
+     * @param hasTelecomSupport {@code true} if the app making the non-telecom call has Telecom
+     *                                      support (i.e. has a phone account};
+     *                                      {@code false} otherwise.
+     * @param uid The uid of the app making the call.
+     * @param durationMillis The duration of the call, in millis.
+     */
+    public void onNonTelecomCallEnd(final boolean hasTelecomSupport, final int uid,
+            final long durationMillis) {
+        post(() -> log(CALL_STATS__CALL_DIRECTION__DIR_UNKNOWN,
+                false /* isExternalCall */,
+                false /* isEmergencyCall */,
+                false /* hasMultipleAudioDevices  */,
+                hasTelecomSupport ?
+                        CALL_STATS__ACCOUNT_TYPE__ACCOUNT_NON_TELECOM_VOIP_WITH_TELECOM_SUPPORT :
+                        CALL_STATS__ACCOUNT_TYPE__ACCOUNT_NON_TELECOM_VOIP,
+                uid, (int) durationMillis));
+    }
+
     private int getAccountType(PhoneAccount account) {
         if (account == null) {
             return CALL_STATS__ACCOUNT_TYPE__ACCOUNT_UNKNOWN;
@@ -212,15 +252,28 @@ public class CallStats extends TelecomPulledAtom {
         final boolean mIsMultipleAudioAvailable;
         final int mAccountType;
         final int mUid;
+        final int mCause;
+        final int mSimultaneousType;
+        final boolean mHasVideoCall;
+
+        CallStatsKey(int direction, boolean isExternal, boolean isEmergency,
+            boolean isMultipleAudioAvailable, int accountType, int uid) {
+            this(direction, isExternal, isEmergency, isMultipleAudioAvailable, accountType, uid,
+                    0, 0, false);
+        }
 
         CallStatsKey(int direction, boolean isExternal, boolean isEmergency,
-                boolean isMultipleAudioAvailable, int accountType, int uid) {
+                boolean isMultipleAudioAvailable, int accountType, int uid,
+                int cause, int simultaneousType, boolean hasVideoCall) {
             mDirection = direction;
             mIsExternal = isExternal;
             mIsEmergency = isEmergency;
             mIsMultipleAudioAvailable = isMultipleAudioAvailable;
             mAccountType = accountType;
             mUid = uid;
+            mCause = cause;
+            mSimultaneousType = simultaneousType;
+            mHasVideoCall = hasVideoCall;
         }
 
         @Override
@@ -234,13 +287,15 @@ public class CallStats extends TelecomPulledAtom {
             return this.mDirection == obj.mDirection && this.mIsExternal == obj.mIsExternal
                     && this.mIsEmergency == obj.mIsEmergency
                     && this.mIsMultipleAudioAvailable == obj.mIsMultipleAudioAvailable
-                    && this.mAccountType == obj.mAccountType && this.mUid == obj.mUid;
+                    && this.mAccountType == obj.mAccountType && this.mUid == obj.mUid
+                    && this.mCause == obj.mCause && this.mSimultaneousType == obj.mSimultaneousType
+                    && this.mHasVideoCall == obj.mHasVideoCall;
         }
 
         @Override
         public int hashCode() {
             return Objects.hash(mDirection, mIsExternal, mIsEmergency, mIsMultipleAudioAvailable,
-                    mAccountType, mUid);
+                    mAccountType, mUid, mCause, mSimultaneousType, mHasVideoCall);
         }
 
         @Override
@@ -248,7 +303,8 @@ public class CallStats extends TelecomPulledAtom {
             return "[CallStatsKey: mDirection=" + mDirection + ", mIsExternal=" + mIsExternal
                     + ", mIsEmergency=" + mIsEmergency + ", mIsMultipleAudioAvailable="
                     + mIsMultipleAudioAvailable + ", mAccountType=" + mAccountType + ", mUid="
-                    + mUid + "]";
+                    + mUid + ", mCause=" + mCause + ", mScType=" + mSimultaneousType
+                    + ", mHasVideoCall =" + mHasVideoCall + "]";
         }
     }
 
diff --git a/src/com/android/server/telecom/metrics/ErrorStats.java b/src/com/android/server/telecom/metrics/ErrorStats.java
index f334710f6..7f8ddd751 100644
--- a/src/com/android/server/telecom/metrics/ErrorStats.java
+++ b/src/com/android/server/telecom/metrics/ErrorStats.java
@@ -118,8 +118,8 @@ public class ErrorStats extends TelecomPulledAtom {
     private static final String FILE_NAME = "error_stats";
     private Map<ErrorEvent, Integer> mErrorStatsMap;
 
-    public ErrorStats(@NonNull Context context, @NonNull Looper looper) {
-        super(context, looper);
+    public ErrorStats(@NonNull Context context, @NonNull Looper looper, boolean isTestMode) {
+        super(context, looper, isTestMode);
     }
 
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
diff --git a/src/com/android/server/telecom/metrics/EventStats.java b/src/com/android/server/telecom/metrics/EventStats.java
new file mode 100644
index 000000000..18e68fbec
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/EventStats.java
@@ -0,0 +1,224 @@
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_EVENT_STATS;
+
+import android.annotation.IntDef;
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.telecom.CallException;
+import android.telecom.Log;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.TelecomStatsLog;
+import com.android.server.telecom.metrics.ApiStats.ApiEvent;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import java.lang.annotation.Retention;
+import java.lang.annotation.RetentionPolicy;
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+public class EventStats extends TelecomPulledAtom {
+    public static final int ID_UNKNOWN = TelecomStatsLog.TELECOM_EVENT_STATS__EVENT__EVENT_UNKNOWN;
+    public static final int ID_INIT = TelecomStatsLog.TELECOM_EVENT_STATS__EVENT__EVENT_INIT;
+    public static final int ID_DEFAULT_DIALER_CHANGED = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT__EVENT_DEFAULT_DIALER_CHANGED;
+    public static final int ID_ADD_CALL = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT__EVENT_ADD_CALL;
+
+    public static final int CAUSE_UNKNOWN = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT_CAUSE__CAUSE_UNKNOWN;
+    public static final int CAUSE_GENERIC_SUCCESS = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT_CAUSE__CAUSE_GENERIC_SUCCESS;
+    public static final int CAUSE_GENERIC_FAILURE = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT_CAUSE__CAUSE_GENERIC_FAILURE;
+    public static final int CAUSE_CALL_TRANSACTION_SUCCESS = TelecomStatsLog
+            .TELECOM_EVENT_STATS__EVENT_CAUSE__CALL_TRANSACTION_SUCCESS;
+    public static final int CAUSE_CALL_TRANSACTION_BASE = CAUSE_CALL_TRANSACTION_SUCCESS;
+    public static final int CAUSE_CALL_TRANSACTION_ERROR_UNKNOWN =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_ERROR_UNKNOWN;
+    public static final int CAUSE_CALL_TRANSACTION_CANNOT_HOLD_CURRENT_ACTIVE_CALL =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_CANNOT_HOLD_CURRENT_ACTIVE_CALL;
+    public static final int CAUSE_CALL_TRANSACTION_CALL_IS_NOT_BEING_TRACKED =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_CALL_IS_NOT_BEING_TRACKED;
+    public static final int CAUSE_CALL_TRANSACTION_CALL_CANNOT_BE_SET_TO_ACTIVE =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_CALL_CANNOT_BE_SET_TO_ACTIVE;
+    public static final int CAUSE_CALL_TRANSACTION_CALL_NOT_PERMITTED_AT_PRESENT_TIME =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_CALL_NOT_PERMITTED_AT_PRESENT_TIME;
+    public static final int CAUSE_CALL_TRANSACTION_OPERATION_TIMED_OUT =
+            CAUSE_CALL_TRANSACTION_BASE + CallException.CODE_OPERATION_TIMED_OUT;
+    private static final String TAG = EventStats.class.getSimpleName();
+    private static final String FILE_NAME = "event_stats";
+    private Map<CriticalEvent, Integer> mEventStatsMap;
+
+    public EventStats(@NonNull Context context, @NonNull Looper looper,
+                      boolean isTestMode) {
+        super(context, looper, isTestMode);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public int getTag() {
+        return TELECOM_EVENT_STATS;
+    }
+
+    @Override
+    protected String getFileName() {
+        return FILE_NAME;
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized int onPull(final List<StatsEvent> data) {
+        if (mPulledAtoms.telecomEventStats.length != 0) {
+            Arrays.stream(mPulledAtoms.telecomEventStats).forEach(v -> data.add(
+                    TelecomStatsLog.buildStatsEvent(getTag(),
+                            v.getEvent(), v.getUid(), v.getEventCause(), v.getCount())));
+            mEventStatsMap.clear();
+            onAggregate();
+            return StatsManager.PULL_SUCCESS;
+        } else {
+            return StatsManager.PULL_SKIP;
+        }
+    }
+
+    @Override
+    protected synchronized void onLoad() {
+        if (mPulledAtoms.telecomEventStats != null) {
+            mEventStatsMap = new HashMap<>();
+            for (PulledAtomsClass.TelecomEventStats v : mPulledAtoms.telecomEventStats) {
+                mEventStatsMap.put(new CriticalEvent(v.getEvent(), v.getUid(),
+                        v.getEventCause()), v.getCount());
+            }
+            mLastPulledTimestamps = mPulledAtoms.getTelecomEventStatsPullTimestampMillis();
+        }
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized void onAggregate() {
+        Log.d(TAG, "onAggregate: %s", mEventStatsMap);
+        clearAtoms();
+        if (mEventStatsMap.isEmpty()) {
+            return;
+        }
+        mPulledAtoms.setTelecomEventStatsPullTimestampMillis(mLastPulledTimestamps);
+        mPulledAtoms.telecomEventStats =
+                new PulledAtomsClass.TelecomEventStats[mEventStatsMap.size()];
+        int[] index = new int[1];
+        mEventStatsMap.forEach((k, v) -> {
+            mPulledAtoms.telecomEventStats[index[0]] = new PulledAtomsClass.TelecomEventStats();
+            mPulledAtoms.telecomEventStats[index[0]].setEvent(k.mId);
+            mPulledAtoms.telecomEventStats[index[0]].setUid(k.mUid);
+            mPulledAtoms.telecomEventStats[index[0]].setEventCause(k.mCause);
+            mPulledAtoms.telecomEventStats[index[0]].setCount(v);
+            index[0]++;
+        });
+        save(DELAY_FOR_PERSISTENT_MILLIS);
+    }
+
+    public void log(@NonNull CriticalEvent event) {
+        post(() -> {
+            mEventStatsMap.put(event, mEventStatsMap.getOrDefault(event, 0) + 1);
+            onAggregate();
+        });
+    }
+
+    @IntDef(prefix = "ID_", value = {
+            ID_UNKNOWN,
+            ID_INIT,
+            ID_DEFAULT_DIALER_CHANGED,
+            ID_ADD_CALL
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface EventId {
+    }
+
+    @IntDef(prefix = "CAUSE_", value = {
+            CAUSE_UNKNOWN,
+            CAUSE_GENERIC_SUCCESS,
+            CAUSE_GENERIC_FAILURE,
+            CAUSE_CALL_TRANSACTION_SUCCESS,
+            CAUSE_CALL_TRANSACTION_ERROR_UNKNOWN,
+            CAUSE_CALL_TRANSACTION_CANNOT_HOLD_CURRENT_ACTIVE_CALL,
+            CAUSE_CALL_TRANSACTION_CALL_IS_NOT_BEING_TRACKED,
+            CAUSE_CALL_TRANSACTION_CALL_CANNOT_BE_SET_TO_ACTIVE,
+            CAUSE_CALL_TRANSACTION_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
+            CAUSE_CALL_TRANSACTION_OPERATION_TIMED_OUT
+    })
+    @Retention(RetentionPolicy.SOURCE)
+    public @interface CauseId {
+    }
+
+    public static class CriticalEvent {
+
+        @EventId
+        int mId;
+        int mUid;
+        @CauseId
+        int mCause;
+
+        public CriticalEvent(@EventId int id, int uid, @CauseId int cause) {
+            mId = id;
+            mUid = uid;
+            mCause = cause;
+        }
+
+        public void setUid(int uid) {
+            this.mUid = uid;
+        }
+
+        public void setResult(@CauseId int result) {
+            this.mCause = result;
+        }
+
+        @Override
+        public boolean equals(Object other) {
+            if (this == other) {
+                return true;
+            }
+            if (!(other instanceof ApiEvent obj)) {
+                return false;
+            }
+            return this.mId == obj.mId && this.mUid == obj.mCallerUid
+                    && this.mCause == obj.mResult;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mId, mUid, mCause);
+        }
+
+        @Override
+        public String toString() {
+            return "[CriticalEvent: mId=" + mId + ", m"
+                    + "Uid=" + mUid
+                    + ", mResult=" + mCause + "]";
+        }
+    }
+
+
+}
diff --git a/src/com/android/server/telecom/metrics/TelecomMetricsController.java b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
index df735c044..980c18064 100644
--- a/src/com/android/server/telecom/metrics/TelecomMetricsController.java
+++ b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
@@ -20,10 +20,12 @@ import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS;
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_EVENT_STATS;
 
 import android.annotation.NonNull;
 import android.app.StatsManager;
 import android.content.Context;
+import android.os.Binder;
 import android.os.HandlerThread;
 import android.telecom.Log;
 import android.util.StatsEvent;
@@ -36,6 +38,7 @@ import java.util.List;
 import java.util.Map;
 import java.util.Objects;
 import java.util.concurrent.ConcurrentHashMap;
+import java.util.concurrent.atomic.AtomicBoolean;
 
 public class TelecomMetricsController implements StatsManager.StatsPullAtomCallback {
 
@@ -44,6 +47,7 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     private final Context mContext;
     private final HandlerThread mHandlerThread;
     private final ConcurrentHashMap<Integer, TelecomPulledAtom> mStats = new ConcurrentHashMap<>();
+    private final AtomicBoolean mIsTestMode = new AtomicBoolean(false);
 
     private TelecomMetricsController(@NonNull Context context,
                                      @NonNull HandlerThread handlerThread) {
@@ -73,8 +77,13 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     public ApiStats getApiStats() {
         ApiStats stats = (ApiStats) mStats.get(TELECOM_API_STATS);
         if (stats == null) {
-            stats = new ApiStats(mContext, mHandlerThread.getLooper());
-            registerAtom(stats.getTag(), stats);
+            long token = Binder.clearCallingIdentity();
+            try {
+                stats = new ApiStats(mContext, mHandlerThread.getLooper(), isTestMode());
+                registerAtom(stats.getTag(), stats);
+            } finally {
+                Binder.restoreCallingIdentity(token);
+            }
         }
         return stats;
     }
@@ -83,7 +92,7 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     public AudioRouteStats getAudioRouteStats() {
         AudioRouteStats stats = (AudioRouteStats) mStats.get(CALL_AUDIO_ROUTE_STATS);
         if (stats == null) {
-            stats = new AudioRouteStats(mContext, mHandlerThread.getLooper());
+            stats = new AudioRouteStats(mContext, mHandlerThread.getLooper(), isTestMode());
             registerAtom(stats.getTag(), stats);
         }
         return stats;
@@ -93,7 +102,7 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     public CallStats getCallStats() {
         CallStats stats = (CallStats) mStats.get(CALL_STATS);
         if (stats == null) {
-            stats = new CallStats(mContext, mHandlerThread.getLooper());
+            stats = new CallStats(mContext, mHandlerThread.getLooper(), isTestMode());
             registerAtom(stats.getTag(), stats);
         }
         return stats;
@@ -103,7 +112,17 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     public ErrorStats getErrorStats() {
         ErrorStats stats = (ErrorStats) mStats.get(TELECOM_ERROR_STATS);
         if (stats == null) {
-            stats = new ErrorStats(mContext, mHandlerThread.getLooper());
+            stats = new ErrorStats(mContext, mHandlerThread.getLooper(), isTestMode());
+            registerAtom(stats.getTag(), stats);
+        }
+        return stats;
+    }
+
+    @NonNull
+    public EventStats getEventStats() {
+        EventStats stats = (EventStats) mStats.get(TELECOM_EVENT_STATS);
+        if (stats == null) {
+            stats = new EventStats(mContext, mHandlerThread.getLooper(), isTestMode());
             registerAtom(stats.getTag(), stats);
         }
         return stats;
@@ -134,14 +153,30 @@ public class TelecomMetricsController implements StatsManager.StatsPullAtomCallb
     }
 
     public void destroy() {
+        clearStats();
+        mHandlerThread.quitSafely();
+    }
+
+    public void setTestMode(boolean enabled) {
+        mIsTestMode.set(enabled);
+        clearStats();
+    }
+
+    public boolean isTestMode() {
+        return mIsTestMode.get();
+    }
+
+    private void clearStats() {
         final StatsManager statsManager = mContext.getSystemService(StatsManager.class);
         if (statsManager != null) {
-            mStats.forEach((tag, stat) -> statsManager.clearPullAtomCallback(tag));
+            mStats.forEach((tag, stat) -> {
+                statsManager.clearPullAtomCallback(tag);
+                stat.flush();
+            });
         } else {
             Log.w(TAG, "Unable to clear pulled atoms as StatsManager is null");
         }
 
         mStats.clear();
-        mHandlerThread.quitSafely();
     }
 }
diff --git a/src/com/android/server/telecom/metrics/TelecomPulledAtom.java b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
index 161eaa8a4..d60fc7719 100644
--- a/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
+++ b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
@@ -45,23 +45,28 @@ public abstract class TelecomPulledAtom extends Handler {
     private static final long MIN_PULL_INTERVAL_MILLIS = 23L * 60 * 60 * 1000;
     private static final int EVENT_SAVE = 1;
     protected final Context mContext;
+    protected final boolean mIsTestMode;
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     public PulledAtoms mPulledAtoms;
     protected long mLastPulledTimestamps;
 
-    protected TelecomPulledAtom(@NonNull Context context, @NonNull Looper looper) {
+    protected TelecomPulledAtom(@NonNull Context context, @NonNull Looper looper,
+                                boolean isTestMode) {
         super(looper);
         mContext = context;
+        mIsTestMode = isTestMode;
         mPulledAtoms = loadAtomsFromFile();
         onLoad();
     }
 
     public synchronized int pull(final List<StatsEvent> data) {
-        long cur = System.currentTimeMillis();
-        if (cur - mLastPulledTimestamps < MIN_PULL_INTERVAL_MILLIS) {
-            return StatsManager.PULL_SKIP;
+        if (!mIsTestMode) {
+            long cur = System.currentTimeMillis();
+            if (cur - mLastPulledTimestamps < MIN_PULL_INTERVAL_MILLIS) {
+                return StatsManager.PULL_SKIP;
+            }
+            mLastPulledTimestamps = cur;
         }
-        mLastPulledTimestamps = cur;
         return onPull(data);
     }
 
@@ -76,21 +81,22 @@ public abstract class TelecomPulledAtom extends Handler {
     @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
     public abstract void onAggregate();
 
-    public void onFlush() {
+    public void flush() {
         save(0);
     }
 
     protected abstract String getFileName();
 
     private synchronized PulledAtoms loadAtomsFromFile() {
-        try {
-            return
-                    PulledAtoms.parseFrom(
-                            Files.readAllBytes(mContext.getFileStreamPath(getFileName()).toPath()));
-        } catch (NoSuchFileException e) {
-            Log.e(TAG, e, "the atom file not found");
-        } catch (IOException | NullPointerException e) {
-            Log.e(TAG, e, "cannot load/parse the atom file");
+        if (!mIsTestMode) {
+            try {
+                return PulledAtoms.parseFrom(
+                        Files.readAllBytes(mContext.getFileStreamPath(getFileName()).toPath()));
+            } catch (NoSuchFileException e) {
+                Log.e(TAG, e, "the atom file not found");
+            } catch (IOException | NullPointerException e) {
+                Log.e(TAG, e, "cannot load/parse the atom file");
+            }
         }
         return makeNewPulledAtoms();
     }
@@ -100,14 +106,16 @@ public abstract class TelecomPulledAtom extends Handler {
     }
 
     private synchronized void onSave() {
-        try (FileOutputStream stream = mContext.openFileOutput(getFileName(),
-                Context.MODE_PRIVATE)) {
-            Log.d(TAG, "save " + getTag());
-            stream.write(PulledAtoms.toByteArray(mPulledAtoms));
-        } catch (IOException e) {
-            Log.e(TAG, e, "cannot save the atom to file");
-        } catch (UnsupportedOperationException e) {
-            Log.e(TAG, e, "cannot open the file");
+        if (!mIsTestMode) {
+            try (FileOutputStream stream = mContext.openFileOutput(getFileName(),
+                    Context.MODE_PRIVATE)) {
+                Log.d(TAG, "save " + getTag());
+                stream.write(PulledAtoms.toByteArray(mPulledAtoms));
+            } catch (IOException e) {
+                Log.e(TAG, e, "cannot save the atom to file");
+            } catch (UnsupportedOperationException e) {
+                Log.e(TAG, e, "cannot open the file");
+            }
         }
     }
 
diff --git a/src/com/android/server/telecom/settings/BlockedNumbersActivity.java b/src/com/android/server/telecom/settings/BlockedNumbersActivity.java
index edc8da657..89f5cdcfe 100644
--- a/src/com/android/server/telecom/settings/BlockedNumbersActivity.java
+++ b/src/com/android/server/telecom/settings/BlockedNumbersActivity.java
@@ -18,6 +18,7 @@ package com.android.server.telecom.settings;
 
 import android.annotation.Nullable;
 import android.app.ActionBar;
+import android.app.Activity;
 import android.app.AlertDialog;
 import android.app.Fragment;
 import android.app.FragmentManager;
@@ -54,6 +55,10 @@ import android.widget.RelativeLayout;
 import android.widget.TextView;
 import android.widget.Toast;
 
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.R;
 import com.android.server.telecom.flags.FeatureFlags;
@@ -109,6 +114,7 @@ public class BlockedNumbersActivity extends ListActivity
             // set the talkback voice prompt to "Back" instead of "Navigate Up"
             actionBar.setHomeActionContentDescription(R.string.back);
         }
+        SettingsConstants.setupEdgeToEdge(this);
 
         if (!BlockedNumberContract.canCurrentUserBlockNumbers(this)) {
             TextView nonPrimaryUserText = (TextView) findViewById(R.id.non_primary_user);
diff --git a/src/com/android/server/telecom/settings/EnableAccountPreferenceActivity.java b/src/com/android/server/telecom/settings/EnableAccountPreferenceActivity.java
index ad7d7b736..57b232ae7 100644
--- a/src/com/android/server/telecom/settings/EnableAccountPreferenceActivity.java
+++ b/src/com/android/server/telecom/settings/EnableAccountPreferenceActivity.java
@@ -43,6 +43,7 @@ public class EnableAccountPreferenceActivity extends Activity {
         if (actionBar != null) {
             actionBar.setDisplayHomeAsUpEnabled(true);
         }
+        SettingsConstants.setupEdgeToEdge(this);
     }
 
     /** ${inheritDoc} */
diff --git a/src/com/android/server/telecom/settings/SettingsConstants.java b/src/com/android/server/telecom/settings/SettingsConstants.java
new file mode 100644
index 000000000..68a9c2485
--- /dev/null
+++ b/src/com/android/server/telecom/settings/SettingsConstants.java
@@ -0,0 +1,43 @@
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
+package com.android.server.telecom.settings;
+
+import android.app.Activity;
+
+import androidx.core.graphics.Insets;
+import androidx.core.view.ViewCompat;
+import androidx.core.view.WindowInsetsCompat;
+
+public class SettingsConstants {
+    /**
+     * Given an activity, configure the activity to adjust for edge to edge restrictions.
+     * @param activity the activity.
+     */
+    public static void setupEdgeToEdge(Activity activity) {
+        ViewCompat.setOnApplyWindowInsetsListener(activity.findViewById(android.R.id.content),
+            (v, windowInsets) -> {
+                Insets insets = windowInsets.getInsets(
+                    WindowInsetsCompat.Type.systemBars() | WindowInsetsCompat.Type.ime());
+
+                // Apply the insets paddings to the view.
+                v.setPadding(insets.left, insets.top, insets.right, insets.bottom);
+
+                // Return CONSUMED if you don't want the window insets to keep being
+                // passed down to descendant views.
+                return WindowInsetsCompat.CONSUMED;
+            });
+    }
+}
diff --git a/tests/src/com/android/server/telecom/tests/BasicCallTests.java b/tests/src/com/android/server/telecom/tests/BasicCallTests.java
index 7646c2d08..ef2d1a8d8 100644
--- a/tests/src/com/android/server/telecom/tests/BasicCallTests.java
+++ b/tests/src/com/android/server/telecom/tests/BasicCallTests.java
@@ -36,7 +36,7 @@ import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
-import static org.mockito.Mockito.verifyZeroInteractions;
+import static org.mockito.Mockito.verifyNoMoreInteractions;
 import static org.mockito.Mockito.when;
 
 import android.content.Context;
@@ -695,7 +695,10 @@ public class BasicCallTests extends TelecomSystemTest {
                 ArgumentCaptor.forClass(AudioDeviceInfo.class);
         verify(audioManager, timeout(TEST_TIMEOUT).atLeast(1))
                 .setCommunicationDevice(infoArgumentCaptor.capture());
-        assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, infoArgumentCaptor.getValue().getType());
+        var deviceType = infoArgumentCaptor.getValue().getType();
+        if (deviceType != AudioDeviceInfo.TYPE_BUS) { // on automotive, we expect BUS
+            assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, deviceType);
+        }
         mInCallServiceFixtureX.mInCallAdapter.setAudioRoute(CallAudioState.ROUTE_EARPIECE, null);
         waitForHandlerAction(mTelecomSystem.getCallsManager().getCallAudioManager()
                 .getCallAudioRouteAdapter().getAdapterHandler(), TEST_TIMEOUT);
@@ -857,7 +860,7 @@ public class BasicCallTests extends TelecomSystemTest {
 
         mInCallServiceFixtureX.mInCallAdapter.sendCallEvent(ids.mCallId, TEST_EVENT, 26, null);
         verify(mConnectionServiceFixtureA.getTestDouble(), timeout(TEST_TIMEOUT))
-                .sendCallEvent(eq(ids.mConnectionId), eq(TEST_EVENT), isNull(Bundle.class), any());
+                .sendCallEvent(eq(ids.mConnectionId), eq(TEST_EVENT), isNull(), any());
     }
 
     /**
@@ -905,7 +908,7 @@ public class BasicCallTests extends TelecomSystemTest {
     }
 
     private void verifyNoBlockChecks() {
-        verifyZeroInteractions(getBlockedNumberProvider());
+        verifyNoMoreInteractions(getBlockedNumberProvider());
     }
 
     private IContentProvider getBlockedNumberProvider() {
@@ -1282,7 +1285,7 @@ public class BasicCallTests extends TelecomSystemTest {
         // Stub intent for call2
         Intent callIntent2 = new Intent();
         Bundle callExtras1 = new Bundle();
-        Icon icon = Icon.createWithContentUri("content://10@media/external/images/media/");
+        Icon icon = Icon.createWithContentUri("content://12@media/external/images/media/");
         // Load StatusHints extra into TelecomManager.EXTRA_OUTGOING_CALL_EXTRAS to be processed
         // as the call extras. This will be leveraged in ConnectionServiceFixture to set the
         // StatusHints for the given connection.
@@ -1315,7 +1318,7 @@ public class BasicCallTests extends TelecomSystemTest {
     @Test
     public void testValidateStatusHintsImage_handleCreateConnectionComplete() throws Exception {
         Bundle extras = new Bundle();
-        Icon icon = Icon.createWithContentUri("content://10@media/external/images/media/");
+        Icon icon = Icon.createWithContentUri("content://12@media/external/images/media/");
         // Load the bundle with the test extra in order to simulate an app directly invoking the
         // binder on ConnectionServiceWrapper#handleCreateConnectionComplete.
         StatusHints statusHints = new StatusHints(icon);
@@ -1349,7 +1352,7 @@ public class BasicCallTests extends TelecomSystemTest {
                 mPhoneAccountA0.getAccountHandle(), mConnectionServiceFixtureA);
 
         // Modify existing connection with StatusHints image exploit
-        Icon icon = Icon.createWithContentUri("content://10@media/external/images/media/");
+        Icon icon = Icon.createWithContentUri("content://12@media/external/images/media/");
         StatusHints statusHints = new StatusHints(icon);
         assertNotNull(statusHints.getIcon());
         ConnectionServiceFixture.ConnectionInfo connectionInfo = mConnectionServiceFixtureA
@@ -1384,7 +1387,7 @@ public class BasicCallTests extends TelecomSystemTest {
                 mPhoneAccountA0.getAccountHandle(), mConnectionServiceFixtureA);
 
         // Modify existing connection with StatusHints image exploit
-        Icon icon = Icon.createWithContentUri("content://10@media/external/images/media/");
+        Icon icon = Icon.createWithContentUri("content://12@media/external/images/media/");
         StatusHints modifiedStatusHints = new StatusHints(icon);
         assertNotNull(modifiedStatusHints.getIcon());
         ConnectionServiceFixture.ConnectionInfo connectionInfo = mConnectionServiceFixtureA
diff --git a/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java b/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
index ac4a94e23..9f97bbe3b 100644
--- a/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
@@ -18,6 +18,9 @@ package com.android.server.telecom.tests;
 
 import static android.media.AudioDeviceInfo.TYPE_BUILTIN_SPEAKER;
 
+import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_BASELINE_ROUTE;
+import static com.android.server.telecom.CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE;
+
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertNull;
@@ -44,11 +47,14 @@ import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.os.Bundle;
 import android.os.Parcel;
+import android.telecom.CallAudioState;
 
 import androidx.test.filters.SmallTest;
 
+import com.android.server.telecom.AudioRoute;
 import com.android.server.telecom.CallAudioCommunicationDeviceTracker;
 import com.android.server.telecom.CallAudioRouteAdapter;
+import com.android.server.telecom.CallAudioRouteController;
 import com.android.server.telecom.bluetooth.BluetoothDeviceManager;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
 import com.android.server.telecom.bluetooth.BluetoothStateReceiver;
@@ -64,7 +70,9 @@ import org.mockito.Mock;
 import static org.mockito.Mockito.reset;
 import java.util.ArrayList;
 import java.util.Arrays;
+import java.util.HashMap;
 import java.util.List;
+import java.util.Map;
 import java.util.concurrent.Executor;
 
 @RunWith(JUnit4.class)
@@ -79,6 +87,8 @@ public class BluetoothDeviceManagerTest extends TelecomTestCase {
     @Mock AudioManager mockAudioManager;
     @Mock AudioDeviceInfo mSpeakerInfo;
     @Mock Executor mExecutor;
+    @Mock CallAudioRouteController mCallAudioRouteController;
+    @Mock CallAudioState mCallAudioState;
 
     BluetoothDeviceManager mBluetoothDeviceManager;
     BluetoothProfile.ServiceListener serviceListenerUnderTest;
@@ -115,6 +125,7 @@ public class BluetoothDeviceManagerTest extends TelecomTestCase {
         mBluetoothDeviceManager = new BluetoothDeviceManager(mContext, mAdapter,
                 mCommunicationDeviceTracker, mFeatureFlags);
         mBluetoothDeviceManager.setBluetoothRouteManager(mRouteManager);
+        mBluetoothDeviceManager.setCallAudioRouteAdapter(mCallAudioRouteController);
         mCommunicationDeviceTracker.setBluetoothRouteManager(mRouteManager);
 
         mockAudioManager = mContext.getSystemService(AudioManager.class);
@@ -297,6 +308,38 @@ public class BluetoothDeviceManagerTest extends TelecomTestCase {
         assertEquals(2, mBluetoothDeviceManager.getUniqueConnectedDevices().size());
     }
 
+    @SmallTest
+    @Test
+    public void testHandleAudioRefactoringServiceDisconnectedWhileBluetooth() {
+        when(mFeatureFlags.skipBaselineSwitchWhenRouteNotBluetooth()).thenReturn(true);
+        Map<AudioRoute, BluetoothDevice> btRoutes = new HashMap<>();
+        when(mCallAudioRouteController.getBluetoothRoutes()).thenReturn(btRoutes);
+        when(mCallAudioRouteController.getCurrentCallAudioState()).thenReturn(mCallAudioState);
+        when(mCallAudioState.getRoute()).thenReturn(CallAudioState.ROUTE_BLUETOOTH);
+
+        mBluetoothDeviceManager
+                .handleAudioRefactoringServiceDisconnected(BluetoothProfile.LE_AUDIO);
+
+        verify(mCallAudioRouteController).sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                INCLUDE_BLUETOOTH_IN_BASELINE, (String) null);
+    }
+
+    @SmallTest
+    @Test
+    public void testHandleAudioRefactoringServiceDisconnectedWhileSpeaker() {
+        when(mFeatureFlags.skipBaselineSwitchWhenRouteNotBluetooth()).thenReturn(true);
+        Map<AudioRoute, BluetoothDevice> btRoutes = new HashMap<>();
+        when(mCallAudioRouteController.getBluetoothRoutes()).thenReturn(btRoutes);
+        when(mCallAudioRouteController.getCurrentCallAudioState()).thenReturn(mCallAudioState);
+        when(mCallAudioState.getRoute()).thenReturn(CallAudioState.ROUTE_SPEAKER);
+
+        mBluetoothDeviceManager
+                .handleAudioRefactoringServiceDisconnected(BluetoothProfile.LE_AUDIO);
+
+        verify(mCallAudioRouteController, never()).sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                INCLUDE_BLUETOOTH_IN_BASELINE, (String) null);
+    }
+
     @SmallTest
     @Test
     public void testHeadsetServiceDisconnect() {
diff --git a/tests/src/com/android/server/telecom/tests/BluetoothRouteManagerTest.java b/tests/src/com/android/server/telecom/tests/BluetoothRouteManagerTest.java
index 1c885c134..4913904d2 100644
--- a/tests/src/com/android/server/telecom/tests/BluetoothRouteManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/BluetoothRouteManagerTest.java
@@ -35,6 +35,7 @@ import android.bluetooth.BluetoothLeAudio;
 import android.bluetooth.BluetoothProfile;
 import android.bluetooth.BluetoothStatusCodes;
 import android.content.ContentResolver;
+import android.media.AudioDeviceInfo;
 import android.os.Parcel;
 import android.telecom.Log;
 
@@ -104,6 +105,8 @@ public class BluetoothRouteManagerTest extends TelecomTestCase {
             BluetoothDeviceManager.DEVICE_TYPE_HEARING_AID);
         when(mDeviceManager.connectAudio(anyString(), anyBoolean())).thenReturn(true);
         when(mDeviceManager.isHearingAidSetAsCommunicationDevice()).thenReturn(true);
+        when(mCommunicationDeviceTracker.isAudioDeviceSetForType(
+                eq(AudioDeviceInfo.TYPE_HEARING_AID))).thenReturn(true);
 
         setupConnectedDevices(null, HEARING_AIDS, null, null, HEARING_AIDS, null);
         when(mBluetoothHeadset.getAudioState(nullable(BluetoothDevice.class)))
@@ -130,7 +133,8 @@ public class BluetoothRouteManagerTest extends TelecomTestCase {
             BluetoothDeviceManager.DEVICE_TYPE_HEARING_AID);
         when(mDeviceManager.connectAudio(anyString(), anyBoolean())).thenReturn(true);
         when(mDeviceManager.isHearingAidSetAsCommunicationDevice()).thenReturn(true);
-
+        when(mCommunicationDeviceTracker.isAudioDeviceSetForType(
+                eq(AudioDeviceInfo.TYPE_HEARING_AID))).thenReturn(true);
 
         setupConnectedDevices(null, HEARING_AIDS, null, null, HEARING_AIDS, null);
         when(mBluetoothHeadset.getAudioState(nullable(BluetoothDevice.class)))
@@ -299,7 +303,8 @@ public class BluetoothRouteManagerTest extends TelecomTestCase {
         resetMocks();
         BluetoothRouteManager sm = new BluetoothRouteManager(mContext,
                 new TelecomSystem.SyncRoot() { }, mDeviceManager,
-                mTimeoutsAdapter, mCommunicationDeviceTracker, mFeatureFlags);
+                mTimeoutsAdapter, mCommunicationDeviceTracker, mFeatureFlags,
+                mContext.getMainLooper());
         sm.setListener(mListener);
         sm.setInitialStateForTesting(initialState, initialDevice);
         waitForHandlerAction(sm.getHandler(), TEST_TIMEOUT);
diff --git a/tests/src/com/android/server/telecom/tests/BluetoothRouteTransitionTests.java b/tests/src/com/android/server/telecom/tests/BluetoothRouteTransitionTests.java
index c546c3f05..004bcd3e5 100644
--- a/tests/src/com/android/server/telecom/tests/BluetoothRouteTransitionTests.java
+++ b/tests/src/com/android/server/telecom/tests/BluetoothRouteTransitionTests.java
@@ -420,7 +420,8 @@ public class BluetoothRouteTransitionTests extends TelecomTestCase {
                 nullable(ContentResolver.class))).thenReturn(100000L);
         BluetoothRouteManager sm = new BluetoothRouteManager(mContext,
                 new TelecomSystem.SyncRoot() { }, mDeviceManager,
-                mTimeoutsAdapter, mCommunicationDeviceTracker, mFeatureFlags);
+                mTimeoutsAdapter, mCommunicationDeviceTracker, mFeatureFlags,
+                mContext.getMainLooper());
         sm.setListener(mListener);
         sm.setInitialStateForTesting(initialState, initialDevice);
         waitForHandlerAction(sm.getHandler(), TEST_TIMEOUT);
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
index 809abb4b2..f6f16863d 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
@@ -37,13 +37,13 @@ import static com.android.server.telecom.CallAudioRouteAdapter.STREAMING_FORCE_D
 import static com.android.server.telecom.CallAudioRouteAdapter.STREAMING_FORCE_ENABLED;
 import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_BASELINE_ROUTE;
 import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_FOCUS;
+import static com.android.server.telecom.CallAudioRouteAdapter.TOGGLE_MUTE;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_BASELINE_ROUTE;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_BLUETOOTH;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_EARPIECE;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_HEADSET;
 import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_SPEAKER;
 import static com.android.server.telecom.CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE;
-
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
@@ -56,6 +56,7 @@ import static org.mockito.Mockito.doAnswer;
 import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
@@ -67,10 +68,13 @@ import android.bluetooth.BluetoothLeAudio;
 import android.content.BroadcastReceiver;
 import android.content.Intent;
 import android.content.IntentFilter;
+import android.media.AudioAttributes;
+import android.media.AudioDeviceAttributes;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.media.IAudioService;
 import android.media.audiopolicy.AudioProductStrategy;
+import android.os.Looper;
 import android.os.UserHandle;
 import android.telecom.CallAudioState;
 import android.telecom.VideoProfile;
@@ -100,45 +104,60 @@ import org.junit.runners.JUnit4;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 
+import java.util.ArrayList;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
+import java.util.concurrent.TimeUnit;
 
 @RunWith(JUnit4.class)
 public class CallAudioRouteControllerTest extends TelecomTestCase {
-    private CallAudioRouteController mController;
-    @Mock WiredHeadsetManager mWiredHeadsetManager;
-    @Mock AudioManager mAudioManager;
-    @Mock AudioDeviceInfo mEarpieceDeviceInfo;
-    @Mock CallsManager mCallsManager;
-    @Mock CallAudioManager.AudioServiceFactory mAudioServiceFactory;
-    @Mock IAudioService mAudioService;
-    @Mock BluetoothRouteManager mBluetoothRouteManager;
-    @Mock BluetoothDeviceManager mBluetoothDeviceManager;
-    @Mock BluetoothAdapter mBluetoothAdapter;
-    @Mock StatusBarNotifier mockStatusBarNotifier;
-    @Mock AudioDeviceInfo mAudioDeviceInfo;
-    @Mock BluetoothLeAudio mBluetoothLeAudio;
-    @Mock CallAudioManager mCallAudioManager;
-    @Mock Call mCall;
-    @Mock private TelecomSystem.SyncRoot mLock;
-    @Mock private TelecomMetricsController mMockTelecomMetricsController;
-    private AudioRoute mEarpieceRoute;
-    private AudioRoute mSpeakerRoute;
-    private boolean mOverrideSpeakerToBus;
     private static final String BT_ADDRESS_1 = "00:00:00:00:00:01";
     private static final BluetoothDevice BLUETOOTH_DEVICE_1 =
             BluetoothRouteManagerTest.makeBluetoothDevice("00:00:00:00:00:01");
-    private static final Set<BluetoothDevice> BLUETOOTH_DEVICES;
-    static {
-        BLUETOOTH_DEVICES = new HashSet<>();
-        BLUETOOTH_DEVICES.add(BLUETOOTH_DEVICE_1);
-    }
+    private static final Set<BluetoothDevice> BLUETOOTH_DEVICES = new HashSet<>();
     private static final int TEST_TIMEOUT = 500;
+
+    @Mock
+    WiredHeadsetManager mWiredHeadsetManager;
+    @Mock
+    AudioManager mAudioManager;
+    @Mock
+    AudioDeviceInfo mEarpieceDeviceInfo;
+    @Mock
+    CallsManager mCallsManager;
+    @Mock
+    CallAudioManager.AudioServiceFactory mAudioServiceFactory;
+    @Mock
+    IAudioService mAudioService;
+    @Mock
+    BluetoothRouteManager mBluetoothRouteManager;
+    @Mock
+    BluetoothDeviceManager mBluetoothDeviceManager;
+    @Mock
+    BluetoothAdapter mBluetoothAdapter;
+    @Mock
+    StatusBarNotifier mockStatusBarNotifier;
+    @Mock
+    AudioDeviceInfo mAudioDeviceInfo;
+    @Mock
+    BluetoothLeAudio mBluetoothLeAudio;
+    @Mock
+    CallAudioManager mCallAudioManager;
+    @Mock
+    Call mCall;
+    private CallAudioRouteController mController;
+    @Mock
+    private TelecomSystem.SyncRoot mLock;
+    @Mock
+    private TelecomMetricsController mMockTelecomMetricsController;
+    private AudioRoute mEarpieceRoute;
+    private AudioRoute mSpeakerRoute;
+    private boolean mOverrideSpeakerToBus;
     AudioRoute.Factory mAudioRouteFactory = new AudioRoute.Factory() {
         @Override
         public AudioRoute create(@AudioRoute.AudioRouteType int type, String bluetoothAddress,
-                                 AudioManager audioManager) {
+                AudioManager audioManager) {
             if (mOverrideSpeakerToBus && type == AudioRoute.TYPE_SPEAKER) {
                 type = AudioRoute.TYPE_BUS;
             }
@@ -152,7 +171,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         when(mWiredHeadsetManager.isPluggedIn()).thenReturn(false);
         when(mEarpieceDeviceInfo.getType()).thenReturn(AudioDeviceInfo.TYPE_BUILTIN_EARPIECE);
         when(mAudioManager.getDevices(eq(AudioManager.GET_DEVICES_OUTPUTS))).thenReturn(
-                new AudioDeviceInfo[] {
+                new AudioDeviceInfo[]{
                         mEarpieceDeviceInfo
                 });
         when(mAudioManager.getPreferredDeviceForStrategy(nullable(AudioProductStrategy.class)))
@@ -171,7 +190,8 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         when(mCallsManager.getLock()).thenReturn(mLock);
         when(mCallsManager.getForegroundCall()).thenReturn(mCall);
         when(mBluetoothRouteManager.getDeviceManager()).thenReturn(mBluetoothDeviceManager);
-        when(mBluetoothDeviceManager.connectAudio(any(BluetoothDevice.class), anyInt()))
+        when(mBluetoothDeviceManager.connectAudio(any(BluetoothDevice.class), anyInt(),
+                anyBoolean()))
                 .thenReturn(true);
         when(mBluetoothDeviceManager.getBluetoothAdapter()).thenReturn(mBluetoothAdapter);
         when(mBluetoothAdapter.getActiveDevices(anyInt())).thenReturn(List.of(BLUETOOTH_DEVICE_1));
@@ -197,12 +217,18 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(false);
         when(mFeatureFlags.newAudioPathSpeakerBroadcastAndUnfocusedRouting()).thenReturn(false);
         when(mFeatureFlags.fixUserRequestBaselineRouteVideoCall()).thenReturn(false);
+        when(mFeatureFlags.callAudioRoutingPerformanceImprovemenent()).thenReturn(true);
+        BLUETOOTH_DEVICES.add(BLUETOOTH_DEVICE_1);
     }
 
     @After
     public void tearDown() throws Exception {
-        mController.getAdapterHandler().getLooper().quit();
-        mController.getAdapterHandler().getLooper().getThread().join();
+        Looper looper = mController.getAdapterHandler().getLooper();
+        if (looper != Looper.getMainLooper()) {
+            mController.getAdapterHandler().getLooper().quit();
+            mController.getAdapterHandler().getLooper().getThread().join();
+        }
+        BLUETOOTH_DEVICES.clear();
         super.tearDown();
     }
 
@@ -219,7 +245,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     @Test
     public void testInitializeWithoutEarpiece() {
         when(mAudioManager.getDevices(eq(AudioManager.GET_DEVICES_OUTPUTS))).thenReturn(
-                new AudioDeviceInfo[] {});
+                new AudioDeviceInfo[]{});
 
         mController.initialize();
         assertEquals(mSpeakerRoute, mController.getCurrentRoute());
@@ -236,6 +262,87 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         assertTrue(mController.getAvailableRoutes().contains(mSpeakerRoute));
     }
 
+    @SmallTest
+    @Test
+    public void testEarpieceCreatedWhenWiredHeadsetDisconnected() {
+        // Initialize the controller with the wired headset.
+        AudioRoute wiredHeadsetRoute = new AudioRoute(AudioRoute.TYPE_WIRED, null, null);
+        when(mWiredHeadsetManager.isPluggedIn()).thenReturn(true);
+        mController.initialize();
+        assertEquals(wiredHeadsetRoute, mController.getCurrentRoute());
+        // Verify that the earpiece route isn't created.
+        assertFalse(mController.getAvailableRoutes().contains(mEarpieceRoute));
+        // When we disconnect the wired headset, we should create the earpiece route if it hasn't
+        // already been created.
+        mController.sendMessageWithSessionInfo(DISCONNECT_WIRED_HEADSET);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        // Verify that the earpiece route is created.
+        assertTrue(mController.getAvailableRoutes().contains(mEarpieceRoute));
+    }
+
+    @SmallTest
+    @Test
+    public void testAudioRouteForPreferredDeviceStrategy() {
+        when(mFeatureFlags.updatePreferredAudioDeviceLogic()).thenReturn(true);
+        mController.initialize();
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
+        waitForRouteActiveStateAndVerify(true);
+        // Verify preferred device strategy still needs to be used since audio routing hasn't gone
+        // active
+        assertTrue(mController.getUsePreferredDeviceStrategy());
+
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        waitForHandlerAction(mController.getAdapterHandler(), TEST_TIMEOUT);
+        assertTrue(mController.isActive());
+        // Verify that we should no longer are using the preferred device strategy once we process
+        // active focus switch.
+        assertFalse(mController.getUsePreferredDeviceStrategy());
+    }
+
+    @SmallTest
+    @Test
+    public void testAudioRouteCommunicationDeviceSyncWithPreferredDeviceStrategy() {
+        when(mFeatureFlags.updatePreferredAudioDeviceLogic()).thenReturn(true);
+        mController.initialize();
+        // Set up tests so that the current communication device is different from the preferred
+        // device for strategy.
+        AudioDeviceInfo infoCommunicationDevice = mock(AudioDeviceInfo.class);
+        when(infoCommunicationDevice.getType()).thenReturn(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER);
+        mController.setCurrentCommunicationDevice(infoCommunicationDevice);
+        // Setup mocks to test the preferred device strategy.
+        setUpPreferredDeviceMocks();
+
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
+        waitForRouteActiveStateAndVerify(true);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Verify that routing remains unchanged once active focus is processed (we still check
+        // for preferred device strategy). Do note that we still end up using the reported
+        // communication device instead as it's not synced with the preferred device).
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // For sanity, verify that routing falls back on earpiece if focus is switched to active
+        // again (we don't try to use the preferred device strategy).
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        mController.sendMessageWithSessionInfo(SPEAKER_OFF);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
     @SmallTest
     @Test
     public void testNormalCallRouteToEarpiece() {
@@ -367,7 +474,8 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     @SmallTest
     @Test
     public void testSwitchFocusForBluetoothDeviceSupportInbandRinging() {
-        when(mBluetoothRouteManager.isInbandRingEnabled(eq(BLUETOOTH_DEVICE_1))).thenReturn(true);
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(AudioRoute.TYPE_BLUETOOTH_SCO),
+                eq(BLUETOOTH_DEVICE_1))).thenReturn(true);
 
         mController.initialize();
         mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
@@ -384,8 +492,8 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
         mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT))
-                .connectAudio(BLUETOOTH_DEVICE_1, AudioRoute.TYPE_BLUETOOTH_SCO);
-        assertTrue(mController.isActive());
+                .connectAudio(BLUETOOTH_DEVICE_1, AudioRoute.TYPE_BLUETOOTH_SCO, false);
+        waitForRouteActiveStateAndVerify(true);
 
         mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         assertTrue(mController.isActive());
@@ -397,7 +505,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
         // Ensure the BT device is disconnected.
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT).atLeastOnce()).disconnectSco();
-        assertFalse(mController.isActive());
+        waitForRouteActiveStateAndVerify(false);
     }
 
     @SmallTest
@@ -419,6 +527,40 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
     }
 
+    @SmallTest
+    @Test
+    public void testDefaultSpeakerOnWiredHeadsetDisconnect() {
+        mController.initialize();
+        mController.setActive(true);
+        verifyMaybeDefaultSpeakerOnDisconnectWiredHeadset(
+                CallAudioState.ROUTE_SPEAKER /* expectedAudioType */,
+                false /* includeUserSwitch */);
+    }
+
+    @SmallTest
+    @Test
+    public void testIgnoreDefaultSpeakerOnWiredHeadsetDisconnect() {
+        // Note here that the routing isn't active to represent that we're not in a call. If a wired
+        // headset is disconnected and the last route was speaker, we shouldn't switch back to
+        // speaker when we're not in a call.
+        mController.initialize();
+        verifyMaybeDefaultSpeakerOnDisconnectWiredHeadset(
+                CallAudioState.ROUTE_EARPIECE /* expectedAudioType */,
+                false /* includeUserSwitch */);
+    }
+
+    @SmallTest
+    @Test
+    public void testIgnoreDefaultSpeakerOnWiredHeadsetDisconnect_UserSwitchesOutOfSpeaker() {
+        mController.initialize();
+        mController.setActive(true);
+        // Verify that when we turn speaker on/off when a wired headset is plugged in and after the
+        // headset is disconnected that we don't default audio routing back to speaker.
+        verifyMaybeDefaultSpeakerOnDisconnectWiredHeadset(
+                CallAudioState.ROUTE_EARPIECE /* expectedAudioType */,
+                true /* includeUserSwitch */);
+    }
+
     @SmallTest
     @Test
     public void testConnectAndDisconnectDock() {
@@ -573,11 +715,11 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
 
         mController.sendMessageWithSessionInfo(SPEAKER_ON);
-        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
 
         mController.sendMessageWithSessionInfo(CONNECT_WIRED_HEADSET);
-        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
 
         mController.sendMessageWithSessionInfo(STREAMING_FORCE_DISABLED);
@@ -619,7 +761,6 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         assertTrue(foundValid);
     }
 
-
     @SmallTest
     @Test
     public void testToggleMute() throws Exception {
@@ -645,6 +786,17 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 anyInt(), anyString());
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
+
+        // Send TOGGLE_MUTE
+        when(mAudioManager.isMicrophoneMute()).thenReturn(false);
+        mController.sendMessageWithSessionInfo(TOGGLE_MUTE);
+        expectedState = new CallAudioState(true, CallAudioState.ROUTE_EARPIECE,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mAudioService, timeout(TEST_TIMEOUT).atLeastOnce()).setMicrophoneMute(eq(true),
+                anyString(), anyInt(), anyString());
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
     }
 
     @SmallTest
@@ -705,7 +857,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         mController.sendMessageWithSessionInfo(DISCONNECT_WIRED_HEADSET);
         expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
                 CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
-                        | CallAudioState.ROUTE_BLUETOOTH, null , BLUETOOTH_DEVICES);
+                        | CallAudioState.ROUTE_BLUETOOTH, null, BLUETOOTH_DEVICES);
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
     }
@@ -717,6 +869,14 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
     }
 
+    @SmallTest
+    @Test
+    public void testConnectDisconnectScoDuringCallNoClear() {
+        when(mFeatureFlags.onlyClearCommunicationDeviceOnInactive()).thenReturn(true);
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+    }
+
     @SmallTest
     @Test
     public void testConnectAndDisconnectLeDeviceDuringCall() {
@@ -726,6 +886,16 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_LE);
     }
 
+    @SmallTest
+    @Test
+    public void testConnectAndDisconnectLeDeviceDuringCallNoClear() {
+        when(mFeatureFlags.onlyClearCommunicationDeviceOnInactive()).thenReturn(true);
+        when(mBluetoothLeAudio.getConnectedGroupLeadDevice(anyInt()))
+                .thenReturn(BLUETOOTH_DEVICE_1);
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_LE);
+        verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_LE);
+    }
+
     @SmallTest
     @Test
     public void testConnectAndDisconnectHearingAidDuringCall() {
@@ -733,6 +903,14 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_HA);
     }
 
+    @SmallTest
+    @Test
+    public void testConnectAndDisconnectHearingAidDuringCallNoClear() {
+        when(mFeatureFlags.onlyClearCommunicationDeviceOnInactive()).thenReturn(true);
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_HA);
+        verifyDisconnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_HA);
+    }
+
     @SmallTest
     @Test
     public void testSwitchBetweenLeAndScoDevices() {
@@ -775,7 +953,8 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     @SmallTest
     @Test
     public void testFallbackWhenBluetoothConnectionFails() {
-        when(mBluetoothDeviceManager.connectAudio(any(BluetoothDevice.class), anyInt()))
+        when(mBluetoothDeviceManager.connectAudio(any(BluetoothDevice.class), anyInt(),
+                anyBoolean()))
                 .thenReturn(false);
 
         AudioDeviceInfo mockAudioDeviceInfo = mock(AudioDeviceInfo.class);
@@ -798,7 +977,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
                 AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice.getAddress());
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT))
-                .connectAudio(scoDevice, AudioRoute.TYPE_BLUETOOTH_SCO);
+                .connectAudio(scoDevice, AudioRoute.TYPE_BLUETOOTH_SCO, false);
         expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
                 CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
                         | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
@@ -831,35 +1010,36 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     public void testRouteFromBtSwitchInRingingSelected() {
         when(mFeatureFlags.ignoreAutoRouteToWatchDevice()).thenReturn(true);
         when(mBluetoothRouteManager.isWatch(any(BluetoothDevice.class))).thenReturn(true);
-        when(mBluetoothRouteManager.isInbandRingEnabled(eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(AudioRoute.TYPE_BLUETOOTH_SCO),
+                eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
 
         mController.initialize();
         mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
-            BLUETOOTH_DEVICE_1);
+                BLUETOOTH_DEVICE_1);
         CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
-            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
-                | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
-            any(CallAudioState.class), eq(expectedState));
+                any(CallAudioState.class), eq(expectedState));
 
         mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
         assertFalse(mController.isActive());
 
         // BT device should be cached. Verify routing into BT device once focus becomes active.
         mController.sendMessageWithSessionInfo(USER_SWITCH_BLUETOOTH, 0,
-            BLUETOOTH_DEVICE_1.getAddress());
+                BLUETOOTH_DEVICE_1.getAddress());
         expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
-            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
-                | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
-            any(CallAudioState.class), eq(expectedState));
+                any(CallAudioState.class), eq(expectedState));
         mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0, BLUETOOTH_DEVICE_1);
         expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
-            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
-                | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
-            any(CallAudioState.class), eq(expectedState));
+                any(CallAudioState.class), eq(expectedState));
     }
 
     @SmallTest
@@ -936,7 +1116,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         mController.sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
                 INCLUDE_BLUETOOTH_IN_BASELINE, BLUETOOTH_DEVICE_1.getAddress());
         // Process BT_AUDIO_CONNECTED from connecting to BT device in active focus request.
-        mController.setIsScoAudioConnected(true);
+        mController.setScoAudioConnectedDevice(BLUETOOTH_DEVICE_1);
         mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0, BLUETOOTH_DEVICE_1);
         // Verify SCO not disconnected and route stays on connected BT device.
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT).times(0)).disconnectSco();
@@ -1024,11 +1204,11 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
         // Now switch call to active focus so that base route can be recalculated.
         mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
-        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
-                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
-                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
-        // Verify that audio is still routed into BLUETOOTH_DEVICE_1 and not the 2nd BT device.
-        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+        // Verify that audio is still routed into BLUETOOTH_DEVICE_1 and not the 2nd BT device. Add
+        // atLeastOnce verification because the expected route would've been hit when we first
+        // initially added the scoDevice and is getting captured here along with the invocation
+        // from switching to active focus.
+        verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
 
         // Clean up BLUETOOTH_DEVICES for subsequent tests.
@@ -1117,7 +1297,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 watchDevice);
         CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
                 CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
-                | CallAudioState.ROUTE_BLUETOOTH, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+                        | CallAudioState.ROUTE_BLUETOOTH, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
 
@@ -1156,12 +1336,12 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         BLUETOOTH_DEVICES.remove(watchDevice);
     }
 
-
     @Test
     @SmallTest
     public void testAbandonCallAudioFocusAfterCallEnd() {
         // Make sure in-band ringing is disabled so that route never becomes active
-        when(mBluetoothRouteManager.isInbandRingEnabled(eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(AudioRoute.TYPE_BLUETOOTH_SCO),
+                eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
 
         mController.initialize();
         mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
@@ -1189,6 +1369,131 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         verify(mCallAudioManager, timeout(TEST_TIMEOUT)).notifyAudioOperationsComplete();
     }
 
+    @Test
+    @SmallTest
+    public void testActiveDevicePresentRoutesOnCurrentActive() {
+        when(mFeatureFlags.resolveActiveBtRoutingAndBtTimingIssue()).thenReturn(true);
+        // Connect first BT device.
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        // Connect another BT device.
+        String scoDeviceAddress = "00:00:00:00:00:03";
+        BluetoothDevice scoDevice2 =
+                BluetoothRouteManagerTest.makeBluetoothDevice(scoDeviceAddress);
+        BLUETOOTH_DEVICES.add(scoDevice2);
+
+        // Signal second BT device added in controller and verify routing to that device upon
+        // receiving active focus.
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                scoDevice2);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
+                        | CallAudioState.ROUTE_BLUETOOTH, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Update the currently tracked active device to be BLUETOOTH_DEVICE_1.
+        mController.updateActiveBluetoothDevice(
+                new Pair<>(AudioRoute.TYPE_BLUETOOTH_SCO, BLUETOOTH_DEVICE_1.getAddress()));
+        // Verify that sending BT_ACTIVE_DEVICE_PRESENT when BLUETOOTH_DEVICE_1 isn't the currently
+        // tracked active device, that we ignore routing.
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice2.getAddress());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Now update the active device so that it's scoDevice2 and verify that
+        // BT_ACTIVE_DEVICE_PRESENT is properly processed and that we route into the device.
+        mController.updateActiveBluetoothDevice(
+                new Pair<>(AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice2.getAddress()));
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice2.getAddress());
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                BLUETOOTH_DEVICE_1);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED,
+                0, scoDevice2);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER
+                        | CallAudioState.ROUTE_BLUETOOTH, scoDevice2, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    @Test
+    @SmallTest
+    public void testRouteToInactiveWhenInbandRingingDisabledDuringRinging() {
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(AudioRoute.TYPE_BLUETOOTH_SCO),
+                eq(BLUETOOTH_DEVICE_1))).thenReturn(true);
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
+        assertTrue(mController.isActive());
+
+        // Connect another HFP device while call is still ringing
+        BluetoothDevice scoDevice =
+                BluetoothRouteManagerTest.makeBluetoothDevice("00:00:00:00:00:03");
+        BLUETOOTH_DEVICES.add(scoDevice);
+
+        // Add SCO device.
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                scoDevice);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(AudioRoute.TYPE_BLUETOOTH_SCO),
+                any(BluetoothDevice.class))).thenReturn(false);
+        // Emulate second device becoming active and first device getting disconnected as in-band
+        // ringing is disabled.
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice.getAddress());
+        mController.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                BLUETOOTH_DEVICE_1);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, scoDevice, BLUETOOTH_DEVICES);
+        // Verify routing goes to the new HFP device but that the routing is now inactive.
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        assertFalse(mController.isActive());
+    }
+
+    @Test
+    @SmallTest
+    public void testSkipConnectBluetoothWhenScoAudioAlreadyConnected() {
+        verifyConnectBluetoothDevice(AudioRoute.TYPE_BLUETOOTH_SCO);
+        // Connect another HFP device while call is still ringing
+        BluetoothDevice scoDevice =
+                BluetoothRouteManagerTest.makeBluetoothDevice("00:00:00:00:00:03");
+        BLUETOOTH_DEVICES.add(scoDevice);
+
+        // Add SCO device.
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+                scoDevice);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Emulate scenario where BT stack signals SCO audio connected for the second HFP device
+        // before Telecom finishes processing the route change to this device. We should ensure
+        // that we don't accidentally disconnect SCO in this case (thinking that we're disconnecting
+        // the first HFP device).
+        mController.setScoAudioConnectedDevice(scoDevice);
+        mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT,
+                AudioRoute.TYPE_BLUETOOTH_SCO, scoDevice.getAddress());
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                        | CallAudioState.ROUTE_SPEAKER, scoDevice, BLUETOOTH_DEVICES);
+        // Verify routing goes to the new HFP device and we never disconnect SCO when clearing the
+        // original pending route.
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT).times(0)).disconnectSco();
+    }
+
     private void verifyConnectBluetoothDevice(int audioType) {
         mController.initialize();
         mController.setActive(true);
@@ -1203,7 +1508,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         mController.sendMessageWithSessionInfo(BT_ACTIVE_DEVICE_PRESENT, audioType, BT_ADDRESS_1);
         if (audioType == AudioRoute.TYPE_BLUETOOTH_SCO) {
             verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT))
-                    .connectAudio(BLUETOOTH_DEVICE_1, AudioRoute.TYPE_BLUETOOTH_SCO);
+                    .connectAudio(BLUETOOTH_DEVICE_1, AudioRoute.TYPE_BLUETOOTH_SCO, false);
             mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED,
                     0, BLUETOOTH_DEVICE_1);
         } else {
@@ -1239,9 +1544,95 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         if (audioType == AudioRoute.TYPE_BLUETOOTH_SCO) {
             verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT)).disconnectSco();
         } else {
-            verify(mAudioManager, timeout(TEST_TIMEOUT)).clearCommunicationDevice();
+            if (mFeatureFlags.onlyClearCommunicationDeviceOnInactive()) {
+                verify(mAudioManager, timeout(TEST_TIMEOUT).times(2))
+                        .setCommunicationDevice(any(AudioDeviceInfo.class));
+                // Don't use a timeout here because that will cause the test to pause for a long
+                // period of time to verify; the previous verify has a timeout on it, so it will
+                // have already waited for any AudioManager invocations to take place.  Any
+                // potential clear would have happened by now.
+                verify(mAudioManager, never()).clearCommunicationDevice();
+            } else {
+                verify(mAudioManager, timeout(TEST_TIMEOUT)).clearCommunicationDevice();
+            }
+        }
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
+    private void verifyMaybeDefaultSpeakerOnDisconnectWiredHeadset(int expectedAudioType, boolean includeUserSwitch) {
+        // Ensure audio is routed to speaker initially
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Then simulate wired headset being connected after speaker was initially the audio route
+        mController.sendMessageWithSessionInfo(CONNECT_WIRED_HEADSET);
+        mController.sendMessageWithSessionInfo(SPEAKER_OFF);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_WIRED_HEADSET,
+                CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Emulate scenario with user turning on/off speaker. This is to verify that when the user
+        // switches off speaker that we don't auto route back to speaker when the wired headset
+        // disconnects.
+        if (includeUserSwitch) {
+            // Verify speaker turned on from USER_SWITCH_SPEAKER
+            mController.sendMessageWithSessionInfo(USER_SWITCH_SPEAKER);
+            mController.sendMessageWithSessionInfo(SPEAKER_ON);
+            expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                    CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                    new HashSet<>());
+            verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                    any(CallAudioState.class), eq(expectedState));
+
+            // Verify speaker turned off from turning off speaker
+            mController.sendMessageWithSessionInfo(USER_SWITCH_BASELINE_ROUTE,
+                    INCLUDE_BLUETOOTH_IN_BASELINE);
+            mController.sendMessageWithSessionInfo(SPEAKER_OFF);
+            expectedState = new CallAudioState(false, CallAudioState.ROUTE_WIRED_HEADSET,
+                    CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                    new HashSet<>());
+            verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                    any(CallAudioState.class), eq(expectedState));
         }
+
+        // Verify that we route back into speaker once the wired headset disconnects
+        mController.sendMessageWithSessionInfo(DISCONNECT_WIRED_HEADSET);
+        expectedState = new CallAudioState(false, expectedAudioType,
+                CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
         verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
     }
+
+    private void waitForRouteActiveStateAndVerify(boolean expectActive) {
+        try {
+            if (expectActive) {
+                mController.getAudioActiveCompleteLatch().await(TEST_TIMEOUT,
+                        TimeUnit.MILLISECONDS);
+            } else {
+                mController.getAudioOperationsCompleteLatch().await(TEST_TIMEOUT,
+                        TimeUnit.MILLISECONDS);
+            }
+        } catch (Exception e) {
+            // Catch timeout exception and allow failure below.
+        } finally {
+            assertEquals(mController.isActive(), expectActive);
+        }
+    }
+
+    private void setUpPreferredDeviceMocks() {
+        AudioProductStrategy s = mock(AudioProductStrategy.class);
+        when(s.supportsAudioAttributes(any(AudioAttributes.class))).thenReturn(true);
+        AudioDeviceAttributes deviceAttr = mock(AudioDeviceAttributes.class);
+        when(mAudioManager.getPreferredDeviceForStrategy(any(AudioProductStrategy.class)))
+                .thenReturn(deviceAttr);
+        when(deviceAttr.getType()).thenReturn(AudioDeviceInfo.TYPE_BUILTIN_EARPIECE);
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioRouteStateMachineTest.java b/tests/src/com/android/server/telecom/tests/CallAudioRouteStateMachineTest.java
index e97de2e60..95c3a5a42 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioRouteStateMachineTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioRouteStateMachineTest.java
@@ -113,7 +113,6 @@ public class CallAudioRouteStateMachineTest extends TelecomTestCase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        MockitoAnnotations.initMocks(this);
         mThreadHandler = new HandlerThread("CallAudioRouteStateMachineTest");
         mThreadHandler.start();
         mContext = mComponentContextFixture.getTestDouble().getApplicationContext();
@@ -144,7 +143,6 @@ public class CallAudioRouteStateMachineTest extends TelecomTestCase {
         doNothing().when(mockConnectionServiceWrapper).onCallAudioStateChanged(any(Call.class),
                 any(CallAudioState.class));
         when(mFeatureFlags.ignoreAutoRouteToWatchDevice()).thenReturn(false);
-        when(mFeatureFlags.callAudioCommunicationDeviceRefactor()).thenReturn(false);
     }
 
     @Override
@@ -696,7 +694,10 @@ public class CallAudioRouteStateMachineTest extends TelecomTestCase {
                 0, bluetoothDevice2.getAddress());
         waitForHandlerAction(stateMachine.getAdapterHandler(), TEST_TIMEOUT);
 
-        verify(mockBluetoothRouteManager).connectBluetoothAudio(bluetoothDevice2.getAddress());
+        // It's possible that this is called again when we actually move into the active BT route
+        // and we end up verifying this after that has happened.
+        verify(mockBluetoothRouteManager, atLeastOnce()).connectBluetoothAudio(
+                bluetoothDevice2.getAddress());
         waitForHandlerAction(stateMachine.getAdapterHandler(), TEST_TIMEOUT);
         CallAudioState expectedEndState = new CallAudioState(false,
                 CallAudioState.ROUTE_BLUETOOTH,
@@ -838,7 +839,10 @@ public class CallAudioRouteStateMachineTest extends TelecomTestCase {
         ArgumentCaptor<AudioDeviceInfo> infoArgumentCaptor = ArgumentCaptor.forClass(
                 AudioDeviceInfo.class);
         verify(mockAudioManager).setCommunicationDevice(infoArgumentCaptor.capture());
-        assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, infoArgumentCaptor.getValue().getType());
+        var deviceType = infoArgumentCaptor.getValue().getType();
+        if (deviceType != AudioDeviceInfo.TYPE_BUS) { // on automotive, we expect BUS
+            assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, deviceType);
+        }
     }
 
     @SmallTest
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioRouteTransitionTests.java b/tests/src/com/android/server/telecom/tests/CallAudioRouteTransitionTests.java
index 6b9b5c817..c288d1711 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioRouteTransitionTests.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioRouteTransitionTests.java
@@ -172,7 +172,6 @@ public class CallAudioRouteTransitionTests extends TelecomTestCase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        MockitoAnnotations.initMocks(this);
         mHandlerThread = new HandlerThread("CallAudioRouteTransitionTests");
         mHandlerThread.start();
         mContext = mComponentContextFixture.getTestDouble().getApplicationContext();
@@ -344,8 +343,10 @@ public class CallAudioRouteTransitionTests extends TelecomTestCase {
                 ArgumentCaptor<AudioDeviceInfo> infoArgumentCaptor = ArgumentCaptor.forClass(
                         AudioDeviceInfo.class);
                 verify(mockAudioManager).setCommunicationDevice(infoArgumentCaptor.capture());
-                assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER,
-                        infoArgumentCaptor.getValue().getType());
+                var deviceType = infoArgumentCaptor.getValue().getType();
+                if (deviceType != AudioDeviceInfo.TYPE_BUS) { // on automotive, we expect BUS
+                    assertEquals(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, deviceType);
+                }
                 break;
             case OFF:
                 verify(mockAudioManager).clearCommunicationDevice();
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioWatchdogTest.java b/tests/src/com/android/server/telecom/tests/CallAudioWatchdogTest.java
new file mode 100644
index 000000000..4f988f1af
--- /dev/null
+++ b/tests/src/com/android/server/telecom/tests/CallAudioWatchdogTest.java
@@ -0,0 +1,296 @@
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
+ * limitations under the License
+ */
+
+package com.android.server.telecom.tests;
+
+import static android.media.AudioPlaybackConfiguration.PLAYER_STATE_IDLE;
+import static android.media.AudioPlaybackConfiguration.PLAYER_STATE_STARTED;
+
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyLong;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.annotation.NonNull;
+import android.content.ComponentName;
+import android.media.AudioAttributes;
+import android.media.AudioDeviceInfo;
+import android.media.AudioPlaybackConfiguration;
+import android.media.AudioRecordingConfiguration;
+import android.media.IPlayer;
+import android.media.MediaRecorder;
+import android.media.PlayerBase;
+import android.telecom.PhoneAccountHandle;
+import android.util.ArrayMap;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallAudioWatchdog;
+import com.android.server.telecom.ClockProxy;
+import com.android.server.telecom.metrics.CallStats;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+
+import java.util.ArrayList;
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.Map;
+import java.util.Optional;
+
+/**
+ * Tests for {@link com.android.server.telecom.CallAudioWatchdog}.
+ */
+@RunWith(JUnit4.class)
+public class CallAudioWatchdogTest extends TelecomTestCase {
+    private static final String TEST_CALL_ID = "TC@90210";
+    private static final int TEST_APP_1_UID = 10001;
+    private static final int TEST_APP_2_UID = 10002;
+    private static final PhoneAccountHandle TEST_APP_1_HANDLE = new PhoneAccountHandle(
+            new ComponentName("com.app1.package", "class1"), "1");
+    private static final ArrayMap<Integer, PhoneAccountHandle> TEST_UID_TO_PHAC = new ArrayMap<>();
+    private CallAudioWatchdog.PhoneAccountRegistrarProxy mPhoneAccountRegistrarProxy =
+            new CallAudioWatchdog.PhoneAccountRegistrarProxy() {
+                @Override
+                public boolean hasPhoneAccountForUid(int uid) {
+                    return TEST_UID_TO_PHAC.containsKey(uid);
+                }
+
+                @Override
+                public int getUidForPhoneAccountHandle(PhoneAccountHandle handle) {
+                    Optional<Map.Entry<Integer, PhoneAccountHandle>> entry =
+                            TEST_UID_TO_PHAC.entrySet().stream().filter(
+                                    e -> e.getValue().equals(handle)).findFirst();
+                    if (entry.isPresent()) {
+                        return entry.get().getKey();
+                    } else {
+                        return -1;
+                    }
+                }
+            };
+
+    @Mock private ClockProxy mClockProxy;
+    @Mock private TelecomMetricsController mMetricsController;
+    @Mock private CallStats mCallStats;
+    private CallAudioWatchdog mCallAudioWatchdog;
+
+    @Override
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        when(mMetricsController.getCallStats()).thenReturn(mCallStats);
+        when(mClockProxy.elapsedRealtime()).thenReturn(0L);
+        TEST_UID_TO_PHAC.put(TEST_APP_1_UID, TEST_APP_1_HANDLE);
+        mCallAudioWatchdog = new CallAudioWatchdog(mComponentContextFixture.getAudioManager(),
+                mPhoneAccountRegistrarProxy, mClockProxy, null /* mHandler */, mMetricsController);
+    }
+
+    @Override
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Verifies that a new Telecom call added results in a session being added for that call.
+     */
+    @Test
+    public void testAddTelecomCall() {
+        Call mockCall = createMockCall();
+        mCallAudioWatchdog.onCallAdded(mockCall);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+        CallAudioWatchdog.CommunicationSession session = mCallAudioWatchdog
+                .getCommunicationSessions().get(TEST_APP_1_UID);
+        assertFalse(session.hasMediaResources());
+        assertEquals(TEST_CALL_ID, session.getTelecomCall().getId());
+    }
+
+    /**
+     * Verifies tracking of multiple audio sessions.
+     */
+    @Test
+    public void testTrackAudioPlayback() {
+        var client1Idle = makeAudioPlaybackConfiguration(
+                TEST_APP_1_UID, PLAYER_STATE_IDLE, 1);
+        mCallAudioWatchdog.getWatchdogAudioPlayback().onPlaybackConfigChanged(
+                Arrays.asList(client1Idle));
+        assertFalse(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        var client1Playing = makeAudioPlaybackConfiguration(
+                TEST_APP_1_UID, PLAYER_STATE_STARTED, 1);
+        mCallAudioWatchdog.getWatchdogAudioPlayback().onPlaybackConfigChanged(
+                Arrays.asList(client1Playing));
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        var client2Playing = makeAudioPlaybackConfiguration(
+                TEST_APP_1_UID, PLAYER_STATE_STARTED, 2);
+        mCallAudioWatchdog.getWatchdogAudioPlayback().onPlaybackConfigChanged(
+                Arrays.asList(client1Playing, client2Playing));
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        mCallAudioWatchdog.getWatchdogAudioPlayback().onPlaybackConfigChanged(
+                Arrays.asList(client2Playing));
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        mCallAudioWatchdog.getWatchdogAudioPlayback().onPlaybackConfigChanged(
+                Arrays.asList(makeAudioPlaybackConfiguration(
+                        TEST_APP_1_UID, PLAYER_STATE_IDLE, 2)));
+        assertFalse(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+    }
+
+    /**
+     * Verifies ability of the audio watchdog to handle changes to the audio record configs.
+     */
+    @Test
+    public void testTrackAudioRecord() {
+        var client1Recording = makeAudioRecordingConfiguration(TEST_APP_1_UID, 1);
+        var theRecords = Arrays.asList(client1Recording);
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(theRecords);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(theRecords);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        var client2Recording = makeAudioRecordingConfiguration(TEST_APP_1_UID, 2);
+        theRecords = Arrays.asList(client1Recording, client2Recording);
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(theRecords);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(theRecords);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        theRecords = Arrays.asList(client2Recording);
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(theRecords);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(theRecords);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(Collections.EMPTY_LIST);
+        when(mClockProxy.elapsedRealtime()).thenReturn(1000L);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(
+                Collections.EMPTY_LIST);
+        assertFalse(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        // Ensure that a call with telecom support but which did not use Telecom gets logged to
+        // metrics as a non-telecom call.
+        verify(mCallStats).onNonTelecomCallEnd(eq(true), eq(TEST_APP_1_UID), eq(1000L));
+    }
+
+    /**
+     * Verifies ability of the audio watchdog to track non-telecom calls where there is no Telecom
+     * integration.
+     */
+    @Test
+    public void testNonTelecomCallMetricsTracking() {
+        var client1Recording = makeAudioRecordingConfiguration(TEST_APP_2_UID, 1);
+        var theRecords = Arrays.asList(client1Recording);
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(theRecords);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(theRecords);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_2_UID));
+
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(Collections.EMPTY_LIST);
+        when(mClockProxy.elapsedRealtime()).thenReturn(1000L);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(
+                Collections.EMPTY_LIST);
+        assertFalse(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_2_UID));
+
+        // This should log as a non-telecom call with no telecom support.
+        verify(mCallStats).onNonTelecomCallEnd(eq(false), eq(TEST_APP_2_UID), eq(1000L));
+    }
+
+    /**
+     * Verifies that if a call known to Telecom is added, that we don't try to track it in the
+     * non-telecom metrics.
+     */
+    @Test
+    public void testTelecomCallMetricsTracking() {
+        var client1Recording = makeAudioRecordingConfiguration(TEST_APP_1_UID, 1);
+        var theRecords = Arrays.asList(client1Recording);
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(theRecords);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(theRecords);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        Call mockCall = mock(Call.class);
+        when(mockCall.isSelfManaged()).thenReturn(true);
+        when(mockCall.isExternalCall()).thenReturn(false);
+        when(mockCall.getTargetPhoneAccount()).thenReturn(TEST_APP_1_HANDLE);
+        when(mockCall.getId()).thenReturn("90210");
+        mCallAudioWatchdog.onCallAdded(mockCall);
+
+        when(mComponentContextFixture.getAudioManager().getActiveRecordingConfigurations())
+                .thenReturn(Collections.EMPTY_LIST);
+        when(mClockProxy.elapsedRealtime()).thenReturn(1000L);
+        mCallAudioWatchdog.getWatchdogAudioRecordCallack().onRecordingConfigChanged(
+                Collections.EMPTY_LIST);
+        assertTrue(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        mCallAudioWatchdog.onCallRemoved(mockCall);
+        assertFalse(mCallAudioWatchdog.getCommunicationSessions().containsKey(TEST_APP_1_UID));
+
+        // We should not log a non-telecom call.  Note; we are purposely NOT trying to check if a
+        // Telecom call metric is logged here since that is done elsewhere and this unit test is
+        // only testing CallAudioWatchdog in isolation.
+        verify(mCallStats, never()).onNonTelecomCallEnd(anyBoolean(), anyInt(), anyLong());
+
+    }
+
+    private AudioPlaybackConfiguration makeAudioPlaybackConfiguration(int clientUid,
+            int playerState, int playerInterfaceId) {
+        AudioAttributes attributes = new AudioAttributes.Builder()
+                             .setUsage(AudioAttributes.USAGE_VOICE_COMMUNICATION)
+                             .setContentType(AudioAttributes.CONTENT_TYPE_SPEECH)
+                             .build();
+        AudioPlaybackConfiguration configuration = mock(AudioPlaybackConfiguration.class);
+        when(configuration.getAudioAttributes()).thenReturn(attributes);
+        when(configuration.getClientUid()).thenReturn(clientUid);
+        when(configuration.getPlayerState()).thenReturn(playerState);
+        when(configuration.getPlayerInterfaceId()).thenReturn(playerInterfaceId);
+        return configuration;
+    }
+
+    private AudioRecordingConfiguration makeAudioRecordingConfiguration(int clientUid,
+            int clientAudioSessionId) {
+        AudioRecordingConfiguration configuration = mock(AudioRecordingConfiguration.class);
+        when(configuration.getClientUid()).thenReturn(clientUid);
+        when(configuration.getClientAudioSource()).thenReturn(
+                MediaRecorder.AudioSource.VOICE_COMMUNICATION);
+        when(configuration.getClientAudioSessionId()).thenReturn(clientAudioSessionId);
+        return configuration;
+    }
+
+    private Call createMockCall() {
+        Call mockCall = mock(Call.class);
+        when(mockCall.getId()).thenReturn(TEST_CALL_ID);
+        when(mockCall.isSelfManaged()).thenReturn(true);
+        when(mockCall.getTargetPhoneAccount()).thenReturn(TEST_APP_1_HANDLE);
+        return mockCall;
+    }
+}
diff --git a/tests/src/com/android/server/telecom/tests/CallLogManagerTest.java b/tests/src/com/android/server/telecom/tests/CallLogManagerTest.java
index cb04dc3f1..fcb8966a0 100644
--- a/tests/src/com/android/server/telecom/tests/CallLogManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallLogManagerTest.java
@@ -588,7 +588,8 @@ public class CallLogManagerTest extends TelecomTestCase {
         assertEquals(insertedValues.getAsString(CallLog.Calls.NUMBER),
                 TEL_PHONEHANDLE.getSchemeSpecificPart());
         assertEquals(insertedValues.getAsString(CallLog.Calls.POST_DIAL_DIGITS), POST_DIAL_STRING);
-        String expectedNumber = PhoneNumberUtils.formatNumber(VIA_NUMBER_STRING, "US");
+        String expectedNumber = PhoneNumberUtils.formatNumber(VIA_NUMBER_STRING,
+                mCallLogManager.getCountryIso());
         assertEquals(insertedValues.getAsString(Calls.VIA_NUMBER), expectedNumber);
     }
 
diff --git a/tests/src/com/android/server/telecom/tests/CallSequencingTests.java b/tests/src/com/android/server/telecom/tests/CallSequencingTests.java
new file mode 100644
index 000000000..fc476f884
--- /dev/null
+++ b/tests/src/com/android/server/telecom/tests/CallSequencingTests.java
@@ -0,0 +1,768 @@
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
+ * limitations under the License
+ */
+
+package com.android.server.telecom.tests;
+
+import static com.android.server.telecom.CallsManager.CALL_FILTER_ALL;
+import static com.android.server.telecom.CallsManager.ONGOING_CALL_STATES;
+
+import static junit.framework.Assert.assertNotNull;
+import static junit.framework.TestCase.fail;
+
+import static org.junit.Assert.assertEquals;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.ArgumentMatchers.anyBoolean;
+import static org.mockito.ArgumentMatchers.anyInt;
+import static org.mockito.ArgumentMatchers.anyString;
+import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+import static org.junit.Assert.assertTrue;
+import static org.junit.Assert.assertFalse;
+
+import android.content.ComponentName;
+import android.content.Context;
+import android.content.Intent;
+import android.net.Uri;
+import android.os.Bundle;
+import android.os.OutcomeReceiver;
+import android.os.PersistableBundle;
+import android.os.UserHandle;
+import android.telecom.CallAttributes;
+import android.telecom.CallException;
+import android.telecom.Connection;
+import android.telecom.DisconnectCause;
+import android.telecom.PhoneAccount;
+import android.telecom.PhoneAccountHandle;
+import android.telephony.CarrierConfigManager;
+
+import androidx.test.filters.SmallTest;
+
+import com.android.server.telecom.Analytics;
+import com.android.server.telecom.AnomalyReporterAdapter;
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallState;
+import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.ClockProxy;
+import com.android.server.telecom.ConnectionServiceFocusManager;
+import com.android.server.telecom.MmiUtils;
+import com.android.server.telecom.PhoneAccountRegistrar;
+import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.callsequencing.CallSequencingController;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.voip.OutgoingCallTransactionSequencing;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+import com.android.server.telecom.stats.CallFailureCause;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.junit.runners.JUnit4;
+import org.mockito.Mock;
+
+import java.util.Arrays;
+import java.util.Collections;
+import java.util.List;
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.CountDownLatch;
+import java.util.concurrent.TimeUnit;
+
+@RunWith(JUnit4.class)
+public class CallSequencingTests extends TelecomTestCase {
+    private static final long SEQUENCING_TIMEOUT_MS = 2000L;
+    private static final PhoneAccountHandle mHandle1 = new PhoneAccountHandle(
+            new ComponentName("foo", "bar"), "1");
+    private static final PhoneAccountHandle mHandle2 = new PhoneAccountHandle(
+            new ComponentName("bar", "foo"), "2");
+    private static final String TEST_NAME = "Alan Turing";
+    private static final Uri TEST_URI = Uri.fromParts("tel", "abc", "123");
+    private static final String ACTIVE_CALL_ID = "TC@1";
+    private static final String NEW_CALL_ID = "TC@2";
+
+    private CallSequencingController mController;
+    @Mock
+    private CallsManager mCallsManager;
+    @Mock Context mContext;
+    @Mock ClockProxy mClockProxy;
+    @Mock AnomalyReporterAdapter mAnomalyReporter;
+    @Mock Timeouts.Adapter mTimeoutsAdapter;
+    @Mock TelecomMetricsController mMetricsController;
+    @Mock MmiUtils mMmiUtils;
+    @Mock
+    ConnectionServiceFocusManager mConnectionServiceFocusManager;
+    @Mock Call mActiveCall;
+    @Mock Call mHeldCall;
+    @Mock Call mNewCall;
+    @Mock Call mRingingCall;
+
+    @Override
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        when(mFeatureFlags.enableCallSequencing()).thenReturn(true);
+        mController = new CallSequencingController(mCallsManager, mContext, mClockProxy,
+                mAnomalyReporter, mTimeoutsAdapter, mMetricsController, mMmiUtils, mFeatureFlags);
+
+        when(mActiveCall.getState()).thenReturn(CallState.ACTIVE);
+        when(mRingingCall.getState()).thenReturn(CallState.RINGING);
+        when(mHeldCall.getState()).thenReturn(CallState.ON_HOLD);
+
+        when(mActiveCall.getId()).thenReturn(ACTIVE_CALL_ID);
+        when(mNewCall.getId()).thenReturn(NEW_CALL_ID);
+    }
+
+    @Override
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+
+    @Test
+    @SmallTest
+    public void testTransactionOutgoingCall_CallNotPermitted() {
+        String callingPkg = "testPkg";
+        CallAttributes outgoingCallAttributes = getOutgoingCallAttributes();
+
+        // Outgoing call is not permitted
+        when(mCallsManager.isOutgoingCallPermitted(mHandle1)).thenReturn(false);
+        CompletableFuture<CallTransaction> transactionFuture = mController
+                .createTransactionalOutgoingCall("callId", outgoingCallAttributes,
+                        new Bundle(), callingPkg);
+        OutgoingCallTransactionSequencing transaction = (OutgoingCallTransactionSequencing)
+                transactionFuture.getNow(null);
+        assertNotNull(transaction);
+        assertTrue(transaction.getCallNotPermitted());
+
+        // Call future is null
+        when(mCallsManager.isOutgoingCallPermitted(mHandle1)).thenReturn(true);
+        when(mCallsManager.startOutgoingCall(any(Uri.class), any(PhoneAccountHandle.class),
+                any(Bundle.class), any(UserHandle.class), any(Intent.class), anyString()))
+                .thenReturn(null);
+        transactionFuture = mController
+                .createTransactionalOutgoingCall("callId", outgoingCallAttributes,
+                        new Bundle(), callingPkg);
+        transaction = (OutgoingCallTransactionSequencing) transactionFuture
+                .getNow(null);
+        assertNotNull(transaction);
+        assertTrue(transaction.getCallNotPermitted());
+    }
+
+    @Test
+    @SmallTest
+    public void testTransactionOutgoingCall() {
+        String callingPkg = "testPkg";
+        CallAttributes outgoingCallAttributes = getOutgoingCallAttributes();
+
+        when(mCallsManager.isOutgoingCallPermitted(mHandle1)).thenReturn(true);
+        when(mCallsManager.startOutgoingCall(any(Uri.class), any(PhoneAccountHandle.class),
+                any(Bundle.class), any(UserHandle.class), any(Intent.class), anyString()))
+                .thenReturn(CompletableFuture.completedFuture(mNewCall));
+        CompletableFuture<CallTransaction> transactionFuture = mController
+                .createTransactionalOutgoingCall("callId", outgoingCallAttributes,
+                        new Bundle(), callingPkg);
+        try {
+            OutgoingCallTransactionSequencing transaction = (OutgoingCallTransactionSequencing)
+                    transactionFuture.get(SEQUENCING_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+            assertNotNull(transaction);
+            assertFalse(transaction.getCallNotPermitted());
+        } catch (Exception e) {
+            fail("Failed to retrieve future in allocated time (" + SEQUENCING_TIMEOUT_MS + ").");
+        }
+    }
+
+    @SmallTest
+    @Test
+    public void testAnswerCall() {
+        // This will allow holdActiveCallForNewCallWithSequencing to immediately return true
+        setActiveCallFocus(null);
+        mController.answerCall(mNewCall, 0, CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS))
+                .requestFocusActionAnswerCall(eq(mNewCall), eq(0));
+    }
+
+    @SmallTest
+    @Test
+    public void testAnswerCallFail() {
+        setupHoldActiveCallForNewCallFailMocks();
+        mController.answerCall(mNewCall, 0, CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS).times(0))
+                .requestFocusActionAnswerCall(eq(mNewCall), eq(0));
+    }
+
+    @SmallTest
+    @Test
+    public void testAnswerCallAcceptedFromTelecom() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(true);
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(true));
+
+        when(mHeldCall.isSelfManaged()).thenReturn(false);
+        when(mNewCall.isSelfManaged()).thenReturn(true);
+        mController.answerCall(mNewCall, 0, CallsManager.REQUEST_ORIGIN_TELECOM_DISAMBIGUATION);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS).times(1))
+                .requestFocusActionAnswerCall(eq(mNewCall), eq(0));
+    }
+
+    @SmallTest
+    @Test
+    public void testSetSelfManagedCallActive() {
+        // This will allow holdActiveCallForNewCallWithSequencing to immediately return true
+        setActiveCallFocus(null);
+        mController.handleSetSelfManagedCallActive(mNewCall);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS))
+                .requestActionSetActiveCall(eq(mNewCall), anyString());
+    }
+
+    @SmallTest
+    @Test
+    public void testSetSelfManagedCallActiveFail() {
+        setupHoldActiveCallForNewCallFailMocks();
+        mController.handleSetSelfManagedCallActive(mNewCall);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS).times(0))
+                .requestActionSetActiveCall(eq(mNewCall), anyString());
+    }
+
+    @SmallTest
+    @Test
+    public void testTransactionHoldActiveCallForNewCall() throws InterruptedException {
+        // This will allow holdActiveCallForNewCallWithSequencing to immediately return true
+        setActiveCallFocus(null);
+        CountDownLatch latch = new CountDownLatch(1);
+        OutcomeReceiver<Boolean, CallException> callback = new OutcomeReceiver<>() {
+            @Override
+            public void onResult(Boolean result) {
+                // Expected result
+                latch.countDown();
+            }
+            @Override
+            public void onError(CallException exception) {
+            }
+        };
+        verifyTransactionHoldActiveCallForNewCall(callback, latch);
+    }
+
+    @SmallTest
+    @Test
+    public void testTransactionHoldActiveCallForNewCallFail() {
+        setupHoldActiveCallForNewCallFailMocks();
+        CountDownLatch latch = new CountDownLatch(1);
+        OutcomeReceiver<Boolean, CallException> callback = new OutcomeReceiver<>() {
+            @Override
+            public void onResult(Boolean result) {
+            }
+
+            @Override
+            public void onError(CallException exception) {
+                // Expected result
+                latch.countDown();
+            }
+        };
+        verifyTransactionHoldActiveCallForNewCall(callback, latch);
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_NoActiveCall() {
+        setActiveCallFocus(null);
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertTrue(waitForFutureResult(resultFuture, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_CanHold() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(true);
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(true));
+
+        // Cross phone account case (sequencing enabled)
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertTrue(waitForFutureResult(resultFuture, false));
+
+        // Same phone account case
+        setPhoneAccounts(mNewCall, mActiveCall, true);
+        assertTrue(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        resultFuture = mController.holdActiveCallForNewCallWithSequencing(mNewCall,
+                CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertTrue(waitForFutureResult(resultFuture, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_SupportsHold() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(true);
+        when(mCallsManager.getFirstCallWithState(anyInt())).thenReturn(mHeldCall);
+        when(mHeldCall.isSelfManaged()).thenReturn(true);
+        when(mNewCall.isSelfManaged()).thenReturn(false);
+        when(mHeldCall.disconnect()).thenReturn(CompletableFuture.completedFuture(true));
+        when(mActiveCall.hold()).thenReturn(CompletableFuture.completedFuture(true));
+
+        // Verify that we abort transaction when there's a new (VOIP) call and we're trying to
+        // disconnect the active (carrier) call.
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mHeldCall, timeout(SEQUENCING_TIMEOUT_MS)).disconnect();
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).hold();
+        verify(mNewCall).increaseHeldByThisCallCount();
+        assertTrue(waitForFutureResult(resultFuture, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_SupportsHold_NoHeldCall() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(true);
+        when(mCallsManager.getFirstCallWithState(anyInt())).thenReturn(null);
+        when(mActiveCall.hold()).thenReturn(CompletableFuture.completedFuture(true));
+
+        // Cross phone account case (sequencing enabled)
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).hold();
+        verify(mNewCall).increaseHeldByThisCallCount();
+        assertTrue(waitForFutureResult(resultFuture, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_DoesNotSupportHold_Disconnect() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.getCalls()).thenReturn(Collections.singletonList(mActiveCall));
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(false);
+        when(mActiveCall.disconnect(anyString())).thenReturn(
+                CompletableFuture.completedFuture(true));
+        when(mActiveCall.isEmergencyCall()).thenReturn(false);
+
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).disconnect(anyString());
+        assertTrue(waitForFutureResult(resultFuture, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCallFail_SupportsHold_VoipPstn() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(true);
+        when(mCallsManager.getFirstCallWithState(anyInt())).thenReturn(mHeldCall);
+        when(mHeldCall.isSelfManaged()).thenReturn(false);
+        when(mNewCall.isSelfManaged()).thenReturn(true);
+
+        // Verify that we abort transaction when there's a new (VOIP) call and we're trying to
+        // disconnect the active (carrier) call.
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertFalse(waitForFutureResult(resultFuture, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCall_DoesNotSupportHold_SameManagedPA() {
+        setPhoneAccounts(mNewCall, mActiveCall, true);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(false);
+        when(mActiveCall.isEmergencyCall()).thenReturn(false);
+
+        assertTrue(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertTrue(waitForFutureResult(resultFuture, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCallFail_DoesNotSupportHold_Reject() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(false);
+        when(mNewCall.reject(anyBoolean(), anyString(), anyString()))
+                .thenReturn(CompletableFuture.completedFuture(true));
+        when(mActiveCall.isEmergencyCall()).thenReturn(true);
+
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        verify(mNewCall, timeout(SEQUENCING_TIMEOUT_MS)).reject(
+                anyBoolean(), anyString(), anyString());
+        assertFalse(waitForFutureResult(resultFuture, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testHoldCallForNewCallFail_DoesNotSupportHold_Abort() {
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.supportsHold(mActiveCall)).thenReturn(false);
+        when(mActiveCall.isEmergencyCall()).thenReturn(false);
+        when(mActiveCall.isSelfManaged()).thenReturn(false);
+        when(mNewCall.isSelfManaged()).thenReturn(true);
+
+        assertFalse(mController.arePhoneAccountsSame(mNewCall, mActiveCall));
+        CompletableFuture<Boolean> resultFuture = mController
+                .holdActiveCallForNewCallWithSequencing(mNewCall,
+                        CallsManager.REQUEST_ORIGIN_UNKNOWN);
+        assertFalse(waitForFutureResult(resultFuture, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testUnholdCallNoActiveCall() {
+        setActiveCallFocus(null);
+        mController.unholdCall(mHeldCall);
+        verify(mCallsManager).requestActionUnholdCall(eq(mHeldCall), eq(null));
+    }
+
+    @Test
+    @SmallTest
+    public void testUnholdCallSwapCase() {
+        when(mActiveCall.can(eq(Connection.CAPABILITY_SUPPORT_HOLD))).thenReturn(true);
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(true));
+        when(mActiveCall.isLocallyDisconnecting()).thenReturn(false);
+        setPhoneAccounts(mHeldCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+
+        mController.unholdCall(mHeldCall);
+        assertFalse(mController.arePhoneAccountsSame(mActiveCall, mHeldCall));
+        verify(mActiveCall).hold(anyString());
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS))
+                .requestActionUnholdCall(eq(mHeldCall), eq(ACTIVE_CALL_ID));
+    }
+
+    @Test
+    @SmallTest
+    public void testUnholdCallFail_DoesNotSupportHold() {
+        when(mActiveCall.can(eq(Connection.CAPABILITY_SUPPORT_HOLD))).thenReturn(false);
+        when(mActiveCall.isEmergencyCall()).thenReturn(true);
+        when(mActiveCall.isLocallyDisconnecting()).thenReturn(false);
+        setPhoneAccounts(mHeldCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+
+        // Emergency call case
+        mController.unholdCall(mHeldCall);
+        assertFalse(mController.arePhoneAccountsSame(mActiveCall, mHeldCall));
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS).times(0))
+                .requestActionUnholdCall(eq(mHeldCall), anyString());
+    }
+
+    @Test
+    @SmallTest
+    public void testUnholdFail() {
+        // Fail the hold.
+        when(mActiveCall.can(eq(Connection.CAPABILITY_SUPPORT_HOLD))).thenReturn(true);
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(false));
+        when(mActiveCall.isLocallyDisconnecting()).thenReturn(false);
+        // Use different phone accounts so that the sequencing code path is hit.
+        setPhoneAccounts(mHeldCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+
+        mController.unholdCall(mHeldCall);
+        assertFalse(mController.arePhoneAccountsSame(mActiveCall, mHeldCall));
+        verify(mActiveCall).hold(anyString());
+        // Verify unhold is never reached.
+        verify(mCallsManager, never())
+                .requestActionUnholdCall(eq(mHeldCall), anyString());
+    }
+
+    @SmallTest
+    @Test
+    public void testMakeRoomForOutgoingEmergencyCall_SamePkg() {
+        // Ensure that the live call and emergency call are from the same pkg.
+        when(mActiveCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(mNewCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(mRingingCall.getTargetPhoneAccount()).thenReturn(mHandle2);
+        setupMakeRoomForOutgoingEmergencyCallMocks();
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(true, mNewCall);
+        verify(mRingingCall, timeout(SEQUENCING_TIMEOUT_MS))
+                .reject(anyBoolean(), eq(null), anyString());
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).hold(anyString());
+        assertTrue(waitForFutureResult(future, false));
+    }
+
+    @SmallTest
+    @Test
+    public void testMakeRoomForOutgoingEmergencyCall_CanHold() {
+        // Ensure that the live call and emergency call are from different pkgs.
+        when(mActiveCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(mNewCall.getTargetPhoneAccount()).thenReturn(mHandle2);
+        when(mRingingCall.getTargetPhoneAccount()).thenReturn(mHandle2);
+        setupMakeRoomForOutgoingEmergencyCallMocks();
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(true, mNewCall);
+        verify(mRingingCall, timeout(SEQUENCING_TIMEOUT_MS))
+                .reject(anyBoolean(), eq(null), anyString());
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).hold(anyString());
+        assertTrue(waitForFutureResult(future, false));
+    }
+
+    @SmallTest
+    @Test
+    public void testMakeRoomForOutgoingEmergencyCall_DoesNotSupportHoldingEmergency() {
+        setupMakeRoomForOutgoingEmergencyCallMocks();
+        when(mCallsManager.getCalls()).thenReturn(List.of(mActiveCall, mRingingCall));
+        when(mActiveCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        // Set the KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL carrier config to false for the active
+        // call's phone account.
+        PersistableBundle bundle = new PersistableBundle();
+        bundle.putBoolean(CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, false);
+        when(mCallsManager.getCarrierConfigForPhoneAccount(eq(mHandle1))).thenReturn(bundle);
+        when(mNewCall.getTargetPhoneAccount()).thenReturn(mHandle2);
+        when(mRingingCall.getTargetPhoneAccount()).thenReturn(mHandle2);
+
+        mController.makeRoomForOutgoingCall(true, mNewCall);
+        // Verify that the active call got disconnected as it doesn't support holding for emergency.
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).disconnect(anyString());
+    }
+
+    @Test
+    @SmallTest
+    public void testMakeRoomForOutgoingCall() {
+        setupMakeRoomForOutgoingCallMocks();
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(true));
+        Analytics.CallInfo newCallAnalytics = mock(Analytics.CallInfo.class);
+        Analytics.CallInfo activeCallAnalytics = mock(Analytics.CallInfo.class);
+        when(mNewCall.getAnalytics()).thenReturn(newCallAnalytics);
+        when(mActiveCall.getAnalytics()).thenReturn(activeCallAnalytics);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(true);
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(false, mNewCall);
+        verify(mActiveCall, timeout(SEQUENCING_TIMEOUT_MS)).hold(anyString());
+        verify(newCallAnalytics).setCallIsAdditional(eq(true));
+        verify(activeCallAnalytics).setCallIsInterrupted(eq(true));
+        assertTrue(waitForFutureResult(future, false));
+    }
+
+    @Test
+    @SmallTest
+    public void testMakeRoomForOutgoingCallFail_MaxCalls() {
+        setupMakeRoomForOutgoingCallMocks();
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.hasMaximumManagedHoldingCalls(mNewCall)).thenReturn(true);
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(false, mNewCall);
+        verify(mNewCall).setStartFailCause(eq(CallFailureCause.MAX_OUTGOING_CALLS));
+        assertFalse(waitForFutureResult(future, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testMakeRoomForOutgoingCallFail_CannotHold() {
+        setupMakeRoomForOutgoingCallMocks();
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(false);
+        when(mCallsManager.hasMaximumManagedHoldingCalls(mNewCall)).thenReturn(false);
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(false, mNewCall);
+        verify(mNewCall).setStartFailCause(eq(CallFailureCause.CANNOT_HOLD_CALL));
+        assertFalse(waitForFutureResult(future, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testMakeRoomForOutgoingCallFail_RingingCall() {
+        when(mNewCall.isSelfManaged()).thenReturn(false);
+        when(mCallsManager.hasManagedRingingOrSimulatedRingingCall()).thenReturn(true);
+
+        CompletableFuture<Boolean> future = mController.makeRoomForOutgoingCall(false, mNewCall);
+        assertFalse(waitForFutureResult(future, true));
+    }
+
+    @Test
+    @SmallTest
+    public void testDisconnectCallSuccess() {
+        when(mActiveCall.disconnect()).thenReturn(CompletableFuture.completedFuture(true));
+        int previousState = CallState.ACTIVE;
+        mController.disconnectCall(mActiveCall, previousState);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS))
+                .processDisconnectCallAndCleanup(eq(mActiveCall), eq(previousState));
+    }
+
+    @Test
+    @SmallTest
+    public void testDisconnectCallFail() {
+        when(mActiveCall.disconnect()).thenReturn(CompletableFuture.completedFuture(false));
+        int previousState = CallState.ACTIVE;
+        mController.disconnectCall(mActiveCall, previousState);
+        verify(mCallsManager, timeout(SEQUENCING_TIMEOUT_MS).times(0))
+                .processDisconnectCallAndCleanup(eq(mActiveCall), eq(previousState));
+    }
+
+    @Test
+    @SmallTest
+    public void testMmiCodeRestrictionReject() {
+        // Verify that when calls are detected across other phone accounts,
+        // that the MMI code is rejected.
+        when(mNewCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(mCallsManager.getNumCallsWithStateWithoutHandle(CALL_FILTER_ALL, mNewCall,
+                mHandle1, ONGOING_CALL_STATES)).thenReturn(1);
+        assertTrue(mController.hasMmiCodeRestriction(mNewCall));
+        verify(mNewCall).setOverrideDisconnectCauseCode(any(DisconnectCause.class));
+    }
+
+    @Test
+    @SmallTest
+    public void testMmiCodeRestrictionAllow() {
+        // Verify that when no calls are detected across other phone accounts,
+        // that the MMI code is allowed.
+        when(mNewCall.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(mCallsManager.getNumCallsWithStateWithoutHandle(CALL_FILTER_ALL, mNewCall,
+                mHandle1, ONGOING_CALL_STATES)).thenReturn(0);
+        assertFalse(mController.hasMmiCodeRestriction(mNewCall));
+        verify(mNewCall, times(0)).setOverrideDisconnectCauseCode(any(DisconnectCause.class));
+    }
+
+    /* Helpers */
+    private void setPhoneAccounts(Call call1, Call call2, boolean useSamePhoneAccount) {
+        when(call1.getTargetPhoneAccount()).thenReturn(mHandle1);
+        when(call2.getTargetPhoneAccount()).thenReturn(useSamePhoneAccount ? mHandle1 : mHandle2);
+    }
+
+    private void setActiveCallFocus(Call call) {
+        when(mCallsManager.getConnectionServiceFocusManager())
+                .thenReturn(mConnectionServiceFocusManager);
+        when(mConnectionServiceFocusManager.getCurrentFocusCall()).thenReturn(call);
+    }
+
+    private void setupMakeRoomForOutgoingEmergencyCallMocks() {
+        when(mNewCall.isEmergencyCall()).thenReturn(true);
+        when(mCallsManager.hasRingingOrSimulatedRingingCall()).thenReturn(true);
+        when(mCallsManager.getRingingOrSimulatedRingingCall()).thenReturn(mRingingCall);
+        when(mCallsManager.hasMaximumLiveCalls(mNewCall)).thenReturn(true);
+        when(mCallsManager.getFirstCallWithLiveState()).thenReturn(mActiveCall);
+        when(mCallsManager.hasMaximumOutgoingCalls(mNewCall)).thenReturn(false);
+        when(mCallsManager.hasMaximumManagedHoldingCalls(mNewCall)).thenReturn(false);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(true);
+
+        // Setup analytics mocks
+        setupCallAnalytics(Arrays.asList(mNewCall, mActiveCall, mRingingCall));
+
+        // Setup ecall related checks
+        setupEmergencyCallPaCapabilities();
+        setupCarrierConfigAllowEmergencyCallHold();
+
+        // Setup CompletableFuture mocking for call actions
+        when(mRingingCall.reject(anyBoolean(), eq(null), anyString()))
+                .thenReturn(CompletableFuture.completedFuture(true));
+        when(mActiveCall.hold(anyString())).thenReturn(
+                CompletableFuture.completedFuture(true));
+    }
+
+    private void setupEmergencyCallPaCapabilities() {
+        PhoneAccount pa = mock(PhoneAccount.class);
+        PhoneAccountRegistrar paRegistrar = mock(PhoneAccountRegistrar.class);
+        when(mCallsManager.getPhoneAccountRegistrar()).thenReturn(paRegistrar);
+        when(paRegistrar.getPhoneAccountUnchecked(any(PhoneAccountHandle.class))).thenReturn(pa);
+        when(pa.getCapabilities()).thenReturn(PhoneAccount.CAPABILITY_PLACE_EMERGENCY_CALLS);
+    }
+
+    private void setupCarrierConfigAllowEmergencyCallHold() {
+        PersistableBundle bundle = mock(PersistableBundle.class);
+        when(mCallsManager.getCarrierConfigForPhoneAccount(any(PhoneAccountHandle.class)))
+                .thenReturn(bundle);
+        when(bundle.getBoolean(
+                CarrierConfigManager.KEY_ALLOW_HOLD_CALL_DURING_EMERGENCY_BOOL, true))
+                .thenReturn(true);
+    }
+
+    private void setupMakeRoomForOutgoingCallMocks() {
+        when(mCallsManager.hasMaximumLiveCalls(mNewCall)).thenReturn(true);
+        when(mCallsManager.getFirstCallWithLiveState()).thenReturn(mActiveCall);
+        setPhoneAccounts(mActiveCall, mNewCall, false);
+        when(mActiveCall.isConference()).thenReturn(false);
+        when(mCallsManager.hasMaximumOutgoingCalls(mNewCall)).thenReturn(false);
+    }
+
+    private void setupHoldActiveCallForNewCallFailMocks() {
+        // Setup holdActiveCallForNewCallWithSequencing to fail.
+        setPhoneAccounts(mNewCall, mActiveCall, false);
+        setActiveCallFocus(mActiveCall);
+        when(mCallsManager.canHold(mActiveCall)).thenReturn(true);
+        when(mActiveCall.hold(anyString())).thenReturn(CompletableFuture.completedFuture(false));
+    }
+
+    private void verifyTransactionHoldActiveCallForNewCall(
+            OutcomeReceiver<Boolean, CallException> callback, CountDownLatch latch) {
+        mController.transactionHoldPotentialActiveCallForNewCallSequencing(mNewCall, callback);
+        while (latch.getCount() > 0) {
+            try {
+                latch.await(SEQUENCING_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+            } catch (InterruptedException e) {
+                // do nothing
+            }
+        }
+        assertEquals(latch.getCount(), 0);
+    }
+
+    private CallAttributes getOutgoingCallAttributes() {
+        return new CallAttributes.Builder(mHandle1,
+                CallAttributes.DIRECTION_OUTGOING, TEST_NAME, TEST_URI)
+                .setCallType(CallAttributes.AUDIO_CALL)
+                .setCallCapabilities(CallAttributes.SUPPORTS_SET_INACTIVE)
+                .build();
+    }
+
+    private void setupCallAnalytics(List<Call> calls) {
+        for (Call call: calls) {
+            Analytics.CallInfo analyticsInfo = mock(Analytics.CallInfo.class);
+            when(call.getAnalytics()).thenReturn(analyticsInfo);
+        }
+    }
+
+    private boolean waitForFutureResult(CompletableFuture<Boolean> future, boolean defaultValue) {
+        boolean result = defaultValue;
+        try {
+            result = future.get(SEQUENCING_TIMEOUT_MS, TimeUnit.MILLISECONDS);
+        } catch (Exception e) {
+            // Pass through
+        }
+        return result;
+    }
+}
+
diff --git a/tests/src/com/android/server/telecom/tests/CallTest.java b/tests/src/com/android/server/telecom/tests/CallTest.java
index 3a7a82207..b2cdd7de4 100644
--- a/tests/src/com/android/server/telecom/tests/CallTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallTest.java
@@ -999,6 +999,7 @@ public class CallTest extends TelecomTestCase {
         @Test
     @SmallTest
     public void testOnConnectionEventNotifiesListener() {
+        when(mFeatureFlags.enableCallSequencing()).thenReturn(true);
         Call.Listener listener = mock(Call.Listener.class);
         Call call = createCall("1");
         call.addListener(listener);
@@ -1017,6 +1018,9 @@ public class CallTest extends TelecomTestCase {
         call.onConnectionEvent(Connection.EVENT_CALL_SWITCH_FAILED, null);
         verify(listener).onCallSwitchFailed(call);
 
+        call.onConnectionEvent(Connection.EVENT_CALL_RESUME_FAILED, null);
+        verify(listener).onCallResumeFailed(call);
+
         final int d2dType = 1;
         final int d2dValue = 2;
         final Bundle d2dExtras = new Bundle();
diff --git a/tests/src/com/android/server/telecom/tests/CallerInfoLookupHelperTest.java b/tests/src/com/android/server/telecom/tests/CallerInfoLookupHelperTest.java
index 614ef7116..645e2e45b 100644
--- a/tests/src/com/android/server/telecom/tests/CallerInfoLookupHelperTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallerInfoLookupHelperTest.java
@@ -116,7 +116,7 @@ public class CallerInfoLookupHelperTest extends TelecomTestCase {
                 CallerInfoLookupHelper.OnQueryCompleteListener.class);
         mCallerInfoLookupHelper.startLookup(Uri.EMPTY, listener);
 
-        verify(listener).onCallerInfoQueryComplete(eq(Uri.EMPTY), isNull(CallerInfo.class));
+        verify(listener).onCallerInfoQueryComplete(eq(Uri.EMPTY), isNull());
         verifyProperCleanup();
     }
 
diff --git a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
index 79fd3d501..7f1f1ec13 100644
--- a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
@@ -103,6 +103,8 @@ import com.android.server.telecom.CallEndpointControllerFactory;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallerInfoLookupHelper;
 import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallSequencingController;
+import com.android.server.telecom.callsequencing.CallsManagerCallSequencingAdapter;
 import com.android.server.telecom.ClockProxy;
 import com.android.server.telecom.ConnectionServiceFocusManager;
 import com.android.server.telecom.ConnectionServiceFocusManager.ConnectionServiceFocusManagerFactory;
@@ -199,7 +201,8 @@ public class CallsManagerTest extends TelecomTestCase {
     private static final PhoneAccountHandle SELF_MANAGED_2_HANDLE = new PhoneAccountHandle(
             ComponentName.unflattenFromString("com.baz/.Self2"), "Self2");
     private static final PhoneAccountHandle WORK_HANDLE = new PhoneAccountHandle(
-            ComponentName.unflattenFromString("com.foo/.Blah"), "work", new UserHandle(10));
+            ComponentName.unflattenFromString("com.foo/.Blah"), "work",
+            new UserHandle(SECONDARY_USER_ID));
     private static final PhoneAccountHandle SELF_MANAGED_W_CUSTOM_HANDLE = new PhoneAccountHandle(
             new ComponentName(TEST_PACKAGE_NAME, "class"), "1", TEST_USER_HANDLE);
     private static final PhoneAccount SIM_1_ACCOUNT = new PhoneAccount.Builder(SIM_1_HANDLE, "Sim1")
@@ -3044,9 +3047,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is no active call to place
-     * on hold.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is no active call to
+     * place on hold.
      */
     @MediumTest
     @Test
@@ -3068,8 +3071,8 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onError when there is an active call that
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onError when there is an active call that
      * cannot be held, and it's a CallControlRequest.
      */
     @MediumTest
@@ -3086,9 +3089,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is a holdable call and
-     * it's a CallControlRequest.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is a holdable call
+     * and it's a CallControlRequest.
      */
     @MediumTest
     @Test
@@ -3105,9 +3108,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call that
-     * supports hold, and it's a CallControlRequest.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call
+     * that supports hold, and it's a CallControlRequest.
      */
     @MediumTest
     @Test
@@ -3124,9 +3127,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call that
-     * supports hold + can hold, and it's a CallControlRequest.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call
+     * that supports hold + can hold, and it's a CallControlRequest.
      */
     @MediumTest
     @Test
@@ -3145,9 +3148,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call that
-     * supports hold + can hold, and it's a CallControlCallbackRequest.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active call
+     * that supports hold + can hold, and it's a CallControlCallbackRequest.
      */
     @MediumTest
     @Test
@@ -3165,9 +3168,9 @@ public class CallsManagerTest extends TelecomTestCase {
 
     /**
      * Verify that
-     * {@link CallsManager#transactionHoldPotentialActiveCallForNewCall(Call, boolean,
-     * OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active unholdable call,
-     * and it's a CallControlCallbackRequest.
+     * {@link CallsManagerCallSequencingAdapter#transactionHoldPotentialActiveCallForNewCall(Call,
+     * boolean, OutcomeReceiver)}s OutcomeReceiver returns onResult when there is an active
+     * unholdable call, and it's a CallControlCallbackRequest.
      */
     @MediumTest
     @Test
@@ -3775,6 +3778,66 @@ public class CallsManagerTest extends TelecomTestCase {
         inOrder.verify(call).setState(eq(CallState.RINGING), anyString());
     }
 
+    @SmallTest
+    @Test
+    public void testSimultaneousCallType() {
+        when(mFeatureFlags.enableCallSequencing()).thenReturn(true);
+        // Setup CallsManagerCallSequencingAdapter
+        CallSequencingController sequencingController = mock(CallSequencingController.class);
+        CallAudioManager callAudioManager = mock(CallAudioManager.class);
+        CallsManagerCallSequencingAdapter adapter = new CallsManagerCallSequencingAdapter(
+                mCallsManager, mContext, sequencingController, callAudioManager, mFeatureFlags);
+        mCallsManager.setCallSequencingAdapter(adapter);
+        // Explicitly disable simultaneous calling
+        TelephonyManager mockTelephonyManager = mComponentContextFixture.getTelephonyManager();
+        when(mockTelephonyManager.getMaxNumberOfSimultaneouslyActiveSims()).thenReturn(1);
+
+        Call call1 = addSpyCall(SIM_1_HANDLE, CallState.ACTIVE);
+        assertEquals(call1.getSimultaneousType(), Call.CALL_SIMULTANEOUS_DISABLED_SAME_ACCOUNT);
+
+        // Emulate adding another concurrent call on a different call when simultaneous calling
+        // isn't supported by the device.
+        Call call2 = addSpyCall(SIM_2_HANDLE, CallState.ON_HOLD);
+        assertEquals(call1.getSimultaneousType(), Call.CALL_SIMULTANEOUS_DISABLED_DIFF_ACCOUNT);
+        assertEquals(call2.getSimultaneousType(), Call.CALL_SIMULTANEOUS_DISABLED_DIFF_ACCOUNT);
+        mCallsManager.removeCall(call2);
+
+        // Now enable simultaneous calling and verify the updated call simultaneous types when
+        // adding another call.
+        when(mockTelephonyManager.getMaxNumberOfSimultaneouslyActiveSims()).thenReturn(2);
+        call2 = addSpyCall(SIM_1_HANDLE, CallState.ON_HOLD);
+        assertEquals(call1.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_SAME_ACCOUNT);
+        assertEquals(call2.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_SAME_ACCOUNT);
+
+        // Add a new call and remove the held one (emulation).
+        mCallsManager.removeCall(call2);
+        // Verify that the simultaneous call type priority of the 1st call has been upgraded.
+        Call call3 = addSpyCall(SIM_2_HANDLE, CallState.ACTIVE);
+        assertEquals(call1.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_DIFF_ACCOUNT);
+        assertEquals(call3.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_DIFF_ACCOUNT);
+
+        // Remove the first call and add another call with the same handle as the third call.
+        mCallsManager.removeCall(call1);
+        Call call4 = addSpyCall(SIM_2_HANDLE, CallState.ON_HOLD);
+        // Verify that call3's priority remains unchanged but call4's priority is
+        // Call.CALL_DIRECTION_DUAL_SAME_ACCOUNT.
+        assertEquals(call3.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_DIFF_ACCOUNT);
+        assertEquals(call4.getSimultaneousType(), Call.CALL_DIRECTION_DUAL_SAME_ACCOUNT);
+    }
+
+    @SmallTest
+    @Test
+    public void testPendingAccountSelectionNotClearedWithNewCall() {
+        Call ongoingCall = createSpyCall(SIM_1_HANDLE, CallState.ACTIVE);
+        mCallsManager.getPendingAccountSelection().put(ongoingCall.getId(),
+                CompletableFuture.completedFuture(new Pair<>(ongoingCall, SIM_1_HANDLE)));
+        Call pendingCall = createSpyCall(SIM_1_HANDLE, CallState.SELECT_PHONE_ACCOUNT);
+        mCallsManager.getPendingAccountSelection().put(pendingCall.getId(),
+                CompletableFuture.completedFuture(new Pair<>(pendingCall, SIM_1_HANDLE)));
+        mCallsManager.processDisconnectCallAndCleanup(ongoingCall, CallState.DISCONNECTED);
+        assertFalse(mCallsManager.getPendingAccountSelection().containsKey(ongoingCall.getId()));
+        assertTrue(mCallsManager.getPendingAccountSelection().containsKey(pendingCall.getId()));
+    }
 
     private Call addSpyCall() {
         return addSpyCall(SIM_2_HANDLE, CallState.ACTIVE);
@@ -3803,9 +3866,9 @@ public class CallsManagerTest extends TelecomTestCase {
         Call callSpy = Mockito.spy(ongoingCall);
 
         // Mocks some methods to not call the real method.
-        doNothing().when(callSpy).unhold();
-        doNothing().when(callSpy).hold();
-        doNothing().when(callSpy).answer(ArgumentMatchers.anyInt());
+        doReturn(null).when(callSpy).unhold();
+        doReturn(null).when(callSpy).hold();
+        doReturn(null).when(callSpy).answer(ArgumentMatchers.anyInt());
         doNothing().when(callSpy).setStartWithSpeakerphoneOn(ArgumentMatchers.anyBoolean());
 
         mCallsManager.addCall(callSpy);
@@ -3817,10 +3880,10 @@ public class CallsManagerTest extends TelecomTestCase {
         Call callSpy = Mockito.spy(ongoingCall);
 
         // Mocks some methods to not call the real method.
-        doNothing().when(callSpy).unhold();
-        doNothing().when(callSpy).hold();
-        doNothing().when(callSpy).disconnect();
-        doNothing().when(callSpy).answer(ArgumentMatchers.anyInt());
+        doReturn(null).when(callSpy).unhold();
+        doReturn(null).when(callSpy).hold();
+        doReturn(null).when(callSpy).disconnect();
+        doReturn(null).when(callSpy).answer(ArgumentMatchers.anyInt());
         doNothing().when(callSpy).setStartWithSpeakerphoneOn(ArgumentMatchers.anyBoolean());
 
         return callSpy;
@@ -3940,7 +4003,7 @@ public class CallsManagerTest extends TelecomTestCase {
         CountDownLatch latch = new CountDownLatch(1);
         when(mFeatureFlags.transactionalHoldDisconnectsUnholdable()).thenReturn(true);
         when(mConnectionSvrFocusMgr.getCurrentFocusCall()).thenReturn(activeCall);
-        mCallsManager.transactionHoldPotentialActiveCallForNewCall(
+        mCallsManager.getCallSequencingAdapter().transactionHoldPotentialActiveCallForNewCall(
                 newCall,
                 isCallControlRequest,
                 new LatchedOutcomeReceiver(latch, expectOnResult));
diff --git a/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java b/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
index 1432834b0..12612652c 100644
--- a/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
+++ b/tests/src/com/android/server/telecom/tests/ComponentContextFixture.java
@@ -756,6 +756,17 @@ public class ComponentContextFixture implements TestFixture<Context> {
         Log.VERBOSE = true;
     }
 
+    public void destroy() {
+        if (mHandlerThread == null) return;
+        mHandlerThread.quit();
+        try {
+            mHandlerThread.join();
+        } catch (InterruptedException ex) {
+            Log.w(this, "HandlerThread join interrupted", ex);
+        }
+        mHandlerThread = null;
+    }
+
     @Override
     public Context getTestDouble() {
         return mContext;
diff --git a/tests/src/com/android/server/telecom/tests/ContactsAsyncHelperTest.java b/tests/src/com/android/server/telecom/tests/ContactsAsyncHelperTest.java
index 7adb32cbb..0536ddb20 100644
--- a/tests/src/com/android/server/telecom/tests/ContactsAsyncHelperTest.java
+++ b/tests/src/com/android/server/telecom/tests/ContactsAsyncHelperTest.java
@@ -19,7 +19,6 @@ package com.android.server.telecom.tests;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyInt;
-import static org.mockito.ArgumentMatchers.anyObject;
 import static org.mockito.ArgumentMatchers.eq;
 import static org.mockito.ArgumentMatchers.isNull;
 import static org.mockito.Mockito.never;
@@ -116,7 +115,7 @@ public class ContactsAsyncHelperTest extends TelecomTestCase {
         }
         Thread.sleep(TEST_TIMEOUT);
         verify(mListener, never()).onImageLoadComplete(anyInt(),
-                any(Drawable.class), any(Bitmap.class), anyObject());
+                any(Drawable.class), any(Bitmap.class), any());
     }
 
     @SmallTest
@@ -127,7 +126,7 @@ public class ContactsAsyncHelperTest extends TelecomTestCase {
         cah.startObtainPhotoAsync(TOKEN, mContext, SAMPLE_CONTACT_PHOTO_URI, mListener, COOKIE);
 
         verify(mListener, timeout(TEST_TIMEOUT)).onImageLoadComplete(eq(TOKEN),
-                isNull(Drawable.class), isNull(Bitmap.class), eq(COOKIE));
+                isNull(), isNull(), eq(COOKIE));
     }
 
     @SmallTest
diff --git a/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java b/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
index e497f485d..406bc8af4 100644
--- a/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
+++ b/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
@@ -51,6 +51,7 @@ import com.android.internal.telephony.flags.Flags;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallIdMapper;
 import com.android.server.telecom.CallState;
+import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.ConnectionServiceFocusManager;
 import com.android.server.telecom.ConnectionServiceRepository;
 import com.android.server.telecom.ConnectionServiceWrapper;
@@ -97,6 +98,8 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
     @Mock
     PhoneAccountRegistrar mMockAccountRegistrar;
     @Mock
+    CallsManager mCallsManager;
+    @Mock
     CreateConnectionResponse mMockCreateConnectionResponse;
     @Mock
     Call mMockCall;
@@ -136,7 +139,7 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
 
         mTestCreateConnectionProcessor = new CreateConnectionProcessor(mMockCall,
                 mMockConnectionServiceRepository, mMockCreateConnectionResponse,
-                mMockAccountRegistrar, mContext, mFeatureFlags, mTimeoutsAdapter);
+                mMockAccountRegistrar, mCallsManager, mContext, mFeatureFlags, mTimeoutsAdapter);
 
         mAccountToSub = new HashMap<>();
         phoneAccounts = new ArrayList<>();
@@ -162,8 +165,6 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
 
         mTestCreateConnectionTimeout = new CreateConnectionTimeout(mContext, mMockAccountRegistrar,
                 makeConnectionServiceWrapper(), mMockCall, mTimeoutsAdapter);
-
-        mSetFlagsRule.enableFlags(Flags.FLAG_CARRIER_ENABLED_SATELLITE_FLAG);
     }
 
     @Override
@@ -1127,4 +1128,4 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
                 .setIsEnabled(true)
                 .build();
     }
-}
\ No newline at end of file
+}
diff --git a/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java b/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
index 3da9284d3..ecabf64f4 100644
--- a/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
+++ b/tests/src/com/android/server/telecom/tests/DefaultDialerCacheTest.java
@@ -84,7 +84,7 @@ public class DefaultDialerCacheTest extends TelecomTestCase {
 
         verify(mContext, times(2)).registerReceiverAsUser(
                 packageReceiverCaptor.capture(), eq(UserHandle.ALL), any(IntentFilter.class),
-                isNull(String.class), isNull(Handler.class));
+                isNull(), isNull());
         // Receive the first receiver that was captured, the package change receiver.
         mPackageChangeReceiver = packageReceiverCaptor.getAllValues().get(0);
 
diff --git a/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java b/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
index df2668484..4459d1b63 100644
--- a/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
+++ b/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
@@ -127,7 +127,8 @@ public class InCallTonePlayerTest extends TelecomTestCase {
                 mCallAudioRouteStateMachine, mBluetoothRouteManager, mWiredHeadsetManager,
                 mDockManager, mRingtonePlayer);
         mFactory = new InCallTonePlayer.Factory(mCallAudioRoutePeripheralAdapter, mLock,
-                mToneGeneratorFactory, mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags);
+                mToneGeneratorFactory, mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags,
+                getLooper());
         mFactory.setCallAudioManager(mCallAudioManager);
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_CALL_ENDED);
     }
@@ -136,7 +137,10 @@ public class InCallTonePlayerTest extends TelecomTestCase {
     @After
     public void tearDown() throws Exception {
         super.tearDown();
-        mInCallTonePlayer.cleanup();
+        if (mInCallTonePlayer != null) {
+            mInCallTonePlayer.cleanup();
+            mInCallTonePlayer = null;
+        }
     }
 
     @SmallTest
diff --git a/tests/src/com/android/server/telecom/tests/MissedCallNotifierImplTest.java b/tests/src/com/android/server/telecom/tests/MissedCallNotifierImplTest.java
index 17764117a..39836eefd 100644
--- a/tests/src/com/android/server/telecom/tests/MissedCallNotifierImplTest.java
+++ b/tests/src/com/android/server/telecom/tests/MissedCallNotifierImplTest.java
@@ -578,7 +578,7 @@ public class MissedCallNotifierImplTest extends TelecomTestCase {
 
         CallerInfo ci = new CallerInfo();
         listenerCaptor.getValue().onCallerInfoQueryComplete(escapedHandle, ci);
-        verify(mockCallInfoFactory).makeCallInfo(eq(ci), isNull(PhoneAccountHandle.class),
+        verify(mockCallInfoFactory).makeCallInfo(eq(ci), isNull(),
                 eq(escapedHandle), eq(CALL_TIMESTAMP));
     }
 
diff --git a/tests/src/com/android/server/telecom/tests/NewOutgoingCallIntentBroadcasterTest.java b/tests/src/com/android/server/telecom/tests/NewOutgoingCallIntentBroadcasterTest.java
index e75ad9755..1ea0ed1c0 100644
--- a/tests/src/com/android/server/telecom/tests/NewOutgoingCallIntentBroadcasterTest.java
+++ b/tests/src/com/android/server/telecom/tests/NewOutgoingCallIntentBroadcasterTest.java
@@ -385,7 +385,7 @@ public class NewOutgoingCallIntentBroadcasterTest extends TelecomTestCase {
         assertEquals(false, callDisposition.requestRedirection);
         assertEquals(DisconnectCause.NOT_DISCONNECTED, callDisposition.disconnectCause);
 
-        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(handle), isNull(GatewayInfo.class),
+        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(handle), isNull(),
                 eq(isSpeakerphoneOn), eq(videoState));
 
         Bundle expectedExtras = createNumberExtras(handle.getSchemeSpecificPart());
@@ -409,7 +409,7 @@ public class NewOutgoingCallIntentBroadcasterTest extends TelecomTestCase {
 
         result.receiver.onReceive(mContext, result.intent);
 
-        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(handle), isNull(GatewayInfo.class),
+        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(handle), isNull(),
                 eq(true), eq(VideoProfile.STATE_BIDIRECTIONAL));
     }
 
@@ -427,7 +427,7 @@ public class NewOutgoingCallIntentBroadcasterTest extends TelecomTestCase {
 
         Uri encHandle = Uri.fromParts(handle.getScheme(),
                 handle.getSchemeSpecificPart(), null);
-        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(encHandle), isNull(GatewayInfo.class),
+        verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(encHandle), isNull(),
                 eq(true), eq(VideoProfile.STATE_BIDIRECTIONAL));
     }
 
@@ -448,7 +448,7 @@ public class NewOutgoingCallIntentBroadcasterTest extends TelecomTestCase {
         result.receiver.onReceive(mContext, result.intent);
 
         verify(mCallsManager).placeOutgoingCall(eq(mCall), eq(handle),
-                isNotNull(GatewayInfo.class), eq(true), eq(VideoProfile.STATE_BIDIRECTIONAL));
+                isNotNull(), eq(true), eq(VideoProfile.STATE_BIDIRECTIONAL));
     }
 
     @SmallTest
@@ -645,10 +645,10 @@ public class NewOutgoingCallIntentBroadcasterTest extends TelecomTestCase {
                 eq(AppOpsManager.OP_PROCESS_OUTGOING_CALLS),
                 any(Bundle.class),
                 receiverCaptor.capture(),
-                isNull(Handler.class),
+                isNull(),
                 eq(Activity.RESULT_OK),
                 eq(number),
-                isNull(Bundle.class));
+                isNull());
 
         Intent capturedIntent = intentCaptor.getValue();
         assertEquals(Intent.ACTION_NEW_OUTGOING_CALL, capturedIntent.getAction());
diff --git a/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java b/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
index a480a7b5c..23e8dab26 100644
--- a/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
+++ b/tests/src/com/android/server/telecom/tests/PhoneAccountRegistrarTest.java
@@ -113,8 +113,7 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
     private final String PACKAGE_1 = "PACKAGE_1";
     private final String PACKAGE_2 = "PACKAGE_2";
     private final String COMPONENT_NAME = "com.android.server.telecom.tests.MockConnectionService";
-    private final UserHandle USER_HANDLE_10 = UserHandle.of(10);
-    private final UserHandle USER_HANDLE_1000 = UserHandle.of(1000);
+    private final UserHandle USER_HANDLE_10 = new UserHandle(10);
     private final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() { };
     private PhoneAccountRegistrar mRegistrar;
     @Mock private SubscriptionManager mSubscriptionManager;
@@ -141,7 +140,6 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
         mRegistrar = new PhoneAccountRegistrar(
                 mComponentContextFixture.getTestDouble().getApplicationContext(), mLock, FILE_NAME,
                 mDefaultDialerCache, mAppLabelProxy, mTelephonyFeatureFlags, mFeatureFlags);
-        mRegistrar.setCurrentUserHandle(UserHandle.SYSTEM);
         when(mFeatureFlags.onlyUpdateTelephonyOnValidSubIds()).thenReturn(false);
         when(mFeatureFlags.unregisterUnresolvableAccounts()).thenReturn(true);
         when(mTelephonyFeatureFlags.workProfileApiSplit()).thenReturn(false);
@@ -1308,7 +1306,8 @@ public class PhoneAccountRegistrarTest extends TelecomTestCase {
                 Mockito.mock(IConnectionService.class));
         UserManager userManager = mContext.getSystemService(UserManager.class);
 
-        List<UserHandle> users = Arrays.asList(UserHandle.SYSTEM, USER_HANDLE_1000);
+        List<UserHandle> users = Arrays.asList(new UserHandle(0),
+                new UserHandle(10));
 
         PhoneAccount pa1 = new PhoneAccount.Builder(
                 new PhoneAccountHandle(new ComponentName(PACKAGE_1, COMPONENT_NAME), "1234",
diff --git a/tests/src/com/android/server/telecom/tests/RingerTest.java b/tests/src/com/android/server/telecom/tests/RingerTest.java
index 46916fd48..9c9dbf6d6 100644
--- a/tests/src/com/android/server/telecom/tests/RingerTest.java
+++ b/tests/src/com/android/server/telecom/tests/RingerTest.java
@@ -22,6 +22,7 @@ import static android.provider.Settings.Global.ZEN_MODE_IMPORTANT_INTERRUPTIONS;
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.junit.Assume.assumeNotNull;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
@@ -37,7 +38,6 @@ import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.verifyNoMoreInteractions;
-import static org.mockito.Mockito.verifyZeroInteractions;
 import static org.mockito.Mockito.when;
 
 import android.app.NotificationManager;
@@ -46,10 +46,12 @@ import android.content.Context;
 import android.media.AudioAttributes;
 import android.media.AudioManager;
 import android.media.Ringtone;
+import android.media.RingtoneManager;
 import android.media.VolumeShaper;
 import android.media.audio.Flags;
 import android.net.Uri;
 import android.os.Bundle;
+import android.os.TestLooperManager;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.os.VibrationAttributes;
@@ -64,7 +66,9 @@ import android.telecom.PhoneAccountHandle;
 import android.telecom.TelecomManager;
 import android.util.Pair;
 
+import androidx.test.core.app.ApplicationProvider;
 import androidx.test.filters.SmallTest;
+import androidx.test.platform.app.InstrumentationRegistry;
 
 import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.AsyncRingtonePlayer;
@@ -83,6 +87,7 @@ import org.junit.Rule;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 import org.mockito.Spy;
 
@@ -136,6 +141,7 @@ public class RingerTest extends TelecomTestCase {
             new PhoneAccountHandle(new ComponentName("pa_pkg", "pa_cls"),
                     "pa_id");
 
+    TestLooperManager mLooperManager;
     boolean mIsHapticPlaybackSupported = true;  // Note: initializeRinger() after changes.
     AsyncRingtonePlayer asyncRingtonePlayer = new AsyncRingtonePlayer();
     Ringer mRingerUnderTest;
@@ -191,6 +197,18 @@ public class RingerTest extends TelecomTestCase {
         super.tearDown();
     }
 
+    private void acquireLooper() {
+        mLooperManager = InstrumentationRegistry.getInstrumentation()
+                .acquireLooperManager(asyncRingtonePlayer.getLooper());
+    }
+
+    private void processAllMessages() {
+        for (var msg = mLooperManager.poll(); msg != null && msg.getTarget() != null;) {
+            mLooperManager.execute(msg);
+            mLooperManager.recycle(msg);
+        }
+    }
+
     @SmallTest
     @Test
     public void testSimpleVibrationPrecedesValidSupportedDefaultRingVibrationOverride()
@@ -347,7 +365,7 @@ public class RingerTest extends TelecomTestCase {
         mRingerUnderTest.startCallWaiting(mockCall1);
         assertFalse(startRingingAndWaitForAsync(mockCall2, false));
 
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockTonePlayer, never()).stopTone();
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
@@ -363,7 +381,7 @@ public class RingerTest extends TelecomTestCase {
         ensureRingerIsNotAudible();
         assertFalse(startRingingAndWaitForAsync(mockCall2, false));
 
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockTonePlayer, never()).stopTone();
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(AudioAttributes.class));
@@ -379,7 +397,7 @@ public class RingerTest extends TelecomTestCase {
                 any(UserHandle.class))).thenReturn(true);
         ensureRingerIsAudible();
         assertTrue(startRingingAndWaitForAsync(mockCall2, false));
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockTonePlayer, never()).stopTone();
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
@@ -394,7 +412,7 @@ public class RingerTest extends TelecomTestCase {
         // We do want to acquire audio focus when self-managed
         assertTrue(startRingingAndWaitForAsync(mockCall2, true));
 
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockTonePlayer, never()).stopTone();
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
@@ -410,7 +428,7 @@ public class RingerTest extends TelecomTestCase {
 
         assertFalse(startRingingAndWaitForAsync(mockCall2, false));
 
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockTonePlayer).stopTone();
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
@@ -548,7 +566,7 @@ public class RingerTest extends TelecomTestCase {
         enableVibrationWhenRinging();
         assertFalse(startRingingAndWaitForAsync(mockCall2, false));
         verify(mockTonePlayer).stopTone();
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
 
         // Play default vibration when future completes with no audio coupled haptics
         verify(mockVibrator).vibrate(eq(mRingerUnderTest.mDefaultVibrationEffect),
@@ -618,7 +636,7 @@ public class RingerTest extends TelecomTestCase {
         assertTrue(startRingingAndWaitForAsync(mockCall2, true));
         verify(mockTonePlayer).stopTone();
         // Ringer not audible, so never tries to create a ringtone.
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
     }
@@ -643,16 +661,20 @@ public class RingerTest extends TelecomTestCase {
     @SmallTest
     @Test
     public void testDelayRingerForBtHfpDevices() throws Exception {
+        acquireLooper();
+
         asyncRingtonePlayer.updateBtActiveState(false);
         Ringtone mockRingtone = ensureRingtoneMocked();
 
         ensureRingerIsAudible();
         assertTrue(mRingerUnderTest.startRinging(mockCall1, true));
         assertTrue(mRingerUnderTest.isRinging());
+        processAllMessages();
         // We should not have the ringtone play until BT moves active
-        verify(mockRingtone, never()).play();
+        // TODO(b/395089048): verify(mockRingtone, never()).play();
 
         asyncRingtonePlayer.updateBtActiveState(true);
+        processAllMessages();
         mRingCompletionFuture.get();
         verify(mockRingtoneFactory, atLeastOnce())
                 .getRingtone(any(Call.class), nullable(VolumeShaper.Configuration.class),
@@ -661,25 +683,31 @@ public class RingerTest extends TelecomTestCase {
         verify(mockRingtone).play();
 
         mRingerUnderTest.stopRinging();
-        verify(mockRingtone, timeout(1000/*ms*/)).stop();
+        processAllMessages();
+        verify(mockRingtone).stop();
         assertFalse(mRingerUnderTest.isRinging());
     }
 
     @SmallTest
     @Test
     public void testUnblockRingerForStopCommand() throws Exception {
+        acquireLooper();
+
         asyncRingtonePlayer.updateBtActiveState(false);
         Ringtone mockRingtone = ensureRingtoneMocked();
 
         ensureRingerIsAudible();
         assertTrue(mRingerUnderTest.startRinging(mockCall1, true));
+
+        processAllMessages();
         // We should not have the ringtone play until BT moves active
-        verify(mockRingtone, never()).play();
+        // TODO(b/395089048): verify(mockRingtone, never()).play();
 
         // We are not setting BT active, but calling stop ringing while the other thread is waiting
         // for BT active should also unblock it.
         mRingerUnderTest.stopRinging();
-        verify(mockRingtone, timeout(1000/*ms*/)).stop();
+        processAllMessages();
+        verify(mockRingtone).stop();
     }
 
     /**
@@ -812,7 +840,7 @@ public class RingerTest extends TelecomTestCase {
         assertFalse(startRingingAndWaitForAsync(mockCall2, true));
 
         verify(mockTonePlayer, never()).stopTone();
-        verifyZeroInteractions(mockRingtoneFactory);
+        verifyNoMoreInteractions(mockRingtoneFactory);
         verify(mockVibrator, never())
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
     }
@@ -821,8 +849,12 @@ public class RingerTest extends TelecomTestCase {
     @Test
     @EnableFlags(Flags.FLAG_ENABLE_RINGTONE_HAPTICS_CUSTOMIZATION)
     public void testNoVibrateForSilentRingtoneIfRingtoneHasVibration() throws Exception {
+        final Context context = ApplicationProvider.getApplicationContext();
+        Uri defaultRingtoneUri = RingtoneManager.getActualDefaultRingtoneUri(context,
+                RingtoneManager.TYPE_RINGTONE);
+        assumeNotNull(defaultRingtoneUri);
         Uri FAKE_RINGTONE_VIBRATION_URI =
-                FAKE_RINGTONE_URI.buildUpon().appendQueryParameter(
+                defaultRingtoneUri.buildUpon().appendQueryParameter(
                         VIBRATION_PARAM, FAKE_VIBRATION_URI.toString()).build();
         Ringtone mockRingtone = mock(Ringtone.class);
         Pair<Uri, Ringtone> ringtoneInfo = new Pair(FAKE_RINGTONE_VIBRATION_URI, mockRingtone);
@@ -831,21 +863,61 @@ public class RingerTest extends TelecomTestCase {
                 .thenReturn(ringtoneInfo);
         mComponentContextFixture.putBooleanResource(
                 com.android.internal.R.bool.config_ringtoneVibrationSettingsSupported, true);
-        createRingerUnderTest(); // Needed after mock the config.
-
-        mRingerUnderTest.startCallWaiting(mockCall1);
-        when(mockAudioManager.getRingerMode()).thenReturn(AudioManager.RINGER_MODE_VIBRATE);
-        when(mockAudioManager.getStreamVolume(AudioManager.STREAM_RING)).thenReturn(0);
-        enableVibrationWhenRinging();
-        assertFalse(startRingingAndWaitForAsync(mockCall2, false));
+        try {
+            RingtoneManager.setActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE,
+                    FAKE_RINGTONE_VIBRATION_URI);
+            createRingerUnderTest(); // Needed after mock the config.
+
+            mRingerUnderTest.startCallWaiting(mockCall1);
+            when(mockAudioManager.getRingerMode()).thenReturn(AudioManager.RINGER_MODE_VIBRATE);
+            when(mockAudioManager.getStreamVolume(AudioManager.STREAM_RING)).thenReturn(0);
+            enableVibrationWhenRinging();
+            assertFalse(startRingingAndWaitForAsync(mockCall2, false));
+
+            verify(mockRingtoneFactory, atLeastOnce())
+                    .getRingtone(any(Call.class), eq(null), eq(false));
+            verifyNoMoreInteractions(mockRingtoneFactory);
+            verify(mockTonePlayer).stopTone();
+            // Skip vibration play in Ringer if a vibration was specified to the ringtone
+            verify(mockVibrator, never()).vibrate(any(VibrationEffect.class),
+                    any(VibrationAttributes.class));
+        } finally {
+            // Restore the default ringtone Uri
+            RingtoneManager.setActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE,
+                    defaultRingtoneUri);
+        }
+    }
 
-        verify(mockRingtoneFactory, atLeastOnce())
-                .getRingtone(any(Call.class), eq(null), eq(false));
-        verifyNoMoreInteractions(mockRingtoneFactory);
-        verify(mockTonePlayer).stopTone();
-        // Skip vibration play in Ringer if a vibration was specified to the ringtone
-        verify(mockVibrator, never()).vibrate(any(VibrationEffect.class),
-                any(VibrationAttributes.class));
+    @SmallTest
+    @Test
+    @EnableFlags(Flags.FLAG_ENABLE_RINGTONE_HAPTICS_CUSTOMIZATION)
+    public void testNotMuteHapticChannelWithRampingRinger() throws Exception {
+        final Context context = ApplicationProvider.getApplicationContext();
+        Uri defaultRingtoneUri = RingtoneManager.getActualDefaultRingtoneUri(context,
+                RingtoneManager.TYPE_RINGTONE);
+        assumeNotNull(defaultRingtoneUri);
+        Uri FAKE_RINGTONE_VIBRATION_URI = defaultRingtoneUri.buildUpon().appendQueryParameter(
+                        VIBRATION_PARAM, FAKE_VIBRATION_URI.toString()).build();
+        mComponentContextFixture.putBooleanResource(
+                com.android.internal.R.bool.config_ringtoneVibrationSettingsSupported, true);
+        ArgumentCaptor<Boolean> muteHapticChannelCaptor = ArgumentCaptor.forClass(Boolean.class);
+        try {
+            RingtoneManager.setActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE,
+                    FAKE_RINGTONE_VIBRATION_URI);
+            createRingerUnderTest(); // Needed after mock the config.
+            mRingerUnderTest.startCallWaiting(mockCall1);
+            ensureRingerIsAudible();
+            enableRampingRinger();
+            enableVibrationWhenRinging();
+            assertTrue(startRingingAndWaitForAsync(mockCall2, false));
+            verify(mockRingtoneFactory, atLeastOnce()).getRingtone(any(Call.class),
+                    nullable(VolumeShaper.Configuration.class), muteHapticChannelCaptor.capture());
+            assertFalse(muteHapticChannelCaptor.getValue());
+        } finally {
+            // Restore the default ringtone Uri
+            RingtoneManager.setActualDefaultRingtoneUri(context, RingtoneManager.TYPE_RINGTONE,
+                    defaultRingtoneUri);
+        }
     }
 
     /**
diff --git a/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
index 4d494f343..3e128e62d 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
@@ -19,9 +19,9 @@ import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS;
 import static com.android.server.telecom.TelecomStatsLog.CALL_STATS;
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
 import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_EVENT_STATS;
 import static com.google.common.truth.Truth.assertThat;
 import static org.mockito.ArgumentMatchers.any;
-import static org.mockito.ArgumentMatchers.anyObject;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
@@ -38,6 +38,7 @@ import com.android.server.telecom.metrics.ApiStats;
 import com.android.server.telecom.metrics.AudioRouteStats;
 import com.android.server.telecom.metrics.CallStats;
 import com.android.server.telecom.metrics.ErrorStats;
+import com.android.server.telecom.metrics.EventStats;
 import com.android.server.telecom.metrics.TelecomMetricsController;
 
 import org.junit.After;
@@ -61,6 +62,8 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
     CallStats mCallStats;
     @Mock
     ErrorStats mErrorStats;
+    @Mock
+    EventStats mEventStats;
 
     HandlerThread mHandlerThread;
 
@@ -113,6 +116,13 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
         assertThat(stats1).isSameInstanceAs(stats2);
     }
 
+    @Test
+    public void testGetEventStatsReturnsSameInstance() {
+        EventStats stats1 = mTelecomMetricsController.getEventStats();
+        EventStats stats2 = mTelecomMetricsController.getEventStats();
+        assertThat(stats1).isSameInstanceAs(stats2);
+    }
+
     @Test
     public void testOnPullAtomReturnsPullSkipIfAtomNotRegistered() {
         mTelecomMetricsController.getStats().clear();
@@ -128,8 +138,8 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
 
         mTelecomMetricsController.registerAtom(TELECOM_API_STATS, stats);
 
-        verify(statsManager, times(1)).setPullAtomCallback(eq(TELECOM_API_STATS), anyObject(),
-                anyObject(), eq(mTelecomMetricsController));
+        verify(statsManager, times(1)).setPullAtomCallback(eq(TELECOM_API_STATS), any(),
+                any(), eq(mTelecomMetricsController));
         assertThat(mTelecomMetricsController.getStats().get(TELECOM_API_STATS))
                 .isSameInstanceAs(stats);
     }
@@ -143,6 +153,7 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
         verify(statsManager, times(1)).clearPullAtomCallback(eq(CALL_STATS));
         verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_API_STATS));
         verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_ERROR_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_EVENT_STATS));
         assertThat(mTelecomMetricsController.getStats()).isEmpty();
     }
 
@@ -159,11 +170,42 @@ public class TelecomMetricsControllerTest extends TelecomTestCase {
         assertThat(captor.getValue()).isEqualTo(data);
     }
 
+    @Test
+    public void testSetTestMode() {
+        StatsManager statsManager = mContext.getSystemService(StatsManager.class);
+        ApiStats apiStats1 = mTelecomMetricsController.getApiStats();
+        AudioRouteStats audioStats1 = mTelecomMetricsController.getAudioRouteStats();
+        CallStats callStats1 = mTelecomMetricsController.getCallStats();
+        ErrorStats errorStats1 = mTelecomMetricsController.getErrorStats();
+        mTelecomMetricsController.setTestMode(true);
+
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(CALL_AUDIO_ROUTE_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(CALL_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_API_STATS));
+        verify(statsManager, times(1)).clearPullAtomCallback(eq(TELECOM_ERROR_STATS));
+        assertThat(mTelecomMetricsController.getStats()).isEmpty();
+
+        ApiStats apiStats2 = mTelecomMetricsController.getApiStats();
+        AudioRouteStats audioStats2 = mTelecomMetricsController.getAudioRouteStats();
+        CallStats callStats2 = mTelecomMetricsController.getCallStats();
+        ErrorStats errorStats2 = mTelecomMetricsController.getErrorStats();
+
+        assertThat(apiStats1).isNotSameInstanceAs(apiStats2);
+        assertThat(audioStats1).isNotSameInstanceAs(audioStats2);
+        assertThat(callStats1).isNotSameInstanceAs(callStats2);
+        assertThat(errorStats1).isNotSameInstanceAs(errorStats2);
+
+        mTelecomMetricsController.setTestMode(false);
+
+        assertThat(mTelecomMetricsController.getStats()).isEmpty();
+    }
+
     private void setUpStats() {
         mTelecomMetricsController.getStats().put(CALL_AUDIO_ROUTE_STATS,
                 mAudioRouteStats);
         mTelecomMetricsController.getStats().put(CALL_STATS, mCallStats);
         mTelecomMetricsController.getStats().put(TELECOM_API_STATS, mApiStats);
         mTelecomMetricsController.getStats().put(TELECOM_ERROR_STATS, mErrorStats);
+        mTelecomMetricsController.getStats().put(TELECOM_EVENT_STATS, mEventStats);
     }
 }
diff --git a/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
index d3c7859e4..0859ec4fe 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
@@ -42,6 +42,7 @@ import android.content.Context;
 import android.content.pm.ApplicationInfo;
 import android.content.pm.PackageManager;
 import android.os.Looper;
+import android.telecom.DisconnectCause;
 import android.telecom.PhoneAccount;
 import android.telecom.PhoneAccountHandle;
 import android.util.StatsEvent;
@@ -55,6 +56,7 @@ import com.android.server.telecom.metrics.ApiStats;
 import com.android.server.telecom.metrics.AudioRouteStats;
 import com.android.server.telecom.metrics.CallStats;
 import com.android.server.telecom.metrics.ErrorStats;
+import com.android.server.telecom.metrics.EventStats;
 import com.android.server.telecom.nano.PulledAtomsClass;
 
 import org.junit.After;
@@ -104,6 +106,10 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     private static final int VALUE_ERROR_ID = 1;
     private static final int VALUE_ERROR_COUNT = 1;
 
+    private static final int VALUE_EVENT_ID = 1;
+    private static final int VALUE_CAUSE_ID = 1;
+    private static final int VALUE_EVENT_COUNT = 1;
+
     @Rule
     public TemporaryFolder mTempFolder = new TemporaryFolder();
     @Mock
@@ -145,22 +151,22 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     public void testNewPulledAtomsFromFileInvalid() throws Exception {
         mTempFile.delete();
 
-        ApiStats apiStats = new ApiStats(mSpyContext, mLooper);
+        ApiStats apiStats = new ApiStats(mSpyContext, mLooper, false);
 
         assertNotNull(apiStats.mPulledAtoms);
         assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 0);
 
-        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper);
+        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper, false);
 
         assertNotNull(audioRouteStats.mPulledAtoms);
         assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 0);
 
-        CallStats callStats = new CallStats(mSpyContext, mLooper);
+        CallStats callStats = new CallStats(mSpyContext, mLooper, false);
 
         assertNotNull(callStats.mPulledAtoms);
         assertEquals(callStats.mPulledAtoms.callStats.length, 0);
 
-        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper);
+        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper, false);
 
         assertNotNull(errorStats.mPulledAtoms);
         assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 0);
@@ -169,30 +175,35 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testNewPulledAtomsFromFileValid() throws Exception {
         createTestFileForApiStats(DEFAULT_TIMESTAMPS_MILLIS);
-        ApiStats apiStats = new ApiStats(mSpyContext, mLooper);
+        ApiStats apiStats = new ApiStats(mSpyContext, mLooper, false);
 
         verifyTestDataForApiStats(apiStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
 
         createTestFileForAudioRouteStats(DEFAULT_TIMESTAMPS_MILLIS);
-        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper);
+        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper, false);
 
         verifyTestDataForAudioRouteStats(audioRouteStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
 
         createTestFileForCallStats(DEFAULT_TIMESTAMPS_MILLIS);
-        CallStats callStats = new CallStats(mSpyContext, mLooper);
+        CallStats callStats = new CallStats(mSpyContext, mLooper, false);
 
         verifyTestDataForCallStats(callStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
 
         createTestFileForErrorStats(DEFAULT_TIMESTAMPS_MILLIS);
-        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper);
+        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper, false);
 
         verifyTestDataForErrorStats(errorStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
+
+        createTestFileForEventStats(DEFAULT_TIMESTAMPS_MILLIS);
+        EventStats eventStats = new EventStats(mSpyContext, mLooper, false);
+
+        verifyTestDataForEventStats(eventStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
     }
 
     @Test
     public void testPullApiStatsLessThanMinPullIntervalShouldSkip() throws Exception {
         createTestFileForApiStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
-        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
 
         int result = apiStats.pull(data);
@@ -205,7 +216,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullApiStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
         createTestFileForApiStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
-        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
         int sizePulled = apiStats.mPulledAtoms.telecomApiStats.length;
 
@@ -220,7 +231,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullAudioRouteStatsLessThanMinPullIntervalShouldSkip() throws Exception {
         createTestFileForAudioRouteStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
 
         int result = audioRouteStats.pull(data);
@@ -233,7 +244,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullAudioRouteStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
         createTestFileForAudioRouteStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
         int sizePulled = audioRouteStats.mPulledAtoms.callAudioRouteStats.length;
 
@@ -248,7 +259,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullCallStatsLessThanMinPullIntervalShouldSkip() throws Exception {
         createTestFileForCallStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
-        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
 
         int result = callStats.pull(data);
@@ -261,7 +272,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullCallStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
         createTestFileForCallStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
-        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
         int sizePulled = callStats.mPulledAtoms.callStats.length;
 
@@ -276,7 +287,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullErrorStatsLessThanMinPullIntervalShouldSkip() throws Exception {
         createTestFileForErrorStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
-        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
 
         int result = errorStats.pull(data);
@@ -289,7 +300,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testPullErrorStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
         createTestFileForErrorStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
-        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper, false));
         final List<StatsEvent> data = new ArrayList<>();
         int sizePulled = errorStats.mPulledAtoms.telecomErrorStats.length;
 
@@ -303,7 +314,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
     @Test
     public void testApiStatsLogCount() throws Exception {
-        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper, false));
         ApiStats.ApiEvent event = new ApiStats.ApiEvent(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
 
         for (int i = 0; i < 10; i++) {
@@ -384,7 +395,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         };
         final int[] results = {ApiStats.RESULT_UNKNOWN, ApiStats.RESULT_NORMAL,
                 ApiStats.RESULT_EXCEPTION, ApiStats.RESULT_PERMISSION};
-        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper, false));
         Random rand = new Random();
         Map<ApiStats.ApiEvent, Integer> eventMap = new HashMap<>();
 
@@ -408,7 +419,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
     @Test
     public void testAudioRouteStatsLog() throws Exception {
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.log(VALUE_AUDIO_ROUTE_TYPE1, VALUE_AUDIO_ROUTE_TYPE2, true, false,
                 VALUE_AUDIO_ROUTE_LATENCY);
@@ -436,7 +447,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testAudioRouteStatsOnEnterThenExit() throws Exception {
         int latency = 500;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -466,7 +477,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         int delay = 100;
         int latency = 500;
         int duration = 1000;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -502,7 +513,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     public void testAudioRouteStatsOnRevertToSourceBeyondThreshold() throws Exception {
         int delay = 100;
         int latency = 500;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -540,7 +551,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         int delay = 100;
         int latency = 500;
         int duration = 1000;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -575,7 +586,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testAudioRouteStatsOnMultipleEnterWithoutExit() throws Exception {
         int latency = 500;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -596,7 +607,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testAudioRouteStatsOnMultipleEnterWithExit() throws Exception {
         int latency = 500;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
         waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
@@ -619,7 +630,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
     @Test
     public void testAudioRouteStatsOnRouteToSameDestWithExit() throws Exception {
         int latency = 500;
-        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, false));
         doReturn(mMockSourceRoute).when(mMockPendingAudioRoute).getDestRoute();
 
         audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
@@ -640,7 +651,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
     @Test
     public void testCallStatsLog() throws Exception {
-        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, false));
 
         callStats.log(VALUE_CALL_DIRECTION, false, false, true, VALUE_CALL_ACCOUNT_TYPE,
                 VALUE_UID, VALUE_CALL_DURATION);
@@ -681,6 +692,9 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(cn).when(handle).getComponentName();
         Call call = mock(Call.class);
         doReturn(true).when(call).isIncoming();
+        doReturn(new DisconnectCause(0)).when(call).getDisconnectCause();
+        doReturn(0).when(call).getSimultaneousType();
+        doReturn(false).when(call).hasVideoCall();
         doReturn(account).when(call).getPhoneAccountFromHandle();
         doReturn((long) duration).when(call).getAgeMillis();
         doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
@@ -688,7 +702,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
         doReturn(callingPackage).when(call).getCallingPackageIdentity();
         doReturn(handle).when(call).getTargetPhoneAccount();
-        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, false));
 
         callStats.onCallStart(call);
         waitForHandlerAction(callStats, TEST_TIMEOUT);
@@ -698,7 +712,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
         verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
                 eq(false), eq(false), eq(false), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
-                eq(fakeUid), eq(duration));
+                eq(fakeUid), eq(0), eq(0), eq(false), eq(duration));
     }
 
     @Test
@@ -719,6 +733,9 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(cn).when(handle).getComponentName();
         Call call = mock(Call.class);
         doReturn(true).when(call).isIncoming();
+        doReturn(new DisconnectCause(0)).when(call).getDisconnectCause();
+        doReturn(0).when(call).getSimultaneousType();
+        doReturn(false).when(call).hasVideoCall();
         doReturn(account).when(call).getPhoneAccountFromHandle();
         doReturn((long) duration).when(call).getAgeMillis();
         doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
@@ -726,7 +743,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
         doReturn(callingPackage).when(call).getCallingPackageIdentity();
         doReturn(handle).when(call).getTargetPhoneAccount();
-        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, false));
 
         callStats.onCallStart(call);
         waitForHandlerAction(callStats, TEST_TIMEOUT);
@@ -739,12 +756,12 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
         verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
                 eq(false), eq(false), eq(true), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
-                eq(fakeUid), eq(duration));
+                eq(fakeUid), eq(0), eq(0), eq(false), eq(duration));
     }
 
     @Test
     public void testErrorStatsLogCount() throws Exception {
-        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper, false));
         for (int i = 0; i < 10; i++) {
             errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
             waitForHandlerAction(errorStats, TEST_TIMEOUT);
@@ -760,7 +777,7 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
 
     @Test
     public void testErrorStatsLogEvent() throws Exception {
-        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper, false));
         int[] modules = {
                 ErrorStats.SUB_UNKNOWN,
                 ErrorStats.SUB_CALL_AUDIO,
@@ -823,6 +840,142 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         }
     }
 
+    @Test
+    public void testApiStatsWithTestModeOn() throws Exception {
+        final List<StatsEvent> data = new ArrayList<>();
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper, true));
+        apiStats.pull(data);
+        apiStats.flush();
+
+        verify(mSpyContext, never()).getFileStreamPath(anyString());
+        verify(apiStats, times(1)).onPull(any());
+        verify(mSpyContext, never()).openFileOutput(anyString(), anyInt());
+    }
+
+    @Test
+    public void testAudioRouteStatsWithTestModeOn() throws Exception {
+        final List<StatsEvent> data = new ArrayList<>();
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper, true));
+        audioRouteStats.pull(data);
+        audioRouteStats.flush();
+
+        verify(mSpyContext, never()).getFileStreamPath(anyString());
+        verify(audioRouteStats, times(1)).onPull(any());
+        verify(mSpyContext, never()).openFileOutput(anyString(), anyInt());
+    }
+
+    @Test
+    public void testCallStatsWithTestModeOn() throws Exception {
+        final List<StatsEvent> data = new ArrayList<>();
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper, true));
+        callStats.pull(data);
+        callStats.flush();
+
+        verify(mSpyContext, never()).getFileStreamPath(anyString());
+        verify(callStats, times(1)).onPull(any());
+        verify(mSpyContext, never()).openFileOutput(anyString(), anyInt());
+    }
+
+    @Test
+    public void testErrorStatsWithTestModeOn() throws Exception {
+        final List<StatsEvent> data = new ArrayList<>();
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper, true));
+        errorStats.pull(data);
+        errorStats.flush();
+
+        verify(mSpyContext, never()).getFileStreamPath(anyString());
+        verify(errorStats, times(1)).onPull(any());
+        verify(mSpyContext, never()).openFileOutput(anyString(), anyInt());
+    }
+
+    @Test
+    public void testPullEventStatsLessThanMinPullIntervalShouldSkip() throws Exception {
+        createTestFileForEventStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
+        EventStats eventStats = spy(new EventStats(mSpyContext, mLooper, false));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = eventStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SKIP, result);
+        verify(eventStats, never()).onPull(any());
+        assertEquals(data.size(), 0);
+    }
+
+    @Test
+    public void testPullEventStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
+        createTestFileForEventStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
+        EventStats eventStats = spy(new EventStats(mSpyContext, mLooper, false));
+        final List<StatsEvent> data = new ArrayList<>();
+        int sizePulled = eventStats.mPulledAtoms.telecomEventStats.length;
+
+        int result = eventStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SUCCESS, result);
+        verify(eventStats).onPull(eq(data));
+        assertEquals(data.size(), sizePulled);
+        assertEquals(eventStats.mPulledAtoms.telecomEventStats.length, 0);
+    }
+
+    @Test
+    public void testEventStatsLogCount() throws Exception {
+        EventStats eventStats = spy(new EventStats(mSpyContext, mLooper, false));
+        EventStats.CriticalEvent event = new EventStats.CriticalEvent(
+                VALUE_EVENT_ID, VALUE_UID, VALUE_CAUSE_ID);
+
+        for (int i = 0; i < 10; i++) {
+            eventStats.log(event);
+            waitForHandlerAction(eventStats, TEST_TIMEOUT);
+
+            verify(eventStats, times(i + 1)).onAggregate();
+            verify(eventStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(eventStats.mPulledAtoms.telecomEventStats.length, 1);
+            verifyMessageForEventStats(eventStats.mPulledAtoms.telecomEventStats[0],
+                    VALUE_EVENT_ID, VALUE_UID, VALUE_CAUSE_ID, i + 1);
+        }
+    }
+
+    @Test
+    public void testEventStatsLogEvent() throws Exception {
+        EventStats eventStats = spy(new EventStats(mSpyContext, mLooper, false));
+        int[] events = {
+                EventStats.ID_UNKNOWN,
+                EventStats.ID_INIT,
+                EventStats.ID_DEFAULT_DIALER_CHANGED,
+                EventStats.ID_ADD_CALL,
+        };
+        int[] causes = {
+                EventStats.CAUSE_UNKNOWN,
+                EventStats.CAUSE_GENERIC_SUCCESS,
+                EventStats.CAUSE_GENERIC_FAILURE,
+                EventStats.CAUSE_CALL_TRANSACTION_SUCCESS,
+                EventStats.CAUSE_CALL_TRANSACTION_ERROR_UNKNOWN,
+                EventStats.CAUSE_CALL_TRANSACTION_CALL_CANNOT_BE_SET_TO_ACTIVE,
+                EventStats.CAUSE_CALL_TRANSACTION_CALL_IS_NOT_BEING_TRACKED,
+                EventStats.CAUSE_CALL_TRANSACTION_CANNOT_HOLD_CURRENT_ACTIVE_CALL,
+                EventStats.CAUSE_CALL_TRANSACTION_CALL_NOT_PERMITTED_AT_PRESENT_TIME,
+                EventStats.CAUSE_CALL_TRANSACTION_OPERATION_TIMED_OUT,
+        };
+        Random rand = new Random();
+        Map<EventStats.CriticalEvent, Integer> eventMap = new HashMap<>();
+
+        for (int i = 0; i < 10; i++) {
+            int e = events[rand.nextInt(events.length)];
+            int uid = rand.nextInt(65535);
+            int cause = causes[rand.nextInt(causes.length)];
+            EventStats.CriticalEvent ce = new EventStats.CriticalEvent(e, uid, cause);
+            eventMap.put(ce, eventMap.getOrDefault(ce, 0) + 1);
+
+            eventStats.log(ce);
+            waitForHandlerAction(eventStats, TEST_TIMEOUT);
+
+            verify(eventStats, times(i + 1)).onAggregate();
+            verify(eventStats, times(i + 1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+            assertEquals(eventStats.mPulledAtoms.telecomEventStats.length, eventMap.size());
+            assertTrue(hasMessageForEventStats(eventStats.mPulledAtoms.telecomEventStats,
+                    e, uid, cause, eventMap.get(ce)));
+        }
+    }
+
     private void createTestFileForApiStats(long timestamps) throws IOException {
         PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
         atom.telecomApiStats =
@@ -989,8 +1142,8 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         assertEquals(atom.telecomErrorStats.length, VALUE_ATOM_COUNT);
         for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
             assertNotNull(atom.telecomErrorStats[i]);
-            verifyMessageForErrorStats(atom.telecomErrorStats[i], VALUE_MODULE_ID, VALUE_ERROR_ID
-                    , VALUE_ERROR_COUNT);
+            verifyMessageForErrorStats(atom.telecomErrorStats[i], VALUE_MODULE_ID,
+                    VALUE_ERROR_ID, VALUE_ERROR_COUNT);
         }
     }
 
@@ -1011,4 +1164,53 @@ public class TelecomPulledAtomTest extends TelecomTestCase {
         }
         return false;
     }
+
+    private void createTestFileForEventStats(long timestamps) throws IOException {
+        PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
+        atom.telecomEventStats =
+                new PulledAtomsClass.TelecomEventStats[VALUE_ATOM_COUNT];
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            atom.telecomEventStats[i] = new PulledAtomsClass.TelecomEventStats();
+            atom.telecomEventStats[i].setEvent(VALUE_EVENT_ID + i);
+            atom.telecomEventStats[i].setUid(VALUE_UID);
+            atom.telecomEventStats[i].setEventCause(VALUE_CAUSE_ID);
+            atom.telecomEventStats[i].setCount(VALUE_EVENT_COUNT);
+        }
+        atom.setTelecomEventStatsPullTimestampMillis(timestamps);
+        FileOutputStream stream = new FileOutputStream(mTempFile);
+        stream.write(PulledAtomsClass.PulledAtoms.toByteArray(atom));
+        stream.close();
+    }
+
+    private void verifyTestDataForEventStats(
+            final PulledAtomsClass.PulledAtoms atom, long timestamps) {
+        assertNotNull(atom);
+        assertEquals(atom.getTelecomEventStatsPullTimestampMillis(), timestamps);
+        assertNotNull(atom.telecomEventStats);
+        assertEquals(atom.telecomEventStats.length, VALUE_ATOM_COUNT);
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            assertNotNull(atom.telecomEventStats[i]);
+            verifyMessageForEventStats(atom.telecomEventStats[i], VALUE_EVENT_ID + i,
+                    VALUE_UID, VALUE_CAUSE_ID, VALUE_EVENT_COUNT);
+        }
+    }
+
+    private void verifyMessageForEventStats(final PulledAtomsClass.TelecomEventStats msg,
+                                            int eventId, int uid, int causeId, int count) {
+        assertEquals(msg.getEvent(), eventId);
+        assertEquals(msg.getUid(), uid);
+        assertEquals(msg.getEventCause(), causeId);
+        assertEquals(msg.getCount(), count);
+    }
+
+    private boolean hasMessageForEventStats(final PulledAtomsClass.TelecomEventStats[] msgs,
+                                            int eventId, int uid, int causeId, int count) {
+        for (PulledAtomsClass.TelecomEventStats msg : msgs) {
+            if (msg.getEvent() == eventId && msg.getUid() == uid
+                    && msg.getEventCause() == causeId && msg.getCount() == count) {
+                return true;
+            }
+        }
+        return false;
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java b/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
index 96bf05ad8..30a5a192a 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomServiceImplTest.java
@@ -93,6 +93,7 @@ import com.android.server.telecom.InCallController;
 import com.android.server.telecom.PhoneAccountRegistrar;
 import com.android.server.telecom.TelecomServiceImpl;
 import com.android.server.telecom.TelecomSystem;
+import com.android.server.telecom.callsequencing.CallTransaction;
 import com.android.server.telecom.components.UserCallIntentProcessor;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
@@ -116,6 +117,7 @@ import java.util.Collections;
 import java.util.HashSet;
 import java.util.List;
 import java.util.Set;
+import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.Executor;
 import java.util.function.IntConsumer;
 
@@ -206,6 +208,8 @@ public class TelecomServiceImplTest extends TelecomTestCase {
 
     @Mock private InCallController mInCallController;
     @Mock private TelecomMetricsController mMockTelecomMetricsController;
+    @Mock private OutgoingCallTransaction mOutgoingCallTransaction;
+    @Mock private IncomingCallTransaction mIncomingCallTransaction;
 
     private final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() { };
 
@@ -282,6 +286,7 @@ public class TelecomServiceImplTest extends TelecomTestCase {
         when(mPackageManager.getPackageUid(anyString(), eq(0))).thenReturn(Binder.getCallingUid());
         when(mFeatureFlags.earlyBindingToIncallService()).thenReturn(true);
         when(mTelephonyFeatureFlags.workProfileApiSplit()).thenReturn(false);
+        when(mFeatureFlags.enableCallSequencing()).thenReturn(false);
     }
 
     @Override
@@ -457,6 +462,9 @@ public class TelecomServiceImplTest extends TelecomTestCase {
         // WHEN
         when(mFakePhoneAccountRegistrar.getPhoneAccountUnchecked(TEL_PA_HANDLE_CURRENT)).thenReturn(
                 phoneAccount);
+        when(mFakeCallsManager.createTransactionalCall(any(String.class),
+                any(CallAttributes.class), any(Bundle.class), any(String.class)))
+                .thenReturn(CompletableFuture.completedFuture(mOutgoingCallTransaction));
 
         doReturn(phoneAccount).when(mFakePhoneAccountRegistrar).getPhoneAccount(
                 eq(TEL_PA_HANDLE_CURRENT), any(UserHandle.class));
@@ -485,6 +493,9 @@ public class TelecomServiceImplTest extends TelecomTestCase {
 
         doReturn(phoneAccount).when(mFakePhoneAccountRegistrar).getPhoneAccount(
                 eq(TEL_PA_HANDLE_CURRENT), any(UserHandle.class));
+        when(mFakeCallsManager.createTransactionalCall(any(String.class),
+                any(CallAttributes.class), any(Bundle.class), any(String.class)))
+                .thenReturn(CompletableFuture.completedFuture(mIncomingCallTransaction));
 
         mTSIBinder.addCall(mIncomingCallAttributes, mICallEventCallback, "1", CALLING_PACKAGE);
 
@@ -1085,9 +1096,10 @@ public class TelecomServiceImplTest extends TelecomTestCase {
     @Test
     public void testRegisterPhoneAccountImageIconCrossUser() throws RemoteException {
         String packageNameToUse = "com.android.officialpackage";
+        String callingUserId = String.valueOf(Binder.getCallingUserHandle().getIdentifier());
         PhoneAccountHandle phHandle = new PhoneAccountHandle(new ComponentName(
                 packageNameToUse, "cs"), "test", Binder.getCallingUserHandle());
-        Icon icon = Icon.createWithContentUri("content://10@media/external/images/media/");
+        Icon icon = Icon.createWithContentUri("content://12@media/external/images/media/");
         PhoneAccount phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
         doReturn(PackageManager.PERMISSION_GRANTED)
                 .when(mContext).checkCallingOrSelfPermission(MODIFY_PHONE_STATE);
@@ -1097,19 +1109,21 @@ public class TelecomServiceImplTest extends TelecomTestCase {
 
         icon = Icon.createWithContentUri(
                 new Uri.Builder().scheme("content")
-                        .encodedAuthority("10%40media")
+                        .encodedAuthority("12%40media")
                         .path("external/images/media/${mediaId.text}".trim())
                         .build());
         phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
         // This should fail; security exception will be thrown
         registerPhoneAccountTestHelper(phoneAccount, false);
 
-        icon = Icon.createWithContentUri( Uri.parse("content://10%40play.ground"));
+        icon = Icon.createWithContentUri( Uri.parse("content://12%40play.ground"));
         phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
         // This should fail; security exception will be thrown
         registerPhoneAccountTestHelper(phoneAccount, false);
 
-        icon = Icon.createWithContentUri("content://0@media/external/images/media/");
+        // Generate a URI referencing the calling/current user ID:
+        String currentUserUri = "content://" + callingUserId + "@media/external/images/media/";
+        icon = Icon.createWithContentUri(currentUserUri);
         phoneAccount = makePhoneAccount(phHandle).setIcon(icon).build();
         // This should succeed.
         registerPhoneAccountTestHelper(phoneAccount, true);
@@ -1976,7 +1990,7 @@ public class TelecomServiceImplTest extends TelecomTestCase {
     @SmallTest
     @Test
     public void testGetVoicemailNumberWithNullAccountHandle() throws Exception {
-        when(mFakePhoneAccountRegistrar.getPhoneAccount(isNull(PhoneAccountHandle.class),
+        when(mFakePhoneAccountRegistrar.getPhoneAccount(isNull(),
                 eq(Binder.getCallingUserHandle())))
                 .thenReturn(makePhoneAccount(TEL_PA_HANDLE_CURRENT).build());
         int subId = 58374;
diff --git a/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java b/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
index 1e6501103..4aceae43b 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomSystemTest.java
@@ -99,6 +99,7 @@ import com.android.server.telecom.Timeouts;
 import com.android.server.telecom.WiredHeadsetManager;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
 import com.android.server.telecom.callfiltering.BlockedNumbersAdapter;
+import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
 import com.android.server.telecom.components.UserCallIntentProcessor;
 import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.ui.IncomingCallNotifier;
@@ -418,7 +419,11 @@ public class TelecomSystemTest extends TelecomTestCase{
                 handlerThread.quitSafely();
             }
             handlerThreads.clear();
-            mTelecomSystem.getCallsManager().getVoipCallMonitor().stopMonitor();
+
+            VoipCallMonitor vcm = mTelecomSystem.getCallsManager().getVoipCallMonitor();
+            if (vcm != null) {
+                vcm.unregisterNotificationListener();
+            }
         }
         waitForHandlerAction(new Handler(Looper.getMainLooper()), TEST_TIMEOUT);
         waitForHandlerAction(mHandlerThread.getThreadHandler(), TEST_TIMEOUT);
@@ -518,6 +523,7 @@ public class TelecomSystemTest extends TelecomTestCase{
         when(mRoleManagerAdapter.getDefaultCallScreeningApp(any(UserHandle.class)))
                 .thenReturn(null);
         when(mRoleManagerAdapter.getBTInCallService()).thenReturn(new String[] {"bt_pkg"});
+        when(mFeatureFlags.callAudioCommunicationDeviceRefactor()).thenReturn(true);
         when(mFeatureFlags.useRefactoredAudioRouteSwitching()).thenReturn(false);
         mTelecomSystem = new TelecomSystem(
                 mComponentContextFixture.getTestDouble(),
@@ -587,7 +593,8 @@ public class TelecomSystemTest extends TelecomTestCase{
                 Runnable::run,
                 mBlockedNumbersAdapter,
                 mFeatureFlags,
-                mTelephonyFlags);
+                mTelephonyFlags,
+                mHandlerThread.getLooper());
 
         mComponentContextFixture.setTelecomManager(new TelecomManager(
                 mComponentContextFixture.getTestDouble(),
diff --git a/tests/src/com/android/server/telecom/tests/TelecomTestCase.java b/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
index 5b5c3ed7e..6956621f6 100644
--- a/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
+++ b/tests/src/com/android/server/telecom/tests/TelecomTestCase.java
@@ -18,6 +18,8 @@ package com.android.server.telecom.tests;
 
 import android.content.Context;
 import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.Looper;
 import android.telecom.Log;
 
 import androidx.test.InstrumentationRegistry;
@@ -38,6 +40,7 @@ public abstract class TelecomTestCase {
     protected Context mContext;
     @Mock
     FeatureFlags mFeatureFlags;
+    private HandlerThread mHandlerThread;
 
     MockitoHelper mMockitoHelper = new MockitoHelper();
     ComponentContextFixture mComponentContextFixture;
@@ -49,6 +52,7 @@ public abstract class TelecomTestCase {
         mMockitoHelper.setUp(InstrumentationRegistry.getContext(), getClass());
         MockitoAnnotations.initMocks(this);
 
+        Mockito.when(mFeatureFlags.callAudioCommunicationDeviceRefactor()).thenReturn(true);
         mComponentContextFixture = new ComponentContextFixture(mFeatureFlags);
         mContext = mComponentContextFixture.getTestDouble().getApplicationContext();
         Log.setSessionManager(mComponentContextFixture.getTestDouble().getApplicationContext(),
@@ -56,11 +60,25 @@ public abstract class TelecomTestCase {
     }
 
     public void tearDown() throws Exception {
+        if (mHandlerThread != null) {
+            mHandlerThread.quit();
+            mHandlerThread.join();
+            mHandlerThread = null;
+        }
+        mComponentContextFixture.destroy();
         mComponentContextFixture = null;
         mMockitoHelper.tearDown();
         Mockito.framework().clearInlineMocks();
     }
 
+    protected Looper getLooper() {
+        if (mHandlerThread == null) {
+            mHandlerThread = new HandlerThread("TelecomTestCase");
+            mHandlerThread.start();
+        }
+        return mHandlerThread.getLooper();
+    }
+
     protected static void waitForHandlerAction(Handler h, long timeoutMillis) {
         final CountDownLatch lock = new CountDownLatch(1);
         h.post(lock::countDown);
diff --git a/tests/src/com/android/server/telecom/tests/TransactionTests.java b/tests/src/com/android/server/telecom/tests/TransactionTests.java
index 78c22109d..6c049f65a 100644
--- a/tests/src/com/android/server/telecom/tests/TransactionTests.java
+++ b/tests/src/com/android/server/telecom/tests/TransactionTests.java
@@ -63,6 +63,7 @@ import com.android.server.telecom.ConnectionServiceWrapper;
 import com.android.server.telecom.PhoneNumberUtilsAdapter;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.callsequencing.CallsManagerCallSequencingAdapter;
 import com.android.server.telecom.callsequencing.TransactionManager;
 import com.android.server.telecom.callsequencing.VerifyCallStateChangeTransaction;
 import com.android.server.telecom.callsequencing.voip.EndCallTransaction;
@@ -97,6 +98,7 @@ public class TransactionTests extends TelecomTestCase {
     @Mock private Call mMockCall1;
     @Mock private Context mMockContext;
     @Mock private CallsManager mCallsManager;
+    @Mock private CallsManagerCallSequencingAdapter mCallSequencingAdapter;
     @Mock private ToastFactory mToastFactory;
     @Mock private ClockProxy mClockProxy;
     @Mock private PhoneNumberUtilsAdapter mPhoneNumberUtilsAdapter;
@@ -113,6 +115,7 @@ public class TransactionTests extends TelecomTestCase {
         MockitoAnnotations.initMocks(this);
         Mockito.when(mMockCall1.getId()).thenReturn(CALL_ID_1);
         Mockito.when(mMockContext.getResources()).thenReturn(Mockito.mock(Resources.class));
+        when(mCallsManager.getCallSequencingAdapter()).thenReturn(mCallSequencingAdapter);
     }
 
     @Override
@@ -220,7 +223,7 @@ public class TransactionTests extends TelecomTestCase {
         transaction.processTransaction(null);
 
         // THEN
-        verify(mCallsManager, times(1))
+        verify(mCallsManager.getCallSequencingAdapter(), times(1))
                 .transactionHoldPotentialActiveCallForNewCall(eq(mMockCall1), eq(false),
                         isA(OutcomeReceiver.class));
     }
@@ -292,20 +295,21 @@ public class TransactionTests extends TelecomTestCase {
                 .setCallType(CallAttributes.VIDEO_CALL)
                 .build();
 
+        Bundle extras = new Bundle();
         OutgoingCallTransaction t = new OutgoingCallTransaction(null,
-                mContext, null, mCallsManager, new Bundle(), mFeatureFlags);
+                mContext, null, mCallsManager, extras, mFeatureFlags);
 
         // WHEN
         when(mFeatureFlags.transactionalVideoState()).thenReturn(true);
         t.setFeatureFlags(mFeatureFlags);
 
         // THEN
-        assertEquals(VideoProfile.STATE_AUDIO_ONLY, t
-                .generateExtras(audioOnlyAttributes)
+        assertEquals(VideoProfile.STATE_AUDIO_ONLY, OutgoingCallTransaction
+                .generateExtras(null, extras, audioOnlyAttributes, mFeatureFlags)
                 .getInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE));
 
-        assertEquals(VideoProfile.STATE_BIDIRECTIONAL, t
-                .generateExtras(videoAttributes)
+        assertEquals(VideoProfile.STATE_BIDIRECTIONAL, OutgoingCallTransaction
+                .generateExtras(null, extras, videoAttributes, mFeatureFlags)
                 .getInt(TelecomManager.EXTRA_START_CALL_WITH_VIDEO_STATE));
     }
 
@@ -448,9 +452,9 @@ public class TransactionTests extends TelecomTestCase {
         callSpy.setState(initialState, "manual set in test");
 
         // Mocks some methods to not call the real method.
-        doNothing().when(callSpy).unhold();
-        doNothing().when(callSpy).hold();
-        doNothing().when(callSpy).disconnect();
+        doReturn(null).when(callSpy).unhold();
+        doReturn(null).when(callSpy).hold();
+        doReturn(null).when(callSpy).disconnect();
 
         return callSpy;
     }
diff --git a/tests/src/com/android/server/telecom/tests/TransactionalCallSequencingAdapterTest.java b/tests/src/com/android/server/telecom/tests/TransactionalCallSequencingAdapterTest.java
new file mode 100644
index 000000000..6449ea7b7
--- /dev/null
+++ b/tests/src/com/android/server/telecom/tests/TransactionalCallSequencingAdapterTest.java
@@ -0,0 +1,171 @@
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
+package com.android.server.telecom.tests;
+
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+import static org.mockito.Mockito.when;
+
+import android.content.Context;
+import android.content.res.Resources;
+import android.os.OutcomeReceiver;
+import android.telecom.CallException;
+import android.telecom.DisconnectCause;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.CallsManager;
+import com.android.server.telecom.callsequencing.CallTransaction;
+import com.android.server.telecom.callsequencing.CallTransactionResult;
+import com.android.server.telecom.callsequencing.TransactionManager;
+import com.android.server.telecom.callsequencing.TransactionalCallSequencingAdapter;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+import org.mockito.Mockito;
+import org.mockito.MockitoAnnotations;
+
+import java.util.concurrent.CompletableFuture;
+import java.util.concurrent.ExecutionException;
+
+
+/**
+ * Unit tests for {@link TransactionalCallSequencingAdapter}.
+ *
+ * These tests verify the behavior of the TransactionalCallSequencingAdapter, focusing on
+ * how it interacts with the TransactionManager and CallsManager, particularly in the
+ * context of asynchronous operations and feature flag configurations (e.g., setting
+ * rejected calls to a disconnected state).
+ */
+public class TransactionalCallSequencingAdapterTest extends TelecomTestCase {
+
+    private static final String CALL_ID_1 = "1";
+    private static final DisconnectCause REJECTED_DISCONNECT_CAUSE =
+            new DisconnectCause(DisconnectCause.REJECTED);
+
+    @Mock private Call mMockCall1;
+    @Mock private Context mMockContext;
+    @Mock private CallsManager mCallsManager;
+    @Mock private TransactionManager mTransactionManager;
+
+    private TransactionalCallSequencingAdapter mAdapter;
+
+    @Override
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        MockitoAnnotations.initMocks(this);
+        when(mMockCall1.getId()).thenReturn(CALL_ID_1);
+        when(mMockContext.getResources()).thenReturn(Mockito.mock(Resources.class));
+        mAdapter = new TransactionalCallSequencingAdapter(
+                mTransactionManager, mCallsManager, true);
+    }
+
+    @Override
+    @After
+    public void tearDown() throws Exception {
+        super.tearDown();
+    }
+
+    /**
+     * Tests the scenario where an incoming call is rejected and the onSetDisconnect is called.
+     * Verifies that {@link CallsManager#markCallAsDisconnected} *is* called and that the
+     * {@link OutcomeReceiver} receives the correct result, handling the asynchronous nature of
+     * the operation.
+     */
+    @Test
+    public void testOnSetDisconnected() {
+        // GIVEN -a new incoming call that is rejected
+
+        // Create a CompletableFuture to control the asynchronous operation.
+        CompletableFuture<Boolean> future = new CompletableFuture<>();
+
+        // Mock the TransactionManager's addTransaction method.
+        setupAddTransactionMock(future);
+
+        // Create a mock OutcomeReceiver to verify interactions.
+        OutcomeReceiver<CallTransactionResult, CallException> resultReceiver =
+                mock(OutcomeReceiver.class);
+
+        // WHEN - Call onSetDisconnected and get the result future.
+        mAdapter.onSetDisconnected(
+                mMockCall1,
+                REJECTED_DISCONNECT_CAUSE,
+                mock(CallTransaction.class),
+                resultReceiver);
+
+        // Simulate the asynchronous operation completing.
+        completeAddTransactionSuccessfully(future);
+
+        // THEN - Verify that markCallAsDisconnected and the receiver's onResult were called.
+        verifyMarkCallAsDisconnectedAndReceiverResult(resultReceiver);
+    }
+    /**
+     * Sets up the mock behavior for {@link TransactionManager#addTransaction}.
+     *
+     * @param future The CompletableFuture to be returned by the mocked method.
+     */
+    private void setupAddTransactionMock(CompletableFuture<Boolean> future) {
+        when(mTransactionManager.addTransaction(any(), any())).thenAnswer(invocation -> {
+            return future; // Return the provided future.
+        });
+    }
+    /**
+     * Simulates the successful completion of the asynchronous operation tracked by the given
+     * future. Captures the {@link OutcomeReceiver} passed to
+     * {@link TransactionManager#addTransaction}, completes the future, and invokes
+     * {@link OutcomeReceiver#onResult} with a successful result.
+     *
+     * @param future The CompletableFuture to complete.
+     */
+    private void completeAddTransactionSuccessfully(CompletableFuture<Boolean> future) {
+        // Capture the OutcomeReceiver passed to addTransaction.
+        ArgumentCaptor<OutcomeReceiver<CallTransactionResult, CallException>> captor =
+                ArgumentCaptor.forClass(OutcomeReceiver.class);
+        verify(mTransactionManager).addTransaction(any(CallTransaction.class), captor.capture());
+
+        // Complete the future to signal the end of the asynchronous operation.
+        future.complete(true);
+
+        // Create a successful CallTransactionResult.
+        CallTransactionResult callTransactionResult = new CallTransactionResult(
+                CallTransactionResult.RESULT_SUCCEED,
+                "EndCallTransaction: RESULT_SUCCEED");
+
+        // Invoke onResult on the captured OutcomeReceiver.
+        captor.getValue().onResult(callTransactionResult);
+
+    }
+    /**
+     * Verifies that {@link CallsManager#markCallAsDisconnected} and the provided
+     * {@link OutcomeReceiver}'s {@code onResult} method were called.  Also waits for the future
+     * to complete.
+     *
+     * @param resultReceiver The mock OutcomeReceiver.
+     */
+    private void verifyMarkCallAsDisconnectedAndReceiverResult(
+            OutcomeReceiver<CallTransactionResult, CallException> resultReceiver) {
+        verify(mCallsManager, times(1)).markCallAsDisconnected(
+                mMockCall1,
+                REJECTED_DISCONNECT_CAUSE);
+        verify(resultReceiver).onResult(any());
+    }
+}
\ No newline at end of file
diff --git a/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java b/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
index fea613583..16b6e44b1 100644
--- a/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
+++ b/tests/src/com/android/server/telecom/tests/TransactionalServiceWrapperTest.java
@@ -34,6 +34,7 @@ import android.telecom.PhoneAccountHandle;
 
 import com.android.internal.telecom.ICallControl;
 import com.android.internal.telecom.ICallEventCallback;
+import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.TelecomSystem;
@@ -70,6 +71,7 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
     @Mock private TransactionManager mTransactionManager;
     @Mock private ICallEventCallback mCallEventCallback;
     @Mock private TransactionalServiceRepository mRepository;
+    @Mock private AnomalyReporterAdapter mAnomalyReporterAdapter;
     @Mock private IBinder mIBinder;
     private final TelecomSystem.SyncRoot mLock = new TelecomSystem.SyncRoot() {};
 
@@ -84,7 +86,7 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
         Mockito.when(mCallEventCallback.asBinder()).thenReturn(mIBinder);
         mTransactionalServiceWrapper = new TransactionalServiceWrapper(mCallEventCallback,
                 mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
-                false /*call sequencing*/);
+                false /*call sequencing*/, mFeatureFlags, mAnomalyReporterAdapter);
     }
 
     @Override
@@ -98,7 +100,7 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
         TransactionalServiceWrapper service =
                 new TransactionalServiceWrapper(mCallEventCallback,
                         mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
-                        false /*call sequencing*/);
+                        false /*call sequencing*/, mFeatureFlags, mAnomalyReporterAdapter);
 
         assertEquals(SERVICE_HANDLE, service.getPhoneAccountHandle());
         assertEquals(1, service.getNumberOfTrackedCalls());
@@ -109,7 +111,7 @@ public class TransactionalServiceWrapperTest extends TelecomTestCase {
         TransactionalServiceWrapper service =
                 new TransactionalServiceWrapper(mCallEventCallback,
                         mCallsManager, SERVICE_HANDLE, mMockCall1, mRepository, mTransactionManager,
-                        false /*call sequencing*/);
+                        false /*call sequencing*/, mFeatureFlags, mAnomalyReporterAdapter);
 
         assertEquals(1, service.getNumberOfTrackedCalls());
         service.trackCall(mMockCall2);
diff --git a/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java b/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
index bf68f8c43..1b3856c38 100644
--- a/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
+++ b/tests/src/com/android/server/telecom/tests/VoipCallMonitorTest.java
@@ -22,11 +22,16 @@ import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
 import static android.content.pm.ServiceInfo.FOREGROUND_SERVICE_TYPE_PHONE_CALL;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertNull;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.eq;
+import static org.mockito.Mockito.atLeastOnce;
 import static org.mockito.Mockito.mock;
-import static org.mockito.Mockito.never;
 import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
@@ -39,6 +44,7 @@ import android.content.ComponentName;
 import android.content.Intent;
 import android.content.ServiceConnection;
 import android.os.Bundle;
+import android.os.Handler;
 import android.os.IBinder;
 import android.os.UserHandle;
 import android.service.notification.StatusBarNotification;
@@ -51,13 +57,18 @@ import com.android.server.telecom.CallState;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.callsequencing.voip.VoipCallMonitor;
 
+import org.junit.After;
 import org.junit.Before;
+import org.junit.Ignore;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
 import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 
+import java.util.Set;
+import java.util.concurrent.ConcurrentHashMap;
+
 @RunWith(JUnit4.class)
 public class VoipCallMonitorTest extends TelecomTestCase {
     private VoipCallMonitor mMonitor;
@@ -68,8 +79,9 @@ public class VoipCallMonitorTest extends TelecomTestCase {
     private static final String ID_1 = "id1";
     public static final String CHANNEL_ID = "TelecomVoipAppChannelId";
     private static final UserHandle USER_HANDLE_1 = new UserHandle(1);
-    private static final long TIMEOUT = 5000L;
+    private static final long TIMEOUT = 6000L;
 
+    @Mock private Handler mHandler;
     @Mock private TelecomSystem.SyncRoot mLock;
     @Mock private ActivityManagerInternal mActivityManagerInternal;
     @Mock private IBinder mServiceConnection;
@@ -83,15 +95,23 @@ public class VoipCallMonitorTest extends TelecomTestCase {
     @Before
     public void setUp() throws Exception {
         super.setUp();
-        mMonitor = new VoipCallMonitor(mContext, mLock);
+        mHandler = mock(Handler.class);
+        mMonitor = new VoipCallMonitor(mContext, mHandler, mLock);
         mActivityManagerInternal = mock(ActivityManagerInternal.class);
         mMonitor.setActivityManagerInternal(mActivityManagerInternal);
-        mMonitor.startMonitor();
+        mMonitor.registerNotificationListener();
         when(mActivityManagerInternal.startForegroundServiceDelegate(any(
                 ForegroundServiceDelegationOptions.class), any(ServiceConnection.class)))
                 .thenReturn(true);
     }
 
+    @Override
+    @After
+    public void tearDown() throws Exception {
+        mMonitor.unregisterNotificationListener();
+        super.tearDown();
+    }
+
     /**
      * This test ensures VoipCallMonitor is passing the correct foregroundServiceTypes when starting
      * foreground service delegation on behalf of a client.
@@ -106,65 +126,98 @@ public class VoipCallMonitorTest extends TelecomTestCase {
         mMonitor.onCallAdded(call);
 
         verify(mActivityManagerInternal, timeout(TIMEOUT)).startForegroundServiceDelegate(
-                 optionsCaptor.capture(), any(ServiceConnection.class));
+                optionsCaptor.capture(), any(ServiceConnection.class));
 
-        assertEquals( FOREGROUND_SERVICE_TYPE_PHONE_CALL |
-                FOREGROUND_SERVICE_TYPE_MICROPHONE |
-                FOREGROUND_SERVICE_TYPE_CAMERA |
-                FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
+        assertEquals(FOREGROUND_SERVICE_TYPE_PHONE_CALL |
+                        FOREGROUND_SERVICE_TYPE_MICROPHONE |
+                        FOREGROUND_SERVICE_TYPE_CAMERA |
+                        FOREGROUND_SERVICE_TYPE_CONNECTED_DEVICE,
                 optionsCaptor.getValue().mForegroundServiceTypes);
 
         mMonitor.onCallRemoved(call);
     }
 
+    /**
+     * Tests that {@link VoipCallMonitor#stopFGSDelegation} does not throw a NullPointerException
+     * when called on a transactional call that has not been tracked by the account to calls
+     * mapping, and that no calls are made to ActivityManagerInternal.stopForegroundServiceDelegate.
+     */
+    @SmallTest
+    @Test
+    public void testStopFgsDelegationWithoutAnyTrackedCalls() {
+        //GIVEN: a transactional call that has NOT been added to the monitor tracking
+        Call call = createTestCall("testCall", mHandle1User1);
+        ConcurrentHashMap<PhoneAccountHandle, Set<Call>> m = mMonitor.getAccountToCallsMapping();
+        assertEquals(0, m.size());
+        assertNull(m.get(mHandle1User1));
+
+        // WHEN: stop is called on the transactional call
+        mMonitor.stopFGSDelegation(call, mHandle1User1);
+
+        // THEN: a NullPointerException should not be thrown at runtime
+        verify(mActivityManagerInternal, times(0))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
+        assertEquals(0, m.size());
+        assertNull(m.get(mHandle1User1));
+    }
+
     @SmallTest
     @Test
     public void testStartMonitorForOneCall() {
+        // GIVEN - a single call and notification for a voip app
         Call call = createTestCall("testCall", mHandle1User1);
-        IBinder service = mock(IBinder.class);
+        StatusBarNotification sbn = createStatusBarNotificationFromHandle(mHandle1User1, 1);
 
-        ArgumentCaptor<ServiceConnection> captor = ArgumentCaptor.forClass(ServiceConnection.class);
-        mMonitor.onCallAdded(call);
-        verify(mActivityManagerInternal, timeout(TIMEOUT)).startForegroundServiceDelegate(any(
-                ForegroundServiceDelegationOptions.class), captor.capture());
-        ServiceConnection conn = captor.getValue();
-        conn.onServiceConnected(mHandle1User1.getComponentName(), service);
+        // WHEN - the Voip call is added and a notification is posted, verify FGS is gained
+        addCallAndVerifyFgsIsGained(call);
+        mMonitor.postNotification(sbn);
+        assertNotificationTimeoutTriggered();
+        assertFalse(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call));
 
+        // THEN - when the Voip call is removed, verify that FGS is revoked for the app
         mMonitor.onCallRemoved(call);
-        verify(mActivityManagerInternal, timeout(TIMEOUT)).stopForegroundServiceDelegate(eq(conn));
+        mMonitor.removeNotification(sbn);
+        verify(mActivityManagerInternal, times(1))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
     }
 
+    /**
+     * Verify FGS is not lost if another call is ongoing for a Voip app
+     */
     @SmallTest
     @Test
-    public void testMonitorForTwoCallsOnSameHandle() {
+    public void testStopDelegation_SameApp() {
+        // GIVEN - 2 consecutive calls for a single Voip app
         Call call1 = createTestCall("testCall1", mHandle1User1);
+        StatusBarNotification sbn1 = createStatusBarNotificationFromHandle(mHandle1User1, 1);
         Call call2 = createTestCall("testCall2", mHandle1User1);
-        IBinder service = mock(IBinder.class);
-
-        ArgumentCaptor<ServiceConnection> captor1 =
-                ArgumentCaptor.forClass(ServiceConnection.class);
-        mMonitor.onCallAdded(call1);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
-                .startForegroundServiceDelegate(any(ForegroundServiceDelegationOptions.class),
-                        captor1.capture());
-        ServiceConnection conn1 = captor1.getValue();
-        conn1.onServiceConnected(mHandle1User1.getComponentName(), service);
-
-        ArgumentCaptor<ServiceConnection> captor2 =
-                ArgumentCaptor.forClass(ServiceConnection.class);
+        StatusBarNotification sbn2 = createStatusBarNotificationFromHandle(mHandle1User1, 2);
+
+        // WHEN - the second call is added and the first is disconnected
+        // -- add the first all and post the corresponding notification
+        addCallAndVerifyFgsIsGained(call1);
+        assertTrue(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call1));
+        mMonitor.postNotification(sbn1);
+        assertNotificationTimeoutTriggered();
+        assertFalse(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call1));
+        // -- add the second call and post the corresponding notification
         mMonitor.onCallAdded(call2);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(2))
-                .startForegroundServiceDelegate(any(ForegroundServiceDelegationOptions.class),
-                        captor2.capture());
-        ServiceConnection conn2 = captor2.getValue();
-        conn2.onServiceConnected(mHandle1User1.getComponentName(), service);
+        assertTrue(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call2));
+        mMonitor.postNotification(sbn2);
+        assertNotificationTimeoutTriggered();
+        assertFalse(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call2));
 
+        // THEN - assert FGS is maintained for the process since there is still an ongoing call
         mMonitor.onCallRemoved(call1);
-        verify(mActivityManagerInternal, never()).stopForegroundServiceDelegate(
-                any(ServiceConnection.class));
+        mMonitor.removeNotification(sbn1);
+        assertNotificationTimeoutTriggered();
+        verify(mActivityManagerInternal, times(0))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
+        // once all calls are removed, verify FGS is stopped
         mMonitor.onCallRemoved(call2);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
-                .stopForegroundServiceDelegate(eq(conn2));
+        mMonitor.removeNotification(sbn2);
+        verify(mActivityManagerInternal, times(1))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
     }
 
     @SmallTest
@@ -204,40 +257,6 @@ public class VoipCallMonitorTest extends TelecomTestCase {
         verify(mActivityManagerInternal).stopForegroundServiceDelegate(eq(conn1));
     }
 
-    @SmallTest
-    @Test
-    public void testStopDelegation() {
-        Call call1 = createTestCall("testCall1", mHandle1User1);
-        Call call2 = createTestCall("testCall2", mHandle1User1);
-        IBinder service = mock(IBinder.class);
-
-        ArgumentCaptor<ServiceConnection> captor1 =
-                ArgumentCaptor.forClass(ServiceConnection.class);
-        mMonitor.onCallAdded(call1);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
-                .startForegroundServiceDelegate(any(ForegroundServiceDelegationOptions.class),
-                        captor1.capture());
-        ServiceConnection conn1 = captor1.getValue();
-        conn1.onServiceConnected(mHandle1User1.getComponentName(), service);
-
-        ArgumentCaptor<ServiceConnection> captor2 =
-                ArgumentCaptor.forClass(ServiceConnection.class);
-        mMonitor.onCallAdded(call2);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(2))
-                .startForegroundServiceDelegate(any(ForegroundServiceDelegationOptions.class),
-                        captor2.capture());
-        ServiceConnection conn2 = captor2.getValue();
-        conn2.onServiceConnected(mHandle1User1.getComponentName(), service);
-
-        mMonitor.stopFGSDelegation(call1);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
-                .stopForegroundServiceDelegate(eq(conn2));
-        conn2.onServiceDisconnected(mHandle1User1.getComponentName());
-        mMonitor.onCallRemoved(call1);
-        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
-                .stopForegroundServiceDelegate(any(ServiceConnection.class));
-    }
-
     /**
      * Ensure an app loses foreground service delegation if the user dismisses the call style
      * notification or the app removes the notification.
@@ -245,9 +264,10 @@ public class VoipCallMonitorTest extends TelecomTestCase {
      */
     @SmallTest
     @Test
+    @Ignore("b/383403913") // when b/383403913 is fixed, remove the @Ignore
     public void testStopFgsIfCallNotificationIsRemoved_PostedAfterFgsIsGained() {
         // GIVEN
-        StatusBarNotification sbn = createStatusBarNotificationFromHandle(mHandle1User1);
+        StatusBarNotification sbn = createStatusBarNotificationFromHandle(mHandle1User1, 1);
 
         // WHEN
         // FGS is gained after the call is added to VoipCallMonitor
@@ -259,33 +279,71 @@ public class VoipCallMonitorTest extends TelecomTestCase {
         // shortly after posting the notification, simulate the user dismissing it
         mMonitor.removeNotification(sbn);
         // FGS should be removed once the notification is removed
-        verify(mActivityManagerInternal, timeout(TIMEOUT)).stopForegroundServiceDelegate(c);
+        assertNotificationTimeoutTriggered();
+        verify(mActivityManagerInternal, times(1)).stopForegroundServiceDelegate(c);
     }
 
+
     /**
-     * Ensure an app loses foreground service delegation if the user dismisses the call style
-     * notification or the app removes the notification.
-     * Note: post the notification BEFORE foreground service delegation is gained
+     * Tests the behavior of foreground service (FGS) delegation for a VoIP app during a scenario
+     * with two consecutive calls.  In this scenario, the first call is disconnected shortly after
+     * being created but the second call continues.  The apps foreground service should be
+     * maintained.
+     *
+     * GIVEN: Two calls (call1 and call2) are created for the same VoIP app.
+     * WHEN:
+     *  - call1 is added, starting the FGS.
+     *  - call2 is added immediately after.
+     *  - call1 is removed.
+     *  - call1 notification is finally posted (late)
+     *  - call1 notification is removed shortly after since the call was disconnected
+     * THEN:
+     *  - Verifies that the FGS is NOT stopped while call2 is still active.
+     *  - Verifies that the FGS IS stopped after call2 is removed and its notification is gone.
      */
     @SmallTest
     @Test
-    public void testStopFgsIfCallNotificationIsRemoved_PostedBeforeFgsIsGained() {
-        // GIVEN
-        StatusBarNotification sbn = createStatusBarNotificationFromHandle(mHandle1User1);
+    public void test2CallsInQuickSuccession() {
+        // GIVEN - 2 consecutive calls for a single Voip app
+        Call call1 = createTestCall("testCall1", mHandle1User1);
+        StatusBarNotification sbn1 = createStatusBarNotificationFromHandle(mHandle1User1, 1);
+        Call call2 = createTestCall("testCall2", mHandle1User1);
+        StatusBarNotification sbn2 = createStatusBarNotificationFromHandle(mHandle1User1, 2);
 
-        // WHEN
-        //  an app posts a call style notification before FGS is gained
-        mMonitor.postNotification(sbn);
-        // FGS is gained after the call is added to VoipCallMonitor
-        ServiceConnection c = addCallAndVerifyFgsIsGained(createTestCall("1", mHandle1User1));
+        // WHEN - add the calls to the VoipCallMonitor class
+        addCallAndVerifyFgsIsGained(call1);
+        mMonitor.onCallAdded(call2);
+        assertTrue(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call1));
+        assertTrue(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call2));
+        // -- mock the app disconnecting the first
+        mMonitor.onCallRemoved(call1);
+        // Shortly after, simulate the notification updates coming in to the class
+        // -- post and remove the first call-style notification
+        mMonitor.postNotification(sbn1);
+        assertFalse(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call1));
+        mMonitor.removeNotification(sbn1);
+        assertNotificationTimeoutTriggered();
+
+        // -- keep the second notification up since the call will continue
+        mMonitor.postNotification(sbn2);
+        assertFalse(mMonitor.getNewCallsMissingCallStyleNotificationQueue().contains(call2));
+
+        // THEN - assert FGS is maintained for the process since there is still an ongoing call
+        assertNotificationTimeoutTriggered();
+        verify(mActivityManagerInternal, times(0))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
 
-        // THEN
-        // shortly after posting the notification, simulate the user dismissing it
-        mMonitor.removeNotification(sbn);
-        // FGS should be removed once the notification is removed
-        verify(mActivityManagerInternal, timeout(TIMEOUT)).stopForegroundServiceDelegate(c);
+        // once all calls are removed, verify FGS is stopped
+        mMonitor.onCallRemoved(call2);
+        mMonitor.removeNotification(sbn2);
+        verify(mActivityManagerInternal, timeout(TIMEOUT).times(1))
+                .stopForegroundServiceDelegate(any(ServiceConnection.class));
     }
 
+    /**
+     * Helpers for testing
+     */
+
     private Call createTestCall(String id, PhoneAccountHandle handle) {
         Call call = mock(Call.class);
         when(call.getTargetPhoneAccount()).thenReturn(handle);
@@ -311,9 +369,10 @@ public class VoipCallMonitorTest extends TelecomTestCase {
                 .build();
     }
 
-    private StatusBarNotification createStatusBarNotificationFromHandle(PhoneAccountHandle handle) {
+    private StatusBarNotification createStatusBarNotificationFromHandle(
+            PhoneAccountHandle handle, int id) {
         return new StatusBarNotification(
-                handle.getComponentName().getPackageName(), "", 0, "", 0, 0,
+                handle.getComponentName().getPackageName(), "", id, "", 0, 0,
                 createCallStyleNotification(), handle.getUserHandle(), "", 0);
     }
 
@@ -329,7 +388,22 @@ public class VoipCallMonitorTest extends TelecomTestCase {
         // onServiceConnected must be called in order for VoipCallMonitor to start monitoring for
         // a notification before the timeout expires
         ServiceConnection serviceConnection = captor.getValue();
-        serviceConnection.onServiceConnected(mHandle1User1.getComponentName(), mServiceConnection);
+        serviceConnection.onServiceConnected(
+                call.getTargetPhoneAccount().getComponentName(),
+                mServiceConnection);
         return serviceConnection;
     }
+
+    /**
+     * Verifies that a delayed runnable is posted to the handler to handle the notification timeout.
+     * This also executes the captured runnable to simulate the timeout occurring.
+     */
+    private void assertNotificationTimeoutTriggered() {
+        ArgumentCaptor<Runnable> runnableCaptor = ArgumentCaptor.forClass(Runnable.class);
+        verify(mHandler, atLeastOnce()).postDelayed(
+                runnableCaptor.capture(),
+                eq(VoipCallMonitor.NOTIFICATION_NOT_POSTED_IN_TIME_TIMEOUT));
+        Runnable capturedRunnable = runnableCaptor.getValue();
+        capturedRunnable.run();
+    }
 }
```

