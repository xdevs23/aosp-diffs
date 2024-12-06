```diff
diff --git a/Android.bp b/Android.bp
index 94654a62e..0d1c81ddd 100644
--- a/Android.bp
+++ b/Android.bp
@@ -84,9 +84,9 @@ android_test {
         "tests/res",
     ],
     libs: [
-        "android.test.mock",
-        "android.test.base",
-        "android.test.runner",
+        "android.test.mock.stubs.system",
+        "android.test.base.stubs.system",
+        "android.test.runner.stubs.system",
     ],
 
     jni_libs: [
diff --git a/AndroidManifest.xml b/AndroidManifest.xml
index a9b6154a5..08521a58a 100644
--- a/AndroidManifest.xml
+++ b/AndroidManifest.xml
@@ -45,6 +45,8 @@
     <!-- Required to determine source of ongoing audio recordings. -->
     <uses-permission android:name="android.permission.MODIFY_AUDIO_ROUTING"/>
     <uses-permission android:name="android.permission.MODIFY_PHONE_STATE"/>
+    <!-- Required to query the audio framework to determine if a notification sound should play. -->
+    <uses-permission android:name="android.permission.QUERY_AUDIO_STATE"/>
     <uses-permission android:name="android.permission.READ_CALL_LOG"/>
     <!-- Required to check for direct to voicemail, to load custom ringtones for incoming calls
         which are specified on a per contact basis, and also to determine user preferred
@@ -66,7 +68,6 @@
     <uses-permission android:name="android.permission.USE_FULL_SCREEN_INTENT"/>
     <uses-permission android:name="android.permission.ACCESS_LAST_KNOWN_CELL_ID"/>
     <uses-permission android:name="android.permission.STATUS_BAR_SERVICE" />
-    <uses-permission android:name="android.permission.MODIFY_AUDIO_ROUTING" />
 
     <permission android:name="android.permission.BROADCAST_CALLLOG_INFO"
          android:label="Broadcast the call type/duration information"
@@ -136,7 +137,7 @@
                          contacts provider entries. Any data not fitting the schema described is ignored. -->
         <activity android:name=".components.UserCallActivity"
              android:label="@string/userCallActivityLabel"
-             android:theme="@style/Theme.Telecomm.Transparent"
+             android:theme="@style/Theme.Telecomm.UserCallActivityNoSplash"
              android:permission="android.permission.CALL_PHONE"
              android:excludeFromRecents="true"
              android:process=":ui"
diff --git a/TEST_MAPPING b/TEST_MAPPING
index acab8ef61..09ebfe255 100644
--- a/TEST_MAPPING
+++ b/TEST_MAPPING
@@ -58,5 +58,15 @@
         }
       ]
     }
+  ],
+  "postsubmit": [
+    {
+      "name": "CtsTelecomCujTestCases",
+      "options": [
+        {
+          "exclude-annotation": "androidx.test.filters.FlakyTest"
+        }
+      ]
+    }
   ]
 }
diff --git a/flags/Android.bp b/flags/Android.bp
index 45acacf3d..501eba40c 100644
--- a/flags/Android.bp
+++ b/flags/Android.bp
@@ -43,5 +43,7 @@ aconfig_declarations {
         "telecom_profile_user_flags.aconfig",
         "telecom_bluetoothdevicemanager_flags.aconfig",
         "telecom_non_critical_security_flags.aconfig",
+        "telecom_headless_system_user_mode.aconfig",
+        "telecom_metrics_flags.aconfig",
     ],
 }
diff --git a/flags/telecom_anomaly_report_flags.aconfig b/flags/telecom_anomaly_report_flags.aconfig
index 296b300f5..b060ed0eb 100644
--- a/flags/telecom_anomaly_report_flags.aconfig
+++ b/flags/telecom_anomaly_report_flags.aconfig
@@ -8,3 +8,11 @@ flag {
   description: "When getCurrentFocusCall times out, generate an anom. report"
   bug: "309541253"
 }
+
+# OWNER=tjstuart TARGET=25Q2
+flag {
+  name: "disconnect_self_managed_stuck_startup_calls"
+  namespace: "telecom"
+  description: "If a self-managed call is stuck in certain states, disconnect it"
+  bug: "360298368"
+}
diff --git a/flags/telecom_call_filtering_flags.aconfig b/flags/telecom_call_filtering_flags.aconfig
index d80cfa3b9..693d727b0 100644
--- a/flags/telecom_call_filtering_flags.aconfig
+++ b/flags/telecom_call_filtering_flags.aconfig
@@ -7,4 +7,15 @@ flag {
   namespace: "telecom"
   description: "Gates whether to still perform Dnd filter when phone account has skip_filter call extra."
   bug: "222333869"
-}
\ No newline at end of file
+}
+
+# OWNER=tjstuart TARGET=25Q1
+flag {
+  name: "check_completed_filters_on_timeout"
+  namespace: "telecom"
+  description: "If the Filtering Graph times out, combine the finished results"
+  bug: "364946812"
+  metadata {
+    purpose: PURPOSE_BUGFIX
+  }
+}
diff --git a/flags/telecom_call_flags.aconfig b/flags/telecom_call_flags.aconfig
index ed75f145e..634d7a383 100644
--- a/flags/telecom_call_flags.aconfig
+++ b/flags/telecom_call_flags.aconfig
@@ -2,6 +2,13 @@ package: "com.android.server.telecom.flags"
 container: "system"
 
 # OWNER=tjstuart TARGET=24Q3
+flag {
+  name: "prevent_redundant_location_permission_grant_and_revoke"
+  namespace: "telecom"
+  description: "avoid redundant action of grant and revoke location permission for multiple emergency calls"
+  bug: "345386002"
+}
+
 flag {
   name: "transactional_cs_verifier"
   namespace: "telecom"
@@ -16,6 +23,17 @@ flag {
   bug: "321369729"
 }
 
+# OWNER=breadley TARGET=24Q4
+flag {
+  name: "cache_call_events"
+  namespace: "telecom"
+  description: "Cache call events to wait for the ServiceWrapper to be set"
+  bug: "364311190"
+  metadata {
+      purpose: PURPOSE_BUGFIX
+    }
+}
+
 # OWNER = breadley TARGET=24Q3
 flag {
   name: "cancel_removal_on_emergency_redial"
@@ -26,3 +44,25 @@ flag {
       purpose: PURPOSE_BUGFIX
     }
 }
+
+# OWNER=breadley TARGET=24Q4
+flag {
+  name: "use_stream_voice_call_tones"
+  namespace: "telecom"
+  description: "Use STREAM_VOICE_CALL only for ToneGenerator"
+  bug: "363262590"
+  metadata {
+      purpose: PURPOSE_BUGFIX
+    }
+}
+
+# OWNER=tjstuart TARGET=25Q1
+flag {
+  name: "remap_transactional_capabilities"
+  namespace: "telecom"
+  description: "Transactional call capabilities need to be remapped to Connection capabilities"
+  bug: "366063695"
+  metadata {
+      purpose: PURPOSE_BUGFIX
+    }
+}
\ No newline at end of file
diff --git a/flags/telecom_connection_service_wrapper_flags.aconfig b/flags/telecom_connection_service_wrapper_flags.aconfig
index 38e5e139f..8e77af516 100644
--- a/flags/telecom_connection_service_wrapper_flags.aconfig
+++ b/flags/telecom_connection_service_wrapper_flags.aconfig
@@ -7,4 +7,15 @@ flag {
   namespace: "telecom"
   description: "Ensure that the associatedCallCount of CS and RCS is accurately being tracked."
   bug: "286154316"
+}
+
+# OWNER=tjstuart TARGET=24Q4
+flag {
+  name: "csw_service_interface_is_null"
+  namespace: "telecom"
+  description: "fix potential NPE in onCreateConnection when the ServiceInterface is cleared out"
+  bug: "364811868"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+      }
 }
\ No newline at end of file
diff --git a/flags/telecom_headless_system_user_mode.aconfig b/flags/telecom_headless_system_user_mode.aconfig
new file mode 100644
index 000000000..f79873354
--- /dev/null
+++ b/flags/telecom_headless_system_user_mode.aconfig
@@ -0,0 +1,14 @@
+package: "com.android.server.telecom.flags"
+container: "system"
+
+# OWNER=grantmenke TARGET=25Q1
+flag {
+    name: "telecom_main_user_in_get_respond_message_app"
+    is_exported: true
+    namespace: "telecom"
+    description: "Support HSUM mode by using the main user when getting respond via message app."
+    bug: "358587742"
+    metadata {
+        purpose: PURPOSE_BUGFIX
+      }
+}
\ No newline at end of file
diff --git a/flags/telecom_incallservice_flags.aconfig b/flags/telecom_incallservice_flags.aconfig
index ea842ac76..c95816a0c 100644
--- a/flags/telecom_incallservice_flags.aconfig
+++ b/flags/telecom_incallservice_flags.aconfig
@@ -24,3 +24,19 @@ flag {
   description: "Binding/Unbinding to BluetoothInCallServices in proper time to improve call audio"
   bug: "306395598"
 }
+
+# OWNER=pmadapurmath TARGET=24Q4
+flag {
+  name: "on_call_endpoint_changed_ics_on_connected"
+  namespace: "telecom"
+  description: "Ensure onCallEndpointChanged is sent to ICS when it connects."
+  bug: "348297436"
+}
+
+# OWNER=tjstuart TARGET=24Q4
+flag {
+  name: "do_not_send_call_to_null_ics"
+  namespace: "telecom"
+  description: "Only send calls to the InCallService if the binding is not null"
+  bug: "345473659"
+}
diff --git a/flags/telecom_metrics_flags.aconfig b/flags/telecom_metrics_flags.aconfig
new file mode 100644
index 000000000..e582e9ecc
--- /dev/null
+++ b/flags/telecom_metrics_flags.aconfig
@@ -0,0 +1,10 @@
+package: "com.android.server.telecom.flags"
+container: "system"
+
+# OWNER=huiwang TARGET=25Q1
+flag {
+  name: "telecom_metrics_support"
+  namespace: "telecom"
+  description: "Support telecom metrics"
+  bug: "362394177"
+}
diff --git a/flags/telecom_ringer_flag_declarations.aconfig b/flags/telecom_ringer_flag_declarations.aconfig
index f126bf349..6517e0f62 100644
--- a/flags/telecom_ringer_flag_declarations.aconfig
+++ b/flags/telecom_ringer_flag_declarations.aconfig
@@ -7,4 +7,12 @@ flag {
   namespace: "telecom"
   description: "Gates whether to use a serialized, device-specific ring vibration."
   bug: "282113261"
+}
+
+# OWNER=grantmenke TARGET=24Q4
+flag {
+  name: "ensure_in_car_ringing"
+  namespace: "telecom"
+  description: "Gates whether to ensure that when a user is in their car, they are able to hear ringing for an incoming call."
+  bug: "348708398"
 }
\ No newline at end of file
diff --git a/proto/pulled_atoms.proto b/proto/pulled_atoms.proto
new file mode 100644
index 000000000..7360b6a0a
--- /dev/null
+++ b/proto/pulled_atoms.proto
@@ -0,0 +1,114 @@
+syntax = "proto2";
+
+package com.android.server.telecom;
+
+option java_package = "com.android.server.telecom";
+option java_outer_classname = "PulledAtomsClass";
+
+message PulledAtoms {
+  repeated CallStats call_stats = 1;
+  optional int64 call_stats_pull_timestamp_millis = 2;
+  repeated CallAudioRouteStats call_audio_route_stats = 3;
+  optional int64 call_audio_route_stats_pull_timestamp_millis = 4;
+  repeated TelecomApiStats telecom_api_stats = 5;
+  optional int64 telecom_api_stats_pull_timestamp_millis = 6;
+  repeated TelecomErrorStats telecom_error_stats = 7;
+  optional int64 telecom_error_stats_pull_timestamp_millis = 8;
+}
+
+/**
+ * Pulled atom to capture stats of the calls
+ * From frameworks/proto_logging/stats/atoms/telecomm/telecom_extension_atom.proto
+ */
+message CallStats {
+    // The value should be converted to android.telecom.CallDirectionEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 call_direction = 1;
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
+    // The value should be converted to android.telecom.AccountTypeEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 account_type = 5;
+
+    // UID of the package to init the call. This should always be -1/unknown for
+    // the private space calls
+    optional int32 uid = 6;
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
+ * From frameworks/proto_logging/stats/atoms/telecomm/telecom_extension_atom.proto
+ */
+message CallAudioRouteStats {
+    // The value should be converted to android.telecom.CallAudioEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 call_audio_route_source = 1;
+
+    // The value should be converted to android.telecom.CallAudioEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 call_audio_route_dest = 2;
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
+ * From frameworks/proto_logging/stats/atoms/telecomm/telecom_extension_atom.proto
+ */
+message TelecomApiStats {
+    // The value should be converted to android.telecom.ApiNameEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 api_name = 1;
+
+    // UID of the caller. This is always -1/unknown for the private space.
+    optional int32 uid = 2;
+
+    // The value should be converted to android.telecom.ApiResultEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 api_result = 3;
+
+    // The number of times this event occurs
+    optional int32 count = 4;
+}
+
+/**
+ * Pulled atom to capture stats of Telecom module errors
+ * From frameworks/proto_logging/stats/atoms/telecomm/telecom_extension_atom.proto
+ */
+message TelecomErrorStats {
+    // The value should be converted to android.telecom.SubmoduleNameEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 submodule_name = 1;
+
+    // The value should be converted to android.telecom.ErrorNameEnum
+    // From frameworks/proto_logging/stats/enums/telecomm/enums.proto
+    optional int32 error_name = 2;
+
+    // The number of times this error occurs
+    optional int32 count = 3;
+}
diff --git a/res/values-af/strings.xml b/res/values-af/strings.xml
index 50bead54c..71564e874 100644
--- a/res/values-af/strings.xml
+++ b/res/values-af/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"As jy antwoord, sal dit jou huidige video-oproep beëindig"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Antwoord"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Wys af"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Oproep kan nie geplaas word nie, want daar is geen oproeprekeninge wat hierdie tipe oproepe ondersteun nie."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Kan nie oproep maak nie. Gaan jou toestel se verbinding na."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Oproep kan nie gemaak word nie weens jou <xliff:g id="OTHER_CALL">%1$s</xliff:g>-oproep."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Oproep kan nie gemaak word nie weens jou <xliff:g id="OTHER_CALL">%1$s</xliff:g>-oproepe."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Oproep kan nie gemaak word nie weens \'n oproep in \'n ander program."</string>
diff --git a/res/values-am/strings.xml b/res/values-am/strings.xml
index f0923d5ca..dafbe6e7b 100644
--- a/res/values-am/strings.xml
+++ b/res/values-am/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"መመለስ እየተካሄደ ያለ የቪዲዮ ጥሪዎን ይጨርሳል"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ይመልሱ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"አትቀበል"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"የዚህን ዓይነት ጥሪዎች የሚደግፉ መደወያ መለያዎች ስለሌሉ ጥሪ መደረግ አይችልም።"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ጥሪ ማድረግ አልተቻለም። የመሣሪያዎን ግንኙነት ይፈትሹ።"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"በ<xliff:g id="OTHER_CALL">%1$s</xliff:g> ጥሪዎ ምክንያት ጥሪ መደረግ አይችልም።"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"በ<xliff:g id="OTHER_CALL">%1$s</xliff:g> ጥሪዎችዎ ምክንያት ጥሪዎች መደረግ አይችሉም።"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"በሌላ መተግበሪያ ውስጥ ባለ ጥሪ ምክንያት ጥሪ መደረግ አይችልም።"</string>
diff --git a/res/values-ar/strings.xml b/res/values-ar/strings.xml
index 2a568091b..9eb3a35c1 100644
--- a/res/values-ar/strings.xml
+++ b/res/values-ar/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"سيؤدي الرد إلى إنهاء مكالمات الفيديو"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"رد"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"رفض"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"يتعذَّر إجراء المكالمة بسبب عدم وجود حسابات اتصال يمكن استخدامها مع المكالمات من هذا النوع."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"لا يمكن إجراء المكالمة. يُرجى التأكّد من إمكانية الاتصال على جهازك."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"يتعذر إجراء المكالمة نتيجة لمكالمة <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"يتعذر إجراء المكالمة نتيجة لمكالمات <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"يتعذر إجراء المكالمة نتيجة لوجود مكالمة في تطبيق آخر."</string>
diff --git a/res/values-as/strings.xml b/res/values-as/strings.xml
index 72ac4dbb9..668f5e55d 100644
--- a/res/values-as/strings.xml
+++ b/res/values-as/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"উত্তৰ দিলে আপোনাৰ বৰ্তমান চলি থকা ভিডিঅ\' কলটোৰ অন্ত পৰিব"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"উত্তৰ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"প্ৰত্যাখ্যান কৰক"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"এইধৰণৰ কল কৰিব পৰা কলিং একাউণ্ট নোহোৱাৰ কাৰণে কল কৰিব নোৱাৰি।"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"কল কৰিব নোৱাৰি। আপোনাৰ ডিভাইচৰ সংযোগ পৰীক্ষা কৰক।"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"আপোনাৰ <xliff:g id="OTHER_CALL">%1$s</xliff:g> কল চলি থকাৰ কাৰণে বেলেগ কল কৰিব নোৱাৰি।"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"আপোনাৰ <xliff:g id="OTHER_CALL">%1$s</xliff:g> কলকেইটা চলি থকাৰ কাৰণে বেলেগ কল কৰিব নোৱাৰি।"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"অইন এটা এপত কল চলি থকাৰ কাৰণে বেলেগ কল কৰিব নোৱাৰি।"</string>
diff --git a/res/values-az/strings.xml b/res/values-az/strings.xml
index ead7f5433..c9751591a 100644
--- a/res/values-az/strings.xml
+++ b/res/values-az/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Cavab versəniz, davam edən video zəng sonlandırılacaq"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Cavab"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rədd edin"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Bu növ zəngləri dəstəkləyən hesablar olmadığına görə zəng etmək mümkün deyil."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Zəng etmək olmur. Cihazınızın bağlantısını yoxlayın."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> zəngi səbəbilə çağrı edilə bilməz."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> zəngləri səbəbilə çağrı edilə bilməz."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Başqa bir tətbiqdəki zəng səbəbilə çağrı edilə bilməz."</string>
diff --git a/res/values-b+sr+Latn/strings.xml b/res/values-b+sr+Latn/strings.xml
index d5278427b..3709c251c 100644
--- a/res/values-b+sr+Latn/strings.xml
+++ b/res/values-b+sr+Latn/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ako odgovorite, završićete video poziv koji je u toku"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Odgovori"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odbij"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Upućivanje poziva nije moguće jer nemate nijedan nalog za pozivanje koji podržava pozive ovog tipa."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Pozivanje nije uspelo. Proverite vezu uređaja."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Ne možete da uputite poziv zbog <xliff:g id="OTHER_CALL">%1$s</xliff:g> poziva."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Ne možete da uputite poziv zbog <xliff:g id="OTHER_CALL">%1$s</xliff:g> poziva."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Ne možete da uputite poziv zbog poziva u drugoj aplikaciji."</string>
diff --git a/res/values-be/strings.xml b/res/values-be/strings.xml
index c5b59bddd..c3c6e2f4f 100644
--- a/res/values-be/strings.xml
+++ b/res/values-be/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Адказ на гэты выклік завершыць ваш бягучы відэавыклік"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Адказаць"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Адхіліць"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Не ўдалося зрабіць выклік, бо на прыладзе няма ўліковых запісаў для гэтага тыпу выклікаў."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Не ўдаецца зрабіць выклік. Праверце падключэнне прылады."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Выклік немагчыма выканаць, бо ідзе выклік <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Выклік немагчыма выканаць, бо ідуць выклікі <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Выклік немагчыма выканаць, бо ідзе выклік у іншай праграме."</string>
diff --git a/res/values-bg/strings.xml b/res/values-bg/strings.xml
index fe5d70f56..116c88408 100644
--- a/res/values-bg/strings.xml
+++ b/res/values-bg/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ако отговорите, текущото ви видеообаждане ще прекъсне"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Отговаряне"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Отхвърляне"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Обаждането не може да бъде извършено, защото няма профили за обаждане, които поддържат обаждания от този тип."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Не може да се извърши обаждане. Проверете връзката на устройството си."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Не можете да се обадите заради обаждането си през <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Не можете да се обадите заради обажданията си през <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Не можете да се обадите заради обаждане в друго приложение."</string>
diff --git a/res/values-bn/strings.xml b/res/values-bn/strings.xml
index 49e6ba320..4f4fea6fc 100644
--- a/res/values-bn/strings.xml
+++ b/res/values-bn/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"উত্তর দেওয়া হলে আপনার চালু থাকা ভিডিও কলটি কেটে যাবে"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"উত্তর দিন"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"প্রত্যাখ্যান করুন"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"এই ধরনের কল করার জন্য যে কলিং অ্যাকাউন্টের প্রয়োজন সেটি না থাকার জন্য এই কলটি করা যাবে না।"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"কল করা যাবে না। আপনার ডিভাইসের কানেকশন চেক করুন।"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"আপনার <xliff:g id="OTHER_CALL">%1$s</xliff:g> কলটির কারণে কলটি করা যাবে না।"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"আপনার <xliff:g id="OTHER_CALL">%1$s</xliff:g> কলগুলির কারণে কলটি করা যাবে না।"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"অন্য একটি অ্যাপের কলের কারণে কলটি করা যাবে না।"</string>
diff --git a/res/values-bs/strings.xml b/res/values-bs/strings.xml
index 61b86db16..d2ac13aa7 100644
--- a/res/values-bs/strings.xml
+++ b/res/values-bs/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Odgovaranje će prekinuti video poziv koji je u toku"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Odgovori"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odbij"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Ne može se uputiti poziv zato što ne postoji nijedan račun za pozivanje koji podržava ovu vrstu poziva."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nije moguće uputiti poziv. Provjerite vezu uređaja."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Pozivanje nije moguće zbog poziva: <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Pozivanje nije moguće zbog poziva: <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Pozivanje nije moguće zbog poziva u drugoj aplikaciji."</string>
diff --git a/res/values-ca/strings.xml b/res/values-ca/strings.xml
index 113d14428..579344939 100644
--- a/res/values-ca/strings.xml
+++ b/res/values-ca/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"En respondre, finalitzarà la videotrucada en curs"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Respon"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rebutja"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"No es pot trucar perquè, en aquest moment, no hi ha cap compte de trucades compatible amb les trucades d\'aquest tipus."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"No es pot fer la trucada. Comprova la connexió del dispositiu."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"No es pot trucar perquè ja hi ha una trucada en curs a <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"No es pot trucar perquè ja hi ha trucades en curs a <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"No es pot trucar perquè ja hi ha una trucada en curs en una altra aplicació."</string>
diff --git a/res/values-cs/strings.xml b/res/values-cs/strings.xml
index 0adb30c15..06193081a 100644
--- a/res/values-cs/strings.xml
+++ b/res/values-cs/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Přijetím hovoru ukončíte probíhající videohovor"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Přijmout"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odmítnout"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Hovor není možné provést, protože není k dispozici žádný účet, který by tento typ hovoru podporoval."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nelze volat. Zkontrolujte připojení zařízení."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Hovor není možné provést kvůli hovoru <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Hovor není možné provést kvůli hovorům <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Hovor není možné provést kvůli hovoru v jiné aplikaci."</string>
diff --git a/res/values-da/strings.xml b/res/values-da/strings.xml
index 4eead6668..0eb69ff43 100644
--- a/res/values-da/strings.xml
+++ b/res/values-da/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Hvis du besvarer, afsluttes dit igangværende videoopkald"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Besvar"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Afvis"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Opkaldet kan ikke foretages, fordi der ikke er nogen opkaldskonti, der understøtter opkald af denne type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Det er ikke muligt at foretage opkald. Tjek din enheds forbindelse."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Opkaldet kan ikke foretages på grund af dit opkald i <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Opkaldet kan ikke foretages på grund af dine opkald i <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Opkaldet kan ikke foretages på grund et opkald i en anden app."</string>
diff --git a/res/values-de/strings.xml b/res/values-de/strings.xml
index dccdb87c0..665124abc 100644
--- a/res/values-de/strings.xml
+++ b/res/values-de/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Wenn du den Anruf annimmst, wird der Videoanruf beendet"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Annehmen"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Ablehnen"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Der Anruf kann nicht ausgehen, da es keine Anrufkonten gibt, die Anrufe dieses Typs unterstützen."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Keine Anrufe möglich. Prüfe die Verbindung deines Geräts."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Dieser Anruf kann aufgrund des Anrufs in <xliff:g id="OTHER_CALL">%1$s</xliff:g> nicht getätigt werden."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Dieser Anruf kann aufgrund deiner Anrufe in <xliff:g id="OTHER_CALL">%1$s</xliff:g> nicht getätigt werden."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Dieser Anruf kann aufgrund eines Anrufs in einer anderen App nicht getätigt werden."</string>
diff --git a/res/values-el/strings.xml b/res/values-el/strings.xml
index 6b58863e8..ba504d7d3 100644
--- a/res/values-el/strings.xml
+++ b/res/values-el/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Εάν απαντήσετε, η τρέχουσα βιντεοκλήση σας θα τερματιστεί"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Απάντηση"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Απόρριψη"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Δεν είναι δυνατή η πραγματοποίηση της κλήσης, επειδή δεν υπάρχουν λογαριασμοί κλήσεων που υποστηρίζουν κλήσεις αυτού του τύπου."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Δεν είναι δυνατή η πραγματοποίηση της κλήσης. Ελέγξτε τη σύνδεση της συσκευής σας."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Δεν είναι δυνατή η πραγματοποίηση της κλήσης, λόγω της κλήσης σας μέσω <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Δεν είναι δυνατή η πραγματοποίηση της κλήσης, λόγω των κλήσεών σας μέσω <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Δεν είναι δυνατή η πραγματοποίηση της κλήσης, λόγω κάποιας κλήσης μέσω άλλης εφαρμογής."</string>
diff --git a/res/values-en-rAU/strings.xml b/res/values-en-rAU/strings.xml
index 250ab62ed..1ce62df44 100644
--- a/res/values-en-rAU/strings.xml
+++ b/res/values-en-rAU/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Answering will end your ongoing video call"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Answer"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Decline"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Call cannot be placed because there are no calling accounts that support calls of this type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Can\'t make call. Check your device\'s connection."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> call."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> calls."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Call cannot be placed due to a call in another app."</string>
diff --git a/res/values-en-rCA/strings.xml b/res/values-en-rCA/strings.xml
index e6291f47b..8ae9c0a99 100644
--- a/res/values-en-rCA/strings.xml
+++ b/res/values-en-rCA/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Answering will end your ongoing video call"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Answer"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Decline"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Call cannot be placed because there are no calling accounts which support calls of this type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Can\'t make call. Check your device\'s connection."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> call."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> calls."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Call cannot be placed due to a call in another app."</string>
diff --git a/res/values-en-rGB/strings.xml b/res/values-en-rGB/strings.xml
index 250ab62ed..1ce62df44 100644
--- a/res/values-en-rGB/strings.xml
+++ b/res/values-en-rGB/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Answering will end your ongoing video call"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Answer"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Decline"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Call cannot be placed because there are no calling accounts that support calls of this type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Can\'t make call. Check your device\'s connection."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> call."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> calls."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Call cannot be placed due to a call in another app."</string>
diff --git a/res/values-en-rIN/strings.xml b/res/values-en-rIN/strings.xml
index 250ab62ed..1ce62df44 100644
--- a/res/values-en-rIN/strings.xml
+++ b/res/values-en-rIN/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Answering will end your ongoing video call"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Answer"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Decline"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Call cannot be placed because there are no calling accounts that support calls of this type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Can\'t make call. Check your device\'s connection."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> call."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Call cannot be placed due to your <xliff:g id="OTHER_CALL">%1$s</xliff:g> calls."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Call cannot be placed due to a call in another app."</string>
diff --git a/res/values-en-rXC/strings.xml b/res/values-en-rXC/strings.xml
index 5bd0e25eb..6849084a4 100644
--- a/res/values-en-rXC/strings.xml
+++ b/res/values-en-rXC/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‏‎‏‏‏‎‎‏‏‎‎‎‏‎‎‏‏‎‎‏‏‎‏‏‎‏‎‏‏‏‎‎‎‎‏‏‎‏‏‏‏‏‏‎‎‎‏‏‎‎‎‎‎‏‎‏‏‏‏‏‎Answering will end your ongoing video call‎‏‎‎‏‎"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‏‏‎‎‎‏‏‎‎‏‎‎‎‏‏‏‎‏‎‏‎‎‎‎‏‎‎‏‏‎‎‏‎‏‏‏‎‎‎‎‏‎‎‏‏‏‏‏‎‏‎‎‏‎‎‏‏‏‏‎‎Answer‎‏‎‎‏‎"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‎‏‏‎‎‏‏‎‎‏‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‎‏‎‎‎‏‎‏‏‎‏‏‎‏‎‎‎‏‏‎‎‏‎‏‏‎‏‏‏‏‏‎‏‏‏‎‎Decline‎‏‎‎‏‎"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‎‏‏‎‏‏‎‏‎‏‏‎‎‏‎‏‏‏‎‏‎‎‏‏‎‎‎‎‏‏‏‏‏‎‎‏‏‎‎‏‎‎‎‎‎‏‏‏‎‏‎‎‎‏‎‏‏‎‎‎‏‎‏‎Call cannot be placed because there are no calling accounts which support calls of this type.‎‏‎‎‏‎"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‏‏‎‏‎‏‎‎‎‏‎‏‎‎‏‎‎‎‏‏‏‏‎‎‏‎‎‏‏‎‏‏‎‎‏‎‏‏‏‎‎‎‎‎‏‏‏‏‏‎‎‎‎‎‏‏‏‎‏‏‎Can\'t make call. Check your device\'s connection.‎‏‎‎‏‎"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‎‏‏‏‏‎‎‎‏‎‏‎‎‏‏‎‎‎‎‎‏‏‎‎‏‏‏‏‏‎‏‏‏‏‎‏‎‏‏‏‏‏‎‏‎‎‎‎‏‏‎‎‎‏‎‎‏‎‏‎‏‎Call cannot be placed due to your ‎‏‎‎‏‏‎<xliff:g id="OTHER_CALL">%1$s</xliff:g>‎‏‎‎‏‏‏‎ call.‎‏‎‎‏‎"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‎‏‏‎‎‎‏‎‎‎‎‏‏‏‎‏‎‏‎‏‏‏‏‎‏‎‏‏‎‎‎‏‏‎‏‏‎‏‏‎‎‏‎‎‎‏‎‏‎‎‎‎‏‏‎‏‏‎‎‏‎‎‎Call cannot be placed due to your ‎‏‎‎‏‏‎<xliff:g id="OTHER_CALL">%1$s</xliff:g>‎‏‎‎‏‏‏‎ calls.‎‏‎‎‏‎"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"‎‏‎‎‎‎‎‏‎‏‏‏‎‎‎‎‎‎‏‎‎‏‎‎‎‎‎‏‏‏‏‏‏‏‏‏‎‎‏‎‎‏‏‎‎‏‏‎‏‏‏‎‏‎‎‎‏‏‏‏‏‎‏‎‎‎‏‎‎‎‏‎‏‎‏‎‏‎‏‏‏‏‏‏‎‎‎‎‎‏‎‏‎‏‎‎‎Call cannot be placed due to a call in another app.‎‏‎‎‏‎"</string>
diff --git a/res/values-es-rUS/strings.xml b/res/values-es-rUS/strings.xml
index c0f4e179a..668a696a7 100644
--- a/res/values-es-rUS/strings.xml
+++ b/res/values-es-rUS/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Si respondes, finalizará tu videollamada en curso"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Responder"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rechazar"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"No se puede realizar la llamada porque no hay ninguna cuenta compatible con este tipo de llamadas."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"No se puede realizar la llamada. Comprueba la conexión del dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"No se puede realizar la llamada porque hay una llamada en curso en <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"No se puede realizar la llamada porque hay otras llamadas en curso en <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"No se puede realizar la llamada porque hay una llamada en curso en otra app."</string>
diff --git a/res/values-es/strings.xml b/res/values-es/strings.xml
index 20b80a5e1..96163b32f 100644
--- a/res/values-es/strings.xml
+++ b/res/values-es/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Al responder, finalizará la videollamada en curso"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Responder"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rechazar"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"No puedes llamar porque no hay cuentas de llamada que admitan este tipo de llamadas."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"No se puede hacer la llamada. Comprueba la conexión de tu dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"No puedes llamar porque tienes una llamada de <xliff:g id="OTHER_CALL">%1$s</xliff:g> en curso."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"No puedes llamar porque tienes varias llamadas de <xliff:g id="OTHER_CALL">%1$s</xliff:g> en curso."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"No puedes llamar porque tienes una llamada en curso en otra aplicación."</string>
diff --git a/res/values-et/strings.xml b/res/values-et/strings.xml
index cac1fd6d3..6fd55929b 100644
--- a/res/values-et/strings.xml
+++ b/res/values-et/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Vastamisel lõpetatakse pooleliolev videokõne"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Vasta"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Keeldu"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Helistada ei saa, kuna pole ühtegi kõnekontot, mis toetaks seda tüüpi kõnesid."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Kõnet ei saa teha. Kontrollige seadme ühendust."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Kõnet ei saa teenuse <xliff:g id="OTHER_CALL">%1$s</xliff:g> kõne tõttu teha."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Kõnet ei saa teenuse <xliff:g id="OTHER_CALL">%1$s</xliff:g> kõnede tõttu teha."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Kõnet ei saa teise rakenduse kõne tõttu teha."</string>
diff --git a/res/values-eu/strings.xml b/res/values-eu/strings.xml
index d1aa5457e..3efbc0720 100644
--- a/res/values-eu/strings.xml
+++ b/res/values-eu/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Erantzuten baduzu, amaitu egingo da oraingo bideodeia"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Erantzun"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Baztertu"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Ezin da egin deia, ez dagoelako mota honetako deiak onartzen duen deiak egiteko konturik."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Ezin da egin deia. Egiaztatu gailua konektatuta dagoela."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Ezin da egin deia, beste dei bat abian delako <xliff:g id="OTHER_CALL">%1$s</xliff:g> zerbitzuan."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Ezin da egin deia, beste dei batzuk abian direlako <xliff:g id="OTHER_CALL">%1$s</xliff:g> zerbitzuan."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Ezin da egin deia, beste dei bat abian delako beste aplikazio batean."</string>
diff --git a/res/values-fa/strings.xml b/res/values-fa/strings.xml
index 8d562ec30..6bd2ff67e 100644
--- a/res/values-fa/strings.xml
+++ b/res/values-fa/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"پاسخ‌گویی به تماس تصویری درحال انجامتان پایان می‌دهد"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"پاسخ‌گویی"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"نپذیرفتن"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"به‌دلیل اینکه هیچ حساب تماسی وجود ندارد که از این نوع تماس پشتیبانی کند، تماس برقرار نشد."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"تماس برقرار نشد. اتصال دستگاهتان را بررسی کنید."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"به دلیل تماس <xliff:g id="OTHER_CALL">%1$s</xliff:g>، نمی‌توان تماسی برقرار کرد."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"به دلیل تماس‌های <xliff:g id="OTHER_CALL">%1$s</xliff:g>، نمی‌توان تماسی برقرار کرد."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"به دلیل تماسی در برنامه دیگر، نمی‌توان تماسی برقرار کرد."</string>
diff --git a/res/values-fi/strings.xml b/res/values-fi/strings.xml
index 338e42921..0d5fdbbb7 100644
--- a/res/values-fi/strings.xml
+++ b/res/values-fi/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Vastaaminen päättää käynnissä olevan videopuhelun."</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Vastaa"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Hylkää"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Puhelua ei voi soittaa, koska laitteella ei ole puhelutiliä, joka tukisi tätä puhelutyyppiä."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Soittaminen epäonnistui. Tarkista laitteen yhteys."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Puhelua ei voi soittaa, koska toisessa sovelluksessa (<xliff:g id="OTHER_CALL">%1$s</xliff:g>) on puhelu käynnissä."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Puhelua ei voi soittaa, koska toisessa sovelluksessa (<xliff:g id="OTHER_CALL">%1$s</xliff:g>) on puheluja käynnissä."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Puhelua ei voi soittaa, koska toisessa sovelluksessa on puhelu käynnissä."</string>
diff --git a/res/values-fr-rCA/strings.xml b/res/values-fr-rCA/strings.xml
index 031b25d29..cfd153b94 100644
--- a/res/values-fr-rCA/strings.xml
+++ b/res/values-fr-rCA/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Si vous répondez, vous mettrez fin à l\'appel vidéo en cours"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Répondre"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Refuser"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Impossible de passer cet appel, car aucun compte d\'appel ne prend en charge les appels de ce type."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Impossible de passer l\'appel. Vérifiez la connexion de votre appareil."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Impossible de faire l\'appel en raison de votre appel <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Impossible de faire l\'appel en raison de vos appels <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Impossible de faire l\'appel en raison d\'un appel dans une autre appli."</string>
diff --git a/res/values-fr/strings.xml b/res/values-fr/strings.xml
index a14cbb13c..9dbca8f5a 100644
--- a/res/values-fr/strings.xml
+++ b/res/values-fr/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Si vous répondez, vous mettrez fin à l\'appel vidéo en cours"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Répondre"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Refuser"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Impossible de passer cet appel, car aucun compte téléphonique ne prend en charge ce type d\'appel."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Impossible de passer l\'appel. Vérifiez la connexion de votre appareil."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Vous ne pouvez pas passer cet appel, car vous avez une communication en cours dans <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Vous ne pouvez pas passer cet appel, car vous avez des communications en cours dans <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Vous ne pouvez pas passer cet appel, car vous avez une communication en cours dans une autre application."</string>
diff --git a/res/values-gl/strings.xml b/res/values-gl/strings.xml
index 8e82fcec2..f8eb32cbb 100644
--- a/res/values-gl/strings.xml
+++ b/res/values-gl/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ao responder, finalizarán as túas videochamadas en curso"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Contestar"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rexeitar"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Non se pode realizar a chamada porque non hai ningunha conta de chamadas que admita chamadas deste tipo."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Non se puido facer a chamada. Revisa a conexión do dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Non se pode realizar a chamada porque hai unha chamada en curso en <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Non se pode realizar a chamada porque hai chamadas en curso en <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Non se pode realizar a chamada porque hai chamadas en curso noutra aplicación."</string>
diff --git a/res/values-gu/strings.xml b/res/values-gu/strings.xml
index 1b5c5ce5a..dd04bcf84 100644
--- a/res/values-gu/strings.xml
+++ b/res/values-gu/strings.xml
@@ -43,8 +43,8 @@
     <string name="respond_via_sms_setting_title_2" msgid="4914853536609553457">"હાજરજવાબમાં ફેરફાર કરો"</string>
     <string name="respond_via_sms_setting_summary" msgid="8054571501085436868"></string>
     <string name="respond_via_sms_edittext_dialog_title" msgid="6579353156073272157">"ઝડપી પ્રતિસાદ"</string>
-    <string name="respond_via_sms_confirmation_format" msgid="2932395476561267842">"<xliff:g id="PHONE_NUMBER">%s</xliff:g> પર સંદેશ મોકલ્યો."</string>
-    <string name="respond_via_sms_failure_format" msgid="5198680980054596391">"<xliff:g id="PHONE_NUMBER">%s</xliff:g>ને સંદેશ મોકલવામાં નિષ્ફળ રહ્યાં."</string>
+    <string name="respond_via_sms_confirmation_format" msgid="2932395476561267842">"<xliff:g id="PHONE_NUMBER">%s</xliff:g> પર મેસેજ મોકલ્યો."</string>
+    <string name="respond_via_sms_failure_format" msgid="5198680980054596391">"<xliff:g id="PHONE_NUMBER">%s</xliff:g> પર મેસેજ મોકલવામાં નિષ્ફળ રહ્યાં."</string>
     <string name="enable_account_preference_title" msgid="6949224486748457976">"કૉલ કરવા માટેના એકાઉન્ટ"</string>
     <string name="outgoing_call_not_allowed_user_restriction" msgid="3424338207838851646">"ફક્ત કટોકટીના કૉલ્સને મંજૂરી છે."</string>
     <string name="outgoing_call_not_allowed_no_permission" msgid="8590468836581488679">"ફોન પરવાનગી વિના આ ઍપ્લિકેશન આઉટગોઇંગ કૉલ્સ કરી શકતી નથી."</string>
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"જવાબ આપવાથી તમારો ચાલુ વિડિઓ કૉલ સમાપ્ત થશે"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"જવાબ આપો"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"નકારો"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"કૉલ કરી શકાતો નથી કારણ કે આ પ્રકારના કૉલની સુવિધા આપતા હોય એવા કોઈ કૉલિંગ એકાઉન્ટ નથી."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"કૉલ કરી શકતા નથી. તમારા ડિવાઇસનું કનેક્શન ચેક કરો."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"તમારા <xliff:g id="OTHER_CALL">%1$s</xliff:g> કૉલને કારણે કૉલ કરી શકતાં નથી."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"તમારા <xliff:g id="OTHER_CALL">%1$s</xliff:g> કૉલને કારણે કૉલ કરી શકતાં નથી."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"અન્ય ઍપ્લિકેશનમાં કૉલને કારણે કૉલ કરી શકતાં નથી."</string>
diff --git a/res/values-hi/strings.xml b/res/values-hi/strings.xml
index c32f58268..683a5ab8e 100644
--- a/res/values-hi/strings.xml
+++ b/res/values-hi/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"उत्तर देने से आपका जारी वीडियो कॉल खत्म हो जाएगा"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"उत्तर दें"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"अस्वीकार करें"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"कॉल नहीं किया जा सकता क्योंकि कॉल करने के लिए ऐसा कोई खाता नहीं है जिस पर इस तरह के कॉल की सुविधा हो."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"कॉल नहीं किया जा सकता. अपने डिवाइस के कनेक्शन की जांच करें."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"आपके <xliff:g id="OTHER_CALL">%1$s</xliff:g> कॉल के कारण कॉल नहीं लगाया जा सकता."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"आपके <xliff:g id="OTHER_CALL">%1$s</xliff:g> कॉल के कारण कॉल नहीं लगाया जा सकता."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"किसी दूसरे ऐप्लिकेशन में कॉल के कारण कॉल नहीं लगाया जा सकता."</string>
diff --git a/res/values-hr/strings.xml b/res/values-hr/strings.xml
index d6b209e08..b664e5c29 100644
--- a/res/values-hr/strings.xml
+++ b/res/values-hr/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ako odgovorite, prekinut ćete videopoziv u tijeku"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Odgovori"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odbij"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Poziv se ne može uputiti jer nema računa za pozivanje koji podržavaju pozive te vrste."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Poziv se ne može uputiti. Provjerite vezu uređaja."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Poziv se ne može uspostaviti zbog poziva u aplikaciji <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Poziv se ne može uspostaviti zbog poziva u aplikaciji <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Poziv se ne može uspostaviti zbog poziva u drugoj aplikaciji."</string>
diff --git a/res/values-hu/strings.xml b/res/values-hu/strings.xml
index 63f04b653..0a0c37787 100644
--- a/res/values-hu/strings.xml
+++ b/res/values-hu/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ha válaszol a hívásra, megszakítja a meglévő videohívást"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Hívás fogadása"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Elutasítás"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"A hívás nem indítható el, mert nincs olyan hívásra alkalmas fiók, amely támogatná az ilyen típusú hívásokat."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nem lehet hívást indítani. Ellenőrizze eszköze kapcsolatát."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"A(z) <xliff:g id="OTHER_CALL">%1$s</xliff:g>-hívás miatt nem indítható hívás."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"A(z) <xliff:g id="OTHER_CALL">%1$s</xliff:g>-hívások miatt nem indítható hívás."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Egy másik alkalmazásban folytatott hívás miatt nem indítható hívás."</string>
diff --git a/res/values-hy/strings.xml b/res/values-hy/strings.xml
index 169ea3602..7f877c590 100644
--- a/res/values-hy/strings.xml
+++ b/res/values-hy/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Եթե պատասխանեք այս զանգին, ընթացիկ տեսազանգը կընդհատվի"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Պատասխանել"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Մերժել"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Զանգը հնարավոր չէ կատարել, քանի որ հաշիվներ չկան, որոնք աջակցում են այս տեսակի զանգեր:"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Հնարավոր չէ զանգել։ Ստուգեք սարքի միացումը։"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Զանգը հնարավոր չէ կատարել՝ <xliff:g id="OTHER_CALL">%1$s</xliff:g>-ի ընթացիկ զանգի պատճառով:"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Զանգը հնարավոր չէ կատարել՝ <xliff:g id="OTHER_CALL">%1$s</xliff:g>-ի ընթացիկ զանգերի պատճառով:"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Զանգը հնարավոր չէ կատարել՝ մեկ այլ հավելվածի ընթացիկ զանգի պատճառով:"</string>
diff --git a/res/values-in/strings.xml b/res/values-in/strings.xml
index 1e51f7a66..34c0c6693 100644
--- a/res/values-in/strings.xml
+++ b/res/values-in/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Menjawab panggilan akan mengakhiri panggilan video yang sedang berlangsung"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Jawab"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Tolak"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Panggilan tidak dapat dilakukan karena tidak ada akun panggilan yang mendukung jenis panggilan ini."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Tidak dapat menelepon. Periksa koneksi perangkat Anda."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Panggilan tidak dapat dilakukan karena panggilan <xliff:g id="OTHER_CALL">%1$s</xliff:g> Anda."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Panggilan tidak dapat dilakukan karena panggilan <xliff:g id="OTHER_CALL">%1$s</xliff:g> Anda."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Panggilan tidak dapat dilakukan karena adanya panggilan di aplikasi lain."</string>
diff --git a/res/values-is/strings.xml b/res/values-is/strings.xml
index 7009b7cb9..c2fcf8f22 100644
--- a/res/values-is/strings.xml
+++ b/res/values-is/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ef þessu er svarað lýkur myndsímtalinu"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Svara"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Hafna"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Ekki er hægt að hringja vegna þess að engir símtalareikningar eru til staðar sem styðja svona símtöl."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Ekki er hægt að hringja. Athugaðu tengingu tækisins."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Ekki er hægt að hringja sökum símtalsins með <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Ekki er hægt að hringja sökum símtala með <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Ekki er hægt að hringja sökum símtals í öðru forriti."</string>
diff --git a/res/values-it/strings.xml b/res/values-it/strings.xml
index 4a17d18c4..42cb0c8d3 100644
--- a/res/values-it/strings.xml
+++ b/res/values-it/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Se rispondi, la videochiamata in corso verrà terminata"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Rispondi"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rifiuta"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Impossibile effettuare la chiamata perché non sono presenti account che supportano chiamate di questo tipo."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Impossibile effettuare la chiamata. Controlla la connessione del dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Impossibile effettuare la chiamata a causa della chiamata <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Impossibile effettuare la chiamata a causa delle chiamate <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Impossibile effettuare la chiamata a causa di una chiamata in un\'altra app."</string>
diff --git a/res/values-iw/strings.xml b/res/values-iw/strings.xml
index 05ec712b0..98c53470b 100644
--- a/res/values-iw/strings.xml
+++ b/res/values-iw/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"מענה יסיים את שיחת הווידאו הנוכחית"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"מענה"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"דחייה"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"אי אפשר להתקשר כי אין במכשיר חשבון שתומך בשיחות מהסוג הזה."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"אי אפשר להתקשר. כדאי לבדוק את החיבורים השונים של המכשיר."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"אי אפשר להתקשר בגלל שיש שיחה ב-<xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"אי אפשר להתקשר בגלל שיש שיחות ב-<xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"אי אפשר להתקשר בגלל שיש שיחה באפליקציה אחרת."</string>
diff --git a/res/values-ja/strings.xml b/res/values-ja/strings.xml
index 19387ffb5..2df673616 100644
--- a/res/values-ja/strings.xml
+++ b/res/values-ja/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"応答すると、進行中のビデオ通話は終了します"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"応答"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"拒否"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"この種の通話に対応している通話アカウントがないため、通話を発信できません。"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"発信できません。デバイスの接続状態を確認してください。"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> で通話中のため、この通話を発信することはできません。"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> で通話中のため、この通話を発信することはできません。"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"別のアプリで通話中のため、この通話を発信することはできません。"</string>
diff --git a/res/values-ka/strings.xml b/res/values-ka/strings.xml
index d56873f25..f2a3e90bb 100644
--- a/res/values-ka/strings.xml
+++ b/res/values-ka/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"პასუხის გაცემა თქვენს მიმდინარე ვიდეოზარს დაასრულებს"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"პასუხი"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"უარყოფა"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ზარის განხორციელება შეუძლებელია, რადგან არ არის დარეკვის ის ანგარიშები, რომლებიც მხარს უჭერს ამ ტიპის ზარებს."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ზარი ვერ ხორციელდება. შეამოწმეთ თქვენი მოწყობილობის კავშირი."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ზარი ვერ ხორციელდება <xliff:g id="OTHER_CALL">%1$s</xliff:g> ზარის გამო."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ზარი ვერ ხორციელდება <xliff:g id="OTHER_CALL">%1$s</xliff:g> ზარების გამო."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ზარი ვერ ხორციელდება ზარის გამო სხვა აპში."</string>
diff --git a/res/values-kk/strings.xml b/res/values-kk/strings.xml
index 399da2030..22ac1fc82 100644
--- a/res/values-kk/strings.xml
+++ b/res/values-kk/strings.xml
@@ -62,7 +62,7 @@
     <string name="change_default_call_screening_warning_message" msgid="9020537562292754269">"<xliff:g id="NEW_APP">%s</xliff:g> контактілер тізімінде жоқ қоңырау шалушылар туралы ақпаратты көріп, бұндай қоңырауларды бөгей алады. Әдепкі қоңырауды тексеру қолданбасы ретінде тек өзіңіз сенетін қолданбаларды ғана орнатқан дұрыс."</string>
     <string name="change_default_call_screening_dialog_affirmative" msgid="7162433828280058647">"Әдепкі ретінде орнату"</string>
     <string name="change_default_call_screening_dialog_negative" msgid="1839266125623106342">"Жабу"</string>
-    <string name="blocked_numbers" msgid="8322134197039865180">"Бөгелген нөмірлер"</string>
+    <string name="blocked_numbers" msgid="8322134197039865180">"Блокталған нөмірлер"</string>
     <string name="blocked_numbers_msg" msgid="2797422132329662697">"Тыйым салынған нөмірлерден қоңыраулар немесе мәтіндік хабарлар алмайсыз."</string>
     <string name="block_number" msgid="3784343046852802722">"Нөмір қосу"</string>
     <string name="unblock_dialog_body" msgid="2723393535797217261">"<xliff:g id="NUMBER_TO_BLOCK">%1$s</xliff:g> бөгеуден шығарылсын ба?"</string>
@@ -70,7 +70,7 @@
     <string name="add_blocked_dialog_body" msgid="8599974422407139255">"Қоңыраулары мен мәтіндік хабарлары бөгелетін нөмір"</string>
     <string name="add_blocked_number_hint" msgid="8769422085658041097">"Телефон нөмірі"</string>
     <string name="block_button" msgid="485080149164258770">"Блоктау"</string>
-    <string name="non_primary_user" msgid="315564589279622098">"Бөгелген нөмірлерді тек құрылғы иесі көре және басқара алады."</string>
+    <string name="non_primary_user" msgid="315564589279622098">"Блокталған нөмірлерді тек құрылғы иесі көре және басқара алады."</string>
     <string name="delete_icon_description" msgid="5335959254954774373">"Бөгеуді алу"</string>
     <string name="blocked_numbers_butter_bar_title" msgid="582982373755950791">"Тыйым уақытша алынды"</string>
     <string name="blocked_numbers_butter_bar_body" msgid="1261213114919301485">"Төтенше жағдай нөмірін терген немесе мәтіндік хабар жіберген соң, төтенше жағдай қызметтері сізге хабарласа алуы үшін тыйым алынады."</string>
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Жауап беру қазіргі бейне қоңырауды тоқтатады"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Жауап беру"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Қабылдамау"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Қоңырау шалу мүмкін емес, себебі бұндай қоңырауларға қолдау көрсететін аккаунт жоқ."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Қоңырау шалу мүмкін емес. Құрылғы байланысын тексеріңіз."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Қоңырау шалу мүмкін емес, себебі <xliff:g id="OTHER_CALL">%1$s</xliff:g> қоңырауы белсенді."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Қоңырау шалу мүмкін емес, себебі <xliff:g id="OTHER_CALL">%1$s</xliff:g> қоңыраулары белсенді."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Қоңырау шалу мүмкін емес, себебі басқа қолданбадан қоңырау шалынуда."</string>
diff --git a/res/values-km/strings.xml b/res/values-km/strings.xml
index 1c28d3711..41b02f307 100644
--- a/res/values-km/strings.xml
+++ b/res/values-km/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ការ​ឆ្លើយ​នឹង​បញ្ចប់​ការ​ហៅ​តាម​វីដេអូ​ដែល​កំពុង​តែ​ដំណើរការ​របស់​អ្នក"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ឆ្លើយ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"បដិសេធ"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"មិន​អាច​ធ្វើ​ការ​ហៅ​ទូរសព្ទ​បាន​ទេ ពីព្រោះ​មិនមាន​គណនី​ហៅ​ទូរសព្ទ​ដែល​អាច​ប្រើបាន​ជាមួយ​ការ​ហៅ​ប្រភេទ​នេះ​ទេ។"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"មិនអាច​ហៅទូរសព្ទ​បានទេ។ សូម​ពិនិត្យមើល​ការតភ្ជាប់​របស់​ឧបករណ៍​អ្នក។"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ការ​ហៅ​មិន​អាចធ្វើ​បាន​ទេ ដោយ​សារ​ការហៅ​ <xliff:g id="OTHER_CALL">%1$s</xliff:g> របស់​អ្នក។"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ការ​ហៅ​មិន​អាច​ធ្វើ​បាន​ទេ ដោយ​សារ​ការ​ហៅ <xliff:g id="OTHER_CALL">%1$s</xliff:g> របស់​អ្នក។"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ការ​ហៅ​មិន​អាច​ធ្វើ​បាន​ទេ ដោយ​សារ​មាន​ការហៅ​មួយ​នៅ​ក្នុង​កម្មវិធី​ផ្សេង។"</string>
diff --git a/res/values-kn/strings.xml b/res/values-kn/strings.xml
index cbaa2036b..886ccdfea 100644
--- a/res/values-kn/strings.xml
+++ b/res/values-kn/strings.xml
@@ -56,7 +56,7 @@
     <string name="change_default_dialer_dialog_title" msgid="5861469279421508060">"<xliff:g id="NEW_APP">%s</xliff:g> ಅನ್ನು ನಿಮ್ಮ ಡಿಫಾಲ್ಟ್ ಫೋನ್ ಆ್ಯಪ್ ಆಗಿ ಮಾಡಬೇಕೆ?"</string>
     <string name="change_default_dialer_dialog_affirmative" msgid="8604665314757739550">"ಡಿಫಾಲ್ಟ್ ಹೊಂದಿಸಿ"</string>
     <string name="change_default_dialer_dialog_negative" msgid="8648669840052697821">"ರದ್ದುಮಾಡಿ"</string>
-    <string name="change_default_dialer_warning_message" msgid="8461963987376916114">"<xliff:g id="NEW_APP">%s</xliff:g> ಗೆ ನಿಮ್ಮ ಕರೆಗಳ ಎಲ್ಲಾ ಅಂಶಗಳನ್ನು ನಿಯಂತ್ರಿಸಲು ಮತ್ತು ಕರೆಗಳನ್ನು ಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತದೆ. ನೀವು ವಿಶ್ವಾಸವಿರಿಸಿರುವಂತಹ ಅಪ್ಲಿಕೇಶನ್‌ಗಳನ್ನು ಮಾತ್ರ ನಿಮ್ಮ ಡಿಫಾಲ್ಟ್ ಅಪ್ಲಿಕೇಶನ್ ಆಗಿ ಹೊಂದಿಸಬೇಕು."</string>
+    <string name="change_default_dialer_warning_message" msgid="8461963987376916114">"<xliff:g id="NEW_APP">%s</xliff:g> ಗೆ ನಿಮ್ಮ ಕರೆಗಳ ಎಲ್ಲಾ ಅಂಶಗಳನ್ನು ನಿಯಂತ್ರಿಸಲು ಮತ್ತು ಕರೆಗಳನ್ನು ಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತದೆ. ನೀವು ವಿಶ್ವಾಸವಿರಿಸಿರುವಂತಹ ಆ್ಯಪ್‌ಗಳನ್ನು ಮಾತ್ರ ನಿಮ್ಮ ಡಿಫಾಲ್ಟ್ ಆ್ಯಪ್‌ ಆಗಿ ಹೊಂದಿಸಬೇಕು."</string>
     <string name="change_default_call_screening_dialog_title" msgid="5365787219927262408">"<xliff:g id="NEW_APP">%s</xliff:g> ನಿಮ್ಮ ಡೀಫಾಲ್ಟ್ ಕರೆ ಸ್ಕ್ರೀನಿಂಗ್ ಆ್ಯಪ್‌ ಆಗಿ ಮಾಡಬೇಕೇ?"</string>
     <string name="change_default_call_screening_warning_message_for_disable_old_app" msgid="2039830033533243164">"<xliff:g id="OLD_APP">%s</xliff:g> ಇನ್ನು ಮುಂದೆ ಕರೆಗಳನ್ನು ಸ್ಕ್ರೀನ್‌ ಮಾಡಲು ಸಾಧ್ಯವಾಗುವುದಿಲ್ಲ."</string>
     <string name="change_default_call_screening_warning_message" msgid="9020537562292754269">"<xliff:g id="NEW_APP">%s</xliff:g> ಗೆ ನಿಮ್ಮ ಸಂಪರ್ಕಗಳಲ್ಲಿ ಇಲ್ಲದ ಕರೆದಾರರ ಬಗ್ಗೆ ಮಾಹಿತಿಯನ್ನು ನೋಡಲು ಮತ್ತು ಈ ಕರೆಗಳನ್ನು ಬ್ಲಾಕ್ ಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತದೆ. ನೀವು ವಿಶ್ವಾಸವಿರಿಸಿರುವಂತಹ ಆ್ಯಪ್‌ಗಳನ್ನು ಮಾತ್ರ ನಿಮ್ಮ ಡೀಫಾಲ್ಟ್ ಕರೆ ಸ್ಕ್ರೀನಿಂಗ್ ಆ್ಯಪ್‌ ಆಗಿ ಹೊಂದಿಸಬೇಕು."</string>
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ಕರೆಗೆ ಉತ್ತರಿಸುವುದರಿಂದ ನಿಮ್ಮ ಚಾಲ್ತಿಯಲ್ಲಿರುವ ವೀಡಿಯೊ ಕರೆಯು ಅಂತ್ಯಗೊಳ್ಳುತ್ತದೆ"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ಉತ್ತರ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ನಿರಾಕರಿಸಿ"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ಈ ಪ್ರಕಾರದ ಕರೆಗಳನ್ನು ಬೆಂಬಲಿಸುವ ಯಾವುದೇ ಕರೆಮಾಡುವಿಕೆ ಖಾತೆಗಳು ಇಲ್ಲದಿರುವ ಕಾರಣ ಕರೆಮಾಡಲು ಸಾಧ್ಯವಾಗುತ್ತಿಲ್ಲ."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಿಲ್ಲ. ನಿಮ್ಮ ಸಾಧನದ ಕನೆಕ್ಷನ್ ಅನ್ನು ಪರಿಶೀಲಿಸಿ."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ನಿಮ್ಮ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ಕರೆ ಇರುವ ಕಾರಣ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಾಗಿಲ್ಲ."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ನಿಮ್ಮ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ಕರೆಗಳ ಕಾರಣ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಾಗಿಲ್ಲ."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ಬೇರೊಂದು ಅಪ್ಲಿಕೇಶನ್‍ನಲ್ಲಿ ಕರೆಯಲ್ಲಿರುವುದರಿಂದ ಕರೆ ಮಾಡಲು ಸಾಧ್ಯವಾಗಲಿಲ್ಲ."</string>
diff --git a/res/values-ko/strings.xml b/res/values-ko/strings.xml
index dc793e320..f0b95fd06 100644
--- a/res/values-ko/strings.xml
+++ b/res/values-ko/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"전화를 받으면 진행 중인 화상 통화가 종료됩니다."</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"통화"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"거부"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"이 유형의 전화를 지원하는 전화 계정이 없으므로 전화를 걸 수 없습니다."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"전화를 걸 수 없습니다. 기기의 연결 상태를 확인하세요."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> 통화 중이므로 전화를 걸 수 없습니다."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> 통화 중이므로 전화를 걸 수 없습니다."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"다른 앱에서 통화 중이므로 전화를 걸 수 없습니다."</string>
diff --git a/res/values-ky/strings.xml b/res/values-ky/strings.xml
index 43def8b66..ad19dd767 100644
--- a/res/values-ky/strings.xml
+++ b/res/values-ky/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Чалууга жооп берсеңиз, учурдагы видео чалууңуз бүтүп калат"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Жооп берүү"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Четке кагуу"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Бул түрдөгү чалуударды колдоого алган чалуу аккаунттары жок болгондуктан, чалуу аткарылбай койду."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Чалуу мүмкүн эмес. Түзмөгүңүздүн туташуусун текшериңиз."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Учурда <xliff:g id="OTHER_CALL">%1$s</xliff:g> чалууңуздан улам, башка жерге чала албайсыз."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Учурда <xliff:g id="OTHER_CALL">%1$s</xliff:g> чалууларыңуздан улам, башка жерге чала албайсыз."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Башка колдонмодо чалып жатасыз, ошондуктан чала албайсыз."</string>
diff --git a/res/values-lo/strings.xml b/res/values-lo/strings.xml
index ff79144c1..8e439359d 100644
--- a/res/values-lo/strings.xml
+++ b/res/values-lo/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ການຮັບສາຍຈະເປັນການວາງສາຍວິດີໂອທີ່ທ່ານກຳລັງໂທອອກ"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ຮັບສາຍ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ປະຕິເສດ"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ບໍ່ສາມາດໂທໄດ້ເນື່ອງຈາກບໍ່ມີບັນຊີການໂທທີ່ຮອງຮັບການໂທປະເພດນີ້."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ບໍ່ສາມາດໂທອອກໄດ້. ກວດເບິ່ງການເຊື່ອມຕໍ່ຂອງອຸປະກອນຂອງທ່ານ."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກການໂທ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ຂອງທ່ານ"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກການໂທ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ຂອງທ່ານ"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ບໍ່ສາມາດໂທອອກໄດ້ເນື່ອງຈາກສາຍໃນແອັບອື່ນ."</string>
diff --git a/res/values-lt/strings.xml b/res/values-lt/strings.xml
index 945443122..04f4c96c4 100644
--- a/res/values-lt/strings.xml
+++ b/res/values-lt/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Atsakius bus užbaigtas vykstantis vaizdo skambutis"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Atsakyti"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Atmesti"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Negalima skambinti, nes nėra jokių skambinimo paskyrų, kuriose palaikomi šio tipo skambučiai."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nepavyko paskambinti. Patikrinkite įrenginio ryšį."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Negalima skambinti dėl „<xliff:g id="OTHER_CALL">%1$s</xliff:g>“ skambučio."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Negalima skambinti dėl „<xliff:g id="OTHER_CALL">%1$s</xliff:g>“ skambučių."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Negalima skambinti dėl skambučio kitoje programoje."</string>
diff --git a/res/values-lv/strings.xml b/res/values-lv/strings.xml
index 5ebdd8eb2..ee807da0b 100644
--- a/res/values-lv/strings.xml
+++ b/res/values-lv/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Atbildot uz zvanu, tiks beigts pašreizējais videozvans"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Atbildēt"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Noraidīt"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Nevar veikt zvanu, jo ierīcē nav neviena zvanu konta, kurā tiktu atbalstīti šī veida zvani."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nevar veikt zvanu. Pārbaudiet ierīces savienojumu."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Nevar veikt zvanu notiekoša <xliff:g id="OTHER_CALL">%1$s</xliff:g> zvana dēļ."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Nevar veikt zvanu notiekošu <xliff:g id="OTHER_CALL">%1$s</xliff:g> zvanu dēļ."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Nevar veikt zvanu citā lietotnē notiekoša zvana dēļ."</string>
diff --git a/res/values-mk/strings.xml b/res/values-mk/strings.xml
index 57a3fce6c..0f6e41fe9 100644
--- a/res/values-mk/strings.xml
+++ b/res/values-mk/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ако одговорите, ќе се прекине вашиот тековен видеоповик"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Одговорете"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Одбијте"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Повикот не може да се воспостави затоа што нема сметки за повикување што поддржуваат ваков тип повици."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Не може да се оствари повик. Проверете ја врската на уредот."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Не може да се воспостави повик поради вашиот повик на <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Не може да се воспостави повик поради вашите повици на <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Не може да се воспостави повик поради вашиот повик на друга апликација."</string>
diff --git a/res/values-ml/strings.xml b/res/values-ml/strings.xml
index a6d1626d9..1301b4432 100644
--- a/res/values-ml/strings.xml
+++ b/res/values-ml/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"കോൾ സ്വീകരിക്കുന്നത് നിങ്ങളുടെ നിലവിലുള്ള വീഡിയോ കോൾ അവസാനിക്കാനിടയാക്കും"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"മറുപടി നൽകുക"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"നിരസിക്കുക"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ഇത്തരം കോളുകൾക്ക് അനുയോജ്യമായ അക്കൗണ്ടുകളൊന്നും ഇല്ലാത്തതിനാൽ കോൾ ചെയ്യാനായില്ല."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"കോൾ ചെയ്യാനാകില്ല. നിങ്ങളുടെ ഉപകരണത്തിന്റെ കണക്ഷൻ പരിശോധിക്കുക."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"നിങ്ങളുടെ <xliff:g id="OTHER_CALL">%1$s</xliff:g> കോൾ കാരണം കോൾ ചെയ്യാനായില്ല."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"നിങ്ങളുടെ <xliff:g id="OTHER_CALL">%1$s</xliff:g> കോളുകൾ കാരണം കോൾ ചെയ്യാനായില്ല."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"മറ്റൊരു ആപ്പിലുള്ള കോൾ കാരണം കോൾ ചെയ്യാനായില്ല."</string>
diff --git a/res/values-mn/strings.xml b/res/values-mn/strings.xml
index 70dde8a44..0b26e7e29 100644
--- a/res/values-mn/strings.xml
+++ b/res/values-mn/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Хариулбал таны одоогийн видео дуудлагыг таслах болно"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Хариулах"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Татгалзах"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Энэ төрлийн дуудлага дэмждэг дуудлагын бүртгэл байхгүй тул дуудлага хийх боломжгүй байна."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Дуудлага хийх боломжгүй. Төхөөрөмжийнхөө холболтыг шалгана уу."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Таны <xliff:g id="OTHER_CALL">%1$s</xliff:g> дуудлагаас шалтгаалан дуудлага хийх боломжгүй байна."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Таны <xliff:g id="OTHER_CALL">%1$s</xliff:g> дуудлагаас шалтгаалан дуудлага хийх боломжгүй байна."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Өөр апп доторх дуудлагаас шалтгаалан дуудлага хийх боломжгүй байна."</string>
diff --git a/res/values-mr/strings.xml b/res/values-mr/strings.xml
index c4438aebc..eca7b4de0 100644
--- a/res/values-mr/strings.xml
+++ b/res/values-mr/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"उत्तर देण्यामुळे तुमचा सुरू असलेला व्हिडिओ कॉल समाप्त होईल"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"उत्तर द्या"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"नकार द्या"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"कॉल करू शकत नाही कारण अशाप्रकारच्या कॉलला सपोर्ट करतील अशी कोणतीही कॉलिंग खाती नाहीत."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"कॉल करू शकत नाही. तुमच्या डिव्हाइसचे कनेक्शन तपासणे."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"आपल्या <xliff:g id="OTHER_CALL">%1$s</xliff:g> कॉलमुळे कॉल केला जाऊ शकत नाही."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"आपल्या <xliff:g id="OTHER_CALL">%1$s</xliff:g> कॉलमुळे कॉल केला जाऊ शकत नाही."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"दुसर्‍या ॲपमधील कॉलमुळे कॉल केला जाऊ शकत नाही."</string>
diff --git a/res/values-ms/strings.xml b/res/values-ms/strings.xml
index 355502cc4..ebfffd04c 100644
--- a/res/values-ms/strings.xml
+++ b/res/values-ms/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Menjawab akan menamatkan panggilan video semasa anda"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Jawab"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Tolak"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Panggilan tidak dapat dibuat kerana tiada akaun panggilan yang menyokong panggilan jenis ini."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Tidak dapat membuat panggilan. Semak sambungan peranti anda."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Panggilan tidak dapat dibuat disebabkan panggilan <xliff:g id="OTHER_CALL">%1$s</xliff:g> anda."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Panggilan tidak dapat dibuat disebabkan panggilan <xliff:g id="OTHER_CALL">%1$s</xliff:g> anda."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Panggilan tidak dapat dibuat disebabkan panggilan dalam apl lain."</string>
diff --git a/res/values-my/strings.xml b/res/values-my/strings.xml
index c9e559384..e7f0fd439 100644
--- a/res/values-my/strings.xml
+++ b/res/values-my/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ဖုန်းကိုင်လိုက်လျှင် လက်ရှိဗီဒီယိုပြောနေခြင်းကိုဖြတ်ပစ်ပါမည်"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ဖုန်းကိုင်ရန်"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ဖုန်းမကိုင်ရန်"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ဤဖုန်းခေါ်ဆိုမှု အမျိုးအစားကို ပံ့ပိုးပေးသည့် ခေါ်ဆိုမှုအကောင့်များ မရှိသဖြင့် ဖုန်းခေါ်၍ မရပါ။"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ဖုန်းမခေါ်ဆိုနိုင်ပါ။ သင့်စက်၏ ချိတ်ဆက်မှုကို စစ်ပါ။"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> သုံးပြီးပြောနေသည့်အတွက် အထွက်ခေါ်ဆိုမှုကို မပြုလုပ်နိုင်ပါ။"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> သုံးပြီးပြောနေသည့်အတွက် အထွက်ခေါ်ဆိုမှုများကို မပြုလုပ်နိုင်ပါ။"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"အခြားအက်ပ်သုံးပြီးပြောနေသည့်အတွက် အထွက်ခေါ်ဆိုမှုကို မပြုလုပ်နိုင်ပါ။"</string>
diff --git a/res/values-nb/strings.xml b/res/values-nb/strings.xml
index 8bebbff63..66e6ffc72 100644
--- a/res/values-nb/strings.xml
+++ b/res/values-nb/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Hvis du svarer, avsluttes videosamtalen du er i nå"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Svar"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Avvis"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Anropet kan ikke utføres fordi du ikke har noen ringekontoer som støtter denne typen anrop."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Kan ikke ringe. Sjekk tilkoblingen på enheten."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Kan ikke ringe ut på grunn av <xliff:g id="OTHER_CALL">%1$s</xliff:g>-samtalen din."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Kan ikke ringe ut på grunn av <xliff:g id="OTHER_CALL">%1$s</xliff:g>-samtalene dine."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Kan ikke ringe ut på grunn av en samtale i en annen app."</string>
diff --git a/res/values-ne/strings.xml b/res/values-ne/strings.xml
index df2c70c7f..d8fc473bf 100644
--- a/res/values-ne/strings.xml
+++ b/res/values-ne/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"जवाफ फर्काउनुले तपाईंको जारी भिडियो कल समाप्त हुनेछ"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"जवाफ दिनुहोस्"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"अस्वीकार गर्नुहोस्"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"यस प्रकारका कलहरूलाई समर्थन गर्ने कुनै पनि कल गर्ने खाता नभएकाले कल गर्न सकिँदैन।"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"कल गर्न सकिएन। आफ्नो डिभाइसको इन्टरनेट जाँच्नुहोस्।"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"तपाईंको <xliff:g id="OTHER_CALL">%1$s</xliff:g> कलका कारण कल गर्न सकिँदैन।"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"तपाईंका <xliff:g id="OTHER_CALL">%1$s</xliff:g> कलहरूका कारण कल गर्न सकिँदैन।"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"अर्को एपमा जारी कलका कारण कल गर्न सकिँदैन।"</string>
diff --git a/res/values-nl/strings.xml b/res/values-nl/strings.xml
index 8dfee8189..e395ef1d0 100644
--- a/res/values-nl/strings.xml
+++ b/res/values-nl/strings.xml
@@ -16,7 +16,7 @@
 
 <resources xmlns:android="http://schemas.android.com/apk/res/android"
     xmlns:xliff="urn:oasis:names:tc:xliff:document:1.2">
-    <string name="telecommAppLabel" product="default" msgid="1825598513414129827">"Telefoongesprekken"</string>
+    <string name="telecommAppLabel" product="default" msgid="1825598513414129827">"Telefoon­gesprekken"</string>
     <string name="userCallActivityLabel" product="default" msgid="3605391260292846248">"Telefoon"</string>
     <string name="unknown" msgid="6993977514360123431">"Onbekend"</string>
     <string name="notification_missedCallTitle" msgid="5060387047205532974">"Gemist gesprek"</string>
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Als je opneemt, wordt je actieve videogesprek beëindigd"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Beantwoorden"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Weigeren"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Gesprek kan niet worden geplaatst omdat er geen gespreksaccounts zijn die gesprekken van dit type ondersteunen."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Kan niet bellen. Check de verbinding van je apparaat."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Gesprek kan niet worden gestart vanwege je <xliff:g id="OTHER_CALL">%1$s</xliff:g>-gesprek."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Gesprek kan niet worden gestart vanwege je <xliff:g id="OTHER_CALL">%1$s</xliff:g>-gesprekken."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Gesprek kan niet worden gestart vanwege een gesprek in een andere app."</string>
diff --git a/res/values-or/strings.xml b/res/values-or/strings.xml
index 6f3ebe3a9..535583ae8 100644
--- a/res/values-or/strings.xml
+++ b/res/values-or/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ଉତ୍ତର ଦେବାଦ୍ଵାରା ଆପଣଙ୍କର ଜାରି ରହିଥିବା ଭିଡିଓ କଲ୍ ସମାପ୍ତ ହୋ‌ଇଯିବ"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ଉତ୍ତର ଦିଅନ୍ତୁ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ଅସ୍ୱୀକାର"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ଏହି ପ୍ରକାରର କଲ୍ ସମର୍ଥନ କରୁଥିବା କଲିଂ ଆକାଉଣ୍ଟ ନଥିବା ଯୋଗୁଁ କଲ୍‌ କରାଯାଇପାରିବ ନାହିଁ।"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"କଲ କରାଯାଇପାରିବ ନାହିଁ। ଆପଣଙ୍କ ଡିଭାଇସର କନେକ୍ସନ ଯାଞ୍ଚ କରନ୍ତୁ।"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ଆପଣଙ୍କର <xliff:g id="OTHER_CALL">%1$s</xliff:g> କଲ୍ ହେତୁ କଲ୍ କରାଯାଇପାରିବ ନାହିଁ।"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ଆପଣଙ୍କର <xliff:g id="OTHER_CALL">%1$s</xliff:g> କଲ୍ ହେତୁ କଲ୍ କରାଯାଇପାରିବ ନାହିଁ।"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ଅନ୍ୟ ଆପ୍‌ରେ କରାଯାଇଥିବା କଲ୍ ହେତୁ କଲ୍ କରାଯାଇପାରିବ ନାହିଁ।"</string>
diff --git a/res/values-pa/strings.xml b/res/values-pa/strings.xml
index b96a1dbe4..831f26045 100644
--- a/res/values-pa/strings.xml
+++ b/res/values-pa/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"ਜਵਾਬ ਦੇਣ ਨਾਲ ਤੁਹਾਡੀ ਜਾਰੀ ਵੀਡੀਓ ਕਾਲ ਸਮਾਪਤ ਹੋ ਜਾਵੇਗੀ"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"ਕਾਲ ਚੁੱਕੋ"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ਕਾਲ ਕੱਟੋ"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ ਕਿਉਂਕਿ ਇੱਥੇ ਅਜਿਹੇ ਕੋਈ ਕਾਲਿੰਗ ਖਾਤੇ ਨਹੀਂ ਹਨ ਜਿਨ੍ਹਾਂ ਵਿੱਚ ਇਸ ਕਿਸਮ ਦੀਆਂ ਕਾਲਾਂ ਦੀ ਸੁਵਿਧਾ ਹੋਵੇ।"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ। ਆਪਣੇ ਡੀਵਾਈਸ ਦੇ ਕਨੈਕਸ਼ਨ ਦੀ ਜਾਂਚ ਕਰੋ।"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ਤੁਹਾਡੀ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ਕਾਲ ਦੇ ਕਾਰਨ ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ।"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ਤੁਹਾਡੀਆਂ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ਕਾਲਾਂ ਦੇ ਕਾਰਨ ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ।"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ਕਿਸੇ ਹੋਰ ਐਪ ਵਿੱਚ ਇੱਕ ਕਾਲ ਹੋਣ ਦੇ ਕਾਰਨ ਕਾਲ ਨਹੀਂ ਕੀਤੀ ਜਾ ਸਕਦੀ।"</string>
diff --git a/res/values-pl/strings.xml b/res/values-pl/strings.xml
index df5d29eb1..23776f56a 100644
--- a/res/values-pl/strings.xml
+++ b/res/values-pl/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Jeśli odbierzesz połączenie, zakończysz rozmowę wideo"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Odbierz"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odrzuć"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Nie można nawiązać połączenia, ponieważ nie ma żadnego konta, które obsługuje połączenia tego typu."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nie udało się zadzwonić. Sprawdź połączenie urządzenia."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Nie możesz zadzwonić z powodu trwającej rozmowy w <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Nie możesz zadzwonić z powodu trwających rozmów w <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Nie możesz zadzwonić z powodu trwającej rozmowy w innej aplikacji."</string>
diff --git a/res/values-pt-rPT/strings.xml b/res/values-pt-rPT/strings.xml
index 5fbe1d3aa..122615af4 100644
--- a/res/values-pt-rPT/strings.xml
+++ b/res/values-pt-rPT/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ao atender, a sua videochamada em curso será terminada"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Atender"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Recusar"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Não é possível efetuar a chamada porque não existem contas de chamadas que suportem chamadas deste tipo."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Não é possível fazer a chamada. Verifique a ligação do seu dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Não é possível efetuar a chamada devido à sua chamada do <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Não é possível efetuar a chamada devido às suas chamadas do <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Não é possível efetuar a chamada devido a uma chamada noutra app."</string>
diff --git a/res/values-pt/strings.xml b/res/values-pt/strings.xml
index a7fc3c741..1e8b027fb 100644
--- a/res/values-pt/strings.xml
+++ b/res/values-pt/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Se você atender, a videochamada em andamento será encerrada"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Atender"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Recusar"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Não é possível ligar porque não há contas compatíveis com chamadas deste tipo."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Não foi possível fazer a chamada. Verifique a conexão do dispositivo."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Não é possível ligar com uma chamada em andamento no <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Não é possível ligar com chamadas em andamento no <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Não é possível ligar com uma chamada em andamento em outro aplicativo."</string>
diff --git a/res/values-ro/strings.xml b/res/values-ro/strings.xml
index 8e485d019..fe5ad9367 100644
--- a/res/values-ro/strings.xml
+++ b/res/values-ro/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Dacă răspunzi, apelul video în curs va fi încheiat."</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Răspunde"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Respinge"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Apelul nu poate fi inițiat deoarece nu există conturi pentru apelare compatibile cu apeluri de acest tip."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Apelul nu poate fi inițiat. Verifică conexiunea dispozitivului."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Apelul nu poate fi inițiat din cauza apelului <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Apelul nu poate fi inițiat din cauza apelurilor <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Apelul nu poate fi inițiat din cauza unui apel din altă aplicație."</string>
diff --git a/res/values-ru/strings.xml b/res/values-ru/strings.xml
index 67ab2e904..cc69d40b8 100644
--- a/res/values-ru/strings.xml
+++ b/res/values-ru/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Если вы ответите, текущий видеовызов будет завершен."</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Ответить"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Отклонить"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Невозможно позвонить, так как нет аккаунтов, которые поддерживают вызовы этого типа."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Не удалось позвонить. Проверьте подключение устройства."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Вы не можете отправить вызов, пока не завершите другой в приложении <xliff:g id="OTHER_CALL">%1$s</xliff:g>"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Вы не можете отправить вызов, пока не завершите другие в приложении <xliff:g id="OTHER_CALL">%1$s</xliff:g>"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Вы не можете отправить новый вызов, пока не завершите текущий в другом приложении"</string>
diff --git a/res/values-si/strings.xml b/res/values-si/strings.xml
index 71442e0ea..2ea058f0a 100644
--- a/res/values-si/strings.xml
+++ b/res/values-si/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"පිළිතුරු දීම ඔබේ යන වීඩියෝ ඇමතුම අවසන් කරනු ඇත"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"පිළිතුරු දෙන්න"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ප්‍රතික්ෂේප කරන්න"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"මෙම වර්ගයේ ඇමතුම්වලට සහාය දක්වන ඇමතීමේ ගිණුම් නොමැති නිසා ඇමතුම ගැනීමට නොහැකිය."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"ඇමතුම ගත නොහැක. ඔබේ‏‏‏ උපාංගයේ සම්බන්ධතාවය පරීක්ෂා කරන්න."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ඔබේ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ඇමතුම හේතුවෙන් ඇමතුම ගැනීමට නොහැකිය."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ඔබේ <xliff:g id="OTHER_CALL">%1$s</xliff:g> ඇමතුම් හේතුවෙන් ඇමතුම ගැනීමට නොහැකිය."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"වෙනත් යෙදුමක ඇමතුමක් හේතුවෙන් ඇමතුම ගැනීමට නොහැකිය."</string>
diff --git a/res/values-sk/strings.xml b/res/values-sk/strings.xml
index a001130b1..fc7108af3 100644
--- a/res/values-sk/strings.xml
+++ b/res/values-sk/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Prijatím hovoru ukončíte prebiehajúci videohovor"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Prijať"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Odmietnuť"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Hovor sa nedá uskutočniť, pretože nie je k dispozícii žiaden účet, ktorý by tento typ hovorov podporoval."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Nedá sa volať. Skontrolujte pripojenie zariadenia."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Hovor sa nedá uskutočniť, pretože prebieha hovor <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Hovor sa nedá uskutočniť, pretože prebiehajú hovory <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Hovor sa nedá uskutočniť, pretože prebieha hovor v inej aplikácii."</string>
diff --git a/res/values-sl/strings.xml b/res/values-sl/strings.xml
index 994bc7e35..7ee0b0b88 100644
--- a/res/values-sl/strings.xml
+++ b/res/values-sl/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Če sprejmete, bo končan aktivni videoklic"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Sprejmi"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Zavrni"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Klica ni mogoče vzpostaviti, ker ni računov za klicanje, ki podpirajo tovrstne klice."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Klica ni mogoče vzpostaviti. Preverite povezavo naprave."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Klica ni mogoče vzpostaviti zaradi klica prek aplikacije <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Klica ni mogoče vzpostaviti zaradi klicev prek aplikacije <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Klica ni mogoče vzpostaviti zaradi klica prek druge aplikacije."</string>
diff --git a/res/values-sq/strings.xml b/res/values-sq/strings.xml
index 89ae852a1..876b0497a 100644
--- a/res/values-sq/strings.xml
+++ b/res/values-sq/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Përgjigjja do ta mbyllë telefonatën me video në vazhdim"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Përgjigju"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Refuzo"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Telefonata nuk mund të kryhet pasi nuk ka asnjë llogari telefonatash që i mbështet telefonatat e këtij lloji."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Telefonata nuk mund të kryhet. Kontrollo lidhjen e pajisjes sate."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Telefonata nuk mund të kryhet për shkak të telefonatës tënde të <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Telefonata nuk mund të kryhet për shkak të telefonatave të tua të <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Telefonata nuk mund të kryhet për shkak të një telefonate në një aplikacion tjetër."</string>
diff --git a/res/values-sr/strings.xml b/res/values-sr/strings.xml
index 113438003..148cb14d1 100644
--- a/res/values-sr/strings.xml
+++ b/res/values-sr/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ако одговорите, завршићете видео позив који је у току"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Одговори"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Одбиј"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Упућивање позива није могуће јер немате ниједан налог за позивање који подржава позиве овог типа."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Позивање није успело. Проверите везу уређаја."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Не можете да упутите позив због <xliff:g id="OTHER_CALL">%1$s</xliff:g> позива."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Не можете да упутите позив због <xliff:g id="OTHER_CALL">%1$s</xliff:g> позива."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Не можете да упутите позив због позива у другој апликацији."</string>
diff --git a/res/values-sv/strings.xml b/res/values-sv/strings.xml
index c6f6ec9e3..d4a930cd3 100644
--- a/res/values-sv/strings.xml
+++ b/res/values-sv/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Det pågående videosamtalet avslutas om du svarar"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Svara"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Avvisa"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Det går inte att ringa på grund av att det inte finns uppringningskonton som stöder den här samtalstypen."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Det går inte att ringa samtalet. Kontrollera enhetens anslutning."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Det går inte att ringa på grund av samtalet via <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Det går inte att ringa på grund av samtalen via <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Det går inte att ringa på grund av ett samtal via en annan app."</string>
diff --git a/res/values-sw/strings.xml b/res/values-sw/strings.xml
index ef58c0044..ac0518dfe 100644
--- a/res/values-sw/strings.xml
+++ b/res/values-sw/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ukijibu utakata simu yako ya video inayoendelea"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Jibu"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Kataa"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Haiwezi kupiga simu kwa sababu hakuna akaunti za kupiga simu zinazoweza kupiga aina hii ya simu."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Imeshindwa kupiga simu. Kagua muunganisho wa kifaa chako."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Haiwezekani kupiga kwa sababu ya simu yako ya <xliff:g id="OTHER_CALL">%1$s</xliff:g> inayoendelea."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Haiwezekani kupiga kwa sababu ya simu zako za <xliff:g id="OTHER_CALL">%1$s</xliff:g> zinazoendelea."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Haiwezekani kwa sababu kuna simu inayoendelea kwenye programu nyingine."</string>
diff --git a/res/values-ta/strings.xml b/res/values-ta/strings.xml
index 9f37d8760..57c70f4bb 100644
--- a/res/values-ta/strings.xml
+++ b/res/values-ta/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"பதிலளித்தால், செயலில் உள்ள வீடியோ அழைப்பு துண்டிக்கப்படும்"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"பதிலளி"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"நிராகரி"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"இந்த வகை அழைப்புகளை ஆதரிக்கும் அழைப்புக் கணக்குகள் இல்லாததால், அழைப்பை மேற்கொள்ள முடியாது."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"அழைப்பை மேற்கொள்ள முடியவில்லை. உங்கள் சாதனத்தின் இணைப்பைச் சரிபார்க்கவும்."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> அழைப்பு செயலில் உள்ளதால், புதிய அழைப்பைச் செய்ய முடியாது."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"<xliff:g id="OTHER_CALL">%1$s</xliff:g> அழைப்புகள் செயலில் உள்ளதால், புதிய அழைப்பைச் செய்ய முடியாது."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"மற்றொரு பயன்பாட்டில் அழைப்பு செயலில் உள்ளதால், புதிய அழைப்பைச் செய்ய முடியாது."</string>
diff --git a/res/values-te/strings.xml b/res/values-te/strings.xml
index 8f8a23e4d..22f4b8a4d 100644
--- a/res/values-te/strings.xml
+++ b/res/values-te/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"సమాధానమివ్వడం వలన మీ కొనసాగుతున్న వీడియో కాల్ ముగుస్తుంది"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"సమాధానమివ్వండి"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"తిరస్కరించు"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"కాల్ చేయడం సాధ్యపడదు ఎందుకంటే, ఈ రకమైన కాల్స్‌కు మద్దతిచ్చే కాల్ చేయడానికి ఉపయోగించే ఖాతాలు లేవు."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"కాల్ చేయడం సాధ్యపడదు. మీ పరికర కనెక్షన్‌ను చెక్ చేయండి."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"మీ <xliff:g id="OTHER_CALL">%1$s</xliff:g> కాల్ కొనసాగుతున్నందున కాల్ చేయడం సాధ్యపడదు."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"మీ <xliff:g id="OTHER_CALL">%1$s</xliff:g> కాల్స్‌ కొనసాగుతున్నందున కాల్ చేయడం సాధ్యపడదు."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"వేరొక యాప్‌లో కాల్ కొనసాగుతున్నందున కాల్ చేయడం సాధ్యపడదు."</string>
diff --git a/res/values-th/strings.xml b/res/values-th/strings.xml
index b8dc9f0d2..e3a20b129 100644
--- a/res/values-th/strings.xml
+++ b/res/values-th/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"การรับสายนี้จะวางสาย Hangouts วิดีโอที่สนทนาอยู่"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"รับสาย"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"ปฏิเสธ"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"การโทรไม่สำเร็จเนื่องจากไม่มีบัญชีการโทรที่รองรับการโทรประเภทนี้"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"โทรออกไม่ได้ โปรดตรวจสอบการเชื่อมต่อของอุปกรณ์"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"ไม่สามารถโทรออกได้เนื่องจากกำลังใช้สายอยู่ใน <xliff:g id="OTHER_CALL">%1$s</xliff:g>"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"ไม่สามารถโทรออกได้เนื่องจากกำลังใช้สายอยู่ใน <xliff:g id="OTHER_CALL">%1$s</xliff:g>"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"ไม่สามารถโทรออกได้เนื่องจากกำลังใช้สายอยู่ในแอปอื่น"</string>
diff --git a/res/values-tl/strings.xml b/res/values-tl/strings.xml
index 91e1b3323..001a19ae1 100644
--- a/res/values-tl/strings.xml
+++ b/res/values-tl/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Kung sasagutin, matatapos ang iyong kasalukuyang video call"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Sagutin"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Tanggihan"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Hindi maisasagawa ang tawag dahil walang account sa pagtawag na sumusuporta sa ganitong uri ng mga tawag."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Hindi makatawag. Suriin ang koneksyon ng iyong device."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Hindi makakatawag dahil sa iyong tawag sa <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Hindi makakatawag dahil sa iyong mga tawag sa <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Hindi makakatawag dahil sa isang tawag sa isa pang app."</string>
diff --git a/res/values-tr/strings.xml b/res/values-tr/strings.xml
index 0aa2e20d0..1924d922f 100644
--- a/res/values-tr/strings.xml
+++ b/res/values-tr/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Cevapladığınızda, devam eden görüntülü görüşme sona erecek"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Cevapla"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Reddet"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Bu tür görüşmeleri destekleyen bir arama hesabı olmadığı için arama yapılamıyor."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Arama yapılamıyor. Cihazınızın bağlantısını kontrol edin."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Devam eden <xliff:g id="OTHER_CALL">%1$s</xliff:g> çağrınız nedeniyle telefon araması yapılamıyor."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Devam eden <xliff:g id="OTHER_CALL">%1$s</xliff:g> çağrılarınız nedeniyle telefon araması yapılamıyor."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Başka bir uygulamada devam eden çağrınız nedeniyle telefon araması yapılamıyor."</string>
diff --git a/res/values-uk/strings.xml b/res/values-uk/strings.xml
index a4d01d175..2d4f5bc46 100644
--- a/res/values-uk/strings.xml
+++ b/res/values-uk/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Якщо відповісти на виклик, поточний відеодзвінок завершиться"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Відповісти"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Відхилити"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Такі виклики не підтримуються. Немає потрібного облікового запису чи сервісу."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Не вдається здійснити виклик. Перевірте підключення пристрою."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Неможливо зателефонувати через поточний виклик у <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Неможливо зателефонувати через поточні виклики в <xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Неможливо зателефонувати через поточний виклик в іншому додатку."</string>
diff --git a/res/values-ur/strings.xml b/res/values-ur/strings.xml
index 6649f4200..b09f244b6 100644
--- a/res/values-ur/strings.xml
+++ b/res/values-ur/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"جواب دینا آپ کی جاری ویڈیو کال کو ختم کر دے گا"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"جواب دیں"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"مسترد کریں"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"کال نہیں کی جا سکی کیونکہ اس قسم کی کالز کو سپورٹ کرنے والا کوئی کالنگ اکاؤنٹ نہیں ہے۔"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"کال نہیں کر سکتے۔ اپنے آلے کا کنکشن چیک کریں۔"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"آپ کی <xliff:g id="OTHER_CALL">%1$s</xliff:g> کال کی وجہ سے کال نہیں کی جاسکتی۔"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"آپ کی <xliff:g id="OTHER_CALL">%1$s</xliff:g> کالز کی وجہ سے کالز نہیں کی جاسکتیں۔"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"کسی دوسری ایپ میں موجود کال کی کی وجہ سے کال نہیں کی جا سکتی۔"</string>
diff --git a/res/values-uz/strings.xml b/res/values-uz/strings.xml
index c6805ea8b..ff049035b 100644
--- a/res/values-uz/strings.xml
+++ b/res/values-uz/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Chaqiruvga javob berilsa, joriy video suhbat tugatiladi."</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Javob berish"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Rad etish"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Telefon qilish imkonsiz, chunki bunday turdagi chaqiruvni qo‘llab-quvvatlaydigan hisob yo‘q."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Telefon ishlamaydi. Qurilma aloqasini tekshiring."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Joriy <xliff:g id="OTHER_CALL">%1$s</xliff:g> qo‘ng‘ir. tufayli boshqa raqamni chaqirib bo‘lmaydi."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Joriy <xliff:g id="OTHER_CALL">%1$s</xliff:g> qo‘ng‘ir-r tufayli boshqa raqamni chaqirib bo‘lmaydi."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Boshqa ilovadagi joriy qo‘ng‘iroq tufayli boshqa raqamni chaqirib bo‘lmaydi."</string>
diff --git a/res/values-vi/strings.xml b/res/values-vi/strings.xml
index 70f9bfc5e..142026c31 100644
--- a/res/values-vi/strings.xml
+++ b/res/values-vi/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Trả lời sẽ kết thúc cuộc gọi video đang diễn ra của bạn"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Trả lời"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Từ chối"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Không thể thực hiện cuộc gọi do không có tài khoản hỗ trợ loại cuộc gọi này."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Không thể gọi điện. Hãy kiểm tra kết nối của thiết bị."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Không thể thực hiện cuộc gọi do cuộc gọi <xliff:g id="OTHER_CALL">%1$s</xliff:g> của bạn."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Không thể thực hiện cuộc gọi do cuộc gọi <xliff:g id="OTHER_CALL">%1$s</xliff:g> của bạn."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Không thể thực hiện cuộc gọi do có cuộc gọi trong một ứng dụng khác."</string>
diff --git a/res/values-zh-rCN/strings.xml b/res/values-zh-rCN/strings.xml
index 1ef0a552f..7cb8a7a13 100644
--- a/res/values-zh-rCN/strings.xml
+++ b/res/values-zh-rCN/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"如果接听此来电，您当前的视频通话会中断。"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"接听"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"拒接"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"无法拨出电话，因为没有通话账号支持拨打这类电话。"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"无法拨打电话。请检查设备的连接情况。"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"由于当前正在进行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通话，因此无法拨打电话。"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"由于当前正在进行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通话，因此无法拨打电话。"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"由于当前正在通过其他应用通话，因此无法拨打电话。"</string>
diff --git a/res/values-zh-rHK/strings.xml b/res/values-zh-rHK/strings.xml
index 0140f26a7..213255a19 100644
--- a/res/values-zh-rHK/strings.xml
+++ b/res/values-zh-rHK/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"如果接聽，你進行中的視像通話將會結束"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"接聽"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"拒絕"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"沒有通話帳戶支援這類通話，因此無法撥打電話。"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"無法撥打電話。請檢查裝置是否正確連接。"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"由於你已在進行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通話，因此無法撥打電話。"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"由於你已在進行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通話，因此無法撥打電話。"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"由於已在另一個應用程式中進行通話，因此無法撥打電話。"</string>
diff --git a/res/values-zh-rTW/strings.xml b/res/values-zh-rTW/strings.xml
index eeb98b56b..287f62713 100644
--- a/res/values-zh-rTW/strings.xml
+++ b/res/values-zh-rTW/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"接聽之後，你正在進行的視訊通話就會結束"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"接聽"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"拒接"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"你尚未設定支援這類通話的通話帳戶，因此無法撥打電話。"</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"無法撥打電話，請檢查裝置的藍牙連線。"</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"你正在進行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通話，因此無法撥打電話。"</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"你正在進行 <xliff:g id="OTHER_CALL">%1$s</xliff:g> 通話，所以無法撥打電話。"</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"你正在使用其他應用程式進行通話，因此無法撥打電話。"</string>
diff --git a/res/values-zu/strings.xml b/res/values-zu/strings.xml
index faee0d9ab..8d0437d80 100644
--- a/res/values-zu/strings.xml
+++ b/res/values-zu/strings.xml
@@ -90,7 +90,7 @@
     <string name="answering_ends_other_managed_video_call" msgid="1988508241432031327">"Ukuphendula kuzoqeda ikholi yakho yevidiyo eqhubekayo"</string>
     <string name="answer_incoming_call" msgid="2045888814782215326">"Phendula"</string>
     <string name="decline_incoming_call" msgid="922147089348451310">"Yenqaba"</string>
-    <string name="cant_call_due_to_no_supported_service" msgid="1635626384149947077">"Ikholi ayikwazi ukubekwa ngoba awasekho ama-akhawunti okushaya asekela amakholi walolu hlobo."</string>
+    <string name="cant_call_due_to_no_supported_service" msgid="6720817368116820027">"Ayikwazi ukwenza ikholi. Hlola ukuxhumeka kwedivayisi yakho."</string>
     <string name="cant_call_due_to_ongoing_call" msgid="8004235328451385493">"Ikholi ayikwazi ukwenziwa ngenxa yekholi yakho ye-<xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_calls" msgid="6379163795277824868">"Ikholi ayikwazi ukwenziwa ngenxa yamakholi akho e-<xliff:g id="OTHER_CALL">%1$s</xliff:g>."</string>
     <string name="cant_call_due_to_ongoing_unknown_call" msgid="8243532328969433172">"Ikholi ayikwazi ukwenziwa ngenxa yekholi kolunye uhlelo lokusebenza."</string>
diff --git a/res/values/config.xml b/res/values/config.xml
index ae5d88ec1..8ebbd8617 100644
--- a/res/values/config.xml
+++ b/res/values/config.xml
@@ -83,8 +83,8 @@
     <!-- When true, skip fetching quick reply response -->
     <bool name="skip_loading_canned_text_response">false</bool>
 
-    <!-- When true, skip fetching incoming caller info -->
-    <bool name="skip_incoming_caller_info_query">false</bool>
+    <!-- When set, telecom will skip fetching incoming caller info for this account -->
+    <string name="skip_incoming_caller_info_account_package"></string>
 
     <string-array name="system_bluetooth_stack_package_name" translatable="false">
         <!-- AOSP -->
diff --git a/res/values/strings.xml b/res/values/strings.xml
index ec278f008..aefd2e6f9 100644
--- a/res/values/strings.xml
+++ b/res/values/strings.xml
@@ -290,9 +290,11 @@
 
     <!-- Error message shown to the user when an outgoing call cannot be placed because there no
          calling service is present on the device which supports this call type.
-         This is typically encountered when the user tries to dial a SIP/VOIP call, but there are
-         no calling services present which support SIP calling. [CHAR LIMIT=none] -->
-    <string name="cant_call_due_to_no_supported_service">Call cannot be placed because there are no calling accounts which support calls of this type.</string>
+         This can happen on a device such as a watch or tablet which provides calling using a
+         service that may not be available all the time.  For example, a watch may rely on Bluetooth
+         to be enabled for calling to work; when Bluetooth is disabled calling would not work.
+         [CHAR LIMIT=none] -->
+    <string name="cant_call_due_to_no_supported_service">Can\'t make call. Check your device\'s connection.</string>
 
     <!-- Error message shown to the user when an outgoing call cannot be placed due to an ongoing
          phone call in a third-party app.  For example:
diff --git a/res/values/styles.xml b/res/values/styles.xml
index 0624082e6..0660fd584 100644
--- a/res/values/styles.xml
+++ b/res/values/styles.xml
@@ -26,6 +26,18 @@
         <item name="android:windowAnimationStyle">@android:style/Animation.Dialog</item>
     </style>
 
+    <style name="Theme.Telecomm.UserCallActivityNoSplash" parent="@android:style/Theme.DeviceDefault.Light">
+        <item name="android:forceDarkAllowed">true</item>
+        <item name="android:windowIsTranslucent">true</item>
+        <item name="android:windowBackground">@android:color/transparent</item>
+        <item name="android:windowContentOverlay">@null</item>
+        <item name="android:windowNoTitle">true</item>
+        <item name="android:windowIsFloating">true</item>
+        <item name="android:backgroundDimEnabled">true</item>
+        <item name="android:windowAnimationStyle">@android:style/Animation.Dialog</item>
+        <item name="android:windowDisablePreview">true</item>
+    </style>
+
    <style name="Theme.Telecom.DialerSettings" parent="@android:style/Theme.DeviceDefault.Light">
         <item name="android:forceDarkAllowed">true</item>
         <item name="android:actionBarStyle">@style/TelecomDialerSettingsActionBarStyle</item>
diff --git a/src/com/android/server/telecom/AudioRoute.java b/src/com/android/server/telecom/AudioRoute.java
index 8a5e85811..d469a4364 100644
--- a/src/com/android/server/telecom/AudioRoute.java
+++ b/src/com/android/server/telecom/AudioRoute.java
@@ -70,7 +70,7 @@ public class AudioRoute {
                 return;
             }
 
-            Log.i(this, "creating AudioRoute with type %s and address %s, retry count %d",
+            Log.i(this, "createRetry; type=%s, address=%s, retryCount=%d",
                     DEVICE_TYPE_STRINGS.get(type), bluetoothAddress, retryCount);
             AudioDeviceInfo routeInfo = null;
             List<AudioDeviceInfo> infos = audioManager.getAvailableCommunicationDevices();
@@ -117,6 +117,8 @@ public class AudioRoute {
     public static final int TYPE_BLUETOOTH_HA = 6;
     public static final int TYPE_BLUETOOTH_LE = 7;
     public static final int TYPE_STREAMING = 8;
+    // Used by auto
+    public static final int TYPE_BUS = 9;
     @IntDef(prefix = "TYPE", value = {
             TYPE_INVALID,
             TYPE_EARPIECE,
@@ -126,7 +128,8 @@ public class AudioRoute {
             TYPE_BLUETOOTH_SCO,
             TYPE_BLUETOOTH_HA,
             TYPE_BLUETOOTH_LE,
-            TYPE_STREAMING
+            TYPE_STREAMING,
+            TYPE_BUS
     })
     @Retention(RetentionPolicy.SOURCE)
     public @interface AudioRouteType {}
@@ -134,6 +137,7 @@ public class AudioRoute {
     private @AudioRouteType int mAudioRouteType;
     private String mBluetoothAddress;
     private AudioDeviceInfo mInfo;
+    private boolean mIsDestRouteForWatch;
     public static final Set<Integer> BT_AUDIO_DEVICE_INFO_TYPES = Set.of(
             AudioDeviceInfo.TYPE_BLE_HEADSET,
             AudioDeviceInfo.TYPE_BLE_SPEAKER,
@@ -155,35 +159,38 @@ public class AudioRoute {
         DEVICE_TYPE_STRINGS.put(TYPE_WIRED, "TYPE_WIRED_HEADSET");
         DEVICE_TYPE_STRINGS.put(TYPE_SPEAKER, "TYPE_SPEAKER");
         DEVICE_TYPE_STRINGS.put(TYPE_DOCK, "TYPE_DOCK");
+        DEVICE_TYPE_STRINGS.put(TYPE_BUS, "TYPE_BUS");
         DEVICE_TYPE_STRINGS.put(TYPE_BLUETOOTH_SCO, "TYPE_BLUETOOTH_SCO");
         DEVICE_TYPE_STRINGS.put(TYPE_BLUETOOTH_HA, "TYPE_BLUETOOTH_HA");
         DEVICE_TYPE_STRINGS.put(TYPE_BLUETOOTH_LE, "TYPE_BLUETOOTH_LE");
         DEVICE_TYPE_STRINGS.put(TYPE_STREAMING, "TYPE_STREAMING");
     }
 
-    public static final HashMap<Integer, Integer> DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE;
+    public static final HashMap<Integer, Integer> DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE;
     static {
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE = new HashMap<>();
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BUILTIN_EARPIECE,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE = new HashMap<>();
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BUILTIN_EARPIECE,
                 TYPE_EARPIECE);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER, TYPE_SPEAKER);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_WIRED_HEADSET, TYPE_WIRED);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_WIRED_HEADPHONES, TYPE_WIRED);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER,
+                TYPE_SPEAKER);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_WIRED_HEADSET, TYPE_WIRED);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_WIRED_HEADPHONES, TYPE_WIRED);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLUETOOTH_SCO,
                 TYPE_BLUETOOTH_SCO);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_DEVICE, TYPE_WIRED);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_ACCESSORY, TYPE_WIRED);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_DOCK, TYPE_DOCK);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_HEADSET, TYPE_WIRED);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_HEARING_AID,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_DEVICE, TYPE_WIRED);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_ACCESSORY, TYPE_WIRED);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_DOCK, TYPE_DOCK);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_USB_HEADSET, TYPE_WIRED);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_HEARING_AID,
                 TYPE_BLUETOOTH_HA);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_HEADSET,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_HEADSET,
                 TYPE_BLUETOOTH_LE);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_SPEAKER,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_SPEAKER,
                 TYPE_BLUETOOTH_LE);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_BROADCAST,
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BLE_BROADCAST,
                 TYPE_BLUETOOTH_LE);
-        DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_DOCK_ANALOG, TYPE_DOCK);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_DOCK_ANALOG, TYPE_DOCK);
+        DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.put(AudioDeviceInfo.TYPE_BUS, TYPE_BUS);
     }
 
     private static final HashMap<Integer, List<Integer>> AUDIO_ROUTE_TYPE_TO_DEVICE_INFO_TYPE;
@@ -210,6 +217,10 @@ public class AudioRoute {
         dockDeviceInfoTypes.add(AudioDeviceInfo.TYPE_DOCK_ANALOG);
         AUDIO_ROUTE_TYPE_TO_DEVICE_INFO_TYPE.put(TYPE_DOCK, dockDeviceInfoTypes);
 
+        List<Integer> busDeviceInfoTypes = new ArrayList<>();
+        busDeviceInfoTypes.add(AudioDeviceInfo.TYPE_BUS);
+        AUDIO_ROUTE_TYPE_TO_DEVICE_INFO_TYPE.put(TYPE_BUS, busDeviceInfoTypes);
+
         List<Integer> bluetoothScoDeviceInfoTypes = new ArrayList<>();
         bluetoothScoDeviceInfoTypes.add(AudioDeviceInfo.TYPE_BLUETOOTH_A2DP);
         bluetoothScoDeviceInfoTypes.add(AudioDeviceInfo.TYPE_BLUETOOTH_SCO);
@@ -231,6 +242,10 @@ public class AudioRoute {
         return mAudioRouteType;
     }
 
+    public boolean isWatch() {
+        return mIsDestRouteForWatch;
+    }
+
     String getBluetoothAddress() {
         return mBluetoothAddress;
     }
@@ -239,7 +254,8 @@ public class AudioRoute {
     void onDestRouteAsPendingRoute(boolean active, PendingAudioRoute pendingAudioRoute,
             BluetoothDevice device, AudioManager audioManager,
             BluetoothRouteManager bluetoothRouteManager, boolean isScoAudioConnected) {
-        Log.i(this, "onDestRouteAsPendingRoute: active (%b), type (%d)", active, mAudioRouteType);
+        Log.i(this, "onDestRouteAsPendingRoute: active (%b), type (%s)", active,
+                DEVICE_TYPE_STRINGS.get(mAudioRouteType));
         if (pendingAudioRoute.isActive() && !active) {
             clearCommunicationDevice(pendingAudioRoute, bluetoothRouteManager, audioManager);
         } else if (active) {
@@ -249,6 +265,8 @@ public class AudioRoute {
                         audioManager, bluetoothRouteManager);
                 // Special handling for SCO case.
                 if (mAudioRouteType == TYPE_BLUETOOTH_SCO) {
+                    // Set whether the dest route is for the watch
+                    mIsDestRouteForWatch = bluetoothRouteManager.isWatch(device);
                     // Check if the communication device was set for the device, even if
                     // BluetoothHeadset#connectAudio reports that the SCO connection wasn't
                     // successfully established.
@@ -281,8 +299,8 @@ public class AudioRoute {
                     if (result) {
                         pendingAudioRoute.setCommunicationDeviceType(mAudioRouteType);
                     }
-                    Log.i(this, "Result of setting communication device for audio "
-                            + "route (%s) - %b", this, result);
+                    Log.i(this, "onDestRouteAsPendingRoute: route=%s, "
+                            + "AudioManager#setCommunicationDevice()=%b", this, result);
                     break;
                 }
             }
@@ -380,11 +398,11 @@ public class AudioRoute {
 
         int result = BluetoothStatusCodes.SUCCESS;
         if (pendingAudioRoute.getCommunicationDeviceType() == TYPE_BLUETOOTH_SCO) {
-            Log.i(this, "Disconnecting SCO device.");
+            Log.i(this, "clearCommunicationDevice: Disconnecting SCO device.");
             result = bluetoothRouteManager.getDeviceManager().disconnectSco();
         } else {
-            Log.i(this, "Clearing communication device for audio type %d.",
-                    pendingAudioRoute.getCommunicationDeviceType());
+            Log.i(this, "clearCommunicationDevice: AudioManager#clearCommunicationDevice, type=%s",
+                    DEVICE_TYPE_STRINGS.get(pendingAudioRoute.getCommunicationDeviceType()));
             audioManager.clearCommunicationDevice();
         }
 
diff --git a/src/com/android/server/telecom/CachedAvailableEndpointsChange.java b/src/com/android/server/telecom/CachedAvailableEndpointsChange.java
index 232f00df3..fc989917c 100644
--- a/src/com/android/server/telecom/CachedAvailableEndpointsChange.java
+++ b/src/com/android/server/telecom/CachedAvailableEndpointsChange.java
@@ -33,6 +33,11 @@ public class CachedAvailableEndpointsChange implements CachedCallback {
         mAvailableEndpoints = endpoints;
     }
 
+    @Override
+    public int getCacheType() {
+        return TYPE_STATE;
+    }
+
     @Override
     public void executeCallback(CallSourceService service, Call call) {
         service.onAvailableCallEndpointsChanged(call, mAvailableEndpoints);
diff --git a/src/com/android/server/telecom/CachedCallEventQueue.java b/src/com/android/server/telecom/CachedCallEventQueue.java
new file mode 100644
index 000000000..9ce51bf30
--- /dev/null
+++ b/src/com/android/server/telecom/CachedCallEventQueue.java
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
+package com.android.server.telecom;
+
+import android.os.Bundle;
+import android.telecom.Log;
+
+public class CachedCallEventQueue implements CachedCallback {
+    public static final String ID = CachedCallEventQueue.class.getSimpleName();
+
+    private final String mEvent;
+    private final Bundle mExtras;
+
+    public CachedCallEventQueue(String event, Bundle extras) {
+        mEvent = event;
+        mExtras = extras;
+    }
+
+    @Override
+    public int getCacheType() {
+        return TYPE_QUEUE;
+    }
+
+    @Override
+    public void executeCallback(CallSourceService service, Call call) {
+        Log.addEvent(call, LogUtils.Events.CALL_EVENT, mEvent);
+        service.sendCallEvent(call, mEvent, mExtras);
+    }
+
+    @Override
+    public String getCallbackId() {
+        return ID;
+    }
+}
diff --git a/src/com/android/server/telecom/CachedCallback.java b/src/com/android/server/telecom/CachedCallback.java
index 88dad0726..c354beb55 100644
--- a/src/com/android/server/telecom/CachedCallback.java
+++ b/src/com/android/server/telecom/CachedCallback.java
@@ -22,6 +22,27 @@ package com.android.server.telecom;
  * The callback will be executed once the service is set.
  */
 public interface CachedCallback {
+
+    /**
+     * This callback is caching a state, meaning any new CachedCallbacks with the same
+     * {@link #getCallbackId()} will REPLACE any existing CachedCallback.
+     */
+    int TYPE_STATE = 0;
+    /**
+     * This callback is caching a Queue, meaning that any new CachedCallbacks with the same
+     * {@link #getCallbackId()} will enqueue as a FIFO queue and each instance of this
+     * CachedCallback will run {@link #executeCallback(CallSourceService, Call)}.
+     */
+    int TYPE_QUEUE = 1;
+
+    /**
+     * This method allows the callback to determine whether it is caching a {@link #TYPE_STATE} or
+     * a {@link #TYPE_QUEUE}.
+     *
+     * @return Either {@link #TYPE_STATE} or {@link #TYPE_QUEUE} based on the callback type.
+     */
+    int getCacheType();
+
     /**
      * This method executes the callback that was cached because the service was not available
      * at the time the callback was ready.
@@ -33,11 +54,19 @@ public interface CachedCallback {
     void executeCallback(CallSourceService service, Call call);
 
     /**
-     * This method is helpful for caching the callbacks.  If the callback is called multiple times
-     * while the service is not set, ONLY the last callback should be sent to the client since the
-     * last callback is the most relevant
+     * The ID that this CachedCallback should use to identify itself as a distinct operation.
+     * <p>
+     * If {@link #TYPE_STATE} is set for {@link #getCacheType()}, and a CachedCallback with the
+     * same ID is called multiple times while the service is not set, ONLY the last callback will be
+     * sent to the client since the last callback is the most relevant.
+     * <p>
+     * If {@link #TYPE_QUEUE} is set for {@link #getCacheType()} and the CachedCallback with the
+     * same ID is called multiple times while the service is not set, each CachedCallback will be
+     * enqueued in FIFO order. Once the service is set, {@link #executeCallback} will be called
+     * for each CachedCallback with the same ID.
      *
-     * @return the callback id that is used in a map to only store the last callback value
+     * @return A unique callback id that will be used differentiate this CachedCallback type with
+     * other CachedCallback types.
      */
     String getCallbackId();
 }
diff --git a/src/com/android/server/telecom/CachedCurrentEndpointChange.java b/src/com/android/server/telecom/CachedCurrentEndpointChange.java
index 0d5bac94d..1d838f0b2 100644
--- a/src/com/android/server/telecom/CachedCurrentEndpointChange.java
+++ b/src/com/android/server/telecom/CachedCurrentEndpointChange.java
@@ -32,6 +32,11 @@ public class CachedCurrentEndpointChange implements CachedCallback {
         mCurrentCallEndpoint = callEndpoint;
     }
 
+    @Override
+    public int getCacheType() {
+        return TYPE_STATE;
+    }
+
     @Override
     public void executeCallback(CallSourceService service, Call call) {
         service.onCallEndpointChanged(call, mCurrentCallEndpoint);
diff --git a/src/com/android/server/telecom/CachedMuteStateChange.java b/src/com/android/server/telecom/CachedMuteStateChange.java
index 45cbfaa76..ee1227b35 100644
--- a/src/com/android/server/telecom/CachedMuteStateChange.java
+++ b/src/com/android/server/telecom/CachedMuteStateChange.java
@@ -28,6 +28,11 @@ public class CachedMuteStateChange implements CachedCallback {
         mIsMuted = isMuted;
     }
 
+    @Override
+    public int getCacheType() {
+        return TYPE_STATE;
+    }
+
     @Override
     public void executeCallback(CallSourceService service, Call call) {
         service.onMuteStateChanged(call, mIsMuted);
diff --git a/src/com/android/server/telecom/CachedVideoStateChange.java b/src/com/android/server/telecom/CachedVideoStateChange.java
index 0892c33bb..cefb92bcb 100644
--- a/src/com/android/server/telecom/CachedVideoStateChange.java
+++ b/src/com/android/server/telecom/CachedVideoStateChange.java
@@ -32,6 +32,11 @@ public class CachedVideoStateChange implements CachedCallback {
         mCurrentVideoState = videoState;
     }
 
+    @Override
+    public int getCacheType() {
+        return TYPE_STATE;
+    }
+
     @Override
     public void executeCallback(CallSourceService service, Call call) {
         service.onVideoStateChanged(call, mCurrentVideoState);
diff --git a/src/com/android/server/telecom/Call.java b/src/com/android/server/telecom/Call.java
index 760028df7..c3916414d 100644
--- a/src/com/android/server/telecom/Call.java
+++ b/src/com/android/server/telecom/Call.java
@@ -19,6 +19,8 @@ package com.android.server.telecom;
 import static android.provider.CallLog.Calls.MISSED_REASON_NOT_MISSED;
 import static android.telephony.TelephonyManager.EVENT_DISPLAY_EMERGENCY_MESSAGE;
 
+import static com.android.server.telecom.CachedCallback.TYPE_QUEUE;
+import static com.android.server.telecom.CachedCallback.TYPE_STATE;
 import static com.android.server.telecom.voip.VideoStateTranslation.TransactionalVideoStateToString;
 import static com.android.server.telecom.voip.VideoStateTranslation.VideoProfileStateToTransactionalVideoState;
 
@@ -37,7 +39,6 @@ import android.os.OutcomeReceiver;
 import android.os.ParcelFileDescriptor;
 import android.os.RemoteException;
 import android.os.SystemClock;
-import android.os.Trace;
 import android.os.UserHandle;
 import android.provider.CallLog;
 import android.provider.ContactsContract.Contacts;
@@ -850,14 +851,51 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      */
     private CompletableFuture<Boolean> mBtIcsFuture;
 
-    Map<String, CachedCallback> mCachedServiceCallbacks = new HashMap<>();
+    /**
+     * Map of CachedCallbacks that are pending to be executed when the *ServiceWrapper connects
+     */
+    private final Map<String, List<CachedCallback>> mCachedServiceCallbacks = new HashMap<>();
 
     public void cacheServiceCallback(CachedCallback callback) {
-        mCachedServiceCallbacks.put(callback.getCallbackId(), callback);
+        synchronized (mCachedServiceCallbacks) {
+            if (mFlags.cacheCallEvents()) {
+                // If there are multiple threads caching + calling processCachedCallbacks at the
+                // same time, there is a race - double check here to ensure that we do not lose an
+                // operation due to a a cache happening after processCachedCallbacks.
+                // Either service will be non-null in this case, but both will not be non-null
+                if (mConnectionService != null) {
+                    callback.executeCallback(mConnectionService, this);
+                    return;
+                }
+                if (mTransactionalService != null) {
+                    callback.executeCallback(mTransactionalService, this);
+                    return;
+                }
+            }
+            List<CachedCallback> cbs = mCachedServiceCallbacks.computeIfAbsent(
+                    callback.getCallbackId(), k -> new ArrayList<>());
+            switch (callback.getCacheType()) {
+                case TYPE_STATE: {
+                    cbs.clear();
+                    cbs.add(callback);
+                    break;
+                }
+                case TYPE_QUEUE: {
+                    cbs.add(callback);
+                }
+            }
+        }
     }
 
-    public Map<String, CachedCallback> getCachedServiceCallbacks() {
-        return mCachedServiceCallbacks;
+    @VisibleForTesting
+    public Map<String, List<CachedCallback>> getCachedServiceCallbacksCopy() {
+        synchronized (mCachedServiceCallbacks) {
+            // This should only be used during testing, but to be safe, since there is internally a
+            // List value, we need to do a deep copy to ensure someone with a ref to the Map doesn't
+            // mutate the underlying list while we are modifying it in cacheServiceCallback.
+            return mCachedServiceCallbacks.entrySet().stream().collect(
+                    Collectors.toUnmodifiableMap(Map.Entry::getKey, e-> List.copyOf(e.getValue())));
+        }
     }
 
     private FeatureFlags mFlags;
@@ -931,7 +969,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         mLock = lock;
         mRepository = repository;
         mPhoneNumberUtilsAdapter = phoneNumberUtilsAdapter;
-        setHandle(handle);
         mParticipants = participants;
         mPostDialDigits = handle != null
                 ? PhoneNumberUtils.extractPostDialPortion(handle.getSchemeSpecificPart()) : "";
@@ -939,6 +976,7 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         setConnectionManagerPhoneAccount(connectionManagerPhoneAccountHandle);
         mCallDirection = callDirection;
         setTargetPhoneAccount(targetPhoneAccountHandle);
+        setHandle(handle);
         mIsConference = isConference;
         mShouldAttachToExistingConnection = shouldAttachToExistingConnection
                 || callDirection == CALL_DIRECTION_INCOMING;
@@ -1611,9 +1649,11 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 mIsTestEmergencyCall = mHandle != null &&
                         isTestEmergencyCall(mHandle.getSchemeSpecificPart());
             }
-            if (!mContext.getResources().getBoolean(R.bool.skip_incoming_caller_info_query)) {
+            if (mTargetPhoneAccountHandle == null || !mContext.getResources().getString(
+                    R.string.skip_incoming_caller_info_account_package).equalsIgnoreCase(
+                    mTargetPhoneAccountHandle.getComponentName().getPackageName())) {
                 startCallerInfoLookup();
-            } else  {
+            } else {
                 Log.i(this, "skip incoming caller info lookup");
             }
             for (Listener l : mListeners) {
@@ -1940,7 +1980,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 PhoneAccount.EXTRA_LOG_SELF_MANAGED_CALLS, false);
     }
 
-    @VisibleForTesting
     public boolean isIncoming() {
         return mCallDirection == CALL_DIRECTION_INCOMING;
     }
@@ -2051,11 +2090,13 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
 
     private void processCachedCallbacks(CallSourceService service) {
         if(mFlags.cacheCallAudioCallbacks()) {
-            for (CachedCallback callback : mCachedServiceCallbacks.values()) {
-                callback.executeCallback(service, this);
+            synchronized (mCachedServiceCallbacks) {
+                for (List<CachedCallback> callbacks : mCachedServiceCallbacks.values()) {
+                    callbacks.forEach( callback -> callback.executeCallback(service, this));
+                }
+                // clear list for memory cleanup purposes. The Service should never be reset
+                mCachedServiceCallbacks.clear();
             }
-            // clear list for memory cleanup purposes. The Service should never be reset
-            mCachedServiceCallbacks.clear();
         }
     }
 
@@ -2149,10 +2190,15 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 isWorkCall = UserUtil.isManagedProfile(mContext, userHandle, mFlags);
             }
 
-            isCallRecordingToneSupported = (phoneAccount.hasCapabilities(
-                    PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION) && phoneAccount.getExtras() != null
-                    && phoneAccount.getExtras().getBoolean(
-                    PhoneAccount.EXTRA_PLAY_CALL_RECORDING_TONE, false));
+            if (!mFlags.telecomResolveHiddenDependencies()) {
+                isCallRecordingToneSupported = (phoneAccount.hasCapabilities(
+                        PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION)
+                        && phoneAccount.getExtras() != null
+                        && phoneAccount.getExtras().getBoolean(
+                        PhoneAccount.EXTRA_PLAY_CALL_RECORDING_TONE, false));
+            } else {
+                isCallRecordingToneSupported = false;
+            }
             isSimCall = phoneAccount.hasCapabilities(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION);
         }
         mIsWorkCall = isWorkCall;
@@ -2225,7 +2271,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      * @return The "age" of this call object in milliseconds, which typically also represents the
      *     period since this call was added to the set pending outgoing calls.
      */
-    @VisibleForTesting
     public long getAgeMillis() {
         if (mState == CallState.DISCONNECTED &&
                 (mDisconnectCause.getCode() == DisconnectCause.REJECTED ||
@@ -2284,6 +2329,25 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         setConnectionCapabilities(connectionCapabilities, false /* forceUpdate */);
     }
 
+    public void setTransactionalCapabilities(Bundle extras) {
+        if (!mFlags.remapTransactionalCapabilities()) {
+            setConnectionCapabilities(
+                    extras.getInt(CallAttributes.CALL_CAPABILITIES_KEY,
+                            CallAttributes.SUPPORTS_SET_INACTIVE), true);
+            return;
+        }
+        int connectionCapabilitesBitmap = 0;
+        int transactionalCapabilitiesBitmap = extras.getInt(
+                CallAttributes.CALL_CAPABILITIES_KEY,
+                CallAttributes.SUPPORTS_SET_INACTIVE);
+        if ((transactionalCapabilitiesBitmap & CallAttributes.SUPPORTS_SET_INACTIVE)
+                == CallAttributes.SUPPORTS_SET_INACTIVE) {
+            connectionCapabilitesBitmap = connectionCapabilitesBitmap | Connection.CAPABILITY_HOLD
+                    | Connection.CAPABILITY_SUPPORT_HOLD;
+        }
+        setConnectionCapabilities(connectionCapabilitesBitmap, true);
+    }
+
     void setConnectionCapabilities(int connectionCapabilities, boolean forceUpdate) {
         Log.v(this, "setConnectionCapabilities: %s", Connection.capabilitiesToString(
                 connectionCapabilities));
@@ -3513,27 +3577,13 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
         mConnectionService.pullExternalCall(this);
     }
 
-    /**
-     * Sends a call event to the {@link ConnectionService} for this call. This function is
-     * called for event other than {@link Call#EVENT_REQUEST_HANDOVER}
-     *
-     * @param event The call event.
-     * @param extras Associated extras.
-     */
-    public void sendCallEvent(String event, Bundle extras) {
-        sendCallEvent(event, 0/*For Event != EVENT_REQUEST_HANDOVER*/, extras);
-    }
-
     /**
      * Sends a call event to the {@link ConnectionService} for this call.
      *
-     * See {@link Call#sendCallEvent(String, Bundle)}.
-     *
      * @param event The call event.
-     * @param targetSdkVer SDK version of the app calling this api
      * @param extras Associated extras.
      */
-    public void sendCallEvent(String event, int targetSdkVer, Bundle extras) {
+    public void sendCallEvent(String event, Bundle extras) {
         if (mConnectionService != null || mTransactionalService != null) {
             // Relay bluetooth call quality reports to the call diagnostic service.
             if (BluetoothCallQualityReport.EVENT_BLUETOOTH_CALL_QUALITY_REPORT.equals(event)
@@ -3546,19 +3596,25 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
             Log.addEvent(this, LogUtils.Events.CALL_EVENT, event);
             sendEventToService(this, event, extras);
         } else {
-            Log.e(this, new NullPointerException(),
-                    "sendCallEvent failed due to null CS callId=%s", getId());
+            if (mFlags.cacheCallEvents()) {
+                Log.i(this, "sendCallEvent: caching call event for callId=%s, event=%s",
+                        getId(), event);
+                cacheServiceCallback(new CachedCallEventQueue(event, extras));
+            } else {
+                Log.e(this, new NullPointerException(),
+                        "sendCallEvent failed due to null CS callId=%s", getId());
+            }
         }
     }
 
     /**
-     *  This method should only be called from sendCallEvent(String, int, Bundle).
+     *  This method should only be called from sendCallEvent(String, Bundle).
      */
     private void sendEventToService(Call call, String event, Bundle extras) {
         if (mConnectionService != null) {
             mConnectionService.sendCallEvent(call, event, extras);
         } else if (mTransactionalService != null) {
-            mTransactionalService.onEvent(call, event, extras);
+            mTransactionalService.sendCallEvent(call, event, extras);
         }
     }
 
@@ -3856,7 +3912,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
      * @param callerInfo The new caller information to set.
      */
     private void setCallerInfo(Uri handle, CallerInfo callerInfo) {
-        Trace.beginSection("setCallerInfo");
         if (callerInfo == null) {
             Log.i(this, "CallerInfo lookup returned null, skipping update");
             return;
@@ -3880,8 +3935,6 @@ public class Call implements CreateConnectionResponse, EventManager.Loggable,
                 l.onCallerInfoChanged(this);
             }
         }
-
-        Trace.endSection();
     }
 
     public CallerInfo getCallerInfo() {
diff --git a/src/com/android/server/telecom/CallAnomalyWatchdog.java b/src/com/android/server/telecom/CallAnomalyWatchdog.java
index 045671e25..384110c3e 100644
--- a/src/com/android/server/telecom/CallAnomalyWatchdog.java
+++ b/src/com/android/server/telecom/CallAnomalyWatchdog.java
@@ -18,15 +18,23 @@ package com.android.server.telecom;
 
 import static com.android.server.telecom.LogUtils.Events.STATE_TIMEOUT;
 
+import android.content.Context;
+import android.content.pm.ApplicationInfo;
+import android.content.pm.PackageManager;
+import android.os.Build;
+import android.os.UserHandle;
 import android.provider.DeviceConfig;
 import android.telecom.ConnectionService;
 import android.telecom.DisconnectCause;
 import android.telecom.Log;
+import android.telecom.PhoneAccountHandle;
 import android.util.LocalLog;
 
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.internal.util.IndentingPrintWriter;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.stats.CallStateChangedAtomWriter;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.Collections;
 import java.util.Map;
@@ -113,6 +121,7 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
     private final TelecomSystem.SyncRoot mLock;
     private final Timeouts.Adapter mTimeoutAdapter;
     private final ClockProxy mClockProxy;
+    private final FeatureFlags mFeatureFlags;
     private AnomalyReporterAdapter mAnomalyReporter = new AnomalyReporterAdapterImpl();
     // Pre-allocate space for 2 calls; realistically thats all we should ever need (tm)
     private final Map<Call, ScheduledFuture<?>> mScheduledFutureMap = new ConcurrentHashMap<>(2);
@@ -122,6 +131,7 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
     private final Set<Call> mCallsPendingDestruction = Collections.newSetFromMap(
             new ConcurrentHashMap<>(2));
     private final LocalLog mLocalLog = new LocalLog(20);
+    private final TelecomMetricsController mMetricsController;
 
     /**
      * Enables the action to disconnect the call when the Transitory state and Intermediate state
@@ -140,6 +150,11 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
             UUID.fromString("d57d8aab-d723-485e-a0dd-d1abb0f346c8");
     public static final String WATCHDOG_DISCONNECTED_STUCK_EMERGENCY_CALL_MSG =
             "Telecom CallAnomalyWatchdog caught and disconnected a stuck/zombie emergency call.";
+    public static final UUID WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_UUID =
+            UUID.fromString("3fbecd12-059d-4fd3-87b7-6c3079891c23");
+    public static final String WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_MSG =
+            "Telecom CallAnomalyWatchdog caught stuck VoIP call in a starting state";
+
 
     @VisibleForTesting
     public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter){
@@ -148,13 +163,17 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
 
     public CallAnomalyWatchdog(ScheduledExecutorService executorService,
             TelecomSystem.SyncRoot lock,
+            FeatureFlags featureFlags,
             Timeouts.Adapter timeoutAdapter, ClockProxy clockProxy,
-            EmergencyCallDiagnosticLogger emergencyCallDiagnosticLogger) {
+            EmergencyCallDiagnosticLogger emergencyCallDiagnosticLogger,
+            TelecomMetricsController metricsController) {
         mScheduledExecutorService = executorService;
         mLock = lock;
+        mFeatureFlags = featureFlags;
         mTimeoutAdapter = timeoutAdapter;
         mClockProxy = clockProxy;
         mEmergencyCallDiagnosticLogger = emergencyCallDiagnosticLogger;
+        mMetricsController = metricsController;
     }
 
     /**
@@ -170,6 +189,9 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
     @Override
     public void onCallAdded(Call call) {
         maybeTrackCall(call);
+        if (mFeatureFlags.telecomMetricsSupport()) {
+            mMetricsController.getCallStats().onCallStart(call);
+        }
     }
 
     /**
@@ -191,6 +213,9 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
     public void onCallRemoved(Call call) {
         Log.i(this, "onCallRemoved: call=%s", call.toString());
         stopTrackingCall(call);
+        if (mFeatureFlags.telecomMetricsSupport()) {
+            mMetricsController.getCallStats().onCallEnd(call);
+        }
     }
 
     /**
@@ -272,8 +297,13 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
      */
     private void maybeTrackCall(Call call) {
         final WatchdogCallState currentState = mWatchdogCallStateMap.get(call);
+        boolean isCreateConnectionComplete = call.isCreateConnectionComplete();
+        if (mFeatureFlags.disconnectSelfManagedStuckStartupCalls()) {
+            isCreateConnectionComplete =
+                    isCreateConnectionComplete || call.isTransactionalCall();
+        }
         final WatchdogCallState newState = new WatchdogCallState(call.getState(),
-                call.isCreateConnectionComplete(), mClockProxy.elapsedRealtime());
+                isCreateConnectionComplete, mClockProxy.elapsedRealtime());
         if (Objects.equals(currentState, newState)) {
             // No state change; skip.
             return;
@@ -348,8 +378,13 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
                 }
                 // Ensure that at timeout we are still in the original state when we posted the
                 // timeout.
+                boolean isCreateConnectionComplete = call.isCreateConnectionComplete();
+                if (mFeatureFlags.disconnectSelfManagedStuckStartupCalls()) {
+                    isCreateConnectionComplete =
+                            isCreateConnectionComplete || call.isTransactionalCall();
+                }
                 final WatchdogCallState expiredState = new WatchdogCallState(call.getState(),
-                        call.isCreateConnectionComplete(), mClockProxy.elapsedRealtime());
+                        isCreateConnectionComplete, mClockProxy.elapsedRealtime());
                 if (expiredState.equals(newState)
                         && getDurationInCurrentStateMillis(newState) > timeoutMillis) {
                     // The call has been in this transitory or intermediate state too long,
@@ -368,7 +403,7 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
                                 WATCHDOG_DISCONNECTED_STUCK_CALL_MSG);
                     }
 
-                    if (isEnabledDisconnect) {
+                    if (isEnabledDisconnect || isInSelfManagedStuckStartingState(call)) {
                         call.setOverrideDisconnectCauseCode(
                                 new DisconnectCause(DisconnectCause.ERROR, "state_timeout"));
                         call.disconnect("State timeout");
@@ -387,6 +422,50 @@ public class CallAnomalyWatchdog extends CallsManagerListenerBase implements Cal
         return cleanupRunnable;
     }
 
+    private boolean isInSelfManagedStuckStartingState(Call call) {
+        Context context = call.getContext();
+        if (!mFeatureFlags.disconnectSelfManagedStuckStartupCalls() || context == null) {
+            return false;
+        }
+        int currentStuckState = call.getState();
+        return call.isSelfManaged() &&
+                (currentStuckState == CallState.NEW ||
+                        currentStuckState == CallState.RINGING ||
+                        currentStuckState == CallState.DIALING ||
+                        currentStuckState == CallState.CONNECTING) &&
+                isVanillaIceCreamBuildOrHigher(context, call);
+    }
+
+    private boolean isVanillaIceCreamBuildOrHigher(Context context, Call call) {
+        // report the anomaly for metrics purposes
+        mAnomalyReporter.reportAnomaly(
+                WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_UUID,
+                WATCHDOG_DISCONNECTED_STUCK_VOIP_CALL_MSG);
+        // only disconnect calls running on V and when the flag is enabled!
+        PhoneAccountHandle phoneAccountHandle = call.getTargetPhoneAccount();
+        PackageManager pm = context.getPackageManager();
+        if (pm == null ||
+                phoneAccountHandle == null ||
+                phoneAccountHandle.getComponentName() == null) {
+            return false;
+        }
+        String packageName = phoneAccountHandle.getComponentName().getPackageName();
+        Log.d(this, "pah=[%s], user=[%s]", phoneAccountHandle, call.getAssociatedUser());
+        ApplicationInfo applicationInfo;
+        try {
+            applicationInfo = pm.getApplicationInfoAsUser(
+                    packageName,
+                    0,
+                    call.getAssociatedUser());
+        } catch (Exception e) {
+            Log.e(this, e, "iVICBOH: pm.getApplicationInfoAsUser(...) exception");
+            return false;
+        }
+        int targetSdk = (applicationInfo == null) ? 0 : applicationInfo.targetSdkVersion;
+        Log.i(this, "iVICBOH: packageName=[%s], sdk=[%d]", packageName, targetSdk);
+        return targetSdk >= Build.VERSION_CODES.VANILLA_ICE_CREAM;
+    }
+
     /**
      * Returns whether the action to disconnect the call when the Transitory state and
      * Intermediate state time expires is enabled or disabled.
diff --git a/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java b/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
index 813068540..8d5f9fd77 100644
--- a/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
+++ b/src/com/android/server/telecom/CallAudioCommunicationDeviceTracker.java
@@ -46,7 +46,7 @@ public class CallAudioCommunicationDeviceTracker {
     private static final int sAUDIO_DEVICE_TYPE_INVALID = -1;
     private AudioManager mAudioManager;
     private BluetoothRouteManager mBluetoothRouteManager;
-    private int mAudioDeviceType = sAUDIO_DEVICE_TYPE_INVALID;
+    private @AudioDeviceInfo.AudioDeviceType int mAudioDeviceType = sAUDIO_DEVICE_TYPE_INVALID;
     // Keep track of the locally requested BT audio device if set
     private String mBtAudioDevice = null;
     private final Lock mLock = new ReentrantLock();
@@ -59,7 +59,7 @@ public class CallAudioCommunicationDeviceTracker {
         mBluetoothRouteManager = bluetoothRouteManager;
     }
 
-    public boolean isAudioDeviceSetForType(int audioDeviceType) {
+    public boolean isAudioDeviceSetForType(@AudioDeviceInfo.AudioDeviceType int audioDeviceType) {
         if (Flags.communicationDeviceProtectedByLock()) {
             mLock.lock();
         }
@@ -86,7 +86,7 @@ public class CallAudioCommunicationDeviceTracker {
     }
 
     @VisibleForTesting
-    public void setTestCommunicationDevice(int audioDeviceType) {
+    public void setTestCommunicationDevice(@AudioDeviceInfo.AudioDeviceType int audioDeviceType) {
         mAudioDeviceType = audioDeviceType;
     }
 
@@ -119,7 +119,7 @@ public class CallAudioCommunicationDeviceTracker {
      * @return {@code true} if the device was set for communication, {@code false} if the device
      * wasn't set.
      */
-    public boolean setCommunicationDevice(int audioDeviceType,
+    public boolean setCommunicationDevice(@AudioDeviceInfo.AudioDeviceType int audioDeviceType,
             BluetoothDevice btDevice) {
         if (Flags.communicationDeviceProtectedByLock()) {
             mLock.lock();
@@ -133,8 +133,8 @@ public class CallAudioCommunicationDeviceTracker {
         }
     }
 
-    private boolean processSetCommunicationDevice(int audioDeviceType,
-            BluetoothDevice btDevice) {
+    private boolean processSetCommunicationDevice(
+        @AudioDeviceInfo.AudioDeviceType int audioDeviceType, BluetoothDevice btDevice) {
         // There is only one audio device type associated with each type of BT device.
         boolean isBtDevice = BT_AUDIO_DEVICE_INFO_TYPES.contains(audioDeviceType);
         Log.i(this, "setCommunicationDevice: type = %s, isBtDevice = %s, btDevice = %s",
@@ -208,7 +208,7 @@ public class CallAudioCommunicationDeviceTracker {
      * has previously been set for communication.
      * @param audioDeviceTypes The supported audio device types for the device.
      */
-    public void clearCommunicationDevice(int audioDeviceType) {
+    public void clearCommunicationDevice(@AudioDeviceInfo.AudioDeviceType int audioDeviceType) {
         if (Flags.communicationDeviceProtectedByLock()) {
             mLock.lock();
         }
@@ -221,7 +221,8 @@ public class CallAudioCommunicationDeviceTracker {
         }
     }
 
-    public void processClearCommunicationDevice(int audioDeviceType) {
+    public void processClearCommunicationDevice(
+        @AudioDeviceInfo.AudioDeviceType int audioDeviceType) {
         if (audioDeviceType == sAUDIO_DEVICE_TYPE_INVALID) {
             Log.i(this, "clearCommunicationDevice: Skip clearing communication device"
                     + "for invalid audio type (-1).");
@@ -260,7 +261,8 @@ public class CallAudioCommunicationDeviceTracker {
         }
     }
 
-    private boolean isUsbHeadsetType(int audioDeviceType, int sourceType) {
+    private boolean isUsbHeadsetType(@AudioDeviceInfo.AudioDeviceType int audioDeviceType,
+        @AudioDeviceInfo.AudioDeviceType int sourceType) {
         return audioDeviceType == AudioDeviceInfo.TYPE_WIRED_HEADSET
                 && sourceType == AudioDeviceInfo.TYPE_USB_HEADSET;
     }
diff --git a/src/com/android/server/telecom/CallAudioManager.java b/src/com/android/server/telecom/CallAudioManager.java
index 1f1ca9d48..8c2f63152 100644
--- a/src/com/android/server/telecom/CallAudioManager.java
+++ b/src/com/android/server/telecom/CallAudioManager.java
@@ -144,6 +144,12 @@ public class CallAudioManager extends CallsManagerListenerBase {
         updateForegroundCall();
         if (shouldPlayDisconnectTone(oldState, newState)) {
             playToneForDisconnectedCall(call);
+        } else {
+            if (newState == CallState.DISCONNECTED) {
+                // This call is not disconnected, but it won't generate a disconnect tone, so
+                // complete the future to ensure we unbind from BT promptly.
+                completeDisconnectToneFuture(call);
+            }
         }
 
         onCallLeavingState(call, oldState);
@@ -438,6 +444,10 @@ public class CallAudioManager extends CallsManagerListenerBase {
 
     @VisibleForTesting(visibility = VisibleForTesting.Visibility.PACKAGE)
     public void onRingerModeChange() {
+        if (mFeatureFlags.ensureInCarRinging()) {
+            // Stop the current ringtone before attempting to start the new ringtone:
+            stopRinging();
+        }
         mCallAudioModeStateMachine.sendMessageWithArgs(
                 CallAudioModeStateMachine.RINGER_MODE_CHANGE, makeArgsForModeStateMachine());
     }
@@ -576,8 +586,25 @@ public class CallAudioManager extends CallsManagerListenerBase {
 
     @VisibleForTesting
     public void setCallAudioRouteFocusState(int focusState) {
-        mCallAudioRouteAdapter.sendMessageWithSessionInfo(
-                CallAudioRouteStateMachine.SWITCH_FOCUS, focusState);
+        if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+            mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                    CallAudioRouteStateMachine.SWITCH_FOCUS, focusState, 0);
+        } else {
+            mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                    CallAudioRouteStateMachine.SWITCH_FOCUS, focusState);
+        }
+    }
+
+    public void setCallAudioRouteFocusStateForEndTone() {
+        if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
+            mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                    CallAudioRouteStateMachine.SWITCH_FOCUS,
+                    CallAudioRouteStateMachine.ACTIVE_FOCUS, 1);
+        } else {
+            mCallAudioRouteAdapter.sendMessageWithSessionInfo(
+                    CallAudioRouteStateMachine.SWITCH_FOCUS,
+                    CallAudioRouteStateMachine.ACTIVE_FOCUS);
+        }
     }
 
     public void notifyAudioOperationsComplete() {
@@ -1068,6 +1095,10 @@ public class CallAudioManager extends CallsManagerListenerBase {
         CompletableFuture<Void> disconnectedToneFuture = mCallsManager.getInCallController()
                 .getDisconnectedToneBtFutures().get(call.getId());
         if (disconnectedToneFuture != null) {
+            Log.i(this,
+                    "completeDisconnectToneFuture: completing deferred disconnect tone future for"
+                            + " call %s",
+                    call.getId());
             disconnectedToneFuture.complete(null);
         }
     }
diff --git a/src/com/android/server/telecom/CallAudioModeStateMachine.java b/src/com/android/server/telecom/CallAudioModeStateMachine.java
index 6420f2e52..fb196f2e6 100644
--- a/src/com/android/server/telecom/CallAudioModeStateMachine.java
+++ b/src/com/android/server/telecom/CallAudioModeStateMachine.java
@@ -21,7 +21,6 @@ import android.media.AudioFocusRequest;
 import android.media.AudioManager;
 import android.os.Looper;
 import android.os.Message;
-import android.os.Trace;
 import android.telecom.Log;
 import android.telecom.Logging.Runnable;
 import android.telecom.Logging.Session;
@@ -288,12 +287,14 @@ public class CallAudioModeStateMachine extends StateMachine {
                             .getCurrentLocallyRequestedCommunicationDevice());
                 }
                 if (mFeatureFlags.setAudioModeBeforeAbandonFocus()) {
+                    Log.i(this, "enter: AudioManager#setMode(MODE_NORMAL)");
                     mAudioManager.setMode(AudioManager.MODE_NORMAL);
                     mCallAudioManager.setCallAudioRouteFocusState(
                             CallAudioRouteStateMachine.NO_FOCUS);
                 } else {
                     mCallAudioManager.setCallAudioRouteFocusState(
                             CallAudioRouteStateMachine.NO_FOCUS);
+                    Log.i(this, "enter: AudioManager#setMode(MODE_NORMAL)");
                     mAudioManager.setMode(AudioManager.MODE_NORMAL);
                 }
                 mLocalLog.log("Mode MODE_NORMAL");
@@ -347,11 +348,14 @@ public class CallAudioModeStateMachine extends StateMachine {
                             + args.toString());
                     return HANDLED;
                 case AUDIO_OPERATIONS_COMPLETE:
-                    Log.i(LOG_TAG, "Abandoning audio focus: now UNFOCUSED");
                     if (mFeatureFlags.telecomResolveHiddenDependencies()) {
                         if (mCurrentAudioFocusRequest != null) {
+                            Log.i(this, "AudioOperationsComplete: "
+                                    + "AudioManager#abandonAudioFocusRequest(); now unfocused");
                             mAudioManager.abandonAudioFocusRequest(mCurrentAudioFocusRequest);
                             mCurrentAudioFocusRequest = null;
+                        } else {
+                            Log.i(this, "AudioOperationsComplete: already unfocused");
                         }
                     } else {
                         mAudioManager.abandonAudioFocusForCall();
@@ -377,6 +381,7 @@ public class CallAudioModeStateMachine extends StateMachine {
             mLocalLog.log("Enter AUDIO_PROCESSING");
             if (mIsInitialized) {
                 mCallAudioManager.setCallAudioRouteFocusState(CallAudioRouteStateMachine.NO_FOCUS);
+                Log.i(this, "enter: AudioManager#setMode(MODE_AUDIO_PROCESSING)");
                 mAudioManager.setMode(NEW_AUDIO_MODE_FOR_AUDIO_PROCESSING);
                 mLocalLog.log("Mode MODE_CALL_SCREENING");
                 mMostRecentMode = NEW_AUDIO_MODE_FOR_AUDIO_PROCESSING;
@@ -431,7 +436,8 @@ public class CallAudioModeStateMachine extends StateMachine {
                     transitionTo(mStreamingFocusState);
                     return HANDLED;
                 case AUDIO_OPERATIONS_COMPLETE:
-                    Log.i(LOG_TAG, "Abandoning audio focus: now AUDIO_PROCESSING");
+                    Log.i(LOG_TAG, "AudioManager#abandonAudioFocusRequest: now "
+                            + "AUDIO_PROCESSING");
                     if (mFeatureFlags.telecomResolveHiddenDependencies()) {
                         if (mCurrentAudioFocusRequest != null) {
                             mAudioManager.abandonAudioFocusRequest(mCurrentAudioFocusRequest);
@@ -454,38 +460,35 @@ public class CallAudioModeStateMachine extends StateMachine {
         private boolean mHasFocus = false;
 
         private void tryStartRinging() {
-            Trace.traceBegin(Trace.TRACE_TAG_AUDIO, "CallAudioMode.tryStartRinging");
-            try {
-                if (mHasFocus && mCallAudioManager.isRingtonePlaying()) {
-                    Log.i(LOG_TAG,
-                        "RingingFocusState#tryStartRinging -- audio focus previously"
-                            + " acquired and ringtone already playing -- skipping.");
-                    return;
-                }
+            if (mHasFocus && mCallAudioManager.isRingtonePlaying()) {
+                Log.i(LOG_TAG,
+                    "RingingFocusState#tryStartRinging -- audio focus previously"
+                        + " acquired and ringtone already playing -- skipping.");
+                return;
+            }
 
-                if (mCallAudioManager.startRinging()) {
-                    if (mFeatureFlags.telecomResolveHiddenDependencies()) {
-                        mCurrentAudioFocusRequest = RING_AUDIO_FOCUS_REQUEST;
-                        mAudioManager.requestAudioFocus(RING_AUDIO_FOCUS_REQUEST);
-                    } else {
-                        mAudioManager.requestAudioFocusForCall(
-                                AudioManager.STREAM_RING, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
-                    }
-                    // Do not set MODE_RINGTONE if we were previously in the CALL_SCREENING mode --
-                    // this trips up the audio system.
-                    if (mAudioManager.getMode() != AudioManager.MODE_CALL_SCREENING) {
-                        mAudioManager.setMode(AudioManager.MODE_RINGTONE);
-                        mLocalLog.log("Mode MODE_RINGTONE");
-                    }
-                    mCallAudioManager.setCallAudioRouteFocusState(
-                        CallAudioRouteStateMachine.RINGING_FOCUS);
-                    mHasFocus = true;
+            if (mCallAudioManager.startRinging()) {
+                if (mFeatureFlags.telecomResolveHiddenDependencies()) {
+                    mCurrentAudioFocusRequest = RING_AUDIO_FOCUS_REQUEST;
+                    Log.i(this, "tryStartRinging: AudioManager#requestAudioFocus(RING)");
+                    mAudioManager.requestAudioFocus(RING_AUDIO_FOCUS_REQUEST);
                 } else {
-                    Log.i(
-                        LOG_TAG, "RINGING state, try start ringing but not acquiring audio focus");
+                    mAudioManager.requestAudioFocusForCall(
+                            AudioManager.STREAM_RING, AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
+                }
+                // Do not set MODE_RINGTONE if we were previously in the CALL_SCREENING mode --
+                // this trips up the audio system.
+                if (mAudioManager.getMode() != AudioManager.MODE_CALL_SCREENING) {
+                    Log.i(this, "enter: AudioManager#setMode(MODE_RINGTONE)");
+                    mAudioManager.setMode(AudioManager.MODE_RINGTONE);
+                    mLocalLog.log("Mode MODE_RINGTONE");
                 }
-            } finally {
-                Trace.traceEnd(Trace.TRACE_TAG_AUDIO);
+                mCallAudioManager.setCallAudioRouteFocusState(
+                    CallAudioRouteStateMachine.RINGING_FOCUS);
+                mHasFocus = true;
+            } else {
+                Log.i(
+                    LOG_TAG, "RINGING state, try start ringing but not acquiring audio focus");
             }
         }
 
@@ -569,11 +572,13 @@ public class CallAudioModeStateMachine extends StateMachine {
             mLocalLog.log("Enter SIM_CALL");
             if (mFeatureFlags.telecomResolveHiddenDependencies()) {
                 mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
+                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
                 mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
             } else {
                 mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
                         AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             }
+            Log.i(this, "enter: AudioManager#setMode(MODE_IN_CALL)");
             mAudioManager.setMode(AudioManager.MODE_IN_CALL);
             mLocalLog.log("Mode MODE_IN_CALL");
             mMostRecentMode = AudioManager.MODE_IN_CALL;
@@ -657,11 +662,13 @@ public class CallAudioModeStateMachine extends StateMachine {
             mLocalLog.log("Enter VOIP_CALL");
             if (mFeatureFlags.telecomResolveHiddenDependencies()) {
                 mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
+                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
                 mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
             } else {
                 mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
                         AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             }
+            Log.i(this, "enter: AudioManager#setMode(MODE_IN_COMMUNICATION)");
             mAudioManager.setMode(AudioManager.MODE_IN_COMMUNICATION);
             mLocalLog.log("Mode MODE_IN_COMMUNICATION");
             mMostRecentMode = AudioManager.MODE_IN_COMMUNICATION;
@@ -740,6 +747,7 @@ public class CallAudioModeStateMachine extends StateMachine {
             Log.i(LOG_TAG, "Audio focus entering streaming state");
             mLocalLog.log("Enter Streaming");
             mLocalLog.log("Mode MODE_COMMUNICATION_REDIRECT");
+            Log.i(this, "enter: AudioManager#setMode(MODE_COMMUNICATION_REDIRECT");
             mAudioManager.setMode(AudioManager.MODE_COMMUNICATION_REDIRECT);
             mMostRecentMode = AudioManager.MODE_NORMAL;
             mCallAudioManager.setCallAudioRouteFocusState(CallAudioRouteStateMachine.ACTIVE_FOCUS);
@@ -817,14 +825,16 @@ public class CallAudioModeStateMachine extends StateMachine {
             mLocalLog.log("Enter TONE/HOLDING");
             if (mFeatureFlags.telecomResolveHiddenDependencies()) {
                 mCurrentAudioFocusRequest = CALL_AUDIO_FOCUS_REQUEST;
+                Log.i(this, "enter: AudioManager#requestAudioFocus(CALL)");
                 mAudioManager.requestAudioFocus(CALL_AUDIO_FOCUS_REQUEST);
             } else {
                 mAudioManager.requestAudioFocusForCall(AudioManager.STREAM_VOICE_CALL,
                         AudioManager.AUDIOFOCUS_GAIN_TRANSIENT);
             }
+            Log.i(this, "enter: AudioManager#setMode(%d)", mMostRecentMode);
             mAudioManager.setMode(mMostRecentMode);
             mLocalLog.log("Mode " + mMostRecentMode);
-            mCallAudioManager.setCallAudioRouteFocusState(CallAudioRouteStateMachine.ACTIVE_FOCUS);
+            mCallAudioManager.setCallAudioRouteFocusStateForEndTone();
         }
 
         @Override
diff --git a/src/com/android/server/telecom/CallAudioRouteAdapter.java b/src/com/android/server/telecom/CallAudioRouteAdapter.java
index 9927c22ab..b23851dec 100644
--- a/src/com/android/server/telecom/CallAudioRouteAdapter.java
+++ b/src/com/android/server/telecom/CallAudioRouteAdapter.java
@@ -128,6 +128,7 @@ public interface CallAudioRouteAdapter {
     void sendMessageWithSessionInfo(int message);
     void sendMessageWithSessionInfo(int message, int arg);
     void sendMessageWithSessionInfo(int message, int arg, String data);
+    void sendMessageWithSessionInfo(int message, int arg, int data);
     void sendMessageWithSessionInfo(int message, int arg, BluetoothDevice bluetoothDevice);
     void sendMessage(int message, Runnable r);
     void setCallAudioManager(CallAudioManager callAudioManager);
diff --git a/src/com/android/server/telecom/CallAudioRouteController.java b/src/com/android/server/telecom/CallAudioRouteController.java
index 76555c34d..e27535a8a 100644
--- a/src/com/android/server/telecom/CallAudioRouteController.java
+++ b/src/com/android/server/telecom/CallAudioRouteController.java
@@ -52,7 +52,9 @@ import com.android.internal.os.SomeArgs;
 import com.android.internal.util.IndentingPrintWriter;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 
+import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.HashSet;
 import java.util.LinkedHashMap;
@@ -62,15 +64,16 @@ import java.util.Objects;
 import java.util.Set;
 
 public class CallAudioRouteController implements CallAudioRouteAdapter {
-    private static final long TIMEOUT_LIMIT = 2000L;
     private static final AudioRoute DUMMY_ROUTE = new AudioRoute(TYPE_INVALID, null, null);
     private static final Map<Integer, Integer> ROUTE_MAP;
     static {
         ROUTE_MAP = new ArrayMap<>();
+        ROUTE_MAP.put(TYPE_INVALID, 0);
         ROUTE_MAP.put(AudioRoute.TYPE_EARPIECE, CallAudioState.ROUTE_EARPIECE);
         ROUTE_MAP.put(AudioRoute.TYPE_WIRED, CallAudioState.ROUTE_WIRED_HEADSET);
         ROUTE_MAP.put(AudioRoute.TYPE_SPEAKER, CallAudioState.ROUTE_SPEAKER);
         ROUTE_MAP.put(AudioRoute.TYPE_DOCK, CallAudioState.ROUTE_SPEAKER);
+        ROUTE_MAP.put(AudioRoute.TYPE_BUS, CallAudioState.ROUTE_SPEAKER);
         ROUTE_MAP.put(AudioRoute.TYPE_BLUETOOTH_SCO, CallAudioState.ROUTE_BLUETOOTH);
         ROUTE_MAP.put(AudioRoute.TYPE_BLUETOOTH_HA, CallAudioState.ROUTE_BLUETOOTH);
         ROUTE_MAP.put(AudioRoute.TYPE_BLUETOOTH_LE, CallAudioState.ROUTE_BLUETOOTH);
@@ -89,6 +92,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private final Handler mHandler;
     private final WiredHeadsetManager mWiredHeadsetManager;
     private Set<AudioRoute> mAvailableRoutes;
+    private Set<AudioRoute> mCallSupportedRoutes;
     private AudioRoute mCurrentRoute;
     private AudioRoute mEarpieceWiredRoute;
     private AudioRoute mSpeakerDockRoute;
@@ -97,13 +101,16 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private Map<AudioRoute, BluetoothDevice> mBluetoothRoutes;
     private Pair<Integer, String> mActiveBluetoothDevice;
     private Map<Integer, String> mActiveDeviceCache;
+    private String mBluetoothAddressForRinging;
     private Map<Integer, AudioRoute> mTypeRoutes;
     private PendingAudioRoute mPendingAudioRoute;
     private AudioRoute.Factory mAudioRouteFactory;
     private StatusBarNotifier mStatusBarNotifier;
     private FeatureFlags mFeatureFlags;
     private int mFocusType;
+    private int mCallSupportedRouteMask = -1;
     private boolean mIsScoAudioConnected;
+    private boolean mAvailableRoutesUpdated;
     private final Object mLock = new Object();
     private final TelecomSystem.SyncRoot mTelecomLock;
     private final BroadcastReceiver mSpeakerPhoneChangeReceiver = new BroadcastReceiver() {
@@ -166,13 +173,14 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     private boolean mIsMute;
     private boolean mIsPending;
     private boolean mIsActive;
+    private final TelecomMetricsController mMetricsController;
 
     public CallAudioRouteController(
             Context context, CallsManager callsManager,
             CallAudioManager.AudioServiceFactory audioServiceFactory,
             AudioRoute.Factory audioRouteFactory, WiredHeadsetManager wiredHeadsetManager,
             BluetoothRouteManager bluetoothRouteManager, StatusBarNotifier statusBarNotifier,
-            FeatureFlags featureFlags) {
+            FeatureFlags featureFlags, TelecomMetricsController metricsController) {
         mContext = context;
         mCallsManager = callsManager;
         mAudioManager = context.getSystemService(AudioManager.class);
@@ -183,6 +191,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mBluetoothRouteManager = bluetoothRouteManager;
         mStatusBarNotifier = statusBarNotifier;
         mFeatureFlags = featureFlags;
+        mMetricsController = metricsController;
         mFocusType = NO_FOCUS;
         mIsScoAudioConnected = false;
         mTelecomLock = callsManager.getLock();
@@ -213,6 +222,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     String address;
                     BluetoothDevice bluetoothDevice;
                     int focus;
+                    int handleEndTone;
                     @AudioRoute.AudioRouteType int type;
                     switch (msg.what) {
                         case CONNECT_WIRED_HEADSET:
@@ -305,11 +315,21 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                             break;
                         case SWITCH_FOCUS:
                             focus = msg.arg1;
-                            handleSwitchFocus(focus);
+                            handleEndTone = (int) ((SomeArgs) msg.obj).arg2;
+                            handleSwitchFocus(focus, handleEndTone);
                             break;
                         case EXIT_PENDING_ROUTE:
                             handleExitPendingRoute();
                             break;
+                        case UPDATE_SYSTEM_AUDIO_ROUTE:
+                            // Based on the available routes for foreground call, adjust routing.
+                            updateRouteForForeground();
+                            // Force update to notify all ICS/CS.
+                            updateCallAudioState(new CallAudioState(mIsMute,
+                                    mCallAudioState.getRoute(),
+                                    mCallAudioState.getSupportedRouteMask(),
+                                    mCallAudioState.getActiveBluetoothDevice(),
+                                    mCallAudioState.getSupportedBluetoothDevices()));
                         default:
                             break;
                     }
@@ -321,6 +341,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     @Override
     public void initialize() {
         mAvailableRoutes = new HashSet<>();
+        mCallSupportedRoutes = new HashSet<>();
         mBluetoothRoutes = new LinkedHashMap<>();
         mActiveDeviceCache = new HashMap<>();
         mActiveDeviceCache.put(AudioRoute.TYPE_BLUETOOTH_SCO, null);
@@ -329,20 +350,30 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mActiveBluetoothDevice = null;
         mTypeRoutes = new ArrayMap<>();
         mStreamingRoutes = new HashSet<>();
-        mPendingAudioRoute = new PendingAudioRoute(this, mAudioManager, mBluetoothRouteManager);
+        mPendingAudioRoute = new PendingAudioRoute(this, mAudioManager, mBluetoothRouteManager,
+                mFeatureFlags);
         mStreamingRoute = new AudioRoute(AudioRoute.TYPE_STREAMING, null, null);
         mStreamingRoutes.add(mStreamingRoute);
 
         int supportMask = calculateSupportedRouteMaskInit();
         if ((supportMask & CallAudioState.ROUTE_SPEAKER) != 0) {
+            int audioRouteType = AudioRoute.TYPE_SPEAKER;
             // Create speaker routes
             mSpeakerDockRoute = mAudioRouteFactory.create(AudioRoute.TYPE_SPEAKER, null,
                     mAudioManager);
-            if (mSpeakerDockRoute == null) {
-                Log.w(this, "Can't find available audio device info for route TYPE_SPEAKER");
+            if (mSpeakerDockRoute == null){
+                Log.i(this, "Can't find available audio device info for route TYPE_SPEAKER, trying"
+                        + " for TYPE_BUS");
+                mSpeakerDockRoute = mAudioRouteFactory.create(AudioRoute.TYPE_BUS, null,
+                        mAudioManager);
+                audioRouteType = AudioRoute.TYPE_BUS;
+            }
+            if (mSpeakerDockRoute != null) {
+                mTypeRoutes.put(audioRouteType, mSpeakerDockRoute);
+                updateAvailableRoutes(mSpeakerDockRoute, true);
             } else {
-                mTypeRoutes.put(AudioRoute.TYPE_SPEAKER, mSpeakerDockRoute);
-                mAvailableRoutes.add(mSpeakerDockRoute);
+                Log.w(this, "Can't find available audio device info for route TYPE_SPEAKER "
+                        + "or TYPE_BUS.");
             }
         }
 
@@ -354,7 +385,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 Log.w(this, "Can't find available audio device info for route TYPE_WIRED_HEADSET");
             } else {
                 mTypeRoutes.put(AudioRoute.TYPE_WIRED, mEarpieceWiredRoute);
-                mAvailableRoutes.add(mEarpieceWiredRoute);
+                updateAvailableRoutes(mEarpieceWiredRoute, true);
             }
         } else if ((supportMask & CallAudioState.ROUTE_EARPIECE) != 0) {
             // Create earpiece routes
@@ -364,15 +395,17 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 Log.w(this, "Can't find available audio device info for route TYPE_EARPIECE");
             } else {
                 mTypeRoutes.put(AudioRoute.TYPE_EARPIECE, mEarpieceWiredRoute);
-                mAvailableRoutes.add(mEarpieceWiredRoute);
+                updateAvailableRoutes(mEarpieceWiredRoute, true);
             }
         }
 
         // set current route
         if (mEarpieceWiredRoute != null) {
             mCurrentRoute = mEarpieceWiredRoute;
-        } else {
+        } else if (mSpeakerDockRoute != null) {
             mCurrentRoute = mSpeakerDockRoute;
+        } else {
+            mCurrentRoute = DUMMY_ROUTE;
         }
         mIsActive = false;
         mCallAudioState = new CallAudioState(mIsMute, ROUTE_MAP.get(mCurrentRoute.getType()),
@@ -397,6 +430,14 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         sendMessage(message, arg, 0, args);
     }
 
+    @Override
+    public void sendMessageWithSessionInfo(int message, int arg, int data) {
+        SomeArgs args = SomeArgs.obtain();
+        args.arg1 = Log.createSubsession();
+        args.arg2 = data;
+        sendMessage(message, arg, 0, args);
+    }
+
     @Override
     public void sendMessageWithSessionInfo(int message, int arg, BluetoothDevice bluetoothDevice) {
         SomeArgs args = SomeArgs.obtain();
@@ -468,7 +509,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     }
 
     private void routeTo(boolean active, AudioRoute destRoute) {
-        if (!destRoute.equals(mStreamingRoute) && !getAvailableRoutes().contains(destRoute)) {
+        if (destRoute == null || (!destRoute.equals(mStreamingRoute)
+                && !getCallSupportedRoutes().contains(destRoute))) {
             Log.i(this, "Ignore routing to unavailable route: %s", destRoute);
             return;
         }
@@ -493,7 +535,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             Log.i(this, "Enter pending route, orig%s(active=%b), dest%s(active=%b)", mCurrentRoute,
                     mIsActive, destRoute, active);
             // route to pending route
-            if (getAvailableRoutes().contains(mCurrentRoute)) {
+            if (getCallSupportedRoutes().contains(mCurrentRoute)) {
                 mPendingAudioRoute.setOrigRoute(mIsActive, mCurrentRoute);
             } else {
                 // Avoid waiting for pending messages for an unavailable route
@@ -505,14 +547,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 mIsScoAudioConnected);
         mIsActive = active;
         mPendingAudioRoute.evaluatePendingState();
-        postTimeoutMessage();
-    }
-
-    private void postTimeoutMessage() {
-        // reset timeout handler
-        mHandler.removeMessages(PENDING_ROUTE_TIMEOUT);
-        mHandler.postDelayed(() -> mHandler.sendMessage(
-                Message.obtain(mHandler, PENDING_ROUTE_TIMEOUT)), TIMEOUT_LIMIT);
+        if (mFeatureFlags.telecomMetricsSupport()) {
+            mMetricsController.getAudioRouteStats().onRouteEnter(mPendingAudioRoute);
+        }
     }
 
     private void handleWiredHeadsetConnected() {
@@ -526,8 +563,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
 
         if (wiredHeadsetRoute != null) {
-            mAvailableRoutes.add(wiredHeadsetRoute);
-            mAvailableRoutes.remove(mEarpieceWiredRoute);
+            updateAvailableRoutes(wiredHeadsetRoute, true);
+            updateAvailableRoutes(mEarpieceWiredRoute, false);
             mTypeRoutes.put(AudioRoute.TYPE_WIRED, wiredHeadsetRoute);
             mEarpieceWiredRoute = wiredHeadsetRoute;
             routeTo(mIsActive, wiredHeadsetRoute);
@@ -539,12 +576,12 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         // Update audio route states
         AudioRoute wiredHeadsetRoute = mTypeRoutes.remove(AudioRoute.TYPE_WIRED);
         if (wiredHeadsetRoute != null) {
-            mAvailableRoutes.remove(wiredHeadsetRoute);
+            updateAvailableRoutes(wiredHeadsetRoute, false);
             mEarpieceWiredRoute = null;
         }
         AudioRoute earpieceRoute = mTypeRoutes.get(AudioRoute.TYPE_EARPIECE);
         if (earpieceRoute != null) {
-            mAvailableRoutes.add(earpieceRoute);
+            updateAvailableRoutes(earpieceRoute, true);
             mEarpieceWiredRoute = earpieceRoute;
         }
         onAvailableRoutesChanged();
@@ -565,8 +602,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
 
         if (dockRoute != null) {
-            mAvailableRoutes.add(dockRoute);
-            mAvailableRoutes.remove(mSpeakerDockRoute);
+            updateAvailableRoutes(dockRoute, true);
+            updateAvailableRoutes(mSpeakerDockRoute, false);
             mTypeRoutes.put(AudioRoute.TYPE_DOCK, dockRoute);
             mSpeakerDockRoute = dockRoute;
             routeTo(mIsActive, dockRoute);
@@ -578,12 +615,12 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         // Update audio route states
         AudioRoute dockRoute = mTypeRoutes.get(AudioRoute.TYPE_DOCK);
         if (dockRoute != null) {
-            mAvailableRoutes.remove(dockRoute);
+            updateAvailableRoutes(dockRoute, false);
             mSpeakerDockRoute = null;
         }
         AudioRoute speakerRoute = mTypeRoutes.get(AudioRoute.TYPE_SPEAKER);
         if (speakerRoute != null) {
-            mAvailableRoutes.add(speakerRoute);
+            updateAvailableRoutes(speakerRoute, true);
             mSpeakerDockRoute = speakerRoute;
         }
         onAvailableRoutesChanged();
@@ -629,9 +666,6 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 mPendingAudioRoute.onMessageReceived(new Pair<>(BT_AUDIO_CONNECTED,
                         bluetoothDevice.getAddress()), null);
             }
-        } else {
-            // ignore, not triggered by telecom
-            Log.i(this, "handleBtAudioActive: ignoring handling bt audio active.");
         }
     }
 
@@ -651,9 +685,6 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 mPendingAudioRoute.onMessageReceived(new Pair<>(BT_AUDIO_DISCONNECTED,
                         bluetoothDevice.getAddress()), null);
             }
-        } else {
-            // ignore, not triggered by telecom
-            Log.i(this, "handleBtAudioInactive: ignoring handling bt audio inactive.");
         }
     }
 
@@ -665,7 +696,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      * Message being handled: BT_DEVICE_ADDED
      */
     private void handleBtConnected(@AudioRoute.AudioRouteType int type,
-                                   BluetoothDevice bluetoothDevice) {
+            BluetoothDevice bluetoothDevice) {
         if (containsHearingAidPair(type, bluetoothDevice)) {
             return;
         }
@@ -677,7 +708,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     + AudioRoute.DEVICE_TYPE_STRINGS.get(type));
         } else {
             Log.i(this, "bluetooth route added: " + bluetoothRoute);
-            mAvailableRoutes.add(bluetoothRoute);
+            updateAvailableRoutes(bluetoothRoute, true);
             mBluetoothRoutes.put(bluetoothRoute, bluetoothDevice);
             onAvailableRoutesChanged();
         }
@@ -692,13 +723,13 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      * Message being handled: BT_DEVICE_REMOVED
      */
     private void handleBtDisconnected(@AudioRoute.AudioRouteType int type,
-                                      BluetoothDevice bluetoothDevice) {
+            BluetoothDevice bluetoothDevice) {
         // Clean up unavailable routes
         AudioRoute bluetoothRoute = getBluetoothRoute(type, bluetoothDevice.getAddress());
         if (bluetoothRoute != null) {
             Log.i(this, "bluetooth route removed: " + bluetoothRoute);
             mBluetoothRoutes.remove(bluetoothRoute);
-            mAvailableRoutes.remove(bluetoothRoute);
+            updateAvailableRoutes(bluetoothRoute, false);
             onAvailableRoutesChanged();
         }
 
@@ -716,7 +747,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
      * Message being handled: BT_ACTIVE_DEVICE_PRESENT
      */
     private void handleBtActiveDevicePresent(@AudioRoute.AudioRouteType int type,
-                                             String deviceAddress) {
+            String deviceAddress) {
         AudioRoute bluetoothRoute = getBluetoothRoute(type, deviceAddress);
         if (bluetoothRoute != null) {
             Log.i(this, "request to route to bluetooth route: %s (active=%b)", bluetoothRoute,
@@ -766,24 +797,44 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         onMuteStateChanged(mIsMute);
     }
 
-    private void handleSwitchFocus(int focus) {
+    private void handleSwitchFocus(int focus, int handleEndTone) {
         Log.i(this, "handleSwitchFocus: focus (%s)", focus);
         mFocusType = focus;
         switch (focus) {
             case NO_FOCUS -> {
                 if (mIsActive) {
+                    // Notify the CallAudioModeStateMachine that audio operations are complete so
+                    // that we can relinquish audio focus.
+                    mCallAudioManager.notifyAudioOperationsComplete();
+
                     // Reset mute state after call ends.
                     handleMuteChanged(false);
                     // Route back to inactive route.
                     routeTo(false, mCurrentRoute);
                     // Clear pending messages
                     mPendingAudioRoute.clearPendingMessages();
+                    clearRingingBluetoothAddress();
                 }
             }
             case ACTIVE_FOCUS -> {
                 // Route to active baseline route (we may need to change audio route in the case
-                // when a video call is put on hold).
-                routeTo(true, getBaseRoute(true, null));
+                // when a video call is put on hold). Ignore route changes if we're handling playing
+                // the end tone. Otherwise, it's possible that we'll override the route a client has
+                // previously requested.
+                if (handleEndTone == 0) {
+                    // Cache BT device switch in the case that inband ringing is disabled and audio
+                    // was routed to a watch. When active focus is received, this selection will be
+                    // honored provided that the current route is associated.
+                    Log.i(this, "handleSwitchFocus (ACTIVE_FOCUS): mBluetoothAddressForRinging = "
+                            + "%s, mCurrentRoute = %s", mBluetoothAddressForRinging, mCurrentRoute);
+                    AudioRoute audioRoute = mBluetoothAddressForRinging != null
+                            && mBluetoothAddressForRinging.equals(
+                                    mCurrentRoute.getBluetoothAddress())
+                            ? mCurrentRoute
+                            : getBaseRoute(true, null);
+                    routeTo(true, audioRoute);
+                    clearRingingBluetoothAddress();
+                }
             }
             case RINGING_FOCUS -> {
                 if (!mIsActive) {
@@ -809,7 +860,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
 
     public void handleSwitchEarpiece() {
         AudioRoute earpieceRoute = mTypeRoutes.get(AudioRoute.TYPE_EARPIECE);
-        if (earpieceRoute != null && getAvailableRoutes().contains(earpieceRoute)) {
+        if (earpieceRoute != null && getCallSupportedRoutes().contains(earpieceRoute)) {
             routeTo(mIsActive, earpieceRoute);
         } else {
             Log.i(this, "ignore switch earpiece request");
@@ -824,7 +875,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             bluetoothRoute = getArbitraryBluetoothDevice();
             bluetoothDevice = mBluetoothRoutes.get(bluetoothRoute);
         } else {
-            for (AudioRoute route : getAvailableRoutes()) {
+            for (AudioRoute route : getCallSupportedRoutes()) {
                 if (Objects.equals(address, route.getBluetoothAddress())) {
                     bluetoothRoute = route;
                     bluetoothDevice = mBluetoothRoutes.get(route);
@@ -837,6 +888,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             if (mFocusType == RINGING_FOCUS) {
                 routeTo(mBluetoothRouteManager.isInbandRingEnabled(bluetoothDevice) && mIsActive,
                         bluetoothRoute);
+                mBluetoothAddressForRinging = bluetoothDevice.getAddress();
             } else {
                 routeTo(mIsActive, bluetoothRoute);
             }
@@ -861,7 +913,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
 
     private void handleSwitchHeadset() {
         AudioRoute headsetRoute = mTypeRoutes.get(AudioRoute.TYPE_WIRED);
-        if (headsetRoute != null && getAvailableRoutes().contains(headsetRoute)) {
+        if (headsetRoute != null && getCallSupportedRoutes().contains(headsetRoute)) {
             routeTo(mIsActive, headsetRoute);
         } else {
             Log.i(this, "ignore switch headset request");
@@ -869,7 +921,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     }
 
     private void handleSwitchSpeaker() {
-        if (mSpeakerDockRoute != null && getAvailableRoutes().contains(mSpeakerDockRoute)) {
+        if (mSpeakerDockRoute != null && getCallSupportedRoutes().contains(mSpeakerDockRoute)
+                && mSpeakerDockRoute.getType() == AudioRoute.TYPE_SPEAKER) {
             routeTo(mIsActive, mSpeakerDockRoute);
         } else {
             Log.i(this, "ignore switch speaker request");
@@ -877,7 +930,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     }
 
     private void handleSwitchBaselineRoute(boolean includeBluetooth, String btAddressToExclude) {
-        routeTo(mIsActive, getBaseRoute(includeBluetooth, btAddressToExclude));
+        routeTo(mIsActive, calculateBaselineRoute(includeBluetooth, btAddressToExclude));
     }
 
     private void handleSpeakerOn() {
@@ -887,7 +940,8 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             // Update status bar notification if we are in a call.
             mStatusBarNotifier.notifySpeakerphone(mCallsManager.hasAnyCalls());
         } else {
-            if (mSpeakerDockRoute != null && getAvailableRoutes().contains(mSpeakerDockRoute)) {
+            if (mSpeakerDockRoute != null && getCallSupportedRoutes().contains(mSpeakerDockRoute)
+                    && mSpeakerDockRoute.getType() == AudioRoute.TYPE_SPEAKER) {
                 routeTo(mIsActive, mSpeakerDockRoute);
                 // Since the route switching triggered by this message, we need to manually send it
                 // again so that we won't stuck in the pending route
@@ -927,6 +981,9 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             mIsPending = false;
             mPendingAudioRoute.clearPendingMessages();
             onCurrentRouteChanged();
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mMetricsController.getAudioRouteStats().onRouteExit(mPendingAudioRoute, true);
+            }
         }
     }
 
@@ -951,7 +1008,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         synchronized (mLock) {
             int routeMask = 0;
             Set<BluetoothDevice> availableBluetoothDevices = new HashSet<>();
-            for (AudioRoute route : getAvailableRoutes()) {
+            for (AudioRoute route : getCallSupportedRoutes()) {
                 routeMask |= ROUTE_MAP.get(route.getType());
                 if (BT_AUDIO_ROUTE_TYPES.contains(route.getType())) {
                     BluetoothDevice deviceToAdd = mBluetoothRoutes.get(route);
@@ -971,6 +1028,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                     }
                 }
             }
+
             updateCallAudioState(new CallAudioState(mIsMute, mCallAudioState.getRoute(), routeMask,
                     mCallAudioState.getActiveBluetoothDevice(), availableBluetoothDevices));
         }
@@ -982,18 +1040,62 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
                 mCallAudioState.getSupportedBluetoothDevices()));
     }
 
+    /**
+     * Retrieves the current call's supported audio route and adjusts the audio routing if the
+     * current route isn't supported.
+     */
+    private void updateRouteForForeground() {
+        boolean updatedRouteForCall = updateCallSupportedAudioRoutes();
+        // Ensure that current call audio state has updated routes for current call.
+        if (updatedRouteForCall) {
+            mCallAudioState = new CallAudioState(mIsMute, mCallAudioState.getRoute(),
+                    mCallSupportedRouteMask, mCallAudioState.getActiveBluetoothDevice(),
+                    mCallAudioState.getSupportedBluetoothDevices());
+            // Update audio route if foreground call doesn't support the current route.
+            if ((mCallSupportedRouteMask & mCallAudioState.getRoute()) == 0) {
+                routeTo(mIsActive, getBaseRoute(true, null));
+            }
+        }
+    }
+
+    /**
+     * Update supported audio routes for the foreground call if present.
+     */
+    private boolean updateCallSupportedAudioRoutes() {
+        int availableRouteMask = 0;
+        Call foregroundCall = mCallsManager.getForegroundCall();
+        mCallSupportedRoutes.clear();
+        if (foregroundCall != null) {
+            int foregroundCallSupportedRouteMask = foregroundCall.getSupportedAudioRoutes();
+            for (AudioRoute route : getAvailableRoutes()) {
+                int routeType = ROUTE_MAP.get(route.getType());
+                availableRouteMask |= routeType;
+                if ((routeType & foregroundCallSupportedRouteMask) == routeType) {
+                    mCallSupportedRoutes.add(route);
+                }
+            }
+            mCallSupportedRouteMask = availableRouteMask & foregroundCallSupportedRouteMask;
+            return true;
+        } else {
+            mCallSupportedRouteMask = -1;
+            return false;
+        }
+    }
+
     private void updateCallAudioState(CallAudioState newCallAudioState) {
-        Log.i(this, "updateCallAudioState: updating call audio state to %s", newCallAudioState);
-        CallAudioState oldState = mCallAudioState;
-        mCallAudioState = newCallAudioState;
-        // Update status bar notification
-        mStatusBarNotifier.notifyMute(newCallAudioState.isMuted());
-        mCallsManager.onCallAudioStateChanged(oldState, mCallAudioState);
-        updateAudioStateForTrackedCalls(mCallAudioState);
+        synchronized (mTelecomLock) {
+            Log.i(this, "updateCallAudioState: updating call audio state to %s", newCallAudioState);
+            CallAudioState oldState = mCallAudioState;
+            mCallAudioState = newCallAudioState;
+            // Update status bar notification
+            mStatusBarNotifier.notifyMute(newCallAudioState.isMuted());
+            mCallsManager.onCallAudioStateChanged(oldState, mCallAudioState);
+            updateAudioStateForTrackedCalls(mCallAudioState);
+        }
     }
 
     private void updateAudioStateForTrackedCalls(CallAudioState newCallAudioState) {
-        Set<Call> calls = mCallsManager.getTrackedCalls();
+        List<Call> calls = new ArrayList<>(mCallsManager.getTrackedCalls());
         for (Call call : calls) {
             if (call != null && call.getConnectionService() != null) {
                 call.getConnectionService().onCallAudioStateChanged(call, newCallAudioState);
@@ -1002,6 +1104,24 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
     }
 
     private AudioRoute getPreferredAudioRouteFromStrategy() {
+        // Get preferred device
+        AudioDeviceAttributes deviceAttr = getPreferredDeviceForStrategy();
+        Log.i(this, "getPreferredAudioRouteFromStrategy: preferred device is %s", deviceAttr);
+        if (deviceAttr == null) {
+            return null;
+        }
+
+        // Get corresponding audio route
+        @AudioRoute.AudioRouteType int type = AudioRoute.DEVICE_INFO_TYPE_TO_AUDIO_ROUTE_TYPE.get(
+                deviceAttr.getType());
+        if (BT_AUDIO_ROUTE_TYPES.contains(type)) {
+            return getBluetoothRoute(type, deviceAttr.getAddress());
+        } else {
+            return mTypeRoutes.get(type);
+        }
+    }
+
+    private AudioDeviceAttributes getPreferredDeviceForStrategy() {
         // Get audio produce strategy
         AudioProductStrategy strategy = null;
         final AudioAttributes attr = new AudioAttributes.Builder()
@@ -1017,22 +1137,7 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
             return null;
         }
 
-        // Get preferred device
-        AudioDeviceAttributes deviceAttr = mAudioManager.getPreferredDeviceForStrategy(strategy);
-        Log.i(this, "getPreferredAudioRouteFromStrategy: preferred device is %s", deviceAttr);
-        if (deviceAttr == null) {
-            return null;
-        }
-
-        // Get corresponding audio route
-        @AudioRoute.AudioRouteType int type = AudioRoute.DEVICE_INFO_TYPETO_AUDIO_ROUTE_TYPE.get(
-                deviceAttr.getType());
-        if (BT_AUDIO_ROUTE_TYPES.contains(type)) {
-            return getBluetoothRoute(type, deviceAttr.getAddress());
-        } else {
-            return mTypeRoutes.get(deviceAttr.getType());
-
-        }
+        return mAudioManager.getPreferredDeviceForStrategy(strategy);
     }
 
     private AudioRoute getPreferredAudioRouteFromDefault(boolean includeBluetooth,
@@ -1047,16 +1152,23 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         // are only wearables available.
         AudioRoute activeWatchOrNonWatchDeviceRoute =
                 getActiveWatchOrNonWatchDeviceRoute(btAddressToExclude);
-        if (mBluetoothRoutes.isEmpty() || !includeBluetooth
-                || activeWatchOrNonWatchDeviceRoute == null) {
+        if ((!mCallSupportedRoutes.isEmpty() && (mCallSupportedRouteMask
+                & CallAudioState.ROUTE_BLUETOOTH) == 0) || mBluetoothRoutes.isEmpty()
+                || !includeBluetooth || activeWatchOrNonWatchDeviceRoute == null) {
             Log.i(this, "getPreferredAudioRouteFromDefault: Audio routing defaulting to "
                     + "available non-BT route.");
-            AudioRoute defaultRoute = mEarpieceWiredRoute != null
+            boolean callSupportsEarpieceWiredRoute = mCallSupportedRoutes.isEmpty()
+                    || mCallSupportedRoutes.contains(mEarpieceWiredRoute);
+            // If call supported route doesn't contain earpiece/wired/BT, it should have speaker
+            // enabled. Otherwise, no routes would be supported for the call which should never be
+            // the case.
+            AudioRoute defaultRoute = mEarpieceWiredRoute != null && callSupportsEarpieceWiredRoute
                     ? mEarpieceWiredRoute
                     : mSpeakerDockRoute;
             // Ensure that we default to speaker route if we're in a video call, but disregard it if
             // a wired headset is plugged in.
-            if (skipEarpiece && defaultRoute.getType() == AudioRoute.TYPE_EARPIECE) {
+            if (skipEarpiece && defaultRoute != null
+                    && defaultRoute.getType() == AudioRoute.TYPE_EARPIECE) {
                 Log.i(this, "getPreferredAudioRouteFromDefault: Audio routing defaulting to "
                         + "speaker route for video call.");
                 defaultRoute = mSpeakerDockRoute;
@@ -1103,6 +1215,18 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
     }
 
+    public Set<AudioRoute> getCallSupportedRoutes() {
+        if (mCurrentRoute.equals(mStreamingRoute)) {
+            return mStreamingRoutes;
+        } else {
+            if (mAvailableRoutesUpdated) {
+                updateCallSupportedAudioRoutes();
+                mAvailableRoutesUpdated = false;
+            }
+            return mCallSupportedRoutes.isEmpty() ? mAvailableRoutes : mCallSupportedRoutes;
+        }
+    }
+
     public AudioRoute getCurrentRoute() {
         return mCurrentRoute;
     }
@@ -1119,10 +1243,22 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
 
     public AudioRoute getBaseRoute(boolean includeBluetooth, String btAddressToExclude) {
         AudioRoute destRoute = getPreferredAudioRouteFromStrategy();
-        if (destRoute == null || (destRoute.getBluetoothAddress() != null && !includeBluetooth)) {
+        Log.i(this, "getBaseRoute: preferred audio route is %s", destRoute);
+        if (destRoute == null || (destRoute.getBluetoothAddress() != null && (!includeBluetooth
+                || destRoute.getBluetoothAddress().equals(btAddressToExclude)))) {
             destRoute = getPreferredAudioRouteFromDefault(includeBluetooth, btAddressToExclude);
         }
-        if (destRoute != null && !getAvailableRoutes().contains(destRoute)) {
+        if (destRoute != null && !getCallSupportedRoutes().contains(destRoute)) {
+            destRoute = null;
+        }
+        Log.i(this, "getBaseRoute - audio routing to %s", destRoute);
+        return destRoute;
+    }
+
+    private AudioRoute calculateBaselineRoute(boolean includeBluetooth, String btAddressToExclude) {
+        AudioRoute destRoute = getPreferredAudioRouteFromDefault(
+                includeBluetooth, btAddressToExclude);
+        if (destRoute != null && !getCallSupportedRoutes().contains(destRoute)) {
             destRoute = null;
         }
         Log.i(this, "getBaseRoute - audio routing to %s", destRoute);
@@ -1277,6 +1413,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         mIsScoAudioConnected = value;
     }
 
+    private void clearRingingBluetoothAddress() {
+        mBluetoothAddressForRinging = null;
+    }
+
     /**
      * Update the active bluetooth device being tracked (as well as for individual profiles).
      * We need to keep track of active devices for individual profiles because of potential
@@ -1310,6 +1450,15 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
     }
 
+    private void updateAvailableRoutes(AudioRoute route, boolean includeRoute) {
+        if (includeRoute) {
+            mAvailableRoutes.add(route);
+        } else {
+            mAvailableRoutes.remove(route);
+        }
+        mAvailableRoutesUpdated = true;
+    }
+
     @VisibleForTesting
     public void setActive(boolean active) {
         if (active) {
@@ -1319,4 +1468,10 @@ public class CallAudioRouteController implements CallAudioRouteAdapter {
         }
         mIsActive = active;
     }
+
+    void fallBack(String btAddressToExclude) {
+        mMetricsController.getAudioRouteStats().onRouteExit(mPendingAudioRoute, false);
+        sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE,
+                btAddressToExclude);
+    }
 }
diff --git a/src/com/android/server/telecom/CallAudioRouteStateMachine.java b/src/com/android/server/telecom/CallAudioRouteStateMachine.java
index 74d23a9d5..4283b7b7b 100644
--- a/src/com/android/server/telecom/CallAudioRouteStateMachine.java
+++ b/src/com/android/server/telecom/CallAudioRouteStateMachine.java
@@ -1685,6 +1685,10 @@ public class CallAudioRouteStateMachine extends StateMachine implements CallAudi
         sendMessage(message, arg, 0, args);
     }
 
+    public void sendMessageWithSessionInfo(int message, int arg, int data) {
+        // ignore, only used in CallAudioRouteController
+    }
+
     public void sendMessageWithSessionInfo(int message, int arg, BluetoothDevice bluetoothDevice) {
         // ignore, only used in CallAudioRouteController
     }
@@ -2106,8 +2110,9 @@ public class CallAudioRouteStateMachine extends StateMachine implements CallAudi
     private int getCurrentCallSupportedRoutes() {
         int supportedRoutes = CallAudioState.ROUTE_ALL;
 
-        if (mCallsManager.getForegroundCall() != null) {
-            supportedRoutes &= mCallsManager.getForegroundCall().getSupportedAudioRoutes();
+        Call foregroundCall = mCallsManager.getForegroundCall();
+        if (foregroundCall != null) {
+            supportedRoutes &= foregroundCall.getSupportedAudioRoutes();
         }
 
         return supportedRoutes;
diff --git a/src/com/android/server/telecom/CallEndpointController.java b/src/com/android/server/telecom/CallEndpointController.java
index 49c0d51d5..016b75ee8 100644
--- a/src/com/android/server/telecom/CallEndpointController.java
+++ b/src/com/android/server/telecom/CallEndpointController.java
@@ -29,7 +29,9 @@ import android.telecom.Log;
 import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.flags.FeatureFlags;
 
+import java.util.ArrayList;
 import java.util.HashMap;
+import java.util.List;
 import java.util.Map;
 import java.util.HashSet;
 import java.util.Set;
@@ -197,7 +199,7 @@ public class CallEndpointController extends CallsManagerListenerBase {
         }
         mCallsManager.updateCallEndpoint(mActiveCallEndpoint);
 
-        Set<Call> calls = mCallsManager.getTrackedCalls();
+        List<Call> calls = new ArrayList<>(mCallsManager.getTrackedCalls());
         for (Call call : calls) {
             if (mFeatureFlags.cacheCallAudioCallbacks()) {
                 onCallEndpointChangedOrCache(call);
@@ -227,7 +229,7 @@ public class CallEndpointController extends CallsManagerListenerBase {
     private void notifyAvailableCallEndpointsChange() {
         mCallsManager.updateAvailableCallEndpoints(mAvailableCallEndpoints);
 
-        Set<Call> calls = mCallsManager.getTrackedCalls();
+        List<Call> calls = new ArrayList<>(mCallsManager.getTrackedCalls());
         for (Call call : calls) {
             if (mFeatureFlags.cacheCallAudioCallbacks()) {
                 onAvailableEndpointsChangedOrCache(call);
@@ -258,7 +260,7 @@ public class CallEndpointController extends CallsManagerListenerBase {
     private void notifyMuteStateChange(boolean isMuted) {
         mCallsManager.updateMuteState(isMuted);
 
-        Set<Call> calls = mCallsManager.getTrackedCalls();
+        List<Call> calls = new ArrayList<>(mCallsManager.getTrackedCalls());
         for (Call call : calls) {
             if (mFeatureFlags.cacheCallAudioCallbacks()) {
                 onMuteStateChangedOrCache(call, isMuted);
diff --git a/src/com/android/server/telecom/CallIntentProcessor.java b/src/com/android/server/telecom/CallIntentProcessor.java
index 8e1f75416..c77b9ff14 100644
--- a/src/com/android/server/telecom/CallIntentProcessor.java
+++ b/src/com/android/server/telecom/CallIntentProcessor.java
@@ -14,7 +14,6 @@ import android.content.pm.ResolveInfo;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.Looper;
-import android.os.Trace;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.telecom.DefaultDialerManager;
@@ -95,14 +94,12 @@ public class CallIntentProcessor {
         final boolean isUnknownCall = intent.getBooleanExtra(KEY_IS_UNKNOWN_CALL, false);
         Log.i(this, "onReceive - isUnknownCall: %s", isUnknownCall);
 
-        Trace.beginSection("processNewCallCallIntent");
         if (isUnknownCall) {
             processUnknownCallIntent(mCallsManager, intent);
         } else {
             processOutgoingCallIntent(mContext, mCallsManager, intent, callingPackage,
                     mDefaultDialerCache, mFeatureFlags);
         }
-        Trace.endSection();
     }
 
 
diff --git a/src/com/android/server/telecom/CallSourceService.java b/src/com/android/server/telecom/CallSourceService.java
index d57954273..6f16129a4 100644
--- a/src/com/android/server/telecom/CallSourceService.java
+++ b/src/com/android/server/telecom/CallSourceService.java
@@ -16,6 +16,7 @@
 
 package com.android.server.telecom;
 
+import android.os.Bundle;
 import android.telecom.CallEndpoint;
 
 import java.util.Set;
@@ -37,4 +38,6 @@ public interface CallSourceService {
     void onAvailableCallEndpointsChanged(Call activeCall, Set<CallEndpoint> availableCallEndpoints);
 
     void onVideoStateChanged(Call activeCall, int videoState);
+
+    void sendCallEvent(Call activeCall, String event, Bundle extras);
 }
diff --git a/src/com/android/server/telecom/CallsManager.java b/src/com/android/server/telecom/CallsManager.java
index 600f84769..028d8c1c9 100644
--- a/src/com/android/server/telecom/CallsManager.java
+++ b/src/com/android/server/telecom/CallsManager.java
@@ -75,7 +75,6 @@ import android.os.ResultReceiver;
 import android.os.SystemClock;
 import android.os.SystemProperties;
 import android.os.SystemVibrator;
-import android.os.Trace;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.provider.BlockedNumberContract;
@@ -135,6 +134,7 @@ import com.android.server.telecom.callredirection.CallRedirectionProcessor;
 import com.android.server.telecom.components.ErrorDialogActivity;
 import com.android.server.telecom.components.TelecomBroadcastReceiver;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.stats.CallFailureCause;
 import com.android.server.telecom.ui.AudioProcessingNotification;
 import com.android.server.telecom.ui.CallRedirectionTimeoutDialogActivity;
@@ -444,6 +444,7 @@ public class CallsManager extends Call.ListenerBase
     private final InCallController mInCallController;
     private final CallDiagnosticServiceController mCallDiagnosticServiceController;
     private final CallAudioManager mCallAudioManager;
+    /** @deprecated not used any more */
     private final CallRecordingTonePlayer mCallRecordingTonePlayer;
     private RespondViaSmsManager mRespondViaSmsManager;
     private final Ringer mRinger;
@@ -616,7 +617,8 @@ public class CallsManager extends Call.ListenerBase
             BluetoothDeviceManager bluetoothDeviceManager,
             FeatureFlags featureFlags,
             com.android.internal.telephony.flags.FeatureFlags telephonyFlags,
-            IncomingCallFilterGraphProvider incomingCallFilterGraphProvider) {
+            IncomingCallFilterGraphProvider incomingCallFilterGraphProvider,
+            TelecomMetricsController metricsController) {
 
         mContext = context;
         mLock = lock;
@@ -659,7 +661,7 @@ public class CallsManager extends Call.ListenerBase
         } else {
             callAudioRouteAdapter = new CallAudioRouteController(context, this, audioServiceFactory,
                     new AudioRoute.Factory(), wiredHeadsetManager, mBluetoothRouteManager,
-                    statusBarNotifier, featureFlags);
+                    statusBarNotifier, featureFlags, metricsController);
         }
         callAudioRouteAdapter.initialize();
         bluetoothStateReceiver.setCallAudioRouteAdapter(callAudioRouteAdapter);
@@ -680,7 +682,7 @@ public class CallsManager extends Call.ListenerBase
                                         audioManager.generateAudioSessionId()));
         InCallTonePlayer.Factory playerFactory = new InCallTonePlayer.Factory(
                 callAudioRoutePeripheralAdapter, lock, toneGeneratorFactory, mediaPlayerFactory,
-                () -> audioManager.getStreamVolume(AudioManager.STREAM_RING) > 0);
+                () -> audioManager.getStreamVolume(AudioManager.STREAM_RING) > 0, featureFlags);
 
         SystemSettingsUtil systemSettingsUtil = new SystemSettingsUtil();
         RingtoneFactory ringtoneFactory = new RingtoneFactory(this, context, featureFlags);
@@ -696,8 +698,13 @@ public class CallsManager extends Call.ListenerBase
                 new Ringer.VibrationEffectProxy(), mInCallController,
                 mContext.getSystemService(NotificationManager.class),
                 accessibilityManagerAdapter, featureFlags);
-        mCallRecordingTonePlayer = new CallRecordingTonePlayer(mContext, audioManager,
-                mTimeoutsAdapter, mLock);
+        if (featureFlags.telecomResolveHiddenDependencies()) {
+            // This is now deprecated
+            mCallRecordingTonePlayer = null;
+        } else {
+            mCallRecordingTonePlayer = new CallRecordingTonePlayer(mContext, audioManager,
+                    mTimeoutsAdapter, mLock);
+        }
         mCallAudioManager = new CallAudioManager(callAudioRouteAdapter,
                 this, callAudioModeStateMachineFactory.create(systemStateHelper,
                 (AudioManager) mContext.getSystemService(Context.AUDIO_SERVICE),
@@ -742,7 +749,9 @@ public class CallsManager extends Call.ListenerBase
         mListeners.add(mCallEndpointController);
         mListeners.add(mCallDiagnosticServiceController);
         mListeners.add(mCallAudioManager);
-        mListeners.add(mCallRecordingTonePlayer);
+        if (!featureFlags.telecomResolveHiddenDependencies()) {
+            mListeners.add(mCallRecordingTonePlayer);
+        }
         mListeners.add(missedCallNotifier);
         mListeners.add(mDisconnectedCallNotifier);
         mListeners.add(mHeadsetMediaButton);
@@ -906,7 +915,7 @@ public class CallsManager extends Call.ListenerBase
         DndCallFilter dndCallFilter = new DndCallFilter(incomingHfpCall, mRinger);
         IncomingCallFilterGraph graph = mIncomingCallFilterGraphProvider.createGraph(
                 incomingHfpCall,
-                this::onCallFilteringComplete, mContext, mTimeoutsAdapter, mLock);
+                this::onCallFilteringComplete, mContext, mTimeoutsAdapter, mFeatureFlags, mLock);
         graph.addFilter(dndCallFilter);
         mGraphHandlerThreads.add(graph.getHandlerThread());
         return graph;
@@ -925,7 +934,7 @@ public class CallsManager extends Call.ListenerBase
         ParcelableCallUtils.Converter converter = new ParcelableCallUtils.Converter();
 
         IncomingCallFilterGraph graph = mIncomingCallFilterGraphProvider.createGraph(incomingCall,
-                this::onCallFilteringComplete, mContext, mTimeoutsAdapter, mLock);
+                this::onCallFilteringComplete, mContext, mTimeoutsAdapter, mFeatureFlags, mLock);
         DirectToVoicemailFilter voicemailFilter = new DirectToVoicemailFilter(incomingCall,
                 mCallerInfoLookupHelper);
         BlockCheckerFilter blockCheckerFilter = new BlockCheckerFilter(mContext, incomingCall,
@@ -1556,9 +1565,7 @@ public class CallsManager extends Call.ListenerBase
         if (extras.containsKey(TelecomManager.TRANSACTION_CALL_ID_KEY)) {
             call.setIsTransactionalCall(true);
             call.setCallingPackageIdentity(extras);
-            call.setConnectionCapabilities(
-                    extras.getInt(CallAttributes.CALL_CAPABILITIES_KEY,
-                            CallAttributes.SUPPORTS_SET_INACTIVE), true);
+            call.setTransactionalCapabilities(extras);
             call.setTargetPhoneAccount(phoneAccountHandle);
             if (extras.containsKey(CallAttributes.DISPLAY_NAME_KEY)) {
                 CharSequence displayName = extras.getCharSequence(CallAttributes.DISPLAY_NAME_KEY);
@@ -1910,9 +1917,7 @@ public class CallsManager extends Call.ListenerBase
             if (extras.containsKey(TelecomManager.TRANSACTION_CALL_ID_KEY)) {
                 call.setIsTransactionalCall(true);
                 call.setCallingPackageIdentity(extras);
-                call.setConnectionCapabilities(
-                        extras.getInt(CallAttributes.CALL_CAPABILITIES_KEY,
-                                CallAttributes.SUPPORTS_SET_INACTIVE), true);
+                call.setTransactionalCapabilities(extras);
                 if (extras.containsKey(CallAttributes.DISPLAY_NAME_KEY)) {
                     CharSequence displayName = extras.getCharSequence(
                             CallAttributes.DISPLAY_NAME_KEY);
@@ -2059,7 +2064,8 @@ public class CallsManager extends Call.ListenerBase
                         return CompletableFuture.completedFuture(
                                 Collections.singletonList(suggestion));
                     }
-                    return PhoneAccountSuggestionHelper.bindAndGetSuggestions(mContext,
+                    Context userContext = mContext.createContextAsUser(getCurrentUserHandle(), 0);
+                    return PhoneAccountSuggestionHelper.bindAndGetSuggestions(userContext,
                             finalCall.getHandle(), potentialPhoneAccounts);
                 }, new LoggedHandlerExecutor(outgoingCallHandler, "CM.cOCSS", mLock));
 
@@ -4621,7 +4627,6 @@ public class CallsManager extends Call.ListenerBase
             Log.i(this, "addCall(%s) is already added");
             return;
         }
-        Trace.beginSection("addCall");
         Log.i(this, "addCall(%s)", call);
         call.addListener(this);
         mCalls.add(call);
@@ -4638,20 +4643,12 @@ public class CallsManager extends Call.ListenerBase
         updateExternalCallCanPullSupport();
         // onCallAdded for calls which immediately take the foreground (like the first call).
         for (CallsManagerListener listener : mListeners) {
-            if (LogUtils.SYSTRACE_DEBUG) {
-                Trace.beginSection(listener.getClass().toString() + " addCall");
-            }
             listener.onCallAdded(call);
-            if (LogUtils.SYSTRACE_DEBUG) {
-                Trace.endSection();
-            }
         }
-        Trace.endSection();
     }
 
     @VisibleForTesting
     public void removeCall(Call call) {
-        Trace.beginSection("removeCall");
         Log.v(this, "removeCall(%s)", call);
 
         if (call.isTransactionalCall() && call.getTransactionServiceWrapper() != null) {
@@ -4678,16 +4675,9 @@ public class CallsManager extends Call.ListenerBase
             updateCanAddCall();
             updateHasActiveRttCall();
             for (CallsManagerListener listener : mListeners) {
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.beginSection(listener.getClass().toString() + " onCallRemoved");
-                }
                 listener.onCallRemoved(call);
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.endSection();
-                }
             }
         }
-        Trace.endSection();
     }
 
     private void updateHasActiveRttCall() {
@@ -4750,13 +4740,8 @@ public class CallsManager extends Call.ListenerBase
                 call.getAnalytics().setMissedReason(call.getMissedReason());
 
                 maybeShowErrorDialogOnDisconnect(call);
-
-                Trace.beginSection("onCallStateChanged");
-
                 maybeHandleHandover(call, newState);
                 notifyCallStateChanged(call, oldState, newState);
-
-                Trace.endSection();
             } else {
                 Log.i(this, "failed in setting the state to new state");
             }
@@ -4769,14 +4754,7 @@ public class CallsManager extends Call.ListenerBase
             updateCanAddCall();
             updateHasActiveRttCall();
             for (CallsManagerListener listener : mListeners) {
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.beginSection(listener.getClass().toString() +
-                            " onCallStateChanged");
-                }
                 listener.onCallStateChanged(call, oldState, newState);
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.endSection();
-                }
             }
         }
     }
@@ -4901,13 +4879,7 @@ public class CallsManager extends Call.ListenerBase
         if (newCanAddCall != mCanAddCall) {
             mCanAddCall = newCanAddCall;
             for (CallsManagerListener listener : mListeners) {
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.beginSection(listener.getClass().toString() + " updateCanAddCall");
-                }
                 listener.onCanAddCallChanged(mCanAddCall);
-                if (LogUtils.SYSTRACE_DEBUG) {
-                    Trace.endSection();
-                }
             }
         }
     }
diff --git a/src/com/android/server/telecom/ConnectionServiceWrapper.java b/src/com/android/server/telecom/ConnectionServiceWrapper.java
index c3c0c1c15..44686b707 100644
--- a/src/com/android/server/telecom/ConnectionServiceWrapper.java
+++ b/src/com/android/server/telecom/ConnectionServiceWrapper.java
@@ -44,7 +44,6 @@ import android.telecom.ConnectionService;
 import android.telecom.DisconnectCause;
 import android.telecom.GatewayInfo;
 import android.telecom.Log;
-import android.telecom.Logging.Runnable;
 import android.telecom.Logging.Session;
 import android.telecom.ParcelableConference;
 import android.telecom.ParcelableConnection;
@@ -74,13 +73,10 @@ import java.util.HashMap;
 import java.util.List;
 import java.util.Map;
 import java.util.Set;
-import java.util.UUID;
 import java.util.concurrent.CompletableFuture;
 import java.util.concurrent.ConcurrentHashMap;
 import java.util.concurrent.ExecutorService;
 import java.util.concurrent.Executors;
-import java.util.concurrent.ScheduledExecutorService;
-import java.util.concurrent.ScheduledFuture;
 import java.util.concurrent.TimeUnit;
 import java.util.Objects;
 
@@ -94,28 +90,11 @@ import java.util.Objects;
 public class ConnectionServiceWrapper extends ServiceBinder implements
         ConnectionServiceFocusManager.ConnectionServiceFocus, CallSourceService {
 
-    /**
-     * Anomaly Report UUIDs and corresponding error descriptions specific to CallsManager.
-     */
-    public static final UUID CREATE_CONNECTION_TIMEOUT_ERROR_UUID =
-            UUID.fromString("54b7203d-a79f-4cbd-b639-85cd93a39cbb");
-    public static final String CREATE_CONNECTION_TIMEOUT_ERROR_MSG =
-            "Timeout expired before Telecom connection was created.";
-    public static final UUID CREATE_CONFERENCE_TIMEOUT_ERROR_UUID =
-            UUID.fromString("caafe5ea-2472-4c61-b2d8-acb9d47e13dd");
-    public static final String CREATE_CONFERENCE_TIMEOUT_ERROR_MSG =
-            "Timeout expired before Telecom conference was created.";
-
     private static final String TELECOM_ABBREVIATION = "cast";
-    private static final long SERVICE_BINDING_TIMEOUT = 15000L;
     private CompletableFuture<Pair<Integer, Location>> mQueryLocationFuture = null;
     private @Nullable CancellationSignal mOngoingQueryLocationRequest = null;
     private final ExecutorService mQueryLocationExecutor = Executors.newSingleThreadExecutor();
-    private ScheduledExecutorService mScheduledExecutor =
-            Executors.newSingleThreadScheduledExecutor();
-    // Pre-allocate space for 2 calls; realistically thats all we should ever need (tm)
-    private final Map<Call, ScheduledFuture<?>> mScheduledFutureMap = new ConcurrentHashMap<>(2);
-    private AnomalyReporterAdapter mAnomalyReporter = new AnomalyReporterAdapterImpl();
+
     private final class Adapter extends IConnectionServiceAdapter.Stub {
 
         @Override
@@ -128,12 +107,6 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
             try {
                 synchronized (mLock) {
                     logIncoming("handleCreateConnectionComplete %s", callId);
-                    Call call = mCallIdMapper.getCall(callId);
-                    if (mScheduledFutureMap.containsKey(call)) {
-                        ScheduledFuture<?> existingTimeout = mScheduledFutureMap.get(call);
-                        existingTimeout.cancel(false /* cancelIfRunning */);
-                        mScheduledFutureMap.remove(call);
-                    }
                     // Check status hints image for cross user access
                     if (connection.getStatusHints() != null) {
                         Icon icon = connection.getStatusHints().getIcon();
@@ -178,12 +151,6 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                         conference.getStatusHints().setIcon(StatusHints.
                                 validateAccountIconUserBoundary(icon, callingUserHandle));
                     }
-                    Call call = mCallIdMapper.getCall(callId);
-                    if (mScheduledFutureMap.containsKey(call)) {
-                        ScheduledFuture<?> existingTimeout = mScheduledFutureMap.get(call);
-                        existingTimeout.cancel(false /* cancelIfRunning */);
-                        mScheduledFutureMap.remove(call);
-                    }
                     ConnectionServiceWrapper.this
                             .handleCreateConferenceComplete(callId, request, conference);
 
@@ -1644,29 +1611,6 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                         .setParticipants(call.getParticipants())
                         .setIsAdhocConferenceCall(call.isAdhocConferenceCall())
                         .build();
-                Runnable r = new Runnable("CSW.cC", mLock) {
-                            @Override
-                            public void loggedRun() {
-                                if (!call.isCreateConnectionComplete()) {
-                                    Log.e(this, new Exception(),
-                                            "Conference %s creation timeout",
-                                            getComponentName());
-                                    Log.addEvent(call, LogUtils.Events.CREATE_CONFERENCE_TIMEOUT,
-                                            Log.piiHandle(call.getHandle()) + " via:" +
-                                                    getComponentName().getPackageName());
-                                    mAnomalyReporter.reportAnomaly(
-                                            CREATE_CONFERENCE_TIMEOUT_ERROR_UUID,
-                                            CREATE_CONFERENCE_TIMEOUT_ERROR_MSG);
-                                    response.handleCreateConferenceFailure(
-                                            new DisconnectCause(DisconnectCause.ERROR));
-                                }
-                            }
-                        };
-                // Post cleanup to the executor service and cache the future, so we can cancel it if
-                // needed.
-                ScheduledFuture<?> future = mScheduledExecutor.schedule(r.getRunnableToCancel(),
-                        SERVICE_BINDING_TIMEOUT, TimeUnit.MILLISECONDS);
-                mScheduledFutureMap.put(call, future);
                 try {
                     mServiceInterface.createConference(
                             call.getConnectionManagerPhoneAccount(),
@@ -1767,38 +1711,20 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
                         .setRttPipeFromInCall(call.getInCallToCsRttPipeForCs())
                         .setRttPipeToInCall(call.getCsToInCallRttPipeForCs())
                         .build();
-                Runnable r = new Runnable("CSW.cC", mLock) {
-                            @Override
-                            public void loggedRun() {
-                                if (!call.isCreateConnectionComplete()) {
-                                    Log.e(this, new Exception(),
-                                            "Connection %s creation timeout",
-                                            getComponentName());
-                                    Log.addEvent(call, LogUtils.Events.CREATE_CONNECTION_TIMEOUT,
-                                            Log.piiHandle(call.getHandle()) + " via:" +
-                                                    getComponentName().getPackageName());
-                                    mAnomalyReporter.reportAnomaly(
-                                            CREATE_CONNECTION_TIMEOUT_ERROR_UUID,
-                                            CREATE_CONNECTION_TIMEOUT_ERROR_MSG);
-                                    response.handleCreateConnectionFailure(
-                                            new DisconnectCause(DisconnectCause.ERROR));
-                                }
-                            }
-                        };
-                // Post cleanup to the executor service and cache the future, so we can cancel it if
-                // needed.
-                ScheduledFuture<?> future = mScheduledExecutor.schedule(r.getRunnableToCancel(),
-                        SERVICE_BINDING_TIMEOUT, TimeUnit.MILLISECONDS);
-                mScheduledFutureMap.put(call, future);
                 try {
-                    mServiceInterface.createConnection(
-                            call.getConnectionManagerPhoneAccount(),
-                            callId,
-                            connectionRequest,
-                            call.shouldAttachToExistingConnection(),
-                            call.isUnknown(),
-                            Log.getExternalSession(TELECOM_ABBREVIATION));
-
+                    if (mFlags.cswServiceInterfaceIsNull() && mServiceInterface == null) {
+                        mPendingResponses.remove(callId).handleCreateConnectionFailure(
+                                new DisconnectCause(DisconnectCause.ERROR,
+                                        "CSW#oCC ServiceInterface is null"));
+                    } else {
+                        mServiceInterface.createConnection(
+                                call.getConnectionManagerPhoneAccount(),
+                                callId,
+                                connectionRequest,
+                                call.shouldAttachToExistingConnection(),
+                                call.isUnknown(),
+                                Log.getExternalSession(TELECOM_ABBREVIATION));
+                    }
                 } catch (RemoteException e) {
                     Log.e(this, e, "Failure to createConnection -- %s", getComponentName());
                     mPendingResponses.remove(callId).handleCreateConnectionFailure(
@@ -2256,8 +2182,7 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         }
     }
 
-    @VisibleForTesting
-    public void addCall(Call call) {
+    void addCall(Call call) {
         if (mCallIdMapper.getCallId(call) == null) {
             mCallIdMapper.addCall(call);
         }
@@ -2379,7 +2304,8 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         }
     }
 
-    void sendCallEvent(Call call, String event, Bundle extras) {
+    @Override
+    public void sendCallEvent(Call call, String event, Bundle extras) {
         final String callId = mCallIdMapper.getCallId(call);
         if (callId != null && isServiceValid("sendCallEvent")) {
             try {
@@ -2725,14 +2651,4 @@ public class ConnectionServiceWrapper extends ServiceBinder implements
         sb.append("]");
         return sb.toString();
     }
-
-    @VisibleForTesting
-    public void setScheduledExecutorService(ScheduledExecutorService service) {
-        mScheduledExecutor = service;
-    }
-
-    @VisibleForTesting
-    public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter){
-        mAnomalyReporter = mAnomalyReporterAdapter;
-    }
 }
diff --git a/src/com/android/server/telecom/EmergencyCallHelper.java b/src/com/android/server/telecom/EmergencyCallHelper.java
index 5ab0e99d0..c0e38ca12 100644
--- a/src/com/android/server/telecom/EmergencyCallHelper.java
+++ b/src/com/android/server/telecom/EmergencyCallHelper.java
@@ -24,6 +24,7 @@ import android.telecom.Log;
 import android.telecom.PhoneAccountHandle;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.telecom.flags.FeatureFlags;
 
 /**
  * Helps with emergency calls by:
@@ -51,19 +52,25 @@ public class EmergencyCallHelper {
     private long mLastEmergencyCallTimestampMillis;
     private long mLastOutgoingEmergencyCallTimestampMillis;
 
+    private final FeatureFlags mFeatureFlags;
+
     @VisibleForTesting
     public EmergencyCallHelper(
             Context context,
             DefaultDialerCache defaultDialerCache,
-            Timeouts.Adapter timeoutsAdapter) {
+            Timeouts.Adapter timeoutsAdapter,
+            FeatureFlags featureFlags) {
         mContext = context;
         mDefaultDialerCache = defaultDialerCache;
         mTimeoutsAdapter = timeoutsAdapter;
+        mFeatureFlags = featureFlags;
     }
 
     @VisibleForTesting
     public void maybeGrantTemporaryLocationPermission(Call call, UserHandle userHandle) {
-        if (shouldGrantTemporaryLocationPermission(call)) {
+        if (shouldGrantTemporaryLocationPermission(call) && (
+                !mFeatureFlags.preventRedundantLocationPermissionGrantAndRevoke()
+                || !wasGrantedTemporaryLocationPermission())) {
             grantLocationPermission(userHandle);
         }
         if (call != null && call.isEmergencyCall()) {
diff --git a/src/com/android/server/telecom/InCallAdapter.java b/src/com/android/server/telecom/InCallAdapter.java
index 514ba48dd..8836fffae 100755
--- a/src/com/android/server/telecom/InCallAdapter.java
+++ b/src/com/android/server/telecom/InCallAdapter.java
@@ -606,7 +606,7 @@ class InCallAdapter extends IInCallAdapter.Stub {
                 synchronized (mLock) {
                     Call call = mCallIdMapper.getCall(callId);
                     if (call != null) {
-                        call.sendCallEvent(event, targetSdkVer, extras);
+                        call.sendCallEvent(event, extras);
                     } else {
                         Log.w(this, "sendCallEvent, unknown call id: %s", callId);
                     }
diff --git a/src/com/android/server/telecom/InCallController.java b/src/com/android/server/telecom/InCallController.java
index f3c84baca..529bc79f1 100644
--- a/src/com/android/server/telecom/InCallController.java
+++ b/src/com/android/server/telecom/InCallController.java
@@ -45,7 +45,6 @@ import android.os.IBinder;
 import android.os.Looper;
 import android.os.PackageTagsList;
 import android.os.RemoteException;
-import android.os.Trace;
 import android.os.UserHandle;
 import android.os.UserManager;
 import android.telecom.CallAudioState;
@@ -103,7 +102,10 @@ public class InCallController extends CallsManagerListenerBase implements
             UUID.fromString("0c2adf96-353a-433c-afe9-1e5564f304f9");
     public static final String SET_IN_CALL_ADAPTER_ERROR_MSG =
             "Exception thrown while setting the in-call adapter.";
-
+    public static final UUID NULL_IN_CALL_SERVICE_BINDING_UUID =
+            UUID.fromString("7d58dedf-b71d-4c18-9d23-47b434bde58b");
+    public static final String NULL_IN_CALL_SERVICE_BINDING_ERROR_MSG =
+            "InCallController#sendCallToInCallService with null InCallService binding";
     @VisibleForTesting
     public void setAnomalyReporterAdapter(AnomalyReporterAdapter mAnomalyReporterAdapter){
         mAnomalyReporter = mAnomalyReporterAdapter;
@@ -1299,6 +1301,8 @@ public class InCallController extends CallsManagerListenerBase implements
     private ArraySet<String> mAllCarrierPrivilegedApps = new ArraySet<>();
     private ArraySet<String> mActiveCarrierPrivilegedApps = new ArraySet<>();
 
+    private java.lang.Runnable mCallRemovedRunnable;
+
     public InCallController(Context context, TelecomSystem.SyncRoot lock, CallsManager callsManager,
             SystemStateHelper systemStateHelper, DefaultDialerCache defaultDialerCache,
             Timeouts.Adapter timeoutsAdapter, EmergencyCallHelper emergencyCallHelper,
@@ -1514,7 +1518,11 @@ public class InCallController extends CallsManagerListenerBase implements
             /** Let's add a 2 second delay before we send unbind to the services to hopefully
              *  give them enough time to process all the pending messages.
              */
-            mHandler.postDelayed(new Runnable("ICC.oCR", mLock) {
+            if (mCallRemovedRunnable != null
+                    && mFeatureFlags.preventRedundantLocationPermissionGrantAndRevoke()) {
+                mHandler.removeCallbacks(mCallRemovedRunnable);
+            }
+            mCallRemovedRunnable = new Runnable("ICC.oCR", mLock) {
                 @Override
                 public void loggedRun() {
                     // Check again to make sure there are no active calls for the associated user.
@@ -1528,8 +1536,10 @@ public class InCallController extends CallsManagerListenerBase implements
                         mEmergencyCallHelper.maybeRevokeTemporaryLocationPermission();
                     }
                 }
-            }.prepare(), mTimeoutsAdapter.getCallRemoveUnbindInCallServicesDelay(
-                    mContext.getContentResolver()));
+            }.prepare();
+            mHandler.postDelayed(mCallRemovedRunnable,
+                    mTimeoutsAdapter.getCallRemoveUnbindInCallServicesDelay(
+                            mContext.getContentResolver()));
         }
         call.removeListener(mCallListener);
         mCallIdMapper.removeCall(call);
@@ -1561,8 +1571,22 @@ public class InCallController extends CallsManagerListenerBase implements
                     }
                     UserHandle userHandle = getUserFromCall(call);
                     if (mBTInCallServiceConnections.containsKey(userHandle)) {
-                        Log.i(this, "onDisconnectedTonePlaying: Unbinding BT service");
-                        mBTInCallServiceConnections.get(userHandle).disconnect();
+                        Log.i(this, "onDisconnectedTonePlaying: Schedule unbind BT service");
+                        final InCallServiceConnection connection =
+                                mBTInCallServiceConnections.get(userHandle);
+
+                        // Similar to in onCallRemoved when we unbind from the other ICS, we need to
+                        // delay unbinding from the BT ICS because we need to give the ICS a
+                        // moment to finish the onCallRemoved signal it got just prior.
+                        mHandler.postDelayed(new Runnable("ICC.oDCTP", mLock) {
+                            @Override
+                            public void loggedRun() {
+                                Log.i(this, "onDisconnectedTonePlaying: unbinding");
+                                connection.disconnect();
+                            }
+                        }.prepare(), mTimeoutsAdapter.getCallRemoveUnbindInCallServicesDelay(
+                                mContext.getContentResolver()));
+
                         mBTInCallServiceConnections.remove(userHandle);
                     }
                     // Ensure that BT ICS instance is cleaned up
@@ -2570,7 +2594,6 @@ public class InCallController extends CallsManagerListenerBase implements
             Log.e(this, e, "Failed to set the in-call adapter.");
             mAnomalyReporter.reportAnomaly(SET_IN_CALL_ADAPTER_ERROR_UUID,
                     SET_IN_CALL_ADAPTER_ERROR_MSG);
-            Trace.endSection();
             return false;
         }
 
@@ -2587,6 +2610,10 @@ public class InCallController extends CallsManagerListenerBase implements
         try {
             inCallService.onCallAudioStateChanged(mCallsManager.getAudioState());
             inCallService.onCanAddCallChanged(mCallsManager.canAddCall());
+            if (mFeatureFlags.onCallEndpointChangedIcsOnConnected()) {
+                inCallService.onCallEndpointChanged(mCallsManager.getCallEndpointController()
+                        .getCurrentCallEndpoint());
+            }
         } catch (RemoteException ignored) {
         }
         // Don't complete the binding future for non-ui incalls
@@ -2598,7 +2625,8 @@ public class InCallController extends CallsManagerListenerBase implements
         return true;
     }
 
-    private int sendCallToService(Call call, InCallServiceInfo info,
+    @VisibleForTesting
+    public int sendCallToService(Call call, InCallServiceInfo info,
             IInCallService inCallService) {
         try {
             if ((call.isSelfManaged() && (!info.isSelfManagedCallsSupported()
@@ -2624,7 +2652,20 @@ public class InCallController extends CallsManagerListenerBase implements
                     includeRttCall,
                     info.getType() == IN_CALL_SERVICE_TYPE_SYSTEM_UI ||
                             info.getType() == IN_CALL_SERVICE_TYPE_NON_UI);
-            inCallService.addCall(sanitizeParcelableCallForService(info, parcelableCall));
+            if (mFeatureFlags.doNotSendCallToNullIcs()) {
+                if (inCallService != null) {
+                    inCallService.addCall(sanitizeParcelableCallForService(info, parcelableCall));
+                } else {
+                    Log.w(this, "call=[%s], was not sent to InCallService"
+                                    + " with info=[%s] due to a null InCallService binding",
+                            call, info);
+                    mAnomalyReporter.reportAnomaly(NULL_IN_CALL_SERVICE_BINDING_UUID,
+                            NULL_IN_CALL_SERVICE_BINDING_ERROR_MSG);
+                    return 0;
+                }
+            } else {
+                inCallService.addCall(sanitizeParcelableCallForService(info, parcelableCall));
+            }
             updateCallTracking(call, info, true /* isAdd */);
             return 1;
         } catch (RemoteException ignored) {
@@ -2716,21 +2757,39 @@ public class InCallController extends CallsManagerListenerBase implements
                         info.getType() == IN_CALL_SERVICE_TYPE_SYSTEM_UI ||
                         info.getType() == IN_CALL_SERVICE_TYPE_NON_UI);
                 IInCallService inCallService = entry.getValue();
-                componentsUpdated.add(componentName);
-
-                if (info.getType() == IN_CALL_SERVICE_TYPE_BLUETOOTH
-                        && call.getState() == CallState.DISCONNECTED
-                        && !mDisconnectedToneBtFutures.containsKey(call.getId())) {
-                    CompletableFuture<Void> disconnectedToneFuture = new CompletableFuture<Void>()
-                            .completeOnTimeout(null, DISCONNECTED_TONE_TIMEOUT,
-                                    TimeUnit.MILLISECONDS);
-                    mDisconnectedToneBtFutures.put(call.getId(), disconnectedToneFuture);
-                    mDisconnectedToneBtFutures.get(call.getId()).thenRunAsync(() -> {
-                        Log.i(this, "updateCall: Sending call disconnected update to BT ICS.");
-                        updateCallToIcs(inCallService, info, parcelableCall, componentName);
-                        mDisconnectedToneBtFutures.remove(call.getId());
-                    }, new LoggedHandlerExecutor(mHandler, "ICC.uC", mLock));
+                boolean isDisconnectingBtIcs = info.getType() == IN_CALL_SERVICE_TYPE_BLUETOOTH
+                        && call.getState() == CallState.DISCONNECTED;
+
+                if (isDisconnectingBtIcs) {
+                    // If this is the first we heard about the disconnect for the BT ICS, then we
+                    // will setup a future to notify the disconnet later.
+                    if (!mDisconnectedToneBtFutures.containsKey(call.getId())) {
+                        // Create the base future with timeout, we will chain more operations on to
+                        // this.
+                        CompletableFuture<Void> disconnectedToneFuture =
+                                new CompletableFuture<Void>()
+                                        .completeOnTimeout(null, DISCONNECTED_TONE_TIMEOUT,
+                                                TimeUnit.MILLISECONDS);
+                        // Note: DO NOT chain async work onto this future; using thenRun ensures
+                        // when disconnectedToneFuture is completed that the chained work is run
+                        // synchronously.
+                        disconnectedToneFuture.thenRun(() -> {
+                            Log.i(this,
+                                    "updateCall: (deferred) Sending call disconnected update "
+                                            + "to BT ICS.");
+                            updateCallToIcs(inCallService, info, parcelableCall, componentName);
+                            mDisconnectedToneBtFutures.remove(call.getId());
+                        });
+                        mDisconnectedToneBtFutures.put(call.getId(), disconnectedToneFuture);
+                    } else {
+                        // If we have already cached a disconnect signal for the BT ICS, don't sent
+                        // any other updates (ie due to extras or whatnot) to the BT ICS.  If we do
+                        // then it will hear about the disconnect in advance and not play the call
+                        // end tone.
+                        Log.i(this, "updateCall: skip update for disconnected call to BT ICS");
+                    }
                 } else {
+                    componentsUpdated.add(componentName);
                     updateCallToIcs(inCallService, info, parcelableCall, componentName);
                 }
             }
diff --git a/src/com/android/server/telecom/InCallTonePlayer.java b/src/com/android/server/telecom/InCallTonePlayer.java
index a5942f02e..b7edeb512 100644
--- a/src/com/android/server/telecom/InCallTonePlayer.java
+++ b/src/com/android/server/telecom/InCallTonePlayer.java
@@ -30,6 +30,7 @@ import android.telecom.Logging.Runnable;
 import android.telecom.Logging.Session;
 
 import com.android.internal.annotations.VisibleForTesting;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.concurrent.CountDownLatch;
 import java.util.concurrent.TimeUnit;
@@ -54,15 +55,18 @@ public class InCallTonePlayer extends Thread {
         private final ToneGeneratorFactory mToneGeneratorFactory;
         private final MediaPlayerFactory mMediaPlayerFactory;
         private final AudioManagerAdapter mAudioManagerAdapter;
+        private final FeatureFlags mFeatureFlags;
 
         public Factory(CallAudioRoutePeripheralAdapter callAudioRoutePeripheralAdapter,
                 TelecomSystem.SyncRoot lock, ToneGeneratorFactory toneGeneratorFactory,
-                MediaPlayerFactory mediaPlayerFactory, AudioManagerAdapter audioManagerAdapter) {
+                MediaPlayerFactory mediaPlayerFactory, AudioManagerAdapter audioManagerAdapter,
+                FeatureFlags flags) {
             mCallAudioRoutePeripheralAdapter = callAudioRoutePeripheralAdapter;
             mLock = lock;
             mToneGeneratorFactory = toneGeneratorFactory;
             mMediaPlayerFactory = mediaPlayerFactory;
             mAudioManagerAdapter = audioManagerAdapter;
+            mFeatureFlags = flags;
         }
 
         public void setCallAudioManager(CallAudioManager callAudioManager) {
@@ -72,7 +76,7 @@ public class InCallTonePlayer extends Thread {
         public InCallTonePlayer createPlayer(Call call, int tone) {
             return new InCallTonePlayer(call, tone, mCallAudioManager,
                     mCallAudioRoutePeripheralAdapter, mLock, mToneGeneratorFactory,
-                    mMediaPlayerFactory, mAudioManagerAdapter);
+                    mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags);
         }
     }
 
@@ -216,6 +220,7 @@ public class InCallTonePlayer extends Thread {
     private final ToneGeneratorFactory mToneGenerator;
     private final MediaPlayerFactory mMediaPlayerFactory;
     private final AudioManagerAdapter mAudioManagerAdapter;
+    private final FeatureFlags mFeatureFlags;
 
     /**
      * Latch used for awaiting on playback, which may be interrupted if the tone is stopped from
@@ -236,7 +241,8 @@ public class InCallTonePlayer extends Thread {
             TelecomSystem.SyncRoot lock,
             ToneGeneratorFactory toneGeneratorFactory,
             MediaPlayerFactory mediaPlayerFactor,
-            AudioManagerAdapter audioManagerAdapter) {
+            AudioManagerAdapter audioManagerAdapter,
+            FeatureFlags flags) {
         mCall = call;
         mState = STATE_OFF;
         mToneId = toneId;
@@ -246,6 +252,7 @@ public class InCallTonePlayer extends Thread {
         mToneGenerator = toneGeneratorFactory;
         mMediaPlayerFactory = mediaPlayerFactor;
         mAudioManagerAdapter = audioManagerAdapter;
+        mFeatureFlags = flags;
     }
 
     /** {@inheritDoc} */
@@ -364,18 +371,8 @@ public class InCallTonePlayer extends Thread {
                     throw new IllegalStateException("Bad toneId: " + mToneId);
             }
 
-            int stream = AudioManager.STREAM_VOICE_CALL;
-            if (mCallAudioRoutePeripheralAdapter.isBluetoothAudioOn()) {
-                stream = AudioManager.STREAM_BLUETOOTH_SCO;
-            }
+            int stream = getStreamType(toneType);
             if (toneType != ToneGenerator.TONE_UNKNOWN) {
-                if (stream == AudioManager.STREAM_BLUETOOTH_SCO) {
-                    // Override audio stream for BT le device and hearing aid device
-                    if (mCallAudioRoutePeripheralAdapter.isLeAudioDeviceOn()
-                            || mCallAudioRoutePeripheralAdapter.isHearingAidDeviceOn()) {
-                        stream = AudioManager.STREAM_VOICE_CALL;
-                    }
-                }
                 playToneGeneratorTone(stream, toneVolume, toneType, toneLengthMillis);
             } else if (mediaResourceId != TONE_RESOURCE_ID_UNDEFINED) {
                 playMediaTone(stream, mediaResourceId);
@@ -386,6 +383,31 @@ public class InCallTonePlayer extends Thread {
         }
     }
 
+    /**
+     * @param toneType The ToneGenerator tone type
+     * @return The ToneGenerator stream type
+     */
+    private int getStreamType(int toneType) {
+        if (mFeatureFlags.useStreamVoiceCallTones()) {
+            return AudioManager.STREAM_VOICE_CALL;
+        }
+
+        int stream = AudioManager.STREAM_VOICE_CALL;
+        if (mCallAudioRoutePeripheralAdapter.isBluetoothAudioOn()) {
+            stream = AudioManager.STREAM_BLUETOOTH_SCO;
+        }
+        if (toneType != ToneGenerator.TONE_UNKNOWN) {
+            if (stream == AudioManager.STREAM_BLUETOOTH_SCO) {
+                // Override audio stream for BT le device and hearing aid device
+                if (mCallAudioRoutePeripheralAdapter.isLeAudioDeviceOn()
+                        || mCallAudioRoutePeripheralAdapter.isHearingAidDeviceOn()) {
+                    stream = AudioManager.STREAM_VOICE_CALL;
+                }
+            }
+        }
+        return stream;
+    }
+
     /**
      * Play a tone generated by the {@link ToneGenerator}.
      * @param stream The stream on which the tone will be played.
diff --git a/src/com/android/server/telecom/LogUtils.java b/src/com/android/server/telecom/LogUtils.java
index d98ebfe6b..0d6acd51d 100644
--- a/src/com/android/server/telecom/LogUtils.java
+++ b/src/com/android/server/telecom/LogUtils.java
@@ -139,10 +139,8 @@ public class LogUtils {
         public static final String STOP_CALL_WAITING_TONE = "STOP_CALL_WAITING_TONE";
         public static final String START_CONNECTION = "START_CONNECTION";
         public static final String CREATE_CONNECTION_FAILED = "CREATE_CONNECTION_FAILED";
-        public static final String CREATE_CONNECTION_TIMEOUT = "CREATE_CONNECTION_TIMEOUT";
         public static final String START_CONFERENCE = "START_CONFERENCE";
         public static final String CREATE_CONFERENCE_FAILED = "CREATE_CONFERENCE_FAILED";
-        public static final String CREATE_CONFERENCE_TIMEOUT = "CREATE_CONFERENCE_TIMEOUT";
         public static final String BIND_CS = "BIND_CS";
         public static final String CS_BOUND = "CS_BOUND";
         public static final String CONFERENCE_WITH = "CONF_WITH";
diff --git a/src/com/android/server/telecom/NewOutgoingCallIntentBroadcaster.java b/src/com/android/server/telecom/NewOutgoingCallIntentBroadcaster.java
index c24ac9701..fce3f1a69 100644
--- a/src/com/android/server/telecom/NewOutgoingCallIntentBroadcaster.java
+++ b/src/com/android/server/telecom/NewOutgoingCallIntentBroadcaster.java
@@ -25,7 +25,6 @@ import android.content.Context;
 import android.content.Intent;
 import android.net.Uri;
 import android.os.Bundle;
-import android.os.Trace;
 import android.os.UserHandle;
 import android.telecom.GatewayInfo;
 import android.telecom.Log;
@@ -126,7 +125,6 @@ public class NewOutgoingCallIntentBroadcaster {
         public void onReceive(Context context, Intent intent) {
             try {
                 Log.startSession("NOCBIR.oR");
-                Trace.beginSection("onReceiveNewOutgoingCallBroadcast");
                 synchronized (mLock) {
                     Log.v(this, "onReceive: %s", intent);
 
@@ -194,7 +192,6 @@ public class NewOutgoingCallIntentBroadcaster {
                                     VideoProfile.STATE_AUDIO_ONLY));
                 }
             } finally {
-                Trace.endSection();
                 Log.endSession();
             }
         }
diff --git a/src/com/android/server/telecom/PendingAudioRoute.java b/src/com/android/server/telecom/PendingAudioRoute.java
index 396aca0d6..ffde9640c 100644
--- a/src/com/android/server/telecom/PendingAudioRoute.java
+++ b/src/com/android/server/telecom/PendingAudioRoute.java
@@ -27,6 +27,7 @@ import android.util.ArraySet;
 import android.util.Pair;
 
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.Set;
 
@@ -41,6 +42,7 @@ public class PendingAudioRoute {
     private CallAudioRouteController mCallAudioRouteController;
     private AudioManager mAudioManager;
     private BluetoothRouteManager mBluetoothRouteManager;
+    private FeatureFlags mFeatureFlags;
     /**
      * The {@link AudioRoute} that this pending audio switching started with
      */
@@ -58,10 +60,11 @@ public class PendingAudioRoute {
     private @AudioRoute.AudioRouteType int mCommunicationDeviceType = AudioRoute.TYPE_INVALID;
 
     PendingAudioRoute(CallAudioRouteController controller, AudioManager audioManager,
-            BluetoothRouteManager bluetoothRouteManager) {
+            BluetoothRouteManager bluetoothRouteManager, FeatureFlags featureFlags) {
         mCallAudioRouteController = controller;
         mAudioManager = audioManager;
         mBluetoothRouteManager = bluetoothRouteManager;
+        mFeatureFlags = featureFlags;
         mPendingMessages = new ArraySet<>();
         mActive = false;
         mCommunicationDeviceType = AudioRoute.TYPE_INVALID;
@@ -72,7 +75,7 @@ public class PendingAudioRoute {
         mOrigRoute = origRoute;
     }
 
-    AudioRoute getOrigRoute() {
+    public AudioRoute getOrigRoute() {
         return mOrigRoute;
     }
 
@@ -96,8 +99,12 @@ public class PendingAudioRoute {
         Log.i(this, "onMessageReceived: message - %s", message);
         if (message.first == PENDING_ROUTE_FAILED) {
             // Fallback to base route
-            mCallAudioRouteController.sendMessageWithSessionInfo(
-                    SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE, btAddressToExclude);
+            if (mFeatureFlags.telecomMetricsSupport()) {
+                mCallAudioRouteController.fallBack(btAddressToExclude);
+            } else {
+                mCallAudioRouteController.sendMessageWithSessionInfo(
+                        SWITCH_BASELINE_ROUTE, INCLUDE_BLUETOOTH_IN_BASELINE, btAddressToExclude);
+            }
             return;
         }
 
diff --git a/src/com/android/server/telecom/PhoneAccountSuggestionHelper.java b/src/com/android/server/telecom/PhoneAccountSuggestionHelper.java
index 438ee6830..ab5570344 100644
--- a/src/com/android/server/telecom/PhoneAccountSuggestionHelper.java
+++ b/src/com/android/server/telecom/PhoneAccountSuggestionHelper.java
@@ -27,6 +27,7 @@ import android.net.Uri;
 import android.os.Handler;
 import android.os.IBinder;
 import android.os.RemoteException;
+import android.os.UserHandle;
 import android.telecom.Log;
 import android.telecom.Logging.Session;
 import android.telecom.PhoneAccountHandle;
@@ -46,6 +47,7 @@ import java.util.stream.Stream;
 public class PhoneAccountSuggestionHelper {
     private static final String TAG = PhoneAccountSuggestionHelper.class.getSimpleName();
     private static ComponentName sOverrideComponent;
+    private static UserHandle sOverrideUserHandle;
 
     /**
      * @return A future (possible already complete) that contains a list of suggestions.
@@ -53,6 +55,15 @@ public class PhoneAccountSuggestionHelper {
     public static CompletableFuture<List<PhoneAccountSuggestion>>
     bindAndGetSuggestions(Context context, Uri handle,
             List<PhoneAccountHandle> availablePhoneAccounts) {
+        Context userContext;
+        if (sOverrideUserHandle != null) {
+            userContext = context.createContextAsUser(sOverrideUserHandle, 0);
+            Log.i(TAG, "bindAndGetSuggestions created context as user;  userContext=%s",
+                    userContext);
+        } else {
+            userContext = context;
+        }
+
         // Use the default list if there's no handle
         if (handle == null) {
             return CompletableFuture.completedFuture(getDefaultSuggestions(availablePhoneAccounts));
@@ -60,7 +71,7 @@ public class PhoneAccountSuggestionHelper {
         String number = PhoneNumberUtils.extractNetworkPortion(handle.getSchemeSpecificPart());
 
         // Use the default list if there's no service on the device.
-        ServiceInfo suggestionServiceInfo = getSuggestionServiceInfo(context);
+        ServiceInfo suggestionServiceInfo = getSuggestionServiceInfo(userContext);
         if (suggestionServiceInfo == null) {
             return CompletableFuture.completedFuture(getDefaultSuggestions(availablePhoneAccounts));
         }
@@ -124,7 +135,7 @@ public class PhoneAccountSuggestionHelper {
             }
         };
 
-        if (!context.bindService(bindIntent, serviceConnection, Context.BIND_AUTO_CREATE)) {
+        if (!userContext.bindService(bindIntent, serviceConnection, Context.BIND_AUTO_CREATE)) {
             Log.i(TAG, "Cancelling suggestion process due to bind failure.");
             future.complete(getDefaultSuggestions(availablePhoneAccounts));
         }
@@ -143,7 +154,7 @@ public class PhoneAccountSuggestionHelper {
                         Log.endSession();
                     }
                 },
-                Timeouts.getPhoneAccountSuggestionServiceTimeout(context.getContentResolver()));
+                Timeouts.getPhoneAccountSuggestionServiceTimeout(userContext.getContentResolver()));
         return future;
     }
 
@@ -162,10 +173,25 @@ public class PhoneAccountSuggestionHelper {
     }
 
     private static ServiceInfo getSuggestionServiceInfo(Context context) {
-        PackageManager packageManager = context.getPackageManager();
+        Context userContext;
+        if (sOverrideUserHandle != null) {
+            userContext = context.createContextAsUser(sOverrideUserHandle, 0);
+            Log.i(TAG, "getSuggestionServiceInfo: Created context as user; userContext= %s",
+                    userContext);
+        } else {
+            userContext = context;
+        }
+
+        PackageManager packageManager = userContext.getPackageManager();
+
         Intent queryIntent = new Intent();
         queryIntent.setAction(PhoneAccountSuggestionService.SERVICE_INTERFACE);
 
+        if (packageManager == null) {
+            Log.i(TAG, "getSuggestionServiceInfo: PackageManager is null. Using defaults.");
+            return null;
+        }
+
         List<ResolveInfo> services;
         if (sOverrideComponent == null) {
             services = packageManager.queryIntentServices(queryIntent,
@@ -199,6 +225,15 @@ public class PhoneAccountSuggestionHelper {
         }
     }
 
+    static void setOverrideUserHandle(UserHandle userHandle) {
+        try {
+            sOverrideUserHandle = userHandle;
+        } catch (Exception e) {
+            sOverrideUserHandle = null;
+            throw e;
+        }
+    }
+
     private static List<PhoneAccountSuggestion> getDefaultSuggestions(
             List<PhoneAccountHandle> phoneAccountHandles) {
         return phoneAccountHandles.stream().map(phoneAccountHandle ->
diff --git a/src/com/android/server/telecom/Ringer.java b/src/com/android/server/telecom/Ringer.java
index e148ef558..c309dd5fc 100644
--- a/src/com/android/server/telecom/Ringer.java
+++ b/src/com/android/server/telecom/Ringer.java
@@ -28,9 +28,12 @@ import android.app.NotificationManager;
 import android.app.Person;
 import android.content.Context;
 import android.content.res.Resources;
+import android.media.AudioAttributes;
 import android.media.AudioManager;
 import android.media.Ringtone;
+import android.media.Utils;
 import android.media.VolumeShaper;
+import android.media.audio.Flags;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.Handler;
@@ -51,9 +54,9 @@ import com.android.internal.annotations.VisibleForTesting;
 import com.android.server.telecom.LogUtils.EventTimer;
 import com.android.server.telecom.flags.FeatureFlags;
 
+import java.io.IOException;
 import java.io.InputStream;
 import java.io.InputStreamReader;
-import java.io.IOException;
 import java.nio.charset.StandardCharsets;
 import java.util.ArrayList;
 import java.util.concurrent.CompletableFuture;
@@ -187,6 +190,7 @@ public class Ringer {
     private final VibrationEffectProxy mVibrationEffectProxy;
     private final boolean mIsHapticPlaybackSupportedByDevice;
     private final FeatureFlags mFlags;
+    private final boolean mRingtoneVibrationSupported;
     /**
      * For unit testing purposes only; when set, {@link #startRinging(Call, boolean)} will complete
      * the future provided by the test using {@link #setBlockOnRingingFuture(CompletableFuture)}.
@@ -258,6 +262,8 @@ public class Ringer {
 
         mAudioManager = mContext.getSystemService(AudioManager.class);
         mFlags = featureFlags;
+        mRingtoneVibrationSupported = mContext.getResources().getBoolean(
+                com.android.internal.R.bool.config_ringtoneVibrationSettingsSupported);
     }
 
     @VisibleForTesting
@@ -414,19 +420,14 @@ public class Ringer {
                         isVibratorEnabled, mIsHapticPlaybackSupportedByDevice);
             }
             // Defer ringtone creation to the async player thread.
-            Supplier<Pair<Uri, Ringtone>> ringtoneInfoSupplier;
+            Supplier<Pair<Uri, Ringtone>> ringtoneInfoSupplier = null;
             final boolean finalHapticChannelsMuted = hapticChannelsMuted;
-            if (isHapticOnly) {
-                if (hapticChannelsMuted) {
-                    Log.i(this,
-                            "want haptic only ringtone but haptics are muted, skip ringtone play");
-                    ringtoneInfoSupplier = null;
-                } else {
-                    ringtoneInfoSupplier = mRingtoneFactory::getHapticOnlyRingtone;
-                }
-            } else {
+            if (!isHapticOnly) {
                 ringtoneInfoSupplier = () -> mRingtoneFactory.getRingtone(
                         foregroundCall, mVolumeShaperConfig, finalHapticChannelsMuted);
+            } else if (Flags.enableRingtoneHapticsCustomization() && mRingtoneVibrationSupported) {
+                ringtoneInfoSupplier = () -> mRingtoneFactory.getRingtone(
+                        foregroundCall, null, false);
             }
 
             // If vibration will be done, reserve the vibrator.
@@ -478,7 +479,8 @@ public class Ringer {
                     boolean isUsingAudioCoupledHaptics =
                             !finalHapticChannelsMuted && ringtone != null
                                     && ringtone.hasHapticChannels();
-                    vibrateIfNeeded(isUsingAudioCoupledHaptics, foregroundCall, vibrationEffect);
+                    vibrateIfNeeded(isUsingAudioCoupledHaptics, foregroundCall, vibrationEffect,
+                            ringtoneUri);
                 } finally {
                     // This is used to signal to tests that the async play() call has completed.
                     if (mBlockOnRingingFuture != null) {
@@ -530,13 +532,20 @@ public class Ringer {
    }
 
     private void vibrateIfNeeded(boolean isUsingAudioCoupledHaptics, Call foregroundCall,
-            VibrationEffect effect) {
+            VibrationEffect effect, Uri ringtoneUri) {
         if (isUsingAudioCoupledHaptics) {
             Log.addEvent(
                 foregroundCall, LogUtils.Events.SKIP_VIBRATION, "using audio-coupled haptics");
             return;
         }
 
+        if (Flags.enableRingtoneHapticsCustomization() && mRingtoneVibrationSupported
+                && Utils.hasVibration(ringtoneUri)) {
+            Log.addEvent(
+                    foregroundCall, LogUtils.Events.SKIP_VIBRATION, "using custom haptics");
+            return;
+        }
+
         synchronized (mLock) {
             // Ensure the reservation is live. The mIsVibrating check should be redundant.
             if (foregroundCall == mVibratingCall && !mIsVibrating) {
@@ -578,10 +587,6 @@ public class Ringer {
     }
 
     public void startCallWaiting(Call call, String reason) {
-        if (mSystemSettingsUtil.isTheaterModeOn(mContext)) {
-            return;
-        }
-
         if (mInCallController.doesConnectedDialerSupportRinging(
                 call.getAssociatedUser())) {
             Log.addEvent(call, LogUtils.Events.SKIP_RINGING, "Dialer handles");
@@ -704,7 +709,16 @@ public class Ringer {
 
         LogUtils.EventTimer timer = new EventTimer();
 
-        boolean isVolumeOverZero = mAudioManager.getStreamVolume(AudioManager.STREAM_RING) > 0;
+        boolean isVolumeOverZero;
+
+        if (mFlags.ensureInCarRinging()) {
+            AudioAttributes aa = new AudioAttributes.Builder()
+                    .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
+                    .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build();
+            isVolumeOverZero = mAudioManager.shouldNotificationSoundPlay(aa);
+        } else {
+            isVolumeOverZero = mAudioManager.getStreamVolume(AudioManager.STREAM_RING) > 0;
+        }
         timer.record("isVolumeOverZero");
         boolean shouldRingForContact = shouldRingForContact(call);
         timer.record("shouldRingForContact");
@@ -724,8 +738,6 @@ public class Ringer {
         boolean hasExternalRinger = hasExternalRinger(call);
         timer.record("hasExternalRinger");
         // Don't do call waiting operations or vibration unless these are false.
-        boolean isTheaterModeOn = mSystemSettingsUtil.isTheaterModeOn(mContext);
-        timer.record("isTheaterModeOn");
         boolean letDialerHandleRinging = mInCallController.doesConnectedDialerSupportRinging(
                 call.getAssociatedUser());
         timer.record("letDialerHandleRinging");
@@ -734,15 +746,24 @@ public class Ringer {
         timer.record("isWorkProfileInQuietMode");
 
         Log.i(this, "startRinging timings: " + timer);
-        boolean endEarly = isTheaterModeOn || letDialerHandleRinging || isSelfManaged ||
-                hasExternalRinger || isSilentRingingRequested || isWorkProfileInQuietMode;
+        boolean endEarly =
+                letDialerHandleRinging
+                        || isSelfManaged
+                        || hasExternalRinger
+                        || isSilentRingingRequested
+                        || isWorkProfileInQuietMode;
 
         if (endEarly) {
-            Log.i(this, "Ending early -- isTheaterModeOn=%s, letDialerHandleRinging=%s, " +
-                            "isSelfManaged=%s, hasExternalRinger=%s, silentRingingRequested=%s, " +
-                            "isWorkProfileInQuietMode=%s",
-                    isTheaterModeOn, letDialerHandleRinging, isSelfManaged, hasExternalRinger,
-                    isSilentRingingRequested, isWorkProfileInQuietMode);
+            Log.i(
+                    this,
+                    "Ending early -- letDialerHandleRinging=%s, isSelfManaged=%s, "
+                            + "hasExternalRinger=%s, silentRingingRequested=%s, "
+                            + "isWorkProfileInQuietMode=%s",
+                    letDialerHandleRinging,
+                    isSelfManaged,
+                    hasExternalRinger,
+                    isSilentRingingRequested,
+                    isWorkProfileInQuietMode);
         }
 
         // Acquire audio focus under any of the following conditions:
diff --git a/src/com/android/server/telecom/RingtoneFactory.java b/src/com/android/server/telecom/RingtoneFactory.java
index 16fa0c4cd..c740c2461 100644
--- a/src/com/android/server/telecom/RingtoneFactory.java
+++ b/src/com/android/server/telecom/RingtoneFactory.java
@@ -127,24 +127,6 @@ public class RingtoneFactory {
             .build();
     }
 
-    /** Returns a ringtone to be used when ringer is not audible for the incoming call. */
-    @Nullable
-    public Pair<Uri, Ringtone> getHapticOnlyRingtone() {
-        // Initializing ringtones on the main thread can deadlock
-        ThreadUtil.checkNotOnMainThread();
-        Uri ringtoneUri = Uri.parse("file://" + mContext.getString(
-                com.android.internal.R.string.config_defaultRingtoneVibrationSound));
-        AudioAttributes audioAttrs = getDefaultRingtoneAudioAttributes(
-            /* hapticChannelsMuted */ false);
-        Ringtone ringtone = RingtoneManager.getRingtone(
-                mContext, ringtoneUri, /* volumeShaperConfig */ null, audioAttrs);
-        if (ringtone != null) {
-            // Make sure the sound is muted.
-            ringtone.setVolume(0);
-        }
-        return new Pair(ringtoneUri, ringtone);
-    }
-
     private Context getWorkProfileContextForUser(UserHandle userHandle) {
         // UserManager.getUserProfiles returns the enabled profiles along with the context user's
         // handle itself (so we must filter out the user).
diff --git a/src/com/android/server/telecom/SystemSettingsUtil.java b/src/com/android/server/telecom/SystemSettingsUtil.java
index cdd14df21..d846cce20 100644
--- a/src/com/android/server/telecom/SystemSettingsUtil.java
+++ b/src/com/android/server/telecom/SystemSettingsUtil.java
@@ -35,11 +35,6 @@ public class SystemSettingsUtil {
     private static final String RAMPING_RINGER_AUDIO_COUPLED_VIBRATION_ENABLED =
             "ramping_ringer_audio_coupled_vibration_enabled";
 
-    public boolean isTheaterModeOn(Context context) {
-        return Settings.Global.getInt(context.getContentResolver(), Settings.Global.THEATER_MODE_ON,
-                0) == 1;
-    }
-
     public boolean isRingVibrationEnabled(Context context) {
         // VIBRATE_WHEN_RINGING setting was deprecated, only RING_VIBRATION_INTENSITY controls the
         // ringtone vibrations on/off state now. Ramping ringer should only be applied when ring
diff --git a/src/com/android/server/telecom/TelecomServiceImpl.java b/src/com/android/server/telecom/TelecomServiceImpl.java
index 20320f234..b8141bf95 100644
--- a/src/com/android/server/telecom/TelecomServiceImpl.java
+++ b/src/com/android/server/telecom/TelecomServiceImpl.java
@@ -2555,7 +2555,8 @@ public class TelecomServiceImpl {
         }
 
         @Override
-        public void setTestPhoneAcctSuggestionComponent(String flattenedComponentName) {
+        public void setTestPhoneAcctSuggestionComponent(String flattenedComponentName,
+                UserHandle userHandle) {
             try {
                 Log.startSession("TSI.sPASA");
                 enforceModifyPermission();
@@ -2565,6 +2566,7 @@ public class TelecomServiceImpl {
                 }
                 synchronized (mLock) {
                     PhoneAccountSuggestionHelper.setOverrideServiceName(flattenedComponentName);
+                    PhoneAccountSuggestionHelper.setOverrideUserHandle(userHandle);
                 }
             } finally {
                 Log.endSession();
diff --git a/src/com/android/server/telecom/TelecomShellCommand.java b/src/com/android/server/telecom/TelecomShellCommand.java
index 557002c3e..11ceb26b6 100644
--- a/src/com/android/server/telecom/TelecomShellCommand.java
+++ b/src/com/android/server/telecom/TelecomShellCommand.java
@@ -341,7 +341,8 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
 
     private void runSetTestPhoneAcctSuggestionComponent() throws RemoteException {
         final String componentName = getNextArg();
-        mTelecomService.setTestPhoneAcctSuggestionComponent(componentName);
+        final UserHandle userHandle = getUserHandleFromArgs();
+        mTelecomService.setTestPhoneAcctSuggestionComponent(componentName, userHandle);
     }
 
     private void runSetUserSelectedOutgoingPhoneAccount() throws RemoteException {
@@ -457,6 +458,22 @@ public class TelecomShellCommand extends BasicShellCommandHandler {
         mTelecomService.requestLogMark(message);
     }
 
+    private UserHandle getUserHandleFromArgs() throws RemoteException {
+        if (TextUtils.isEmpty(peekNextArg())) {
+            return null;
+        }
+        final String userSnInStr = getNextArgRequired();
+        UserHandle userHandle;
+        try {
+            final int userSn = Integer.parseInt(userSnInStr);
+            userHandle = UserHandle.of(getUserManager().getUserHandle(userSn));
+        } catch (NumberFormatException ex) {
+            Log.w(this, "getPhoneAccountHandleFromArgs - invalid user %s", userSnInStr);
+            throw new IllegalArgumentException ("Invalid user serial number " + userSnInStr);
+        }
+        return userHandle;
+    }
+
     private PhoneAccountHandle getPhoneAccountHandleFromArgs() throws RemoteException {
         if (TextUtils.isEmpty(peekNextArg())) {
             return null;
diff --git a/src/com/android/server/telecom/TelecomSystem.java b/src/com/android/server/telecom/TelecomSystem.java
index d7dcf3812..fd1053ff5 100644
--- a/src/com/android/server/telecom/TelecomSystem.java
+++ b/src/com/android/server/telecom/TelecomSystem.java
@@ -48,6 +48,7 @@ import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
 import com.android.server.telecom.components.UserCallIntentProcessor;
 import com.android.server.telecom.components.UserCallIntentProcessorFactory;
 import com.android.server.telecom.flags.FeatureFlags;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.ui.AudioProcessingNotification;
 import com.android.server.telecom.ui.CallStreamingNotification;
 import com.android.server.telecom.ui.DisconnectedCallNotifier;
@@ -285,7 +286,7 @@ public class TelecomSystem {
                             mContactsAsyncHelper, mLock);
 
             EmergencyCallHelper emergencyCallHelper = new EmergencyCallHelper(mContext,
-                    defaultDialerCache, timeoutsAdapter);
+                    defaultDialerCache, timeoutsAdapter, mFeatureFlags);
 
             InCallControllerFactory inCallControllerFactory = new InCallControllerFactory() {
                 @Override
@@ -373,9 +374,13 @@ public class TelecomSystem {
                             BugreportManager.class), timeoutsAdapter, mContext.getSystemService(
                             DropBoxManager.class), asyncTaskExecutor, clockProxy);
 
+            TelecomMetricsController metricsController = featureFlags.telecomMetricsSupport()
+                    ? TelecomMetricsController.make(mContext) : null;
+
             CallAnomalyWatchdog callAnomalyWatchdog = new CallAnomalyWatchdog(
                     Executors.newSingleThreadScheduledExecutor(),
-                    mLock, timeoutsAdapter, clockProxy, emergencyCallDiagnosticLogger);
+                    mLock, mFeatureFlags, timeoutsAdapter, clockProxy,
+                    emergencyCallDiagnosticLogger, metricsController);
 
             TransactionManager transactionManager = TransactionManager.getInstance();
 
@@ -427,7 +432,8 @@ public class TelecomSystem {
                     bluetoothDeviceManager,
                     featureFlags,
                     telephonyFlags,
-                    IncomingCallFilterGraph::new);
+                    IncomingCallFilterGraph::new,
+                    metricsController);
 
             mIncomingCallNotifier = incomingCallNotifier;
             incomingCallNotifier.setCallsManagerProxy(new IncomingCallNotifier.CallsManagerProxy() {
diff --git a/src/com/android/server/telecom/TransactionalServiceWrapper.java b/src/com/android/server/telecom/TransactionalServiceWrapper.java
index 50ef2e8f3..b73de2345 100644
--- a/src/com/android/server/telecom/TransactionalServiceWrapper.java
+++ b/src/com/android/server/telecom/TransactionalServiceWrapper.java
@@ -626,7 +626,8 @@ public class TransactionalServiceWrapper implements
         }
     }
 
-    public void onEvent(Call call, String event, Bundle extras) {
+    @Override
+    public void sendCallEvent(Call call, String event, Bundle extras) {
         if (call != null) {
             try {
                 mICallEventCallback.onEvent(call.getId(), event, extras);
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
index 3c97d4190..0f27dad17 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothDeviceManager.java
@@ -430,7 +430,8 @@ public class BluetoothDeviceManager {
                 return mBluetoothHeadset;
             } catch (TimeoutException | InterruptedException | ExecutionException e) {
                 // ignore
-                Log.w(this, "Acquire BluetoothHeadset service failed due to: " + e);
+                Log.w(this, "getBluetoothHeadset: Acquire BluetoothHeadset service failed due to: "
+                        + e);
                 return null;
             }
         } else {
@@ -483,7 +484,7 @@ public class BluetoothDeviceManager {
             LinkedHashMap<String, BluetoothDevice> targetDeviceMap;
             if (deviceType == DEVICE_TYPE_LE_AUDIO) {
                 if (mBluetoothLeAudioService == null) {
-                    Log.w(this, "LE audio service null when receiving device added broadcast");
+                    Log.w(this, "onDeviceConnected: LE audio service null");
                     return;
                 }
                 /* Check if group is known. */
@@ -497,7 +498,7 @@ public class BluetoothDeviceManager {
                 targetDeviceMap = mLeAudioDevicesByAddress;
             } else if (deviceType == DEVICE_TYPE_HEARING_AID) {
                 if (mBluetoothHearingAid == null) {
-                    Log.w(this, "Hearing aid service null when receiving device added broadcast");
+                    Log.w(this, "onDeviceConnected: Hearing aid service null");
                     return;
                 }
                 long hiSyncId = mBluetoothHearingAid.getHiSyncId(device);
@@ -505,18 +506,18 @@ public class BluetoothDeviceManager {
                 targetDeviceMap = mHearingAidDevicesByAddress;
             } else if (deviceType == DEVICE_TYPE_HEADSET) {
                 if (getBluetoothHeadset() == null) {
-                    Log.w(this, "Headset service null when receiving device added broadcast");
+                    Log.w(this, "onDeviceConnected: Headset service null");
                     return;
                 }
                 targetDeviceMap = mHfpDevicesByAddress;
             } else {
-                Log.w(this, "Device: " + device.getAddress() + " with invalid type: "
-                            + getDeviceTypeString(deviceType));
+                Log.w(this, "onDeviceConnected: Device: %s; invalid type %s", device.getAddress(),
+                        getDeviceTypeString(deviceType));
                 return;
             }
             if (!targetDeviceMap.containsKey(device.getAddress())) {
-                Log.i(this, "Adding device with address: " + device + " and devicetype="
-                        + getDeviceTypeString(deviceType));
+                Log.i(this, "onDeviceConnected: Adding device with address: %s and devicetype=%s",
+                        device, getDeviceTypeString(deviceType));
                 targetDeviceMap.put(device.getAddress(), device);
                 mBluetoothRouteManager.onDeviceAdded(device.getAddress());
             }
@@ -542,13 +543,13 @@ public class BluetoothDeviceManager {
             } else if (deviceType == DEVICE_TYPE_HEADSET) {
                 targetDeviceMap = mHfpDevicesByAddress;
             } else {
-                Log.w(this, "Device: " + device.getAddress() + " with invalid type: "
-                            + getDeviceTypeString(deviceType));
+                Log.w(this, "onDeviceDisconnected: Device: %s with invalid type: %s",
+                        device.getAddress(), getDeviceTypeString(deviceType));
                 return;
             }
             if (targetDeviceMap.containsKey(device.getAddress())) {
-                Log.i(this, "Removing device with address: " + device + " and devicetype="
-                        + getDeviceTypeString(deviceType));
+                Log.i(this, "onDeviceDisconnected: Removing device with address: %s, devicetype=%s",
+                        device, getDeviceTypeString(deviceType));
                 targetDeviceMap.remove(device.getAddress());
                 mBluetoothRouteManager.onDeviceLost(device.getAddress());
             }
@@ -569,9 +570,10 @@ public class BluetoothDeviceManager {
     public int disconnectSco() {
         int result = BluetoothStatusCodes.ERROR_UNKNOWN;
         if (getBluetoothHeadset() == null) {
-            Log.w(this, "Trying to disconnect audio but no headset service exists.");
+            Log.w(this, "disconnectSco: Trying to disconnect audio but no headset service exists.");
         } else {
             result = mBluetoothHeadset.disconnectAudio();
+            Log.i(this, "disconnectSco: BluetoothHeadset#disconnectAudio()=%b", result);
         }
         return result;
     }
@@ -605,6 +607,7 @@ public class BluetoothDeviceManager {
         if (audioDeviceInfo != null && audioDeviceInfo.getType()
                 == AudioDeviceInfo.TYPE_BLE_HEADSET) {
             mBluetoothRouteManager.onAudioLost(audioDeviceInfo.getAddress());
+            Log.i(this, "clearLeAudioCommunicationDevice: audioManager#clearCommunicationDevice");
             mAudioManager.clearCommunicationDevice();
         }
     }
@@ -629,32 +632,33 @@ public class BluetoothDeviceManager {
         AudioDeviceInfo audioDeviceInfo = mAudioManager.getCommunicationDevice();
         if (audioDeviceInfo != null && audioDeviceInfo.getType()
                 == AudioDeviceInfo.TYPE_HEARING_AID) {
+            Log.i(this, "clearHearingAidCommunicationDevice: "
+                    + "audioManager#clearCommunicationDevice");
             mAudioManager.clearCommunicationDevice();
         }
     }
 
     public boolean setLeAudioCommunicationDevice() {
-        Log.i(this, "setLeAudioCommunicationDevice");
-
         if (mLeAudioSetAsCommunicationDevice) {
-            Log.i(this, "setLeAudioCommunicationDevice already set");
+            Log.i(this, "setLeAudioCommunicationDevice: already set");
             return true;
         }
 
         if (mAudioManager == null) {
-            Log.w(this, " mAudioManager is null");
+            Log.w(this, "setLeAudioCommunicationDevice: mAudioManager is null");
             return false;
         }
 
         AudioDeviceInfo bleHeadset = null;
         List<AudioDeviceInfo> devices = mAudioManager.getAvailableCommunicationDevices();
         if (devices.size() == 0) {
-            Log.w(this, " No communication devices available.");
+            Log.w(this, "setLeAudioCommunicationDevice: No communication devices available.");
             return false;
         }
 
         for (AudioDeviceInfo device : devices) {
-            Log.i(this, " Available device type:  " + device.getType());
+            Log.d(this, "setLeAudioCommunicationDevice: Available device type:  "
+                    + device.getType());
             if (device.getType() == AudioDeviceInfo.TYPE_BLE_HEADSET) {
                 bleHeadset = device;
                 break;
@@ -662,7 +666,7 @@ public class BluetoothDeviceManager {
         }
 
         if (bleHeadset == null) {
-            Log.w(this, " No bleHeadset device available");
+            Log.w(this, "setLeAudioCommunicationDevice: No bleHeadset device available");
             return false;
         }
 
@@ -672,9 +676,11 @@ public class BluetoothDeviceManager {
         // Turn BLE_OUT_HEADSET ON.
         boolean result = mAudioManager.setCommunicationDevice(bleHeadset);
         if (!result) {
-            Log.w(this, " Could not set bleHeadset device");
+            Log.w(this, "setLeAudioCommunicationDevice: AudioManager#setCommunicationDevice(%s)=%b;"
+                    + " Could not set bleHeadset device", bleHeadset, result);
         } else {
-            Log.i(this, " bleHeadset device set");
+            Log.i(this, "setLeAudioCommunicationDevice: "
+                    + "AudioManager#setCommunicationDevice(%s)=%b", bleHeadset, result);
             mBluetoothRouteManager.onAudioOn(bleHeadset.getAddress());
             mLeAudioSetAsCommunicationDevice = true;
             mLeAudioDevice = bleHeadset.getAddress();
@@ -683,27 +689,26 @@ public class BluetoothDeviceManager {
     }
 
     public boolean setHearingAidCommunicationDevice() {
-        Log.i(this, "setHearingAidCommunicationDevice");
-
         if (mHearingAidSetAsCommunicationDevice) {
-            Log.i(this, "mHearingAidSetAsCommunicationDevice already set");
+            Log.i(this, "setHearingAidCommunicationDevice: already set");
             return true;
         }
 
         if (mAudioManager == null) {
-            Log.w(this, " mAudioManager is null");
+            Log.w(this, "setHearingAidCommunicationDevice: mAudioManager is null");
             return false;
         }
 
         AudioDeviceInfo hearingAid = null;
         List<AudioDeviceInfo> devices = mAudioManager.getAvailableCommunicationDevices();
         if (devices.size() == 0) {
-            Log.w(this, " No communication devices available.");
+            Log.w(this, "setHearingAidCommunicationDevice: No communication devices available.");
             return false;
         }
 
         for (AudioDeviceInfo device : devices) {
-            Log.i(this, " Available device type:  " + device.getType());
+            Log.d(this, "setHearingAidCommunicationDevice: Available device type: "
+                    + device.getType());
             if (device.getType() == AudioDeviceInfo.TYPE_HEARING_AID) {
                 hearingAid = device;
                 break;
@@ -711,7 +716,7 @@ public class BluetoothDeviceManager {
         }
 
         if (hearingAid == null) {
-            Log.w(this, " No hearingAid device available");
+            Log.w(this, "setHearingAidCommunicationDevice: No hearingAid device available");
             return false;
         }
 
@@ -721,9 +726,12 @@ public class BluetoothDeviceManager {
         // Turn hearing aid ON.
         boolean result = mAudioManager.setCommunicationDevice(hearingAid);
         if (!result) {
-            Log.w(this, " Could not set hearingAid device");
+            Log.w(this, "setHearingAidCommunicationDevice: "
+                    + "AudioManager#setCommunicationDevice(%s)=%b; Could not set HA device",
+                    hearingAid, result);
         } else {
-            Log.i(this, " hearingAid device set");
+            Log.i(this, "setHearingAidCommunicationDevice: "
+                            + "AudioManager#setCommunicationDevice(%s)=%b", hearingAid, result);
             mHearingAidDevice = hearingAid.getAddress();
             mHearingAidSetAsCommunicationDevice = true;
         }
@@ -734,66 +742,77 @@ public class BluetoothDeviceManager {
         AudioDeviceInfo deviceInfo = null;
         List<AudioDeviceInfo> devices = mAudioManager.getAvailableCommunicationDevices();
         if (devices.size() == 0) {
-            Log.w(this, " No communication devices available.");
+            Log.w(this, "setCommunicationDeviceForAddress: No communication devices available.");
             return false;
         }
 
         for (AudioDeviceInfo device : devices) {
-            Log.i(this, " Available device type:  " + device.getType());
+            Log.d(this, "setCommunicationDeviceForAddress: Available device type: "
+                    + device.getType());
             if (device.getAddress().equals(address)) {
                 deviceInfo = device;
                 break;
             }
         }
 
-        if (!mAudioManager.getCommunicationDevice().equals(deviceInfo)) {
-            return mAudioManager.setCommunicationDevice(deviceInfo);
+        if (deviceInfo == null) {
+            Log.w(this, "setCommunicationDeviceForAddress: Device %s not found.", address);
+            return false;
+        }
+        if (mAudioManager.getCommunicationDevice().equals(deviceInfo)) {
+            Log.i(this, "setCommunicationDeviceForAddress: Device %s already active.", address);
+            return true;
         }
-        return true;
+        boolean success = mAudioManager.setCommunicationDevice(deviceInfo);
+        Log.i(this, "setCommunicationDeviceForAddress: "
+                + "AudioManager#setCommunicationDevice(%s)=%b", deviceInfo, success);
+        return success;
     }
 
     // Connect audio to the bluetooth device at address, checking to see whether it's
     // le audio, hearing aid or a HFP device, and using the proper BT API.
     public boolean connectAudio(String address, boolean switchingBtDevices) {
         int callProfile = BluetoothProfile.LE_AUDIO;
-        Log.i(this, "Telecomm connecting audio to device: " + address);
         BluetoothDevice device = null;
         if (mLeAudioDevicesByAddress.containsKey(address)) {
-            Log.i(this, "Telecomm found LE Audio device for address: " + address);
+            Log.i(this, "connectAudio: found LE Audio device for address: %s", address);
             if (mBluetoothLeAudioService == null) {
-                Log.w(this, "Attempting to turn on audio when the le audio service is null");
+                Log.w(this, "connectAudio: Attempting to turn on audio when the le audio service "
+                        + "is null");
                 return false;
             }
             device = mLeAudioDevicesByAddress.get(address);
             callProfile = BluetoothProfile.LE_AUDIO;
         } else if (mHearingAidDevicesByAddress.containsKey(address)) {
-            Log.i(this, "Telecomm found hearing aid device for address: " + address);
             if (mBluetoothHearingAid == null) {
-                Log.w(this, "Attempting to turn on audio when the hearing aid service is null");
+                Log.w(this, "connectAudio: Attempting to turn on audio when the hearing aid "
+                        + "service is null");
                 return false;
             }
+            Log.i(this, "connectAudio: found hearing aid device for address: %s", address);
             device = mHearingAidDevicesByAddress.get(address);
             callProfile = BluetoothProfile.HEARING_AID;
         } else if (mHfpDevicesByAddress.containsKey(address)) {
-            Log.i(this, "Telecomm found HFP device for address: " + address);
             if (getBluetoothHeadset() == null) {
-                Log.w(this, "Attempting to turn on audio when the headset service is null");
+                Log.w(this, "connectAudio: Attempting to turn on audio when the headset service "
+                        + "is null");
                 return false;
             }
+            Log.i(this, "connectAudio: found HFP device for address: %s", address);
             device = mHfpDevicesByAddress.get(address);
             callProfile = BluetoothProfile.HEADSET;
         }
 
         if (device == null) {
-            Log.w(this, "No active profiles for Bluetooth address=" + address);
+            Log.w(this, "No active profiles for Bluetooth address: %s", address);
             return false;
         }
 
         Bundle preferredAudioProfiles = mBluetoothAdapter.getPreferredAudioProfiles(device);
         if (preferredAudioProfiles != null && !preferredAudioProfiles.isEmpty()
             && preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX) != 0) {
-            Log.i(this, "Preferred duplex profile for device=" + address + " is "
-                + preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX));
+            Log.i(this, "connectAudio: Preferred duplex profile for device=% is %d", address,
+                preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX));
             callProfile = preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
         }
 
@@ -830,20 +849,24 @@ public class BluetoothDeviceManager {
             boolean success = mBluetoothAdapter.setActiveDevice(device,
                 BluetoothAdapter.ACTIVE_DEVICE_PHONE_CALL);
             if (!success) {
-                Log.w(this, "Couldn't set active device to %s", address);
+                Log.w(this, "connectAudio: Couldn't set active device to %s", address);
                 return false;
             }
+            Log.i(this, "connectAudio: BluetoothAdapter#setActiveDevice(%s)", address);
             if (getBluetoothHeadset() != null) {
                 int scoConnectionRequest = mBluetoothHeadset.connectAudio();
+                Log.i(this, "connectAudio: BluetoothHeadset#connectAudio()=%d",
+                        scoConnectionRequest);
                 return scoConnectionRequest == BluetoothStatusCodes.SUCCESS ||
                         scoConnectionRequest
                                 == BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_CONNECTED;
             } else {
-                Log.w(this, "Couldn't find bluetooth headset service");
+                Log.w(this, "connectAudio: Couldn't find bluetooth headset service");
                 return false;
             }
         } else {
-            Log.w(this, "Attempting to turn on audio for a disconnected device");
+            Log.w(this, "connectAudio: Attempting to turn on audio for disconnected device %s",
+                    address);
             return false;
         }
     }
@@ -866,8 +889,8 @@ public class BluetoothDeviceManager {
         Bundle preferredAudioProfiles = mBluetoothAdapter.getPreferredAudioProfiles(device);
         if (preferredAudioProfiles != null && !preferredAudioProfiles.isEmpty()
                 && preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX) != 0) {
-            Log.i(this, "Preferred duplex profile for device=" + address + " is "
-                    + preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX));
+            Log.i(this, "connectAudio: Preferred duplex profile for device=%s is %d", address,
+                    preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX));
             callProfile = preferredAudioProfiles.getInt(BluetoothAdapter.AUDIO_MODE_DUPLEX);
         }
 
@@ -878,20 +901,23 @@ public class BluetoothDeviceManager {
             boolean success = mBluetoothAdapter.setActiveDevice(device,
                     BluetoothAdapter.ACTIVE_DEVICE_PHONE_CALL);
             if (!success) {
-                Log.w(this, "Couldn't set active device to %s", address);
+                Log.w(this, "connectAudio: Couldn't set active device to %s", address);
                 return false;
             }
             if (getBluetoothHeadset() != null) {
                 int scoConnectionRequest = mBluetoothHeadset.connectAudio();
+                Log.i(this, "connectaudio: BluetoothHeadset#connectAudio()=%d",
+                        scoConnectionRequest);
                 return scoConnectionRequest == BluetoothStatusCodes.SUCCESS ||
                         scoConnectionRequest
                                 == BluetoothStatusCodes.ERROR_AUDIO_DEVICE_ALREADY_CONNECTED;
             } else {
-                Log.w(this, "Couldn't find bluetooth headset service");
+                Log.w(this, "connectAudio: Couldn't find bluetooth headset service");
                 return false;
             }
         } else {
-            Log.w(this, "Attempting to turn on audio for a disconnected device");
+            Log.w(this, "connectAudio: Attempting to turn on audio for a disconnected device %s",
+                    address);
             return false;
         }
     }
@@ -911,6 +937,8 @@ public class BluetoothDeviceManager {
         if (mBluetoothHearingAidActiveDeviceCache != null) {
             mBluetoothAdapter.setActiveDevice(mBluetoothHearingAidActiveDeviceCache,
                     BluetoothAdapter.ACTIVE_DEVICE_ALL);
+            Log.i(this, "restoreHearingAidDevice: BluetoothAdapter#setActiveDevice(%s)",
+                    mBluetoothHearingAidActiveDeviceCache.getAddress());
             mBluetoothHearingAidActiveDeviceCache = null;
         }
     }
@@ -923,7 +951,6 @@ public class BluetoothDeviceManager {
     }
 
     public boolean isInbandRingEnabled(BluetoothDevice bluetoothDevice) {
-        Log.i(this, "isInbandRingEnabled: device: " + bluetoothDevice);
         if (mBluetoothRouteManager.isCachedLeAudioDevice(bluetoothDevice)) {
             if (mBluetoothLeAudioService == null) {
                 Log.i(this, "isInbandRingingEnabled: no leaudio service available.");
@@ -936,7 +963,10 @@ public class BluetoothDeviceManager {
                 Log.i(this, "isInbandRingingEnabled: no headset service available.");
                 return false;
             }
-            return mBluetoothHeadset.isInbandRingingEnabled();
+            boolean isEnabled = mBluetoothHeadset.isInbandRingingEnabled();
+            Log.i(this, "isInbandRingEnabled: device: %s, isEnabled: %b", bluetoothDevice,
+                    isEnabled);
+            return isEnabled;
         }
     }
 
diff --git a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
index f76391cd9..cd52889d2 100644
--- a/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
+++ b/src/com/android/server/telecom/bluetooth/BluetoothStateReceiver.java
@@ -23,6 +23,8 @@ import static com.android.server.telecom.CallAudioRouteAdapter.BT_AUDIO_DISCONNE
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_DEVICE_ADDED;
 import static com.android.server.telecom.CallAudioRouteAdapter.BT_DEVICE_REMOVED;
 import static com.android.server.telecom.CallAudioRouteAdapter.PENDING_ROUTE_FAILED;
+import static com.android.server.telecom.CallAudioRouteAdapter.SWITCH_BASELINE_ROUTE;
+import static com.android.server.telecom.CallAudioRouteController.INCLUDE_BLUETOOTH_IN_BASELINE;
 import static com.android.server.telecom.bluetooth.BluetoothRouteManager.BT_AUDIO_IS_ON;
 import static com.android.server.telecom.bluetooth.BluetoothRouteManager.BT_AUDIO_LOST;
 
@@ -149,12 +151,23 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                 }
                 break;
             case BluetoothHeadset.STATE_AUDIO_DISCONNECTED:
-                if (Flags.useRefactoredAudioRouteSwitching()) {
+                if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                     CallAudioRouteController audioRouteController =
                             (CallAudioRouteController) mCallAudioRouteAdapter;
                     audioRouteController.setIsScoAudioConnected(false);
-                    mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
-                            device);
+                    if (audioRouteController.isPending()) {
+                        mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_AUDIO_DISCONNECTED, 0,
+                                device);
+                    } else {
+                        // Handle case where BT stack signals SCO disconnected but Telecom isn't
+                        // processing any pending routes. This explicitly addresses cf instances
+                        // where a remote device disconnects SCO. Telecom should ensure that audio
+                        // is properly routed in the UI.
+                        audioRouteController.getPendingAudioRoute()
+                                .setCommunicationDeviceType(AudioRoute.TYPE_INVALID);
+                        mCallAudioRouteAdapter.sendMessageWithSessionInfo(SWITCH_BASELINE_ROUTE,
+                                INCLUDE_BLUETOOTH_IN_BASELINE, device.getAddress());
+                    }
                 }  else {
                     mBluetoothRouteManager.sendMessage(BT_AUDIO_LOST, args);
                 }
@@ -195,7 +208,7 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
                 device.getAddress(), bluetoothHeadsetState);
 
         if (bluetoothHeadsetState == BluetoothProfile.STATE_CONNECTED) {
-            if (Flags.useRefactoredAudioRouteSwitching()) {
+            if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_DEVICE_ADDED,
                         audioRouteType, device);
             } else {
@@ -203,7 +216,7 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
             }
         } else if (bluetoothHeadsetState == BluetoothProfile.STATE_DISCONNECTED
                 || bluetoothHeadsetState == BluetoothProfile.STATE_DISCONNECTING) {
-            if (Flags.useRefactoredAudioRouteSwitching()) {
+            if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
                 mCallAudioRouteAdapter.sendMessageWithSessionInfo(BT_DEVICE_REMOVED,
                         audioRouteType, device);
             } else {
@@ -235,7 +248,7 @@ public class BluetoothStateReceiver extends BroadcastReceiver {
         Log.i(LOG_TAG, "Device %s is now the preferred BT device for %s", device,
                 BluetoothDeviceManager.getDeviceTypeString(deviceType));
 
-        if (Flags.useRefactoredAudioRouteSwitching()) {
+        if (mFeatureFlags.useRefactoredAudioRouteSwitching()) {
             CallAudioRouteController audioRouteController = (CallAudioRouteController)
                     mCallAudioRouteAdapter;
             if (device == null) {
diff --git a/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraph.java b/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraph.java
index d79e80ea6..a606a4d25 100644
--- a/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraph.java
+++ b/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraph.java
@@ -27,6 +27,7 @@ import com.android.server.telecom.LoggedHandlerExecutor;
 import com.android.server.telecom.LogUtils;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import java.util.ArrayList;
 import java.util.List;
@@ -55,6 +56,7 @@ public class IncomingCallFilterGraph {
     private CallFilteringResult mCurrentResult;
     private Context mContext;
     private Timeouts.Adapter mTimeoutsAdapter;
+    private final FeatureFlags mFeatureFlags;
 
     private class PostFilterTask {
         private final CallFilter mFilter;
@@ -84,11 +86,12 @@ public class IncomingCallFilterGraph {
     }
 
     public IncomingCallFilterGraph(Call call, CallFilterResultCallback listener, Context context,
-            Timeouts.Adapter timeoutsAdapter, TelecomSystem.SyncRoot lock) {
+            Timeouts.Adapter timeoutsAdapter, FeatureFlags featureFlags,
+            TelecomSystem.SyncRoot lock) {
         mListener = listener;
         mCall = call;
         mFiltersList = new ArrayList<>();
-
+        mFeatureFlags = featureFlags;
         mHandlerThread = new HandlerThread(TAG);
         mHandlerThread.start();
         mHandler = new Handler(mHandlerThread.getLooper());
@@ -121,8 +124,8 @@ public class IncomingCallFilterGraph {
             @Override
             public void loggedRun() {
                 if (!mFinished) {
-                    Log.i(this, "Graph timed out when performing filtering.");
                     Log.addEvent(mCall, LogUtils.Events.FILTERING_TIMED_OUT);
+                    mCurrentResult = onTimeoutCombineFinishedFilters(mFiltersList, mCurrentResult);
                     mListener.onCallFilteringComplete(mCall, mCurrentResult, true);
                     mFinished = true;
                     mHandlerThread.quit();
@@ -137,6 +140,28 @@ public class IncomingCallFilterGraph {
         }.prepare(), mTimeoutsAdapter.getCallScreeningTimeoutMillis(mContext.getContentResolver()));
     }
 
+    /**
+     * This helper takes all the call filters that were added to the graph, checks if filters have
+     * finished, and combines the results.
+     *
+     * @param filtersList   all the CallFilters that were added to the call
+     * @param currentResult the current call filter result
+     * @return CallFilterResult of the combined finished Filters.
+     */
+    private CallFilteringResult onTimeoutCombineFinishedFilters(
+            List<CallFilter> filtersList,
+            CallFilteringResult currentResult) {
+        if (!mFeatureFlags.checkCompletedFiltersOnTimeout()) {
+            return currentResult;
+        }
+        for (CallFilter filter : filtersList) {
+            if (filter.result != null) {
+                currentResult = currentResult.combine(filter.result);
+            }
+        }
+        return currentResult;
+    }
+
     private void scheduleFilter(CallFilter filter) {
         CallFilteringResult result = new CallFilteringResult.Builder()
                 .setShouldAllowCall(true)
@@ -147,6 +172,9 @@ public class IncomingCallFilterGraph {
                 .setDndSuppressed(false)
                 .build();
         for (CallFilter dependencyFilter : filter.getDependencies()) {
+            // When sequential nodes are completed, they are combined progressively.
+            // ex.) node_a --> node_b  --> node_c
+            // node_a will combine with node_b before starting node_c
             result = result.combine(dependencyFilter.getResult());
         }
         mCurrentResult = result;
diff --git a/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraphProvider.java b/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraphProvider.java
index 1501280de..4424178bf 100644
--- a/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraphProvider.java
+++ b/src/com/android/server/telecom/callfiltering/IncomingCallFilterGraphProvider.java
@@ -21,6 +21,7 @@ import android.content.Context;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.flags.FeatureFlags;
 
 /**
  * Interface to provide a {@link IncomingCallFilterGraph}. This class serve for unit test purpose
@@ -35,10 +36,13 @@ public interface IncomingCallFilterGraphProvider {
      * @param listener Callback object to trigger when filtering is done.
      * @param context An android context.
      * @param timeoutsAdapter Adapter to provide timeout value for call filtering.
+     * @param featureFlags Telecom flags
      * @param lock Telecom lock.
      * @return
      */
     IncomingCallFilterGraph createGraph(Call call, CallFilterResultCallback listener,
             Context context,
-            Timeouts.Adapter timeoutsAdapter, TelecomSystem.SyncRoot lock);
+            Timeouts.Adapter timeoutsAdapter,
+            FeatureFlags featureFlags,
+            TelecomSystem.SyncRoot lock);
 }
diff --git a/src/com/android/server/telecom/metrics/ApiStats.java b/src/com/android/server/telecom/metrics/ApiStats.java
new file mode 100644
index 000000000..b37569f0d
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/ApiStats.java
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.TelecomStatsLog;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+public class ApiStats extends TelecomPulledAtom {
+
+    private static final String FILE_NAME = "api_stats";
+    private Map<ApiStatsKey, Integer> mApiStatsMap;
+
+    public ApiStats(@NonNull Context context, @NonNull Looper looper) {
+        super(context, looper);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public int getTag() {
+        return TELECOM_API_STATS;
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
+        if (mPulledAtoms.telecomApiStats.length != 0) {
+            Arrays.stream(mPulledAtoms.telecomApiStats).forEach(v -> data.add(
+                    TelecomStatsLog.buildStatsEvent(getTag(),
+                            v.getApiName(), v.getUid(), v.getApiResult(), v.getCount())));
+            return StatsManager.PULL_SUCCESS;
+        } else {
+            return StatsManager.PULL_SKIP;
+        }
+    }
+
+    @Override
+    protected synchronized void onLoad() {
+        if (mPulledAtoms.telecomApiStats != null) {
+            mApiStatsMap = new HashMap<>();
+            for (PulledAtomsClass.TelecomApiStats v : mPulledAtoms.telecomApiStats) {
+                mApiStatsMap.put(new ApiStatsKey(v.getApiName(), v.getUid(), v.getApiResult()),
+                        v.getCount());
+            }
+            mLastPulledTimestamps = mPulledAtoms.getTelecomApiStatsPullTimestampMillis();
+        }
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized void onAggregate() {
+        clearAtoms();
+        if (mApiStatsMap.isEmpty()) {
+            return;
+        }
+        mPulledAtoms.setTelecomApiStatsPullTimestampMillis(mLastPulledTimestamps);
+        mPulledAtoms.telecomApiStats =
+                new PulledAtomsClass.TelecomApiStats[mApiStatsMap.size()];
+        int[] index = new int[1];
+        mApiStatsMap.forEach((k, v) -> {
+            mPulledAtoms.telecomApiStats[index[0]] = new PulledAtomsClass.TelecomApiStats();
+            mPulledAtoms.telecomApiStats[index[0]].setApiName(k.mApiId);
+            mPulledAtoms.telecomApiStats[index[0]].setUid(k.mCallerUid);
+            mPulledAtoms.telecomApiStats[index[0]].setApiResult(k.mResult);
+            mPulledAtoms.telecomApiStats[index[0]].setCount(v);
+            index[0]++;
+        });
+        save(DELAY_FOR_PERSISTENT_MILLIS);
+    }
+
+    public void log(int apiId, int callerUid, int result) {
+        post(() -> {
+            ApiStatsKey key = new ApiStatsKey(apiId, callerUid, result);
+            mApiStatsMap.put(key, mApiStatsMap.getOrDefault(key, 0) + 1);
+            onAggregate();
+        });
+    }
+
+    static class ApiStatsKey {
+
+        int mApiId;
+        int mCallerUid;
+        int mResult;
+
+        ApiStatsKey(int apiId, int callerUid, int result) {
+            mApiId = apiId;
+            mCallerUid = callerUid;
+            mResult = result;
+        }
+
+        @Override
+        public boolean equals(Object other) {
+            if (this == other) {
+                return true;
+            }
+            if (other == null || !(other instanceof ApiStatsKey obj)) {
+                return false;
+            }
+            return this.mApiId == obj.mApiId && this.mCallerUid == obj.mCallerUid
+                    && this.mResult == obj.mResult;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mApiId, mCallerUid, mResult);
+        }
+
+        @Override
+        public String toString() {
+            return "[ApiStatsKey: mApiId=" + mApiId + ", mCallerUid=" + mCallerUid
+                    + ", mResult=" + mResult + "]";
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/metrics/AudioRouteStats.java b/src/com/android/server/telecom/metrics/AudioRouteStats.java
new file mode 100644
index 000000000..21624f1fa
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/AudioRouteStats.java
@@ -0,0 +1,354 @@
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.AudioRoute.TYPE_BLUETOOTH_HA;
+import static com.android.server.telecom.AudioRoute.TYPE_BLUETOOTH_LE;
+import static com.android.server.telecom.AudioRoute.TYPE_BLUETOOTH_SCO;
+import static com.android.server.telecom.AudioRoute.TYPE_DOCK;
+import static com.android.server.telecom.AudioRoute.TYPE_EARPIECE;
+import static com.android.server.telecom.AudioRoute.TYPE_SPEAKER;
+import static com.android.server.telecom.AudioRoute.TYPE_STREAMING;
+import static com.android.server.telecom.AudioRoute.TYPE_WIRED;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_BLUETOOTH;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_BLUETOOTH_LE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_EARPIECE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_HEARING_AID;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_PHONE_SPEAKER;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_UNSPECIFIED;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_WATCH_SPEAKER;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_WIRED_HEADSET;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_HEARING_AID;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_PHONE_SPEAKER;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_UNSPECIFIED;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_WATCH_SPEAKER;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_WIRED_HEADSET;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.os.Message;
+import android.os.SystemClock;
+import android.telecom.Log;
+import android.util.Pair;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.AudioRoute;
+import com.android.server.telecom.PendingAudioRoute;
+import com.android.server.telecom.TelecomStatsLog;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+public class AudioRouteStats extends TelecomPulledAtom {
+    @VisibleForTesting
+    public static final long THRESHOLD_REVERT_MS = 5000;
+    @VisibleForTesting
+    public static final int EVENT_REVERT_THRESHOLD_EXPIRED = EVENT_SUB_BASE + 1;
+    private static final String TAG = AudioRouteStats.class.getSimpleName();
+    private static final String FILE_NAME = "audio_route_stats";
+    private Map<AudioRouteStatsKey, AudioRouteStatsData> mAudioRouteStatsMap;
+    private Pair<AudioRouteStatsKey, long[]> mCur;
+    private boolean mIsOngoing;
+
+    public AudioRouteStats(@NonNull Context context, @NonNull Looper looper) {
+        super(context, looper);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public int getTag() {
+        return CALL_AUDIO_ROUTE_STATS;
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
+        if (mPulledAtoms.callAudioRouteStats.length != 0) {
+            Arrays.stream(mPulledAtoms.callAudioRouteStats).forEach(v -> data.add(
+                    TelecomStatsLog.buildStatsEvent(getTag(),
+                            v.getCallAudioRouteSource(), v.getCallAudioRouteDest(),
+                            v.getSuccess(), v.getRevert(), v.getCount(), v.getAverageLatencyMs())));
+            return StatsManager.PULL_SUCCESS;
+        } else {
+            return StatsManager.PULL_SKIP;
+        }
+    }
+
+    @Override
+    protected synchronized void onLoad() {
+        if (mPulledAtoms.callAudioRouteStats != null) {
+            mAudioRouteStatsMap = new HashMap<>();
+            for (PulledAtomsClass.CallAudioRouteStats v : mPulledAtoms.callAudioRouteStats) {
+                mAudioRouteStatsMap.put(new AudioRouteStatsKey(v.getCallAudioRouteSource(),
+                                v.getCallAudioRouteDest(), v.getSuccess(), v.getRevert()),
+                        new AudioRouteStatsData(v.getCount(), v.getAverageLatencyMs()));
+            }
+            mLastPulledTimestamps = mPulledAtoms.getCallAudioRouteStatsPullTimestampMillis();
+        }
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized void onAggregate() {
+        Log.d(TAG, "onAggregate: %s", mAudioRouteStatsMap);
+        clearAtoms();
+        if (mAudioRouteStatsMap.isEmpty()) {
+            return;
+        }
+        mPulledAtoms.setCallAudioRouteStatsPullTimestampMillis(mLastPulledTimestamps);
+        mPulledAtoms.callAudioRouteStats =
+                new PulledAtomsClass.CallAudioRouteStats[mAudioRouteStatsMap.size()];
+        int[] index = new int[1];
+        mAudioRouteStatsMap.forEach((k, v) -> {
+            mPulledAtoms.callAudioRouteStats[index[0]] = new PulledAtomsClass.CallAudioRouteStats();
+            mPulledAtoms.callAudioRouteStats[index[0]].setCallAudioRouteSource(k.mSource);
+            mPulledAtoms.callAudioRouteStats[index[0]].setCallAudioRouteDest(k.mDest);
+            mPulledAtoms.callAudioRouteStats[index[0]].setSuccess(k.mIsSuccess);
+            mPulledAtoms.callAudioRouteStats[index[0]].setRevert(k.mIsRevert);
+            mPulledAtoms.callAudioRouteStats[index[0]].setCount(v.mCount);
+            mPulledAtoms.callAudioRouteStats[index[0]].setAverageLatencyMs(v.mAverageLatency);
+            index[0]++;
+        });
+        save(DELAY_FOR_PERSISTENT_MILLIS);
+    }
+
+    @VisibleForTesting
+    public void log(int source, int target, boolean isSuccess, boolean isRevert, int latency) {
+        post(() -> onLog(new AudioRouteStatsKey(source, target, isSuccess, isRevert), latency));
+    }
+
+    public void onRouteEnter(PendingAudioRoute pendingRoute) {
+        int sourceType = convertAudioType(pendingRoute.getOrigRoute(), true);
+        int destType = convertAudioType(pendingRoute.getDestRoute(), false);
+        long curTime = SystemClock.elapsedRealtime();
+
+        post(() -> {
+            // Ignore the transition route
+            if (!mIsOngoing) {
+                mIsOngoing = true;
+                // Check if the previous route is reverted as the revert time has not been expired.
+                if (mCur != null) {
+                    if (destType == mCur.first.getSource() && curTime - mCur.second[0]
+                            < THRESHOLD_REVERT_MS) {
+                        mCur.first.setRevert(true);
+                    }
+                    if (mCur.second[1] < 0) {
+                        mCur.second[1] = curTime;
+                    }
+                    onLog();
+                }
+                mCur = new Pair<>(new AudioRouteStatsKey(sourceType, destType), new long[]{curTime,
+                        -1});
+                if (hasMessages(EVENT_REVERT_THRESHOLD_EXPIRED)) {
+                    // Only keep the latest event
+                    removeMessages(EVENT_REVERT_THRESHOLD_EXPIRED);
+                }
+                sendMessageDelayed(
+                        obtainMessage(EVENT_REVERT_THRESHOLD_EXPIRED), THRESHOLD_REVERT_MS);
+            }
+        });
+    }
+
+    public void onRouteExit(PendingAudioRoute pendingRoute, boolean isSuccess) {
+        // Check the dest type on the route exiting as it may be different as the enter
+        int destType = convertAudioType(pendingRoute.getDestRoute(), false);
+        long curTime = SystemClock.elapsedRealtime();
+        post(() -> {
+            if (mIsOngoing) {
+                mIsOngoing = false;
+                // Should not be null unless the route is not done before the revert timer expired.
+                if (mCur != null) {
+                    mCur.first.setDestType(destType);
+                    mCur.first.setSuccess(isSuccess);
+                    mCur.second[1] = curTime;
+                }
+            }
+        });
+    }
+
+    private void onLog() {
+        if (mCur != null) {
+            // Ignore the case if the source and dest types are same
+            if (mCur.first.mSource != mCur.first.mDest) {
+                // The route should have been done before the revert timer expires. Otherwise, it
+                // would be logged as the failed case
+                if (mCur.second[1] < 0) {
+                    mCur.second[1] = SystemClock.elapsedRealtime();
+                }
+                onLog(mCur.first, (int) (mCur.second[1] - mCur.second[0]));
+            }
+            mCur = null;
+        }
+    }
+
+    private void onLog(AudioRouteStatsKey key, int latency) {
+        AudioRouteStatsData data = mAudioRouteStatsMap.computeIfAbsent(key,
+                k -> new AudioRouteStatsData(0, 0));
+        data.add(latency);
+        onAggregate();
+    }
+
+    private int convertAudioType(AudioRoute route, boolean isSource) {
+        if (route != null) {
+            switch (route.getType()) {
+                case TYPE_EARPIECE:
+                    return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE
+                            : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_EARPIECE;
+                case TYPE_WIRED:
+                    return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_WIRED_HEADSET
+                            : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_WIRED_HEADSET;
+                case TYPE_SPEAKER:
+                    return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_PHONE_SPEAKER
+                            : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_PHONE_SPEAKER;
+                case TYPE_BLUETOOTH_LE:
+                    return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE
+                            : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_BLUETOOTH_LE;
+                case TYPE_BLUETOOTH_SCO:
+                    if (isSource) {
+                        return route.isWatch()
+                                ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_WATCH_SPEAKER
+                                : CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH;
+                    } else {
+                        return route.isWatch()
+                                ? CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_WATCH_SPEAKER
+                                : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_BLUETOOTH;
+                    }
+                case TYPE_BLUETOOTH_HA:
+                    return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_HEARING_AID
+                            : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_HEARING_AID;
+                case TYPE_DOCK:
+                    // Reserved for the future
+                case TYPE_STREAMING:
+                    // Reserved for the future
+                default:
+                    break;
+            }
+        }
+
+        return isSource ? CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_UNSPECIFIED
+                : CALL_AUDIO_ROUTE_STATS__ROUTE_DEST__CALL_AUDIO_UNSPECIFIED;
+    }
+
+    @Override
+    public void handleMessage(Message msg) {
+        switch (msg.what) {
+            case EVENT_REVERT_THRESHOLD_EXPIRED:
+                onLog();
+                break;
+            default:
+                super.handleMessage(msg);
+        }
+    }
+
+    static class AudioRouteStatsKey {
+
+        final int mSource;
+        int mDest;
+        boolean mIsSuccess;
+        boolean mIsRevert;
+
+        AudioRouteStatsKey(int source, int dest) {
+            mSource = source;
+            mDest = dest;
+        }
+
+        AudioRouteStatsKey(int source, int dest, boolean isSuccess, boolean isRevert) {
+            mSource = source;
+            mDest = dest;
+            mIsSuccess = isSuccess;
+            mIsRevert = isRevert;
+        }
+
+        void setDestType(int dest) {
+            mDest = dest;
+        }
+
+        void setSuccess(boolean isSuccess) {
+            mIsSuccess = isSuccess;
+        }
+
+        void setRevert(boolean isRevert) {
+            mIsRevert = isRevert;
+        }
+
+        int getSource() {
+            return mSource;
+        }
+
+        @Override
+        public boolean equals(Object other) {
+            if (this == other) {
+                return true;
+            }
+            if (!(other instanceof AudioRouteStatsKey obj)) {
+                return false;
+            }
+            return this.mSource == obj.mSource && this.mDest == obj.mDest
+                    && this.mIsSuccess == obj.mIsSuccess && this.mIsRevert == obj.mIsRevert;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mSource, mDest, mIsSuccess, mIsRevert);
+        }
+
+        @Override
+        public String toString() {
+            return "[AudioRouteStatsKey: mSource=" + mSource + ", mDest=" + mDest
+                    + ", mIsSuccess=" + mIsSuccess + ", mIsRevert=" + mIsRevert + "]";
+        }
+    }
+
+    static class AudioRouteStatsData {
+
+        int mCount;
+        int mAverageLatency;
+
+        AudioRouteStatsData(int count, int averageLatency) {
+            mCount = count;
+            mAverageLatency = averageLatency;
+        }
+
+        void add(int latency) {
+            mCount++;
+            mAverageLatency += (latency - mAverageLatency) / mCount;
+        }
+
+        @Override
+        public String toString() {
+            return "[AudioRouteStatsData: mCount=" + mCount + ", mAverageLatency:"
+                    + mAverageLatency + "]";
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/metrics/CallStats.java b/src/com/android/server/telecom/metrics/CallStats.java
new file mode 100644
index 000000000..39b0e6d77
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/CallStats.java
@@ -0,0 +1,264 @@
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_MANAGED;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SELFMANAGED;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_UNKNOWN;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_VOIP_API;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_INCOMING;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_OUTGOING;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_UNKNOWN;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.telecom.Log;
+import android.telecom.PhoneAccount;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.Call;
+import com.android.server.telecom.TelecomStatsLog;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.HashSet;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+import java.util.Set;
+
+public class CallStats extends TelecomPulledAtom {
+    private static final String TAG = CallStats.class.getSimpleName();
+
+    private static final String FILE_NAME = "call_stats";
+    private final Set<String> mOngoingCallsWithoutMultipleAudioDevices = new HashSet<>();
+    private final Set<String> mOngoingCallsWithMultipleAudioDevices = new HashSet<>();
+    private Map<CallStatsKey, CallStatsData> mCallStatsMap;
+    private boolean mHasMultipleAudioDevices;
+
+    public CallStats(@NonNull Context context, @NonNull Looper looper) {
+        super(context, looper);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public int getTag() {
+        return CALL_STATS;
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
+        if (mPulledAtoms.callStats.length != 0) {
+            Arrays.stream(mPulledAtoms.callStats).forEach(v -> data.add(
+                    TelecomStatsLog.buildStatsEvent(getTag(),
+                            v.getCallDirection(), v.getExternalCall(), v.getEmergencyCall(),
+                            v.getMultipleAudioAvailable(), v.getAccountType(), v.getUid(),
+                            v.getCount(), v.getAverageDurationMs())));
+            return StatsManager.PULL_SUCCESS;
+        } else {
+            return StatsManager.PULL_SKIP;
+        }
+    }
+
+    @Override
+    protected synchronized void onLoad() {
+        if (mPulledAtoms.callStats != null) {
+            mCallStatsMap = new HashMap<>();
+            for (PulledAtomsClass.CallStats v : mPulledAtoms.callStats) {
+                mCallStatsMap.put(new CallStatsKey(v.getCallDirection(),
+                                v.getExternalCall(), v.getEmergencyCall(),
+                                v.getMultipleAudioAvailable(),
+                                v.getAccountType(), v.getUid()),
+                        new CallStatsData(v.getCount(), v.getAverageDurationMs()));
+            }
+            mLastPulledTimestamps = mPulledAtoms.getCallStatsPullTimestampMillis();
+        }
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized void onAggregate() {
+        Log.d(TAG, "onAggregate: %s", mCallStatsMap);
+        clearAtoms();
+        if (mCallStatsMap.isEmpty()) {
+            return;
+        }
+        mPulledAtoms.setCallStatsPullTimestampMillis(mLastPulledTimestamps);
+        mPulledAtoms.callStats = new PulledAtomsClass.CallStats[mCallStatsMap.size()];
+        int[] index = new int[1];
+        mCallStatsMap.forEach((k, v) -> {
+            mPulledAtoms.callStats[index[0]] = new PulledAtomsClass.CallStats();
+            mPulledAtoms.callStats[index[0]].setCallDirection(k.mDirection);
+            mPulledAtoms.callStats[index[0]].setExternalCall(k.mIsExternal);
+            mPulledAtoms.callStats[index[0]].setEmergencyCall(k.mIsEmergency);
+            mPulledAtoms.callStats[index[0]].setMultipleAudioAvailable(k.mIsMultipleAudioAvailable);
+            mPulledAtoms.callStats[index[0]].setAccountType(k.mAccountType);
+            mPulledAtoms.callStats[index[0]].setUid(k.mUid);
+            mPulledAtoms.callStats[index[0]].setCount(v.mCount);
+            mPulledAtoms.callStats[index[0]].setAverageDurationMs(v.mAverageDuration);
+            index[0]++;
+        });
+        save(DELAY_FOR_PERSISTENT_MILLIS);
+    }
+
+    public void log(int direction, boolean isExternal, boolean isEmergency,
+                    boolean isMultipleAudioAvailable, int accountType, int uid, int duration) {
+        post(() -> {
+            CallStatsKey key = new CallStatsKey(direction, isExternal, isEmergency,
+                    isMultipleAudioAvailable, accountType, uid);
+            CallStatsData data = mCallStatsMap.computeIfAbsent(key, k -> new CallStatsData(0, 0));
+            data.add(duration);
+            onAggregate();
+        });
+    }
+
+    public void onCallStart(Call call) {
+        post(() -> {
+            if (mHasMultipleAudioDevices) {
+                mOngoingCallsWithMultipleAudioDevices.add(call.getId());
+            } else {
+                mOngoingCallsWithoutMultipleAudioDevices.add(call.getId());
+            }
+        });
+    }
+
+    public void onCallEnd(Call call) {
+        final int duration = (int) (call.getAgeMillis());
+        post(() -> {
+            final boolean hasMultipleAudioDevices = mOngoingCallsWithMultipleAudioDevices.remove(
+                    call.getId());
+            final int direction = call.isIncoming() ? CALL_STATS__CALL_DIRECTION__DIR_INCOMING
+                    : (call.isOutgoing() ? CALL_STATS__CALL_DIRECTION__DIR_OUTGOING
+                    : CALL_STATS__CALL_DIRECTION__DIR_UNKNOWN);
+            final int accountType = getAccountType(call.getPhoneAccountFromHandle());
+            final int uid = call.getAssociatedUser().getIdentifier();
+            log(direction, call.isExternalCall(), call.isEmergencyCall(), hasMultipleAudioDevices,
+                    accountType, uid, duration);
+        });
+    }
+
+    private int getAccountType(PhoneAccount account) {
+        if (account.hasCapabilities(PhoneAccount.CAPABILITY_SELF_MANAGED)) {
+            return account.hasCapabilities(
+                    PhoneAccount.CAPABILITY_SUPPORTS_TRANSACTIONAL_OPERATIONS)
+                    ? CALL_STATS__ACCOUNT_TYPE__ACCOUNT_VOIP_API
+                    : CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SELFMANAGED;
+        }
+        if (account.hasCapabilities(PhoneAccount.CAPABILITY_CALL_PROVIDER)) {
+            return account.hasCapabilities(
+                    PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION)
+                    ? CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM
+                    : CALL_STATS__ACCOUNT_TYPE__ACCOUNT_MANAGED;
+        }
+        return CALL_STATS__ACCOUNT_TYPE__ACCOUNT_UNKNOWN;
+    }
+
+    public void onAudioDevicesChange(boolean hasMultipleAudioDevices) {
+        post(() -> {
+            if (mHasMultipleAudioDevices != hasMultipleAudioDevices) {
+                mHasMultipleAudioDevices = hasMultipleAudioDevices;
+                if (mHasMultipleAudioDevices) {
+                    mOngoingCallsWithMultipleAudioDevices.addAll(
+                            mOngoingCallsWithoutMultipleAudioDevices);
+                    mOngoingCallsWithoutMultipleAudioDevices.clear();
+                }
+            }
+        });
+    }
+
+    static class CallStatsKey {
+        final int mDirection;
+        final boolean mIsExternal;
+        final boolean mIsEmergency;
+        final boolean mIsMultipleAudioAvailable;
+        final int mAccountType;
+        final int mUid;
+
+        CallStatsKey(int direction, boolean isExternal, boolean isEmergency,
+                     boolean isMultipleAudioAvailable, int accountType, int uid) {
+            mDirection = direction;
+            mIsExternal = isExternal;
+            mIsEmergency = isEmergency;
+            mIsMultipleAudioAvailable = isMultipleAudioAvailable;
+            mAccountType = accountType;
+            mUid = uid;
+        }
+
+        @Override
+        public boolean equals(Object other) {
+            if (this == other) {
+                return true;
+            }
+            if (!(other instanceof CallStatsKey obj)) {
+                return false;
+            }
+            return this.mDirection == obj.mDirection && this.mIsExternal == obj.mIsExternal
+                    && this.mIsEmergency == obj.mIsEmergency
+                    && this.mIsMultipleAudioAvailable == obj.mIsMultipleAudioAvailable
+                    && this.mAccountType == obj.mAccountType && this.mUid == obj.mUid;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mDirection, mIsExternal, mIsEmergency, mIsMultipleAudioAvailable,
+                    mAccountType, mUid);
+        }
+
+        @Override
+        public String toString() {
+            return "[CallStatsKey: mDirection=" + mDirection + ", mIsExternal=" + mIsExternal
+                    + ", mIsEmergency=" + mIsEmergency + ", mIsMultipleAudioAvailable="
+                    + mIsMultipleAudioAvailable + ", mAccountType=" + mAccountType + ", mUid="
+                    + mUid + "]";
+        }
+    }
+
+    static class CallStatsData {
+
+        int mCount;
+        int mAverageDuration;
+
+        CallStatsData(int count, int averageDuration) {
+            mCount = count;
+            mAverageDuration = averageDuration;
+        }
+
+        void add(int duration) {
+            mCount++;
+            mAverageDuration += (duration - mAverageDuration) / mCount;
+        }
+
+        @Override
+        public String toString() {
+            return "[CallStatsData: mCount=" + mCount + ", mAverageDuration:" + mAverageDuration
+                    + "]";
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/metrics/ErrorStats.java b/src/com/android/server/telecom/metrics/ErrorStats.java
new file mode 100644
index 000000000..e4d0a51ca
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/ErrorStats.java
@@ -0,0 +1,143 @@
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.TelecomStatsLog;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import java.util.Arrays;
+import java.util.HashMap;
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+
+public class ErrorStats extends TelecomPulledAtom {
+
+    private static final String FILE_NAME = "error_stats";
+    private Map<ErrorStatsKey, Integer> mErrorStatsMap;
+
+    public ErrorStats(@NonNull Context context, @NonNull Looper looper) {
+        super(context, looper);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public int getTag() {
+        return TELECOM_ERROR_STATS;
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
+        if (mPulledAtoms.telecomErrorStats.length != 0) {
+            Arrays.stream(mPulledAtoms.telecomErrorStats).forEach(v -> data.add(
+                    TelecomStatsLog.buildStatsEvent(getTag(),
+                            v.getSubmoduleName(), v.getErrorName(), v.getCount())));
+            return StatsManager.PULL_SUCCESS;
+        } else {
+            return StatsManager.PULL_SKIP;
+        }
+    }
+
+    @Override
+    protected synchronized void onLoad() {
+        if (mPulledAtoms.telecomErrorStats != null) {
+            mErrorStatsMap = new HashMap<>();
+            for (PulledAtomsClass.TelecomErrorStats v : mPulledAtoms.telecomErrorStats) {
+                mErrorStatsMap.put(new ErrorStatsKey(v.getSubmoduleName(), v.getErrorName()),
+                        v.getCount());
+            }
+            mLastPulledTimestamps = mPulledAtoms.getTelecomErrorStatsPullTimestampMillis();
+        }
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    @Override
+    public synchronized void onAggregate() {
+        clearAtoms();
+        if (mErrorStatsMap.isEmpty()) {
+            return;
+        }
+        mPulledAtoms.setTelecomErrorStatsPullTimestampMillis(mLastPulledTimestamps);
+        mPulledAtoms.telecomErrorStats =
+                new PulledAtomsClass.TelecomErrorStats[mErrorStatsMap.size()];
+        int[] index = new int[1];
+        mErrorStatsMap.forEach((k, v) -> {
+            mPulledAtoms.telecomErrorStats[index[0]] = new PulledAtomsClass.TelecomErrorStats();
+            mPulledAtoms.telecomErrorStats[index[0]].setSubmoduleName(k.mModuleId);
+            mPulledAtoms.telecomErrorStats[index[0]].setErrorName(k.mErrorId);
+            mPulledAtoms.telecomErrorStats[index[0]].setCount(v);
+            index[0]++;
+        });
+        save(DELAY_FOR_PERSISTENT_MILLIS);
+    }
+
+    public void log(int moduleId, int errorId) {
+        post(() -> {
+            ErrorStatsKey key = new ErrorStatsKey(moduleId, errorId);
+            mErrorStatsMap.put(key, mErrorStatsMap.getOrDefault(key, 0) + 1);
+            onAggregate();
+        });
+    }
+
+    static class ErrorStatsKey {
+
+        final int mModuleId;
+        final int mErrorId;
+
+        ErrorStatsKey(int moduleId, int errorId) {
+            mModuleId = moduleId;
+            mErrorId = errorId;
+        }
+
+        @Override
+        public boolean equals(Object other) {
+            if (this == other) {
+                return true;
+            }
+            if (!(other instanceof ErrorStatsKey obj)) {
+                return false;
+            }
+            return this.mModuleId == obj.mModuleId && this.mErrorId == obj.mErrorId;
+        }
+
+        @Override
+        public int hashCode() {
+            return Objects.hash(mModuleId, mErrorId);
+        }
+
+        @Override
+        public String toString() {
+            return "[ErrorStatsKey: mModuleId=" + mModuleId + ", mErrorId=" + mErrorId + "]";
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/metrics/TelecomMetricsController.java b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
new file mode 100644
index 000000000..8903b0259
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/TelecomMetricsController.java
@@ -0,0 +1,132 @@
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
+package com.android.server.telecom.metrics;
+
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.HandlerThread;
+import android.telecom.Log;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import java.util.List;
+import java.util.Map;
+import java.util.Objects;
+import java.util.concurrent.ConcurrentHashMap;
+
+public class TelecomMetricsController implements StatsManager.StatsPullAtomCallback {
+
+    private static final String TAG = TelecomMetricsController.class.getSimpleName();
+
+    private final Context mContext;
+    private final HandlerThread mHandlerThread;
+    private final ConcurrentHashMap<Integer, TelecomPulledAtom> mStats = new ConcurrentHashMap<>();
+
+    private TelecomMetricsController(@NonNull Context context,
+                                     @NonNull HandlerThread handlerThread) {
+        mContext = context;
+        mHandlerThread = handlerThread;
+    }
+
+    @NonNull
+    public static TelecomMetricsController make(@NonNull Context context) {
+        Log.i(TAG, "TMC.iN1");
+        HandlerThread handlerThread = new HandlerThread(TAG);
+        handlerThread.start();
+        return make(context, handlerThread);
+    }
+
+    @VisibleForTesting
+    @NonNull
+    public static TelecomMetricsController make(@NonNull Context context,
+                                                @NonNull HandlerThread handlerThread) {
+        Log.i(TAG, "TMC.iN2");
+        Objects.requireNonNull(context);
+        Objects.requireNonNull(handlerThread);
+        return new TelecomMetricsController(context, handlerThread);
+    }
+
+    @NonNull
+    public ApiStats getApiStats() {
+        ApiStats stats = (ApiStats) mStats.get(TELECOM_API_STATS);
+        if (stats == null) {
+            stats = new ApiStats(mContext, mHandlerThread.getLooper());
+            registerAtom(stats.getTag(), stats);
+        }
+        return stats;
+    }
+
+    @NonNull
+    public AudioRouteStats getAudioRouteStats() {
+        AudioRouteStats stats = (AudioRouteStats) mStats.get(CALL_AUDIO_ROUTE_STATS);
+        if (stats == null) {
+            stats = new AudioRouteStats(mContext, mHandlerThread.getLooper());
+            registerAtom(stats.getTag(), stats);
+        }
+        return stats;
+    }
+
+    @NonNull
+    public CallStats getCallStats() {
+        CallStats stats = (CallStats) mStats.get(CALL_STATS);
+        if (stats == null) {
+            stats = new CallStats(mContext, mHandlerThread.getLooper());
+            registerAtom(stats.getTag(), stats);
+        }
+        return stats;
+    }
+
+    @NonNull
+    public ErrorStats getErrorStats() {
+        ErrorStats stats = (ErrorStats) mStats.get(TELECOM_ERROR_STATS);
+        if (stats == null) {
+            stats = new ErrorStats(mContext, mHandlerThread.getLooper());
+            registerAtom(stats.getTag(), stats);
+        }
+        return stats;
+    }
+
+    @Override
+    public int onPullAtom(final int atomTag, final List<StatsEvent> data) {
+        if (mStats.containsKey(atomTag)) {
+            return Objects.requireNonNull(mStats.get(atomTag)).pull(data);
+        }
+        return StatsManager.PULL_SKIP;
+    }
+
+    @VisibleForTesting
+    public Map<Integer, TelecomPulledAtom> getStats() {
+        return mStats;
+    }
+
+    @VisibleForTesting
+    public void registerAtom(int tag, TelecomPulledAtom atom) {
+        mStats.put(tag, atom);
+    }
+
+    public void destroy() {
+        mStats.clear();
+        mHandlerThread.quitSafely();
+    }
+}
diff --git a/src/com/android/server/telecom/metrics/TelecomPulledAtom.java b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
new file mode 100644
index 000000000..d6eb039a4
--- /dev/null
+++ b/src/com/android/server/telecom/metrics/TelecomPulledAtom.java
@@ -0,0 +1,135 @@
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
+package com.android.server.telecom.metrics;
+
+import android.annotation.NonNull;
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Handler;
+import android.os.Looper;
+import android.os.Message;
+import android.telecom.Log;
+import android.util.StatsEvent;
+
+import androidx.annotation.VisibleForTesting;
+
+import com.android.server.telecom.nano.PulledAtomsClass.PulledAtoms;
+
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.nio.file.Files;
+import java.nio.file.NoSuchFileException;
+import java.util.List;
+
+public abstract class TelecomPulledAtom extends Handler {
+    /**
+     * Min interval to persist the data.
+     */
+    protected static final int DELAY_FOR_PERSISTENT_MILLIS = 30000;
+    protected static final int EVENT_SUB_BASE = 1000;
+    private static final String TAG = TelecomPulledAtom.class.getSimpleName();
+    private static final long MIN_PULL_INTERVAL_MILLIS = 23L * 60 * 60 * 1000;
+    private static final int EVENT_SAVE = 1;
+    private final Context mContext;
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    public PulledAtoms mPulledAtoms;
+    protected long mLastPulledTimestamps;
+
+    protected TelecomPulledAtom(@NonNull Context context, @NonNull Looper looper) {
+        super(looper);
+        mContext = context;
+        mPulledAtoms = loadAtomsFromFile();
+        onLoad();
+    }
+
+    public synchronized int pull(final List<StatsEvent> data) {
+        long cur = System.currentTimeMillis();
+        if (cur - mLastPulledTimestamps < MIN_PULL_INTERVAL_MILLIS) {
+            return StatsManager.PULL_SKIP;
+        }
+        mLastPulledTimestamps = cur;
+        return onPull(data);
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    abstract public int getTag();
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    public abstract int onPull(List<StatsEvent> data);
+
+    protected abstract void onLoad();
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    public abstract void onAggregate();
+
+    public void onFlush() {
+        save(0);
+    }
+
+    protected abstract String getFileName();
+
+    private synchronized PulledAtoms loadAtomsFromFile() {
+        try {
+            return
+                    PulledAtoms.parseFrom(
+                            Files.readAllBytes(mContext.getFileStreamPath(getFileName()).toPath()));
+        } catch (NoSuchFileException e) {
+            Log.e(TAG, e, "the atom file not found");
+        } catch (IOException | NullPointerException e) {
+            Log.e(TAG, e, "cannot load/parse the atom file");
+        }
+        return makeNewPulledAtoms();
+    }
+
+    protected synchronized void clearAtoms() {
+        mPulledAtoms = makeNewPulledAtoms();
+    }
+
+    private synchronized void onSave() {
+        try (FileOutputStream stream = mContext.openFileOutput(getFileName(),
+                Context.MODE_PRIVATE)) {
+            Log.d(TAG, "save " + getTag());
+            stream.write(PulledAtoms.toByteArray(mPulledAtoms));
+        } catch (IOException e) {
+            Log.e(TAG, e, "cannot save the atom to file");
+        } catch (UnsupportedOperationException e) {
+            Log.e(TAG, e, "cannot open the file");
+        }
+    }
+
+    private PulledAtoms makeNewPulledAtoms() {
+        return new PulledAtoms();
+    }
+
+    @VisibleForTesting(otherwise = VisibleForTesting.PROTECTED)
+    public void save(int delayMillis) {
+        if (delayMillis > 0) {
+            if (!hasMessages(EVENT_SAVE)) {
+                sendMessageDelayed(obtainMessage(EVENT_SAVE), delayMillis);
+            }
+        } else {
+            onSave();
+        }
+    }
+
+    @Override
+    public void handleMessage(Message msg) {
+        if (msg.what == EVENT_SAVE) {
+            onSave();
+        }
+    }
+}
diff --git a/src/com/android/server/telecom/settings/BlockedNumbersUtil.java b/src/com/android/server/telecom/settings/BlockedNumbersUtil.java
index 3e1da17de..99c57466a 100644
--- a/src/com/android/server/telecom/settings/BlockedNumbersUtil.java
+++ b/src/com/android/server/telecom/settings/BlockedNumbersUtil.java
@@ -133,9 +133,12 @@ public final class BlockedNumbersUtil {
     public static boolean isEnhancedCallBlockingEnabledByPlatform(Context context) {
         CarrierConfigManager configManager = (CarrierConfigManager) context.getSystemService(
                 Context.CARRIER_CONFIG_SERVICE);
-        PersistableBundle carrierConfig = configManager.getConfig();
+        PersistableBundle carrierConfig = null;
+        if (configManager != null) {
+            carrierConfig = configManager.getConfig();
+        }
         if (carrierConfig == null) {
-            carrierConfig = configManager.getDefaultConfig();
+            carrierConfig = CarrierConfigManager.getDefaultConfig();
         }
         return carrierConfig.getBoolean(
                 CarrierConfigManager.KEY_SUPPORT_ENHANCED_CALL_BLOCKING_BOOL)
diff --git a/src/com/android/server/telecom/ui/NotificationChannelManager.java b/src/com/android/server/telecom/ui/NotificationChannelManager.java
index b3cb2c3c4..987b6b3ad 100644
--- a/src/com/android/server/telecom/ui/NotificationChannelManager.java
+++ b/src/com/android/server/telecom/ui/NotificationChannelManager.java
@@ -83,61 +83,62 @@ public class NotificationChannelManager {
         boolean vibration = false;
         Uri sound = silentRingtone;
         switch (channelId) {
-            case CHANNEL_ID_INCOMING_CALLS:
+            case CHANNEL_ID_INCOMING_CALLS -> {
                 name = context.getText(R.string.notification_channel_incoming_call);
                 importance = NotificationManager.IMPORTANCE_MAX;
                 canShowBadge = false;
                 lights = true;
                 vibration = false;
                 sound = silentRingtone;
-                break;
-            case CHANNEL_ID_MISSED_CALLS:
+            }
+            case CHANNEL_ID_MISSED_CALLS -> {
                 name = context.getText(R.string.notification_channel_missed_call);
                 importance = NotificationManager.IMPORTANCE_DEFAULT;
                 canShowBadge = true;
                 lights = true;
                 vibration = true;
                 sound = silentRingtone;
-                break;
-            case CHANNEL_ID_CALL_BLOCKING:
+            }
+            case CHANNEL_ID_CALL_BLOCKING -> {
                 name = context.getText(R.string.notification_channel_call_blocking);
                 importance = NotificationManager.IMPORTANCE_LOW;
                 canShowBadge = false;
                 lights = false;
                 vibration = false;
                 sound = null;
-                break;
-            case CHANNEL_ID_AUDIO_PROCESSING:
+            }
+            case CHANNEL_ID_AUDIO_PROCESSING -> {
                 name = context.getText(R.string.notification_channel_background_calls);
                 importance = NotificationManager.IMPORTANCE_LOW;
                 canShowBadge = false;
                 lights = false;
                 vibration = false;
                 sound = null;
-                break;
-            case CHANNEL_ID_DISCONNECTED_CALLS:
+            }
+            case CHANNEL_ID_DISCONNECTED_CALLS -> {
                 name = context.getText(R.string.notification_channel_disconnected_calls);
                 importance = NotificationManager.IMPORTANCE_DEFAULT;
                 canShowBadge = true;
                 lights = true;
                 vibration = true;
                 sound = silentRingtone;
-                break;
-            case CHANNEL_ID_IN_CALL_SERVICE_CRASH:
+            }
+            case CHANNEL_ID_IN_CALL_SERVICE_CRASH -> {
                 name = context.getText(R.string.notification_channel_in_call_service_crash);
                 importance = NotificationManager.IMPORTANCE_DEFAULT;
                 canShowBadge = true;
                 lights = true;
                 vibration = true;
                 sound = null;
-            case CHANNEL_ID_CALL_STREAMING:
+            }
+            case CHANNEL_ID_CALL_STREAMING -> {
                 name = context.getText(R.string.notification_channel_call_streaming);
                 importance = NotificationManager.IMPORTANCE_DEFAULT;
                 canShowBadge = false;
                 lights = false;
                 vibration = false;
                 sound = null;
-                break;
+            }
         }
 
         NotificationChannel channel = new NotificationChannel(channelId, name, importance);
diff --git a/src/com/android/server/telecom/voip/OutgoingCallTransaction.java b/src/com/android/server/telecom/voip/OutgoingCallTransaction.java
index 8c970db20..68ffecfed 100644
--- a/src/com/android/server/telecom/voip/OutgoingCallTransaction.java
+++ b/src/com/android/server/telecom/voip/OutgoingCallTransaction.java
@@ -114,6 +114,12 @@ public class OutgoingCallTransaction extends VoipCallTransaction {
                             Log.d(TAG, "processTransaction: call done. id=" + call.getId());
                         }
 
+                        if (mFeatureFlags.disconnectSelfManagedStuckStartupCalls()) {
+                            // set to dialing so the CallAnomalyWatchdog gives the VoIP calls 1
+                            // minute to timeout rather than 5 seconds.
+                            mCallsManager.markCallAsDialing(call);
+                        }
+
                         return CompletableFuture.completedFuture(
                                 new VoipCallTransactionResult(
                                         VoipCallTransactionResult.RESULT_SUCCEED,
diff --git a/tests/AndroidManifest.xml b/tests/AndroidManifest.xml
index 1c27b14b1..04dcef8a6 100644
--- a/tests/AndroidManifest.xml
+++ b/tests/AndroidManifest.xml
@@ -45,10 +45,13 @@
     <!-- Used to access PlatformCompat APIs -->
     <uses-permission android:name="android.permission.READ_COMPAT_CHANGE_CONFIG" />
     <uses-permission android:name="android.permission.LOG_COMPAT_CHANGE" />
-    
+
     <!-- Used to register NotificationListenerService -->
     <uses-permission android:name="android.permission.STATUS_BAR_SERVICE" />
 
+    <!-- Used to query the audio framework to determine if a notification sound should play. -->
+    <uses-permission android:name="android.permission.QUERY_AUDIO_STATE"/>
+
     <application android:label="@string/app_name"
                  android:debuggable="true">
         <uses-library android:name="android.test.runner" />
diff --git a/tests/src/com/android/server/telecom/tests/BasicCallTests.java b/tests/src/com/android/server/telecom/tests/BasicCallTests.java
index 7646c2d08..4bca30de1 100644
--- a/tests/src/com/android/server/telecom/tests/BasicCallTests.java
+++ b/tests/src/com/android/server/telecom/tests/BasicCallTests.java
@@ -1036,7 +1036,6 @@ public class BasicCallTests extends TelecomSystemTest {
         call.setTargetPhoneAccount(mPhoneAccountA1.getAccountHandle());
         assert(call.isVideoCallingSupportedByPhoneAccount());
         assertEquals(VideoProfile.STATE_BIDIRECTIONAL, call.getVideoState());
-        call.setIsCreateConnectionComplete(true);
     }
 
     /**
@@ -1060,7 +1059,6 @@ public class BasicCallTests extends TelecomSystemTest {
         call.setTargetPhoneAccount(mPhoneAccountA2.getAccountHandle());
         assert(!call.isVideoCallingSupportedByPhoneAccount());
         assertEquals(VideoProfile.STATE_AUDIO_ONLY, call.getVideoState());
-        call.setIsCreateConnectionComplete(true);
     }
 
     /**
diff --git a/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java b/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
index d5e903b8f..ac4a94e23 100644
--- a/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/BluetoothDeviceManagerTest.java
@@ -48,6 +48,7 @@ import android.os.Parcel;
 import androidx.test.filters.SmallTest;
 
 import com.android.server.telecom.CallAudioCommunicationDeviceTracker;
+import com.android.server.telecom.CallAudioRouteAdapter;
 import com.android.server.telecom.bluetooth.BluetoothDeviceManager;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
 import com.android.server.telecom.bluetooth.BluetoothStateReceiver;
@@ -138,6 +139,7 @@ public class BluetoothDeviceManagerTest extends TelecomTestCase {
 
         when(mSpeakerInfo.getType()).thenReturn(TYPE_BUILTIN_SPEAKER);
         when(mFeatureFlags.callAudioCommunicationDeviceRefactor()).thenReturn(false);
+        when(mFeatureFlags.useRefactoredAudioRouteSwitching()).thenReturn(false);
     }
 
     @Override
diff --git a/tests/src/com/android/server/telecom/tests/CallAnomalyWatchdogTest.java b/tests/src/com/android/server/telecom/tests/CallAnomalyWatchdogTest.java
index 86d24f96f..d608d0a50 100644
--- a/tests/src/com/android/server/telecom/tests/CallAnomalyWatchdogTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAnomalyWatchdogTest.java
@@ -45,6 +45,7 @@ import com.android.server.telecom.PhoneAccountRegistrar;
 import com.android.server.telecom.PhoneNumberUtilsAdapter;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.ui.ToastFactory;
 
 import org.junit.After;
@@ -90,6 +91,7 @@ public class CallAnomalyWatchdogTest extends TelecomTestCase {
     @Mock private AnomalyReporterAdapter mAnomalyReporterAdapter;
 
     @Mock private EmergencyCallDiagnosticLogger mMockEmergencyCallDiagnosticLogger;
+    @Mock private TelecomMetricsController mMockTelecomMetricsController;
 
     @Override
     @Before
@@ -122,7 +124,8 @@ public class CallAnomalyWatchdogTest extends TelecomTestCase {
         doReturn(new ComponentName(mContext, CallTest.class))
                 .when(mMockConnectionService).getComponentName();
         mCallAnomalyWatchdog = new CallAnomalyWatchdog(mTestScheduledExecutorService, mLock,
-                mTimeouts, mMockClockProxy, mMockEmergencyCallDiagnosticLogger);
+                mFeatureFlags, mTimeouts, mMockClockProxy, mMockEmergencyCallDiagnosticLogger,
+                mMockTelecomMetricsController);
         mCallAnomalyWatchdog.setAnomalyReporterAdapter(mAnomalyReporterAdapter);
         when(mMockCallsManager.getCurrentUserHandle()).thenReturn(UserHandle.CURRENT);
     }
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioManagerTest.java b/tests/src/com/android/server/telecom/tests/CallAudioManagerTest.java
index 1d641ba8b..d1a3eb6ce 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioManagerTest.java
@@ -53,6 +53,7 @@ import com.android.server.telecom.CallAudioRouteStateMachine;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.DtmfLocalTonePlayer;
+import com.android.server.telecom.InCallController;
 import com.android.server.telecom.InCallTonePlayer;
 import com.android.server.telecom.RingbackPlayer;
 import com.android.server.telecom.Ringer;
@@ -77,6 +78,7 @@ import java.util.stream.Collectors;
 @RunWith(JUnit4.class)
 public class CallAudioManagerTest extends TelecomTestCase {
     @Mock private CallAudioRouteStateMachine mCallAudioRouteStateMachine;
+    @Mock private InCallController mInCallController;
     @Mock private CallsManager mCallsManager;
     @Mock private CallAudioModeStateMachine mCallAudioModeStateMachine;
     @Mock private InCallTonePlayer.Factory mPlayerFactory;
@@ -103,6 +105,8 @@ public class CallAudioManagerTest extends TelecomTestCase {
             return mockInCallTonePlayer;
         }).when(mPlayerFactory).createPlayer(any(Call.class), anyInt());
         when(mCallsManager.getLock()).thenReturn(mLock);
+        when(mCallsManager.getInCallController()).thenReturn(mInCallController);
+        when(mInCallController.getBtBindingFuture(any(Call.class))).thenReturn(null);
         when(mFlags.ensureAudioModeUpdatesOnForegroundCallChange()).thenReturn(true);
         mCallAudioManager = new CallAudioManager(
                 mCallAudioRouteStateMachine,
diff --git a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
index 59473bd2b..ade2a2285 100644
--- a/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallAudioRouteControllerTest.java
@@ -43,6 +43,7 @@ import static com.android.server.telecom.CallAudioRouteAdapter.USER_SWITCH_SPEAK
 import static org.junit.Assert.assertEquals;
 import static org.junit.Assert.assertFalse;
 import static org.junit.Assert.assertTrue;
+import static org.mockito.ArgumentMatchers.anyBoolean;
 import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.anyString;
 import static org.mockito.ArgumentMatchers.nullable;
@@ -52,12 +53,16 @@ import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.eq;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.timeout;
+import static org.mockito.Mockito.times;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
 import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothDevice;
 import android.bluetooth.BluetoothLeAudio;
+import android.content.BroadcastReceiver;
+import android.content.Intent;
+import android.content.IntentFilter;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.media.IAudioService;
@@ -72,6 +77,7 @@ import com.android.server.telecom.AudioRoute;
 import com.android.server.telecom.Call;
 import com.android.server.telecom.CallAudioManager;
 import com.android.server.telecom.CallAudioRouteController;
+import com.android.server.telecom.CallAudioRouteStateMachine;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.PendingAudioRoute;
 import com.android.server.telecom.StatusBarNotifier;
@@ -79,12 +85,14 @@ import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.WiredHeadsetManager;
 import com.android.server.telecom.bluetooth.BluetoothDeviceManager;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 
 import org.junit.After;
 import org.junit.Before;
 import org.junit.Test;
 import org.junit.runner.RunWith;
 import org.junit.runners.JUnit4;
+import org.mockito.ArgumentCaptor;
 import org.mockito.Mock;
 
 import java.util.HashSet;
@@ -109,8 +117,10 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     @Mock CallAudioManager mCallAudioManager;
     @Mock Call mCall;
     @Mock private TelecomSystem.SyncRoot mLock;
+    @Mock private TelecomMetricsController mMockTelecomMetricsController;
     private AudioRoute mEarpieceRoute;
     private AudioRoute mSpeakerRoute;
+    private boolean mOverrideSpeakerToBus;
     private static final String BT_ADDRESS_1 = "00:00:00:00:00:01";
     private static final BluetoothDevice BLUETOOTH_DEVICE_1 =
             BluetoothRouteManagerTest.makeBluetoothDevice("00:00:00:00:00:01");
@@ -124,6 +134,9 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         @Override
         public AudioRoute create(@AudioRoute.AudioRouteType int type, String bluetoothAddress,
                                  AudioManager audioManager) {
+            if (mOverrideSpeakerToBus && type == AudioRoute.TYPE_SPEAKER) {
+                type = AudioRoute.TYPE_BUS;
+            }
             return new AudioRoute(type, bluetoothAddress, mAudioDeviceInfo);
         }
     };
@@ -151,6 +164,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
         when(mCallsManager.getCurrentUserHandle()).thenReturn(
                 new UserHandle(UserHandle.USER_SYSTEM));
         when(mCallsManager.getLock()).thenReturn(mLock);
+        when(mCallsManager.getForegroundCall()).thenReturn(mCall);
         when(mBluetoothRouteManager.getDeviceManager()).thenReturn(mBluetoothDeviceManager);
         when(mBluetoothDeviceManager.connectAudio(any(BluetoothDevice.class), anyInt()))
                 .thenReturn(true);
@@ -162,16 +176,19 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 .thenReturn(BLUETOOTH_DEVICE_1);
         when(mAudioDeviceInfo.getAddress()).thenReturn(BT_ADDRESS_1);
         mController = new CallAudioRouteController(mContext, mCallsManager, mAudioServiceFactory,
-                mAudioRouteFactory, mWiredHeadsetManager,
-                mBluetoothRouteManager, mockStatusBarNotifier, mFeatureFlags);
+                mAudioRouteFactory, mWiredHeadsetManager, mBluetoothRouteManager,
+                mockStatusBarNotifier, mFeatureFlags, mMockTelecomMetricsController);
         mController.setAudioRouteFactory(mAudioRouteFactory);
         mController.setAudioManager(mAudioManager);
         mEarpieceRoute = new AudioRoute(AudioRoute.TYPE_EARPIECE, null, null);
         mSpeakerRoute = new AudioRoute(AudioRoute.TYPE_SPEAKER, null, null);
+        mOverrideSpeakerToBus = false;
         mController.setCallAudioManager(mCallAudioManager);
         when(mCallAudioManager.getForegroundCall()).thenReturn(mCall);
         when(mCall.getVideoState()).thenReturn(VideoProfile.STATE_AUDIO_ONLY);
+        when(mCall.getSupportedAudioRoutes()).thenReturn(CallAudioState.ROUTE_ALL);
         when(mFeatureFlags.ignoreAutoRouteToWatchDevice()).thenReturn(false);
+        when(mFeatureFlags.useRefactoredAudioRouteSwitching()).thenReturn(true);
     }
 
     @After
@@ -215,7 +232,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     @Test
     public void testNormalCallRouteToEarpiece() {
         mController.initialize();
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         // Verify that pending audio destination route is set to speaker. This will trigger pending
         // message to wait for SPEAKER_ON message once communication device is set before routing.
         waitForHandlerAction(mController.getAdapterHandler(), TEST_TIMEOUT);
@@ -229,11 +246,54 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
     }
 
+    @SmallTest
+    @Test
+    public void testActiveFocusAudioRouting() {
+        mController.initialize();
+        // Connect wired headset
+        mController.sendMessageWithSessionInfo(CONNECT_WIRED_HEADSET);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_WIRED_HEADSET,
+                CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Explicitly switch to speaker
+        mController.sendMessageWithSessionInfo(USER_SWITCH_SPEAKER);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        // Expect that active focus received from a new active call will force route to baseline
+        // (in this case, this should be the wired headset).
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_WIRED_HEADSET,
+                CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Switch back to speaker and send active focus for end tone to confirm that audio routing
+        // doesn't fall back onto the baseline.
+        mController.sendMessageWithSessionInfo(USER_SWITCH_SPEAKER);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_WIRED_HEADSET | CallAudioState.ROUTE_SPEAKER, null,
+                new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 1);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+    }
+
     @SmallTest
     @Test
     public void testVideoCallHoldRouteToEarpiece() {
         mController.initialize();
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         // Verify that pending audio destination route is not defaulted to speaker when a video call
         // is not the foreground call.
         waitForHandlerAction(mController.getAdapterHandler(), TEST_TIMEOUT);
@@ -246,7 +306,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
     public void testVideoCallRouteToSpeaker() {
         when(mCall.getVideoState()).thenReturn(VideoProfile.STATE_BIDIRECTIONAL);
         mController.initialize();
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         // Verify that pending audio destination route is set to speaker. This will trigger pending
         // message to wait for SPEAKER_ON message once communication device is set before routing.
         waitForHandlerAction(mController.getAdapterHandler(), TEST_TIMEOUT);
@@ -314,15 +374,20 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
         assertFalse(mController.isActive());
 
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT))
                 .connectAudio(BLUETOOTH_DEVICE_1, AudioRoute.TYPE_BLUETOOTH_SCO);
         assertTrue(mController.isActive());
 
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
         assertTrue(mController.isActive());
 
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS, 0);
+        // Ensure we tell the CallAudioManager that audio operations are done so that we can ensure
+        // audio focus is relinquished.
+        verify(mCallAudioManager, timeout(TEST_TIMEOUT)).notifyAudioOperationsComplete();
+
+        // Ensure the BT device is disconnected.
         verify(mBluetoothDeviceManager, timeout(TEST_TIMEOUT).atLeastOnce()).disconnectSco();
         assertFalse(mController.isActive());
     }
@@ -463,7 +528,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
     @SmallTest
     @Test
-    public void tesetSwitchSpeakerAndHeadset() {
+    public void testSwitchSpeakerAndHeadset() {
         mController.initialize();
         mController.sendMessageWithSessionInfo(CONNECT_WIRED_HEADSET);
         CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_WIRED_HEADSET,
@@ -515,6 +580,38 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
     }
 
+    @SmallTest
+    @Test
+    public void testStreamRingMuteChange() {
+        mController.initialize();
+
+        // Make sure we register a receiver for the STREAM_MUTE_CHANGED_ACTION so we can see if the
+        // ring stream unmutes.
+        ArgumentCaptor<BroadcastReceiver> brCaptor = ArgumentCaptor.forClass(
+                BroadcastReceiver.class);
+        ArgumentCaptor<IntentFilter> filterCaptor = ArgumentCaptor.forClass(IntentFilter.class);
+        verify(mContext, times(3)).registerReceiver(brCaptor.capture(), filterCaptor.capture());
+        boolean foundValid = false;
+        for (int ix = 0; ix < brCaptor.getAllValues().size(); ix++) {
+            BroadcastReceiver receiver = brCaptor.getAllValues().get(ix);
+            IntentFilter filter = filterCaptor.getAllValues().get(ix);
+            if (!filter.hasAction(AudioManager.STREAM_MUTE_CHANGED_ACTION)) {
+                continue;
+            }
+
+            // Fake out a call to the broadcast receiver and make sure we call into audio manager
+            // to trigger re-evaluation of ringing.
+            Intent intent = new Intent(AudioManager.STREAM_MUTE_CHANGED_ACTION);
+            intent.putExtra(AudioManager.EXTRA_STREAM_VOLUME_MUTED, false);
+            intent.putExtra(AudioManager.EXTRA_VOLUME_STREAM_TYPE, AudioManager.STREAM_RING);
+            receiver.onReceive(mContext, intent);
+            verify(mCallAudioManager).onRingerModeChange();
+            foundValid = true;
+        }
+        assertTrue(foundValid);
+    }
+
+
     @SmallTest
     @Test
     public void testToggleMute() throws Exception {
@@ -560,7 +657,7 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
 
         // Switch to NO_FOCUS to indicate call termination and verify mute is reset.
         when(mAudioManager.isMicrophoneMute()).thenReturn(true);
-        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS);
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, NO_FOCUS, 0);
         expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
                 CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_SPEAKER, null,
                 new HashSet<>());
@@ -568,6 +665,9 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 anyInt(), anyString());
         verify(mCallsManager, timeout(TEST_TIMEOUT).atLeastOnce()).onCallAudioStateChanged(
                 any(CallAudioState.class), eq(expectedState));
+        // Ensure we tell the CallAudioManager that audio operations are done so that we can ensure
+        // audio focus is relinquished.
+        verify(mCallAudioManager, timeout(TEST_TIMEOUT)).notifyAudioOperationsComplete();
     }
 
     @SmallTest
@@ -718,6 +818,96 @@ public class CallAudioRouteControllerTest extends TelecomTestCase {
                 any(CallAudioState.class), eq(expectedState));
     }
 
+    @SmallTest
+    @Test
+    public void testRouteFromBtSwitchInRingingSelected() {
+        when(mFeatureFlags.ignoreAutoRouteToWatchDevice()).thenReturn(true);
+        when(mBluetoothRouteManager.isWatch(any(BluetoothDevice.class))).thenReturn(true);
+        when(mBluetoothRouteManager.isInbandRingEnabled(eq(BLUETOOTH_DEVICE_1))).thenReturn(false);
+
+        mController.initialize();
+        mController.sendMessageWithSessionInfo(BT_DEVICE_ADDED, AudioRoute.TYPE_BLUETOOTH_SCO,
+            BLUETOOTH_DEVICE_1);
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_EARPIECE,
+            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                | CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+            any(CallAudioState.class), eq(expectedState));
+
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, RINGING_FOCUS, 0);
+        assertFalse(mController.isActive());
+
+        // BT device should be cached. Verify routing into BT device once focus becomes active.
+        mController.sendMessageWithSessionInfo(USER_SWITCH_BLUETOOTH, 0,
+            BLUETOOTH_DEVICE_1.getAddress());
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+            any(CallAudioState.class), eq(expectedState));
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        mController.sendMessageWithSessionInfo(BT_AUDIO_CONNECTED, 0, BLUETOOTH_DEVICE_1);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_BLUETOOTH,
+            CallAudioState.ROUTE_EARPIECE | CallAudioState.ROUTE_BLUETOOTH
+                | CallAudioState.ROUTE_SPEAKER, BLUETOOTH_DEVICE_1, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+            any(CallAudioState.class), eq(expectedState));
+    }
+
+    @SmallTest
+    @Test
+    public void testUpdateRouteForForeground() {
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
+
+        // Ensure that supported routes is updated along with the current route to reflect the
+        // foreground call's supported audio routes.
+        when(mCall.getSupportedAudioRoutes()).thenReturn(CallAudioState.ROUTE_SPEAKER);
+        mController.sendMessageWithSessionInfo(
+                CallAudioRouteStateMachine.UPDATE_SYSTEM_AUDIO_ROUTE);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_SPEAKER, null, BLUETOOTH_DEVICES);
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+        assertEquals(3, mController.getAvailableRoutes().size());
+        assertEquals(1, mController.getCallSupportedRoutes().size());
+    }
+
+    @SmallTest
+    @Test
+    public void testRouteToBusForAuto() {
+        when(mAudioManager.getDevices(AudioManager.GET_DEVICES_OUTPUTS))
+                .thenReturn(new AudioDeviceInfo[0]);
+        mOverrideSpeakerToBus = true;
+        mController.initialize();
+
+        mController.sendMessageWithSessionInfo(SWITCH_FOCUS, ACTIVE_FOCUS, 0);
+        waitForHandlerAction(mController.getAdapterHandler(), TEST_TIMEOUT);
+        PendingAudioRoute pendingRoute = mController.getPendingAudioRoute();
+        assertEquals(AudioRoute.TYPE_BUS, pendingRoute.getDestRoute().getType());
+
+        CallAudioState expectedState = new CallAudioState(false, CallAudioState.ROUTE_SPEAKER,
+                CallAudioState.ROUTE_SPEAKER, null, new HashSet<>());
+        verify(mCallsManager, timeout(TEST_TIMEOUT)).onCallAudioStateChanged(
+                any(CallAudioState.class), eq(expectedState));
+
+        // Ensure that turning speaker phone on doesn't get triggered when speaker isn't available.
+        mController.sendMessageWithSessionInfo(USER_SWITCH_SPEAKER);
+        mController.sendMessageWithSessionInfo(SPEAKER_ON);
+        verify(mockStatusBarNotifier, times(0)).notifySpeakerphone(anyBoolean());
+
+    }
+
     private void verifyConnectBluetoothDevice(int audioType) {
         mController.initialize();
         mController.setActive(true);
diff --git a/tests/src/com/android/server/telecom/tests/CallRecordingTonePlayerTest.java b/tests/src/com/android/server/telecom/tests/CallRecordingTonePlayerTest.java
index 60952d34d..5ccb2fe28 100644
--- a/tests/src/com/android/server/telecom/tests/CallRecordingTonePlayerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallRecordingTonePlayerTest.java
@@ -42,6 +42,7 @@ import android.media.MediaPlayer;
 import android.media.MediaRecorder;
 import android.os.Handler;
 import android.os.Looper;
+import android.platform.test.annotations.RequiresFlagsDisabled;
 import android.telecom.PhoneAccountHandle;
 
 import androidx.test.filters.MediumTest;
@@ -52,6 +53,7 @@ import com.android.server.telecom.CallRecordingTonePlayer;
 import com.android.server.telecom.CallState;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
+import com.android.server.telecom.flags.Flags;
 
 import org.junit.After;
 import org.junit.Before;
@@ -71,6 +73,7 @@ import java.util.List;
  * Unit tests for the {@link com.android.server.telecom.CallRecordingTonePlayer} class.
  */
 @RunWith(JUnit4.class)
+@RequiresFlagsDisabled(Flags.FLAG_TELECOM_RESOLVE_HIDDEN_DEPENDENCIES)
 public class CallRecordingTonePlayerTest extends TelecomTestCase {
 
     private static final String PHONE_ACCOUNT_PACKAGE = "com.android.telecom.test";
diff --git a/tests/src/com/android/server/telecom/tests/CallTest.java b/tests/src/com/android/server/telecom/tests/CallTest.java
index a22d2cae2..3a7a82207 100644
--- a/tests/src/com/android/server/telecom/tests/CallTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallTest.java
@@ -23,10 +23,8 @@ import static org.junit.Assert.assertNull;
 import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.any;
 import static org.mockito.ArgumentMatchers.anyBoolean;
-import static org.mockito.ArgumentMatchers.anyInt;
 import static org.mockito.ArgumentMatchers.argThat;
 import static org.mockito.ArgumentMatchers.eq;
-import static org.mockito.Mockito.doNothing;
 import static org.mockito.Mockito.doReturn;
 import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.never;
@@ -42,6 +40,7 @@ import android.graphics.Bitmap;
 import android.graphics.drawable.ColorDrawable;
 import android.net.Uri;
 import android.os.Bundle;
+import android.os.PersistableBundle;
 import android.os.UserHandle;
 import android.telecom.CallAttributes;
 import android.telecom.CallEndpoint;
@@ -56,12 +55,12 @@ import android.telecom.StatusHints;
 import android.telecom.TelecomManager;
 import android.telecom.VideoProfile;
 import android.telephony.CallQuality;
-import android.widget.Toast;
 
 import androidx.test.ext.junit.runners.AndroidJUnit4;
 import androidx.test.filters.SmallTest;
 
 import com.android.server.telecom.CachedAvailableEndpointsChange;
+import com.android.server.telecom.CachedCallEventQueue;
 import com.android.server.telecom.CachedCurrentEndpointChange;
 import com.android.server.telecom.CachedMuteStateChange;
 import com.android.server.telecom.Call;
@@ -130,8 +129,8 @@ public class CallTest extends TelecomTestCase {
         Resources mockResources = mContext.getResources();
         when(mockResources.getBoolean(R.bool.skip_loading_canned_text_response))
                 .thenReturn(false);
-        when(mockResources.getBoolean(R.bool.skip_incoming_caller_info_query))
-                .thenReturn(false);
+        when(mockResources.getString(R.string.skip_incoming_caller_info_account_package))
+                .thenReturn("");
         EmergencyCallHelper helper = mock(EmergencyCallHelper.class);
         doReturn(helper).when(mMockCallsManager).getEmergencyCallHelper();
     }
@@ -152,6 +151,32 @@ public class CallTest extends TelecomTestCase {
         assertTrue(call.hasGoneActiveBefore());
     }
 
+    /**
+     * Verify that transactional calls remap the [CallAttributes#CallCapability]s to
+     * Connection capabilities.
+     */
+    @Test
+    @SmallTest
+    public void testTransactionalCallCapabilityRemapping() {
+        // ensure when the flag is disabled, the old behavior is unchanged
+        Bundle disabledFlagExtras = new Bundle();
+        Call call = createCall("1", Call.CALL_DIRECTION_INCOMING);
+        disabledFlagExtras.putInt(CallAttributes.CALL_CAPABILITIES_KEY,
+                Connection.CAPABILITY_MERGE_CONFERENCE);
+        when(mFeatureFlags.remapTransactionalCapabilities()).thenReturn(false);
+        call.setTransactionalCapabilities(disabledFlagExtras);
+        assertTrue(call.can(Connection.CAPABILITY_MERGE_CONFERENCE));
+        // enable the bug fix flag and ensure the transactional capabilities are remapped
+        Bundle enabledFlagExtras = new Bundle();
+        Call call2 = createCall("2", Call.CALL_DIRECTION_INCOMING);
+        enabledFlagExtras.putInt(CallAttributes.CALL_CAPABILITIES_KEY,
+                CallAttributes.SUPPORTS_SET_INACTIVE);
+        when(mFeatureFlags.remapTransactionalCapabilities()).thenReturn(true);
+        call2.setTransactionalCapabilities(enabledFlagExtras);
+        assertTrue(call2.can(Connection.CAPABILITY_HOLD));
+        assertTrue(call2.can(Connection.CAPABILITY_SUPPORT_HOLD));
+    }
+
     /**
      * Verify Call#setVideoState will only upgrade to video if the PhoneAccount supports video
      * state capabilities
@@ -215,6 +240,44 @@ public class CallTest extends TelecomTestCase {
         verify(tsw, times(3)).onVideoStateChanged(call, CallAttributes.VIDEO_CALL);
     }
 
+    @Test
+    public void testMultipleCachedCallEvents() {
+        when(mFeatureFlags.cacheCallAudioCallbacks()).thenReturn(true);
+        when(mFeatureFlags.cacheCallEvents()).thenReturn(true);
+        TransactionalServiceWrapper tsw = Mockito.mock(TransactionalServiceWrapper.class);
+        Call call = createCall("1", Call.CALL_DIRECTION_INCOMING);
+
+        assertNull(call.getTransactionServiceWrapper());
+
+        String testEvent1 = "test1";
+        Bundle testBundle1 = new Bundle();
+        testBundle1.putInt("testKey", 1);
+        call.sendCallEvent(testEvent1, testBundle1);
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedCallEventQueue.ID).size());
+
+        String testEvent2 = "test2";
+        Bundle testBundle2 = new Bundle();
+        testBundle2.putInt("testKey", 2);
+        call.sendCallEvent(testEvent2, testBundle2);
+        assertEquals(2,
+                call.getCachedServiceCallbacksCopy().get(CachedCallEventQueue.ID).size());
+
+        String testEvent3 = "test3";
+        Bundle testBundle3 = new Bundle();
+        testBundle2.putInt("testKey", 3);
+        call.sendCallEvent(testEvent3, testBundle3);
+        assertEquals(3,
+                call.getCachedServiceCallbacksCopy().get(CachedCallEventQueue.ID).size());
+
+        verify(tsw, times(0)).sendCallEvent(any(), any(), any());
+        call.setTransactionServiceWrapper(tsw);
+        verify(tsw, times(1)).sendCallEvent(any(), eq(testEvent1), eq(testBundle1));
+        verify(tsw, times(1)).sendCallEvent(any(), eq(testEvent2), eq(testBundle2));
+        verify(tsw, times(1)).sendCallEvent(any(), eq(testEvent3), eq(testBundle3));
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
+    }
+
     @Test
     public void testMultipleCachedMuteStateChanges() {
         when(mFeatureFlags.cacheCallAudioCallbacks()).thenReturn(true);
@@ -224,20 +287,39 @@ public class CallTest extends TelecomTestCase {
         assertNull(call.getTransactionServiceWrapper());
 
         call.cacheServiceCallback(new CachedMuteStateChange(true));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedMuteStateChange.ID).size());
 
         call.cacheServiceCallback(new CachedMuteStateChange(false));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedMuteStateChange.ID).size());
 
         CachedMuteStateChange currentCacheMuteState = (CachedMuteStateChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedMuteStateChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedMuteStateChange.ID)
+                .getLast();
 
         assertFalse(currentCacheMuteState.isMuted());
 
         call.setTransactionServiceWrapper(tsw);
         verify(tsw, times(1)).onMuteStateChanged(any(), eq(false));
-        assertEquals(0, call.getCachedServiceCallbacks().size());
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
+    }
+
+    @Test
+    public void testCacheAfterServiceSet() {
+        when(mFeatureFlags.cacheCallAudioCallbacks()).thenReturn(true);
+        when(mFeatureFlags.cacheCallEvents()).thenReturn(true);
+        TransactionalServiceWrapper tsw = Mockito.mock(TransactionalServiceWrapper.class);
+        Call call = createCall("1", Call.CALL_DIRECTION_INCOMING);
+
+        assertNull(call.getTransactionServiceWrapper());
+        call.setTransactionServiceWrapper(tsw);
+        call.cacheServiceCallback(new CachedMuteStateChange(true));
+        // Ensure that we do not lose events if for some reason a CachedCallback is cached after
+        // the service is set
+        verify(tsw, times(1)).onMuteStateChanged(any(), eq(true));
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
     }
 
     @Test
@@ -254,21 +336,24 @@ public class CallTest extends TelecomTestCase {
         assertNull(call.getTransactionServiceWrapper());
 
         call.cacheServiceCallback(new CachedCurrentEndpointChange(earpiece));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedCurrentEndpointChange.ID).size());
 
         call.cacheServiceCallback(new CachedCurrentEndpointChange(speaker));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedCurrentEndpointChange.ID).size());
 
         CachedCurrentEndpointChange currentEndpointChange = (CachedCurrentEndpointChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedCurrentEndpointChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedCurrentEndpointChange.ID)
+                .getLast();
 
         assertEquals(CallEndpoint.TYPE_SPEAKER,
                 currentEndpointChange.getCurrentCallEndpoint().getEndpointType());
 
         call.setTransactionServiceWrapper(tsw);
         verify(tsw, times(1)).onCallEndpointChanged(any(), any());
-        assertEquals(0, call.getCachedServiceCallbacks().size());
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
     }
 
     @Test
@@ -287,20 +372,23 @@ public class CallTest extends TelecomTestCase {
         assertNull(call.getTransactionServiceWrapper());
 
         call.cacheServiceCallback(new CachedAvailableEndpointsChange(initialSet));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedAvailableEndpointsChange.ID).size());
 
         call.cacheServiceCallback(new CachedAvailableEndpointsChange(finalSet));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1,
+                call.getCachedServiceCallbacksCopy().get(CachedAvailableEndpointsChange.ID).size());
 
         CachedAvailableEndpointsChange availableEndpoints = (CachedAvailableEndpointsChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedAvailableEndpointsChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedAvailableEndpointsChange.ID)
+                .getLast();
 
         assertEquals(2, availableEndpoints.getAvailableEndpoints().size());
 
         call.setTransactionServiceWrapper(tsw);
         verify(tsw, times(1)).onAvailableCallEndpointsChanged(any(), any());
-        assertEquals(0, call.getCachedServiceCallbacks().size());
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
     }
 
     /**
@@ -310,6 +398,7 @@ public class CallTest extends TelecomTestCase {
     @Test
     public void testAllCachedCallbacks() {
         when(mFeatureFlags.cacheCallAudioCallbacks()).thenReturn(true);
+        when(mFeatureFlags.cacheCallEvents()).thenReturn(true);
         TransactionalServiceWrapper tsw = Mockito.mock(TransactionalServiceWrapper.class);
         CallEndpoint earpiece = Mockito.mock(CallEndpoint.class);
         CallEndpoint bluetooth = Mockito.mock(CallEndpoint.class);
@@ -323,23 +412,29 @@ public class CallTest extends TelecomTestCase {
 
         // add cached callbacks
         call.cacheServiceCallback(new CachedMuteStateChange(false));
-        assertEquals(1, call.getCachedServiceCallbacks().size());
+        assertEquals(1, call.getCachedServiceCallbacksCopy().size());
         call.cacheServiceCallback(new CachedCurrentEndpointChange(earpiece));
-        assertEquals(2, call.getCachedServiceCallbacks().size());
+        assertEquals(2, call.getCachedServiceCallbacksCopy().size());
         call.cacheServiceCallback(new CachedAvailableEndpointsChange(availableEndpointsSet));
-        assertEquals(3, call.getCachedServiceCallbacks().size());
+        assertEquals(3, call.getCachedServiceCallbacksCopy().size());
+        String testEvent = "testEvent";
+        Bundle testBundle = new Bundle();
+        call.sendCallEvent("testEvent", testBundle);
 
         // verify the cached callbacks are stored properly within the cache map and the values
         // can be evaluated
         CachedMuteStateChange currentCacheMuteState = (CachedMuteStateChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedMuteStateChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedMuteStateChange.ID)
+                .getLast();
         CachedCurrentEndpointChange currentEndpointChange = (CachedCurrentEndpointChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedCurrentEndpointChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedCurrentEndpointChange.ID)
+                .getLast();
         CachedAvailableEndpointsChange availableEndpoints = (CachedAvailableEndpointsChange) call
-                .getCachedServiceCallbacks()
-                .get(CachedAvailableEndpointsChange.ID);
+                .getCachedServiceCallbacksCopy()
+                .get(CachedAvailableEndpointsChange.ID)
+                .getLast();
         assertFalse(currentCacheMuteState.isMuted());
         assertEquals(CallEndpoint.TYPE_EARPIECE,
                 currentEndpointChange.getCurrentCallEndpoint().getEndpointType());
@@ -352,9 +447,10 @@ public class CallTest extends TelecomTestCase {
         verify(tsw, times(1)).onMuteStateChanged(any(), anyBoolean());
         verify(tsw, times(1)).onCallEndpointChanged(any(), any());
         verify(tsw, times(1)).onAvailableCallEndpointsChanged(any(), any());
+        verify(tsw, times(1)).sendCallEvent(any(), eq(testEvent), eq(testBundle));
 
         // the cache map should be cleared
-        assertEquals(0, call.getCachedServiceCallbacks().size());
+        assertEquals(0, call.getCachedServiceCallbacksCopy().size());
     }
 
     /**
@@ -694,8 +790,8 @@ public class CallTest extends TelecomTestCase {
     @SmallTest
     public void testGetFromCallerInfo_skipLookup() {
         Resources mockResources = mContext.getResources();
-        when(mockResources.getBoolean(R.bool.skip_incoming_caller_info_query))
-                .thenReturn(true);
+        when(mockResources.getString(R.string.skip_incoming_caller_info_account_package))
+                .thenReturn("com.foo");
 
         createCall("1");
 
diff --git a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
index ae5e6c1f2..c2acfd620 100644
--- a/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
+++ b/tests/src/com/android/server/telecom/tests/CallsManagerTest.java
@@ -59,7 +59,6 @@ import android.media.AudioManager;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.Handler;
-import android.os.IBinder;
 import android.os.Looper;
 import android.os.OutcomeReceiver;
 import android.os.Process;
@@ -88,7 +87,6 @@ import android.widget.Toast;
 import androidx.test.filters.MediumTest;
 import androidx.test.filters.SmallTest;
 
-import com.android.internal.telecom.IConnectionService;
 import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.AsyncRingtonePlayer;
 import com.android.server.telecom.Call;
@@ -107,7 +105,6 @@ import com.android.server.telecom.ClockProxy;
 import com.android.server.telecom.ConnectionServiceFocusManager;
 import com.android.server.telecom.ConnectionServiceFocusManager.ConnectionServiceFocusManagerFactory;
 import com.android.server.telecom.ConnectionServiceWrapper;
-import com.android.server.telecom.CreateConnectionResponse;
 import com.android.server.telecom.DefaultDialerCache;
 import com.android.server.telecom.EmergencyCallDiagnosticLogger;
 import com.android.server.telecom.EmergencyCallHelper;
@@ -137,6 +134,7 @@ import com.android.server.telecom.callfiltering.BlockedNumbersAdapter;
 import com.android.server.telecom.callfiltering.CallFilteringResult;
 import com.android.server.telecom.flags.FeatureFlags;
 import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
+import com.android.server.telecom.metrics.TelecomMetricsController;
 import com.android.server.telecom.ui.AudioProcessingNotification;
 import com.android.server.telecom.ui.CallStreamingNotification;
 import com.android.server.telecom.ui.DisconnectedCallNotifier;
@@ -318,7 +316,7 @@ public class CallsManagerTest extends TelecomTestCase {
     @Mock private IncomingCallFilterGraph mIncomingCallFilterGraph;
     @Mock private Context mMockCreateContextAsUser;
     @Mock private UserManager mMockCurrentUserManager;
-    @Mock private IConnectionService mIConnectionService;
+    @Mock private TelecomMetricsController mMockTelecomMetricsController;
     private CallsManager mCallsManager;
 
     @Override
@@ -396,7 +394,9 @@ public class CallsManagerTest extends TelecomTestCase {
                 mBluetoothDeviceManager,
                 mFeatureFlags,
                 mTelephonyFlags,
-                (call, listener, context, timeoutsAdapter, lock) -> mIncomingCallFilterGraph);
+                (call, listener, context, timeoutsAdapter,
+                        mFeatureFlags, lock) -> mIncomingCallFilterGraph,
+                mMockTelecomMetricsController);
 
         when(mPhoneAccountRegistrar.getPhoneAccount(
                 eq(SELF_MANAGED_HANDLE), any())).thenReturn(SELF_MANAGED_ACCOUNT);
@@ -416,17 +416,11 @@ public class CallsManagerTest extends TelecomTestCase {
                 .thenReturn(mMockCreateContextAsUser);
         when(mMockCreateContextAsUser.getSystemService(UserManager.class))
                 .thenReturn(mMockCurrentUserManager);
-        when(mIConnectionService.asBinder()).thenReturn(mock(IBinder.class));
-
-        mComponentContextFixture.addConnectionService(
-                SIM_1_ACCOUNT.getAccountHandle().getComponentName(), mIConnectionService);
     }
 
     @Override
     @After
     public void tearDown() throws Exception {
-        mComponentContextFixture.removeConnectionService(
-                SIM_1_ACCOUNT.getAccountHandle().getComponentName(), mIConnectionService);
         super.tearDown();
     }
 
@@ -3247,35 +3241,6 @@ public class CallsManagerTest extends TelecomTestCase {
         assertTrue(result.contains("onReceiveResult"));
     }
 
-    @Test
-    public void testConnectionServiceCreateConnectionTimeout() throws Exception {
-        ConnectionServiceWrapper service = new ConnectionServiceWrapper(
-                SIM_1_ACCOUNT.getAccountHandle().getComponentName(), null,
-                mPhoneAccountRegistrar, mCallsManager, mContext, mLock, null, mFeatureFlags);
-        TestScheduledExecutorService scheduledExecutorService = new TestScheduledExecutorService();
-        service.setScheduledExecutorService(scheduledExecutorService);
-        Call call = addSpyCall();
-        service.addCall(call);
-        when(call.isCreateConnectionComplete()).thenReturn(false);
-        CreateConnectionResponse response = mock(CreateConnectionResponse.class);
-
-        service.createConnection(call, response);
-        waitUntilConditionIsTrueOrTimeout(new Condition() {
-            @Override
-            public Object expected() {
-                return true;
-            }
-
-            @Override
-            public Object actual() {
-                return scheduledExecutorService.isRunnableScheduledAtTime(15000L);
-            }
-        }, 5000L, "Expected job failed to schedule");
-        scheduledExecutorService.advanceTime(15000L);
-        verify(response).handleCreateConnectionFailure(
-                eq(new DisconnectCause(DisconnectCause.ERROR)));
-    }
-
     @SmallTest
     @Test
     public void testOnFailedOutgoingCallUnholdsCallAfterLocallyDisconnect() {
diff --git a/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java b/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
index ddbc25068..e497f485d 100644
--- a/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
+++ b/tests/src/com/android/server/telecom/tests/CreateConnectionProcessorTest.java
@@ -88,6 +88,8 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
     private static final String TEST_PACKAGE = "com.android.server.telecom.tests";
     private static final String TEST_CLASS =
             "com.android.server.telecom.tests.MockConnectionService";
+    private static final String CONNECTION_MANAGER_TEST_CLASS =
+            "com.android.server.telecom.tests.ConnectionManagerConnectionService";
     private static final UserHandle USER_HANDLE_10 = new UserHandle(10);
 
     @Mock
@@ -195,7 +197,7 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
 
     @SmallTest
     @Test
-    public void testbadPhoneAccount() throws Exception {
+    public void testBadPhoneAccount() throws Exception {
         PhoneAccountHandle pAHandle = null;
         when(mMockCall.isEmergencyCall()).thenReturn(false);
         when(mMockCall.getTargetPhoneAccount()).thenReturn(pAHandle);
@@ -219,9 +221,9 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         setTargetPhoneAccount(mMockCall, pAHandle);
         when(mMockCall.isEmergencyCall()).thenReturn(false);
         // Include a Connection Manager
-        PhoneAccountHandle callManagerPAHandle = getNewConnectionMangerHandleForCall(mMockCall,
+        PhoneAccountHandle callManagerPAHandle = getNewConnectionManagerHandleForCall(mMockCall,
                 "cm_acct");
-        ConnectionServiceWrapper service = makeConnectionServiceWrapper();
+        ConnectionServiceWrapper service = makeConnMgrConnectionServiceWrapper();
         // Make sure the target phone account has the correct permissions
         PhoneAccount mFakeTargetPhoneAccount = makeQuickAccount("cm_acct",
                 PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION, null);
@@ -241,16 +243,54 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         verify(mMockCreateConnectionResponse).handleCreateConnectionSuccess(mockCallIdMapper, null);
     }
 
+    @SmallTest
+    @Test
+    public void testConnectionManagerConnectionServiceSuccess() throws Exception {
+        when(mFeatureFlags.updatedRcsCallCountTracking()).thenReturn(true);
+
+        // Configure the target phone account as the remote connection service:
+        PhoneAccountHandle pAHandle = getNewTargetPhoneAccountHandle("tel_acct");
+        setTargetPhoneAccount(mMockCall, pAHandle);
+        when(mMockCall.isEmergencyCall()).thenReturn(false);
+        ConnectionServiceWrapper remoteService = makeConnectionServiceWrapper();
+
+        // Configure the connection manager phone account as the primary connection service:
+        PhoneAccountHandle callManagerPAHandle = getNewConnectionManagerHandleForCall(mMockCall,
+                "cm_acct");
+        ConnectionServiceWrapper service = makeConnMgrConnectionServiceWrapper();
+
+        // Make sure the target phone account has the correct permissions
+        PhoneAccount mFakeTargetPhoneAccount = makeQuickAccount("cm_acct",
+                PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION, null);
+        when(mMockAccountRegistrar.getPhoneAccountUnchecked(pAHandle)).thenReturn(
+                mFakeTargetPhoneAccount);
+
+        mTestCreateConnectionProcessor.process();
+
+        verify(mMockCall).setConnectionManagerPhoneAccount(eq(callManagerPAHandle));
+        verify(mMockCall).setTargetPhoneAccount(eq(pAHandle));
+        // Ensure the remote connection service and primary connection service are set properly:
+        verify(mMockCall).setConnectionService(eq(service), eq(remoteService));
+        verify(service).createConnection(eq(mMockCall),
+                any(CreateConnectionResponse.class));
+        // Notify successful connection to call:
+        CallIdMapper mockCallIdMapper = mock(CallIdMapper.class);
+        mTestCreateConnectionProcessor.handleCreateConnectionSuccess(mockCallIdMapper, null);
+        verify(mMockCreateConnectionResponse).handleCreateConnectionSuccess(mockCallIdMapper, null);
+    }
+
     @SmallTest
     @Test
     public void testConnectionManagerFailedFallToSim() throws Exception {
         PhoneAccountHandle pAHandle = getNewTargetPhoneAccountHandle("tel_acct");
         setTargetPhoneAccount(mMockCall, pAHandle);
         when(mMockCall.isEmergencyCall()).thenReturn(false);
+        ConnectionServiceWrapper remoteService = makeConnectionServiceWrapper();
+
         // Include a Connection Manager
-        PhoneAccountHandle callManagerPAHandle = getNewConnectionMangerHandleForCall(mMockCall,
+        PhoneAccountHandle callManagerPAHandle = getNewConnectionManagerHandleForCall(mMockCall,
                 "cm_acct");
-        ConnectionServiceWrapper service = makeConnectionServiceWrapper();
+        ConnectionServiceWrapper service = makeConnMgrConnectionServiceWrapper();
         when(mMockCall.getConnectionManagerPhoneAccount()).thenReturn(callManagerPAHandle);
         PhoneAccount mFakeTargetPhoneAccount = makeQuickAccount("cm_acct",
                 PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION, null);
@@ -273,8 +313,8 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         // Verify that the Sim Phone Account is used correctly
         verify(mMockCall).setConnectionManagerPhoneAccount(eq(pAHandle));
         verify(mMockCall).setTargetPhoneAccount(eq(pAHandle));
-        verify(mMockCall).setConnectionService(eq(service));
-        verify(service).createConnection(eq(mMockCall), any(CreateConnectionResponse.class));
+        verify(mMockCall).setConnectionService(eq(remoteService));
+        verify(remoteService).createConnection(eq(mMockCall), any(CreateConnectionResponse.class));
         // Notify successful connection to call
         CallIdMapper mockCallIdMapper = mock(CallIdMapper.class);
         mTestCreateConnectionProcessor.handleCreateConnectionSuccess(mockCallIdMapper, null);
@@ -288,7 +328,7 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         setTargetPhoneAccount(mMockCall, pAHandle);
         when(mMockCall.isEmergencyCall()).thenReturn(false);
         // Include a Connection Manager
-        PhoneAccountHandle callManagerPAHandle = getNewConnectionMangerHandleForCall(mMockCall,
+        PhoneAccountHandle callManagerPAHandle = getNewConnectionManagerHandleForCall(mMockCall,
                 "cm_acct");
         ConnectionServiceWrapper service = makeConnectionServiceWrapper();
         when(mMockCall.getConnectionManagerPhoneAccount()).thenReturn(callManagerPAHandle);
@@ -990,8 +1030,8 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         when(mMockAccountRegistrar.phoneAccountRequiresBindPermission(eq(handle))).thenReturn(true);
     }
 
-    private PhoneAccountHandle getNewConnectionMangerHandleForCall(Call call, String id) {
-        PhoneAccountHandle callManagerPAHandle = makeQuickAccountHandle(id, null);
+    private PhoneAccountHandle getNewConnectionManagerHandleForCall(Call call, String id) {
+        PhoneAccountHandle callManagerPAHandle = makeQuickConnMgrAccountHandle(id, null);
         when(mMockAccountRegistrar.getSimCallManagerFromCall(eq(call))).thenReturn(
                 callManagerPAHandle);
         givePhoneAccountBindPermission(callManagerPAHandle);
@@ -1033,6 +1073,10 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         return new ComponentName(TEST_PACKAGE, TEST_CLASS);
     }
 
+    private static ComponentName makeQuickConnMgrConnectionServiceComponentName() {
+        return new ComponentName(TEST_PACKAGE, CONNECTION_MANAGER_TEST_CLASS);
+    }
+
     private ConnectionServiceWrapper makeConnectionServiceWrapper() {
         ConnectionServiceWrapper wrapper = mock(ConnectionServiceWrapper.class);
 
@@ -1042,6 +1086,24 @@ public class CreateConnectionProcessorTest extends TelecomTestCase {
         return wrapper;
     }
 
+    private ConnectionServiceWrapper makeConnMgrConnectionServiceWrapper() {
+        ConnectionServiceWrapper wrapper = mock(ConnectionServiceWrapper.class);
+
+        when(mMockConnectionServiceRepository.getService(
+                eq(makeQuickConnMgrConnectionServiceComponentName()), any(UserHandle.class)))
+                .thenReturn(wrapper);
+        return wrapper;
+    }
+
+    private static PhoneAccountHandle makeQuickConnMgrAccountHandle(String id,
+            UserHandle userHandle) {
+        if (userHandle == null) {
+            userHandle = Binder.getCallingUserHandle();
+        }
+        return new PhoneAccountHandle(makeQuickConnMgrConnectionServiceComponentName(),
+                id, userHandle);
+    }
+
     private static PhoneAccountHandle makeQuickAccountHandle(String id, UserHandle userHandle) {
         if (userHandle == null) {
             userHandle = Binder.getCallingUserHandle();
diff --git a/tests/src/com/android/server/telecom/tests/EmergencyCallHelperTest.java b/tests/src/com/android/server/telecom/tests/EmergencyCallHelperTest.java
index f2ad2f739..cc1c38a19 100644
--- a/tests/src/com/android/server/telecom/tests/EmergencyCallHelperTest.java
+++ b/tests/src/com/android/server/telecom/tests/EmergencyCallHelperTest.java
@@ -75,7 +75,7 @@ public class EmergencyCallHelperTest extends TelecomTestCase {
     mContext = mComponentContextFixture.getTestDouble().getApplicationContext();
     when(mContext.getPackageManager()).thenReturn(mPackageManager);
     mEmergencyCallHelper = new EmergencyCallHelper(mContext, mDefaultDialerCache,
-        mTimeoutsAdapter);
+        mTimeoutsAdapter, mFeatureFlags);
     when(mDefaultDialerCache.getSystemDialerApplication()).thenReturn(SYSTEM_DIALER_PACKAGE);
 
     //start with no perms
@@ -183,6 +183,61 @@ public class EmergencyCallHelperTest extends TelecomTestCase {
     verifyRevokeNotInvokedFor(ACCESS_FINE_LOCATION);
   }
 
+  @SmallTest
+  @Test
+  public void testPermGrantAndRevokeForEmergencyCall() {
+
+    when(mFeatureFlags.preventRedundantLocationPermissionGrantAndRevoke()).thenReturn(true);
+
+    mEmergencyCallHelper.maybeGrantTemporaryLocationPermission(mCall, mUserHandle);
+    mEmergencyCallHelper.maybeRevokeTemporaryLocationPermission();
+
+    //permissions should be granted then revoked
+    verifyGrantInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyGrantInvokedFor(ACCESS_FINE_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_FINE_LOCATION);
+  }
+
+  @SmallTest
+  @Test
+  public void testPermGrantAndRevokeForMultiEmergencyCall() {
+
+    when(mFeatureFlags.preventRedundantLocationPermissionGrantAndRevoke()).thenReturn(true);
+
+    //first call is emergency call
+    mEmergencyCallHelper.maybeGrantTemporaryLocationPermission(mCall, mUserHandle);
+    //second call is emergency call
+    mEmergencyCallHelper.maybeGrantTemporaryLocationPermission(mCall, mUserHandle);
+    mEmergencyCallHelper.maybeRevokeTemporaryLocationPermission();
+
+    //permissions should be granted then revoked
+    verifyGrantInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyGrantInvokedFor(ACCESS_FINE_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_FINE_LOCATION);
+  }
+
+  @SmallTest
+  @Test
+  public void testPermGrantAndRevokeForEmergencyCallAndNormalCall() {
+
+    when(mFeatureFlags.preventRedundantLocationPermissionGrantAndRevoke()).thenReturn(true);
+
+    //first call is emergency call
+    mEmergencyCallHelper.maybeGrantTemporaryLocationPermission(mCall, mUserHandle);
+    //second call is normal call
+    when(mCall.isEmergencyCall()).thenReturn(false);
+    mEmergencyCallHelper.maybeGrantTemporaryLocationPermission(mCall, mUserHandle);
+    mEmergencyCallHelper.maybeRevokeTemporaryLocationPermission();
+
+    //permissions should be granted then revoked
+    verifyGrantInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyGrantInvokedFor(ACCESS_FINE_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_BACKGROUND_LOCATION);
+    verifyRevokeInvokedFor(ACCESS_FINE_LOCATION);
+  }
+
   @SmallTest
   @Test
   public void testNoPermGrantForNonEmergencyCall() {
diff --git a/tests/src/com/android/server/telecom/tests/InCallControllerTests.java b/tests/src/com/android/server/telecom/tests/InCallControllerTests.java
index 6af31ae6e..bea3fe3a7 100644
--- a/tests/src/com/android/server/telecom/tests/InCallControllerTests.java
+++ b/tests/src/com/android/server/telecom/tests/InCallControllerTests.java
@@ -79,6 +79,7 @@ import android.os.UserHandle;
 import android.os.UserManager;
 import android.permission.PermissionCheckerManager;
 import android.telecom.CallAudioState;
+import android.telecom.CallEndpoint;
 import android.telecom.InCallService;
 import android.telecom.ParcelableCall;
 import android.telecom.PhoneAccountHandle;
@@ -95,6 +96,7 @@ import com.android.internal.telecom.IInCallService;
 import com.android.server.telecom.Analytics;
 import com.android.server.telecom.AnomalyReporterAdapter;
 import com.android.server.telecom.Call;
+import com.android.server.telecom.CallEndpointController;
 import com.android.server.telecom.CallsManager;
 import com.android.server.telecom.CarModeTracker;
 import com.android.server.telecom.ClockProxy;
@@ -157,6 +159,7 @@ public class InCallControllerTests extends TelecomTestCase {
     @Mock UserManager mMockUserManager;
     @Mock Context mMockCreateContextAsUser;
     @Mock UserManager mMockCurrentUserManager;
+    @Mock CallEndpointController mMockCallEndpointController;
 
     @Rule
     public TestRule compatChangeRule = new PlatformCompatChangeRule();
@@ -227,7 +230,7 @@ public class InCallControllerTests extends TelecomTestCase {
                 new ComponentName(SYS_PKG, SYS_CLASS));
         when(mDefaultDialerCache.getBTInCallServicePackages()).thenReturn(new String[] {BT_PKG});
         mEmergencyCallHelper = new EmergencyCallHelper(mMockContext, mDefaultDialerCache,
-                mTimeoutsAdapter);
+                mTimeoutsAdapter, mFeatureFlags);
         when(mMockCallsManager.getRoleManagerAdapter()).thenReturn(mMockRoleManagerAdapter);
         when(mMockContext.getSystemService(eq(Context.NOTIFICATION_SERVICE)))
                 .thenReturn(mNotificationManager);
@@ -307,6 +310,10 @@ public class InCallControllerTests extends TelecomTestCase {
                 .thenReturn(PackageManager.PERMISSION_DENIED);
 
         when(mMockCallsManager.getAudioState()).thenReturn(new CallAudioState(false, 0, 0));
+        when(mFeatureFlags.onCallEndpointChangedIcsOnConnected()).thenReturn(true);
+        when(mMockCallsManager.getCallEndpointController()).thenReturn(mMockCallEndpointController);
+        when(mMockCallEndpointController.getCurrentCallEndpoint())
+                .thenReturn(new CallEndpoint("Earpiece", 1));
 
         when(mMockContext.getSystemService(eq(Context.USER_SERVICE))).thenReturn(mMockUserManager);
         when(mMockContext.getSystemService(eq(UserManager.class)))
@@ -1939,6 +1946,25 @@ public class InCallControllerTests extends TelecomTestCase {
         when(mFeatureFlags.profileUserSupport()).thenReturn(true);
     }
 
+    /**
+     * Verify that if a null inCallService object is passed to sendCallToInCallService, a
+     * NullPointerException is not thrown.
+     */
+    @Test
+    public void testSendCallToInCallServiceWithNullService() {
+        when(mFeatureFlags.doNotSendCallToNullIcs()).thenReturn(true);
+        //Setup up parent and child/work profile relation
+        when(mMockChildUserCall.getAssociatedUser()).thenReturn(mChildUserHandle);
+        when(mMockCallsManager.getCurrentUserHandle()).thenReturn(mParentUserHandle);
+        when(mMockUserManager.getProfileParent(mChildUserHandle)).thenReturn(mParentUserHandle);
+        when(mFeatureFlags.profileUserSupport()).thenReturn(true);
+        when(mMockContext.getSystemService(eq(UserManager.class)))
+                .thenReturn(mMockUserManager);
+        // verify a NullPointerException is not thrown
+        int res = mInCallController.sendCallToService(mMockCall, mInCallServiceInfo, null);
+        assertEquals(0, res);
+    }
+
     @Test
     public void testProfileCallQueriesIcsUsingParentUserToo() throws Exception {
         setupMocksForProfileTest();
diff --git a/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java b/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
index c9faa5243..df2668484 100644
--- a/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
+++ b/tests/src/com/android/server/telecom/tests/InCallTonePlayerTest.java
@@ -27,7 +27,6 @@ import static org.mockito.Mockito.timeout;
 import static org.mockito.Mockito.verify;
 import static org.mockito.Mockito.when;
 
-import android.bluetooth.BluetoothAdapter;
 import android.bluetooth.BluetoothDevice;
 import android.media.AudioManager;
 import android.media.MediaPlayer;
@@ -43,10 +42,10 @@ import com.android.server.telecom.CallAudioRouteStateMachine;
 import com.android.server.telecom.DockManager;
 import com.android.server.telecom.InCallTonePlayer;
 import com.android.server.telecom.TelecomSystem;
-import com.android.server.telecom.Timeouts;
 import com.android.server.telecom.WiredHeadsetManager;
 import com.android.server.telecom.bluetooth.BluetoothDeviceManager;
 import com.android.server.telecom.bluetooth.BluetoothRouteManager;
+import com.android.server.telecom.flags.FeatureFlags;
 
 import org.junit.After;
 import org.junit.Before;
@@ -64,7 +63,6 @@ public class InCallTonePlayerTest extends TelecomTestCase {
 
     @Mock private BluetoothRouteManager mBluetoothRouteManager;
     @Mock private CallAudioRouteStateMachine mCallAudioRouteStateMachine;
-    @Mock private Timeouts.Adapter mTimeoutsAdapter;
     @Mock private BluetoothDeviceManager mBluetoothDeviceManager;
     @Mock private TelecomSystem.SyncRoot mLock;
     @Mock private ToneGenerator mToneGenerator;
@@ -73,7 +71,6 @@ public class InCallTonePlayerTest extends TelecomTestCase {
     @Mock private DockManager mDockManager;
     @Mock private AsyncRingtonePlayer mRingtonePlayer;
     @Mock private BluetoothDevice mDevice;
-    @Mock private BluetoothAdapter mBluetoothAdapter;
 
     private InCallTonePlayer.MediaPlayerAdapter mMediaPlayerAdapter =
             new InCallTonePlayer.MediaPlayerAdapter() {
@@ -115,7 +112,6 @@ public class InCallTonePlayerTest extends TelecomTestCase {
     private CallAudioManager mCallAudioManager;
     @Mock
     private Call mCall;
-
     private InCallTonePlayer mInCallTonePlayer;
 
     @Override
@@ -131,7 +127,7 @@ public class InCallTonePlayerTest extends TelecomTestCase {
                 mCallAudioRouteStateMachine, mBluetoothRouteManager, mWiredHeadsetManager,
                 mDockManager, mRingtonePlayer);
         mFactory = new InCallTonePlayer.Factory(mCallAudioRoutePeripheralAdapter, mLock,
-                mToneGeneratorFactory, mMediaPlayerFactory, mAudioManagerAdapter);
+                mToneGeneratorFactory, mMediaPlayerFactory, mAudioManagerAdapter, mFeatureFlags);
         mFactory.setCallAudioManager(mCallAudioManager);
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_CALL_ENDED);
     }
@@ -209,55 +205,92 @@ public class InCallTonePlayerTest extends TelecomTestCase {
                 eq(true));
     }
 
+    /**
+     * Only applicable when {@link FeatureFlags#useStreamVoiceCallTones()} is false and we use
+     * STREAM_BLUETOOTH_SCO for tones.
+     */
     @SmallTest
     @Test
     public void testRingbackToneAudioStreamHeadset() {
+        when(mFeatureFlags.useStreamVoiceCallTones()).thenReturn(false);
         when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
-        mBluetoothDeviceManager.setBluetoothRouteManager(mBluetoothRouteManager);
-        when(mBluetoothRouteManager.getBluetoothAudioConnectedDevice()).thenReturn(mDevice);
-        when(mBluetoothRouteManager.isBluetoothAudioConnectedOrPending()).thenReturn(true);
-
-        when(mBluetoothRouteManager.isCachedLeAudioDevice(mDevice)).thenReturn(false);
-        when(mBluetoothRouteManager.isCachedHearingAidDevice(mDevice)).thenReturn(false);
+        setConnectedBluetoothDevice(false /*isLe*/, false /*isHearingAid*/);
 
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_RING_BACK);
         assertTrue(mInCallTonePlayer.startTone());
+
         verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
                 .get(eq(AudioManager.STREAM_BLUETOOTH_SCO), anyInt());
         verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
     }
 
+    /**
+     * Only applicable when {@link FeatureFlags#useStreamVoiceCallTones()} is false and we use
+     * STREAM_BLUETOOTH_SCO for tones.
+     */
     @SmallTest
     @Test
     public void testCallWaitingToneAudioStreamHeadset() {
+        when(mFeatureFlags.useStreamVoiceCallTones()).thenReturn(false);
         when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
-        mBluetoothDeviceManager.setBluetoothRouteManager(mBluetoothRouteManager);
-        when(mBluetoothRouteManager.getBluetoothAudioConnectedDevice()).thenReturn(mDevice);
-        when(mBluetoothRouteManager.isBluetoothAudioConnectedOrPending()).thenReturn(true);
-
-        when(mBluetoothRouteManager.isCachedLeAudioDevice(mDevice)).thenReturn(false);
-        when(mBluetoothRouteManager.isCachedHearingAidDevice(mDevice)).thenReturn(false);
+        setConnectedBluetoothDevice(false /*isLe*/, false /*isHearingAid*/);
 
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_CALL_WAITING);
         assertTrue(mInCallTonePlayer.startTone());
+
         verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
                 .get(eq(AudioManager.STREAM_BLUETOOTH_SCO), anyInt());
         verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
     }
 
+
+    /**
+     * Only applicable when {@link FeatureFlags#useStreamVoiceCallTones()} is true and we use
+     * STREAM_VOICE_CALL for ALL tones.
+     */
     @SmallTest
     @Test
-    public void testRingbackToneAudioStreamHearingAid() {
+    public void testRingbackToneAudioStreamSco() {
+        when(mFeatureFlags.useStreamVoiceCallTones()).thenReturn(true);
         when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
-        mBluetoothDeviceManager.setBluetoothRouteManager(mBluetoothRouteManager);
-        when(mBluetoothRouteManager.getBluetoothAudioConnectedDevice()).thenReturn(mDevice);
-        when(mBluetoothRouteManager.isBluetoothAudioConnectedOrPending()).thenReturn(true);
+        setConnectedBluetoothDevice(false /*isLe*/, false /*isHearingAid*/);
+
+        mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_RING_BACK);
+        assertTrue(mInCallTonePlayer.startTone());
+
+        verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
+                .get(eq(AudioManager.STREAM_VOICE_CALL), anyInt());
+        verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
+    }
+
+    /**
+     * Only applicable when {@link FeatureFlags#useStreamVoiceCallTones()} is true and we use
+     * STREAM_VOICE_CALL for ALL tones.
+     */
+    @SmallTest
+    @Test
+    public void testRingbackToneAudioStreamLe() {
+        when(mFeatureFlags.useStreamVoiceCallTones()).thenReturn(true);
+        when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
+        setConnectedBluetoothDevice(true /*isLe*/, false /*isHearingAid*/);
 
-        when(mBluetoothRouteManager.isCachedLeAudioDevice(mDevice)).thenReturn(false);
-        when(mBluetoothRouteManager.isCachedHearingAidDevice(mDevice)).thenReturn(true);
+        mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_RING_BACK);
+        assertTrue(mInCallTonePlayer.startTone());
+
+        verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
+                .get(eq(AudioManager.STREAM_VOICE_CALL), anyInt());
+        verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
+    }
+
+    @SmallTest
+    @Test
+    public void testRingbackToneAudioStreamHearingAid() {
+        when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
+        setConnectedBluetoothDevice(false /*isLe*/, true /*isHearingAid*/);
 
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_RING_BACK);
         assertTrue(mInCallTonePlayer.startTone());
+
         verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
                 .get(eq(AudioManager.STREAM_VOICE_CALL), anyInt());
         verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
@@ -267,17 +300,27 @@ public class InCallTonePlayerTest extends TelecomTestCase {
     @Test
     public void testCallWaitingToneAudioStreamHearingAid() {
         when(mAudioManagerAdapter.isVolumeOverZero()).thenReturn(true);
-        mBluetoothDeviceManager.setBluetoothRouteManager(mBluetoothRouteManager);
-        when(mBluetoothRouteManager.getBluetoothAudioConnectedDevice()).thenReturn(mDevice);
-        when(mBluetoothRouteManager.isBluetoothAudioConnectedOrPending()).thenReturn(true);
-
-        when(mBluetoothRouteManager.isCachedLeAudioDevice(mDevice)).thenReturn(false);
-        when(mBluetoothRouteManager.isCachedHearingAidDevice(mDevice)).thenReturn(true);
+        setConnectedBluetoothDevice(false /*isLe*/, true /*isHearingAid*/);
 
         mInCallTonePlayer = mFactory.createPlayer(mCall, InCallTonePlayer.TONE_CALL_WAITING);
         assertTrue(mInCallTonePlayer.startTone());
+
         verify(mToneGeneratorFactory, timeout(TEST_TIMEOUT))
                 .get(eq(AudioManager.STREAM_VOICE_CALL), anyInt());
         verify(mCallAudioManager).setIsTonePlaying(any(Call.class), eq(true));
     }
+
+    /**
+     * Set a connected BT device. If not LE or Hearing Aid, it will be configured as SCO
+     * @param isLe true if LE
+     * @param isHearingAid true if hearing aid
+     */
+    private void setConnectedBluetoothDevice(boolean isLe, boolean isHearingAid) {
+        mBluetoothDeviceManager.setBluetoothRouteManager(mBluetoothRouteManager);
+        when(mBluetoothRouteManager.getBluetoothAudioConnectedDevice()).thenReturn(mDevice);
+        when(mBluetoothRouteManager.isBluetoothAudioConnectedOrPending()).thenReturn(true);
+
+        when(mBluetoothRouteManager.isCachedLeAudioDevice(mDevice)).thenReturn(isLe);
+        when(mBluetoothRouteManager.isCachedHearingAidDevice(mDevice)).thenReturn(isHearingAid);
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/IncomingCallFilterGraphTest.java b/tests/src/com/android/server/telecom/tests/IncomingCallFilterGraphTest.java
index 66ac55383..d7905b27e 100644
--- a/tests/src/com/android/server/telecom/tests/IncomingCallFilterGraphTest.java
+++ b/tests/src/com/android/server/telecom/tests/IncomingCallFilterGraphTest.java
@@ -17,22 +17,28 @@
 package com.android.server.telecom.tests;
 
 import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertFalse;
+import static org.junit.Assert.assertTrue;
 import static org.mockito.ArgumentMatchers.nullable;
+import static org.mockito.Mockito.mock;
 import static org.mockito.Mockito.when;
 
 import android.content.ContentResolver;
 import android.content.Context;
 import android.os.Handler;
 import android.os.HandlerThread;
+import android.util.Log;
 
 import androidx.test.filters.SmallTest;
 
 import com.android.server.telecom.Call;
+import com.android.server.telecom.Ringer;
 import com.android.server.telecom.TelecomSystem;
 import com.android.server.telecom.Timeouts;
 import com.android.server.telecom.callfiltering.CallFilter;
 import com.android.server.telecom.callfiltering.CallFilterResultCallback;
 import com.android.server.telecom.callfiltering.CallFilteringResult;
+import com.android.server.telecom.callfiltering.DndCallFilter;
 import com.android.server.telecom.callfiltering.IncomingCallFilterGraph;
 
 import org.junit.Before;
@@ -47,6 +53,7 @@ import java.util.concurrent.TimeUnit;
 
 @RunWith(JUnit4.class)
 public class IncomingCallFilterGraphTest extends TelecomTestCase {
+    private final String TAG = IncomingCallFilterGraphTest.class.getSimpleName();
     @Mock private Call mCall;
     @Mock private Context mContext;
     @Mock private Timeouts.Adapter mTimeoutsAdapter;
@@ -88,13 +95,15 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
         @Override
         public CompletionStage<CallFilteringResult> startFilterLookup(
                 CallFilteringResult priorStageResult) {
-            HandlerThread handlerThread = new HandlerThread("TimeoutFilter");
-            handlerThread.start();
-            Handler handler = new Handler(handlerThread.getLooper());
-
-            CompletableFuture<CallFilteringResult> resultFuture = new CompletableFuture<>();
-            handler.postDelayed(() -> resultFuture.complete(PASS_CALL_RESULT),
-                    TIMEOUT_FILTER_SLEEP_TIME);
+            Log.i(TAG, "TimeoutFilter: startFilterLookup: about to sleep");
+            try {
+                // Currently, there are no tools to fake a timeout with [CompletableFuture]s
+                // in the Android Platform. Thread sleep is the best option for an end-to-end test.
+                Thread.sleep(FILTER_TIMEOUT); // Simulate a filter timeout
+            } catch (InterruptedException e) {
+                e.printStackTrace();
+            }
+            Log.i(TAG, "TimeoutFilter: startFilterLookup: continuing test");
             return CompletableFuture.completedFuture(PASS_CALL_RESULT);
         }
     }
@@ -116,7 +125,7 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
         CallFilterResultCallback listener = (call, result, timeout) -> testResult.complete(result);
 
         IncomingCallFilterGraph graph = new IncomingCallFilterGraph(mCall, listener, mContext,
-                mTimeoutsAdapter, mLock);
+                mTimeoutsAdapter, mFeatureFlags, mLock);
         graph.performFiltering();
 
         assertEquals(PASS_CALL_RESULT, testResult.get(TEST_TIMEOUT, TimeUnit.MILLISECONDS));
@@ -129,7 +138,7 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
         CallFilterResultCallback listener = (call, result, timeout) -> testResult.complete(result);
 
         IncomingCallFilterGraph graph = new IncomingCallFilterGraph(mCall, listener, mContext,
-                mTimeoutsAdapter, mLock);
+                mTimeoutsAdapter, mFeatureFlags, mLock);
         AllowFilter allowFilter = new AllowFilter();
         DisallowFilter disallowFilter = new DisallowFilter();
         graph.addFilter(allowFilter);
@@ -147,7 +156,7 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
         CallFilterResultCallback listener = (call, result, timeout) -> testResult.complete(result);
 
         IncomingCallFilterGraph graph = new IncomingCallFilterGraph(mCall, listener, mContext,
-                mTimeoutsAdapter, mLock);
+                mTimeoutsAdapter, mFeatureFlags, mLock);
         AllowFilter allowFilter1 = new AllowFilter();
         AllowFilter allowFilter2 = new AllowFilter();
         DisallowFilter disallowFilter = new DisallowFilter();
@@ -166,7 +175,7 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
         CallFilterResultCallback listener = (call, result, timeout) -> testResult.complete(result);
 
         IncomingCallFilterGraph graph = new IncomingCallFilterGraph(mCall, listener, mContext,
-                mTimeoutsAdapter, mLock);
+                mTimeoutsAdapter, mFeatureFlags, mLock);
         DisallowFilter disallowFilter = new DisallowFilter();
         TimeoutFilter timeoutFilter = new TimeoutFilter();
         graph.addFilter(disallowFilter);
@@ -176,4 +185,57 @@ public class IncomingCallFilterGraphTest extends TelecomTestCase {
 
         assertEquals(REJECT_CALL_RESULT, testResult.get(TEST_TIMEOUT, TimeUnit.MILLISECONDS));
     }
+
+    /**
+     * Verify that when the Call Filtering Graph times out, already completed filters are combined.
+     * Graph being tested:
+     *
+     * startFilterLookup --> [ ALLOW_FILTER ]
+     *                            |
+     *         ---------------------------------
+     *        |                                |
+     *        |                                |
+     *    [DND_FILTER]                  [TIMEOUT_FILTER]
+     *        |                                |
+     *        |                        * timeout at 5 seconds *
+     *        |
+     *        |
+     *       --------[ CallFilteringResult ]
+     */
+    @SmallTest
+    @Test
+    public void testFilterTimesOutWithDndFilterComputedAlready() throws Exception {
+        // GIVEN: a graph that is set up like the above diagram in the test comment
+        Ringer mockRinger = mock(Ringer.class);
+        CompletableFuture<CallFilteringResult> testResult = new CompletableFuture<>();
+        IncomingCallFilterGraph graph = new IncomingCallFilterGraph(
+                mCall,
+                (call, result, timeout) -> testResult.complete(result),
+                mContext,
+                mTimeoutsAdapter,
+                mFeatureFlags,
+                mLock);
+        // create the filters / nodes  for the graph
+        TimeoutFilter timeoutFilter = new TimeoutFilter();
+        DndCallFilter dndCallFilter = new DndCallFilter(mCall, mockRinger);
+        AllowFilter allowFilter1 = new AllowFilter();
+        // adding them to the graph does not create the edges
+        graph.addFilter(allowFilter1);
+        graph.addFilter(timeoutFilter);
+        graph.addFilter(dndCallFilter);
+        // set up the graph so that the DND filter can process in parallel to the timeout
+        IncomingCallFilterGraph.addEdge(allowFilter1, dndCallFilter);
+        IncomingCallFilterGraph.addEdge(allowFilter1, timeoutFilter);
+
+        // WHEN:  DND is on and the caller cannot interrupt and the graph is processed
+        when(mockRinger.shouldRingForContact(mCall)).thenReturn(false);
+        when(mFeatureFlags.checkCompletedFiltersOnTimeout()).thenReturn(true);
+        dndCallFilter.startFilterLookup(IncomingCallFilterGraph.DEFAULT_RESULT);
+        graph.performFiltering();
+
+        // THEN: assert shouldSuppressCallDueToDndStatus is true!
+        assertFalse(IncomingCallFilterGraph.DEFAULT_RESULT.shouldSuppressCallDueToDndStatus);
+        assertTrue(testResult.get(TIMEOUT_FILTER_SLEEP_TIME,
+                TimeUnit.MILLISECONDS).shouldSuppressCallDueToDndStatus);
+    }
 }
diff --git a/tests/src/com/android/server/telecom/tests/RingerTest.java b/tests/src/com/android/server/telecom/tests/RingerTest.java
index 1215fd389..c4d967823 100644
--- a/tests/src/com/android/server/telecom/tests/RingerTest.java
+++ b/tests/src/com/android/server/telecom/tests/RingerTest.java
@@ -47,6 +47,7 @@ import android.media.AudioAttributes;
 import android.media.AudioManager;
 import android.media.Ringtone;
 import android.media.VolumeShaper;
+import android.media.audio.Flags;
 import android.net.Uri;
 import android.os.Bundle;
 import android.os.UserHandle;
@@ -55,8 +56,10 @@ import android.os.VibrationAttributes;
 import android.os.VibrationEffect;
 import android.os.Vibrator;
 import android.os.VibratorInfo;
+import android.platform.test.annotations.EnableFlags;
 import android.platform.test.flag.junit.CheckFlagsRule;
 import android.platform.test.flag.junit.DeviceFlagsValueProvider;
+import android.platform.test.flag.junit.SetFlagsRule;
 import android.telecom.PhoneAccountHandle;
 import android.telecom.TelecomManager;
 import android.util.Pair;
@@ -91,7 +94,14 @@ public class RingerTest extends TelecomTestCase {
     @Rule
     public final CheckFlagsRule mCheckFlagsRule = DeviceFlagsValueProvider.createCheckFlagsRule();
 
+    @Rule
+    public final SetFlagsRule mSetFlagsRule = new SetFlagsRule();
+
     private static final Uri FAKE_RINGTONE_URI = Uri.parse("content://media/fake/audio/1729");
+
+    private static final Uri FAKE_VIBRATION_URI = Uri.parse("file://media/fake/vibration/1729");
+
+    private static final String VIBRATION_PARAM = "vibration_uri";
     // Returned when the a URI-based VibrationEffect is attempted, to avoid depending on actual
     // device configuration for ringtone URIs. The actual Uri can be verified via the
     // VibrationEffectProxy mock invocation.
@@ -136,6 +146,7 @@ public class RingerTest extends TelecomTestCase {
         super.setUp();
         mContext = spy(mComponentContextFixture.getTestDouble().getApplicationContext());
         when(mFeatureFlags.telecomResolveHiddenDependencies()).thenReturn(true);
+        when(mFeatureFlags.ensureInCarRinging()).thenReturn(false);
         doReturn(URI_VIBRATION_EFFECT).when(spyVibrationEffectProxy).get(any(), any());
         when(mockPlayerFactory.createPlayer(any(Call.class), anyInt())).thenReturn(mockTonePlayer);
         mockAudioManager = mContext.getSystemService(AudioManager.class);
@@ -323,19 +334,6 @@ public class RingerTest extends TelecomTestCase {
         assertEquals(EXPECTED_SIMPLE_VIBRATION_PATTERN, mRingerUnderTest.mDefaultVibrationEffect);
     }
 
-    @SmallTest
-    @Test
-    public void testNoActionInTheaterMode() throws Exception {
-        // Start call waiting to make sure that it doesn't stop when we start ringing
-        mRingerUnderTest.startCallWaiting(mockCall1);
-        when(mockSystemSettingsUtil.isTheaterModeOn(any(Context.class))).thenReturn(true);
-        assertFalse(startRingingAndWaitForAsync(mockCall2, false));
-        verifyZeroInteractions(mockRingtoneFactory);
-        verify(mockTonePlayer, never()).stopTone();
-        verify(mockVibrator, never())
-                .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
-    }
-
     @SmallTest
     @Test
     public void testNoActionWithExternalRinger() throws Exception {
@@ -436,6 +434,62 @@ public class RingerTest extends TelecomTestCase {
                 any(VibrationAttributes.class));
     }
 
+    @SmallTest
+    @Test
+    public void testAudibleRingWhenNotificationSoundShouldPlay() throws Exception {
+        when(mFeatureFlags.ensureInCarRinging()).thenReturn(true);
+        Ringtone mockRingtone = ensureRingtoneMocked();
+
+        mRingerUnderTest.startCallWaiting(mockCall1);
+        AudioAttributes aa = new AudioAttributes.Builder()
+                .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
+                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build();
+        // Set AudioManager#shouldNotificationSoundPlay to true:
+        when(mockAudioManager.shouldNotificationSoundPlay(aa)).thenReturn(true);
+        enableVibrationWhenRinging();
+
+        // This will set AudioManager#getStreamVolume to 0. This test ensures that whether a
+        // ringtone is audible is controlled by AudioManager#shouldNotificationSoundPlay instead:
+        ensureRingerIsNotAudible();
+
+        // Ensure an audible ringtone is played:
+        assertTrue(startRingingAndWaitForAsync(mockCall2, false));
+        verify(mockTonePlayer).stopTone();
+        verify(mockRingtoneFactory, atLeastOnce()).getRingtone(any(Call.class),
+                nullable(VolumeShaper.Configuration.class), anyBoolean());
+        verifyNoMoreInteractions(mockRingtoneFactory);
+        verify(mockRingtone).play();
+
+        // Ensure a vibration plays:
+        verify(mockVibrator).vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
+    }
+
+    @SmallTest
+    @Test
+    public void testNoAudibleRingWhenNotificationSoundShouldNotPlay() throws Exception {
+        when(mFeatureFlags.ensureInCarRinging()).thenReturn(true);
+        Ringtone mockRingtone = ensureRingtoneMocked();
+
+        mRingerUnderTest.startCallWaiting(mockCall1);
+        AudioAttributes aa = new AudioAttributes.Builder()
+                .setUsage(AudioAttributes.USAGE_NOTIFICATION_RINGTONE)
+                .setContentType(AudioAttributes.CONTENT_TYPE_SONIFICATION).build();
+        // Set AudioManager#shouldNotificationSoundPlay to false:
+        when(mockAudioManager.shouldNotificationSoundPlay(aa)).thenReturn(false);
+        enableVibrationWhenRinging();
+
+        // This will set AudioManager#getStreamVolume to 100. This test ensures that whether a
+        // ringtone is audible is controlled by AudioManager#shouldNotificationSoundPlay instead:
+        ensureRingerIsAudible();
+
+        // Ensure no audible ringtone is played:
+        assertFalse(startRingingAndWaitForAsync(mockCall2, false));
+        verify(mockTonePlayer).stopTone();
+
+        // Ensure a vibration plays:
+        verify(mockVibrator).vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
+    }
+
     @SmallTest
     @Test
     public void testVibrateButNoRingForNullRingtone() throws Exception {
@@ -475,10 +529,6 @@ public class RingerTest extends TelecomTestCase {
         enableVibrationWhenRinging();
         assertFalse(startRingingAndWaitForAsync(mockCall2, false));
         verify(mockTonePlayer).stopTone();
-        // Try to play a silent haptics ringtone
-        verify(mockRingtoneFactory, atLeastOnce()).getHapticOnlyRingtone();
-        verifyNoMoreInteractions(mockRingtoneFactory);
-        verify(mockRingtone).play();
 
         // Play default vibration when future completes with no audio coupled haptics
         verify(mockVibrator).vibrate(eq(mRingerUnderTest.mDefaultVibrationEffect),
@@ -503,28 +553,6 @@ public class RingerTest extends TelecomTestCase {
                 any(VibrationAttributes.class));
     }
 
-    @SmallTest
-    @Test
-    public void testAudioCoupledHapticsForSilentRingtone() throws Exception {
-        Ringtone mockRingtone = ensureRingtoneMocked();
-
-        mRingerUnderTest.startCallWaiting(mockCall1);
-        when(mockAudioManager.getRingerMode()).thenReturn(AudioManager.RINGER_MODE_VIBRATE);
-        when(mockAudioManager.getStreamVolume(AudioManager.STREAM_RING)).thenReturn(0);
-        setIsUsingHaptics(mockRingtone, true);
-        enableVibrationWhenRinging();
-        assertFalse(startRingingAndWaitForAsync(mockCall2, false));
-
-        verify(mockRingtoneFactory, atLeastOnce()).getHapticOnlyRingtone();
-        verifyNoMoreInteractions(mockRingtoneFactory);
-        verify(mockTonePlayer).stopTone();
-        // Try to play a silent haptics ringtone
-        verify(mockRingtone).play();
-        // Skip vibration for audio coupled haptics
-        verify(mockVibrator, never()).vibrate(any(VibrationEffect.class),
-                any(VibrationAttributes.class));
-    }
-
     @SmallTest
     @Test
     public void testCustomVibrationForRingtone() throws Exception {
@@ -787,6 +815,37 @@ public class RingerTest extends TelecomTestCase {
                 .vibrate(any(VibrationEffect.class), any(VibrationAttributes.class));
     }
 
+    @SmallTest
+    @Test
+    @EnableFlags(Flags.FLAG_ENABLE_RINGTONE_HAPTICS_CUSTOMIZATION)
+    public void testNoVibrateForSilentRingtoneIfRingtoneHasVibration() throws Exception {
+        Uri FAKE_RINGTONE_VIBRATION_URI =
+                FAKE_RINGTONE_URI.buildUpon().appendQueryParameter(
+                        VIBRATION_PARAM, FAKE_VIBRATION_URI.toString()).build();
+        Ringtone mockRingtone = mock(Ringtone.class);
+        Pair<Uri, Ringtone> ringtoneInfo = new Pair(FAKE_RINGTONE_VIBRATION_URI, mockRingtone);
+        when(mockRingtoneFactory.getRingtone(
+                any(Call.class), nullable(VolumeShaper.Configuration.class), anyBoolean()))
+                .thenReturn(ringtoneInfo);
+        mComponentContextFixture.putBooleanResource(
+                com.android.internal.R.bool.config_ringtoneVibrationSettingsSupported, true);
+        createRingerUnderTest(); // Needed after mock the config.
+
+        mRingerUnderTest.startCallWaiting(mockCall1);
+        when(mockAudioManager.getRingerMode()).thenReturn(AudioManager.RINGER_MODE_VIBRATE);
+        when(mockAudioManager.getStreamVolume(AudioManager.STREAM_RING)).thenReturn(0);
+        enableVibrationWhenRinging();
+        assertFalse(startRingingAndWaitForAsync(mockCall2, false));
+
+        verify(mockRingtoneFactory, atLeastOnce())
+                .getRingtone(any(Call.class), eq(null), eq(false));
+        verifyNoMoreInteractions(mockRingtoneFactory);
+        verify(mockTonePlayer).stopTone();
+        // Skip vibration play in Ringer if a vibration was specified to the ringtone
+        verify(mockVibrator, never()).vibrate(any(VibrationEffect.class),
+                any(VibrationAttributes.class));
+    }
+
     /**
      * Call startRinging and wait for its effects to have played out, to allow reliable assertions
      * after it. The effects are generally "start playing ringtone" and "start vibration" - not
@@ -838,7 +897,6 @@ public class RingerTest extends TelecomTestCase {
         when(mockRingtoneFactory.getRingtone(
                 any(Call.class), nullable(VolumeShaper.Configuration.class), anyBoolean()))
                 .thenReturn(ringtoneInfo);
-        when(mockRingtoneFactory.getHapticOnlyRingtone()).thenReturn(ringtoneInfo);
         return mockRingtone;
     }
 
diff --git a/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
new file mode 100644
index 000000000..e2ab8d6ac
--- /dev/null
+++ b/tests/src/com/android/server/telecom/tests/TelecomMetricsControllerTest.java
@@ -0,0 +1,157 @@
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
+package com.android.server.telecom.tests;
+
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_API_STATS;
+import static com.android.server.telecom.TelecomStatsLog.TELECOM_ERROR_STATS;
+import static com.google.common.truth.Truth.assertThat;
+import static org.mockito.ArgumentMatchers.any;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.verify;
+
+import android.app.StatsManager;
+import android.os.HandlerThread;
+import android.util.StatsEvent;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.server.telecom.metrics.ApiStats;
+import com.android.server.telecom.metrics.AudioRouteStats;
+import com.android.server.telecom.metrics.CallStats;
+import com.android.server.telecom.metrics.ErrorStats;
+import com.android.server.telecom.metrics.TelecomMetricsController;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Test;
+import org.junit.runner.RunWith;
+import org.mockito.ArgumentCaptor;
+import org.mockito.Mock;
+
+import java.util.ArrayList;
+import java.util.List;
+
+@RunWith(AndroidJUnit4.class)
+public class TelecomMetricsControllerTest extends TelecomTestCase {
+
+    @Mock
+    ApiStats mApiStats;
+    @Mock
+    AudioRouteStats mAudioRouteStats;
+    @Mock
+    CallStats mCallStats;
+    @Mock
+    ErrorStats mErrorStats;
+
+    HandlerThread mHandlerThread;
+
+    TelecomMetricsController mTelecomMetricsController;
+
+    @Override
+    @Before
+    public void setUp() throws Exception {
+        super.setUp();
+        mHandlerThread = new HandlerThread("TelecomMetricsControllerTest");
+        mHandlerThread.start();
+        mTelecomMetricsController = TelecomMetricsController.make(mContext, mHandlerThread);
+        assertThat(mTelecomMetricsController).isNotNull();
+        setUpStats();
+    }
+
+    @Override
+    @After
+    public void tearDown() throws Exception {
+        mTelecomMetricsController.destroy();
+        mHandlerThread.quitSafely();
+        super.tearDown();
+    }
+
+    @Test
+    public void testGetApiStatsReturnsSameInstance() {
+        ApiStats stats1 = mTelecomMetricsController.getApiStats();
+        ApiStats stats2 = mTelecomMetricsController.getApiStats();
+        assertThat(stats1).isSameInstanceAs(stats2);
+    }
+
+    @Test
+    public void testGetAudioRouteStatsReturnsSameInstance() {
+        AudioRouteStats stats1 = mTelecomMetricsController.getAudioRouteStats();
+        AudioRouteStats stats2 = mTelecomMetricsController.getAudioRouteStats();
+        assertThat(stats1).isSameInstanceAs(stats2);
+    }
+
+    @Test
+    public void testGetCallStatsReturnsSameInstance() {
+        CallStats stats1 = mTelecomMetricsController.getCallStats();
+        CallStats stats2 = mTelecomMetricsController.getCallStats();
+        assertThat(stats1).isSameInstanceAs(stats2);
+    }
+
+    @Test
+    public void testGetErrorStatsReturnsSameInstance() {
+        ErrorStats stats1 = mTelecomMetricsController.getErrorStats();
+        ErrorStats stats2 = mTelecomMetricsController.getErrorStats();
+        assertThat(stats1).isSameInstanceAs(stats2);
+    }
+
+    @Test
+    public void testOnPullAtomReturnsPullSkipIfAtomNotRegistered() {
+        mTelecomMetricsController.getStats().clear();
+
+        int result = mTelecomMetricsController.onPullAtom(TELECOM_API_STATS, null);
+        assertThat(result).isEqualTo(StatsManager.PULL_SKIP);
+    }
+
+    @Test
+    public void testRegisterAtomIsSameInstance() {
+        ApiStats stats = mock(ApiStats.class);
+
+        mTelecomMetricsController.registerAtom(TELECOM_API_STATS, stats);
+
+        assertThat(mTelecomMetricsController.getStats().get(TELECOM_API_STATS))
+                .isSameInstanceAs(stats);
+    }
+
+    @Test
+    public void testDestroy() {
+        mTelecomMetricsController.destroy();
+        assertThat(mTelecomMetricsController.getStats()).isEmpty();
+    }
+
+    @Test
+    public void testOnPullAtomIsPulled() {
+        final List<StatsEvent> data = new ArrayList<>();
+        final ArgumentCaptor<List<StatsEvent>> captor = ArgumentCaptor.forClass((Class) List.class);
+        doReturn(StatsManager.PULL_SUCCESS).when(mApiStats).pull(any());
+
+        int result = mTelecomMetricsController.onPullAtom(TELECOM_API_STATS, data);
+
+        verify(mApiStats).pull(captor.capture());
+        assertThat(result).isEqualTo(StatsManager.PULL_SUCCESS);
+        assertThat(captor.getValue()).isEqualTo(data);
+    }
+
+    private void setUpStats() {
+        mTelecomMetricsController.getStats().put(CALL_AUDIO_ROUTE_STATS,
+                mAudioRouteStats);
+        mTelecomMetricsController.getStats().put(CALL_STATS, mCallStats);
+        mTelecomMetricsController.getStats().put(TELECOM_API_STATS, mApiStats);
+        mTelecomMetricsController.getStats().put(TELECOM_ERROR_STATS, mErrorStats);
+    }
+}
diff --git a/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
new file mode 100644
index 000000000..bc8aeac8e
--- /dev/null
+++ b/tests/src/com/android/server/telecom/tests/TelecomPulledAtomTest.java
@@ -0,0 +1,814 @@
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
+package com.android.server.telecom.tests;
+
+import static com.android.server.telecom.AudioRoute.TYPE_BLUETOOTH_LE;
+import static com.android.server.telecom.AudioRoute.TYPE_EARPIECE;
+import static com.android.server.telecom.AudioRoute.TYPE_SPEAKER;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM;
+import static com.android.server.telecom.TelecomStatsLog.CALL_STATS__CALL_DIRECTION__DIR_INCOMING;
+import static org.junit.Assert.assertEquals;
+import static org.junit.Assert.assertNotNull;
+import static org.junit.Assert.assertTrue;
+import static org.mockito.Mockito.any;
+import static org.mockito.Mockito.anyInt;
+import static org.mockito.Mockito.anyString;
+import static org.mockito.Mockito.doReturn;
+import static org.mockito.Mockito.eq;
+import static org.mockito.Mockito.mock;
+import static org.mockito.Mockito.never;
+import static org.mockito.Mockito.spy;
+import static org.mockito.Mockito.times;
+import static org.mockito.Mockito.verify;
+
+import android.app.StatsManager;
+import android.content.Context;
+import android.os.Looper;
+import android.os.UserHandle;
+import android.telecom.PhoneAccount;
+import android.util.StatsEvent;
+
+import androidx.test.ext.junit.runners.AndroidJUnit4;
+
+import com.android.server.telecom.AudioRoute;
+import com.android.server.telecom.Call;
+import com.android.server.telecom.PendingAudioRoute;
+import com.android.server.telecom.metrics.ApiStats;
+import com.android.server.telecom.metrics.AudioRouteStats;
+import com.android.server.telecom.metrics.CallStats;
+import com.android.server.telecom.metrics.ErrorStats;
+import com.android.server.telecom.nano.PulledAtomsClass;
+
+import org.junit.After;
+import org.junit.Before;
+import org.junit.Rule;
+import org.junit.Test;
+import org.junit.rules.TemporaryFolder;
+import org.junit.runner.RunWith;
+import org.mockito.Mock;
+
+import java.io.File;
+import java.io.FileOutputStream;
+import java.io.IOException;
+import java.util.ArrayList;
+import java.util.List;
+
+@RunWith(AndroidJUnit4.class)
+public class TelecomPulledAtomTest extends TelecomTestCase {
+    private static final long MIN_PULL_INTERVAL_MILLIS = 23L * 60 * 60 * 1000;
+    private static final long DEFAULT_TIMESTAMPS_MILLIS = 3000;
+    private static final int DELAY_FOR_PERSISTENT_MILLIS = 30000;
+    private static final int DELAY_TOLERANCE = 50;
+    private static final int TEST_TIMEOUT = (int) AudioRouteStats.THRESHOLD_REVERT_MS + 1000;
+    private static final String FILE_NAME_TEST_ATOM = "test_atom.pb";
+
+    private static final int VALUE_ATOM_COUNT = 1;
+
+    private static final int VALUE_UID = 10000 + 1;
+    private static final int VALUE_API_ID = 1;
+    private static final int VALUE_API_RESULT = 1;
+    private static final int VALUE_API_COUNT = 1;
+
+    private static final int VALUE_AUDIO_ROUTE_TYPE1 = 1;
+    private static final int VALUE_AUDIO_ROUTE_TYPE2 = 2;
+    private static final int VALUE_AUDIO_ROUTE_COUNT = 1;
+    private static final int VALUE_AUDIO_ROUTE_LATENCY = 300;
+
+    private static final int VALUE_CALL_DIRECTION = 1;
+    private static final int VALUE_CALL_ACCOUNT_TYPE = 1;
+    private static final int VALUE_CALL_COUNT = 1;
+    private static final int VALUE_CALL_DURATION = 3000;
+
+    private static final int VALUE_MODULE_ID = 1;
+    private static final int VALUE_ERROR_ID = 1;
+    private static final int VALUE_ERROR_COUNT = 1;
+
+    @Rule
+    public TemporaryFolder mTempFolder = new TemporaryFolder();
+    @Mock
+    FileOutputStream mFileOutputStream;
+    @Mock
+    PendingAudioRoute mMockPendingAudioRoute;
+    @Mock
+    AudioRoute mMockSourceRoute;
+    @Mock
+    AudioRoute mMockDestRoute;
+    private File mTempFile;
+    private Looper mLooper;
+    private Context mSpyContext;
+
+    @Before
+    @Override
+    public void setUp() throws Exception {
+        super.setUp();
+
+        mSpyContext = spy(mContext);
+        mLooper = Looper.getMainLooper();
+        mTempFile = mTempFolder.newFile(FILE_NAME_TEST_ATOM);
+        doReturn(mTempFile).when(mSpyContext).getFileStreamPath(anyString());
+        doReturn(mFileOutputStream).when(mSpyContext).openFileOutput(anyString(), anyInt());
+        doReturn(mMockSourceRoute).when(mMockPendingAudioRoute).getOrigRoute();
+        doReturn(mMockDestRoute).when(mMockPendingAudioRoute).getDestRoute();
+        doReturn(TYPE_EARPIECE).when(mMockSourceRoute).getType();
+        doReturn(TYPE_BLUETOOTH_LE).when(mMockDestRoute).getType();
+    }
+
+    @After
+    @Override
+    public void tearDown() throws Exception {
+        mTempFile.delete();
+        super.tearDown();
+    }
+
+    @Test
+    public void testNewPulledAtomsFromFileInvalid() throws Exception {
+        mTempFile.delete();
+
+        ApiStats apiStats = new ApiStats(mSpyContext, mLooper);
+
+        assertNotNull(apiStats.mPulledAtoms);
+        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 0);
+
+        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper);
+
+        assertNotNull(audioRouteStats.mPulledAtoms);
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 0);
+
+        CallStats callStats = new CallStats(mSpyContext, mLooper);
+
+        assertNotNull(callStats.mPulledAtoms);
+        assertEquals(callStats.mPulledAtoms.callStats.length, 0);
+
+        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper);
+
+        assertNotNull(errorStats.mPulledAtoms);
+        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 0);
+    }
+
+    @Test
+    public void testNewPulledAtomsFromFileValid() throws Exception {
+        createTestFileForApiStats(DEFAULT_TIMESTAMPS_MILLIS);
+        ApiStats apiStats = new ApiStats(mSpyContext, mLooper);
+
+        verifyTestDataForApiStats(apiStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
+
+        createTestFileForAudioRouteStats(DEFAULT_TIMESTAMPS_MILLIS);
+        AudioRouteStats audioRouteStats = new AudioRouteStats(mSpyContext, mLooper);
+
+        verifyTestDataForAudioRouteStats(audioRouteStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
+
+        createTestFileForCallStats(DEFAULT_TIMESTAMPS_MILLIS);
+        CallStats callStats = new CallStats(mSpyContext, mLooper);
+
+        verifyTestDataForCallStats(callStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
+
+        createTestFileForErrorStats(DEFAULT_TIMESTAMPS_MILLIS);
+        ErrorStats errorStats = new ErrorStats(mSpyContext, mLooper);
+
+        verifyTestDataForErrorStats(errorStats.mPulledAtoms, DEFAULT_TIMESTAMPS_MILLIS);
+    }
+
+    @Test
+    public void testPullApiStatsLessThanMinPullIntervalShouldSkip() throws Exception {
+        createTestFileForApiStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = apiStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SKIP, result);
+        verify(apiStats, never()).onPull(any());
+        assertEquals(data.size(), 0);
+    }
+
+    @Test
+    public void testPullApiStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
+        createTestFileForApiStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = apiStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SUCCESS, result);
+        verify(apiStats).onPull(eq(data));
+        assertEquals(data.size(), apiStats.mPulledAtoms.telecomApiStats.length);
+    }
+
+    @Test
+    public void testPullAudioRouteStatsLessThanMinPullIntervalShouldSkip() throws Exception {
+        createTestFileForAudioRouteStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = audioRouteStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SKIP, result);
+        verify(audioRouteStats, never()).onPull(any());
+        assertEquals(data.size(), 0);
+    }
+
+    @Test
+    public void testPullAudioRouteStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
+        createTestFileForAudioRouteStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = audioRouteStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SUCCESS, result);
+        verify(audioRouteStats).onPull(eq(data));
+        assertEquals(data.size(), audioRouteStats.mPulledAtoms.callAudioRouteStats.length);
+    }
+
+    @Test
+    public void testPullCallStatsLessThanMinPullIntervalShouldSkip() throws Exception {
+        createTestFileForCallStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = callStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SKIP, result);
+        verify(callStats, never()).onPull(any());
+        assertEquals(data.size(), 0);
+    }
+
+    @Test
+    public void testPullCallStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
+        createTestFileForCallStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = callStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SUCCESS, result);
+        verify(callStats).onPull(eq(data));
+        assertEquals(data.size(), callStats.mPulledAtoms.callStats.length);
+    }
+
+    @Test
+    public void testPullErrorStatsLessThanMinPullIntervalShouldSkip() throws Exception {
+        createTestFileForErrorStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS / 2);
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = errorStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SKIP, result);
+        verify(errorStats, never()).onPull(any());
+        assertEquals(data.size(), 0);
+    }
+
+    @Test
+    public void testPullErrorStatsGreaterThanMinPullIntervalShouldNotSkip() throws Exception {
+        createTestFileForErrorStats(System.currentTimeMillis() - MIN_PULL_INTERVAL_MILLIS - 1);
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+        final List<StatsEvent> data = new ArrayList<>();
+
+        int result = errorStats.pull(data);
+
+        assertEquals(StatsManager.PULL_SUCCESS, result);
+        verify(errorStats).onPull(eq(data));
+        assertEquals(data.size(), errorStats.mPulledAtoms.telecomErrorStats.length);
+    }
+
+    @Test
+    public void testApiStatsLog() throws Exception {
+        ApiStats apiStats = spy(new ApiStats(mSpyContext, mLooper));
+
+        apiStats.log(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
+        waitForHandlerAction(apiStats, TEST_TIMEOUT);
+
+        verify(apiStats, times(1)).onAggregate();
+        verify(apiStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 1);
+        verifyMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats[0], VALUE_API_ID,
+                VALUE_UID, VALUE_API_RESULT, 1);
+
+        apiStats.log(VALUE_API_ID, VALUE_UID, VALUE_API_RESULT);
+        waitForHandlerAction(apiStats, TEST_TIMEOUT);
+
+        verify(apiStats, times(2)).onAggregate();
+        verify(apiStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(apiStats.mPulledAtoms.telecomApiStats.length, 1);
+        verifyMessageForApiStats(apiStats.mPulledAtoms.telecomApiStats[0], VALUE_API_ID,
+                VALUE_UID, VALUE_API_RESULT, 2);
+    }
+
+    @Test
+    public void testAudioRouteStatsLog() throws Exception {
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.log(VALUE_AUDIO_ROUTE_TYPE1, VALUE_AUDIO_ROUTE_TYPE2, true, false,
+                VALUE_AUDIO_ROUTE_LATENCY);
+        waitForHandlerAction(audioRouteStats, TEST_TIMEOUT);
+
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                VALUE_AUDIO_ROUTE_TYPE1, VALUE_AUDIO_ROUTE_TYPE2, true, false, 1,
+                VALUE_AUDIO_ROUTE_LATENCY);
+
+        audioRouteStats.log(VALUE_AUDIO_ROUTE_TYPE1, VALUE_AUDIO_ROUTE_TYPE2, true, false,
+                VALUE_AUDIO_ROUTE_LATENCY);
+        waitForHandlerAction(audioRouteStats, TEST_TIMEOUT);
+
+        verify(audioRouteStats, times(2)).onAggregate();
+        verify(audioRouteStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                VALUE_AUDIO_ROUTE_TYPE1, VALUE_AUDIO_ROUTE_TYPE2, true, false, 2,
+                VALUE_AUDIO_ROUTE_LATENCY);
+    }
+
+    @Test
+    public void testAudioRouteStatsOnEnterThenExit() throws Exception {
+        int latency = 500;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+        audioRouteStats.onRouteExit(mMockPendingAudioRoute, true);
+        waitForHandlerAction(audioRouteStats, 100);
+
+        // Verify that the stats should not be saved before the revert threshold is expired
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+
+        // Verify that the stats should be saved when the revert threshold is expired
+        waitForHandlerActionDelayed(
+                audioRouteStats, TEST_TIMEOUT, AudioRouteStats.THRESHOLD_REVERT_MS);
+
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE,
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE, true, false, 1,
+                latency);
+    }
+
+    @Test
+    public void testAudioRouteStatsOnRevertToSourceInThreshold() throws Exception {
+        int delay = 100;
+        int latency = 500;
+        int duration = 1000;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+        audioRouteStats.onRouteExit(mMockPendingAudioRoute, true);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        // Verify that the stats should not be saved before the revert threshold is expired
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+
+        // Verify that the event should be saved as revert when routing back to the source before
+        // the revert threshold is expired
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, duration);
+
+        // Reverse the audio types
+        doReturn(TYPE_BLUETOOTH_LE).when(mMockSourceRoute).getType();
+        doReturn(TYPE_EARPIECE).when(mMockDestRoute).getType();
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE,
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE, true, true, 1,
+                latency);
+    }
+
+    @Test
+    public void testAudioRouteStatsOnRevertToSourceBeyondThreshold() throws Exception {
+        int delay = 100;
+        int latency = 500;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+        audioRouteStats.onRouteExit(mMockPendingAudioRoute, true);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        // Verify that the stats should not be saved before the revert threshold is expired
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+
+        // Verify that the event should not be saved as revert when routing back to the source
+        // after the revert threshold is expired
+        waitForHandlerActionDelayed(
+                audioRouteStats, TEST_TIMEOUT, AudioRouteStats.THRESHOLD_REVERT_MS);
+
+        // Reverse the audio types
+        doReturn(TYPE_BLUETOOTH_LE).when(mMockSourceRoute).getType();
+        doReturn(TYPE_EARPIECE).when(mMockDestRoute).getType();
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE,
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE, true, false, 1,
+                latency);
+    }
+
+    @Test
+    public void testAudioRouteStatsOnRouteToAnotherDestInThreshold() throws Exception {
+        int delay = 100;
+        int latency = 500;
+        int duration = 1000;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+        audioRouteStats.onRouteExit(mMockPendingAudioRoute, true);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        // Verify that the stats should not be saved before the revert threshold is expired
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+
+        // Verify that the event should not be saved as  revert when routing to a type different
+        // as the source before the revert threshold is expired
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, duration);
+
+        AudioRoute dest2 = mock(AudioRoute.class);
+        doReturn(TYPE_SPEAKER).when(dest2).getType();
+        doReturn(dest2).when(mMockPendingAudioRoute).getDestRoute();
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerAction(audioRouteStats, delay);
+
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(audioRouteStats.mPulledAtoms.callAudioRouteStats.length, 1);
+        verifyMessageForAudioRouteStats(audioRouteStats.mPulledAtoms.callAudioRouteStats[0],
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_EARPIECE,
+                CALL_AUDIO_ROUTE_STATS__ROUTE_SOURCE__CALL_AUDIO_BLUETOOTH_LE, true, false, 1,
+                latency);
+    }
+
+    @Test
+    public void testAudioRouteStatsOnMultipleEnterWithoutExit() throws Exception {
+        int latency = 500;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+
+        doReturn(mMockDestRoute).when(mMockPendingAudioRoute).getOrigRoute();
+        AudioRoute dest2 = mock(AudioRoute.class);
+        doReturn(TYPE_SPEAKER).when(dest2).getType();
+        doReturn(dest2).when(mMockPendingAudioRoute).getDestRoute();
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+
+        // Verify that the stats should not be saved without exit
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+    }
+
+    @Test
+    public void testAudioRouteStatsOnMultipleEnterWithExit() throws Exception {
+        int latency = 500;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+        audioRouteStats.onRouteExit(mMockPendingAudioRoute, true);
+        waitForHandlerAction(audioRouteStats, 100);
+
+        doReturn(mMockDestRoute).when(mMockPendingAudioRoute).getOrigRoute();
+        AudioRoute dest2 = mock(AudioRoute.class);
+        doReturn(TYPE_SPEAKER).when(dest2).getType();
+        doReturn(dest2).when(mMockPendingAudioRoute).getDestRoute();
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+
+        // Verify that the stats should be saved after exit
+        verify(audioRouteStats, times(1)).onAggregate();
+        verify(audioRouteStats, times(1)).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+    }
+
+    @Test
+    public void testAudioRouteStatsOnRouteToSameDestWithExit() throws Exception {
+        int latency = 500;
+        AudioRouteStats audioRouteStats = spy(new AudioRouteStats(mSpyContext, mLooper));
+        doReturn(mMockSourceRoute).when(mMockPendingAudioRoute).getDestRoute();
+
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+
+        // Enter again to trigger the log
+        AudioRoute dest2 = mock(AudioRoute.class);
+        doReturn(TYPE_SPEAKER).when(dest2).getType();
+        doReturn(dest2).when(mMockPendingAudioRoute).getDestRoute();
+        audioRouteStats.onRouteEnter(mMockPendingAudioRoute);
+        waitForHandlerActionDelayed(audioRouteStats, TEST_TIMEOUT, latency);
+
+        // Verify that the stats should not be saved without exit
+        verify(audioRouteStats, never()).onAggregate();
+        verify(audioRouteStats, never()).save(anyInt());
+        assertTrue(audioRouteStats.hasMessages(AudioRouteStats.EVENT_REVERT_THRESHOLD_EXPIRED));
+    }
+
+    @Test
+    public void testCallStatsLog() throws Exception {
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+
+        callStats.log(VALUE_CALL_DIRECTION, false, false, true, VALUE_CALL_ACCOUNT_TYPE,
+                VALUE_UID, VALUE_CALL_DURATION);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        verify(callStats, times(1)).onAggregate();
+        verify(callStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(callStats.mPulledAtoms.callStats.length, 1);
+        verifyMessageForCallStats(callStats.mPulledAtoms.callStats[0], VALUE_CALL_DIRECTION,
+                false, false, true, VALUE_CALL_ACCOUNT_TYPE, VALUE_UID, 1, VALUE_CALL_DURATION);
+
+        callStats.log(VALUE_CALL_DIRECTION, false, false, true, VALUE_CALL_ACCOUNT_TYPE,
+                VALUE_UID, VALUE_CALL_DURATION);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        verify(callStats, times(2)).onAggregate();
+        verify(callStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(callStats.mPulledAtoms.callStats.length, 1);
+        verifyMessageForCallStats(callStats.mPulledAtoms.callStats[0], VALUE_CALL_DIRECTION,
+                false, false, true, VALUE_CALL_ACCOUNT_TYPE, VALUE_UID, 2, VALUE_CALL_DURATION);
+    }
+
+    @Test
+    public void testCallStatsOnStartThenEnd() throws Exception {
+        int duration = 1000;
+        UserHandle uh = UserHandle.of(UserHandle.USER_SYSTEM);
+        PhoneAccount account = mock(PhoneAccount.class);
+        Call call = mock(Call.class);
+        doReturn(true).when(call).isIncoming();
+        doReturn(account).when(call).getPhoneAccountFromHandle();
+        doReturn((long) duration).when(call).getAgeMillis();
+        doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
+        doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_CALL_PROVIDER));
+        doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
+        doReturn(uh).when(call).getAssociatedUser();
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+
+        callStats.onCallStart(call);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        callStats.onCallEnd(call);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
+                eq(false), eq(false), eq(false), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
+                eq(UserHandle.USER_SYSTEM), eq(duration));
+    }
+
+    @Test
+    public void testCallStatsOnMultipleAudioDevices() throws Exception {
+        int duration = 1000;
+        UserHandle uh = UserHandle.of(UserHandle.USER_SYSTEM);
+        PhoneAccount account = mock(PhoneAccount.class);
+        Call call = mock(Call.class);
+        doReturn(true).when(call).isIncoming();
+        doReturn(account).when(call).getPhoneAccountFromHandle();
+        doReturn((long) duration).when(call).getAgeMillis();
+        doReturn(false).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SELF_MANAGED));
+        doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_CALL_PROVIDER));
+        doReturn(true).when(account).hasCapabilities(eq(PhoneAccount.CAPABILITY_SIM_SUBSCRIPTION));
+        doReturn(uh).when(call).getAssociatedUser();
+        CallStats callStats = spy(new CallStats(mSpyContext, mLooper));
+
+        callStats.onCallStart(call);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        callStats.onAudioDevicesChange(true);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        callStats.onCallEnd(call);
+        waitForHandlerAction(callStats, TEST_TIMEOUT);
+
+        verify(callStats, times(1)).log(eq(CALL_STATS__CALL_DIRECTION__DIR_INCOMING),
+                eq(false), eq(false), eq(true), eq(CALL_STATS__ACCOUNT_TYPE__ACCOUNT_SIM),
+                eq(UserHandle.USER_SYSTEM), eq(duration));
+    }
+
+    @Test
+    public void testErrorStatsLog() throws Exception {
+        ErrorStats errorStats = spy(new ErrorStats(mSpyContext, mLooper));
+
+        errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
+        waitForHandlerAction(errorStats, TEST_TIMEOUT);
+
+        verify(errorStats, times(1)).onAggregate();
+        verify(errorStats, times(1)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 1);
+        verifyMessageForErrorStats(errorStats.mPulledAtoms.telecomErrorStats[0], VALUE_MODULE_ID,
+                VALUE_ERROR_ID, 1);
+
+        errorStats.log(VALUE_MODULE_ID, VALUE_ERROR_ID);
+        waitForHandlerAction(errorStats, TEST_TIMEOUT);
+
+        verify(errorStats, times(2)).onAggregate();
+        verify(errorStats, times(2)).save(eq(DELAY_FOR_PERSISTENT_MILLIS));
+        assertEquals(errorStats.mPulledAtoms.telecomErrorStats.length, 1);
+        verifyMessageForErrorStats(errorStats.mPulledAtoms.telecomErrorStats[0], VALUE_MODULE_ID,
+                VALUE_ERROR_ID, 2);
+    }
+
+    private void createTestFileForApiStats(long timestamps) throws IOException {
+        PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
+        atom.telecomApiStats =
+                new PulledAtomsClass.TelecomApiStats[VALUE_ATOM_COUNT];
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            atom.telecomApiStats[i] = new PulledAtomsClass.TelecomApiStats();
+            atom.telecomApiStats[i].setApiName(VALUE_API_ID + i);
+            atom.telecomApiStats[i].setUid(VALUE_UID);
+            atom.telecomApiStats[i].setApiResult(VALUE_API_RESULT);
+            atom.telecomApiStats[i].setCount(VALUE_API_COUNT);
+        }
+        atom.setTelecomApiStatsPullTimestampMillis(timestamps);
+
+        FileOutputStream stream = new FileOutputStream(mTempFile);
+        stream.write(PulledAtomsClass.PulledAtoms.toByteArray(atom));
+        stream.close();
+    }
+
+    private void verifyTestDataForApiStats(final PulledAtomsClass.PulledAtoms atom,
+                                           long timestamps) {
+        assertNotNull(atom);
+        assertEquals(atom.getTelecomApiStatsPullTimestampMillis(), timestamps);
+        assertNotNull(atom.telecomApiStats);
+        assertEquals(atom.telecomApiStats.length, VALUE_ATOM_COUNT);
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            assertNotNull(atom.telecomApiStats[i]);
+            verifyMessageForApiStats(atom.telecomApiStats[i], VALUE_API_ID + i, VALUE_UID,
+                    VALUE_API_RESULT, VALUE_API_COUNT);
+        }
+    }
+
+    private void verifyMessageForApiStats(final PulledAtomsClass.TelecomApiStats msg, int apiId,
+                                          int uid, int result, int count) {
+        assertEquals(msg.getApiName(), apiId);
+        assertEquals(msg.getUid(), uid);
+        assertEquals(msg.getApiResult(), result);
+        assertEquals(msg.getCount(), count);
+    }
+
+    private void createTestFileForAudioRouteStats(long timestamps) throws IOException {
+        PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
+        atom.callAudioRouteStats =
+                new PulledAtomsClass.CallAudioRouteStats[VALUE_ATOM_COUNT];
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            atom.callAudioRouteStats[i] = new PulledAtomsClass.CallAudioRouteStats();
+            atom.callAudioRouteStats[i].setCallAudioRouteSource(VALUE_AUDIO_ROUTE_TYPE1);
+            atom.callAudioRouteStats[i].setCallAudioRouteDest(VALUE_AUDIO_ROUTE_TYPE2);
+            atom.callAudioRouteStats[i].setSuccess(true);
+            atom.callAudioRouteStats[i].setRevert(false);
+            atom.callAudioRouteStats[i].setCount(VALUE_AUDIO_ROUTE_COUNT);
+            atom.callAudioRouteStats[i].setAverageLatencyMs(VALUE_AUDIO_ROUTE_LATENCY);
+        }
+        atom.setCallAudioRouteStatsPullTimestampMillis(timestamps);
+        FileOutputStream stream = new FileOutputStream(mTempFile);
+        stream.write(PulledAtomsClass.PulledAtoms.toByteArray(atom));
+        stream.close();
+    }
+
+    private void verifyTestDataForAudioRouteStats(final PulledAtomsClass.PulledAtoms atom,
+                                                  long timestamps) {
+        assertNotNull(atom);
+        assertEquals(atom.getCallAudioRouteStatsPullTimestampMillis(), timestamps);
+        assertNotNull(atom.callAudioRouteStats);
+        assertEquals(atom.callAudioRouteStats.length, VALUE_ATOM_COUNT);
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            assertNotNull(atom.callAudioRouteStats[i]);
+            verifyMessageForAudioRouteStats(atom.callAudioRouteStats[i], VALUE_AUDIO_ROUTE_TYPE1,
+                    VALUE_AUDIO_ROUTE_TYPE2, true, false, VALUE_AUDIO_ROUTE_COUNT,
+                    VALUE_AUDIO_ROUTE_LATENCY);
+        }
+    }
+
+    private void verifyMessageForAudioRouteStats(
+            final PulledAtomsClass.CallAudioRouteStats msg, int source, int dest, boolean success,
+            boolean revert, int count, int latency) {
+        assertEquals(msg.getCallAudioRouteSource(), source);
+        assertEquals(msg.getCallAudioRouteDest(), dest);
+        assertEquals(msg.getSuccess(), success);
+        assertEquals(msg.getRevert(), revert);
+        assertEquals(msg.getCount(), count);
+        assertTrue(Math.abs(latency - msg.getAverageLatencyMs()) < DELAY_TOLERANCE);
+    }
+
+    private void createTestFileForCallStats(long timestamps) throws IOException {
+        PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
+        atom.callStats =
+                new PulledAtomsClass.CallStats[VALUE_ATOM_COUNT];
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            atom.callStats[i] = new PulledAtomsClass.CallStats();
+            atom.callStats[i].setCallDirection(VALUE_CALL_DIRECTION);
+            atom.callStats[i].setExternalCall(false);
+            atom.callStats[i].setEmergencyCall(false);
+            atom.callStats[i].setMultipleAudioAvailable(false);
+            atom.callStats[i].setAccountType(VALUE_CALL_ACCOUNT_TYPE);
+            atom.callStats[i].setUid(VALUE_UID);
+            atom.callStats[i].setCount(VALUE_CALL_COUNT);
+            atom.callStats[i].setAverageDurationMs(VALUE_CALL_DURATION);
+        }
+        atom.setCallStatsPullTimestampMillis(timestamps);
+        FileOutputStream stream = new FileOutputStream(mTempFile);
+        stream.write(PulledAtomsClass.PulledAtoms.toByteArray(atom));
+        stream.close();
+    }
+
+    private void verifyTestDataForCallStats(final PulledAtomsClass.PulledAtoms atom,
+                                            long timestamps) {
+        assertNotNull(atom);
+        assertEquals(atom.getCallStatsPullTimestampMillis(), timestamps);
+        assertNotNull(atom.callStats);
+        assertEquals(atom.callStats.length, VALUE_ATOM_COUNT);
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            assertNotNull(atom.callStats[i]);
+            verifyMessageForCallStats(atom.callStats[i], VALUE_CALL_DIRECTION, false, false,
+                    false, VALUE_CALL_ACCOUNT_TYPE, VALUE_UID, VALUE_CALL_COUNT,
+                    VALUE_CALL_DURATION);
+        }
+    }
+
+    private void verifyMessageForCallStats(final PulledAtomsClass.CallStats msg,
+            int direction, boolean external, boolean emergency, boolean multipleAudio,
+            int accountType, int uid, int count, int duration) {
+        assertEquals(msg.getCallDirection(), direction);
+        assertEquals(msg.getExternalCall(), external);
+        assertEquals(msg.getEmergencyCall(), emergency);
+        assertEquals(msg.getMultipleAudioAvailable(), multipleAudio);
+        assertEquals(msg.getAccountType(), accountType);
+        assertEquals(msg.getUid(), uid);
+        assertEquals(msg.getCount(), count);
+        assertEquals(msg.getAverageDurationMs(), duration);
+    }
+
+    private void createTestFileForErrorStats(long timestamps) throws IOException {
+        PulledAtomsClass.PulledAtoms atom = new PulledAtomsClass.PulledAtoms();
+        atom.telecomErrorStats =
+                new PulledAtomsClass.TelecomErrorStats[VALUE_ATOM_COUNT];
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            atom.telecomErrorStats[i] = new PulledAtomsClass.TelecomErrorStats();
+            atom.telecomErrorStats[i].setSubmoduleName(VALUE_MODULE_ID);
+            atom.telecomErrorStats[i].setErrorName(VALUE_ERROR_ID);
+            atom.telecomErrorStats[i].setCount(VALUE_ERROR_COUNT);
+        }
+        atom.setTelecomErrorStatsPullTimestampMillis(timestamps);
+        FileOutputStream stream = new FileOutputStream(mTempFile);
+        stream.write(PulledAtomsClass.PulledAtoms.toByteArray(atom));
+        stream.close();
+    }
+
+    private void verifyTestDataForErrorStats(
+            final PulledAtomsClass.PulledAtoms atom, long timestamps) {
+        assertNotNull(atom);
+        assertEquals(atom.getTelecomErrorStatsPullTimestampMillis(), timestamps);
+        assertNotNull(atom.telecomErrorStats);
+        assertEquals(atom.telecomErrorStats.length, VALUE_ATOM_COUNT);
+        for (int i = 0; i < VALUE_ATOM_COUNT; i++) {
+            assertNotNull(atom.telecomErrorStats[i]);
+            verifyMessageForErrorStats(atom.telecomErrorStats[i], VALUE_MODULE_ID, VALUE_ERROR_ID
+                    , VALUE_ERROR_COUNT);
+        }
+    }
+
+    private void verifyMessageForErrorStats(final PulledAtomsClass.TelecomErrorStats msg,
+            int moduleId, int errorId, int count) {
+        assertEquals(msg.getSubmoduleName(), moduleId);
+        assertEquals(msg.getErrorName(), errorId);
+        assertEquals(msg.getCount(), count);
+    }
+}
```

