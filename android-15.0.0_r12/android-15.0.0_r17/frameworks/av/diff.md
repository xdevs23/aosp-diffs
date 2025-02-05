```diff
diff --git a/media/utils/ServiceUtilities.cpp b/media/utils/ServiceUtilities.cpp
index e13f8f7581..0315ac91ee 100644
--- a/media/utils/ServiceUtilities.cpp
+++ b/media/utils/ServiceUtilities.cpp
@@ -41,10 +41,6 @@
 
 namespace android {
 
-namespace {
-constexpr auto PERMISSION_HARD_DENIED = permission::PermissionChecker::PERMISSION_HARD_DENIED;
-}
-
 using content::AttributionSourceState;
 
 static const String16 sAndroidPermissionRecordAudio("android.permission.RECORD_AUDIO");
@@ -119,7 +115,7 @@ std::optional<AttributionSourceState> resolveAttributionSource(
     return std::optional<AttributionSourceState>{myAttributionSource};
 }
 
-    static int checkRecordingInternal(const AttributionSourceState &attributionSource,
+    static bool checkRecordingInternal(const AttributionSourceState &attributionSource,
                                        const uint32_t virtualDeviceId,
                                        const String16 &msg, bool start, audio_source_t source) {
     // Okay to not track in app ops as audio server or media server is us and if
@@ -142,15 +138,15 @@ std::optional<AttributionSourceState> resolveAttributionSource(
     const int32_t attributedOpCode = getOpForSource(source);
 
     permission::PermissionChecker permissionChecker;
-    int permitted;
+    bool permitted = false;
     if (start) {
-        permitted = permissionChecker.checkPermissionForStartDataDeliveryFromDatasource(
+        permitted = (permissionChecker.checkPermissionForStartDataDeliveryFromDatasource(
                 sAndroidPermissionRecordAudio, resolvedAttributionSource.value(), msg,
-                attributedOpCode);
+                attributedOpCode) != permission::PermissionChecker::PERMISSION_HARD_DENIED);
     } else {
-        permitted = permissionChecker.checkPermissionForPreflightFromDatasource(
+        permitted = (permissionChecker.checkPermissionForPreflightFromDatasource(
                 sAndroidPermissionRecordAudio, resolvedAttributionSource.value(), msg,
-                attributedOpCode);
+                attributedOpCode) != permission::PermissionChecker::PERMISSION_HARD_DENIED);
     }
 
     return permitted;
@@ -160,17 +156,17 @@ static constexpr int DEVICE_ID_DEFAULT = 0;
 
 bool recordingAllowed(const AttributionSourceState &attributionSource, audio_source_t source) {
     return checkRecordingInternal(attributionSource, DEVICE_ID_DEFAULT, String16(), /*start*/ false,
-                                  source) != PERMISSION_HARD_DENIED;
+                                  source);
 }
 
 bool recordingAllowed(const AttributionSourceState &attributionSource,
                       const uint32_t virtualDeviceId,
                       audio_source_t source) {
     return checkRecordingInternal(attributionSource, virtualDeviceId,
-                                  String16(), /*start*/ false, source) != PERMISSION_HARD_DENIED;
+                                  String16(), /*start*/ false, source);
 }
 
-int startRecording(const AttributionSourceState& attributionSource,
+bool startRecording(const AttributionSourceState& attributionSource,
                     const uint32_t virtualDeviceId,
                     const String16& msg,
                     audio_source_t source) {
diff --git a/media/utils/include/mediautils/ServiceUtilities.h b/media/utils/include/mediautils/ServiceUtilities.h
index 2631469719..b365648cf5 100644
--- a/media/utils/include/mediautils/ServiceUtilities.h
+++ b/media/utils/include/mediautils/ServiceUtilities.h
@@ -92,7 +92,7 @@ bool recordingAllowed(const AttributionSourceState& attributionSource,
 bool recordingAllowed(const AttributionSourceState &attributionSource,
                       uint32_t virtualDeviceId,
                       audio_source_t source);
-int startRecording(const AttributionSourceState& attributionSource, uint32_t virtualDeviceId,
+bool startRecording(const AttributionSourceState& attributionSource, uint32_t virtualDeviceId,
                     const String16& msg, audio_source_t source);
 void finishRecording(const AttributionSourceState& attributionSource, uint32_t virtualDeviceId,
                      audio_source_t source);
diff --git a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
index f4b659c815..d0520f48eb 100644
--- a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
+++ b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
@@ -89,10 +89,6 @@ using media::audio::common::AudioUuid;
 using media::audio::common::Int;
 
 constexpr int kDefaultVirtualDeviceId = 0;
-namespace {
-constexpr auto PERMISSION_HARD_DENIED = permission::PermissionChecker::PERMISSION_HARD_DENIED;
-constexpr auto PERMISSION_GRANTED = permission::PermissionChecker::PERMISSION_GRANTED;
-}
 
 const std::vector<audio_usage_t>& SYSTEM_USAGES = {
     AUDIO_USAGE_CALL_ASSISTANT,
@@ -910,13 +906,13 @@ Status AudioPolicyService::startInput(int32_t portIdAidl)
 
     std::stringstream msg;
     msg << "Audio recording on session " << client->session;
-    const auto permitted = startRecording(client->attributionSource, client->virtualDeviceId,
-            String16(msg.str().c_str()), client->attributes.source);
 
     // check calling permissions
-    if (permitted == PERMISSION_HARD_DENIED && client->attributes.source != AUDIO_SOURCE_FM_TUNER
-            && client->attributes.source != AUDIO_SOURCE_REMOTE_SUBMIX
-            && client->attributes.source != AUDIO_SOURCE_ECHO_REFERENCE) {
+    if (!(startRecording(client->attributionSource, client->virtualDeviceId,
+                         String16(msg.str().c_str()), client->attributes.source)
+            || client->attributes.source == AUDIO_SOURCE_FM_TUNER
+            || client->attributes.source == AUDIO_SOURCE_REMOTE_SUBMIX
+            || client->attributes.source == AUDIO_SOURCE_ECHO_REFERENCE)) {
         ALOGE("%s permission denied: recording not allowed for attribution source %s",
                 __func__, client->attributionSource.toString().c_str());
         return binderStatusFromStatusT(PERMISSION_DENIED);
@@ -936,17 +932,13 @@ Status AudioPolicyService::startInput(int32_t portIdAidl)
         return binderStatusFromStatusT(INVALID_OPERATION);
     }
 
-    // Force the possibly silenced client to match the state on the appops side
-    // following the call to startRecording (i.e. unsilenced iff call succeeded)
-    // At this point in time, the client is inactive, so no calls to appops are
-    // sent in setAppState_l. This ensures existing clients have the same
-    // behavior as new clients.
+    // Force the possibly silenced client to be unsilenced since we just called
+    // startRecording (i.e. we have assumed it is unsilenced).
+    // At this point in time, the client is inactive, so no calls to appops are sent in
+    // setAppState_l.
+    // This ensures existing clients have the same behavior as new clients (starting unsilenced).
     // TODO(b/282076713)
-    if (permitted == PERMISSION_GRANTED) {
-        setAppState_l(client, APP_STATE_TOP);
-    } else {
-        setAppState_l(client, APP_STATE_IDLE);
-    }
+    setAppState_l(client, APP_STATE_TOP);
 
     client->active = true;
     client->startTimeNs = systemTime();
@@ -1032,10 +1024,8 @@ Status AudioPolicyService::startInput(int32_t portIdAidl)
         client->active = false;
         client->startTimeNs = 0;
         updateUidStates_l();
-        if (!client->silenced) {
-            finishRecording(client->attributionSource, client->virtualDeviceId,
-                    client->attributes.source);
-        }
+        finishRecording(client->attributionSource, client->virtualDeviceId,
+                        client->attributes.source);
     }
 
     return binderStatusFromStatusT(status);
@@ -1064,11 +1054,7 @@ Status AudioPolicyService::stopInput(int32_t portIdAidl)
     updateUidStates_l();
 
     // finish the recording app op
-    if (!client->silenced) {
-        finishRecording(client->attributionSource, client->virtualDeviceId,
-                client->attributes.source);
-    }
-
+    finishRecording(client->attributionSource, client->virtualDeviceId, client->attributes.source);
     AutoCallerClear acc;
     return binderStatusFromStatusT(mAudioPolicyManager->stopInput(portId));
 }
diff --git a/services/audiopolicy/service/AudioPolicyService.cpp b/services/audiopolicy/service/AudioPolicyService.cpp
index 7b7275ea99..fee3c8d565 100644
--- a/services/audiopolicy/service/AudioPolicyService.cpp
+++ b/services/audiopolicy/service/AudioPolicyService.cpp
@@ -61,10 +61,6 @@ static const nsecs_t kAudioCommandTimeoutNs = seconds(3); // 3 seconds
 
 static const String16 sManageAudioPolicyPermission("android.permission.MANAGE_AUDIO_POLICY");
 
-namespace {
-constexpr auto PERMISSION_GRANTED = permission::PermissionChecker::PERMISSION_GRANTED;
-}
-
 // Creates an association between Binder code to name for IAudioPolicyService.
 #define IAUDIOPOLICYSERVICE_BINDER_METHOD_MACRO_LIST \
 BINDER_METHOD_ENTRY(onNewAudioModulesAvailable) \
@@ -1220,10 +1216,9 @@ void AudioPolicyService::setAppState_l(sp<AudioRecordClient> client, app_state_t
                 } else {
                     std::stringstream msg;
                     msg << "Audio recording un-silenced on session " << client->session;
-                    if (startRecording(client->attributionSource, client->virtualDeviceId,
-                                String16(msg.str().c_str()), client->attributes.source)
-                                != PERMISSION_GRANTED) {
-                        return;
+                    if (!startRecording(client->attributionSource, client->virtualDeviceId,
+                                        String16(msg.str().c_str()), client->attributes.source)) {
+                        silenced = true;
                     }
                 }
             }
```

