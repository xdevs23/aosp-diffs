```diff
diff --git a/media/libaudioclient/AudioSystem.cpp b/media/libaudioclient/AudioSystem.cpp
index ee4407421d..0974866812 100644
--- a/media/libaudioclient/AudioSystem.cpp
+++ b/media/libaudioclient/AudioSystem.cpp
@@ -1206,7 +1206,8 @@ status_t AudioSystem::getInputForAttr(const audio_attributes_t* attr,
                                       audio_config_base_t* config,
                                       audio_input_flags_t flags,
                                       audio_port_handle_t* selectedDeviceId,
-                                      audio_port_handle_t* portId) {
+                                      audio_port_handle_t* portId,
+                                      audio_source_t* source) {
     if (attr == NULL) {
         ALOGE("getInputForAttr NULL attr - shouldn't happen");
         return BAD_VALUE;
@@ -1253,7 +1254,7 @@ status_t AudioSystem::getInputForAttr(const audio_attributes_t* attr,
     *selectedDeviceId = VALUE_OR_RETURN_STATUS(
             aidl2legacy_int32_t_audio_port_handle_t(response.selectedDeviceId));
     *portId = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_port_handle_t(response.portId));
-
+    *source = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioSource_audio_source_t(response.source));
     return OK;
 }
 
diff --git a/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl b/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
index 347bf79aec..b7d67fd3c3 100644
--- a/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
+++ b/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
@@ -17,6 +17,7 @@
 package android.media;
 
 import android.media.audio.common.AudioConfigBase;
+import android.media.audio.common.AudioSource;
 
 /**
  * {@hide}
@@ -30,4 +31,6 @@ parcelable GetInputForAttrResponse {
     int portId;
     /** The suggested config if fails to get an input. **/
     AudioConfigBase config;
+    /** The audio source, possibly updated by audio policy manager */
+    AudioSource source;
 }
diff --git a/media/libaudioclient/include/media/AudioSystem.h b/media/libaudioclient/include/media/AudioSystem.h
index 40e5673944..0d8ca41881 100644
--- a/media/libaudioclient/include/media/AudioSystem.h
+++ b/media/libaudioclient/include/media/AudioSystem.h
@@ -367,6 +367,7 @@ public:
      * @param[in|out] selectedDeviceId the requested device id for playback, the actual device id
      *                                 for playback will be returned
      * @param[out] portId the generated port id to identify the client
+     * @param[out] source the audio source validated by audio policy manager
      * @return if the call is successful or not
      */
     static status_t getInputForAttr(const audio_attributes_t *attr,
@@ -377,7 +378,8 @@ public:
                                     audio_config_base_t *config,
                                     audio_input_flags_t flags,
                                     audio_port_handle_t *selectedDeviceId,
-                                    audio_port_handle_t *portId);
+                                    audio_port_handle_t *portId,
+                                    audio_source_t *source);
 
     static status_t startInput(audio_port_handle_t portId);
     static status_t stopInput(audio_port_handle_t portId);
diff --git a/services/audioflinger/AudioFlinger.cpp b/services/audioflinger/AudioFlinger.cpp
index 00340274b3..a133324b9b 100644
--- a/services/audioflinger/AudioFlinger.cpp
+++ b/services/audioflinger/AudioFlinger.cpp
@@ -638,12 +638,15 @@ status_t AudioFlinger::openMmapStream(MmapStreamInterface::stream_direction_t di
         ALOGW_IF(!secondaryOutputs.empty(),
                  "%s does not support secondary outputs, ignoring them", __func__);
     } else {
+        audio_source_t source = AUDIO_SOURCE_DEFAULT;
         ret = AudioSystem::getInputForAttr(&localAttr, &io,
                                               RECORD_RIID_INVALID,
                                               actualSessionId,
                                               adjAttributionSource,
                                               config,
-                                              AUDIO_INPUT_FLAG_MMAP_NOIRQ, deviceId, &portId);
+                                              AUDIO_INPUT_FLAG_MMAP_NOIRQ,
+                                              deviceId, &portId, &source);
+        localAttr.source = source;
     }
     if (ret != NO_ERROR) {
         return ret;
@@ -2489,17 +2492,19 @@ status_t AudioFlinger::createRecord(const media::CreateRecordRequest& _input,
         output.selectedDeviceId = input.selectedDeviceId;
         portId = AUDIO_PORT_HANDLE_NONE;
     }
+    audio_source_t source = AUDIO_SOURCE_DEFAULT;
     lStatus = AudioSystem::getInputForAttr(&input.attr, &output.inputId,
                                       input.riid,
                                       sessionId,
                                     // FIXME compare to AudioTrack
                                       adjAttributionSource,
                                       &input.config,
-                                      output.flags, &output.selectedDeviceId, &portId);
+                                      output.flags, &output.selectedDeviceId, &portId, &source);
     if (lStatus != NO_ERROR) {
         ALOGE("createRecord() getInputForAttr return error %d", lStatus);
         goto Exit;
     }
+    input.attr.source = source;
 
     {
         audio_utils::lock_guard _l(mutex());
diff --git a/services/audioflinger/Threads.cpp b/services/audioflinger/Threads.cpp
index 3f0bd70c5d..6c0db391cb 100644
--- a/services/audioflinger/Threads.cpp
+++ b/services/audioflinger/Threads.cpp
@@ -10474,6 +10474,7 @@ status_t MmapThread::start(const AudioClient& client,
         config.channel_mask = mChannelMask;
         config.format = mFormat;
         audio_port_handle_t deviceId = mDeviceId;
+        audio_source_t source = AUDIO_SOURCE_DEFAULT;
         mutex().unlock();
         ret = AudioSystem::getInputForAttr(&localAttr, &io,
                                               RECORD_RIID_INVALID,
@@ -10482,9 +10483,11 @@ status_t MmapThread::start(const AudioClient& client,
                                               &config,
                                               AUDIO_INPUT_FLAG_MMAP_NOIRQ,
                                               &deviceId,
-                                              &portId);
+                                              &portId,
+                                              &source);
         mutex().lock();
         // localAttr is const for getInputForAttr.
+        localAttr.source = source;
     }
     // APM should not chose a different input or output stream for the same set of attributes
     // and audo configuration
diff --git a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
index f4b659c815..e519520bb8 100644
--- a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
+++ b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
@@ -876,6 +876,8 @@ Status AudioPolicyService::getInputForAttr(const media::audio::common::AudioAttr
             legacy2aidl_audio_port_handle_t_int32_t(selectedDeviceId));
     _aidl_return->portId = VALUE_OR_RETURN_BINDER_STATUS(
             legacy2aidl_audio_port_handle_t_int32_t(portId));
+    _aidl_return->source = VALUE_OR_RETURN_BINDER_STATUS(
+            legacy2aidl_audio_source_t_AudioSource(inputSource));
     return Status::ok();
 }
 
```

