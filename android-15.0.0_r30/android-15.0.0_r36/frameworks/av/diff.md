```diff
diff --git a/media/libaudioclient/AudioSystem.cpp b/media/libaudioclient/AudioSystem.cpp
index c675c343c9..1430913fcf 100644
--- a/media/libaudioclient/AudioSystem.cpp
+++ b/media/libaudioclient/AudioSystem.cpp
@@ -1399,7 +1399,8 @@ status_t AudioSystem::getInputForAttr(const audio_attributes_t* attr,
                                       audio_config_base_t* config,
                                       audio_input_flags_t flags,
                                       audio_port_handle_t* selectedDeviceId,
-                                      audio_port_handle_t* portId) {
+                                      audio_port_handle_t* portId,
+                                      audio_source_t* source) {
     if (attr == NULL) {
         ALOGE("getInputForAttr NULL attr - shouldn't happen");
         return BAD_VALUE;
@@ -1447,7 +1448,7 @@ status_t AudioSystem::getInputForAttr(const audio_attributes_t* attr,
     *selectedDeviceId = VALUE_OR_RETURN_STATUS(
             aidl2legacy_int32_t_audio_port_handle_t(response.selectedDeviceId));
     *portId = VALUE_OR_RETURN_STATUS(aidl2legacy_int32_t_audio_port_handle_t(response.portId));
-
+    *source = VALUE_OR_RETURN_STATUS(aidl2legacy_AudioSource_audio_source_t(response.source));
     return OK;
 }
 
diff --git a/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl b/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
index 9e578206d5..f886f2c338 100644
--- a/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
+++ b/media/libaudioclient/aidl/android/media/GetInputForAttrResponse.aidl
@@ -17,6 +17,7 @@
 package android.media;
 
 import android.media.audio.common.AudioConfigBase;
+import android.media.audio.common.AudioSource;
 
 /**
  * {@hide}
@@ -32,4 +33,6 @@ parcelable GetInputForAttrResponse {
     int virtualDeviceId;
     /** The suggested config if fails to get an input. **/
     AudioConfigBase config;
+    /** The audio source, possibly updated by audio policy manager */
+    AudioSource source;
 }
diff --git a/media/libaudioclient/include/media/AudioSystem.h b/media/libaudioclient/include/media/AudioSystem.h
index 45ede3c6da..1c171abbda 100644
--- a/media/libaudioclient/include/media/AudioSystem.h
+++ b/media/libaudioclient/include/media/AudioSystem.h
@@ -370,6 +370,7 @@ public:
      * @param[in|out] selectedDeviceId the requested device id for playback, the actual device id
      *                                 for playback will be returned
      * @param[out] portId the generated port id to identify the client
+     * @param[out] source the audio source validated by audio policy manager
      * @return if the call is successful or not
      */
     static status_t getInputForAttr(const audio_attributes_t *attr,
@@ -380,7 +381,8 @@ public:
                                     audio_config_base_t *config,
                                     audio_input_flags_t flags,
                                     audio_port_handle_t *selectedDeviceId,
-                                    audio_port_handle_t *portId);
+                                    audio_port_handle_t *portId,
+                                    audio_source_t *source);
 
     static status_t startInput(audio_port_handle_t portId);
     static status_t stopInput(audio_port_handle_t portId);
diff --git a/services/audioflinger/AudioFlinger.cpp b/services/audioflinger/AudioFlinger.cpp
index c67fa13415..68c3626027 100644
--- a/services/audioflinger/AudioFlinger.cpp
+++ b/services/audioflinger/AudioFlinger.cpp
@@ -646,12 +646,15 @@ status_t AudioFlinger::openMmapStream(MmapStreamInterface::stream_direction_t di
                  "%s does not support secondary outputs, ignoring them", __func__);
     } else {
         audio_port_handle_t deviceId = getFirstDeviceId(*deviceIds);
+        audio_source_t source = AUDIO_SOURCE_DEFAULT;
         ret = AudioSystem::getInputForAttr(&localAttr, &io,
                                               RECORD_RIID_INVALID,
                                               actualSessionId,
                                               adjAttributionSource,
                                               config,
-                                              AUDIO_INPUT_FLAG_MMAP_NOIRQ, &deviceId, &portId);
+                                              AUDIO_INPUT_FLAG_MMAP_NOIRQ,
+                                              &deviceId, &portId, &source);
+        localAttr.source = source;
         deviceIds->clear();
         if (deviceId != AUDIO_PORT_HANDLE_NONE) {
             deviceIds->push_back(deviceId);
@@ -2534,17 +2537,19 @@ status_t AudioFlinger::createRecord(const media::CreateRecordRequest& _input,
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
index 2d2ab544f3..2229655e26 100644
--- a/services/audioflinger/Threads.cpp
+++ b/services/audioflinger/Threads.cpp
@@ -10561,6 +10561,7 @@ status_t MmapThread::start(const AudioClient& client,
         config.channel_mask = mChannelMask;
         config.format = mFormat;
         audio_port_handle_t deviceId = getFirstDeviceId(mDeviceIds);
+        audio_source_t source = AUDIO_SOURCE_DEFAULT;
         mutex().unlock();
         ret = AudioSystem::getInputForAttr(&localAttr, &io,
                                               RECORD_RIID_INVALID,
@@ -10569,9 +10570,11 @@ status_t MmapThread::start(const AudioClient& client,
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
diff --git a/services/audiopolicy/managerdefault/AudioPolicyManager.cpp b/services/audiopolicy/managerdefault/AudioPolicyManager.cpp
index 73b574ccfa..f133dfa2ca 100644
--- a/services/audiopolicy/managerdefault/AudioPolicyManager.cpp
+++ b/services/audiopolicy/managerdefault/AudioPolicyManager.cpp
@@ -3147,6 +3147,7 @@ AudioPolicyManager::getInputForAttr(audio_attributes_t attributes,
     ret.portId = allocatedPortId;
     ret.virtualDeviceId = permReq.virtualDeviceId;
     ret.config = legacy2aidl_audio_config_base_t_AudioConfigBase(config, true /*isInput*/).value();
+    ret.source = legacy2aidl_audio_source_t_AudioSource(attributes.source).value();
     return ret;
 }
 
diff --git a/services/audiopolicy/tests/audiopolicymanager_tests.cpp b/services/audiopolicy/tests/audiopolicymanager_tests.cpp
index 40e99af048..2eccebfeed 100644
--- a/services/audiopolicy/tests/audiopolicymanager_tests.cpp
+++ b/services/audiopolicy/tests/audiopolicymanager_tests.cpp
@@ -1375,6 +1375,36 @@ TEST_F(AudioPolicyManagerTestWithConfigurationFile, MatchesMoreInputFlagsWhenPos
     EXPECT_EQ(expectedChannelMask, requestedChannelMask);
 }
 
+TEST_F(AudioPolicyManagerTestWithConfigurationFile, AudioSourceFixedByGetInputforAttr) {
+    const audio_port_handle_t requestedDeviceId = AUDIO_PORT_HANDLE_NONE;
+    const audio_io_handle_t requestedInput = AUDIO_PORT_HANDLE_NONE;
+    const AttributionSourceState attributionSource = createAttributionSourceState(/*uid=*/ 0);
+
+    audio_attributes_t attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
+                               AUDIO_SOURCE_DEFAULT, AUDIO_FLAG_NONE, ""};
+    audio_config_base_t requestedConfig = {
+            .sample_rate = k48000SamplingRate,
+            .channel_mask = AUDIO_CHANNEL_IN_STEREO,
+            .format = AUDIO_FORMAT_PCM_16_BIT,
+    };
+    auto inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId,
+                                              requestedConfig, AUDIO_INPUT_FLAG_NONE, 1 /*riid*/,
+                                              AUDIO_SESSION_NONE, attributionSource);
+    ASSERT_TRUE(inputRes.has_value());
+    ASSERT_NE(VALUE_OR_FATAL(aidl2legacy_AudioSource_audio_source_t(inputRes.value().source)),
+                             AUDIO_SOURCE_DEFAULT);
+
+    attr = {AUDIO_CONTENT_TYPE_UNKNOWN, AUDIO_USAGE_UNKNOWN,
+            AUDIO_SOURCE_VOICE_COMMUNICATION, AUDIO_FLAG_NONE, ""};
+
+    inputRes = mManager->getInputForAttr(attr, requestedInput, requestedDeviceId, requestedConfig,
+                                         AUDIO_INPUT_FLAG_NONE, 1 /*riid*/, AUDIO_SESSION_NONE,
+                                         attributionSource);
+    ASSERT_TRUE(inputRes.has_value());
+    ASSERT_EQ(VALUE_OR_FATAL(aidl2legacy_AudioSource_audio_source_t(inputRes.value().source)),
+                             AUDIO_SOURCE_VOICE_COMMUNICATION);
+}
+
 class AudioPolicyManagerTestDynamicPolicy : public AudioPolicyManagerTestWithConfigurationFile {
 protected:
     void TearDown() override;
```

