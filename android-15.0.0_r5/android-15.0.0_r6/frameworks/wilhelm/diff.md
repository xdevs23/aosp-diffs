```diff
diff --git a/Android.bp b/Android.bp
index c5e3230..a961572 100644
--- a/Android.bp
+++ b/Android.bp
@@ -43,9 +43,6 @@ ndk_library {
     symbol_file: "src/libOpenMAXAL.map.txt",
     first_version: "14",
     unversioned_until: "current",
-    export_header_libs: [
-        "libOpenMAXAL_headers",
-    ],
 }
 
 ndk_headers {
@@ -61,9 +58,6 @@ ndk_library {
     symbol_file: "src/libOpenSLES.map.txt",
     first_version: "9",
     unversioned_until: "current",
-    export_header_libs: [
-        "libOpenSLES_ndk_headers",
-    ],
 }
 
 cc_library_headers {
diff --git a/src/android/AudioPlayer_to_android.cpp b/src/android/AudioPlayer_to_android.cpp
index 5df053d..134bf3d 100644
--- a/src/android/AudioPlayer_to_android.cpp
+++ b/src/android/AudioPlayer_to_android.cpp
@@ -623,7 +623,7 @@ SLresult audioPlayer_getPerformanceMode(CAudioPlayer* ap, SLuint32 *pMode) {
 
 //-----------------------------------------------------------------------------
 void audioPlayer_auxEffectUpdate(CAudioPlayer* ap) {
-    if ((ap->mTrackPlayer->mAudioTrack != 0) && (ap->mAuxEffect != 0)) {
+    if ((ap->mTrackPlayer->getAudioTrack() != 0) && (ap->mAuxEffect != 0)) {
         android_fxSend_attach(ap, true, ap->mAuxEffect, ap->mVolume.mLevel + ap->mAuxSendLevel);
     }
 }
@@ -877,8 +877,9 @@ static void sfplayer_handlePrefetchEvent(int event, int data1, int data2, void*
 
     case android::GenericPlayer::kEventEndOfStream: {
         audioPlayer_dispatch_headAtEnd_lockPlay(ap, true /*set state to paused?*/, true);
-        if ((ap->mTrackPlayer->mAudioTrack != 0) && (!ap->mSeek.mLoopEnabled)) {
-            ap->mTrackPlayer->mAudioTrack->stop();
+        auto audioTrack = ap->mTrackPlayer->getAudioTrack();
+        if ((audioTrack != 0) && (!ap->mSeek.mLoopEnabled)) {
+            audioTrack->stop();
         }
         ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STOPPED, AUDIO_PORT_HANDLE_NONE);
         }
@@ -1542,7 +1543,7 @@ compatible: ;
 // AudioTrack to adjust performance mode based on actual output flags
 static void checkAndSetPerformanceModePost(CAudioPlayer *pAudioPlayer)
 {
-    audio_output_flags_t flags = pAudioPlayer->mTrackPlayer->mAudioTrack->getFlags();
+    audio_output_flags_t flags = pAudioPlayer->mTrackPlayer->getAudioTrack()->getFlags();
     switch (pAudioPlayer->mPerformanceMode) {
     case ANDROID_PERFORMANCE_MODE_LATENCY:
         if ((flags & (AUDIO_OUTPUT_FLAG_FAST | AUDIO_OUTPUT_FLAG_RAW)) ==
@@ -1698,11 +1699,11 @@ SLresult android_audioPlayer_realize(CAudioPlayer *pAudioPlayer, SLboolean async
             j_env->ExceptionClear();
             j_env->CallVoidMethod(pAudioPlayer->mAndroidConfiguration.mRoutingProxy,
                                   midRoutingProxy_connect,
-                                  (jlong)pAudioPlayer->mTrackPlayer->mAudioTrack.get());
+                                  (jlong)pAudioPlayer->mTrackPlayer->getAudioTrack().get());
             if (j_env->ExceptionCheck()) {
                 SL_LOGE("Java exception releasing player routing object.");
                 result = SL_RESULT_INTERNAL_ERROR;
-                pAudioPlayer->mTrackPlayer->mAudioTrack.clear();
+                pAudioPlayer->mTrackPlayer->clearAudioTrack();
                 return result;
             }
         }
@@ -1988,8 +1989,9 @@ SLresult android_audioPlayer_setPlaybackRateAndConstraints(CAudioPlayer *ap, SLp
         // get the content sample rate
         uint32_t contentRate = sles_to_android_sampleRate(ap->mSampleRateMilliHz);
         // apply the SL ES playback rate on the AudioTrack as a factor of its content sample rate
-        if (ap->mTrackPlayer->mAudioTrack != 0) {
-            ap->mTrackPlayer->mAudioTrack->setSampleRate(contentRate * (rate/1000.0f));
+        auto audioTrack = ap->mTrackPlayer->getAudioTrack();
+        if (audioTrack != 0) {
+            audioTrack->setSampleRate(contentRate * (rate/1000.0f));
         }
         }
         break;
@@ -2195,8 +2197,10 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
     SLuint32 playState = ap->mPlay.mState;
 
     audio_port_handle_t deviceId = AUDIO_PORT_HANDLE_NONE;
-    if (ap->mTrackPlayer != 0 && ap->mTrackPlayer->mAudioTrack != 0) {
-        deviceId = ap->mTrackPlayer->mAudioTrack->getRoutedDeviceId();
+    android::sp<android::AudioTrack> audioTrack =
+        ap->mTrackPlayer != 0 ? ap->mTrackPlayer->getAudioTrack() : nullptr;
+    if (audioTrack != 0) {
+        deviceId = audioTrack->getRoutedDeviceId();
     }
 
     switch (ap->mAndroidObjType) {
@@ -2212,7 +2216,7 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
             break;
         case SL_PLAYSTATE_PLAYING:
             SL_LOGV("setting AudioPlayer to SL_PLAYSTATE_PLAYING");
-            if (ap->mTrackPlayer->mAudioTrack != 0) {
+            if (audioTrack != 0) {
                 // instead of ap->mTrackPlayer->mAudioTrack->start();
                 if (!ap->mDeferredStart) {
                     // state change
@@ -2268,19 +2272,20 @@ void android_audioPlayer_usePlayEventMask(CAudioPlayer *ap) {
     /*switch (ap->mAndroidObjType) {
     case AUDIOPLAYER_FROM_PCM_BUFFERQUEUE:*/
 
+    auto audioTrack = ap->mTrackPlayer->getAudioTrack();
     if (ap->mAPlayer != 0) {
-        assert(ap->mTrackPlayer->mAudioTrack == 0);
+        assert(audioTrack == 0);
         ap->mAPlayer->setPlayEvents((int32_t) eventFlags, (int32_t) pPlayItf->mMarkerPosition,
                 (int32_t) pPlayItf->mPositionUpdatePeriod);
         return;
     }
 
-    if (ap->mTrackPlayer->mAudioTrack == 0) {
+    if (audioTrack == 0) {
         return;
     }
 
     if (eventFlags & SL_PLAYEVENT_HEADATMARKER) {
-        ap->mTrackPlayer->mAudioTrack->setMarkerPosition(
+        audioTrack->setMarkerPosition(
             (uint32_t) (
                 (int64_t) pPlayItf->mMarkerPosition *
                 sles_to_android_sampleRate(ap->mSampleRateMilliHz) /
@@ -2288,16 +2293,16 @@ void android_audioPlayer_usePlayEventMask(CAudioPlayer *ap) {
             ));
     } else {
         // clear marker
-        ap->mTrackPlayer->mAudioTrack->setMarkerPosition(0);
+        audioTrack->setMarkerPosition(0);
     }
 
     if (eventFlags & SL_PLAYEVENT_HEADATNEWPOS) {
-         ap->mTrackPlayer->mAudioTrack->setPositionUpdatePeriod(
+         audioTrack->setPositionUpdatePeriod(
                 (uint32_t)((((int64_t)pPlayItf->mPositionUpdatePeriod
                 * sles_to_android_sampleRate(ap->mSampleRateMilliHz)))/1000));
     } else {
         // clear periodic update
-        ap->mTrackPlayer->mAudioTrack->setPositionUpdatePeriod(0);
+        audioTrack->setPositionUpdatePeriod(0);
     }
 
     if (eventFlags & SL_PLAYEVENT_HEADATEND) {
@@ -2348,16 +2353,18 @@ void android_audioPlayer_getPosition(IPlay *pPlayItf, SLmillisecond *pPosMsec) {
     CAudioPlayer *ap = (CAudioPlayer *)pPlayItf->mThis;
     switch (ap->mAndroidObjType) {
 
-      case AUDIOPLAYER_FROM_PCM_BUFFERQUEUE:
-        if (ap->mSampleRateMilliHz == UNKNOWN_SAMPLERATE || ap->mTrackPlayer->mAudioTrack == 0) {
+      case AUDIOPLAYER_FROM_PCM_BUFFERQUEUE: {
+        auto audioTrack = ap->mTrackPlayer->getAudioTrack();
+        if (ap->mSampleRateMilliHz == UNKNOWN_SAMPLERATE || audioTrack == 0) {
             *pPosMsec = 0;
         } else {
             uint32_t positionInFrames;
-            ap->mTrackPlayer->mAudioTrack->getPosition(&positionInFrames);
+            audioTrack->getPosition(&positionInFrames);
             *pPosMsec = ((int64_t)positionInFrames * 1000) /
                     sles_to_android_sampleRate(ap->mSampleRateMilliHz);
         }
         break;
+      }
 
       case AUDIOPLAYER_FROM_TS_ANDROIDBUFFERQUEUE:    // intended fall-through
       case AUDIOPLAYER_FROM_URIFD:
@@ -2447,9 +2454,10 @@ void android_audioPlayer_bufferQueue_onRefilled_l(CAudioPlayer *ap) {
     // the AudioTrack associated with the AudioPlayer receiving audio from a PCM buffer
     // queue was stopped when the queue become empty, we restart as soon as a new buffer
     // has been enqueued since we're in playing state
-    if (ap->mTrackPlayer->mAudioTrack != 0) {
+    auto audioTrack = ap->mTrackPlayer->getAudioTrack();
+    if (audioTrack != 0) {
         ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STARTED,
-                            ap->mTrackPlayer->mAudioTrack->getRoutedDeviceId());
+                            audioTrack->getRoutedDeviceId());
         // instead of ap->mTrackPlayer->mAudioTrack->start();
         ap->mDeferredStart = true;
     }
@@ -2484,11 +2492,13 @@ SLresult android_audioPlayer_bufferQueue_onClear(CAudioPlayer *ap) {
     switch (ap->mAndroidObjType) {
     //-----------------------------------
     // AudioTrack
-    case AUDIOPLAYER_FROM_PCM_BUFFERQUEUE:
-        if (ap->mTrackPlayer->mAudioTrack != 0) {
-            ap->mTrackPlayer->mAudioTrack->flush();
+    case AUDIOPLAYER_FROM_PCM_BUFFERQUEUE: {
+        auto audioTrack = ap->mTrackPlayer->getAudioTrack();
+        if (audioTrack != 0) {
+            audioTrack->flush();
         }
         break;
+    }
     default:
         result = SL_RESULT_INTERNAL_ERROR;
         break;
diff --git a/src/android/AudioRecordCallback.h b/src/android/AudioRecordCallback.h
index 53b7e35..1503382 100644
--- a/src/android/AudioRecordCallback.h
+++ b/src/android/AudioRecordCallback.h
@@ -30,51 +30,54 @@ size_t audioRecorder_handleMoreData_lockRecord(CAudioRecorder* ar,
 //--------------------------------------------------------------------------------------------------
 namespace android {
 
-class AudioRecordCallback : public android::AudioRecord::IAudioRecordCallback {
+class AudioRecordCallback : public AudioRecord::IAudioRecordCallback {
   public:
-    AudioRecordCallback(CAudioRecorder * audioRecorder) : mAr(audioRecorder) {}
+    AudioRecordCallback(CAudioRecorder * audioRecorder) : mAr(audioRecorder),
+            mCallbackProtector(mAr->mCallbackProtector) {}
     AudioRecordCallback(const AudioRecordCallback&) = delete;
     AudioRecordCallback& operator=(const AudioRecordCallback&) = delete;
 
   private:
-    size_t onMoreData(const android::AudioRecord::Buffer& buffer) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAr->mCallbackProtector)) {
+    size_t onMoreData(const AudioRecord::Buffer& buffer) override {
+        if (!CallbackProtector::enterCbIfOk(mCallbackProtector)) {
             // it is not safe to enter the callback (the track is about to go away)
             return buffer.size(); // replicate existing behavior
         }
         size_t bytesRead = audioRecorder_handleMoreData_lockRecord(mAr, buffer);
-        mAr->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
         return bytesRead;
     }
 
 
     void onOverrun() override {
-        if (!android::CallbackProtector::enterCbIfOk(mAr->mCallbackProtector)) {
+        if (!CallbackProtector::enterCbIfOk(mCallbackProtector)) {
             // it is not safe to enter the callback (the track is about to go away)
             return;
         }
         audioRecorder_handleOverrun_lockRecord(mAr);
-        mAr->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
     void onMarker(uint32_t) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAr->mCallbackProtector)) {
+        if (!CallbackProtector::enterCbIfOk(mCallbackProtector)) {
             // it is not safe to enter the callback (the track is about to go away)
             return;
         }
 
         audioRecorder_handleMarker_lockRecord(mAr);
-        mAr->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
     void onNewPos(uint32_t) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAr->mCallbackProtector)) {
+        if (!CallbackProtector::enterCbIfOk(mCallbackProtector)) {
             // it is not safe to enter the callback (the track is about to go away)
             return;
         }
 
         audioRecorder_handleNewPos_lockRecord(mAr);
-        mAr->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
+
     CAudioRecorder * const mAr;
+    const sp<CallbackProtector> mCallbackProtector;
 };
 
 } // namespace android
diff --git a/src/android/AudioTrackCallback.h b/src/android/AudioTrackCallback.h
index 7020606..c2cb78c 100644
--- a/src/android/AudioTrackCallback.h
+++ b/src/android/AudioTrackCallback.h
@@ -33,46 +33,47 @@ size_t audioTrack_handleMoreData_lockPlay(CAudioPlayer* ap,
 namespace android {
 class AudioTrackCallback : public AudioTrack::IAudioTrackCallback {
   public:
-    AudioTrackCallback(CAudioPlayer * player) : mAp(player) {}
+    AudioTrackCallback(CAudioPlayer * player) : mAp(player),
+            mCallbackProtector(mAp->mCallbackProtector) {}
 
     size_t onMoreData(const AudioTrack::Buffer& buffer) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAp->mCallbackProtector)) {
+        if (!android::CallbackProtector::enterCbIfOk(mCallbackProtector)) {
           // it is not safe to enter the callback (the track is about to go away)
           return buffer.size(); // duplicate existing behavior
         }
         size_t bytesCopied = audioTrack_handleMoreData_lockPlay(mAp, buffer);
-        mAp->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
         return bytesCopied;
       }
 
     void onUnderrun() override {
-        if (!android::CallbackProtector::enterCbIfOk(mAp->mCallbackProtector)) {
+        if (!android::CallbackProtector::enterCbIfOk(mCallbackProtector)) {
           // it is not safe to enter the callback (the track is about to go away)
             return;
         }
         audioTrack_handleUnderrun_lockPlay(mAp);
-        mAp->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
 
     void onLoopEnd([[maybe_unused]] int32_t loopsRemaining) override {
         SL_LOGE("Encountered loop end for CAudioPlayer %p", mAp);
     }
     void onMarker([[maybe_unused]] uint32_t markerPosition) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAp->mCallbackProtector)) {
+        if (!android::CallbackProtector::enterCbIfOk(mCallbackProtector)) {
           // it is not safe to enter the callback (the track is about to go away)
           return;
         }
         audioTrack_handleMarker_lockPlay(mAp);
-        mAp->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
 
     void onNewPos([[maybe_unused]] uint32_t newPos) override {
-        if (!android::CallbackProtector::enterCbIfOk(mAp->mCallbackProtector)) {
+        if (!android::CallbackProtector::enterCbIfOk(mCallbackProtector)) {
           // it is not safe to enter the callback (the track is about to go away)
           return;
         }
         audioTrack_handleNewPos_lockPlay(mAp);
-        mAp->mCallbackProtector->exitCb();
+        mCallbackProtector->exitCb();
     }
     void onBufferEnd() override {
         SL_LOGE("Encountered buffer end for CAudioPlayer %p", mAp);
@@ -94,5 +95,6 @@ class AudioTrackCallback : public AudioTrack::IAudioTrackCallback {
     AudioTrackCallback(const AudioTrackCallback&) = delete;
     AudioTrackCallback& operator=(const AudioTrackCallback&) = delete;
     CAudioPlayer* const mAp;
+    const sp<CallbackProtector> mCallbackProtector;
 };
 }  // namespace android
diff --git a/src/android/VideoCodec_to_android.cpp b/src/android/VideoCodec_to_android.cpp
index b0d4c6f..729894c 100644
--- a/src/android/VideoCodec_to_android.cpp
+++ b/src/android/VideoCodec_to_android.cpp
@@ -37,11 +37,11 @@ static const char *kVideoMimeTypes[] = {
 static const size_t kNbVideoMimeTypes = sizeof(kVideoMimeTypes) / sizeof(kVideoMimeTypes[0]);
 
 // codec capabilities in the following arrays maps to the mime types defined in kVideoMimeTypes
-struct CodecCapabilities {
+struct CodecCaps {
     Vector<MediaCodecInfo::ProfileLevel> mProfileLevels;
 };
 
-static CodecCapabilities VideoDecoderCapabilities[kNbVideoMimeTypes];
+static CodecCaps VideoDecoderCapabilities[kNbVideoMimeTypes];
 static XAuint32 VideoDecoderNbProfLevel[kNbVideoMimeTypes];
 
 static XAuint32 NbSupportedDecoderTypes = 0;
diff --git a/src/android/android_Effect.cpp b/src/android/android_Effect.cpp
index c87e584..8d7607e 100644
--- a/src/android/android_Effect.cpp
+++ b/src/android/android_Effect.cpp
@@ -511,8 +511,9 @@ android::status_t android_fxSend_attach(CAudioPlayer* ap, bool attach,
     //  mAPlayer == 0 && mAudioTrack != 0 means playing PCM audio
     //  mAPlayer == 0 && mAudioTrack == 0 means player not fully configured yet
     // The asserts document and verify this.
+    auto audioTrack = ap->mTrackPlayer->getAudioTrack();
     if (ap->mAPlayer != 0) {
-        assert(ap->mTrackPlayer->mAudioTrack == 0);
+        assert(audioTrack == 0);
         if (attach) {
             ap->mAPlayer->attachAuxEffect(pFx->id());
             ap->mAPlayer->setAuxEffectSendLevel( sles_to_android_amplification(sendLevel) );
@@ -522,7 +523,7 @@ android::status_t android_fxSend_attach(CAudioPlayer* ap, bool attach,
         return android::NO_ERROR;
     }
 
-    if (ap->mTrackPlayer->mAudioTrack == 0) {
+    if (audioTrack == 0) {
         // the player doesn't have an AudioTrack at the moment, so store this info to use it
         // when the AudioTrack becomes available
         if (attach) {
@@ -536,16 +537,15 @@ android::status_t android_fxSend_attach(CAudioPlayer* ap, bool attach,
     }
 
     if (attach) {
-        android::status_t status = ap->mTrackPlayer->mAudioTrack->attachAuxEffect(pFx->id());
+        android::status_t status = audioTrack->attachAuxEffect(pFx->id());
         //SL_LOGV("attachAuxEffect(%d) returned %d", pFx->id(), status);
         if (android::NO_ERROR == status) {
-            status =
-                ap->mTrackPlayer->mAudioTrack->setAuxEffectSendLevel(
-                        sles_to_android_amplification(sendLevel) );
+            status = audioTrack->setAuxEffectSendLevel(
+                    sles_to_android_amplification(sendLevel) );
         }
         return status;
     } else {
-        return ap->mTrackPlayer->mAudioTrack->attachAuxEffect(0);
+        return audioTrack->attachAuxEffect(0);
     }
 }
 
@@ -593,17 +593,18 @@ android::status_t android_fxSend_setSendLevel(CAudioPlayer* ap, SLmillibel sendL
     // we keep track of the send level, independently of the current audio player level
     ap->mAuxSendLevel = sendLevel - ap->mVolume.mLevel;
 
+    auto audioTrack = ap->mTrackPlayer->getAudioTrack();
     if (ap->mAPlayer != 0) {
-        assert(ap->mTrackPlayer->mAudioTrack == 0);
+        assert(audioTrack == 0);
         ap->mAPlayer->setAuxEffectSendLevel( sles_to_android_amplification(sendLevel) );
         return android::NO_ERROR;
     }
 
-    if (ap->mTrackPlayer->mAudioTrack == 0) {
+    if (audioTrack == 0) {
         return android::NO_ERROR;
     }
 
-    return ap->mTrackPlayer->mAudioTrack->setAuxEffectSendLevel(
+    return audioTrack->setAuxEffectSendLevel(
             sles_to_android_amplification(sendLevel) );
 }
 
diff --git a/src/itf/IAndroidConfiguration.cpp b/src/itf/IAndroidConfiguration.cpp
index 412ef70..f3d23e1 100644
--- a/src/itf/IAndroidConfiguration.cpp
+++ b/src/itf/IAndroidConfiguration.cpp
@@ -154,7 +154,7 @@ static SLresult AllocPlayerRoutingProxy(IAndroidConfiguration* iConfig, jobject*
     SLresult result;
 
     IObject* configObj = iConfig->mThis;                // get corresponding object
-    android::AudioTrack* pAudioTrack = ((CAudioPlayer*)configObj)->mTrackPlayer->mAudioTrack.get();
+    auto audioTrack = ((CAudioPlayer*)configObj)->mTrackPlayer->getAudioTrack();
 
     JNIEnv* j_env = android::AndroidRuntime::getJNIEnv();
 
@@ -163,7 +163,7 @@ static SLresult AllocPlayerRoutingProxy(IAndroidConfiguration* iConfig, jobject*
     jobject localObjRef =
         j_env->NewObject(gClsAudioTrackRoutingProxy,
                          gMidAudioTrackRoutingProxy_ctor,
-                         (jlong)pAudioTrack /*audioTrackObjInLong*/);
+                         (jlong)audioTrack.get() /*audioTrackObjInLong*/);
 
     *proxyObj = j_env->NewGlobalRef(localObjRef);
 
@@ -381,4 +381,3 @@ void IAndroidConfiguration_deinit(void *self)
         thiz->mItf->ReleaseJavaProxy(&thiz->mItf, SL_ANDROID_JAVA_PROXY_ROUTING);
     }
 }
-
diff --git a/src/itf/IAndroidEffect.cpp b/src/itf/IAndroidEffect.cpp
index 6748561..e17ad7b 100644
--- a/src/itf/IAndroidEffect.cpp
+++ b/src/itf/IAndroidEffect.cpp
@@ -28,7 +28,7 @@ static SLresult IAndroidEffect_CreateEffect(SLAndroidEffectItf self,
     IAndroidEffect *thiz = (IAndroidEffect *) self;
     if (SL_OBJECTID_AUDIOPLAYER == IObjectToObjectID(thiz->mThis)) {
         CAudioPlayer *ap = (CAudioPlayer *)thiz->mThis;
-        if (ap->mTrackPlayer->mAudioTrack != 0) {
+        if (ap->mTrackPlayer->getAudioTrack() != 0) {
             result = android_genericFx_createEffect(thiz, effectImplementationId, ap->mSessionId);
         } else {
             result = SL_RESULT_RESOURCE_ERROR;
diff --git a/src/locks.cpp b/src/locks.cpp
index f3edd33..d2d7cb5 100644
--- a/src/locks.cpp
+++ b/src/locks.cpp
@@ -228,7 +228,7 @@ void object_unlock_exclusive_attributes(IObject *thiz, unsigned attributes)
         ap->mPrefetchStatus.mDeferredPrefetchContext  = NULL;
         ap->mPrefetchStatus.mDeferredPrefetchEvents   = SL_PREFETCHEVENT_NONE;
         if (ap->mDeferredStart) {
-            audioTrack = ap->mTrackPlayer->mAudioTrack;
+            audioTrack = ap->mTrackPlayer->getAudioTrack();
             ap->mDeferredStart = false;
         }
     }
```

