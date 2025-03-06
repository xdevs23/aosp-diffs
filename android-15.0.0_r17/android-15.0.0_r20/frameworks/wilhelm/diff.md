```diff
diff --git a/src/android/AudioPlayer_to_android.cpp b/src/android/AudioPlayer_to_android.cpp
index 134bf3d..a0b0de9 100644
--- a/src/android/AudioPlayer_to_android.cpp
+++ b/src/android/AudioPlayer_to_android.cpp
@@ -35,6 +35,7 @@
 
 #include <system/audio.h>
 #include <SLES/OpenSLES_Android.h>
+#include <media/AudioContainers.h>
 
 template class android::KeyedVector<SLuint32,
                                     android::sp<android::AudioEffect> > ;
@@ -51,9 +52,13 @@ template class android::KeyedVector<SLuint32,
 //-----------------------------------------------------------------------------
 // Inline functions to communicate with AudioService through the native AudioManager interface
 inline void audioManagerPlayerEvent(CAudioPlayer* ap, android::player_state_t event,
-        audio_port_handle_t deviceId) {
+        const android::DeviceIdVector& deviceIds) {
     if (ap->mObject.mEngine->mAudioManager != 0) {
-        ap->mObject.mEngine->mAudioManager->playerEvent(ap->mPIId, event, deviceId);
+        std::vector<audio_port_handle_t> eventIdVector;
+        for (auto deviceId : deviceIds) {
+            eventIdVector.push_back(deviceId);
+        }
+        ap->mObject.mEngine->mAudioManager->playerEvent(ap->mPIId, event, eventIdVector);
     }
 }
 
@@ -881,7 +886,8 @@ static void sfplayer_handlePrefetchEvent(int event, int data1, int data2, void*
         if ((audioTrack != 0) && (!ap->mSeek.mLoopEnabled)) {
             audioTrack->stop();
         }
-        ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STOPPED, AUDIO_PORT_HANDLE_NONE);
+        android::DeviceIdVector emptyDeviceIdVector;
+        ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STOPPED, emptyDeviceIdVector);
         }
         break;
 
@@ -2196,11 +2202,12 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
 
     SLuint32 playState = ap->mPlay.mState;
 
-    audio_port_handle_t deviceId = AUDIO_PORT_HANDLE_NONE;
+    android::DeviceIdVector deviceIds;
+    android::DeviceIdVector emptyDeviceIdVector;
     android::sp<android::AudioTrack> audioTrack =
         ap->mTrackPlayer != 0 ? ap->mTrackPlayer->getAudioTrack() : nullptr;
     if (audioTrack != 0) {
-        deviceId = audioTrack->getRoutedDeviceId();
+        deviceIds = audioTrack->getRoutedDeviceIds();
     }
 
     switch (ap->mAndroidObjType) {
@@ -2220,7 +2227,7 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
                 // instead of ap->mTrackPlayer->mAudioTrack->start();
                 if (!ap->mDeferredStart) {
                     // state change
-                    ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STARTED, deviceId);
+                    ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STARTED, deviceIds);
                 }
                 ap->mDeferredStart = true;
             }
@@ -2235,14 +2242,14 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
         switch (playState) {
         case SL_PLAYSTATE_STOPPED:
             aplayer_setPlayState(ap->mAPlayer, playState, &ap->mAndroidObjState);
-            audioManagerPlayerEvent(ap, android::PLAYER_STATE_STOPPED, AUDIO_PORT_HANDLE_NONE);
+            audioManagerPlayerEvent(ap, android::PLAYER_STATE_STOPPED, emptyDeviceIdVector);
             break;
         case SL_PLAYSTATE_PAUSED:
             aplayer_setPlayState(ap->mAPlayer, playState, &ap->mAndroidObjState);
-            audioManagerPlayerEvent(ap, android::PLAYER_STATE_PAUSED, AUDIO_PORT_HANDLE_NONE);
+            audioManagerPlayerEvent(ap, android::PLAYER_STATE_PAUSED, emptyDeviceIdVector);
             break;
         case SL_PLAYSTATE_PLAYING:
-            audioManagerPlayerEvent(ap, android::PLAYER_STATE_STARTED, deviceId);
+            audioManagerPlayerEvent(ap, android::PLAYER_STATE_STARTED, deviceIds);
             aplayer_setPlayState(ap->mAPlayer, playState, &ap->mAndroidObjState);
             break;
         }
@@ -2457,7 +2464,7 @@ void android_audioPlayer_bufferQueue_onRefilled_l(CAudioPlayer *ap) {
     auto audioTrack = ap->mTrackPlayer->getAudioTrack();
     if (audioTrack != 0) {
         ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STARTED,
-                            audioTrack->getRoutedDeviceId());
+                            audioTrack->getRoutedDeviceIds());
         // instead of ap->mTrackPlayer->mAudioTrack->start();
         ap->mDeferredStart = true;
     }
```

