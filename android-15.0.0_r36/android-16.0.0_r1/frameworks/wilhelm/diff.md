```diff
diff --git a/OWNERS b/OWNERS
index 8e61fa7..03ee79a 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
 # TODO: add more owners
-gkasten@google.com
 elaurent@google.com
 philburk@google.com
diff --git a/src/Android.bp b/src/Android.bp
index 49e282b..67a31ea 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -39,6 +39,7 @@ cc_library_static {
 
     cflags: [
         "-Wno-initializer-overrides",
+        "-Wno-cast-function-type-mismatch",
         //"-Wno-missing-field-initializers",
         // optional, see comments in MPH_to.c:
         //"-DUSE_DESIGNATED_INITIALIZERS",
@@ -88,6 +89,7 @@ cc_library_shared {
         "-fvisibility=hidden",
         "-DLI_API=__attribute__((visibility(\"default\")))",
 
+        "-Wno-cast-function-type-mismatch",
         "-Wno-multichar",
         "-Wno-invalid-offsetof",
 
diff --git a/src/android/AudioPlayer_to_android.cpp b/src/android/AudioPlayer_to_android.cpp
index a0b0de9..536d76f 100644
--- a/src/android/AudioPlayer_to_android.cpp
+++ b/src/android/AudioPlayer_to_android.cpp
@@ -2226,6 +2226,7 @@ void android_audioPlayer_setPlayState(CAudioPlayer *ap) {
             if (audioTrack != 0) {
                 // instead of ap->mTrackPlayer->mAudioTrack->start();
                 if (!ap->mDeferredStart) {
+                    ap->mTrackPlayer->baseUpdateDeviceIds(deviceIds);
                     // state change
                     ap->mTrackPlayer->reportEvent(android::PLAYER_STATE_STARTED, deviceIds);
                 }
```

