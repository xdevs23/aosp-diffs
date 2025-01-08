```diff
diff --git a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
index a5b23d4749..f4b659c815 100644
--- a/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
+++ b/services/audiopolicy/service/AudioPolicyInterfaceImpl.cpp
@@ -24,6 +24,7 @@
 #include <android/content/AttributionSourceState.h>
 #include <android_media_audiopolicy.h>
 #include <com_android_media_audio.h>
+#include <cutils/properties.h>
 #include <error/expected_utils.h>
 #include <media/AidlConversion.h>
 #include <media/AudioPolicy.h>
@@ -480,8 +481,11 @@ Status AudioPolicyService::getOutputForAttr(const media::audio::common::AudioAtt
     }
 
     if (result == NO_ERROR) {
-        attr = VALUE_OR_RETURN_BINDER_STATUS(
-                mUsecaseValidator->verifyAudioAttributes(output, attributionSource, attr));
+        // usecase validator is disabled by default
+        if (property_get_bool("ro.audio.usecase_validator_enabled", false /* default */)) {
+                attr = VALUE_OR_RETURN_BINDER_STATUS(
+                        mUsecaseValidator->verifyAudioAttributes(output, attributionSource, attr));
+        }
 
         sp<AudioPlaybackClient> client =
                 new AudioPlaybackClient(attr, output, attributionSource, session,
```

