```diff
diff --git a/METADATA b/METADATA
index 072f4631..3d34cfec 100644
--- a/METADATA
+++ b/METADATA
@@ -1,14 +1,18 @@
+# This project was upgraded with external_updater.
+# Usage: tools/external_updater/updater.sh update external/oboe
+# For more info, check https://cs.android.com/android/platform/superproject/main/+/main:tools/external_updater/README.md
+
 name: "Oboe"
 description: "Native audio API for Android that calls AAudio or OpenSL ES."
 third_party {
-  url {
-    type: GIT
-    value: "https://github.com/google/oboe"
-  }
-  version: "1.7.0"
   last_upgrade_date {
-    year: 2022
-    month: 12
-    day: 14
+    year: 2025
+    month: 4
+    day: 15
+  }
+  identifier {
+    type: "Git"
+    value: "https://github.com/google/oboe"
+    version: "56c587a79cd9081d006a5021aba1522fc01faf2d"
   }
 }
diff --git a/apps/OboeTester/app/CMakeLists.txt b/apps/OboeTester/app/CMakeLists.txt
index a47e6abf..f005e492 100644
--- a/apps/OboeTester/app/CMakeLists.txt
+++ b/apps/OboeTester/app/CMakeLists.txt
@@ -6,7 +6,7 @@ set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
 
 link_directories(${CMAKE_CURRENT_LIST_DIR}/..)
 
-# Increment this number when adding files to OboeTester => 105
+# Increment this number when adding files to OboeTester => 106
 # The change in this file will help Android Studio resync
 # and generate new build files that reference the new code.
 file(GLOB_RECURSE app_native_sources src/main/cpp/*)
diff --git a/apps/OboeTester/app/build.gradle b/apps/OboeTester/app/build.gradle
index 00ca8224..4b96e625 100644
--- a/apps/OboeTester/app/build.gradle
+++ b/apps/OboeTester/app/build.gradle
@@ -6,8 +6,8 @@ android {
         applicationId = "com.mobileer.oboetester"
         minSdkVersion 23
         targetSdkVersion 34
-        versionCode 94
-        versionName "2.7.5"
+        versionCode 95
+        versionName "2.7.6"
         testInstrumentationRunner "android.support.test.runner.AndroidJUnitRunner"
         externalNativeBuild {
             cmake {
diff --git a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
index d0ac6ddd..14f45f3f 100644
--- a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
+++ b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
@@ -172,7 +172,6 @@ int ActivityContext::open(jint nativeApi,
                           jboolean isMMap,
                           jboolean isInput,
                           jint spatializationBehavior) {
-
     oboe::AudioApi audioApi = oboe::AudioApi::Unspecified;
     switch (nativeApi) {
         case NATIVE_MODE_UNSPECIFIED:
@@ -366,6 +365,7 @@ void ActivityTestOutput::close(int32_t streamIndex) {
     mSinkI16.reset();
     mSinkI24.reset();
     mSinkI32.reset();
+    mSinkMemoryDirect.reset();
 }
 
 void ActivityTestOutput::setChannelEnabled(int channelIndex, bool enabled) {
@@ -414,6 +414,9 @@ void ActivityTestOutput::configureAfterOpen() {
     mSinkI16 = std::make_shared<SinkI16>(mChannelCount);
     mSinkI24 = std::make_shared<SinkI24>(mChannelCount);
     mSinkI32 = std::make_shared<SinkI32>(mChannelCount);
+    static constexpr int COMPRESSED_FORMAT_BYTES_PER_FRAME = 1;
+    mSinkMemoryDirect = std::make_shared<SinkMemoryDirect>(
+            mChannelCount, COMPRESSED_FORMAT_BYTES_PER_FRAME);
 
     mTriangleOscillator.setSampleRate(outputStream->getSampleRate());
     mTriangleOscillator.frequency.setValue(1.0/kSweepPeriod);
@@ -458,6 +461,7 @@ void ActivityTestOutput::configureAfterOpen() {
     mSinkI16->pullReset();
     mSinkI24->pullReset();
     mSinkI32->pullReset();
+    mSinkMemoryDirect->pullReset();
 
     configureStreamGateway();
 }
@@ -472,6 +476,8 @@ void ActivityTestOutput::configureStreamGateway() {
         audioStreamGateway.setAudioSink(mSinkI32);
     } else if (outputStream->getFormat() == oboe::AudioFormat::Float) {
         audioStreamGateway.setAudioSink(mSinkFloat);
+    } else if (outputStream->getFormat() == oboe::AudioFormat::MP3) {
+        audioStreamGateway.setAudioSink(mSinkMemoryDirect);
     }
 
     if (mUseCallback) {
@@ -517,12 +523,19 @@ oboe::Result ActivityTestOutput::startStreams() {
     mSinkI16->pullReset();
     mSinkI24->pullReset();
     mSinkI32->pullReset();
+    mSinkMemoryDirect->pullReset();
     if (mVolumeRamp != nullptr) {
         mVolumeRamp->setTarget(mAmplitude);
     }
     return getOutputStream()->start();
 }
 
+void ActivityTestOutput::setupMemoryBuffer(std::unique_ptr<uint8_t[]> &buffer, int length) {
+    if (mSinkMemoryDirect != nullptr) {
+        mSinkMemoryDirect->setupMemoryBuffer(buffer, length);
+    }
+}
+
 // ======================================================================= ActivityTestInput
 void ActivityTestInput::configureAfterOpen() {
     mInputAnalyzer.reset();
diff --git a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
index 9ec67552..e13ae2e9 100644
--- a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
+++ b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
@@ -28,6 +28,7 @@
 
 #include "aaudio/AAudioExtensions.h"
 #include "AudioStreamGateway.h"
+#include "SinkMemoryDirect.h"
 
 #include "flowunits/ImpulseOscillator.h"
 #include "flowgraph/ManyToMultiConverter.h"
@@ -306,6 +307,9 @@ public:
         oboeCallbackProxy.setWorkloadReportingEnabled(enabled);
     }
 
+    virtual void setupMemoryBuffer([[maybe_unused]] std::unique_ptr<uint8_t[]>& buffer,
+                                   [[maybe_unused]] int length) {}
+
 protected:
     std::shared_ptr<oboe::AudioStream> getInputStream();
     std::shared_ptr<oboe::AudioStream> getOutputStream();
@@ -451,6 +455,8 @@ public:
         }
     }
 
+    void setupMemoryBuffer(std::unique_ptr<uint8_t[]>& buffer, int length) final;
+
 protected:
     SignalType                       mSignalType = SignalType::Sine;
 
@@ -474,6 +480,7 @@ protected:
     std::shared_ptr<oboe::flowgraph::SinkI16>     mSinkI16;
     std::shared_ptr<oboe::flowgraph::SinkI24>     mSinkI24;
     std::shared_ptr<oboe::flowgraph::SinkI32>     mSinkI32;
+    std::shared_ptr<SinkMemoryDirect>             mSinkMemoryDirect;
 };
 
 /**
diff --git a/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.cpp b/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.cpp
new file mode 100644
index 00000000..e0158362
--- /dev/null
+++ b/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.cpp
@@ -0,0 +1,50 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+#include "SinkMemoryDirect.h"
+#include "common/OboeDebug.h"
+
+SinkMemoryDirect::SinkMemoryDirect(int channelCount, int bytesPerFrame) :
+        oboe::flowgraph::FlowGraphSink(channelCount), mBytesPerFrame(bytesPerFrame) {
+}
+
+void SinkMemoryDirect::setupMemoryBuffer(std::unique_ptr<uint8_t[]>& buffer, int length) {
+    mBuffer = std::make_unique<uint8_t[]>(length);
+    memcpy(mBuffer.get(), buffer.get(), length);
+    mBufferLength = length;
+    mCurPosition = 0;
+}
+
+void SinkMemoryDirect::reset() {
+    oboe::flowgraph::FlowGraphNode::reset();
+    mCurPosition = 0;
+}
+
+int32_t SinkMemoryDirect::read(void *data, int32_t numFrames) {
+    auto uint8Data = static_cast<uint8_t*>(data);
+    int bytesLeft = numFrames * mBytesPerFrame;
+    while (bytesLeft > 0) {
+        int bytesToCopy = std::min(bytesLeft, mBufferLength - mCurPosition);
+        memcpy(uint8Data, mBuffer.get() + mCurPosition, bytesToCopy);
+        mCurPosition += bytesToCopy;
+        if (mCurPosition >= mBufferLength) {
+            mCurPosition = 0;
+        }
+        bytesLeft -= bytesToCopy;
+        uint8Data += bytesToCopy;
+    }
+    return numFrames;
+}
diff --git a/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.h b/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.h
new file mode 100644
index 00000000..7ea42149
--- /dev/null
+++ b/apps/OboeTester/app/src/main/cpp/SinkMemoryDirect.h
@@ -0,0 +1,43 @@
+/*
+ * Copyright 2025 The Android Open Source Project
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
+#pragma once
+
+#include <memory>
+
+#include "flowgraph/FlowGraphNode.h"
+
+/**
+ * AudioSink that provides data from a cached memory.
+ * Data conversion is not allowed when using this sink.
+ */
+class SinkMemoryDirect : public oboe::flowgraph::FlowGraphSink {
+public:
+    explicit SinkMemoryDirect(int channelCount, int bytesPerFrame);
+
+    void setupMemoryBuffer(std::unique_ptr<uint8_t[]>& buffer, int length);
+
+    void reset() final;
+
+    int32_t read(void* data, int32_t numFrames) final;
+
+private:
+    std::unique_ptr<uint8_t[]> mBuffer = nullptr;
+    int mBufferLength = 0;
+    int mCurPosition = 0;
+
+    const int mBytesPerFrame;
+};
diff --git a/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp b/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
index e5240797..512e5dba 100644
--- a/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
+++ b/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
@@ -19,6 +19,7 @@
 #include <cassert>
 #include <cstring>
 #include <jni.h>
+#include <memory>
 #include <stdint.h>
 #include <sys/sysinfo.h>
 #include <thread>
@@ -213,6 +214,16 @@ Java_com_mobileer_oboetester_TestAudioActivity_getFramesPerCallback(JNIEnv *env,
     return (jint) engine.getCurrentActivity()->getFramesPerCallback();
 }
 
+JNIEXPORT void JNICALL
+Java_com_mobileer_oboetester_TestAudioActivity_setupMemoryBuffer(JNIEnv *env, jobject thiz,
+                                                                 jbyteArray buffer, jint offset,
+                                                                 jint length) {
+    auto buf = std::make_unique<uint8_t[]>(length);
+
+    env->GetByteArrayRegion(buffer, offset, length, reinterpret_cast<jbyte *>(buf.get()));
+    engine.getCurrentActivity()->setupMemoryBuffer(buf, length);
+}
+
 JNIEXPORT jint JNICALL
 Java_com_mobileer_oboetester_OboeAudioStream_startPlaybackNative(JNIEnv *env, jobject) {
     return (jint) engine.getCurrentActivity()->startPlayback();
@@ -459,6 +470,29 @@ Java_com_mobileer_oboetester_OboeAudioStream_getDeviceId(
     return result;
 }
 
+JNIEXPORT jintArray JNICALL
+Java_com_mobileer_oboetester_OboeAudioStream_getDeviceIds(
+        JNIEnv *env, jobject, jint streamIndex) {
+    std::shared_ptr<oboe::AudioStream> oboeStream = engine.getCurrentActivity()->getStream(streamIndex);
+    if (oboeStream != nullptr) {
+        std::vector<int32_t> deviceIds = oboeStream->getDeviceIds();
+        jsize length = deviceIds.size();
+        jintArray result = env->NewIntArray(length);
+
+        if (result == nullptr) {
+            return nullptr;
+        }
+
+        if (length > 0) {
+            env->SetIntArrayRegion(result, 0, length,
+                                   reinterpret_cast<jint*>(deviceIds.data()));
+        }
+
+        return result;
+    }
+    return nullptr;
+}
+
 JNIEXPORT jint JNICALL
 Java_com_mobileer_oboetester_OboeAudioStream_getSessionId(
         JNIEnv *env, jobject, jint streamIndex) {
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
index 3bf5286b..3ce4968f 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
@@ -209,6 +209,10 @@ public abstract class AudioStreamBase {
 
     public abstract void close();
 
+    public int getFormat() {
+        return mActualStreamConfiguration.getFormat();
+    }
+
     public int getChannelCount() {
         return mActualStreamConfiguration.getChannelCount();
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
index 6f08767a..5e0080e1 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
@@ -16,6 +16,8 @@
 
 package com.mobileer.oboetester;
 
+import androidx.annotation.Nullable;
+
 import java.io.IOException;
 
 /**
@@ -92,6 +94,7 @@ abstract class OboeAudioStream extends AudioStreamBase {
         actualConfiguration.setChannelCount(getChannelCount());
         actualConfiguration.setChannelMask(getChannelMask());
         actualConfiguration.setDeviceId(getDeviceId());
+        actualConfiguration.setDeviceIds(getDeviceIds());
         actualConfiguration.setSessionId(getSessionId());
         actualConfiguration.setFormat(getFormat());
         actualConfiguration.setMMap(isMMap());
@@ -245,6 +248,11 @@ abstract class OboeAudioStream extends AudioStreamBase {
     }
     private native int getDeviceId(int streamIndex);
 
+    public int[] getDeviceIds() {
+        return getDeviceIds(streamIndex);
+    }
+    @Nullable private native int[] getDeviceIds(int streamIndex);
+
     public int getSessionId() {
         return getSessionId(streamIndex);
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
index 56a74d7f..8a0a1116 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
@@ -16,7 +16,12 @@
 
 package com.mobileer.oboetester;
 
+import android.text.TextUtils;
+
+import androidx.annotation.Nullable;
+
 import java.util.ArrayList;
+import java.util.Arrays;
 import java.util.HashMap;
 import java.util.List;
 import java.util.Locale;
@@ -44,6 +49,7 @@ public class StreamConfiguration {
     public static final int AUDIO_FORMAT_PCM_24 = 3; // must match AAUDIO
     public static final int AUDIO_FORMAT_PCM_32 = 4; // must match AAUDIO
     public static final int AUDIO_FORMAT_IEC61937 = 5; // must match AAUDIO
+    public static final int AUDIO_FORMAT_MP3 = 6; // must match AAUDIO
 
     public static final int DIRECTION_OUTPUT = 0; // must match AAUDIO
     public static final int DIRECTION_INPUT = 1; // must match AAUDIO
@@ -275,6 +281,10 @@ public class StreamConfiguration {
             CHANNEL_FRONT_BACK
     };
 
+    public static boolean isCompressedFormat(int format) {
+        return format == AUDIO_FORMAT_MP3;
+    }
+
     private static HashMap<String,Integer> mUsageStringToIntegerMap;
     private static HashMap<String,Integer> mContentTypeStringToIntegerMap;
     private static HashMap<String,Integer> mChannelMaskStringToIntegerMap;
@@ -284,6 +294,7 @@ public class StreamConfiguration {
     private int mBufferCapacityInFrames;
     private int mChannelCount;
     private int mDeviceId;
+    @Nullable private int[] mDeviceIds;
     private int mSessionId;
     private int mDirection; // does not get reset
     private int mFormat;
@@ -341,6 +352,7 @@ public class StreamConfiguration {
         mChannelCount = UNSPECIFIED;
         mChannelMask = UNSPECIFIED;
         mDeviceId = UNSPECIFIED;
+        mDeviceIds = new int[0];
         mSessionId = -1;
         mFormat = AUDIO_FORMAT_PCM_FLOAT;
         mSampleRate = UNSPECIFIED;
@@ -525,6 +537,8 @@ public class StreamConfiguration {
                 return "Float";
             case AUDIO_FORMAT_IEC61937:
                 return "IEC61937";
+            case AUDIO_FORMAT_MP3:
+                return "MP3";
             default:
                 return "Invalid";
         }
@@ -647,6 +661,7 @@ public class StreamConfiguration {
                 convertNativeApiToText(getNativeApi()).toLowerCase(Locale.getDefault())));
         message.append(String.format(Locale.getDefault(), "%s.rate = %d\n", prefix, mSampleRate));
         message.append(String.format(Locale.getDefault(), "%s.device = %d\n", prefix, mDeviceId));
+        message.append(String.format(Locale.getDefault(), "%s.devices = %s\n", prefix, convertDeviceIdsToText(mDeviceIds)));
         message.append(String.format(Locale.getDefault(), "%s.mmap = %s\n", prefix, isMMap() ? "yes" : "no"));
         message.append(String.format(Locale.getDefault(), "%s.rate.conversion.quality = %d\n", prefix, mRateConversionQuality));
         message.append(String.format(Locale.getDefault(), "%s.hardware.channels = %d\n", prefix, mHardwareChannelCount));
@@ -775,6 +790,14 @@ public class StreamConfiguration {
         this.mDeviceId = deviceId;
     }
 
+    public int[] getDeviceIds() {
+        return mDeviceIds;
+    }
+
+    public void setDeviceIds(int[] deviceIds) {
+        this.mDeviceIds = deviceIds;
+    }
+
     public int getSessionId() {
         return mSessionId;
     }
@@ -897,4 +920,18 @@ public class StreamConfiguration {
                 return "?=" + error;
         }
     }
+
+    public static String convertDeviceIdsToText(int[] deviceIds) {
+        if (deviceIds == null || deviceIds.length == 0) {
+            return "[]";
+        }
+
+        List<String> deviceIdStrings = new ArrayList<>();
+        for (int deviceId : deviceIds) {
+            deviceIdStrings.add(String.valueOf(deviceId));
+        }
+
+        String joinedIds = TextUtils.join(",", deviceIdStrings);
+        return "[" + joinedIds + "]";
+    }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
index c0ffe3b7..fc569aeb 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
@@ -482,8 +482,9 @@ public class StreamConfigurationView extends LinearLayout {
         value = actualConfiguration.getNativeApi();
         mActualNativeApiView.setText(StreamConfiguration.convertNativeApiToText(value));
 
-        value = actualConfiguration.getDeviceId();
-        mActualDeviceIdView.setText(String.valueOf(value));
+        String deviceIdsText = StreamConfiguration.convertDeviceIdsToText(
+                actualConfiguration.getDeviceIds());
+        mActualDeviceIdView.setText(deviceIdsText);
 
         mActualMMapView.setText(yesOrNo(actualConfiguration.isMMap()));
         int sharingMode = actualConfiguration.getSharingMode();
@@ -525,7 +526,7 @@ public class StreamConfigurationView extends LinearLayout {
 
         String msg = "";
         msg += "burst = " + actualConfiguration.getFramesPerBurst();
-        msg += ", devID = " + actualConfiguration.getDeviceId();
+        msg += ", devIDs = " + deviceIdsText;
         msg += ", " + (actualConfiguration.isMMap() ? "MMAP" : "Legacy");
         msg += (isMMap ? ", " + StreamConfiguration.convertSharingModeToText(sharingMode) : "");
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
index f286ffbb..0bc3898a 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
@@ -45,6 +45,9 @@ import androidx.appcompat.app.AppCompatActivity;
 
 import java.io.File;
 import java.io.IOException;
+import java.io.InputStream;
+import java.nio.ByteBuffer;
+import java.nio.ByteOrder;
 import java.util.ArrayList;
 import java.util.Locale;
 
@@ -82,6 +85,11 @@ abstract class TestAudioActivity extends AppCompatActivity {
     public static final int ACTIVITY_DATA_PATHS = 8;
     public static final int ACTIVITY_DYNAMIC_WORKLOAD = 9;
 
+    private static final int MP3_RES_ID = R.raw.sine441stereo;
+    private static final AudioConfig MP3_FILE_CONFIG =
+            new AudioConfig(44100 /*sampleRate*/, StreamConfiguration.AUDIO_FORMAT_MP3,
+                    StreamConfiguration.CHANNEL_STEREO, 2 /*channelCount*/);
+
     private int mAudioState = AUDIO_STATE_CLOSED;
 
     protected ArrayList<StreamContext> mStreamContexts;
@@ -656,6 +664,11 @@ abstract class TestAudioActivity extends AppCompatActivity {
                     int actualContentType = streamContext.tester.actualConfiguration.getContentType();
                     setStreamControlByAttributes(actualUsage, actualContentType);
                 }
+
+                if (streamContext.tester.actualConfiguration.getFormat() ==
+                        StreamConfiguration.AUDIO_FORMAT_MP3) {
+                    setupMp3BufferFromFile();
+                }
             }
         }
         for (StreamContext streamContext : mStreamContexts) {
@@ -711,6 +724,15 @@ abstract class TestAudioActivity extends AppCompatActivity {
         StreamConfiguration requestedConfig = streamContext.tester.requestedConfiguration;
         StreamConfiguration actualConfig = streamContext.tester.actualConfiguration;
 
+        if (requestedConfig.getFormat() == StreamConfiguration.AUDIO_FORMAT_MP3 &&
+                (requestedConfig.getDirection() != StreamConfiguration.DIRECTION_OUTPUT ||
+                        requestedConfig.getChannelMask() != MP3_FILE_CONFIG.mChannelMask ||
+                        requestedConfig.getSampleRate() != MP3_FILE_CONFIG.mSampleRate)) {
+            showErrorToast("MP3 format uses builtin 44.1kHz stereo mp3 file for playback, " +
+                           "the requested configuration must be 44.1kHz stereo when format is MP3");
+            return;
+        }
+
         streamContext.tester.open(); // OPEN the stream
 
         mSampleRate = actualConfig.getSampleRate();
@@ -743,6 +765,8 @@ abstract class TestAudioActivity extends AppCompatActivity {
 
     private native int getFramesPerCallback();
 
+    private native void setupMemoryBuffer(byte[] buffer, int offset, int length);
+
     public native void setUseAlternativeAdpf(boolean enabled);
 
     private static native void setDefaultAudioValues(int audioManagerSampleRate, int audioManagerFramesPerBurst);
@@ -916,4 +940,34 @@ abstract class TestAudioActivity extends AppCompatActivity {
         }
         return fileWritten;
     }
+
+    void setupMp3BufferFromFile() {
+        try {
+            InputStream inputStream = this.getResources().openRawResource(MP3_RES_ID);
+            final int length = inputStream.available();
+            byte[] buffer = new byte[length];
+            int readLength = inputStream.read(buffer, 0 /*off*/, length);
+            inputStream.close();
+            Log.i(TAG, "Total file length=" + length + ", read length=" + readLength);
+            ByteBuffer byteBuffer = ByteBuffer.wrap(buffer);
+            byteBuffer.order(ByteOrder.nativeOrder());
+            setupMemoryBuffer(byteBuffer.array(), 0, readLength);
+        } catch (Exception e) {
+            showErrorToast("Failed to load mp3 file " + e.getMessage());
+        }
+    }
+
+    private static class AudioConfig {
+        public int mSampleRate;
+        public int mFormat;
+        public int mChannelMask;
+        public int mChannelCount;
+
+        public AudioConfig(int sampleRate, int format, int channelMask, int channelCount) {
+            mSampleRate = sampleRate;
+            mFormat = format;
+            mChannelMask = channelMask;
+            mChannelCount = channelCount;
+        }
+    }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivity.java
index f2ac5ed5..52cc110d 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivity.java
@@ -40,6 +40,7 @@ public final class TestOutputActivity extends TestOutputActivityBase {
     private TextView mVolumeTextView;
     private SeekBar mVolumeSeekBar;
     private CheckBox mShouldSetStreamControlByAttributes;
+    private boolean mShouldDisableForCompressedFormat = false;
 
     private class OutputSignalSpinnerListener implements android.widget.AdapterView.OnItemSelectedListener {
         @Override
@@ -99,7 +100,7 @@ public final class TestOutputActivity extends TestOutputActivityBase {
         mChannelBoxes[ic++] = (CheckBox) findViewById(R.id.channelBox13);
         mChannelBoxes[ic++] = (CheckBox) findViewById(R.id.channelBox14);
         mChannelBoxes[ic++] = (CheckBox) findViewById(R.id.channelBox15);
-        configureChannelBoxes(0);
+        configureChannelBoxes(0 /*channelCount*/, false /*shouldDisable*/);
 
         mOutputSignalSpinner = (Spinner) findViewById(R.id.spinnerOutputSignal);
         mOutputSignalSpinner.setOnItemSelectedListener(new OutputSignalSpinnerListener());
@@ -122,12 +123,14 @@ public final class TestOutputActivity extends TestOutputActivityBase {
     public void openAudio() throws IOException {
         super.openAudio();
         mShouldSetStreamControlByAttributes.setEnabled(false);
+        mShouldDisableForCompressedFormat = StreamConfiguration.isCompressedFormat(
+                mAudioOutTester.getCurrentAudioStream().getFormat());
     }
 
-    private void configureChannelBoxes(int channelCount) {
+    private void configureChannelBoxes(int channelCount, boolean shouldDisable) {
         for (int i = 0; i < mChannelBoxes.length; i++) {
             mChannelBoxes[i].setChecked(i < channelCount);
-            mChannelBoxes[i].setEnabled(i < channelCount);
+            mChannelBoxes[i].setEnabled(!shouldDisable && (i < channelCount));
         }
     }
 
@@ -146,25 +149,25 @@ public final class TestOutputActivity extends TestOutputActivityBase {
 
 
     public void stopAudio() {
-        configureChannelBoxes(0);
-        mOutputSignalSpinner.setEnabled(true);
+        configureChannelBoxes(0 /*channelCount*/, mShouldDisableForCompressedFormat);
+        mOutputSignalSpinner.setEnabled(!mShouldDisableForCompressedFormat);
         super.stopAudio();
     }
 
     public void pauseAudio() {
-        configureChannelBoxes(0);
-        mOutputSignalSpinner.setEnabled(true);
+        configureChannelBoxes(0 /*channelCount*/, mShouldDisableForCompressedFormat);
+        mOutputSignalSpinner.setEnabled(!mShouldDisableForCompressedFormat);
         super.pauseAudio();
     }
 
     public void releaseAudio() {
-        configureChannelBoxes(0);
+        configureChannelBoxes(0 /*channelCount*/, false /*shouldDisable*/);
         mOutputSignalSpinner.setEnabled(true);
         super.releaseAudio();
     }
 
     public void closeAudio() {
-        configureChannelBoxes(0);
+        configureChannelBoxes(0 /*channelCount*/, false /*shouldDisable*/);
         mOutputSignalSpinner.setEnabled(true);
         mShouldSetStreamControlByAttributes.setEnabled(true);
         super.closeAudio();
@@ -173,7 +176,7 @@ public final class TestOutputActivity extends TestOutputActivityBase {
     public void startAudio() throws IOException {
         super.startAudio();
         int channelCount = mAudioOutTester.getCurrentAudioStream().getChannelCount();
-        configureChannelBoxes(channelCount);
+        configureChannelBoxes(channelCount, mShouldDisableForCompressedFormat);
         mOutputSignalSpinner.setEnabled(false);
     }
 
diff --git a/apps/OboeTester/app/src/main/res/raw/sine441stereo.mp3 b/apps/OboeTester/app/src/main/res/raw/sine441stereo.mp3
new file mode 100644
index 00000000..29bc6832
Binary files /dev/null and b/apps/OboeTester/app/src/main/res/raw/sine441stereo.mp3 differ
diff --git a/apps/OboeTester/app/src/main/res/values/strings.xml b/apps/OboeTester/app/src/main/res/values/strings.xml
index 2c67ef1f..176d1a3b 100644
--- a/apps/OboeTester/app/src/main/res/values/strings.xml
+++ b/apps/OboeTester/app/src/main/res/values/strings.xml
@@ -100,6 +100,7 @@
         <item>PCM_I24</item>
         <item>PCM_I32</item>
         <item>IEC61937</item>
+        <item>MP3</item>
     </string-array>
 
     <string name="input_preset_prompt">InPreset:</string>
diff --git a/apps/OboeTester/docs/TestOutput.md b/apps/OboeTester/docs/TestOutput.md
index 9e7e539a..e9b10116 100644
--- a/apps/OboeTester/docs/TestOutput.md
+++ b/apps/OboeTester/docs/TestOutput.md
@@ -14,7 +14,7 @@ DRAFT for testing image embedding.
       The resulting setting will displayed on the far right when the stream is opened.<br/>
       API: select between OpenSL ES or AAudio (default)<br/>
       Device: setect output device by type.<br/>
-      Format: note that the 24 and 32-bit formats are only supported in Android 12+<br/>
+      Format: note that the 24 and 32-bit formats are only supported in Android 12+. MP3 is only supported on Android 16+. The test uses a 44.1kHz stereo MP3 file for playback. The stream must be configured as 44.1kHz stereo selecting MP3 format.<br/>
       MMAP: will be disabled if device does not support MMAP<br/>
       Effect: will enable a simple effect, may prevent LOW_LATENCY<br/>
       Convert: conversion done in Oboe may allow you to get LOW_LATENCY<br/>
diff --git a/docs/FullGuide.md b/docs/FullGuide.md
index b04a1b1a..a3721199 100644
--- a/docs/FullGuide.md
+++ b/docs/FullGuide.md
@@ -56,6 +56,13 @@ Oboe permits these sample formats:
 | I24 | N/A | 24-bit samples packed into 3 bytes, [Q0.23 format](https://source.android.com/devices/audio/data_formats#androidFormats). Added in API 31 |
 | I32 | int32_t | common 32-bit samples, [Q0.31 format](https://source.android.com/devices/audio/data_formats#androidFormats). Added in API 31 |
 | IEC61937 | N/A | compressed audio wrapped in IEC61937 for HDMI or S/PDIF passthrough. Added in API 34 |
+| MP3 | N/A | compressed audio format in MP3 format. Added in API36 |
+| AAC_LC | N/A | compressed audio format in AAC LC format. Added in API 36 |
+| AAC_HE_V1 | N/A | compressed audio format in AAC HE V1 format. Added in API 36 |
+| AAC_HE_V2 | N/A | compressed audio format in AAC HE V2 format. Added in API 36 |
+| AAC_ELD | N/A | compressed audio format in AAC ELD format. Added in API 36 |
+| AAC_XHE | N/A | compressed audio format in AAC XHE format. Added in API 36 |
+| OPUS | N/A | compressed audio format in OPUS format. Added in API 36 |
 
 Oboe might perform sample conversion on its own. For example, if an app is writing AudioFormat::Float data but the HAL uses AudioFormat::I16, Oboe might convert the samples automatically. Conversion can happen in either direction. If your app processes audio input, it is wise to verify the input format and be prepared to convert data if necessary, as in this example:
 
diff --git a/include/oboe/AudioStream.h b/include/oboe/AudioStream.h
index 67856020..9649f8bb 100644
--- a/include/oboe/AudioStream.h
+++ b/include/oboe/AudioStream.h
@@ -25,6 +25,7 @@
 #include "oboe/ResultWithValue.h"
 #include "oboe/AudioStreamBuilder.h"
 #include "oboe/AudioStreamBase.h"
+#include "oboe/Utilities.h"
 
 namespace oboe {
 
@@ -242,14 +243,20 @@ public:
      * and the sample format. For example, a 2 channel floating point stream will have
      * 2 * 4 = 8 bytes per frame.
      *
+     * Note for compressed formats, bytes per frames is treated as 1 by convention.
+     *
      * @return number of bytes in each audio frame.
      */
-    int32_t getBytesPerFrame() const { return mChannelCount * getBytesPerSample(); }
+    int32_t getBytesPerFrame() const {
+        return isCompressedFormat(mFormat) ? 1 : mChannelCount * getBytesPerSample(); }
 
     /**
      * Get the number of bytes per sample. This is calculated using the sample format. For example,
      * a stream using 16-bit integer samples will have 2 bytes per sample.
      *
+     * Note for compressed formats, they may not have a fixed bytes per sample. In that case,
+     * this method will return 0 for compressed format.
+     *
      * @return the number of bytes per sample.
      */
     int32_t getBytesPerSample() const;
@@ -568,14 +575,12 @@ public:
      * @param appWorkload workload in application units, such as number of voices
      * @return OK or an error such as ErrorInvalidState if the PerformanceHint was not enabled.
      */
-    virtual oboe::Result reportWorkload(int32_t appWorkload) {
-        std::ignore = appWorkload;
+    virtual oboe::Result reportWorkload([[maybe_unused]] int32_t appWorkload) {
         return oboe::Result::ErrorUnimplemented;
     }
 
-    virtual oboe::Result setOffloadDelayPadding(int32_t delayInFrames, int32_t paddingInFrames) {
-        std::ignore = delayInFrames;
-        std::ignore = paddingInFrames;
+    virtual oboe::Result setOffloadDelayPadding([[maybe_unused]] int32_t delayInFrames,
+                                                [[maybe_unused]] int32_t paddingInFrames) {
         return Result::ErrorUnimplemented;
     }
 
diff --git a/include/oboe/AudioStreamBase.h b/include/oboe/AudioStreamBase.h
index 6ef6b1ea..47b77252 100644
--- a/include/oboe/AudioStreamBase.h
+++ b/include/oboe/AudioStreamBase.h
@@ -19,6 +19,7 @@
 
 #include <memory>
 #include <string>
+#include <vector>
 #include "oboe/AudioStreamCallback.h"
 #include "oboe/Definitions.h"
 
@@ -103,7 +104,13 @@ public:
     /**
      * @return the device ID of the stream.
      */
-    int32_t getDeviceId() const { return mDeviceId; }
+    int32_t getDeviceId() const {
+        return mDeviceIds.empty() ? kUnspecified :  mDeviceIds[0];
+    }
+
+    std::vector<int32_t> getDeviceIds() const {
+        return mDeviceIds;
+    }
 
     /**
      * For internal use only.
@@ -267,8 +274,6 @@ protected:
     int32_t                         mChannelCount = kUnspecified;
     /** Stream sample rate */
     int32_t                         mSampleRate = kUnspecified;
-    /** Stream audio device ID */
-    int32_t                         mDeviceId = kUnspecified;
     /** Stream buffer capacity specified as a number of audio frames */
     int32_t                         mBufferCapacityInFrames = kUnspecified;
     /** Stream buffer size specified as a number of audio frames */
@@ -326,6 +331,8 @@ protected:
     // Control whether and how Oboe can convert sample rates to achieve optimal results.
     SampleRateConversionQuality     mSampleRateConversionQuality = SampleRateConversionQuality::Medium;
 
+    std::vector<int32_t>            mDeviceIds;
+
     /** Validate stream parameters that might not be checked in lower layers */
     virtual Result isValidConfig() {
         switch (mFormat) {
@@ -335,6 +342,13 @@ protected:
             case AudioFormat::I24:
             case AudioFormat::I32:
             case AudioFormat::IEC61937:
+            case AudioFormat::MP3:
+            case AudioFormat::AAC_LC:
+            case AudioFormat::AAC_HE_V1:
+            case AudioFormat::AAC_HE_V2:
+            case AudioFormat::AAC_ELD:
+            case AudioFormat::AAC_XHE:
+            case AudioFormat::OPUS:
                 break;
 
             default:
diff --git a/include/oboe/AudioStreamBuilder.h b/include/oboe/AudioStreamBuilder.h
index accea2f4..04866320 100644
--- a/include/oboe/AudioStreamBuilder.h
+++ b/include/oboe/AudioStreamBuilder.h
@@ -344,7 +344,10 @@ public:
      * @return pointer to the builder so calls can be chained
      */
     AudioStreamBuilder *setDeviceId(int32_t deviceId) {
-        mDeviceId = deviceId;
+        mDeviceIds.clear();
+        if (deviceId != kUnspecified) {
+            mDeviceIds.push_back(deviceId);
+        }
         return this;
     }
 
diff --git a/include/oboe/Oboe.h b/include/oboe/Oboe.h
index 9cd90968..614ce267 100644
--- a/include/oboe/Oboe.h
+++ b/include/oboe/Oboe.h
@@ -20,7 +20,10 @@
 /**
  * \mainpage API reference
  *
- * All documentation is found in the <a href="namespaceoboe.html">oboe namespace section</a>
+ * See our <a href="https://github.com/google/oboe/blob/main/docs/FullGuide.md">guide</a> on Github
+ * for a guide on Oboe.
+ *
+ * Click the classes tab to see the reference for various Oboe functions.
  *
  */
 
diff --git a/include/oboe/Utilities.h b/include/oboe/Utilities.h
index f0f41865..84341cab 100644
--- a/include/oboe/Utilities.h
+++ b/include/oboe/Utilities.h
@@ -94,6 +94,8 @@ bool isAtLeastPreReleaseCodename(const std::string& codename);
 
 int getChannelCountFromChannelMask(ChannelMask channelMask);
 
+bool isCompressedFormat(AudioFormat format);
+
 } // namespace oboe
 
 #endif //OBOE_UTILITIES_H
diff --git a/include/oboe/Version.h b/include/oboe/Version.h
index 38150078..42196336 100644
--- a/include/oboe/Version.h
+++ b/include/oboe/Version.h
@@ -37,7 +37,7 @@
 #define OBOE_VERSION_MINOR 9
 
 // Type: 16-bit unsigned int. Min value: 0 Max value: 65535. See below for description.
-#define OBOE_VERSION_PATCH 3
+#define OBOE_VERSION_PATCH 4
 
 #define OBOE_STRINGIFY(x) #x
 #define OBOE_TOSTRING(x) OBOE_STRINGIFY(x)
diff --git a/samples/SoundBoard/soundboard_image.png b/samples/SoundBoard/soundboard_image.png
index d3bc21bf..9f10fef4 100644
Binary files a/samples/SoundBoard/soundboard_image.png and b/samples/SoundBoard/soundboard_image.png differ
diff --git a/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MainActivity.kt b/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MainActivity.kt
index a697bdb5..5f0205f5 100644
--- a/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MainActivity.kt
+++ b/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MainActivity.kt
@@ -24,6 +24,8 @@ import android.graphics.Rect
 import android.media.AudioManager
 import android.os.Build
 import android.os.Bundle
+import android.view.WindowInsets
+import android.view.WindowManager
 import androidx.annotation.RequiresApi
 import androidx.appcompat.app.AppCompatActivity
 import kotlin.math.min
@@ -38,7 +40,8 @@ class MainActivity : AppCompatActivity() {
         private const val DIMENSION_MAX_SIZE = 8
         private var mNumColumns : Int = 0;
         private var mNumRows : Int = 0;
-        private var mRectangles = ArrayList<Rect>()
+        private var mTiles = ArrayList<Rect>()
+        private var mBorders = ArrayList<Rect>()
 
         private var mEngineHandle: Long = 0
 
@@ -81,19 +84,25 @@ class MainActivity : AppCompatActivity() {
     }
 
     private fun calculateAndSetRectangles(context: Context) {
-        val width: Int
-        val height: Int
+        val windowManager = context.getSystemService(Context.WINDOW_SERVICE) as WindowManager
+        val display = windowManager.defaultDisplay
+        val size = Point()
 
         if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
-            width = windowManager.currentWindowMetrics.bounds.width()
-            height = windowManager.currentWindowMetrics.bounds.height()
+            val windowMetrics = windowManager.currentWindowMetrics
+            val windowInsets = windowMetrics.windowInsets
+            val insets = windowInsets.getInsetsIgnoringVisibility(
+                    WindowInsets.Type.navigationBars() or WindowInsets.Type.statusBars())
+            val width = windowMetrics.bounds.width() - insets.left - insets.right
+            val height = windowMetrics.bounds.height() - insets.top - insets.bottom
+            size.set(width, height)
         } else {
-            val size = Point()
-            windowManager.defaultDisplay.getRealSize(size)
-            height = size.y
-            width = size.x
+            display.getSize(size) // Use getSize to exclude navigation bar if visible
         }
 
+        val width = size.x
+        val height = size.y
+
         if (height > width) {
             mNumColumns = DIMENSION_MIN_SIZE
             mNumRows = min(DIMENSION_MIN_SIZE * height / width, DIMENSION_MAX_SIZE)
@@ -103,8 +112,9 @@ class MainActivity : AppCompatActivity() {
         }
         val tileLength = min(height / mNumRows, width / mNumColumns)
         val xStartLocation = (width - tileLength * mNumColumns) / 2
-        val yStartLocation = 0
-        mRectangles = ArrayList<Rect>()
+        val yStartLocation = (height - tileLength * mNumRows) / 2
+
+        mTiles = ArrayList<Rect>()
         for (i in 0 until mNumRows) {
             for (j in 0 until mNumColumns) {
                 val rectangle = Rect(
@@ -113,13 +123,23 @@ class MainActivity : AppCompatActivity() {
                     xStartLocation + j * tileLength + tileLength,
                     yStartLocation + i * tileLength + tileLength
                 )
-                mRectangles.add(rectangle)
+                mTiles.add(rectangle)
             }
         }
+
+        mBorders = ArrayList<Rect>()
+        // Top border
+        mBorders.add(Rect(0, 0, width, yStartLocation))
+        // Bottom border
+        mBorders.add(Rect(0, yStartLocation + tileLength * mNumRows, width, height))
+        // Left border
+        mBorders.add(Rect(0, 0, xStartLocation, height))
+        // Right border
+        mBorders.add(Rect(xStartLocation + tileLength * mNumColumns, 0, width, height))
     }
 
     private fun createMusicTiles(context: Context) {
-        setContentView(MusicTileView(this, mRectangles, NoteListener(mEngineHandle),
+        setContentView(MusicTileView(this, mTiles, mBorders, NoteListener(mEngineHandle),
                 ScreenChangeListener { setup() }))
     }
 
diff --git a/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MusicTileView.kt b/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MusicTileView.kt
index ac813450..e31fd383 100644
--- a/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MusicTileView.kt
+++ b/samples/SoundBoard/src/main/kotlin/com/google/oboe/samples/soundboard/MusicTileView.kt
@@ -22,14 +22,16 @@ import android.graphics.*
 import android.util.SparseArray
 import android.view.MotionEvent
 import android.view.View
+import androidx.core.content.ContextCompat
 
 class MusicTileView(
     context: Context?,
-    private val mRectangles: ArrayList<Rect>,
+    private val mTiles: ArrayList<Rect>,
+    private val mBorders: ArrayList<Rect>,
     tileListener: TileListener,
     configChangeListener: ConfigChangeListener
 ) : View(context) {
-    private val mIsPressedPerRectangle: BooleanArray = BooleanArray(mRectangles.size)
+    private val mIsPressedPerRectangle: BooleanArray = BooleanArray(mTiles.size)
     private val mPaint: Paint = Paint()
     private val mLocationsOfFingers: SparseArray<PointF> = SparseArray()
     private val mTileListener: TileListener
@@ -45,8 +47,8 @@ class MusicTileView(
     }
 
     private fun getIndexFromLocation(pointF: PointF): Int {
-        for (i in mRectangles.indices) {
-            if (pointF.x > mRectangles[i].left && pointF.x < mRectangles[i].right && pointF.y > mRectangles[i].top && pointF.y < mRectangles[i].bottom) {
+        for (i in mTiles.indices) {
+            if (pointF.x > mTiles[i].left && pointF.x < mTiles[i].right && pointF.y > mTiles[i].top && pointF.y < mTiles[i].bottom) {
                 return i
             }
         }
@@ -54,20 +56,25 @@ class MusicTileView(
     }
 
     override fun onDraw(canvas: Canvas) {
-        for (i in mRectangles.indices) {
+        for (i in mTiles.indices) {
             mPaint.style = Paint.Style.FILL
             if (mIsPressedPerRectangle[i]) {
-                mPaint.color = Color.rgb(128, 0, 0)
+                mPaint.color = ContextCompat.getColor(context, R.color.colorPrimary)
             } else {
                 mPaint.color = Color.BLACK
             }
-            canvas.drawRect(mRectangles[i], mPaint)
+            canvas.drawRect(mTiles[i], mPaint)
 
-            // border
+            // white border
             mPaint.style = Paint.Style.STROKE
             mPaint.strokeWidth = 10f
             mPaint.color = Color.WHITE
-            canvas.drawRect(mRectangles[i], mPaint)
+            canvas.drawRect(mTiles[i], mPaint)
+        }
+        for (i in mBorders.indices) {
+            mPaint.style = Paint.Style.FILL
+            mPaint.color = ContextCompat.getColor(context, R.color.colorPrimaryDark)
+            canvas.drawRect(mBorders[i], mPaint)
         }
     }
 
@@ -82,7 +89,7 @@ class MusicTileView(
                 // Create an array to check for finger changes as multiple fingers may be on the
                 // same tile. This two-pass algorithm records the overall difference before changing
                 // the actual tiles.
-                val notesChangedBy = IntArray(mRectangles.size)
+                val notesChangedBy = IntArray(mTiles.size)
                 run {
                     val size = event.pointerCount
                     var i = 0
@@ -108,7 +115,7 @@ class MusicTileView(
 
                 // Now go through the rectangles to see if they have changed
                 var i = 0
-                while (i < mRectangles.size) {
+                while (i < mTiles.size) {
                     if (notesChangedBy[i] > 0) {
                         mIsPressedPerRectangle[i] = true
                         mTileListener.onTileOn(i)
diff --git a/samples/SoundBoard/src/main/res/values/colors.xml b/samples/SoundBoard/src/main/res/values/colors.xml
index 5783a670..8b538864 100644
--- a/samples/SoundBoard/src/main/res/values/colors.xml
+++ b/samples/SoundBoard/src/main/res/values/colors.xml
@@ -1,6 +1,6 @@
 <?xml version="1.0" encoding="utf-8"?>
 <resources>
-    <color name="colorPrimary">#800000</color>
-    <color name="colorPrimaryDark">#300000</color>
+    <color name="colorPrimary">#700000</color>
+    <color name="colorPrimaryDark">#280000</color>
     <color name="colorAccent">#D81B60</color>
 </resources>
diff --git a/samples/SoundBoard/src/main/res/values/styles.xml b/samples/SoundBoard/src/main/res/values/styles.xml
index 5885930d..0eb88fe3 100644
--- a/samples/SoundBoard/src/main/res/values/styles.xml
+++ b/samples/SoundBoard/src/main/res/values/styles.xml
@@ -1,7 +1,7 @@
 <resources>
 
     <!-- Base application theme. -->
-    <style name="AppTheme" parent="Theme.AppCompat.Light.DarkActionBar">
+    <style name="AppTheme" parent="Theme.AppCompat.Light.NoActionBar">
         <!-- Customize your theme here. -->
         <item name="colorPrimary">@color/colorPrimary</item>
         <item name="colorPrimaryDark">@color/colorPrimaryDark</item>
diff --git a/src/aaudio/AAudioLoader.cpp b/src/aaudio/AAudioLoader.cpp
index 65609996..80e45a88 100644
--- a/src/aaudio/AAudioLoader.cpp
+++ b/src/aaudio/AAudioLoader.cpp
@@ -181,7 +181,8 @@ int AAudioLoader::open() {
         stream_getHardwareFormat = load_F_PS("AAudioStream_getHardwareFormat");
     }
 
-    if (getSdkVersion() >= __ANDROID_API_B__) {
+    // TODO: Remove pre-release check after Android B release
+    if (getSdkVersion() >= __ANDROID_API_B__ || isAtLeastPreReleaseCodename("Baklava")) {
         aaudio_getPlatformMMapPolicy = load_I_II("AAudio_getPlatformMMapPolicy");
         aaudio_getPlatformMMapExclusivePolicy = load_I_II("AAudio_getPlatformMMapExclusivePolicy");
         aaudio_setMMapPolicy = load_I_I("AAudio_setMMapPolicy");
@@ -192,6 +193,8 @@ int AAudioLoader::open() {
         stream_getOffloadDelay = load_I_PS("AAudioStream_getOffloadDelay");
         stream_getOffloadPadding = load_I_PS("AAudioStream_getOffloadPadding");
         stream_setOffloadEndOfStream = load_I_PS("AAudioStream_setOffloadEndOfStream");
+
+        stream_getDeviceIds = load_I_PSPIPI("AAudioStream_getDeviceIds");
     }
 
     return 0;
@@ -353,6 +356,12 @@ AAudioLoader::signature_I_PSII AAudioLoader::load_I_PSII(const char *functionNam
     return reinterpret_cast<signature_I_PSII>(proc);
 }
 
+AAudioLoader::signature_I_PSPIPI AAudioLoader::load_I_PSPIPI(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_I_PSPIPI>(proc);
+}
+
 // Ensure that all AAudio primitive data types are int32_t
 #define ASSERT_INT32(type) static_assert(std::is_same<int32_t, type>::value, \
 #type" must be int32_t")
diff --git a/src/aaudio/AAudioLoader.h b/src/aaudio/AAudioLoader.h
index 3eb5c640..0e77613f 100644
--- a/src/aaudio/AAudioLoader.h
+++ b/src/aaudio/AAudioLoader.h
@@ -193,6 +193,9 @@ class AAudioLoader {
     typedef int32_t (*signature_I)();
     typedef int32_t (*signature_I_PSII)(AAudioStream *, int32_t, int32_t);
 
+    // AAudioStream_getDeviceIds()
+    typedef int32_t (*signature_I_PSPIPI)(AAudioStream *, int32_t *, int32_t *);
+
     static AAudioLoader* getInstance(); // singleton
 
     /**
@@ -253,6 +256,8 @@ class AAudioLoader {
 
     signature_I_PSKPLPL stream_getTimestamp = nullptr;
 
+    signature_I_PSPIPI  stream_getDeviceIds = nullptr;
+
     signature_I_PS   stream_release = nullptr;
     signature_I_PS   stream_close = nullptr;
 
@@ -338,6 +343,7 @@ class AAudioLoader {
     signature_I         load_I(const char *name);
     signature_V_PBPRPV  load_V_PBPRPV(const char *name);
     signature_I_PSII    load_I_PSII(const char *name);
+    signature_I_PSPIPI  load_I_PSPIPI(const char *name);
 
     void *mLibHandle = nullptr;
 };
diff --git a/src/aaudio/AudioStreamAAudio.cpp b/src/aaudio/AudioStreamAAudio.cpp
index 851318f7..9f800470 100644
--- a/src/aaudio/AudioStreamAAudio.cpp
+++ b/src/aaudio/AudioStreamAAudio.cpp
@@ -298,7 +298,7 @@ Result AudioStreamAAudio::open() {
     } else {
         mLibLoader->builder_setChannelCount(aaudioBuilder, mChannelCount);
     }
-    mLibLoader->builder_setDeviceId(aaudioBuilder, mDeviceId);
+    mLibLoader->builder_setDeviceId(aaudioBuilder, getDeviceId());
     mLibLoader->builder_setDirection(aaudioBuilder, static_cast<aaudio_direction_t>(mDirection));
     mLibLoader->builder_setFormat(aaudioBuilder, static_cast<aaudio_format_t>(mFormat));
     mLibLoader->builder_setSampleRate(aaudioBuilder, mSampleRate);
@@ -403,7 +403,6 @@ Result AudioStreamAAudio::open() {
     }
 
     // Query and cache the stream properties
-    mDeviceId = mLibLoader->stream_getDeviceId(mAAudioStream);
     mChannelCount = mLibLoader->stream_getChannelCount(mAAudioStream);
     mSampleRate = mLibLoader->stream_getSampleRate(mAAudioStream);
     mFormat = static_cast<AudioFormat>(mLibLoader->stream_getFormat(mAAudioStream));
@@ -468,6 +467,8 @@ Result AudioStreamAAudio::open() {
         mHardwareFormat = static_cast<AudioFormat>(mLibLoader->stream_getHardwareFormat(mAAudioStream));
     }
 
+    updateDeviceIds();
+
     LOGD("AudioStreamAAudio.open() format=%d, sampleRate=%d, capacity = %d",
             static_cast<int>(mFormat), static_cast<int>(mSampleRate),
             static_cast<int>(mBufferCapacityInFrames));
@@ -981,4 +982,41 @@ Result AudioStreamAAudio::setOffloadEndOfStream() {
     return static_cast<Result>(mLibLoader->stream_setOffloadEndOfStream(stream));
 }
 
+void AudioStreamAAudio::updateDeviceIds() {
+    // If stream_getDeviceIds is not supported, use stream_getDeviceId.
+    if (mLibLoader->stream_getDeviceIds == nullptr) {
+        mDeviceIds.clear();
+        int32_t deviceId = mLibLoader->stream_getDeviceId(mAAudioStream);
+        if (deviceId != kUnspecified) {
+            mDeviceIds.push_back(deviceId);
+        }
+    } else {
+        // Allocate a temp vector with 16 elements. This should be enough to cover all cases.
+        // Please file a bug on Oboe if you discover that this returns AAUDIO_ERROR_OUT_OF_RANGE.
+        // When AAUDIO_ERROR_OUT_OF_RANGE is returned, the actual size will be still returned as the
+        // value of deviceIdSize but deviceIds will be empty.
+
+        static constexpr int kDefaultDeviceIdSize = 16;
+        int deviceIdSize = kDefaultDeviceIdSize;
+        std::vector<int32_t> deviceIds(deviceIdSize);
+        aaudio_result_t getDeviceIdResult =
+                mLibLoader->stream_getDeviceIds(mAAudioStream, deviceIds.data(), &deviceIdSize);
+        if (getDeviceIdResult != AAUDIO_OK) {
+            LOGE("stream_getDeviceIds did not return AAUDIO_OK. Error: %d",
+                    static_cast<int>(getDeviceIdResult));
+            return;
+        }
+
+        mDeviceIds.clear();
+        for (int i = 0; i < deviceIdSize; i++) {
+            mDeviceIds.push_back(deviceIds[i]);
+        }
+    }
+
+    // This should not happen in most cases. Please file a bug on Oboe if you see this happening.
+    if (mDeviceIds.empty()) {
+        LOGW("updateDeviceIds() returns an empty array.");
+    }
+}
+
 } // namespace oboe
diff --git a/src/aaudio/AudioStreamAAudio.h b/src/aaudio/AudioStreamAAudio.h
index c69723b1..53df75da 100644
--- a/src/aaudio/AudioStreamAAudio.h
+++ b/src/aaudio/AudioStreamAAudio.h
@@ -149,6 +149,8 @@ private:
      */
     void launchStopThread();
 
+    void updateDeviceIds();
+
 private:
 
     std::atomic<bool>    mCallbackThreadEnabled;
diff --git a/src/common/FilterAudioStream.h b/src/common/FilterAudioStream.h
index 99f6f5ac..dfcb4a75 100644
--- a/src/common/FilterAudioStream.h
+++ b/src/common/FilterAudioStream.h
@@ -58,7 +58,7 @@ public:
         mSharingMode = mChildStream->getSharingMode();
         mInputPreset = mChildStream->getInputPreset();
         mFramesPerBurst = mChildStream->getFramesPerBurst();
-        mDeviceId = mChildStream->getDeviceId();
+        mDeviceIds = mChildStream->getDeviceIds();
         mHardwareSampleRate = mChildStream->getHardwareSampleRate();
         mHardwareChannelCount = mChildStream->getHardwareChannelCount();
         mHardwareFormat = mChildStream->getHardwareFormat();
diff --git a/src/common/QuirksManager.cpp b/src/common/QuirksManager.cpp
index f9890be5..319c7f25 100644
--- a/src/common/QuirksManager.cpp
+++ b/src/common/QuirksManager.cpp
@@ -16,6 +16,7 @@
 
 #include <oboe/AudioStreamBuilder.h>
 #include <oboe/Oboe.h>
+#include <oboe/Utilities.h>
 
 #include "OboeDebug.h"
 #include "QuirksManager.h"
@@ -201,6 +202,7 @@ bool QuirksManager::isConversionNeeded(
     const bool isInput = builder.getDirection() == Direction::Input;
     const bool isFloat = builder.getFormat() == AudioFormat::Float;
     const bool isIEC61937 = builder.getFormat() == AudioFormat::IEC61937;
+    const bool isCompressed = isCompressedFormat(builder.getFormat());
 
     // There should be no conversion for IEC61937. Sample rates and channel counts must be set explicitly.
     if (isIEC61937) {
@@ -208,6 +210,12 @@ bool QuirksManager::isConversionNeeded(
         return false;
     }
 
+    if (isCompressed) {
+        LOGI("QuirksManager::%s() conversion not needed for compressed format %d",
+             __func__, builder.getFormat());
+        return false;
+    }
+
     // There are multiple bugs involving using callback with a specified callback size.
     // Issue #778: O to Q had a problem with Legacy INPUT streams for FLOAT streams
     // and a specified callback size. It would assert because of a bad buffer size.
diff --git a/src/common/Utilities.cpp b/src/common/Utilities.cpp
index d84d35f4..98cbb569 100644
--- a/src/common/Utilities.cpp
+++ b/src/common/Utilities.cpp
@@ -17,6 +17,7 @@
 
 #include <stdlib.h>
 #include <unistd.h>
+#include <set>
 #include <sstream>
 
 #ifdef __ANDROID__
@@ -69,6 +70,17 @@ int32_t convertFormatToSizeInBytes(AudioFormat format) {
         case AudioFormat::IEC61937:
             size = sizeof(int16_t);
             break;
+        case AudioFormat::MP3:
+        case AudioFormat::AAC_LC:
+        case AudioFormat::AAC_HE_V1:
+        case AudioFormat::AAC_HE_V2:
+        case AudioFormat::AAC_ELD:
+        case AudioFormat::AAC_XHE:
+        case AudioFormat::OPUS:
+            // For compressed formats, set the size per sample as 0 as they may not have
+            // fix size per sample.
+            size = 0;
+            break;
         default:
             break;
     }
@@ -110,6 +122,13 @@ const char *convertToText<AudioFormat>(AudioFormat format) {
         case AudioFormat::I24:          return "I24";
         case AudioFormat::I32:          return "I32";
         case AudioFormat::IEC61937:     return "IEC61937";
+        case AudioFormat::MP3:          return "MP3";
+        case AudioFormat::AAC_LC:       return "AAC_LC";
+        case AudioFormat::AAC_HE_V1:    return "AAC_HE_V1";
+        case AudioFormat::AAC_HE_V2:    return "AAC_HE_V2";
+        case AudioFormat::AAC_ELD:      return "AAC_ELD";
+        case AudioFormat::AAC_XHE:      return "AAC_XHE";
+        case AudioFormat::OPUS:         return "OPUS";
         default:                        return "Unrecognized format";
     }
 }
@@ -344,4 +363,13 @@ int getChannelCountFromChannelMask(ChannelMask channelMask) {
     return __builtin_popcount(static_cast<uint32_t>(channelMask));
 }
 
+
+std::set<AudioFormat> COMPRESSED_FORMATS = {
+        AudioFormat::MP3, AudioFormat::AAC_LC, AudioFormat::AAC_HE_V1, AudioFormat::AAC_HE_V2,
+        AudioFormat::AAC_ELD, AudioFormat::AAC_XHE, AudioFormat::OPUS
+};
+bool isCompressedFormat(AudioFormat format) {
+    return COMPRESSED_FORMATS.count(format) != 0;
+}
+
 }// namespace oboe
diff --git a/src/opensles/AudioStreamOpenSLES.cpp b/src/opensles/AudioStreamOpenSLES.cpp
index d96a4616..70f78b66 100644
--- a/src/opensles/AudioStreamOpenSLES.cpp
+++ b/src/opensles/AudioStreamOpenSLES.cpp
@@ -29,7 +29,7 @@ using namespace oboe;
 AudioStreamOpenSLES::AudioStreamOpenSLES(const AudioStreamBuilder &builder)
     : AudioStreamBuffered(builder) {
     // OpenSL ES does not support device IDs. So overwrite value from builder.
-    mDeviceId = kUnspecified;
+    mDeviceIds.clear();
     // OpenSL ES does not support session IDs. So overwrite value from builder.
     mSessionId = SessionId::None;
 }
@@ -265,7 +265,7 @@ void AudioStreamOpenSLES::logUnsupportedAttributes() {
     // only report if changed from the default
 
     // Device ID
-    if (mDeviceId != kUnspecified) {
+    if (!mDeviceIds.empty()) {
         LOGW("Device ID [AudioStreamBuilder::setDeviceId()] "
              "is not supported on OpenSLES streams.");
     }
diff --git a/src/opensles/OpenSLESUtilities.cpp b/src/opensles/OpenSLESUtilities.cpp
index 534f641c..e81445d2 100644
--- a/src/opensles/OpenSLESUtilities.cpp
+++ b/src/opensles/OpenSLESUtilities.cpp
@@ -88,6 +88,13 @@ SLuint32 OpenSLES_ConvertFormatToRepresentation(AudioFormat format) {
         case AudioFormat::IEC61937:
         case AudioFormat::Invalid:
         case AudioFormat::Unspecified:
+        case AudioFormat::MP3:
+        case AudioFormat::AAC_LC:
+        case AudioFormat::AAC_HE_V1:
+        case AudioFormat::AAC_HE_V2:
+        case AudioFormat::AAC_ELD:
+        case AudioFormat::AAC_XHE:
+        case AudioFormat::OPUS:
         default:
             return 0;
     }
```

