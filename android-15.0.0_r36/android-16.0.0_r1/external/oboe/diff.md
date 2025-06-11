```diff
diff --git a/.github/dependabot.yml b/.github/dependabot.yml
new file mode 100644
index 00000000..709bcf56
--- /dev/null
+++ b/.github/dependabot.yml
@@ -0,0 +1,36 @@
+# To get started with Dependabot version updates, you'll need to specify which
+# package ecosystems to update and where the package manifests are located.
+# Please see the documentation for all configuration options:
+# https://docs.github.com/github/administering-a-repository/configuration-options-for-dependency-updates
+version: 2
+
+#Workaround for https://github.com/dependabot/dependabot-core/issues/6888#issuecomment-1539501116
+registries:
+  maven-google:
+    type: maven-repository
+    url: "https://dl.google.com/dl/android/maven2/"
+
+updates:
+  #Check for updates to Github Actions
+  - package-ecosystem: "github-actions"
+    directory: "/"               #Location of package manifests
+    target-branch: "main"
+    open-pull-requests-limit: 5
+    labels:
+      - "dependencies"
+      - "dependencies/github-actions"
+    schedule:
+      interval: "daily"
+
+  #Check updates for Gradle dependencies
+  - package-ecosystem: "gradle"
+    registries:
+      - maven-google
+    directory: "/"               #Location of package manifests
+    target-branch: "main"
+    open-pull-requests-limit: 10
+    labels:
+      - "dependencies"
+      - "dependencies/gradle"
+    schedule:
+      interval: "daily"
diff --git a/.github/workflows/build-ci.yml b/.github/workflows/build-ci.yml
index 42d40a2f..f10c4624 100644
--- a/.github/workflows/build-ci.yml
+++ b/.github/workflows/build-ci.yml
@@ -6,19 +6,23 @@ on:
   pull_request:
     branches: [ main ]
 
+permissions:
+  contents: write
+  security-events: write
+
 jobs:
   build:
     runs-on: ubuntu-latest
 
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
     - name: set up JDK 17
-      uses: actions/setup-java@v3
+      uses: actions/setup-java@v4
       with:
         distribution: 'temurin'
-        java-version: 17
+        java-version: 18
     - name: build samples and apps
-      uses: github/codeql-action/init@v2
+      uses: github/codeql-action/init@v3
       with:
         languages: cpp
     - run: |
@@ -35,4 +39,4 @@ jobs:
         ./gradlew -q clean bundleDebug
         popd
     - name: Perform CodeQL Analysis
-      uses: github/codeql-action/analyze@v2
+      uses: github/codeql-action/analyze@v3
diff --git a/.github/workflows/update-docs.yml b/.github/workflows/update-docs.yml
index a563e7f0..b47ed942 100644
--- a/.github/workflows/update-docs.yml
+++ b/.github/workflows/update-docs.yml
@@ -4,21 +4,24 @@ on:
   push:
     branches: [ main ]
 
+permissions:
+  contents: write
+
 jobs:
   build:
     runs-on: ubuntu-latest
 
     steps:
-    - uses: actions/checkout@v3
+    - uses: actions/checkout@v4
 
     - name: Doxygen Action
-      uses: mattnotmitt/doxygen-action@v1.1.0
+      uses: mattnotmitt/doxygen-action@v1.12.0
       with:
         doxyfile-path: "./Doxyfile"
         working-directory: "."
 
     - name: Deploy
-      uses: peaceiris/actions-gh-pages@v3
+      uses: peaceiris/actions-gh-pages@v4
       with:
         github_token: ${{ secrets.GITHUB_TOKEN }}
         publish_dir: ./docs/reference
diff --git a/CMakeLists.txt b/CMakeLists.txt
index ac798aac..55e3984d 100644
--- a/CMakeLists.txt
+++ b/CMakeLists.txt
@@ -95,7 +95,11 @@ target_compile_options(oboe
 # Enable logging of D,V for debug builds
 target_compile_definitions(oboe PUBLIC $<$<CONFIG:DEBUG>:OBOE_ENABLE_LOGGING=1>)
 
+option(OBOE_DO_NOT_DEFINE_OPENSL_ES_CONSTANTS "Do not define OpenSLES constants" OFF)
+target_compile_definitions(oboe PRIVATE $<$<BOOL:${OBOE_DO_NOT_DEFINE_OPENSL_ES_CONSTANTS}>:DO_NOT_DEFINE_OPENSL_ES_CONSTANTS=1>)
+
 target_link_libraries(oboe PRIVATE log OpenSLES)
+target_link_options(oboe PRIVATE "-Wl,-z,max-page-size=16384")
 
 # When installing oboe put the libraries in the lib/<ABI> folder e.g. lib/arm64-v8a
 install(TARGETS oboe
diff --git a/OWNERS b/OWNERS
index f4d51f91..e2a8324f 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1 +1,2 @@
 philburk@google.com
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/apps/OboeTester/app/CMakeLists.txt b/apps/OboeTester/app/CMakeLists.txt
index 8361d882..a47e6abf 100644
--- a/apps/OboeTester/app/CMakeLists.txt
+++ b/apps/OboeTester/app/CMakeLists.txt
@@ -6,7 +6,7 @@ set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} -O3")
 
 link_directories(${CMAKE_CURRENT_LIST_DIR}/..)
 
-# Increment this number when adding files to OboeTester => 104
+# Increment this number when adding files to OboeTester => 105
 # The change in this file will help Android Studio resync
 # and generate new build files that reference the new code.
 file(GLOB_RECURSE app_native_sources src/main/cpp/*)
@@ -33,4 +33,4 @@ include_directories(
 
 # link to oboe
 target_link_libraries(oboetester log oboe atomic)
-
+target_link_options(oboetester PRIVATE "-Wl,-z,max-page-size=16384")
diff --git a/apps/OboeTester/app/build.gradle b/apps/OboeTester/app/build.gradle
index 702d290b..00ca8224 100644
--- a/apps/OboeTester/app/build.gradle
+++ b/apps/OboeTester/app/build.gradle
@@ -6,8 +6,8 @@ android {
         applicationId = "com.mobileer.oboetester"
         minSdkVersion 23
         targetSdkVersion 34
-        versionCode 83
-        versionName "2.5.12"
+        versionCode 94
+        versionName "2.7.5"
         testInstrumentationRunner "android.support.test.runner.AndroidJUnitRunner"
         externalNativeBuild {
             cmake {
@@ -30,12 +30,14 @@ android {
             path "CMakeLists.txt"
         }
     }
+    namespace 'com.mobileer.oboetester'
 }
 
 dependencies {
     implementation fileTree(include: ['*.jar'], dir: 'libs')
     implementation "androidx.core:core-ktx:1.9.0"
     implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
+    implementation 'androidx.appcompat:appcompat:1.6.1'
 
     androidTestImplementation 'androidx.test.ext:junit:1.1.5'
     androidTestImplementation 'androidx.test.espresso:espresso-core:3.5.1'
diff --git a/apps/OboeTester/app/src/main/AndroidManifest.xml b/apps/OboeTester/app/src/main/AndroidManifest.xml
index fdfd8d95..1bd168ba 100644
--- a/apps/OboeTester/app/src/main/AndroidManifest.xml
+++ b/apps/OboeTester/app/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.mobileer.oboetester">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
     <uses-feature
         android:name="android.hardware.microphone"
         android:required="false" />
@@ -21,10 +20,11 @@
     <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
     <uses-permission android:name="android.permission.INTERNET" />
     <uses-permission android:name="android.permission.READ_PHONE_STATE" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE" />
 
     <application
-        android:allowBackup="false"
-        android:fullBackupContent="false"
         android:icon="@mipmap/ic_launcher"
         android:label="@string/app_name"
         android:supportsRtl="true"
@@ -33,7 +33,6 @@
         android:banner="@mipmap/ic_launcher">
         <activity
             android:name=".MainActivity"
-            android:label="@string/app_name"
             android:launchMode="singleTask"
             android:screenOrientation="portrait"
             android:exported="true">
@@ -91,34 +90,44 @@
         <activity
             android:name=".ExtraTestsActivity"
             android:exported="true"
-            android:label="@string/title_extra_tests" />
+            android:label="@string/title_extra_tests"
+            android:screenOrientation="portrait" />
 
         <activity
             android:name=".ExternalTapToToneActivity"
             android:label="@string/title_external_tap"
-            android:exported="true" />
+            android:exported="true"
+            android:screenOrientation="portrait" />
         <activity
             android:name=".TestPlugLatencyActivity"
             android:label="@string/title_plug_latency"
-            android:exported="true" />
+            android:exported="true"
+            android:screenOrientation="portrait" />
         <activity
             android:name=".TestErrorCallbackActivity"
             android:label="@string/title_error_callback"
-            android:exported="true" />
+            android:exported="true"
+            android:screenOrientation="portrait" />
         <activity
             android:name=".TestRouteDuringCallbackActivity"
             android:label="@string/title_route_during_callback"
-            android:exported="true" />
-
+            android:exported="true"
+            android:screenOrientation="portrait" />
         <activity
             android:name=".DynamicWorkloadActivity"
             android:label="@string/title_dynamic_load"
-            android:exported="true" />
-
+            android:exported="true"
+            android:screenOrientation="portrait" />
         <activity
             android:name=".TestColdStartLatencyActivity"
             android:label="@string/title_cold_start_latency"
-            android:exported="true" />
+            android:exported="true"
+            android:screenOrientation="portrait" />
+        <activity
+            android:name=".TestRapidCycleActivity"
+            android:label="@string/title_rapid_cycle"
+            android:exported="true"
+            android:screenOrientation="portrait" />
 
         <service
             android:name=".MidiTapTester"
@@ -133,6 +142,12 @@
                 android:resource="@xml/service_device_info" />
         </service>
 
+        <service
+            android:name=".AudioForegroundService"
+            android:foregroundServiceType="mediaPlayback|microphone"
+            android:exported="false">
+        </service>
+
         <provider
             android:name="androidx.core.content.FileProvider"
             android:authorities="${applicationId}.provider"
diff --git a/apps/OboeTester/app/src/main/cpp/FormatConverterBox.cpp b/apps/OboeTester/app/src/main/cpp/FormatConverterBox.cpp
index 0974b4c4..f380d0a0 100644
--- a/apps/OboeTester/app/src/main/cpp/FormatConverterBox.cpp
+++ b/apps/OboeTester/app/src/main/cpp/FormatConverterBox.cpp
@@ -43,6 +43,14 @@ FormatConverterBox::FormatConverterBox(int32_t maxSamples,
         case oboe::AudioFormat::Unspecified:
             mSource = std::make_unique<oboe::flowgraph::SourceFloat>(1);
             break;
+        case oboe::AudioFormat::MP3:
+        case oboe::AudioFormat::AAC_LC:
+        case oboe::AudioFormat::AAC_HE_V1:
+        case oboe::AudioFormat::AAC_HE_V2:
+        case oboe::AudioFormat::AAC_ELD:
+        case oboe::AudioFormat::AAC_XHE:
+        case oboe::AudioFormat::OPUS:
+            break;
     }
 
     mSink.reset();
@@ -62,6 +70,14 @@ FormatConverterBox::FormatConverterBox(int32_t maxSamples,
         case oboe::AudioFormat::Unspecified:
             mSink = std::make_unique<oboe::flowgraph::SinkFloat>(1);
             break;
+        case oboe::AudioFormat::MP3:
+        case oboe::AudioFormat::AAC_LC:
+        case oboe::AudioFormat::AAC_HE_V1:
+        case oboe::AudioFormat::AAC_HE_V2:
+        case oboe::AudioFormat::AAC_ELD:
+        case oboe::AudioFormat::AAC_XHE:
+        case oboe::AudioFormat::OPUS:
+            break;
     }
 
     if (mSource && mSink) {
diff --git a/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.cpp b/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.cpp
index 243c647c..fe872d72 100644
--- a/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.cpp
+++ b/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.cpp
@@ -45,10 +45,13 @@ oboe::DataCallbackResult FullDuplexAnalyzer::onBothStreamsReadyFloat(
     (void) getLoopbackProcessor()->process(inputFloat, inputStride, numInputFrames,
                                    outputFloat, outputStride, numOutputFrames);
 
-    // write the first channel of output and input to the stereo recorder
+    // Save data for later analysis or for writing to a WAVE file.
     if (mRecording != nullptr) {
         float buffer[2];
         int numBoth = std::min(numInputFrames, numOutputFrames);
+        // Offset to the selected channels that we are analyzing.
+        inputFloat += getLoopbackProcessor()->getInputChannel();
+        outputFloat += getLoopbackProcessor()->getOutputChannel();
         for (int i = 0; i < numBoth; i++) {
             buffer[0] = *outputFloat;
             outputFloat += outputStride;
@@ -57,13 +60,14 @@ oboe::DataCallbackResult FullDuplexAnalyzer::onBothStreamsReadyFloat(
             mRecording->write(buffer, 1);
         }
         // Handle mismatch in numFrames.
-        buffer[0] = 0.0f; // gap in output
+        const float gapMarker = -0.9f; // Recognizable value so we can tell underruns from DSP gaps.
+        buffer[0] = gapMarker; // gap in output
         for (int i = numBoth; i < numInputFrames; i++) {
             buffer[1] = *inputFloat;
             inputFloat += inputStride;
             mRecording->write(buffer, 1);
         }
-        buffer[1] = 0.0f; // gap in input
+        buffer[1] = gapMarker; // gap in input
         for (int i = numBoth; i < numOutputFrames; i++) {
             buffer[0] = *outputFloat;
             outputFloat += outputStride;
diff --git a/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.h b/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.h
index 4163aa82..82b1abed 100644
--- a/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.h
+++ b/apps/OboeTester/app/src/main/cpp/FullDuplexAnalyzer.h
@@ -29,7 +29,6 @@ class FullDuplexAnalyzer : public FullDuplexStreamWithConversion {
 public:
     FullDuplexAnalyzer(LoopbackProcessor *processor)
             : mLoopbackProcessor(processor) {
-        setNumInputBurstsCushion(1);
     }
 
     /**
diff --git a/apps/OboeTester/app/src/main/cpp/FullDuplexStreamWithConversion.cpp b/apps/OboeTester/app/src/main/cpp/FullDuplexStreamWithConversion.cpp
index a64b8d96..a6184c3c 100644
--- a/apps/OboeTester/app/src/main/cpp/FullDuplexStreamWithConversion.cpp
+++ b/apps/OboeTester/app/src/main/cpp/FullDuplexStreamWithConversion.cpp
@@ -19,12 +19,13 @@
 
 oboe::Result FullDuplexStreamWithConversion::start() {
     // Determine maximum size that could possibly be called.
-    int32_t bufferSize = getOutputStream()->getBufferCapacityInFrames()
-                         * getOutputStream()->getChannelCount();
-    mInputConverter = std::make_unique<FormatConverterBox>(bufferSize,
+    int32_t maxFrames = getOutputStream()->getBufferCapacityInFrames();
+    int32_t inputBufferSize = maxFrames * getInputStream()->getChannelCount();
+    int32_t outputBufferSize = maxFrames * getOutputStream()->getChannelCount();
+    mInputConverter = std::make_unique<FormatConverterBox>(inputBufferSize,
                                                            getInputStream()->getFormat(),
                                                            oboe::AudioFormat::Float);
-    mOutputConverter = std::make_unique<FormatConverterBox>(bufferSize,
+    mOutputConverter = std::make_unique<FormatConverterBox>(outputBufferSize,
                                                             oboe::AudioFormat::Float,
                                                             getOutputStream()->getFormat());
     return FullDuplexStream::start();
diff --git a/apps/OboeTester/app/src/main/cpp/MultiChannelRecording.h b/apps/OboeTester/app/src/main/cpp/MultiChannelRecording.h
index eed37435..595e2c3a 100644
--- a/apps/OboeTester/app/src/main/cpp/MultiChannelRecording.h
+++ b/apps/OboeTester/app/src/main/cpp/MultiChannelRecording.h
@@ -17,6 +17,7 @@
 #ifndef NATIVEOBOE_MULTICHANNEL_RECORDING_H
 #define NATIVEOBOE_MULTICHANNEL_RECORDING_H
 
+#include <algorithm>
 #include <memory.h>
 #include <unistd.h>
 #include <sys/types.h>
diff --git a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
index 2aa6eeb9..d0ac6ddd 100644
--- a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
+++ b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.cpp
@@ -28,7 +28,7 @@
 #include <vector>
 #include <common/AudioClock.h>
 
-#include <common/AudioClock.h>
+#include "oboe/AudioClock.h"
 #include "util/WaveFileWriter.h"
 
 #include "NativeAudioContext.h"
@@ -170,7 +170,8 @@ int ActivityContext::open(jint nativeApi,
                           jboolean formatConversionAllowed,
                           jint rateConversionQuality,
                           jboolean isMMap,
-                          jboolean isInput) {
+                          jboolean isInput,
+                          jint spatializationBehavior) {
 
     oboe::AudioApi audioApi = oboe::AudioApi::Unspecified;
     switch (nativeApi) {
@@ -211,6 +212,7 @@ int ActivityContext::open(jint nativeApi,
             ->setChannelConversionAllowed(channelConversionAllowed)
             ->setFormatConversionAllowed(formatConversionAllowed)
             ->setSampleRateConversionQuality((oboe::SampleRateConversionQuality) rateConversionQuality)
+            ->setSpatializationBehavior((oboe::SpatializationBehavior) spatializationBehavior)
             ;
     if (channelMask != (jint) oboe::ChannelMask::Unspecified) {
         // Set channel mask when it is specified.
@@ -249,7 +251,7 @@ int ActivityContext::open(jint nativeApi,
 
         createRecording();
 
-        finishOpen(isInput, oboeStream.get());
+        finishOpen(isInput, oboeStream);
     }
 
     if (!mUseCallback) {
@@ -320,10 +322,11 @@ int32_t  ActivityContext::saveWaveFile(const char *filename) {
     }
     MyOboeOutputStream outStream;
     WaveFileWriter writer(&outStream);
-
+    // You must setup the format before the first write().
     writer.setFrameRate(mSampleRate);
     writer.setSamplesPerFrame(mRecording->getChannelCount());
     writer.setBitsPerSample(24);
+    writer.setFrameCount(mRecording->getSizeInFrames());
     float buffer[mRecording->getChannelCount()];
     // Read samples from start to finish.
     mRecording->rewind();
@@ -427,15 +430,17 @@ void ActivityTestOutput::configureAfterOpen() {
     mTriangleOscillator.output.connect(&(mExponentialShape.input));
     {
         double frequency = 330.0;
+        // Go up by a minor third or a perfect fourth just intoned interval.
+        const float interval = (mChannelCount > 8) ? (6.0f / 5.0f) : (4.0f / 3.0f);
         for (int i = 0; i < mChannelCount; i++) {
             sineOscillators[i].setSampleRate(outputStream->getSampleRate());
             sineOscillators[i].frequency.setValue(frequency);
-            sineOscillators[i].amplitude.setValue(AMPLITUDE_SINE);
+            sineOscillators[i].amplitude.setValue(AMPLITUDE_SINE / mChannelCount);
             sawtoothOscillators[i].setSampleRate(outputStream->getSampleRate());
             sawtoothOscillators[i].frequency.setValue(frequency);
-            sawtoothOscillators[i].amplitude.setValue(AMPLITUDE_SAWTOOTH);
+            sawtoothOscillators[i].amplitude.setValue(AMPLITUDE_SAWTOOTH / mChannelCount);
 
-            frequency *= 4.0 / 3.0; // each wave is at a higher frequency
+            frequency *= interval; // each wave is at a higher frequency
             setChannelEnabled(i, true);
         }
     }
@@ -653,11 +658,11 @@ void ActivityEcho::configureBuilder(bool isInput, oboe::AudioStreamBuilder &buil
     }
 }
 
-void ActivityEcho::finishOpen(bool isInput, oboe::AudioStream *oboeStream) {
+void ActivityEcho::finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) {
     if (isInput) {
-        mFullDuplexEcho->setInputStream(oboeStream);
+        mFullDuplexEcho->setSharedInputStream(oboeStream);
     } else {
-        mFullDuplexEcho->setOutputStream(oboeStream);
+        mFullDuplexEcho->setSharedOutputStream(oboeStream);
     }
 }
 
@@ -675,12 +680,13 @@ void ActivityRoundTripLatency::configureBuilder(bool isInput, oboe::AudioStreamB
     }
 }
 
-void ActivityRoundTripLatency::finishOpen(bool isInput, AudioStream *oboeStream) {
+void ActivityRoundTripLatency::finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream>
+        &oboeStream) {
     if (isInput) {
-        mFullDuplexLatency->setInputStream(oboeStream);
+        mFullDuplexLatency->setSharedInputStream(oboeStream);
         mFullDuplexLatency->setRecording(mRecording.get());
     } else {
-        mFullDuplexLatency->setOutputStream(oboeStream);
+        mFullDuplexLatency->setSharedOutputStream(oboeStream);
     }
 }
 
@@ -730,12 +736,12 @@ void ActivityGlitches::configureBuilder(bool isInput, oboe::AudioStreamBuilder &
     }
 }
 
-void ActivityGlitches::finishOpen(bool isInput, oboe::AudioStream *oboeStream) {
+void ActivityGlitches::finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) {
     if (isInput) {
-        mFullDuplexGlitches->setInputStream(oboeStream);
+        mFullDuplexGlitches->setSharedInputStream(oboeStream);
         mFullDuplexGlitches->setRecording(mRecording.get());
     } else {
-        mFullDuplexGlitches->setOutputStream(oboeStream);
+        mFullDuplexGlitches->setSharedOutputStream(oboeStream);
     }
 }
 
@@ -753,12 +759,12 @@ void ActivityDataPath::configureBuilder(bool isInput, oboe::AudioStreamBuilder &
     }
 }
 
-void ActivityDataPath::finishOpen(bool isInput, oboe::AudioStream *oboeStream) {
+void ActivityDataPath::finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) {
     if (isInput) {
-        mFullDuplexDataPath->setInputStream(oboeStream);
+        mFullDuplexDataPath->setSharedInputStream(oboeStream);
         mFullDuplexDataPath->setRecording(mRecording.get());
     } else {
-        mFullDuplexDataPath->setOutputStream(oboeStream);
+        mFullDuplexDataPath->setSharedOutputStream(oboeStream);
     }
 }
 
diff --git a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
index 94ae680d..9ec67552 100644
--- a/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
+++ b/apps/OboeTester/app/src/main/cpp/NativeAudioContext.h
@@ -109,6 +109,7 @@ public:
      * @param rateConversionQuality
      * @param isMMap
      * @param isInput
+     * @param spatializationBehavior
      * @return stream ID
      */
     int open(jint nativeApi,
@@ -128,7 +129,8 @@ public:
              jboolean formatConversionAllowed,
              jint rateConversionQuality,
              jboolean isMMap,
-             jboolean isInput);
+             jboolean isInput,
+             jint spatializationBehavior);
 
     oboe::Result release();
 
@@ -300,6 +302,10 @@ public:
         oboeCallbackProxy.setCpuAffinityMask(mask);
     }
 
+    void setWorkloadReportingEnabled(bool enabled) {
+        oboeCallbackProxy.setWorkloadReportingEnabled(enabled);
+    }
+
 protected:
     std::shared_ptr<oboe::AudioStream> getInputStream();
     std::shared_ptr<oboe::AudioStream> getOutputStream();
@@ -311,7 +317,7 @@ protected:
                                                              SECONDS_TO_RECORD * mSampleRate);
     }
 
-    virtual void finishOpen(bool isInput, oboe::AudioStream *oboeStream) {}
+    virtual void finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) {}
 
     virtual oboe::Result startStreams() = 0;
 
@@ -544,7 +550,7 @@ public:
     }
 
 protected:
-    void finishOpen(bool isInput, oboe::AudioStream *oboeStream) override;
+    void finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) override;
 
 private:
     std::unique_ptr<FullDuplexEcho>   mFullDuplexEcho{};
@@ -616,7 +622,7 @@ public:
     jdouble measureTimestampLatency();
 
 protected:
-    void finishOpen(bool isInput, oboe::AudioStream *oboeStream) override;
+    void finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) override;
 
 private:
     std::unique_ptr<FullDuplexAnalyzer>   mFullDuplexLatency{};
@@ -658,7 +664,7 @@ public:
     }
 
 protected:
-    void finishOpen(bool isInput, oboe::AudioStream *oboeStream) override;
+    void finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) override;
 
 private:
     std::unique_ptr<FullDuplexAnalyzer>   mFullDuplexGlitches{};
@@ -700,7 +706,7 @@ public:
     }
 
 protected:
-    void finishOpen(bool isInput, oboe::AudioStream *oboeStream) override;
+    void finishOpen(bool isInput, std::shared_ptr<oboe::AudioStream> &oboeStream) override;
 
 private:
     std::unique_ptr<FullDuplexAnalyzer>   mFullDuplexDataPath{};
diff --git a/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.cpp b/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.cpp
index 20a20e05..4f95e9da 100644
--- a/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.cpp
+++ b/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.cpp
@@ -25,10 +25,16 @@ oboe::DataCallbackResult OboeStreamCallbackProxy::onAudioReady(
         int numFrames) {
     oboe::DataCallbackResult callbackResult = oboe::DataCallbackResult::Stop;
     int64_t startTimeNanos = getNanoseconds();
+    int32_t numWorkloadVoices = mNumWorkloadVoices;
 
     // Record which CPU this is running on.
     orCurrentCpuMask(sched_getcpu());
 
+    // Tell ADPF in advance what our workload will be.
+    if (mWorkloadReportingEnabled) {
+        audioStream->reportWorkload(numWorkloadVoices);
+    }
+
     // Change affinity if app requested a change.
     uint32_t mask = mCpuAffinityMask;
     if (mask != mPreviousMask) {
@@ -49,8 +55,8 @@ oboe::DataCallbackResult OboeStreamCallbackProxy::onAudioReady(
         callbackResult = mCallback->onAudioReady(audioStream, audioData, numFrames);
     }
 
-    mSynthWorkload.onCallback(mNumWorkloadVoices);
-    if (mNumWorkloadVoices > 0) {
+    mSynthWorkload.onCallback(numWorkloadVoices);
+    if (numWorkloadVoices > 0) {
         // Render into the buffer or discard the synth voices.
         float *buffer = (audioStream->getChannelCount() == 2 && mHearWorkload)
                         ? static_cast<float *>(audioData) : nullptr;
diff --git a/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.h b/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.h
index 157c0817..b8b8d5af 100644
--- a/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.h
+++ b/apps/OboeTester/app/src/main/cpp/OboeStreamCallbackProxy.h
@@ -241,15 +241,20 @@ public:
         mCpuAffinityMask = mask;
     }
 
+    void setWorkloadReportingEnabled(bool enabled) {
+        mWorkloadReportingEnabled = enabled;
+    }
+
 private:
     static constexpr double    kNsToMsScaler = 0.000001;
     std::atomic<float>         mCpuLoad{0.0f};
     std::atomic<float>         mMaxCpuLoad{0.0f};
     int64_t                    mPreviousCallbackTimeNs = 0;
     DoubleStatistics           mStatistics;
-    int32_t                    mNumWorkloadVoices = 0;
+    std::atomic<int32_t>       mNumWorkloadVoices{0};
     SynthWorkload              mSynthWorkload;
     bool                       mHearWorkload = false;
+    bool                       mWorkloadReportingEnabled = false;
 
     oboe::AudioStreamDataCallback *mCallback = nullptr;
     static bool                mCallbackReturnStop;
diff --git a/apps/OboeTester/app/src/main/cpp/TestColdStartLatency.cpp b/apps/OboeTester/app/src/main/cpp/TestColdStartLatency.cpp
index 7de1c7ab..9b4f25ca 100644
--- a/apps/OboeTester/app/src/main/cpp/TestColdStartLatency.cpp
+++ b/apps/OboeTester/app/src/main/cpp/TestColdStartLatency.cpp
@@ -18,7 +18,7 @@
 #include <aaudio/AAudioExtensions.h>
 
 #include "common/OboeDebug.h"
-#include "common/AudioClock.h"
+#include "oboe/AudioClock.h"
 #include "TestColdStartLatency.h"
 #include "OboeTools.h"
 
diff --git a/apps/OboeTester/app/src/main/cpp/TestErrorCallback.h b/apps/OboeTester/app/src/main/cpp/TestErrorCallback.h
index a7611fe4..d7ce8980 100644
--- a/apps/OboeTester/app/src/main/cpp/TestErrorCallback.h
+++ b/apps/OboeTester/app/src/main/cpp/TestErrorCallback.h
@@ -17,6 +17,7 @@
 #ifndef OBOETESTER_TEST_ERROR_CALLBACK_H
 #define OBOETESTER_TEST_ERROR_CALLBACK_H
 
+#include "common/OboeDebug.h"
 #include "oboe/Oboe.h"
 #include <thread>
 
diff --git a/apps/OboeTester/app/src/main/cpp/TestRapidCycle.cpp b/apps/OboeTester/app/src/main/cpp/TestRapidCycle.cpp
new file mode 100644
index 00000000..4e6a9cb0
--- /dev/null
+++ b/apps/OboeTester/app/src/main/cpp/TestRapidCycle.cpp
@@ -0,0 +1,97 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#include <stdlib.h>
+#include <aaudio/AAudioExtensions.h>
+
+#include "common/OboeDebug.h"
+#include "oboe/AudioClock.h"
+#include "TestRapidCycle.h"
+
+using namespace oboe;
+
+// start a thread to cycle through stream tests
+int32_t TestRapidCycle::start(bool useOpenSL) {
+    mThreadEnabled = true;
+    mCycleCount = 0;
+    mCycleThread = std::thread([this, useOpenSL]() {
+        cycleRapidly(useOpenSL);
+    });
+    return 0;
+}
+int32_t TestRapidCycle::stop() {
+    mThreadEnabled = false;
+    mCycleThread.join();
+    return 0;
+}
+
+void TestRapidCycle::cycleRapidly(bool useOpenSL) {
+    while(mThreadEnabled && (oneCycle(useOpenSL) == 0));
+}
+
+int32_t TestRapidCycle::oneCycle(bool useOpenSL) {
+    mCycleCount++;
+    mDataCallback = std::make_shared<MyDataCallback>();
+
+    AudioStreamBuilder builder;
+    oboe::Result result = builder.setFormat(oboe::AudioFormat::Float)
+            ->setAudioApi(useOpenSL ? oboe::AudioApi::OpenSLES : oboe::AudioApi::AAudio)
+            ->setPerformanceMode(oboe::PerformanceMode::LowLatency)
+            ->setChannelCount(kChannelCount)
+            ->setDataCallback(mDataCallback)
+            ->setUsage(oboe::Usage::Notification)
+            ->openStream(mStream);
+    if (result != oboe::Result::OK) {
+        return (int32_t) result;
+    }
+
+    mStream->setDelayBeforeCloseMillis(0);
+
+    result = mStream->requestStart();
+    if (result != oboe::Result::OK) {
+        mStream->close();
+        return (int32_t) result;
+    }
+// Sleep for some random time.
+    int32_t durationMicros = (int32_t)(drand48() * kMaxSleepMicros);
+    LOGD("TestRapidCycle::oneCycle() - Sleep for %d micros", durationMicros);
+    usleep(durationMicros);
+    LOGD("TestRapidCycle::oneCycle() - Woke up, close stream");
+    mDataCallback->returnStop = true;
+    result = mStream->close();
+    return (int32_t) result;
+}
+
+// Callback that sleeps then touches the audio buffer.
+DataCallbackResult TestRapidCycle::MyDataCallback::onAudioReady(
+        AudioStream *audioStream,
+        void *audioData,
+        int32_t numFrames) {
+    float *floatData = (float *) audioData;
+    const int numSamples = numFrames * kChannelCount;
+
+    // Fill buffer with white noise.
+    for (int i = 0; i < numSamples; i++) {
+        floatData[i] = ((float) drand48() - 0.5f) * 2 * 0.1f;
+    }
+    usleep(500); // half a millisecond
+    if (returnStop) {
+        usleep(20 * 1000);
+        return DataCallbackResult::Stop;
+    } else {
+        return DataCallbackResult::Continue;
+    }
+}
diff --git a/apps/OboeTester/app/src/main/cpp/TestRapidCycle.h b/apps/OboeTester/app/src/main/cpp/TestRapidCycle.h
new file mode 100644
index 00000000..772933df
--- /dev/null
+++ b/apps/OboeTester/app/src/main/cpp/TestRapidCycle.h
@@ -0,0 +1,67 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+#ifndef OBOETESTER_TEST_RAPID_CYCLE_H
+#define OBOETESTER_TEST_RAPID_CYCLE_H
+
+#include "oboe/Oboe.h"
+#include <thread>
+
+
+/**
+ * Try to cause a crash by changing routing during a data callback.
+ * We use Use::VoiceCommunication for the stream and
+ * setSpeakerPhoneOn(b) to force a routing change.
+ * This works best when connected to a BT headset.
+ */
+class TestRapidCycle {
+public:
+
+    int32_t start(bool useOpenSL);
+    int32_t stop();
+
+    int32_t getCycleCount() {
+        return mCycleCount.load();
+    }
+
+private:
+
+    void cycleRapidly(bool useOpenSL);
+    int32_t oneCycle(bool useOpenSL);
+
+    class MyDataCallback : public oboe::AudioStreamDataCallback {    public:
+
+        MyDataCallback() {}
+
+        oboe::DataCallbackResult onAudioReady(
+                oboe::AudioStream *audioStream,
+                void *audioData,
+                int32_t numFrames) override;
+
+        bool returnStop = false;
+    };
+
+    std::shared_ptr<oboe::AudioStream> mStream;
+    std::shared_ptr<MyDataCallback> mDataCallback;
+    std::atomic<int32_t> mCycleCount{0};
+    std::atomic<bool> mThreadEnabled{false};
+    std::thread mCycleThread;
+
+    static constexpr int kChannelCount = 1;
+    static constexpr int kMaxSleepMicros = 25000;
+};
+
+#endif //OBOETESTER_TEST_RAPID_CYCLE_H
diff --git a/apps/OboeTester/app/src/main/cpp/TestRoutingCrash.cpp b/apps/OboeTester/app/src/main/cpp/TestRoutingCrash.cpp
index 633e1186..0a0c30ba 100644
--- a/apps/OboeTester/app/src/main/cpp/TestRoutingCrash.cpp
+++ b/apps/OboeTester/app/src/main/cpp/TestRoutingCrash.cpp
@@ -18,7 +18,7 @@
 #include <aaudio/AAudioExtensions.h>
 
 #include "common/OboeDebug.h"
-#include "common/AudioClock.h"
+#include "oboe/AudioClock.h"
 #include "TestRoutingCrash.h"
 
 using namespace oboe;
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/BaseSineAnalyzer.h b/apps/OboeTester/app/src/main/cpp/analyzer/BaseSineAnalyzer.h
index b9ae220f..1ecece52 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/BaseSineAnalyzer.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/BaseSineAnalyzer.h
@@ -58,22 +58,6 @@ public:
         return mMagnitude;
     }
 
-    void setInputChannel(int inputChannel) {
-        mInputChannel = inputChannel;
-    }
-
-    int getInputChannel() const {
-        return mInputChannel;
-    }
-
-    void setOutputChannel(int outputChannel) {
-        mOutputChannel = outputChannel;
-    }
-
-    int getOutputChannel() const {
-        return mOutputChannel;
-    }
-
     void setNoiseAmplitude(double noiseAmplitude) {
         mNoiseAmplitude = noiseAmplitude;
     }
@@ -90,6 +74,14 @@ public:
         mTolerance = tolerance;
     }
 
+    // advance and wrap phase
+    void incrementInputPhase() {
+        mInputPhase += mPhaseIncrement;
+        if (mInputPhase > M_PI) {
+            mInputPhase -= (2.0 * M_PI);
+        }
+    }
+
     // advance and wrap phase
     void incrementOutputPhase() {
         mOutputPhase += mPhaseIncrement;
@@ -98,6 +90,7 @@ public:
         }
     }
 
+
     /**
      * @param frameData upon return, contains the reference sine wave
      * @param channelCount
@@ -113,7 +106,7 @@ public:
             // ALOGD("sin(%f) = %f, %f\n", mOutputPhase, sinOut,  kPhaseIncrement);
         }
         for (int i = 0; i < channelCount; i++) {
-            frameData[i] = (i == mOutputChannel) ? output : 0.0f;
+            frameData[i] = (i == getOutputChannel()) ? output : 0.0f;
         }
         return RESULT_OK;
     }
@@ -158,11 +151,12 @@ public:
      * @param referencePhase
      * @return true if magnitude and phase updated
      */
-    bool transformSample(float sample, float referencePhase) {
-        // Track incoming signal and slowly adjust magnitude to account
-        // for drift in the DRC or AGC.
-        mSinAccumulator += static_cast<double>(sample) * sinf(referencePhase);
-        mCosAccumulator += static_cast<double>(sample) * cosf(referencePhase);
+    bool transformSample(float sample) {
+        // Compare incoming signal with the reference input sine wave.
+        mSinAccumulator += static_cast<double>(sample) * sinf(mInputPhase);
+        mCosAccumulator += static_cast<double>(sample) * cosf(mInputPhase);
+        incrementInputPhase();
+
         mFramesAccumulated++;
         // Must be a multiple of the period or the calculation will not be accurate.
         if (mFramesAccumulated == mSinePeriod) {
@@ -197,6 +191,7 @@ public:
     void prepareToTest() override {
         LoopbackProcessor::prepareToTest();
         mSinePeriod = getSampleRate() / kTargetGlitchFrequency;
+        mInputPhase = 0.0f;
         mOutputPhase = 0.0f;
         mInverseSinePeriod = 1.0 / mSinePeriod;
         mPhaseIncrement = 2.0 * M_PI * mInverseSinePeriod;
@@ -209,9 +204,13 @@ protected:
     int32_t mSinePeriod = 1; // this will be set before use
     double  mInverseSinePeriod = 1.0;
     double  mPhaseIncrement = 0.0;
+    // Use two sine wave phases, input and output.
+    // This is because the number of input and output samples may differ
+    // in a callback and the output frame count may advance ahead of the input, or visa versa.
+    double  mInputPhase = 0.0;
     double  mOutputPhase = 0.0;
     double  mOutputAmplitude = 0.75;
-    // This is the phase offset between the output sine wave and the recorded
+    // This is the phase offset between the mInputPhase sine wave and the recorded
     // signal at the tuned frequency.
     // If this jumps around then we are probably just hearing noise.
     // Noise can cause the magnitude to be high but mPhaseOffset will be pretty random.
@@ -232,8 +231,6 @@ protected:
     InfiniteRecording<float> mInfiniteRecording;
 
 private:
-    int32_t mInputChannel = 0;
-    int32_t mOutputChannel = 0;
     float   mTolerance = 0.10; // scaled from 0.0 to 1.0
 
     float mNoiseAmplitude = 0.00; // Used to experiment with warbling caused by DRC.
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/DataPathAnalyzer.h b/apps/OboeTester/app/src/main/cpp/analyzer/DataPathAnalyzer.h
index f13996b2..deabaa96 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/DataPathAnalyzer.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/DataPathAnalyzer.h
@@ -63,7 +63,7 @@ public:
         float sample = frameData[getInputChannel()];
         mInfiniteRecording.write(sample);
 
-        if (transformSample(sample, mOutputPhase)) {
+        if (transformSample(sample)) {
             // Analyze magnitude and phase on every period.
             if (mPhaseOffset != kPhaseInvalid) {
                 double diff = fabs(calculatePhaseError(mPhaseOffset, mPreviousPhaseOffset));
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/GlitchAnalyzer.h b/apps/OboeTester/app/src/main/cpp/analyzer/GlitchAnalyzer.h
index fff87902..42647440 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/GlitchAnalyzer.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/GlitchAnalyzer.h
@@ -229,7 +229,7 @@ public:
                     // Track incoming signal and slowly adjust magnitude to account
                     // for drift in the DRC or AGC.
                     // Must be a multiple of the period or the calculation will not be accurate.
-                    if (transformSample(sample, mInputPhase)) {
+                    if (transformSample(sample)) {
                         // Adjust phase to account for sample rate drift.
                         mInputPhase += mPhaseOffset;
 
@@ -249,7 +249,6 @@ public:
                         }
                     }
                 }
-                incrementInputPhase();
             } break;
 
             case STATE_GLITCHING: {
@@ -288,14 +287,6 @@ public:
 
     int maxMeasurableGlitchLength() const { return 2 * mSinePeriod; }
 
-    // advance and wrap phase
-    void incrementInputPhase() {
-        mInputPhase += mPhaseIncrement;
-        if (mInputPhase > M_PI) {
-            mInputPhase -= (2.0 * M_PI);
-        }
-    }
-
     bool isOutputEnabled() override { return mState != STATE_IDLE; }
 
     void onGlitchStart() {
@@ -399,7 +390,6 @@ private:
     sine_state_t  mState = STATE_IDLE;
     int64_t       mLastGlitchPosition;
 
-    double  mInputPhase = 0.0;
     double  mMaxGlitchDelta = 0.0;
     int32_t mGlitchCount = 0;
     int32_t mConsecutiveBadFrames = 0;
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/LatencyAnalyzer.h b/apps/OboeTester/app/src/main/cpp/analyzer/LatencyAnalyzer.h
index 19f6cb11..165ba140 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/LatencyAnalyzer.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/LatencyAnalyzer.h
@@ -56,7 +56,7 @@ static constexpr int32_t kMillisPerSecond   = 1000;  // by definition
 static constexpr int32_t kMaxLatencyMillis  = 1000;  // arbitrary and generous
 
 struct LatencyReport {
-    int32_t latencyInFrames = 0.0;
+    int32_t latencyInFrames = 0;
     double correlation = 0.0;
 
     void reset() {
@@ -428,10 +428,41 @@ public:
         reset();
     }
 
+    /**
+     * Some analyzers may only look at one channel.
+     * You can optionally specify that channel here.
+     *
+     * @param inputChannel
+     */
+    void setInputChannel(int inputChannel) {
+        mInputChannel = inputChannel;
+    }
+
+    int getInputChannel() const {
+        return mInputChannel;
+    }
+
+    /**
+     * Some analyzers may only generate one channel.
+     * You can optionally specify that channel here.
+     *
+     * @param outputChannel
+     */
+    void setOutputChannel(int outputChannel) {
+        mOutputChannel = outputChannel;
+    }
+
+    int getOutputChannel() const {
+        return mOutputChannel;
+    }
+
 protected:
     int32_t   mResetCount = 0;
 
 private:
+
+    int32_t mInputChannel = 0;
+    int32_t mOutputChannel = 0;
     int32_t mSampleRate = kDefaultSampleRate;
     int32_t mResult = 0;
 };
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/PseudoRandom.h b/apps/OboeTester/app/src/main/cpp/analyzer/PseudoRandom.h
index 1c4938cb..ce26ecc1 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/PseudoRandom.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/PseudoRandom.h
@@ -18,7 +18,7 @@
 #ifndef ANALYZER_PSEUDORANDOM_H
 #define ANALYZER_PSEUDORANDOM_H
 
-#include <cctype>
+#include <cstdint>
 
 class PseudoRandom {
 public:
diff --git a/apps/OboeTester/app/src/main/cpp/analyzer/RoundedManchesterEncoder.h b/apps/OboeTester/app/src/main/cpp/analyzer/RoundedManchesterEncoder.h
index f2eba840..51461526 100644
--- a/apps/OboeTester/app/src/main/cpp/analyzer/RoundedManchesterEncoder.h
+++ b/apps/OboeTester/app/src/main/cpp/analyzer/RoundedManchesterEncoder.h
@@ -18,7 +18,7 @@
 #define ANALYZER_ROUNDED_MANCHESTER_ENCODER_H
 
 #include <math.h>
-#include <memory.h>
+#include <memory>
 #include <stdlib.h>
 #include "ManchesterEncoder.h"
 
diff --git a/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp b/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
index 9cb9ffe6..e5240797 100644
--- a/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
+++ b/apps/OboeTester/app/src/main/cpp/jni-bridge.cpp
@@ -31,6 +31,7 @@
 #include "TestColdStartLatency.h"
 #include "TestErrorCallback.h"
 #include "TestRoutingCrash.h"
+#include "TestRapidCycle.h"
 
 static NativeAudioContext engine;
 
@@ -58,7 +59,8 @@ Java_com_mobileer_oboetester_OboeAudioStream_openNative(JNIEnv *env, jobject,
                                                        jboolean formatConversionAllowed,
                                                        jint rateConversionQuality,
                                                        jboolean isMMap,
-                                                       jboolean isInput);
+                                                       jboolean isInput,
+                                                       jint spatializationBehavior);
 JNIEXPORT void JNICALL
 Java_com_mobileer_oboetester_OboeAudioStream_close(JNIEnv *env, jobject, jint);
 
@@ -123,12 +125,19 @@ Java_com_mobileer_oboetester_NativeEngine_getCpuCount(JNIEnv *env, jclass type)
 }
 
 JNIEXPORT void JNICALL
-        Java_com_mobileer_oboetester_NativeEngine_setCpuAffinityMask(JNIEnv *env,
+Java_com_mobileer_oboetester_NativeEngine_setCpuAffinityMask(JNIEnv *env,
                                                                      jclass type,
                                                                      jint mask) {
     engine.getCurrentActivity()->setCpuAffinityMask(mask);
 }
 
+JNIEXPORT void JNICALL
+Java_com_mobileer_oboetester_NativeEngine_setWorkloadReportingEnabled(JNIEnv *env,
+                                                             jclass type,
+                                                             jboolean enabled) {
+    engine.getCurrentActivity()->setWorkloadReportingEnabled(enabled);
+}
+
 JNIEXPORT jint JNICALL
 Java_com_mobileer_oboetester_OboeAudioStream_openNative(
         JNIEnv *env, jobject synth,
@@ -149,7 +158,8 @@ Java_com_mobileer_oboetester_OboeAudioStream_openNative(
         jboolean formatConversionAllowed,
         jint rateConversionQuality,
         jboolean isMMap,
-        jboolean isInput) {
+        jboolean isInput,
+        jint spatializationBehavior) {
     LOGD("OboeAudioStream_openNative: sampleRate = %d", sampleRate);
 
     return (jint) engine.getCurrentActivity()->open(nativeApi,
@@ -169,7 +179,8 @@ Java_com_mobileer_oboetester_OboeAudioStream_openNative(
                                                     formatConversionAllowed,
                                                     rateConversionQuality,
                                                     isMMap,
-                                                    isInput);
+                                                    isInput,
+                                                    spatializationBehavior);
 }
 
 JNIEXPORT jint JNICALL
@@ -214,7 +225,7 @@ Java_com_mobileer_oboetester_OboeAudioStream_close(JNIEnv *env, jobject, jint st
 
 JNIEXPORT void JNICALL
 Java_com_mobileer_oboetester_TestAudioActivity_setUseAlternativeAdpf(JNIEnv *env, jobject, jboolean enabled) {
-    AdpfWrapper::setUseAlternative(enabled);
+    oboe::AdpfWrapper::setUseAlternative(enabled);
 }
 
 JNIEXPORT jint JNICALL
@@ -331,6 +342,17 @@ Java_com_mobileer_oboetester_OboeAudioStream_getInputPreset(
     return result;
 }
 
+JNIEXPORT jint JNICALL
+Java_com_mobileer_oboetester_OboeAudioStream_getSpatializationBehavior(
+        JNIEnv *env, jobject, jint streamIndex) {
+    jint result = (jint) oboe::Result::ErrorNull;
+    std::shared_ptr<oboe::AudioStream> oboeStream = engine.getCurrentActivity()->getStream(streamIndex);
+    if (oboeStream != nullptr) {
+        result = (jint) oboeStream->getSpatializationBehavior();
+    }
+    return result;
+}
+
 JNIEXPORT jint JNICALL
 Java_com_mobileer_oboetester_OboeAudioStream_getFramesPerBurst(
         JNIEnv *env, jobject, jint streamIndex) {
@@ -978,4 +1000,22 @@ Java_com_mobileer_oboetester_TestColdStartLatencyActivity_getAudioDeviceId(
     return sColdStartLatency.getDeviceId();
 }
 
+static TestRapidCycle sRapidCycle;
+
+JNIEXPORT jint JNICALL
+Java_com_mobileer_oboetester_TestRapidCycleActivity_startRapidCycleTest(JNIEnv *env, jobject thiz,
+                                                                        jboolean use_open_sl) {
+    return sRapidCycle.start(use_open_sl);
+}
+
+JNIEXPORT jint JNICALL
+Java_com_mobileer_oboetester_TestRapidCycleActivity_stopRapidCycleTest(JNIEnv *env, jobject thiz) {
+    return sRapidCycle.stop();
 }
+
+JNIEXPORT jint JNICALL
+Java_com_mobileer_oboetester_TestRapidCycleActivity_getCycleCount(JNIEnv *env, jobject thiz) {
+    return sRapidCycle.getCycleCount();
+}
+
+} // extern "C"
diff --git a/apps/OboeTester/app/src/main/cpp/synth/SawtoothOscillatorDPW.h b/apps/OboeTester/app/src/main/cpp/synth/SawtoothOscillatorDPW.h
index a6eb4015..ffb5d191 100644
--- a/apps/OboeTester/app/src/main/cpp/synth/SawtoothOscillatorDPW.h
+++ b/apps/OboeTester/app/src/main/cpp/synth/SawtoothOscillatorDPW.h
@@ -25,6 +25,7 @@
 #include <math.h>
 #include "SynthTools.h"
 #include "DifferentiatedParabola.h"
+#include "SawtoothOscillator.h"
 
 namespace marksynth {
 /**
diff --git a/apps/OboeTester/app/src/main/cpp/synth/SineOscillator.h b/apps/OboeTester/app/src/main/cpp/synth/SineOscillator.h
index 6a1c55d6..28be4460 100644
--- a/apps/OboeTester/app/src/main/cpp/synth/SineOscillator.h
+++ b/apps/OboeTester/app/src/main/cpp/synth/SineOscillator.h
@@ -23,6 +23,7 @@
 
 #include <cstdint>
 #include <math.h>
+#include "SawtoothOscillator.h"
 #include "SynthTools.h"
 
 namespace marksynth {
diff --git a/apps/OboeTester/app/src/main/cpp/synth/SquareOscillatorDPW.h b/apps/OboeTester/app/src/main/cpp/synth/SquareOscillatorDPW.h
index 01587152..ca82a478 100644
--- a/apps/OboeTester/app/src/main/cpp/synth/SquareOscillatorDPW.h
+++ b/apps/OboeTester/app/src/main/cpp/synth/SquareOscillatorDPW.h
@@ -25,6 +25,7 @@
 #include <math.h>
 #include "SynthTools.h"
 #include "DifferentiatedParabola.h"
+#include "SawtoothOscillator.h"
 
 namespace marksynth {
 /**
diff --git a/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.cpp b/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.cpp
index 5744d8f5..9e8d37d3 100644
--- a/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.cpp
+++ b/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.cpp
@@ -17,10 +17,10 @@
 #include "WaveFileWriter.h"
 
 void WaveFileWriter::WaveFileWriter::write(float value) {
-    if (!headerWritten) {
+    if (!mHeaderWritten) {
         writeHeader();
     }
-    if (bitsPerSample == 24) {
+    if (mBitsPerSample == 24) {
         writePCM24(value);
     } else {
         writePCM16(value);
@@ -46,7 +46,7 @@ void WaveFileWriter::writeShortLittle(int16_t n) {
 }
 
 void WaveFileWriter::writeFormatChunk() {
-    int32_t bytesPerSample = (bitsPerSample + 7) / 8;
+    int32_t bytesPerSample = (mBitsPerSample + 7) / 8;
 
     writeByte('f');
     writeByte('m');
@@ -60,7 +60,13 @@ void WaveFileWriter::writeFormatChunk() {
     writeIntLittle(mFrameRate * mSamplesPerFrame * bytesPerSample);
     // block align
     writeShortLittle((int16_t) (mSamplesPerFrame * bytesPerSample));
-    writeShortLittle((int16_t) bitsPerSample);
+    writeShortLittle((int16_t) mBitsPerSample);
+}
+
+int32_t WaveFileWriter::getDataSizeInBytes() {
+    if (mFrameCount <= 0) return INT32_MAX;
+    int64_t dataSize = ((int64_t)mFrameCount) * mSamplesPerFrame * mBitsPerSample / 8;
+    return (int32_t)std::min(dataSize, (int64_t)INT32_MAX);
 }
 
 void WaveFileWriter::writeDataChunkHeader() {
@@ -68,22 +74,20 @@ void WaveFileWriter::writeDataChunkHeader() {
     writeByte('a');
     writeByte('t');
     writeByte('a');
-    // Maximum size is not strictly correct but is commonly used
-    // when we do not know the final size.
-    writeIntLittle(INT32_MAX);
+    writeIntLittle(getDataSizeInBytes());
 }
 
 void WaveFileWriter::writeHeader() {
     writeRiffHeader();
     writeFormatChunk();
     writeDataChunkHeader();
-    headerWritten = true;
+    mHeaderWritten = true;
 }
 
 // Write lower 8 bits. Upper bits ignored.
 void WaveFileWriter::writeByte(uint8_t b) {
     mOutputStream->write(b);
-    bytesWritten += 1;
+    mBytesWritten += 1;
 }
 
 void WaveFileWriter::writePCM24(float value) {
@@ -124,7 +128,11 @@ void WaveFileWriter::writeRiffHeader() {
     writeByte('F');
     // Maximum size is not strictly correct but is commonly used
     // when we do not know the final size.
-    writeIntLittle(INT32_MAX);
+    const int kExtraHeaderBytes = 36;
+    int32_t dataSize = getDataSizeInBytes();
+    writeIntLittle((dataSize > (INT32_MAX - kExtraHeaderBytes))
+            ? INT32_MAX
+            : dataSize + kExtraHeaderBytes);
     writeByte('W');
     writeByte('A');
     writeByte('V');
diff --git a/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.h b/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.h
index 56abd1ce..e3cebce4 100644
--- a/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.h
+++ b/apps/OboeTester/app/src/main/cpp/util/WaveFileWriter.h
@@ -22,6 +22,7 @@
 
 #include <cassert>
 #include <stdio.h>
+#include <algorithm>
 
 class WaveFileOutputStream {
 public:
@@ -57,6 +58,10 @@ public:
     }
 
     /**
+     * Set the number of frames per second, also known as "sample rate".
+     *
+     * If you call this then it must be called before the first write().
+     *
      * @param frameRate default is 44100
      */
     void setFrameRate(int32_t frameRate) {
@@ -68,25 +73,49 @@ public:
     }
 
     /**
+     * Set the size of one frame.
      * For stereo, set this to 2. Default is mono = 1.
-     * Also known as ChannelCount
+     * Also known as ChannelCount.
+     *
+     * If you call this then it must be called before the first write().
+     *
+     * @param samplesPerFrame is 2 for stereo or 1 for mono
      */
     void setSamplesPerFrame(int32_t samplesPerFrame) {
         mSamplesPerFrame = samplesPerFrame;
     }
 
+    /**
+     * Sets the number of frames in the file.
+     *
+     * If you do not know the final number of frames then that is OK.
+     * Just do not call this method and the RIFF and DATA chunk sizes
+     * will default to INT32_MAX. That is technically invalid WAV format
+     * but is common practice.
+     *
+     * If you call this then it must be called before the first write().
+     * @param frameCount number of frames to be written
+     */
+    void setFrameCount(int32_t frameCount) {
+        mFrameCount = frameCount;
+    }
+
     int32_t getSamplesPerFrame() const {
         return mSamplesPerFrame;
     }
 
-    /** Only 16 or 24 bit samples supported at the moment. Default is 16. */
+    /** Only 16 or 24 bit samples supported at the moment. Default is 16.
+     *
+     * If you call this then it must be called before the first write().
+     * @param bits number of bits in a PCM sample
+     */
     void setBitsPerSample(int32_t bits) {
         assert((bits == 16) || (bits == 24));
-        bitsPerSample = bits;
+        mBitsPerSample = bits;
     }
 
     int32_t getBitsPerSample() const {
-        return bitsPerSample;
+        return mBitsPerSample;
     }
 
     void close() {
@@ -139,13 +168,16 @@ private:
      */
     void writeRiffHeader();
 
+    int32_t getDataSizeInBytes();
+
     static constexpr int WAVE_FORMAT_PCM = 1;
     WaveFileOutputStream *mOutputStream = nullptr;
     int32_t mFrameRate = 48000;
     int32_t mSamplesPerFrame = 1;
-    int32_t bitsPerSample = 16;
-    int32_t bytesWritten = 0;
-    bool headerWritten = false;
+    int32_t mFrameCount = 0; // 0 for unknown
+    int32_t mBitsPerSample = 16;
+    int32_t mBytesWritten = 0;
+    bool mHeaderWritten = false;
     static constexpr int32_t PCM24_MIN = -(1 << 23);
     static constexpr int32_t PCM24_MAX = (1 << 23) - 1;
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceAdapter.java b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceAdapter.java
index 6444b2a7..4542227b 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceAdapter.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceAdapter.java
@@ -21,6 +21,7 @@ import android.view.View;
 import android.view.ViewGroup;
 import android.widget.ArrayAdapter;
 import android.widget.TextView;
+
 import androidx.annotation.NonNull;
 import androidx.annotation.Nullable;
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceInfoConverter.java b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceInfoConverter.java
index 14c635d2..d5829d03 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceInfoConverter.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceInfoConverter.java
@@ -17,6 +17,8 @@ package com.mobileer.audio_device;
 
 import android.media.AudioDescriptor;
 import android.media.AudioDeviceInfo;
+import android.media.AudioManager;
+import android.media.AudioMixerAttributes;
 import android.media.AudioProfile;
 import android.os.Build;
 
@@ -31,7 +33,7 @@ public class AudioDeviceInfoConverter {
      * @param adi The AudioDeviceInfo object to be converted to a String
      * @return String containing all the information from the AudioDeviceInfo object
      */
-    public static String toString(AudioDeviceInfo adi){
+    public static String toString(AudioManager audioManager, AudioDeviceInfo adi){
 
         StringBuilder sb = new StringBuilder();
         sb.append("Id: ");
@@ -74,30 +76,37 @@ public class AudioDeviceInfoConverter {
             sb.append(adi.getAddress());
         }
 
-        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
             sb.append("\nEncapsulation Metadata Types: ");
             int[] encapsulationMetadataTypes = adi.getEncapsulationMetadataTypes();
             sb.append(intArrayToString(encapsulationMetadataTypes));
         }
 
-        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.R) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
             sb.append("\nEncapsulation Modes: ");
             int[] encapsulationModes = adi.getEncapsulationModes();
             sb.append(intArrayToString(encapsulationModes));
         }
 
-        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
             sb.append("\nAudio Descriptors: ");
             List<AudioDescriptor> audioDescriptors = adi.getAudioDescriptors();
             sb.append(audioDescriptors);
         }
 
-        if (android.os.Build.VERSION.SDK_INT >= android.os.Build.VERSION_CODES.S) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
             sb.append("\nAudio Profiles: ");
             List<AudioProfile> audioProfiles = adi.getAudioProfiles();
             sb.append(audioProfiles);
         }
 
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
+            sb.append("\nSupported Mixer Attributes: ");
+            List<AudioMixerAttributes> audioMixerAttributes =
+                    audioManager.getSupportedMixerAttributes(adi);
+            sb.append(audioMixerAttributes);
+        }
+
         sb.append("\n");
         return sb.toString();
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceSpinner.java b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceSpinner.java
index 3c4390ae..2e0333d7 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceSpinner.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/AudioDeviceSpinner.java
@@ -22,13 +22,14 @@ import android.media.AudioDeviceCallback;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.util.AttributeSet;
-import android.widget.Spinner;
+
+import androidx.appcompat.widget.AppCompatSpinner;
 
 import com.mobileer.oboetester.R;
 
 import java.util.List;
 
-public class AudioDeviceSpinner extends Spinner {
+public class AudioDeviceSpinner extends AppCompatSpinner {
 
     private static final int AUTO_SELECT_DEVICE_ID = 0;
     private static final String TAG = AudioDeviceSpinner.class.getName();
@@ -63,14 +64,8 @@ public class AudioDeviceSpinner extends Spinner {
     }
 
     public AudioDeviceSpinner(Context context, AttributeSet attrs, int defStyleAttr,
-                              int defStyleRes, int mode){
-        super(context, attrs, defStyleAttr, defStyleRes, mode);
-        setup(context);
-    }
-
-    public AudioDeviceSpinner(Context context, AttributeSet attrs, int defStyleAttr,
-                              int defStyleRes, int mode, Theme popupTheme){
-        super(context, attrs, defStyleAttr, defStyleRes, mode, popupTheme);
+                                      int mode, Theme popupTheme){
+        super(context, attrs, defStyleAttr, mode, popupTheme);
         setup(context);
     }
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/CommunicationDeviceSpinner.java b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/CommunicationDeviceSpinner.java
index 46a924f5..32ccda5d 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/CommunicationDeviceSpinner.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/audio_device/CommunicationDeviceSpinner.java
@@ -22,13 +22,14 @@ import android.media.AudioDeviceCallback;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.util.AttributeSet;
-import android.widget.Spinner;
+
+import androidx.appcompat.widget.AppCompatSpinner;
 
 import com.mobileer.oboetester.R;
 
 import java.util.List;
 
-public class CommunicationDeviceSpinner extends Spinner {
+public class CommunicationDeviceSpinner extends AppCompatSpinner {
     private static final String TAG = CommunicationDeviceSpinner.class.getName();
     // menu positions
     public static final int POS_CLEAR = 0;
@@ -64,14 +65,8 @@ public class CommunicationDeviceSpinner extends Spinner {
     }
 
     public CommunicationDeviceSpinner(Context context, AttributeSet attrs, int defStyleAttr,
-                                      int defStyleRes, int mode){
-        super(context, attrs, defStyleAttr, defStyleRes, mode);
-        setup(context);
-    }
-
-    public CommunicationDeviceSpinner(Context context, AttributeSet attrs, int defStyleAttr,
-                                      int defStyleRes, int mode, Theme popupTheme){
-        super(context, attrs, defStyleAttr, defStyleRes, mode, popupTheme);
+                                      int mode, Theme popupTheme){
+        super(context, attrs, defStyleAttr, mode, popupTheme);
         setup(context);
     }
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AnalyzerActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AnalyzerActivity.java
index 5e22c0bc..69a8b829 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AnalyzerActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AnalyzerActivity.java
@@ -16,21 +16,15 @@
 
 package com.mobileer.oboetester;
 
-import android.Manifest;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.os.Build;
 import android.os.Bundle;
 import android.widget.Toast;
+
 import androidx.annotation.NonNull;
-import androidx.core.app.ActivityCompat;
-import androidx.core.content.ContextCompat;
 
-import java.io.File;
-import java.io.FileOutputStream;
 import java.io.IOException;
-import java.io.OutputStreamWriter;
-import java.io.Writer;
 import java.util.Locale;
 
 /**
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioForegroundService.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioForegroundService.java
new file mode 100644
index 00000000..2ebb5a2f
--- /dev/null
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioForegroundService.java
@@ -0,0 +1,80 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.mobileer.oboetester;
+
+import android.app.Notification;
+import android.app.NotificationChannel;
+import android.app.NotificationManager;
+import android.app.Service;
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.ServiceInfo;
+import android.os.Build;
+import android.os.IBinder;
+import android.util.Log;
+
+public class AudioForegroundService extends Service {
+    private static final String TAG = "OboeTester";
+    public static final String ACTION_START = "ACTION_START";
+    public static final String ACTION_STOP = "ACTION_STOP";
+
+    @Override
+    public IBinder onBind(Intent intent) {
+        // We don't provide binding, so return null
+        return null;
+    }
+
+    private Notification buildNotification() {
+        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
+
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
+            manager.createNotificationChannel(new NotificationChannel(
+                    "all",
+                    "All Notifications",
+                    NotificationManager.IMPORTANCE_NONE));
+
+            return new Notification.Builder(this, "all")
+                    .setContentTitle("Playing/recording audio")
+                    .setContentText("playing/recording...")
+                    .setSmallIcon(R.drawable.ic_notification)
+                    .build();
+        }
+        return null;
+    }
+
+    @Override
+    public int onStartCommand(Intent intent, int flags, int startId) {
+        Log.i(TAG, "Receive onStartCommand" + intent);
+        switch (intent.getAction()) {
+            case ACTION_START:
+                Log.i(TAG, "Receive ACTION_START " + intent.getExtras());
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+                    int serviceTypes = intent.getIntExtra("service_types", 0);
+                    Log.i(TAG, "ServiceTypes: " + serviceTypes);
+                    startForeground(1, buildNotification(), serviceTypes);
+                }
+                break;
+            case ACTION_STOP:
+                Log.i(TAG, "Receive ACTION_STOP " + intent.getExtras());
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+                    stopForeground(STOP_FOREGROUND_REMOVE);
+                }
+                break;
+        }
+        return START_NOT_STICKY;
+    }
+}
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioQueryTools.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioQueryTools.java
index a4dd6fc4..c0be795b 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioQueryTools.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioQueryTools.java
@@ -69,6 +69,16 @@ public class AudioQueryTools {
                 + packageManager.hasSystemFeature(PackageManager.FEATURE_USB_HOST));
         report.append("\nUSB Accessory Feature: "
                 + packageManager.hasSystemFeature(PackageManager.FEATURE_USB_ACCESSORY));
+        report.append("\nBluetooth Feature    : "
+                + packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH));
+        report.append("\nBluetooth LE Feature : "
+                + packageManager.hasSystemFeature(PackageManager.FEATURE_BLUETOOTH_LE));
+        if (android.os.Build.VERSION.SDK_INT > Build.VERSION_CODES.TIRAMISU) {
+            report.append("\nTelecom Feature      : "
+                    + packageManager.hasSystemFeature(PackageManager.FEATURE_TELECOM));
+            report.append("\nTelephonyCall Feature: "
+                    + packageManager.hasSystemFeature(PackageManager.FEATURE_TELEPHONY_CALLING));
+        }
         return report.toString();
     }
 
@@ -160,6 +170,7 @@ public class AudioQueryTools {
         report.append(getSystemPropertyLine("ro.board.platform"));
         report.append(getSystemPropertyLine("ro.build.changelist"));
         report.append(getSystemPropertyLine("ro.build.description"));
+        report.append(getSystemPropertyLine("ro.build.date"));
         return report.toString();
     }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
index 14eb163e..3bf5286b 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AudioStreamBase.java
@@ -221,6 +221,18 @@ public abstract class AudioStreamBase {
         return mActualStreamConfiguration.getFramesPerBurst();
     }
 
+    public int getHardwareChannelCount() {
+        return mActualStreamConfiguration.getHardwareChannelCount();
+    }
+
+    public int getHardwareSampleRate() {
+        return mActualStreamConfiguration.getHardwareSampleRate();
+    }
+
+    public int getHardwareFormat() {
+        return mActualStreamConfiguration.getHardwareFormat();
+    }
+
     public int getBufferCapacityInFrames() {
         return mBufferSizeInFrames;
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedGlitchActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedGlitchActivity.java
index ae53a7f6..5cdb4017 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedGlitchActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedGlitchActivity.java
@@ -29,13 +29,7 @@ import android.widget.Spinner;
  */
 public class AutomatedGlitchActivity  extends BaseAutoGlitchActivity {
 
-    private Spinner mDurationSpinner;
-
     // Test with these configurations.
-    private static final int[] PERFORMANCE_MODES = {
-            StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY,
-            StreamConfiguration.PERFORMANCE_MODE_NONE
-    };
     private static final int[] SAMPLE_RATES = { 48000, 44100, 16000 };
     private static final int MONO = 1;
     private static final int STEREO = 2;
@@ -63,8 +57,8 @@ public class AutomatedGlitchActivity  extends BaseAutoGlitchActivity {
     protected void onCreate(Bundle savedInstanceState) {
         super.onCreate(savedInstanceState);
 
-        mDurationSpinner = (Spinner) findViewById(R.id.spinner_glitch_duration);
-        mDurationSpinner.setOnItemSelectedListener(new DurationSpinnerListener());
+        Spinner durationSpinner = (Spinner) findViewById(R.id.spinner_glitch_duration);
+        durationSpinner.setOnItemSelectedListener(new DurationSpinnerListener());
 
         setAnalyzerText(getString(R.string.auto_glitch_instructions));
     }
@@ -74,9 +68,7 @@ public class AutomatedGlitchActivity  extends BaseAutoGlitchActivity {
         return "AutoGlitch";
     }
 
-    private void testConfiguration(int perfMode,
-                                   int sharingMode,
-                                   int sampleRate,
+    private void testConfiguration(int sampleRate,
                                    int inChannels,
                                    int outChannels) throws InterruptedException {
 
@@ -87,30 +79,18 @@ public class AutomatedGlitchActivity  extends BaseAutoGlitchActivity {
         requestedInConfig.reset();
         requestedOutConfig.reset();
 
-        requestedInConfig.setPerformanceMode(perfMode);
-        requestedOutConfig.setPerformanceMode(perfMode);
-
-        requestedInConfig.setSharingMode(sharingMode);
-        requestedOutConfig.setSharingMode(sharingMode);
-
         requestedInConfig.setSampleRate(sampleRate);
         requestedOutConfig.setSampleRate(sampleRate);
 
         requestedInConfig.setChannelCount(inChannels);
         requestedOutConfig.setChannelCount(outChannels);
 
-        testCurrentConfigurations();
+        testPerformancePaths();
     }
 
-    private void testConfiguration(int performanceMode,
-                                   int sharingMode,
-                                   int sampleRate) throws InterruptedException {
-        testConfiguration(performanceMode,
-                sharingMode,
-                sampleRate, MONO, STEREO);
-        testConfiguration(performanceMode,
-                sharingMode,
-                sampleRate, STEREO, MONO);
+    private void testConfiguration(int sampleRate) throws InterruptedException {
+        testConfiguration(sampleRate, MONO, STEREO);
+        testConfiguration(sampleRate, STEREO, MONO);
     }
 
     @Override
@@ -121,22 +101,11 @@ public class AutomatedGlitchActivity  extends BaseAutoGlitchActivity {
             mTestResults.clear();
 
             // Test with STEREO on both input and output.
-            testConfiguration(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY,
-                    StreamConfiguration.SHARING_MODE_EXCLUSIVE,
-                    UNSPECIFIED, STEREO, STEREO);
-
-            // Test EXCLUSIVE mode with a configuration most likely to work.
-            testConfiguration(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY,
-                    StreamConfiguration.SHARING_MODE_EXCLUSIVE,
-                    UNSPECIFIED);
+            testConfiguration(UNSPECIFIED, STEREO, STEREO);
 
             // Test various combinations.
-            for (int perfMode : PERFORMANCE_MODES) {
-                for (int sampleRate : SAMPLE_RATES) {
-                    testConfiguration(perfMode,
-                            StreamConfiguration.SHARING_MODE_SHARED,
-                            sampleRate);
-                }
+            for (int sampleRate : SAMPLE_RATES) {
+                testConfiguration(sampleRate);
             }
 
             compareFailedTestsWithNearestPassingTest();
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedTestRunner.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedTestRunner.java
index 27fc0456..e102c61d 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedTestRunner.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/AutomatedTestRunner.java
@@ -13,6 +13,8 @@ import android.widget.LinearLayout;
 import android.widget.ScrollView;
 import android.widget.TextView;
 
+import androidx.annotation.NonNull;
+
 import java.text.DateFormat;
 import java.text.SimpleDateFormat;
 import java.util.Calendar;
@@ -36,6 +38,7 @@ public  class AutomatedTestRunner extends LinearLayout implements Runnable {
     private int          mTestCount;
     private int          mPassCount;
     private int          mFailCount;
+    private int          mSkipCount;
     private TestAudioActivity  mActivity;
 
     private Thread            mAutoThread;
@@ -142,6 +145,9 @@ public  class AutomatedTestRunner extends LinearLayout implements Runnable {
     public void incrementPassCount() {
         mPassCount++;
     }
+    public void incrementSkipCount() {
+        mSkipCount++;
+    }
     public void incrementTestCount() {
         mTestCount++;
     }
@@ -286,6 +292,7 @@ public  class AutomatedTestRunner extends LinearLayout implements Runnable {
         mTestCount = 0;
         mPassCount = 0;
         mFailCount = 0;
+        mSkipCount = 0;
         try {
             mActivity.runTest();
             log("Tests finished.");
@@ -307,10 +314,7 @@ public  class AutomatedTestRunner extends LinearLayout implements Runnable {
             } else {
                 log("No tests were run!");
             }
-            int skipped = mTestCount - (mPassCount + mFailCount);
-            log(mPassCount + " passed. "
-                    + mFailCount + " failed. "
-                    + skipped + " skipped. ");
+            log(getPassFailReport());
             log("== FINISHED at " + new Date());
 
             flushLog();
@@ -327,4 +331,11 @@ public  class AutomatedTestRunner extends LinearLayout implements Runnable {
         }
     }
 
+    @NonNull
+    public String getPassFailReport() {
+        return  mPassCount + " passed. "
+                + mFailCount + " failed. "
+                + mSkipCount + " skipped. ";
+    }
+
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseAutoGlitchActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseAutoGlitchActivity.java
index e19b5eff..92d1b6e1 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseAutoGlitchActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseAutoGlitchActivity.java
@@ -22,9 +22,11 @@ import android.content.Context;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.os.Bundle;
+import android.os.Environment;
 
 import androidx.annotation.Nullable;
 
+import java.io.File;
 import java.io.IOException;
 import java.util.ArrayList;
 import java.util.Locale;
@@ -80,6 +82,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
         public final int mmapUsed;
         public final int performanceMode;
         public final int sharingMode;
+        public final int sessionId;
 
         public TestStreamOptions(StreamConfiguration configuration, int channelUsed) {
             this.channelUsed = channelUsed;
@@ -89,6 +92,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
             mmapUsed = configuration.isMMap() ? 1 : 0;
             performanceMode = configuration.getPerformanceMode();
             sharingMode = configuration.getSharingMode();
+            sessionId = configuration.getSessionId();
         }
 
         int countDifferences(TestStreamOptions other) {
@@ -100,6 +104,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
             count += (mmapUsed != other.mmapUsed) ? 1 : 0;
             count += (performanceMode != other.performanceMode) ? 1 : 0;
             count += (sharingMode != other.sharingMode) ? 1 : 0;
+            count += (sessionId != other.sessionId) ? 1 : 0;
             return count;
         }
 
@@ -112,6 +117,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
             text.append(TestDataPathsActivity.comparePassedField(prefix,this, passed, "mmapUsed"));
             text.append(TestDataPathsActivity.comparePassedField(prefix,this, passed, "performanceMode"));
             text.append(TestDataPathsActivity.comparePassedField(prefix,this, passed, "sharingMode"));
+            text.append(TestDataPathsActivity.comparePassedField(prefix,this, passed, "sessionId"));
             return text.toString();
         }
         @Override
@@ -236,6 +242,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
                 + ", ID = " + String.format(Locale.getDefault(), "%2d", config.getDeviceId())
                 + ", Perf = " + StreamConfiguration.convertPerformanceModeToText(
                         config.getPerformanceMode())
+                + ((config.getSessionId() > 0) ? (", sessionId = " + config.getSessionId()) : "")
                 + ",\n     ch = " + channelText(channel, config.getChannelCount())
                 + ", cm = " + convertChannelMaskToText(config.getChannelMask());
     }
@@ -244,6 +251,10 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
         return ("burst=" + stream.getFramesPerBurst()
                 + ", size=" + stream.getBufferSizeInFrames()
                 + ", cap=" + stream.getBufferCapacityInFrames()
+                + "\n     HW: sr=" + stream.getHardwareSampleRate()
+                + ", ch=" + stream.getHardwareChannelCount()
+                + ", fmt=" + (stream.getHardwareFormat() == StreamConfiguration.UNSPECIFIED ?
+                "?" : StreamConfiguration.convertFormatToText(stream.getHardwareFormat()))
         );
     }
 
@@ -257,6 +268,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
     protected TestResult testCurrentConfigurations() throws InterruptedException {
         mAutomatedTestRunner.incrementTestCount();
         if ((getSingleTestIndex() >= 0) && (getTestCount() != getSingleTestIndex())) {
+            mAutomatedTestRunner.incrementSkipCount();
             return null;
         }
 
@@ -287,9 +299,9 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
             outStream.setBufferSizeInFrames(sizeFrames);
             AudioStreamBase inStream = mAudioInputTester.getCurrentAudioStream();
             log("  " + getConfigText(actualInConfig));
-            log("      " + getStreamText(inStream));
+            log("     " + getStreamText(inStream));
             log("  " + getConfigText(actualOutConfig));
-            log("      " + getStreamText(outStream));
+            log("     " + getStreamText(outStream));
         } catch (Exception e) {
             openFailed = true;
             log(e.getMessage());
@@ -357,6 +369,7 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
             mAutomatedTestRunner.incrementFailCount();
         } else if (skipped) {
             log(TEXT_SKIP + " - " + skipReason);
+            mAutomatedTestRunner.incrementSkipCount();
         } else {
             log("Result:");
             reason += didTestFail();
@@ -372,13 +385,13 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
                 appendFailedSummary("  " + getConfigText(actualInConfig) + "\n");
                 appendFailedSummary("  " + getConfigText(actualOutConfig) + "\n");
                 appendFailedSummary("    " + resultText + "\n");
+                saveRecordingAsWave();
                 mAutomatedTestRunner.incrementFailCount();
                 result = TEST_RESULT_FAILED;
             } else {
                 mAutomatedTestRunner.incrementPassCount();
                 result = TEST_RESULT_PASSED;
             }
-
         }
         mAutomatedTestRunner.flushLog();
 
@@ -392,6 +405,46 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
         return testResult;
     }
 
+    void testPerformancePaths() throws InterruptedException {
+        StreamConfiguration requestedInConfig = mAudioInputTester.requestedConfiguration;
+        StreamConfiguration requestedOutConfig = mAudioOutTester.requestedConfiguration;
+
+        requestedInConfig.setSharingMode(StreamConfiguration.SHARING_MODE_SHARED);
+        requestedOutConfig.setSharingMode(StreamConfiguration.SHARING_MODE_SHARED);
+
+        // Legacy NONE
+        requestedInConfig.setMMap(false);
+        requestedOutConfig.setMMap(false);
+        requestedInConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_NONE);
+        requestedOutConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_NONE);
+        testCurrentConfigurations();
+
+        // Legacy LOW_LATENCY
+        requestedInConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
+        requestedOutConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
+        testCurrentConfigurations();
+
+        // MMAP LowLatency
+        if (NativeEngine.isMMapSupported()) {
+            requestedInConfig.setMMap(true);
+            requestedOutConfig.setMMap(true);
+            testCurrentConfigurations();
+        }
+        requestedInConfig.setMMap(false);
+        requestedOutConfig.setMMap(false);
+    }
+
+    private void saveRecordingAsWave() {
+        File recordingDir = getExternalFilesDir(Environment.DIRECTORY_MUSIC);
+        File waveFile = new File(recordingDir, String.format("glitch_%03d.wav", getTestCount()));
+        int saveResult = saveWaveFile(waveFile.getAbsolutePath());
+        if (saveResult > 0) {
+            appendFailedSummary("Saved in " + waveFile.getAbsolutePath() + "\n");
+        } else {
+            appendFailedSummary("saveWaveFile() returned " + saveResult + "\n");
+        }
+    }
+
     protected int getTestCount() {
         return mAutomatedTestRunner.getTestCount();
     }
@@ -437,6 +490,10 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
         }
     }
 
+    /**
+     * @param type
+     * @return list of compatible device types in preferred order
+     */
     protected ArrayList<Integer> getCompatibleDeviceTypes(int type) {
         ArrayList<Integer> compatibleTypes = new ArrayList<Integer>();
         switch(type) {
@@ -448,10 +505,15 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
                 compatibleTypes.add(AudioDeviceInfo.TYPE_BUILTIN_SPEAKER);
                 break;
             case AudioDeviceInfo.TYPE_USB_DEVICE:
+                // Give priority to an exact match of DEVICE.
                 compatibleTypes.add(AudioDeviceInfo.TYPE_USB_DEVICE);
-                // A USB Device is often mistaken for a headset.
                 compatibleTypes.add(AudioDeviceInfo.TYPE_USB_HEADSET);
                 break;
+            case AudioDeviceInfo.TYPE_USB_HEADSET:
+                // Give priority to an exact match of HEADSET.
+                compatibleTypes.add(AudioDeviceInfo.TYPE_USB_HEADSET);
+                compatibleTypes.add(AudioDeviceInfo.TYPE_USB_DEVICE);
+                break;
             default:
                 compatibleTypes.add(type);
                 break;
@@ -467,9 +529,12 @@ public class BaseAutoGlitchActivity extends GlitchActivity {
     protected AudioDeviceInfo findCompatibleInputDevice(int outputDeviceType) {
         ArrayList<Integer> compatibleDeviceTypes = getCompatibleDeviceTypes(outputDeviceType);
         AudioDeviceInfo[] devices = mAudioManager.getDevices(AudioManager.GET_DEVICES_INPUTS);
-        for (AudioDeviceInfo candidate : devices) {
-            if (compatibleDeviceTypes.contains(candidate.getType())) {
-                return candidate;
+        // Scan the compatible types in order of preference.
+        for (int compatibleType : compatibleDeviceTypes) {
+            for (AudioDeviceInfo candidate : devices) {
+                if (candidate.getType() == compatibleType) {
+                    return candidate;
+                }
             }
         }
         return null;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseOboeTesterActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseOboeTesterActivity.java
index 4bf57496..a82ff4ff 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseOboeTesterActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BaseOboeTesterActivity.java
@@ -17,18 +17,19 @@
 package com.mobileer.oboetester;
 
 import android.Manifest;
-import android.app.Activity;
 import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.widget.Toast;
+
 import androidx.annotation.NonNull;
+import androidx.appcompat.app.AppCompatActivity;
 import androidx.core.app.ActivityCompat;
 
 /**
  * Support requesting RECORD_AUDIO permission.
  */
 
-public abstract class BaseOboeTesterActivity extends Activity
+public abstract class BaseOboeTesterActivity extends AppCompatActivity
         implements ActivityCompat.OnRequestPermissionsResultCallback {
 
     private static final int MY_PERMISSIONS_REQUEST_RECORD_AUDIO = 938355;
@@ -103,4 +104,5 @@ public abstract class BaseOboeTesterActivity extends Activity
     private void beginTestThatRequiresRecording() {
         launchTestActivity(mTestClass);
     }
+
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BufferSizeView.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BufferSizeView.java
index 432e0ff3..da7e6a2f 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BufferSizeView.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/BufferSizeView.java
@@ -19,14 +19,12 @@ package com.mobileer.oboetester;
 import android.content.Context;
 import android.util.AttributeSet;
 import android.view.LayoutInflater;
-
-
 import android.view.View;
+import android.widget.LinearLayout;
 import android.widget.RadioButton;
 import android.widget.RadioGroup;
 import android.widget.SeekBar;
 import android.widget.TextView;
-import android.widget.LinearLayout;
 
 public class BufferSizeView extends LinearLayout {
     private OboeAudioStream mStream;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/CommunicationDeviceView.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/CommunicationDeviceView.java
index 3e4c96df..870d5cd6 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/CommunicationDeviceView.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/CommunicationDeviceView.java
@@ -16,7 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.app.Activity;
 import android.content.BroadcastReceiver;
 import android.content.Context;
 import android.content.Intent;
@@ -35,8 +34,6 @@ import android.widget.TextView;
 
 import com.mobileer.audio_device.CommunicationDeviceSpinner;
 
-import java.util.Locale;
-
 public class CommunicationDeviceView extends LinearLayout {
 
     private AudioManager mAudioManager;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DeviceReportActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DeviceReportActivity.java
index 31146236..44f0da08 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DeviceReportActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DeviceReportActivity.java
@@ -17,7 +17,6 @@
 package com.mobileer.oboetester;
 
 import android.annotation.TargetApi;
-import android.app.Activity;
 import android.content.Context;
 import android.content.Intent;
 import android.hardware.usb.UsbDevice;
@@ -25,6 +24,8 @@ import android.hardware.usb.UsbManager;
 import android.media.AudioDeviceCallback;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
+import android.media.MediaCodecInfo;
+import android.media.MediaCodecList;
 import android.media.MicrophoneInfo;
 import android.media.midi.MidiDeviceInfo;
 import android.media.midi.MidiManager;
@@ -36,9 +37,12 @@ import android.view.MenuItem;
 import android.widget.TextView;
 import android.widget.Toast;
 
+import androidx.appcompat.app.AppCompatActivity;
+
 import com.mobileer.audio_device.AudioDeviceInfoConverter;
 
 import java.io.IOException;
+import java.util.Arrays;
 import java.util.Collection;
 import java.util.HashMap;
 import java.util.List;
@@ -47,7 +51,7 @@ import java.util.Set;
 /**
  * Print a report of all the available audio devices.
  */
-public class DeviceReportActivity extends Activity {
+public class DeviceReportActivity extends AppCompatActivity {
 
     class MyAudioDeviceCallback extends AudioDeviceCallback {
         private HashMap<Integer, AudioDeviceInfo> mDevices
@@ -136,15 +140,17 @@ public class DeviceReportActivity extends Activity {
                 .append(", ").append(Build.PRODUCT).append("\n");
 
         report.append(reportExtraDeviceInfo());
+        report.append("\n");
 
         for (AudioDeviceInfo deviceInfo : devices) {
             report.append("\n==== Device =================== " + deviceInfo.getId() + "\n");
-            String item = AudioDeviceInfoConverter.toString(deviceInfo);
+            String item = AudioDeviceInfoConverter.toString(mAudioManager, deviceInfo);
             report.append(item);
         }
         report.append(reportAllMicrophones());
         report.append(reportUsbDevices());
         report.append(reportMidiDevices());
+        report.append(reportMediaCodecs());
         log(report.toString());
     }
 
@@ -253,6 +259,55 @@ public class DeviceReportActivity extends Activity {
         return report.toString();
     }
 
+    public String reportMediaCodecs() {
+        StringBuffer report = new StringBuffer();
+        report.append("\n############################");
+        report.append("\nMedia Codec Device Report:\n");
+        try {
+            MediaCodecList mediaCodecList = new MediaCodecList(MediaCodecList.REGULAR_CODECS);
+            MediaCodecInfo[] mediaCodecInfos = mediaCodecList.getCodecInfos();
+            for (MediaCodecInfo mediaCodecInfo : mediaCodecInfos) {
+                report.append("\n==== MediaCodecInfo ========= " + mediaCodecInfo.getName());
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                    report.append("\nCanonical Name         : " + mediaCodecInfo.getCanonicalName());
+                    report.append("\nIs Alias               : " + mediaCodecInfo.isAlias());
+                    report.append("\nIs Hardware Accelerated: " + mediaCodecInfo.isHardwareAccelerated());
+                    report.append("\nIs Software Only       : " + mediaCodecInfo.isSoftwareOnly());
+                    report.append("\nIs Vendor              : " + mediaCodecInfo.isVendor());
+                }
+                report.append("\nIs Encoder             : " + mediaCodecInfo.isEncoder());
+                report.append("\nSupported Types        : " + Arrays.toString(mediaCodecInfo.getSupportedTypes()));
+                for(String type : mediaCodecInfo.getSupportedTypes()) {
+                    MediaCodecInfo.CodecCapabilities codecCapabilities =
+                            mediaCodecInfo.getCapabilitiesForType(type);
+                    MediaCodecInfo.AudioCapabilities audioCapabilities =
+                            codecCapabilities.getAudioCapabilities();
+                    if (audioCapabilities != null) {
+                        report.append("\nAudio Type: " + type);
+                        report.append("\nBitrate Range: " + audioCapabilities.getBitrateRange());
+                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
+                            report.append("\nInput Channel Count Ranges: " + Arrays.toString(audioCapabilities.getInputChannelCountRanges()));
+                            report.append("\nMin Input Channel Count: " + audioCapabilities.getMinInputChannelCount());
+                        }
+                        report.append("\nMax Input Channel Count: " + audioCapabilities.getMaxInputChannelCount());
+                        report.append("\nSupported Sample Rate Ranges: " + Arrays.toString(audioCapabilities.getSupportedSampleRateRanges()));
+                        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
+                            // Avoid bug b/122116282
+                            report.append("\nSupported Sample Rates: " + Arrays.toString(audioCapabilities.getSupportedSampleRates()));
+                        }
+                    }
+                    report.append("\nIs Encoder             : " + mediaCodecInfo.isEncoder());
+                }
+                report.append("\n");
+            }
+        } catch (Exception e) {
+            Log.e(TestAudioActivity.TAG, "Caught ", e);
+            showErrorToast(e.getMessage());
+            report.append("\nERROR: " + e.getMessage() + "\n");
+        }
+        return report.toString();
+    }
+
     // Write to scrollable TextView
     private void log(final String text) {
         runOnUiThread(new Runnable() {
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DynamicWorkloadActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DynamicWorkloadActivity.java
index 8c94a3b7..5fe2046c 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DynamicWorkloadActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/DynamicWorkloadActivity.java
@@ -16,11 +16,15 @@
 
 package com.mobileer.oboetester;
 
+import android.content.Context;
 import android.graphics.Color;
 import android.graphics.Typeface;
+import android.media.AudioManager;
+import android.os.Build;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
+import android.os.PowerManager;
 import android.view.View;
 import android.widget.Button;
 import android.widget.CheckBox;
@@ -51,6 +55,13 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
     // By default, set high workload to 70 voices, which is reasonable for most devices.
     public static final double WORKLOAD_PROGRESS_FOR_70_VOICES = 0.53;
 
+    public static final String KEY_USE_ADPF = "use_adpf";
+    public static final boolean VALUE_DEFAULT_USE_ADPF = false;
+    public static final String KEY_USE_WORKLOAD = "use_workload";
+    public static final boolean VALUE_DEFAULT_USE_WORKLOAD = false;
+    public static final String KEY_SCROLL_GRAPHICS = "scroll_graphics";
+    public static final boolean VALUE_DEFAULT_SCROLL_GRAPHICS = false;
+
     private Button mStopButton;
     private Button mStartButton;
     private TextView mResultView;
@@ -63,9 +74,13 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
     private MultiLineChart.Trace mWorkloadTrace;
     private CheckBox mUseAltAdpfBox;
     private CheckBox mPerfHintBox;
+    private CheckBox mWorkloadReportBox;
     private boolean mDrawChartAlways = true;
     private CheckBox mDrawAlwaysBox;
+    private CheckBox mSustainedPerformanceModeBox;
     private int mCpuCount;
+    private boolean mShouldUseADPF;
+    private boolean mShouldUseWorkloadReporting;
 
     private static final int WORKLOAD_LOW = 1;
     private int mWorkloadHigh; // this will get set later
@@ -281,6 +296,7 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
                 0.0f, (MARGIN_ABOVE_WORKLOAD_FOR_CPU * WORKLOAD_HIGH_MAX));
 
         mPerfHintBox = (CheckBox) findViewById(R.id.enable_perf_hint);
+        mWorkloadReportBox = (CheckBox) findViewById(R.id.enable_workload_report);
 
         // TODO remove when finished with ADPF experiments.
         mUseAltAdpfBox = (CheckBox) findViewById(R.id.use_alternative_adpf);
@@ -293,9 +309,18 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
 
         mPerfHintBox.setOnClickListener(buttonView -> {
                 CheckBox checkBox = (CheckBox) buttonView;
-                setPerformanceHintEnabled(checkBox.isChecked());
-                mUseAltAdpfBox.setEnabled(!checkBox.isChecked());
+                mShouldUseADPF = checkBox.isChecked();
+                setPerformanceHintEnabled(mShouldUseADPF);
+                mUseAltAdpfBox.setEnabled(!mShouldUseADPF);
+                mWorkloadReportBox.setEnabled(mShouldUseADPF);
+        });
+
+        mWorkloadReportBox.setOnClickListener(buttonView -> {
+            CheckBox checkBox = (CheckBox) buttonView;
+            mShouldUseWorkloadReporting = checkBox.isChecked();
+            setWorkloadReportingEnabled(mShouldUseWorkloadReporting);
         });
+        mWorkloadReportBox.setEnabled(mShouldUseADPF);
 
         CheckBox hearWorkloadBox = (CheckBox) findViewById(R.id.hear_workload);
         hearWorkloadBox.setOnClickListener(buttonView -> {
@@ -309,6 +334,19 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
             mDrawChartAlways = checkBox.isChecked();
         });
 
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
+            PowerManager powerManager = (PowerManager) getApplicationContext().getSystemService(Context.POWER_SERVICE);
+            mSustainedPerformanceModeBox = (CheckBox) findViewById(R.id.sustained_perf_mode);
+            if (powerManager.isSustainedPerformanceModeSupported()) {
+                mSustainedPerformanceModeBox.setOnClickListener(buttonView -> {
+                    CheckBox checkBox = (CheckBox) buttonView;
+                    getWindow().setSustainedPerformanceMode(checkBox.isChecked());
+                });
+            } else {
+                mSustainedPerformanceModeBox.setEnabled(false);
+            }
+        }
+
         if (mDynamicWorkloadView != null) {
             mDynamicWorkloadView.setWorkloadReceiver((w) -> {
                 setWorkloadHigh(w);
@@ -329,13 +367,18 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
     }
 
     private void setPerformanceHintEnabled(boolean checked) {
-      mAudioOutTester.getCurrentAudioStream().setPerformanceHintEnabled(checked);
+        mAudioOutTester.getCurrentAudioStream().setPerformanceHintEnabled(checked);
+    }
+
+    private void setWorkloadReportingEnabled(boolean enabled) {
+        NativeEngine.setWorkloadReportingEnabled(enabled);
     }
 
     private void updateButtons(boolean running) {
         mStartButton.setEnabled(!running);
         mStopButton.setEnabled(running);
         mPerfHintBox.setEnabled(running);
+        mWorkloadReportBox.setEnabled(running);
     }
 
     private void postResult(final String text) {
@@ -352,6 +395,10 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
     }
 
     public void startTest(View view) {
+        startTest();
+    }
+
+    private void startTest() {
         try {
             openAudio();
         } catch (IOException e) {
@@ -385,4 +432,60 @@ public class DynamicWorkloadActivity extends TestOutputActivityBase {
         updateButtons(false);
         super.onStopTest();
     }
+
+
+    @Override
+    public void startTestUsingBundle() {
+        try {
+            StreamConfiguration requestedOutConfig = mAudioOutTester.requestedConfiguration;
+            IntentBasedTestSupport.configureOutputStreamFromBundle(mBundleFromIntent, requestedOutConfig);
+
+            // Specific options.
+            mShouldUseADPF = mBundleFromIntent.getBoolean(KEY_USE_ADPF,
+                    VALUE_DEFAULT_USE_ADPF);
+            mShouldUseWorkloadReporting = mBundleFromIntent.getBoolean(KEY_USE_WORKLOAD,
+                    VALUE_DEFAULT_USE_WORKLOAD);
+            mDrawChartAlways =
+                    mBundleFromIntent.getBoolean(KEY_SCROLL_GRAPHICS,
+                            VALUE_DEFAULT_SCROLL_GRAPHICS);
+
+            startTest();
+
+            runOnUiThread(() -> {
+                mPerfHintBox.setChecked(mShouldUseADPF);
+                setPerformanceHintEnabled(mShouldUseADPF);
+                mWorkloadReportBox.setChecked(mShouldUseWorkloadReporting);
+                setWorkloadReportingEnabled(mShouldUseWorkloadReporting);
+                mDrawAlwaysBox.setChecked(mDrawChartAlways);
+            });
+
+            int durationSeconds = IntentBasedTestSupport.getDurationSeconds(mBundleFromIntent);
+            if (durationSeconds > 0) {
+                // Schedule the end of the test.
+                Handler handler = new Handler(Looper.getMainLooper()); // UI thread
+                handler.postDelayed(new Runnable() {
+                    @Override
+                    public void run() {
+                        stopAutomaticTest();
+                    }
+                }, durationSeconds * 1000);
+            }
+        } catch (Exception e) {
+            showErrorToast(e.getMessage());
+        } finally {
+            mBundleFromIntent = null;
+        }
+    }
+
+    void stopAutomaticTest() {
+        String report = getCommonTestReport();
+        AudioStreamBase outputStream =mAudioOutTester.getCurrentAudioStream();
+        report += "out.xruns = " + outputStream.getXRunCount() + "\n";
+        report += "use.adpf = " + (mShouldUseADPF ? "yes" : "no") + "\n";
+        report += "use.workload = " + (mShouldUseWorkloadReporting ? "yes" : "no") + "\n";
+        report += "scroll.graphics = " + (mDrawChartAlways ? "yes" : "no") + "\n";
+        onStopTest();
+        maybeWriteTestResult(report);
+        mTestRunningByIntent = false;
+    }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/EchoActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/EchoActivity.java
index 9ce258a5..b78f2b96 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/EchoActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/EchoActivity.java
@@ -16,7 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.app.Activity;
 import android.os.Bundle;
 import android.view.View;
 import android.widget.Button;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExternalTapToToneActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExternalTapToToneActivity.java
index c978da37..a08e5cef 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExternalTapToToneActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExternalTapToToneActivity.java
@@ -1,21 +1,19 @@
 package com.mobileer.oboetester;
 
-import android.Manifest;
-import android.app.Activity;
-import android.content.pm.PackageManager;
 import android.os.Bundle;
-import android.util.Log;
 import android.view.View;
 import android.view.WindowManager;
 import android.widget.Button;
 import android.widget.Toast;
 
+import androidx.appcompat.app.AppCompatActivity;
+
 import java.io.IOException;
 
 /**
  * Measure the tap-to-tone latency for other apps or devices.
  */
-public class ExternalTapToToneActivity extends Activity {
+public class ExternalTapToToneActivity extends AppCompatActivity {
     private static final String TAG = "OboeTester";
 
     protected TapToToneTester mTapToToneTester;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExtraTestsActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExtraTestsActivity.java
index c744329b..12b9efb8 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExtraTestsActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/ExtraTestsActivity.java
@@ -1,7 +1,5 @@
 package com.mobileer.oboetester;
 
-import android.content.Intent;
-import android.app.Activity;
 import android.os.Bundle;
 import android.view.View;
 
@@ -40,4 +38,8 @@ public class ExtraTestsActivity extends BaseOboeTesterActivity {
     public void onLaunchColdStartLatencyTest(View view) {
         launchTestActivity(TestColdStartLatencyActivity.class);
     }
+
+    public void onLaunchRapidCycleTest(View view) {
+        launchTestActivity(TestRapidCycleActivity.class);
+    }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/GlitchActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/GlitchActivity.java
index 63abe5cf..eddf8913 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/GlitchActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/GlitchActivity.java
@@ -16,7 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.app.Activity;
 import android.os.Bundle;
 import android.view.View;
 import android.widget.Button;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/IntentBasedTestSupport.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/IntentBasedTestSupport.java
index 4746ec72..5f2d00e7 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/IntentBasedTestSupport.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/IntentBasedTestSupport.java
@@ -16,7 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.content.Intent;
 import android.media.AudioManager;
 import android.os.Bundle;
 
@@ -61,6 +60,7 @@ public class IntentBasedTestSupport {
     public static final String KEY_FILE_NAME = "file";
     public static final String KEY_BUFFER_BURSTS = "buffer_bursts";
     public static final String KEY_BACKGROUND = "background";
+    public static final String KEY_FOREGROUND_SERVICE = "foreground_service";
     public static final String KEY_VOLUME = "volume";
 
     public static final String KEY_VOLUME_TYPE = "volume_type";
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MainActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MainActivity.java
index 145dfbc0..5e3d19f8 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MainActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MainActivity.java
@@ -16,10 +16,10 @@
 
 package com.mobileer.oboetester;
 
-import android.content.BroadcastReceiver;
+import static com.mobileer.oboetester.AudioQueryTools.getSystemProperty;
+
 import android.content.Context;
 import android.content.Intent;
-import android.content.IntentFilter;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
 import android.graphics.Point;
@@ -46,6 +46,7 @@ public class MainActivity extends BaseOboeTesterActivity {
     public static final String VALUE_TEST_NAME_DATA_PATHS = "data_paths";
     public static final String VALUE_TEST_NAME_OUTPUT = "output";
     public static final String VALUE_TEST_NAME_INPUT = "input";
+    public static final String VALUE_TEST_NAME_CPU_LOAD = "cpu_load";
 
     static {
         // Must match name in CMakeLists.txt
@@ -60,6 +61,7 @@ public class MainActivity extends BaseOboeTesterActivity {
     private Bundle mBundleFromIntent;
     private CheckBox mWorkaroundsCheckBox;
     private CheckBox mBackgroundCheckBox;
+    private CheckBox mForegroundServiceCheckBox;
     private static String mVersionText;
 
     @Override
@@ -111,9 +113,11 @@ public class MainActivity extends BaseOboeTesterActivity {
         NativeEngine.setWorkaroundsEnabled(false);
 
         mBackgroundCheckBox = (CheckBox) findViewById(R.id.boxEnableBackground);
+        mForegroundServiceCheckBox = (CheckBox) findViewById(R.id.boxEnableForegroundService);
 
         mBuildTextView = (TextView) findViewById(R.id.text_build_info);
-        mBuildTextView.setText(Build.DISPLAY);
+        mBuildTextView.setText(Build.DISPLAY
+                + "\n" + getSystemProperty("ro.build.date"));
 
         saveIntentBundleForLaterProcessing(getIntent());
     }
@@ -133,6 +137,7 @@ public class MainActivity extends BaseOboeTesterActivity {
 
     @Override
     public void onNewIntent(Intent intent) {
+        super.onNewIntent(intent);
         saveIntentBundleForLaterProcessing(intent);
     }
 
@@ -147,16 +152,19 @@ public class MainActivity extends BaseOboeTesterActivity {
         }
         Intent intent = getTestIntent(mBundleFromIntent);
         if (intent != null) {
-            setBackgroundFromIntent();
+            setTogglesFromIntent();
             startActivity(intent);
         }
         mBundleFromIntent = null;
     }
 
-    private void setBackgroundFromIntent() {
+    private void setTogglesFromIntent() {
         boolean backgroundEnabled = mBundleFromIntent.getBoolean(
                 IntentBasedTestSupport.KEY_BACKGROUND, false);
         TestAudioActivity.setBackgroundEnabled(backgroundEnabled);
+        boolean foregroundServiceEnabled = mBundleFromIntent.getBoolean(
+                IntentBasedTestSupport.KEY_FOREGROUND_SERVICE, false);
+        TestAudioActivity.setBackgroundEnabled(foregroundServiceEnabled);
     }
 
     private Intent getTestIntent(Bundle bundle) {
@@ -178,6 +186,9 @@ public class MainActivity extends BaseOboeTesterActivity {
             } else if (VALUE_TEST_NAME_OUTPUT.equals(testName)) {
                 intent = new Intent(this, TestOutputActivity.class);
                 intent.putExtras(bundle);
+            } else if (VALUE_TEST_NAME_CPU_LOAD.equals(testName)) {
+                intent = new Intent(this, DynamicWorkloadActivity.class);
+                intent.putExtras(bundle);
             }
         }
         return intent;
@@ -253,6 +264,7 @@ public class MainActivity extends BaseOboeTesterActivity {
 
         NativeEngine.setWorkaroundsEnabled(mWorkaroundsCheckBox.isChecked());
         TestAudioActivity.setBackgroundEnabled(mBackgroundCheckBox.isChecked());
+        TestAudioActivity.setForegroundServiceEnabled(mForegroundServiceCheckBox.isChecked());
     }
 
     @Override
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MicrophoneInfoConverter.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MicrophoneInfoConverter.java
index e96b4cb3..388bab95 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MicrophoneInfoConverter.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/MicrophoneInfoConverter.java
@@ -1,13 +1,15 @@
 package com.mobileer.oboetester;
 
+import android.annotation.TargetApi;
 import android.media.MicrophoneInfo;
+import android.os.Build;
 import android.util.Pair;
 
 import java.util.List;
 import java.util.Locale;
 
 public class MicrophoneInfoConverter {
-
+    @TargetApi(Build.VERSION_CODES.P)
     static String convertDirectionality(int directionality) {
         switch(directionality) {
             case MicrophoneInfo.DIRECTIONALITY_BI_DIRECTIONAL:
@@ -25,6 +27,7 @@ public class MicrophoneInfoConverter {
         }
     }
 
+    @TargetApi(Build.VERSION_CODES.P)
     static String convertLocation(int location) {
         switch(location) {
             case MicrophoneInfo.LOCATION_MAINBODY:
@@ -38,12 +41,14 @@ public class MicrophoneInfoConverter {
         }
     }
 
+    @TargetApi(Build.VERSION_CODES.P)
     static String convertCoordinates(MicrophoneInfo.Coordinate3F coordinates) {
         if (coordinates == MicrophoneInfo.POSITION_UNKNOWN) return "Unknown";
         return String.format(Locale.getDefault(), "{ %6.4g, %5.3g, %5.3g }",
                 coordinates.x, coordinates.y, coordinates.z);
     }
 
+    @TargetApi(Build.VERSION_CODES.P)
     public static String reportMicrophoneInfo(MicrophoneInfo micInfo) {
         StringBuffer sb = new StringBuffer();
         sb.append("\n==== Microphone ========= " + micInfo.getId());
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeEngine.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeEngine.java
index 985797b1..95129dba 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeEngine.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeEngine.java
@@ -13,4 +13,6 @@ public class NativeEngine {
     static native int getCpuCount();
 
     static native void setCpuAffinityMask(int mask);
+
+    static native void setWorkloadReportingEnabled(boolean enabled);
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeSniffer.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeSniffer.java
index 222173d7..bd871316 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeSniffer.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/NativeSniffer.java
@@ -27,8 +27,12 @@ abstract class NativeSniffer implements Runnable {
 
     @Override
     public void run() {
-        if (mEnabled && !isComplete()) {
+        if (!isComplete()) {
             updateStatusText();
+        }
+
+        // When this is no longer enabled, stop calling run.
+        if (mEnabled) {
             mHandler.postDelayed(this, SNIFFER_UPDATE_PERIOD_MSEC);
         }
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
index 5c8b2109..6f08767a 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/OboeAudioStream.java
@@ -67,7 +67,8 @@ abstract class OboeAudioStream extends AudioStreamBase {
                 requestedConfiguration.getFormatConversionAllowed(),
                 requestedConfiguration.getRateConversionQuality(),
                 requestedConfiguration.isMMap(),
-                isInput()
+                isInput(),
+                requestedConfiguration.getSpatializationBehavior()
         );
         if (result < 0) {
             streamIndex = INVALID_STREAM_INDEX;
@@ -100,6 +101,7 @@ abstract class OboeAudioStream extends AudioStreamBase {
         actualConfiguration.setHardwareChannelCount(getHardwareChannelCount());
         actualConfiguration.setHardwareSampleRate(getHardwareSampleRate());
         actualConfiguration.setHardwareFormat(getHardwareFormat());
+        actualConfiguration.setSpatializationBehavior(getSpatializationBehavior());
     }
 
     private native int openNative(
@@ -120,7 +122,8 @@ abstract class OboeAudioStream extends AudioStreamBase {
             boolean formatConversionAllowed,
             int rateConversionQuality,
             boolean isMMap,
-            boolean isInput);
+            boolean isInput,
+            int spatializationBehavior);
 
     @Override
     public void close() {
@@ -187,6 +190,11 @@ abstract class OboeAudioStream extends AudioStreamBase {
     }
     private native int getInputPreset(int streamIndex);
 
+    public int getSpatializationBehavior() {
+        return getSpatializationBehavior(streamIndex);
+    }
+    private native int getSpatializationBehavior(int streamIndex);
+
     public int getSampleRate() {
         return getSampleRate(streamIndex);
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/RoundTripLatencyActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/RoundTripLatencyActivity.java
index 8f81f558..9e323201 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/RoundTripLatencyActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/RoundTripLatencyActivity.java
@@ -21,10 +21,10 @@ import static com.mobileer.oboetester.IntentBasedTestSupport.configureStreamsFro
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
-import android.util.Log;
 import android.view.View;
 import android.widget.Button;
 import android.widget.TextView;
+
 import androidx.annotation.NonNull;
 
 import java.io.File;
@@ -47,17 +47,53 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
     private TextView mAnalyzerView;
     private Button   mMeasureButton;
     private Button   mAverageButton;
+    private Button   mScanButton;
     private Button   mCancelButton;
     private Button   mShareButton;
     private boolean  mHasRecording = false;
 
     private int     mBufferBursts = -1;
+    private int     mInputBufferCapacityInBursts = -1;
+    private int     mInputFramesPerBurst;
+    private int     mOutputBufferCapacityInBursts = -1;
+    private int     mOutputFramesPerBurst;
+    private int     mActualBufferBursts;
+    private boolean mOutputIsMMapExclusive;
+    private boolean mInputIsMMapExclusive;
+
     private Handler mHandler = new Handler(Looper.getMainLooper()); // UI thread
 
     DoubleStatistics mTimestampLatencyStats = new DoubleStatistics(); // for single measurement
 
+    protected abstract class MultipleLatencyTestRunner {
+        final static int AVERAGE_TEST_DELAY_MSEC = 1000; // arbitrary
+        boolean mActive;
+        String  mLastReport = "";
+
+        abstract String onAnalyserDone();
+
+        public abstract void start();
+
+        public void clear() {
+            mActive = false;
+            mLastReport = "";
+        }
+
+        public void cancel() {
+            mActive = false;
+        }
+
+        public boolean isActive() {
+            return mActive;
+        }
+
+        public String getLastReport() {
+            return mLastReport;
+        }
+    }
+
     // Run the test several times and report the average latency.
-    protected class AverageLatencyTestRunner {
+    protected class AverageLatencyTestRunner extends MultipleLatencyTestRunner {
         private final static int AVERAGE_TEST_DELAY_MSEC = 1000; // arbitrary
         private static final int GOOD_RUNS_REQUIRED = 5; // arbitrary
         private static final int MAX_BAD_RUNS_ALLOWED = 5; // arbitrary
@@ -66,14 +102,13 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
         DoubleStatistics mLatencies = new DoubleStatistics();
         DoubleStatistics mConfidences = new DoubleStatistics();
         DoubleStatistics mTimestampLatencies = new DoubleStatistics(); // for multiple measurements
-        private boolean mActive;
-        private String  mLastReport = "";
 
         private int getGoodCount() {
             return mLatencies.count();
         }
 
         // Called on UI thread.
+        @Override
         String onAnalyserDone() {
             String message;
             boolean reschedule = false;
@@ -155,6 +190,7 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
         }
 
         // Called on UI thread.
+        @Override
         public void start() {
             mLatencies = new DoubleStatistics();
             mConfidences = new DoubleStatistics();
@@ -165,30 +201,297 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
             measureSingleLatency();
         }
 
-        public void clear() {
-            mActive = false;
-            mLastReport = "";
+    }
+    AverageLatencyTestRunner mAverageLatencyTestRunner = new AverageLatencyTestRunner();
+    MultipleLatencyTestRunner mCurrentLatencyTestRunner = mAverageLatencyTestRunner;
+
+    /**
+     * Search for a discontinuity in latency based on a number of bursts.
+     * Use binary subdivision search algorithm.
+     */
+    protected static class BinaryDiscontinuityFinder {
+        public static final double MAX_ALLOWED_DEVIATION = 0.2;
+        // Run the test with various buffer sizes to detect DSP MMAP position errors.
+        private int mLowBufferBursts = 2;
+        private int mLowBufferLatency = -1;
+        private int mMiddleBufferBursts = -1;
+        private int mMiddleBufferLatency = -1;
+        private int mHighBufferBursts = -1;
+        private int mHighBufferLatency = -1;
+        private String mMessage = "---";
+
+        private static final int STATE_MEASURE_LOW = 1;
+        private static final int STATE_MEASURE_HIGH = 2;
+        private static final int STATE_MEASURE_MIDDLE = 3;
+        private static final int STATE_DONE = 4;
+        private int mState = STATE_MEASURE_LOW;
+        private int mFramesPerBurst;
+
+        public static final int RESULT_CONTINUE= 1;
+        public static final int RESULT_OK = 0;
+        public static final int RESULT_DISCONTINUITY = -1; // DSP is reading from the wrong place.
+        public static final int RESULT_ERROR = -2; // Could not measure latency
+        public static final int RESULT_UNDEFINED = -3; // Could not measure latency
+
+        public int getFramesPerBurst() {
+            return mFramesPerBurst;
         }
 
-        public void cancel() {
-            mActive = false;
+        public void setFramesPerBurst(int framesPerBurst) {
+            mFramesPerBurst = framesPerBurst;
         }
 
-        public boolean isActive() {
-            return mActive;
+        public String getMessage() {
+            return mMessage;
         }
 
-        public String getLastReport() {
-            return mLastReport;
+        public static class Result {
+            public int code = RESULT_UNDEFINED;
+            public int numBursts = -1;
+        }
+
+        /**
+         * @return Result object with number of bursts and a RESULT code
+         */
+        Result onAnalyserDone(int latencyFrames,
+                           double confidence,
+                           int actualBufferBursts,
+                           int capacityInBursts,
+                           boolean isMMapExclusive) {
+            Result result = new Result();
+            mMessage = "analyzing";
+            if (!isMMapExclusive) {
+                mMessage = "skipped, not MMAP Exclusive";
+                result.code = RESULT_OK;
+                return result;
+            }
+            result.code = RESULT_CONTINUE;
+            switch (mState) {
+                case STATE_MEASURE_LOW:
+                    mLowBufferLatency = latencyFrames;
+                    mLowBufferBursts = actualBufferBursts;
+                    // Now we measure the high side.
+                    mHighBufferBursts = capacityInBursts;
+                    result.code = RESULT_CONTINUE;
+                    result.numBursts = mHighBufferBursts;
+                    mMessage = "checked low bufferSize";
+                    mState = STATE_MEASURE_HIGH;
+                    break;
+                case STATE_MEASURE_HIGH:
+                    mMessage = "checked high bufferSize";
+                    mHighBufferLatency = latencyFrames;
+                    mHighBufferBursts = actualBufferBursts;
+                    if (measureLatencyLinearity(mLowBufferBursts,
+                            mLowBufferLatency,
+                            mHighBufferBursts,
+                            mHighBufferLatency) > MAX_ALLOWED_DEVIATION) {
+                        mState = STATE_MEASURE_MIDDLE;
+                    } else {
+                        result.code = RESULT_OK;
+                        mMessage = "DSP position looks good";
+                        mState = STATE_DONE;
+                    }
+                    break;
+                case STATE_MEASURE_MIDDLE:
+                    mMiddleBufferLatency = latencyFrames;
+                    mMiddleBufferBursts = actualBufferBursts;
+                    // Check to see which side is bad.
+                    if (confidence < 0.5) {
+                        // We may have landed on the DSP so we got a scrambled result.
+                        result.code = RESULT_DISCONTINUITY;
+                        mMessage = "on top of DSP!";
+                        mState = STATE_DONE;
+                    } else  {
+                        double deviationLow = measureLatencyLinearity(
+                                mLowBufferBursts,
+                                mLowBufferLatency,
+                                mMiddleBufferBursts,
+                                mMiddleBufferLatency);
+                        double deviationHigh = measureLatencyLinearity(
+                                mMiddleBufferBursts,
+                                mMiddleBufferLatency,
+                                mHighBufferBursts,
+                                mHighBufferLatency);
+                        if (deviationLow >= deviationHigh) {
+                            // bottom half was bad so subdivide it
+                            mHighBufferBursts = mMiddleBufferBursts;
+                            mHighBufferLatency = mMiddleBufferLatency;
+                            mMessage = "low half not linear";
+                        } else {
+                            // top half was bad so subdivide it
+                            mLowBufferBursts = mMiddleBufferBursts;
+                            mLowBufferLatency = mMiddleBufferLatency;
+                            mMessage = "high half not linear";
+                        }
+                    }
+                    break;
+                default:
+                    break;
+            }
+
+            if (result.code == RESULT_CONTINUE) {
+                if (mState == STATE_MEASURE_MIDDLE) {
+                    if ((mHighBufferBursts - mLowBufferBursts) <= 1) {
+                        result.code = RESULT_DISCONTINUITY;
+                        mMessage = "ERROR - DSP position error between "
+                                + mLowBufferBursts + " and "
+                                + mHighBufferBursts + " bursts!";
+                    } else {
+                        // Subdivide the remaining search space.
+                        mMiddleBufferBursts = (mHighBufferBursts + mLowBufferBursts) / 2;
+                        result.numBursts = mMiddleBufferBursts;
+                    }
+                }
+            } else if (result.code == RESULT_OK) {
+                mMessage = "PASS - no discontinuity";
+            }
+            return result;
+        }
+
+        private double measureLatencyLinearity(int bufferBursts1, int bufferLatency1,
+                                                int bufferBursts2, int bufferLatency2) {
+            int bufferFrames1 = bufferBursts1 * mFramesPerBurst;
+            int bufferFrames2 = bufferBursts2 * mFramesPerBurst;
+            int expectedLatencyDifference = bufferFrames2 - bufferFrames1;
+            int actualLatencyDifference = bufferLatency2 - bufferLatency1;
+            return Math.abs(expectedLatencyDifference - actualLatencyDifference)
+                    / (double) expectedLatencyDifference;
+        }
+
+        private String reportResults(String prefix) {
+            String message;
+            message = prefix + "buffer.bursts.low = " + mLowBufferBursts + "\n";
+            message += prefix + "latency.frames.low = " + mLowBufferLatency + "\n";
+            message += prefix + "buffer.bursts.high = " + mHighBufferBursts + "\n";
+            message += prefix + "latency.frames.high = " + mHighBufferLatency + "\n";
+            message += prefix + "result = " + mMessage + "\n";
+            return message;
         }
     }
-    AverageLatencyTestRunner mAverageLatencyTestRunner = new AverageLatencyTestRunner();
+
+    protected class ScanLatencyTestRunner extends MultipleLatencyTestRunner {
+        BinaryDiscontinuityFinder inputFinder;
+        BinaryDiscontinuityFinder outputFinder;
+        private static final int MAX_BAD_RUNS_ALLOWED = 5; // arbitrary
+        private int mBadCount = 0; // number of bad measurements
+
+        private static final int STATE_SCANNING_OUTPUT = 0;
+        private static final int STATE_SCANNING_INPUT = 1;
+        private static final int STATE_DONE = 2;
+        private int mState = STATE_SCANNING_OUTPUT;
+
+        // Called on UI thread after each single latency measurement is complete.
+        // It decides whether the series is complete or more measurements are needed.
+        // If more measurements are needed then it sets mBufferBursts for Output or mInputMarginBursts for Input
+        // It keeps moving the low and high sizes until it bounds the discontinuity within a single burst.
+        @Override
+        String onAnalyserDone() {
+            BinaryDiscontinuityFinder.Result result = new BinaryDiscontinuityFinder.Result();
+            result.code = BinaryDiscontinuityFinder.RESULT_OK;
+            String message = "";
+
+            if (!mActive) {
+                message = "done";
+            } else if (getMeasuredResult() != 0) {
+                mBadCount++;
+                if (mBadCount > MAX_BAD_RUNS_ALLOWED) {
+                    cancel();
+                    result.code = BinaryDiscontinuityFinder.RESULT_ERROR;
+                    updateButtons(false);
+                    message = "scanning cancelled due to error, " + mBadCount + " bad runs\n";
+                } else {
+                    message = "skipping this bad run, "
+                            + mBadCount + " of " + MAX_BAD_RUNS_ALLOWED + " max\n";
+                    result.numBursts = mActualBufferBursts;
+                }
+            } else {
+                switch (mState) {
+                    case STATE_SCANNING_OUTPUT:
+                        outputFinder.setFramesPerBurst(mOutputFramesPerBurst);
+                        result = outputFinder.onAnalyserDone(getMeasuredLatency(),
+                                getMeasuredConfidence(),
+                                mActualBufferBursts,
+                                mOutputBufferCapacityInBursts,
+                                mOutputIsMMapExclusive);
+                        mBufferBursts = result.numBursts;
+                        mInputMarginBursts = 0;
+                        break;
+                    case STATE_SCANNING_INPUT:
+                        inputFinder.setFramesPerBurst(mInputFramesPerBurst);
+                        result = inputFinder.onAnalyserDone(getMeasuredLatency(),
+                                getMeasuredConfidence(),
+                                mInputMarginBursts,
+                                mInputBufferCapacityInBursts,
+                                mInputIsMMapExclusive);
+                        mBufferBursts = -1;
+                        mInputMarginBursts = Math.min(result.numBursts,
+                                mInputBufferCapacityInBursts - 1);
+                        break;
+                }
+            }
+
+            if (result.code == BinaryDiscontinuityFinder.RESULT_CONTINUE) {
+                runAnotherTest();
+            } else {
+                // We finished one series.
+                mBufferBursts = -1;
+                mInputMarginBursts = 0;
+                switch (mState) {
+                    case STATE_SCANNING_OUTPUT:
+                        // Finished an output series to start an input series.
+                        mState = STATE_SCANNING_INPUT;
+                        runAnotherTest();
+                        break;
+                    case STATE_SCANNING_INPUT:
+                        mActive = false;
+                        updateButtons(false);
+                        mState = STATE_DONE;
+                        break;
+                }
+            }
+            message += reportResults();
+            return message;
+        }
+
+        private void runAnotherTest() {
+            mHandler.postDelayed(new Runnable() {
+                @Override
+                public void run() {
+                    measureSingleLatency();
+                }
+            }, AVERAGE_TEST_DELAY_MSEC);
+        }
+
+        private String reportResults() {
+            String message = "test = check MMAP DSP position\n";
+            message += outputFinder.reportResults("output.");
+            message += "\n"; // separator between in/out
+            message += inputFinder.reportResults("input.");
+            mLastReport = message;
+            return message;
+        }
+
+        // Called on UI thread.
+        @Override
+        public void start() {
+            mBadCount = 0;
+            inputFinder = new BinaryDiscontinuityFinder();
+            outputFinder = new BinaryDiscontinuityFinder();
+            mState = STATE_SCANNING_OUTPUT;
+            mBufferBursts = 2;
+            mActive = true;
+            mLastReport = "";
+            measureSingleLatency();
+        }
+    }
+    ScanLatencyTestRunner mScanLatencyTestRunner = new ScanLatencyTestRunner();
 
     // Periodically query the status of the stream.
     protected class LatencySniffer {
-        private int counter = 0;
+        private int mCounter = 0;
         public static final int SNIFFER_UPDATE_PERIOD_MSEC = 150;
         public static final int SNIFFER_UPDATE_DELAY_MSEC = 300;
+        public static final int SNIFFER_MAX_COUNTER = 30 * 1000 / SNIFFER_UPDATE_PERIOD_MSEC;
 
         // Display status info for the stream.
         private Runnable runnableCode = new Runnable() {
@@ -206,8 +509,8 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
 
                 String message;
                 if (isAnalyzerDone()) {
-                    if (mAverageLatencyTestRunner.isActive()) {
-                        message = mAverageLatencyTestRunner.onAnalyserDone();
+                    if (mCurrentLatencyTestRunner.isActive()) {
+                        message = mCurrentLatencyTestRunner.onAnalyserDone();
                     } else {
                         message = getResultString();
                     }
@@ -215,21 +518,24 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
                     if (resultFile != null) {
                         message = "result.file = " + resultFile.getAbsolutePath() + "\n" + message;
                     }
+                } else if (mCounter > SNIFFER_MAX_COUNTER) {
+                    message = getProgressText();
+                    message += convertStateToString(getAnalyzerState()) + "\n";
+                    message += "TIMEOUT after " + mCounter + " loops!\n";
                 } else {
                     message = getProgressText();
-                    message += "please wait... " + counter + "\n";
+                    message += "please wait... " + mCounter + "\n";
                     message += convertStateToString(getAnalyzerState()) + "\n";
-
                     // Repeat this runnable code block again.
                     mHandler.postDelayed(runnableCode, SNIFFER_UPDATE_PERIOD_MSEC);
                 }
                 setAnalyzerText(message);
-                counter++;
+                mCounter++;
             }
         };
 
         private void startSniffer() {
-            counter = 0;
+            mCounter = 0;
             // Start the initial runnable task by posting through the handler
             mHandler.postDelayed(runnableCode, SNIFFER_UPDATE_DELAY_MSEC);
         }
@@ -256,7 +562,7 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
         int resetCount = getResetCount();
         String message = String.format(Locale.getDefault(), "progress = %d\nstate = %d\n#resets = %d\n",
                 progress, state, resetCount);
-        message += mAverageLatencyTestRunner.getLastReport();
+        message += mCurrentLatencyTestRunner.getLastReport();
         return message;
     }
 
@@ -347,6 +653,7 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
         super.onCreate(savedInstanceState);
         mMeasureButton = (Button) findViewById(R.id.button_measure);
         mAverageButton = (Button) findViewById(R.id.button_average);
+        mScanButton = (Button) findViewById(R.id.button_scan);
         mCancelButton = (Button) findViewById(R.id.button_cancel);
         mShareButton = (Button) findViewById(R.id.button_share);
         mShareButton.setEnabled(false);
@@ -358,7 +665,6 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
         mBufferSizeView.setFaderNormalizedProgress(0.0); // for lowest latency
 
         mCommunicationDeviceView = (CommunicationDeviceView) findViewById(R.id.comm_device_view);
-
     }
 
     @Override
@@ -395,14 +701,15 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
     }
 
     public void onMeasure(View view) {
-        mAverageLatencyTestRunner.clear();
+        mCurrentLatencyTestRunner.clear();
         measureSingleLatency();
     }
 
     void updateButtons(boolean running) {
-        boolean busy = running || mAverageLatencyTestRunner.isActive();
+        boolean busy = running || mCurrentLatencyTestRunner.isActive();
         mMeasureButton.setEnabled(!busy);
         mAverageButton.setEnabled(!busy);
+        mScanButton.setEnabled(!busy && NativeEngine.isMMapExclusiveSupported());
         mCancelButton.setEnabled(running);
         mShareButton.setEnabled(!busy && mHasRecording);
     }
@@ -410,14 +717,25 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
     private void measureSingleLatency() {
         try {
             openAudio();
+            AudioStreamBase outputStream = mAudioOutTester.getCurrentAudioStream();
+            mOutputFramesPerBurst = outputStream.getFramesPerBurst();
+            mOutputBufferCapacityInBursts = outputStream.getBufferCapacityInFrames() / mOutputFramesPerBurst ;
+            mOutputIsMMapExclusive = mAudioOutTester.actualConfiguration.getSharingMode()
+                    == StreamConfiguration.SHARING_MODE_EXCLUSIVE;
+            AudioStreamBase inputStream = mAudioInputTester.getCurrentAudioStream();
+            mInputFramesPerBurst = inputStream.getFramesPerBurst();
+            mInputBufferCapacityInBursts = inputStream.getBufferCapacityInFrames() / mInputFramesPerBurst ;
+            mInputIsMMapExclusive = mAudioInputTester.actualConfiguration.getSharingMode()
+                    == StreamConfiguration.SHARING_MODE_EXCLUSIVE;
+
             if (mBufferBursts >= 0) {
-                AudioStreamBase stream = mAudioOutTester.getCurrentAudioStream();
-                int framesPerBurst = stream.getFramesPerBurst();
-                stream.setBufferSizeInFrames(framesPerBurst * mBufferBursts);
+                int actualBufferSizeInFrames = outputStream.setBufferSizeInFrames(mOutputFramesPerBurst * mBufferBursts);
+                mActualBufferBursts = actualBufferSizeInFrames / mOutputFramesPerBurst;
                 // override buffer size fader
                 mBufferSizeView.setEnabled(false);
                 mBufferBursts = -1;
             }
+
             startAudio();
             mTimestampLatencyStats  = new DoubleStatistics();
             mLatencySniffer.startSniffer();
@@ -428,11 +746,17 @@ public class RoundTripLatencyActivity extends AnalyzerActivity {
     }
 
     public void onAverage(View view) {
-        mAverageLatencyTestRunner.start();
+        mCurrentLatencyTestRunner = mAverageLatencyTestRunner;
+        mCurrentLatencyTestRunner.start();
+    }
+
+    public void onScan(View view) {
+        mCurrentLatencyTestRunner = mScanLatencyTestRunner;
+        mCurrentLatencyTestRunner.start();
     }
 
     public void onCancel(View view) {
-        mAverageLatencyTestRunner.cancel();
+        mCurrentLatencyTestRunner.cancel();
         stopAudioTest();
     }
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
index 5c1f32b7..56a74d7f 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfiguration.java
@@ -16,8 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.content.res.Resources;
-
 import java.util.ArrayList;
 import java.util.HashMap;
 import java.util.List;
@@ -56,6 +54,7 @@ public class StreamConfiguration {
     public static final int PERFORMANCE_MODE_NONE = 10; // must match AAUDIO
     public static final int PERFORMANCE_MODE_POWER_SAVING = 11; // must match AAUDIO
     public static final int PERFORMANCE_MODE_LOW_LATENCY = 12; // must match AAUDIO
+    public static final int PERFORMANCE_MODE_POWER_SAVING_OFFLOAD = 13; // must match AAUDIO
 
     public static final int RATE_CONVERSION_QUALITY_NONE = 0; // must match Oboe
     public static final int RATE_CONVERSION_QUALITY_FASTEST = 1; // must match Oboe
@@ -74,6 +73,9 @@ public class StreamConfiguration {
     public static final int INPUT_PRESET_UNPROCESSED = 9; // must match Oboe
     public static final int INPUT_PRESET_VOICE_PERFORMANCE = 10; // must match Oboe
 
+    public static final int SPATIALIZATION_BEHAVIOR_AUTO = 1; // must match Oboe
+    public static final int SPATIALIZATION_BEHAVIOR_NEVER = 2; // must match Oboe
+
     public static final int ERROR_BASE = -900; // must match Oboe
     public static final int ERROR_DISCONNECTED = -899; // must match Oboe
     public static final int ERROR_ILLEGAL_ARGUMENT = -898; // must match Oboe
@@ -300,6 +302,7 @@ public class StreamConfiguration {
     private int mHardwareChannelCount;
     private int mHardwareSampleRate;
     private int mHardwareFormat;
+    private int mSpatializationBehavior;
 
     public StreamConfiguration() {
         reset();
@@ -353,6 +356,7 @@ public class StreamConfiguration {
         mHardwareChannelCount = UNSPECIFIED;
         mHardwareSampleRate = UNSPECIFIED;
         mHardwareFormat = UNSPECIFIED;
+        mSpatializationBehavior = UNSPECIFIED;
     }
 
     public int getFramesPerBurst() {
@@ -403,6 +407,8 @@ public class StreamConfiguration {
                 return "PS";
             case PERFORMANCE_MODE_LOW_LATENCY:
                 return "LL";
+            case PERFORMANCE_MODE_POWER_SAVING_OFFLOAD:
+                return "PSO";
             default:
                 return "??";
         }
@@ -413,6 +419,11 @@ public class StreamConfiguration {
         this.mInputPreset = inputPreset;
     }
 
+    public int getSpatializationBehavior() { return mSpatializationBehavior; }
+    public void setSpatializationBehavior(int spatializationBehavior) {
+        this.mSpatializationBehavior = spatializationBehavior;
+    }
+
     public int getUsage() { return mUsage; }
     public void setUsage(int usage) {
         this.mUsage = usage;
@@ -642,6 +653,8 @@ public class StreamConfiguration {
         message.append(String.format(Locale.getDefault(), "%s.hardware.sampleRate = %d\n", prefix, mHardwareSampleRate));
         message.append(String.format(Locale.getDefault(), "%s.hardware.format = %s\n", prefix,
                 convertFormatToText(mHardwareFormat).toLowerCase(Locale.getDefault())));
+        message.append(String.format(Locale.getDefault(), "%s.spatializationBehavior = %s\n", prefix,
+                convertSpatializationBehaviorToText(mSpatializationBehavior).toLowerCase(Locale.getDefault())));
         return message.toString();
     }
 
@@ -699,6 +712,45 @@ public class StreamConfiguration {
         return -1;
     }
 
+    // text must match menu values
+    public static final String NAME_SPATIALIZATION_BEHAVIOR_UNSPECIFIED = "Unspecified";
+    public static final String NAME_SPATIALIZATION_BEHAVIOR_AUTO = "Auto";
+    public static final String NAME_SPATIALIZATION_BEHAVIOR_NEVER = "Never";
+
+    public static String convertSpatializationBehaviorToText(int spatializationBehavior) {
+        switch(spatializationBehavior) {
+            case UNSPECIFIED:
+                return NAME_SPATIALIZATION_BEHAVIOR_UNSPECIFIED;
+            case SPATIALIZATION_BEHAVIOR_AUTO:
+                return NAME_SPATIALIZATION_BEHAVIOR_AUTO;
+            case SPATIALIZATION_BEHAVIOR_NEVER:
+                return NAME_SPATIALIZATION_BEHAVIOR_NEVER;
+            default:
+                return "Invalid";
+        }
+    }
+
+    private static boolean matchSpatializationBehavior(String text, int spatializationBehavior) {
+        return convertSpatializationBehaviorToText(spatializationBehavior).toLowerCase(Locale.getDefault()).equals(text);
+    }
+
+    /**
+     * Case insensitive.
+     * @param text
+     * @return spatializationBehavior, eg. SPATIALIZATION_BEHAVIOR_NEVER
+     */
+    public static int convertTextToSpatializationBehavior(String text) {
+        text = text.toLowerCase(Locale.getDefault());
+        if (matchSpatializationBehavior(text, UNSPECIFIED)) {
+            return UNSPECIFIED;
+        } else if (matchSpatializationBehavior(text, SPATIALIZATION_BEHAVIOR_AUTO)) {
+            return SPATIALIZATION_BEHAVIOR_AUTO;
+        } else if (matchSpatializationBehavior(text, SPATIALIZATION_BEHAVIOR_NEVER)) {
+            return SPATIALIZATION_BEHAVIOR_NEVER;
+        }
+        return -1;
+    }
+
     public int getChannelCount() {
         return mChannelCount;
     }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
index 9a6fd266..c0ffe3b7 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/StreamConfigurationView.java
@@ -22,19 +22,20 @@ import android.media.audiofx.AcousticEchoCanceler;
 import android.media.audiofx.AutomaticGainControl;
 import android.media.audiofx.BassBoost;
 import android.media.audiofx.LoudnessEnhancer;
+import android.media.audiofx.NoiseSuppressor;
 import android.util.AttributeSet;
+import android.util.Log;
 import android.view.LayoutInflater;
 import android.view.View;
 import android.widget.AdapterView;
 import android.widget.ArrayAdapter;
 import android.widget.CheckBox;
 import android.widget.CompoundButton;
+import android.widget.LinearLayout;
 import android.widget.SeekBar;
 import android.widget.Spinner;
 import android.widget.TableRow;
 import android.widget.TextView;
-import android.widget.LinearLayout;
-import android.util.Log;
 
 import com.mobileer.audio_device.AudioDeviceListEntry;
 import com.mobileer.audio_device.AudioDeviceSpinner;
@@ -51,6 +52,7 @@ public class StreamConfigurationView extends LinearLayout {
 
     protected Spinner mNativeApiSpinner;
     private TextView mActualNativeApiView;
+    private TextView mActualDeviceIdView;
 
     private TextView mActualMMapView;
     private CheckBox mRequestedMMapView;
@@ -79,6 +81,10 @@ public class StreamConfigurationView extends LinearLayout {
     private Spinner  mContentTypeSpinner;
     private TextView mActualContentTypeView;
 
+    private TableRow mSpatializationBehaviorTableRow;
+    private Spinner  mSpatializationBehaviorSpinner;
+    private TextView mActualSpatializationBehaviorView;
+
     private Spinner  mFormatSpinner;
     private Spinner  mSampleRateSpinner;
     private Spinner  mRateConversionQualitySpinner;
@@ -88,6 +94,7 @@ public class StreamConfigurationView extends LinearLayout {
     private AudioDeviceSpinner mDeviceSpinner;
     private TextView mActualSessionIdView;
     private CheckBox mRequestAudioEffect;
+    private CheckBox mRequestSessionId;
 
     private TextView mStreamInfoView;
     private TextView mStreamStatusView;
@@ -99,7 +106,11 @@ public class StreamConfigurationView extends LinearLayout {
     private LinearLayout mOutputEffectsLayout;
 
     private CheckBox mAutomaticGainControlCheckBox;
+    private CharSequence mAutomaticGainControlText;
     private CheckBox mAcousticEchoCancelerCheckBox;
+    private CharSequence mAcousticEchoCancelerText;
+    private CheckBox mNoiseSuppressorCheckBox;
+    private CharSequence mNoiseSuppressorText;
     private TextView mBassBoostTextView;
     private SeekBar mBassBoostSeekBar;
     private TextView mLoudnessEnhancerTextView;
@@ -111,8 +122,9 @@ public class StreamConfigurationView extends LinearLayout {
 
     private BassBoost mBassBoost;
     private LoudnessEnhancer mLoudnessEnhancer;
-    private AcousticEchoCanceler mAcousticEchoCanceler;
     private AutomaticGainControl mAutomaticGainControl;
+    private AcousticEchoCanceler mAcousticEchoCanceler;
+    private NoiseSuppressor mNoiseSuppressor;
 
     // Create an anonymous implementation of OnClickListener
     private View.OnClickListener mToggleListener = new View.OnClickListener() {
@@ -194,6 +206,8 @@ public class StreamConfigurationView extends LinearLayout {
 
         mActualNativeApiView = (TextView) findViewById(R.id.actualNativeApi);
 
+        mActualDeviceIdView = (TextView) findViewById(R.id.actualDeviceId);
+
         mChannelConversionBox = (CheckBox) findViewById(R.id.checkChannelConversion);
 
         mFormatConversionBox = (CheckBox) findViewById(R.id.checkFormatConversion);
@@ -211,6 +225,7 @@ public class StreamConfigurationView extends LinearLayout {
         mRequestedExclusiveView.setEnabled(mmapExclusiveSupported);
         mRequestedExclusiveView.setChecked(mmapExclusiveSupported);
 
+        mRequestSessionId = (CheckBox) findViewById(R.id.requestSessionId);
         mActualSessionIdView = (TextView) findViewById(R.id.sessionId);
         mRequestAudioEffect = (CheckBox) findViewById(R.id.requestAudioEffect);
 
@@ -226,13 +241,18 @@ public class StreamConfigurationView extends LinearLayout {
 
         mAutomaticGainControlCheckBox = (CheckBox) findViewById(R.id.checkBoxAutomaticGainControl);
         mAcousticEchoCancelerCheckBox = (CheckBox) findViewById(R.id.checkBoxAcousticEchoCanceler);
+        mNoiseSuppressorCheckBox = (CheckBox) findViewById(R.id.checkBoxNoiseSuppressor);
         mBassBoostTextView = (TextView) findViewById(R.id.textBassBoost);
         mBassBoostSeekBar = (SeekBar) findViewById(R.id.seekBarBassBoost);
         mLoudnessEnhancerTextView = (TextView) findViewById(R.id.textLoudnessEnhancer);
         mLoudnessEnhancerSeekBar = (SeekBar) findViewById(R.id.seekBarLoudnessEnhancer);
 
         mAutomaticGainControlCheckBox.setEnabled(AutomaticGainControl.isAvailable());
+        mAutomaticGainControlText = mAutomaticGainControlCheckBox.getText();
         mAcousticEchoCancelerCheckBox.setEnabled(AcousticEchoCanceler.isAvailable());
+        mAcousticEchoCancelerText = mAcousticEchoCancelerCheckBox.getText();
+        mNoiseSuppressorCheckBox.setEnabled(NoiseSuppressor.isAvailable());
+        mNoiseSuppressorText = mNoiseSuppressorCheckBox.getText();
 
         mBassBoostSeekBar.setOnSeekBarChangeListener(new SeekBar.OnSeekBarChangeListener() {
             public void onProgressChanged(SeekBar seekBar, int progress, boolean fromUser) {
@@ -273,6 +293,11 @@ public class StreamConfigurationView extends LinearLayout {
                 onAcousticEchoCancelerCheckBoxChanged(isChecked);
             }
         });
+        mNoiseSuppressorCheckBox.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
+            public void onCheckedChanged(CompoundButton buttonView, boolean isChecked) {
+                onNoiseSuppressorCheckBoxChanged(isChecked);
+            }
+        });
 
         mActualSampleRateView = (TextView) findViewById(R.id.actualSampleRate);
         mSampleRateSpinner = (Spinner) findViewById(R.id.spinnerSampleRate);
@@ -315,6 +340,10 @@ public class StreamConfigurationView extends LinearLayout {
         mActualContentTypeView = (TextView) findViewById(R.id.actualContentType);
         mContentTypeSpinner = (Spinner) findViewById(R.id.spinnerContentType);
 
+        mSpatializationBehaviorTableRow = (TableRow) findViewById(R.id.rowSpatializationBehavior);
+        mActualSpatializationBehaviorView = (TextView) findViewById(R.id.actualSpatializationBehavior);
+        mSpatializationBehaviorSpinner = (Spinner) findViewById(R.id.spinnerSpatializationBehavior);
+
         mStreamInfoView = (TextView) findViewById(R.id.streamInfo);
 
         mStreamStatusView = (TextView) findViewById(R.id.statusView);
@@ -388,6 +417,10 @@ public class StreamConfigurationView extends LinearLayout {
         int contentType = StreamConfiguration.convertTextToContentType(text);
         config.setContentType(contentType);
 
+        text = mSpatializationBehaviorSpinner.getSelectedItem().toString();
+        int spatializationBehavior = StreamConfiguration.convertTextToSpatializationBehavior(text);
+        config.setSpatializationBehavior(spatializationBehavior);
+
         // The corresponding channel count of the selected channel mask may be different from
         // the selected channel count, the last selected will be respected.
         if (mIsChannelMaskLastSelected) {
@@ -412,7 +445,7 @@ public class StreamConfigurationView extends LinearLayout {
         config.setSharingMode(mRequestedExclusiveView.isChecked()
                 ? StreamConfiguration.SHARING_MODE_EXCLUSIVE
                 : StreamConfiguration.SHARING_MODE_SHARED);
-        config.setSessionId(mRequestAudioEffect.isChecked()
+        config.setSessionId(mRequestSessionId.isChecked()
                 ? StreamConfiguration.SESSION_ID_ALLOCATE
                 : StreamConfiguration.SESSION_ID_NONE);
 
@@ -434,9 +467,11 @@ public class StreamConfigurationView extends LinearLayout {
         mUsageSpinner.setEnabled(enabled);
         mContentTypeSpinner.setEnabled(enabled);
         mFormatSpinner.setEnabled(enabled);
+        mSpatializationBehaviorSpinner.setEnabled(enabled);
         mSampleRateSpinner.setEnabled(enabled);
         mRateConversionQualitySpinner.setEnabled(enabled);
         mDeviceSpinner.setEnabled(enabled);
+        mRequestSessionId.setEnabled(enabled);
         mRequestAudioEffect.setEnabled(enabled);
     }
 
@@ -447,6 +482,9 @@ public class StreamConfigurationView extends LinearLayout {
         value = actualConfiguration.getNativeApi();
         mActualNativeApiView.setText(StreamConfiguration.convertNativeApiToText(value));
 
+        value = actualConfiguration.getDeviceId();
+        mActualDeviceIdView.setText(String.valueOf(value));
+
         mActualMMapView.setText(yesOrNo(actualConfiguration.isMMap()));
         int sharingMode = actualConfiguration.getSharingMode();
         boolean isExclusive = (sharingMode == StreamConfiguration.SHARING_MODE_EXCLUSIVE);
@@ -472,6 +510,10 @@ public class StreamConfigurationView extends LinearLayout {
         mActualContentTypeView.setText(StreamConfiguration.convertContentTypeToText(value));
         mActualContentTypeView.requestLayout();
 
+        value = actualConfiguration.getSpatializationBehavior();
+        mActualSpatializationBehaviorView.setText(StreamConfiguration.convertSpatializationBehaviorToText(value));
+        mActualSpatializationBehaviorView.requestLayout();
+
         mActualChannelCountView.setText(actualConfiguration.getChannelCount() + "");
         mActualSampleRateView.setText(actualConfiguration.getSampleRate() + "");
         mActualSessionIdView.setText("S#: " + actualConfiguration.getSessionId());
@@ -534,13 +576,16 @@ public class StreamConfigurationView extends LinearLayout {
     }
 
     private void onRequestAudioEffectClicked(boolean isChecked) {
-        if (isChecked){
+        if (isChecked) {
+            mRequestSessionId.setEnabled(false);
+            mRequestSessionId.setChecked(true);
             if (misOutput) {
                 mOutputEffectsLayout.setVisibility(VISIBLE);
             } else {
                 mInputEffectsLayout.setVisibility(VISIBLE);
             }
         } else {
+            mRequestSessionId.setEnabled(true);
             if (misOutput) {
                 mOutputEffectsLayout.setVisibility(GONE);
             } else {
@@ -550,6 +595,9 @@ public class StreamConfigurationView extends LinearLayout {
     }
 
     public void setupEffects(int sessionId) {
+        if (!mRequestAudioEffect.isChecked()) {
+            return;
+        }
         if (misOutput) {
             mBassBoost = new BassBoost(0, sessionId);
             mBassBoost.setStrength((short) mBassBoostSeekBar.getProgress());
@@ -560,20 +608,40 @@ public class StreamConfigurationView extends LinearLayout {
             if (mAcousticEchoCancelerCheckBox.isEnabled()) {
                 mAcousticEchoCanceler = AcousticEchoCanceler.create(sessionId);
                 if (mAcousticEchoCanceler != null) {
+                    boolean wasOn = mAcousticEchoCanceler.getEnabled();
+                    String text = mAcousticEchoCancelerText + "(" + (wasOn ? "Y" : "N") + ")";
+                    mAcousticEchoCancelerCheckBox.setText(text);
                     mAcousticEchoCanceler.setEnabled(mAcousticEchoCancelerCheckBox.isChecked());
                 } else {
                     Log.e(TAG, String.format(Locale.getDefault(), "Could not create AcousticEchoCanceler"));
                 }
             }
+
             // If AGC is not available, the checkbox will be disabled in initializeViews().
             if (mAutomaticGainControlCheckBox.isEnabled()) {
                 mAutomaticGainControl = AutomaticGainControl.create(sessionId);
                 if (mAutomaticGainControl != null) {
+                    boolean wasOn = mAutomaticGainControl.getEnabled();
+                    String text = mAutomaticGainControlText + "(" + (wasOn ? "Y" : "N") + ")";
+                    mAutomaticGainControlCheckBox.setText(text);
                     mAutomaticGainControl.setEnabled(mAutomaticGainControlCheckBox.isChecked());
                 } else {
                     Log.e(TAG, String.format(Locale.getDefault(), "Could not create AutomaticGainControl"));
                 }
             }
+
+            // If Noise Suppressor is not available, the checkbox will be disabled in initializeViews().
+            if (mNoiseSuppressorCheckBox.isEnabled()) {
+                mNoiseSuppressor = NoiseSuppressor.create(sessionId);
+                if (mNoiseSuppressor != null) {
+                    boolean wasOn = mNoiseSuppressor.getEnabled();
+                    String text = mNoiseSuppressorText + "(" + (wasOn ? "Y" : "N") + ")";
+                    mNoiseSuppressorCheckBox.setText(text);
+                    mNoiseSuppressor.setEnabled(mNoiseSuppressorCheckBox.isChecked());
+                } else {
+                    Log.e(TAG, String.format(Locale.getDefault(), "Could not create NoiseSuppressor"));
+                }
+            }
         }
     }
 
@@ -602,4 +670,10 @@ public class StreamConfigurationView extends LinearLayout {
             mAcousticEchoCanceler.setEnabled(isChecked);
         }
     }
+
+    private void onNoiseSuppressorCheckBoxChanged(boolean isChecked) {
+        if (mNoiseSuppressorCheckBox.isEnabled() && mNoiseSuppressor != null) {
+            mNoiseSuppressor.setEnabled(isChecked);
+        }
+    }
 }
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TapToToneActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TapToToneActivity.java
index ad2c3c97..26c7dc3e 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TapToToneActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TapToToneActivity.java
@@ -16,7 +16,8 @@
 
 package com.mobileer.oboetester;
 
-import android.Manifest;
+import static com.mobileer.oboetester.MidiTapTester.NoteListener;
+
 import android.content.pm.PackageManager;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
@@ -28,12 +29,9 @@ import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
 import android.util.Log;
-import android.view.Menu;
-import android.view.MenuItem;
 import android.view.MotionEvent;
 import android.view.View;
 import android.view.WindowManager;
-import android.widget.AdapterView;
 import android.widget.Button;
 import android.widget.Toast;
 
@@ -46,8 +44,6 @@ import com.mobileer.miditools.MidiTools;
 import java.io.IOException;
 import java.sql.Timestamp;
 
-import static com.mobileer.oboetester.MidiTapTester.NoteListener;
-
 public class TapToToneActivity extends TestOutputActivityBase {
     // Names from obsolete version of Oboetester.
     public static final String OLD_PRODUCT_NAME = "AudioLatencyTester";
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
index 9043f28d..f286ffbb 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestAudioActivity.java
@@ -16,11 +16,14 @@
 
 package com.mobileer.oboetester;
 
-import android.app.Activity;
+import static com.mobileer.oboetester.AudioForegroundService.ACTION_START;
+import static com.mobileer.oboetester.AudioForegroundService.ACTION_STOP;
+
 import android.content.Context;
 import android.content.Intent;
 import android.content.pm.PackageInfo;
 import android.content.pm.PackageManager;
+import android.content.pm.ServiceInfo;
 import android.media.AudioAttributes;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
@@ -36,7 +39,9 @@ import android.widget.Button;
 import android.widget.CheckBox;
 import android.widget.Spinner;
 import android.widget.Toast;
+
 import androidx.annotation.NonNull;
+import androidx.appcompat.app.AppCompatActivity;
 
 import java.io.File;
 import java.io.IOException;
@@ -46,7 +51,7 @@ import java.util.Locale;
 /**
  * Base class for other Activities.
  */
-abstract class TestAudioActivity extends Activity {
+abstract class TestAudioActivity extends AppCompatActivity {
     public static final String TAG = "OboeTester";
 
     protected static final int FADER_PROGRESS_MAX = 1000;
@@ -96,6 +101,7 @@ abstract class TestAudioActivity extends Activity {
     private int mSampleRate;
     private int mSingleTestIndex = -1;
     private static boolean mBackgroundEnabled;
+    private static boolean mForegroundServiceEnabled;
 
     protected Bundle mBundleFromIntent;
     protected boolean mTestRunningByIntent;
@@ -182,6 +188,49 @@ abstract class TestAudioActivity extends Activity {
         return mBackgroundEnabled;
     }
 
+    public static void setForegroundServiceEnabled(boolean enabled) {
+        mForegroundServiceEnabled = enabled;
+    }
+
+    public static boolean isForegroundServiceEnabled() {
+        return mForegroundServiceEnabled;
+    }
+
+    public int getServiceType() {
+        switch(getActivityType()) {
+            case ACTIVITY_TEST_OUTPUT:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK;
+            case ACTIVITY_TEST_INPUT:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_TAP_TO_TONE:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_RECORD_PLAY:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_ECHO:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_RT_LATENCY:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_GLITCHES:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_TEST_DISCONNECT:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_DATA_PATHS:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                        | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE;
+            case ACTIVITY_DYNAMIC_WORKLOAD:
+                return ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK;
+            default:
+                Log.i(TAG, "getServiceType() called on unknown activity type " + getActivityType());
+                return 0;
+        }
+    }
+
     public void onStreamClosed() {
     }
 
@@ -201,6 +250,7 @@ abstract class TestAudioActivity extends Activity {
 
     @Override
     public void onNewIntent(Intent intent) {
+        super.onNewIntent(intent);
         mBundleFromIntent = intent.getExtras();
     }
 
@@ -235,6 +285,9 @@ abstract class TestAudioActivity extends Activity {
         if (mCommunicationDeviceView != null) {
             mCommunicationDeviceView.onStart();
         }
+        if (isForegroundServiceEnabled()) {
+            enableForegroundService(true);
+        }
     }
 
     protected void resetConfiguration() {
@@ -298,6 +351,9 @@ abstract class TestAudioActivity extends Activity {
         if (!isBackgroundEnabled()) {
             Log.i(TAG, "onStop() called so stop the test =========================");
             onStopTest();
+            if (isForegroundServiceEnabled()) {
+                enableForegroundService(false);
+            }
         }
         if (mCommunicationDeviceView != null) {
             mCommunicationDeviceView.onStop();
@@ -310,11 +366,24 @@ abstract class TestAudioActivity extends Activity {
         if (isBackgroundEnabled()) {
             Log.i(TAG, "onDestroy() called so stop the test =========================");
             onStopTest();
+            if (isForegroundServiceEnabled()) {
+                enableForegroundService(false);
+            }
         }
         mAudioState = AUDIO_STATE_CLOSED;
         super.onDestroy();
     }
 
+    public void enableForegroundService(boolean enabled) {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+            String action = enabled ? ACTION_START : ACTION_STOP;
+            Intent serviceIntent = new Intent(action, null, this,
+                    AudioForegroundService.class);
+            serviceIntent.putExtra("service_types", getServiceType());
+            startForegroundService(serviceIntent);
+        }
+    }
+
     protected void updateEnabledWidgets() {
         if (mOpenButton != null) {
             mOpenButton.setBackgroundColor(mAudioState == AUDIO_STATE_OPEN ? COLOR_ACTIVE : COLOR_IDLE);
@@ -827,7 +896,8 @@ abstract class TestAudioActivity extends Activity {
             int framesPerBurst = streamTester.getCurrentAudioStream().getFramesPerBurst();
             status.framesPerCallback = getFramesPerCallback();
             report.append("timestamp.latency = " + latencyStatistics.dump() + "\n");
-            report.append(status.dump(framesPerBurst));
+            // TODO The following report is not in a name=value format!
+            // report.append(status.dump(framesPerBurst));
         }
 
         return report.toString();
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestColdStartLatencyActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestColdStartLatencyActivity.java
index b88b611c..b0202e8e 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestColdStartLatencyActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestColdStartLatencyActivity.java
@@ -18,7 +18,6 @@ package com.mobileer.oboetester;
 
 import static com.mobileer.oboetester.TestAudioActivity.TAG;
 
-import android.app.Activity;
 import android.content.Context;
 import android.media.AudioManager;
 import android.os.Bundle;
@@ -31,12 +30,12 @@ import android.widget.RadioButton;
 import android.widget.Spinner;
 import android.widget.TextView;
 
-import java.util.Random;
+import androidx.appcompat.app.AppCompatActivity;
 
 /**
  * Test for getting the cold start latency
  */
-public class TestColdStartLatencyActivity extends Activity {
+public class TestColdStartLatencyActivity extends AppCompatActivity {
 
     private TextView mStatusView;
     private MyStreamSniffer mStreamSniffer;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDataPathsActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDataPathsActivity.java
index bfe4b83d..bd0e6d0b 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDataPathsActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDataPathsActivity.java
@@ -17,15 +17,14 @@
 package com.mobileer.oboetester;
 
 import static com.mobileer.oboetester.IntentBasedTestSupport.configureStreamsFromBundle;
+import static com.mobileer.oboetester.StreamConfiguration.UNSPECIFIED;
 import static com.mobileer.oboetester.StreamConfiguration.convertChannelMaskToText;
 
-import android.app.Instrumentation;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.os.Build;
 import android.os.Bundle;
 import android.util.Log;
-import android.view.KeyEvent;
 import android.widget.CheckBox;
 import android.widget.RadioButton;
 import android.widget.RadioGroup;
@@ -88,7 +87,7 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
     public static final boolean VALUE_DEFAULT_USE_OUTPUT_DEVICES = true;
 
 
-    public static final int DURATION_SECONDS = 3;
+    public static final int DURATION_SECONDS = 4;
     private final static double MIN_REQUIRED_MAGNITUDE = 0.001;
     private final static int MAX_SINE_FREQUENCY = 1000;
     private final static int TYPICAL_SAMPLE_RATE = 48000;
@@ -144,6 +143,8 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
     private double mPhaseErrorSum;
     private double mPhaseErrorCount;
 
+    private boolean mSkipRemainingTests;
+
     private CheckBox mCheckBoxInputPresets;
     private CheckBox mCheckBoxAllChannels;
     private CheckBox mCheckBoxInputChannelMasks;
@@ -296,7 +297,10 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
                     + "\nphase = " + getMagnitudeText(mPhase)
                     + ", jitter = " + getJitterText()
                     + ", #" + mPhaseCount
-                    + "\n");
+                    + "\n"
+                    + mAutomatedTestRunner.getPassFailReport()
+                    + "\n"
+            );
             return message.toString();
         }
 
@@ -401,11 +405,13 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
                 && (requestedInConfig.getDeviceId() != actualInConfig.getDeviceId())) {
             why += "inDev(" + requestedInConfig.getDeviceId()
                     + "!=" + actualInConfig.getDeviceId() + "),";
+            mSkipRemainingTests = true; // the device must have been unplugged
         }
         if (requestedOutConfig.getDeviceId() != 0
                 && (requestedOutConfig.getDeviceId() != actualOutConfig.getDeviceId())) {
             why += ", outDev(" + requestedOutConfig.getDeviceId()
                     + "!=" + actualOutConfig.getDeviceId() + "),";
+            mSkipRemainingTests = true; // the device must have been unplugged
         }
         if ((requestedInConfig.getInputPreset() != actualInConfig.getInputPreset())) {
             why += ", inPre(" + requestedInConfig.getInputPreset()
@@ -466,6 +472,9 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
 
     @Override
     protected TestResult testCurrentConfigurations() throws InterruptedException {
+        if (mSkipRemainingTests) {
+            throw new DeviceUnpluggedException();
+        }
         TestResult testResult = super.testCurrentConfigurations();
         if (testResult != null) {
             testResult.addComment("mag = " + TestDataPathsActivity.getMagnitudeText(mMagnitude)
@@ -475,17 +484,20 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
             int result = testResult.result;
             if (result == TEST_RESULT_FAILED) {
                 int id = mAudioOutTester.actualConfiguration.getDeviceId();
-                int deviceType = getDeviceInfoById(id).getType();
                 int channelCount = mAudioOutTester.actualConfiguration.getChannelCount();
-                if (deviceType == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE
-                        && channelCount == 2
-                        && getOutputChannel() == 1) {
-                    testResult.addComment("Maybe EARPIECE does not mix stereo to mono!");
-                }
-                if (deviceType == TYPE_BUILTIN_SPEAKER_SAFE
-                        && channelCount == 2
-                        && getOutputChannel() == 0) {
-                    testResult.addComment("Maybe SPEAKER_SAFE dropped channel zero!");
+                AudioDeviceInfo info = getDeviceInfoById(id);
+                if (info != null) {
+                    int deviceType = getDeviceInfoById(id).getType();
+                    if (deviceType == AudioDeviceInfo.TYPE_BUILTIN_EARPIECE
+                            && channelCount == 2
+                            && getOutputChannel() == 1) {
+                        testResult.addComment("Maybe EARPIECE does not mix stereo to mono!");
+                    }
+                    if (deviceType == TYPE_BUILTIN_SPEAKER_SAFE
+                            && channelCount == 2
+                            && getOutputChannel() == 0) {
+                        testResult.addComment("Maybe SPEAKER_SAFE dropped channel zero!");
+                    }
                 }
             }
         }
@@ -572,6 +584,8 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
          requestedOutConfig.setDeviceId(outputDeviceInfo.getId());
          resetChannelConfigurations(requestedInConfig, requestedOutConfig);
 
+         testBug_270535408(inputDeviceInfo, outputDeviceInfo);
+
          if (mCheckBoxAllChannels.isChecked()) {
              runOnUiThread(() -> mCheckBoxAllChannels.setEnabled(false));
              testOutputChannelCounts(inputDeviceInfo, outputDeviceInfo);
@@ -662,7 +676,7 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
         setInstructionsText(deviceText);
 
         if (inputDeviceInfo == null) {
-            deviceText += "ERROR - cannot find compatible device type for input!";
+            deviceText += "\nERROR - no compatible input device!";
         } else {
             deviceText = "IN: type = "
                     + AudioDeviceInfoConverter.typeToString(inputDeviceInfo.getType())
@@ -694,12 +708,14 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
     }
 
     private void testOutputChannelCounts(AudioDeviceInfo inputDeviceInfo, AudioDeviceInfo outputDeviceInfo) throws InterruptedException {
+        final int maxOutputChannelsToTest = 4; // takes too long
         logSection("Output Channel Counts");
-        ArrayList<Integer> channelCountsTested =new ArrayList<Integer>();
+        ArrayList<Integer> channelCountsTested = new ArrayList<Integer>();
         StreamConfiguration requestedInConfig = mAudioInputTester.requestedConfiguration;
         StreamConfiguration requestedOutConfig = mAudioOutTester.requestedConfiguration;
 
         int[] outputChannelCounts = outputDeviceInfo.getChannelCounts();
+        // Are the output channels mixed together in the air or in a loopback plug?
         if (isDeviceTypeMixedForLoopback(outputDeviceInfo.getType())) {
             requestedInConfig.setChannelCount(1);
             setInputChannel(0);
@@ -715,22 +731,30 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
             testPerformancePaths();
             setOutputChannel(1);
             testPerformancePaths();
+
             // Test channels for each channelCount above 2
             for (int numChannels : outputChannelCounts) {
-                log("numChannels = " + numChannels);
-                if (numChannels > 4) {
-                    log("numChannels forced to 4!");
-                }
-                if (!channelCountsTested.contains(numChannels)) {
-                    requestedOutConfig.setChannelCount(numChannels);
-                    channelCountsTested.add(numChannels);
-                    for (int channel = 0; channel < numChannels; channel++) {
-                        setOutputChannel(channel);
-                        testPerformancePaths();
+                if (numChannels > maxOutputChannelsToTest) {
+                    log("skip numChannels = " + numChannels);
+                } else {
+                    if (!channelCountsTested.contains(numChannels)) {
+                        log("--- test numChannels = " + numChannels);
+                        requestedOutConfig.setChannelCount(numChannels);
+                        channelCountsTested.add(numChannels);
+                        for (int channel = 0; channel < numChannels; channel++) {
+                            setOutputChannel(channel);
+                            testPerformancePaths();
+                        }
                     }
                 }
+
             }
         } else {
+            // This device does not mix so we have to match the input and output channel indices.
+            // Find the maximum number of input channels.
+            int[] inputChannelCounts = inputDeviceInfo.getChannelCounts();
+            int maxInputChannels = findLargestChannelCount(inputChannelCounts);
+            int maxInputChannelsToTest = Math.min(maxOutputChannelsToTest, maxInputChannels);
             // test mono
             testMatchingChannels(1);
             channelCountsTested.add(1);
@@ -739,14 +763,14 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
             channelCountsTested.add(2);
             // Test matching channels for each channelCount above 2
             for (int numChannels : outputChannelCounts) {
-                log("numChannels = " + numChannels);
-                if (numChannels > 4) {
-                    log("numChannels forced to 4!");
-                    numChannels = 4;
-                }
-                if (!channelCountsTested.contains(numChannels)) {
-                    testMatchingChannels(numChannels);
-                    channelCountsTested.add(numChannels);
+                if (numChannels > maxInputChannelsToTest) {
+                    log("skip numChannels = " + numChannels + " because > #inputs");
+                } else {
+                    if (!channelCountsTested.contains(numChannels)) {
+                        log("--- test numChannels = " + numChannels);
+                        testMatchingChannels(numChannels);
+                        channelCountsTested.add(numChannels);
+                    }
                 }
             }
         }
@@ -767,34 +791,24 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
         }
     }
 
-    private void testPerformancePaths() throws InterruptedException {
-        StreamConfiguration requestedInConfig = mAudioInputTester.requestedConfiguration;
-        StreamConfiguration requestedOutConfig = mAudioOutTester.requestedConfiguration;
-
-        requestedInConfig.setSharingMode(StreamConfiguration.SHARING_MODE_SHARED);
-        requestedOutConfig.setSharingMode(StreamConfiguration.SHARING_MODE_SHARED);
-
-        // Legacy NONE
-        requestedInConfig.setMMap(false);
-        requestedOutConfig.setMMap(false);
-        requestedInConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_NONE);
-        requestedOutConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_NONE);
-        testCurrentConfigurations();
-
-        // Legacy LOW_LATENCY
-        requestedInConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
-        requestedOutConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
-        testCurrentConfigurations();
-
-        // MMAP LowLatency
-        if (NativeEngine.isMMapSupported()) {
-            requestedInConfig.setMMap(true);
-            requestedOutConfig.setMMap(true);
+    // b/270535408 | no input when channels=3 and sessionId is allocated
+    private void testBug_270535408(AudioDeviceInfo inputDeviceInfo,
+                                   AudioDeviceInfo outputDeviceInfo) throws InterruptedException {
+        int[] inputChannelCounts = inputDeviceInfo.getChannelCounts();
+        if (findLargestChannelCount(inputChannelCounts) >= 3) {
+            logSection("Bug 270535408, 3ch + SessionId");
+            StreamConfiguration requestedInConfig = mAudioInputTester.requestedConfiguration;
+            StreamConfiguration requestedOutConfig = mAudioOutTester.requestedConfiguration;
+            requestedInConfig.setChannelCount(3);
+            requestedInConfig.setSessionId(AudioManager.AUDIO_SESSION_ID_GENERATE);
+            requestedInConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
+            requestedOutConfig.setPerformanceMode(StreamConfiguration.PERFORMANCE_MODE_LOW_LATENCY);
+            testCurrentConfigurations();
+            // Now test without a sessionId so we have a passing test to compare with.
+            requestedInConfig.setSessionId(-1); // AAUDIO_SESSION_ID_NONE
             testCurrentConfigurations();
+            requestedInConfig.setChannelCount(UNSPECIFIED);
         }
-        requestedInConfig.setMMap(false);
-        requestedOutConfig.setMMap(false);
-
     }
 
     private void testOutputDeviceTypes()  throws InterruptedException {
@@ -831,6 +845,12 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
         }
     }
 
+    class DeviceUnpluggedException extends RuntimeException {
+        public DeviceUnpluggedException() {
+            super("Device was unplugged.");
+        }
+    }
+
     @Override
     public void runTest() {
         try {
@@ -844,7 +864,12 @@ public class TestDataPathsActivity  extends BaseAutoGlitchActivity {
 
             runOnUiThread(() -> keepScreenOn(true));
 
-            testOutputDeviceTypes();
+            mSkipRemainingTests = false;
+            try {
+                testOutputDeviceTypes();
+            } catch(DeviceUnpluggedException e) {
+                log("Remaining tests were skipped, " + e.getMessage());
+            }
 
             compareFailedTestsWithNearestPassingTest();
 
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDisconnectActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDisconnectActivity.java
index b74c3b10..458a3ef0 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDisconnectActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestDisconnectActivity.java
@@ -22,7 +22,6 @@ import android.content.Intent;
 import android.content.IntentFilter;
 import android.hardware.usb.UsbConstants;
 import android.hardware.usb.UsbDevice;
-import android.hardware.usb.UsbEndpoint;
 import android.hardware.usb.UsbInterface;
 import android.hardware.usb.UsbManager;
 import android.os.Bundle;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestErrorCallbackActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestErrorCallbackActivity.java
index b3b4497d..d8545e38 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestErrorCallbackActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestErrorCallbackActivity.java
@@ -16,14 +16,15 @@
 
 package com.mobileer.oboetester;
 
-import android.app.Activity;
 import android.os.Bundle;
 import android.os.Handler;
 import android.os.Looper;
 import android.view.View;
 import android.widget.TextView;
 
-public class TestErrorCallbackActivity extends Activity {
+import androidx.appcompat.app.AppCompatActivity;
+
+public class TestErrorCallbackActivity extends AppCompatActivity {
 
     private TextView mStatusDeleteCallback;
     // This must match the value in TestErrorCallback.h
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestInputActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestInputActivity.java
index a6c9bbd6..f2d328e5 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestInputActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestInputActivity.java
@@ -24,6 +24,7 @@ import android.os.Handler;
 import android.os.Looper;
 import android.view.View;
 import android.widget.RadioButton;
+
 import androidx.annotation.NonNull;
 import androidx.core.content.FileProvider;
 
@@ -41,7 +42,7 @@ public class TestInputActivity  extends TestAudioActivity {
     private static final int NUM_VOLUME_BARS = 8;
     private VolumeBarView[] mVolumeBars = new VolumeBarView[NUM_VOLUME_BARS];
     private InputMarginView mInputMarginView;
-    private int mInputMarginBursts = 0;
+    int mInputMarginBursts = 0;
     private WorkloadView mWorkloadView;
 
     public native void setMinimumFramesBeforeRead(int frames);
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivityBase.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivityBase.java
index 731351b9..c7420456 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivityBase.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestOutputActivityBase.java
@@ -16,10 +16,6 @@
 
 package com.mobileer.oboetester;
 
-import android.media.audiofx.Equalizer;
-import android.media.audiofx.PresetReverb;
-import android.util.Log;
-
 import java.io.IOException;
 
 abstract class TestOutputActivityBase extends TestAudioActivity {
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestPlugLatencyActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestPlugLatencyActivity.java
index b55fa127..5f23cae0 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestPlugLatencyActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestPlugLatencyActivity.java
@@ -17,16 +17,11 @@
 package com.mobileer.oboetester;
 
 import android.annotation.TargetApi;
-import android.content.BroadcastReceiver;
 import android.content.Context;
-import android.content.Intent;
-import android.content.IntentFilter;
 import android.media.AudioDeviceCallback;
 import android.media.AudioDeviceInfo;
 import android.media.AudioManager;
 import android.os.Bundle;
-import android.view.View;
-import android.widget.Button;
 import android.widget.TextView;
 
 import com.mobileer.audio_device.AudioDeviceInfoConverter;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRapidCycleActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRapidCycleActivity.java
new file mode 100644
index 00000000..a265e359
--- /dev/null
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRapidCycleActivity.java
@@ -0,0 +1,155 @@
+/*
+ * Copyright 2023 The Android Open Source Project
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
+package com.mobileer.oboetester;
+
+import static com.mobileer.oboetester.TestAudioActivity.TAG;
+
+import android.content.Context;
+import android.media.AudioManager;
+import android.os.Bundle;
+import android.util.Log;
+import android.view.View;
+import android.view.WindowManager;
+import android.widget.Button;
+import android.widget.RadioButton;
+import android.widget.TextView;
+
+import androidx.appcompat.app.AppCompatActivity;
+
+/**
+ * Try to hang streams by rapidly opening and closing.
+ * See b/348615156
+ */
+public class TestRapidCycleActivity extends AppCompatActivity {
+
+    private TextView mStatusView;
+    private MyStreamSniffer mStreamSniffer;
+    private AudioManager mAudioManager;
+    private RadioButton mApiOpenSLButton;
+    private RadioButton mApiAAudioButton;
+    private Button mStartButton;
+    private Button mStopButton;
+
+    @Override
+    protected void onCreate(Bundle savedInstanceState) {
+        super.onCreate(savedInstanceState);
+        setContentView(R.layout.activity_rapid_cycle);
+        mStatusView = (TextView) findViewById(R.id.text_callback_status);
+        mAudioManager = (AudioManager) getSystemService(Context.AUDIO_SERVICE);
+
+        mStartButton = (Button) findViewById(R.id.button_start_test);
+        mStopButton = (Button) findViewById(R.id.button_stop_test);
+        mApiOpenSLButton = (RadioButton) findViewById(R.id.audio_api_opensl);
+        mApiOpenSLButton.setChecked(true);
+        mApiAAudioButton = (RadioButton) findViewById(R.id.audio_api_aaudio);
+        setButtonsEnabled(false);
+    }
+
+    public void onStartCycleTest(View view) { startCycleTest(); }
+    public void onStopCycleTest(View view) {
+        stopCycleTest();
+    }
+
+    private void setButtonsEnabled(boolean running) {
+        mStartButton.setEnabled(!running);
+        mStopButton.setEnabled(running);
+        mApiOpenSLButton.setEnabled(!running);
+        mApiAAudioButton.setEnabled(!running);
+    }
+
+    // Change routing while the stream is playing.
+    // Keep trying until we crash.
+    protected class MyStreamSniffer extends Thread {
+        boolean enabled = true;
+        StringBuffer statusBuffer = new StringBuffer();
+
+        @Override
+        public void run() {
+            int lastCycleCount = -1;
+            boolean useOpenSL = mApiOpenSLButton.isChecked();
+            startRapidCycleTest(useOpenSL);
+            try {
+                while (enabled) {
+                    statusBuffer = new StringBuffer();
+                    sleep(100);
+                    int cycleCount = getCycleCount();
+                    if (cycleCount > lastCycleCount) { // reduce spam
+                        log("#" + cycleCount + " open/close cycles\n");
+                        lastCycleCount = cycleCount;
+                    }
+                }
+            } catch (InterruptedException e) {
+            } finally {
+                stopRapidCycleTest();
+            }
+        }
+
+        // Log to screen and logcat.
+        private void log(String text) {
+            Log.d(TAG, "RapidCycle: " + text);
+            statusBuffer.append(text);
+            showStatus(statusBuffer.toString());
+        }
+
+        // Stop the test thread.
+        void finish() {
+            enabled = false;
+            interrupt();
+            try {
+                join(2000);
+            } catch (InterruptedException e) {
+                e.printStackTrace();
+            }
+        }
+    }
+
+    protected void showStatus(final String message) {
+        runOnUiThread(new Runnable() {
+            @Override
+            public void run() {
+                mStatusView.setText(message);
+            }
+        });
+    }
+
+    private native int startRapidCycleTest(boolean useOpenSL);
+    private native int stopRapidCycleTest();
+    private native int getCycleCount();
+
+    @Override
+    public void onPause() {
+        super.onPause();
+        Log.i(TAG, "onPause() called so stop the test =========================");
+        stopCycleTest();
+    }
+
+    private void startCycleTest() {
+        getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
+        setButtonsEnabled(true);
+        mStreamSniffer = new MyStreamSniffer();
+        mStreamSniffer.start();
+    }
+
+    private void stopCycleTest() {
+        if (mStreamSniffer != null) {
+            mStreamSniffer.finish();
+            mStreamSniffer = null;
+            getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
+            setButtonsEnabled(false);
+        }
+    }
+}
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRouteDuringCallbackActivity.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRouteDuringCallbackActivity.java
index 4dfce073..0e43f37e 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRouteDuringCallbackActivity.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/TestRouteDuringCallbackActivity.java
@@ -18,7 +18,6 @@ package com.mobileer.oboetester;
 
 import static com.mobileer.oboetester.TestAudioActivity.TAG;
 
-import android.app.Activity;
 import android.content.Context;
 import android.media.AudioManager;
 import android.os.Bundle;
@@ -29,6 +28,8 @@ import android.widget.Button;
 import android.widget.RadioButton;
 import android.widget.TextView;
 
+import androidx.appcompat.app.AppCompatActivity;
+
 import java.util.Random;
 
 /**
@@ -36,7 +37,7 @@ import java.util.Random;
  * while playing audio. The buffer may get deleted while we are writing to it!
  * See b/274815060
  */
-public class TestRouteDuringCallbackActivity extends Activity {
+public class TestRouteDuringCallbackActivity extends AppCompatActivity {
 
     private TextView mStatusView;
     private MyStreamSniffer mStreamSniffer;
diff --git a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/WorkloadView.java b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/WorkloadView.java
index 74027c2c..87d3d1df 100644
--- a/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/WorkloadView.java
+++ b/apps/OboeTester/app/src/main/java/com/mobileer/oboetester/WorkloadView.java
@@ -18,7 +18,6 @@ package com.mobileer.oboetester;
 
 import android.content.Context;
 import android.util.AttributeSet;
-import android.util.Log;
 import android.view.LayoutInflater;
 import android.widget.LinearLayout;
 import android.widget.SeekBar;
diff --git a/apps/OboeTester/app/src/main/res/drawable/ic_notification.xml b/apps/OboeTester/app/src/main/res/drawable/ic_notification.xml
new file mode 100644
index 00000000..61f9d9c3
--- /dev/null
+++ b/apps/OboeTester/app/src/main/res/drawable/ic_notification.xml
@@ -0,0 +1,83 @@
+<vector xmlns:android="http://schemas.android.com/apk/res/android"
+    android:width="108dp"
+    android:height="108dp"
+    android:viewportWidth="108"
+    android:viewportHeight="108">
+  <path android:fillColor="#3DDC84"
+      android:pathData="M0,0h108v108h-108z"/>
+  <path android:fillColor="#00000000" android:pathData="M9,0L9,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,0L19,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M29,0L29,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M39,0L39,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M49,0L49,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M59,0L59,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M69,0L69,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M79,0L79,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M89,0L89,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M99,0L99,108"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,9L108,9"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,19L108,19"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,29L108,29"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,39L108,39"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,49L108,49"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,59L108,59"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,69L108,69"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,79L108,79"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,89L108,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M0,99L108,99"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,29L89,29"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,39L89,39"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,49L89,49"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,59L89,59"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,69L89,69"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M19,79L89,79"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M29,19L29,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M39,19L39,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M49,19L49,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M59,19L59,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M69,19L69,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+  <path android:fillColor="#00000000" android:pathData="M79,19L79,89"
+      android:strokeColor="#33FFFFFF" android:strokeWidth="0.8"/>
+
+  <group android:scaleX="2.61"
+      android:scaleY="2.61"
+      android:translateX="22.68"
+      android:translateY="22.68"
+      android:tint="#0D49B0">
+    <path
+        android:fillColor="#0D49B0"
+        android:pathData="M17,16.99c-1.35,0 -2.2,0.42 -2.95,0.8 -0.65,0.33 -1.18,0.6 -2.05,0.6 -0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.38 -1.57,-0.8 -2.95,-0.8s-2.2,0.42 -2.95,0.8c-0.65,0.33 -1.17,0.6 -2.05,0.6v1.95c1.35,0 2.2,-0.42 2.95,-0.8 0.65,-0.33 1.17,-0.6 2.05,-0.6s1.4,0.25 2.05,0.6c0.75,0.38 1.57,0.8 2.95,0.8s2.2,-0.42 2.95,-0.8c0.65,-0.33 1.18,-0.6 2.05,-0.6 0.9,0 1.4,0.25 2.05,0.6 0.75,0.38 1.58,0.8 2.95,0.8v-1.95c-0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.38 -1.6,-0.8 -2.95,-0.8zM17,12.54c-1.35,0 -2.2,0.43 -2.95,0.8 -0.65,0.32 -1.18,0.6 -2.05,0.6 -0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.38 -1.57,-0.8 -2.95,-0.8s-2.2,0.43 -2.95,0.8c-0.65,0.32 -1.17,0.6 -2.05,0.6v1.95c1.35,0 2.2,-0.43 2.95,-0.8 0.65,-0.35 1.15,-0.6 2.05,-0.6s1.4,0.25 2.05,0.6c0.75,0.38 1.57,0.8 2.95,0.8s2.2,-0.43 2.95,-0.8c0.65,-0.35 1.15,-0.6 2.05,-0.6s1.4,0.25 2.05,0.6c0.75,0.38 1.58,0.8 2.95,0.8v-1.95c-0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.38 -1.6,-0.8 -2.95,-0.8zM19.95,4.46c-0.75,-0.38 -1.58,-0.8 -2.95,-0.8s-2.2,0.42 -2.95,0.8c-0.65,0.32 -1.18,0.6 -2.05,0.6 -0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.37 -1.57,-0.8 -2.95,-0.8s-2.2,0.42 -2.95,0.8c-0.65,0.33 -1.17,0.6 -2.05,0.6v1.93c1.35,0 2.2,-0.43 2.95,-0.8 0.65,-0.33 1.17,-0.6 2.05,-0.6s1.4,0.25 2.05,0.6c0.75,0.38 1.57,0.8 2.95,0.8s2.2,-0.43 2.95,-0.8c0.65,-0.32 1.18,-0.6 2.05,-0.6 0.9,0 1.4,0.25 2.05,0.6 0.75,0.38 1.58,0.8 2.95,0.8L22,5.04c-0.9,0 -1.4,-0.25 -2.05,-0.58zM17,8.09c-1.35,0 -2.2,0.43 -2.95,0.8 -0.65,0.35 -1.15,0.6 -2.05,0.6s-1.4,-0.25 -2.05,-0.6c-0.75,-0.38 -1.57,-0.8 -2.95,-0.8s-2.2,0.43 -2.95,0.8c-0.65,0.35 -1.15,0.6 -2.05,0.6v1.95c1.35,0 2.2,-0.43 2.95,-0.8 0.65,-0.32 1.18,-0.6 2.05,-0.6s1.4,0.25 2.05,0.6c0.75,0.38 1.57,0.8 2.95,0.8s2.2,-0.43 2.95,-0.8c0.65,-0.32 1.18,-0.6 2.05,-0.6 0.9,0 1.4,0.25 2.05,0.6 0.75,0.38 1.58,0.8 2.95,0.8L22,9.49c-0.9,0 -1.4,-0.25 -2.05,-0.6 -0.75,-0.38 -1.6,-0.8 -2.95,-0.8z"/>
+  </group>
+
+</vector>
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_dynamic_workload.xml b/apps/OboeTester/app/src/main/res/layout/activity_dynamic_workload.xml
index 2212b5bf..7b7e3463 100644
--- a/apps/OboeTester/app/src/main/res/layout/activity_dynamic_workload.xml
+++ b/apps/OboeTester/app/src/main/res/layout/activity_dynamic_workload.xml
@@ -40,12 +40,32 @@
             android:layout_marginRight="8sp"
             android:text="ADPF" />
 
+        <CheckBox
+            android:id="@+id/enable_workload_report"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginRight="8sp"
+            android:text="Wkload" />
+
         <CheckBox
             android:id="@+id/use_alternative_adpf"
             android:layout_width="wrap_content"
             android:layout_height="wrap_content"
             android:layout_marginRight="8sp"
             android:text="Alt ADPF" />
+    </LinearLayout>
+
+    <LinearLayout xmlns:android="http://schemas.android.com/apk/res/android"
+        xmlns:tools="http://schemas.android.com/tools"
+
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:orientation="horizontal"
+        android:paddingLeft="@dimen/small_horizontal_margin"
+        android:paddingTop="@dimen/small_vertical_margin"
+        android:paddingRight="@dimen/small_horizontal_margin"
+        android:paddingBottom="@dimen/small_vertical_margin"
+        tools:context="com.mobileer.oboetester.DynamicWorkloadActivity">
 
         <CheckBox
             android:id="@+id/hear_workload"
@@ -61,6 +81,13 @@
             android:layout_marginRight="8sp"
             android:checked="true"
             android:text="Scroll" />
+
+        <CheckBox
+            android:id="@+id/sustained_perf_mode"
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:layout_marginRight="8sp"
+            android:text="Sustain" />
     </LinearLayout>
 
     <HorizontalScrollView
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_echo.xml b/apps/OboeTester/app/src/main/res/layout/activity_echo.xml
index 42ed4d59..815e41a2 100644
--- a/apps/OboeTester/app/src/main/res/layout/activity_echo.xml
+++ b/apps/OboeTester/app/src/main/res/layout/activity_echo.xml
@@ -117,7 +117,6 @@
             android:text="@string/echo_instructions"
             android:textSize="14sp"
             android:textStyle="bold" />
-≈
     </LinearLayout>
 
 </ScrollView>
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_extra_tests.xml b/apps/OboeTester/app/src/main/res/layout/activity_extra_tests.xml
index 347db970..ddffc35b 100644
--- a/apps/OboeTester/app/src/main/res/layout/activity_extra_tests.xml
+++ b/apps/OboeTester/app/src/main/res/layout/activity_extra_tests.xml
@@ -81,5 +81,15 @@
             android:backgroundTint="@color/button_tint"
             android:onClick="onLaunchColdStartLatencyTest"
             android:text="Cold Start Latency" />
+
+        <Button
+            android:id="@+id/buttonRapidCycle"
+            android:layout_width="0dp"
+            android:layout_height="wrap_content"
+            android:layout_columnWeight="1"
+            android:layout_gravity="fill"
+            android:backgroundTint="@color/button_tint"
+            android:onClick="onLaunchRapidCycleTest"
+            android:text="Rapid Cycle" />
     </GridLayout>
 </androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_main.xml b/apps/OboeTester/app/src/main/res/layout/activity_main.xml
index a40a91cb..a7626752 100644
--- a/apps/OboeTester/app/src/main/res/layout/activity_main.xml
+++ b/apps/OboeTester/app/src/main/res/layout/activity_main.xml
@@ -212,13 +212,23 @@
         app:layout_constraintTop_toBottomOf="@+id/boxEnableWorkarounds" />
 
 
+    <CheckBox
+        android:id="@+id/boxEnableForegroundService"
+        android:layout_width="wrap_content"
+        android:layout_height="wrap_content"
+        android:layout_marginTop="6dp"
+        android:checked="false"
+        android:text="enable foreground service"
+        app:layout_constraintStart_toStartOf="@+id/boxEnableBackground"
+        app:layout_constraintTop_toBottomOf="@+id/boxEnableBackground" />
+
     <TextView
         android:id="@+id/textView2"
         android:layout_width="wrap_content"
         android:layout_height="wrap_content"
         android:text="Mode:"
         app:layout_constraintBaseline_toBaselineOf="@+id/spinnerAudioMode"
-        app:layout_constraintStart_toStartOf="@+id/boxEnableBackground" />
+        app:layout_constraintStart_toStartOf="@+id/boxEnableForegroundService" />
 
     <Spinner
         android:id="@+id/spinnerAudioMode"
@@ -227,7 +237,7 @@
         android:entries="@array/audio_modes"
         android:prompt="@string/audio_mode_prompt"
         app:layout_constraintStart_toEndOf="@+id/textView2"
-        app:layout_constraintTop_toBottomOf="@+id/boxEnableBackground" />
+        app:layout_constraintTop_toBottomOf="@+id/boxEnableForegroundService" />
 
     <TextView
         android:id="@+id/deviceView"
@@ -240,9 +250,9 @@
 
     <TextView
         android:id="@+id/text_build_info"
-        android:layout_width="0dp"
+        android:layout_width="match_parent"
         android:layout_height="wrap_content"
-        android:layout_marginEnd="1dp"
+        android:lines="3"
         android:ems="10"
         android:text="V?"
         app:layout_constraintEnd_toEndOf="@+id/callbackSize"
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_rapid_cycle.xml b/apps/OboeTester/app/src/main/res/layout/activity_rapid_cycle.xml
new file mode 100644
index 00000000..ac2393d7
--- /dev/null
+++ b/apps/OboeTester/app/src/main/res/layout/activity_rapid_cycle.xml
@@ -0,0 +1,79 @@
+<?xml version="1.0" encoding="utf-8"?>
+<androidx.constraintlayout.widget.ConstraintLayout xmlns:android="http://schemas.android.com/apk/res/android"
+    xmlns:app="http://schemas.android.com/apk/res-auto"
+    xmlns:tools="http://schemas.android.com/tools"
+    android:layout_width="match_parent"
+    android:layout_height="match_parent"
+    tools:context=".TestRapidCycleActivity">
+
+    <LinearLayout
+        android:id="@+id/buttonGrid"
+        android:layout_width="match_parent"
+        android:layout_height="wrap_content"
+        android:orientation="vertical">
+
+        <TextView
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:fontFamily="monospace"
+            android:gravity="bottom"
+            android:text="@string/rapid_cycle_intro" />
+
+        <RadioGroup
+            android:layout_width="wrap_content"
+            android:layout_height="wrap_content"
+            android:checkedButton="@+id/direction_output"
+            android:orientation="horizontal">
+            <TextView
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:fontFamily="monospace"
+                android:gravity="bottom"
+                android:text="API:" />
+            <RadioButton
+                android:id="@+id/audio_api_opensl"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:text="OpenSL ES" />
+
+            <RadioButton
+                android:id="@+id/audio_api_aaudio"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:text="AAudio" />
+        </RadioGroup>
+
+        <LinearLayout
+            android:layout_width="match_parent"
+            android:layout_height="wrap_content"
+            android:orientation="horizontal">
+
+            <Button
+                android:id="@+id/button_start_test"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_weight="1"
+                android:backgroundTint="@color/button_tint"
+                android:onClick="onStartCycleTest"
+                android:text="Start Test" />
+            <Button
+                android:id="@+id/button_stop_test"
+                android:layout_width="match_parent"
+                android:layout_height="wrap_content"
+                android:layout_weight="1"
+                android:backgroundTint="@color/button_tint"
+                android:onClick="onStopCycleTest"
+                android:text="Stop Test" />
+        </LinearLayout>
+
+        <TextView
+            android:id="@+id/text_callback_status"
+            android:layout_width="match_parent"
+            android:layout_height="match_parent"
+            android:fontFamily="monospace"
+            android:gravity="bottom"
+            android:lines="10"
+            android:text="@string/init_status" />
+
+    </LinearLayout>
+</androidx.constraintlayout.widget.ConstraintLayout>
diff --git a/apps/OboeTester/app/src/main/res/layout/activity_rt_latency.xml b/apps/OboeTester/app/src/main/res/layout/activity_rt_latency.xml
index 83c50ae4..0c81f138 100644
--- a/apps/OboeTester/app/src/main/res/layout/activity_rt_latency.xml
+++ b/apps/OboeTester/app/src/main/res/layout/activity_rt_latency.xml
@@ -62,7 +62,7 @@
             android:layout_weight="1"
             android:onClick="onMeasure"
             android:text="@string/measure"
-            android:textSize="12sp" />
+            android:textSize="10sp" />
 
         <Button
             android:id="@+id/button_average"
@@ -71,7 +71,17 @@
             android:layout_height="wrap_content"
             android:onClick="onAverage"
             android:text="@string/average"
-            android:textSize="12sp" />
+            android:textSize="10sp" />
+
+        <Button
+            android:id="@+id/button_scan"
+            android:layout_width="0dp"
+            android:layout_weight="1"
+            android:layout_height="wrap_content"
+            android:enabled="false"
+            android:onClick="onScan"
+            android:text="@string/scan"
+            android:textSize="10sp" />
 
         <Button
             android:id="@+id/button_cancel"
@@ -81,7 +91,7 @@
             android:enabled="false"
             android:onClick="onCancel"
             android:text="@string/cancel"
-            android:textSize="12sp" />
+            android:textSize="10sp" />
 
         <Button
             android:id="@+id/button_share"
@@ -90,7 +100,7 @@
             android:layout_height="wrap_content"
             android:onClick="onShareFile"
             android:text="@string/share"
-            android:textSize="12sp" />
+            android:textSize="10sp" />
     </LinearLayout>
 
     <com.mobileer.oboetester.CommunicationDeviceView
diff --git a/apps/OboeTester/app/src/main/res/layout/stream_config.xml b/apps/OboeTester/app/src/main/res/layout/stream_config.xml
index 4ccfb8a1..24d12c13 100644
--- a/apps/OboeTester/app/src/main/res/layout/stream_config.xml
+++ b/apps/OboeTester/app/src/main/res/layout/stream_config.xml
@@ -57,6 +57,11 @@
                     android:id="@+id/devices_spinner"
                     android:layout_width="wrap_content"
                     android:layout_height="wrap_content"/>
+                <TextView
+                    android:id="@+id/actualDeviceId"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:text="\?" />
 
             </TableRow>
 
@@ -256,6 +261,28 @@
 
             </TableRow>
 
+            <TableRow
+                android:id="@+id/rowSpatializationBehavior">
+
+                <TextView
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:text="@string/spatialization_behavior_prompt"/>
+
+                <Spinner
+                    android:id="@+id/spinnerSpatializationBehavior"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:entries="@array/spatialization_behaviors" />
+
+                <TextView
+                    android:id="@+id/actualSpatializationBehavior"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:text="\?" />
+
+            </TableRow>
+
         </TableLayout>
 
         <LinearLayout
@@ -299,18 +326,26 @@
             android:orientation="horizontal">
 
             <CheckBox
-                android:id="@+id/requestAudioEffect"
+                android:id="@+id/requestSessionId"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
                 android:layout_marginRight="10sp"
-                android:text="Effect" />
+                android:text="Session Id" />
 
             <TextView
                 android:id="@+id/sessionId"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
+                android:layout_marginRight="12sp"
                 android:text="\?" />
 
+            <CheckBox
+                android:id="@+id/requestAudioEffect"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginRight="10sp"
+                android:text="Effect" />
+
         </LinearLayout>
 
         <LinearLayout
@@ -325,14 +360,21 @@
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
                 android:layout_marginRight="8sp"
-                android:text="Automatic Gain Control" />
+                android:text="AGC" />
 
             <CheckBox
                 android:id="@+id/checkBoxAcousticEchoCanceler"
                 android:layout_width="wrap_content"
                 android:layout_height="wrap_content"
                 android:layout_marginRight="8sp"
-                android:text="Acoustic Echo Canceler" />
+                android:text="AEC" />
+
+            <CheckBox
+                android:id="@+id/checkBoxNoiseSuppressor"
+                android:layout_width="wrap_content"
+                android:layout_height="wrap_content"
+                android:layout_marginRight="8sp"
+                android:text="NoNoise" />
 
         </LinearLayout>
 
diff --git a/apps/OboeTester/app/src/main/res/values-night/styles.xml b/apps/OboeTester/app/src/main/res/values-night/styles.xml
deleted file mode 100644
index 35c861d9..00000000
--- a/apps/OboeTester/app/src/main/res/values-night/styles.xml
+++ /dev/null
@@ -1,7 +0,0 @@
-<resources>
-
-    <style name="Widget.AppTheme.MyView" parent="">
-        <item name="android:background">@color/gray_600</item>
-        <item name="exampleColor">@color/light_blue_600</item>
-    </style>
-</resources>
\ No newline at end of file
diff --git a/apps/OboeTester/app/src/main/res/values-v21/styles.xml b/apps/OboeTester/app/src/main/res/values-v21/styles.xml
deleted file mode 100644
index dba3c417..00000000
--- a/apps/OboeTester/app/src/main/res/values-v21/styles.xml
+++ /dev/null
@@ -1,5 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<resources>
-    <style name="AppTheme" parent="android:Theme.Material.Light">
-    </style>
-</resources>
diff --git a/apps/OboeTester/app/src/main/res/values/strings.xml b/apps/OboeTester/app/src/main/res/values/strings.xml
index da57ffe5..2c67ef1f 100644
--- a/apps/OboeTester/app/src/main/res/values/strings.xml
+++ b/apps/OboeTester/app/src/main/res/values/strings.xml
@@ -15,6 +15,7 @@
     <string name="playAudio">Play</string>
     <string name="measure">Measure</string>
     <string name="cancel">Cancel</string>
+    <string name="scan">Scan</string>
     <string name="clear">Clear</string>
     <string name="clear_comm">clearCommunicationDevice()</string>
     <string name="runTest">Run</string>
@@ -136,6 +137,13 @@
         <item>Sonification</item>
     </string-array>
 
+    <string name="spatialization_behavior_prompt">Spatialization:</string>
+    <string-array name="spatialization_behaviors">
+        <item>Unspecified</item>
+        <item>Auto</item>
+        <item>Never</item>
+    </string-array>
+
     <string name="channel_count_prompt">Channels:</string>
     <string-array name="channel_counts">
         <item>0</item>
@@ -183,6 +191,7 @@
         <item>NONE</item>
         <item>POWER_SAVING</item>
         <item>LOW_LATENCY</item>
+        <item>POWER_SAVING_OFFLOAD</item>
     </string-array>
 
     <!--Must match SignalType in NativeAudioContext.h-->
@@ -240,6 +249,7 @@
     <string name="title_route_during_callback">Route Callback Test</string>
     <string name="title_dynamic_load">Dynamic CPU Load</string>
     <string name="title_cold_start_latency">Cold Start Latency</string>
+    <string name="title_rapid_cycle">Rapid Cycle</string>
 
     <string name="need_record_audio_permission">"This app needs RECORD_AUDIO permission"</string>
     <string name="share">Share</string>
@@ -272,6 +282,11 @@
         Issue #1763
     </string>
 
+    <string name="rapid_cycle_intro">
+        Maybe cause a crash or hang by rapidly\n
+        opening, starting, and closing streams.\n
+    </string>
+
     <string-array name="conversion_qualities">
         <item>None</item>
         <item>Fastest</item>
diff --git a/apps/OboeTester/app/src/main/res/values/styles.xml b/apps/OboeTester/app/src/main/res/values/styles.xml
index 58dadb7f..81003449 100644
--- a/apps/OboeTester/app/src/main/res/values/styles.xml
+++ b/apps/OboeTester/app/src/main/res/values/styles.xml
@@ -1,7 +1,7 @@
 <resources>
 
     <!-- Base application theme. -->
-    <style name="AppTheme" parent="android:Theme.Holo.Light.DarkActionBar">
+    <style name="AppTheme" parent="Theme.AppCompat.Light">
         <!-- Customize your theme here. -->
     </style>
 
diff --git a/apps/OboeTester/build.gradle b/apps/OboeTester/build.gradle
index 3e8fe4d5..af0bbfda 100644
--- a/apps/OboeTester/build.gradle
+++ b/apps/OboeTester/build.gradle
@@ -6,7 +6,7 @@ buildscript {
         jcenter()
     }
     dependencies {
-        classpath 'com.android.tools.build:gradle:7.2.2'
+        classpath 'com.android.tools.build:gradle:8.5.1'
     }
 }
 
diff --git a/apps/OboeTester/docs/AutomatedTesting.md b/apps/OboeTester/docs/AutomatedTesting.md
index e9333ac2..69ec4a4e 100644
--- a/apps/OboeTester/docs/AutomatedTesting.md
+++ b/apps/OboeTester/docs/AutomatedTesting.md
@@ -59,13 +59,14 @@ For example:
 
 There are two required parameters for all tests:
 
-    --es test {latency, glitch, data_paths, input, output}
+    --es test {latency, glitch, data_paths, input, output, cpu_load}
             The "latency" test will perform a Round Trip Latency test.
             It will request EXCLUSIVE mode for minimal latency.
             The "glitch" test will perform a single Glitch test.
             The "data_paths" test will verify input and output streams in many possible configurations.
             The "input" test will open and start an input stream.
             The "output" test will open and start an output stream.
+            The "cpu_load" test will run the CPU LOAD activity.
 
     --es file {name of resulting file}
 
@@ -78,6 +79,7 @@ There are some optional parameter in common for all tests:
     --es volume_type        {"accessibility", "alarm", "dtmf", "music", "notification", "ring", "system", "voice_call"}
                             Stream type for the setStreamVolume() call. Default is "music".
     --ez background         {"true", 1, "false", 0} // if true then Oboetester will continue to run in the background
+    --ez foreground_service {"true", 1, "false", 0} // if true then Oboetester will ask for record/play permissions via a foreground service
 
 There are several optional parameters in common for glitch, latency, input, and output tests:
 
@@ -124,12 +126,18 @@ These parameters were used with the "data_paths" test prior to v2.5.11.
 
     --ez use_input_devices  {"true", 1, "false", 0}  // Whether to test various input devices.
     --ez use_output_devices {"true", 1, "false", 0}  // Whether to test various output devices.
-    --ez use_all_output_channel_masks {"true", 1, "false", 0}  // Whether to test all output channel masks. Default is false
+    --ez use_all_output_channel_masks {"true", 1, "false", 0}  // Whether to test all output channel masks. Default is false.
 
 There are some optional parameters for just the "output" test:
 
     --es signal_type        {sine, sawtooth, freq_sweep, pitch_sweep, white_noise} // type of sound to play, default is sine
 
+There are some optional parameters for just the "cpu_load" test:
+
+    --ez use_adpf         {true, false} // if true, use work boost from performance hints. Default is false.
+    --ez use_workload     {true, false} // if true and using ADPF then report workload changes. Default is false.
+    --ez scroll_graphics  {true, false} // if true then continually update the power scope. Default is false.
+
 For example, a complete command for a "latency" test might be:
 
     adb shell am start -n com.mobileer.oboetester/.MainActivity \
@@ -137,7 +145,6 @@ For example, a complete command for a "latency" test might be:
         --ei buffer_bursts 2 \
         --ef volume 0.8 \
         --es volume_type music \
-        --ei buffer_bursts 2 \
         --ei out_channels 1 \
         --es out_usage game \
         --es file latency20230608.txt
diff --git a/apps/OboeTester/docs/Build.md b/apps/OboeTester/docs/Build.md
index e4baf13a..880e6b4a 100644
--- a/apps/OboeTester/docs/Build.md
+++ b/apps/OboeTester/docs/Build.md
@@ -10,7 +10,7 @@ Then use Android Studio (3.3 or above) to build the app in this "apps/OboeTester
 
 ## Requirements
 
-* AndroidStudio
+* Android Studio
 * Android device or emulator
 * git installed on your computer (optional)
 * USB cable to connect your computer and your phone
@@ -27,9 +27,9 @@ If you don't use git then just download the Zip archive.
 ## Build and Run OboeTester
 
 1. Launch Android Studio
-2. Clock Open from the File menu and browse to the "oboe/apps/OboeTester" folder. Select that folder.
+2. Click Open from the File menu and browse to the "oboe/apps/OboeTester" folder. Select that folder.
 3. Wait about a minute for the project to load.
 4. Connect an Android phone to your computer using a USB cable.
 5. Look at your phone. You may need to give permission to use ADB on your phone.
 5. Select "Run App" from the "Run" menu.
-6. OboeTester should build and then appear on your computer.
+6. OboeTester should build and then appear on your Android device.
diff --git a/apps/OboeTester/docs/README.md b/apps/OboeTester/docs/README.md
index 81db8b11..1468daa7 100644
--- a/apps/OboeTester/docs/README.md
+++ b/apps/OboeTester/docs/README.md
@@ -9,8 +9,8 @@ It can also be run as part of an [automated test using Intents](AutomatedTesting
 ## Install OboeTester
 
 You have two options:
-1) Download OboeTester from [Play Store](https://play.google.com/store/apps/details?id=com.mobileer.oboetester)
-2) OR [Build latest OboeTester using Android Studio](Build.md)
+1) Download OboeTester from the [Play Store](https://play.google.com/store/apps/details?id=com.mobileer.oboetester)
+2) OR [build the latest version of OboeTester using Android Studio](Build.md)
 
 ## [How to Use OboeTester Interactively](Usage.md)
 
diff --git a/apps/OboeTester/docs/Usage.md b/apps/OboeTester/docs/Usage.md
index 6ff69389..cdb5e2f8 100644
--- a/apps/OboeTester/docs/Usage.md
+++ b/apps/OboeTester/docs/Usage.md
@@ -135,15 +135,21 @@ After that, simply press the share button and you should be able to email this t
 
 ### Data Paths
 
-This checks for dead speaker and mic channels, dead Input Presets and other audio data path problems.
+This checks for dead channels, broken Input Presets and other audio data path problems.
 
 1. Tap "DATA PATHS" button.
-1. Unplug or disconnect any headphones.
+1. Connect an analog or USB loopback adapter if desired.
 1. Set volume to medium high.
-1. Place the phone on a table in a quiet room and hit START.
-1. Wait a few minutes, quietly, for the test to complete. You will hear some sine tones.
+1. Place the phone on a table and hit START.
+2. If you are testing the speaker/mic combination then the room must be quiet. You will hear some sine tones.
+1. Wait a few minutes, quietly, for the test to complete.
 1. You will get a report at the end that you can SHARE by GMail or Drive.
 
+When a subtest fails it will write a WAV file of the recorded audio to storage. You can pull the file from the Android device and
+view it using Audacity of other audio editor. For example, if test #7 failed, enter:
+
+    adb pull /storage/emulated/0/Android/data/com.mobileer.oboetester/files/Music/glitch_007.wav ~/.
+
 ### External Tap-to-Tone
 
 This lets you measure the latency between touching a screen to the sound coming out on a second device.
@@ -170,4 +176,4 @@ Changes the VoiceCommunication route while playing audio. Targeted test for issu
 ### CPU Load
 This test plays a tone and alternates between low and high workloads.
 It exercises the kernel's CPU scheduler, which controls CPU frequency and core migration.
-Moredetails on the [wiki/OboeTester_DynamicCpuLoad](https://github.com/google/oboe/wiki/OboeTester_DynamicCpuLoad).
+More details on the [wiki/OboeTester_DynamicCpuLoad](https://github.com/google/oboe/wiki/OboeTester_DynamicCpuLoad).
diff --git a/apps/OboeTester/gradle.properties b/apps/OboeTester/gradle.properties
index 8eebfffb..d7a0e8eb 100644
--- a/apps/OboeTester/gradle.properties
+++ b/apps/OboeTester/gradle.properties
@@ -35,3 +35,6 @@
 # org.gradle.parallel=true
 android.useAndroidX=true
 android.enableJetifier=true
+android.defaults.buildfeatures.buildconfig=true
+android.nonTransitiveRClass=false
+android.nonFinalResIds=false
diff --git a/apps/OboeTester/gradle/wrapper/gradle-wrapper.properties b/apps/OboeTester/gradle/wrapper/gradle-wrapper.properties
index 37518245..7a9f45ad 100644
--- a/apps/OboeTester/gradle/wrapper/gradle-wrapper.properties
+++ b/apps/OboeTester/gradle/wrapper/gradle-wrapper.properties
@@ -3,4 +3,4 @@ distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.3-all.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.7-all.zip
diff --git a/apps/fxlab/app/CMakeLists.txt b/apps/fxlab/app/CMakeLists.txt
index 4c7c02d7..6f608689 100644
--- a/apps/fxlab/app/CMakeLists.txt
+++ b/apps/fxlab/app/CMakeLists.txt
@@ -76,4 +76,4 @@ target_link_libraries( # Specifies the target library.
         # Links the target library to the log library
         # included in the NDK.
         ${log-lib})
-
+target_link_options(native-lib PRIVATE "-Wl,-z,max-page-size=16384")
diff --git a/apps/fxlab/app/build.gradle b/apps/fxlab/app/build.gradle
index 52c34d81..794dfc5a 100644
--- a/apps/fxlab/app/build.gradle
+++ b/apps/fxlab/app/build.gradle
@@ -18,20 +18,15 @@ apply plugin: 'com.android.application'
 
 apply plugin: 'kotlin-android'
 
-apply plugin: 'kotlin-android-extensions'
-
 apply plugin: 'kotlin-kapt'
 
 android {
-    compileSdkVersion 34
-    compileOptions {
-        sourceCompatibility JavaVersion.VERSION_1_8
-        targetCompatibility JavaVersion.VERSION_1_8
-    }
+    compileSdkVersion 35
+
     defaultConfig {
         applicationId "com.mobileer.androidfxlab"
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
         versionCode 1
         versionName "1.0"
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
@@ -42,26 +37,33 @@ android {
             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
         }
     }
+    compileOptions {
+        sourceCompatibility = JavaVersion.VERSION_18
+        targetCompatibility = JavaVersion.VERSION_18
+    }
+    kotlinOptions {
+        jvmTarget = "18"
+    }
     externalNativeBuild {
         cmake {
             path "./CMakeLists.txt"
-            version "3.10.2"
         }
     }
     dataBinding {
         enabled = true
     }
+    namespace 'com.mobileer.androidfxlab'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
-    implementation"org.jetbrains.kotlin:kotlin-stdlib-jdk7:$kotlin_version"
-    implementation 'androidx.appcompat:appcompat:1.1.0'
-    implementation 'androidx.core:core-ktx:1.1.0'
-    implementation 'androidx.constraintlayout:constraintlayout:1.1.3'
-    implementation 'androidx.recyclerview:recyclerview:1.0.0'
-    implementation 'com.google.android.material:material:1.2.0-alpha01'
-    testImplementation 'junit:junit:4.12'
-    androidTestImplementation 'androidx.test:runner:1.2.0'
-    androidTestImplementation 'androidx.test.espresso:espresso-core:3.2.0'
+    implementation "org.jetbrains.kotlin:kotlin-stdlib-jdk7:$kotlin_version"
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.core:core-ktx:1.15.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
+    implementation 'androidx.recyclerview:recyclerview:1.4.0'
+    implementation 'com.google.android.material:material:1.12.0'
+    testImplementation 'junit:junit:4.13.2'
+    androidTestImplementation 'androidx.test:runner:1.6.2'
+    androidTestImplementation 'androidx.test.espresso:espresso-core:3.6.1'
 }
diff --git a/apps/fxlab/app/src/main/AndroidManifest.xml b/apps/fxlab/app/src/main/AndroidManifest.xml
index 87375b4f..4b91d528 100644
--- a/apps/fxlab/app/src/main/AndroidManifest.xml
+++ b/apps/fxlab/app/src/main/AndroidManifest.xml
@@ -15,8 +15,7 @@
   ~ limitations under the License.
   -->
 
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-          package="com.mobileer.androidfxlab">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
             android:allowBackup="true"
diff --git a/apps/fxlab/app/src/main/cpp/native-lib.cpp b/apps/fxlab/app/src/main/cpp/native-lib.cpp
index 5ccdfb05..165de68b 100644
--- a/apps/fxlab/app/src/main/cpp/native-lib.cpp
+++ b/apps/fxlab/app/src/main/cpp/native-lib.cpp
@@ -16,6 +16,7 @@
 
 #include <jni.h>
 
+#include <cassert>
 #include <string>
 #include <functional>
 #include <utility>
diff --git a/apps/fxlab/build.gradle b/apps/fxlab/build.gradle
index 228fb6be..c1d13a54 100644
--- a/apps/fxlab/build.gradle
+++ b/apps/fxlab/build.gradle
@@ -17,28 +17,29 @@
 // Top-level build file where you can add configuration options common to all sub-projects/modules.
 
 buildscript {
-    ext.kotlin_version = '1.7.0'
+    ext {
+        kotlin_version = '2.1.10'
+    }
     repositories {
         google()
-        jcenter()
-        
+        mavenCentral()
     }
     dependencies {
-        classpath 'com.android.tools.build:gradle:7.2.1'
-        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
+        classpath 'com.android.tools.build:gradle:8.9.0'
         // NOTE: Do not place your application dependencies here; they belong
         // in the individual module build.gradle files
+        classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
+        classpath "org.jetbrains.kotlin:compose-compiler-gradle-plugin:$kotlin_version"
     }
 }
 
 allprojects {
     repositories {
         google()
-        jcenter()
-        
+        mavenCentral()
     }
 }
 
-task clean(type: Delete) {
-    delete rootProject.buildDir
+tasks.register('clean', Delete) {
+    delete rootProject.layout.buildDirectory
 }
diff --git a/apps/fxlab/gradle.properties b/apps/fxlab/gradle.properties
index 5b3f78ef..a2bb5f48 100644
--- a/apps/fxlab/gradle.properties
+++ b/apps/fxlab/gradle.properties
@@ -35,3 +35,6 @@ android.useAndroidX=true
 android.enableJetifier=true
 # Kotlin code style for this project: "official" or "obsolete":
 kotlin.code.style=official
+android.defaults.buildfeatures.buildconfig=true
+android.nonTransitiveRClass=false
+android.nonFinalResIds=false
diff --git a/apps/fxlab/gradle/wrapper/gradle-wrapper.properties b/apps/fxlab/gradle/wrapper/gradle-wrapper.properties
index 3bd6ace6..b1049b58 100644
--- a/apps/fxlab/gradle/wrapper/gradle-wrapper.properties
+++ b/apps/fxlab/gradle/wrapper/gradle-wrapper.properties
@@ -1,6 +1,6 @@
-#Tue Jun 25 14:12:01 PDT 2019
+#Tue Mar 11 13:58:39 EDT 2025
 distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.11.1-bin.zip
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.3-all.zip
diff --git a/build_all_android.sh b/build_all_android.sh
index 1e5e624a..98ae0456 100755
--- a/build_all_android.sh
+++ b/build_all_android.sh
@@ -51,6 +51,7 @@ function build_oboe {
         -DANDROID_ABI=${ABI} \
         -DCMAKE_ARCHIVE_OUTPUT_DIRECTORY=${STAGING_DIR}/lib/${ABI} \
         -DANDROID_PLATFORM=android-${MINIMUM_API_LEVEL}\
+        -DANDROID_SUPPORT_FLEXIBLE_PAGE_SIZES=ON \
         ${CMAKE_ARGS}
 
   pushd ${ABI_BUILD_DIR}
diff --git a/docs/AppsUsingOboe.md b/docs/AppsUsingOboe.md
deleted file mode 100644
index e6594ca6..00000000
--- a/docs/AppsUsingOboe.md
+++ /dev/null
@@ -1,3 +0,0 @@
-# Projects using Oboe or AAudio
-
-This page was moved to the Wiki at [AppsUsingOboe](https://github.com/google/oboe/wiki/AppsUsingOboe).
diff --git a/docs/FullGuide.md b/docs/FullGuide.md
index 405e48f2..b04a1b1a 100644
--- a/docs/FullGuide.md
+++ b/docs/FullGuide.md
@@ -53,6 +53,9 @@ Oboe permits these sample formats:
 | :------------ | :---------- | :---- |
 | I16 | int16_t | common 16-bit samples, [Q0.15 format](https://source.android.com/devices/audio/data_formats#androidFormats) |
 | Float | float | -1.0 to +1.0 |
+| I24 | N/A | 24-bit samples packed into 3 bytes, [Q0.23 format](https://source.android.com/devices/audio/data_formats#androidFormats). Added in API 31 |
+| I32 | int32_t | common 32-bit samples, [Q0.31 format](https://source.android.com/devices/audio/data_formats#androidFormats). Added in API 31 |
+| IEC61937 | N/A | compressed audio wrapped in IEC61937 for HDMI or S/PDIF passthrough. Added in API 34 |
 
 Oboe might perform sample conversion on its own. For example, if an app is writing AudioFormat::Float data but the HAL uses AudioFormat::I16, Oboe might convert the samples automatically. Conversion can happen in either direction. If your app processes audio input, it is wise to verify the input format and be prepared to convert data if necessary, as in this example:
 
@@ -115,7 +118,7 @@ The following properties are guaranteed to be set. However, if these properties
 are unspecified, a default value will still be set, and should be queried by the 
 appropriate accessor.
 
-* framesPerCallback
+* framesPerDataCallback
 * sampleRate
 * channelCount
 * format
@@ -154,6 +157,13 @@ Oboe or the underlyng API will limit the size between zero and the buffer capaci
 It may also be limited further to reduce glitching on particular devices.
 This feature is not supported when using a callback with OpenSL ES.
 
+The following properties are helpful for older devices to achieve optimal results.
+
+* `setChannelConversionAllowed()` enables channel conversions. This is false by default.
+* `setFormatConversionAllowed()` enables format conversions. This is false by default.
+* `setSampleRateConversionQuality()` enables sample rate conversions.
+  This defaults to SampleRateConversionQuality::Medium.
+
 Many of the stream's properties may vary (whether or not you set
 them) depending on the capabilities of the audio device and the Android device on 
 which it's running. If you need to know these values then you must query them using 
@@ -178,10 +188,17 @@ builder setting:
 | `setChannelCount()` | `getChannelCount()` |
 | `setFormat()` | `getFormat()` |
 | `setBufferCapacityInFrames()` | `getBufferCapacityInFrames()` |
-| `setFramesPerCallback()` | `getFramesPerCallback()` |
+| `setFramesPerDataCallback()` | `getFramesPerDataCallback()` |
 |  --  | `getFramesPerBurst()` |
 | `setDeviceId()` (not respected on OpenSLES) | `getDeviceId()` |
 | `setAudioApi()` (mainly for debugging) | `getAudioApi()` |
+| `setChannelConversionAllowed()` | `isChannelConversionAllowed()` |
+| `setFormatConversionAllowed()` | `setFormatConversionAllowed()` |
+| `setSampleRateConversionQuality` | `getSampleRateConversionQuality()` |
+
+### AAudio specific AudioStreamBuilder fields
+
+Some AudioStreamBuilder fields are only applied to AAudio
 
 The following AudioStreamBuilder fields were added in API 28 to
 specify additional information about the AudioStream to the device. Currently, 
@@ -197,9 +214,35 @@ it is set to VoiceRecognition, which is optimized for low latency.
   by the stream.
 * `setInputPreset(oboe::InputPreset inputPreset)` - The recording configuration
   for an audio input.
-* `setSessionId(SessionId sessionId)` - Allocate SessionID to connect to the
+* `setSessionId(oboe::SessionId sessionId)` - Allocate SessionID to connect to the
   Java AudioEffects API.
 
+In API 29, `setAllowedCapturePolicy(oboe::AllowedCapturePolicy allowedCapturePolicy)` was added.
+This specifies whether this stream audio may or may not be captured by other apps or the system.
+
+In API 30, `setPrivacySensitiveMode(oboe::PrivacySensitiveMode privacySensitiveMode)` was added.
+Concurrent capture is not permitted for privacy sensitive input streams.
+
+In API 31, the following APIs were added:
+* `setPackageName(std::string packageName)` - Declare the name of the package creating the stream.
+  The default, if you do not call this function, is a random package in the calling uid.
+* `setAttributionTag(std::string attributionTag)` - Declare the attribution tag of the context creating the stream.
+  Attribution can be used in complex apps to logically separate parts of the app.
+
+In API 32, the following APIs were added:
+* `setIsContentSpatialized(bool isContentSpatialized)` - Marks that the content is already spatialized
+  to prevent double-processing.
+* `setSpatializationBehavior(oboe::SpatializationBehavior spatializationBehavior)` - Marks what the default
+  spatialization behavior should be.
+* `setChannelMask(oboe::ChannelMask)` - Requests a specific channel mask. The number of channels may be
+  different than setChannelCount. The last called will be respected if this function and setChannelCount()
+  are called.
+
+In API 34, the following APIs were added to streams to get properties of the hardware.
+* `getHardwareChannelCount()`
+* `getHardwareSampleRate()`
+* `getHardwareFormat()`
+
 
 ## Using an audio stream
 
@@ -336,7 +379,11 @@ If you need to be informed when an audio device is disconnected, write a class
 which extends `AudioStreamErrorCallback` and then register your class using `builder.setErrorCallback(yourCallbackClass)`. It is recommended to pass a shared_ptr.
 If you register a callback, then it will automatically close the stream in a separate thread if the stream is disconnected.
 
-Your callback can implement the following methods (called in a separate thread): 
+Note that error callbacks will only be called when a data callback has been specified
+and the stream is started. If you are not using a data callback then the read(), write()
+and requestStart() methods will return errors if the stream is disconnected.
+     
+Your error callback can implement the following methods (called in a separate thread): 
 
 * `onErrorBeforeClose(stream, error)` - called when the stream has been disconnected but not yet closed,
   so you can still reference the underlying stream (e.g.`getXRunCount()`).
diff --git a/docs/GettingStarted.md b/docs/GettingStarted.md
index 5d1d3797..307d0e44 100644
--- a/docs/GettingStarted.md
+++ b/docs/GettingStarted.md
@@ -1,4 +1,7 @@
 # Adding Oboe to your project
+
+Oboe is a C++ library. So your Android Studio project will need to [support native C++ code](https://developer.android.com/studio/projects/add-native-code).
+
 There are two ways use Oboe in your Android Studio project: 
 
 1) **Use the Oboe pre-built library binaries and headers**. Use this approach if you just want to use a stable version of the Oboe library in your project.
@@ -17,6 +20,10 @@ Add the oboe dependency to your app's `build.gradle` file. Replace "X.X.X" with
         implementation 'com.google.oboe:oboe:X.X.X'
     }
 
+For `build.gradle.kts` add parentheses:
+
+        implementation("com.google.oboe:oboe:X.X.X")
+
 Also enable prefab by adding:
 
     android {
@@ -24,6 +31,10 @@ Also enable prefab by adding:
             prefab true
         }
     }
+
+For `build.gradle.kts` add an equal sign:
+
+            prefab = true
     
 Include and link to oboe by updating your `CMakeLists.txt`: 
 
@@ -51,10 +62,14 @@ Configure your app to use the shared STL by updating your `app/build.gradle`:
                 cmake {
                     arguments "-DANDROID_STL=c++_shared"
                 }
-	        }
+            }
         }
     }
 
+For `app/build.gradle.kts` add parentheses:
+
+          arguments("-DANDROID_STL=c++_shared")
+
 ## Option 2) Building from source
 
 ### 1. Clone the github repository
diff --git a/docs/README.md b/docs/README.md
index 33ce62c8..371fe6bc 100644
--- a/docs/README.md
+++ b/docs/README.md
@@ -2,7 +2,7 @@ Oboe documentation
 ===
 - [Android Audio History](AndroidAudioHistory.md)
 - [API reference](https://google.github.io/oboe/)
-- [Apps using Oboe](AppsUsingOboe.md)
+- [Apps using Oboe](https://github.com/google/oboe/wiki/AppsUsingOboe)
 - [FAQs](FAQ.md)
 - [Full Guide to Oboe](FullGuide.md)
 - [Getting Started with Oboe](GettingStarted.md)
diff --git a/src/common/AudioClock.h b/include/oboe/AudioClock.h
similarity index 95%
rename from src/common/AudioClock.h
rename to include/oboe/AudioClock.h
index 3fe20cb0..efbfbf7f 100644
--- a/src/common/AudioClock.h
+++ b/include/oboe/AudioClock.h
@@ -23,7 +23,6 @@
 
 namespace oboe {
 
-// TODO: Move this class into the public headers because it is useful when calculating stream latency
 class AudioClock {
 public:
     static int64_t getNanoseconds(clockid_t clockId = CLOCK_MONOTONIC) {
diff --git a/include/oboe/AudioStream.h b/include/oboe/AudioStream.h
index 817099d5..67856020 100644
--- a/include/oboe/AudioStream.h
+++ b/include/oboe/AudioStream.h
@@ -26,8 +26,6 @@
 #include "oboe/AudioStreamBuilder.h"
 #include "oboe/AudioStreamBase.h"
 
-/** WARNING - UNDER CONSTRUCTION - THIS API WILL CHANGE. */
-
 namespace oboe {
 
 /**
@@ -54,7 +52,7 @@ public:
      */
     explicit AudioStream(const AudioStreamBuilder &builder);
 
-    virtual ~AudioStream() = default;
+    virtual ~AudioStream();
 
     /**
      * Open a stream based on the current settings.
@@ -517,18 +515,18 @@ public:
      *
      * The flag will be checked in the Oboe data callback. If it transitions from false to true
      * then the PerformanceHint feature will be started.
-     * This only needs to be called once.
+     * This only needs to be called once for each stream.
      *
      * You may want to enable this if you have a dynamically changing workload
-     * and you notice that you are getting underruns and glitches when your workload increases.
+     * and you notice that you are getting under-runs and glitches when your workload increases.
      * This might happen, for example, if you suddenly go from playing one note to
      * ten notes on a synthesizer.
      *
-     * Try the CPU Load test in OboeTester if you would like to experiment with this interactively.
+     * Try the "CPU Load" test in OboeTester if you would like to experiment with this interactively.
      *
      * On some devices, this may be implemented using the "ADPF" library.
      *
-     * @param enabled true if you would like a performance boost
+     * @param enabled true if you would like a performance boost, default is false
      */
     void setPerformanceHintEnabled(bool enabled) {
         mPerformanceHintEnabled = enabled;
@@ -544,6 +542,55 @@ public:
         return mPerformanceHintEnabled;
     }
 
+    /**
+     * Use this to give the performance manager more information about your workload.
+     * You can call this at the beginning of the callback when you figure
+     * out what your workload will be.
+     *
+     * Call this if (1) you have called setPerformanceHintEnabled(true), and
+     * (2) you have a varying workload, and
+     * (3) you hear glitches when your workload suddenly increases.
+     *
+     * This might happen when you go from a single note to a big chord on a synthesizer.
+     *
+     * The workload can be in your own units. If you are synthesizing music
+     * then the workload could be the number of active voices.
+     * If your app is a game then it could be the number of sound effects.
+     * The units are arbitrary. They just have to be proportional to
+     * the estimated computational load. For example, if some of your voices take 20%
+     * more computation than a basic voice then assign 6 units to the complex voice
+     * and 5 units to the basic voice.
+     *
+     * The performance hint code can use this as an advance warning that the callback duration
+     * will probably increase. Rather than wait for the long duration and possibly under-run,
+     * we can boost the CPU immediately before we start doing the calculations.
+     *
+     * @param appWorkload workload in application units, such as number of voices
+     * @return OK or an error such as ErrorInvalidState if the PerformanceHint was not enabled.
+     */
+    virtual oboe::Result reportWorkload(int32_t appWorkload) {
+        std::ignore = appWorkload;
+        return oboe::Result::ErrorUnimplemented;
+    }
+
+    virtual oboe::Result setOffloadDelayPadding(int32_t delayInFrames, int32_t paddingInFrames) {
+        std::ignore = delayInFrames;
+        std::ignore = paddingInFrames;
+        return Result::ErrorUnimplemented;
+    }
+
+    virtual ResultWithValue<int32_t> getOffloadDelay() {
+        return ResultWithValue<int32_t>(Result::ErrorUnimplemented);
+    }
+
+    virtual ResultWithValue<int32_t> getOffloadPadding() {
+        return ResultWithValue<int32_t>(Result::ErrorUnimplemented);
+    }
+
+    virtual oboe::Result setOffloadEndOfStream() {
+        return Result::ErrorUnimplemented;
+    }
+
 protected:
 
     /**
diff --git a/include/oboe/AudioStreamBase.h b/include/oboe/AudioStreamBase.h
index 6222e448..6ef6b1ea 100644
--- a/include/oboe/AudioStreamBase.h
+++ b/include/oboe/AudioStreamBase.h
@@ -121,6 +121,14 @@ public:
         return mErrorCallback;
     }
 
+    /**
+     * For internal use only.
+     * @return the presentation callback object for this stream, if set.
+     */
+    std::shared_ptr<AudioStreamPresentationCallback> getPresentationCallback() const {
+        return mSharedPresentationCallback;
+    }
+
     /**
      * @return true if a data callback was set for this stream
      */
@@ -137,6 +145,13 @@ public:
         return mErrorCallback != nullptr;
     }
 
+    /**
+     * @return true if a presentation callback was set for this stream
+     */
+    bool isPresentationCallbackSpecified() const {
+        return mSharedPresentationCallback != nullptr;
+    }
+
     /**
      * @return the usage for this stream.
      */
@@ -244,6 +259,8 @@ protected:
     AudioStreamErrorCallback       *mErrorCallback = nullptr;
     std::shared_ptr<AudioStreamErrorCallback> mSharedErrorCallback;
 
+    std::shared_ptr<AudioStreamPresentationCallback> mSharedPresentationCallback;
+
     /** Number of audio frames which will be requested in each callback */
     int32_t                         mFramesPerCallback = kUnspecified;
     /** Stream channel count */
@@ -307,7 +324,7 @@ protected:
     // Control whether Oboe can convert data formats to achieve optimal results.
     bool                            mFormatConversionAllowed = false;
     // Control whether and how Oboe can convert sample rates to achieve optimal results.
-    SampleRateConversionQuality     mSampleRateConversionQuality = SampleRateConversionQuality::None;
+    SampleRateConversionQuality     mSampleRateConversionQuality = SampleRateConversionQuality::Medium;
 
     /** Validate stream parameters that might not be checked in lower layers */
     virtual Result isValidConfig() {
diff --git a/include/oboe/AudioStreamBuilder.h b/include/oboe/AudioStreamBuilder.h
index 1574a398..accea2f4 100644
--- a/include/oboe/AudioStreamBuilder.h
+++ b/include/oboe/AudioStreamBuilder.h
@@ -465,6 +465,10 @@ public:
      * This can occur when a stream is disconnected because a headset is plugged in or unplugged.
      * It can also occur if the audio service fails or if an exclusive stream is stolen by
      * another stream.
+     * 
+     * Note that error callbacks will only be called when a data callback has been specified
+     * and the stream is started. If you are not using a data callback then the read(), write()
+     * and requestStart() methods will return errors if the stream is disconnected.
      *
      * <strong>Important: See AudioStreamCallback for restrictions on what may be called
      * from the callback methods.</strong>
@@ -501,6 +505,30 @@ public:
         return this;
     }
 
+    /**
+     * Specifies an object to handle data presentation related callbacks from the underlying API.
+     * This can occur when all data queued in the audio system for an offload stream has been
+     * played.
+     *
+     * Note that presentation callbacks will only be called when a data callback has been specified
+     * and the stream is started.
+     *
+     * <strong>Important: See AudioStreamCallback for restrictions on what may be called
+     * from the callback methods.</strong>
+     *
+     * We pass a shared_ptr so that the presentationCallback object cannot be deleted before the
+     * stream is deleted. If the stream was created using a shared_ptr then the stream cannot be
+     * deleted before the presentation callback has finished running.
+     *
+     * @param sharedPresentationCallback
+     * @return pointer to the builder so calls can be chained
+     */
+    AudioStreamBuilder *setPresentationCallback(
+            std::shared_ptr<AudioStreamPresentationCallback> sharedPresentationCallback) {
+        mSharedPresentationCallback = sharedPresentationCallback;
+        return this;
+    }
+
     /**
      * Specifies an object to handle data or error related callbacks from the underlying API.
      *
@@ -556,7 +584,7 @@ public:
      *
      * If you do the conversion in Oboe then you might still get a low latency stream.
      *
-     * Default is SampleRateConversionQuality::None
+     * Default is SampleRateConversionQuality::Medium
      */
     AudioStreamBuilder *setSampleRateConversionQuality(SampleRateConversionQuality quality) {
         mSampleRateConversionQuality = quality;
diff --git a/include/oboe/AudioStreamCallback.h b/include/oboe/AudioStreamCallback.h
index 8d8e2feb..8a9aada0 100644
--- a/include/oboe/AudioStreamCallback.h
+++ b/include/oboe/AudioStreamCallback.h
@@ -169,6 +169,27 @@ public:
 
 };
 
+/**
+ * AudioStreamPresentationCallback defines a callback interface for
+ * being notified when a data presentation event is filed.
+ *
+ * It is used with AudioStreamBuilder::setPresentationCallback().
+ */
+class AudioStreamPresentationCallback {
+public:
+    virtual ~AudioStreamPresentationCallback() = default;
+
+    /**
+     * This will be called when all the buffers of an offloaded
+     * stream that were queued in the audio system (e.g. the
+     * combination of the Android audio framework and the device's
+     * audio hardware) have been played.
+     *
+     * @param audioStream pointer to the associated stream
+     */
+    virtual void onPresentationEnded(AudioStream* /* audioStream */) {}
+};
+
 /**
  * AudioStreamCallback defines a callback interface for:
  *
diff --git a/include/oboe/Definitions.h b/include/oboe/Definitions.h
index aaf4d640..769f3f13 100644
--- a/include/oboe/Definitions.h
+++ b/include/oboe/Definitions.h
@@ -152,6 +152,41 @@ namespace oboe {
         * Available since API 34 (U).
         */
         IEC61937 = 5, // AAUDIO_FORMAT_IEC61937
+
+        /**
+         * This format is used for audio compressed in MP3 format.
+         */
+        MP3 = 6, // AAUDIO_FORMAT_MP3
+
+        /**
+         * This format is used for audio compressed in AAC LC format.
+         */
+        AAC_LC, // AAUDIO_FORMAT_AAC_LC
+
+        /**
+         * This format is used for audio compressed in AAC HE V1 format.
+         */
+        AAC_HE_V1, // AAUDIO_FORMAT_AAC_HE_V1,
+
+        /**
+         * This format is used for audio compressed in AAC HE V2 format.
+         */
+        AAC_HE_V2, // AAUDIO_FORMAT_AAC_HE_V2
+
+        /**
+         * This format is used for audio compressed in AAC ELD format.
+         */
+        AAC_ELD, // AAUDIO_FORMAT_AAC_ELD
+
+        /**
+         * This format is used for audio compressed in AAC XHE format.
+         */
+        AAC_XHE, // AAUDIO_FORMAT_AAC_XHE
+
+        /**
+         * This format is used for audio compressed in OPUS.
+         */
+        OPUS, // AAUDIO_FORMAT_OPUS
     };
 
     /**
@@ -246,6 +281,16 @@ namespace oboe {
          * Reducing latency is most important.
          */
         LowLatency = 12, // AAUDIO_PERFORMANCE_MODE_LOW_LATENCY
+
+        /**
+         * Extending battery life is more important than low latency.
+         *
+         * This mode is not supported in input streams.
+         * This mode will play through the offloaded audio path to save battery life.
+         * With the offload playback, the default data callback size will be large and it
+         * allows data feeding thread to sleep longer time after sending enough data.
+         */
+        POWER_SAVING_OFFLOADED = 13, // AAUDIO_PERFORMANCE_MODE_POWER_SAVING_OFFLOADED
     };
 
     /**
@@ -834,6 +879,204 @@ namespace oboe {
         None = 3,
     };
 
+    /**
+     * Audio device type.
+     *
+     * Note that these match the device types defined in android/media/AudioDeviceInfo.java
+     * and the definitions of AAudio_DeviceType in AAudio.h.
+     *
+     * Added in API level 36 for AAudio.
+     */
+    enum class DeviceType : int32_t {
+        /**
+         * A device type describing the attached earphone speaker.
+         */
+        BuiltinEarpiece = 1,
+
+        /**
+         * A device type describing the speaker system (i.e. a mono speaker or stereo speakers)
+         * built in a device.
+         */
+        BuiltinSpeaker = 2,
+
+        /**
+         * A device type describing a headset, which is the combination of a headphones and
+         * microphone.
+         */
+        WiredHeadset = 3,
+
+        /**
+         * A device type describing a pair of wired headphones.
+         */
+        WiredHeadphones = 4,
+
+        /**
+         * A device type describing an analog line-level connection.
+         */
+        LineAnalog = 5,
+
+        /**
+         * A device type describing a digital line connection (e.g. SPDIF).
+         */
+        LineDigital = 6,
+
+        /**
+         * A device type describing a Bluetooth device typically used for telephony.
+         */
+        BluetoothSco = 7,
+
+        /**
+         * A device type describing a Bluetooth device supporting the A2DP profile.
+         */
+        BluetoothA2dp = 8,
+
+        /**
+         * A device type describing an HDMI connection .
+         */
+        Hdmi = 9,
+
+        /**
+         * A device type describing the Audio Return Channel of an HDMI connection.
+         */
+        HdmiArc = 10,
+
+        /**
+         * A device type describing a USB audio device.
+         */
+        UsbDevice = 11,
+
+        /**
+         * A device type describing a USB audio device in accessory mode.
+         */
+        UsbAccessory = 12,
+
+        /**
+         * A device type describing the audio device associated with a dock.
+         */
+        Dock = 13,
+
+        /**
+         * A device type associated with the transmission of audio signals over FM.
+         */
+        FM = 14,
+
+        /**
+         * A device type describing the microphone(s) built in a device.
+         */
+        BuiltinMic = 15,
+
+        /**
+         * A device type for accessing the audio content transmitted over FM.
+         */
+        FMTuner = 16,
+
+        /**
+         * A device type for accessing the audio content transmitted over the TV tuner system.
+         */
+        TVTuner = 17,
+
+        /**
+         * A device type describing the transmission of audio signals over the telephony network.
+         */
+        Telephony = 18,
+
+        /**
+         * A device type describing the auxiliary line-level connectors.
+         */
+        AuxLine = 19,
+
+        /**
+         * A device type connected over IP.
+         */
+        IP = 20,
+
+        /**
+         * A type-agnostic device used for communication with external audio systems.
+         */
+        Bus = 21,
+
+        /**
+         * A device type describing a USB audio headset.
+         */
+        UsbHeadset = 22,
+
+        /**
+         * A device type describing a Hearing Aid.
+         */
+        HearingAid = 23,
+
+        /**
+         * A device type describing the speaker system (i.e. a mono speaker or stereo speakers)
+         * built in a device, that is specifically tuned for outputting sounds like notifications
+         * and alarms (i.e. sounds the user couldn't necessarily anticipate).
+         * <p>Note that this physical audio device may be the same as {@link #TYPE_BUILTIN_SPEAKER}
+         * but is driven differently to safely accommodate the different use case.</p>
+         */
+        BuiltinSpeakerSafe = 24,
+
+        /**
+         * A device type for rerouting audio within the Android framework between mixes and
+         * system applications.
+         */
+        RemoteSubmix = 25,
+        /**
+         * A device type describing a Bluetooth Low Energy (BLE) audio headset or headphones.
+         * Headphones are grouped with headsets when the device is a sink:
+         * the features of headsets and headphones with regard to playback are the same.
+         */
+        BleHeadset = 26,
+
+        /**
+         * A device type describing a Bluetooth Low Energy (BLE) audio speaker.
+         */
+        BleSpeaker = 27,
+
+        /**
+         * A device type describing the Enhanced Audio Return Channel of an HDMI connection.
+         */
+        HdmiEarc = 29,
+
+        /**
+         * A device type describing a Bluetooth Low Energy (BLE) broadcast group.
+         */
+        BleBroadcast = 30,
+
+        /**
+         * A device type describing the audio device associated with a dock using an
+         * analog connection.
+         */
+        DockAnalog = 31
+    };
+
+    /**
+     * MMAP policy is defined to describe how aaudio MMAP will be used.
+     *
+     * Added in API level 36.
+     */
+    enum class MMapPolicy : int32_t {
+        /**
+         * When MMAP policy is not specified or the querying API is not supported.
+         */
+        Unspecified = kUnspecified,
+
+        /**
+         * AAudio MMAP is disabled and never used.
+         */
+        Never = 1,
+
+        /**
+         * AAudio MMAP support depends on device's availability. It will be used
+         * when it is possible or fallback to the normal path, where the audio data
+         * will be delivered via audio framework data pipeline.
+         */
+        Auto,
+
+        /**
+         * AAudio MMAP must be used or fail.
+         */
+        Always
+    };
+
     /**
      * On API 16 to 26 OpenSL ES will be used. When using OpenSL ES the optimal values for sampleRate and
      * framesPerBurst are not known by the native code.
diff --git a/include/oboe/FullDuplexStream.h b/include/oboe/FullDuplexStream.h
index d3ee3abf..0e9585f4 100644
--- a/include/oboe/FullDuplexStream.h
+++ b/include/oboe/FullDuplexStream.h
@@ -53,39 +53,69 @@ public:
     virtual ~FullDuplexStream() = default;
 
     /**
-     * Sets the input stream. Calling this is mandatory.
+     * Sets the input stream.
      *
+     * @deprecated Call setSharedInputStream(std::shared_ptr<AudioStream> &stream) instead.
      * @param stream the output stream
      */
     void setInputStream(AudioStream *stream) {
-        mInputStream = stream;
+        mRawInputStream = stream;
+    }
+
+    /**
+     * Sets the input stream. Calling this is mandatory.
+     *
+     * @param stream the output stream
+     */
+    void setSharedInputStream(std::shared_ptr<AudioStream> &stream) {
+        mSharedInputStream = stream;
     }
 
     /**
-     * Gets the input stream
+     * Gets the current input stream. This function tries to return the shared input stream if it
+     * is set before the raw input stream.
      *
-     * @return the input stream
+     * @return pointer to an output stream or nullptr.
      */
     AudioStream *getInputStream() {
-        return mInputStream;
+        if (mSharedInputStream) {
+            return mSharedInputStream.get();
+        } else {
+            return mRawInputStream;
+        }
     }
 
     /**
-     * Sets the output stream. Calling this is mandatory.
+     * Sets the output stream.
      *
+     * @deprecated Call setSharedOutputStream(std::shared_ptr<AudioStream> &stream) instead.
      * @param stream the output stream
      */
     void setOutputStream(AudioStream *stream) {
-        mOutputStream = stream;
+        mRawOutputStream = stream;
+    }
+
+    /**
+     * Sets the output stream. Calling this is mandatory.
+     *
+     * @param stream the output stream
+     */
+    void setSharedOutputStream(std::shared_ptr<AudioStream> &stream) {
+        mSharedOutputStream = stream;
     }
 
     /**
-     * Gets the output stream
+     * Gets the current output stream. This function tries to return the shared output stream if it
+     * is set before the raw output stream.
      *
-     * @return the output stream
+     * @return pointer to an output stream or nullptr.
      */
     AudioStream *getOutputStream() {
-        return mOutputStream;
+        if (mSharedOutputStream) {
+            return mSharedOutputStream.get();
+        } else {
+            return mRawOutputStream;
+        }
     }
 
     /**
@@ -123,10 +153,10 @@ public:
         Result outputResult = Result::OK;
         Result inputResult = Result::OK;
         if (getOutputStream()) {
-            outputResult = mOutputStream->requestStop();
+            outputResult = getOutputStream()->requestStop();
         }
         if (getInputStream()) {
-            inputResult = mInputStream->requestStop();
+            inputResult = getOutputStream()->requestStop();
         }
         if (outputResult != Result::OK) {
             return outputResult;
@@ -312,8 +342,10 @@ private:
     // Discard some callbacks so the input and output reach equilibrium.
     int32_t              mCountCallbacksToDiscard = kNumCallbacksToDiscard;
 
-    AudioStream   *mInputStream = nullptr;
-    AudioStream   *mOutputStream = nullptr;
+    AudioStream *mRawInputStream = nullptr;
+    AudioStream *mRawOutputStream = nullptr;
+    std::shared_ptr<AudioStream> mSharedInputStream;
+    std::shared_ptr<AudioStream> mSharedOutputStream;
 
     int32_t              mBufferSize = 0;
     std::unique_ptr<float[]> mInputBuffer;
diff --git a/include/oboe/Oboe.h b/include/oboe/Oboe.h
index b9c948af..9cd90968 100644
--- a/include/oboe/Oboe.h
+++ b/include/oboe/Oboe.h
@@ -36,5 +36,6 @@
 #include "oboe/FifoBuffer.h"
 #include "oboe/OboeExtensions.h"
 #include "oboe/FullDuplexStream.h"
+#include "oboe/AudioClock.h"
 
 #endif //OBOE_OBOE_H
diff --git a/include/oboe/Version.h b/include/oboe/Version.h
index a410f0f4..38150078 100644
--- a/include/oboe/Version.h
+++ b/include/oboe/Version.h
@@ -34,10 +34,10 @@
 #define OBOE_VERSION_MAJOR 1
 
 // Type: 8-bit unsigned int. Min value: 0 Max value: 255. See below for description.
-#define OBOE_VERSION_MINOR 8
+#define OBOE_VERSION_MINOR 9
 
 // Type: 16-bit unsigned int. Min value: 0 Max value: 65535. See below for description.
-#define OBOE_VERSION_PATCH 2
+#define OBOE_VERSION_PATCH 3
 
 #define OBOE_STRINGIFY(x) #x
 #define OBOE_TOSTRING(x) OBOE_STRINGIFY(x)
diff --git a/samples/LiveEffect/build.gradle b/samples/LiveEffect/build.gradle
index 50fb0953..a3ff386d 100644
--- a/samples/LiveEffect/build.gradle
+++ b/samples/LiveEffect/build.gradle
@@ -1,12 +1,12 @@
 apply plugin: 'com.android.application'
+apply plugin: 'kotlin-android'
 
 android {
-    compileSdkVersion 34
-
+    compileSdkVersion 35
     defaultConfig {
         applicationId 'com.google.oboe.samples.liveeffect'
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
         versionCode 1
         versionName '1.0'
         ndk {
@@ -24,15 +24,20 @@ android {
             minifyEnabled false
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path 'src/main/cpp/CMakeLists.txt'
         }
     }
+    namespace 'com.google.oboe.samples.liveEffect'
 }
 
 dependencies {
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    implementation 'androidx.constraintlayout:constraintlayout:1.1.3'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
     implementation project(':audio-device')
 }
diff --git a/samples/LiveEffect/src/main/AndroidManifest.xml b/samples/LiveEffect/src/main/AndroidManifest.xml
index a43a6d76..93686306 100644
--- a/samples/LiveEffect/src/main/AndroidManifest.xml
+++ b/samples/LiveEffect/src/main/AndroidManifest.xml
@@ -1,11 +1,13 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.liveEffect" >
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <uses-feature android:name="android.hardware.microphone" android:required="true" />
     <uses-feature android:name="android.hardware.audio.output" android:required="true" />
     <uses-permission android:name="android.permission.RECORD_AUDIO" />
     <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MEDIA_PLAYBACK" />
+    <uses-permission android:name="android.permission.FOREGROUND_SERVICE_MICROPHONE" />
     <application
         android:allowBackup="false"
         android:fullBackupContent="false"
@@ -13,15 +15,21 @@
         android:icon="@mipmap/ic_launcher"
         android:label="@string/app_name"
         android:theme="@style/AppTheme" >
-      <activity
-          android:name="com.google.oboe.samples.liveEffect.MainActivity"
-          android:label="@string/app_name"
-          android:screenOrientation="portrait"
-          android:exported="true">
-        <intent-filter>
-          <action android:name="android.intent.action.MAIN" />
-          <category android:name="android.intent.category.LAUNCHER" />
-        </intent-filter>
-      </activity>
+        <activity
+            android:name="com.google.oboe.samples.liveEffect.MainActivity"
+            android:label="@string/app_name"
+            android:screenOrientation="portrait"
+            android:exported="true">
+            <intent-filter>
+                <action android:name="android.intent.action.MAIN" />
+                <category android:name="android.intent.category.LAUNCHER" />
+            </intent-filter>
+        </activity>
+
+        <service
+            android:name=".DuplexStreamForegroundService"
+            android:foregroundServiceType="mediaPlayback|microphone"
+            android:exported="false">
+        </service>
     </application>
 </manifest>
diff --git a/samples/LiveEffect/src/main/cpp/CMakeLists.txt b/samples/LiveEffect/src/main/cpp/CMakeLists.txt
index 4f16621c..916edc0c 100644
--- a/samples/LiveEffect/src/main/cpp/CMakeLists.txt
+++ b/samples/LiveEffect/src/main/cpp/CMakeLists.txt
@@ -38,6 +38,7 @@ target_link_libraries(liveEffect
         android
         atomic
         log)
+target_link_options(liveEffect PRIVATE "-Wl,-z,max-page-size=16384")
 
 # Enable optimization flags: if having problems with source level debugging,
 # disable -Ofast ( and debug ), re-enable it after done debugging.
diff --git a/samples/LiveEffect/src/main/cpp/LiveEffectEngine.cpp b/samples/LiveEffect/src/main/cpp/LiveEffectEngine.cpp
index 140dd328..63d0a55a 100644
--- a/samples/LiveEffect/src/main/cpp/LiveEffectEngine.cpp
+++ b/samples/LiveEffect/src/main/cpp/LiveEffectEngine.cpp
@@ -47,11 +47,9 @@ bool LiveEffectEngine::setEffectOn(bool isOn) {
         if (isOn) {
             success = openStreams() == oboe::Result::OK;
             if (success) {
-                mFullDuplexPass.start();
                 mIsEffectOn = isOn;
             }
         } else {
-            mFullDuplexPass.stop();
             closeStreams();
             mIsEffectOn = isOn;
        }
@@ -68,11 +66,10 @@ void LiveEffectEngine::closeStreams() {
     * which would cause the app to crash since the recording stream would be
     * null.
     */
+    mDuplexStream->stop();
     closeStream(mPlayStream);
-    mFullDuplexPass.setOutputStream(nullptr);
-
     closeStream(mRecordingStream);
-    mFullDuplexPass.setInputStream(nullptr);
+    mDuplexStream.reset();
 }
 
 oboe::Result  LiveEffectEngine::openStreams() {
@@ -102,8 +99,10 @@ oboe::Result  LiveEffectEngine::openStreams() {
     }
     warnIfNotLowLatency(mRecordingStream);
 
-    mFullDuplexPass.setInputStream(mRecordingStream.get());
-    mFullDuplexPass.setOutputStream(mPlayStream.get());
+    mDuplexStream = std::make_unique<FullDuplexPass>();
+    mDuplexStream->setSharedInputStream(mRecordingStream);
+    mDuplexStream->setSharedOutputStream(mPlayStream);
+    mDuplexStream->start();
     return result;
 }
 
@@ -208,7 +207,7 @@ void LiveEffectEngine::warnIfNotLowLatency(std::shared_ptr<oboe::AudioStream> &s
  */
 oboe::DataCallbackResult LiveEffectEngine::onAudioReady(
     oboe::AudioStream *oboeStream, void *audioData, int32_t numFrames) {
-    return mFullDuplexPass.onAudioReady(oboeStream, audioData, numFrames);
+    return mDuplexStream->onAudioReady(oboeStream, audioData, numFrames);
 }
 
 /**
@@ -236,19 +235,11 @@ void LiveEffectEngine::onErrorAfterClose(oboe::AudioStream *oboeStream,
          oboe::convertToText(oboeStream->getDirection()),
          oboe::convertToText(error));
 
-    // Stop the Full Duplex stream.
-    // Since the error callback occurs only for the output stream, close the input stream.
-    mFullDuplexPass.stop();
-    mFullDuplexPass.setOutputStream(nullptr);
-    closeStream(mRecordingStream);
-    mFullDuplexPass.setInputStream(nullptr);
+    closeStreams();
 
     // Restart the stream if the error is a disconnect.
     if (error == oboe::Result::ErrorDisconnected) {
         LOGI("Restarting AudioStream");
-        oboe::Result result = openStreams();
-        if (result == oboe::Result::OK) {
-            mFullDuplexPass.start();
-        }
+        openStreams();
     }
 }
diff --git a/samples/LiveEffect/src/main/cpp/LiveEffectEngine.h b/samples/LiveEffect/src/main/cpp/LiveEffectEngine.h
index 962b16f3..faea3b07 100644
--- a/samples/LiveEffect/src/main/cpp/LiveEffectEngine.h
+++ b/samples/LiveEffect/src/main/cpp/LiveEffectEngine.h
@@ -52,7 +52,6 @@ public:
     bool isAAudioRecommended(void);
 
 private:
-    FullDuplexPass    mFullDuplexPass;
     bool              mIsEffectOn = false;
     int32_t           mRecordingDeviceId = oboe::kUnspecified;
     int32_t           mPlaybackDeviceId = oboe::kUnspecified;
@@ -62,6 +61,7 @@ private:
     const int32_t     mInputChannelCount = oboe::ChannelCount::Stereo;
     const int32_t     mOutputChannelCount = oboe::ChannelCount::Stereo;
 
+    std::unique_ptr<FullDuplexPass> mDuplexStream;
     std::shared_ptr<oboe::AudioStream> mRecordingStream;
     std::shared_ptr<oboe::AudioStream> mPlayStream;
 
diff --git a/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/DuplexStreamForegroundService.java b/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/DuplexStreamForegroundService.java
new file mode 100644
index 00000000..1ed9637d
--- /dev/null
+++ b/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/DuplexStreamForegroundService.java
@@ -0,0 +1,92 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+package com.google.oboe.samples.liveEffect;
+
+import android.app.ForegroundServiceStartNotAllowedException;
+import android.app.Notification;
+import android.app.NotificationChannel;
+import android.app.NotificationManager;
+import android.app.Service;
+import android.content.Context;
+import android.content.Intent;
+import android.content.pm.PackageManager;
+import android.content.pm.ServiceInfo;
+import android.os.Build;
+import android.os.Bundle;
+import android.os.Handler;
+import android.os.HandlerThread;
+import android.os.IBinder;
+import android.os.Looper;
+import android.os.Message;
+import android.util.Log;
+import android.widget.Toast;
+
+import androidx.core.app.NotificationCompat;
+import androidx.core.app.ServiceCompat;
+import androidx.core.content.ContextCompat;
+
+public class DuplexStreamForegroundService extends Service {
+    private static final String TAG = "DuplexStreamFS";
+    public static final String ACTION_START = "ACTION_START";
+    public static final String ACTION_STOP = "ACTION_STOP";
+
+    @Override
+    public IBinder onBind(Intent intent) {
+        // We don't provide binding, so return null
+        return null;
+    }
+
+    private Notification buildNotification() {
+        NotificationManager manager = (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
+
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
+            manager.createNotificationChannel(new NotificationChannel(
+                    "all",
+                    "All Notifications",
+                    NotificationManager.IMPORTANCE_NONE));
+
+            return new Notification.Builder(this, "all")
+                    .setContentTitle("Playing/recording audio")
+                    .setContentText("playing/recording...")
+                    .setSmallIcon(R.mipmap.ic_launcher)
+                    .build();
+        }
+        return null;
+    }
+
+    @Override
+    public int onStartCommand(Intent intent, int flags, int startId) {
+        Log.i(TAG, "Receive onStartCommand" + intent);
+        switch (intent.getAction()) {
+            case ACTION_START:
+                Log.i(TAG, "Receive ACTION_START" + intent.getExtras());
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+                    startForeground(1, buildNotification(),
+                            ServiceInfo.FOREGROUND_SERVICE_TYPE_MEDIA_PLAYBACK
+                                    | ServiceInfo.FOREGROUND_SERVICE_TYPE_MICROPHONE);
+                }
+                break;
+            case ACTION_STOP:
+                Log.i(TAG, "Receive ACTION_STOP" + intent.getExtras());
+                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+                    stopForeground(STOP_FOREGROUND_REMOVE);
+                }
+                break;
+        }
+        return START_NOT_STICKY;
+    }
+}
diff --git a/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/MainActivity.java b/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/MainActivity.java
index 5d877b71..339fe936 100644
--- a/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/MainActivity.java
+++ b/samples/LiveEffect/src/main/java/com/google/oboe/samples/liveEffect/MainActivity.java
@@ -16,8 +16,12 @@
 
 package com.google.oboe.samples.liveEffect;
 
+import static com.google.oboe.samples.liveEffect.DuplexStreamForegroundService.ACTION_START;
+import static com.google.oboe.samples.liveEffect.DuplexStreamForegroundService.ACTION_STOP;
+
 import android.Manifest;
 import android.app.Activity;
+import android.content.Intent;
 import android.content.pm.PackageManager;
 import android.media.AudioManager;
 import android.os.Build;
@@ -124,6 +128,15 @@ public class MainActivity extends Activity
         });
 
         LiveEffectEngine.setDefaultStreamValues(this);
+        setVolumeControlStream(AudioManager.STREAM_MUSIC);
+
+        if (!isRecordPermissionGranted()){
+            requestRecordPermission();
+        } else {
+            startForegroundService();
+        }
+
+        onStartTest();
     }
 
     private void EnableAudioApiUI(boolean enable) {
@@ -146,22 +159,39 @@ public class MainActivity extends Activity
     @Override
     protected void onStart() {
         super.onStart();
-        setVolumeControlStream(AudioManager.STREAM_MUSIC);
     }
 
     @Override
     protected void onResume() {
         super.onResume();
+    }
+    @Override
+    protected void onPause() {
+        super.onPause();
+    }
+
+    @Override
+    protected void onDestroy() {
+        onStopTest();
+
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+            Intent serviceIntent = new Intent(ACTION_STOP, null, this,
+                    DuplexStreamForegroundService.class);
+            startForegroundService(serviceIntent);
+        }
+        super.onDestroy();
+    }
+
+    private void onStartTest() {
         LiveEffectEngine.create();
         mAAudioRecommended = LiveEffectEngine.isAAudioRecommended();
         EnableAudioApiUI(true);
         LiveEffectEngine.setAPI(apiSelection);
     }
-    @Override
-    protected void onPause() {
+
+    private void onStopTest() {
         stopEffect();
         LiveEffectEngine.delete();
-        super.onPause();
     }
 
     public void toggleEffect() {
@@ -176,11 +206,6 @@ public class MainActivity extends Activity
     private void startEffect() {
         Log.d(TAG, "Attempting to start");
 
-        if (!isRecordPermissionGranted()){
-            requestRecordPermission();
-            return;
-        }
-
         boolean success = LiveEffectEngine.setEffectOn(true);
         if (success) {
             statusText.setText(R.string.status_playing);
@@ -237,6 +262,14 @@ public class MainActivity extends Activity
         statusText.setText(R.string.status_warning);
     }
 
+    private void startForegroundService() {
+        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
+            Intent serviceIntent = new Intent(ACTION_START, null, this,
+                    DuplexStreamForegroundService.class);
+            startForegroundService(serviceIntent);
+        }
+    }
+
     @Override
     public void onRequestPermissionsResult(int requestCode, @NonNull String[] permissions,
                                            @NonNull int[] grantResults) {
@@ -256,9 +289,11 @@ public class MainActivity extends Activity
                     getString(R.string.need_record_audio_permission),
                     Toast.LENGTH_SHORT)
                     .show();
+            EnableAudioApiUI(false);
+            toggleEffectButton.setEnabled(false);
         } else {
-            // Permission was granted, start live effect
-            toggleEffect();
+            // Permission was granted, start foreground service.
+            startForegroundService();
         }
     }
 }
diff --git a/samples/LiveEffect/src/main/res/drawable/balance_seekbar.xml b/samples/LiveEffect/src/main/res/drawable/balance_seekbar.xml
deleted file mode 100644
index fd1b3fa8..00000000
--- a/samples/LiveEffect/src/main/res/drawable/balance_seekbar.xml
+++ /dev/null
@@ -1,17 +0,0 @@
-<?xml version="1.0" encoding="utf-8"?>
-<layer-list xmlns:android="http://schemas.android.com/apk/res/android" >
-    <item android:id="@android:id/background">
-        <shape android:shape="rectangle" >
-            <solid
-                android:color="@color/colorBlue" />
-        </shape>
-    </item>
-    <item android:id="@android:id/progress">
-        <clip>
-            <shape android:shape="rectangle" >
-                <solid
-                    android:color="@color/colorBlue" />
-            </shape>
-        </clip>
-    </item>
-</layer-list>
diff --git a/samples/MegaDrone/build.gradle b/samples/MegaDrone/build.gradle
index 1096b111..580903d4 100644
--- a/samples/MegaDrone/build.gradle
+++ b/samples/MegaDrone/build.gradle
@@ -1,11 +1,12 @@
 apply plugin: 'com.android.application'
+apply plugin: 'kotlin-android'
 
 android {
-    compileSdkVersion 34
     defaultConfig {
         applicationId "com.google.oboe.samples.megadrone"
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
         versionCode 1
         versionName "1.0"
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
@@ -33,15 +34,20 @@ android {
             debuggable false
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path "src/main/cpp/CMakeLists.txt"
         }
     }
+    namespace 'com.google.oboe.samples.megadrone'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    implementation 'androidx.constraintlayout:constraintlayout:1.1.3'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
 }
diff --git a/samples/MegaDrone/src/main/AndroidManifest.xml b/samples/MegaDrone/src/main/AndroidManifest.xml
index d47eefef..f89313dc 100644
--- a/samples/MegaDrone/src/main/AndroidManifest.xml
+++ b/samples/MegaDrone/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.megadrone">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
         android:allowBackup="true"
diff --git a/samples/MegaDrone/src/main/cpp/CMakeLists.txt b/samples/MegaDrone/src/main/cpp/CMakeLists.txt
index ca6c2b39..658eb076 100644
--- a/samples/MegaDrone/src/main/cpp/CMakeLists.txt
+++ b/samples/MegaDrone/src/main/cpp/CMakeLists.txt
@@ -21,7 +21,8 @@ add_library( megadrone SHARED
         MegaDroneEngine.cpp
         )
 
-target_link_libraries( megadrone log oboe )
+target_link_libraries(megadrone log oboe )
+target_link_options(megadrone PRIVATE "-Wl,-z,max-page-size=16384")
 
 # Enable optimization flags: if having problems with source level debugging,
 # disable -Ofast ( and debug ), re-enable it after done debugging.
diff --git a/samples/RhythmGame/CMakeLists.txt b/samples/RhythmGame/CMakeLists.txt
index 7197c92b..74fd746d 100644
--- a/samples/RhythmGame/CMakeLists.txt
+++ b/samples/RhythmGame/CMakeLists.txt
@@ -60,8 +60,8 @@ else()
     set (TARGET_LIBS ${TARGET_LIBS} mediandk)
 endif()
 
-target_link_libraries( native-lib ${TARGET_LIBS} )
-
+target_link_libraries(native-lib ${TARGET_LIBS} )
+target_link_options(native-lib PRIVATE "-Wl,-z,max-page-size=16384")
 
 # Set the path to the Oboe directory.
 set (OBOE_DIR ../..)
diff --git a/samples/RhythmGame/build.gradle b/samples/RhythmGame/build.gradle
index c453fcb5..271497b5 100644
--- a/samples/RhythmGame/build.gradle
+++ b/samples/RhythmGame/build.gradle
@@ -1,10 +1,11 @@
 apply plugin: 'com.android.application'
+apply plugin: 'kotlin-android'
 
 android {
-    compileSdkVersion 34
     defaultConfig {
         applicationId "com.google.oboe.samples.rhythmgame"
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
         versionCode 1
         versionName "1.0"
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
@@ -21,6 +22,10 @@ android {
             proguardFiles getDefaultProguardFile('proguard-android.txt'), 'proguard-rules.pro'
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path "CMakeLists.txt"
@@ -46,7 +51,7 @@ android {
          * - Uncomment this block
          * - Change the build variant to ffmpegExtractor
          * - Update the FFMPEG_DIR variable in CMakeLists.txt to the local FFmpeg path
-        */
+         */
         /*
         ffmpegExtractor {
             dimension "extractorLibrary"
@@ -59,10 +64,14 @@ android {
         }
         */
     }
+    namespace 'com.google.oboe.samples.rhythmgame'
+    buildFeatures {
+        buildConfig true
+    }
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    implementation 'androidx.constraintlayout:constraintlayout:1.1.3'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
 }
diff --git a/samples/RhythmGame/src/main/AndroidManifest.xml b/samples/RhythmGame/src/main/AndroidManifest.xml
index 4798cc2e..36840c66 100644
--- a/samples/RhythmGame/src/main/AndroidManifest.xml
+++ b/samples/RhythmGame/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.rhythmgame">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
         android:allowBackup="true"
diff --git a/samples/SoundBoard/README.md b/samples/SoundBoard/README.md
index 23e14e68..47c70358 100644
--- a/samples/SoundBoard/README.md
+++ b/samples/SoundBoard/README.md
@@ -37,7 +37,7 @@ The compiler optimization flag `-Ofast` can be found in [CMakeLists.txt](CMakeLi
 
 Each SynthSound is a series of 5 Oscillators, creating a pleasant sounding note when combined.
 
-There are 30 notes, corresponding to G3 to C6, moving left to right, top to bottom.
+The number of notes depends on the shape of the screen, with G3 being the first note.
 
 In order to determine whether a note should be played, MusicTileView demonstrates how to keep track of where each finger is.
 
diff --git a/samples/SoundBoard/build.gradle b/samples/SoundBoard/build.gradle
index fdfe8a72..a6b72411 100644
--- a/samples/SoundBoard/build.gradle
+++ b/samples/SoundBoard/build.gradle
@@ -1,14 +1,12 @@
-plugins {
-    id 'com.android.application'
-    id 'org.jetbrains.kotlin.android'
-}
+apply plugin: 'com.android.application'
+apply plugin: 'kotlin-android'
 
 android {
-    compileSdkVersion 34
     defaultConfig {
         applicationId "com.google.oboe.samples.soundboard"
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
         versionCode 1
         versionName "1.0"
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
@@ -39,15 +37,23 @@ android {
          debuggable true
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
+    kotlinOptions {
+        jvmTarget = '18'
+    }
     externalNativeBuild {
         cmake {
             path "src/main/cpp/CMakeLists.txt"
         }
     }
+    namespace 'com.google.oboe.samples.soundboard'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    implementation 'androidx.constraintlayout:constraintlayout:2.1.4'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
 }
diff --git a/samples/SoundBoard/src/main/AndroidManifest.xml b/samples/SoundBoard/src/main/AndroidManifest.xml
index 707b32a3..bd480402 100644
--- a/samples/SoundBoard/src/main/AndroidManifest.xml
+++ b/samples/SoundBoard/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.soundboard">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
         android:allowBackup="true"
diff --git a/samples/SoundBoard/src/main/cpp/CMakeLists.txt b/samples/SoundBoard/src/main/cpp/CMakeLists.txt
index cf5ef3cd..6e997e55 100644
--- a/samples/SoundBoard/src/main/cpp/CMakeLists.txt
+++ b/samples/SoundBoard/src/main/cpp/CMakeLists.txt
@@ -21,7 +21,8 @@ add_library( soundboard SHARED
         SoundBoardEngine.cpp
         )
 
-target_link_libraries( soundboard log oboe )
+target_link_libraries(soundboard log oboe )
+target_link_options(soundboard PRIVATE "-Wl,-z,max-page-size=16384")
 
 # Enable optimization flags: if having problems with source level debugging,
 # disable -Ofast ( and debug ), re-enable it after done debugging.
diff --git a/samples/audio-device/build.gradle b/samples/audio-device/build.gradle
index 320888bf..6ff7f1cd 100644
--- a/samples/audio-device/build.gradle
+++ b/samples/audio-device/build.gradle
@@ -1,10 +1,10 @@
 apply plugin: 'com.android.library'
 
 android {
-    compileSdkVersion 34
     defaultConfig {
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
     }
     buildTypes {
         release {
@@ -12,8 +12,13 @@ android {
             proguardFiles getDefaultProguardFile('proguard-android.txt')
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
+    namespace 'com.google.oboe.samples.audio_device'
 }
 
 dependencies {
-    implementation 'androidx.appcompat:appcompat:1.0.0-rc02'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
 }
diff --git a/samples/audio-device/src/main/AndroidManifest.xml b/samples/audio-device/src/main/AndroidManifest.xml
index fb04a53e..bdae66c8 100644
--- a/samples/audio-device/src/main/AndroidManifest.xml
+++ b/samples/audio-device/src/main/AndroidManifest.xml
@@ -1,2 +1,2 @@
-<manifest package="com.google.oboe.samples.audio_device">
+<manifest>
 </manifest>
diff --git a/samples/build.gradle b/samples/build.gradle
index 6b8dbbf9..c8047aa5 100644
--- a/samples/build.gradle
+++ b/samples/build.gradle
@@ -19,8 +19,10 @@
 
 buildscript {
     ext {
-        compose_version = '1.2.0'
-        kotlin_version = '1.7.0'
+        compose_version = '1.7.8'
+        core_version = "1.15.0"
+        lifecycle_version = "2.8.7"
+        kotlin_version = '2.1.10'
     }
 
     repositories {
@@ -28,10 +30,11 @@ buildscript {
         mavenCentral()
     }
     dependencies {
-        classpath 'com.android.tools.build:gradle:7.2.2'
+        classpath 'com.android.tools.build:gradle:8.9.0'
         // NOTE: Do not place your application dependencies here; they belong
         // in the individual module build.gradle files.
         classpath "org.jetbrains.kotlin:kotlin-gradle-plugin:$kotlin_version"
+        classpath "org.jetbrains.kotlin:compose-compiler-gradle-plugin:$kotlin_version"
     }
 }
 
diff --git a/samples/drumthumper/build.gradle b/samples/drumthumper/build.gradle
index 7a19c632..b8651b9c 100644
--- a/samples/drumthumper/build.gradle
+++ b/samples/drumthumper/build.gradle
@@ -3,8 +3,6 @@ plugins {
     id 'org.jetbrains.kotlin.android'
 }
 android {
-    compileSdkVersion 34
-
     defaultConfig {
         // Usually the applicationId follows the same scheme as the application package name,
         // however, this sample will be published on the Google Play Store which will not allow an
@@ -13,32 +11,39 @@ android {
         // who publishes using the application Id prefix of "com.plausiblesoftware".
         applicationId "com.plausiblesoftware.drumthumper"
         minSdkVersion 23
-        targetSdkVersion 34
+        compileSdkVersion 35
+        targetSdkVersion 35
         versionCode 2
         versionName "1.01"
 
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
     }
-
     buildTypes {
         release {
             minifyEnabled false
             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
         }
     }
-
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
+    kotlinOptions {
+        jvmTarget = '18'
+    }
     externalNativeBuild {
         cmake {
             path 'src/main/cpp/CMakeLists.txt'
         }
     }
+
+    namespace 'com.plausiblesoftware.drumthumper'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
-    implementation "androidx.core:core-ktx:$kotlin_version"
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    def lifecycle_version = "2.5.1"
+    implementation "androidx.core:core-ktx:$core_version"
+    implementation 'androidx.appcompat:appcompat:1.7.0'
     implementation "androidx.lifecycle:lifecycle-viewmodel:$lifecycle_version"
     implementation "androidx.lifecycle:lifecycle-viewmodel-ktx:$lifecycle_version"
     implementation project(path: ':iolib')
diff --git a/samples/drumthumper/src/main/AndroidManifest.xml b/samples/drumthumper/src/main/AndroidManifest.xml
index ea4c376c..e7d59e0a 100644
--- a/samples/drumthumper/src/main/AndroidManifest.xml
+++ b/samples/drumthumper/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.plausiblesoftware.drumthumper">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
         android:allowBackup="true"
diff --git a/samples/drumthumper/src/main/cpp/CMakeLists.txt b/samples/drumthumper/src/main/cpp/CMakeLists.txt
index 9d2250ac..75fe8652 100644
--- a/samples/drumthumper/src/main/cpp/CMakeLists.txt
+++ b/samples/drumthumper/src/main/cpp/CMakeLists.txt
@@ -71,3 +71,4 @@ target_link_libraries( # Specifies the target library.
         # Links the target library to the log library
         # included in the NDK.
         log)
+target_link_options(drumthumper PRIVATE "-Wl,-z,max-page-size=16384")
diff --git a/samples/drumthumper/src/main/cpp/DrumPlayerJNI.cpp b/samples/drumthumper/src/main/cpp/DrumPlayerJNI.cpp
index 44f546f8..90eb36ff 100644
--- a/samples/drumthumper/src/main/cpp/DrumPlayerJNI.cpp
+++ b/samples/drumthumper/src/main/cpp/DrumPlayerJNI.cpp
@@ -162,6 +162,11 @@ JNIEXPORT jfloat JNICALL Java_com_plausiblesoftware_drumthumper_DrumPlayer_getGa
     return sDTPlayer.getGain(index);
 }
 
+JNIEXPORT void JNICALL Java_com_plausiblesoftware_drumthumper_DrumPlayer_setLoopMode(
+        JNIEnv *env, jobject thiz, jint  index, jboolean isLoopMode) {
+    sDTPlayer.setLoopMode(index, isLoopMode);
+}
+
 #ifdef __cplusplus
 }
 #endif
diff --git a/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumPlayer.kt b/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumPlayer.kt
index c47f6745..762fad44 100644
--- a/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumPlayer.kt
+++ b/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumPlayer.kt
@@ -107,6 +107,8 @@ class DrumPlayer {
     external fun setGain(index: Int, gain: Float)
     external fun getGain(index: Int): Float
 
+    external fun setLoopMode(index: Int, isLoopMode: Boolean)
+
     external fun getOutputReset() : Boolean
     external fun clearOutputReset()
 
diff --git a/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumThumperActivity.kt b/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumThumperActivity.kt
index ffb30308..7d1dd911 100644
--- a/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumThumperActivity.kt
+++ b/samples/drumthumper/src/main/kotlin/com/plausibleaudio/drumthumper/DrumThumperActivity.kt
@@ -50,6 +50,21 @@ class DrumThumperActivity : AppCompatActivity(),
 
     private var mMixControlsShowing = false
 
+    // Store the loop mode states for each drum
+    private val mLoopModes = mutableMapOf(
+        DrumPlayer.BASSDRUM to false,
+        DrumPlayer.SNAREDRUM to false,
+        DrumPlayer.CRASHCYMBAL to false,
+        DrumPlayer.RIDECYMBAL to false,
+        DrumPlayer.MIDTOM to false,
+        DrumPlayer.LOWTOM to false,
+        DrumPlayer.HIHATOPEN to false,
+        DrumPlayer.HIHATCLOSED to false
+    )
+
+    // Store the button references
+    private val mLoopButtons = mutableMapOf<Int, Button>()
+
     init {
         // Load the library containing the a native code including the JNI  functions
         System.loadLibrary("drumthumper")
@@ -160,7 +175,6 @@ class DrumThumperActivity : AppCompatActivity(),
         super.onCreate(savedInstanceState)
 
         mAudioMgr = getSystemService(Context.AUDIO_SERVICE) as AudioManager
-
     }
 
     override fun onStart() {
@@ -186,34 +200,50 @@ class DrumThumperActivity : AppCompatActivity(),
         // "Kick" drum
         findViewById<TriggerPad>(R.id.kickPad).addListener(this)
         connectMixSliders(R.id.kickPan, R.id.kickGain, DrumPlayer.BASSDRUM)
+        mLoopButtons[DrumPlayer.BASSDRUM] = findViewById(R.id.kickLoopBtn)
+        mLoopButtons[DrumPlayer.BASSDRUM]?.setOnClickListener(this)
 
         // Snare drum
         findViewById<TriggerPad>(R.id.snarePad).addListener(this)
         connectMixSliders(R.id.snarePan, R.id.snareGain, DrumPlayer.SNAREDRUM)
+        mLoopButtons[DrumPlayer.SNAREDRUM] = findViewById(R.id.snareLoopBtn)
+        mLoopButtons[DrumPlayer.SNAREDRUM]?.setOnClickListener(this)
 
         // Mid tom
         findViewById<TriggerPad>(R.id.midTomPad).addListener(this)
         connectMixSliders(R.id.midTomPan, R.id.midTomGain, DrumPlayer.MIDTOM)
+        mLoopButtons[DrumPlayer.MIDTOM] = findViewById(R.id.midTomLoopBtn)
+        mLoopButtons[DrumPlayer.MIDTOM]?.setOnClickListener(this)
 
         // Low tom
         findViewById<TriggerPad>(R.id.lowTomPad).addListener(this)
         connectMixSliders(R.id.lowTomPan, R.id.lowTomGain, DrumPlayer.LOWTOM)
+        mLoopButtons[DrumPlayer.LOWTOM] = findViewById(R.id.lowTomLoopBtn)
+        mLoopButtons[DrumPlayer.LOWTOM]?.setOnClickListener(this)
 
         // Open hihat
         findViewById<TriggerPad>(R.id.hihatOpenPad).addListener(this)
         connectMixSliders(R.id.hihatOpenPan, R.id.hihatOpenGain, DrumPlayer.HIHATOPEN)
+        mLoopButtons[DrumPlayer.HIHATOPEN] = findViewById(R.id.hihatOpenLoopBtn)
+        mLoopButtons[DrumPlayer.HIHATOPEN]?.setOnClickListener(this)
 
         // Closed hihat
         findViewById<TriggerPad>(R.id.hihatClosedPad).addListener(this)
         connectMixSliders(R.id.hihatClosedPan, R.id.hihatClosedGain, DrumPlayer.HIHATCLOSED)
+        mLoopButtons[DrumPlayer.HIHATCLOSED] = findViewById(R.id.hihatClosedLoopBtn)
+        mLoopButtons[DrumPlayer.HIHATCLOSED]?.setOnClickListener(this)
 
         // Ride cymbal
         findViewById<TriggerPad>(R.id.ridePad).addListener(this)
         connectMixSliders(R.id.ridePan, R.id.rideGain, DrumPlayer.RIDECYMBAL)
+        mLoopButtons[DrumPlayer.RIDECYMBAL] = findViewById(R.id.rideLoopBtn)
+        mLoopButtons[DrumPlayer.RIDECYMBAL]?.setOnClickListener(this)
 
         // Crash cymbal
         findViewById<TriggerPad>(R.id.crashPad).addListener(this)
         connectMixSliders(R.id.crashPan, R.id.crashGain, DrumPlayer.CRASHCYMBAL)
+        mLoopButtons[DrumPlayer.CRASHCYMBAL] = findViewById(R.id.crashLoopBtn)
+        mLoopButtons[DrumPlayer.CRASHCYMBAL]?.setOnClickListener(this)
 
         findViewById<Button>(R.id.mixCtrlBtn).setOnClickListener(this)
         showMixControls(false)
@@ -310,7 +340,26 @@ class DrumThumperActivity : AppCompatActivity(),
     }
 
     override fun onClick(v: View?) {
-        showMixControls(!mMixControlsShowing)
+        when (v?.id) {
+            R.id.mixCtrlBtn -> showMixControls(!mMixControlsShowing)
+            R.id.kickLoopBtn -> handleLoopButtonClick(DrumPlayer.BASSDRUM)
+            R.id.snareLoopBtn -> handleLoopButtonClick(DrumPlayer.SNAREDRUM)
+            R.id.midTomLoopBtn -> handleLoopButtonClick(DrumPlayer.MIDTOM)
+            R.id.lowTomLoopBtn -> handleLoopButtonClick(DrumPlayer.LOWTOM)
+            R.id.hihatOpenLoopBtn -> handleLoopButtonClick(DrumPlayer.HIHATOPEN)
+            R.id.hihatClosedLoopBtn -> handleLoopButtonClick(DrumPlayer.HIHATCLOSED)
+            R.id.rideLoopBtn -> handleLoopButtonClick(DrumPlayer.RIDECYMBAL)
+            R.id.crashLoopBtn -> handleLoopButtonClick(DrumPlayer.CRASHCYMBAL)
+        }
     }
 
+    private fun handleLoopButtonClick(drumIndex: Int) {
+        // Toggle the loop mode
+        mLoopModes[drumIndex] = !mLoopModes[drumIndex]!!
+        mDrumPlayer.setLoopMode(drumIndex, mLoopModes[drumIndex]!!)
+
+        // Update the button appearance
+        val button = mLoopButtons[drumIndex]
+        button?.setTextColor(if (mLoopModes[drumIndex]!!) getColor(R.color.red) else getColor(R.color.black))
+    }
 }
diff --git a/samples/drumthumper/src/main/res/layout-land/drumthumper_activity.xml b/samples/drumthumper/src/main/res/layout-land/drumthumper_activity.xml
index b6577387..6529a2eb 100644
--- a/samples/drumthumper/src/main/res/layout-land/drumthumper_activity.xml
+++ b/samples/drumthumper/src/main/res/layout-land/drumthumper_activity.xml
@@ -68,6 +68,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/kickLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -128,6 +142,20 @@
                         android:max="200" />
 
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/snareLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -187,6 +215,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/hihatOpenLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -246,6 +288,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/hihatClosedLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
@@ -311,6 +367,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/midTomLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -370,6 +440,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/lowTomLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -429,6 +513,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/rideLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -488,6 +586,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/crashLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
diff --git a/samples/drumthumper/src/main/res/layout/drumthumper_activity.xml b/samples/drumthumper/src/main/res/layout/drumthumper_activity.xml
index 1c0573b5..265afdbe 100644
--- a/samples/drumthumper/src/main/res/layout/drumthumper_activity.xml
+++ b/samples/drumthumper/src/main/res/layout/drumthumper_activity.xml
@@ -68,6 +68,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/kickLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -128,6 +142,20 @@
                         android:max="200" />
 
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/snareLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
@@ -193,6 +221,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/hihatOpenLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -251,7 +293,21 @@
                         android:layout_height="20dp"
                         android:layout_marginTop="5dp"
                         android:max="200" />
-            </LinearLayout>
+                </LinearLayout>
+
+                <Button
+                    android:id="@+id/hihatClosedLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
@@ -317,6 +373,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/midTomLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -376,6 +446,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/lowTomLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
@@ -441,6 +525,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/rideLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
 
@@ -500,6 +598,20 @@
                         android:layout_marginTop="5dp"
                         android:max="200" />
                 </LinearLayout>
+
+                <Button
+                    android:id="@+id/crashLoopBtn"
+                    android:layout_width="wrap_content"
+                    android:layout_height="wrap_content"
+                    android:layout_gravity="center"
+                    android:layout_marginTop="5dp"
+                    android:minHeight="0dp"
+                    android:minWidth="0dp"
+                    android:padding="0dp"
+                    android:text="Loop"
+                    android:textSize="12sp"
+                    android:layout_marginStart="60dp"
+                    android:layout_marginEnd="60dp"/>
             </LinearLayout>
         </LinearLayout>
     </LinearLayout>
diff --git a/samples/drumthumper/src/main/res/values/colors.xml b/samples/drumthumper/src/main/res/values/colors.xml
index 69b22338..20fd3cc5 100644
--- a/samples/drumthumper/src/main/res/values/colors.xml
+++ b/samples/drumthumper/src/main/res/values/colors.xml
@@ -3,4 +3,6 @@
     <color name="colorPrimary">#008577</color>
     <color name="colorPrimaryDark">#00574B</color>
     <color name="colorAccent">#D81B60</color>
+    <color name="black">#FF000000</color>
+    <color name="red">#BB0000</color>
 </resources>
diff --git a/samples/gradle.properties b/samples/gradle.properties
index d8e5383d..3afe4fd2 100644
--- a/samples/gradle.properties
+++ b/samples/gradle.properties
@@ -34,4 +34,7 @@
 # http://www.gradle.org/docs/current/userguide/multi_project_builds.html#sec:decoupled_projects
 # org.gradle.parallel=true
 android.enableJetifier=true
+android.nonFinalResIds=false
+android.nonTransitiveRClass=false
 android.useAndroidX=true
+org.gradle.configuration-cache=true
diff --git a/samples/gradle/wrapper/gradle-wrapper.properties b/samples/gradle/wrapper/gradle-wrapper.properties
index efcdb875..c72b7059 100644
--- a/samples/gradle/wrapper/gradle-wrapper.properties
+++ b/samples/gradle/wrapper/gradle-wrapper.properties
@@ -3,4 +3,4 @@ distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.3-bin.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.11.1-bin.zip
diff --git a/samples/hello-oboe/build.gradle b/samples/hello-oboe/build.gradle
index 59b0b188..e35d9199 100644
--- a/samples/hello-oboe/build.gradle
+++ b/samples/hello-oboe/build.gradle
@@ -1,12 +1,13 @@
 apply plugin: 'com.android.application'
+apply plugin: 'kotlin-android'
 
 android {
-    compileSdkVersion 34
-
+    compileSdkVersion 35
     defaultConfig {
         applicationId 'com.google.oboe.samples.hellooboe'
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
         versionCode 1
         versionName '1.0'
         externalNativeBuild {
@@ -25,16 +26,21 @@ android {
                           'proguard-rules.pro'
         }
     }
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path 'src/main/cpp/CMakeLists.txt'
         }
     }
+    namespace 'com.google.oboe.samples.hellooboe'
 }
 
 dependencies {
     implementation fileTree(include: ['*.jar'], dir: 'libs')
     implementation project(':audio-device')
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
-    implementation 'androidx.constraintlayout:constraintlayout:1.1.3'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
+    implementation 'androidx.constraintlayout:constraintlayout:2.2.1'
 }
diff --git a/samples/hello-oboe/src/main/AndroidManifest.xml b/samples/hello-oboe/src/main/AndroidManifest.xml
index 593873e6..84b5c0a8 100644
--- a/samples/hello-oboe/src/main/AndroidManifest.xml
+++ b/samples/hello-oboe/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.hellooboe" >
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <uses-feature android:name="android.hardware.audio.output" android:required="true" />
     <uses-permission android:name="android.permission.MODIFY_AUDIO_SETTINGS" />
diff --git a/samples/hello-oboe/src/main/cpp/CMakeLists.txt b/samples/hello-oboe/src/main/cpp/CMakeLists.txt
index 77e898e1..48fc94ef 100644
--- a/samples/hello-oboe/src/main/cpp/CMakeLists.txt
+++ b/samples/hello-oboe/src/main/cpp/CMakeLists.txt
@@ -53,6 +53,7 @@ add_library(hello-oboe SHARED
 
 # Specify the libraries needed for hello-oboe
 target_link_libraries(hello-oboe android log oboe)
+target_link_options(hello-oboe PRIVATE "-Wl,-z,max-page-size=16384")
 
 # Enable optimization flags: if having problems with source level debugging,
 # disable -Ofast ( and debug ), re-enable after done debugging.
diff --git a/samples/iolib/build.gradle b/samples/iolib/build.gradle
index 266c9789..8bad13d1 100644
--- a/samples/iolib/build.gradle
+++ b/samples/iolib/build.gradle
@@ -1,32 +1,34 @@
 apply plugin: 'com.android.library'
 
 android {
-    compileSdkVersion 34
-
     defaultConfig {
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
 
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
         consumerProguardFiles 'consumer-rules.pro'
     }
-
     buildTypes {
         release {
             minifyEnabled false
             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-rules.pro'
         }
     }
-
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path 'src/main/cpp/CMakeLists.txt'
         }
     }
+    namespace 'com.google.oboe.samples.iolib'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
 
-    implementation 'androidx.appcompat:appcompat:1.1.0'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
 }
diff --git a/samples/iolib/src/main/AndroidManifest.xml b/samples/iolib/src/main/AndroidManifest.xml
index 0e0c7eda..94cbbcfc 100644
--- a/samples/iolib/src/main/AndroidManifest.xml
+++ b/samples/iolib/src/main/AndroidManifest.xml
@@ -1,2 +1 @@
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples.iolib" />
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" />
diff --git a/samples/iolib/src/main/cpp/player/OneShotSampleSource.cpp b/samples/iolib/src/main/cpp/player/OneShotSampleSource.cpp
index 568d76f2..74fef60b 100644
--- a/samples/iolib/src/main/cpp/player/OneShotSampleSource.cpp
+++ b/samples/iolib/src/main/cpp/player/OneShotSampleSource.cpp
@@ -25,49 +25,58 @@ namespace iolib {
 void OneShotSampleSource::mixAudio(float* outBuff, int numChannels, int32_t numFrames) {
     int32_t numSamples = mSampleBuffer->getNumSamples();
     int32_t sampleChannels = mSampleBuffer->getProperties().channelCount;
-    int32_t samplesLeft = numSamples - mCurSampleIndex;
-    int32_t numWriteFrames = mIsPlaying
-                         ? std::min(numFrames, samplesLeft / sampleChannels)
-                         : 0;
+    int32_t totalSamplesNeeded = numFrames * numChannels; // Total samples to fill the output buffer
+    int32_t samplesProcessed = 0;
+    bool isLoopMode = mIsLoopMode;
 
-    if (numWriteFrames != 0) {
-        const float* data  = mSampleBuffer->getSampleData();
-        if ((sampleChannels == 1) && (numChannels == 1)) {
-            // MONO output from MONO samples
-            for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
-                outBuff[frameIndex] += data[mCurSampleIndex++] * mGain;
-            }
-        } else if ((sampleChannels == 1) && (numChannels == 2)) {
-            // STEREO output from MONO samples
-            int dstSampleIndex = 0;
-            for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
-                outBuff[dstSampleIndex++] += data[mCurSampleIndex] * mLeftGain;
-                outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mRightGain;
-            }
-        } else if ((sampleChannels == 2) && (numChannels == 1)) {
-            // MONO output from STEREO samples
-            int dstSampleIndex = 0;
-            for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
-                outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mLeftGain +
-                                             data[mCurSampleIndex++] * mRightGain;
-            }
-        } else if ((sampleChannels == 2) && (numChannels == 2)) {
-            // STEREO output from STEREO samples
-            int dstSampleIndex = 0;
-            for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
-                outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mLeftGain;
-                outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mRightGain;
+    while (samplesProcessed < totalSamplesNeeded && mIsPlaying) {
+        int32_t samplesLeft = numSamples - mCurSampleIndex;
+        int32_t framesLeft = (totalSamplesNeeded - samplesProcessed) / numChannels;
+        int32_t numWriteFrames = std::min(framesLeft, samplesLeft / sampleChannels);
+
+        if (numWriteFrames > 0) {
+            const float* data = mSampleBuffer->getSampleData();
+            if ((sampleChannels == 1) && (numChannels == 1)) {
+                // MONO output from MONO samples
+                for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
+                    outBuff[samplesProcessed + frameIndex] += data[mCurSampleIndex++] * mGain;
+                }
+            } else if ((sampleChannels == 1) && (numChannels == 2)) {
+                // STEREO output from MONO samples
+                int dstSampleIndex = samplesProcessed;
+                for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
+                    outBuff[dstSampleIndex++] += data[mCurSampleIndex] * mLeftGain;
+                    outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mRightGain;
+                }
+            } else if ((sampleChannels == 2) && (numChannels == 1)) {
+                // MONO output from STEREO samples
+                int dstSampleIndex = samplesProcessed;
+                for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
+                    outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mLeftGain +
+                                                 data[mCurSampleIndex++] * mRightGain;
+                }
+            } else if ((sampleChannels == 2) && (numChannels == 2)) {
+                // STEREO output from STEREO samples
+                int dstSampleIndex = samplesProcessed;
+                for (int32_t frameIndex = 0; frameIndex < numWriteFrames; frameIndex++) {
+                    outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mLeftGain;
+                    outBuff[dstSampleIndex++] += data[mCurSampleIndex++] * mRightGain;
+                }
             }
-        }
 
-        if (mCurSampleIndex >= numSamples) {
-            mIsPlaying = false;
+            samplesProcessed += numWriteFrames * numChannels;
+
+            if (mCurSampleIndex >= numSamples) {
+                if (isLoopMode) {
+                    mCurSampleIndex = 0;
+                } else {
+                    mIsPlaying = false;
+                }
+            }
+        } else {
+            break; // No more samples to write in the current chunk
         }
     }
-
-    // silence
-    // no need as the output buffer would need to have been filled with silence
-    // to be mixed into
 }
 
 } // namespace wavlib
diff --git a/samples/iolib/src/main/cpp/player/SampleSource.h b/samples/iolib/src/main/cpp/player/SampleSource.h
index 80be39df..54edbf1f 100644
--- a/samples/iolib/src/main/cpp/player/SampleSource.h
+++ b/samples/iolib/src/main/cpp/player/SampleSource.h
@@ -39,7 +39,7 @@ public:
     static constexpr float PAN_CENTER = 0.0f;
 
     SampleSource(SampleBuffer *sampleBuffer, float pan)
-     : mSampleBuffer(sampleBuffer), mCurSampleIndex(0), mIsPlaying(false), mGain(1.0f) {
+     : mSampleBuffer(sampleBuffer), mCurSampleIndex(0), mIsPlaying(false), mIsLoopMode(false), mGain(1.0f) {
         setPan(pan);
     }
     virtual ~SampleSource() {}
@@ -47,6 +47,8 @@ public:
     void setPlayMode() { mCurSampleIndex = 0; mIsPlaying = true; }
     void setStopMode() { mIsPlaying = false; mCurSampleIndex = 0; }
 
+    void setLoopMode(bool isLoopMode) { mIsLoopMode = isLoopMode; }
+
     bool isPlaying() { return mIsPlaying; }
 
     void setPan(float pan) {
@@ -79,6 +81,7 @@ protected:
     int32_t mCurSampleIndex;
 
     bool mIsPlaying;
+    std::atomic<bool> mIsLoopMode;
 
     // Logical pan value
     float mPan;
diff --git a/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.cpp b/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.cpp
index 4948d88a..a3072587 100644
--- a/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.cpp
+++ b/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.cpp
@@ -119,7 +119,7 @@ bool SimpleMultiPlayer::startStream() {
     int tryCount = 0;
     while (tryCount < 3) {
         bool wasOpenSuccessful = true;
-        // Assume that apenStream() was called successfully before startStream() call.
+        // Assume that openStream() was called successfully before startStream() call.
         if (tryCount > 0) {
             usleep(20 * 1000); // Sleep between tries to give the system time to settle.
             wasOpenSuccessful = openStream(); // Try to open the stream again after the first try.
@@ -217,4 +217,8 @@ float SimpleMultiPlayer::getGain(int index) {
     return mSampleSources[index]->getGain();
 }
 
+void SimpleMultiPlayer::setLoopMode(int index, bool isLoopMode) {
+    mSampleSources[index]->setLoopMode(isLoopMode);
+}
+
 }
diff --git a/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.h b/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.h
index b388b8f3..43a6dd6c 100644
--- a/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.h
+++ b/samples/iolib/src/main/cpp/player/SimpleMultiPlayer.h
@@ -68,6 +68,8 @@ public:
     void setGain(int index, float gain);
     float getGain(int index);
 
+    void setLoopMode(int index, bool isLoopMode);
+
 private:
     class MyDataCallback : public oboe::AudioStreamDataCallback {
     public:
diff --git a/samples/minimaloboe/build.gradle b/samples/minimaloboe/build.gradle
index bf03f789..a6feaaec 100644
--- a/samples/minimaloboe/build.gradle
+++ b/samples/minimaloboe/build.gradle
@@ -1,15 +1,15 @@
 plugins {
     id 'com.android.application'
     id 'org.jetbrains.kotlin.android'
+    id 'org.jetbrains.kotlin.plugin.compose'
 }
 
 android {
-    compileSdk 33
-
     defaultConfig {
         applicationId "com.example.minimaloboe"
-        minSdk 21
-        targetSdk 32
+        minSdkVersion 21
+        targetSdkVersion 35
+        compileSdkVersion 35
         versionCode 1
         versionName "1.0"
 
@@ -18,7 +18,6 @@ android {
             useSupportLibrary true
         }
     }
-
     buildTypes {
         release {
             minifyEnabled false
@@ -26,11 +25,11 @@ android {
         }
     }
     compileOptions {
-        sourceCompatibility JavaVersion.VERSION_1_8
-        targetCompatibility JavaVersion.VERSION_1_8
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
     }
     kotlinOptions {
-        jvmTarget = '1.8'
+        jvmTarget = '18'
     }
     buildFeatures {
         compose true
@@ -49,14 +48,14 @@ android {
             excludes += '/META-INF/{AL2.0,LGPL2.1}'
         }
     }
+    namespace 'com.example.minimaloboe'
 }
 
 dependencies {
-    implementation "androidx.core:core-ktx:$kotlin_version"
-    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.6.4"
-    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.6.4"
-    implementation "androidx.activity:activity-ktx:1.6.0"
-    def lifecycle_version = "2.6.0-alpha02"
+    implementation "androidx.core:core-ktx:$core_version"
+    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-core:1.10.1"
+    implementation "org.jetbrains.kotlinx:kotlinx-coroutines-android:1.10.1"
+    implementation "androidx.activity:activity-ktx:1.10.1"
     implementation "androidx.lifecycle:lifecycle-process:$lifecycle_version"
     implementation "androidx.lifecycle:lifecycle-viewmodel:$lifecycle_version"
     implementation "androidx.lifecycle:lifecycle-viewmodel-compose:$lifecycle_version"
@@ -65,11 +64,11 @@ dependencies {
     implementation "androidx.compose.ui:ui:$compose_version"
     implementation "androidx.compose.material:material:$compose_version"
     implementation "androidx.compose.ui:ui-tooling-preview:$compose_version"
-    implementation 'androidx.activity:activity-compose:1.3.1'
-    implementation 'androidx.appcompat:appcompat:1.6.0-rc01'
+    implementation 'androidx.activity:activity-compose:1.10.1'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
     testImplementation 'junit:junit:4.13.2'
-    androidTestImplementation 'androidx.test.ext:junit:1.1.3'
-    androidTestImplementation 'androidx.test.espresso:espresso-core:3.4.0'
+    androidTestImplementation 'androidx.test.ext:junit:1.2.1'
+    androidTestImplementation 'androidx.test.espresso:espresso-core:3.6.1'
     androidTestImplementation "androidx.compose.ui:ui-test-junit4:$compose_version"
     debugImplementation "androidx.compose.ui:ui-tooling:$compose_version"
     debugImplementation "androidx.compose.ui:ui-test-manifest:$compose_version"
diff --git a/samples/minimaloboe/src/main/AndroidManifest.xml b/samples/minimaloboe/src/main/AndroidManifest.xml
index 25d9e02c..6ec83897 100644
--- a/samples/minimaloboe/src/main/AndroidManifest.xml
+++ b/samples/minimaloboe/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.example.minimaloboe">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <application
         android:allowBackup="true"
diff --git a/samples/minimaloboe/src/main/cpp/CMakeLists.txt b/samples/minimaloboe/src/main/cpp/CMakeLists.txt
index 045ff5c5..027b27bc 100644
--- a/samples/minimaloboe/src/main/cpp/CMakeLists.txt
+++ b/samples/minimaloboe/src/main/cpp/CMakeLists.txt
@@ -50,3 +50,4 @@ target_link_libraries( # Specifies the target library.
         # Links the target library to the log library
         # included in the NDK.
         log)
+target_link_options(minimaloboe PRIVATE "-Wl,-z,max-page-size=16384")
diff --git a/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/AudioPlayer.kt b/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/AudioPlayer.kt
index 445e3644..6615562f 100644
--- a/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/AudioPlayer.kt
+++ b/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/AudioPlayer.kt
@@ -20,14 +20,12 @@ import androidx.lifecycle.DefaultLifecycleObserver
 import androidx.lifecycle.LifecycleOwner
 import kotlinx.coroutines.CoroutineScope
 import kotlinx.coroutines.Dispatchers
-import kotlinx.coroutines.GlobalScope
 import kotlinx.coroutines.Job
 import kotlinx.coroutines.flow.MutableStateFlow
 import kotlinx.coroutines.flow.asStateFlow
 import kotlinx.coroutines.flow.update
 import kotlinx.coroutines.launch
 import kotlinx.coroutines.plus
-import kotlin.coroutines.CoroutineContext
 
 object AudioPlayer : DefaultLifecycleObserver {
 
@@ -35,7 +33,6 @@ object AudioPlayer : DefaultLifecycleObserver {
     // player is ever destroyed (for example, if it was no longer a singleton and had multiple
     // instances) any jobs would also be cancelled.
     private val coroutineScope = CoroutineScope(Dispatchers.Default) + Job()
-
     private var _playerState = MutableStateFlow<PlayerState>(PlayerState.NoResultYet)
     val playerState = _playerState.asStateFlow()
 
diff --git a/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/MainActivity.kt b/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/MainActivity.kt
index edb29011..891e255d 100644
--- a/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/MainActivity.kt
+++ b/samples/minimaloboe/src/main/kotlin/com/example/minimaloboe/MainActivity.kt
@@ -31,13 +31,11 @@ import androidx.compose.runtime.getValue
 import androidx.compose.ui.Modifier
 import androidx.compose.ui.tooling.preview.Preview
 import androidx.lifecycle.ProcessLifecycleOwner
-import androidx.lifecycle.compose.ExperimentalLifecycleComposeApi
 import androidx.lifecycle.compose.collectAsStateWithLifecycle
 import com.example.minimaloboe.ui.theme.SamplesTheme
 
 class MainActivity : ComponentActivity() {
 
-    @OptIn(ExperimentalLifecycleComposeApi::class)
     override fun onCreate(savedInstanceState: Bundle?) {
         super.onCreate(savedInstanceState)
 
@@ -59,23 +57,18 @@ class MainActivity : ComponentActivity() {
     }
 }
 
-@ExperimentalLifecycleComposeApi
 @Composable
 fun MainControls() {
     val playerState by AudioPlayer.playerState.collectAsStateWithLifecycle()
     MainControls(playerState, AudioPlayer::setPlaybackEnabled)
 }
 
-@ExperimentalLifecycleComposeApi
 @Composable
 fun MainControls(playerState: PlayerState, setPlaybackEnabled: (Boolean) -> Unit) {
 
     Column {
-
         val isPlaying = playerState is PlayerState.Started
-
         Text(text = "Minimal Oboe!")
-
         Row {
             Button(
                 onClick = { setPlaybackEnabled(true) },
@@ -101,12 +94,10 @@ fun MainControls(playerState: PlayerState, setPlaybackEnabled: (Boolean) -> Unit
                         "Unknown. Result = " + playerState.resultCode
                     }
                 }
-
         Text(uiStatusMessage)
     }
 }
 
-@OptIn(ExperimentalLifecycleComposeApi::class)
 @Preview(showBackground = true)
 @Composable
 fun DefaultPreview() {
diff --git a/samples/parselib/build.gradle b/samples/parselib/build.gradle
index c593a5de..fb547e2c 100644
--- a/samples/parselib/build.gradle
+++ b/samples/parselib/build.gradle
@@ -1,31 +1,33 @@
 apply plugin: 'com.android.library'
 
 android {
-    compileSdkVersion 34
-
     defaultConfig {
         minSdkVersion 21
-        targetSdkVersion 34
+        targetSdkVersion 35
+        compileSdkVersion 35
 
         testInstrumentationRunner "androidx.test.runner.AndroidJUnitRunner"
     }
-
     buildTypes {
         release {
             minifyEnabled false
             proguardFiles getDefaultProguardFile('proguard-android-optimize.txt')
         }
     }
-
+    compileOptions {
+        sourceCompatibility JavaVersion.VERSION_18
+        targetCompatibility JavaVersion.VERSION_18
+    }
     externalNativeBuild {
         cmake {
             path 'src/main/cpp/CMakeLists.txt'
         }
     }
+    namespace 'com.google.oboe.samples'
 }
 
 dependencies {
     implementation fileTree(dir: 'libs', include: ['*.jar'])
 
-    implementation 'androidx.appcompat:appcompat:1.1.0'
+    implementation 'androidx.appcompat:appcompat:1.7.0'
 }
diff --git a/samples/parselib/src/main/AndroidManifest.xml b/samples/parselib/src/main/AndroidManifest.xml
index 009cab7d..94cbbcfc 100644
--- a/samples/parselib/src/main/AndroidManifest.xml
+++ b/samples/parselib/src/main/AndroidManifest.xml
@@ -1,2 +1 @@
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.samples" />
+<manifest xmlns:android="http://schemas.android.com/apk/res/android" />
diff --git a/samples/parselib/src/main/cpp/wav/AudioEncoding.h b/samples/parselib/src/main/cpp/wav/AudioEncoding.h
index 2b9703a4..0a510739 100644
--- a/samples/parselib/src/main/cpp/wav/AudioEncoding.h
+++ b/samples/parselib/src/main/cpp/wav/AudioEncoding.h
@@ -27,6 +27,8 @@ public:
     static const int PCM_16 = 0;
     static const int PCM_8 = 1;
     static const int PCM_IEEEFLOAT = 2;
+    static const int PCM_24 = 3;
+    static const int PCM_32 = 4;
 };
 
 } // namespace parselib
diff --git a/samples/parselib/src/main/cpp/wav/WavStreamReader.cpp b/samples/parselib/src/main/cpp/wav/WavStreamReader.cpp
index 968c8a98..ba59c9ee 100644
--- a/samples/parselib/src/main/cpp/wav/WavStreamReader.cpp
+++ b/samples/parselib/src/main/cpp/wav/WavStreamReader.cpp
@@ -52,8 +52,10 @@ int WavStreamReader::getSampleEncoding() {
                 return AudioEncoding::PCM_16;
 
             case 24:
-                // TODO - Support 24-bit WAV data
-                return AudioEncoding::INVALID; // for now
+                return AudioEncoding::PCM_24;
+
+            case 32:
+                return AudioEncoding::PCM_32;
 
             default:
                 return AudioEncoding::INVALID;
diff --git a/src/aaudio/AAudioExtensions.h b/src/aaudio/AAudioExtensions.h
index eed73f37..d3f41a65 100644
--- a/src/aaudio/AAudioExtensions.h
+++ b/src/aaudio/AAudioExtensions.h
@@ -18,6 +18,7 @@
 #define OBOE_AAUDIO_EXTENSIONS_H
 
 #include <dlfcn.h>
+#include <set>
 #include <stdint.h>
 
 #include <sys/system_properties.h>
@@ -37,22 +38,82 @@ namespace oboe {
 
 typedef struct AAudioStreamStruct         AAudioStream;
 
+// The output device type collection must be updated if there is any new added output device type
+const static std::set<DeviceType> ALL_OUTPUT_DEVICE_TYPES = {
+        DeviceType::BuiltinEarpiece,
+        DeviceType::BuiltinSpeaker,
+        DeviceType::WiredHeadset,
+        DeviceType::WiredHeadphones,
+        DeviceType::LineAnalog,
+        DeviceType::LineDigital,
+        DeviceType::BluetoothSco,
+        DeviceType::BluetoothA2dp,
+        DeviceType::Hdmi,
+        DeviceType::HdmiArc,
+        DeviceType::HdmiEarc,
+        DeviceType::UsbDevice,
+        DeviceType::UsbHeadset,
+        DeviceType::UsbAccessory,
+        DeviceType::Dock,
+        DeviceType::DockAnalog,
+        DeviceType::FM,
+        DeviceType::Telephony,
+        DeviceType::AuxLine,
+        DeviceType::IP,
+        DeviceType::Bus,
+        DeviceType::HearingAid,
+        DeviceType::BuiltinSpeakerSafe,
+        DeviceType::RemoteSubmix,
+        DeviceType::BleHeadset,
+        DeviceType::BleSpeaker,
+        DeviceType::BleBroadcast,
+};
+
+// The input device type collection must be updated if there is any new added input device type
+const static std::set<DeviceType> ALL_INPUT_DEVICE_TYPES = {
+        DeviceType::BuiltinMic,
+        DeviceType::BluetoothSco,
+        DeviceType::WiredHeadset,
+        DeviceType::Hdmi,
+        DeviceType::Telephony,
+        DeviceType::Dock,
+        DeviceType::DockAnalog,
+        DeviceType::UsbAccessory,
+        DeviceType::UsbDevice,
+        DeviceType::UsbHeadset,
+        DeviceType::FMTuner,
+        DeviceType::TVTuner,
+        DeviceType::LineAnalog,
+        DeviceType::LineDigital,
+        DeviceType::BluetoothA2dp,
+        DeviceType::IP,
+        DeviceType::Bus,
+        DeviceType::RemoteSubmix,
+        DeviceType::BleHeadset,
+        DeviceType::HdmiArc,
+        DeviceType::HdmiEarc,
+};
+
 /**
  * Call some AAudio test routines that are not part of the normal API.
  */
 class AAudioExtensions {
 private: // Because it is a singleton. Call getInstance() instead.
     AAudioExtensions() {
-        int32_t policy = getIntegerProperty("aaudio.mmap_policy", 0);
-        mMMapSupported = isPolicyEnabled(policy);
+        mLibLoader = AAudioLoader::getInstance();
+        if (!initMMapPolicy()) {
+            int32_t policy = getIntegerProperty("aaudio.mmap_policy", 0);
+            mMMapSupported = isPolicyEnabled(policy);
 
-        policy = getIntegerProperty("aaudio.mmap_exclusive_policy", 0);
-        mMMapExclusiveSupported = isPolicyEnabled(policy);
+            policy = getIntegerProperty("aaudio.mmap_exclusive_policy", 0);
+            mMMapExclusiveSupported = isPolicyEnabled(policy);
+        }
     }
 
 public:
     static bool isPolicyEnabled(int32_t policy) {
-        return (policy == AAUDIO_POLICY_AUTO || policy == AAUDIO_POLICY_ALWAYS);
+        const MMapPolicy mmapPolicy = static_cast<MMapPolicy>(policy);
+        return (mmapPolicy == MMapPolicy::Auto || mmapPolicy == MMapPolicy::Always);
     }
 
     static AAudioExtensions &getInstance() {
@@ -66,6 +127,9 @@ public:
     }
 
     bool isMMapUsed(AAudioStream *aaudioStream) {
+        if (mLibLoader != nullptr && mLibLoader->stream_isMMapUsed != nullptr) {
+            return mLibLoader->stream_isMMapUsed(aaudioStream);
+        }
         if (loadSymbols()) return false;
         if (mAAudioStream_isMMap == nullptr) return false;
         return mAAudioStream_isMMap(aaudioStream);
@@ -80,12 +144,27 @@ public:
      * @return 0 or a negative error code
      */
     int32_t setMMapEnabled(bool enabled) {
+        // The API for setting mmap policy is public after API level 36.
+        if (mLibLoader != nullptr && mLibLoader->aaudio_setMMapPolicy != nullptr) {
+            return mLibLoader->aaudio_setMMapPolicy(
+                    static_cast<aaudio_policy_t>(enabled ? MMapPolicy::Auto : MMapPolicy::Never));
+        }
+        // When there is no public API, fallback to loading the symbol from hidden API.
         if (loadSymbols()) return AAUDIO_ERROR_UNAVAILABLE;
         if (mAAudio_setMMapPolicy == nullptr) return false;
-        return mAAudio_setMMapPolicy(enabled ? AAUDIO_POLICY_AUTO : AAUDIO_POLICY_NEVER);
+        return mAAudio_setMMapPolicy(
+                static_cast<int32_t>(enabled ? MMapPolicy::Auto : MMapPolicy::Never));
     }
 
     bool isMMapEnabled() {
+        // The API for getting mmap policy is public after API level 36.
+        // Use it when it is available.
+        if (mLibLoader != nullptr && mLibLoader->aaudio_getMMapPolicy != nullptr) {
+            MMapPolicy policy = static_cast<MMapPolicy>(mLibLoader->aaudio_getMMapPolicy());
+            return policy == MMapPolicy::Unspecified
+                    ? mMMapSupported : isPolicyEnabled(static_cast<int32_t>(policy));
+        }
+        // When there is no public API, fallback to loading the symbol from hidden API.
         if (loadSymbols()) return false;
         if (mAAudio_getMMapPolicy == nullptr) return false;
         int32_t policy = mAAudio_getMMapPolicy();
@@ -100,14 +179,59 @@ public:
         return mMMapExclusiveSupported;
     }
 
-private:
+    MMapPolicy getMMapPolicy(DeviceType deviceType, Direction direction) {
+        if (mLibLoader == nullptr ||
+            mLibLoader->aaudio_getPlatformMMapPolicy == nullptr) {
+            return MMapPolicy::Unspecified;
+        }
+        return static_cast<MMapPolicy>(mLibLoader->aaudio_getPlatformMMapPolicy(
+                static_cast<AAudio_DeviceType>(deviceType),
+                static_cast<aaudio_direction_t>(direction)));
+    }
 
-    enum {
-        AAUDIO_POLICY_NEVER = 1,
-        AAUDIO_POLICY_AUTO,
-        AAUDIO_POLICY_ALWAYS
-    };
-    typedef int32_t aaudio_policy_t;
+    MMapPolicy getMMapExclusivePolicy(DeviceType deviceType, Direction direction) {
+        if (mLibLoader == nullptr ||
+            mLibLoader->aaudio_getPlatformMMapExclusivePolicy == nullptr) {
+            return MMapPolicy::Unspecified;
+        }
+        return static_cast<MMapPolicy>(mLibLoader->aaudio_getPlatformMMapExclusivePolicy(
+                static_cast<AAudio_DeviceType>(deviceType),
+                static_cast<aaudio_direction_t>(direction)));
+    }
+
+private:
+    bool initMMapPolicy() {
+        if (mLibLoader == nullptr || mLibLoader->open() != 0) {
+            return false;
+        }
+        if (mLibLoader->aaudio_getPlatformMMapPolicy == nullptr ||
+            mLibLoader->aaudio_getPlatformMMapExclusivePolicy == nullptr) {
+            return false;
+        }
+        mMMapSupported =
+                std::any_of(ALL_INPUT_DEVICE_TYPES.begin(), ALL_INPUT_DEVICE_TYPES.end(),
+                            [this](DeviceType deviceType) {
+                                return  isPolicyEnabled(static_cast<int32_t>(
+                                        getMMapPolicy(deviceType, Direction::Input)));
+                            }) ||
+                std::any_of(ALL_OUTPUT_DEVICE_TYPES.begin(), ALL_OUTPUT_DEVICE_TYPES.end(),
+                            [this](DeviceType deviceType) {
+                                return  isPolicyEnabled(static_cast<int32_t>(
+                                        getMMapPolicy(deviceType, Direction::Output)));
+                            });
+        mMMapExclusiveSupported =
+                std::any_of(ALL_INPUT_DEVICE_TYPES.begin(), ALL_INPUT_DEVICE_TYPES.end(),
+                            [this](DeviceType deviceType) {
+                                return  isPolicyEnabled(static_cast<int32_t>(
+                                        getMMapExclusivePolicy(deviceType, Direction::Input)));
+                            }) ||
+                std::any_of(ALL_OUTPUT_DEVICE_TYPES.begin(), ALL_OUTPUT_DEVICE_TYPES.end(),
+                            [this](DeviceType deviceType) {
+                                return  isPolicyEnabled(static_cast<int32_t>(
+                                        getMMapExclusivePolicy(deviceType, Direction::Output)));
+                            });
+        return true;
+    }
 
     int getIntegerProperty(const char *name, int defaultValue) {
         int result = defaultValue;
@@ -130,14 +254,12 @@ private:
             return 0;
         }
 
-        AAudioLoader *libLoader = AAudioLoader::getInstance();
-        int openResult = libLoader->open();
-        if (openResult != 0) {
+        if (mLibLoader == nullptr || mLibLoader->open() != 0) {
             LOGD("%s() could not open " LIB_AAUDIO_NAME, __func__);
             return AAUDIO_ERROR_UNAVAILABLE;
         }
 
-        void *libHandle = AAudioLoader::getInstance()->getLibHandle();
+        void *libHandle = mLibLoader->getLibHandle();
         if (libHandle == nullptr) {
             LOGE("%s() could not find " LIB_AAUDIO_NAME, __func__);
             return AAUDIO_ERROR_UNAVAILABLE;
@@ -173,6 +295,8 @@ private:
     bool    (*mAAudioStream_isMMap)(AAudioStream *stream) = nullptr;
     int32_t (*mAAudio_setMMapPolicy)(aaudio_policy_t policy) = nullptr;
     aaudio_policy_t (*mAAudio_getMMapPolicy)() = nullptr;
+
+    AAudioLoader *mLibLoader;
 };
 
 } // namespace oboe
diff --git a/src/aaudio/AAudioLoader.cpp b/src/aaudio/AAudioLoader.cpp
index 213a6ef9..65609996 100644
--- a/src/aaudio/AAudioLoader.cpp
+++ b/src/aaudio/AAudioLoader.cpp
@@ -102,6 +102,10 @@ int AAudioLoader::open() {
         builder_setSpatializationBehavior = load_V_PBI("AAudioStreamBuilder_setSpatializationBehavior");
     }
 
+    if (getSdkVersion() >= __ANDROID_API_B__) {
+        builder_setPresentationEndCallback = load_V_PBPRPV("AAudioStreamBuilder_setPresentationEndCallback");
+    }
+
     builder_delete             = load_I_PB("AAudioStreamBuilder_delete");
 
 
@@ -177,6 +181,19 @@ int AAudioLoader::open() {
         stream_getHardwareFormat = load_F_PS("AAudioStream_getHardwareFormat");
     }
 
+    if (getSdkVersion() >= __ANDROID_API_B__) {
+        aaudio_getPlatformMMapPolicy = load_I_II("AAudio_getPlatformMMapPolicy");
+        aaudio_getPlatformMMapExclusivePolicy = load_I_II("AAudio_getPlatformMMapExclusivePolicy");
+        aaudio_setMMapPolicy = load_I_I("AAudio_setMMapPolicy");
+        aaudio_getMMapPolicy = load_I("AAudio_getMMapPolicy");
+        stream_isMMapUsed = load_O_PS("AAudioStream_isMMapUsed");
+
+        stream_setOffloadDelayPadding = load_I_PSII("AAudioStream_setOffloadDelayPadding");
+        stream_getOffloadDelay = load_I_PS("AAudioStream_getOffloadDelay");
+        stream_getOffloadPadding = load_I_PS("AAudioStream_getOffloadPadding");
+        stream_setOffloadEndOfStream = load_I_PS("AAudioStream_setOffloadEndOfStream");
+    }
+
     return 0;
 }
 
@@ -306,6 +323,36 @@ AAudioLoader::signature_V_PBO AAudioLoader::load_V_PBO(const char *functionName)
     return reinterpret_cast<signature_V_PBO>(proc);
 }
 
+AAudioLoader::signature_I_II AAudioLoader::load_I_II(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_I_II>(proc);
+}
+
+AAudioLoader::signature_I_I AAudioLoader::load_I_I(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_I_I>(proc);
+}
+
+AAudioLoader::signature_I AAudioLoader::load_I(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_I>(proc);
+}
+
+AAudioLoader::signature_V_PBPRPV AAudioLoader::load_V_PBPRPV(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_V_PBPRPV>(proc);
+}
+
+AAudioLoader::signature_I_PSII AAudioLoader::load_I_PSII(const char *functionName) {
+    void *proc = dlsym(mLibHandle, functionName);
+    AAudioLoader_check(proc, functionName);
+    return reinterpret_cast<signature_I_PSII>(proc);
+}
+
 // Ensure that all AAudio primitive data types are int32_t
 #define ASSERT_INT32(type) static_assert(std::is_same<int32_t, type>::value, \
 #type" must be int32_t")
@@ -501,6 +548,50 @@ AAudioLoader::signature_V_PBO AAudioLoader::load_V_PBO(const char *functionName)
 
 #endif
 
+// The aaudio device type and aaudio policy were added in NDK 28,
+// which is the first version to support Android W (API 36).
+#if __NDK_MAJOR__ >= 29
+
+    ASSERT_INT32(AAudio_DeviceType);
+    static_assert((int32_t)DeviceType::BuiltinEarpiece == AAUDIO_DEVICE_BUILTIN_EARPIECE, ERRMSG);
+    static_assert((int32_t)DeviceType::BuiltinSpeaker == AAUDIO_DEVICE_BUILTIN_SPEAKER, ERRMSG);
+    static_assert((int32_t)DeviceType::WiredHeadset == AAUDIO_DEVICE_WIRED_HEADSET, ERRMSG);
+    static_assert((int32_t)DeviceType::WiredHeadphones == AAUDIO_DEVICE_WIRED_HEADPHONES, ERRMSG);
+    static_assert((int32_t)DeviceType::LineAnalog == AAUDIO_DEVICE_LINE_ANALOG, ERRMSG);
+    static_assert((int32_t)DeviceType::LineDigital == AAUDIO_DEVICE_LINE_DIGITAL, ERRMSG);
+    static_assert((int32_t)DeviceType::BluetoothSco == AAUDIO_DEVICE_BLUETOOTH_SCO, ERRMSG);
+    static_assert((int32_t)DeviceType::BluetoothA2dp == AAUDIO_DEVICE_BLUETOOTH_A2DP, ERRMSG);
+    static_assert((int32_t)DeviceType::Hdmi == AAUDIO_DEVICE_HDMI, ERRMSG);
+    static_assert((int32_t)DeviceType::HdmiArc == AAUDIO_DEVICE_HDMI_ARC, ERRMSG);
+    static_assert((int32_t)DeviceType::UsbDevice == AAUDIO_DEVICE_USB_DEVICE, ERRMSG);
+    static_assert((int32_t)DeviceType::UsbAccessory == AAUDIO_DEVICE_USB_ACCESSORY, ERRMSG);
+    static_assert((int32_t)DeviceType::Dock == AAUDIO_DEVICE_DOCK, ERRMSG);
+    static_assert((int32_t)DeviceType::FM == AAUDIO_DEVICE_FM, ERRMSG);
+    static_assert((int32_t)DeviceType::BuiltinMic == AAUDIO_DEVICE_BUILTIN_MIC, ERRMSG);
+    static_assert((int32_t)DeviceType::FMTuner == AAUDIO_DEVICE_FM_TUNER, ERRMSG);
+    static_assert((int32_t)DeviceType::TVTuner == AAUDIO_DEVICE_TV_TUNER, ERRMSG);
+    static_assert((int32_t)DeviceType::Telephony == AAUDIO_DEVICE_TELEPHONY, ERRMSG);
+    static_assert((int32_t)DeviceType::AuxLine == AAUDIO_DEVICE_AUX_LINE, ERRMSG);
+    static_assert((int32_t)DeviceType::IP == AAUDIO_DEVICE_IP, ERRMSG);
+    static_assert((int32_t)DeviceType::Bus == AAUDIO_DEVICE_BUS, ERRMSG);
+    static_assert((int32_t)DeviceType::UsbHeadset == AAUDIO_DEVICE_USB_HEADSET, ERRMSG);
+    static_assert((int32_t)DeviceType::HearingAid == AAUDIO_DEVICE_HEARING_AID, ERRMSG);
+    static_assert((int32_t)DeviceType::BuiltinSpeakerSafe == AAUDIO_DEVICE_BUILTIN_SPEAKER_SAFE, ERRMSG);
+    static_assert((int32_t)DeviceType::RemoteSubmix == AAUDIO_DEVICE_REMOTE_SUBMIX, ERRMSG);
+    static_assert((int32_t)DeviceType::BleHeadset == AAUDIO_DEVICE_BLE_HEADSET, ERRMSG);
+    static_assert((int32_t)DeviceType::BleSpeaker == AAUDIO_DEVICE_BLE_SPEAKER, ERRMSG);
+    static_assert((int32_t)DeviceType::HdmiEarc == AAUDIO_DEVICE_HDMI_EARC, ERRMSG);
+    static_assert((int32_t)DeviceType::BleBroadcast == AAUDIO_DEVICE_BLE_BROADCAST, ERRMSG);
+    static_assert((int32_t)DeviceType::DockAnalog == AAUDIO_DEVICE_DOCK_ANALOG, ERRMSG);
+
+    ASSERT_INT32(aaudio_policy_t);
+    static_assert((int32_t)MMapPolicy::Unspecified == AAUDIO_UNSPECIFIED, ERRMSG);
+    static_assert((int32_t)MMapPolicy::Never == AAUDIO_POLICY_NEVER, ERRMSG);
+    static_assert((int32_t)MMapPolicy::Auto == AAUDIO_POLICY_AUTO, ERRMSG);
+    static_assert((int32_t)MMapPolicy::Always == AAUDIO_POLICY_ALWAYS, ERRMSG);
+
+#endif // __NDK_MAJOR__ >= 28
+
 #endif // AAUDIO_AAUDIO_H
 
 } // namespace oboe
diff --git a/src/aaudio/AAudioLoader.h b/src/aaudio/AAudioLoader.h
index 2378464e..3eb5c640 100644
--- a/src/aaudio/AAudioLoader.h
+++ b/src/aaudio/AAudioLoader.h
@@ -62,8 +62,11 @@ typedef int32_t aaudio_session_id_t;
 #include <aaudio/AAudio.h>
 #endif
 
-#ifndef __NDK_MAJOR__
+#ifdef __NDK_MAJOR__
+#define OBOE_USING_NDK 1
+#else
 #define __NDK_MAJOR__ 0
+#define OBOE_USING_NDK 0
 #endif
 
 #if __NDK_MAJOR__ < 24
@@ -72,6 +75,13 @@ typedef uint32_t aaudio_channel_mask_t;
 typedef int32_t aaudio_spatialization_behavior_t;
 #endif
 
+#if OBOE_USING_NDK && __NDK_MAJOR__ < 29
+// Defined in Android B
+typedef void (*AAudioStream_presentationEndCallback)(
+        AAudioStream* stream,
+        void* userData);
+#endif
+
 #ifndef __ANDROID_API_Q__
 #define __ANDROID_API_Q__ 29
 #endif
@@ -92,6 +102,16 @@ typedef int32_t aaudio_spatialization_behavior_t;
 #define __ANDROID_API_U__ 34
 #endif
 
+#ifndef __ANDROID_API_B__
+#define __ANDROID_API_B__ 36
+#endif
+
+#if OBOE_USING_NDK && __NDK_MAJOR__ < 29
+// These were defined in Android B
+typedef int32_t AAudio_DeviceType;
+typedef int32_t aaudio_policy_t;
+#endif
+
 namespace oboe {
 
 /**
@@ -114,6 +134,7 @@ class AAudioLoader {
     // H = cHar
     // U = uint32_t
     // O = bOol
+    // R = pResentation end callback
 
     typedef int32_t  (*signature_I_PPB)(AAudioStreamBuilder **builder);
 
@@ -147,6 +168,10 @@ class AAudioLoader {
                                           AAudioStream_errorCallback,
                                           void *);
 
+    typedef void (*signature_V_PBPRPV)(AAudioStreamBuilder *,
+                                       AAudioStream_presentationEndCallback,
+                                       void *);
+
     typedef aaudio_format_t (*signature_F_PS)(AAudioStream *stream);
 
     typedef int32_t (*signature_I_PSPVIL)(AAudioStream *, void *, int32_t, int64_t);
@@ -163,6 +188,11 @@ class AAudioLoader {
 
     typedef uint32_t (*signature_U_PS)(AAudioStream *);
 
+    typedef int32_t (*signature_I_II)(int32_t, int32_t);
+    typedef int32_t (*signature_I_I)(int32_t);
+    typedef int32_t (*signature_I)();
+    typedef int32_t (*signature_I_PSII)(AAudioStream *, int32_t, int32_t);
+
     static AAudioLoader* getInstance(); // singleton
 
     /**
@@ -210,6 +240,7 @@ class AAudioLoader {
 
     signature_V_PBPDPV  builder_setDataCallback = nullptr;
     signature_V_PBPEPV  builder_setErrorCallback = nullptr;
+    signature_V_PBPRPV  builder_setPresentationEndCallback = nullptr;
 
     signature_I_PB      builder_delete = nullptr;
 
@@ -265,6 +296,18 @@ class AAudioLoader {
     signature_I_PS   stream_getHardwareSampleRate = nullptr;
     signature_F_PS   stream_getHardwareFormat = nullptr;
 
+
+    signature_I_II   aaudio_getPlatformMMapPolicy = nullptr;
+    signature_I_II   aaudio_getPlatformMMapExclusivePolicy = nullptr;
+    signature_I_I    aaudio_setMMapPolicy = nullptr;
+    signature_I      aaudio_getMMapPolicy = nullptr;
+    signature_O_PS   stream_isMMapUsed = nullptr;
+
+    signature_I_PSII stream_setOffloadDelayPadding = nullptr;
+    signature_I_PS   stream_getOffloadDelay = nullptr;
+    signature_I_PS   stream_getOffloadPadding = nullptr;
+    signature_I_PS   stream_setOffloadEndOfStream = nullptr;
+
   private:
     AAudioLoader() {}
     ~AAudioLoader();
@@ -290,6 +333,11 @@ class AAudioLoader {
     signature_V_PBU     load_V_PBU(const char *name);
     signature_U_PS      load_U_PS(const char *name);
     signature_V_PBO     load_V_PBO(const char *name);
+    signature_I_II      load_I_II(const char *name);
+    signature_I_I       load_I_I(const char *name);
+    signature_I         load_I(const char *name);
+    signature_V_PBPRPV  load_V_PBPRPV(const char *name);
+    signature_I_PSII    load_I_PSII(const char *name);
 
     void *mLibHandle = nullptr;
 };
diff --git a/src/aaudio/AudioStreamAAudio.cpp b/src/aaudio/AudioStreamAAudio.cpp
index 421798df..851318f7 100644
--- a/src/aaudio/AudioStreamAAudio.cpp
+++ b/src/aaudio/AudioStreamAAudio.cpp
@@ -20,8 +20,8 @@
 
 #include "aaudio/AAudioLoader.h"
 #include "aaudio/AudioStreamAAudio.h"
-#include "common/AudioClock.h"
 #include "common/OboeDebug.h"
+#include "oboe/AudioClock.h"
 #include "oboe/Utilities.h"
 #include "AAudioExtensions.h"
 
@@ -60,9 +60,13 @@ static aaudio_data_callback_result_t oboe_aaudio_data_callback_proc(
 // This runs in its own thread.
 // Only one of these threads will be launched from internalErrorCallback().
 // It calls app error callbacks from a static function in case the stream gets deleted.
-static void oboe_aaudio_error_thread_proc(AudioStreamAAudio *oboeStream,
+static void oboe_aaudio_error_thread_proc_common(AudioStreamAAudio *oboeStream,
                                           Result error) {
-    LOGD("%s(,%d) - entering >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", __func__, error);
+#if 0
+    LOGE("%s() sleep for 5 seconds", __func__);
+    usleep(5*1000*1000);
+    LOGD("%s() - woke up -------------------------", __func__);
+#endif
     AudioStreamErrorCallback *errorCallback = oboeStream->getErrorCallback();
     if (errorCallback == nullptr) return; // should be impossible
     bool isErrorHandled = errorCallback->onError(oboeStream, error);
@@ -74,16 +78,46 @@ static void oboe_aaudio_error_thread_proc(AudioStreamAAudio *oboeStream,
         // Warning, oboeStream may get deleted by this callback.
         errorCallback->onErrorAfterClose(oboeStream, error);
     }
+}
+
+// Callback thread for raw pointers.
+static void oboe_aaudio_error_thread_proc(AudioStreamAAudio *oboeStream,
+                                          Result error) {
+    LOGD("%s(,%d) - entering >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", __func__, error);
+    oboe_aaudio_error_thread_proc_common(oboeStream, error);
     LOGD("%s() - exiting <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", __func__);
 }
 
-// This runs in its own thread.
-// Only one of these threads will be launched from internalErrorCallback().
-// Prevents deletion of the stream if the app is using AudioStreamBuilder::openSharedStream()
+// Callback thread for shared pointers.
 static void oboe_aaudio_error_thread_proc_shared(std::shared_ptr<AudioStream> sharedStream,
                                           Result error) {
+    LOGD("%s(,%d) - entering >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", __func__, error);
+    // Hold the shared pointer while we use the raw pointer.
+    AudioStreamAAudio *oboeStream = reinterpret_cast<AudioStreamAAudio*>(sharedStream.get());
+    oboe_aaudio_error_thread_proc_common(oboeStream, error);
+    LOGD("%s() - exiting <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", __func__);
+}
+
+static void oboe_aaudio_presentation_thread_proc_common(AudioStreamAAudio *oboeStream) {
+    auto presentationCallback = oboeStream->getPresentationCallback();
+    if (presentationCallback == nullptr) return; // should be impossible
+    presentationCallback->onPresentationEnded(oboeStream);
+}
+
+// Callback thread for raw pointers
+static void oboe_aaudio_presentation_thread_proc(AudioStreamAAudio *oboeStream) {
+    LOGD("%s() - entering >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", __func__);
+    oboe_aaudio_presentation_thread_proc_common(oboeStream);
+    LOGD("%s() - exiting <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", __func__);
+}
+
+// Callback thread for shared pointers
+static void oboe_aaudio_presentation_end_thread_proc_shared(
+        std::shared_ptr<AudioStream> sharedStream) {
+    LOGD("%s() - entering >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>", __func__);
     AudioStreamAAudio *oboeStream = reinterpret_cast<AudioStreamAAudio*>(sharedStream.get());
-    oboe_aaudio_error_thread_proc(oboeStream, error);
+    oboe_aaudio_presentation_thread_proc_common(oboeStream);
+    LOGD("%s() - exiting <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<", __func__);
 }
 
 namespace oboe {
@@ -346,6 +380,13 @@ Result AudioStreamAAudio::open() {
     // Else if the data callback is not being used then the write method will return an error
     // and the app can stop and close the stream.
 
+    if (isPresentationCallbackSpecified() &&
+        mLibLoader->builder_setPresentationEndCallback != nullptr) {
+        mLibLoader->builder_setPresentationEndCallback(aaudioBuilder,
+                                                       internalPresentationEndCallback,
+                                                       this);
+    }
+
     // ============= OPEN THE STREAM ================
     {
         AAudioStream *stream = nullptr;
@@ -865,4 +906,79 @@ bool AudioStreamAAudio::isMMapUsed() {
     }
 }
 
+// static
+// Static method for the presentation end callback.
+// We use a method so we can access protected methods on the stream.
+// Launch a thread to handle the error.
+// That other thread can safely stop, close and delete the stream.
+void AudioStreamAAudio::internalPresentationEndCallback(AAudioStream *stream, void *userData) {
+    AudioStreamAAudio *oboeStream = reinterpret_cast<AudioStreamAAudio*>(userData);
+
+    // Prevents deletion of the stream if the app is using AudioStreamBuilder::openStream(shared_ptr)
+    std::shared_ptr<AudioStream> sharedStream = oboeStream->lockWeakThis();
+
+    if (stream != oboeStream->getUnderlyingStream()) {
+        LOGW("%s() stream already closed or closing", __func__); // might happen if there are bugs
+    } else if (sharedStream) {
+        // Handle error on a separate thread using shared pointer.
+        std::thread t(oboe_aaudio_presentation_end_thread_proc_shared, sharedStream);
+        t.detach();
+    } else {
+        // Handle error on a separate thread.
+        std::thread t(oboe_aaudio_presentation_thread_proc, oboeStream);
+        t.detach();
+    }
+}
+
+Result AudioStreamAAudio::setOffloadDelayPadding(
+        int32_t delayInFrames, int32_t paddingInFrames) {
+    if (mLibLoader->stream_setOffloadDelayPadding == nullptr) {
+        return Result::ErrorUnimplemented;
+    }
+    std::shared_lock<std::shared_mutex> lock(mAAudioStreamLock);
+    AAudioStream *stream = mAAudioStream.load();
+    if (stream == nullptr) {
+        return Result::ErrorClosed;
+    }
+    return static_cast<Result>(
+            mLibLoader->stream_setOffloadDelayPadding(stream, delayInFrames, paddingInFrames));
+}
+
+ResultWithValue<int32_t> AudioStreamAAudio::getOffloadDelay() {
+    if (mLibLoader->stream_getOffloadDelay == nullptr) {
+        return ResultWithValue<int32_t>(Result::ErrorUnimplemented);
+    }
+    std::shared_lock<std::shared_mutex> lock(mAAudioStreamLock);
+    AAudioStream *stream = mAAudioStream.load();
+    if (stream == nullptr) {
+        return Result::ErrorClosed;
+    }
+    return ResultWithValue<int32_t>::createBasedOnSign(mLibLoader->stream_getOffloadDelay(stream));
+}
+
+ResultWithValue<int32_t> AudioStreamAAudio::getOffloadPadding() {
+    if (mLibLoader->stream_getOffloadPadding == nullptr) {
+        return ResultWithValue<int32_t>(Result::ErrorUnimplemented);
+    }
+    std::shared_lock<std::shared_mutex> lock(mAAudioStreamLock);
+    AAudioStream *stream = mAAudioStream.load();
+    if (stream == nullptr) {
+        return ResultWithValue<int32_t>(Result::ErrorClosed);
+    }
+    return ResultWithValue<int32_t>::createBasedOnSign(
+            mLibLoader->stream_getOffloadPadding(stream));
+}
+
+Result AudioStreamAAudio::setOffloadEndOfStream() {
+    if (mLibLoader->stream_setOffloadEndOfStream == nullptr) {
+        return Result::ErrorUnimplemented;
+    }
+    std::shared_lock<std::shared_mutex> lock(mAAudioStreamLock);
+    AAudioStream *stream = mAAudioStream.load();
+    if (stream == nullptr) {
+        return ResultWithValue<int32_t>(Result::ErrorClosed);
+    }
+    return static_cast<Result>(mLibLoader->stream_setOffloadEndOfStream(stream));
+}
+
 } // namespace oboe
diff --git a/src/aaudio/AudioStreamAAudio.h b/src/aaudio/AudioStreamAAudio.h
index 2df4d857..c69723b1 100644
--- a/src/aaudio/AudioStreamAAudio.h
+++ b/src/aaudio/AudioStreamAAudio.h
@@ -100,12 +100,29 @@ public:
         mAdpfOpenAttempted = false;
     }
 
+    oboe::Result reportWorkload(int32_t appWorkload) override {
+        if (!isPerformanceHintEnabled()) {
+            return oboe::Result::ErrorInvalidState;
+        }
+        mAdpfWrapper.reportWorkload(appWorkload);
+        return oboe::Result::OK;
+    }
+
+    Result setOffloadDelayPadding(int32_t delayInFrames, int32_t paddingInFrames) override;
+    ResultWithValue<int32_t> getOffloadDelay() override;
+    ResultWithValue<int32_t> getOffloadPadding() override;
+    Result setOffloadEndOfStream() override;
+
 protected:
     static void internalErrorCallback(
             AAudioStream *stream,
             void *userData,
             aaudio_result_t error);
 
+    static void internalPresentationEndCallback(
+            AAudioStream *stream,
+            void *userData);
+
     void *getUnderlyingStream() const override {
         return mAAudioStream.load();
     }
diff --git a/src/common/AdpfWrapper.cpp b/src/common/AdpfWrapper.cpp
index 05accdea..e03880a5 100644
--- a/src/common/AdpfWrapper.cpp
+++ b/src/common/AdpfWrapper.cpp
@@ -18,9 +18,12 @@
 #include <stdint.h>
 #include <sys/types.h>
 
+#include "oboe/AudioClock.h"
 #include "AdpfWrapper.h"
-#include "AudioClock.h"
 #include "OboeDebug.h"
+#include "Trace.h"
+
+using namespace oboe;
 
 typedef APerformanceHintManager* (*APH_getManager)();
 typedef APerformanceHintSession* (*APH_createSession)(APerformanceHintManager*, const int32_t*,
@@ -64,6 +67,9 @@ static int loadAphFunctions() {
     }
 
     gAPerformanceHintBindingInitialized = true;
+
+    Trace::initialize();
+
     return 0;
 }
 
@@ -95,9 +101,12 @@ int AdpfWrapper::open(pid_t threadId,
 void AdpfWrapper::reportActualDuration(int64_t actualDurationNanos) {
     //LOGD("ADPF Oboe %s(dur=%lld)", __func__, (long long)actualDurationNanos);
     std::lock_guard<std::mutex> lock(mLock);
+    Trace::beginSection("reportActualDuration");
+    Trace::setCounter("actualDurationNanos", actualDurationNanos);
     if (mHintSession != nullptr) {
         gAPH_reportActualWorkDurationFn(mHintSession, actualDurationNanos);
     }
+    Trace::endSection();
 }
 
 void AdpfWrapper::close() {
@@ -110,15 +119,32 @@ void AdpfWrapper::close() {
 
 void AdpfWrapper::onBeginCallback() {
     if (isOpen()) {
-        mBeginCallbackNanos = oboe::AudioClock::getNanoseconds(CLOCK_REALTIME);
+        mBeginCallbackNanos = oboe::AudioClock::getNanoseconds();
     }
 }
 
 void AdpfWrapper::onEndCallback(double durationScaler) {
     if (isOpen()) {
-        int64_t endCallbackNanos = oboe::AudioClock::getNanoseconds(CLOCK_REALTIME);
+        int64_t endCallbackNanos = oboe::AudioClock::getNanoseconds();
         int64_t actualDurationNanos = endCallbackNanos - mBeginCallbackNanos;
         int64_t scaledDurationNanos = static_cast<int64_t>(actualDurationNanos * durationScaler);
         reportActualDuration(scaledDurationNanos);
+        // When the workload is non-zero, update the conversion factor from workload
+        // units to nanoseconds duration.
+        if (mPreviousWorkload > 0) {
+            mNanosPerWorkloadUnit = ((double) scaledDurationNanos) / mPreviousWorkload;
+        }
+    }
+}
+
+void AdpfWrapper::reportWorkload(int32_t appWorkload) {
+    if (isOpen()) {
+        // Compare with previous workload. If we think we will need more
+        // time to render the callback then warn ADPF as soon as possible.
+        if (appWorkload > mPreviousWorkload && mNanosPerWorkloadUnit > 0.0) {
+            int64_t predictedDuration = (int64_t) (appWorkload * mNanosPerWorkloadUnit);
+            reportActualDuration(predictedDuration);
+        }
+        mPreviousWorkload = appWorkload;
     }
 }
diff --git a/src/common/AdpfWrapper.h b/src/common/AdpfWrapper.h
index 330ee3c6..ef5da705 100644
--- a/src/common/AdpfWrapper.h
+++ b/src/common/AdpfWrapper.h
@@ -24,62 +24,69 @@
 #include <unistd.h>
 #include <mutex>
 
-struct APerformanceHintManager;
-struct APerformanceHintSession;
+namespace oboe {
 
-typedef struct APerformanceHintManager APerformanceHintManager;
-typedef struct APerformanceHintSession APerformanceHintSession;
+    struct APerformanceHintManager;
+    struct APerformanceHintSession;
 
-class AdpfWrapper {
-public:
-     /**
-      * Create an ADPF session that can be used to boost performance.
-      * @param threadId
-      * @param targetDurationNanos - nominal period of isochronous task
-      * @return zero or negative error
-      */
-    int open(pid_t threadId,
-             int64_t targetDurationNanos);
+    typedef struct APerformanceHintManager APerformanceHintManager;
+    typedef struct APerformanceHintSession APerformanceHintSession;
 
-    bool isOpen() const {
-        return (mHintSession != nullptr);
-    }
+    class AdpfWrapper {
+    public:
+        /**
+         * Create an ADPF session that can be used to boost performance.
+         * @param threadId
+         * @param targetDurationNanos - nominal period of isochronous task
+         * @return zero or negative error
+         */
+        int open(pid_t threadId,
+                 int64_t targetDurationNanos);
 
-    void close();
+        bool isOpen() const {
+            return (mHintSession != nullptr);
+        }
 
-    /**
-     * Call this at the beginning of the callback that you are measuring.
-     */
-    void onBeginCallback();
+        void close();
 
-    /**
-     * Call this at the end of the callback that you are measuring.
-     * It is OK to skip this if you have a short callback.
-     */
-    void onEndCallback(double durationScaler);
+        /**
+         * Call this at the beginning of the callback that you are measuring.
+         */
+        void onBeginCallback();
 
-    /**
-     * For internal use only!
-     * This is a hack for communicating with experimental versions of ADPF.
-     * @param enabled
-     */
-    static void setUseAlternative(bool enabled) {
-        sUseAlternativeHack = enabled;
-    }
+        /**
+         * Call this at the end of the callback that you are measuring.
+         * It is OK to skip this if you have a short callback.
+         */
+        void onEndCallback(double durationScaler);
 
-    /**
-     * Report the measured duration of a callback.
-     * This is normally called by onEndCallback().
-     * You may want to call this directly in order to give an advance hint of a jump in workload.
-     * @param actualDurationNanos
-     */
-    void reportActualDuration(int64_t actualDurationNanos);
+        /**
+         * For internal use only!
+         * This is a hack for communicating with experimental versions of ADPF.
+         * @param enabled
+         */
+        static void setUseAlternative(bool enabled) {
+            sUseAlternativeHack = enabled;
+        }
 
-private:
-    std::mutex               mLock;
-    APerformanceHintSession* mHintSession = nullptr;
-    int64_t                  mBeginCallbackNanos = 0;
-    static bool              sUseAlternativeHack;
-};
+        /**
+         * Report the measured duration of a callback.
+         * This is normally called by onEndCallback().
+         * You may want to call this directly in order to give an advance hint of a jump in workload.
+         * @param actualDurationNanos
+         */
+        void reportActualDuration(int64_t actualDurationNanos);
 
+        void reportWorkload(int32_t appWorkload);
+
+    private:
+        std::mutex mLock;
+        APerformanceHintSession *mHintSession = nullptr;
+        int64_t mBeginCallbackNanos = 0;
+        static bool sUseAlternativeHack;
+        int32_t mPreviousWorkload = 0;
+        double mNanosPerWorkloadUnit = 0.0;
+    };
+
+}
 #endif //SYNTHMARK_ADPF_WRAPPER_H
diff --git a/src/common/AudioStream.cpp b/src/common/AudioStream.cpp
index 06c01118..5eb4e462 100644
--- a/src/common/AudioStream.cpp
+++ b/src/common/AudioStream.cpp
@@ -18,10 +18,10 @@
 #include <pthread.h>
 #include <thread>
 
-#include <oboe/AudioStream.h>
+#include "oboe/AudioClock.h"
+#include "oboe/AudioStream.h"
+#include "oboe/Utilities.h"
 #include "OboeDebug.h"
-#include "AudioClock.h"
-#include <oboe/Utilities.h>
 
 namespace oboe {
 
@@ -30,6 +30,12 @@ namespace oboe {
  */
 AudioStream::AudioStream(const AudioStreamBuilder &builder)
         : AudioStreamBase(builder) {
+    LOGD("Constructor for AudioStream at %p", this);
+}
+
+AudioStream::~AudioStream() {
+    // This is to help debug use after free bugs.
+    LOGD("Destructor for AudioStream at %p", this);
 }
 
 Result AudioStream::close() {
@@ -113,8 +119,12 @@ Result AudioStream::start(int64_t timeoutNanoseconds)
     Result result = requestStart();
     if (result != Result::OK) return result;
     if (timeoutNanoseconds <= 0) return result;
-    return waitForStateTransition(StreamState::Starting,
+    result = waitForStateTransition(StreamState::Starting,
                                   StreamState::Started, timeoutNanoseconds);
+    if (result != Result::OK) {
+        LOGE("AudioStream::%s() timed out before moving from STARTING to STARTED", __func__);
+    }
+    return result;
 }
 
 Result AudioStream::pause(int64_t timeoutNanoseconds)
diff --git a/src/common/AudioStreamBuilder.cpp b/src/common/AudioStreamBuilder.cpp
index b1549b54..474e1ab0 100644
--- a/src/common/AudioStreamBuilder.cpp
+++ b/src/common/AudioStreamBuilder.cpp
@@ -100,8 +100,10 @@ Result AudioStreamBuilder::openStreamInternal(AudioStream **streamPP) {
         return result;
     }
 
+#ifndef OBOE_SUPPRESS_LOG_SPAM
     LOGI("%s() %s -------- %s --------",
          __func__, getDirection() == Direction::Input ? "INPUT" : "OUTPUT", getVersionText());
+#endif
 
     if (streamPP == nullptr) {
         return Result::ErrorNull;
@@ -117,7 +119,7 @@ Result AudioStreamBuilder::openStreamInternal(AudioStream **streamPP) {
     // Do we need to make a child stream and convert.
     if (conversionNeeded) {
         AudioStream *tempStream;
-        result = childBuilder.openStream(&tempStream);
+        result = childBuilder.openStreamInternal(&tempStream);
         if (result != Result::OK) {
             return result;
         }
@@ -144,7 +146,9 @@ Result AudioStreamBuilder::openStreamInternal(AudioStream **streamPP) {
 
             // Use childStream in a FilterAudioStream.
             LOGI("%s() create a FilterAudioStream for data conversion.", __func__);
-            FilterAudioStream *filterStream = new FilterAudioStream(parentBuilder, tempStream);
+            std::shared_ptr<AudioStream> childStream(tempStream);
+            FilterAudioStream *filterStream = new FilterAudioStream(parentBuilder, childStream);
+            childStream->setWeakThis(childStream);
             result = filterStream->configureFlowGraph();
             if (result !=  Result::OK) {
                 filterStream->close();
@@ -178,24 +182,26 @@ Result AudioStreamBuilder::openStreamInternal(AudioStream **streamPP) {
         AAudioExtensions::getInstance().setMMapEnabled(wasMMapOriginallyEnabled); // restore original
     }
     if (result == Result::OK) {
-
-        int32_t  optimalBufferSize = -1;
-        // Use a reasonable default buffer size.
-        if (streamP->getDirection() == Direction::Input) {
-            // For input, small size does not improve latency because the stream is usually
-            // run close to empty. And a low size can result in XRuns so always use the maximum.
-            optimalBufferSize = streamP->getBufferCapacityInFrames();
-        } else if (streamP->getPerformanceMode() == PerformanceMode::LowLatency
-                && streamP->getDirection() == Direction::Output)  { // Output check is redundant.
-            optimalBufferSize = streamP->getFramesPerBurst() *
-                                    kBufferSizeInBurstsForLowLatencyStreams;
-        }
-        if (optimalBufferSize >= 0) {
-            auto setBufferResult = streamP->setBufferSizeInFrames(optimalBufferSize);
-            if (!setBufferResult) {
-                LOGW("Failed to setBufferSizeInFrames(%d). Error was %s",
-                     optimalBufferSize,
-                     convertToText(setBufferResult.error()));
+        // AAudio supports setBufferSizeInFrames() so use it.
+        if (streamP->getAudioApi() == AudioApi::AAudio) {
+            int32_t  optimalBufferSize = -1;
+            // Use a reasonable default buffer size.
+            if (streamP->getDirection() == Direction::Input) {
+                // For input, small size does not improve latency because the stream is usually
+                // run close to empty. And a low size can result in XRuns so always use the maximum.
+                optimalBufferSize = streamP->getBufferCapacityInFrames();
+            } else if (streamP->getPerformanceMode() == PerformanceMode::LowLatency
+                    && streamP->getDirection() == Direction::Output)  { // Output check is redundant.
+                optimalBufferSize = streamP->getFramesPerBurst() *
+                                        kBufferSizeInBurstsForLowLatencyStreams;
+            }
+            if (optimalBufferSize >= 0) {
+                auto setBufferResult = streamP->setBufferSizeInFrames(optimalBufferSize);
+                if (!setBufferResult) {
+                    LOGW("Failed to setBufferSizeInFrames(%d). Error was %s",
+                         optimalBufferSize,
+                         convertToText(setBufferResult.error()));
+                }
             }
         }
 
diff --git a/src/common/FilterAudioStream.h b/src/common/FilterAudioStream.h
index 18907499..99f6f5ac 100644
--- a/src/common/FilterAudioStream.h
+++ b/src/common/FilterAudioStream.h
@@ -38,9 +38,9 @@ public:
      *
      * @param builder containing all the stream's attributes
      */
-    FilterAudioStream(const AudioStreamBuilder &builder, AudioStream *childStream)
+    FilterAudioStream(const AudioStreamBuilder &builder, std::shared_ptr<AudioStream> childStream)
     : AudioStream(builder)
-    , mChildStream(childStream) {
+     , mChildStream(childStream) {
         // Intercept the callback if used.
         if (builder.isErrorCallbackSpecified()) {
             mErrorCallback = mChildStream->swapErrorCallback(this);
@@ -66,10 +66,6 @@ public:
 
     virtual ~FilterAudioStream() = default;
 
-    AudioStream *getChildStream() const {
-        return mChildStream.get();
-    }
-
     Result configureFlowGraph();
 
     // Close child and parent.
@@ -216,7 +212,7 @@ public:
 
 private:
 
-    std::unique_ptr<AudioStream>             mChildStream; // this stream wraps the child stream
+    std::shared_ptr<AudioStream>             mChildStream; // this stream wraps the child stream
     std::unique_ptr<DataConversionFlowGraph> mFlowGraph; // for converting data
     std::unique_ptr<uint8_t[]>               mBlockingBuffer; // temp buffer for write()
     double                                   mRateScaler = 1.0; // ratio parent/child sample rates
diff --git a/src/common/StabilizedCallback.cpp b/src/common/StabilizedCallback.cpp
index a2ac5495..0c561a53 100644
--- a/src/common/StabilizedCallback.cpp
+++ b/src/common/StabilizedCallback.cpp
@@ -14,9 +14,9 @@
  * limitations under the License.
  */
 
-#include "oboe/StabilizedCallback.h"
-#include "common/AudioClock.h"
 #include "common/Trace.h"
+#include "oboe/AudioClock.h"
+#include "oboe/StabilizedCallback.h"
 
 constexpr int32_t kLoadGenerationStepSizeNanos = 20000;
 constexpr float kPercentageOfCallbackToUse = 0.8;
diff --git a/src/common/Trace.cpp b/src/common/Trace.cpp
index f08f36dc..bf81f22d 100644
--- a/src/common/Trace.cpp
+++ b/src/common/Trace.cpp
@@ -19,6 +19,8 @@
 #include "Trace.h"
 #include "OboeDebug.h"
 
+using namespace oboe;
+
 static char buffer[256];
 
 // Tracing functions
@@ -26,35 +28,50 @@ static void *(*ATrace_beginSection)(const char *sectionName);
 
 static void *(*ATrace_endSection)();
 
+static void *(*ATrace_setCounter)(const char *counterName, int64_t counterValue);
+
+static bool *(*ATrace_isEnabled)(void);
+
 typedef void *(*fp_ATrace_beginSection)(const char *sectionName);
 
 typedef void *(*fp_ATrace_endSection)();
 
-bool Trace::mIsTracingSupported = false;
+typedef void *(*fp_ATrace_setCounter)(const char *counterName, int64_t counterValue);
 
-void Trace::beginSection(const char *format, ...){
+typedef bool *(*fp_ATrace_isEnabled)(void);
+
+bool Trace::mIsTracingEnabled = false;
+bool Trace::mIsSetCounterSupported = false;
+bool Trace::mHasErrorBeenShown = false;
 
-    if (mIsTracingSupported) {
+void Trace::beginSection(const char *format, ...){
+    if (mIsTracingEnabled) {
         va_list va;
         va_start(va, format);
         vsprintf(buffer, format, va);
         ATrace_beginSection(buffer);
         va_end(va);
-    } else {
+    } else if (!mHasErrorBeenShown) {
         LOGE("Tracing is either not initialized (call Trace::initialize()) "
              "or not supported on this device");
+        mHasErrorBeenShown = true;
     }
 }
 
 void Trace::endSection() {
-
-    if (mIsTracingSupported) {
+    if (mIsTracingEnabled) {
         ATrace_endSection();
     }
 }
 
-void Trace::initialize() {
+void Trace::setCounter(const char *counterName, int64_t counterValue) {
+    if (mIsSetCounterSupported) {
+        ATrace_setCounter(counterName, counterValue);
+    }
+}
 
+void Trace::initialize() {
+    //LOGE("Trace::initialize");
     // Using dlsym allows us to use tracing on API 21+ without needing android/trace.h which wasn't
     // published until API 23
     void *lib = dlopen("libandroid.so", RTLD_NOW | RTLD_LOCAL);
@@ -67,9 +84,21 @@ void Trace::initialize() {
         ATrace_endSection =
                 reinterpret_cast<fp_ATrace_endSection >(
                         dlsym(lib, "ATrace_endSection"));
+        ATrace_setCounter =
+                reinterpret_cast<fp_ATrace_setCounter >(
+                        dlsym(lib, "ATrace_setCounter"));
+        ATrace_isEnabled =
+                reinterpret_cast<fp_ATrace_isEnabled >(
+                        dlsym(lib, "ATrace_isEnabled"));
 
-        if (ATrace_beginSection != nullptr && ATrace_endSection != nullptr){
-            mIsTracingSupported = true;
+        if (ATrace_beginSection != nullptr && ATrace_endSection != nullptr
+                && ATrace_isEnabled != nullptr && ATrace_isEnabled()) {
+            mIsTracingEnabled = true;
+            if (ATrace_setCounter != nullptr) {
+                mIsSetCounterSupported = true;
+            } else {
+                LOGE("setCounter not supported");
+            }
         }
     }
 }
diff --git a/src/common/Trace.h b/src/common/Trace.h
index dad6c007..d3c1dd77 100644
--- a/src/common/Trace.h
+++ b/src/common/Trace.h
@@ -17,15 +17,29 @@
 #ifndef OBOE_TRACE_H
 #define OBOE_TRACE_H
 
+#include <cstdint>
+
+namespace oboe {
+
+/**
+ * Wrapper for tracing use with Perfetto
+ */
 class Trace {
 
 public:
     static void beginSection(const char *format, ...);
+
     static void endSection();
+
+    static void setCounter(const char *counterName, int64_t counterValue);
+
     static void initialize();
 
 private:
-    static bool mIsTracingSupported;
+    static bool mIsTracingEnabled;
+    static bool mIsSetCounterSupported;
+    static bool mHasErrorBeenShown;
 };
 
+}
 #endif //OBOE_TRACE_H
diff --git a/src/flowgraph/SampleRateConverter.cpp b/src/flowgraph/SampleRateConverter.cpp
index a15fcb8c..890057db 100644
--- a/src/flowgraph/SampleRateConverter.cpp
+++ b/src/flowgraph/SampleRateConverter.cpp
@@ -28,7 +28,8 @@ SampleRateConverter::SampleRateConverter(int32_t channelCount,
 
 void SampleRateConverter::reset() {
     FlowGraphNode::reset();
-    mInputCursor = kInitialCallCount;
+    mInputCallCount = kInitialCallCount;
+    mInputCursor = 0;
 }
 
 // Return true if there is a sample available.
diff --git a/src/flowgraph/SampleRateConverter.h b/src/flowgraph/SampleRateConverter.h
index f883e6ce..a4318f04 100644
--- a/src/flowgraph/SampleRateConverter.h
+++ b/src/flowgraph/SampleRateConverter.h
@@ -54,7 +54,7 @@ private:
     int32_t mNumValidInputFrames = 0; // number of valid frames currently in the input port buffer
     // We need our own callCount for upstream calls because calls occur at a different rate.
     // This means we cannot have cyclic graphs or merges that contain an SRC.
-    int64_t mInputCallCount = 0;
+    int64_t mInputCallCount = kInitialCallCount;
 
 };
 
diff --git a/src/opensles/AudioInputStreamOpenSLES.cpp b/src/opensles/AudioInputStreamOpenSLES.cpp
index 3653d964..8f511796 100644
--- a/src/opensles/AudioInputStreamOpenSLES.cpp
+++ b/src/opensles/AudioInputStreamOpenSLES.cpp
@@ -16,9 +16,6 @@
 
 #include <cassert>
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-
 #include "common/OboeDebug.h"
 #include "oboe/AudioStreamBuilder.h"
 #include "AudioInputStreamOpenSLES.h"
@@ -109,7 +106,7 @@ Result AudioInputStreamOpenSLES::open() {
             SL_DATAFORMAT_PCM,       // formatType
             static_cast<SLuint32>(mChannelCount),           // numChannels
             static_cast<SLuint32>(mSampleRate * kMillisPerSecond), // milliSamplesPerSec
-            bitsPerSample,                      // bitsPerSample
+            bitsPerSample,                      // mBitsPerSample
             bitsPerSample,                      // containerSize;
             channelCountToChannelMask(mChannelCount), // channelMask
             getDefaultByteOrder(),
@@ -151,8 +148,8 @@ Result AudioInputStreamOpenSLES::open() {
 
     // Configure the stream.
     result = (*mObjectInterface)->GetInterface(mObjectInterface,
-                                            SL_IID_ANDROIDCONFIGURATION,
-                                            &configItf);
+            EngineOpenSLES::getInstance().getIidAndroidConfiguration(),
+            &configItf);
 
     if (SL_RESULT_SUCCESS != result) {
         LOGW("%s() GetInterface(SL_IID_ANDROIDCONFIGURATION) failed with %s",
@@ -190,7 +187,9 @@ Result AudioInputStreamOpenSLES::open() {
         goto error;
     }
 
-    result = (*mObjectInterface)->GetInterface(mObjectInterface, SL_IID_RECORD, &mRecordInterface);
+    result = (*mObjectInterface)->GetInterface(mObjectInterface,
+                                               EngineOpenSLES::getInstance().getIidRecord(),
+                                               &mRecordInterface);
     if (SL_RESULT_SUCCESS != result) {
         LOGE("GetInterface RECORD result:%s", getSLErrStr(result));
         goto error;
@@ -213,7 +212,7 @@ Result AudioInputStreamOpenSLES::close() {
     LOGD("AudioInputStreamOpenSLES::%s()", __func__);
     std::lock_guard<std::mutex> lock(mLock);
     Result result = Result::OK;
-    if (getState() == StreamState::Closed){
+    if (getState() == StreamState::Closed) {
         result = Result::ErrorClosed;
     } else {
         (void) requestStop_l();
diff --git a/src/opensles/AudioInputStreamOpenSLES.h b/src/opensles/AudioInputStreamOpenSLES.h
index 08e7a056..0da64801 100644
--- a/src/opensles/AudioInputStreamOpenSLES.h
+++ b/src/opensles/AudioInputStreamOpenSLES.h
@@ -18,10 +18,8 @@
 #define AUDIO_INPUT_STREAM_OPENSL_ES_H_
 
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-
 #include "oboe/Oboe.h"
+#include "EngineOpenSLES.h"
 #include "AudioStreamOpenSLES.h"
 
 namespace oboe {
diff --git a/src/opensles/AudioOutputStreamOpenSLES.cpp b/src/opensles/AudioOutputStreamOpenSLES.cpp
index 2b689905..1b948857 100644
--- a/src/opensles/AudioOutputStreamOpenSLES.cpp
+++ b/src/opensles/AudioOutputStreamOpenSLES.cpp
@@ -16,11 +16,8 @@
 
 #include <cassert>
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-#include <common/AudioClock.h>
-
 #include "common/OboeDebug.h"
+#include "oboe/AudioClock.h"
 #include "oboe/AudioStreamBuilder.h"
 #include "AudioOutputStreamOpenSLES.h"
 #include "AudioStreamOpenSLES.h"
@@ -149,7 +146,7 @@ Result AudioOutputStreamOpenSLES::open() {
             SL_DATAFORMAT_PCM,       // formatType
             static_cast<SLuint32>(mChannelCount),           // numChannels
             static_cast<SLuint32>(mSampleRate * kMillisPerSecond),    // milliSamplesPerSec
-            bitsPerSample,                      // bitsPerSample
+            bitsPerSample,                      // mBitsPerSample
             bitsPerSample,                      // containerSize;
             channelCountToChannelMask(mChannelCount), // channelMask
             getDefaultByteOrder(),
@@ -180,8 +177,8 @@ Result AudioOutputStreamOpenSLES::open() {
 
     // Configure the stream.
     result = (*mObjectInterface)->GetInterface(mObjectInterface,
-                                               SL_IID_ANDROIDCONFIGURATION,
-                                               (void *)&configItf);
+            EngineOpenSLES::getInstance().getIidAndroidConfiguration(),
+            (void *)&configItf);
     if (SL_RESULT_SUCCESS != result) {
         LOGW("%s() GetInterface(SL_IID_ANDROIDCONFIGURATION) failed with %s",
              __func__, getSLErrStr(result));
@@ -207,7 +204,9 @@ Result AudioOutputStreamOpenSLES::open() {
         goto error;
     }
 
-    result = (*mObjectInterface)->GetInterface(mObjectInterface, SL_IID_PLAY, &mPlayInterface);
+    result = (*mObjectInterface)->GetInterface(mObjectInterface,
+                                               EngineOpenSLES::getInstance().getIidPlay(),
+                                               &mPlayInterface);
     if (SL_RESULT_SUCCESS != result) {
         LOGE("GetInterface PLAY result:%s", getSLErrStr(result));
         goto error;
@@ -235,7 +234,7 @@ Result AudioOutputStreamOpenSLES::close() {
     LOGD("AudioOutputStreamOpenSLES::%s()", __func__);
     std::lock_guard<std::mutex> lock(mLock);
     Result result = Result::OK;
-    if (getState() == StreamState::Closed){
+    if (getState() == StreamState::Closed) {
         result = Result::ErrorClosed;
     } else {
         (void) requestPause_l();
@@ -250,8 +249,7 @@ Result AudioOutputStreamOpenSLES::close() {
 }
 
 Result AudioOutputStreamOpenSLES::setPlayState_l(SLuint32 newState) {
-
-    LOGD("AudioOutputStreamOpenSLES(): %s() called", __func__);
+    LOGD("AudioOutputStreamOpenSLES::%s(%d) called", __func__, newState);
     Result result = Result::OK;
 
     if (mPlayInterface == nullptr){
@@ -268,7 +266,7 @@ Result AudioOutputStreamOpenSLES::setPlayState_l(SLuint32 newState) {
 }
 
 Result AudioOutputStreamOpenSLES::requestStart() {
-    LOGD("AudioOutputStreamOpenSLES(): %s() called", __func__);
+    LOGD("AudioOutputStreamOpenSLES::%s() called", __func__);
 
     mLock.lock();
     StreamState initialState = getState();
@@ -318,7 +316,7 @@ Result AudioOutputStreamOpenSLES::requestStart() {
 }
 
 Result AudioOutputStreamOpenSLES::requestPause() {
-    LOGD("AudioOutputStreamOpenSLES(): %s() called", __func__);
+    LOGD("AudioOutputStreamOpenSLES::%s() called", __func__);
     std::lock_guard<std::mutex> lock(mLock);
     return requestPause_l();
 }
@@ -361,7 +359,7 @@ Result AudioOutputStreamOpenSLES::requestFlush() {
 }
 
 Result AudioOutputStreamOpenSLES::requestFlush_l() {
-    LOGD("AudioOutputStreamOpenSLES(): %s() called", __func__);
+    LOGD("AudioOutputStreamOpenSLES::%s() called", __func__);
     if (getState() == StreamState::Closed) {
         return Result::ErrorClosed;
     }
@@ -385,9 +383,8 @@ Result AudioOutputStreamOpenSLES::requestStop() {
 }
 
 Result AudioOutputStreamOpenSLES::requestStop_l() {
-    LOGD("AudioOutputStreamOpenSLES(): %s() called", __func__);
-
     StreamState initialState = getState();
+    LOGD("AudioOutputStreamOpenSLES::%s() called, initialState = %d", __func__, initialState);
     switch (initialState) {
         case StreamState::Stopping:
         case StreamState::Stopped:
diff --git a/src/opensles/AudioOutputStreamOpenSLES.h b/src/opensles/AudioOutputStreamOpenSLES.h
index fc57fd37..29b3de6a 100644
--- a/src/opensles/AudioOutputStreamOpenSLES.h
+++ b/src/opensles/AudioOutputStreamOpenSLES.h
@@ -18,10 +18,8 @@
 #define AUDIO_OUTPUT_STREAM_OPENSL_ES_H_
 
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-
 #include "oboe/Oboe.h"
+#include "EngineOpenSLES.h"
 #include "AudioStreamOpenSLES.h"
 
 namespace oboe {
diff --git a/src/opensles/AudioStreamBuffered.cpp b/src/opensles/AudioStreamBuffered.cpp
index 9737b72b..d608f206 100644
--- a/src/opensles/AudioStreamBuffered.cpp
+++ b/src/opensles/AudioStreamBuffered.cpp
@@ -19,8 +19,8 @@
 #include "oboe/Oboe.h"
 
 #include "common/OboeDebug.h"
+#include "oboe/AudioClock.h"
 #include "opensles/AudioStreamBuffered.h"
-#include "common/AudioClock.h"
 
 namespace oboe {
 
diff --git a/src/opensles/AudioStreamOpenSLES.cpp b/src/opensles/AudioStreamOpenSLES.cpp
index ec041ccb..d96a4616 100644
--- a/src/opensles/AudioStreamOpenSLES.cpp
+++ b/src/opensles/AudioStreamOpenSLES.cpp
@@ -16,13 +16,11 @@
 #include <cassert>
 #include <android/log.h>
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-#include <oboe/AudioStream.h>
-#include <common/AudioClock.h>
-
 #include "common/OboeDebug.h"
+#include "oboe/AudioClock.h"
+#include "oboe/AudioStream.h"
 #include "oboe/AudioStreamBuilder.h"
+#include "EngineOpenSLES.h"
 #include "AudioStreamOpenSLES.h"
 #include "OpenSLESUtilities.h"
 
@@ -67,8 +65,9 @@ SLuint32 AudioStreamOpenSLES::getDefaultByteOrder() {
 }
 
 Result AudioStreamOpenSLES::open() {
-
+#ifndef OBOE_SUPPRESS_LOG_SPAM
     LOGI("AudioStreamOpenSLES::open() chans=%d, rate=%d", mChannelCount, mSampleRate);
+#endif
 
     // OpenSL ES only supports I16 and Float
     if (mFormat != AudioFormat::I16 && mFormat != AudioFormat::Float) {
@@ -282,7 +281,7 @@ void AudioStreamOpenSLES::logUnsupportedAttributes() {
              "is not supported on OpenSLES streams running on pre-Android N-MR1 versions.");
     }
     // Content Type
-    if (mContentType != ContentType::Music) {
+    if (static_cast<const int32_t>(mContentType) != kUnspecified) {
         LOGW("ContentType [AudioStreamBuilder::setContentType()] "
              "is not supported on OpenSLES streams.");
     }
@@ -305,11 +304,28 @@ void AudioStreamOpenSLES::logUnsupportedAttributes() {
              "is not supported on OpenSLES streams.");
     }
 
+    if (mIsContentSpatialized) {
+        LOGW("Boolean [AudioStreamBuilder::setIsContentSpatialized()] "
+             "is not supported on OpenSLES streams.");
+    }
+
     // Allowed Capture Policy
     if (mAllowedCapturePolicy != AllowedCapturePolicy::Unspecified) {
         LOGW("AllowedCapturePolicy [AudioStreamBuilder::setAllowedCapturePolicy()] "
              "is not supported on OpenSLES streams.");
     }
+
+    // Package Name
+    if (!mPackageName.empty()) {
+        LOGW("PackageName [AudioStreamBuilder::setPackageName()] "
+             "is not supported on OpenSLES streams.");
+    }
+
+    // Attribution Tag
+    if (!mAttributionTag.empty()) {
+        LOGW("AttributionTag [AudioStreamBuilder::setAttributionTag()] "
+             "is not supported on OpenSLES streams.");
+    }
 }
 
 SLresult AudioStreamOpenSLES::configurePerformanceMode(SLAndroidConfigurationItf configItf) {
@@ -364,6 +380,7 @@ SLresult AudioStreamOpenSLES::updateStreamParameters(SLAndroidConfigurationItf c
 
 // This is called under mLock.
 Result AudioStreamOpenSLES::close_l() {
+    LOGD("AudioOutputStreamOpenSLES::%s() called", __func__);
     if (mState == StreamState::Closed) {
         return Result::ErrorClosed;
     }
@@ -372,9 +389,17 @@ Result AudioStreamOpenSLES::close_l() {
 
     onBeforeDestroy();
 
-    if (mObjectInterface != nullptr) {
-        (*mObjectInterface)->Destroy(mObjectInterface);
-        mObjectInterface = nullptr;
+    // Mark as CLOSED before we unlock for the join.
+    // This will prevent other threads from trying to close().
+    setState(StreamState::Closed);
+
+    SLObjectItf  tempObjectInterface = mObjectInterface;
+    mObjectInterface = nullptr;
+    if (tempObjectInterface != nullptr) {
+        // Temporarily unlock so we can join() the callback thread.
+        mLock.unlock();
+        (*tempObjectInterface)->Destroy(tempObjectInterface); // Will join the callback!
+        mLock.lock();
     }
 
     onAfterDestroy();
@@ -382,8 +407,6 @@ Result AudioStreamOpenSLES::close_l() {
     mSimpleBufferQueueInterface = nullptr;
     EngineOpenSLES::getInstance().close();
 
-    setState(StreamState::Closed);
-
     return Result::OK;
 }
 
@@ -442,8 +465,9 @@ static void bqCallbackGlue(SLAndroidSimpleBufferQueueItf bq, void *context) {
 
 SLresult AudioStreamOpenSLES::registerBufferQueueCallback() {
     // The BufferQueue
-    SLresult result = (*mObjectInterface)->GetInterface(mObjectInterface, SL_IID_ANDROIDSIMPLEBUFFERQUEUE,
-                                                &mSimpleBufferQueueInterface);
+    SLresult result = (*mObjectInterface)->GetInterface(mObjectInterface,
+            EngineOpenSLES::getInstance().getIidAndroidSimpleBufferQueue(),
+            &mSimpleBufferQueueInterface);
     if (SL_RESULT_SUCCESS != result) {
         LOGE("get buffer queue interface:%p result:%s",
              mSimpleBufferQueueInterface,
diff --git a/src/opensles/AudioStreamOpenSLES.h b/src/opensles/AudioStreamOpenSLES.h
index 0164b839..d86ed22e 100644
--- a/src/opensles/AudioStreamOpenSLES.h
+++ b/src/opensles/AudioStreamOpenSLES.h
@@ -19,9 +19,6 @@
 
 #include <memory>
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
-
 #include "oboe/Oboe.h"
 #include "common/MonotonicCounter.h"
 #include "opensles/AudioStreamBuffered.h"
diff --git a/src/opensles/EngineOpenSLES.cpp b/src/opensles/EngineOpenSLES.cpp
index e1007d10..8c0ca4bb 100644
--- a/src/opensles/EngineOpenSLES.cpp
+++ b/src/opensles/EngineOpenSLES.cpp
@@ -15,6 +15,7 @@
  */
 
 #include <dlfcn.h>
+
 #include "common/OboeDebug.h"
 #include "EngineOpenSLES.h"
 #include "OpenSLESUtilities.h"
@@ -24,40 +25,96 @@ using namespace oboe;
 // OpenSL ES is deprecated in SDK 30.
 // So we use custom dynamic linking to access the library.
 #define LIB_OPENSLES_NAME "libOpenSLES.so"
-typedef SLresult  (*prototype_slCreateEngine)(
-        SLObjectItf             *pEngine,
-        SLuint32                numOptions,
-        const SLEngineOption    *pEngineOptions,
-        SLuint32                numInterfaces,
-        const SLInterfaceID     *pInterfaceIds,
-        const SLboolean         *pInterfaceRequired
-);
-static prototype_slCreateEngine gFunction_slCreateEngine = nullptr;
-static void *gLibOpenSlesLibraryHandle = nullptr;
+
+EngineOpenSLES &EngineOpenSLES::getInstance() {
+    static EngineOpenSLES sInstance;
+    return sInstance;
+}
+
+// Satisfy extern in OpenSLES.h
+// These are required because of b/337360630, which was causing
+// Oboe to have link failures if libOpenSLES.so was not available.
+// If you are statically linking Oboe and libOpenSLES.so is a shared library
+// and you observe crashes, you can pass DO_NOT_DEFINE_OPENSL_ES_CONSTANTS to cmake.
+#ifndef DO_NOT_DEFINE_OPENSL_ES_CONSTANTS
+SL_API const SLInterfaceID SL_IID_ENGINE = nullptr;
+SL_API const SLInterfaceID SL_IID_ANDROIDSIMPLEBUFFERQUEUE = nullptr;
+SL_API const SLInterfaceID SL_IID_ANDROIDCONFIGURATION = nullptr;
+SL_API const SLInterfaceID SL_IID_RECORD = nullptr;
+SL_API const SLInterfaceID SL_IID_BUFFERQUEUE = nullptr;
+SL_API const SLInterfaceID SL_IID_VOLUME = nullptr;
+SL_API const SLInterfaceID SL_IID_PLAY = nullptr;
+#endif
+
+static const char *getSafeDlerror() {
+    static const char *defaultMessage = "not found?";
+    char *errorMessage = dlerror();
+    return (errorMessage == nullptr) ? defaultMessage : errorMessage;
+}
 
 // Load the OpenSL ES library and the one primary entry point.
 // @return true if linked OK
-static bool linkOpenSLES() {
-    if (gLibOpenSlesLibraryHandle == nullptr && gFunction_slCreateEngine == nullptr) {
+bool EngineOpenSLES::linkOpenSLES() {
+    if (mDynamicLinkState == kLinkStateBad) {
+        LOGE("%s(), OpenSL ES not available, based on previous link failure.", __func__);
+    } else if (mDynamicLinkState == kLinkStateUninitialized) {
+        // Set to BAD now in case we return because of an error.
+        // This is safe form race conditions because this function is always called
+        // under mLock amd the state is only accessed from this function.
+        mDynamicLinkState = kLinkStateBad;
         // Use RTLD_NOW to avoid the unpredictable behavior that RTLD_LAZY can cause.
         // Also resolving all the links now will prevent a run-time penalty later.
-        gLibOpenSlesLibraryHandle = dlopen(LIB_OPENSLES_NAME, RTLD_NOW);
-        if (gLibOpenSlesLibraryHandle == nullptr) {
-            LOGE("linkOpenSLES() could not find " LIB_OPENSLES_NAME);
+        mLibOpenSlesLibraryHandle = dlopen(LIB_OPENSLES_NAME, RTLD_NOW);
+        if (mLibOpenSlesLibraryHandle == nullptr) {
+            LOGE("%s() could not dlopen(%s), %s", __func__, LIB_OPENSLES_NAME, getSafeDlerror());
+            return false;
         } else {
-            gFunction_slCreateEngine = (prototype_slCreateEngine) dlsym(
-                    gLibOpenSlesLibraryHandle,
+            mFunction_slCreateEngine = (prototype_slCreateEngine) dlsym(
+                    mLibOpenSlesLibraryHandle,
                     "slCreateEngine");
-            LOGD("linkOpenSLES(): dlsym(%s) returned %p", "slCreateEngine",
-                 gFunction_slCreateEngine);
+            LOGD("%s(): dlsym(%s) returned %p", __func__,
+                 "slCreateEngine", mFunction_slCreateEngine);
+            if (mFunction_slCreateEngine == nullptr) {
+                LOGE("%s(): dlsym(slCreateEngine) returned null, %s", __func__, getSafeDlerror());
+                return false;
+            }
+
+            // Load IID interfaces.
+            LOCAL_SL_IID_ENGINE = getIidPointer("SL_IID_ENGINE");
+            if (LOCAL_SL_IID_ENGINE == nullptr) return false;
+            LOCAL_SL_IID_ANDROIDSIMPLEBUFFERQUEUE = getIidPointer(
+                    "SL_IID_ANDROIDSIMPLEBUFFERQUEUE");
+            if (LOCAL_SL_IID_ANDROIDSIMPLEBUFFERQUEUE == nullptr) return false;
+            LOCAL_SL_IID_ANDROIDCONFIGURATION = getIidPointer(
+                    "SL_IID_ANDROIDCONFIGURATION");
+            if (LOCAL_SL_IID_ANDROIDCONFIGURATION == nullptr) return false;
+            LOCAL_SL_IID_RECORD = getIidPointer("SL_IID_RECORD");
+            if (LOCAL_SL_IID_RECORD == nullptr) return false;
+            LOCAL_SL_IID_BUFFERQUEUE = getIidPointer("SL_IID_BUFFERQUEUE");
+            if (LOCAL_SL_IID_BUFFERQUEUE == nullptr) return false;
+            LOCAL_SL_IID_VOLUME = getIidPointer("SL_IID_VOLUME");
+            if (LOCAL_SL_IID_VOLUME == nullptr) return false;
+            LOCAL_SL_IID_PLAY = getIidPointer("SL_IID_PLAY");
+            if (LOCAL_SL_IID_PLAY == nullptr) return false;
+
+            mDynamicLinkState = kLinkStateGood;
         }
     }
-    return gFunction_slCreateEngine != nullptr;
+    return (mDynamicLinkState == kLinkStateGood);
 }
 
-EngineOpenSLES &EngineOpenSLES::getInstance() {
-    static EngineOpenSLES sInstance;
-    return sInstance;
+// A symbol like SL_IID_PLAY is a pointer to a structure.
+// The dlsym() function returns the address of the pointer, not the structure.
+// To get the address of the structure we have to dereference the pointer.
+SLInterfaceID EngineOpenSLES::getIidPointer(const char *symbolName) {
+    SLInterfaceID *iid_address = (SLInterfaceID *) dlsym(
+            mLibOpenSlesLibraryHandle,
+            symbolName);
+    if (iid_address == nullptr) {
+        LOGE("%s(): dlsym(%s) returned null, %s", __func__, symbolName, getSafeDlerror());
+        return (SLInterfaceID) nullptr;
+    }
+    return *iid_address; // Get address of the structure.
 }
 
 SLresult EngineOpenSLES::open() {
@@ -72,7 +129,7 @@ SLresult EngineOpenSLES::open() {
         };
 
         // create engine
-        result = (*gFunction_slCreateEngine)(&mEngineObject, 0, NULL, 0, NULL, NULL);
+        result = (*mFunction_slCreateEngine)(&mEngineObject, 0, NULL, 0, NULL, NULL);
         if (SL_RESULT_SUCCESS != result) {
             LOGE("EngineOpenSLES - slCreateEngine() result:%s", getSLErrStr(result));
             goto error;
@@ -86,7 +143,9 @@ SLresult EngineOpenSLES::open() {
         }
 
         // get the engine interface, which is needed in order to create other objects
-        result = (*mEngineObject)->GetInterface(mEngineObject, SL_IID_ENGINE, &mEngineInterface);
+        result = (*mEngineObject)->GetInterface(mEngineObject,
+                                                EngineOpenSLES::getInstance().getIidEngine(),
+                                                &mEngineInterface);
         if (SL_RESULT_SUCCESS != result) {
             LOGE("EngineOpenSLES - GetInterface() engine result:%s", getSLErrStr(result));
             goto error;
@@ -96,12 +155,17 @@ SLresult EngineOpenSLES::open() {
     return result;
 
 error:
-    close();
+    close_l();
     return result;
 }
 
 void EngineOpenSLES::close() {
     std::lock_guard<std::mutex> lock(mLock);
+    close_l();
+}
+
+// This must be called under mLock
+void EngineOpenSLES::close_l() {
     if (--mOpenCount == 0) {
         if (mEngineObject != nullptr) {
             (*mEngineObject)->Destroy(mEngineObject);
@@ -119,8 +183,8 @@ SLresult EngineOpenSLES::createAudioPlayer(SLObjectItf *objectItf,
                                            SLDataSource *audioSource,
                                            SLDataSink *audioSink) {
 
-    const SLInterfaceID ids[] = {SL_IID_BUFFERQUEUE, SL_IID_ANDROIDCONFIGURATION};
-    const SLboolean reqs[] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE};
+    SLInterfaceID ids[] = {LOCAL_SL_IID_BUFFERQUEUE, LOCAL_SL_IID_ANDROIDCONFIGURATION};
+    SLboolean reqs[] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE};
 
     return (*mEngineInterface)->CreateAudioPlayer(mEngineInterface, objectItf, audioSource,
                                                   audioSink,
@@ -131,8 +195,9 @@ SLresult EngineOpenSLES::createAudioRecorder(SLObjectItf *objectItf,
                                              SLDataSource *audioSource,
                                              SLDataSink *audioSink) {
 
-    const SLInterfaceID ids[] = {SL_IID_ANDROIDSIMPLEBUFFERQUEUE, SL_IID_ANDROIDCONFIGURATION };
-    const SLboolean reqs[] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE};
+    SLInterfaceID ids[] = {LOCAL_SL_IID_ANDROIDSIMPLEBUFFERQUEUE,
+                           LOCAL_SL_IID_ANDROIDCONFIGURATION };
+    SLboolean reqs[] = {SL_BOOLEAN_TRUE, SL_BOOLEAN_TRUE};
 
     return (*mEngineInterface)->CreateAudioRecorder(mEngineInterface, objectItf, audioSource,
                                                     audioSink,
diff --git a/src/opensles/EngineOpenSLES.h b/src/opensles/EngineOpenSLES.h
index 3d238a8c..f856406b 100644
--- a/src/opensles/EngineOpenSLES.h
+++ b/src/opensles/EngineOpenSLES.h
@@ -25,6 +25,15 @@
 
 namespace oboe {
 
+typedef SLresult  (*prototype_slCreateEngine)(
+        SLObjectItf             *pEngine,
+        SLuint32                numOptions,
+        const SLEngineOption    *pEngineOptions,
+        SLuint32                numInterfaces,
+        const SLInterfaceID     *pInterfaceIds,
+        const SLboolean         *pInterfaceRequired
+);
+
 /**
  * INTERNAL USE ONLY
  */
@@ -32,6 +41,8 @@ class EngineOpenSLES {
 public:
     static EngineOpenSLES &getInstance();
 
+    bool linkOpenSLES();
+
     SLresult open();
 
     void close();
@@ -45,6 +56,14 @@ public:
                                  SLDataSource *audioSource,
                                  SLDataSink *audioSink);
 
+    SLInterfaceID getIidEngine() { return LOCAL_SL_IID_ENGINE; }
+    SLInterfaceID getIidAndroidSimpleBufferQueue() { return LOCAL_SL_IID_ANDROIDSIMPLEBUFFERQUEUE; }
+    SLInterfaceID getIidAndroidConfiguration() { return LOCAL_SL_IID_ANDROIDCONFIGURATION; }
+    SLInterfaceID getIidRecord() { return LOCAL_SL_IID_RECORD; }
+    SLInterfaceID getIidBufferQueue() { return LOCAL_SL_IID_BUFFERQUEUE; }
+    SLInterfaceID getIidVolume() { return LOCAL_SL_IID_VOLUME; }
+    SLInterfaceID getIidPlay() { return LOCAL_SL_IID_PLAY; }
+
 private:
     // Make this a safe Singleton
     EngineOpenSLES()= default;
@@ -52,11 +71,34 @@ private:
     EngineOpenSLES(const EngineOpenSLES&)= delete;
     EngineOpenSLES& operator=(const EngineOpenSLES&)= delete;
 
+    SLInterfaceID getIidPointer(const char *symbolName);
+
+    /**
+     * Close the OpenSL ES engine.
+     * This must be called under mLock
+     */
+    void close_l();
+
     std::mutex             mLock;
     int32_t                mOpenCount = 0;
 
+    static constexpr int32_t kLinkStateUninitialized = 0;
+    static constexpr int32_t kLinkStateGood = 1;
+    static constexpr int32_t kLinkStateBad = 2;
+    int32_t                mDynamicLinkState = kLinkStateUninitialized;
     SLObjectItf            mEngineObject = nullptr;
     SLEngineItf            mEngineInterface = nullptr;
+
+    // These symbols are loaded using dlsym().
+    prototype_slCreateEngine mFunction_slCreateEngine = nullptr;
+    void                  *mLibOpenSlesLibraryHandle = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_ENGINE = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_ANDROIDSIMPLEBUFFERQUEUE = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_ANDROIDCONFIGURATION = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_RECORD = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_BUFFERQUEUE = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_VOLUME = nullptr;
+    SLInterfaceID          LOCAL_SL_IID_PLAY = nullptr;
 };
 
 } // namespace oboe
diff --git a/src/opensles/OutputMixerOpenSLES.h b/src/opensles/OutputMixerOpenSLES.h
index 813fd018..c3784882 100644
--- a/src/opensles/OutputMixerOpenSLES.h
+++ b/src/opensles/OutputMixerOpenSLES.h
@@ -20,8 +20,7 @@
 #include <atomic>
 #include <mutex>
 
-#include <SLES/OpenSLES.h>
-#include <SLES/OpenSLES_Android.h>
+#include "EngineOpenSLES.h"
 
 namespace oboe {
 
diff --git a/tests/CMakeLists.txt b/tests/CMakeLists.txt
index 45b1f8c7..7fb9e533 100644
--- a/tests/CMakeLists.txt
+++ b/tests/CMakeLists.txt
@@ -7,7 +7,7 @@ cmake_minimum_required(VERSION 3.4.1)
 # This may work on Linux.
 # set(ANDROID_NDK $ENV{HOME}/Android/sdk/ndk-bundle)
 
-set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -std=c++17")
+set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror -Wall -std=c++17 -DOBOE_SUPPRESS_LOG_SPAM")
 
 # Include GoogleTest library
 set(GOOGLETEST_ROOT ${ANDROID_NDK}/sources/third_party/googletest)
@@ -27,10 +27,12 @@ include_directories(
 add_executable(
 		testOboe
 		testAAudio.cpp
+		testAudioClock.cpp
 		testFlowgraph.cpp
 		testFullDuplexStream.cpp
 		testResampler.cpp
 		testReturnStop.cpp
+		testReturnStopDeadlock.cpp
 		testStreamClosedMethods.cpp
 		testStreamFramesProcessed.cpp
 		testStreamOpen.cpp
@@ -42,3 +44,4 @@ add_executable(
         )
 
 target_link_libraries(testOboe gtest oboe)
+target_link_options(testOboe PRIVATE "-Wl,-z,max-page-size=16384")
diff --git a/tests/README.md b/tests/README.md
index c8365680..91f47f1c 100644
--- a/tests/README.md
+++ b/tests/README.md
@@ -20,7 +20,9 @@ To test this on Mac or Linux enter:
     echo $ANDROID_NDK
     cmake --version
 
-They may already be set. If not, then this may work on Mac OS:
+They may already be set. If so then skip to "Running the Tests" below.
+
+If not, then this may work on Mac OS:
 
     export ANDROID_HOME=$HOME/Library/Android/sdk
     
@@ -28,7 +30,7 @@ or this may work on Linux:
 
     export ANDROID_HOME=$HOME/Android/Sdk
     
-Now we need to determine the latest installed version of the NDK. Enter:
+Tadb rooto determine the latest installed version of the NDK. Enter:
     
     ls $ANDROID_HOME/ndk
     
@@ -52,7 +54,7 @@ To run the tests, enter:
     cd tests
     ./run_tests.sh
     
-You may need to enter \<control-c\> to exit the script.
+When the tests finish, you may need to enter \<control-c\> to exit the script.
 
 If you get this error:
 
@@ -60,6 +62,9 @@ If you get this error:
         INSTALL_FAILED_UPDATE_INCOMPATIBLE: Package com.google.oboe.tests.unittestrunner
         signatures do not match previously installed version; ignoring!
 
-then uninstall the app "UnitTestRunner" from the Android device.
+then uninstall the app "UnitTestRunner" from the Android device. Or try:
+
+    adb root
+    adb remount -R
 
 See `run_tests.sh` for more documentation
diff --git a/tests/UnitTestRunner/app/build.gradle b/tests/UnitTestRunner/app/build.gradle
index 58bf4aaa..ae2c3166 100644
--- a/tests/UnitTestRunner/app/build.gradle
+++ b/tests/UnitTestRunner/app/build.gradle
@@ -20,6 +20,7 @@ android {
             path file('../../CMakeLists.txt')
         }
     }
+    namespace 'com.google.oboe.tests.unittestrunner'
 }
 
 dependencies {
diff --git a/tests/UnitTestRunner/app/src/main/AndroidManifest.xml b/tests/UnitTestRunner/app/src/main/AndroidManifest.xml
index aad3df6b..97453e31 100644
--- a/tests/UnitTestRunner/app/src/main/AndroidManifest.xml
+++ b/tests/UnitTestRunner/app/src/main/AndroidManifest.xml
@@ -1,6 +1,5 @@
 <?xml version="1.0" encoding="utf-8"?>
-<manifest xmlns:android="http://schemas.android.com/apk/res/android"
-    package="com.google.oboe.tests.unittestrunner">
+<manifest xmlns:android="http://schemas.android.com/apk/res/android">
 
     <uses-permission android:name="android.permission.RECORD_AUDIO" />
     <application
diff --git a/tests/UnitTestRunner/build.gradle b/tests/UnitTestRunner/build.gradle
index 98a6f28d..4ce39f69 100644
--- a/tests/UnitTestRunner/build.gradle
+++ b/tests/UnitTestRunner/build.gradle
@@ -10,7 +10,7 @@ buildscript {
     }
 
     dependencies {
-        classpath 'com.android.tools.build:gradle:7.2.1'
+        classpath 'com.android.tools.build:gradle:8.5.1'
     }
 }
 
diff --git a/tests/UnitTestRunner/gradle.properties b/tests/UnitTestRunner/gradle.properties
index c73d2393..ce7a7fc1 100644
--- a/tests/UnitTestRunner/gradle.properties
+++ b/tests/UnitTestRunner/gradle.properties
@@ -17,3 +17,6 @@ org.gradle.jvmargs=-Xmx1536m
 android.useAndroidX=true
 # Automatically convert third-party libraries to use AndroidX
 android.enableJetifier=true
+android.defaults.buildfeatures.buildconfig=true
+android.nonTransitiveRClass=false
+android.nonFinalResIds=false
diff --git a/tests/UnitTestRunner/gradle/wrapper/gradle-wrapper.properties b/tests/UnitTestRunner/gradle/wrapper/gradle-wrapper.properties
index 1f10e877..528aad21 100644
--- a/tests/UnitTestRunner/gradle/wrapper/gradle-wrapper.properties
+++ b/tests/UnitTestRunner/gradle/wrapper/gradle-wrapper.properties
@@ -3,4 +3,4 @@ distributionBase=GRADLE_USER_HOME
 distributionPath=wrapper/dists
 zipStoreBase=GRADLE_USER_HOME
 zipStorePath=wrapper/dists
-distributionUrl=https\://services.gradle.org/distributions/gradle-7.3.3-all.zip
+distributionUrl=https\://services.gradle.org/distributions/gradle-8.7-all.zip
diff --git a/tests/testAudioClock.cpp b/tests/testAudioClock.cpp
new file mode 100644
index 00000000..cad8d74c
--- /dev/null
+++ b/tests/testAudioClock.cpp
@@ -0,0 +1,92 @@
+/*
+ * Copyright 2022 The Android Open Source Project
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
+/*
+ * Test FlowGraph
+ */
+
+#include "math.h"
+#include "stdio.h"
+
+#include <gtest/gtest.h>
+#include <oboe/Oboe.h>
+
+using namespace oboe;
+
+#define NANOS_PER_MICROSECOND    ((int64_t) 1000)
+
+constexpr int64_t kSleepTimeMicroSec = 50 * 1000;
+constexpr double kMaxLatenessMicroSec = 20 * 1000;
+
+TEST(TestAudioClock, GetNanosecondsMonotonic) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    usleep(kSleepTimeMicroSec);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
+
+TEST(TestAudioClock, GetNanosecondsRealtime) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    usleep(kSleepTimeMicroSec);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
+
+TEST(TestAudioClock, SleepUntilNanoTimeMonotonic) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    AudioClock::sleepUntilNanoTime(startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond, CLOCK_MONOTONIC);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
+
+TEST(TestAudioClock, SleepUntilNanoTimeRealtime) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    AudioClock::sleepUntilNanoTime(startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond, CLOCK_REALTIME);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
+
+TEST(TestAudioClock, SleepForNanosMonotonic) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    AudioClock::sleepForNanos(kSleepTimeMicroSec * kNanosPerMicrosecond, CLOCK_MONOTONIC);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_MONOTONIC);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
+
+TEST(TestAudioClock, SleepForNanosRealtime) {
+
+    int64_t startNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    AudioClock::sleepForNanos(kSleepTimeMicroSec * kNanosPerMicrosecond, CLOCK_REALTIME);
+    int64_t endNanos = AudioClock::getNanoseconds(CLOCK_REALTIME);
+    ASSERT_GE(endNanos, startNanos + kSleepTimeMicroSec * kNanosPerMicrosecond);
+    ASSERT_LT(endNanos, startNanos + ((kSleepTimeMicroSec + kMaxLatenessMicroSec)
+            * kNanosPerMicrosecond));
+}
diff --git a/tests/testFullDuplexStream.cpp b/tests/testFullDuplexStream.cpp
index b3b96f2a..b8b9688e 100644
--- a/tests/testFullDuplexStream.cpp
+++ b/tests/testFullDuplexStream.cpp
@@ -55,7 +55,7 @@ protected:
         mOutputBuilder.setFormat(AudioFormat::Float);
         mOutputBuilder.setDataCallback(this);
 
-        Result r = mOutputBuilder.openStream(&mOutputStream);
+        Result r = mOutputBuilder.openStream(mOutputStream);
         ASSERT_EQ(r, Result::OK) << "Failed to open output stream " << convertToText(r);
 
         mInputBuilder.setDirection(Direction::Input);
@@ -68,11 +68,11 @@ protected:
         mInputBuilder.setBufferCapacityInFrames(mOutputStream->getBufferCapacityInFrames() * 2);
         mInputBuilder.setSampleRate(mOutputStream->getSampleRate());
 
-        r = mInputBuilder.openStream(&mInputStream);
+        r = mInputBuilder.openStream(mInputStream);
         ASSERT_EQ(r, Result::OK) << "Failed to open input stream " << convertToText(r);
 
-        setInputStream(mInputStream);
-        setOutputStream(mOutputStream);
+        setSharedInputStream(mInputStream);
+        setSharedOutputStream(mOutputStream);
     }
 
     void startStream() {
@@ -88,10 +88,8 @@ protected:
     void closeStream() {
         Result r = mOutputStream->close();
         ASSERT_EQ(r, Result::OK) << "Failed to close output stream " << convertToText(r);
-        setOutputStream(nullptr);
         r = mInputStream->close();
         ASSERT_EQ(r, Result::OK) << "Failed to close input stream " << convertToText(r);
-        setInputStream(nullptr);
     }
 
     void checkXRuns() {
@@ -102,13 +100,13 @@ protected:
 
     void checkInputAndOutputBufferSizesMatch() {
         // Expect the large majority of callbacks to have the same sized input and output
-        EXPECT_GE(mGoodCallbackCount, mCallbackCount * 9 / 10);
+        EXPECT_GE(mGoodCallbackCount, mCallbackCount * 4 / 5);
     }
 
     AudioStreamBuilder mInputBuilder;
     AudioStreamBuilder mOutputBuilder;
-    AudioStream *mInputStream = nullptr;
-    AudioStream *mOutputStream = nullptr;
+    std::shared_ptr<AudioStream> mInputStream;
+    std::shared_ptr<AudioStream> mOutputStream;
     std::atomic<int32_t> mCallbackCount{0};
     std::atomic<int32_t> mGoodCallbackCount{0};
 };
diff --git a/tests/testReturnStop.cpp b/tests/testReturnStop.cpp
index 6708894b..25f6764a 100644
--- a/tests/testReturnStop.cpp
+++ b/tests/testReturnStop.cpp
@@ -54,13 +54,12 @@ protected:
     void TearDown() override;
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
 };
 
 void StreamReturnStop::TearDown() {
-    if (mStream != nullptr) {
+    if (mStream) {
         mStream->close();
-        mStream = nullptr;
     }
 }
 
@@ -78,8 +77,7 @@ TEST_P(StreamReturnStop, VerifyStreamReturnStop) {
     if (mBuilder.isAAudioRecommended()) {
         mBuilder.setAudioApi(audioApi);
     }
-    mStream = nullptr;
-    Result r = mBuilder.openStream(&mStream);
+    Result r = mBuilder.openStream(mStream);
     ASSERT_EQ(r, Result::OK) << "Failed to open stream. " << convertToText(r);
 
     // Start and stop several times.
diff --git a/tests/testReturnStopDeadlock.cpp b/tests/testReturnStopDeadlock.cpp
new file mode 100644
index 00000000..ec2277e9
--- /dev/null
+++ b/tests/testReturnStopDeadlock.cpp
@@ -0,0 +1,161 @@
+/*
+ * Copyright 2024 The Android Open Source Project
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
+#include <atomic>
+#include <tuple>
+
+#include <gtest/gtest.h>
+#include <oboe/Oboe.h>
+#include <thread>
+#include <future>
+
+// Test returning DataCallbackResult::Stop from a callback.
+using namespace oboe;
+
+// Test whether there is a deadlock when stopping streams.
+// See Issue #2059
+
+class TestReturnStopDeadlock  : public ::testing::Test {
+public:
+
+    void start(bool useOpenSL);
+    void stop();
+
+    int32_t getCycleCount() {
+        return mCycleCount.load();
+    }
+
+protected:
+    void TearDown() override;
+    
+private:
+
+    void cycleRapidly(bool useOpenSL);
+
+    class MyDataCallback : public oboe::AudioStreamDataCallback {    public:
+
+        MyDataCallback() {}
+
+        oboe::DataCallbackResult onAudioReady(
+                oboe::AudioStream *audioStream,
+                void *audioData,
+                int32_t numFrames) override;
+
+        std::atomic<bool> returnStop = false;
+        std::atomic<int32_t> callbackCount{0};
+    };
+
+    std::shared_ptr<oboe::AudioStream> mStream;
+    std::shared_ptr<MyDataCallback> mDataCallback;
+    std::atomic<int32_t> mCycleCount{0};
+    std::atomic<bool> mThreadEnabled{false};
+    std::thread mCycleThread;
+
+    static constexpr int kChannelCount = 1;
+    static constexpr int kMaxSleepMicros = 25000;
+};
+
+// start a thread to cycle through stream tests
+void TestReturnStopDeadlock::start(bool useOpenSL) {
+    mThreadEnabled = true;
+    mCycleCount = 0;
+    mCycleThread = std::thread([this, useOpenSL]() {
+        cycleRapidly(useOpenSL);
+    });
+}
+
+void TestReturnStopDeadlock::stop() {
+    mThreadEnabled = false;
+    // Terminate the thread with a timeout.
+    const int timeout = 1;
+    auto future = std::async(std::launch::async, &std::thread::join, &mCycleThread);
+    ASSERT_NE(future.wait_for(std::chrono::seconds(timeout)), std::future_status::timeout)
+        << " join() timed out! cycles = " << getCycleCount();
+}
+
+void TestReturnStopDeadlock::TearDown() {
+    if (mStream) {
+        mStream->close();
+    }
+}
+
+void TestReturnStopDeadlock::cycleRapidly(bool useOpenSL) {
+    while(mThreadEnabled) {
+        mCycleCount++;
+        mDataCallback = std::make_shared<MyDataCallback>();
+
+        AudioStreamBuilder builder;
+        oboe::Result result = builder.setFormat(oboe::AudioFormat::Float)
+                ->setAudioApi(useOpenSL ? oboe::AudioApi::OpenSLES : oboe::AudioApi::AAudio)
+                ->setPerformanceMode(oboe::PerformanceMode::LowLatency)
+                ->setChannelCount(kChannelCount)
+                ->setDataCallback(mDataCallback)
+                ->setUsage(oboe::Usage::Notification)
+                ->openStream(mStream);
+        ASSERT_EQ(result, oboe::Result::OK);
+
+        mStream->setDelayBeforeCloseMillis(0);
+
+        result = mStream->requestStart();
+        ASSERT_EQ(result, oboe::Result::OK);
+
+        // Sleep for some random time.
+        int countdown = 100;
+        while ((mDataCallback->callbackCount < 4) && (--countdown > 0)) {
+            int32_t durationMicros = (int32_t)(drand48() * kMaxSleepMicros);
+            usleep(durationMicros);
+        }
+        mDataCallback->returnStop = true;
+        result = mStream->close();
+        ASSERT_EQ(result, oboe::Result::OK);
+        mStream = nullptr;
+        ASSERT_GT(mDataCallback->callbackCount, 1) << " cycleCount = " << mCycleCount;
+    }
+}
+
+// Callback that returns Continue or Stop
+DataCallbackResult TestReturnStopDeadlock::MyDataCallback::onAudioReady(
+        AudioStream *audioStream,
+        void *audioData,
+        int32_t numFrames) {
+    float *floatData = (float *) audioData;
+    const int numSamples = numFrames * kChannelCount;
+    callbackCount++;
+
+    // Fill buffer with white noise.
+    for (int i = 0; i < numSamples; i++) {
+        floatData[i] = ((float) drand48() - 0.5f) * 2 * 0.1f;
+    }
+    usleep(500); // half a millisecond
+    if (returnStop) {
+        usleep(20 * 1000);
+        return DataCallbackResult::Stop;
+    } else {
+        return DataCallbackResult::Continue;
+    }
+}
+
+TEST_F(TestReturnStopDeadlock, RapidCycleAAudio){
+    start(false);
+    usleep(3000 * 1000);
+    stop();
+}
+
+TEST_F(TestReturnStopDeadlock, RapidCycleOpenSL){
+    start(true);
+    usleep(3000 * 1000);
+    stop();
+}
diff --git a/tests/testStreamClosedMethods.cpp b/tests/testStreamClosedMethods.cpp
index 02defa4d..62b08596 100644
--- a/tests/testStreamClosedMethods.cpp
+++ b/tests/testStreamClosedMethods.cpp
@@ -31,7 +31,7 @@ class StreamClosedReturnValues : public ::testing::Test {
 protected:
 
     bool openStream() {
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         return (r == Result::OK);
     }
@@ -89,7 +89,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream       *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
 
 };
 
diff --git a/tests/testStreamFramesProcessed.cpp b/tests/testStreamFramesProcessed.cpp
index daa9c3de..083db6a0 100644
--- a/tests/testStreamFramesProcessed.cpp
+++ b/tests/testStreamFramesProcessed.cpp
@@ -28,7 +28,7 @@ public:
     }
 };
 
-using StreamFramesProcessedParams = std::tuple<Direction, int32_t>;
+using StreamFramesProcessedParams = std::tuple<Direction, int32_t, bool>;
 
 class StreamFramesProcessed : public ::testing::Test,
                               public ::testing::WithParamInterface<StreamFramesProcessedParams> {
@@ -39,30 +39,32 @@ protected:
     static constexpr int PROCESS_TIME_SECONDS = 5;
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
 };
 
 void StreamFramesProcessed::TearDown() {
-    if (mStream != nullptr) {
+    if (mStream) {
         mStream->close();
-        mStream = nullptr;
     }
 }
 
 TEST_P(StreamFramesProcessed, VerifyFramesProcessed) {
     const Direction direction = std::get<0>(GetParam());
     const int32_t sampleRate = std::get<1>(GetParam());
+    const bool useOboeSampleRateConversion = std::get<2>(GetParam());
+
+    SampleRateConversionQuality srcQuality = useOboeSampleRateConversion ?
+            SampleRateConversionQuality::Medium : SampleRateConversionQuality::None;
 
     AudioStreamDataCallback *callback = new FramesProcessedCallback();
     mBuilder.setDirection(direction)
             ->setFormat(AudioFormat::I16)
             ->setSampleRate(sampleRate)
-            ->setSampleRateConversionQuality(SampleRateConversionQuality::Medium)
+            ->setSampleRateConversionQuality(srcQuality)
             ->setPerformanceMode(PerformanceMode::LowLatency)
             ->setSharingMode(SharingMode::Exclusive)
             ->setDataCallback(callback);
-    mStream = nullptr;
-    Result r = mBuilder.openStream(&mStream);
+    Result r = mBuilder.openStream(mStream);
     ASSERT_EQ(r, Result::OK) << "Failed to open stream." << convertToText(r);
 
     r = mStream->start();
@@ -81,11 +83,17 @@ INSTANTIATE_TEST_CASE_P(
         StreamFramesProcessedTest,
         StreamFramesProcessed,
         ::testing::Values(
-                StreamFramesProcessedParams({Direction::Output, 8000}),
-                StreamFramesProcessedParams({Direction::Output, 44100}),
-                StreamFramesProcessedParams({Direction::Output, 96000}),
-                StreamFramesProcessedParams({Direction::Input, 8000}),
-                StreamFramesProcessedParams({Direction::Input, 44100}),
-                StreamFramesProcessedParams({Direction::Input, 96000})
+                StreamFramesProcessedParams({Direction::Output, 8000, true}),
+                StreamFramesProcessedParams({Direction::Output, 44100, true}),
+                StreamFramesProcessedParams({Direction::Output, 96000, true}),
+                StreamFramesProcessedParams({Direction::Input, 8000, true}),
+                StreamFramesProcessedParams({Direction::Input, 44100, true}),
+                StreamFramesProcessedParams({Direction::Input, 96000, true}),
+                StreamFramesProcessedParams({Direction::Output, 8000, false}),
+                StreamFramesProcessedParams({Direction::Output, 44100, false}),
+                StreamFramesProcessedParams({Direction::Output, 96000, false}),
+                StreamFramesProcessedParams({Direction::Input, 8000, false}),
+                StreamFramesProcessedParams({Direction::Input, 44100, false}),
+                StreamFramesProcessedParams({Direction::Input, 96000, false})
                 )
         );
diff --git a/tests/testStreamOpen.cpp b/tests/testStreamOpen.cpp
index 1c6b97f9..869c7a2f 100644
--- a/tests/testStreamOpen.cpp
+++ b/tests/testStreamOpen.cpp
@@ -49,7 +49,7 @@ protected:
 
     bool openStream() {
         EXPECT_EQ(mStream, nullptr);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         EXPECT_EQ(0, openCount) << "Should start with a fresh object every time.";
         openCount++;
@@ -57,11 +57,10 @@ protected:
     }
 
     bool closeStream() {
-        if (mStream != nullptr){
+        if (mStream){
           Result r = mStream->close();
           EXPECT_EQ(r, Result::OK) << "Failed to close stream. " << convertToText(r);
           usleep(500 * 1000); // give previous stream time to settle
-          mStream = nullptr;
           return (r == Result::OK);
         } else {
           return true;
@@ -101,7 +100,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
     int32_t openCount = 0;
 
 };
@@ -145,6 +144,7 @@ TEST_F(StreamOpenOutput, ForOpenSLESDefaultChannelCountIsUsed){
 TEST_F(StreamOpenOutput, OutputForOpenSLESPerformanceModeShouldBeNone){
     // We will not get a LowLatency stream if we request 16000 Hz.
     mBuilder.setSampleRate(16000);
+    mBuilder.setSampleRateConversionQuality(SampleRateConversionQuality::None);
     mBuilder.setPerformanceMode(PerformanceMode::LowLatency);
     mBuilder.setDirection(Direction::Output);
     mBuilder.setAudioApi(AudioApi::OpenSLES);
@@ -156,6 +156,7 @@ TEST_F(StreamOpenOutput, OutputForOpenSLESPerformanceModeShouldBeNone){
 TEST_F(StreamOpenInput, InputForOpenSLESPerformanceModeShouldBeNone){
     // We will not get a LowLatency stream if we request 16000 Hz.
     mBuilder.setSampleRate(16000);
+    mBuilder.setSampleRateConversionQuality(SampleRateConversionQuality::None);
     mBuilder.setPerformanceMode(PerformanceMode::LowLatency);
     mBuilder.setDirection(Direction::Input);
     mBuilder.setAudioApi(AudioApi::OpenSLES);
@@ -168,7 +169,7 @@ TEST_F(StreamOpenOutput, ForOpenSlesIllegalFormatRejectedOutput) {
     mBuilder.setAudioApi(AudioApi::OpenSLES);
     mBuilder.setPerformanceMode(PerformanceMode::LowLatency);
     mBuilder.setFormat(static_cast<AudioFormat>(666));
-    Result r = mBuilder.openStream(&mStream);
+    Result r = mBuilder.openStream(mStream);
     EXPECT_NE(r, Result::OK) << "Should not open stream " << convertToText(r);
     if (mStream != nullptr) {
         mStream->close(); // just in case it accidentally opened
@@ -180,7 +181,7 @@ TEST_F(StreamOpenInput, ForOpenSlesIllegalFormatRejectedInput) {
     mBuilder.setPerformanceMode(PerformanceMode::LowLatency);
     mBuilder.setDirection(Direction::Input);
     mBuilder.setFormat(static_cast<AudioFormat>(666));
-    Result r = mBuilder.openStream(&mStream);
+    Result r = mBuilder.openStream(mStream);
     EXPECT_NE(r, Result::OK) << "Should not open stream " << convertToText(r);
     if (mStream != nullptr) {
         mStream->close(); // just in case it accidentally opened
@@ -282,7 +283,7 @@ TEST_F(StreamOpenInput, RecordingFormatFloatReturnsErrorBeforeMarshmallow){
     if (getSdkVersion() < __ANDROID_API_M__){
         mBuilder.setDirection(Direction::Input);
         mBuilder.setFormat(AudioFormat::Float);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         ASSERT_EQ(r, Result::ErrorInvalidFormat) << convertToText(r);
         ASSERT_TRUE(closeStream());
     }
@@ -335,7 +336,7 @@ TEST_F(StreamOpenOutput, PlaybackFormatFloatReturnsErrorBeforeLollipop){
     if (getSdkVersion() < __ANDROID_API_L__){
         mBuilder.setDirection(Direction::Output);
         mBuilder.setFormat(AudioFormat::Float);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         ASSERT_EQ(r, Result::ErrorInvalidFormat);
         ASSERT_TRUE(closeStream());
     }
@@ -574,7 +575,7 @@ TEST_F(StreamOpenOutput, OboeExtensions){
         ASSERT_EQ(OboeExtensions::setMMapEnabled(false), 0);
         ASSERT_FALSE(OboeExtensions::isMMapEnabled());
         ASSERT_TRUE(openStream());
-        EXPECT_FALSE(OboeExtensions::isMMapUsed(mStream));
+        EXPECT_FALSE(OboeExtensions::isMMapUsed(mStream.get()));
         ASSERT_TRUE(closeStream());
 
         ASSERT_EQ(OboeExtensions::setMMapEnabled(true), 0);
diff --git a/tests/testStreamStates.cpp b/tests/testStreamStates.cpp
index d6e403f2..6f33d2e2 100644
--- a/tests/testStreamStates.cpp
+++ b/tests/testStreamStates.cpp
@@ -35,7 +35,7 @@ protected:
     bool openStream(Direction direction) {
         usleep(100 * 1000);
         mBuilder.setDirection(direction);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         if (r != Result::OK)
             return false;
@@ -125,7 +125,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
     static constexpr int kTimeoutInNanos = 500 * kNanosPerMillisecond;
 
 };
diff --git a/tests/testStreamStop.cpp b/tests/testStreamStop.cpp
index ca7e3658..2e6e86a5 100644
--- a/tests/testStreamStop.cpp
+++ b/tests/testStreamStop.cpp
@@ -42,7 +42,7 @@ protected:
         mBuilder.setPerformanceMode(perfMode);
         mBuilder.setChannelCount(1);
         mBuilder.setFormat(AudioFormat::I16);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         if (r != Result::OK)
             return false;
@@ -53,7 +53,7 @@ protected:
     }
 
     bool openStream(AudioStreamBuilder &builder) {
-        Result r = builder.openStream(&mStream);
+        Result r = builder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         return (r == Result::OK);
     }
@@ -66,7 +66,7 @@ protected:
         EXPECT_EQ(r, Result::OK);
         EXPECT_EQ(next, StreamState::Started) << "next = " << convertToText(next);
 
-        AudioStream *str = mStream;
+        std::shared_ptr<AudioStream> str = mStream;
 
         int16_t buffer[kFramesToWrite] = {};
 
@@ -94,7 +94,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
     static constexpr int kTimeoutInNanos = 1000 * kNanosPerMillisecond;
     static constexpr int64_t kMicroSecondsPerSecond = 1000000;
     static constexpr int kFramesToWrite = 10000;
diff --git a/tests/testStreamWaitState.cpp b/tests/testStreamWaitState.cpp
index 71dd5c9d..bdf3a2f8 100644
--- a/tests/testStreamWaitState.cpp
+++ b/tests/testStreamWaitState.cpp
@@ -34,7 +34,7 @@ protected:
     bool openStream(Direction direction, PerformanceMode perfMode) {
         mBuilder.setDirection(direction);
         mBuilder.setPerformanceMode(perfMode);
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         if (r != Result::OK)
             return false;
@@ -45,7 +45,7 @@ protected:
     }
 
     bool openStream(AudioStreamBuilder &builder) {
-        Result r = builder.openStream(&mStream);
+        Result r = builder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         return (r == Result::OK);
     }
@@ -72,7 +72,8 @@ protected:
         EXPECT_EQ(r, Result::OK);
         EXPECT_EQ(next, StreamState::Started) << "next = " << convertToText(next);
 
-        AudioStream *str = mStream;
+        std::shared_ptr<AudioStream> str = mStream;
+
         std::thread stopper([str] {
             usleep(200 * 1000);
             str->requestStop();
@@ -97,7 +98,8 @@ protected:
         EXPECT_EQ(r, Result::OK);
         EXPECT_EQ(next, StreamState::Started) << "next = " << convertToText(next);
 
-        AudioStream *str = mStream;
+        std::shared_ptr<AudioStream> str = mStream;
+
         std::thread closer([str] {
             usleep(200 * 1000);
             str->close();
@@ -115,7 +117,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
     static constexpr int kTimeoutInNanos = 100 * kNanosPerMillisecond;
 
 };
diff --git a/tests/testXRunBehaviour.cpp b/tests/testXRunBehaviour.cpp
index c28946d6..9f370153 100644
--- a/tests/testXRunBehaviour.cpp
+++ b/tests/testXRunBehaviour.cpp
@@ -33,7 +33,7 @@ class XRunBehaviour : public ::testing::Test {
 protected:
 
     bool openStream() {
-        Result r = mBuilder.openStream(&mStream);
+        Result r = mBuilder.openStream(mStream);
         EXPECT_EQ(r, Result::OK) << "Failed to open stream " << convertToText(r);
         return (r == Result::OK);
     }
@@ -45,7 +45,7 @@ protected:
     }
 
     AudioStreamBuilder mBuilder;
-    AudioStream *mStream = nullptr;
+    std::shared_ptr<AudioStream> mStream;
 
 };
 
```

