```diff
diff --git a/common/Android.bp b/common/Android.bp
index cde85d0..6b571c9 100644
--- a/common/Android.bp
+++ b/common/Android.bp
@@ -20,6 +20,7 @@ cc_library {
         "EncodeHelpers.cpp",
         "FormatConverter.cpp",
         "Fourcc.cpp",
+        "H264.cpp",
         "H264NalParser.cpp",
         "HEVCNalParser.cpp",
         "NalParser.cpp",
diff --git a/common/FormatConverter.cpp b/common/FormatConverter.cpp
index cb1a049..15e59ed 100644
--- a/common/FormatConverter.cpp
+++ b/common/FormatConverter.cpp
@@ -3,6 +3,7 @@
 // found in the LICENSE file.
 
 //#define LOG_NDEBUG 0
+#define ATRACE_TAG ATRACE_TAG_VIDEO
 #define LOG_TAG "FormatConverter"
 
 #include <v4l2_codec2/common/FormatConverter.h>
@@ -19,6 +20,7 @@
 #include <libyuv.h>
 #include <ui/GraphicBuffer.h>
 #include <utils/Log.h>
+#include <utils/Trace.h>
 
 #include <v4l2_codec2/common/VideoTypes.h>  // for HalPixelFormat
 
@@ -176,6 +178,7 @@ c2_status_t FormatConverter::allocateBuffers(uint32_t count) {
 c2_status_t FormatConverter::convertBlock(uint64_t frameIndex,
                                           const C2ConstGraphicBlock& inputBlock,
                                           C2ConstGraphicBlock* convertedBlock) {
+    ATRACE_CALL();
     const C2GraphicView& inputView = inputBlock.map().get();
     C2PlanarLayout inputLayout = inputView.layout();
 
diff --git a/common/H264.cpp b/common/H264.cpp
new file mode 100644
index 0000000..bc969ed
--- /dev/null
+++ b/common/H264.cpp
@@ -0,0 +1,30 @@
+// Copyright 2024 The Chromium Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#include <v4l2_codec2/common/H264.h>
+
+#include <log/log.h>
+
+namespace android {
+
+uint32_t maxFramerateForLevelH264(C2Config::level_t level, const ui::Size& videoSize) {
+    uint32_t maxFramerate = std::numeric_limits<uint32_t>::max();
+
+    bool found = false;
+    for (const H264LevelLimits& limit : kH264Limits) {
+        if (limit.level != level) continue;
+
+        uint64_t frameSizeMB =
+                static_cast<uint64_t>((videoSize.width + 15) / 16) * ((videoSize.height + 15) / 16);
+        maxFramerate = limit.maxMBPS / frameSizeMB;
+        found = true;
+        break;
+    }
+
+    if (!found) ALOGW("%s - failed to find matching H264 level=%d", __func__, level);
+
+    return maxFramerate;
+}
+
+}  // namespace android
diff --git a/common/include/v4l2_codec2/common/H264.h b/common/include/v4l2_codec2/common/H264.h
new file mode 100644
index 0000000..18770ef
--- /dev/null
+++ b/common/include/v4l2_codec2/common/H264.h
@@ -0,0 +1,51 @@
+// Copyright 2024 The Chromium Authors. All rights reserved.
+// Use of this source code is governed by a BSD-style license that can be
+// found in the LICENSE file.
+
+#ifndef ANDROID_V4L2_CODEC2_COMMON_H264_H
+#define ANDROID_V4L2_CODEC2_COMMON_H264_H
+
+#include <C2Config.h>
+
+#include <ui/Size.h>
+
+namespace android {
+
+// Table A-1 in spec
+struct H264LevelLimits {
+    C2Config::level_t level;
+    float maxMBPS;   // max macroblock processing rate in macroblocks per second
+    uint64_t maxFS;  // max frame size in macroblocks
+    uint32_t maxBR;  // max video bitrate in bits per second
+};
+
+constexpr H264LevelLimits kH264Limits[] = {
+        {C2Config::LEVEL_AVC_1, 1485, 99, 64000},
+        {C2Config::LEVEL_AVC_1B, 1485, 99, 128000},
+        {C2Config::LEVEL_AVC_1_1, 3000, 396, 192000},
+        {C2Config::LEVEL_AVC_1_2, 6000, 396, 384000},
+        {C2Config::LEVEL_AVC_1_3, 11880, 396, 768000},
+        {C2Config::LEVEL_AVC_2, 11880, 396, 2000000},
+        {C2Config::LEVEL_AVC_2_1, 19800, 792, 4000000},
+        {C2Config::LEVEL_AVC_2_2, 20250, 1620, 4000000},
+        {C2Config::LEVEL_AVC_3, 40500, 1620, 10000000},
+        {C2Config::LEVEL_AVC_3_1, 108000, 3600, 14000000},
+        {C2Config::LEVEL_AVC_3_2, 216000, 5120, 20000000},
+        {C2Config::LEVEL_AVC_4, 245760, 8192, 20000000},
+        {C2Config::LEVEL_AVC_4_1, 245760, 8192, 50000000},
+        {C2Config::LEVEL_AVC_4_2, 522240, 8704, 50000000},
+        {C2Config::LEVEL_AVC_5, 589824, 22080, 135000000},
+        {C2Config::LEVEL_AVC_5_1, 983040, 36864, 240000000},
+        {C2Config::LEVEL_AVC_5_2, 2073600, 36864, 240000000},
+};
+
+uint32_t maxFramerateForLevelH264(C2Config::level_t level, const ui::Size& videoSize);
+
+inline bool isH264Profile(C2Config::profile_t profile) {
+    return (profile >= C2Config::PROFILE_AVC_BASELINE &&
+            profile <= C2Config::PROFILE_AVC_ENHANCED_MULTIVIEW_DEPTH_HIGH);
+}
+
+}  // namespace android
+
+#endif  // ANDROID_V4L2_CODEC2_COMMON_H264_H
diff --git a/components/EncodeComponent.cpp b/components/EncodeComponent.cpp
index 0c7d044..fc542fa 100644
--- a/components/EncodeComponent.cpp
+++ b/components/EncodeComponent.cpp
@@ -3,6 +3,7 @@
 // found in the LICENSE file
 
 //#define LOG_NDEBUG 0
+#define ATRACE_TAG ATRACE_TAG_VIDEO
 #define LOG_TAG "EncodeComponent"
 
 #include <v4l2_codec2/components/EncodeComponent.h>
@@ -22,9 +23,11 @@
 #include <media/stagefright/MediaDefs.h>
 #include <ui/GraphicBuffer.h>
 #include <ui/Size.h>
+#include <utils/Trace.h>
 
 #include <v4l2_codec2/common/EncodeHelpers.h>
 #include <v4l2_codec2/common/FormatConverter.h>
+#include <v4l2_codec2/common/H264.h>
 #include <v4l2_codec2/components/BitstreamBuffer.h>
 #include <v4l2_codec2/components/EncodeInterface.h>
 #include <v4l2_codec2/components/VideoEncoder.h>
@@ -384,6 +387,7 @@ std::shared_ptr<C2ComponentInterface> EncodeComponent::intf() {
 }
 
 void EncodeComponent::startTask(bool* success, ::base::WaitableEvent* done) {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
 
@@ -392,6 +396,7 @@ void EncodeComponent::startTask(bool* success, ::base::WaitableEvent* done) {
 }
 
 void EncodeComponent::stopTask(::base::WaitableEvent* done) {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
 
@@ -412,6 +417,7 @@ void EncodeComponent::stopTask(::base::WaitableEvent* done) {
 }
 
 void EncodeComponent::queueTask(std::unique_ptr<C2Work> work) {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
     ALOG_ASSERT(mEncoder);
@@ -594,6 +600,7 @@ void EncodeComponent::onDrainDone(bool success) {
 
 void EncodeComponent::flushTask(::base::WaitableEvent* done,
                                 std::list<std::unique_ptr<C2Work>>* const flushedWork) {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
 
@@ -621,6 +628,7 @@ void EncodeComponent::setListenerTask(const std::shared_ptr<Listener>& listener,
 }
 
 bool EncodeComponent::updateEncodingParameters() {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
 
@@ -679,10 +687,18 @@ bool EncodeComponent::updateEncodingParameters() {
         }
     }
 
+    C2Config::profile_t outputProfile = mInterface->getOutputProfile();
+    if (isH264Profile(outputProfile)) {
+        C2Config::level_t outputLevel = mInterface->getOutputLevel();
+        ui::Size inputSize = mInterface->getInputVisibleSize();
+        mMaxFramerate = maxFramerateForLevelH264(outputLevel, inputSize);
+    }
+
     return true;
 }
 
 bool EncodeComponent::encode(C2ConstGraphicBlock block, uint64_t index, int64_t timestamp) {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
     ALOG_ASSERT(mEncoder);
@@ -711,6 +727,18 @@ bool EncodeComponent::encode(C2ConstGraphicBlock block, uint64_t index, int64_t
         int64_t newFramerate = std::max(
                 static_cast<int64_t>(std::round(1000000.0 / (timestamp - *mLastFrameTime))),
                 static_cast<int64_t>(1LL));
+        // Clients using input surface may exceed the maximum allowed framerate for the given
+        // profile. One of such examples is android.media.codec.cts.MediaCodecTest#testAbruptStop.
+        // To mitigate that, value is clamped to the maximum framerate for the given level and
+        // current frame size.
+        // See: b/362902868
+        if (newFramerate > mMaxFramerate) {
+            ALOGW("Frames are coming too fast - new framerate (%" PRIi64
+                  ") would exceed the maximum value (%" PRIu32 ")",
+                  newFramerate, mMaxFramerate);
+            newFramerate = mMaxFramerate;
+        }
+
         if (abs(mFramerate - newFramerate) > kMaxFramerateDiff) {
             ALOGV("Adjusting framerate to %" PRId64 " based on frame timestamps", newFramerate);
             mInterface->setFramerate(static_cast<uint32_t>(newFramerate));
@@ -740,6 +768,7 @@ bool EncodeComponent::encode(C2ConstGraphicBlock block, uint64_t index, int64_t
 }
 
 void EncodeComponent::flush() {
+    ATRACE_CALL();
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mEncoderTaskRunner->RunsTasksInCurrentSequence());
 
@@ -771,6 +800,7 @@ void EncodeComponent::flush() {
 }
 
 void EncodeComponent::fetchOutputBlock(uint32_t size, std::unique_ptr<BitstreamBuffer>* buffer) {
+    ATRACE_CALL();
     ALOGV("Fetching linear block (size: %u)", size);
     std::shared_ptr<C2LinearBlock> block;
     c2_status_t status = mOutputBlockPool->fetchLinearBlock(
@@ -954,6 +984,7 @@ bool EncodeComponent::isWorkDone(const C2Work& work) const {
 }
 
 void EncodeComponent::reportWork(std::unique_ptr<C2Work> work) {
+    ATRACE_CALL();
     ALOG_ASSERT(work);
     ALOGV("%s(): Reporting work item as finished (index: %llu, timestamp: %llu)", __func__,
           work->input.ordinal.frameIndex.peekull(), work->input.ordinal.timestamp.peekull());
diff --git a/components/EncodeInterface.cpp b/components/EncodeInterface.cpp
index 9d7d81f..12152e6 100644
--- a/components/EncodeInterface.cpp
+++ b/components/EncodeInterface.cpp
@@ -17,6 +17,7 @@
 #include <utils/Log.h>
 
 #include <v4l2_codec2/common/Common.h>
+#include <v4l2_codec2/common/H264.h>
 #include <v4l2_codec2/common/VideoTypes.h>
 
 using android::hardware::graphics::common::V1_0::BufferUsage;
@@ -65,33 +66,6 @@ C2R EncodeInterface::H264ProfileLevelSetter(bool /*mayBlock*/,
         }
     }
 
-    // Table A-1 in spec
-    struct LevelLimits {
-        C2Config::level_t level;
-        float maxMBPS;   // max macroblock processing rate in macroblocks per second
-        uint64_t maxFS;  // max frame size in macroblocks
-        uint32_t maxBR;  // max video bitrate in bits per second
-    };
-    constexpr LevelLimits kLimits[] = {
-            {C2Config::LEVEL_AVC_1, 1485, 99, 64000},
-            {C2Config::LEVEL_AVC_1B, 1485, 99, 128000},
-            {C2Config::LEVEL_AVC_1_1, 3000, 396, 192000},
-            {C2Config::LEVEL_AVC_1_2, 6000, 396, 384000},
-            {C2Config::LEVEL_AVC_1_3, 11880, 396, 768000},
-            {C2Config::LEVEL_AVC_2, 11880, 396, 2000000},
-            {C2Config::LEVEL_AVC_2_1, 19800, 792, 4000000},
-            {C2Config::LEVEL_AVC_2_2, 20250, 1620, 4000000},
-            {C2Config::LEVEL_AVC_3, 40500, 1620, 10000000},
-            {C2Config::LEVEL_AVC_3_1, 108000, 3600, 14000000},
-            {C2Config::LEVEL_AVC_3_2, 216000, 5120, 20000000},
-            {C2Config::LEVEL_AVC_4, 245760, 8192, 20000000},
-            {C2Config::LEVEL_AVC_4_1, 245760, 8192, 50000000},
-            {C2Config::LEVEL_AVC_4_2, 522240, 8704, 50000000},
-            {C2Config::LEVEL_AVC_5, 589824, 22080, 135000000},
-            {C2Config::LEVEL_AVC_5_1, 983040, 36864, 240000000},
-            {C2Config::LEVEL_AVC_5_2, 2073600, 36864, 240000000},
-    };
-
     uint64_t targetFS =
             static_cast<uint64_t>((videoSize.v.width + 15) / 16) * ((videoSize.v.height + 15) / 16);
     float targetMBPS = static_cast<float>(targetFS) * frameRate.v.value;
@@ -107,7 +81,7 @@ C2R EncodeInterface::H264ProfileLevelSetter(bool /*mayBlock*/,
 
     bool found = false;
     bool needsUpdate = !info.F(info.v.level).supportsAtAll(info.v.level);
-    for (const LevelLimits& limit : kLimits) {
+    for (const H264LevelLimits& limit : kH264Limits) {
         if (!info.F(info.v.level).supportsAtAll(limit.level)) {
             continue;
         }
diff --git a/components/include/v4l2_codec2/components/EncodeComponent.h b/components/include/v4l2_codec2/components/EncodeComponent.h
index 81c8c6d..2d40dff 100644
--- a/components/include/v4l2_codec2/components/EncodeComponent.h
+++ b/components/include/v4l2_codec2/components/EncodeComponent.h
@@ -6,6 +6,7 @@
 #define ANDROID_V4L2_CODEC2_COMPONENTS_ENCODE_COMPONENT_H
 
 #include <atomic>
+#include <limits>
 #include <memory>
 #include <optional>
 #include <unordered_map>
@@ -164,6 +165,8 @@ protected:
     C2Config::bitrate_mode_t mBitrateMode = C2Config::BITRATE_CONST;
     // The framerate currently configured on the v4l2 device.
     uint32_t mFramerate = 0;
+    // Maximum valid framerate for current output level and input frame size.
+    uint32_t mMaxFramerate = std::numeric_limits<uint32_t>::max();
     // The timestamp of the last frame encoded, used to dynamically adjust the framerate.
     std::optional<int64_t> mLastFrameTime;
 
diff --git a/v4l2/V4L2EncodeComponent.cpp b/v4l2/V4L2EncodeComponent.cpp
index 6d8f037..e3b9b14 100644
--- a/v4l2/V4L2EncodeComponent.cpp
+++ b/v4l2/V4L2EncodeComponent.cpp
@@ -11,21 +11,13 @@
 
 #include <cutils/properties.h>
 
+#include <v4l2_codec2/common/H264.h>
 #include <v4l2_codec2/components/BitstreamBuffer.h>
 #include <v4l2_codec2/components/EncodeInterface.h>
 #include <v4l2_codec2/v4l2/V4L2Encoder.h>
 
 namespace android {
 
-namespace {
-
-// Check whether the specified |profile| is an H.264 profile.
-bool IsH264Profile(C2Config::profile_t profile) {
-    return (profile >= C2Config::PROFILE_AVC_BASELINE &&
-            profile <= C2Config::PROFILE_AVC_ENHANCED_MULTIVIEW_DEPTH_HIGH);
-}
-}  // namespace
-
 // static
 std::atomic<int32_t> V4L2EncodeComponent::sConcurrentInstances = 0;
 
@@ -74,10 +66,10 @@ bool V4L2EncodeComponent::initializeEncoder() {
     C2Config::profile_t outputProfile = mInterface->getOutputProfile();
 
     // CSD only needs to be extracted when using an H.264 profile.
-    mExtractCSD = IsH264Profile(outputProfile);
+    mExtractCSD = isH264Profile(outputProfile);
 
     std::optional<uint8_t> h264Level;
-    if (IsH264Profile(outputProfile)) {
+    if (isH264Profile(outputProfile)) {
         h264Level = c2LevelToV4L2Level(mInterface->getOutputLevel());
     }
 
@@ -120,4 +112,4 @@ bool V4L2EncodeComponent::initializeEncoder() {
     return true;
 }
 
-}  // namespace android
\ No newline at end of file
+}  // namespace android
```

