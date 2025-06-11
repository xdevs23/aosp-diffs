```diff
diff --git a/OWNERS b/OWNERS
index 1ca37c4..b5bf037 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,8 +1,5 @@
-# Default owners are top 3 active developers of the past 1 or 2 years
-# or people with more than 10 commits last year.
-# Please update this list if you find better owner candidates.
-mwojtas@google.com
-bgrzesik@google.com
-mikrawczyk@google.com
-zyta@google.com
-acourbot@google.com
+adelva@google.com
+
+# Note that AOSP _is_ the upstream for this project,
+# so the janitors are not generally useful.
+include platform/system/core:/janitors/OWNERS #{LAST_RESORT_SUGGESTION}
diff --git a/v4l2/V4L2Decoder.cpp b/v4l2/V4L2Decoder.cpp
index d0d862d..182c196 100644
--- a/v4l2/V4L2Decoder.cpp
+++ b/v4l2/V4L2Decoder.cpp
@@ -144,7 +144,7 @@ bool V4L2Decoder::start(const VideoCodec& codec, const size_t inputBufferSize,
         return false;
     }
 
-    if (!sendV4L2DecoderCmd(false)) {
+    if (!tryV4L2DecoderCmd(false)) {
         ALOGE("Device does not support flushing (V4L2_DEC_CMD_STOP)");
         return false;
     }
@@ -983,6 +983,20 @@ bool V4L2Decoder::sendV4L2DecoderCmd(bool start) {
     return true;
 }
 
+bool V4L2Decoder::tryV4L2DecoderCmd(bool start) {
+    ALOGV("%s(start=%d)", __func__, start);
+    ALOG_ASSERT(mTaskRunner->RunsTasksInCurrentSequence());
+
+    struct v4l2_decoder_cmd cmd;
+    memset(&cmd, 0, sizeof(cmd));
+    cmd.cmd = start ? V4L2_DEC_CMD_START : V4L2_DEC_CMD_STOP;
+    if (mDevice->ioctl(VIDIOC_TRY_DECODER_CMD, &cmd) != 0) {
+        return false;
+    }
+
+    return true;
+}
+
 void V4L2Decoder::onError() {
     ALOGV("%s()", __func__);
     ALOG_ASSERT(mTaskRunner->RunsTasksInCurrentSequence());
diff --git a/v4l2/include/v4l2_codec2/v4l2/V4L2Decoder.h b/v4l2/include/v4l2_codec2/v4l2/V4L2Decoder.h
index e569c1c..e537f0c 100644
--- a/v4l2/include/v4l2_codec2/v4l2/V4L2Decoder.h
+++ b/v4l2/include/v4l2_codec2/v4l2/V4L2Decoder.h
@@ -96,6 +96,7 @@ private:
     std::optional<struct v4l2_format> getFormatInfo();
     Rect getVisibleRect(const ui::Size& codedSize);
     bool sendV4L2DecoderCmd(bool start);
+    bool tryV4L2DecoderCmd(bool start);
 
     void setState(State newState);
     void onError();
```

