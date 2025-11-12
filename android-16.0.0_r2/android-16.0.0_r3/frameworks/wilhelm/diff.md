```diff
diff --git a/OWNERS b/OWNERS
index 03ee79a..9a86d14 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,3 +1,3 @@
 # TODO: add more owners
 elaurent@google.com
-philburk@google.com
+jmtrivi@google.com
\ No newline at end of file
diff --git a/src/Android.bp b/src/Android.bp
index 67a31ea..8e748d3 100644
--- a/src/Android.bp
+++ b/src/Android.bp
@@ -10,7 +10,6 @@ cc_library_static {
     name: "libOpenSLESUT",
 
     srcs: [
-        "assert.cpp",
         "ut/OpenSLESUT.c",
         "ut/slesutResult.c",
     ],
@@ -53,7 +52,6 @@ cc_library_static {
     ],
 
     srcs: [
-        "assert.cpp",
         "MPH_to.c",
         "handlers.c",
     ],
@@ -112,7 +110,6 @@ cc_library_shared {
 
     srcs: [
         "OpenSLES_IID.cpp",
-        "assert.cpp",
         "classes.cpp",
         "data.cpp",
         "devices.cpp",
@@ -260,7 +257,6 @@ cc_library_shared {
     srcs: [
         "sl_entry.cpp",
         "sl_iid.cpp",
-        "assert.cpp",
     ],
     include_dirs: [
         "frameworks/native/include/media/openmax",
@@ -293,7 +289,6 @@ cc_library_shared {
     srcs: [
         "xa_entry.cpp",
         "xa_iid.cpp",
-        "assert.cpp",
     ],
     include_dirs: [
         "frameworks/native/include/media/openmax",
diff --git a/src/android/AacBqToPcmCbRenderer.cpp b/src/android/AacBqToPcmCbRenderer.cpp
index 233978e..4076091 100644
--- a/src/android/AacBqToPcmCbRenderer.cpp
+++ b/src/android/AacBqToPcmCbRenderer.cpp
@@ -67,7 +67,7 @@ static size_t getAdtsFrameSize(const uint8_t *data, off64_t offset, size_t size)
         return 0;
     }
 
-    SL_LOGV("AacBqToPcmCbRenderer::getAdtsFrameSize() returns %u", frameSize);
+    SL_LOGV("AacBqToPcmCbRenderer::getAdtsFrameSize() returns %ld", frameSize);
 
     return frameSize;
 }
diff --git a/src/android/BufferQueueSource.cpp b/src/android/BufferQueueSource.cpp
index 66509b9..b37b616 100644
--- a/src/android/BufferQueueSource.cpp
+++ b/src/android/BufferQueueSource.cpp
@@ -55,7 +55,7 @@ status_t BufferQueueSource::initCheck() const {
 }
 
 ssize_t BufferQueueSource::readAt(off64_t offset, void *data, size_t size) {
-    SL_LOGD("BufferQueueSource::readAt(offset=%lld, data=%p, size=%d)", offset, data, size);
+    SL_LOGD("BufferQueueSource::readAt(offset=%ld, data=%p, size=%zu)", offset, data, size);
 
     if (mEosReached) {
         // once EOS has been received from the buffer queue, you can't read anymore
diff --git a/src/android/android_GenericPlayer.cpp b/src/android/android_GenericPlayer.cpp
index b3afc1b..6f60910 100644
--- a/src/android/android_GenericPlayer.cpp
+++ b/src/android/android_GenericPlayer.cpp
@@ -99,7 +99,7 @@ void GenericPlayer::setDataSource(const char *uri) {
 
 
 void GenericPlayer::setDataSource(int fd, int64_t offset, int64_t length, bool closeAfterUse) {
-    SL_LOGV("GenericPlayer::setDataSource(fd=%d, offset=%lld, length=%lld, closeAfterUse=%s)", fd,
+    SL_LOGV("GenericPlayer::setDataSource(fd=%d, offset=%ld, length=%ld, closeAfterUse=%s)", fd,
             offset, length, closeAfterUse ? "true" : "false");
     resetDataLocator();
 
@@ -166,7 +166,7 @@ void GenericPlayer::stop() {
 
 
 void GenericPlayer::seek(int64_t timeMsec) {
-    SL_LOGV("GenericPlayer::seek %lld", timeMsec);
+    SL_LOGV("GenericPlayer::seek %ld", timeMsec);
     if (timeMsec < 0 && timeMsec != ANDROID_UNKNOWN_TIME) {
         SL_LOGE("GenericPlayer::seek error, can't seek to negative time %" PRId64 "ms", timeMsec);
         return;
diff --git a/src/android/util/AacAdtsExtractor.cpp b/src/android/util/AacAdtsExtractor.cpp
index 383f616..cac8463 100644
--- a/src/android/util/AacAdtsExtractor.cpp
+++ b/src/android/util/AacAdtsExtractor.cpp
@@ -242,7 +242,7 @@ status_t AacAdtsSource::read(
     }
 
     size_t frameSize, frameSizeWithoutHeader;
-    SL_LOGV("AacAdtsSource::read() offset=%lld", mOffset);
+    SL_LOGV("AacAdtsSource::read() offset=%ld", mOffset);
     if ((frameSize = getFrameSize(mDataSource, mOffset)) == 0) {
         // EOS is normal, not an error
         SL_LOGV("AacAdtsSource::read() returns EOS");
diff --git a/src/assert.cpp b/src/assert.cpp
deleted file mode 100644
index 0f88e59..0000000
--- a/src/assert.cpp
+++ /dev/null
@@ -1,37 +0,0 @@
-/*
- * Copyright (C) 2011 The Android Open Source Project
- *
- * Licensed under the Apache License, Version 2.0 (the "License");
- * you may not use this file except in compliance with the License.
- * You may obtain a copy of the License at
- *
- *      http://www.apache.org/licenses/LICENSE-2.0
- *
- * Unless required by applicable law or agreed to in writing, software
- * distributed under the License is distributed on an "AS IS" BASIS,
- * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
- * See the License for the specific language governing permissions and
- * limitations under the License.
- */
-
-// Replace bionic/libc/stdlib/assert.c which logs to stderr with our version which does LOGF.
-// To be effective, add CFLAGS += -UNDEBUG and explicitly link in assert.c in all build modules.
-
-#include <utils/Log.h>
-
-#pragma GCC visibility push(default)
-
-void __assert(const char *file, int line, const char *failedexpr)
-{
-    LOG_ALWAYS_FATAL("assertion \"%s\" failed: file \"%s\", line %d", failedexpr, file, line);
-    // not reached
-}
-
-void __assert2(const char *file, int line, const char *func, const char *failedexpr)
-{
-    LOG_ALWAYS_FATAL("assertion \"%s\" failed: file \"%s\", line %d, function \"%s\"",
-            failedexpr, file, line, func);
-    // not reached
-}
-
-#pragma GCC visibility pop
diff --git a/src/libOpenSLES.map.txt b/src/libOpenSLES.map.txt
index b70228f..2f9f43f 100644
--- a/src/libOpenSLES.map.txt
+++ b/src/libOpenSLES.map.txt
@@ -6,15 +6,15 @@ LIBOPENSLES {
     SL_IID_3DLOCATION; # var
     SL_IID_3DMACROSCOPIC; # var
     SL_IID_3DSOURCE; # var
-    SL_IID_ANDROIDACOUSTICECHOCANCELLATION; # var introduced=21
-    SL_IID_ANDROIDAUTOMATICGAINCONTROL; # var introduced=21
-    SL_IID_ANDROIDBUFFERQUEUESOURCE; # var introduced-arm=14 introduced-arm64=21 introduced-mips=14 introduced-mips64=21 introduced-x86=14 introduced-x86_64=21
+    SL_IID_ANDROIDACOUSTICECHOCANCELLATION; # var
+    SL_IID_ANDROIDAUTOMATICGAINCONTROL; # var
+    SL_IID_ANDROIDBUFFERQUEUESOURCE; # var
     SL_IID_ANDROIDCONFIGURATION; # var
     SL_IID_ANDROIDEFFECT; # var
     SL_IID_ANDROIDEFFECTCAPABILITIES; # var
     SL_IID_ANDROIDEFFECTSEND; # var
     SL_IID_ANDROIDSIMPLEBUFFERQUEUE; # var
-    SL_IID_ANDROIDNOISESUPPRESSION; # var introduced=21
+    SL_IID_ANDROIDNOISESUPPRESSION; # var
     SL_IID_AUDIODECODERCAPABILITIES; # var
     SL_IID_AUDIOENCODER; # var
     SL_IID_AUDIOENCODERCAPABILITIES; # var
```

