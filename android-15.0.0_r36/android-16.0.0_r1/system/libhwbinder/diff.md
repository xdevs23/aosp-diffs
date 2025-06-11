```diff
diff --git a/Android.bp b/Android.bp
index b7aff7c..9985a91 100644
--- a/Android.bp
+++ b/Android.bp
@@ -133,7 +133,7 @@ cc_library_static {
     apex_available: [
         "//apex_available:platform",
         "com.android.neuralnetworks",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.media",
         "com.android.media.swcodec",
         "com.android.nfcservices",
diff --git a/ProcessState.cpp b/ProcessState.cpp
index d02c3c0..4b2f4fc 100644
--- a/ProcessState.cpp
+++ b/ProcessState.cpp
@@ -107,7 +107,8 @@ sp<ProcessState> ProcessState::init(size_t mmapSize, bool requireMmapSize) {
 void ProcessState::startThreadPool()
 {
     if (!isHwbinderSupportedBlocking()) {
-        ALOGW("HwBinder is not supported on this device but this process is calling startThreadPool");
+        ALOGW("HwBinder is not supported on this device. Not starting threadpool.");
+        return;
     }
     AutoMutex _l(mLock);
     if (!mThreadPoolStarted) {
diff --git a/vts/OWNERS b/vts/OWNERS
index 6a26ae7..9ff5d87 100644
--- a/vts/OWNERS
+++ b/vts/OWNERS
@@ -1,2 +1 @@
-yim@google.com
 zhuoyao@google.com
```

