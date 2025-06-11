```diff
diff --git a/Android.bp b/Android.bp
index 67d68686..525533b3 100644
--- a/Android.bp
+++ b/Android.bp
@@ -75,10 +75,15 @@ cc_library_headers {
                 "include_vendor",
             ],
         },
+        host: {
+            export_include_dirs: [
+                "include_vendor", // for tests
+            ],
+        },
     },
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.media",
         "com.android.media.swcodec",
     ],
diff --git a/METADATA b/METADATA
deleted file mode 100644
index d97975ca..00000000
--- a/METADATA
+++ /dev/null
@@ -1,3 +0,0 @@
-third_party {
-  license_type: NOTICE
-}
diff --git a/OWNERS b/OWNERS
index 53e5f73f..98ec1622 100644
--- a/OWNERS
+++ b/OWNERS
@@ -1,4 +1,3 @@
-zachoverflow@google.com
 elaurent@google.com
 jpawlowski@google.com
 malchev@google.com
diff --git a/modules/sensors/OWNERS b/modules/sensors/OWNERS
index 7347ac74..4929b3fc 100644
--- a/modules/sensors/OWNERS
+++ b/modules/sensors/OWNERS
@@ -1 +1 @@
-bduddie@google.com
+include platform/frameworks/native:/services/sensorservice/OWNERS
\ No newline at end of file
diff --git a/modules/sensors/dynamic_sensor/ConnectionDetector.cpp b/modules/sensors/dynamic_sensor/ConnectionDetector.cpp
index 99dab5b0..1df002c3 100644
--- a/modules/sensors/dynamic_sensor/ConnectionDetector.cpp
+++ b/modules/sensors/dynamic_sensor/ConnectionDetector.cpp
@@ -47,7 +47,11 @@ SocketConnectionDetector::SocketConnectionDetector(BaseDynamicSensorDaemon *d, i
         }
     };
 
-    ::bind(mListenFd, (struct sockaddr*)&serverAddress, sizeof(serverAddress));
+    if (::bind(mListenFd, (struct sockaddr*)&serverAddress, sizeof(serverAddress)) != NO_ERROR) {
+        ALOGE("Cannot bind to port %d", port);
+        mListenFd = -1;
+        return;
+    }
     if (::listen(mListenFd, 0) != NO_ERROR) {
         ALOGE("Cannot listen to port %d", port);
         mListenFd = -1;
@@ -196,12 +200,12 @@ void FileConnectionDetector::handleInotifyData(ssize_t len, const char *data) {
 bool FileConnectionDetector::readInotifyData() {
     union {
         struct inotify_event ev;
-        char raw[sizeof(inotify_event) + NAME_MAX + 1];
+        char raw[sizeof(inotify_event) + NAME_MAX + 1] = {0};
     } buffer;
 
     bool ret = true;
     while (true) {
-        ssize_t len = ::read(mInotifyFd, &buffer, sizeof(buffer));
+        ssize_t len = ::read(mInotifyFd, &buffer, sizeof(buffer) - sizeof(char));
         if (len == -1 && errno == EAGAIN) {
             // no more data
             break;
diff --git a/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp b/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
index efac5e95..414a71d7 100644
--- a/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
+++ b/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
@@ -22,6 +22,7 @@
 
 #include <utils/Log.h>
 #include <utils/SystemClock.h>
+#include <cutils/properties.h>
 
 #include <cassert>
 
@@ -41,7 +42,10 @@ DynamicSensorManager::DynamicSensorManager(
         mHandleRange(handleBase, handleMax),
         mCallback(callback),
         mFifo(callback ? 0 : kFifoSize),
-        mNextHandle(handleBase+1) {
+        mNextHandle(handleBase+1),
+        kSensorOpTimeout(
+            std::chrono::milliseconds((uint32_t)property_get_int32(
+            "vendor.sensors.dynamic_sensor_op_timeout_ms", 1600))) {
     assert(handleBase > 0 && handleMax > handleBase + 1); // handleBase is reserved
 
     mMetaSensor = (const sensor_t) {
diff --git a/modules/sensors/dynamic_sensor/DynamicSensorManager.h b/modules/sensors/dynamic_sensor/DynamicSensorManager.h
index 2cae1208..7f9bc752 100644
--- a/modules/sensors/dynamic_sensor/DynamicSensorManager.h
+++ b/modules/sensors/dynamic_sensor/DynamicSensorManager.h
@@ -128,8 +128,7 @@ private:
     // Sensor operation queue. Calls to the sensor HAL should complete within ~1
     // second, but to permit delayed replies due to sniff mode, etc., we use a
     // slightly longer timeout here.
-    static constexpr std::chrono::milliseconds
-            kSensorOpTimeout = std::chrono::milliseconds(1600);
+    const std::chrono::milliseconds kSensorOpTimeout;
     std::mutex mSensorOpQueueLock;
     std::queue<std::pair<uint64_t, std::shared_future<int>>> mSensorOpQueue;
     uint64_t mNextSensorOpIndex = 0;
diff --git a/modules/sensors/dynamic_sensor/HidRawSensor.cpp b/modules/sensors/dynamic_sensor/HidRawSensor.cpp
index d9c1e669..f2a8c4a4 100644
--- a/modules/sensors/dynamic_sensor/HidRawSensor.cpp
+++ b/modules/sensors/dynamic_sensor/HidRawSensor.cpp
@@ -814,6 +814,8 @@ bool HidRawSensor::detectAndroidCustomSensor(const std::string &description) {
     if (segments[2].size() == 1) {
         switch (segments[2][0]) {
             case 'B':
+                LOG_W << "BODY_SENSORS permission has been deprecated and should not be used."
+                      << LOG_ENDL;
                 mFeatureInfo.permission = SENSOR_PERMISSION_BODY_SENSORS;
                 permissionParsed = true;
                 break;
diff --git a/modules/sensors/dynamic_sensor/HidUtils/HidParser.cpp b/modules/sensors/dynamic_sensor/HidUtils/HidParser.cpp
index 63210200..b11ba150 100644
--- a/modules/sensors/dynamic_sensor/HidUtils/HidParser.cpp
+++ b/modules/sensors/dynamic_sensor/HidUtils/HidParser.cpp
@@ -117,7 +117,7 @@ bool HidParser::processMainTag(const HidItem &i) {
             HidReport report(reportType, flag, top, mLocal);
             mReport.push_back(report);
             std::shared_ptr<HidTreeNode> node(new HidReportNode(mCurrent, report));
-            mCurrent->addChild(node);
+            mCurrent->addChild(std::move(node));
             break;
         }
         default:
diff --git a/modules/sensors/dynamic_sensor/HidUtils/HidReport.cpp b/modules/sensors/dynamic_sensor/HidUtils/HidReport.cpp
index 9b2b78b9..2b9b4cb2 100644
--- a/modules/sensors/dynamic_sensor/HidUtils/HidReport.cpp
+++ b/modules/sensors/dynamic_sensor/HidUtils/HidReport.cpp
@@ -22,7 +22,8 @@
 namespace HidUtil {
 HidReport::HidReport(uint32_t type, uint32_t data,
                      const HidGlobal &global, const HidLocal &local)
-        : mReportType(type),
+        : mIsCollapsed(false),
+          mReportType(type),
           mFlag(data),
           mUsagePage(global.usagePage.get(0)),   // default value 0
           mUsage(local.getUsage(0)),
```

