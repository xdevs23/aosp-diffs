```diff
diff --git a/include_all/hardware/sensors-base.h b/include_all/hardware/sensors-base.h
index dbf99f57..a13e2389 100644
--- a/include_all/hardware/sensors-base.h
+++ b/include_all/hardware/sensors-base.h
@@ -58,6 +58,7 @@ enum {
     SENSOR_TYPE_ACCELEROMETER_LIMITED_AXES_UNCALIBRATED = 40,
     SENSOR_TYPE_GYROSCOPE_LIMITED_AXES_UNCALIBRATED = 41,
     SENSOR_TYPE_HEADING = 42,
+    SENSOR_TYPE_MOISTURE_INTRUSION = 43,
     SENSOR_TYPE_DEVICE_PRIVATE_BASE = 65536 /* 0x10000 */,
 };
 
diff --git a/include_all/hardware/sensors.h b/include_all/hardware/sensors.h
index 9b3e3333..00a4cd26 100644
--- a/include_all/hardware/sensors.h
+++ b/include_all/hardware/sensors.h
@@ -197,6 +197,7 @@ enum {
 #define SENSOR_STRING_TYPE_ACCELEROMETER_LIMITED_AXES_UNCALIBRATED "android.sensor.accelerometer_limited_axes_uncalibrated"
 #define SENSOR_STRING_TYPE_GYROSCOPE_LIMITED_AXES_UNCALIBRATED "android.sensor.gyroscope_limited_axes_uncalibrated"
 #define SENSOR_STRING_TYPE_HEADING                      "android.sensor.heading"
+#define SENSOR_STRING_TYPE_MOISTURE_INTRUSION           "android.sensor.moisture_intrusion"
 
 /**
  * Values returned by the accelerometer in various locations in the universe.
diff --git a/include_vendor/hardware/audio_alsaops.h b/include_vendor/hardware/audio_alsaops.h
index 476c311f..b16fc2dc 100644
--- a/include_vendor/hardware/audio_alsaops.h
+++ b/include_vendor/hardware/audio_alsaops.h
@@ -98,6 +98,71 @@ static inline audio_format_t audio_format_from_pcm_format(enum pcm_format format
     }
 }
 
+// TINYALSA_VERSION_MAJOR is defined in tinyalsa_new for tinyalsa v2
+#ifndef TINYALSA_VERSION_MAJOR
+#define TINYALSA_VERSION_MAJOR 1
+#endif
+
+static inline enum pcm_format pcm_format_from_audio_format_no_fatal(audio_format_t format) {
+    switch (format) {
+#if HAVE_BIG_ENDIAN
+    case AUDIO_FORMAT_PCM_16_BIT:
+    case AUDIO_FORMAT_PCM_24_BIT_PACKED:
+    case AUDIO_FORMAT_PCM_32_BIT:
+    case AUDIO_FORMAT_PCM_8_24_BIT:
+        return pcm_format_from_audio_format(format);
+#if TINYALSA_VERSION_MAJOR >= 2
+    case AUDIO_FORMAT_PCM_FLOAT:
+        return PCM_FORMAT_FLOAT_BE;
+#endif // TINYALSA_VERSION_MARJO >= 2
+#else // HAVE_BIG_ENDIAN
+    case AUDIO_FORMAT_PCM_16_BIT:
+    case AUDIO_FORMAT_PCM_24_BIT_PACKED:
+    case AUDIO_FORMAT_PCM_32_BIT:
+    case AUDIO_FORMAT_PCM_8_24_BIT:
+        return pcm_format_from_audio_format(format);
+#if TINYALSA_VERSION_MAJOR >= 2
+    case AUDIO_FORMAT_PCM_FLOAT:
+        return PCM_FORMAT_FLOAT_LE;
+#endif // TINYALSA_VERSION_MAJOR >= 2
+#endif // HAVE_BIG_ENDIAN
+    default:
+        ALOGE("pcm_format_from_audio_format_no_fatal: invalid audio format %#x", format);
+        return PCM_FORMAT_INVALID;
+    }
+
+}
+
+static inline audio_format_t audio_format_from_pcm_format_no_fatal(enum pcm_format format) {
+    switch (format) {
+#if HAVE_BIG_ENDIAN
+    case PCM_FORMAT_S16_BE:
+    case PCM_FORMAT_S24_3BE:
+    case PCM_FORMAT_S24_BE:
+    case PCM_FORMAT_S32_BE:
+        return audio_format_from_pcm_format(format);
+#if TINYALSA_VERSION_MAJOR >= 2
+    case PCM_FORMAT_FLOAT_BE:
+        return AUDIO_FORMAT_PCM_FLOAT;
+#endif // TINYALSA_VERSION_MARJO >= 2
+#else // HAVE_BIG_ENDIAN
+    case PCM_FORMAT_S16_LE:
+    case PCM_FORMAT_S24_3LE:
+    case PCM_FORMAT_S24_LE:
+    case PCM_FORMAT_S32_LE:
+        return audio_format_from_pcm_format(format);
+#if TINYALSA_VERSION_MAJOR >= 2
+    case PCM_FORMAT_FLOAT_LE:
+        return AUDIO_FORMAT_PCM_FLOAT;
+#endif // TINYALSA_VERSION_MAJOR >= 2
+#endif // HAVE_BIG_ENDIAN
+    default:
+        ALOGE("pcm_format_from_audio_format_no_fatal: invalid audio format %#x", format);
+        return AUDIO_FORMAT_INVALID;
+    }
+
+}
+
 __END_DECLS
 
 #endif /* ANDROID_AUDIO_ALSAOPS_H */
diff --git a/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp b/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
index 414a71d7..ac2ecea8 100644
--- a/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
+++ b/modules/sensors/dynamic_sensor/DynamicSensorManager.cpp
@@ -37,17 +37,16 @@ DynamicSensorManager* DynamicSensorManager::createInstance(
     return m;
 }
 
-DynamicSensorManager::DynamicSensorManager(
-        int handleBase, int handleMax, SensorEventCallback* callback) :
-        mHandleRange(handleBase, handleMax),
-        mCallback(callback),
-        mFifo(callback ? 0 : kFifoSize),
-        mNextHandle(handleBase+1),
-        kSensorOpTimeout(
-            std::chrono::milliseconds((uint32_t)property_get_int32(
-            "vendor.sensors.dynamic_sensor_op_timeout_ms", 1600))) {
-    assert(handleBase > 0 && handleMax > handleBase + 1); // handleBase is reserved
-
+DynamicSensorManager::DynamicSensorManager(int handleBase, int handleMax,
+                                           SensorEventCallback* callback)
+    : mHandleRange(handleBase, handleMax),
+      mCallback(callback),
+      mFifo(callback ? 0 : kFifoSize),
+      mNextHandle(handleBase + 1),
+      kSensorOpTimeout(std::chrono::milliseconds((uint32_t)property_get_int32(
+          "sensors_hal.dynamic_sensor_hal.op_timeout_ms", 1600))) {
+    assert(handleBase > 0 &&
+           handleMax > handleBase + 1);  // handleBase is reserved
     mMetaSensor = (const sensor_t) {
         "Dynamic Sensor Manager",
         "Google",
diff --git a/modules/usbaudio/audio_hal.c b/modules/usbaudio/audio_hal.c
index 57f523b9..0cd9a610 100644
--- a/modules/usbaudio/audio_hal.c
+++ b/modules/usbaudio/audio_hal.c
@@ -1014,7 +1014,7 @@ static int adev_open_output_stream(struct audio_hw_device *hw_dev,
         proxy_config.format = profile_get_default_format(&device_info->profile);
         config->format = audio_format_from_pcm_format(proxy_config.format);
     } else {
-        enum pcm_format fmt = pcm_format_from_audio_format(config->format);
+        enum pcm_format fmt = pcm_format_from_audio_format_no_fatal(config->format);
         if (profile_is_format_valid(&device_info->profile, fmt)) {
             proxy_config.format = fmt;
         } else {
@@ -1530,7 +1530,7 @@ static int adev_open_input_stream(struct audio_hw_device *hw_dev,
         in->config.format = profile_get_default_format(&device_info->profile);
         config->format = audio_format_from_pcm_format(in->config.format);
     } else {
-        enum pcm_format fmt = pcm_format_from_audio_format(config->format);
+        enum pcm_format fmt = pcm_format_from_audio_format_no_fatal(config->format);
         if (profile_is_format_valid(&device_info->profile, fmt)) {
             in->config.format = fmt;
         } else {
```

