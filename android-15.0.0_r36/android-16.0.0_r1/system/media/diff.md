```diff
diff --git a/alsa_utils/alsa_device_proxy.c b/alsa_utils/alsa_device_proxy.c
index 5a436970..434914a6 100644
--- a/alsa_utils/alsa_device_proxy.c
+++ b/alsa_utils/alsa_device_proxy.c
@@ -307,6 +307,13 @@ int proxy_get_capture_position(const alsa_device_proxy * proxy,
     return ret;
 }
 
+int proxy_stop(alsa_device_proxy * proxy)
+{
+    int ret = -ENOSYS;
+    if (proxy->pcm != NULL) ret = pcm_stop(proxy->pcm);
+    return ret;
+}
+
 /*
  * I/O
  */
diff --git a/alsa_utils/include/alsa_device_proxy.h b/alsa_utils/include/alsa_device_proxy.h
index 0daaef30..eba9f05e 100644
--- a/alsa_utils/include/alsa_device_proxy.h
+++ b/alsa_utils/include/alsa_device_proxy.h
@@ -44,6 +44,7 @@ int proxy_get_presentation_position(const alsa_device_proxy * proxy,
         uint64_t *frames, struct timespec *timestamp);
 int proxy_get_capture_position(const alsa_device_proxy * proxy,
         int64_t *frames, int64_t *time);
+int proxy_stop(alsa_device_proxy * proxy);
 
 /* Attributes */
 unsigned proxy_get_sample_rate(const alsa_device_proxy * proxy);
diff --git a/audio/Android.bp b/audio/Android.bp
index d0714e76..6c25a9d4 100644
--- a/audio/Android.bp
+++ b/audio/Android.bp
@@ -34,7 +34,7 @@ cc_library_headers {
     min_sdk_version: "29",
     apex_available: [
         "//apex_available:platform",
-        "com.android.btservices",
+        "com.android.bt",
         "com.android.media",
         "com.android.media.swcodec",
     ],
diff --git a/audio/include/system/audio-base-utils.h b/audio/include/system/audio-base-utils.h
index e318f6af..3afbb5e5 100644
--- a/audio/include/system/audio-base-utils.h
+++ b/audio/include/system/audio-base-utils.h
@@ -242,6 +242,23 @@ static CONST_ARRAY audio_devices_t AUDIO_DEVICE_OUT_BLE_BROADCAST_ARRAY[] = {
     AUDIO_DEVICE_OUT_BLE_BROADCAST,             // 0x20000002u
 };
 
+static CONST_ARRAY audio_devices_t AUDIO_DEVICE_OUT_PICK_FOR_VOLUME_ARRAY[] = {
+    AUDIO_DEVICE_OUT_WIRED_HEADSET,             // 0x00000004u
+    AUDIO_DEVICE_OUT_WIRED_HEADPHONE,           // 0x00000008u
+    AUDIO_DEVICE_OUT_USB_DEVICE,                // 0x00004000u
+    AUDIO_DEVICE_OUT_USB_HEADSET,               // 0x04000000u
+    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP,            // 0x00000080u,
+    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_HEADPHONES, // 0x00000100u,
+    AUDIO_DEVICE_OUT_BLUETOOTH_A2DP_SPEAKER,    // 0x00000200u,
+    AUDIO_DEVICE_OUT_BLUETOOTH_SCO,             // 0x00000010u,
+    AUDIO_DEVICE_OUT_BLUETOOTH_SCO_HEADSET,     // 0x00000020u,
+    AUDIO_DEVICE_OUT_BLUETOOTH_SCO_CARKIT,      // 0x00000040u,
+    AUDIO_DEVICE_OUT_HEARING_AID,               // 0x08000000u
+    AUDIO_DEVICE_OUT_BLE_HEADSET,               // 0x20000000u
+    AUDIO_DEVICE_OUT_BLE_SPEAKER,               // 0x20000001u
+    AUDIO_DEVICE_OUT_BLE_BROADCAST,             // 0x20000002u
+};
+
 // inline constexpr
 static CONST_ARRAY audio_devices_t AUDIO_DEVICE_IN_ALL_ARRAY[] = {
     AUDIO_DEVICE_IN_COMMUNICATION,              // 0x80000001u
@@ -430,7 +447,7 @@ static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_5POINT1POINT2) == 8);
 static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_5POINT1POINT4) == 10);
 static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_7POINT1POINT2) == 10);
 static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_7POINT1POINT4) == 12);
-static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_13POINT_360RA) == 13);
+static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_13POINT0) == 13);
 static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_22POINT2) == 24);
 
 // Check common channel masks which are a subset of another.
@@ -453,13 +470,13 @@ CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_7POINT1, AUDIO_CHANNEL_OUT_7POINT1POIN
 CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_7POINT1, AUDIO_CHANNEL_OUT_7POINT1POINT4);
 // Note AUDIO_CHANNEL_OUT_7POINT1POINT2 is not subset of AUDIO_CHANNEL_OUT_7POINT1POINT4
 CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_5POINT1POINT4, AUDIO_CHANNEL_OUT_7POINT1POINT4);
-CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_13POINT_360RA, AUDIO_CHANNEL_OUT_22POINT2);
+CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_13POINT0, AUDIO_CHANNEL_OUT_22POINT2);
 CHANNEL_CHECK_SUBSET_OF(AUDIO_CHANNEL_OUT_7POINT1POINT4, AUDIO_CHANNEL_OUT_22POINT2);
 
 #undef CHANNEL_CHECK_SUBSET_OF
 
 // Extra channel mask check
-static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_13POINT_360RA
+static_assert(__builtin_popcount(AUDIO_CHANNEL_OUT_13POINT0
         ^ AUDIO_CHANNEL_OUT_7POINT1POINT4) == 7); // bfl, bfr, bfc + tfc replace lfe + bl + br
 
 #endif // __has_builtin(__builtin_popcount)
diff --git a/audio/include/system/audio-hal-enums.h b/audio/include/system/audio-hal-enums.h
index d8e8e3b5..e258b450 100644
--- a/audio/include/system/audio-hal-enums.h
+++ b/audio/include/system/audio-hal-enums.h
@@ -182,7 +182,8 @@ __BEGIN_DECLS
 #define AUDIO_CHANNEL_OUT_MASK_LIST_DEF(V) \
     AUDIO_CHANNEL_OUT_MASK_LIST_UNIQUE_DEF(V) \
     V(AUDIO_CHANNEL_OUT_5POINT1_BACK, AUDIO_CHANNEL_OUT_5POINT1) \
-    V(AUDIO_CHANNEL_OUT_QUAD_BACK, AUDIO_CHANNEL_OUT_QUAD)
+    V(AUDIO_CHANNEL_OUT_QUAD_BACK, AUDIO_CHANNEL_OUT_QUAD) \
+    V(AUDIO_CHANNEL_OUT_13POINT0, AUDIO_CHANNEL_OUT_13POINT_360RA)
 #define AUDIO_CHANNEL_IN_MASK_LIST_DEF(V) \
     V(AUDIO_CHANNEL_IN_MONO, AUDIO_CHANNEL_IN_FRONT) \
     V(AUDIO_CHANNEL_IN_STEREO, AUDIO_CHANNEL_IN_LEFT | AUDIO_CHANNEL_IN_RIGHT) \
diff --git a/audio/include/system/audio.h b/audio/include/system/audio.h
index b0d5ba96..edceb49b 100644
--- a/audio/include/system/audio.h
+++ b/audio/include/system/audio.h
@@ -127,6 +127,8 @@ typedef struct {
 } __attribute__((packed)) audio_attributes_t; // sent through Binder;
 /** The separator for tags. */
 static const char AUDIO_ATTRIBUTES_TAGS_SEPARATOR = ';';
+/** Tag value for GMAP bidirectional mode indication */
+static const char* AUDIO_ATTRIBUTES_TAG_GMAP_BIDIRECTIONAL = "bidirectional";
 
 // Keep sync with android/media/AudioProductStrategy.java
 static const audio_flags_mask_t AUDIO_FLAGS_AFFECT_STRATEGY_SELECTION =
@@ -367,7 +369,7 @@ static inline CONSTEXPR bool audio_channel_mask_contains_stereo(audio_channel_ma
  * AUDIO_CHANNEL_OUT_7POINT1POINT4
  * AUDIO_CHANNEL_OUT_9POINT1POINT4
  * AUDIO_CHANNEL_OUT_9POINT1POINT6
- * AUDIO_CHANNEL_OUT_13POINT_360RA
+ * AUDIO_CHANNEL_OUT_13POINT0
  * AUDIO_CHANNEL_OUT_22POINT2
  */
 static inline CONSTEXPR bool audio_is_channel_mask_spatialized(audio_channel_mask_t channelMask) {
@@ -2529,6 +2531,9 @@ __END_DECLS
 #define AUDIO_OFFLOAD_CODEC_DELAY_SAMPLES  "delay_samples"
 #define AUDIO_OFFLOAD_CODEC_PADDING_SAMPLES  "padding_samples"
 
+#define AUDIO_PARAMETER_CLIP_TRANSITION_SUPPORT "aosp.clipTransitionSupport"
+#define AUDIO_PARAMETER_CREATE_MMAP_BUFFER "aosp.createMmapBuffer"
+
 /**
  * The maximum supported audio sample rate.
  *
diff --git a/audio/include/system/audio_effects/audio_effects_test.h b/audio/include/system/audio_effects/audio_effects_test.h
new file mode 100644
index 00000000..92eb90ac
--- /dev/null
+++ b/audio/include/system/audio_effects/audio_effects_test.h
@@ -0,0 +1,293 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <system/audio_effect.h>
+#include <utils/Errors.h>
+
+namespace android::effect::utils {
+
+// --- Review of structures and methods used for effects ----
+//
+// effect_param_s structure describes the format of the pCmdData argument of EFFECT_CMD_SET_PARAM
+// command and pCmdData and pReplyData of EFFECT_CMD_GET_PARAM command.
+// psize and vsize represent the actual size of parameter and value.
+//
+// NOTE: the start of value field inside the data field is always on a 32 bit boundary:
+//
+//  +-----------+
+//  | status    | sizeof(int)
+//  +-----------+
+//  | psize     | sizeof(int)
+//  +-----------+
+//  | vsize     | sizeof(int)
+//  +-----------+
+//  |           |   |           |
+//  ~ parameter ~   > psize     |
+//  |           |   |           >  ((psize - 1)/sizeof(int) + 1) * sizeof(int)
+//  +-----------+               |
+//  | padding   |               |
+//  +-----------+
+//  |           |   |
+//  ~ value     ~   > vsize
+//  |           |   |
+//  +-----------+
+//
+// typedef struct effect_param_s {
+//     int32_t     status;     // Transaction status (unused for command, used for reply)
+//     uint32_t    psize;      // Parameter size
+//     uint32_t    vsize;      // Value size
+//     char        data[];     // Start of Parameter + Value data
+// } effect_param_t;
+//
+// From (*handle) can access:
+//
+// int32_t (*process)(effect_handle_t self,
+//         audio_buffer_t *inBuffer,
+//         audio_buffer_t *outBuffer);
+//
+// int32_t (*command)(effect_handle_t self,
+//         uint32_t cmdCode,
+//         uint32_t cmdSize,
+//         void *pCmdData,
+//         uint32_t *replySize,
+//         void *pReplyData);
+
+/**
+ * Invoke an effect command with no data and status reply.
+ */
+inline status_t effect_command_with_status(effect_handle_t handle, uint32_t command) {
+    int32_t reply = 0;
+    uint32_t replySize = sizeof(reply);
+    const int32_t status = (*handle)->command(
+            handle, command, 0 /* cmdSize */, nullptr /* pCmdData */, &replySize, &reply);
+    if (status) return status;
+    return reply;
+}
+
+/**
+ * Invoke an effect command with param data and status reply.
+ */
+template <typename P>
+requires (std::is_trivially_copyable_v<P>)
+status_t effect_command_with_status(effect_handle_t handle, uint32_t command, const P& p) {
+    int32_t reply = 0;
+    uint32_t replySize = sizeof(reply);
+
+    // We use a copy of p in this method to guarantee that p is never changed.
+    P copyP;
+    memcpy(&copyP, &p, sizeof(p));  // memcpy ensures hidden padding is identical.
+
+    const int32_t status = (*handle)->command(
+            handle, command, sizeof(copyP), &copyP, &replySize, &reply);
+
+    // Could also check if copyP has been modified after calling the (*handle)->command function.
+    // The command interface method permits it by void* parameter, but effects shouldn't do so.
+
+    if (status) return status;
+    return reply;
+}
+
+/**
+ * Return the padding size of a parameter type.
+ */
+template <typename P>
+inline constexpr size_t effect_padding_size_v = 4 - (int)sizeof(P) & 3;
+
+/**
+ * Return the size of a variable length tuple of value types.
+ */
+template <typename... Vs>
+inline constexpr size_t effect_value_size_v =  (sizeof(Vs) + ...);
+
+/**
+ * Invoke an effect command with a parameter and a sequence of values, with status reply.
+ */
+template <typename P, typename... Vs>
+requires (std::is_trivially_copyable_v<P> && sizeof...(Vs) > 0)
+status_t effect_command_with_status(
+        effect_handle_t handle, uint32_t command, const P& p, const Vs&... vs) {
+    constexpr size_t psize = sizeof(p);
+    constexpr size_t padding = effect_padding_size_v<P>;
+    constexpr size_t vsize = effect_value_size_v<Vs...>;
+    constexpr size_t dsize = sizeof(effect_param_t) + psize + padding + vsize;
+    uint8_t paramData[dsize];  // to avoid pointer aliasing, only access through param.
+    auto param = reinterpret_cast<effect_param_t*>(paramData);
+
+    // Write param sizes, parameter, and padding.
+    param->psize = psize;
+    param->vsize = vsize;
+    memcpy(&param->data[0], &p, psize);
+    if (padding) memset(&param->data[psize], 0, padding);
+
+    // Write each value in turn to param.
+    const size_t offset = psize + padding;
+    size_t argsize = 0;
+    auto copyArg = [&](auto& v) {
+        // we only allow trivially copyable values at the moment.
+        // allowing special containers requires changing this and the vsize computation above.
+        static_assert(std::is_trivially_copyable_v<std::decay_t<decltype(v)>>);
+        memcpy(&param->data[offset + argsize], &v, sizeof(v));
+        argsize += sizeof(v);
+    };
+    (copyArg(vs), ...);
+
+    // Invoke command
+    int32_t reply = 0;
+    uint32_t replySize = sizeof(reply);
+    const int32_t status = (*handle)->command(handle, command, dsize, param, &replySize, &reply);
+    if (status) return status;
+    return reply;
+}
+
+/**
+ * Enable the effect.
+ */
+//==================================================================================================
+// command: EFFECT_CMD_ENABLE
+//--------------------------------------------------------------------------------------------------
+// description:
+//  Enable the process. Called by the framework before the first call to process()
+//--------------------------------------------------------------------------------------------------
+// command format:
+//  size: 0
+//  data: N/A
+//--------------------------------------------------------------------------------------------------
+// reply format:
+//  size: sizeof(int)
+//  data: status
+//==================================================================================================
+inline status_t effect_enable(effect_handle_t handle) {
+    return effect_command_with_status(handle, EFFECT_CMD_ENABLE);
+}
+
+/**
+ * Disable the effect.
+ */
+//==================================================================================================
+// command: EFFECT_CMD_DISABLE
+//--------------------------------------------------------------------------------------------------
+// description:
+//  Disable the process. Called by the framework after the last call to process()
+//--------------------------------------------------------------------------------------------------
+// command format:
+//  size: 0
+//  data: N/A
+//--------------------------------------------------------------------------------------------------
+// reply format:
+//  size: sizeof(int)
+//  data: status
+//==================================================================================================
+inline status_t effect_disable(effect_handle_t handle) {
+    return effect_command_with_status(handle, EFFECT_CMD_DISABLE);
+}
+
+/**
+ * Sets an effect parameter.
+ */
+//==================================================================================================
+// command: EFFECT_CMD_SET_PARAM
+//--------------------------------------------------------------------------------------------------
+// description:
+//  Set a parameter and apply it immediately
+//--------------------------------------------------------------------------------------------------
+// command format:
+//  size: sizeof(effect_param_t) + size of param and value
+//  data: effect_param_t + param + value. See effect_param_t definition below for value offset
+//--------------------------------------------------------------------------------------------------
+// reply format:
+//  size: sizeof(int)
+//  data: status
+//==================================================================================================
+template <typename P, typename... Vs>
+requires (std::is_trivially_copyable_v<P>)
+status_t effect_set_param(effect_handle_t handle, const P& p, const Vs&... vs) {
+    return effect_command_with_status(handle, EFFECT_CMD_SET_PARAM, p, vs...);
+}
+
+/**
+ * Sets the effect configuration
+ */
+//==================================================================================================
+// command: EFFECT_CMD_SET_CONFIG
+//--------------------------------------------------------------------------------------------------
+// description:
+//  Apply new audio parameters configurations for input and output buffers
+//--------------------------------------------------------------------------------------------------
+// command format:
+//  size: sizeof(effect_config_t)
+//  data: effect_config_t
+//--------------------------------------------------------------------------------------------------
+// reply format:
+//  size: sizeof(int)
+//  data: status
+status_t effect_set_config(effect_handle_t handle, const effect_config_t& config) {
+    return effect_command_with_status(handle, EFFECT_CMD_SET_CONFIG, config);
+}
+
+/**
+ * Sets the effect configuration for a pass-through insert effect.
+ */
+status_t effect_set_config(effect_handle_t handle,
+        uint32_t sample_rate, audio_channel_mask_t channel_mask, bool accumulate = false) {
+    const effect_config_t config = {
+            .inputCfg = {
+                    .buffer = {
+                            .frameCount = 0,
+                            .raw = nullptr,
+                    },
+                    .samplingRate = sample_rate,
+                    .channels = channel_mask,
+                    .bufferProvider = {
+                            .getBuffer = nullptr,
+                            .releaseBuffer = nullptr,
+                            .cookie = nullptr,
+                    },
+                    .format = AUDIO_FORMAT_PCM_FLOAT,
+                    .accessMode = EFFECT_BUFFER_ACCESS_READ,
+                    .mask = EFFECT_CONFIG_ALL,
+            },
+            .outputCfg = {
+                    .buffer = {
+                            .frameCount = 0,
+                            .raw = nullptr,
+                    },
+                    .samplingRate = sample_rate,
+                    .channels = channel_mask,
+                    .bufferProvider = {
+                            .getBuffer = nullptr,
+                            .releaseBuffer = nullptr,
+                            .cookie = nullptr,
+                    },
+                    .format = AUDIO_FORMAT_PCM_FLOAT,
+                    .accessMode = static_cast<uint8_t>(
+                            accumulate ? EFFECT_BUFFER_ACCESS_ACCUMULATE
+                            : EFFECT_BUFFER_ACCESS_WRITE),
+                    .mask = EFFECT_CONFIG_ALL,
+            },
+    };
+    return effect_set_config(handle, config);
+}
+
+/**
+ * Process data
+ */
+inline status_t effect_process(effect_handle_t handle, audio_buffer_t* in, audio_buffer_t* out) {
+    return (*handle)->process(handle, in, out);
+}
+
+}  // namespace android::effect::utils
diff --git a/audio/include/system/audio_effects/audio_effects_utils.h b/audio/include/system/audio_effects/audio_effects_utils.h
index b18ec04c..d984e940 100644
--- a/audio/include/system/audio_effects/audio_effects_utils.h
+++ b/audio/include/system/audio_effects/audio_effects_utils.h
@@ -23,6 +23,7 @@
 #include <sstream>
 #include <string>
 #include <sys/types.h>
+#include <type_traits>
 #include <utils/Errors.h>
 
 #include <system/audio_effect.h>
@@ -275,6 +276,87 @@ inline bool operator!=(const audio_uuid_t& lhs, const audio_uuid_t& rhs) {
     return !(lhs == rhs);
 }
 
+/**
+ * @brief Helper function to write a single parameter (type P) and value (type
+ * V) to effect_param_t, with optional buffer size check.
+ *
+ * Type P and V must be trivially copyable type to ensure safe copying to the
+ * effect_param_t structure.
+ *
+ * Usage:
+ *   effect_param_t *param = (effect_param_t *)buf;
+ *   if (OK != android::effect::utils::writeToEffectParam(param, p, v)) {
+ *       // error handling
+ *   }
+ *
+ * @param param The pointer to effect_param_t buffer.
+ * @param p The parameter to write into effect_param_t, 32 bit padded.
+ * @param v The value to write into effect_param_t, start of value field inside
+ * the data field is always on a 32 bits boundary.
+ * @param bufSize OPTIONAL: The size of the buffer pointer to effect_param_t. If
+ * a valid bufSize provide, it will be used to verify if it's big enough to
+ * write both param and value.
+ * @return status_t OK on success, BAD_VALUE on any failure.
+ * Specifically, BAD_VALUE is returned if:
+ * - The `param` pointer is null.
+ * - The `bufSize` is provided and is insufficient to hold the data.
+ */
+template <typename P, typename V>
+  requires(std::is_trivially_copyable_v<P> && std::is_trivially_copyable_v<V>)
+status_t writeToEffectParam(effect_param_t* param, const P p, const V v,
+                            size_t bufSize = 0) {
+  const size_t pSize = EffectParamWrapper::padding(sizeof(P)),
+               vSize = sizeof(V);
+  if (!param ||
+      (bufSize != 0 && bufSize < sizeof(effect_param_t) + pSize + vSize)) {
+    return BAD_VALUE;
+  }
+
+  param->psize = pSize;
+  param->vsize = vSize;
+  EffectParamWriter writer(*param);
+
+  status_t ret = writer.writeToParameter(&p);
+  return ret == OK ? writer.writeToValue(&v) : ret;
+}
+
+/**
+ * @brief Helper function to read a single parameter (type P) and value (type V)
+ * from effect_param_t.
+ *
+ * Type P and V must be trivially copyable type to ensure safe copying from the
+ * effect_param_t structure.
+ *
+ * Usage:
+ *   effect_param_t *param = (effect_param_t *)buf;
+ *   if (OK != android::effect::utils::readFromEffectParam(param, &p, &v)) {
+ *       // error handling
+ *   }
+ *
+ * @param param The pointer to effect_param_t buffer.
+ * @param p The pointer to the return parameter read from effect_param_t.
+ * @param v The pointer to the return value read from effect_param_t.
+ * @return status_t OK on success, BAD_VALUE on any failure.
+ * Specifically, BAD_VALUE is returned if:
+ * - Any of `param`, `p`, or `v` pointers is null.
+ * - The `psize` or `vsize` is smaller than the size of `P` and `V`.
+ *
+ * **Important:** Even in case of an error (return value `BAD_VALUE`), the
+ * memory location pointed to by `p` might be updated.
+ */
+template <typename P, typename V>
+  requires(std::is_trivially_copyable_v<P> && std::is_trivially_copyable_v<V>)
+status_t readFromEffectParam(const effect_param_t* param, P* p, V* v) {
+  if (!param || !p || !v) return BAD_VALUE;
+
+  const size_t pSize = sizeof(P), vSize = sizeof(V);
+  EffectParamReader reader(*param);
+  if (!reader.validateParamValueSize(pSize, vSize)) return BAD_VALUE;
+
+  status_t ret = reader.readFromParameter(p);
+  return ret == OK ? reader.readFromValue(v) : ret;
+}
+
 }  // namespace utils
 }  // namespace effect
 }  // namespace android
diff --git a/audio_route/audio_route.c b/audio_route/audio_route.c
index a28fa65e..ebd88480 100644
--- a/audio_route/audio_route.c
+++ b/audio_route/audio_route.c
@@ -38,19 +38,43 @@ enum update_direction {
     DIRECTION_REVERSE_RESET
 };
 
-union ctl_values {
-    int *enumerated;
-    long *integer;
-    void *ptr;
-    unsigned char *bytes;
+/*
+ "ctl_values" couples the buffer pointer with a variable "byte_size" to store
+ both types of ctl setting as below in respective ways.
+
+                    | fixed-length            | tlv-typed byte ctl [note 1]
+                    | byte/int/enum ctl       |
+ -------------------+-------------------------+--------------------------------
+  alloc buffer size | num_values * size(type) | num_values * 1     [note 2]
+                    +                         +
+  stored value size | always as the full size | can be any size from 1 up to
+                    | of allocated buffer     | num_values
+                    +                         +
+  "byte_size" value | equal to buffer size,   | equal to stored value size,
+                    | fixed in runtime        | variable according to setting
+
+ additional notes:
+ [1] tlv-typed read/write is not a byte-specific feature but by now it only
+     supports for byte ctls via Tinyalsa API
+ [2] num_values is obtained from mixer_ctl_get_num_values()
+ */
+struct ctl_values {
+    /* anonymous union */
+    union {
+        int *enumerated;
+        long *integer;
+        void *ptr;
+        unsigned char *bytes;
+    };
+    unsigned int byte_size;
 };
 
 struct mixer_state {
     struct mixer_ctl *ctl;
     unsigned int num_values;
-    union ctl_values old_value;
-    union ctl_values new_value;
-    union ctl_values reset_value;
+    struct ctl_values old_value;
+    struct ctl_values new_value;
+    struct ctl_values reset_value;
     unsigned int active_count;
 };
 
@@ -58,7 +82,7 @@ struct mixer_setting {
     unsigned int ctl_index;
     unsigned int num_values;
     unsigned int type;
-    union ctl_values value;
+    struct ctl_values value;
 };
 
 struct mixer_value {
@@ -72,6 +96,7 @@ struct mixer_value {
      or top level initial setting value
      */
     long *values;
+    unsigned int num_values_in_array;
 };
 
 struct mixer_path {
@@ -98,6 +123,40 @@ struct config_parse_state {
     bool enum_mixer_numeric_fallback;
 };
 
+static size_t sizeof_ctl_type(enum mixer_ctl_type type);
+
+static bool ctl_is_tlv_byte_type(struct mixer_ctl *ctl)
+{
+    return mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_BYTE && mixer_ctl_is_access_tlv_rw(ctl);
+}
+
+/* ctl_values helper functions */
+
+static int ctl_values_alloc(struct ctl_values *value, unsigned int num_values,
+                            enum mixer_ctl_type type)
+{
+    void *ptr;
+    size_t value_sz = sizeof_ctl_type(type);
+
+    ptr = calloc(num_values, value_sz);
+    if (!ptr)
+        return -1;
+
+    value->ptr = ptr;
+    value->byte_size = num_values * value_sz;
+    return 0;
+}
+
+static void ctl_values_copy(struct ctl_values *dst, const struct ctl_values *src)
+{
+    /*
+     this should only be used for copying among "ctl_values"-es of a "mixer_state", all of them
+     will be allocated the same size of buffers according to "num_values" obtained from mixer ctl.
+     */
+    memcpy(dst->ptr, src->ptr, src->byte_size);
+    dst->byte_size = src->byte_size;
+}
+
 /* path functions */
 
 static bool is_supported_ctl_type(enum mixer_ctl_type type)
@@ -278,6 +337,7 @@ static int path_add_setting(struct audio_route *ar, struct mixer_path *path,
                             struct mixer_setting *setting)
 {
     int path_index;
+    int rc;
 
     if (find_ctl_index_in_path(path, setting->ctl_index) != -1) {
         struct mixer_ctl *ctl = index_to_ctl(ar, setting->ctl_index);
@@ -300,12 +360,13 @@ static int path_add_setting(struct audio_route *ar, struct mixer_path *path,
     path->setting[path_index].type = setting->type;
     path->setting[path_index].num_values = setting->num_values;
 
-    size_t value_sz = sizeof_ctl_type(setting->type);
-
-    path->setting[path_index].value.ptr = calloc(setting->num_values, value_sz);
+    rc = ctl_values_alloc(&path->setting[path_index].value, setting->num_values, setting->type);
+    if (rc < 0) {
+        ALOGE("failed to allocate mem for path setting");
+        return rc;
+    }
     /* copy all values */
-    memcpy(path->setting[path_index].value.ptr, setting->value.ptr,
-           setting->num_values * value_sz);
+    ctl_values_copy(&path->setting[path_index].value, &setting->value);
 
     return 0;
 }
@@ -317,6 +378,7 @@ static int path_add_value(struct audio_route *ar, struct mixer_path *path,
     int path_index;
     unsigned int num_values;
     struct mixer_ctl *ctl;
+    int rc;
 
     /* Check that mixer value index is within range */
     ctl = index_to_ctl(ar, mixer_value->ctl_index);
@@ -345,8 +407,11 @@ static int path_add_value(struct audio_route *ar, struct mixer_path *path,
         path->setting[path_index].num_values = num_values;
         path->setting[path_index].type = type;
 
-        size_t value_sz = sizeof_ctl_type(type);
-        path->setting[path_index].value.ptr = calloc(num_values, value_sz);
+        rc = ctl_values_alloc(&path->setting[path_index].value, num_values, type);
+        if (rc < 0) {
+            ALOGE("failed to allocate mem for path setting");
+            return rc;
+        }
         if (path->setting[path_index].type == MIXER_CTL_TYPE_BYTE)
             path->setting[path_index].value.bytes[0] = mixer_value->value;
         else if (path->setting[path_index].type == MIXER_CTL_TYPE_ENUM)
@@ -358,8 +423,10 @@ static int path_add_value(struct audio_route *ar, struct mixer_path *path,
     if (mixer_value->index == -1) {
         /* set all values the same except for CTL_TYPE_BYTE and CTL_TYPE_INT */
         if (path->setting[path_index].type == MIXER_CTL_TYPE_BYTE) {
-            for (i = 0; i < num_values; i++)
+            /* update the number of values (bytes) from input "mixer_value" */
+            for (i = 0; i < mixer_value->num_values_in_array; i++)
                 path->setting[path_index].value.bytes[i] = mixer_value->values[i];
+            path->setting[path_index].value.byte_size = mixer_value->num_values_in_array;
         } else if (path->setting[path_index].type == MIXER_CTL_TYPE_INT) {
             for (i = 0; i < num_values; i++)
                 path->setting[path_index].value.integer[i] = mixer_value->values[i];
@@ -414,9 +481,7 @@ static int path_apply(struct audio_route *ar, struct mixer_path *path)
         type = mixer_ctl_get_type(ctl);
         if (!is_supported_ctl_type(type))
             continue;
-        size_t value_sz = sizeof_ctl_type(type);
-        memcpy(ar->mixer_state[ctl_index].new_value.ptr, path->setting[i].value.ptr,
-                   path->setting[i].num_values * value_sz);
+        ctl_values_copy(&ar->mixer_state[ctl_index].new_value, &path->setting[i].value);
     }
 
     return 0;
@@ -436,11 +501,9 @@ static int path_reset(struct audio_route *ar, struct mixer_path *path)
         type = mixer_ctl_get_type(ctl);
         if (!is_supported_ctl_type(type))
             continue;
-        size_t value_sz = sizeof_ctl_type(type);
         /* reset the value(s) */
-        memcpy(ar->mixer_state[ctl_index].new_value.ptr,
-               ar->mixer_state[ctl_index].reset_value.ptr,
-               ar->mixer_state[ctl_index].num_values * value_sz);
+        ctl_values_copy(&ar->mixer_state[ctl_index].new_value,
+                        &ar->mixer_state[ctl_index].reset_value);
     }
 
     return 0;
@@ -493,6 +556,50 @@ static int mixer_enum_string_to_value(struct mixer_ctl *ctl, const char *string,
     return i;
 }
 
+static int mixer_get_bytes_from_file(long **value_array, const char *filepath,
+                                     unsigned int max_bytes)
+{
+    unsigned char *buf = NULL;
+    long *values = NULL;
+    int bytes_read = -1;
+    unsigned int i;
+
+    FILE *file = fopen(filepath, "rb");
+    if (!file) {
+        ALOGE("Failed to open %s: %s", filepath, strerror(errno));
+        return -1;
+    }
+
+    buf = calloc(max_bytes, 1);
+    if (!buf) {
+        ALOGE("failed to allocate mem for file read buffer");
+        goto exit;
+    }
+
+    bytes_read = fread(buf, 1, max_bytes, file);
+    if (bytes_read < 0) {
+        ALOGE("failed to read data from file, rc: %d", bytes_read);
+        goto exit;
+    }
+
+    values = calloc(bytes_read, sizeof(long));
+    if (!values) {
+        ALOGE("failed to allocate mem for values array");
+        bytes_read = -1;
+        goto exit;
+    }
+
+    for (i = 0; i < bytes_read; i++) {
+        values[i] = (long)buf[i];
+    }
+    *value_array = values;
+
+exit:
+    free(buf);
+    fclose(file);
+    return bytes_read;
+}
+
 static void start_tag(void *data, const XML_Char *tag_name,
                       const XML_Char **attr)
 {
@@ -500,6 +607,7 @@ static void start_tag(void *data, const XML_Char *tag_name,
     const XML_Char *attr_id = NULL;
     const XML_Char *attr_value = NULL;
     const XML_Char *attr_enum_mixer_numeric_fallback = NULL;
+    const XML_Char *attr_bin = NULL;
     struct config_parse_state *state = data;
     struct audio_route *ar = state->ar;
     unsigned int i;
@@ -510,6 +618,7 @@ static void start_tag(void *data, const XML_Char *tag_name,
     struct mixer_value mixer_value;
     enum mixer_ctl_type type;
     long* value_array = NULL;
+    unsigned int num_values_in_array = 0;
 
     /* Get name, id and value attributes (these may be empty) */
     for (i = 0; attr[i]; i += 2) {
@@ -521,6 +630,8 @@ static void start_tag(void *data, const XML_Char *tag_name,
             attr_value = attr[i + 1];
         else if (strcmp(attr[i], "enum_mixer_numeric_fallback") == 0)
             attr_enum_mixer_numeric_fallback = attr[i + 1];
+        else if (strcmp(attr[i], "bin") == 0)
+            attr_bin = attr[i + 1];
     }
 
     /* Look at tags */
@@ -566,12 +677,28 @@ static void start_tag(void *data, const XML_Char *tag_name,
         case MIXER_CTL_TYPE_INT:
         case MIXER_CTL_TYPE_BYTE: {
                 char *attr_sub_value, *test_r;
+                unsigned int num_values = mixer_ctl_get_num_values(ctl);
+
+                if (attr_bin && mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_BYTE) {
+                    /* get byte values from binfile */
+                    int bytes_read = mixer_get_bytes_from_file(&value_array, attr_bin, num_values);
+                    if (bytes_read <= 0) {
+                        ALOGE("failed to get bytes from file '%s'", attr_bin);
+                        goto done;
+                    }
+                    if (bytes_read < num_values && mixer_ctl_is_access_tlv_rw(ctl) == 0) {
+                        ALOGE("expect %d values but only %d specified for ctl %s",
+                              num_values, bytes_read, attr_name);
+                        goto done;
+                    }
+                    num_values_in_array = bytes_read;
+                    break;
+                }
 
                 if (attr_value == NULL) {
                     ALOGE("No value specified for ctl %s", attr_name);
                     goto done;
                 }
-                unsigned int num_values = mixer_ctl_get_num_values(ctl);
                 value_array = calloc(num_values, sizeof(long));
                 if (!value_array) {
                     ALOGE("failed to allocate mem for ctl %s", attr_name);
@@ -580,6 +707,12 @@ static void start_tag(void *data, const XML_Char *tag_name,
                 for (i = 0; i < num_values; i++) {
                     attr_sub_value = strtok_r((char *)attr_value, " ", &test_r);
                     if (attr_sub_value == NULL) {
+                        /* the length of setting for tlv-typed byte control
+                           can be any size up to num_value; break the loop so
+                           the current count of values will be recorded */
+                        if (ctl_is_tlv_byte_type(ctl))
+                            break;
+
                         ALOGE("expect %d values but only %d specified for ctl %s",
                             num_values, i, attr_name);
                         goto done;
@@ -590,6 +723,9 @@ static void start_tag(void *data, const XML_Char *tag_name,
                         value_array[i] =
                            (unsigned char) strtol((char *)attr_sub_value, NULL, 16);
 
+                    /* count the number of values written in array */
+                    num_values_in_array++;
+
                     if (attr_id)
                         break;
 
@@ -636,6 +772,12 @@ static void start_tag(void *data, const XML_Char *tag_name,
                     else
                         ALOGW("value id out of range for mixer ctl '%s'",
                               mixer_ctl_get_name(ctl));
+                } else if (ctl_is_tlv_byte_type(ctl)) {
+                    /* for tlv-typed ctl, only set the number of values (bytes) carried by array,
+                       and update the number of bytes */
+                    for (i = 0; i < num_values_in_array; i++)
+                        ar->mixer_state[ctl_index].new_value.bytes[i] = value_array[i];
+                    ar->mixer_state[ctl_index].new_value.byte_size = num_values_in_array;
                 } else {
                     /* set all values the same except for CTL_TYPE_BYTE and CTL_TYPE_INT */
                     for (i = 0; i < ar->mixer_state[ctl_index].num_values; i++)
@@ -656,6 +798,7 @@ static void start_tag(void *data, const XML_Char *tag_name,
                 mixer_ctl_get_type(ctl) == MIXER_CTL_TYPE_INT) {
                 mixer_value.values = value_array;
                 mixer_value.value = value_array[0];
+                mixer_value.num_values_in_array = num_values_in_array;
             } else {
                 mixer_value.value = value;
             }
@@ -707,18 +850,21 @@ static int alloc_mixer_state(struct audio_route *ar)
         if (!is_supported_ctl_type(type))
             continue;
 
-        size_t value_sz = sizeof_ctl_type(type);
-        ar->mixer_state[i].old_value.ptr = calloc(num_values, value_sz);
-        ar->mixer_state[i].new_value.ptr = calloc(num_values, value_sz);
-        ar->mixer_state[i].reset_value.ptr = calloc(num_values, value_sz);
+        /*
+         for tlv-typed ctl, "mixer_ctl_get_num_values()" returns the max length of a
+         setting data. The buffer size allocated per mixer setting should align the
+         max length to be capable of carrying any length of data.
+         */
+        ctl_values_alloc(&ar->mixer_state[i].old_value, num_values, type);
+        ctl_values_alloc(&ar->mixer_state[i].new_value, num_values, type);
+        ctl_values_alloc(&ar->mixer_state[i].reset_value, num_values, type);
 
         if (type == MIXER_CTL_TYPE_ENUM)
             ar->mixer_state[i].old_value.enumerated[0] = mixer_ctl_get_value(ctl, 0);
         else
             mixer_ctl_get_array(ctl, ar->mixer_state[i].old_value.ptr, num_values);
 
-        memcpy(ar->mixer_state[i].new_value.ptr, ar->mixer_state[i].old_value.ptr,
-               num_values * value_sz);
+        ctl_values_copy(&ar->mixer_state[i].new_value, &ar->mixer_state[i].old_value);
     }
 
     return 0;
@@ -743,15 +889,52 @@ static void free_mixer_state(struct audio_route *ar)
     ar->mixer_state = NULL;
 }
 
+static void mixer_set_value_if_changed(struct mixer_state *ms)
+{
+    unsigned int i;
+    struct mixer_ctl *ctl = ms->ctl;
+    enum mixer_ctl_type type = mixer_ctl_get_type(ctl);
+
+    if (type == MIXER_CTL_TYPE_BYTE) {
+        unsigned int num_bytes;
+        /*
+         for tlv-typed ctl, "mixer_ctl_set_array()" should specify the length of data to
+         be set, thus the data can be wrapped into tlv format correctly by Tinyalsa.
+         */
+        num_bytes = ctl_is_tlv_byte_type(ctl) ? ms->new_value.byte_size : ms->num_values;
+        for (i = 0; i < num_bytes; i++) {
+            if (ms->old_value.bytes[i] != ms->new_value.bytes[i]) {
+                mixer_ctl_set_array(ctl, ms->new_value.ptr, num_bytes);
+                ctl_values_copy(&ms->old_value, &ms->new_value);
+                return;
+            }
+        }
+    } else if (type == MIXER_CTL_TYPE_ENUM) {
+        for (i = 0; i < ms->num_values; i++) {
+            if (ms->old_value.enumerated[i] != ms->new_value.enumerated[i]) {
+                mixer_ctl_set_value(ctl, 0, ms->new_value.enumerated[0]);
+                ctl_values_copy(&ms->old_value, &ms->new_value);
+                return;
+            }
+        }
+    } else {
+        for (i = 0; i < ms->num_values; i++) {
+            if (ms->old_value.integer[i] != ms->new_value.integer[i]) {
+                mixer_ctl_set_array(ctl, ms->new_value.ptr, ms->num_values);
+                ctl_values_copy(&ms->old_value, &ms->new_value);
+                return;
+            }
+        }
+    }
+}
+
 /* Update the mixer with any changed values */
 int audio_route_update_mixer(struct audio_route *ar)
 {
     unsigned int i;
-    unsigned int j;
     struct mixer_ctl *ctl;
 
     for (i = 0; i < ar->num_mixer_ctls; i++) {
-        unsigned int num_values = ar->mixer_state[i].num_values;
         enum mixer_ctl_type type;
 
         ctl = ar->mixer_state[i].ctl;
@@ -762,40 +945,7 @@ int audio_route_update_mixer(struct audio_route *ar)
             continue;
 
         /* if the value has changed, update the mixer */
-        bool changed = false;
-        if (type == MIXER_CTL_TYPE_BYTE) {
-            for (j = 0; j < num_values; j++) {
-                if (ar->mixer_state[i].old_value.bytes[j] != ar->mixer_state[i].new_value.bytes[j]) {
-                    changed = true;
-                    break;
-                }
-            }
-         } else if (type == MIXER_CTL_TYPE_ENUM) {
-             for (j = 0; j < num_values; j++) {
-                 if (ar->mixer_state[i].old_value.enumerated[j]
-                         != ar->mixer_state[i].new_value.enumerated[j]) {
-                     changed = true;
-                     break;
-                 }
-             }
-         } else {
-            for (j = 0; j < num_values; j++) {
-                if (ar->mixer_state[i].old_value.integer[j] != ar->mixer_state[i].new_value.integer[j]) {
-                    changed = true;
-                    break;
-                }
-            }
-        }
-        if (changed) {
-            if (type == MIXER_CTL_TYPE_ENUM)
-                mixer_ctl_set_value(ctl, 0, ar->mixer_state[i].new_value.enumerated[0]);
-            else
-                mixer_ctl_set_array(ctl, ar->mixer_state[i].new_value.ptr, num_values);
-
-            size_t value_sz = sizeof_ctl_type(type);
-            memcpy(ar->mixer_state[i].old_value.ptr, ar->mixer_state[i].new_value.ptr,
-                   num_values * value_sz);
-        }
+        mixer_set_value_if_changed(&ar->mixer_state[i]);
     }
 
     return 0;
@@ -812,9 +962,7 @@ static void save_mixer_state(struct audio_route *ar)
         if (!is_supported_ctl_type(type))
             continue;
 
-        size_t value_sz = sizeof_ctl_type(type);
-        memcpy(ar->mixer_state[i].reset_value.ptr, ar->mixer_state[i].new_value.ptr,
-               ar->mixer_state[i].num_values * value_sz);
+        ctl_values_copy(&ar->mixer_state[i].reset_value, &ar->mixer_state[i].new_value);
     }
 }
 
@@ -830,9 +978,7 @@ void audio_route_reset(struct audio_route *ar)
         if (!is_supported_ctl_type(type))
             continue;
 
-        size_t value_sz = sizeof_ctl_type(type);
-        memcpy(ar->mixer_state[i].new_value.ptr, ar->mixer_state[i].reset_value.ptr,
-            ar->mixer_state[i].num_values * value_sz);
+        ctl_values_copy(&ar->mixer_state[i].new_value, &ar->mixer_state[i].reset_value);
     }
 }
 
@@ -914,60 +1060,21 @@ static int audio_route_update_path(struct audio_route *ar, const char *name, int
         }
 
         if (reverse && ms->active_count > 0) {
-            if (force_reset)
+            if (force_reset) {
                 ms->active_count = 0;
-            else
-                ms->active_count--;
+            } else if (--ms->active_count > 0) {
+                ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
+                    "because it is still needed by other paths", __func__,
+                    mixer_ctl_get_name(ms->ctl), name);
+                ctl_values_copy(&ms->new_value, &ms->old_value);
+                continue;
+            }
         } else if (!reverse) {
             ms->active_count++;
         }
 
-       size_t value_sz = sizeof_ctl_type(type);
         /* if any value has changed, update the mixer */
-        for (j = 0; j < ms->num_values; j++) {
-            if (type == MIXER_CTL_TYPE_BYTE) {
-                if (ms->old_value.bytes[j] != ms->new_value.bytes[j]) {
-                    if (reverse && ms->active_count > 0) {
-                        ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
-                            "because it is still needed by other paths", __func__,
-                            mixer_ctl_get_name(ms->ctl), name);
-                        memcpy(ms->new_value.bytes, ms->old_value.bytes,
-                            ms->num_values * value_sz);
-                        break;
-                    }
-                    mixer_ctl_set_array(ms->ctl, ms->new_value.bytes, ms->num_values);
-                    memcpy(ms->old_value.bytes, ms->new_value.bytes, ms->num_values * value_sz);
-                    break;
-                }
-            } else if (type == MIXER_CTL_TYPE_ENUM) {
-                if (ms->old_value.enumerated[j] != ms->new_value.enumerated[j]) {
-                    if (reverse && ms->active_count > 0) {
-                        ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
-                            "because it is still needed by other paths", __func__,
-                            mixer_ctl_get_name(ms->ctl), name);
-                        memcpy(ms->new_value.enumerated, ms->old_value.enumerated,
-                            ms->num_values * value_sz);
-                        break;
-                    }
-                    mixer_ctl_set_value(ms->ctl, 0, ms->new_value.enumerated[0]);
-                    memcpy(ms->old_value.enumerated, ms->new_value.enumerated,
-                            ms->num_values * value_sz);
-                    break;
-                }
-            } else if (ms->old_value.integer[j] != ms->new_value.integer[j]) {
-                if (reverse && ms->active_count > 0) {
-                    ALOGD("%s: skip to reset mixer control '%s' in path '%s' "
-                        "because it is still needed by other paths", __func__,
-                        mixer_ctl_get_name(ms->ctl), name);
-                    memcpy(ms->new_value.integer, ms->old_value.integer,
-                        ms->num_values * value_sz);
-                    break;
-                }
-                mixer_ctl_set_array(ms->ctl, ms->new_value.integer, ms->num_values);
-                memcpy(ms->old_value.integer, ms->new_value.integer, ms->num_values * value_sz);
-                break;
-            }
-        }
+        mixer_set_value_if_changed(ms);
     }
     return 0;
 }
diff --git a/audio_utils/benchmarks/Android.bp b/audio_utils/benchmarks/Android.bp
index c05e9245..42305908 100644
--- a/audio_utils/benchmarks/Android.bp
+++ b/audio_utils/benchmarks/Android.bp
@@ -45,6 +45,17 @@ cc_benchmark {
     ],
 }
 
+cc_benchmark {
+    name: "audio_vectorization_benchmark",
+    host_supported: true,
+
+    srcs: ["audio_vectorization_benchmark.cpp"],
+    cflags: [
+        "-Wall",
+        "-Werror",
+    ],
+}
+
 cc_benchmark {
     name: "biquad_filter_benchmark",
     host_supported: true,
diff --git a/audio_utils/benchmarks/audio_power_benchmark.cpp b/audio_utils/benchmarks/audio_power_benchmark.cpp
index 13c3f758..314c0768 100644
--- a/audio_utils/benchmarks/audio_power_benchmark.cpp
+++ b/audio_utils/benchmarks/audio_power_benchmark.cpp
@@ -240,8 +240,8 @@ static constexpr audio_channel_mask_t kChannelPositionMasks[] = {
     AUDIO_CHANNEL_OUT_5POINT1POINT4,
     AUDIO_CHANNEL_OUT_7POINT1POINT2,
     AUDIO_CHANNEL_OUT_7POINT1POINT4,
+    AUDIO_CHANNEL_OUT_13POINT0,
     AUDIO_CHANNEL_OUT_9POINT1POINT6,
-    AUDIO_CHANNEL_OUT_13POINT_360RA,
     AUDIO_CHANNEL_OUT_22POINT2,
 };
 
diff --git a/audio_utils/benchmarks/audio_vectorization_benchmark.cpp b/audio_utils/benchmarks/audio_vectorization_benchmark.cpp
new file mode 100644
index 00000000..a7f96e0e
--- /dev/null
+++ b/audio_utils/benchmarks/audio_vectorization_benchmark.cpp
@@ -0,0 +1,580 @@
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
+#include <functional>
+#include <random>
+#include <vector>
+
+#include <benchmark/benchmark.h>
+
+/*
+Pixel 6 Pro Android 14
+------------------------------------------------------------------------------
+Benchmark                                    Time             CPU   Iterations
+------------------------------------------------------------------------------
+BM_VectorTestLoopFloat/1                  1216 ns         1212 ns       580560
+BM_VectorTestLoopFloat/2                  2272 ns         2264 ns       309745
+BM_VectorTestLoopFloat/3                  3366 ns         3354 ns       209391
+BM_VectorTestLoopFloat/4                  4495 ns         4478 ns       157291
+BM_VectorTestLoopFloat/5                  5660 ns         5627 ns       124649
+BM_VectorTestLoopFloat/6                  6776 ns         6750 ns       104102
+BM_VectorTestLoopFloat/7                  7942 ns         7916 ns        89257
+BM_VectorTestLoopFloat/8                  9120 ns         9086 ns        77234
+BM_VectorTestLoopFloat/9                 10252 ns        10212 ns        69253
+BM_VectorTestLoopFloat/10                11475 ns        11432 ns        61646
+BM_VectorTestLoopFloat/11                12704 ns        12658 ns        55493
+BM_VectorTestLoopFloat/12                13864 ns        13812 ns        50944
+BM_VectorTestLoopFloat/13                15024 ns        14967 ns        47169
+BM_VectorTestLoopFloat/14                16340 ns        16282 ns        43531
+BM_VectorTestLoopFloat/15                17422 ns        17356 ns        40328
+BM_VectorTestLoopFloat/16                18680 ns        18609 ns        37820
+BM_VectorTestLoopFloat/17                19892 ns        19819 ns        35348
+BM_VectorTestLoopFloat/18                21099 ns        21015 ns        33253
+BM_VectorTestLoopFloat/19                22238 ns        22154 ns        31681
+BM_VectorTestLoopFloat/20                23551 ns        23433 ns        29829
+BM_VectorTestLoopFloat/21                24707 ns        24612 ns        28525
+BM_VectorTestLoopFloat/22                26041 ns        25916 ns        27004
+BM_VectorTestLoopFloat/23                27236 ns        27122 ns        25123
+BM_VectorTestLoopFloat/24                28535 ns        28409 ns        24505
+BM_VectorTestLoopFloat/25                29715 ns        29542 ns        23744
+BM_VectorTestLoopFloat/26                31163 ns        31002 ns        22640
+BM_VectorTestLoopFloat/27                32259 ns        32065 ns        21859
+BM_VectorTestLoopFloat/28                33580 ns        33391 ns        20702
+BM_VectorTestLoopFloat/29                34891 ns        34699 ns        20281
+BM_VectorTestLoopFloat/30                36242 ns        36007 ns        19400
+BM_VectorTestLoopFloat/31                37423 ns        37154 ns        18875
+BM_VectorTestLoopFloat/32                38858 ns        38608 ns        17699
+BM_VectorTestConstArraySizeFloat/1         185 ns          184 ns      3771794
+BM_VectorTestConstArraySizeFloat/2         663 ns          660 ns      1068518
+BM_VectorTestConstArraySizeFloat/3        2159 ns         2152 ns       318170
+BM_VectorTestConstArraySizeFloat/4        3919 ns         3905 ns       179267
+BM_VectorTestConstArraySizeFloat/5        1861 ns         1854 ns       374407
+BM_VectorTestConstArraySizeFloat/6        1964 ns         1956 ns       362563
+BM_VectorTestConstArraySizeFloat/7        2789 ns         2779 ns       252684
+BM_VectorTestConstArraySizeFloat/8        2070 ns         2062 ns       342189
+BM_VectorTestConstArraySizeFloat/9        3191 ns         3179 ns       220216
+BM_VectorTestConstArraySizeFloat/10       3128 ns         3117 ns       225340
+BM_VectorTestConstArraySizeFloat/11       4049 ns         4025 ns       174288
+BM_VectorTestConstArraySizeFloat/12       3124 ns         3106 ns       225711
+BM_VectorTestConstArraySizeFloat/13       4440 ns         4424 ns       158540
+BM_VectorTestConstArraySizeFloat/14       4276 ns         4256 ns       164144
+BM_VectorTestConstArraySizeFloat/15       5325 ns         5306 ns       132282
+BM_VectorTestConstArraySizeFloat/16       4091 ns         4072 ns       172111
+BM_VectorTestConstArraySizeFloat/17       5711 ns         5682 ns       122226
+BM_VectorTestConstArraySizeFloat/18       5373 ns         5349 ns       129827
+BM_VectorTestConstArraySizeFloat/19       6500 ns         6474 ns       108150
+BM_VectorTestConstArraySizeFloat/20       5131 ns         5109 ns       136649
+BM_VectorTestConstArraySizeFloat/21       6896 ns         6867 ns        99598
+BM_VectorTestConstArraySizeFloat/22       6579 ns         6529 ns       108221
+BM_VectorTestConstArraySizeFloat/23       7752 ns         7705 ns        91673
+BM_VectorTestConstArraySizeFloat/24       6129 ns         6102 ns       114269
+BM_VectorTestConstArraySizeFloat/25       8151 ns         8120 ns        85643
+BM_VectorTestConstArraySizeFloat/26       7512 ns         7474 ns        94708
+BM_VectorTestConstArraySizeFloat/27       9100 ns         9047 ns        79200
+BM_VectorTestConstArraySizeFloat/28       7191 ns         7149 ns        97121
+BM_VectorTestConstArraySizeFloat/29       9417 ns         9362 ns        74720
+BM_VectorTestConstArraySizeFloat/30       8952 ns         8893 ns        80378
+BM_VectorTestConstArraySizeFloat/31      10342 ns        10284 ns        66481
+BM_VectorTestConstArraySizeFloat/32       8189 ns         8132 ns        85186
+BM_VectorTestForcedIntrinsics/1            189 ns          189 ns      3629410
+BM_VectorTestForcedIntrinsics/2           1192 ns         1188 ns       572025
+BM_VectorTestForcedIntrinsics/3           1701 ns         1695 ns       412319
+BM_VectorTestForcedIntrinsics/4           1234 ns         1229 ns       563105
+BM_VectorTestForcedIntrinsics/5           1936 ns         1929 ns       367124
+BM_VectorTestForcedIntrinsics/6           2002 ns         1994 ns       350985
+BM_VectorTestForcedIntrinsics/7           2826 ns         2814 ns       247821
+BM_VectorTestForcedIntrinsics/8           2106 ns         2098 ns       332577
+BM_VectorTestForcedIntrinsics/9           3240 ns         3229 ns       216567
+BM_VectorTestForcedIntrinsics/10          3176 ns         3164 ns       219614
+BM_VectorTestForcedIntrinsics/11          4086 ns         4065 ns       173103
+BM_VectorTestForcedIntrinsics/12          3095 ns         3083 ns       226427
+BM_VectorTestForcedIntrinsics/13          4459 ns         4441 ns       157019
+BM_VectorTestForcedIntrinsics/14          4298 ns         4281 ns       162819
+BM_VectorTestForcedIntrinsics/15          5232 ns         5211 ns       130653
+BM_VectorTestForcedIntrinsics/16          4166 ns         4150 ns       168336
+BM_VectorTestForcedIntrinsics/17          5713 ns         5687 ns       122828
+BM_VectorTestForcedIntrinsics/18          5424 ns         5403 ns       131831
+BM_VectorTestForcedIntrinsics/19          6517 ns         6487 ns       107246
+BM_VectorTestForcedIntrinsics/20          5208 ns         5179 ns       135608
+BM_VectorTestForcedIntrinsics/21          6927 ns         6882 ns       101059
+BM_VectorTestForcedIntrinsics/22          6593 ns         6542 ns       108036
+BM_VectorTestForcedIntrinsics/23          7789 ns         7745 ns        90793
+BM_VectorTestForcedIntrinsics/24          6241 ns         6200 ns       113967
+BM_VectorTestForcedIntrinsics/25          8178 ns         8130 ns        84883
+BM_VectorTestForcedIntrinsics/26          7768 ns         7724 ns        91931
+BM_VectorTestForcedIntrinsics/27          9017 ns         8954 ns        78657
+BM_VectorTestForcedIntrinsics/28          7250 ns         7206 ns        98287
+BM_VectorTestForcedIntrinsics/29          9419 ns         9365 ns        74588
+BM_VectorTestForcedIntrinsics/30          8943 ns         8885 ns        77512
+BM_VectorTestForcedIntrinsics/31         10217 ns        10159 ns        69207
+BM_VectorTestForcedIntrinsics/32          8271 ns         8221 ns        86206
+
+Pixel 6 Pro (1/29/2025)
+------------------------------------------------------------------------------
+Benchmark                                    Time             CPU   Iterations
+------------------------------------------------------------------------------
+BM_VectorTestLoopFloat/1                  1522 ns         1514 ns       459906
+BM_VectorTestLoopFloat/2                  2391 ns         2383 ns       293707
+BM_VectorTestLoopFloat/3                  3437 ns         3426 ns       205663
+BM_VectorTestLoopFloat/4                  4482 ns         4468 ns       157406
+BM_VectorTestLoopFloat/5                  5665 ns         5645 ns       125564
+BM_VectorTestLoopFloat/6                  6784 ns         6762 ns       105112
+BM_VectorTestLoopFloat/7                  7930 ns         7902 ns        89104
+BM_VectorTestLoopFloat/8                  9043 ns         9011 ns        77654
+BM_VectorTestLoopFloat/9                 10178 ns        10145 ns        68967
+BM_VectorTestLoopFloat/10                11338 ns        11296 ns        61958
+BM_VectorTestLoopFloat/11                12500 ns        12456 ns        56104
+BM_VectorTestLoopFloat/12                13686 ns        13634 ns        51361
+BM_VectorTestLoopFloat/13                14794 ns        14744 ns        47477
+BM_VectorTestLoopFloat/14                16040 ns        15979 ns        43158
+BM_VectorTestLoopFloat/15                17098 ns        17036 ns        40926
+BM_VectorTestLoopFloat/16                18413 ns        18343 ns        37962
+BM_VectorTestLoopFloat/17                19462 ns        19382 ns        36093
+BM_VectorTestLoopFloat/18                20788 ns        20704 ns        33897
+BM_VectorTestLoopFloat/19                22168 ns        21967 ns        31994
+BM_VectorTestLoopFloat/20                23420 ns        23322 ns        30136
+BM_VectorTestLoopFloat/21                24424 ns        24316 ns        28773
+BM_VectorTestLoopFloat/22                25789 ns        25686 ns        27195
+BM_VectorTestLoopFloat/23                26980 ns        26870 ns        25939
+BM_VectorTestLoopFloat/24                28349 ns        28238 ns        24906
+BM_VectorTestLoopFloat/25                29486 ns        29355 ns        23815
+BM_VectorTestLoopFloat/26                30686 ns        30554 ns        22853
+BM_VectorTestLoopFloat/27                31781 ns        31630 ns        22034
+BM_VectorTestLoopFloat/28                33161 ns        33008 ns        21133
+BM_VectorTestLoopFloat/29                34482 ns        34329 ns        20290
+BM_VectorTestLoopFloat/30                35676 ns        35531 ns        19434
+BM_VectorTestLoopFloat/31                37037 ns        36835 ns        19033
+BM_VectorTestLoopFloat/32                38379 ns        38178 ns        18409
+BM_VectorTestConstArraySizeFloat/1        1138 ns         1134 ns       605601
+BM_VectorTestConstArraySizeFloat/2        1551 ns         1546 ns       451139
+BM_VectorTestConstArraySizeFloat/3        2157 ns         2149 ns       326085
+BM_VectorTestConstArraySizeFloat/4        3082 ns         3070 ns       228235
+BM_VectorTestConstArraySizeFloat/5        3694 ns         3668 ns       191253
+BM_VectorTestConstArraySizeFloat/6        4708 ns         4691 ns       149290
+BM_VectorTestConstArraySizeFloat/7        5255 ns         5236 ns       133227
+BM_VectorTestConstArraySizeFloat/8        6239 ns         6217 ns       115033
+BM_VectorTestConstArraySizeFloat/9        7087 ns         7058 ns        99388
+BM_VectorTestConstArraySizeFloat/10       7640 ns         7613 ns        91195
+BM_VectorTestConstArraySizeFloat/11       8471 ns         8438 ns        83724
+BM_VectorTestConstArraySizeFloat/12       9132 ns         9101 ns        77836
+BM_VectorTestConstArraySizeFloat/13       9963 ns         9928 ns        71043
+BM_VectorTestConstArraySizeFloat/14      10601 ns        10565 ns        67362
+BM_VectorTestConstArraySizeFloat/15      11428 ns        11384 ns        61646
+BM_VectorTestConstArraySizeFloat/16      12061 ns        12017 ns        58708
+BM_VectorTestConstArraySizeFloat/17      13094 ns        13043 ns        53478
+BM_VectorTestConstArraySizeFloat/18      13624 ns        13553 ns        52138
+BM_VectorTestConstArraySizeFloat/19      15633 ns        15541 ns        45464
+BM_VectorTestConstArraySizeFloat/20      17379 ns        17299 ns        40665
+BM_VectorTestConstArraySizeFloat/21      20772 ns        20675 ns        34104
+BM_VectorTestConstArraySizeFloat/22      23613 ns        23485 ns        29856
+BM_VectorTestConstArraySizeFloat/23      24967 ns        24800 ns        28081
+BM_VectorTestConstArraySizeFloat/24      27395 ns        27278 ns        25481
+BM_VectorTestConstArraySizeFloat/25      28858 ns        28701 ns        24520
+BM_VectorTestConstArraySizeFloat/26      29251 ns        29068 ns        24195
+BM_VectorTestConstArraySizeFloat/27      31487 ns        31293 ns        22507
+BM_VectorTestConstArraySizeFloat/28      33355 ns        33137 ns        20929
+BM_VectorTestConstArraySizeFloat/29      34385 ns        34229 ns        20417
+BM_VectorTestConstArraySizeFloat/30      36031 ns        35811 ns        19543
+BM_VectorTestConstArraySizeFloat/31      37079 ns        36905 ns        19051
+BM_VectorTestConstArraySizeFloat/32      36857 ns        36715 ns        19077
+BM_VectorTestForcedIntrinsics/1           1163 ns         1159 ns       598027
+BM_VectorTestForcedIntrinsics/2           1175 ns         1170 ns       599275
+BM_VectorTestForcedIntrinsics/3           1680 ns         1673 ns       419149
+BM_VectorTestForcedIntrinsics/4           1210 ns         1205 ns       581791
+BM_VectorTestForcedIntrinsics/5           1874 ns         1867 ns       374320
+BM_VectorTestForcedIntrinsics/6           1954 ns         1946 ns       364700
+BM_VectorTestForcedIntrinsics/7           2763 ns         2753 ns       253086
+BM_VectorTestForcedIntrinsics/8           2057 ns         2049 ns       347318
+BM_VectorTestForcedIntrinsics/9           3186 ns         3175 ns       218684
+BM_VectorTestForcedIntrinsics/10          3112 ns         3101 ns       225780
+BM_VectorTestForcedIntrinsics/11          4044 ns         4023 ns       175125
+BM_VectorTestForcedIntrinsics/12          3088 ns         3077 ns       229106
+BM_VectorTestForcedIntrinsics/13          4405 ns         4388 ns       159480
+BM_VectorTestForcedIntrinsics/14          4248 ns         4232 ns       164753
+BM_VectorTestForcedIntrinsics/15          5018 ns         4983 ns       140497
+BM_VectorTestForcedIntrinsics/16          4131 ns         4095 ns       172113
+BM_VectorTestForcedIntrinsics/17          5714 ns         5679 ns       123282
+BM_VectorTestForcedIntrinsics/18          5387 ns         5358 ns       132204
+BM_VectorTestForcedIntrinsics/19          6515 ns         6481 ns       110209
+BM_VectorTestForcedIntrinsics/20          5108 ns         5081 ns       100000
+BM_VectorTestForcedIntrinsics/21          6913 ns         6876 ns       101935
+BM_VectorTestForcedIntrinsics/22          6564 ns         6517 ns       108434
+BM_VectorTestForcedIntrinsics/23          7763 ns         7718 ns        92602
+BM_VectorTestForcedIntrinsics/24          6184 ns         6132 ns       115958
+BM_VectorTestForcedIntrinsics/25          8152 ns         8099 ns        87568
+BM_VectorTestForcedIntrinsics/26          7720 ns         7674 ns        93561
+BM_VectorTestForcedIntrinsics/27          8977 ns         8919 ns        78819
+BM_VectorTestForcedIntrinsics/28          7206 ns         7153 ns        99046
+BM_VectorTestForcedIntrinsics/29          9373 ns         9310 ns        74948
+BM_VectorTestForcedIntrinsics/30          8888 ns         8830 ns        79500
+BM_VectorTestForcedIntrinsics/31         10233 ns        10163 ns        70094
+BM_VectorTestForcedIntrinsics/32          8209 ns         8139 ns        84943
+
+*/
+
+// A small subset of code from audio_utils/intrinsic_utils.h
+
+// We conditionally include neon optimizations for ARM devices
+#pragma push_macro("USE_NEON")
+#undef USE_NEON
+
+#if defined(__ARM_NEON__) || defined(__aarch64__)
+#include <arm_neon.h>
+#define USE_NEON
+#endif
+
+template <typename T>
+inline constexpr bool dependent_false_v = false;
+
+// Type of array embedded in a struct that is usable in the Neon template functions below.
+// This type must satisfy std::is_array_v<>.
+template<typename T, size_t N>
+struct internal_array_t {
+    T v[N];
+    static constexpr size_t size() { return N; }
+};
+
+#ifdef USE_NEON
+
+template<int N>
+struct vfloat_struct {};
+
+template<int N>
+using vfloat_t = typename vfloat_struct<N>::t;  // typnemae required for Android 14 and earlier.
+
+template<typename F, int N>
+using vector_hw_t = std::conditional_t<
+        std::is_same_v<F, float>, vfloat_t<N>, internal_array_t<F, N>>;
+
+// Recursively define the NEON types required for a given vector size.
+// intrinsic_utils.h allows structurally recursive type definitions based on
+// pairs of types (much like Lisp list cons pairs).
+template<>
+struct vfloat_struct<1> { using t = float; };
+template<>
+struct vfloat_struct<2> { using t = float32x2_t; };
+template<>
+struct vfloat_struct<3> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<2> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<4> { using t = float32x4_t; };
+template<>
+struct vfloat_struct<5> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<6> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<7> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<8> { using t = float32x4x2_t; };
+template<>
+struct vfloat_struct<9> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<10> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<11> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<12> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<4> b; } s; }; };
+template<>
+struct vfloat_struct<13> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<5> b; } s; }; };
+template<>
+struct vfloat_struct<14> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<6> b; } s; }; };
+template<>
+struct vfloat_struct<15> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<7> b; } s; }; };
+template<>
+struct vfloat_struct<16> { using t = float32x4x4_t; };
+template<>
+struct vfloat_struct<17> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<18> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<19> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<20> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<4> b; } s; }; };
+template<>
+struct vfloat_struct<21> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<5> b; } s; }; };
+template<>
+struct vfloat_struct<22> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<6> b; } s; }; };
+template<>
+struct vfloat_struct<23> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<7> b; } s; }; };
+template<>
+struct vfloat_struct<24> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<8> b; } s; }; };
+template<>
+struct vfloat_struct<25> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<9> b; } s; }; };
+template<>
+struct vfloat_struct<26> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<10> b; } s; }; };
+template<>
+struct vfloat_struct<27> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<11> b; } s; }; };
+template<>
+struct vfloat_struct<28> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<12> b; } s; }; };
+template<>
+struct vfloat_struct<29> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<13> b; } s; }; };
+template<>
+struct vfloat_struct<30> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<14> b; } s; }; };
+template<>
+struct vfloat_struct<31> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<15> b; } s; }; };
+template<>
+struct vfloat_struct<32> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<16> b; } s; }; };
+
+#else
+
+// use loop vectorization if no HW type exists.
+template<typename F, int N>
+using vector_hw_t = internal_array_t<F, N>;
+
+#endif
+
+template<typename T>
+static inline T vmul(T a, T b) {
+    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
+        return a * b;
+
+#ifdef USE_NEON
+    } else if constexpr (std::is_same_v<T, float32x2_t>) {
+        return vmul_f32(a, b);
+    } else if constexpr (std::is_same_v<T, float32x4_t>) {
+        return vmulq_f32(a, b);
+#if defined(__aarch64__)
+    } else if constexpr (std::is_same_v<T, float64x2_t>) {
+        return vmulq_f64(a, b);
+#endif
+#endif // USE_NEON
+
+    } else /* constexpr */ {
+        T ret;
+        auto &[retval] = ret;  // single-member struct
+        const auto &[aval] = a;
+        const auto &[bval] = b;
+        if constexpr (std::is_array_v<decltype(retval)>) {
+#pragma unroll
+            for (size_t i = 0; i < std::size(aval); ++i) {
+                retval[i] = vmul(aval[i], bval[i]);
+            }
+            return ret;
+        } else /* constexpr */ {
+             auto &[r1, r2] = retval;
+             const auto &[a1, a2] = aval;
+             const auto &[b1, b2] = bval;
+             r1 = vmul(a1, b1);
+             r2 = vmul(a2, b2);
+             return ret;
+        }
+    }
+}
+
+#pragma pop_macro("USE_NEON")
+
+// end intrinsics subset
+
+static constexpr size_t kDataSize = 2048;
+
+static void TestArgs(benchmark::internal::Benchmark* b) {
+    constexpr int kChannelCountMin = 1;
+    constexpr int kChannelCountMax = 32;
+    for (int i = kChannelCountMin; i <= kChannelCountMax; ++i) {
+        b->Args({i});
+    }
+}
+
+// Macro test operator
+
+#define OPERATOR(N) \
+    *reinterpret_cast<V<F, N>*>(out) = vmul( \
+    *reinterpret_cast<const V<F, N>*>(in1), \
+    *reinterpret_cast<const V<F, N>*>(in2)); \
+    out += N; \
+    in1 += N; \
+    in2 += N;
+
+// Macro to instantiate switch case statements.
+
+#define INSTANTIATE(N) \
+    case N: \
+    mFunc = [](F* out, const F* in1, const F* in2, size_t count) { \
+        static_assert(sizeof(V<F, N>) == N * sizeof(F)); \
+        for (size_t i = 0; i < count; ++i) { \
+            OPERATOR(N); \
+        } \
+    }; \
+    break;
+
+template <typename Traits>
+class Processor {
+public:
+    // shorthand aliases
+    using F = typename Traits::data_t;
+    template <typename T, int N>
+    using V = typename Traits::template container_t<T, N>;
+
+    Processor(int channelCount)
+        : mChannelCount(channelCount) {
+
+        if constexpr (Traits::loop_) {
+            mFunc = [channelCount](F* out, const F* in1, const F* in2, size_t count) {
+                for (size_t i = 0; i < count; ++i) {
+                    for (size_t j = 0; j < channelCount; ++j) {
+                        OPERATOR(1);
+                    }
+                }
+            };
+            return;
+        }
+        switch (channelCount) {
+        INSTANTIATE(1);
+        INSTANTIATE(2);
+        INSTANTIATE(3);
+        INSTANTIATE(4);
+        INSTANTIATE(5);
+        INSTANTIATE(6);
+        INSTANTIATE(7);
+        INSTANTIATE(8);
+        INSTANTIATE(9);
+        INSTANTIATE(10);
+        INSTANTIATE(11);
+        INSTANTIATE(12);
+        INSTANTIATE(13);
+        INSTANTIATE(14);
+        INSTANTIATE(15);
+        INSTANTIATE(16);
+        INSTANTIATE(17);
+        INSTANTIATE(18);
+        INSTANTIATE(19);
+        INSTANTIATE(20);
+        INSTANTIATE(21);
+        INSTANTIATE(22);
+        INSTANTIATE(23);
+        INSTANTIATE(24);
+        INSTANTIATE(25);
+        INSTANTIATE(26);
+        INSTANTIATE(27);
+        INSTANTIATE(28);
+        INSTANTIATE(29);
+        INSTANTIATE(30);
+        INSTANTIATE(31);
+        INSTANTIATE(32);
+        }
+    }
+
+    void process(F* out, const F* in1, const F* in2, size_t frames) {
+        mFunc(out, in1, in2, frames);
+    }
+
+    const size_t mChannelCount;
+    /* const */ std::function<void(F*, const F*, const F*, size_t)> mFunc;
+};
+
+template <typename Traits>
+static void BM_VectorTest(benchmark::State& state) {
+    using F = typename Traits::data_t;
+    const size_t channelCount = state.range(0);
+
+    std::vector<F> input1(kDataSize * channelCount);
+    std::vector<F> input2(kDataSize * channelCount);
+    std::vector<F> output(kDataSize * channelCount);
+
+    // Initialize input buffer and coefs with deterministic pseudo-random values
+    std::minstd_rand gen(42);
+    const F amplitude = 1.;
+    std::uniform_real_distribution<> dis(-amplitude, amplitude);
+    for (auto& in : input1) {
+        in = dis(gen);
+    }
+    for (auto& in : input2) {
+        in = dis(gen);
+    }
+
+    Processor<Traits> processor(channelCount);
+
+    // Run the test
+    while (state.KeepRunning()) {
+        benchmark::DoNotOptimize(input1.data());
+        benchmark::DoNotOptimize(input2.data());
+        benchmark::DoNotOptimize(output.data());
+        processor.process(output.data(), input1.data(), input2.data(), kDataSize);
+        benchmark::ClobberMemory();
+    }
+    state.SetComplexityN(channelCount);
+}
+
+// Clang has an issue with -frelaxed-template-template-args where
+// it may not follow the C++17 guidelines.  Use a traits struct to
+// pass in parameters.
+
+// Test using two loops.
+struct LoopFloatTraits {
+    template <typename F, int N>
+    using container_t = internal_array_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = true;
+};
+static void BM_VectorTestLoopFloat(benchmark::State& state) {
+    BM_VectorTest<LoopFloatTraits>(state);
+}
+
+// Test using two loops, the inner loop is constexpr size.
+struct ConstArraySizeFloatTraits {
+    template <typename F, int N>
+    using container_t = internal_array_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = false;
+};
+static void BM_VectorTestConstArraySizeFloat(benchmark::State& state) {
+    BM_VectorTest<ConstArraySizeFloatTraits>(state);
+}
+
+// Test using intrinsics, if available.
+struct ForcedIntrinsicsTraits {
+    template <typename F, int N>
+    using container_t = vector_hw_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = false;
+};
+static void BM_VectorTestForcedIntrinsics(benchmark::State& state) {
+    BM_VectorTest<ForcedIntrinsicsTraits>(state);
+}
+
+BENCHMARK(BM_VectorTestLoopFloat)->Apply(TestArgs);
+
+BENCHMARK(BM_VectorTestConstArraySizeFloat)->Apply(TestArgs);
+
+BENCHMARK(BM_VectorTestForcedIntrinsics)->Apply(TestArgs);
+
+BENCHMARK_MAIN();
diff --git a/audio_utils/benchmarks/channelmix_benchmark.cpp b/audio_utils/benchmarks/channelmix_benchmark.cpp
index 022ee579..a76d48c5 100644
--- a/audio_utils/benchmarks/channelmix_benchmark.cpp
+++ b/audio_utils/benchmarks/channelmix_benchmark.cpp
@@ -43,8 +43,8 @@ static constexpr audio_channel_mask_t kChannelPositionMasks[] = {
     AUDIO_CHANNEL_OUT_5POINT1POINT4,
     AUDIO_CHANNEL_OUT_7POINT1POINT2,
     AUDIO_CHANNEL_OUT_7POINT1POINT4,
+    AUDIO_CHANNEL_OUT_13POINT0,
     AUDIO_CHANNEL_OUT_9POINT1POINT6,
-    AUDIO_CHANNEL_OUT_13POINT_360RA,
     AUDIO_CHANNEL_OUT_22POINT2,
 };
 
diff --git a/audio_utils/benchmarks/intrinsic_benchmark.cpp b/audio_utils/benchmarks/intrinsic_benchmark.cpp
index b5aa7bcf..3ebe05de 100644
--- a/audio_utils/benchmarks/intrinsic_benchmark.cpp
+++ b/audio_utils/benchmarks/intrinsic_benchmark.cpp
@@ -25,55 +25,410 @@
 #include <audio_utils/intrinsic_utils.h>
 #include <audio_utils/format.h>
 
-static void BM_Intrinsic(benchmark::State& state) {
-    using D = float;
-    using namespace android::audio_utils::intrinsics;
-    constexpr size_t SIMD_LENGTH = 4;
-
-    // Possible testing types:
-    using vec = android::audio_utils::intrinsics::internal_array_t<D, SIMD_LENGTH>;
-    //using vec = float32x4_t;
-    //using vec = float32x4x4_t;
-
-    constexpr size_t DATA_SIZE = 1024;
-    D a[DATA_SIZE];
-    D b[DATA_SIZE];
-    D c[DATA_SIZE];
-    D d[DATA_SIZE];
-
-    constexpr std::minstd_rand::result_type SEED = 42; // arbitrary choice.
-    std::minstd_rand gen(SEED);
-    const D amplitude = 1.0f;
+/**
+Pixel 6 Pro (using Android 14 clang)
+
+---------------------------------------------------------------------------------
+Benchmark                                       Time             CPU   Iterations
+---------------------------------------------------------------------------------
+BM_VectorTestMulLoopFloat/1                  1199 ns         1195 ns       583505
+BM_VectorTestMulLoopFloat/2                  2255 ns         2248 ns       317302
+BM_VectorTestMulLoopFloat/4                  4454 ns         4438 ns       158692
+BM_VectorTestMulLoopFloat/7                  7786 ns         7757 ns        90247
+BM_VectorTestMulLoopFloat/8                  8995 ns         8962 ns        76373
+BM_VectorTestMulLoopFloat/15                17131 ns        17066 ns        41214
+BM_VectorTestMulLoopFloat/16                18439 ns        18341 ns        38319
+BM_VectorTestMulConstArraySizeFloat/1         183 ns          182 ns      3938572
+BM_VectorTestMulConstArraySizeFloat/2         640 ns          638 ns      1113513
+BM_VectorTestMulConstArraySizeFloat/3        2102 ns         2093 ns       331829
+BM_VectorTestMulConstArraySizeFloat/4        3771 ns         3758 ns       185266
+BM_VectorTestMulConstArraySizeFloat/5        1825 ns         1818 ns       382081
+BM_VectorTestMulConstArraySizeFloat/6        1905 ns         1898 ns       370506
+BM_VectorTestMulConstArraySizeFloat/7        2745 ns         2734 ns       256104
+BM_VectorTestMulConstArraySizeFloat/8        2010 ns         2002 ns       351298
+BM_VectorTestMulConstArraySizeFloat/9        3158 ns         3146 ns       222887
+BM_VectorTestMulConstArraySizeFloat/10       3018 ns         3007 ns       233799
+BM_VectorTestMulConstArraySizeFloat/11       4005 ns         3991 ns       176145
+BM_VectorTestMulConstArraySizeFloat/12       3081 ns         3068 ns       228512
+BM_VectorTestMulConstArraySizeFloat/13       4409 ns         4393 ns       159303
+BM_VectorTestMulConstArraySizeFloat/14       4242 ns         4219 ns       165899
+BM_VectorTestMulConstArraySizeFloat/15       5301 ns         5279 ns       134157
+BM_VectorTestMulConstArraySizeFloat/16       4078 ns         4063 ns       174066
+BM_VectorTestMulConstArraySizeFloat/17       5693 ns         5669 ns       125403
+BM_VectorTestMulConstArraySizeFloat/18       5339 ns         5318 ns       131839
+BM_VectorTestMulConstArraySizeFloat/19       6508 ns         6483 ns       108158
+BM_VectorTestMulConstArraySizeFloat/20       5108 ns         5089 ns       139637
+BM_VectorTestMulConstArraySizeFloat/21       6896 ns         6868 ns       102084
+BM_VectorTestMulConstArraySizeFloat/22       6523 ns         6490 ns       109281
+BM_VectorTestMulConstArraySizeFloat/23       7734 ns         7686 ns        92986
+BM_VectorTestMulConstArraySizeFloat/24       6138 ns         6071 ns       116883
+BM_VectorTestMulConstArraySizeFloat/25       8122 ns         8085 ns        86703
+BM_VectorTestMulConstArraySizeFloat/26       7670 ns         7637 ns        91665
+BM_VectorTestMulConstArraySizeFloat/27       9026 ns         8988 ns        78633
+BM_VectorTestMulConstArraySizeFloat/28       7161 ns         7129 ns        99711
+BM_VectorTestMulConstArraySizeFloat/29       9380 ns         9341 ns        75947
+BM_VectorTestMulConstArraySizeFloat/30       8878 ns         8838 ns        79578
+BM_VectorTestMulConstArraySizeFloat/31      10277 ns        10230 ns        67954
+BM_VectorTestMulConstArraySizeFloat/32       8122 ns         8083 ns        87244
+BM_VectorTestMulForcedIntrinsics/1            188 ns          187 ns      3628943
+BM_VectorTestMulForcedIntrinsics/2           1184 ns         1180 ns       565704
+BM_VectorTestMulForcedIntrinsics/3           1692 ns         1684 ns       414409
+BM_VectorTestMulForcedIntrinsics/4           1227 ns         1222 ns       578638
+BM_VectorTestMulForcedIntrinsics/5           1885 ns         1878 ns       366852
+BM_VectorTestMulForcedIntrinsics/6           1984 ns         1976 ns       352979
+BM_VectorTestMulForcedIntrinsics/7           2815 ns         2803 ns       249306
+BM_VectorTestMulForcedIntrinsics/8           2081 ns         2073 ns       339434
+BM_VectorTestMulForcedIntrinsics/9           3051 ns         3040 ns       229261
+BM_VectorTestMulForcedIntrinsics/10          3198 ns         3187 ns       220889
+BM_VectorTestMulForcedIntrinsics/11          4083 ns         4067 ns       171785
+BM_VectorTestMulForcedIntrinsics/12          3167 ns         3156 ns       221858
+BM_VectorTestMulForcedIntrinsics/13          4497 ns         4479 ns       156926
+BM_VectorTestMulForcedIntrinsics/14          4339 ns         4323 ns       162496
+BM_VectorTestMulForcedIntrinsics/15          5294 ns         5274 ns       135733
+BM_VectorTestMulForcedIntrinsics/16          4167 ns         4150 ns       168642
+BM_VectorTestMulForcedIntrinsics/17          5732 ns         5710 ns       122927
+BM_VectorTestMulForcedIntrinsics/18          5449 ns         5424 ns       131800
+BM_VectorTestMulForcedIntrinsics/19          6539 ns         6504 ns       107850
+BM_VectorTestMulForcedIntrinsics/20          5219 ns         5198 ns       135148
+BM_VectorTestMulForcedIntrinsics/21          6676 ns         6639 ns       105846
+BM_VectorTestMulForcedIntrinsics/22          6618 ns         6589 ns       107258
+BM_VectorTestMulForcedIntrinsics/23          7774 ns         7741 ns        90216
+BM_VectorTestMulForcedIntrinsics/24          6231 ns         6201 ns       116996
+BM_VectorTestMulForcedIntrinsics/25          8156 ns         8121 ns        86237
+BM_VectorTestMulForcedIntrinsics/26          7615 ns         7578 ns        91086
+BM_VectorTestMulForcedIntrinsics/27          9067 ns         8995 ns        76733
+BM_VectorTestMulForcedIntrinsics/28          7090 ns         7031 ns       101117
+BM_VectorTestMulForcedIntrinsics/29          9220 ns         9160 ns        76350
+BM_VectorTestMulForcedIntrinsics/30          8895 ns         8832 ns        80551
+BM_VectorTestMulForcedIntrinsics/31         10060 ns        10001 ns        71265
+BM_VectorTestMulForcedIntrinsics/32          8056 ns         7996 ns        88176
+BM_VectorTestAddConstArraySizeFloat/1         188 ns          187 ns      3742628
+BM_VectorTestAddConstArraySizeFloat/2         634 ns          631 ns      1095480
+BM_VectorTestAddConstArraySizeFloat/4        3723 ns         3710 ns       188332
+BM_VectorTestAddConstArraySizeFloat/7        2791 ns         2777 ns       252911
+BM_VectorTestAddConstArraySizeFloat/8        2060 ns         2051 ns       345573
+BM_VectorTestAddConstArraySizeFloat/15       5322 ns         5302 ns       132415
+BM_VectorTestAddConstArraySizeFloat/16       4101 ns         4083 ns       170300
+BM_VectorTestAddForcedIntrinsics/1            187 ns          186 ns      3656441
+BM_VectorTestAddForcedIntrinsics/2           1184 ns         1178 ns       564643
+BM_VectorTestAddForcedIntrinsics/4           1218 ns         1213 ns       584709
+BM_VectorTestAddForcedIntrinsics/7           2775 ns         2764 ns       252256
+BM_VectorTestAddForcedIntrinsics/8           2070 ns         2062 ns       342709
+BM_VectorTestAddForcedIntrinsics/15          5213 ns         5192 ns       132663
+BM_VectorTestAddForcedIntrinsics/16          4116 ns         4100 ns       171005
+
+
+Pixel 9 XL Pro (using Android 14 clang)
+---------------------------------------------------------------------------------
+Benchmark                                       Time             CPU   Iterations
+---------------------------------------------------------------------------------
+BM_VectorTestMulLoopFloat/1                  1171 ns         1166 ns       450848
+BM_VectorTestMulLoopFloat/2                  1847 ns         1840 ns       381613
+BM_VectorTestMulLoopFloat/4                  3432 ns         3423 ns       205730
+BM_VectorTestMulLoopFloat/7                  5615 ns         5598 ns       124818
+BM_VectorTestMulLoopFloat/8                  6411 ns         6383 ns       109013
+BM_VectorTestMulLoopFloat/15                12371 ns        12332 ns        55439
+BM_VectorTestMulLoopFloat/16                13594 ns        13555 ns        51753
+BM_VectorTestMulConstArraySizeFloat/1         153 ns          152 ns      4534625
+BM_VectorTestMulConstArraySizeFloat/2         683 ns          680 ns      1005789
+BM_VectorTestMulConstArraySizeFloat/3         886 ns          883 ns       803793
+BM_VectorTestMulConstArraySizeFloat/4        1491 ns         1487 ns       471683
+BM_VectorTestMulConstArraySizeFloat/5        1448 ns         1443 ns       486353
+BM_VectorTestMulConstArraySizeFloat/6        1482 ns         1478 ns       474901
+BM_VectorTestMulConstArraySizeFloat/7        2279 ns         2272 ns       308978
+BM_VectorTestMulConstArraySizeFloat/8        1620 ns         1600 ns       438957
+BM_VectorTestMulConstArraySizeFloat/9        2505 ns         2487 ns       283335
+BM_VectorTestMulConstArraySizeFloat/10       2389 ns         2386 ns       293332
+BM_VectorTestMulConstArraySizeFloat/11       3185 ns         3180 ns       219746
+BM_VectorTestMulConstArraySizeFloat/12       2285 ns         2280 ns       307091
+BM_VectorTestMulConstArraySizeFloat/13       3464 ns         3459 ns       201902
+BM_VectorTestMulConstArraySizeFloat/14       3254 ns         3249 ns       215345
+BM_VectorTestMulConstArraySizeFloat/15       4156 ns         4149 ns       169102
+BM_VectorTestMulConstArraySizeFloat/16       3075 ns         3068 ns       228544
+BM_VectorTestMulConstArraySizeFloat/17       4469 ns         4442 ns       157317
+BM_VectorTestMulConstArraySizeFloat/18       4141 ns         4133 ns       170148
+BM_VectorTestMulConstArraySizeFloat/19       5193 ns         5179 ns       135294
+BM_VectorTestMulConstArraySizeFloat/20       3876 ns         3866 ns       181134
+BM_VectorTestMulConstArraySizeFloat/21       5450 ns         5429 ns       129921
+BM_VectorTestMulConstArraySizeFloat/22       5075 ns         5056 ns       139238
+BM_VectorTestMulConstArraySizeFloat/23       6145 ns         6125 ns       114880
+BM_VectorTestMulConstArraySizeFloat/24       4659 ns         4646 ns       150923
+BM_VectorTestMulConstArraySizeFloat/25       6423 ns         6400 ns       109467
+BM_VectorTestMulConstArraySizeFloat/26       5962 ns         5947 ns       117755
+BM_VectorTestMulConstArraySizeFloat/27       7139 ns         7115 ns        98581
+BM_VectorTestMulConstArraySizeFloat/28       5462 ns         5446 ns       128477
+BM_VectorTestMulConstArraySizeFloat/29       7431 ns         7399 ns        94492
+BM_VectorTestMulConstArraySizeFloat/30       6877 ns         6854 ns       101706
+BM_VectorTestMulConstArraySizeFloat/31       8322 ns         8304 ns        83352
+BM_VectorTestMulConstArraySizeFloat/32       6223 ns         6208 ns       114265
+BM_VectorTestMulForcedIntrinsics/1            160 ns          160 ns      4365646
+BM_VectorTestMulForcedIntrinsics/2            848 ns          845 ns       807945
+BM_VectorTestMulForcedIntrinsics/3           1435 ns         1430 ns       489448
+BM_VectorTestMulForcedIntrinsics/4            937 ns          934 ns       757416
+BM_VectorTestMulForcedIntrinsics/5           1477 ns         1473 ns       474891
+BM_VectorTestMulForcedIntrinsics/6           1825 ns         1820 ns       385118
+BM_VectorTestMulForcedIntrinsics/7           2303 ns         2298 ns       303823
+BM_VectorTestMulForcedIntrinsics/8           1643 ns         1638 ns       430851
+BM_VectorTestMulForcedIntrinsics/9           2490 ns         2482 ns       281294
+BM_VectorTestMulForcedIntrinsics/10          2429 ns         2423 ns       291028
+BM_VectorTestMulForcedIntrinsics/11          3201 ns         3193 ns       219256
+BM_VectorTestMulForcedIntrinsics/12          2341 ns         2335 ns       302086
+BM_VectorTestMulForcedIntrinsics/13          3475 ns         3466 ns       201570
+BM_VectorTestMulForcedIntrinsics/14          3294 ns         3286 ns       212762
+BM_VectorTestMulForcedIntrinsics/15          4141 ns         4129 ns       169275
+BM_VectorTestMulForcedIntrinsics/16          3123 ns         3116 ns       225516
+BM_VectorTestMulForcedIntrinsics/17          4447 ns         4436 ns       157620
+BM_VectorTestMulForcedIntrinsics/18          4175 ns         4163 ns       168170
+BM_VectorTestMulForcedIntrinsics/19          5164 ns         5147 ns       134830
+BM_VectorTestMulForcedIntrinsics/20          3927 ns         3917 ns       179070
+BM_VectorTestMulForcedIntrinsics/21          5481 ns         5449 ns       126196
+BM_VectorTestMulForcedIntrinsics/22          5124 ns         5109 ns       138492
+BM_VectorTestMulForcedIntrinsics/23          6142 ns         6125 ns       113071
+BM_VectorTestMulForcedIntrinsics/24          4690 ns         4675 ns       150096
+BM_VectorTestMulForcedIntrinsics/25          6423 ns         6398 ns       108462
+BM_VectorTestMulForcedIntrinsics/26          6047 ns         6029 ns       117408
+BM_VectorTestMulForcedIntrinsics/27          7150 ns         7128 ns        97901
+BM_VectorTestMulForcedIntrinsics/28          5483 ns         5467 ns       129504
+BM_VectorTestMulForcedIntrinsics/29          7416 ns         7390 ns        94167
+BM_VectorTestMulForcedIntrinsics/30          6960 ns         6934 ns       102061
+BM_VectorTestMulForcedIntrinsics/31          8073 ns         8043 ns        87555
+BM_VectorTestMulForcedIntrinsics/32          6255 ns         6235 ns       113705
+BM_VectorTestAddConstArraySizeFloat/1         161 ns          161 ns      4339090
+BM_VectorTestAddConstArraySizeFloat/2         718 ns          716 ns       958914
+BM_VectorTestAddConstArraySizeFloat/4        1500 ns         1496 ns       468059
+BM_VectorTestAddConstArraySizeFloat/7        2334 ns         2326 ns       301694
+BM_VectorTestAddConstArraySizeFloat/8        1655 ns         1651 ns       428569
+BM_VectorTestAddConstArraySizeFloat/15       4224 ns         4214 ns       166108
+BM_VectorTestAddConstArraySizeFloat/16       3229 ns         3219 ns       217681
+BM_VectorTestAddForcedIntrinsics/1            164 ns          163 ns      4286279
+BM_VectorTestAddForcedIntrinsics/2            858 ns          854 ns       795537
+BM_VectorTestAddForcedIntrinsics/4            927 ns          924 ns       761731
+BM_VectorTestAddForcedIntrinsics/7           2333 ns         2325 ns       301963
+BM_VectorTestAddForcedIntrinsics/8           1658 ns         1654 ns       425574
+BM_VectorTestAddForcedIntrinsics/15          4096 ns         4087 ns       171278
+BM_VectorTestAddForcedIntrinsics/16          3245 ns         3236 ns       217538
+
+*/
+
+using namespace android::audio_utils::intrinsics;
+
+static constexpr size_t kDataSize = 2048;
+
+// exhaustively go from 1-32 channels.
+static void TestFullArgs(benchmark::internal::Benchmark* b) {
+    constexpr int kChannelCountMin = 1;
+    constexpr int kChannelCountMax = 32;
+    for (int i = kChannelCountMin; i <= kChannelCountMax; ++i) {
+        b->Args({i});
+    }
+}
+
+// selective channels to test.
+static void TestArgs(benchmark::internal::Benchmark* b) {
+    for (int i : { 1, 2, 4, 7, 8, 15, 16 }) {
+        b->Args({i});
+    }
+}
+
+// Macro test operator
+
+#define OPERATOR(N) \
+    *reinterpret_cast<V<F, N>*>(out) = Traits::func_( \
+    *reinterpret_cast<const V<F, N>*>(in1), \
+    *reinterpret_cast<const V<F, N>*>(in2)); \
+    out += N; \
+    in1 += N; \
+    in2 += N;
+
+// Macro to instantiate switch case statements.
+
+#define INSTANTIATE(N) case N: mFunc = TestFunc<N>;  break;
+
+template <typename Traits>
+class Processor {
+public:
+    // shorthand aliases
+    using F = typename Traits::data_t;
+    template <typename T, int N>
+    using V = typename Traits::template container_t<T, N>;
+    template <size_t N>
+    static void TestFunc(F* out, const F* in1, const F* in2, size_t count) {
+        static_assert(sizeof(V<F, N>) == N * sizeof(F));
+        for (size_t i = 0; i < count; ++i) {
+            OPERATOR(N);
+        }
+    }
+
+    Processor(int channelCount)
+        : mChannelCount(channelCount) {
+
+        if constexpr (Traits::loop_) {
+            mFunc = [channelCount](F* out, const F* in1, const F* in2, size_t count) {
+                for (size_t i = 0; i < count; ++i) {
+                    for (size_t j = 0; j < channelCount; ++j) {
+                        OPERATOR(1);
+                    }
+                }
+            };
+            return;
+        }
+        switch (channelCount) {
+        INSTANTIATE(1);
+        INSTANTIATE(2);
+        INSTANTIATE(3);
+        INSTANTIATE(4);
+        INSTANTIATE(5);
+        INSTANTIATE(6);
+        INSTANTIATE(7);
+        INSTANTIATE(8);
+        INSTANTIATE(9);
+        INSTANTIATE(10);
+        INSTANTIATE(11);
+        INSTANTIATE(12);
+        INSTANTIATE(13);
+        INSTANTIATE(14);
+        INSTANTIATE(15);
+        INSTANTIATE(16);
+        INSTANTIATE(17);
+        INSTANTIATE(18);
+        INSTANTIATE(19);
+        INSTANTIATE(20);
+        INSTANTIATE(21);
+        INSTANTIATE(22);
+        INSTANTIATE(23);
+        INSTANTIATE(24);
+        INSTANTIATE(25);
+        INSTANTIATE(26);
+        INSTANTIATE(27);
+        INSTANTIATE(28);
+        INSTANTIATE(29);
+        INSTANTIATE(30);
+        INSTANTIATE(31);
+        INSTANTIATE(32);
+        }
+    }
+
+    void process(F* out, const F* in1, const F* in2, size_t frames) {
+        mFunc(out, in1, in2, frames);
+    }
+
+    const size_t mChannelCount;
+    /* const */ std::function<void(F*, const F*, const F*, size_t)> mFunc;
+};
+
+template <typename Traits>
+static void BM_VectorTest(benchmark::State& state) {
+    using F = typename Traits::data_t;
+    const size_t channelCount = state.range(0);
+
+    std::vector<F> input1(kDataSize * channelCount);
+    std::vector<F> input2(kDataSize * channelCount);
+    std::vector<F> output(kDataSize * channelCount);
+
+    // Initialize input buffer and coefs with deterministic pseudo-random values
+    std::minstd_rand gen(42);
+    const F amplitude = 1.;
     std::uniform_real_distribution<> dis(-amplitude, amplitude);
-    for (size_t i = 0; i < DATA_SIZE; ++i) {
-        a[i] = dis(gen);
-        b[i] = dis(gen);
-        c[i] = dis(gen);
+    for (auto& in : input1) {
+        in = dis(gen);
+    }
+    for (auto& in : input2) {
+        in = dis(gen);
     }
 
+    Processor<Traits> processor(channelCount);
+
+    // Run the test
     while (state.KeepRunning()) {
-        for (size_t i = 0; i < DATA_SIZE; i += sizeof(vec) / sizeof(D)) {
-            const vec av = vld1<vec>(a + i);
-            const vec bv = vld1<vec>(b + i);
-            const vec cv = vld1<vec>(c + i);
-            const vec dv = vmla(cv, av, bv);
-            vst1(d + i, dv);
-        }
-        benchmark::DoNotOptimize(d[0]);
+        benchmark::DoNotOptimize(input1.data());
+        benchmark::DoNotOptimize(input2.data());
+        benchmark::DoNotOptimize(output.data());
+        processor.process(output.data(), input1.data(), input2.data(), kDataSize);
         benchmark::ClobberMemory();
     }
-    //fprintf(stderr, "%f: %f %f\n %f", d[0], c[0], a[0], b[0]);
-    state.SetComplexityN(state.range(0));
+    state.SetComplexityN(channelCount);
 }
 
-// A simple test using the VMLA intrinsic.
-// One can alter either the intrinsic code or the compilation flags to see the benefit.
-// Recommend using objdump to view the assembly.
-static void BM_IntrinsicArgs(benchmark::internal::Benchmark* b) {
-    for (int k = 0; k < 2; k++) // 0 for normal random data, 1 for subnormal random data
-         b->Args({k});
+// Clang has an issue with -frelaxed-template-template-args where
+// it may not follow the C++17 guidelines.  Use a traits struct to
+// pass in parameters.
+
+// Test using two loops.
+struct LoopFloatTraits {
+    template <typename F, int N>
+    using container_t = internal_array_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = true;
+};
+
+// Test using two loops, the inner loop is constexpr size.
+struct ConstArraySizeFloatTraits {
+    template <typename F, int N>
+    using container_t = internal_array_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = false;
+};
+
+// Test using intrinsics, if available.
+struct ForcedIntrinsicsTraits {
+    template <typename F, int N>
+    using container_t = vector_hw_t<F, N>;
+    using data_t = float;
+    static constexpr bool loop_ = false;
+};
+
+// --- MULTIPLY
+
+struct MulFunc {
+    template <typename T>
+    static T func_(T a, T b) { return vmul(a, b); }
+};
+
+struct MulLoopFloatTraits : public LoopFloatTraits, public MulFunc {};
+
+static void BM_VectorTestMulLoopFloat(benchmark::State& state) {
+    BM_VectorTest<MulLoopFloatTraits>(state);
 }
 
-BENCHMARK(BM_Intrinsic)->Apply(BM_IntrinsicArgs);
+struct MulConstArraySizeFloatTraits : public ConstArraySizeFloatTraits, public MulFunc {};
+
+static void BM_VectorTestMulConstArraySizeFloat(benchmark::State& state) {
+    BM_VectorTest<MulConstArraySizeFloatTraits>(state);
+}
+
+struct MulForcedIntrinsicsTraits : public ForcedIntrinsicsTraits, public MulFunc {};
+
+static void BM_VectorTestMulForcedIntrinsics(benchmark::State& state) {
+    BM_VectorTest<MulForcedIntrinsicsTraits>(state);
+}
+
+BENCHMARK(BM_VectorTestMulLoopFloat)->Apply(TestArgs);
+
+BENCHMARK(BM_VectorTestMulConstArraySizeFloat)->Apply(TestFullArgs);
+
+BENCHMARK(BM_VectorTestMulForcedIntrinsics)->Apply(TestFullArgs);
+
+// --- ADD
+
+struct AddFunc {
+    template <typename T>
+    static T func_(T a, T b) { return vadd(a, b); }
+};
+
+struct AddConstArraySizeFloatTraits : public ConstArraySizeFloatTraits, public AddFunc {};
+
+static void BM_VectorTestAddConstArraySizeFloat(benchmark::State& state) {
+    BM_VectorTest<AddConstArraySizeFloatTraits>(state);
+}
+
+struct AddForcedIntrinsicsTraits : public ForcedIntrinsicsTraits, public AddFunc {};
+
+static void BM_VectorTestAddForcedIntrinsics(benchmark::State& state) {
+    BM_VectorTest<AddForcedIntrinsicsTraits>(state);
+}
+
+BENCHMARK(BM_VectorTestAddConstArraySizeFloat)->Apply(TestArgs);
+
+BENCHMARK(BM_VectorTestAddForcedIntrinsics)->Apply(TestArgs);
 
 BENCHMARK_MAIN();
diff --git a/audio_utils/include/audio_utils/BiquadFilter.h b/audio_utils/include/audio_utils/BiquadFilter.h
index 6f3d34f9..8918b2ec 100644
--- a/audio_utils/include/audio_utils/BiquadFilter.h
+++ b/audio_utils/include/audio_utils/BiquadFilter.h
@@ -18,6 +18,7 @@
 
 #include "intrinsic_utils.h"
 
+#include <algorithm>
 #include <array>
 #include <cmath>
 #include <functional>
diff --git a/audio_utils/include/audio_utils/FdToString.h b/audio_utils/include/audio_utils/FdToString.h
index 64cb875d..b03ba43e 100644
--- a/audio_utils/include/audio_utils/FdToString.h
+++ b/audio_utils/include/audio_utils/FdToString.h
@@ -35,106 +35,6 @@
 namespace android {
 namespace audio_utils {
 
-/**
- * FdToStringOldImpl
- *
- * Captures string data written to a file descriptor.
- * The class will furnish a writable file descriptor by fd().
- * The string may be read through closeAndGetString().
- */
-class FdToStringOldImpl {
-  public:
-    /**
-     * \param prefix is the prefix string prepended to each new line.
-     * \param timeoutMs is the total timeout to wait for obtaining data in milliseconds.
-     */
-    explicit FdToStringOldImpl(const std::string& prefix = "- ", int timeoutMs = 200)
-        : mPrefix(prefix), mTimeoutTimeNs(systemTime() + timeoutMs * NANOS_PER_MILLISECOND) {
-        const int status = pipe2(mPipeFd, O_CLOEXEC);
-        if (status == 0) {
-            mOutput = std::async(std::launch::async, reader, mPipeFd[0], mTimeoutTimeNs, mPrefix);
-        }
-        // on initialization failure fd() returns -1.
-    }
-
-    ~FdToStringOldImpl() {
-        for (auto& fd : mPipeFd) {
-            if (fd >= 0) {
-                close(fd);
-                fd = -1;
-            }
-        }
-    }
-
-    /**
-     * Returns the write end of the pipe as a file descriptor or -1 if invalid or already closed.
-     * Do not close this fd directly as this class should own the fd. Instead, use
-     * closeAndGetString() to close the fd and return the string.
-     */
-    int borrowFdUnsafe() const { return mPipeFd[1]; }
-
-    /**
-     * Returns the string representation of data written to the fd. Awaits reader thread.
-     *
-     * All writers should have returned by this point.
-     *
-     * An empty string is returned on initialization failure or timeout. Closes fd.
-     */
-    std::string closeAndGetString() {
-        if (!mOutput.valid()) return "";
-        if (mPipeFd[1] >= 0) {
-            close(mPipeFd[1]);
-            mPipeFd[1] = -1;
-        }
-        const int waitMs = toMillisecondTimeoutDelay(systemTime(), mTimeoutTimeNs);
-        std::future_status status = mOutput.wait_for(std::chrono::milliseconds(waitMs));
-        return status == std::future_status::ready ? mOutput.get() : "";
-    }
-
-  private:
-    static std::string reader(int fd, int64_t timeoutTimeNs, std::string prefix) {
-        char buf[4096];
-        int red;
-        std::stringstream ss;
-        bool requiresPrefix = true;
-
-        while (true) {
-            struct pollfd pfd = {
-                    .fd = fd,
-                    .events = POLLIN | POLLRDHUP,
-            };
-            const int waitMs = toMillisecondTimeoutDelay(systemTime(), timeoutTimeNs);
-            // ALOGD("waitMs: %d", waitMs);
-            if (waitMs <= 0) break;
-            const int retval = poll(&pfd, 1 /* nfds*/, waitMs);
-            // error, timeout, or hangup (without data to read)
-            if (retval <= 0 || (pfd.revents & POLLIN) != POLLIN) break;
-            // data should be available
-            if ((red = read(fd, buf, sizeof(buf))) <= 0) break;
-            char *delim, *bptr = buf;
-            while (!prefix.empty() && (delim = (char*)memchr(bptr, '\n', red)) != nullptr) {
-                if (requiresPrefix) ss << prefix;
-                const size_t line = delim - bptr + 1;
-                ss.write(bptr, line);
-                bptr += line;
-                red -= line;
-                requiresPrefix = true;
-            }
-            if (red > 0) {
-                ss << prefix;
-                ss.write(bptr, red);
-                requiresPrefix = false;
-            }
-        }
-        return ss.str();
-    }
-
-    const std::string mPrefix;
-    const int64_t mTimeoutTimeNs;
-    int mPipeFd[2] = {-1, -1};
-    std::future<std::string> mOutput;
-};
-
 /**
  * Launch reader task which accumulates data written to the fd that this class exposes.
  * Usage as follows:
diff --git a/audio_utils/include/audio_utils/dsp_utils.h b/audio_utils/include/audio_utils/dsp_utils.h
new file mode 100644
index 00000000..8309c9ab
--- /dev/null
+++ b/audio_utils/include/audio_utils/dsp_utils.h
@@ -0,0 +1,157 @@
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
+#ifdef __cplusplus
+
+#include <algorithm>
+#include <atomic>
+#include <limits>
+#include <random>
+#include <type_traits>
+
+namespace android::audio_utils {
+
+/**
+ * These DSP algorithms are intentionally designed for the typical audio use
+ * case: single contiguous data layout.  This allows eventual vector
+ * intrinsic optimization.
+ *
+ * Compare with STL generalized algorithm accumulate(), for_each[_n](),
+ * or transform(), which use general ForwardIt forward iterators,
+ * and composable ranges.
+ */
+
+/**
+ * Fill a container with a uniform random distribution.
+ *
+ * The quality of the random number generator is tested
+ * by audio_dsp_tests to be sufficient for basic signal
+ * tests, not for audio noise or (shaped) dithering generation.
+ */
+static inline std::atomic<uint32_t> seedCounter = 1;  // random (resettable) seed.
+template <typename T, typename V>
+void initUniformDistribution(V& v, T rangeMin, T rangeMax) {
+    // Fast but not great RNG.  Consider vectorized RNG in future.
+    std::minstd_rand gen(++seedCounter);
+    std::uniform_real_distribution<T> dis(rangeMin, rangeMax);
+
+    for (auto& e : v) {
+        e = dis(gen);
+    }
+}
+
+/**
+ * Return the energy in dB of a uniform distribution.
+ */
+template <typename F>
+requires (std::is_floating_point_v<F>)
+F energyOfUniformDistribution(F rangeMin, F rangeMax) {
+    if (rangeMin == rangeMax) return 0;
+    constexpr auto reciprocal = F(1) / 3;
+    // (b^3 - a^3) / (b - a) = (b^2 + ab + a^2)
+    return 10 * log10(reciprocal *
+            (rangeMax * rangeMax + rangeMax * rangeMin + rangeMin * rangeMin));
+}
+
+/**
+ * Compute the SNR in dB between two input arrays.
+ *
+ * The first array is considered the reference signal,
+ * the second array is considered signal + noise.
+ *
+ * If in1 == in2, infinity is returned.
+ * If count == 0, inifinty (not nan) is returned.
+ */
+template <typename F>
+requires (std::is_floating_point_v<F>)
+F snr(const F* in1, const F* in2, size_t count) {
+    F signal{};
+    F noise{};
+
+    if (count == 0) return std::numeric_limits<F>::infinity();
+
+    // floating point addition precision may depend on ordering.
+    for (size_t i = 0; i < count; ++i) {
+        signal += in1[i] * in1[i];
+        const F diff = in1[i] - in2[i];
+        noise += diff * diff;
+    }
+
+    if (noise == 0 && signal == 0) return std::numeric_limits<F>::infinity();
+    return 10 * log10(signal / noise);
+}
+
+/**
+ * Compute the SNR in dB between two input containers.
+ *
+ * The first container is considered the reference signal,
+ * the second container is considered signal + noise.
+ *
+ * General container examples would be std::array, std::span, or std::vector.
+ */
+template <typename C>
+auto snr(const C& c1, const C& c2) {
+    return snr(c1.data(), c2.data(), std::min(c1.size(), c2.size()));
+}
+
+/**
+ * Compute the energy (or power) in dB from an input array.
+ *
+ * Mean is not removed.
+ *
+ * This is a "square wave" reference dB measurement also known as dBov
+ * (dB relative to overload).
+ *
+ * Audio standards typically use a full scale "sine wave" reference dB
+ * measurement also known as dBFS.  With this terminology 0dBFS = -3dBov.
+ *
+ * If count == 0, 0 is returned.
+ */
+template <typename F>
+requires (std::is_floating_point_v<F>)
+F energy(const F* in, size_t count) {
+    F signal{};
+
+    if (count == 0) return 0;
+    for (size_t i = 0; i < count; ++i) {
+        signal += in[i] * in[i];
+    }
+    return 10 * log10(signal / count);
+}
+
+/**
+ * Compute the energy (or power) in dB from an input container.
+ *
+ * Mean is not removed.
+ *
+ * This is a "square wave" reference dB measurement also known as dBov
+ * (dB relative to overload).
+ *
+ * Audio standards typically use a full scale "sine wave" reference dB
+ * measurement also known as dBFS.  With this terminology 0dBFS = -3dBov.
+ *
+ * General container examples would be std::array, std::span, or std::vector.
+ */
+template <typename C>
+auto energy(const C& c) {
+   return energy(c.data(), c.size());
+}
+
+}  // namespace android::audio_utils
+
+#endif  // __cplusplus
diff --git a/audio_utils/include/audio_utils/intrinsic_utils.h b/audio_utils/include/audio_utils/intrinsic_utils.h
index beedd681..9c1eda5d 100644
--- a/audio_utils/include/audio_utils/intrinsic_utils.h
+++ b/audio_utils/include/audio_utils/intrinsic_utils.h
@@ -19,6 +19,7 @@
 
 #include <array>  // std::size
 #include <type_traits>
+#include "template_utils.h"
 
 /*
   The intrinsics utility library contain helper functions for wide width DSP support.
@@ -37,6 +38,37 @@
 #define USE_NEON
 #endif
 
+// We use macros to hide intrinsic methods that do not exist for
+// incompatible target architectures; otherwise we have a
+// "use of undeclared identifier" compilation error when
+// we invoke our templated method.
+//
+// For example, we pass in DN_(vadd_f32) into implement_arg2().
+// For ARM compilation, this works as expected, vadd_f32 is used.
+// For x64 compilation, the macro converts vadd_f32 to a nullptr
+// (so there is no undeclared identifier) and the calling site is safely
+// ifdef'ed out in implement_arg2() for non ARM architectures.
+//
+// DN_(x) replaces x with nullptr for non-ARM arch
+// DN64_(x) replaces x with nullptr for non-ARM64 arch
+#pragma push_macro("DN_")
+#pragma push_macro("DN64_")
+#undef DN_
+#undef DN64_
+
+#ifdef USE_NEON
+#if defined(__aarch64__)
+#define DN_(x) x
+#define DN64_(x) x
+#else
+#define DN_(x) x
+#define DN64_(x) nullptr
+#endif
+#else
+#define DN_(x) nullptr
+#define DN64_(x) nullptr
+#endif // USE_NEON
+
 namespace android::audio_utils::intrinsics {
 
 // For static assert(false) we need a template version to avoid early failure.
@@ -44,24 +76,838 @@ namespace android::audio_utils::intrinsics {
 template <typename T>
 inline constexpr bool dependent_false_v = false;
 
+// Detect if the value is directly addressable as an array.
+// This is more advanced than std::is_array and works with neon intrinsics.
+template<typename T>
+concept is_array_like = requires(T a) {
+    a[0];  // can index first element
+};
+
+template<typename F, typename T>
+concept takes_identical_parameter_pair_v = requires(F f, T a) {
+    f(a, a);
+};
+
+/**
+ * Applies a functional or a constant to an intrinsic struct.
+ *
+ * The vapply method has no return value, but can modify an input intrinsic struct
+ * through element-wise application of a functional.
+ * Compare the behavior with veval which returns a struct result.
+ *
+ * Using vector terminology:
+ *   if f is a constant: v[i] = f;
+ *   if f is a void method that takes an element value: f(v[i]);
+ *   if f returns an element value but takes no arg: v[i] = f();
+ *   if f returns an element value but takes an element value: v[i] = f(v[i]);
+ */
+template <typename V, typename F>
+constexpr void vapply(const F& f, V& v) {
+    if constexpr (std::is_same_v<V, float> || std::is_same_v<V, double>) {
+        using E = std::decay_t<decltype(v)>;
+        if constexpr (std::is_invocable_r_v<void, F, E>) {
+            f(v);
+        } else if constexpr (std::is_invocable_r_v<E, F, E>) {
+            v = f(v);
+        } else if constexpr (std::is_invocable_r_v<E, F>) {
+            v = f();
+        } else /* constexpr */ {
+            v = f;
+        }
+    } else if constexpr (is_array_like<V>) {
+        // this vector access within a neon object prevents constexpr.
+        using E = std::decay_t<decltype(v[0])>;
+#pragma unroll
+        for (size_t i = 0; i < sizeof(v) / sizeof(v[0]); ++i) {
+            if constexpr (std::is_invocable_r_v<void, F, E>) {
+                f(v[i]);
+            } else if constexpr (std::is_invocable_r_v<E, F, E>) {
+                v[i] = f(v[i]);
+            } else if constexpr (std::is_invocable_r_v<E, F>) {
+                v[i] = f();
+            } else /* constexpr */ {
+                v[i] = f;
+            }
+        }
+    } else /* constexpr */ {
+        auto& [vv] = v;
+        // for constexpr purposes, non-const references can't bind to array elements.
+        using VT = decltype(vv);
+        // automatically generated from tests/generate_constexpr_constructible.cpp
+        if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type
+                >()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27, v28, v29, v30, v31, v32] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+            vapply(f, v28);
+            vapply(f, v29);
+            vapply(f, v30);
+            vapply(f, v31);
+            vapply(f, v32);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27, v28, v29, v30, v31] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+            vapply(f, v28);
+            vapply(f, v29);
+            vapply(f, v30);
+            vapply(f, v31);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27, v28, v29, v30] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+            vapply(f, v28);
+            vapply(f, v29);
+            vapply(f, v30);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27, v28, v29] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+            vapply(f, v28);
+            vapply(f, v29);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27, v28] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+            vapply(f, v28);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26, v27] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+            vapply(f, v27);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25, v26] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+            vapply(f, v26);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24,
+                    v25] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+            vapply(f, v25);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type
+                >()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23, v24] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+            vapply(f, v24);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22, v23] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+            vapply(f, v23);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21, v22] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+            vapply(f, v22);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20, v21] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+            vapply(f, v21);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19, v20] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+            vapply(f, v20);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18, v19] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+            vapply(f, v19);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17, v18] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+            vapply(f, v18);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16,
+                    v17] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+            vapply(f, v17);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type
+                >()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15, v16] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+            vapply(f, v16);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14, v15] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+            vapply(f, v15);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13, v14] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+            vapply(f, v14);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12, v13] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+            vapply(f, v13);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11, v12] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+            vapply(f, v12);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10, v11] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+            vapply(f, v11);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9, v10] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+            vapply(f, v10);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type,
+                any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8,
+                    v9] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+            vapply(f, v9);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type, any_type
+                >()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7, v8] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+            vapply(f, v8);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6, v7] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+            vapply(f, v7);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5, v6] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+            vapply(f, v6);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4, v5] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+            vapply(f, v5);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3, v4] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+            vapply(f, v4);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type, any_type>()) {
+            auto& [v1, v2, v3] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+            vapply(f, v3);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type, any_type>()) {
+            auto& [v1, v2] = vv;
+            vapply(f, v1);
+            vapply(f, v2);
+        } else if constexpr (is_braces_constructible<VT,
+                any_type>()) {
+            auto& [v1] = vv;
+            vapply(f, v1);
+        } else {
+            static_assert(false, "Currently supports up to 32 members only.");
+        }
+    }
+}
+
 // Type of array embedded in a struct that is usable in the Neon template functions below.
 // This type must satisfy std::is_array_v<>.
 template<typename T, size_t N>
 struct internal_array_t {
     T v[N];
     static constexpr size_t size() { return N; }
+    using element_t = T;
+    constexpr bool operator==(const internal_array_t<T, N> other) const {
+        for (size_t i = 0; i < N; ++i) {
+            if (v[i] != other.v[i]) return false;
+        }
+        return true;
+    }
+    constexpr internal_array_t<T, N>& operator=(T value) {
+        for (size_t i = 0; i < N; ++i) {
+            v[i] = value;
+        }
+        return *this;
+    }
+    constexpr internal_array_t() = default;
+    // explicit: disallow internal_array_t<float, 3> x  = 10.f;
+    constexpr explicit internal_array_t(T value) {
+        *this = value;
+    }
+    // allow internal_array_t<float, 3> x  = { 10.f };
+    constexpr internal_array_t(std::initializer_list<T> value) {
+        size_t i = 0;
+        auto vptr = value.begin();
+        for (; i < std::min(N, value.size()); ++i) {
+            v[i] = *vptr++;
+        }
+        for (; i < N; ++i) {
+            v[i] = {};
+        }
+    }
 };
 
-// Detect if the value is directly addressable as an array.
-// This is more advanced than std::is_array and works with neon intrinsics.
-template<typename T>
-concept is_array_like = requires(T a) {
-    a[0];  // can index first element
-};
+// assert our structs are trivially copyable so we can use memcpy freely.
+static_assert(std::is_trivially_copyable_v<internal_array_t<float, 31>>);
+static_assert(std::is_trivially_copyable_v<internal_array_t<double, 31>>);
 
 // Vector convert between type T to type S.
 template <typename S, typename T>
-inline S vconvert(const T& in) {
+constexpr inline S vconvert(const T& in) {
     S out;
 
     if constexpr (is_array_like<S>) {
@@ -124,196 +970,568 @@ inline S vconvert(const T& in) {
   using alternative_15_t = struct { struct { float32x4x2_t a; struct { float v[7]; } b; } s; };
 */
 
-// add a + b
+#ifdef USE_NEON
+
+// This will be specialized later to hold different types.
+template<int N>
+struct vfloat_struct {};
+
+// Helper method to extract type contained in the struct.
+template<int N>
+using vfloat_t = typename vfloat_struct<N>::t;
+
+// Create vfloat_extended_t to add helper methods.
+//
+// It is preferable to use vector_hw_t instead, which
+// chooses between vfloat_extended_t and internal_array_t
+// based on type support.
+//
+// Note: Adding helper methods will not affect std::is_trivially_copyable_v.
+template<size_t N>
+struct vfloat_extended_t : public vfloat_t<N> {
+    static constexpr size_t size() { return N; }
+    using element_t = float;
+    constexpr bool operator==(const vfloat_extended_t<N>& other) const {
+        return veq(*this, other);
+    }
+    vfloat_extended_t<N>& operator=(float value) {
+        vapply(value, *this);
+        return *this;
+    }
+    constexpr vfloat_extended_t(const vfloat_extended_t<N>& other) = default;
+    vfloat_extended_t() = default;
+    // explicit: disallow vfloat_extended_t<float, 3> x  = 10.f;
+    explicit vfloat_extended_t(float value) {
+        *this = value;
+    }
+    // allow internal_array_t<float, 3> x  = { 10.f };
+    vfloat_extended_t(std::initializer_list<float> value) {
+        size_t i = 0;
+        auto vptr = value.begin();
+        float v[N];
+        for (; i < std::min(N, value.size()); ++i) {
+            v[i] = *vptr++;
+        }
+        for (; i < N; ++i) {
+            v[i] = {};
+        }
+        static_assert(sizeof(*this) == sizeof(v));
+        static_assert(sizeof(*this) == N * sizeof(float));
+        memcpy(this, v, sizeof(*this));
+    }
+    vfloat_extended_t(internal_array_t<float, N> value) {
+        static_assert(sizeof(*this) == sizeof(value.v));
+        static_assert(sizeof(*this) == N * sizeof(float));
+        memcpy(this, value.v, sizeof(*this));
+    }
+};
+
+// Create type alias vector_hw_t as platform independent SIMD intrinsic
+// type for hardware support.
+
+template<typename F, size_t N>
+using vector_hw_t = std::conditional_t<
+        std::is_same_v<F, float>, vfloat_extended_t<N>, internal_array_t<F, N>>;
+
+// Recursively define structs containing the NEON intrinsic types for a given vector size.
+// intrinsic_utils.h allows structurally recursive type definitions based on
+// pairs of types (much like Lisp list cons pairs).
+//
+// For unpacking these type pairs, we use structured binding, so the naming of the
+// element members is irrelevant.  Hence, it is possible to use pragma pack and
+// std::pair<> to define these structs as follows:
+//
+// #pragma pack(push, 1)
+// struct vfloat_struct<3> { using t = struct {
+//     std::pair<vfloat_t<2>, vfloat_t<1>> p; }; };
+// #pragma pack(pop)
+//
+// But due to ctor requirements, the resulting struct composed of std::pair is
+// no longer considered trivially copyable.
+//
+template<>
+struct vfloat_struct<1> { using t = struct { float v[1]; }; };
+template<>
+struct vfloat_struct<2> { using t = struct { float32x2_t v[1]; }; };
+template<>
+struct vfloat_struct<3> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<2> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<4> { using t = struct { float32x4_t v[1]; }; };
+template<>
+struct vfloat_struct<5> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<6> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<7> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<4> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<8> { using t = float32x4x2_t; };
+template<>
+struct vfloat_struct<9> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<10> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<11> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<12> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<4> b; } s; }; };
+template<>
+struct vfloat_struct<13> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<5> b; } s; }; };
+template<>
+struct vfloat_struct<14> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<6> b; } s; }; };
+template<>
+struct vfloat_struct<15> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<8> a; vfloat_t<7> b; } s; }; };
+template<>
+struct vfloat_struct<16> { using t = float32x4x4_t; };
+template<>
+struct vfloat_struct<17> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<1> b; } s; }; };
+template<>
+struct vfloat_struct<18> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<2> b; } s; }; };
+template<>
+struct vfloat_struct<19> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<3> b; } s; }; };
+template<>
+struct vfloat_struct<20> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<4> b; } s; }; };
+template<>
+struct vfloat_struct<21> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<5> b; } s; }; };
+template<>
+struct vfloat_struct<22> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<6> b; } s; }; };
+template<>
+struct vfloat_struct<23> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<7> b; } s; }; };
+template<>
+struct vfloat_struct<24> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<8> b; } s; }; };
+template<>
+struct vfloat_struct<25> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<9> b; } s; }; };
+template<>
+struct vfloat_struct<26> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<10> b; } s; }; };
+template<>
+struct vfloat_struct<27> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<11> b; } s; }; };
+template<>
+struct vfloat_struct<28> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<12> b; } s; }; };
+template<>
+struct vfloat_struct<29> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<13> b; } s; }; };
+template<>
+struct vfloat_struct<30> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<14> b; } s; }; };
+template<>
+struct vfloat_struct<31> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<15> b; } s; }; };
+template<>
+struct vfloat_struct<32> { using t = struct { struct __attribute__((packed)) {
+    vfloat_t<16> a; vfloat_t<16> b; } s; }; };
+
+// assert our structs are trivially copyable so we can use memcpy freely.
+static_assert(std::is_trivially_copyable_v<vfloat_struct<31>>);
+static_assert(std::is_trivially_copyable_v<vfloat_t<31>>);
+
+#else
+
+// x64 or risc-v, use loop vectorization if no HW type exists.
+template<typename F, int N>
+using vector_hw_t = internal_array_t<F, N>;
+
+#endif // USE_NEON
+
+/**
+ * Returns the first element of the intrinsic struct.
+ */
+template <typename T>
+constexpr auto first_element_of(const T& t) {
+    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
+        return t;
+    } else if constexpr (is_array_like<T>) {
+        return first_element_of(t[0]);
+    } else /* constexpr */ {
+        const auto& [tval] = t;  // single-member struct
+        if constexpr (std::is_array_v<decltype(tval)>) {
+            return first_element_of(tval[0]);
+        } else /* constexpr */ {
+             const auto& [p1, p2] = tval;
+             return first_element_of(p1);
+        }
+    }
+}
+
+/**
+ * Evaluate f(v1 [, v2 [, v3]]) and return an intrinsic struct result.
+ *
+ * The veval method returns the vector result by element-wise
+ * evaulating a functional f to one or more intrinsic struct inputs.
+ * Compare this method with the single argument vapply,
+ * which can modify a single struct argument in-place.
+ */
+template <typename F, typename V>
+constexpr V veval(const F& f, const V& v1) {
+    if constexpr (std::is_same_v<V, float> || std::is_same_v<V, double>) {
+        return f(v1);
+    } else if constexpr (is_array_like<V>) {
+        V out;
+#pragma unroll
+        // neon intrinsics need sizeof.
+        for (size_t i = 0; i < sizeof(v1) / sizeof(v1[0]); ++i) {
+            out[i] = f(v1[i]);
+        }
+        return out;
+    } else /* constexpr */ {
+        V ret;
+        auto& [retval] = ret;  // single-member struct
+        const auto& [v1val] = v1;
+        if constexpr (std::is_array_v<decltype(v1val)>) {
+#pragma unroll
+            for (size_t i = 0; i < std::size(v1val); ++i) {
+                retval[i] = veval(f, v1val[i]);
+            }
+            return ret;
+        } else /* constexpr */ {
+             auto& [r1, r2] = retval;
+             const auto& [p1, p2] = v1val;
+             r1 = veval(f, p1);
+             r2 = veval(f, p2);
+             return ret;
+        }
+    }
+}
+
+template <typename F, typename V>
+constexpr V veval(const F& f, const V& v1, const V& v2) {
+    if constexpr (std::is_same_v<V, float> || std::is_same_v<V, double>) {
+        return f(v1, v2);
+    } else if constexpr (is_array_like<V>) {
+        V out;
+#pragma unroll
+        // neon intrinsics need sizeof.
+        for (size_t i = 0; i < sizeof(v1) / sizeof(v1[0]); ++i) {
+            out[i] = f(v1[i], v2[i]);
+        }
+        return out;
+    } else /* constexpr */ {
+        V ret;
+        auto& [retval] = ret;  // single-member struct
+        const auto& [v1val] = v1;
+        const auto& [v2val] = v2;
+        if constexpr (std::is_array_v<decltype(v1val)>) {
+#pragma unroll
+            for (size_t i = 0; i < std::size(v1val); ++i) {
+                retval[i] = veval(f, v1val[i], v2val[i]);
+            }
+            return ret;
+        } else /* constexpr */ {
+             auto& [r1, r2] = retval;
+             const auto& [p11, p12] = v1val;
+             const auto& [p21, p22] = v2val;
+             r1 = veval(f, p11, p21);
+             r2 = veval(f, p12, p22);
+             return ret;
+        }
+    }
+}
+
+template <typename F, typename V>
+constexpr V veval(const F& f, const V& v1, const V& v2, const V& v3) {
+    if constexpr (std::is_same_v<V, float> || std::is_same_v<V, double>) {
+        return f(v1, v2, v3);
+    } else if constexpr (is_array_like<V>) {
+        V out;
+#pragma unroll
+        // neon intrinsics need sizeof.
+        for (size_t i = 0; i < sizeof(v1) / sizeof(v1[0]); ++i) {
+            out[i] = f(v1[i], v2[i], v3[i]);
+        }
+        return out;
+    } else /* constexpr */ {
+        V ret;
+        auto& [retval] = ret;  // single-member struct
+        const auto& [v1val] = v1;
+        const auto& [v2val] = v2;
+        const auto& [v3val] = v3;
+        if constexpr (std::is_array_v<decltype(v1val)>) {
+#pragma unroll
+            for (size_t i = 0; i < std::size(v1val); ++i) {
+                retval[i] = veval(f, v1val[i], v2val[i], v3val[i]);
+            }
+            return ret;
+        } else /* constexpr */ {
+             auto& [r1, r2] = retval;
+             const auto& [p11, p12] = v1val;
+             const auto& [p21, p22] = v2val;
+             const auto& [p31, p32] = v3val;
+             r1 = veval(f, p11, p21, p31);
+             r2 = veval(f, p12, p22, p32);
+             return ret;
+        }
+    }
+}
+
+/**
+ * Compare two intrinsic structs and return true iff equal.
+ *
+ * As opposed to memcmp, this handles floating point equality
+ * which is different due to signed 0 and NaN, etc.
+ */
 template<typename T>
-static inline T vadd(T a, T b) {
+inline bool veq(T a, T b) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return a + b;
+        return a == b;
+    } else if constexpr (is_array_like<T>) {
+#pragma unroll
+        for (size_t i = 0; i < sizeof(a) / sizeof(a[0]); ++i) {
+            if (!veq(a[i], b[i])) return false;
+        }
+        return true;
+    } else /* constexpr */ {
+        const auto& [aval] = a;
+        const auto& [bval] = b;
+        if constexpr (std::is_array_v<decltype(aval)>) {
+#pragma unroll
+            for (size_t i = 0; i < std::size(aval); ++i) {
+                if (!veq(aval[i], bval[i])) return false;
+            }
+            return true;
+        } else /* constexpr */ {
+             const auto& [a1, a2] = aval;
+             const auto& [b1, b2] = bval;
+             return veq(a1, b1) && veq(a2, b2);
+        }
+    }
+}
+
+// --------------------------------------------------------------------
 
+template<typename F, typename FN1, typename FN2, typename FN3, typename T>
+inline T implement_arg1(const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a) {
+    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
+        return f(a);
 #ifdef USE_NEON
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vadd_f32(a, b);
+        return fn1(a);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vaddq_f32(a, b);
+        return fn2(a);
 #if defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vaddq_f64(a, b);
+        return fn3(a);
 #endif
 #endif // USE_NEON
 
     } else /* constexpr */ {
         T ret;
-        auto &[retval] = ret;  // single-member struct
-        const auto &[aval] = a;
-        const auto &[bval] = b;
+        auto& [retval] = ret;  // single-member struct
+        const auto& [aval] = a;
         if constexpr (std::is_array_v<decltype(retval)>) {
 #pragma unroll
             for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vadd(aval[i], bval[i]);
+                retval[i] = implement_arg1(f, fn1, fn2, fn3, aval[i]);
             }
             return ret;
         } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             const auto &[a1, a2] = aval;
-             const auto &[b1, b2] = bval;
-             r1 = vadd(a1, b1);
-             r2 = vadd(a2, b2);
+             auto& [r1, r2] = retval;
+             const auto& [a1, a2] = aval;
+             r1 = implement_arg1(f, fn1, fn2, fn3, a1);
+             r2 = implement_arg1(f, fn1, fn2, fn3, a2);
              return ret;
         }
     }
 }
 
-// add internally
-template<typename T>
-inline auto vaddv(const T& a) {
+template<typename F, typename FN1, typename FN2, typename FN3, typename T>
+inline auto implement_arg1v(const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
         return a;
 
-#ifdef USE_NEON
+#if defined(USE_NEON) && defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vaddv_f32(a);
-#if defined(__aarch64__)
+        return fn1(a);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vaddvq_f32(a);
+        return fn2(a);
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vaddvq_f64(a);
-#endif
-#endif // USE_NEON
+        return fn3(a);
+#endif // defined(USE_NEON) && defined(__aarch64__)
     } else if constexpr (is_array_like<T>) {
         using ret_t = std::decay_t<decltype(a[0])>;
 
-        ret_t ret{};
+        ret_t ret = a[0];
         // array_like is not the same as an array, so we use sizeof here
         // to handle neon instrinsics.
 #pragma unroll
-        for (size_t i = 0; i < sizeof(a) / sizeof(a[0]); ++i) {
-            ret += a[i];
+        for (size_t i = 1; i < sizeof(a) / sizeof(a[0]); ++i) {
+            ret = f(ret, a[i]);
         }
         return ret;
     } else /* constexpr */ {
         const auto &[aval] = a;
-        using ret_t = std::decay_t<decltype(aval[0])>;
-        ret_t ret{};
-
+        if constexpr (std::is_array_v<decltype(aval)>) {
+            using ret_t = std::decay_t<decltype(first_element_of(aval[0]))>;
+            ret_t ret = implement_arg1v(f, fn1, fn2, fn3, aval[0]);
 #pragma unroll
-        for (size_t i = 0; i < std::size(aval); ++i) {
-            ret += aval[i];
+            for (size_t i = 1; i < std::size(aval); ++i) {
+                ret = f(ret, implement_arg1v(f, fn1, fn2, fn3, aval[i]));
+            }
+            return ret;
+        } else /* constexpr */ {
+             using ret_t = std::decay_t<decltype(first_element_of(a))>;
+             const auto& [a1, a2] = aval;
+             ret_t ret = implement_arg1v(f, fn1, fn2, fn3, a1);
+             ret = f(ret, implement_arg1v(f, fn1, fn2, fn3, a2));
+             return ret;
         }
-        return ret;
     }
 }
 
-// duplicate float into all elements.
 template<typename T, typename F>
-static inline T vdupn(F f) {
-    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return f;
+inline T vdupn(F f);
+
+/**
+ * Invoke vector intrinsic with a vector argument T and a scalar argument S.
+ *
+ * If the vector intrinsic does not support vector-scalar operation, we dup the scalar
+ * argument.
+ */
+template <typename F, typename T, typename S>
+auto invoke_intrinsic_with_dup_as_needed(const F& f, T a, S b) {
+    if constexpr (takes_identical_parameter_pair_v<F, T>) {
+        return f(a, vdupn<T>(b));
+    } else /* constexpr */ {
+        return f(a, b);
+    }
+}
 
+// arg2 with a vector and scalar parameter.
+template<typename F, typename FN1, typename FN2, typename FN3, typename T, typename S>
+inline auto implement_arg2(const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a, S b) {
+    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
+        if constexpr (std::is_same_v<S, float> || std::is_same_v<S, double>) {
+            return f(a, b);
+        } else /* constexpr */ {
+            return implement_arg2(f, fn1, fn2, fn3, b, a); // we prefer T to be the vector/struct.
+        }
+    } else if constexpr (std::is_same_v<S, float> || std::is_same_v<S, double>) {
+        // handle the lane variant
 #ifdef USE_NEON
-    } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vdup_n_f32(f);
-    } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vdupq_n_f32(f);
+        if constexpr (std::is_same_v<T, float32x2_t>) {
+            return invoke_intrinsic_with_dup_as_needed(fn1, a, b);
+        } else if constexpr (std::is_same_v<T, float32x4_t>) {
+            return invoke_intrinsic_with_dup_as_needed(fn2, a, b);
 #if defined(__aarch64__)
-    } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vdupq_n_f64(f);
+        } else if constexpr (std::is_same_v<T, float64x2_t>) {
+            return invoke_intrinsic_with_dup_as_needed(fn3, a, b);
 #endif
+        } else
 #endif // USE_NEON
-
-    } else /* constexpr */ {
+        {
         T ret;
         auto &[retval] = ret;  // single-member struct
+        const auto &[aval] = a;
         if constexpr (std::is_array_v<decltype(retval)>) {
 #pragma unroll
-            for (auto& val : retval) {
-                val = vdupn<std::decay_t<decltype(val)>>(f);
+            for (size_t i = 0; i < std::size(aval); ++i) {
+                retval[i] = implement_arg2(f, fn1, fn2, fn3, aval[i], b);
             }
             return ret;
         } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             using r1_type = std::decay_t<decltype(r1)>;
-             using r2_type = std::decay_t<decltype(r2)>;
-             r1 = vdupn<r1_type>(f);
-             r2 = vdupn<r2_type>(f);
+             auto& [r1, r2] = retval;
+             const auto& [a1, a2] = aval;
+             r1 = implement_arg2(f, fn1, fn2, fn3, a1, b);
+             r2 = implement_arg2(f, fn1, fn2, fn3, a2, b);
              return ret;
         }
+        }
+    } else {
+        // Both types T and S are non-primitive and they are not equal.
+        static_assert(dependent_false_v<T>);
     }
 }
 
-// load from float pointer.
-template<typename T, typename F>
-static inline T vld1(const F *f) {
+template<typename F, typename FN1, typename FN2, typename FN3, typename T>
+inline T implement_arg2(const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a, T b) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return *f;
+        return f(a, b);
 
 #ifdef USE_NEON
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vld1_f32(f);
+        return fn1(a, b);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vld1q_f32(f);
+        return fn2(a, b);
 #if defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vld1q_f64(f);
+        return fn3(a, b);
 #endif
 #endif // USE_NEON
 
     } else /* constexpr */ {
         T ret;
-        auto &[retval] = ret;  // single-member struct
+        auto& [retval] = ret;  // single-member struct
+        const auto& [aval] = a;
+        const auto& [bval] = b;
         if constexpr (std::is_array_v<decltype(retval)>) {
-            using element_type = std::decay_t<decltype(retval[0])>;
-            constexpr size_t subelements = sizeof(element_type) / sizeof(F);
 #pragma unroll
-            for (size_t i = 0; i < std::size(retval); ++i) {
-                retval[i] = vld1<element_type>(f);
-                f += subelements;
+            for (size_t i = 0; i < std::size(aval); ++i) {
+                retval[i] = implement_arg2(f, fn1, fn2, fn3, aval[i], bval[i]);
             }
             return ret;
         } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             using r1_type = std::decay_t<decltype(r1)>;
-             using r2_type = std::decay_t<decltype(r2)>;
-             r1 = vld1<r1_type>(f);
-             f += sizeof(r1) / sizeof(F);
-             r2 = vld1<r2_type>(f);
+             auto& [r1, r2] = retval;
+             const auto& [a1, a2] = aval;
+             const auto& [b1, b2] = bval;
+             r1 = implement_arg2(f, fn1, fn2, fn3, a1, b1);
+             r2 = implement_arg2(f, fn1, fn2, fn3, a2, b2);
              return ret;
         }
     }
 }
 
-/**
- * Returns c as follows:
- * c_i = a_i * b_i if a and b are the same vector type or
- * c_i = a_i * b if a is a vector and b is scalar or
- * c_i = a * b_i if a is scalar and b is a vector.
- */
-template<typename T, typename S, typename F>
-static inline T vmla(T a, S b, F c) {
-    // Both types T and S are non-primitive and they are not equal.  T == S handled below.
+template<typename F, typename FN1, typename FN2, typename FN3, typename T, typename S, typename R>
+inline auto implement_arg3(
+        const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, R a, T b, S c) {
+    // Arbitrary support is not allowed.
+    (void) f;
+    (void) fn1;
+    (void) fn2;
+    (void) fn3;
     (void) a;
     (void) b;
     (void) c;
     static_assert(dependent_false_v<T>);
 }
 
-template<typename T, typename F>
-static inline T vmla(T a, T b, F c) {
+template<typename F, typename FN1, typename FN2, typename FN3, typename T, typename S>
+inline auto implement_arg3(
+        const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a, T b, S c) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        if constexpr (std::is_same_v<F, float> || std::is_same_v<F, double>) {
-            return a + b * c;
+        if constexpr (std::is_same_v<S, float> || std::is_same_v<S, double>) {
+            return f(a, b, c);
         } else {
             static_assert(dependent_false_v<T>);
         }
-    } else if constexpr (std::is_same_v<F, float> || std::is_same_v<F, double>) {
+    } else if constexpr (std::is_same_v<S, float> || std::is_same_v<S, double>) {
         // handle the lane variant
 #ifdef USE_NEON
         if constexpr (std::is_same_v<T, float32x2_t>) {
-            return vmla_n_f32(a, b, c);
+            return fn1(a, b, c);
         } else if constexpr (std::is_same_v<T, float32x4_t>) {
-            return vmlaq_n_f32(a, b,c);
+            return fn2(a, b, c);
 #if defined(__aarch64__)
         } else if constexpr (std::is_same_v<T, float64x2_t>) {
-            return vmlaq_n_f64(a, b);
+            return fn3(a, b, c);
 #endif
         } else
 #endif // USE_NEON
@@ -325,196 +1543,254 @@ static inline T vmla(T a, T b, F c) {
         if constexpr (std::is_array_v<decltype(retval)>) {
 #pragma unroll
             for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vmla(aval[i], bval[i], c);
+                retval[i] = implement_arg3(f, fn1, fn2, fn3, aval[i], bval[i], c);
             }
             return ret;
         } else /* constexpr */ {
              auto &[r1, r2] = retval;
              const auto &[a1, a2] = aval;
              const auto &[b1, b2] = bval;
-             r1 = vmla(a1, b1, c);
-             r2 = vmla(a2, b2, c);
+             r1 = implement_arg3(f, fn1, fn2, fn3, a1, b1, c);
+             r2 = implement_arg3(f, fn1, fn2, fn3, a2, b2, c);
              return ret;
         }
         }
     } else {
-        // Both types T and F are non-primitive and they are not equal.
+        // Both types T and S are non-primitive and they are not equal.
         static_assert(dependent_false_v<T>);
     }
 }
 
-template<typename T, typename F>
-static inline T vmla(T a, F b, T c) {
-    return vmla(a, c, b);
-}
-
-// fused multiply-add a + b * c
-template<typename T>
-inline T vmla(const T& a, const T& b, const T& c) {
+template<typename F, typename FN1, typename FN2, typename FN3, typename T>
+inline T implement_arg3(
+        const F& f, const FN1& fn1, const FN2& fn2, const FN3& fn3, T a, T b, T c) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return a + b * c;
+        return f(a, b, c);
 
 #ifdef USE_NEON
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vmla_f32(a, b, c);
+        return fn1(a, b, c);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vmlaq_f32(a, b, c);
+        return fn2(a, b, c);
 #if defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vmlaq_f64(a, b, c);
+        return fn3(a, b, c);
 #endif
 #endif // USE_NEON
 
     } else /* constexpr */ {
         T ret;
-        auto &[retval] = ret;  // single-member struct
-        const auto &[aval] = a;
-        const auto &[bval] = b;
-        const auto &[cval] = c;
+        auto& [retval] = ret;  // single-member struct
+        const auto& [aval] = a;
+        const auto& [bval] = b;
+        const auto& [cval] = c;
         if constexpr (std::is_array_v<decltype(retval)>) {
 #pragma unroll
             for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vmla(aval[i], bval[i], cval[i]);
+                retval[i] = implement_arg3(f, fn1, fn2, fn3, aval[i], bval[i], cval[i]);
             }
             return ret;
         } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             const auto &[a1, a2] = aval;
-             const auto &[b1, b2] = bval;
-             const auto &[c1, c2] = cval;
-             r1 = vmla(a1, b1, c1);
-             r2 = vmla(a2, b2, c2);
+             auto& [r1, r2] = retval;
+             const auto& [a1, a2] = aval;
+             const auto& [b1, b2] = bval;
+             const auto& [c1, c2] = cval;
+             r1 = implement_arg3(f, fn1, fn2, fn3, a1, b1, c1);
+             r2 = implement_arg3(f, fn1, fn2, fn3, a2, b2, c2);
              return ret;
         }
     }
 }
 
-/**
- * Returns c as follows:
- * c_i = a_i * b_i if a and b are the same vector type or
- * c_i = a_i * b if a is a vector and b is scalar or
- * c_i = a * b_i if a is scalar and b is a vector.
- */
-template<typename T, typename F>
-static inline auto vmul(T a, F b) {
-    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        if constexpr (std::is_same_v<F, float> || std::is_same_v<F, double>) {
-            return a * b;
-        } else /* constexpr */ {
-            return vmul(b, a); // we prefer T to be the vector/struct form.
-        }
-    } else if constexpr (std::is_same_v<F, float> || std::is_same_v<F, double>) {
-        // handle the lane variant
-#ifdef USE_NEON
-        if constexpr (std::is_same_v<T, float32x2_t>) {
-            return vmul_n_f32(a, b);
-        } else if constexpr (std::is_same_v<T, float32x4_t>) {
-            return vmulq_n_f32(a, b);
-#if defined(__aarch64__)
-        } else if constexpr (std::is_same_v<T, float64x2_t>) {
-            return vmulq_n_f64(a, b);
-#endif
-        } else
-#endif // USE_NEON
-        {
-        T ret;
-        auto &[retval] = ret;  // single-member struct
-        const auto &[aval] = a;
-        if constexpr (std::is_array_v<decltype(retval)>) {
-#pragma unroll
-            for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vmul(aval[i], b);
-            }
-            return ret;
-        } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             const auto &[a1, a2] = aval;
-             r1 = vmul(a1, b);
-             r2 = vmul(a2, b);
-             return ret;
-        }
-        }
-    } else {
-        // Both types T and F are non-primitive and they are not equal.
-        static_assert(dependent_false_v<T>);
-    }
+// absolute value
+template<typename T>
+static inline T vabs(T a) {
+    return implement_arg1([](const auto& x) { return std::abs(x); },
+            DN_(vabs_f32), DN_(vabsq_f32), DN64_(vabsq_f64), a);
+}
+
+template<typename T>
+inline T vadd(T a, T b) {
+    return implement_arg2([](const auto& x, const auto& y) { return x + y; },
+            DN_(vadd_f32), DN_(vaddq_f32), DN64_(vaddq_f64), a, b);
 }
 
+// add internally
 template<typename T>
-static inline T vmul(T a, T b) {
+inline auto vaddv(const T& a) {
+    return implement_arg1v([](const auto& x, const auto& y) { return x + y; },
+            DN64_(vaddv_f32), DN64_(vaddvq_f32), DN64_(vaddvq_f64), a);
+}
+
+// duplicate float into all elements.
+template<typename T, typename F>
+inline T vdupn(F f) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return a * b;
+        return f;
 
 #ifdef USE_NEON
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vmul_f32(a, b);
+        return vdup_n_f32(f);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vmulq_f32(a, b);
+        return vdupq_n_f32(f);
 #if defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vmulq_f64(a, b);
+        return vdupq_n_f64(f);
 #endif
 #endif // USE_NEON
 
     } else /* constexpr */ {
         T ret;
         auto &[retval] = ret;  // single-member struct
-        const auto &[aval] = a;
-        const auto &[bval] = b;
         if constexpr (std::is_array_v<decltype(retval)>) {
 #pragma unroll
-            for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vmul(aval[i], bval[i]);
+            for (auto& val : retval) {
+                val = vdupn<std::decay_t<decltype(val)>>(f);
             }
             return ret;
         } else /* constexpr */ {
              auto &[r1, r2] = retval;
-             const auto &[a1, a2] = aval;
-             const auto &[b1, b2] = bval;
-             r1 = vmul(a1, b1);
-             r2 = vmul(a2, b2);
+             using r1_type = std::decay_t<decltype(r1)>;
+             using r2_type = std::decay_t<decltype(r2)>;
+             r1 = vdupn<r1_type>(f);
+             r2 = vdupn<r2_type>(f);
              return ret;
         }
     }
 }
 
-// negate
-template<typename T>
-static inline T vneg(T f) {
+// load from float pointer.
+template<typename T, typename F>
+static inline T vld1(const F *f) {
     if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return -f;
+        return *f;
 
 #ifdef USE_NEON
     } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vneg_f32(f);
+        return vld1_f32(f);
     } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vnegq_f32(f);
+        return vld1q_f32(f);
 #if defined(__aarch64__)
     } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vnegq_f64(f);
+        return vld1q_f64(f);
 #endif
 #endif // USE_NEON
 
     } else /* constexpr */ {
         T ret;
         auto &[retval] = ret;  // single-member struct
-        const auto &[fval] = f;
         if constexpr (std::is_array_v<decltype(retval)>) {
+            using element_type = std::decay_t<decltype(retval[0])>;
+            constexpr size_t subelements = sizeof(element_type) / sizeof(F);
 #pragma unroll
-            for (size_t i = 0; i < std::size(fval); ++i) {
-                retval[i] = vneg(fval[i]);
+            for (size_t i = 0; i < std::size(retval); ++i) {
+                retval[i] = vld1<element_type>(f);
+                f += subelements;
             }
             return ret;
         } else /* constexpr */ {
              auto &[r1, r2] = retval;
-             const auto &[f1, f2] = fval;
-             r1 = vneg(f1);
-             r2 = vneg(f2);
+             using r1_type = std::decay_t<decltype(r1)>;
+             using r2_type = std::decay_t<decltype(r2)>;
+             r1 = vld1<r1_type>(f);
+             f += sizeof(r1) / sizeof(F);
+             r2 = vld1<r2_type>(f);
              return ret;
         }
     }
 }
 
+template<typename T, typename F>
+inline auto vmax(T a, F b) {
+    return implement_arg2([](const auto& x, const auto& y) { return std::max(x, y); },
+            DN_(vmax_f32), DN_(vmaxq_f32), DN64_(vmaxq_f64), a, b);
+}
+
+template<typename T>
+inline T vmax(T a, T b) {
+    return implement_arg2([](const auto& x, const auto& y) { return std::max(x, y); },
+            DN_(vmax_f32), DN_(vmaxq_f32), DN64_(vmaxq_f64), a, b);
+}
+
+template<typename T>
+inline auto vmaxv(const T& a) {
+    return implement_arg1v([](const auto& x, const auto& y) { return std::max(x, y); },
+            DN64_(vmaxv_f32), DN64_(vmaxvq_f32), DN64_(vmaxvq_f64), a);
+}
+
+template<typename T, typename F>
+inline auto vmin(T a, F b) {
+    return implement_arg2([](const auto& x, const auto& y) { return std::min(x, y); },
+            DN_(vmin_f32), DN_(vminq_f32), DN64_(vminq_f64), a, b);
+}
+
+template<typename T>
+inline T vmin(T a, T b) {
+    return implement_arg2([](const auto& x, const auto& y) { return std::min(x, y); },
+            DN_(vmin_f32), DN_(vminq_f32), DN64_(vminq_f64), a, b);
+}
+
+template<typename T>
+inline auto vminv(const T& a) {
+    return implement_arg1v([](const auto& x, const auto& y) { return std::min(x, y); },
+            DN64_(vminv_f32), DN64_(vminvq_f32), DN64_(vminvq_f64), a);
+}
+
+/**
+ * Returns c as follows:
+ * c_i = a_i * b_i if a and b are the same vector type or
+ * c_i = a_i * b if a is a vector and b is scalar or
+ * c_i = a * b_i if a is scalar and b is a vector.
+ */
+
+// Workaround for missing method.
+#if defined(USE_NEON) && defined(__aarch64__)
+float64x2_t vmlaq_n_f64(float64x2_t __p0, float64x2_t __p1, float64_t __p2);
+#endif
+
+template<typename T, typename F>
+static inline T vmla(T a, T b, F c) {
+    return implement_arg3([](const auto& x, const auto& y, const auto& z) { return x + y * z; },
+            DN_(vmla_n_f32), DN_(vmlaq_n_f32), DN64_(vmlaq_n_f64), a, b, c);
+}
+
+template<typename T, typename F>
+static inline T vmla(T a, F b, T c) {
+    return vmla(a, c, b);
+}
+
+// fused multiply-add a + b * c
+template<typename T>
+inline T vmla(const T& a, const T& b, const T& c) {
+    return implement_arg3([](const auto& x, const auto& y, const auto& z) { return x + y * z; },
+            DN_(vmla_f32), DN_(vmlaq_f32), DN64_(vmlaq_f64), a, b, c);
+}
+
+/**
+ * Returns c as follows:
+ * c_i = a_i * b_i if a and b are the same vector type or
+ * c_i = a_i * b if a is a vector and b is scalar or
+ * c_i = a * b_i if a is scalar and b is a vector.
+ */
+template<typename T, typename F>
+static inline auto vmul(T a, F b) {
+    return implement_arg2([](const auto& x, const auto& y) { return x * y; },
+            DN_(vmul_n_f32), DN_(vmulq_n_f32), DN64_(vmulq_n_f64), a, b);
+}
+
+template<typename T>
+inline T vmul(T a, T b) {
+    return implement_arg2([](const auto& x, const auto& y) { return x * y; },
+            DN_(vmul_f32), DN_(vmulq_f32), DN64_(vmulq_f64), a, b);
+}
+
+// negate
+template<typename T>
+inline T vneg(T a) {
+    return implement_arg1([](const auto& x) { return -x; },
+            DN_(vneg_f32), DN_(vnegq_f32), DN64_(vnegq_f64), a);
+}
+
 // store to float pointer.
 template<typename T, typename F>
 static inline void vst1(F *f, T a) {
@@ -552,45 +1828,25 @@ static inline void vst1(F *f, T a) {
 
 // subtract a - b
 template<typename T>
-static inline T vsub(T a, T b) {
-    if constexpr (std::is_same_v<T, float> || std::is_same_v<T, double>) {
-        return a - b;
+inline T vsub(T a, T b) {
+    return implement_arg2([](const auto& x, const auto& y) { return x - y; },
+            DN_(vsub_f32), DN_(vsubq_f32), DN64_(vsubq_f64), a, b);
+}
 
-#ifdef USE_NEON
-    } else if constexpr (std::is_same_v<T, float32x2_t>) {
-        return vsub_f32(a, b);
-    } else if constexpr (std::is_same_v<T, float32x4_t>) {
-        return vsubq_f32(a, b);
-#if defined(__aarch64__)
-    } else if constexpr (std::is_same_v<T, float64x2_t>) {
-        return vsubq_f64(a, b);
-#endif
-#endif // USE_NEON
+// Derived methods
 
-    } else /* constexpr */ {
-        T ret;
-        auto &[retval] = ret;  // single-member struct
-        const auto &[aval] = a;
-        const auto &[bval] = b;
-        if constexpr (std::is_array_v<decltype(retval)>) {
-#pragma unroll
-            for (size_t i = 0; i < std::size(aval); ++i) {
-                retval[i] = vsub(aval[i], bval[i]);
-            }
-            return ret;
-        } else /* constexpr */ {
-             auto &[r1, r2] = retval;
-             const auto &[a1, a2] = aval;
-             const auto &[b1, b2] = bval;
-             r1 = vsub(a1, b1);
-             r2 = vsub(a2, b2);
-             return ret;
-        }
-    }
+/**
+ * Clamps a value between the specified min and max.
+ */
+template<typename T, typename S, typename R>
+static inline T vclamp(const T& value, const S& min_value, const R& max_value) {
+    return vmin(vmax(value, min_value), max_value);
 }
 
 } // namespace android::audio_utils::intrinsics
 
+#pragma pop_macro("DN64_")
+#pragma pop_macro("DN_")
 #pragma pop_macro("USE_NEON")
 
 #endif // !ANDROID_AUDIO_UTILS_INTRINSIC_UTILS_H
diff --git a/audio_utils/include/audio_utils/template_utils.h b/audio_utils/include/audio_utils/template_utils.h
index 66cafbe1..51d4cc10 100644
--- a/audio_utils/include/audio_utils/template_utils.h
+++ b/audio_utils/include/audio_utils/template_utils.h
@@ -19,6 +19,7 @@
 #ifdef __cplusplus
 
 #include <optional>
+#include <string>
 #include <tuple>
 #include <type_traits>
 #include <utility>
@@ -411,4 +412,4 @@ std::optional<T> op_aggregate(BinaryOp op, const T& a, const T& b) {
 
 }  // namespace android::audio_utils
 
-#endif  // __cplusplus
\ No newline at end of file
+#endif  // __cplusplus
diff --git a/audio_utils/spdif/SPDIFEncoder.cpp b/audio_utils/spdif/SPDIFEncoder.cpp
index 3accc8b8..238862a7 100644
--- a/audio_utils/spdif/SPDIFEncoder.cpp
+++ b/audio_utils/spdif/SPDIFEncoder.cpp
@@ -198,7 +198,8 @@ void SPDIFEncoder::flushBurstBuffer()
         sendZeroPad();
         size_t bytesWritten = 0;
         while (mByteCursor > bytesWritten) {
-            ssize_t res = writeOutput(mBurstBuffer + bytesWritten, mByteCursor - bytesWritten);
+            ssize_t res = writeOutput(reinterpret_cast<uint8_t *>(mBurstBuffer) + bytesWritten,
+                    mByteCursor - bytesWritten);
             if (res < 0) {
                 ALOGE("SPDIFEncoder::%s write error %zd", __func__, res);
                 break;
diff --git a/audio_utils/tests/Android.bp b/audio_utils/tests/Android.bp
index 39898f81..a300c7c3 100644
--- a/audio_utils/tests/Android.bp
+++ b/audio_utils/tests/Android.bp
@@ -44,6 +44,24 @@ cc_test {
     ],
 }
 
+cc_test {
+    name: "audio_dsp_tests",
+    host_supported: true,
+    srcs: ["audio_dsp_tests.cpp"],
+    shared_libs: [
+        "libbase",
+        "liblog",
+    ],
+    header_libs: [
+        "libaudioutils_headers",
+    ],
+    cflags: [
+        "-Wall",
+        "-Werror",
+        "-Wthread-safety",
+    ],
+}
+
 cc_test {
     name: "audio_float_tests",
     host_supported: true,
diff --git a/audio_utils/tests/audio_dsp_tests.cpp b/audio_utils/tests/audio_dsp_tests.cpp
new file mode 100644
index 00000000..23a5b53c
--- /dev/null
+++ b/audio_utils/tests/audio_dsp_tests.cpp
@@ -0,0 +1,78 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#define LOG_TAG "audio_dsp_tests"
+
+#include <audio_utils/dsp_utils.h>
+
+#include <gtest/gtest.h>
+#include <utils/Log.h>
+
+using namespace android::audio_utils;
+
+/*
+ * Check behavior on edge cases of 0 count or identical data.
+ */
+TEST(audio_dsp_tests, edge_cases) {
+    constexpr float* noData{};
+    std::vector<float> zeroData(10);
+    std::vector<float> randomData(20);
+    initUniformDistribution(randomData, -.2, .2);
+
+    EXPECT_EQ(0, energy(noData, 0));
+    EXPECT_EQ(std::numeric_limits<float>::infinity(), snr(noData, noData, 0));
+    EXPECT_EQ(std::numeric_limits<float>::infinity(), snr(zeroData, zeroData));
+    EXPECT_EQ(std::numeric_limits<float>::infinity(), snr(randomData, randomData));
+}
+
+/*
+ * We use random energy tests to determine
+ * whether the audio dsp methods works as expected.
+ *
+ * We avoid testing initUniform random number generator
+ * for audio quality but rather suitability to evaluate
+ * signal methods.
+ */
+TEST(audio_dsp_tests, random_energy) {
+    constexpr size_t frameCount = 4096;
+    constexpr size_t channelCount = 2;
+    constexpr float amplitude = 0.1;
+    constexpr size_t sampleCount = channelCount * frameCount;
+    std::vector<float> randomData(sampleCount);
+    initUniformDistribution(randomData, -amplitude, amplitude);
+
+    // compute the expected energy in dB for a uniform distribution from -amplitude to amplitude.
+    const float expectedEnergydB = energyOfUniformDistribution(-amplitude, amplitude);
+    const float energy1dB = energy(randomData);
+    ALOGD("%s: expectedEnergydB: %f  energy1dB: %f", __func__, expectedEnergydB, energy1dB);
+    EXPECT_NEAR(energy1dB, expectedEnergydB, 0.1 /* epsilon */);  // within 0.1dB.
+
+    std::vector<float> randomData2(sampleCount);
+    initUniformDistribution(randomData2, -amplitude, amplitude);
+    const float energy2dB = energy(randomData2);
+    EXPECT_NEAR(energy1dB, energy2dB, 0.1);  // within 0.1dB.
+    // data is correlated, see the larger epsilon.
+    EXPECT_NEAR(-3, snr(randomData, randomData2), 2. /* epsilon */);
+
+    std::vector<float> scaledData(sampleCount);
+    constexpr float scale = 100.f;
+    std::transform(randomData.begin(), randomData.end(), scaledData.begin(),
+            [](auto e) { return e * scale; });
+    const float energyScaled = energy(scaledData);
+    const float scaledB = 20 * log10(scale);  // 40 = 20 log10(100).
+    EXPECT_NEAR(scaledB, energyScaled - energy1dB, 1. /* epsilon */);
+}
+
diff --git a/audio_utils/tests/channelmix_tests.cpp b/audio_utils/tests/channelmix_tests.cpp
index 5c1a6db0..55647153 100644
--- a/audio_utils/tests/channelmix_tests.cpp
+++ b/audio_utils/tests/channelmix_tests.cpp
@@ -50,8 +50,8 @@ static constexpr audio_channel_mask_t kInputChannelMasks[] = {
     AUDIO_CHANNEL_OUT_5POINT1POINT4,
     AUDIO_CHANNEL_OUT_7POINT1POINT2,
     AUDIO_CHANNEL_OUT_7POINT1POINT4,
+    AUDIO_CHANNEL_OUT_13POINT0,
     AUDIO_CHANNEL_OUT_9POINT1POINT6,
-    AUDIO_CHANNEL_OUT_13POINT_360RA,
     AUDIO_CHANNEL_OUT_22POINT2,
     audio_channel_mask_t(AUDIO_CHANNEL_OUT_22POINT2
             | AUDIO_CHANNEL_OUT_FRONT_WIDE_LEFT | AUDIO_CHANNEL_OUT_FRONT_WIDE_RIGHT),
diff --git a/audio_utils/tests/generate_constexpr_constructible.cpp b/audio_utils/tests/generate_constexpr_constructible.cpp
new file mode 100644
index 00000000..016e56e7
--- /dev/null
+++ b/audio_utils/tests/generate_constexpr_constructible.cpp
@@ -0,0 +1,80 @@
+/*
+ * Copyright (C) 2025 The Android Open Source Project
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
+#include <iostream>
+
+// Generates constexpr code for intrinsic_utils.h
+//
+// To dump the constexpr code to stdout:
+//
+// $ clang++ -std=c++2a generate_constexpr_constructible.cpp
+// $ ./a.out
+//
+
+using namespace std;
+
+int main() {
+  const std::string indent("    ");
+  constexpr size_t kElements = 32;
+  // vapply
+  for (size_t i = kElements; i >= 1; --i) {
+    cout << indent << indent;
+    if (i != kElements) cout << "} else ";
+    cout << "if constexpr (is_braces_constructible<VT,\n";
+    for (size_t j = 0; j < i; ) {
+      cout << indent << indent << indent << indent;
+      for (size_t k = 0; k < 8 && j < i; ++k, ++j) {
+        if (k > 0) cout << " ";
+        cout << "any_type";
+        if (j < i - 1) {
+          cout << ",";
+        } else {
+          if (k == 7) {
+            cout << "\n" << indent << indent << indent << indent;
+          }
+          cout << ">()) {";
+        }
+      }
+      cout << "\n";
+    }
+    for (size_t j = 0; j < i; ) {
+      cout << indent << indent << indent;
+      if (j == 0) {
+        cout << "auto& [";
+      } else {
+        cout << indent << indent;
+      }
+      for (size_t k = 0; k < 8 && j < i; ++k, ++j) {
+        if (k > 0) cout << " ";
+        cout << "v" << (j + 1) <<  (j < i - 1 ? "," : "] = vv;");
+      }
+      cout << "\n";
+    }
+
+    for (size_t j = 0; j < i; ++j) {
+      cout << indent << indent << indent;
+      cout << "vapply(f, v" << (j + 1) << ");\n";
+    }
+  }
+  cout << indent << indent;
+  cout << "} else {\n";
+  cout << indent << indent << indent;
+  cout << "static_assert(false, \"Currently supports up to "
+      << kElements << " members only.\");\n";
+  cout << indent << indent;
+  cout << "}\n";
+  return 0;
+}
diff --git a/audio_utils/tests/intrinsic_tests.cpp b/audio_utils/tests/intrinsic_tests.cpp
index d9686ef2..1c9e2937 100644
--- a/audio_utils/tests/intrinsic_tests.cpp
+++ b/audio_utils/tests/intrinsic_tests.cpp
@@ -17,62 +17,371 @@
 #include <audio_utils/intrinsic_utils.h>
 
 #include <gtest/gtest.h>
+#include <random>
+#include <vector>
+
+static constexpr float kFloatTolerance = 1e-3;
+static constexpr size_t kStandardSize = 8;
+static constexpr float kRangeMin = -10.f;
+static constexpr float kRangeMax = 10.f;
+
+// see also std::seed_seq
+static size_t seedCounter = 42;
+
+// create uniform distribution
+template <typename T, typename V>
+static void initUniform(V& v, T rangeMin, T rangeMax) {
+    std::minstd_rand gen(++seedCounter);
+    std::uniform_real_distribution<T> dis(rangeMin, rangeMax);
+
+    android::audio_utils::intrinsics::vapply([&]() { return dis(gen); }, v);
+}
+
+using android::audio_utils::intrinsics::veval;
+
+// constexpr method tests can use static_assert.
+
+static constexpr android::audio_utils::intrinsics::internal_array_t<float, 3> xyzzy =
+        { 10, 10, 10 };
+
+static_assert(android::audio_utils::intrinsics::internal_array_t<float, 3>(10) ==
+        android::audio_utils::intrinsics::internal_array_t<float, 3>(
+                { 10, 10, 10 }));
+
+static_assert(android::audio_utils::intrinsics::internal_array_t<float, 3>(10) !=
+        android::audio_utils::intrinsics::internal_array_t<float, 3>(
+                { 10, 10, 20 }));
+
+static_assert(android::audio_utils::intrinsics::internal_array_t<float, 3>(10) !=
+        android::audio_utils::intrinsics::internal_array_t<float, 3>(
+                { 10, 10 })); // implicit zero fill at end.
+
+static_assert(android::audio_utils::intrinsics::internal_array_t<float, 3>( { 10, 10, 0 }) ==
+        android::audio_utils::intrinsics::internal_array_t<float, 3>(
+                { 10, 10 })); // implicit zero fill at end.
+
+
+static_assert(android::audio_utils::intrinsics::internal_array_t<float, 3>(3) ==
+    []() { android::audio_utils::intrinsics::internal_array_t<float, 3>  temp;
+           vapply(3, temp);
+           return temp; }());
+
+TEST(IntrisicUtilsTest, vector_hw_ctor_compatibility) {
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> a{ 1, 2, 3 };
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> b(
+        android::audio_utils::intrinsics::internal_array_t<float, 3>{ 1, 2, 3 });
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> c(
+        android::audio_utils::intrinsics::internal_array_t<float, 3>{ 1, 2, 2 });
+    EXPECT_TRUE(android::audio_utils::intrinsics::veq(a, b));
+    EXPECT_FALSE(android::audio_utils::intrinsics::veq(a, c));
+}
+
+TEST(IntrisicUtilsTest, veq_nan) {
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> a(std::nanf(""));
+    EXPECT_EQ(0, std::memcmp(&a, &a, sizeof(a)));  // bitwise equal.
+    EXPECT_FALSE(android::audio_utils::intrinsics::veq(a, a));  // logically nan is not.
+}
+
+TEST(IntrisicUtilsTest, veq_zero) {
+    int32_t neg = 0x8000'0000;
+    int32_t pos = 0;
+    float negzero, poszero;
+    memcpy(&negzero, &neg, sizeof(neg));  // float negative zero.
+    memcpy(&poszero, &pos, sizeof(pos));  // float positive zero.
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> a(negzero);
+    const android::audio_utils::intrinsics::vector_hw_t<float, 3> b(poszero);
+    EXPECT_NE(0, std::memcmp(&a, &b, sizeof(a)));  // bitwise not-equal.
+    EXPECT_TRUE(android::audio_utils::intrinsics::veq(a, b));  // logically equal.
+}
 
 template <typename D>
-class IntrisicUtilsTest : public ::testing::Test { };
+class IntrisicUtilsTest : public ::testing::Test {
+};
 
-// Basic intrinsic tests which are run on the simple scalar types (no NEON SIMD vector registers).
-using FloatTypes = ::testing::Types<float, double>;
+// Basic intrinsic tests.
+using FloatTypes = ::testing::Types<float, double,
+        android::audio_utils::intrinsics::internal_array_t<float, kStandardSize>,
+        android::audio_utils::intrinsics::internal_array_t<float, 1>,
+        android::audio_utils::intrinsics::internal_array_t<double, kStandardSize>,
+        android::audio_utils::intrinsics::vector_hw_t<float, kStandardSize>,
+        android::audio_utils::intrinsics::vector_hw_t<float, 1>,
+        android::audio_utils::intrinsics::vector_hw_t<float, 2>,
+        android::audio_utils::intrinsics::vector_hw_t<float, 4>,
+        android::audio_utils::intrinsics::vector_hw_t<float, 7>,
+        android::audio_utils::intrinsics::vector_hw_t<float, 15>
+        >;
 TYPED_TEST_CASE(IntrisicUtilsTest, FloatTypes);
 
-TYPED_TEST(IntrisicUtilsTest, vadd) {
-    constexpr TypeParam a = 0.25f;
-    constexpr TypeParam b = 0.5f;
-    constexpr TypeParam result = a + b;
-    ASSERT_EQ(result, android::audio_utils::intrinsics::vadd(a, b));
+TYPED_TEST(IntrisicUtilsTest, vector_hw_ctor) {
+    if constexpr (!std::is_arithmetic_v<TypeParam>) {
+        if constexpr(std::is_same_v<float, typename TypeParam::element_t>) {
+            android::audio_utils::intrinsics::vector_hw_t<float, TypeParam::size()>
+                    a(TypeParam(0.5));
+        }
+    }
+}
+
+TYPED_TEST(IntrisicUtilsTest, vabs_constant) {
+    const TypeParam value(-3.125f);
+    const TypeParam result = veval([](auto v) { return std::abs(v); }, value);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vabs(value));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vabs_random) {
+    TypeParam value;
+    initUniform(value, kRangeMin, kRangeMax);
+    const TypeParam result = veval([](auto v) { return std::abs(v); }, value);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vabs(value));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vadd_constant) {
+    const TypeParam a(0.25f);
+    const TypeParam b(0.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x + y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vadd(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vadd_random) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x + y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vadd(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vaddv_random) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    element_t result{};
+    android::audio_utils::intrinsics::vapply([&result] (element_t value) { result += value; }, a);
+    EXPECT_NEAR(result, android::audio_utils::intrinsics::vaddv(a), kFloatTolerance);
 }
 
 TYPED_TEST(IntrisicUtilsTest, vdupn) {
-    constexpr TypeParam value = 1.f;
-    ASSERT_EQ(value, android::audio_utils::intrinsics::vdupn<TypeParam>(value));
+    constexpr float ref = 1.f;
+    const TypeParam value(ref);
+    EXPECT_EQ(value, android::audio_utils::intrinsics::vdupn<TypeParam>(ref));
 }
 
 TYPED_TEST(IntrisicUtilsTest, vld1) {
-    constexpr TypeParam value = 2.f;
-    ASSERT_EQ(value, android::audio_utils::intrinsics::vld1<TypeParam>(&value));
+    const TypeParam value(2.f);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(value));
+    EXPECT_EQ(value, android::audio_utils::intrinsics::vld1<TypeParam>(
+            reinterpret_cast<const element_t*>(&value)));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmax_constant) {
+    const TypeParam a(0.25f);
+    const TypeParam b(0.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::max(x, y); }, a, b);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vmax(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmax_random) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::max(x, y); }, a, b);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vmax(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmaxv_random) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    element_t result = android::audio_utils::intrinsics::first_element_of(a);
+    android::audio_utils::intrinsics::vapply(
+            [&result] (element_t value) { result = std::max(result, value); }, a);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vmaxv(a));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmax_random_scalar) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    const element_t scalar = 3.f;
+    TypeParam b(scalar);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::max(x, y); }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmax(a, scalar));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmax(scalar, a));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmax(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmin_constant) {
+    const TypeParam a(0.25f);
+    const TypeParam b(0.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::min(x, y); }, a, b);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vmin(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmin_random) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::min(x, y); }, a, b);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vmin(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vminv_random) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    element_t result = android::audio_utils::intrinsics::first_element_of(a);
+    android::audio_utils::intrinsics::vapply(
+            [&result] (element_t value) { result = std::min(result, value); }, a);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vminv(a));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmin_random_scalar) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    const element_t scalar = 3.f;
+    TypeParam b(scalar);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return std::min(x, y); }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmin(a, scalar));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmin(scalar, a));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmin(a, b));
 }
 
-TYPED_TEST(IntrisicUtilsTest, vmla) {
-    constexpr TypeParam a = 2.125f;
-    constexpr TypeParam b = 2.25f;
-    constexpr TypeParam c = 2.5f;
-    constexpr TypeParam result = c + a * b;
-    ASSERT_EQ(result, android::audio_utils::intrinsics::vmla(c, a, b));
+TYPED_TEST(IntrisicUtilsTest, vmla_constant) {
+    const TypeParam a(2.125f);
+    const TypeParam b(2.25f);
+    const TypeParam c(2.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y, auto z) { return x + y * z; }, a, b, c);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmla(a, b, c));
 }
 
-TYPED_TEST(IntrisicUtilsTest, vmul) {
-    constexpr TypeParam a = 2.25f;
-    constexpr TypeParam b = 2.5f;
-    constexpr TypeParam result = a * b;
-    ASSERT_EQ(result, android::audio_utils::intrinsics::vmul(a, b));
+TYPED_TEST(IntrisicUtilsTest, vmla_random) {
+    TypeParam a, b, c;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    initUniform(c, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y, auto z) { return x + y * z; }, a, b, c);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmla(a, b, c));
 }
 
-TYPED_TEST(IntrisicUtilsTest, vneg) {
-    constexpr TypeParam value = 3.125f;
-    ASSERT_EQ(-value, android::audio_utils::intrinsics::vneg(value));
+TYPED_TEST(IntrisicUtilsTest, vmla_random_scalar) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    const element_t scalar = 3.f;
+    const TypeParam c(scalar);
+    const TypeParam result = veval(
+            [](auto x, auto y, auto z) { return x + y * z; }, a, b, c);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmla(a, scalar, b));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmla(a, b, scalar));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmla(a, b, c));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmul_constant) {
+    const TypeParam a(2.25f);
+    const TypeParam b(2.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x * y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmul(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmul_random) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x * y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmul(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vmul_random_scalar) {
+    TypeParam a;
+    initUniform(a, kRangeMin, kRangeMax);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(a));
+    const element_t scalar = 3.f;
+    const TypeParam b(scalar);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x * y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmul(a, scalar));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmul(scalar, a));
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vmul(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vneg_constant) {
+    const TypeParam value(3.125f);
+    const TypeParam result = veval([](auto v) { return -v; }, value);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vneg(value));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vneg_random) {
+    TypeParam value;
+    initUniform(value, kRangeMin, kRangeMax);
+    const TypeParam result = veval([](auto v) { return -v; }, value);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vneg(value));
 }
 
 TYPED_TEST(IntrisicUtilsTest, vst1) {
-    constexpr TypeParam value = 2.f;
-    TypeParam destination = 1.f;
+    constexpr float ref = 2.f;
+    const TypeParam value(ref);
+    TypeParam destination(1.f);
+    using element_t = decltype(android::audio_utils::intrinsics::first_element_of(value));
     android::audio_utils::intrinsics::vst1(
-            &destination, android::audio_utils::intrinsics::vdupn<TypeParam>(value));
-    ASSERT_EQ(value, destination);
+            reinterpret_cast<element_t*>(&destination),
+            android::audio_utils::intrinsics::vdupn<TypeParam>(ref));
+    EXPECT_EQ(value, destination);
+}
+
+TYPED_TEST(IntrisicUtilsTest, vsub_constant) {
+    const TypeParam a(1.25f);
+    const TypeParam b(1.5f);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x - y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vsub(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vsub_random) {
+    TypeParam a, b;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y) { return x - y; }, a, b);
+    EXPECT_EQ(result, android::audio_utils::intrinsics::vsub(a, b));
+}
+
+TYPED_TEST(IntrisicUtilsTest, vclamp_constant) {
+    const TypeParam a(0.25f);
+    const TypeParam b(0.5f);
+    const TypeParam c(1.f);
+    const TypeParam result = veval(
+            [](auto x, auto y, auto z) { if (y > z) {
+                return std::min(std::max(x, y), z);  // undefined behavior, make defined.
+            } else {
+                return std::clamp(x, y, z);
+            }
+            }, a, b, c);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vclamp(a, b, c));
 }
 
-TYPED_TEST(IntrisicUtilsTest, vsub) {
-    constexpr TypeParam a = 1.25f;
-    constexpr TypeParam b = 1.5f;
-    constexpr TypeParam result = a - b;
-    ASSERT_EQ(result, android::audio_utils::intrinsics::vsub(a, b));
+TYPED_TEST(IntrisicUtilsTest, vclamp_random) {
+    TypeParam a, b, c;
+    initUniform(a, kRangeMin, kRangeMax);
+    initUniform(b, kRangeMin, kRangeMax);
+    initUniform(c, kRangeMin, kRangeMax);
+    const TypeParam result = veval(
+            [](auto x, auto y, auto z) { if (y > z) {
+                return std::min(std::max(x, y), z);  // undefined behavior, make defined.
+            } else {
+                return std::clamp(x, y, z);
+            }
+            }, a, b, c);
+    ASSERT_EQ(result, android::audio_utils::intrinsics::vclamp(a, b, c));
 }
diff --git a/audio_utils/tests/spatializer_utils_tests.cpp b/audio_utils/tests/spatializer_utils_tests.cpp
index 7e8cc31d..8cc879b9 100644
--- a/audio_utils/tests/spatializer_utils_tests.cpp
+++ b/audio_utils/tests/spatializer_utils_tests.cpp
@@ -33,7 +33,7 @@ TEST(spatializer_utils_tests, basic)
     ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_7POINT1POINT2));
     ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_7POINT1POINT4));
     ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_9POINT1POINT4));
+    ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_13POINT0));
     ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_9POINT1POINT6));
-    ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_13POINT_360RA));
     ASSERT_TRUE(audio_is_channel_mask_spatialized(AUDIO_CHANNEL_OUT_22POINT2));
 }
diff --git a/camera/docs/CameraMetadataEnums.mako b/camera/docs/CameraMetadataEnums.mako
index cbc74e72..d5aaca06 100644
--- a/camera/docs/CameraMetadataEnums.mako
+++ b/camera/docs/CameraMetadataEnums.mako
@@ -71,7 +71,7 @@ ${value.sdk_notes | javadoc(metadata)}\
 ## We only support 1 level of inner namespace, i.e. android.a.b and android.a.b.c works, but not android.a.b.c.d
 ## If we need to support more, we should use a recursive function here instead.. but the indentation gets trickier.
         % for entry in filter_visibility(inner_namespace.entries, ('hidden','public', 'ndk_public', \
-        'java_public', 'fwk_pubic', 'fwk_only', 'extension')):
+        'java_public', 'fwk_public', 'fwk_only', 'extension')):
           % if entry.enum \
               and not (entry.typedef and entry.typedef.languages.get('java')) \
               and not entry.is_clone():
diff --git a/camera/docs/CameraMetadataKeys.mako b/camera/docs/CameraMetadataKeys.mako
index 1de389ac..30327d8d 100644
--- a/camera/docs/CameraMetadataKeys.mako
+++ b/camera/docs/CameraMetadataKeys.mako
@@ -62,7 +62,7 @@ ${entry.deprecation_description | javadoc(metadata)}
   % if entry.deprecated:
     @Deprecated
   % endif
-  % if entry.applied_visibility in ('public', 'java_public', 'fwk_java_public', 'fwk_public'):
+  % if entry.applied_visibility in ('public', 'java_public', 'fwk_java_public', 'fwk_public', 'extension_passthrough'):
     @PublicKey
     @NonNull
   % endif
@@ -89,20 +89,20 @@ ${entry.deprecation_description | javadoc(metadata)}
   % for section in outer_namespace.sections:
     % if section.find_first(lambda x: isinstance(x, metadata_model.Entry) and x.kind == xml_name) and \
          any_visible(section, xml_name, ('public','hidden','ndk_public','java_public','fwk_only',\
-             'fwk_java_public','fwk_public','extension','fwk_system_public') ):
+             'fwk_java_public','fwk_public','extension','fwk_system_public','extension_passthrough') ):
       % for inner_namespace in get_children_by_filtering_kind(section, xml_name, 'namespaces'):
 ## We only support 1 level of inner namespace, i.e. android.a.b and android.a.b.c works, but not android.a.b.c.d
 ## If we need to support more, we should use a recursive function here instead.. but the indentation gets trickier.
         % for entry in filter_visibility(inner_namespace.merged_entries, ('hidden','public',\
               'ndk_public','java_public','fwk_only','fwk_java_public','fwk_public',\
-              'extension','fwk_system_public')):
+              'extension','fwk_system_public','extension_passthrough')):
 ${generate_key(entry)}
        % endfor
     % endfor
     % for entry in filter_visibility( \
         get_children_by_filtering_kind(section, xml_name, 'merged_entries'), \
                ('hidden', 'public', 'ndk_public', 'java_public', 'fwk_only', 'fwk_java_public',\
-               'fwk_public','extension','fwk_system_public')):
+               'fwk_public','extension','fwk_system_public','extension_passthrough')):
 ${generate_key(entry)}
     % endfor
     % endif
diff --git a/camera/docs/CaptureResultTest.mako b/camera/docs/CaptureResultTest.mako
index a111fab7..7a4312a8 100644
--- a/camera/docs/CaptureResultTest.mako
+++ b/camera/docs/CaptureResultTest.mako
@@ -25,7 +25,7 @@
 % for sec in find_all_sections(metadata):
   % for entry in find_unique_entries(sec):
     % if entry.kind == 'dynamic' and entry.visibility in ("public", "java_public",\
-          "fwk_java_public", "fwk_public"):
+          "fwk_java_public", "fwk_public",'extension_passthrough'):
       % if not entry.aconfig_flag:
         resultKeys.add(CaptureResult.${jkey_identifier(entry.name)});
       % else:
diff --git a/camera/docs/aidl/CameraMetadataTag.mako b/camera/docs/aidl/CameraMetadataTag.mako
index db95baeb..d36376a0 100644
--- a/camera/docs/aidl/CameraMetadataTag.mako
+++ b/camera/docs/aidl/CameraMetadataTag.mako
@@ -62,7 +62,7 @@ enum CameraMetadataTag {
 <% curIdx = sec_idx << 16 %>\
     % endif
     % if entry.visibility in ('fwk_only', 'fwk_java_public', 'fwk_public', 'fwk_system_public',\
-          'fwk_ndk_public'):
+          'fwk_ndk_public','extension_passthrough'):
 <% gap = True %>\
 <% curIdx += 1 %>\
 <% continue %>\
diff --git a/camera/docs/camera_device_info.mako b/camera/docs/camera_device_info.mako
index 0923d0b7..627b52ab 100644
--- a/camera/docs/camera_device_info.mako
+++ b/camera/docs/camera_device_info.mako
@@ -9,7 +9,7 @@ option java_outer_classname = "CameraDeviceInfoProto";
 // Content of this file is generated from $(ANDROID_ROOT)/system/media/camera/doc
 // Keep internal protocol buffer definition in sync with this one
 // Camera related device information
-// Next Id: 9
+// Next Id: 10
 message CameraDeviceInfo {
   // Supported profiles from CamcorderProfile.hasProfile
   optional bool profile_480p = 1;
@@ -145,5 +145,7 @@ message CameraDeviceInfo {
 
   // Per camera (front/back) informations
   repeated PerCameraInfo per_camera_info = 8;
+
+  optional bool supports_device_as_webcam = 9;
 } // CameraDeviceInfo
 
diff --git a/camera/docs/camera_device_info.proto b/camera/docs/camera_device_info.proto
index ac8259c7..6ad54302 100644
--- a/camera/docs/camera_device_info.proto
+++ b/camera/docs/camera_device_info.proto
@@ -9,7 +9,7 @@ option java_outer_classname = "CameraDeviceInfoProto";
 // Content of this file is generated from $(ANDROID_ROOT)/system/media/camera/doc
 // Keep internal protocol buffer definition in sync with this one
 // Camera related device information
-// Next Id: 9
+// Next Id: 10
 message CameraDeviceInfo {
   // Supported profiles from CamcorderProfile.hasProfile
   optional bool profile_480p = 1;
@@ -244,5 +244,7 @@ message CameraDeviceInfo {
 
   // Per camera (front/back) informations
   repeated PerCameraInfo per_camera_info = 8;
+
+  optional bool supports_device_as_webcam = 9;
 } // CameraDeviceInfo
 
diff --git a/camera/docs/docs.html b/camera/docs/docs.html
index 4d45e207..da4abace 100644
--- a/camera/docs/docs.html
+++ b/camera/docs/docs.html
@@ -37756,12 +37756,6 @@ by the compliance tests:</p>
 </tr>
 <tr>
 <td style="text-align: center;">PRIV</td>
-<td style="text-align: center;">S1080P</td>
-<td style="text-align: center;">PRIV</td>
-<td style="text-align: center;">UHD</td>
-</tr>
-<tr>
-<td style="text-align: center;">PRIV</td>
 <td style="text-align: center;">S720P</td>
 <td style="text-align: center;">JPEG/<wbr/>JPEG_<wbr/>R</td>
 <td style="text-align: center;">MAXIMUM_<wbr/>16_<wbr/>9</td>
@@ -37814,9 +37808,6 @@ by the compliance tests:</p>
 <p>DYNAMIC_<wbr/>RANGE_<wbr/>PROFILE: {STANDARD,<wbr/> HLG10}</p>
 </li>
 </ul>
-<p>All of the above configurations can be set up with a SessionConfiguration.<wbr/> The list of
-OutputConfiguration contains the stream configurations and DYNAMIC_<wbr/>RANGE_<wbr/>PROFILE,<wbr/> and
-the AE_<wbr/>TARGET_<wbr/>FPS_<wbr/>RANGE and VIDEO_<wbr/>STABILIZATION_<wbr/>MODE are set as session parameters.<wbr/></p>
 <p>When set to BAKLAVA,<wbr/> the additional stream combinations below are verified
 by the compliance tests:</p>
 <table>
@@ -37826,23 +37817,52 @@ by the compliance tests:</p>
 <th style="text-align: center;">Size</th>
 <th style="text-align: center;">Target 2</th>
 <th style="text-align: center;">Size</th>
+<th style="text-align: center;">Target 3</th>
+<th style="text-align: center;">Size</th>
 </tr>
 </thead>
 <tbody>
 <tr>
-<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">PRIV Preview</td>
 <td style="text-align: center;">S1080P</td>
-<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">PRIV Video</td>
 <td style="text-align: center;">S1080P</td>
+<td style="text-align: center;"></td>
+<td style="text-align: center;"></td>
 </tr>
 <tr>
-<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">PRIV Preview</td>
 <td style="text-align: center;">S1080P</td>
-<td style="text-align: center;">PRIV</td>
+<td style="text-align: center;">PRIV Video</td>
 <td style="text-align: center;">S1440P</td>
+<td style="text-align: center;"></td>
+<td style="text-align: center;"></td>
+</tr>
+<tr>
+<td style="text-align: center;">PRIV Preview</td>
+<td style="text-align: center;">S1080P</td>
+<td style="text-align: center;">PRIV Video</td>
+<td style="text-align: center;">UHD</td>
+<td style="text-align: center;"></td>
+<td style="text-align: center;"></td>
+</tr>
+<tr>
+<td style="text-align: center;">PRIV Preview</td>
+<td style="text-align: center;">S1080P</td>
+<td style="text-align: center;">YUV Analysis</td>
+<td style="text-align: center;">S1080P</td>
+<td style="text-align: center;">PRIV Video</td>
+<td style="text-align: center;">1080P</td>
 </tr>
 </tbody>
 </table>
+<ul>
+<li>VIDEO_<wbr/>STABILIZATION_<wbr/>MODE: {OFF,<wbr/> ON} for the newly added stream combinations given the
+presence of dedicated video stream</li>
+</ul>
+<p>All of the above configurations can be set up with a SessionConfiguration.<wbr/> The list of
+OutputConfiguration contains the stream configurations and DYNAMIC_<wbr/>RANGE_<wbr/>PROFILE,<wbr/> and
+the AE_<wbr/>TARGET_<wbr/>FPS_<wbr/>RANGE and VIDEO_<wbr/>STABILIZATION_<wbr/>MODE are set as session parameters.<wbr/></p>
             </td>
           </tr>
 
@@ -42074,7 +42094,7 @@ the following entries,<wbr/> so that applications can determine the camera's exa
             <td class="entry_type">
                 <span class="entry_type_name">int32</span>
 
-              <span class="entry_type_visibility"> [fwk_java_public]</span>
+              <span class="entry_type_visibility"> [extension_passthrough]</span>
 
 
 
@@ -42235,7 +42255,7 @@ then the result type will always match with the configured extension type.<wbr/>
             <td class="entry_type">
                 <span class="entry_type_name">int32</span>
 
-              <span class="entry_type_visibility"> [fwk_java_public]</span>
+              <span class="entry_type_visibility"> [extension_passthrough]</span>
 
 
 
@@ -42824,7 +42844,7 @@ output format/<wbr/>size combination for Jpeg/<wbr/>R streams for CaptureRequest
               android.<wbr/>shared<wbr/>Session.<wbr/>color<wbr/>Space
             </td>
             <td class="entry_type">
-                <span class="entry_type_name entry_type_name_enum">byte</span>
+                <span class="entry_type_name entry_type_name_enum">int32</span>
 
               <span class="entry_type_visibility"> [fwk_only]</span>
 
diff --git a/camera/docs/metadata_definitions.xml b/camera/docs/metadata_definitions.xml
index f947d6c2..b85ee2f0 100644
--- a/camera/docs/metadata_definitions.xml
+++ b/camera/docs/metadata_definitions.xml
@@ -13345,7 +13345,6 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
               PRIV        | S1080P        | JPEG/JPEG_R     | UHD          |
               PRIV        | S1080P        | JPEG/JPEG_R     | S1440P       |
               PRIV        | S1080P        | JPEG/JPEG_R     | S1080P       |
-              PRIV        | S1080P        | PRIV            | UHD          |
               PRIV        | S720P         | JPEG/JPEG_R     | MAXIMUM_16_9 |
               PRIV        | S720P         | JPEG/JPEG_R     | UHD          |
               PRIV        | S720P         | JPEG/JPEG_R     | S1080P       |
@@ -13368,17 +13367,22 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
 
           * DYNAMIC_RANGE_PROFILE: {STANDARD, HLG10}
 
-          All of the above configurations can be set up with a SessionConfiguration. The list of
-          OutputConfiguration contains the stream configurations and DYNAMIC_RANGE_PROFILE, and
-          the AE_TARGET_FPS_RANGE and VIDEO_STABILIZATION_MODE are set as session parameters.
-
           When set to BAKLAVA, the additional stream combinations below are verified
           by the compliance tests:
 
-          Target 1    |     Size      | Target 2        |     Size     |
-          :----------:|:-------------:|:---------------:|:------------:|
-          PRIV        | S1080P        | PRIV            | S1080P       |
-          PRIV        | S1080P        | PRIV            | S1440P       |
+          Target 1     |     Size      | Target 2        |     Size     | Target 3   |    Size     |
+          :-----------:|:-------------:|:---------------:|:------------:|:----------:|:-----------:|
+          PRIV Preview | S1080P        | PRIV Video      | S1080P       |            |             |
+          PRIV Preview | S1080P        | PRIV Video      | S1440P       |            |             |
+          PRIV Preview | S1080P        | PRIV Video      | UHD          |            |             |
+          PRIV Preview | S1080P        | YUV Analysis    | S1080P       | PRIV Video | 1080P       |
+
+          * VIDEO_STABILIZATION_MODE: {OFF, ON} for the newly added stream combinations given the
+          presence of dedicated video stream
+
+          All of the above configurations can be set up with a SessionConfiguration. The list of
+          OutputConfiguration contains the stream configurations and DYNAMIC_RANGE_PROFILE, and
+          the AE_TARGET_FPS_RANGE and VIDEO_STABILIZATION_MODE are set as session parameters.
 
           </details>
           <hal_details>
@@ -15015,7 +15019,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
     </section>
     <section name="extension">
       <controls>
-        <entry name="strength" type="int32" visibility="fwk_java_public" hal_version="3.9">
+        <entry name="strength" type="int32" visibility="extension_passthrough" hal_version="3.9">
           <description>Strength of the extension post-processing effect
           </description>
           <range>0 - 100</range>
@@ -15257,7 +15261,7 @@ xsi:schemaLocation="http://schemas.android.com/service/camera/metadata/ metadata
     </section>
     <section name="sharedSession">
       <static>
-        <entry name="colorSpace" type="byte" visibility="fwk_only" optional="true"
+        <entry name="colorSpace" type="int32" visibility="fwk_only" optional="true"
           enum="true" aconfig_flag="camera_multi_client" hal_version="3.11">
           <enum>
             <value id="-1">UNSPECIFIED</value>
diff --git a/camera/docs/metadata_definitions.xsd b/camera/docs/metadata_definitions.xsd
index 71e74bbf..6e1d0263 100644
--- a/camera/docs/metadata_definitions.xsd
+++ b/camera/docs/metadata_definitions.xsd
@@ -210,7 +210,7 @@
                     <enumeration value="fwk_java_public" /> <!-- public to java. Not included in NDK. Not included in hal interfaces. -->
                     <enumeration value="fwk_system_public" /> <!-- system API in java. Not included in NDK. Not included in hal interfaces -->
                     <enumeration value="fwk_public" /> <!-- public to both java and NDK. Not included in hal interfaces. -->
-                    <enumeration value="fwk_ndk_public" /> <!-- public to NDK. Not included in java or hal interfaces. -->
+                    <enumeration value="extension_passthrough" /> <!-- public to java. Not included in the NDK. Not fwk filtered and Hal passthrough -->
                 </restriction>
             </simpleType>
         </attribute>
@@ -329,6 +329,7 @@
                     <enumeration value="extension" /> <!-- java as @hide. Included as a public enum in the extensions. -->
                     <enumeration value="test" /> <!-- java as @TestApi. Not included in NDK -->
                     <enumeration value="public" /> <!-- public to both java and NDK -->
+                    <enumeration value="extension_passthrough" /> <!-- public to java not included in NDK -->
                 </restriction>
             </simpleType>
         </attribute>
diff --git a/camera/docs/metadata_helpers.py b/camera/docs/metadata_helpers.py
index eafb9929..35b72e31 100644
--- a/camera/docs/metadata_helpers.py
+++ b/camera/docs/metadata_helpers.py
@@ -1126,9 +1126,9 @@ def dedent(text):
     String dedented by above rules.
 
   For example:
-    assertEquals("bar\nline1\nline2",   dedent("bar\n  line1\n  line2"))
-    assertEquals("bar\nline1\nline2",   dedent(" bar\n  line1\n  line2"))
-    assertEquals("bar\n  line1\nline2", dedent(" bar\n    line1\n  line2"))
+    assertEqual("bar\nline1\nline2",   dedent("bar\n  line1\n  line2"))
+    assertEqual("bar\nline1\nline2",   dedent(" bar\n  line1\n  line2"))
+    assertEqual("bar\n  line1\nline2", dedent(" bar\n    line1\n  line2"))
   """
   text = textwrap.dedent(text)
   text_lines = text.split('\n')
@@ -1417,7 +1417,8 @@ def remove_hal_non_visible(entries):
   Yields:
     An iterable of Entry nodes
   """
-  return (e for e in entries if not (e.synthetic or is_not_hal_visible(e)))
+  return (e for e in entries if not (e.synthetic or e.visibility == 'extension_passthrough' or
+                                     is_not_hal_visible(e)))
 
 def remove_ndk_non_visible(entries):
   """
diff --git a/camera/docs/metadata_model_test.py b/camera/docs/metadata_model_test.py
index 540fb341..752bfd9f 100644
--- a/camera/docs/metadata_model_test.py
+++ b/camera/docs/metadata_model_test.py
@@ -35,12 +35,12 @@ class TestInnerNamespace(TestCase):
     combined_ins = [i for i in combined_children_namespace.namespaces]
     combined_ent = [i for i in combined_children_namespace.entries]
 
-    self.assertEquals(kind, combined_children_namespace.parent)
-    self.assertEquals(1, len(combined_ins))
-    self.assertEquals(1, len(combined_ent))
+    self.assertEqual(kind, combined_children_namespace.parent)
+    self.assertEqual(1, len(combined_ins))
+    self.assertEqual(1, len(combined_ent))
 
-    self.assertEquals("ins1", combined_ins[0].name)
-    self.assertEquals("entry3", combined_ent[0].name)
+    self.assertEqual("ins1", combined_ins[0].name)
+    self.assertEqual("entry3", combined_ent[0].name)
 
     new_ins = combined_ins[0]
     self.assertIn(entry1, new_ins.entries)
@@ -75,7 +75,7 @@ class TestKind(TestCase):
     #
     combined_kind = section.combine_kinds_into_single_node()
 
-    self.assertEquals(section, combined_kind.parent)
+    self.assertEqual(section, combined_kind.parent)
 
     self.assertIn(ins1, combined_kind.namespaces)
     self.assertIn(ins2, combined_kind.namespaces)
@@ -115,12 +115,12 @@ class TestKind(TestCase):
     combined_ins = [i for i in combined_children_kind.namespaces]
     combined_ent = [i for i in combined_children_kind.entries]
 
-    self.assertEquals(section, combined_children_kind.parent)
-    self.assertEquals(1, len(combined_ins))
-    self.assertEquals(1, len(combined_ent))
+    self.assertEqual(section, combined_children_kind.parent)
+    self.assertEqual(1, len(combined_ins))
+    self.assertEqual(1, len(combined_ent))
 
-    self.assertEquals("ins1", combined_ins[0].name)
-    self.assertEquals("entry3", combined_ent[0].name)
+    self.assertEqual("ins1", combined_ins[0].name)
+    self.assertEqual("entry3", combined_ent[0].name)
 
     new_ins = combined_ins[0]
     self.assertIn(entry1, new_ins.entries)
diff --git a/camera/include/system/camera_metadata_tags.h b/camera/include/system/camera_metadata_tags.h
index c73950e9..a9ee8449 100644
--- a/camera/include/system/camera_metadata_tags.h
+++ b/camera/include/system/camera_metadata_tags.h
@@ -605,7 +605,7 @@ typedef enum camera_metadata_tag {
             ANDROID_AUTOMOTIVE_LENS_START,
     ANDROID_AUTOMOTIVE_LENS_END,
 
-    ANDROID_EXTENSION_STRENGTH =                      // int32        | fwk_java_public
+    ANDROID_EXTENSION_STRENGTH =                      // int32        | extension_passthrough | HIDL v3.9
             ANDROID_EXTENSION_START,
     ANDROID_EXTENSION_CURRENT_TYPE,                   // int32        | fwk_java_public
     ANDROID_EXTENSION_NIGHT_MODE_INDICATOR,           // enum         | public       | HIDL v3.11
diff --git a/camera/src/camera_metadata_tag_info.c b/camera/src/camera_metadata_tag_info.c
index 59494d29..63d51c02 100644
--- a/camera/src/camera_metadata_tag_info.c
+++ b/camera/src/camera_metadata_tag_info.c
@@ -1027,7 +1027,7 @@ static tag_info_t android_jpegr[ANDROID_JPEGR_END -
 static tag_info_t android_shared_session[ANDROID_SHARED_SESSION_END -
         ANDROID_SHARED_SESSION_START] = {
     [ ANDROID_SHARED_SESSION_COLOR_SPACE - ANDROID_SHARED_SESSION_START ] =
-    { "colorSpace",                    TYPE_BYTE   },
+    { "colorSpace",                    TYPE_INT32  },
     [ ANDROID_SHARED_SESSION_OUTPUT_CONFIGURATIONS - ANDROID_SHARED_SESSION_START ] =
     { "outputConfigurations",          TYPE_INT64  },
 };
diff --git a/tests/audio_effects_utils_tests.cpp b/tests/audio_effects_utils_tests.cpp
index 5af268b4..81ee864c 100644
--- a/tests/audio_effects_utils_tests.cpp
+++ b/tests/audio_effects_utils_tests.cpp
@@ -26,12 +26,7 @@
 #include <system/audio_effects/audio_effects_utils.h>
 
 using namespace android;
-using android::effect::utils::EffectParamReader;
-using android::effect::utils::EffectParamWrapper;
-using android::effect::utils::EffectParamWriter;
-using android::effect::utils::operator==;
-using android::effect::utils::operator!=;
-using android::effect::utils::ToString;
+using namespace android::effect::utils;
 
 TEST(EffectParamWrapperTest, setAndGetMatches) {
     effect_param_t param = {.psize = 2, .vsize = 0x10};
@@ -478,3 +473,92 @@ TEST(AudioEffectsUtilsTest, ToStringBoundaryValues) {
 
     EXPECT_EQ(ToString(uuid), expected);
 }
+
+TEST(AudioEffectsUtilsTest, writeToEffectParamInts) {
+    int32_t buf32[sizeof(effect_param_t) / sizeof(int32_t) + 2 * sizeof(int32_t)];
+    int32_t p = 0x10, v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(OK, writeToEffectParam(param, p, v));
+    EXPECT_EQ(param->psize, sizeof(p));
+    EXPECT_EQ(param->vsize, sizeof(v));
+    EXPECT_EQ(*reinterpret_cast<int32_t*>(param->data), p);
+    EXPECT_EQ(*(reinterpret_cast<int32_t *>(param->data) + 1), v);
+
+    int32_t pRead, vRead;
+    EXPECT_EQ(OK, readFromEffectParam(param, &pRead, &vRead));
+    EXPECT_EQ(pRead, p);
+    EXPECT_EQ(vRead, v);
+}
+
+TEST(AudioEffectsUtilsTest, writeToEffectParamWithPadding) {
+    int32_t buf32[sizeof(effect_param_t) / sizeof(int32_t) + 2 * sizeof(int32_t)];
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(OK, writeToEffectParam(param, p, v));
+    EXPECT_EQ(param->psize, EffectParamWrapper::padding(sizeof(p)));
+    EXPECT_EQ(param->vsize, sizeof(v));
+    EXPECT_EQ(*reinterpret_cast<int32_t*>(param->data), p);
+    EXPECT_EQ(*(reinterpret_cast<int32_t *>(param->data) + 1), v);
+
+    int32_t pRead, vRead;
+    EXPECT_EQ(OK, readFromEffectParam(param, &pRead, &vRead));
+    EXPECT_EQ(pRead, p);
+    EXPECT_EQ(vRead, v);
+}
+
+TEST(AudioEffectsUtilsTest, writeToEffectParamNullptr) {
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    EXPECT_EQ(BAD_VALUE, writeToEffectParam(nullptr, p, v));
+}
+
+TEST(AudioEffectsUtilsTest, writeToEffectParamNoEnoughSpace) {
+    int32_t buf32[sizeof(effect_param_t)];
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(BAD_VALUE, writeToEffectParam(nullptr, p, v, sizeof(effect_param_t)));
+}
+
+TEST(AudioEffectsUtilsTest, readFromEffectParamNullptr) {
+    int32_t buf32[sizeof(effect_param_t)];
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(BAD_VALUE, readFromEffectParam(nullptr, &p, &v));
+    EXPECT_EQ(BAD_VALUE, readFromEffectParam(param, (int8_t*)0, &v));
+    EXPECT_EQ(BAD_VALUE, readFromEffectParam(param, &p, (uint32_t *)0));
+}
+
+TEST(AudioEffectsUtilsTest, readFromEffectParamPSizeTooSmall) {
+    int32_t buf32[sizeof(effect_param_t) / sizeof(int32_t) + 2 * sizeof(int32_t)];
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(OK, writeToEffectParam(param, p, v));
+    EXPECT_EQ(param->psize, EffectParamWrapper::padding(sizeof(p)));
+    EXPECT_EQ(param->vsize, sizeof(v));
+    EXPECT_EQ(*reinterpret_cast<int32_t*>(param->data), p);
+    EXPECT_EQ(*(reinterpret_cast<int32_t *>(param->data) + 1), v);
+
+    param->psize--;
+    int32_t pRead, vRead;
+    EXPECT_EQ(BAD_VALUE, readFromEffectParam(param, &pRead, &vRead));
+}
+
+TEST(AudioEffectsUtilsTest, readFromEffectParamVSizeTooSmall) {
+    int32_t buf32[sizeof(effect_param_t) / sizeof(int32_t) + 2 * sizeof(int32_t)];
+    int8_t p = 0x10;
+    uint32_t v = 0xff;
+    effect_param_t *param = (effect_param_t *)buf32;
+    EXPECT_EQ(OK, writeToEffectParam(param, p, v));
+    EXPECT_EQ(param->psize, EffectParamWrapper::padding(sizeof(p)));
+    EXPECT_EQ(param->vsize, sizeof(v));
+    EXPECT_EQ(*reinterpret_cast<int32_t*>(param->data), p);
+    EXPECT_EQ(*(reinterpret_cast<int32_t *>(param->data) + 1), v);
+
+    param->vsize--;
+    int32_t pRead, vRead;
+    EXPECT_EQ(BAD_VALUE, readFromEffectParam(param, &pRead, &vRead));
+}
```

